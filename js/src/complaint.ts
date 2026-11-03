// Complaints (SPEC §11.3): the voter's proof that the ingest dropped an
// accepted message or refused a valid one. A complaint is a signed event
// (kind 27106, or 7106 from an earlier client) whose content is
// {"v":1,"ack":<the ingest's signed ack>,"body":<the body, as JSON>}.
// Channels keep no copy (ephemeral kinds), so the voter keeps the event
// and hands it on: a link (`#c=<base64url>`) or a file. Anyone judges it
// from the mirror alone:
//
//   dropped        an accepted ack names checkpoint N: the claim holds
//                  when N's entries lack the body (late: it was logged in
//                  a later checkpoint), fails when they hold it, waits
//                  while the mirror does not cover N yet
//   wrong_refusal  a refused ack: the body is judged again by the wasm
//                  judge against the log up to the ack's minute; the
//                  claim holds when the judge accepts it, fails when it
//                  refuses it, is uncertain when the answer depends on
//                  the second within the minute or on what was pending

import { normalizeEntries, type AuditRequest } from './audit.js';
import { IsoloirError } from './errors.js';
import { Mirror, covered, dirSource, type Fetcher, type MirrorSource } from './mirror.js';
import type { ComplaintClaim, LedgerSetup, NostrEvent } from './types.js';
import { Core, messageOf, type IsoloirWasm } from './wasm.js';

/** The base64url (no padding) of a complaint event's JSON: what a link fragment (`#c=…`) or a file carries. */
export function encodeComplaint(event: NostrEvent): string {
	const bytes = new TextEncoder().encode(JSON.stringify(event));
	let bin = '';
	for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
	return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** A complaint event from its base64url (a link's `#c=` value, with or without `#c=`), or its JSON text. */
export function decodeComplaint(text: string): NostrEvent {
	let t = text.trim();
	const frag = /(?:^|[#&])c=([A-Za-z0-9_-]+)/.exec(t);
	if (frag) t = frag[1];
	if (t.startsWith('{')) return parseEvent(t);
	if (!/^[A-Za-z0-9_-]+$/.test(t)) throw new IsoloirError('bad_complaint', 'neither base64url nor JSON');
	let bin: string;
	try {
		bin = atob(t.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (t.length % 4)) % 4));
	} catch {
		throw new IsoloirError('bad_complaint', 'not base64url');
	}
	const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
	let json: string;
	try {
		json = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
	} catch {
		throw new IsoloirError('bad_complaint', 'not UTF-8');
	}
	return parseEvent(json);
}

function parseEvent(json: string): NostrEvent {
	try {
		return JSON.parse(json) as NostrEvent;
	} catch {
		throw new IsoloirError('bad_complaint', 'not JSON');
	}
}

const coreOf = (c: Core | IsoloirWasm) => (c instanceof Core ? c : new Core(c));

/**
 * Reads a complaint: an event, its base64url or its JSON. Checks the
 * event's signature, the complaint's form, the ack's signature (by one of
 * `ingestKeys` when given) and that the ack names the body. Throws
 * bad_complaint otherwise. Judges nothing against the log: judgeComplaint.
 */
export function readComplaint(core: Core | IsoloirWasm, input: NostrEvent | string, ingestKeys: string[] = []): ComplaintClaim {
	const event = typeof input === 'string' ? decodeComplaint(input) : input;
	try {
		return coreOf(core).readComplaint(JSON.stringify(event), ingestKeys);
	} catch (e) {
		throw new IsoloirError('bad_complaint', messageOf(e));
	}
}

export type ComplaintVerdictCode =
	/** The claim holds: the ingest dropped an accepted message, or refused a valid one. */
	| 'holds'
	/** The claim fails: the body is in the checkpoint its ack named, or the judge refuses it too. */
	| 'fails'
	/** The mirror does not cover the checkpoint the ack names yet: judge again later. */
	| 'pending'
	/** Judged again, the refusal depends on the second within the ack's minute or on the messages pending then. */
	| 'uncertain'
	/** A proof the judge needs could not be checked (no verifier, or it failed to run). */
	| 'unchecked'
	/** Not a complaint of this ledger: its form, a signature, or an ack not signed by the ledger's ingest. */
	| 'invalid';

export interface ComplaintVerdict {
	verdict: ComplaintVerdictCode;
	/** What the verdict rests on, in a sentence. */
	detail: string;
	/** What the complaint claims (absent when it could not be read). */
	claim?: ComplaintClaim;
	/** dropped: where the body is in the log, when it is (late: after the checkpoint the ack named). */
	found?: { checkpoint: number; seq: number; late: boolean } | null;
	/** wrong_refusal: the judge's answers, at the first and the last second of the ack's minute, without and with the next checkpoint's entries pending. */
	rejudged?: { time: number; pending: boolean; outcome: 'accepted' | 'rejected' | 'deferred'; reason: string | null }[];
	/** The newest checkpoint the mirror covers when judged. */
	upto?: number;
}

export interface JudgeComplaintOptions {
	/** The ledger's mirror: sources, a directory URL, or a Mirror. */
	mirror: MirrorSource[] | string | Mirror;
	/** The ledger's pinned log key (the app's configuration, never the mirror's). */
	verifierKey: string;
	fetch?: Fetcher;
	/** A refusal judged again may need a ballot proof checked (bbVerifier). */
	verifyProof?(req: Extract<AuditRequest, { type: 'proof' }>): Promise<boolean>;
	/** …or a passport proof (zkPassportVerifier). */
	verifyPassport?(req: Extract<AuditRequest, { type: 'passport' }>): Promise<string | null>;
	/** Accepts the dev passport provider (a local trial). */
	allowDev?: boolean;
	/** How many checkpoints after the named one a dropped body is looked for (default 16). */
	lateSearch?: number;
	signal?: AbortSignal;
	/** A refusal judged again replays the log: checkpoints read so far, of how many. */
	onProgress?(p: { checkpoint: number; checkpoints: number }): void;
}

/** Judges a complaint against the ledger's mirror (SPEC §11.3). */
export async function judgeComplaint(core: Core | IsoloirWasm, input: NostrEvent | string, opts: JudgeComplaintOptions): Promise<ComplaintVerdict> {
	const c = coreOf(core);
	const mirror = opts.mirror instanceof Mirror ? opts.mirror : new Mirror(c, typeof opts.mirror === 'string' ? [dirSource(opts.mirror)] : opts.mirror, opts.verifierKey, opts.fetch);
	let claim: ComplaintClaim;
	try {
		claim = readComplaint(c, input);
	} catch (e) {
		return { verdict: 'invalid', detail: messageOf(e) };
	}
	const latest = await mirror.latest();
	if (!latest) throw new IsoloirError('mirror', 'the mirror has no checkpoint');
	const token = latest.mirror ?? '';
	// The ack must be the ledger's: signed by an ingest key the ledger named.
	const ledgers = await mirror.setupHistory<LedgerSetup>('setup/ledger.json', 'ledger', token);
	const keys = [...new Set(ledgers.map((l) => l.body.ingest))];
	if (!keys.includes(claim.ingest)) return { verdict: 'invalid', detail: 'the ack is not signed by an ingest key of this ledger', claim };
	const upto = covered(latest);
	return claim.claim === 'dropped' ? judgeDropped(c, mirror, claim, upto, token, opts) : judgeRefusal(c, mirror, claim, upto, token, opts);
}

async function judgeDropped(c: Core, mirror: Mirror, claim: ComplaintClaim, upto: number, token: string, opts: JudgeComplaintOptions): Promise<ComplaintVerdict> {
	const n = claim.checkpoint!;
	if (n > upto) return { verdict: 'pending', detail: `checkpoint ${n} is not on the mirror yet (it covers ${upto})`, claim, upto };
	const last = Math.min(upto, n + (opts.lateSearch ?? 16));
	for (let i = n; i <= last; i++) {
		opts.signal?.throwIfAborted();
		const entries = await mirror.entries(i, token);
		if (entries === null) {
			if (i === n) throw new IsoloirError('mirror', `entries/${n}.json is missing`);
			break;
		}
		const mine = entries.find((e) => e.kind === claim.kind && c.bodyHash(e.body) === claim.hash);
		if (mine) {
			const found = { checkpoint: i, seq: mine.seq, late: i > n };
			if (i === n) return { verdict: 'fails', detail: `the body is entry ${mine.seq}, in checkpoint ${n} as its ack said`, claim, found, upto };
			return { verdict: 'holds', detail: `the body is missing from checkpoint ${n}, which its ack named: it was logged late, in checkpoint ${i}`, claim, found, upto };
		}
	}
	return { verdict: 'holds', detail: `the body is missing from checkpoint ${n}, which its ack named, and from the checkpoints after it up to ${last}`, claim, found: null, upto };
}

async function judgeRefusal(c: Core, mirror: Mirror, claim: ComplaintClaim, upto: number, token: string, opts: JudgeComplaintOptions): Promise<ComplaintVerdict> {
	const w = c.w;
	const t0 = claim.time;
	const t1 = claim.time + 59;
	const id = w.audit_start(opts.verifierKey, '{}', opts.allowDev === true);
	try {
		w.audit_quiet(id, true);
		// The state the ingest judged against: the checkpoints of the ack's minute and before.
		let pending = '[]';
		let fed = 0;
		for (let i = 1; i <= upto; i++) {
			opts.signal?.throwIfAborted();
			const [note, entries] = await Promise.all([mirror.text(`checkpoints/${i}.txt`, token), mirror.text(`entries/${i}.json`, token)]);
			if (note === null || entries === null) throw new IsoloirError('mirror', `checkpoint ${i} is missing on the mirror`);
			const time = Number(/^time (\d+)$/m.exec(note)?.[1] ?? NaN);
			const list = normalizeEntries(entries);
			if (time > t0) {
				// The next checkpoint: its entries may have been waiting at the ingest then.
				pending = JSON.stringify((JSON.parse(list) as { kind: string; body: string }[]).map((e) => ({ kind: e.kind, body: e.body })));
				break;
			}
			w.audit_checkpoint(id, note, list);
			fed = i;
			opts.onProgress?.({ checkpoint: i, checkpoints: upto });
		}
		if (fed === 0) return { verdict: 'pending', detail: 'the mirror holds no checkpoint before the refusal yet', claim, upto };
		let out = JSON.parse(w.audit_rejudge(id, claim.kind, claim.body, JSON.stringify([t0, t1]), pending)) as Rejudged;
		if (out.requests.length) {
			const verdicts: Record<string, unknown> = {};
			for (const r of out.requests) {
				try {
					if (r.type === 'proof') {
						if (!opts.verifyProof) throw new Error('no ballot proof verifier');
						verdicts[r.key] = { type: 'proof', ok: await opts.verifyProof(r) };
					} else {
						if (!opts.verifyPassport) throw new Error('no passport verifier');
						verdicts[r.key] = { type: 'passport', uid: await opts.verifyPassport(r) };
					}
				} catch (e) {
					verdicts[r.key] = { type: r.type, error: messageOf(e) };
				}
			}
			w.audit_answer(id, JSON.stringify(verdicts));
			out = JSON.parse(w.audit_rejudge(id, claim.kind, claim.body, JSON.stringify([t0, t1]), pending)) as Rejudged;
		}
		const rejudged = out.verdicts;
		const base = { claim, rejudged, upto };
		if (rejudged.some((v) => v.outcome === 'deferred')) {
			return { ...base, verdict: 'unchecked', detail: `a check could not run: ${rejudged.find((v) => v.outcome === 'deferred')!.reason}` };
		}
		if (rejudged.every((v) => v.outcome === 'accepted')) return { ...base, verdict: 'holds', detail: `refused as ${claim.reason}, the body is valid against the log of that minute` };
		if (rejudged.every((v) => v.outcome === 'rejected')) {
			const reasons = [...new Set(rejudged.map((v) => v.reason))];
			if (reasons.length === 1 && reasons[0] === claim.reason) return { ...base, verdict: 'fails', detail: `judged again, the body is refused as ${claim.reason} too` };
			return { ...base, verdict: 'fails', detail: `judged again, the body is refused (${reasons.join(', ')}), though not for the reason the ack gave (${claim.reason})` };
		}
		return { ...base, verdict: 'uncertain', detail: 'judged again, the body is accepted or refused depending on the second within the minute or on the messages pending then' };
	} finally {
		w.audit_drop(id);
	}
}

interface Rejudged {
	verdicts: NonNullable<ComplaintVerdict['rejudged']>;
	requests: AuditRequest[];
}
