// The audit in the browser (SPEC §16): anyone recounts the ledger from
// its mirror with the same Rust judge the CLI runs (crates/wasm/src/
// audit.rs). The log is read twice: the first pass collects the proofs
// the judge asks for, the page verifies them (ballots with bb.js against
// the mirror's verification keys, passports with the ZKPassport SDK), and
// the second pass replays the log with the verdicts. Then the relays'
// copies are compared with the log (withholding). A check that could not
// run is a problem, never a pass.

import type { IsoloirWasm } from './wasm.js';
import type { Eligibility, NostrEvent, OprfKey } from './types.js';
import type { RelayTransport } from './relay.js';

/** A proof the judge asked for. */
export type AuditRequest =
	| { key: string; type: 'proof'; circuit: string; vk_hash: string; proof: string; inputs: string[] }
	| {
			key: string;
			type: 'passport';
			eligibility: Eligibility;
			proof: { proofs?: unknown[]; result?: Record<string, unknown> } & Record<string, unknown>;
			custom_data: string;
			proof_date: number;
	  };

/** The counts and findings of an audit. */
export interface AuditReport {
	problems: string[];
	warnings: string[];
	checkpoints: number;
	entries: number;
	registrations: number;
	ballots: number;
	rejects: number;
	tallies: number;
}

export interface AuditResult extends AuditReport {
	/** Ballot proofs and passport proofs checked in the page. */
	proofs: { checked: number; failed: number };
	passports: { checked: number; failed: number };
	/** Events read from the relays, and the relays read (null: not checked). */
	relays: { events: number; read: string[]; failed: string[] } | null;
	polls: { id: number; title: string; ballots: number }[];
	ok: boolean;
}

export type AuditPhase = 'download' | 'proofs' | 'replay' | 'relays' | 'done';

export interface AuditProgress {
	phase: AuditPhase;
	/** Checkpoints read in this pass, and how many there are. */
	checkpoint: number;
	checkpoints: number;
	/** Proofs verified so far, and asked for so far. */
	verified: number;
	asked: number;
	report: AuditReport | null;
}

export interface AuditOptions {
	/** A mirror file's text, or null when it is missing (checkpoint.txt, checkpoints/<i>.txt, entries/<i>.json). */
	text(path: string): Promise<string | null>;
	/** The ledger's log key, pinned (from the app's configuration, never from the mirror). */
	logKey: string;
	/** Verifies a ballot proof: true, false, or throws when it could not run. */
	verifyProof(req: Extract<AuditRequest, { type: 'proof' }>): Promise<boolean>;
	/** Verifies a passport proof: the document's unique identifier, null when refused, or throws. */
	verifyPassport(req: Extract<AuditRequest, { type: 'passport' }>): Promise<string | null>;
	/** Reads the relays' copies (withholding); absent, not checked. */
	relays?: RelayTransport;
	onProgress?(p: AuditProgress): void;
	/** Stops the audit (it then throws). */
	signal?: AbortSignal;
	/**
	 * Accepts a registry of the dev passport provider (a local trial, where
	 * anyone may register). Absent, such a registry and its registrations
	 * are problems, as for the ingest and the authority.
	 */
	allowDev?: boolean;
}

type Verdict = { type: 'proof'; ok?: boolean; error?: string } | { type: 'passport'; uid?: string | null; error?: string };

/** Audits the ledger a mirror serves. */
export async function audit(wasm: IsoloirWasm & AuditWasm, opts: AuditOptions): Promise<AuditResult> {
	const latest = await opts.text('checkpoint.txt');
	if (latest === null) throw new Error('the mirror has no checkpoint');
	const last = Number(/^index (\d+)$/m.exec(latest)?.[1] ?? NaN);
	if (!Number.isFinite(last)) throw new Error('checkpoint.txt: no index');

	const verdicts: Record<string, Verdict> = {};
	const progress: AuditProgress = { phase: 'download', checkpoint: 0, checkpoints: last, verified: 0, asked: 0, report: null };
	const tell = () => opts.onProgress?.({ ...progress });
	const proofs = { checked: 0, failed: 0 };
	const passports = { checked: 0, failed: 0 };

	// The proofs are verified while the first pass reads on.
	const queue: AuditRequest[] = [];
	let draining: Promise<void> | null = null;
	const drain = async () => {
		while (queue.length) {
			opts.signal?.throwIfAborted();
			const r = queue.shift()!;
			try {
				if (r.type === 'proof') {
					const ok = await opts.verifyProof(r);
					verdicts[r.key] = { type: 'proof', ok };
					proofs.checked++;
					if (!ok) proofs.failed++;
				} else {
					const uid = await opts.verifyPassport(r);
					verdicts[r.key] = { type: 'passport', uid };
					passports.checked++;
					if (uid === null) passports.failed++;
				}
			} catch (e) {
				verdicts[r.key] = { type: r.type, error: e instanceof Error ? e.message : String(e) } as Verdict;
			}
			progress.verified++;
			tell();
		}
	};
	const ask = (rs: AuditRequest[]) => {
		for (const r of rs) {
			if (r.key in verdicts || queue.some((q) => q.key === r.key)) continue;
			queue.push(r);
			progress.asked++;
		}
		if (!draining) draining = drain().finally(() => (draining = null));
	};

	const pass = async (onCheckpoint: (out: CheckpointOut) => void): Promise<number> => {
		const id = wasm.audit_start(opts.logKey, JSON.stringify(verdicts), opts.allowDev === true);
		try {
			for (let i = 1; i <= last; i++) {
				opts.signal?.throwIfAborted();
				const [note, entries] = await Promise.all([opts.text(`checkpoints/${i}.txt`), opts.text(`entries/${i}.json`)]);
				if (note === null) throw new Error(`checkpoint ${i} is missing on the mirror`);
				if (entries === null) throw new Error(`the entries of checkpoint ${i} are missing on the mirror`);
				const out = JSON.parse(wasm.audit_checkpoint(id, note, entries)) as CheckpointOut;
				progress.checkpoint = i;
				progress.report = out.report;
				onCheckpoint(out);
				tell();
			}
			return id;
		} catch (e) {
			wasm.audit_drop(id);
			throw e;
		}
	};

	// 1. Read the log, collect the proofs and verify them as they come.
	const first = await pass((out) => ask(out.requests));
	wasm.audit_drop(first);
	progress.phase = 'proofs';
	tell();
	while (draining) await draining;

	// 2. Replay with the verdicts.
	progress.phase = 'replay';
	progress.checkpoint = 0;
	tell();
	const second = await pass((out) => {
		// A proof first asked now (it should not happen): verified later, reported meanwhile.
		if (out.requests.length) ask(out.requests);
	});
	try {
		const fin = JSON.parse(wasm.audit_finish(second)) as AuditReport & {
			ledger?: { relays: string[]; tag: string; ingest: string; grace: number };
			polls: AuditResult['polls'];
		};

		// 3. The relays' copies (withholding).
		let relays: AuditResult['relays'] = null;
		if (opts.relays && fin.ledger && fin.ledger.relays.length) {
			progress.phase = 'relays';
			tell();
			const events: NostrEvent[] = [];
			const read: string[] = [];
			const failed: string[] = [];
			await Promise.all(
				fin.ledger.relays.map((url) =>
					readRelay(opts.relays!, url, { kinds: [7100, 7101, 7102, 7105], '#t': [fin.ledger!.tag] }).then(
						(es) => {
							events.push(...es);
							read.push(url);
						},
						() => failed.push(url)
					)
				)
			);
			const found = JSON.parse(wasm.audit_relays(second, JSON.stringify(events))) as string[];
			fin.problems.push(...found);
			for (const u of failed) fin.warnings.push(`relay ${u}: not read`);
			relays = { events: events.length, read, failed };
		}

		progress.phase = 'done';
		progress.report = fin;
		tell();
		const { ledger: _ledger, ...report } = fin;
		return { ...report, proofs, passports, relays, ok: fin.problems.length === 0 };
	} finally {
		wasm.audit_drop(second);
	}
}

interface CheckpointOut {
	index: number;
	time: number;
	report: AuditReport;
	requests: AuditRequest[];
}

/** The audit functions of the wasm core. */
export interface AuditWasm {
	audit_start(log_key: string, verdicts_json: string, allow_dev: boolean): number;
	audit_checkpoint(id: number, note: string, entries_json: string): string;
	audit_finish(id: number): string;
	audit_relays(id: number, events_json: string): string;
	audit_drop(id: number): void;
}

/** A relay's stored events for a filter, up to its end-of-stored-events. */
function readRelay(t: RelayTransport, url: string, filter: Parameters<RelayTransport['subscribe']>[1], timeoutMs = 30_000): Promise<NostrEvent[]> {
	return new Promise((resolve, reject) => {
		const events: NostrEvent[] = [];
		let stop = () => {};
		const timer = setTimeout(() => {
			stop();
			reject(new Error('timeout'));
		}, timeoutMs);
		stop = t.subscribe(url, filter, (e) => events.push(e), {
			onEose: () => {
				clearTimeout(timer);
				stop();
				resolve(events);
			},
			onDown: () => {
				clearTimeout(timer);
				stop();
				reject(new Error('down'));
			}
		});
	});
}

/**
 * Verifies ballot proofs with bb.js against the mirror's verification
 * keys (circuits/<name>/vk), each checked against the hash the poll names
 * (as the CLI does with bb). `bytes` reads a mirror file's bytes.
 */
export function bbVerifier(bytes: (path: string) => Promise<Uint8Array | null>, target = 'noir-recursive'): (req: Extract<AuditRequest, { type: 'proof' }>) => Promise<boolean> {
	const keys = new Map<string, Promise<Uint8Array>>();
	let verifier: Promise<{ verifyProof(p: { proof: Uint8Array; publicInputs: string[]; verificationKey: Uint8Array }, o: { verifierTarget: string }): Promise<boolean> }> | null = null;
	const vk = (name: string, hash: string) => {
		let k = keys.get(hash);
		if (k) return k;
		k = (async () => {
			if (/[/.]/.test(name)) throw new Error(`circuit name ${name}`);
			const b = await bytes(`circuits/${name}/vk`);
			if (!b) throw new Error(`circuits/${name}/vk is missing on the mirror`);
			const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', b as BufferSource));
			const got = '0x' + Array.from(digest, (x) => x.toString(16).padStart(2, '0')).join('');
			if (got !== hash.toLowerCase()) throw new Error(`circuits/${name}/vk: its hash is not the poll's`);
			return b;
		})();
		k.catch(() => keys.delete(hash));
		keys.set(hash, k);
		return k;
	};
	return async (req) => {
		if (!verifier) {
			verifier = (async () => {
				const { Barretenberg, UltraHonkVerifierBackend } = (await import('@aztec/bb.js')) as never as {
					Barretenberg: { new (o: unknown): Promise<unknown> };
					UltraHonkVerifierBackend: new (api: unknown) => never;
				};
				const api = await (Barretenberg as unknown as { new: (o: unknown) => Promise<unknown> }).new({ threads: 1 });
				return new UltraHonkVerifierBackend(api);
			})();
			verifier.catch(() => (verifier = null));
		}
		const [v, key] = await Promise.all([verifier, vk(req.circuit, req.vk_hash)]);
		const proof = Uint8Array.from(atob(req.proof), (c) => c.charCodeAt(0));
		return v.verifyProof({ proof, publicInputs: req.inputs, verificationKey: key }, { verifierTarget: target });
	};
}

/** The parts of @zkpassport/sdk and @zkpassport/utils the passport verifier uses (given by the app). */
export interface ZkPassportSdk {
	ZKPassport: new (domain: string) => {
		createQuery(): unknown;
		verify(o: Record<string, unknown>): Promise<{ verified: boolean; uniqueIdentifier?: string; queryResultErrors?: unknown }>;
	};
	NullifierType: { NON_SALTED: unknown; SALTED: unknown };
}

// The OPRF keys the registries pin, by id: the SDK asks the OPRF nodes for
// the key a salted proof used (`<node>/oprf_pub/<id>`) and gets the
// registry's, so the audit holds when the nodes are down or serve another
// key. Every other request goes through.
const pinnedOprf = new Map<string, OprfKey>();
let oprfFetchPinned = false;
function pinOprfKey(key: OprfKey): void {
	const known = pinnedOprf.get(key.id);
	if (known && (known.x !== key.x || known.y !== key.y)) throw new Error(`two registries pin OPRF key ${key.id} differently`);
	pinnedOprf.set(key.id, key);
	if (oprfFetchPinned) return;
	oprfFetchPinned = true;
	const real = globalThis.fetch.bind(globalThis);
	globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
		const m = /\/oprf_pub\/([^/?#]+)$/.exec(url);
		if (!m) return real(input, init);
		const k = pinnedOprf.get(decodeURIComponent(m[1]));
		if (!k) return new Response('not a registry key', { status: 404 });
		return new Response(JSON.stringify({ key: [k.x, k.y] }), { status: 200, headers: { 'content-type': 'application/json' } });
	};
}

/**
 * Verifies passport proofs with the ZKPassport SDK, locally (its open
 * verifier; the certificate registry roots read on Ethereum through
 * `rpcUrl`; a salted identifier against the registry's pinned OPRF key).
 * The query is rebuilt from the registry's rules and the
 * registration's binding, as the ingest's verifier does (zkverifier/
 * verify.mjs).
 */
export function zkPassportVerifier(sdk: ZkPassportSdk, rpcUrl: string): (req: Extract<AuditRequest, { type: 'passport' }>) => Promise<string | null> {
	return async (req) => {
		const e = req.eligibility;
		if (e.provider !== 'zkpassport') throw new Error(`provider ${e.provider}: no verifier in the page`);
		const proofs = req.proof.proofs;
		if (!Array.isArray(proofs) || proofs.length === 0) return null;
		const zk = new sdk.ZKPassport(e.domain);
		type Builder = {
			gte(k: string, v: unknown): Builder;
			in(k: string, v: unknown): Builder;
			eq(k: string, v: unknown): Builder;
			bind(k: string, v: unknown): Builder;
			facematch(mode: 'strict'): Builder;
			done(): { query: unknown };
		};
		let b = zk.createQuery() as Builder;
		if (e.min_age) b = b.gte('age', e.min_age);
		if (e.nationality?.length) b = b.in('nationality', e.nationality);
		if (e.document_type) b = b.eq('document_type', e.document_type);
		const result = (req.proof.result ?? {}) as { expiry_date?: { gte?: { expected?: string } } };
		if (e.require_expiry) {
			const expected = result.expiry_date?.gte?.expected;
			if (!expected) return null;
			const date = new Date(expected);
			const day = 86_400_000;
			const ref = req.proof_date * 1000;
			if (!(date.getTime() >= ref - 2 * day && date.getTime() <= ref + day)) return null;
			b = b.gte('expiry_date', date);
		}
		// A salted identifier comes with the strict face match (verify.mjs).
		if (e.oprf_key) b = b.facematch('strict');
		b = b.bind('custom_data', req.custom_data);
		const { query } = b.done();
		// The one identifier type the registry names (verify.mjs).
		if (e.oprf_key) pinOprfKey(e.oprf_key);
		const r = await zk.verify({
			proofs,
			originalQuery: query,
			queryResult: req.proof.result,
			scope: e.scope,
			devMode: false,
			uniqueIdentifierType: e.oprf_key ? sdk.NullifierType.SALTED : sdk.NullifierType.NON_SALTED,
			oprfKeyId: e.oprf_key?.id,
			validity: 10 * 365 * 86_400,
			verifierMode: 'local',
			config: { rpcUrl }
		});
		return r.verified && r.uniqueIdentifier ? r.uniqueIdentifier : null;
	};
}
