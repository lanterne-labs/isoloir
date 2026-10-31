// The world around a session, in memory: relays, a mirror, and an ingest
// that judges, acknowledges, checkpoints and mirrors as SPEC.md says (its
// notes and tallies are signed by the wasm core's dev helpers, so the
// session verifies exactly what the real ingest writes). Proofs are not
// checked: the stub prover's bytes are opaque.

import { createRequire } from 'node:module';
import { Core, type IsoloirWasm } from '../src/wasm.js';
import type { Fetcher } from '../src/mirror.js';
import type { Filter, RelayTransport, SubscribeOptions } from '../src/relay.js';
import type { Prover } from '../src/prover.js';
import { DirectChannel, NostrChannel, type ChannelFactory, type HttpFetch } from '../src/channel.js';
import type { Channel, LedgerSetup, NostrEvent, PollSetup, RegistrySetup } from '../src/types.js';

export interface DevWasm extends IsoloirWasm {
	dev_verifier(seed: string, origin: string): string;
	dev_sign_checkpoint(seed: string, checkpoint: string): string;
	dev_authority(seed: string): string;
	dev_ed25519_public(seed: string): string;
	dev_build_tally(req: string): string;
	dev_log_proof(entries: string, i: number, n: number): string;
	dev_tlock_chain(seed: number, round: number): string;
	dev_tlock_open(signature: string, blob: string): string;
}

const require = createRequire(import.meta.url);
export const wasm = require('../wasm/node/isoloir_wasm.js') as DevWasm;
export const core = new Core(wasm);

export const ORIGIN = 'test.example/isoloir';
export const TAG = `isoloir/1/${ORIGIN}`;
export const RELAYS = ['wss://r1.test', 'wss://r2.test', 'wss://r3.test'];
export const DIRECT = 'https://ingest.test';
export const nostr = (url: string): Channel => ({ type: 'nostr', url, state: 'active' });
export const direct = (url: string): Channel => ({ type: 'direct', url, state: 'active' });
export const MIRROR = 'https://mirror.test';

// ------------------------------------------------------------ mirror

export class FakeMirror {
	readonly files = new Map<string, string>();
	reads: string[] = [];
	/** Paths whose fetch never answers (until aborted). */
	readonly hang = new Set<string>();

	put(path: string, v: string | unknown) {
		this.files.set(path, typeof v === 'string' ? v : JSON.stringify(v));
	}

	fetch: Fetcher = async (url, init) => {
		const path = url.slice(MIRROR.length + 1);
		this.reads.push(path);
		if (this.hang.has(path)) {
			return new Promise((_, reject) => init?.signal?.addEventListener('abort', () => reject(new Error('aborted'))));
		}
		const f = this.files.get(path);
		return f === undefined ? { status: 404, ok: false, text: async () => '' } : { status: 200, ok: true, text: async () => f };
	};
}

// ------------------------------------------------------------ relays

interface Sub {
	filter: Filter;
	onEvent: (e: NostrEvent) => void;
}

interface FakeRelay {
	events: NostrEvent[];
	subs: Set<Sub>;
	down: boolean;
	/** Takes acks and never delivers them (a relay that loses messages). */
	dropAcks: boolean;
}

function matches(f: Filter, e: NostrEvent): boolean {
	if (f.ids && !f.ids.includes(e.id)) return false;
	if (f.kinds && !f.kinds.includes(e.kind)) return false;
	if (f.authors && !f.authors.includes(e.pubkey)) return false;
	if (f.since !== undefined && e.created_at < f.since) return false;
	const tagIn = (name: string, values?: string[]) => !values || e.tags.some((t) => t[0] === name && values.includes(t[1]));
	return tagIn('e', f['#e']) && tagIn('t', f['#t']);
}

export class FakeRelays implements RelayTransport {
	readonly relays = new Map<string, FakeRelay>();
	/** Every subscription made, by whom it was asked of. */
	readonly subscriptions: { url: string; filter: Filter }[] = [];

	constructor(urls: string[]) {
		for (const u of urls) this.relays.set(u, { events: [], subs: new Set(), down: false, dropAcks: false });
	}

	relay(url: string): FakeRelay {
		const r = this.relays.get(url);
		if (!r) throw new Error(`no relay ${url}`);
		return r;
	}

	async publish(url: string, event: NostrEvent): Promise<void> {
		const r = this.relays.get(url);
		if (!r || r.down) throw new Error(`${url}: connection failed`);
		if (!core.verifyEvent(event)) throw new Error(`${url} refused: invalid: bad signature`);
		if (r.dropAcks && event.kind === core.kinds.ack) return;
		if (r.events.some((e) => e.id === event.id)) return;
		r.events.push(event);
		for (const s of [...r.subs]) if (matches(s.filter, event)) queueMicrotask(() => s.onEvent(event));
	}

	subscribe(url: string, filter: Filter, onEvent: (e: NostrEvent) => void, opts: SubscribeOptions = {}): () => void {
		this.subscriptions.push({ url, filter });
		const r = this.relays.get(url);
		if (!r || r.down) {
			queueMicrotask(() => opts.onDown?.());
			return () => {};
		}
		const sub = { filter, onEvent };
		const stored = r.events.filter((e) => matches(filter, e));
		queueMicrotask(() => {
			for (const e of stored) onEvent(e);
			opts.onEose?.();
		});
		r.subs.add(sub);
		return () => r.subs.delete(sub);
	}

	/** Every event of a kind on every relay. */
	all(kind: number): NostrEvent[] {
		return [...this.relays.values()].flatMap((r) => r.events.filter((e) => e.kind === kind));
	}
}

// ------------------------------------------------------------ ingest

interface Pending {
	kind: 'register' | 'ballot';
	body: string;
	hash: string;
}

const SHARD = 1024;

export interface Authority {
	sk: string;
	pk: string;
	sign_seed: string;
	sign_key: string;
}

export class FakeIngest {
	readonly secret = '11'.repeat(32);
	readonly pubkey = core.regPubkey(this.secret);
	readonly logSeed = '22'.repeat(32);
	readonly verifier = wasm.dev_verifier(this.logSeed, ORIGIN);
	readonly authority = JSON.parse(wasm.dev_authority('33'.repeat(32))) as Authority;
	readonly ledger: LedgerSetup;
	readonly registry: RegistrySetup;
	readonly polls: PollSetup[];

	seq = 0;
	index = 0;
	pending: Pending[] = [];
	/** The ack of every envelope judged, sent again as it is. */
	readonly acks = new Map<string, NostrEvent>();
	readonly leaves: string[] = [];
	readonly uids = new Set<string>();
	readonly ids = new Set<string>();
	readonly pseudonyms = new Map<string, number>();
	readonly idents = new Set<string>();
	readonly ballotLeaves = new Map<number, string[]>();
	/** The counted ballots per poll: linked by nullifier, delta all. */
	readonly counted = new Map<number, Map<string, string>>();
	/** Bodies acknowledged and never logged (a dishonest ingest). */
	readonly withhold = new Set<string>();
	/** Judges nothing (an ingest that is down). */
	silent = false;

	/** Envelopes the direct endpoint took while the ingest was silent. */
	readonly backlog: NostrEvent[] = [];
	/** Every entry of the log, in seq order: [kind, body]. */
	readonly log: [string, string][] = [];
	/** The accepted bodies and the checkpoint their ack named: a body is answered once, under any envelope. */
	readonly accepted = new Map<string, number>();
	/** Envelopes dated before this are never seen (the ingest reads relays by cursor − 120 s). */
	minCreatedAt = 0;
	/** The setup files, every version. */
	readonly setupFiles = new Map<string, { seq: number; body: string; checkpoint: number; size: number; path: string[] }[]>();

	constructor(
		readonly relays: FakeRelays,
		readonly mirror: FakeMirror,
		readonly channels: Channel[] = RELAYS.map(nostr),
		readonly now: () => number = () => Math.floor(Date.now() / 1000)
	) {
		this.ledger = { v: 1, version: 1, origin: ORIGIN, log_key: this.verifier, ingest: this.pubkey, channels, checkpoint_period: 20, anchor_age: 86400 };
		this.registry = { v: 1, id: 1, version: 1, name: 'Test', eligibility: { provider: 'dev', domain: 'vote.test', scope: 'isoloir/registry/1' }, validity: 3600, depth: 20 };
		const elgamal = { mode: 'elgamal' as const, pk: this.authority.pk, authority: { type: 'single' as const, sign_key: this.authority.sign_key } };
		const base = { v: 1 as const, version: 1, registry: 1, title: 'Q', kind: { type: 'choice' as const, options: ['Oui', 'Non'], blank: true }, encryption: elgamal, publish: { mode: 'open' as const, k_real: 1, min_gap: 0, coin: false }, opens: 0, closes: 4_000_000_000 };
		this.polls = [
			{ ...base, id: 7, revote: 'linked', circuit: { name: 'choice4_single_linked_d20', vk_hash: '0x' + '0'.repeat(64) } },
			{ ...base, id: 8, revote: 'delta', ballot_depth: 22, circuit: { name: 'choice4_single_delta_d20_b22', vk_hash: '0x' + '0'.repeat(64) } },
			{ ...base, id: 9, revote: 'none', publish: { mode: 'closed' }, circuit: { name: 'choice4_single_linked_d20', vk_hash: '0x' + '0'.repeat(64) } }
		];
		// The setups are the log's first entries, in checkpoint 1.
		const setups: { kind: string; body: unknown; path: string }[] = [
			{ kind: 'ledger', body: this.ledger, path: 'setup/ledger.json' },
			{ kind: 'registry', body: this.registry, path: 'registries/1.json' },
			...this.polls.map((p) => ({ kind: 'poll', body: p, path: `polls/${p.id}.json` }))
		];
		const entries = setups.map((s) => {
			const body = core.canonical(s.body);
			const seq = this.seq++;
			this.log.push([s.kind, body]);
			return { seq, kind: s.kind, body, path: s.path };
		});
		this.publishCheckpoint(entries);
		for (const e of entries) this.writeSetup(e.path, e.seq, e.body, this.index);
		for (const url of this.relayUrls()) {
			relays.subscribe(url, { kinds: [core.kinds.register, core.kinds.ballot], '#t': [TAG] }, (e) => this.onRelay(url, e));
		}
	}

	relayUrls(): string[] {
		return this.channels.filter((c) => c.type === 'nostr').map((c) => c.url);
	}

	private onRelay(url: string, e: NostrEvent) {
		const ack = this.judge(e);
		if (ack) void this.relays.publish(url, ack);
	}

	/** Comes back after being down: judges what the relays and the endpoint hold, as a real ingest reads them by cursor. */
	resume(): void {
		this.silent = false;
		for (const url of this.relayUrls()) {
			for (const e of this.relays.relay(url).events) if ((e.kind === core.kinds.register || e.kind === core.kinds.ballot) && !this.acks.has(e.id)) this.onRelay(url, e);
		}
		for (const e of this.backlog.splice(0)) this.judge(e);
	}

	/** The inclusion proof of entry `seq` in checkpoint `checkpoint`'s log (its size). */
	proof(seq: number, size: number): { root: string; path: string[] } {
		return JSON.parse(wasm.dev_log_proof(JSON.stringify(this.log.slice(0, size)), seq, size)) as { root: string; path: string[] };
	}

	/** Adds a version to a setup file, as crates/server/src/mirror.rs writes it. */
	writeSetup(path: string, seq: number, body: string, checkpoint: number, size = this.seq) {
		const list = this.setupFiles.get(path) ?? [];
		list.push({ seq, body, checkpoint, size, path: this.proof(seq, size).path });
		this.setupFiles.set(path, list);
		this.mirror.put(path, { setups: list });
	}

	poll(id: number): PollSetup {
		const p = this.polls.find((x) => x.id === id);
		if (!p) throw new Error(`no poll ${id}`);
		return p;
	}

	/** Judges an envelope once; returns its signed ack (the same on every channel), null when silent. */
	judge(e: NostrEvent): NostrEvent | null {
		if (this.silent || e.created_at < this.minCreatedAt) return null;
		const prior = this.acks.get(e.id);
		if (prior) return prior;
		const kind = e.kind === core.kinds.register ? 'register' : 'ballot';
		const hash = core.bodyHash(e.content);
		// The same body under another envelope: the same outcome (crates/server/src/ingest.rs).
		const before = this.accepted.get(hash);
		const reason = before !== undefined ? null : kind === 'register' ? this.checkRegister(e.content) : this.checkBallot(e.content);
		const ack = reason
			? { v: 1, of: e.id, hash, outcome: 'rejected', reason }
			: { v: 1, of: e.id, hash, outcome: 'accepted', checkpoint: before ?? this.index + 1 };
		if (!reason && before === undefined) {
			this.pending.push({ kind, body: e.content, hash });
			this.accepted.set(hash, this.index + 1);
		}
		const ev = core.signEvent(this.secret, this.now(), core.kinds.ack, [['t', TAG], ['e', e.id]], core.canonical(ack));
		this.acks.set(e.id, ev);
		return ev;
	}

	private checkRegister(text: string): string | null {
		let b: { registry: number; id: string; uid: string; key: string; proof: { custom_data?: string } };
		try {
			b = core.decodeBody('register', text);
			wasm.verify_register(text);
		} catch {
			return 'bad_sig';
		}
		if (b.registry !== 1) return 'unknown';
		const pend = this.pending.filter((p) => p.kind === 'register').map((p) => JSON.parse(p.body) as { uid: string; id: string });
		if (this.uids.has(b.uid) || pend.some((p) => p.uid === b.uid)) return 'uid_used';
		if (this.ids.has(b.id) || pend.some((p) => p.id === b.id)) return 'id_used';
		if (b.proof.custom_data !== core.registrationBinding(1, b.key)) return 'bad_proof';
		return null;
	}

	private checkBallot(text: string): string | null {
		let b: { poll: number; nullifier?: string; seq?: number; ident?: string };
		try {
			b = core.decodeBody('ballot', text);
		} catch (e) {
			return 'malformed';
		}
		const p = this.polls.find((x) => x.id === b.poll);
		if (!p) return 'unknown';
		if (p.revote === 'delta') {
			const pend = this.pending.some((x) => x.kind === 'ballot' && (JSON.parse(x.body) as { ident?: string }).ident === b.ident);
			if (this.idents.has(b.ident!) || pend) return 'duplicate';
			return null;
		}
		const last = Math.max(
			this.pseudonyms.get(b.nullifier!) ?? -1,
			...this.pending.filter((x) => x.kind === 'ballot').map((x) => JSON.parse(x.body) as { nullifier?: string; seq?: number }).filter((x) => x.nullifier === b.nullifier).map((x) => x.seq ?? -1)
		);
		if (last >= 0 && p.revote === 'none') return 'revote_off';
		if (b.seq! <= last) return 'stale_seq';
		return null;
	}

	/** Logs the pending messages in body hash order and publishes a signed checkpoint and the mirror's files. */
	checkpoint(extra: { kind: string; body: string }[] = []): void {
		const batch = [...this.pending].sort((a, b) => (a.hash < b.hash ? -1 : a.hash > b.hash ? 1 : 0));
		this.pending = [];
		const entries: { seq: number; kind: string; body: string }[] = [];
		for (const x of extra) {
			entries.push({ seq: this.seq++, kind: x.kind, body: x.body });
			this.log.push([x.kind, x.body]);
		}
		for (const m of batch) {
			if (this.withhold.has(m.hash)) continue;
			const seq = this.seq++;
			this.log.push([m.kind, m.body]);
			entries.push({ seq, kind: m.kind, body: m.body });
			if (m.kind === 'register') {
				const b = JSON.parse(m.body) as { uid: string; id: string };
				this.uids.add(b.uid);
				this.ids.add(b.id);
				this.leaves.push(b.id);
			} else {
				const b = JSON.parse(m.body) as { poll: number; nullifier?: string; seq?: number; ident?: string; cmt?: string };
				const counted = this.counted.get(b.poll) ?? new Map<string, string>();
				this.counted.set(b.poll, counted);
				if (b.ident) {
					this.idents.add(b.ident);
					const l = this.ballotLeaves.get(b.poll) ?? [];
					l.push(core.deltaLeaf(b.ident, b.cmt!));
					this.ballotLeaves.set(b.poll, l);
					counted.set(b.ident, m.body);
				} else {
					this.pseudonyms.set(b.nullifier!, b.seq!);
					counted.set(b.nullifier!, m.body);
				}
			}
		}
		this.publishCheckpoint(entries);
	}

	private publishCheckpoint(entries: { seq: number; kind: string; body: string }[]) {
		this.index++;
		const regRoot = core.treeRoot(this.registry.depth, this.leaves);
		const ballots = this.polls
			.filter((p) => p.revote === 'delta')
			.map((p) => {
				const l = this.ballotLeaves.get(p.id) ?? [];
				return { poll: p.id, size: l.length, root: core.treeRoot(p.ballot_depth!, l) };
			})
			.filter((b) => b.size > 0);
		const cp = { origin: ORIGIN, size: this.seq, root: this.proof(0, this.seq).root, index: this.index, time: this.now(), registries: [{ id: 1, size: this.leaves.length, root: regRoot }], ballots, mirror: null };
		const note = wasm.dev_sign_checkpoint(this.logSeed, JSON.stringify(cp));
		const m = this.mirror;
		m.put(`entries/${this.index}.json`, entries);
		m.put(`checkpoints/${this.index}.txt`, note);
		m.put('checkpoint.txt', note);
		this.shards('registries/1/leaves', this.leaves);
		const positions = new Map<string, Record<string, number>>();
		this.leaves.forEach((l, i) => {
			const pp = l.slice(2, 4);
			positions.set(pp, { ...(positions.get(pp) ?? {}), [l]: i });
		});
		for (const [pp, v] of positions) m.put(`registries/1/positions/${pp}.json`, v);
		const pseud = new Map<string, Record<string, number>>();
		for (const [n, s] of this.pseudonyms) pseud.set(n.slice(2, 4), { ...(pseud.get(n.slice(2, 4)) ?? {}), [n]: s });
		for (const p of this.polls) if (p.revote !== 'delta') for (const [pp, v] of pseud) m.put(`polls/${p.id}/pseudonyms/${pp}.json`, v);
		for (const [poll, l] of this.ballotLeaves) this.shards(`polls/${poll}/ballots`, l);
		for (const r of this.relayUrls()) void this.relays.publish(r, core.signEvent(this.secret, this.now(), core.kinds.checkpoint, [['t', TAG]], note));
	}

	private shards(dir: string, leaves: string[]) {
		for (let k = 0; k * SHARD < Math.max(leaves.length, 1); k++) this.mirror.put(`${dir}/${k}.json`, leaves.slice(k * SHARD, (k + 1) * SHARD));
	}

	/** The authority's tally of a poll over its counted ballots, on the mirror. */
	tally(pollId: number): string {
		const ballots = [...(this.counted.get(pollId)?.values() ?? [])];
		const req = { poll: this.poll(pollId), upto: this.seq - 1, checkpoint: this.index, final: false, ballots, sk: this.authority.sk, sign_seed: this.authority.sign_seed, seed: '44'.repeat(32) };
		return this.logTally(pollId, wasm.dev_build_tally(JSON.stringify(req)));
	}

	/** Logs a tally body as it is (an authority's, or a forged one) and mirrors it with its proof. */
	logTally(pollId: number, body: string): string {
		const seq = this.seq;
		// Logged, then mirrored with its proof (crates/server/src/mirror.rs).
		this.checkpoint([{ kind: 'tally', body }]);
		const proof = this.proof(seq, this.seq);
		this.mirror.put(`polls/${pollId}/tallies/latest.json`, { seq, body, checkpoint: this.index, size: this.seq, path: proof.path });
		return body;
	}
}

// ------------------------------------------------------------ prover

export class StubProver implements Prover {
	calls: { circuit: string; inputs: Record<string, unknown> }[] = [];
	async prove(circuit: string, inputs: Record<string, unknown>) {
		this.calls.push({ circuit, inputs });
		return { proof: crypto.getRandomValues(new Uint8Array(96)) };
	}
}

// ------------------------------------------------------------ direct

/**
 * The ingest's HTTP endpoint (crates/server/src/direct.rs): POST
 * /v1/messages answers the ack (200) or {pending} (202); GET
 * /v1/acks/{id} the ack (200) or 404.
 */
export class FakeDirect {
	/** The next POST is judged and its response lost (a dropped connection). */
	dropResponse = false;
	/** The next POST is answered 202 and judged this many ms later. */
	deferMs: number | null = null;
	/** POSTs answered with this status (a refusal of the endpoint itself). */
	refuseStatus: number | null = null;
	/** Requests that never answer (until aborted). */
	hang = false;
	readonly received: NostrEvent[] = [];
	readonly requests: string[] = [];

	constructor(
		readonly url: string,
		readonly ingest: FakeIngest
	) {}

	fetch: HttpFetch = async (url, init) => {
		const path = url.slice(this.url.length);
		const method = init?.method ?? 'GET';
		this.requests.push(`${method} ${path}`);
		if (this.hang) return new Promise((_, reject) => init?.signal?.addEventListener('abort', () => reject(new Error('aborted'))));
		const json = (status: number, v: unknown) => ({ status, ok: status < 300, text: async () => JSON.stringify(v) });
		if (method === 'GET') {
			const m = /^\/v1\/acks\/([0-9a-f]{64})$/.exec(path);
			const ack = m ? this.ingest.acks.get(m[1]) : undefined;
			return ack ? json(200, ack) : { status: 404, ok: false, text: async () => '' };
		}
		if (path !== '/v1/messages') return { status: 404, ok: false, text: async () => '' };
		if (this.ingest.silent) throw new TypeError('fetch failed');
		if (this.refuseStatus) return { status: this.refuseStatus, ok: false, text: async () => 'refused' };
		const e = JSON.parse(init!.body!) as NostrEvent;
		if (!core.verifyEvent(e)) return { status: 400, ok: false, text: async () => "the envelope's signature does not verify" };
		this.received.push(e);
		if (e.kind !== core.kinds.register && e.kind !== core.kinds.ballot) return json(202, { pending: e.id });
		if (this.deferMs !== null) {
			const ms = this.deferMs;
			this.deferMs = null;
			setTimeout(() => this.ingest.judge(e), ms);
			return json(202, { pending: e.id });
		}
		const ack = this.ingest.judge(e)!;
		if (this.dropResponse) {
			this.dropResponse = false;
			throw new TypeError('network error');
		}
		return json(200, ack);
	};
}

export function world(channels: Channel[] = RELAYS.map(nostr), now?: () => number) {
	const relays = new FakeRelays(channels.filter((c) => c.type === 'nostr').map((c) => c.url));
	const mirror = new FakeMirror();
	const ingest = new FakeIngest(relays, mirror, channels, now);
	const endpoint = new FakeDirect(channels.find((c) => c.type === 'direct')?.url ?? DIRECT, ingest);
	const factory: ChannelFactory = (c) => (c.type === 'nostr' ? new NostrChannel(c.url, relays) : new DirectChannel(c.url, endpoint.fetch, { pollMs: 10, publishTimeoutMs: 200, requestTimeoutMs: 100 }));
	return { relays, mirror, ingest, direct: endpoint, channels: factory };
}

/** Waits for queued microtasks and timers to run. */
export const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
