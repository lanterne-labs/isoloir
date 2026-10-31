import { afterEach, describe, expect, it } from 'vitest';
import { Session, type SessionConfig } from '../src/session.js';
import { MemoryStore } from '../src/storage.js';
import type { PassportProof, RegistrationRequest, TallyVerdict } from '../src/types.js';
import { core, MIRROR, ORIGIN, RELAYS, StubProver, tick, wasm, world } from './fakes.js';

type World = ReturnType<typeof world>;

const sessions: Session[] = [];
afterEach(() => {
	for (const s of sessions.splice(0)) s.destroy();
});

function session(w: World, opts: Partial<SessionConfig> = {}) {
	const s = new Session({
		core,
		origin: ORIGIN,
		verifierKey: w.ingest.verifier,
		registry: 1,
		poll: 7,
		mirror: MIRROR,
		fetch: w.mirror.fetch,
		channels: w.channels,
		store: new MemoryStore(),
		prover: new StubProver(),
		ackTimeoutMs: 100,
		refreshMs: 0,
		watchRelays: false,
		...opts
	});
	sessions.push(s);
	return s;
}

let uid = 0;
function passport(seen?: RegistrationRequest[]) {
	return async (req: RegistrationRequest): Promise<PassportProof> => {
		seen?.push(req);
		return { uid: `P${++uid}`, proof: { dev: true, custom_data: req.customData }, proofDate: Math.floor(Date.now() / 1000) };
	};
}

/** A registered voter with confirmed words, ready to vote. */
async function voter(w: World, opts: Partial<SessionConfig> = {}) {
	const s = session(w, opts);
	await s.init();
	const { words } = await s.register({ obtainProof: passport(), key: 'words' });
	w.ingest.checkpoint();
	await s.refresh();
	expect(s.confirmWords(words!)).toBe(true);
	return { s, words: words! };
}

describe('registration', () => {
	it('draws the registration key before the scan, then signs, posts and finds its position', async () => {
		const w = world();
		const s = session(w);
		await s.init();
		expect(s.state().phase).toBe('no-key');
		const seen: RegistrationRequest[] = [];
		await s.scanPassport(passport(seen));
		// The proof binds the registration key drawn before any voter key.
		expect(seen[0].customData).toBe(core.registrationBinding(1, seen[0].key));
		expect(seen[0].scope).toBe('isoloir/registry/1');
		expect(s.state().registration.state).toBe('scanned');
		const words = s.createKeyFromWords();
		expect(words.split(' ')).toHaveLength(12);
		expect(s.state().phase).toBe('unregistered');
		await s.submitRegistration();
		expect(s.state().registration.state).toBe('acked');
		expect(s.state().phase).toBe('joining');
		const posted = w.relays.all(core.kinds.register);
		expect(posted).toHaveLength(1);
		expect(JSON.parse(posted[0].content).key).toBe(seen[0].key);
		const receipts: unknown[] = [];
		s.on('receipt', (r) => receipts.push(r));
		w.ingest.checkpoint();
		await s.refresh();
		expect(s.state().phase).toBe('ready');
		expect(s.state().key?.position).toBe(0);
		expect(s.state().registration.state).toBe('verified');
		expect(receipts).toEqual([{ what: 'registration', checkpoint: 2, logSeq: 5, late: false }]);
	});

	it('keeps the registration through a missed ack and resends the same event', async () => {
		const w = world();
		const s = session(w);
		await s.init();
		await s.scanPassport(passport());
		s.createKeyFromWords();
		w.ingest.silent = true;
		await expect(s.submitRegistration()).rejects.toMatchObject({ code: 'no_ack' });
		expect(s.state().registration.state).toBe('failed');
		expect(s.state().phase).toBe('unregistered');
		// Every relay got the same event.
		const ids = new Set(w.relays.all(core.kinds.register).map((e) => e.id));
		expect(ids.size).toBe(1);
		w.ingest.resume();
		await s.resendRegistration();
		expect(s.state().registration.state).toBe('acked');
		w.ingest.checkpoint();
		await s.refresh();
		expect(s.state().phase).toBe('ready');
	});

	it('refuses a stale proof', async () => {
		const w = world();
		const s = session(w);
		await s.init();
		await s.scanPassport(async (req) => ({ uid: 'old', proof: { custom_data: req.customData }, proofDate: Math.floor(Date.now() / 1000) - 7200 }));
		s.createKeyFromWords();
		await expect(s.submitRegistration()).rejects.toMatchObject({ code: 'stale_proof' });
		expect(s.state().registration.stale).toBe(true);
	});

	it('refuses a mirror signed by another key', async () => {
		const w = world();
		const s = session(w, { verifierKey: wasm.dev_verifier('99'.repeat(32), ORIGIN) });
		await expect(s.init()).rejects.toMatchObject({ code: 'log_key' });
		expect(s.state().phase).toBe('error');
	});
});

describe('ballots', () => {
	it('casts, gets its ack and finds its receipt; a re-vote takes the next seq', async () => {
		const w = world();
		const prover = new StubProver();
		const { s } = await voter(w, { prover });
		await s.cast({ pick: 0 });
		expect(s.state().ballot.state).toBe('acked');
		expect(prover.calls[0].circuit).toBe('choice4_elgamal_linked_d20');
		expect(prover.calls[0].inputs.seq).toBe(0);
		w.ingest.checkpoint();
		await s.refresh();
		expect(s.state().ballot.state).toBe('verified');
		await s.cast({ pick: 1 });
		expect(prover.calls[1].inputs.seq).toBe(1);
		expect(s.state().revote.seq).toBe(1);
	});

	it('needs a confirmed backup before the first ballot', async () => {
		const w = world();
		const s = session(w);
		await s.init();
		await s.register({ obtainProof: passport(), key: 'words' });
		w.ingest.checkpoint();
		await s.refresh();
		await expect(s.cast({ pick: 0 })).rejects.toMatchObject({ code: 'backup_required' });
		expect(s.confirmWords('wrong words')).toBe(false);
	});

	it('refuses an invalid choice before proving', async () => {
		const w = world();
		const prover = new StubProver();
		const { s } = await voter(w, { prover });
		await expect(s.cast({ pick: 3 })).rejects.toMatchObject({ code: 'bad_choice' });
		await expect(s.cast({ rank: [0] })).rejects.toMatchObject({ code: 'bad_choice' });
		expect(prover.calls).toHaveLength(0);
	});

	it('moves to the next relay when the first loses the ack', async () => {
		const w = world();
		const { s } = await voter(w);
		const posted: string[] = [];
		s.subscribe((st) => st.ballot.progress && posted.push(`${st.ballot.progress.stage}:${st.ballot.progress.channel}`));
		// Drop the acks on the relay the ballot goes to first.
		const first = firstBallotRelay(s);
		w.relays.relay(first).dropAcks = true;
		await s.cast({ pick: 0 });
		expect(s.state().ballot.state).toBe('acked');
		const waited = [...new Set(posted.filter((p) => p.startsWith('waiting:')).map((p) => p.slice(8)))];
		expect(waited).toHaveLength(2);
		expect(waited[0]).toBe(first);
	});

	it('keeps a ballot no relay acknowledged and resends the same event', async () => {
		const w = world();
		const prover = new StubProver();
		const { s } = await voter(w, { prover });
		w.ingest.silent = true;
		await expect(s.cast({ pick: 2 })).rejects.toMatchObject({ code: 'no_ack' });
		expect(s.state().ballot).toMatchObject({ state: 'failed', reason: 'no_ack', kept: true });
		await expect(s.cast({ pick: 1 })).rejects.toMatchObject({ code: 'pending' });
		w.ingest.resume();
		await s.resendBallot();
		expect(s.state().ballot.state).toBe('acked');
		expect(prover.calls).toHaveLength(1);
		const ids = new Set(w.relays.all(core.kinds.ballot).map((e) => e.id));
		expect(ids.size).toBe(1);
	});

	it('resumes a kept ballot after a reload', async () => {
		const w = world();
		const store = new MemoryStore();
		const { s } = await voter(w, { store });
		w.ingest.silent = true;
		await expect(s.cast({ pick: 0 })).rejects.toMatchObject({ code: 'no_ack' });
		s.destroy();
		const again = session(w, { store });
		await again.init();
		expect(again.state().ballot).toMatchObject({ state: 'failed', reason: 'no_ack', kept: true });
		w.ingest.resume();
		await again.resendBallot();
		expect(again.state().ballot.state).toBe('acked');
	});

	it('posts a complaint when the acked body is missing from the named checkpoint', async () => {
		const w = world();
		const { s } = await voter(w);
		const complaints: unknown[] = [];
		s.on('complaint', (c) => complaints.push(c));
		await s.cast({ pick: 1 });
		const hash = s.state().ballot.hash!;
		w.ingest.withhold.add(hash);
		w.ingest.checkpoint();
		await s.refresh();
		expect(s.state().ballot.state).toBe('missing');
		expect(complaints).toHaveLength(1);
		const posted = w.relays.all(core.kinds.complaint);
		expect(posted.length).toBe(RELAYS.length);
		const c = JSON.parse(posted[0].content) as { v: number; ack: { content: string; pubkey: string }; body: unknown };
		expect(c.v).toBe(1);
		expect(c.ack.pubkey).toBe(w.ingest.pubkey);
		expect(JSON.parse(c.ack.content).hash).toBe(hash);
		expect(core.bodyHash(core.canonical(c.body))).toBe(hash);
		expect(core.verifyEvent(c.ack as never)).toBe(true);
	});

	it('refuses a second ballot in a poll without re-votes', async () => {
		const w = world();
		const { s } = await voter(w, { poll: 9 });
		await s.cast({ pick: 0 });
		w.ingest.checkpoint();
		await s.refresh();
		await expect(s.cast({ pick: 1 })).rejects.toMatchObject({ code: 'revote_off' });
	});
});

describe('delta polls', () => {
	it('corrects the previous ballot from the device record, then from the secret alone', async () => {
		const w = world();
		const prover = new StubProver();
		const { s, words } = await voter(w, { poll: 8, prover });
		await s.cast({ pick: 0 });
		expect(prover.calls[0].inputs.i).toBe(0);
		// The correction waits for the previous ballot in the tree.
		await expect(s.cast({ pick: 1 })).rejects.toMatchObject({ code: 'previous_pending' });
		w.ingest.checkpoint();
		await s.refresh();
		expect(s.state().ballot.state).toBe('verified');
		await s.cast({ pick: 1 });
		expect(prover.calls[1].inputs.i).toBe(1);
		expect(prover.calls[1].inputs.old_pick).toBe(0);
		expect(s.state().revote.previousChoice).toEqual({ pick: 1 });
		w.ingest.checkpoint();

		// Another device, the same words: the chain is found in the ballot tree.
		const prover2 = new StubProver();
		const other = session(w, { poll: 8, prover: prover2 });
		await other.init();
		await other.restoreFromWords(words);
		await other.cast({ pick: 2 });
		expect(prover2.calls[0].inputs.i).toBe(2);
		expect(prover2.calls[0].inputs.old_pick).toBe(1);
		w.ingest.checkpoint();
		const t = JSON.parse(w.ingest.tally(8)) as { values: number[]; counted: number };
		// Three ballots, one voter: the sum of the corrections is the last choice.
		expect(t.counted).toBe(3);
		expect(t.values).toEqual([0, 0, 1, 0]);
	});
});

describe('keys', () => {
	it('restores from the words with the seq of the log', async () => {
		const w = world();
		const { s, words } = await voter(w);
		await s.cast({ pick: 0 });
		w.ingest.checkpoint();
		const prover = new StubProver();
		const other = session(w, { prover });
		await other.init();
		await expect(other.restoreFromWords('not twelve words')).rejects.toMatchObject({ code: 'bad_words' });
		await other.restoreFromWords(words);
		expect(other.state().phase).toBe('ready');
		expect(other.state().key?.position).toBe(0);
		await other.cast({ pick: 1 });
		expect(prover.calls[0].inputs.seq).toBe(1);
	});

	it('refuses words that never registered', async () => {
		const w = world();
		const s = session(w);
		await s.init();
		await expect(s.restoreFromWords(core.newWords('en'))).rejects.toMatchObject({ code: 'not_registered' });
		expect(s.state().phase).toBe('no-key');
	});

	it('links a device after the codes match', async () => {
		const w = world();
		const { s } = await voter(w);
		await s.cast({ pick: 0 });
		const b = session(w);
		await b.init();
		const offers: string[] = [];
		b.on('link-offer', (o) => offers.push(o.code));
		const rx = b.receiveLink();
		const code = await s.sendKeyTo(rx.publicKey);
		await tick(10);
		expect(offers).toEqual([code]);
		expect(rx.offer()).toBe(code);
		rx.answer(true);
		await rx.done;
		expect(b.state().phase).toBe('ready');
		expect(b.state().key?.leaf).toBe(s.state().key?.leaf);
		expect(b.state().key?.backedUp).toBe(true);
		expect(b.state().revote.seq).toBe(0);
	});

	it('derives the key from a passkey PRF and finds it again', async () => {
		const w = world();
		const prf = new Uint8Array(32).fill(7);
		let inputSeen = '';
		const credentials = {
			async create(o: CredentialCreationOptions) {
				inputSeen = new TextDecoder().decode((o.publicKey!.extensions as { prf: { eval: { first: Uint8Array } } }).prf.eval.first);
				return { rawId: new Uint8Array([1, 2, 3]).buffer, getClientExtensionResults: () => ({ prf: { enabled: true, results: { first: prf.buffer } } }) } as unknown as Credential;
			},
			async get() {
				return { rawId: new Uint8Array([1, 2, 3]).buffer, getClientExtensionResults: () => ({ prf: { results: { first: prf.buffer } } }) } as unknown as Credential;
			}
		};
		const s = session(w, { passkey: { credentials, rpId: 'vote.test' } });
		await s.init();
		await s.register({ obtainProof: passport(), key: 'passkey' });
		expect(inputSeen).toBe(`isoloir/1/${ORIGIN}/1`);
		w.ingest.checkpoint();
		await s.refresh();
		expect(s.state().key).toMatchObject({ source: 'passkey', backedUp: true, position: 0 });
		const other = session(w, { passkey: { credentials, rpId: 'vote.test' } });
		await other.init();
		await other.restoreWithPasskey();
		expect(other.state().key?.leaf).toBe(s.state().key?.leaf);
	});
});

describe('results', () => {
	it('verifies the latest tally and maps it to the poll', async () => {
		const w = world();
		const a = await voter(w);
		const b = await voter(w);
		await a.s.cast({ pick: 0 });
		await b.s.cast({ pick: 2 });
		w.ingest.checkpoint();
		// a changes its mind: only its last ballot counts.
		await a.s.refresh();
		await a.s.cast({ pick: 1 });
		w.ingest.checkpoint();
		w.ingest.tally(7);
		const got: TallyVerdict[] = [];
		a.s.on('tally', (t) => got.push(t));
		await a.s.refresh();
		const t = a.s.state().tally!;
		expect(t.ok).toBe(true);
		expect(t.checked).toBe('shares');
		expect(t.results).toMatchObject({ type: 'choice', counted: 2, blank: 1, none: 0 });
		expect(t.results.type === 'choice' && t.results.slots.map((x) => x.count)).toEqual([0, 1, 1]);
		expect(got).toHaveLength(1);

		// A tally whose values were changed does not verify.
		const file = JSON.parse(w.mirror.files.get('polls/7/tallies/latest.json')!) as { seq: number; body: string };
		w.mirror.put('polls/7/tallies/latest.json', { ...file, body: file.body.replace('"values":[0,1,1,0]', '"values":[1,0,1,0]') });
		const v = await a.s.refreshTally();
		expect(v?.ok).toBe(false);
	});
});

function firstBallotRelay(s: Session): string {
	// The relay a ballot goes to first: the second of the key's ranking.
	const stored = (s as unknown as { key(): { secret: string } }).key();
	return core.relayRanking(stored.secret, RELAYS)[1];
}
