import { describe, expect, it } from 'vitest';
import type { RegistrationRequest, TallyVerdict } from '../src/types.js';
import { core, ORIGIN, RELAYS, StubProver, tick, wasm, world } from './fakes.js';
import { answers, passport, session, stored, voter } from './helpers.js';

describe('registration', () => {
	it('draws the registration key before the scan, needs the backup, then signs, posts and finds its position in the entries', async () => {
		const w = world();
		const s = session(w);
		await s.init();
		expect(s.state().phase).toBe('no-key');
		expect(s.state().storage).toBe('memory');
		const seen: RegistrationRequest[] = [];
		await s.scanPassport(passport(seen));
		// The proof binds the registration key drawn before any voter key.
		expect(seen[0].customData).toBe(core.registrationBinding(1, seen[0].key));
		expect(seen[0].scope).toBe('isoloir/registry/1');
		expect(s.state().registration.state).toBe('scanned');
		const words = s.createKeyFromWords();
		expect(words.split(' ')).toHaveLength(12);
		// No registration before a backup.
		await expect(s.submitRegistration()).rejects.toMatchObject({ code: 'backup_required' });
		expect(w.relays.all(core.kinds.register)).toHaveLength(0);
		const asked = s.wordChallenge();
		expect(asked).toHaveLength(3);
		expect(s.confirmWords(asked, await answers({ words, positions: asked })).ok).toBe(true);
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
		// The position came from the entries, not from the leaf's positions shard.
		expect(w.mirror.reads.some((p) => p.includes('/positions/'))).toBe(false);
		expect(w.mirror.reads).toContain('entries/2.json');
	});

	it('a backup declined in so many words lets the registration go, and the words stay readable', async () => {
		const w = world();
		const s = session(w);
		await s.init();
		await s.scanPassport(passport());
		const words = s.createKeyFromWords();
		await expect(s.submitRegistration()).rejects.toMatchObject({ code: 'backup_required' });
		s.declineBackup();
		expect(s.state().key?.backedUp).toBe(true);
		await s.submitRegistration();
		expect(s.state().registration.state).toBe('acked');
		expect(w.relays.all(core.kinds.register)).toHaveLength(1);
		expect(s.words()).toBe(words);
	});

	it('register() asks for the words back and refuses a wrong answer', async () => {
		const w = world();
		const s = session(w);
		await s.init();
		await expect(s.register({ obtainProof: passport(), key: 'words' })).rejects.toMatchObject({ code: 'backup_required' });
		const t = session(w);
		await t.init();
		await expect(t.register({ obtainProof: passport(), key: 'words', confirm: async ({ positions }) => positions.map(() => 'zoo') })).rejects.toMatchObject({ code: 'bad_words' });
		expect(w.relays.all(core.kinds.register)).toHaveLength(0);
	});

	it('keeps the registration through a missed ack and resends its body in a fresh envelope', async () => {
		const w = world();
		const s = session(w);
		await s.init();
		await s.scanPassport(passport());
		const words = s.createKeyFromWords();
		s.confirmWords(words);
		w.ingest.silent = true;
		await expect(s.submitRegistration()).rejects.toMatchObject({ code: 'no_ack' });
		expect(s.state().registration.state).toBe('failed');
		expect(s.state().phase).toBe('unregistered');
		// One body, a fresh envelope on each relay.
		const sent = w.relays.all(core.kinds.register);
		expect(new Set(sent.map((e) => e.content)).size).toBe(1);
		expect(new Set(sent.map((e) => e.id)).size).toBe(RELAYS.length);
		w.ingest.resume();
		await s.resendRegistration();
		expect(s.state().registration.state).toBe('acked');
		w.ingest.checkpoint();
		await s.refresh();
		expect(s.state().phase).toBe('ready');
	});

	it('replaces a stale kept registration with a fresh scan of the same registration key', async () => {
		const w = world();
		let shift = 0;
		const now = () => Date.now() + shift;
		const s = session(w, { now });
		await s.init();
		const seen: RegistrationRequest[] = [];
		await s.scanPassport(passport(seen, 'STALE', () => Math.floor(now() / 1000)));
		s.confirmWords(s.createKeyFromWords());
		w.ingest.silent = true;
		await expect(s.submitRegistration()).rejects.toMatchObject({ code: 'no_ack' });
		// The relays held the first body; the ingest takes it when it comes back.
		w.ingest.resume();
		shift = 2 * 3600_000;
		await expect(s.resendRegistration()).rejects.toMatchObject({ code: 'stale_proof' });
		await s.scanPassport(passport(seen, 'STALE', () => Math.floor(now() / 1000)));
		expect(seen[1].key).toBe(seen[0].key);
		await s.resendRegistration();
		// The new body met the first one's uid: the resend path, the entries say where.
		expect(s.state().registration.state).toBe('acked');
		const bodies = new Set(w.relays.all(core.kinds.register).map((e) => e.content));
		expect(bodies.size).toBe(2);
		w.ingest.checkpoint();
		await s.refresh();
		expect(s.state().phase).toBe('ready');
		expect(s.state().key?.position).toBe(0);
	});

	it('refuses a stale proof', async () => {
		const w = world();
		const s = session(w);
		await s.init();
		await s.scanPassport(async (req) => ({ uid: 'old', proof: { custom_data: req.customData }, proofDate: Math.floor(Date.now() / 1000) - 7200 }));
		s.confirmWords(s.createKeyFromWords());
		await expect(s.submitRegistration()).rejects.toMatchObject({ code: 'stale_proof' });
		expect(s.state().registration.stale).toBe(true);
	});
});

describe('the mirror', () => {
	it('refuses a mirror signed by another key', async () => {
		const w = world();
		const s = session(w, { verifierKey: wasm.dev_verifier('99'.repeat(32), ORIGIN) });
		await expect(s.init()).rejects.toMatchObject({ code: 'log_key' });
		expect(s.state().phase).toBe('error');
	});

	it('uses no setup the log does not prove', async () => {
		// Another ingest key in the ledger file, with the real proof.
		const w = world();
		const file = JSON.parse(w.mirror.files.get('setup/ledger.json')!) as { setups: { body: string }[] };
		const forged = file.setups[0].body.replace(w.ingest.pubkey, core.regPubkey('77'.repeat(32)));
		w.mirror.put('setup/ledger.json', { setups: [{ ...file.setups[0], body: forged }] });
		await expect(session(w).init()).rejects.toMatchObject({ code: 'unproven' });
		// Another poll key.
		const w2 = world();
		const pf = JSON.parse(w2.mirror.files.get('polls/7.json')!) as { setups: { body: string }[] };
		const other = (JSON.parse(wasm.dev_authority('55'.repeat(32))) as { pk: string }).pk;
		w2.mirror.put('polls/7.json', { setups: [{ ...pf.setups[0], body: pf.setups[0].body.replace(w2.ingest.authority.pk, other) }] });
		await expect(session(w2).init()).rejects.toMatchObject({ code: 'unproven' });
		// No proof at all.
		const w3 = world();
		const rf = JSON.parse(w3.mirror.files.get('registries/1.json')!) as { setups: { seq: number; body: string }[] };
		w3.mirror.put('registries/1.json', { setups: [{ seq: rf.setups[0].seq, body: rf.setups[0].body }] });
		await expect(session(w3).init()).rejects.toMatchObject({ code: 'unproven' });
	});

	it('takes the last version of a setup', async () => {
		const w = world();
		const v2 = core.canonical({ ...w.ingest.registry, version: 2, name: 'Test v2' });
		const seq = w.ingest.seq;
		w.ingest.checkpoint([{ kind: 'registry', body: v2 }]);
		w.ingest.writeSetup('registries/1.json', seq, v2, w.ingest.index);
		const s = session(w);
		await s.init();
		expect(s.state().registry?.name).toBe('Test v2');
	});

	it('gives up on a mirror file that hangs', async () => {
		const w = world();
		const { s } = await voter(w, { mirrorTimeoutMs: 50 });
		w.mirror.hang.add('checkpoint.txt');
		const t0 = Date.now();
		await s.refresh();
		expect(Date.now() - t0).toBeLessThan(2000);
		expect(s.state().phase).toBe('ready');
	});
});

describe('ballots', () => {
	it('casts, gets its ack and finds its receipt; a re-vote takes the next seq from the device', async () => {
		const w = world();
		const prover = new StubProver();
		const { s } = await voter(w, { prover });
		await s.cast({ pick: 0 });
		expect(s.state().ballot.state).toBe('acked');
		expect(prover.calls[0].circuit).toBe('choice4_single_linked_d20');
		expect(prover.calls[0].inputs.seq).toBe(0);
		w.ingest.checkpoint();
		await s.refresh();
		expect(s.state().ballot.state).toBe('verified');
		const before = w.mirror.reads.filter((p) => p.includes('/pseudonyms/')).length;
		await s.cast({ pick: 1 });
		expect(prover.calls[1].inputs.seq).toBe(1);
		expect(s.state().revote.seq).toBe(1);
		// The device's record, not the pseudonym shard.
		expect(w.mirror.reads.filter((p) => p.includes('/pseudonyms/')).length).toBe(before);
	});

	it('needs a confirmed backup before the first ballot', async () => {
		const w = world();
		const { s } = await voter(w);
		const k = stored(s);
		k.backups.words = false;
		(s as unknown as { saveKey(k: unknown): void }).saveKey(k);
		await expect(s.cast({ pick: 0 })).rejects.toMatchObject({ code: 'backup_required' });
		const wrong = s.confirmWords([2, 5], ['zoo', 'zoo']);
		expect(wrong.ok).toBe(false);
		expect(wrong.wrong.length).toBeGreaterThan(0);
	});

	it('refuses an invalid choice before proving', async () => {
		const w = world();
		const prover = new StubProver();
		const { s } = await voter(w, { prover });
		await expect(s.cast({ pick: 3 })).rejects.toMatchObject({ code: 'bad_choice' });
		await expect(s.cast({ rank: [0] })).rejects.toMatchObject({ code: 'bad_choice' });
		expect(prover.calls).toHaveLength(0);
	});

	it('refuses to draft against a checkpoint older than 30 minutes', async () => {
		const w = world(undefined, () => Math.floor(Date.now() / 1000) - 3600);
		const prover = new StubProver();
		const { s } = await voter(w, { prover });
		expect(s.state().checkpointAge).toBeGreaterThan(3500);
		await expect(s.cast({ pick: 0 })).rejects.toMatchObject({ code: 'stale_mirror' });
		expect(s.state().ballot).toMatchObject({ state: 'failed', reason: 'stale_mirror' });
		expect(prover.calls).toHaveLength(0);
	});

	it('moves to the next relay when the first loses the ack, never to the registration relay', async () => {
		const w = world();
		const { s } = await voter(w);
		const posted: string[] = [];
		s.subscribe((st) => st.ballot.progress && posted.push(`${st.ballot.progress.stage}:${st.ballot.progress.channel}`));
		const [r0, r1, r2] = core.relayRanking(stored(s).secret, RELAYS);
		w.relays.relay(r1).dropAcks = true;
		await s.cast({ pick: 0 });
		expect(s.state().ballot.state).toBe('acked');
		const waited = [...new Set(posted.filter((p) => p.startsWith('waiting:')).map((p) => p.slice(8)))];
		expect(waited).toEqual([r1, r2]);
		// The other two down: no fallback to the registration relay.
		w.ingest.checkpoint();
		await s.refresh();
		w.relays.relay(r1).down = true;
		w.relays.relay(r2).down = true;
		await expect(s.cast({ pick: 1 })).rejects.toMatchObject({ code: 'no_relay' });
		expect(w.relays.relay(r0).seen.filter((e) => e.kind === core.kinds.ballot)).toHaveLength(0);
	});

	it('watches checkpoints on a relay that is neither the registration nor the ballot relay', async () => {
		const w = world();
		const { s } = await voter(w);
		const [, , r2] = core.relayRanking(stored(s).secret, RELAYS);
		const w2 = session(w, { store: (s as unknown as { store: never }).store, watchRelays: true });
		await w2.init();
		const watches = w.relays.subscriptions.filter((x) => x.filter.kinds?.includes(core.kinds.checkpoint) && x.filter.authors);
		expect(watches.map((x) => x.url)).toEqual([r2]);
	});

	it('keeps a ballot no relay acknowledged and resends its body', async () => {
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
		expect(new Set(w.relays.all(core.kinds.ballot).map((e) => e.content)).size).toBe(1);
	});

	it('wraps a resent body in a fresh envelope the ingest still reads', async () => {
		const w = world();
		let shift = 0;
		const { s } = await voter(w, { now: () => Date.now() + shift });
		w.ingest.silent = true;
		await expect(s.cast({ pick: 0 })).rejects.toMatchObject({ code: 'no_ack' });
		const first = w.relays.all(core.kinds.ballot);
		// Minutes later the ingest reads from its cursor − 120 s: the old envelopes are never seen.
		shift = 5 * 60_000;
		w.ingest.minCreatedAt = Math.max(...first.map((e) => e.created_at)) + 1;
		w.ingest.resume();
		await s.resendBallot();
		expect(s.state().ballot.state).toBe('acked');
		const acked = stored(s).polls['7'].ballot!;
		expect(first.map((e) => e.id)).not.toContain(acked.event.id);
		expect(JSON.parse(acked.ack!.event.content).of).toBe(acked.event.id);
	});

	it('resumes a kept ballot after a reload', async () => {
		const w = world();
		const { s } = await voter(w);
		const store = (s as unknown as { store: never }).store;
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

	it('reads the entries of every checkpoint since the post, whatever the ack named', async () => {
		const w = world();
		const { s } = await voter(w);
		w.ingest.checkpoint();
		w.ingest.checkpoint();
		await s.refresh();
		const from = w.ingest.index;
		await s.cast({ pick: 0 });
		w.ingest.checkpoint();
		w.ingest.checkpoint();
		const reads0 = w.mirror.reads.length;
		await s.refresh();
		const read = w.mirror.reads.slice(reads0).filter((p) => p.startsWith('entries/'));
		expect(read).toEqual([`entries/${from + 1}.json`, `entries/${from + 2}.json`].slice(0, read.length));
		expect(read[0]).toBe(`entries/${from + 1}.json`);
		expect(s.state().ballot.state).toBe('verified');
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
		await other.refresh();
		// Delta: counted counts corrections, so withdrawals are unknown.
		expect(other.state().tally?.results).toMatchObject({ ballots: 'corrections', none: null });
	});

	it('is not stuck on duplicate after a discarded ballot that was logged', async () => {
		// An ingest of the earlier version, on relays that store (legacy kinds): it reads the discarded ballot later.
		const w = world(undefined, undefined, { version: 'old' });
		const prover = new StubProver();
		const { s } = await voter(w, { poll: 8, prover });
		await s.cast({ pick: 0 });
		w.ingest.checkpoint();
		await s.refresh();
		w.ingest.silent = true;
		await expect(s.cast({ pick: 1 })).rejects.toMatchObject({ code: 'no_ack' });
		s.discardKeptBallot();
		// The ingest took the discarded ballot after all.
		w.ingest.resume();
		w.ingest.checkpoint();
		await s.refresh();
		await s.cast({ pick: 2 });
		expect(s.state().ballot.state).toBe('acked');
		// Drafted as ballot 1 (the device's record), refused as a duplicate, found again in the tree.
		expect(prover.calls.map((c) => c.inputs.i)).toEqual([0, 1, 1, 2]);
		const last = prover.calls[prover.calls.length - 1].inputs;
		expect(last.i).toBe(2);
		expect(last.old_pick).toBe(1);
	});
});

describe('keys', () => {
	it('restores from the words, finds its leaf in the tree and learns the seq from stale_seq', async () => {
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
		// No pseudonym file: seq 0 is refused as stale, seq 1 goes.
		expect(prover.calls.map((c) => c.inputs.seq)).toEqual([0, 1]);
		expect(stored(other).polls['7'].seq).toBe(1);
		expect(w.mirror.reads.some((p) => p.includes('/pseudonyms/') || p.includes('/positions/'))).toBe(false);
	});

	it('reads French words without accents and names the wrong ones', async () => {
		const w = world();
		const { s, words } = await voter(w, { wordsLang: 'fr' });
		const bare = words.normalize('NFD').replace(/[̀-ͯ]/g, '').toUpperCase();
		const other = session(w, { wordsLang: 'fr' });
		await other.init();
		const list = bare.split(' ');
		list[1] = 'xyzzy';
		list[9] = 'plugh';
		await expect(other.restoreFromWords(list.join(' '))).rejects.toMatchObject({ code: 'bad_words', data: { unknown: [2, 10] } });
		await other.restoreFromWords(bare);
		expect(other.state().key?.leaf).toBe(s.state().key?.leaf);
		expect(other.confirmWords([1, 12], [bare.split(' ')[0], 'xyzzy'])).toEqual({ ok: false, wrong: [12] });
	});

	it('refuses words that never registered', async () => {
		const w = world();
		const s = session(w);
		await s.init();
		await expect(s.restoreFromWords(core.newWords('en'))).rejects.toMatchObject({ code: 'not_registered' });
		expect(s.state().phase).toBe('no-key');
	});

	it('links a device after the codes match, and counts it only once the receiver confirms', async () => {
		const w = world();
		const { s } = await voter(w);
		await s.cast({ pick: 0 });
		await expect(s.sendKeyTo('not a key')).rejects.toMatchObject({ code: 'bad_link_key' });
		await expect(s.sendKeyTo('04' + '11'.repeat(32))).rejects.toMatchObject({ code: 'bad_link_key' });
		const b = session(w);
		await b.init();
		const offers: string[] = [];
		b.on('link-offer', (o) => offers.push(o.code));
		const rx = b.receiveLink();
		const sender = await s.sendKeyTo(rx.publicKey);
		await tick(10);
		expect(offers).toEqual([sender.code]);
		expect(rx.offer()).toBe(sender.code);
		expect(stored(s).backups.linked).toBe(0);
		rx.answer(true);
		await rx.done;
		await expect(sender.confirmed).resolves.toBe(true);
		expect(stored(s).backups.linked).toBe(1);
		expect(b.state().phase).toBe('ready');
		expect(b.state().key?.leaf).toBe(s.state().key?.leaf);
		expect(b.state().key?.backedUp).toBe(true);
		expect(b.state().revote.seq).toBe(0);
	});

	it('does not count a link the receiver refused', async () => {
		const w = world();
		const { s } = await voter(w);
		const b = session(w);
		await b.init();
		const rx = b.receiveLink();
		const sender = await s.sendKeyTo(rx.publicKey);
		await tick(10);
		rx.answer(false);
		sender.stop();
		await expect(sender.confirmed).resolves.toBe(false);
		expect(stored(s).backups.linked).toBe(0);
	});

	const authData = (bs: boolean) => {
		const a = new Uint8Array(37);
		a[32] = 0x01 | 0x04 | 0x08 | (bs ? 0x10 : 0);
		return a.buffer;
	};
	const passkeys = (bs: boolean) => {
		const prf = new Uint8Array(32).fill(7);
		const seen: { input: string; rpName?: string; created: number } = { input: '', created: 0 };
		const credentials = {
			async create(o: CredentialCreationOptions) {
				seen.created++;
				seen.input = new TextDecoder().decode((o.publicKey!.extensions as { prf: { eval: { first: Uint8Array } } }).prf.eval.first);
				seen.rpName = o.publicKey!.rp.name;
				return {
					rawId: new Uint8Array([1, 2, 3]).buffer,
					response: { getAuthenticatorData: () => authData(bs) },
					getClientExtensionResults: () => ({ prf: { enabled: true, results: { first: prf.buffer } } })
				} as unknown as Credential;
			},
			async get() {
				return { rawId: new Uint8Array([1, 2, 3]).buffer, response: { authenticatorData: authData(bs) }, getClientExtensionResults: () => ({ prf: { results: { first: prf.buffer } } }) } as unknown as Credential;
			}
		};
		return { credentials, seen };
	};

	it('derives the key from a synced passkey PRF and finds it again', async () => {
		const w = world();
		const { credentials, seen } = passkeys(true);
		const s = session(w, { passkey: { credentials, rpId: 'vote.test' } });
		await s.init();
		await s.register({ obtainProof: passport(), key: 'passkey' });
		expect(seen.input).toBe(`isoloir/1/${ORIGIN}/1`);
		expect(seen.rpName).toBe('Test');
		w.ingest.checkpoint();
		await s.refresh();
		expect(s.state().key).toMatchObject({ source: 'passkey', backedUp: true, position: 0 });
		const other = session(w, { passkey: { credentials, rpId: 'vote.test' } });
		await other.init();
		await other.restoreWithPasskey();
		expect(other.state().key?.leaf).toBe(s.state().key?.leaf);
	});

	it('does not take a passkey that is not synced, nor create one without PRF', async () => {
		const w = world();
		const { credentials } = passkeys(false);
		const s = session(w, { passkey: { credentials, rpId: 'vote.test' } });
		await s.init();
		await expect(s.createKeyWithPasskey()).rejects.toMatchObject({ code: 'passkey_not_backed_up' });
		expect(s.state().key).toBeNull();
		const p = passkeys(true);
		const t = session(w, { passkey: { credentials: p.credentials, rpId: 'vote.test', prfCapability: async () => false } });
		await t.init();
		await expect(t.createKeyWithPasskey()).rejects.toMatchObject({ code: 'passkey_noprf' });
		expect(p.seen.created).toBe(0);
	});
});

describe('results', () => {
	it('verifies the latest tally, keeps it, and sets aside one that does not verify', async () => {
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
		const good = w.ingest.tally(7);
		const got: TallyVerdict[] = [];
		a.s.on('tally', (t) => got.push(t));
		await a.s.refresh();
		const t = a.s.state().tally!;
		expect(t.ok).toBe(true);
		expect(t.checked).toBe('shares');
		expect(t.results).toMatchObject({ type: 'choice', counted: 2, blank: 1, none: 0, ballots: 'voters' });
		expect(t.results.type === 'choice' && t.results.slots.map((x) => x.count)).toEqual([0, 1, 1]);
		expect(got).toHaveLength(1);

		// A file changed on the mirror: its proof fails; the verified tally stays.
		const file = JSON.parse(w.mirror.files.get('polls/7/tallies/latest.json')!) as { body: string };
		w.mirror.put('polls/7/tallies/latest.json', { ...file, body: file.body.replace('"values":[0,1,1,0]', '"values":[1,0,1,0]') });
		await a.s.refreshTally();
		expect(a.s.state().tally?.tally.values).toEqual([0, 1, 1, 0]);
		expect(a.s.state().tallyUnverified).toMatchObject({ verdict: null });

		// A forged tally logged as such: proven, but its shares do not verify.
		w.ingest.logTally(7, good.replace('"values":[0,1,1,0]', '"values":[1,0,1,0]'));
		const v = await a.s.refreshTally();
		expect(v?.ok).toBe(false);
		expect(a.s.state().tally?.tally.values).toEqual([0, 1, 1, 0]);
		expect(a.s.state().tallyUnverified?.verdict?.ok).toBe(false);
	});
});
