// The transport-only redesign (SPEC fd7a810 and later): ephemeral kinds
// and the transition from an ingest of the earlier version, the order of
// the channels, the proof of work, the seq a device keeps, the re-vote
// rate, and notes whose mirror commit lags behind.

import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { IngestChannel } from '../src/channel.js';
import { covered } from '../src/mirror.js';
import { powTags, workKey, WorkPool } from '../src/pow.js';
import type { Channel, NostrEvent } from '../src/types.js';
import { core, direct, DIRECT, nostr, ORIGIN, RELAYS, StubProver, TAG, tick, wasm, world } from './fakes.js';
import { answers, passport, session, stored, voter } from './helpers.js';

const POW = 15;

function zeroBits(h: Buffer): number {
	let n = 0;
	for (const b of h) {
		if (b === 0) n += 8;
		else return n + Math.clz32(b) - 24;
	}
	return n;
}

const powOf = (e: NostrEvent) => e.tags.find((t) => t[0] === 'pow');

describe('proof of work', () => {
	it("mines a nonce whose SHA-256 is the spec's, bound to the key, the time and the origin", async () => {
		const k = await workKey(core, ORIGIN, POW, 1_761_900_000);
		expect(k.bits).toBe(POW);
		const h = createHash('sha256').update(`isoloir/1/pow\n${ORIGIN}\n${k.pubkey}\n${k.t}\n${k.nonce}`).digest();
		expect(zeroBits(h)).toBeGreaterThanOrEqual(POW);
		expect(core.powCheck(ORIGIN, k.pubkey, k.t!, k.nonce!, POW)).toBe(true);
		expect(core.powCheck('other.example/isoloir', k.pubkey, k.t!, k.nonce!, POW)).toBe(false);
		expect(core.powCheck(ORIGIN, core.regPubkey(core.newRegSecret()), k.t!, k.nonce!, POW)).toBe(false);
		expect(powTags(k)).toEqual([['pow', String(k.t), k.nonce]]);
	});

	it('difficulty 0: no work, no tag, nothing to wait for', async () => {
		const k = await workKey(core, ORIGIN, 0, 1_761_900_000);
		expect(k.nonce).toBeUndefined();
		expect(powTags(k)).toEqual([]);
		const w = world();
		const { s } = await voter(w);
		await s.startWork();
		expect(s.state().pow).toEqual({ bits: 0, state: 'none' });
		await s.cast({ pick: 0 });
		const posted = w.relays.all([core.kinds.register, core.kinds.ballot]);
		expect(posted).toHaveLength(2);
		expect(posted.every((e) => !powOf(e))).toBe(true);
	});

	it(`a ledger with pow ${POW}: the work is mined ahead, every envelope carries it under its own key`, async () => {
		const w = world(undefined, undefined, { pow: POW });
		const s = session(w);
		await s.init();
		expect(s.state().pow).toEqual({ bits: POW, state: 'none' });
		// A ledger setting the earlier ingest cannot read: the ephemeral kinds.
		expect(s.state().kinds).toBe('ephemeral');
		const ready = s.startWork();
		expect(s.state().pow.state).toBe('mining');
		await ready;
		expect(s.state().pow.state).toBe('ready');
		await s.register({ obtainProof: passport(), key: 'words', confirm: answers });
		w.ingest.checkpoint();
		await s.refresh();
		expect(s.state().phase).toBe('ready');
		await s.cast({ pick: 1 });
		expect(s.state().ballot.state).toBe('acked');
		expect(w.ingest.dropped).toHaveLength(0);
		const posted = w.relays.all([core.kinds.register, core.kinds.ballot]).sort((a, b) => a.kind - b.kind);
		expect(posted.map((e) => e.kind)).toEqual([core.kinds.register, core.kinds.ballot]);
		for (const e of posted) {
			const [, t, nonce] = powOf(e)!;
			expect(core.powCheck(ORIGIN, e.pubkey, Number(t), nonce, POW)).toBe(true);
		}
		expect(posted[0].pubkey).not.toBe(posted[1].pubkey);
	});

	it('an envelope without its work is dropped unanswered', async () => {
		const w = world(undefined, undefined, { pow: POW });
		const bare = core.signEvent('', Math.floor(Date.now() / 1000), core.kinds.ballot, [['t', TAG]], '{"v":1}');
		await w.relays.publish(RELAYS[0], bare);
		const k = await workKey(core, ORIGIN, POW - 4, Math.floor(Date.now() / 1000));
		const weak = core.signEvent(k.secret, Math.floor(Date.now() / 1000), core.kinds.ballot, [['t', TAG], ...powTags(k)], '{"v":1}');
		await w.relays.publish(RELAYS[0], weak);
		await tick();
		expect(w.ingest.dropped.map((e) => e.id)).toEqual(expect.arrayContaining([bare.id]));
		expect(w.relays.all([core.kinds.ack, core.kinds.legacy.ack]).filter((a) => a.tags.some((t) => t[1] === bare.id))).toHaveLength(0);
	});

	it('resends a body in fresh envelopes, each under a fresh key with its work', async () => {
		const w = world(undefined, undefined, { pow: POW });
		const { s } = await voter(w);
		w.ingest.silent = true;
		await expect(s.cast({ pick: 0 })).rejects.toMatchObject({ code: 'no_ack' });
		w.ingest.silent = false;
		await s.resendBallot();
		expect(s.state().ballot.state).toBe('acked');
		const ballots = w.relays.all(core.kinds.ballot);
		expect(ballots.length).toBeGreaterThan(1);
		expect(new Set(ballots.map((e) => e.id)).size).toBe(ballots.length);
		expect(new Set(ballots.map((e) => e.pubkey)).size).toBe(ballots.length);
		expect(new Set(ballots.map((e) => e.content)).size).toBe(1);
		expect(w.ingest.dropped).toHaveLength(0);
	});

	it('the pool never gives two envelopes the same key, and drops work too old for the ingest', async () => {
		let now = 1_761_900_000;
		const pool = new WorkPool(core, ORIGIN, () => 8, () => now);
		const early = pool.start();
		const [a, b] = await Promise.all([pool.take(), pool.take()]);
		expect(a.pubkey).not.toBe(b.pubkey);
		expect((await early).pubkey).toBe(a.pubkey);
		await pool.start();
		// The spare's t falls out of the ingest's window (2 h, less the margin): a fresh one is mined.
		now += 7200;
		const c = await pool.take();
		expect(c.t).toBe(now);
	});
});

describe('kinds during the transition', () => {
	it('an ingest of the earlier version: legacy kinds, its acks in 7102, and it reads nothing else', async () => {
		const w = world(undefined, undefined, { version: 'old' });
		const { s } = await voter(w);
		expect(s.state().kinds).toBe('legacy');
		await s.cast({ pick: 0 });
		expect(s.state().ballot.state).toBe('acked');
		expect(w.relays.all(core.kinds.ballot)).toHaveLength(0);
		expect(w.relays.all(core.kinds.legacy.ballot)).toHaveLength(1);
		expect(w.relays.all(core.kinds.legacy.ack).length).toBeGreaterThan(0);
		// Forced ephemeral, the earlier ingest never answers.
		const t = session(w, { kinds: 'ephemeral' });
		await t.init();
		await expect(t.register({ obtainProof: passport(), key: 'words', confirm: answers })).rejects.toMatchObject({ code: 'no_ack' });
	});

	it('a new ingest without settings or mirror: legacy until its ephemeral checkpoint event shows, then ephemeral', async () => {
		const w = world(undefined, undefined, { noMirror: true });
		const s = session(w, { watchRelays: true });
		await s.init();
		expect(s.state().kinds).toBe('legacy');
		await s.register({ obtainProof: passport(), key: 'words', confirm: answers });
		// Answered in the range of the envelope.
		expect(w.relays.all(core.kinds.legacy.register)).toHaveLength(1);
		w.ingest.checkpoint();
		await tick(10);
		await s.refresh();
		expect(s.state().kinds).toBe('ephemeral');
		await s.cast({ pick: 0 });
		expect(s.state().ballot.state).toBe('acked');
		expect(w.relays.all(core.kinds.ballot)).toHaveLength(1);
	});

	it("a new ingest's note names the checkpoint its commit covers: ephemeral at once", async () => {
		const w = world();
		const s = session(w);
		await s.init();
		expect(s.state().checkpoint?.mirror_index).toBe(1);
		expect(s.state().kinds).toBe('ephemeral');
	});
});

describe('channels', () => {
	it('moves from relays that never answer to the direct endpoint, each in a fresh envelope', async () => {
		const channels: Channel[] = [direct(DIRECT), nostr(RELAYS[0]), nostr(RELAYS[1])];
		const w = world(channels);
		for (const r of RELAYS.slice(0, 2)) w.relays.relay(r).dropAcks = true;
		const s = session(w);
		await s.init();
		const types: string[] = [];
		s.subscribe((st) => {
			const p = st.registration.progress;
			if (p && p.stage === 'posting') types.push(p.type);
		});
		await s.register({ obtainProof: passport(), key: 'words', confirm: answers });
		expect(s.state().registration.state).toBe('acked');
		expect(types).toEqual(['nostr', 'nostr', 'direct']);
		const r = stored(s).registration!;
		expect(r.channel).toBe(DIRECT);
		expect(new Set(r.envelopes!.map((e) => e.id)).size).toBe(3);
	});

	it('orders nostr, iroh, direct, and leaves out a type the factory cannot reach', async () => {
		const iroh: Channel = { type: 'iroh', url: 'iroh://abc123', relay: 'https://relay.iroh.test', state: 'active' };
		const channels: Channel[] = [direct(DIRECT), iroh, nostr(RELAYS[0])];
		const w = world(channels);
		w.relays.relay(RELAYS[0]).dropAcks = true;
		const irohSent: NostrEvent[] = [];
		const irohChannel: IngestChannel = {
			type: 'iroh',
			url: iroh.url,
			send: async (e, o) => {
				irohSent.push(e);
				o.onPosted?.();
				return null;
			},
			publish: async () => {}
		};
		const s = session(w, { channels: (c) => (c.type === 'iroh' ? irohChannel : w.channels(c)) });
		await s.init();
		const order: string[] = [];
		s.subscribe((st) => {
			const p = st.registration.progress;
			if (p && p.stage === 'posting') order.push(p.type);
		});
		await s.register({ obtainProof: passport(), key: 'words', confirm: answers });
		expect(order).toEqual(['nostr', 'iroh', 'direct']);
		expect(irohSent).toHaveLength(1);
		// Without an iroh transport the channel is left out, the others work.
		const t = session(w);
		await t.init();
		expect(t.state().channels.map((c) => c.type)).toEqual(['direct', 'iroh', 'nostr']);
		await t.register({ obtainProof: passport(), key: 'words', confirm: answers });
		expect(stored(t).registration!.channel).toBe(DIRECT);
	});
});

describe('positions and seq', () => {
	it('each registration finds its position from the entries of the checkpoint that logged it', async () => {
		const w = world();
		const ss = [];
		for (let i = 0; i < 3; i++) {
			const s = session(w);
			await s.init();
			await s.register({ obtainProof: passport(), key: 'words', confirm: answers });
			ss.push(s);
		}
		w.ingest.checkpoint();
		for (const s of ss) await s.refresh();
		const positions = ss.map((s) => stored(s).position).sort();
		expect(positions).toEqual([0, 1, 2]);
		for (const s of ss) expect(w.ingest.leaves[stored(s).position]).toBe(stored(s).leaf);
		expect(w.mirror.reads.some((p) => p.includes('/positions/'))).toBe(false);
	});

	it('a device that lost its seq raises it on stale_seq until one is accepted, within the gap', async () => {
		const w = world();
		const { s, words } = await voter(w);
		for (let i = 0; i < 4; i++) {
			await s.cast({ pick: i % 2 });
			w.ingest.checkpoint();
			await s.refresh();
		}
		expect(stored(s).polls['7'].seq).toBe(3);
		const prover = new StubProver();
		const other = session(w, { prover });
		await other.init();
		await other.restoreFromWords(words);
		await other.cast({ pick: 2 });
		expect(other.state().ballot.state).toBe('acked');
		// 0, 1, 3 are stale (the last is 3); 7 is within 16 of it.
		expect(prover.calls.map((c) => c.inputs.seq)).toEqual([0, 1, 3, 7]);
		expect(stored(other).polls['7'].seq).toBe(7);
	});
});

describe('the re-vote rate', () => {
	it("refuses a re-vote within the ledger's revote_gap before proving, with the time it counts", async () => {
		let t = Date.now();
		const w = world(undefined, () => Math.floor(t / 1000), { revoteGap: 3600 });
		const prover = new StubProver();
		const { s } = await voter(w, { now: () => t, prover });
		expect(s.state().revoteGap).toBe(3600);
		await s.cast({ pick: 0 });
		w.ingest.checkpoint();
		await s.refresh();
		expect(s.state().ballot.state).toBe('verified');
		const loggedAt = stored(s).polls['7'].loggedAt!;
		expect(loggedAt).toBe(Math.floor(t / 1000));
		t += 60_000;
		await expect(s.cast({ pick: 1 })).rejects.toMatchObject({ code: 'too_soon', data: { retryAt: loggedAt + 3600, waitSeconds: 3540, exact: true } });
		expect(prover.calls).toHaveLength(1);
		t += 3600_000;
		w.ingest.checkpoint();
		await s.refresh();
		await s.cast({ pick: 1 });
		expect(s.state().ballot.state).toBe('acked');
	});

	it('a re-vote while the last ballot is pending is too_soon too; a device without the record hears it from the ingest', async () => {
		let t = Date.now();
		const w = world(undefined, () => Math.floor(t / 1000), { revoteGap: 600 });
		const { s, words } = await voter(w, { now: () => t });
		await s.cast({ pick: 0 });
		await expect(s.cast({ pick: 1 })).rejects.toMatchObject({ code: 'too_soon', data: { exact: false } });
		w.ingest.checkpoint();
		const other = session(w, { now: () => t });
		await other.init();
		await other.restoreFromWords(words);
		await expect(other.cast({ pick: 1 })).rejects.toMatchObject({ code: 'too_soon' });
		expect(other.state().ballot).toMatchObject({ state: 'rejected', reason: 'too_soon' });
	});
});

describe('a mirror behind its note', () => {
	it('drafts against the checkpoint the pushed commit covers and reads receipts once its files come', async () => {
		const w = world();
		const prover = new StubProver();
		const { s } = await voter(w, { prover });
		const regRoot = s.state().checkpoint!.registries[0].root;
		w.ingest.mirrorLag = 1;
		// A registration the mirror's commit does not hold yet: the tree of the covered checkpoint is the one drafted against.
		const late = session(w);
		await late.init();
		await late.register({ obtainProof: passport(), key: 'words', confirm: answers });
		w.ingest.checkpoint();
		await s.refresh();
		const cp = s.state().checkpoint!;
		expect(covered(cp)).toBe(cp.index - 1);
		expect(cp.registries[0].root).not.toBe(regRoot);
		await s.cast({ pick: 0 });
		expect(stored(s).polls['7'].ballot!.root).toBe(regRoot);
		await late.refresh();
		expect(late.state().registration.state).toBe('acked');
		expect(w.mirror.reads).not.toContain(`entries/${cp.index}.json`);
		w.ingest.mirrorLag = 0;
		w.ingest.checkpoint();
		await late.refresh();
		await s.refresh();
		expect(late.state().phase).toBe('ready');
		expect(s.state().ballot.state).toBe('verified');
	});

	it('reads both forms of the mirror line', () => {
		const sign = (mirror: string | null, index: number) =>
			core.verifyNote(
				wasm.dev_sign_checkpoint('22'.repeat(32), JSON.stringify({ origin: ORIGIN, size: 1, root: 'A'.repeat(43) + '=', index, time: 1, registries: [], ballots: [], mirror })),
				wasm.dev_verifier('22'.repeat(32), ORIGIN)
			);
		const old = sign('abc', 5);
		expect([old.mirror, old.mirror_index, covered(old)]).toEqual(['abc', null, 5]);
		const now = sign('def:3', 5);
		expect([now.mirror, now.mirror_index, covered(now)]).toEqual(['def', 3, 3]);
		const none = sign(null, 5);
		expect([none.mirror, none.mirror_index, covered(none)]).toEqual([null, null, 5]);
	});
});
