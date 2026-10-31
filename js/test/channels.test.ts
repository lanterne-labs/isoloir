import { afterEach, describe, expect, it } from 'vitest';
import { Session, type SessionConfig } from '../src/session.js';
import { MemoryStore } from '../src/storage.js';
import type { Channel, PassportProof, RegistrationRequest } from '../src/types.js';
import { core, direct, DIRECT, MIRROR, nostr, ORIGIN, RELAYS, StubProver, tick, world } from './fakes.js';

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
		ackTimeoutMs: 300,
		refreshMs: 0,
		...opts
	});
	sessions.push(s);
	return s;
}

let uid = 1000;
const passport = (fixed?: string) => async (req: RegistrationRequest): Promise<PassportProof> => ({
	uid: fixed ?? `D${++uid}`,
	proof: { custom_data: req.customData },
	proofDate: Math.floor(Date.now() / 1000)
});

async function voter(w: World, opts: Partial<SessionConfig> = {}) {
	const s = session(w, opts);
	await s.init();
	const { words } = await s.register({ obtainProof: passport(), key: 'words' });
	w.ingest.checkpoint();
	await s.refresh();
	expect(s.state().phase).toBe('ready');
	expect(s.confirmWords(words!)).toBe(true);
	return s;
}

function secretOf(s: Session): string {
	return (s as unknown as { key(): { secret: string } }).key().secret;
}

const directOnly: Channel[] = [direct(DIRECT)];

describe('a direct-only ledger', () => {
	it('registers and votes through the endpoint, with receipts; no device link', async () => {
		const w = world(directOnly);
		const s = await voter(w);
		expect(s.state().channels).toEqual(directOnly);
		expect(s.state().linkAvailable).toBe(false);
		expect(() => s.receiveLink()).toThrow(expect.objectContaining({ code: 'link_unavailable' }));
		await expect(s.sendKeyTo('02' + '11'.repeat(32))).rejects.toMatchObject({ code: 'link_unavailable' });
		await s.cast({ pick: 1 });
		expect(s.state().ballot.state).toBe('acked');
		w.ingest.checkpoint();
		await s.refresh();
		expect(s.state().ballot.state).toBe('verified');
		expect(w.direct.received.map((e) => e.kind)).toEqual([core.kinds.register, core.kinds.ballot]);
	});

	it('asks for the ack when the response is lost', async () => {
		const w = world(directOnly);
		const s = await voter(w);
		w.direct.dropResponse = true;
		await s.cast({ pick: 0 });
		expect(s.state().ballot.state).toBe('acked');
		expect(w.direct.requests.some((r) => r.startsWith('GET /v1/acks/'))).toBe(true);
	});

	it('waits for a deferred judgment (202) with GETs', async () => {
		const w = world(directOnly);
		const s = await voter(w);
		w.direct.deferMs = 40;
		await s.cast({ pick: 2 });
		expect(s.state().ballot.state).toBe('acked');
		expect(w.direct.requests.filter((r) => r.startsWith('GET /v1/acks/')).length).toBeGreaterThan(0);
	});

	it('finds a missed ack again at the next visit', async () => {
		const w = world(directOnly);
		const store = new MemoryStore();
		const s = await voter(w, { store, ackTimeoutMs: 30 });
		w.direct.deferMs = 120;
		await expect(s.cast({ pick: 0 })).rejects.toMatchObject({ code: 'no_ack' });
		expect(s.state().ballot).toMatchObject({ state: 'failed', kept: true });
		s.destroy();
		await tick(200);
		const again = session(w, { store });
		await again.init();
		// No resend: the ack was asked for by GET.
		expect(again.state().ballot.state).toBe('acked');
		expect(w.direct.received.filter((e) => e.kind === core.kinds.ballot)).toHaveLength(1);
	});

	it('reports a refusal by the ingest and by the endpoint', async () => {
		const w = world(directOnly);
		await voter(w);
		const other = session(w);
		await other.init();
		// The same passport again: the ingest refuses it in a signed ack.
		await other.scanPassport(passport(`D${uid}`));
		other.createKeyFromWords();
		await expect(other.submitRegistration()).rejects.toMatchObject({ code: 'reg:uid_used' });
		expect(other.state().registration).toMatchObject({ state: 'rejected', reason: 'uid_used' });

		const third = await voter(w);
		w.direct.refuseStatus = 503;
		await expect(third.cast({ pick: 0 })).rejects.toMatchObject({ code: 'no_relay' });
		expect(third.state().ballot).toMatchObject({ state: 'failed', reason: 'no_relay', kept: true });
		w.direct.refuseStatus = null;
		await third.resendBallot();
		expect(third.state().ballot.state).toBe('acked');
	});

	it('posts a complaint to the endpoint and keeps it on the device', async () => {
		const w = world(directOnly);
		const s = await voter(w);
		await s.cast({ pick: 1 });
		w.ingest.withhold.add(s.state().ballot.hash!);
		w.ingest.checkpoint();
		await s.refresh();
		expect(s.state().ballot.state).toBe('missing');
		expect(s.state().ballot.complaints).toHaveLength(1);
		const c = w.direct.received.filter((e) => e.kind === core.kinds.complaint);
		expect(c).toHaveLength(1);
		expect(c[0].id).toBe(s.state().ballot.complaints![0]);
		expect(JSON.parse(c[0].content).ack.pubkey).toBe(w.ingest.pubkey);
	});
});

describe('a mixed ledger', () => {
	it('posts registrations to the first channel of the key and ballots to the second, with receipts', async () => {
		const channels = [direct(DIRECT), nostr(RELAYS[0])];
		const w = world(channels);
		const s = await voter(w);
		expect(s.state().linkAvailable).toBe(true);
		await s.cast({ pick: 0 });
		w.ingest.checkpoint();
		await s.refresh();
		expect(s.state().ballot.state).toBe('verified');
		const [first, second] = core.relayRanking(secretOf(s), [DIRECT, RELAYS[0]]);
		const via = (kind: number) => (w.direct.received.some((e) => e.kind === kind) ? DIRECT : w.relays.all(kind).length > 0 ? RELAYS[0] : null);
		expect(via(core.kinds.register)).toBe(first);
		expect(via(core.kinds.ballot)).toBe(second);
		// The relay serves live checkpoints and device links.
		const b = session(w);
		await b.init();
		const rx = b.receiveLink();
		const code = await s.sendKeyTo(rx.publicKey);
		await tick(10);
		expect(rx.offer()).toBe(code);
	});

	it('moves to the relay when the endpoint is down', async () => {
		const channels = [direct(DIRECT), nostr(RELAYS[0])];
		const w = world(channels);
		const s = await voter(w);
		w.direct.refuseStatus = 503;
		await s.cast({ pick: 2 });
		expect(s.state().ballot.state).toBe('acked');
		expect(w.relays.all(core.kinds.ballot)).toHaveLength(1);
	});
});
