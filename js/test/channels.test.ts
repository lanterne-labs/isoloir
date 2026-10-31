import { describe, expect, it } from 'vitest';
import type { Channel } from '../src/types.js';
import { core, direct, DIRECT, nostr, RELAYS, tick, world } from './fakes.js';
import { answers, passport, session, stored, voter } from './helpers.js';

const directOnly: Channel[] = [direct(DIRECT)];

describe('a direct-only ledger', () => {
	it('registers and votes through the endpoint, with receipts; no device link', async () => {
		const w = world(directOnly);
		const { s } = await voter(w);
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
		const { s } = await voter(w);
		w.direct.dropResponse = true;
		await s.cast({ pick: 0 });
		expect(s.state().ballot.state).toBe('acked');
		expect(w.direct.requests.some((r) => r.startsWith('GET /v1/acks/'))).toBe(true);
	});

	it('waits for a deferred judgment (202) with GETs', async () => {
		const w = world(directOnly);
		const { s } = await voter(w, { ackTimeoutMs: 300 });
		w.direct.deferMs = 40;
		await s.cast({ pick: 2 });
		expect(s.state().ballot.state).toBe('acked');
		expect(w.direct.requests.filter((r) => r.startsWith('GET /v1/acks/')).length).toBeGreaterThan(0);
	});

	it('gives up on an endpoint that hangs', async () => {
		const w = world(directOnly);
		const { s } = await voter(w, { ackTimeoutMs: 100 });
		w.direct.hang = true;
		const t0 = Date.now();
		await expect(s.cast({ pick: 0 })).rejects.toMatchObject({ code: 'no_relay' });
		expect(Date.now() - t0).toBeLessThan(3000);
	});

	it('finds a missed ack again at the next visit, asking only the channel that took it', async () => {
		const w = world(directOnly);
		const { s } = await voter(w, { ackTimeoutMs: 30 });
		const store = (s as unknown as { store: never }).store;
		w.direct.deferMs = 120;
		await expect(s.cast({ pick: 0 })).rejects.toMatchObject({ code: 'no_ack' });
		expect(s.state().ballot).toMatchObject({ state: 'failed', kept: true });
		s.destroy();
		await tick(200);
		const again = session(w, { store, ackTimeoutMs: 30 });
		await again.init();
		// No resend: the ack was asked for by GET.
		expect(again.state().ballot.state).toBe('acked');
		expect(w.direct.received.filter((e) => e.kind === core.kinds.ballot)).toHaveLength(1);
	});

	it('reports a refusal by the ingest and by the endpoint', async () => {
		const w = world(directOnly);
		await voter(w, {}, 'SAME');
		const other = session(w);
		await other.init();
		// The same passport again: the ingest refuses it in a signed ack.
		await other.scanPassport(passport(undefined, 'SAME'));
		other.confirmWords(other.createKeyFromWords());
		await expect(other.submitRegistration()).rejects.toMatchObject({ code: 'reg:uid_used' });
		expect(other.state().registration).toMatchObject({ state: 'rejected', reason: 'uid_used' });

		const { s: third } = await voter(w);
		w.direct.refuseStatus = 503;
		await expect(third.cast({ pick: 0 })).rejects.toMatchObject({ code: 'no_relay' });
		expect(third.state().ballot).toMatchObject({ state: 'failed', reason: 'no_relay', kept: true });
		w.direct.refuseStatus = null;
		await third.resendBallot();
		expect(third.state().ballot.state).toBe('acked');
	});

	it('posts a complaint to the endpoint and keeps it on the device', async () => {
		const w = world(directOnly);
		const { s } = await voter(w);
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
		expect(stored(s).polls['7'].ballot?.ack?.event.pubkey).toBe(w.ingest.pubkey);
	});
});

describe('a mixed ledger', () => {
	it('leaves the direct endpoint out when there are relays: registration to the first, ballots to the second', async () => {
		const channels = [direct(DIRECT), nostr(RELAYS[0]), nostr(RELAYS[1])];
		const w = world(channels);
		const { s } = await voter(w);
		expect(s.state().linkAvailable).toBe(true);
		await s.cast({ pick: 0 });
		w.ingest.checkpoint();
		await s.refresh();
		expect(s.state().ballot.state).toBe('verified');
		expect(w.direct.received).toHaveLength(0);
		const [first, second] = core.relayRanking(stored(s).secret, [RELAYS[0], RELAYS[1]]);
		expect(w.relays.relay(first).events.some((e) => e.kind === core.kinds.register)).toBe(true);
		expect(w.relays.relay(second).events.some((e) => e.kind === core.kinds.ballot)).toBe(true);
		expect(w.relays.relay(first).events.some((e) => e.kind === core.kinds.ballot)).toBe(false);
		// The relays serve device links.
		const b = session(w);
		await b.init();
		const rx = b.receiveLink();
		const sender = await s.sendKeyTo(rx.publicKey);
		await tick(10);
		expect(rx.offer()).toBe(sender.code);
	});

	it('recovers a registration ack from the relay that holds it only', async () => {
		const w = world();
		const s = session(w);
		await s.init();
		await s.register({ obtainProof: passport(), key: 'words', confirm: answers }).catch(() => undefined);
		const store = (s as unknown as { store: never }).store;
		s.destroy();
		// Pretend the ack was missed: back to "sent".
		const k = stored(s);
		k.registration!.state = 'sent';
		delete k.registration!.ack;
		(s as unknown as { saveKey(k: unknown): void }).saveKey(k);
		const before = w.relays.subscriptions.length;
		const again = session(w, { store });
		await again.init();
		expect(again.state().registration.state).not.toBe('failed');
		const asked = w.relays.subscriptions.slice(before).filter((x) => x.filter['#e']);
		expect(asked.length).toBeGreaterThan(0);
		expect(new Set(asked.map((x) => x.url))).toEqual(new Set([k.registration!.channel]));
	});
});
