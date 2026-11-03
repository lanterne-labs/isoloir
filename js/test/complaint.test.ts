// Complaints (SPEC §11.3): kept whole on the device, carried as base64url,
// read and judged against the mirror by anyone.

import { describe, expect, it } from 'vitest';
import { decodeComplaint, encodeComplaint, judgeComplaint, readComplaint } from '../src/complaint.js';
import type { NostrEvent } from '../src/types.js';
import { core, MIRROR, TAG, world } from './fakes.js';
import { answers, passport, session, stored, voter } from './helpers.js';

type World = ReturnType<typeof world>;

const judge = (w: World, input: NostrEvent | string) => judgeComplaint(core, input, { mirror: MIRROR, fetch: w.mirror.fetch, verifierKey: w.ingest.verifier, allowDev: true });

/** A complaint event made by hand from an ack and a body. */
const complaintOf = (ack: NostrEvent, body: string) => core.signEvent('', Math.floor(Date.now() / 1000), core.kinds.complaint, [['t', TAG]], core.complaintBody(ack, body));

describe('complaints on the device', () => {
	it('keeps the whole signed event of a dropped ballot, across a reload and a re-vote', async () => {
		const w = world();
		const { s } = await voter(w);
		await s.cast({ pick: 1 });
		const hash = s.state().ballot.hash!;
		w.ingest.withhold.add(hash);
		w.ingest.checkpoint();
		await s.refresh();
		const view = s.state().ballot;
		expect(view.state).toBe('missing');
		expect(view.complaintEvents).toHaveLength(1);
		const event = view.complaintEvents![0];
		// The ids stay as before; the events come with them.
		expect(view.complaints).toEqual([event.id]);
		expect(event.kind).toBe(core.kinds.complaint);
		expect(core.verifyEvent(event)).toBe(true);
		const saved = s.state().complaints;
		expect(saved).toHaveLength(1);
		expect(saved[0]).toMatchObject({ what: 'ballot', poll: 7, claim: 'dropped', checkpoint: view.checkpoint, event });
		expect(saved[0].link).toBe(encodeComplaint(event));
		// Persisted with the key: a new session on the same store has it.
		const store = (s as unknown as { store: never }).store;
		const again = session(w, { store });
		await again.init();
		expect(again.state().complaints.map((c) => c.event)).toEqual([event]);
		expect(again.state().ballot.complaintEvents).toEqual([event]);
		// A re-vote replaces the ballot record, not the list of complaints.
		w.ingest.checkpoint();
		await again.cast({ pick: 0 });
		expect(again.state().ballot.complaintEvents).toBeUndefined();
		expect(again.state().complaints).toHaveLength(1);
		expect(stored(again).complaints).toHaveLength(1);
	});

	it('goes through base64url and back, from a link fragment too', async () => {
		const w = world();
		const { s } = await voter(w);
		await s.cast({ pick: 0 });
		w.ingest.withhold.add(s.state().ballot.hash!);
		w.ingest.checkpoint();
		await s.refresh();
		const { event, link } = s.state().complaints[0];
		expect(link).toMatch(/^[A-Za-z0-9_-]+$/);
		expect(decodeComplaint(link)).toEqual(event);
		expect(decodeComplaint(`https://vote.example/complaint#c=${link}`)).toEqual(event);
		expect(decodeComplaint(JSON.stringify(event))).toEqual(event);
		const claim = readComplaint(core, link, [w.ingest.pubkey]);
		expect(claim).toMatchObject({ claim: 'dropped', kind: 'ballot', hash: s.state().ballot.hash, checkpoint: s.state().ballot.checkpoint, ingest: w.ingest.pubkey, event });
		expect(core.bodyHash(claim.body)).toBe(claim.hash);
		expect(() => decodeComplaint('%%%')).toThrow(expect.objectContaining({ code: 'bad_complaint' }));
	});

	it('makes a complaint of a refusal on request, and only of a refusal', async () => {
		const w = world();
		const s = session(w);
		await s.init();
		await expect(s.complainOfRefusal('registration')).rejects.toMatchObject({ code: 'not_ready' });
		w.ingest.refuseNext = 'bad_proof';
		await expect(s.register({ obtainProof: passport(), key: 'words', confirm: answers })).rejects.toMatchObject({ code: 'reg:bad_proof' });
		const saved = await s.complainOfRefusal('registration');
		expect(saved).toMatchObject({ what: 'registration', claim: 'wrong_refusal', checkpoint: null });
		expect(s.state().registration.complaintEvents).toEqual([saved.event]);
		expect(readComplaint(core, saved.event)).toMatchObject({ claim: 'wrong_refusal', kind: 'register', reason: 'bad_proof' });
	});
});

describe('the judge', () => {
	it('a dropped body: holds while missing, holds as late once logged after, waits while the mirror lags', async () => {
		const w = world();
		const { s } = await voter(w);
		await s.cast({ pick: 1 });
		const b = stored(s).polls['7'].ballot!;
		// Acked for the next checkpoint, which the mirror does not hold yet.
		const early = complaintOf(b.ack!.event, b.body);
		expect(await judge(w, early)).toMatchObject({ verdict: 'pending' });
		w.ingest.withhold.add(b.hash);
		w.ingest.checkpoint();
		await s.refresh();
		const { event } = s.state().complaints[0];
		const v = await judge(w, encodeComplaint(event));
		expect(v).toMatchObject({ verdict: 'holds', found: null, claim: { claim: 'dropped', kind: 'ballot' } });
		// Logged two checkpoints later after all.
		w.ingest.withhold.delete(b.hash);
		w.ingest.pending.push({ kind: 'ballot', body: b.body, hash: b.hash });
		w.ingest.checkpoint();
		const late = await judge(w, event);
		expect(late).toMatchObject({ verdict: 'holds', found: { checkpoint: b.ack!.checkpoint! + 1, late: true } });
	});

	it('a body in the checkpoint its ack named: the claim fails', async () => {
		const w = world();
		const { s } = await voter(w);
		await s.cast({ pick: 0 });
		w.ingest.checkpoint();
		const b = stored(s).polls['7'].ballot!;
		const v = await judge(w, complaintOf(b.ack!.event, b.body));
		expect(v).toMatchObject({ verdict: 'fails', found: { checkpoint: b.ack!.checkpoint, late: false } });
	});

	it('a refusal judged again: holds for a valid registration, fails for a passport already registered', async () => {
		const w = world();
		const s = session(w);
		await s.init();
		w.ingest.refuseNext = 'uid_used';
		await expect(s.register({ obtainProof: passport(undefined, 'P-wrong'), key: 'words', confirm: answers })).rejects.toMatchObject({ code: 'reg:uid_used' });
		const wrong = await s.complainOfRefusal('registration');
		w.ingest.checkpoint();
		const v = await judge(w, wrong.link);
		expect(v, JSON.stringify(v.rejudged) + v.detail).toMatchObject({ verdict: 'holds' });
		expect(v.rejudged!.every((r) => r.outcome === 'accepted')).toBe(true);

		await voter(w, {}, 'P-twice');
		const other = session(w);
		await other.init();
		await expect(other.register({ obtainProof: passport(undefined, 'P-twice'), key: 'words', confirm: answers })).rejects.toMatchObject({ code: 'reg:uid_used' });
		const fair = await other.complainOfRefusal('registration');
		w.ingest.checkpoint();
		const f = await judge(w, fair.event);
		expect(f).toMatchObject({ verdict: 'fails', claim: { claim: 'wrong_refusal', reason: 'uid_used' } });
		expect(f.rejudged!.every((r) => r.outcome === 'rejected' && r.reason === 'uid_used')).toBe(true);
	});

	it('refuses what is not a complaint of this ledger', async () => {
		const w = world();
		const { s } = await voter(w);
		await s.cast({ pick: 0 });
		w.ingest.withhold.add(s.state().ballot.hash!);
		w.ingest.checkpoint();
		await s.refresh();
		const { event } = s.state().complaints[0];
		// Another body under the ack.
		const c = JSON.parse(event.content) as { ack: NostrEvent; body: Record<string, unknown> };
		const swapped = core.signEvent('', event.created_at, event.kind, event.tags, core.canonical({ ...c, body: { ...c.body, seq: 99 } }));
		expect(() => readComplaint(core, swapped)).toThrow(expect.objectContaining({ code: 'bad_complaint' }));
		expect(await judge(w, swapped)).toMatchObject({ verdict: 'invalid' });
		// A broken signature.
		expect((await judge(w, { ...event, sig: event.sig.replace(/^./, (x) => (x === '0' ? '1' : '0')) })).verdict).toBe('invalid');
		// An ack signed by a key that is not the ingest's.
		const forged = core.signEvent('', c.ack.created_at, c.ack.kind, c.ack.tags, c.ack.content);
		expect(await judge(w, complaintOf(forged, core.canonical(c.body)))).toMatchObject({ verdict: 'invalid', detail: expect.stringContaining('ingest') });
	});
});
