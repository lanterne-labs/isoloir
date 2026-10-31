import { describe, expect, it } from 'vitest';
import { core, wasm, ORIGIN } from './fakes.js';
import { Mirror, dirSource } from '../src/mirror.js';
import { postWithAck } from '../src/relay.js';
import { FakeRelays } from './fakes.js';

const S = '0x' + '0'.repeat(60) + '1234';

describe('the wasm core from node', () => {
	it('derives keys from words and PRF outputs', () => {
		const w = core.newWords('en');
		expect(w.split(' ')).toHaveLength(12);
		expect(core.secretFromWords(w, 'en')).toBe(core.secretFromWords(`  ${w.toUpperCase()} `, 'en'));
		expect(() => core.secretFromWords('abandon abandon', 'en')).toThrow();
		const fr = core.newWords('fr');
		expect(core.secretFromWords(fr, 'fr')).toMatch(/^0x[0-9a-f]{64}$/);
		const a = core.secretFromPrf(new Uint8Array(32).fill(1));
		expect(a).toMatch(/^0x[0-9a-f]{64}$/);
		expect(core.secretFromPrf(new Uint8Array(32).fill(2))).not.toBe(a);
	});

	it('ranks relays deterministically per key', () => {
		const urls = ['wss://a', 'wss://b', 'wss://c', 'wss://d'];
		const r = core.relayRanking(S, urls);
		expect([...r].sort()).toEqual(urls);
		expect(core.relayRanking(S, [...urls].reverse())).toEqual(r);
	});

	it('seals a device link with matching codes', () => {
		const rx = core.linkReceiver();
		const sealed = core.linkSeal(rx.public, '{"secret":"x"}');
		const opened = core.linkOpen(rx.secret, sealed.sealed);
		expect(opened.payload).toBe('{"secret":"x"}');
		expect(opened.code).toBe(sealed.code);
		expect(sealed.code).toMatch(/^\d{6}$/);
		expect(() => core.linkOpen(core.linkReceiver().secret, sealed.sealed)).toThrow();
	});

	it('writes canonical JSON and hashes bodies', () => {
		expect(core.canonical({ b: 1, a: [true, 'x<y'] })).toBe('{"a":[true,"x<y"],"b":1}');
		expect(() => core.canonical({ a: 1.5 })).toThrow();
		expect(core.bodyHash('{}')).toBe('0x44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a');
	});

	it('signs and verifies events and reads acks', () => {
		const sk = '55'.repeat(32);
		const pk = core.regPubkey(sk);
		const ack = core.canonical({ v: 1, of: 'ab', hash: '0x00', outcome: 'accepted', checkpoint: 3 });
		const e = core.signEvent(sk, 1000, core.kinds.ack, [['e', 'ab']], ack);
		expect(core.verifyEvent(e)).toBe(true);
		expect(core.readAck(e, pk).checkpoint).toBe(3);
		expect(() => core.readAck(e, core.regPubkey('66'.repeat(32)))).toThrow();
		expect(core.verifyEvent({ ...e, content: ack + ' ' })).toBe(false);
	});

	it('verifies checkpoint notes under the pinned key only', async () => {
		const seed = '77'.repeat(32);
		const vk = wasm.dev_verifier(seed, ORIGIN);
		const cp = { origin: ORIGIN, size: 4, root: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', index: 2, time: 99, registries: [{ id: 1, size: 0, root: core.treeRoot(20, []) }], ballots: [], mirror: 'abc' };
		const note = wasm.dev_sign_checkpoint(seed, JSON.stringify(cp));
		expect(core.verifyNote(note, vk).index).toBe(2);
		expect(() => core.verifyNote(note.replace('\n4\n', '\n5\n'), vk)).toThrow();
		const files = new Map([['checkpoint.txt', note]]);
		const fetcher = async (url: string) => {
			const f = files.get(url.replace('https://m.test/', ''));
			return f ? { status: 200, ok: true, text: async () => f } : { status: 404, ok: false, text: async () => '' };
		};
		const good = new Mirror(core, [dirSource('https://m.test')], vk, fetcher);
		expect((await good.latest())?.mirror).toBe('abc');
		const bad = new Mirror(core, [dirSource('https://m.test')], wasm.dev_verifier('78'.repeat(32), ORIGIN), fetcher);
		await expect(bad.latest()).rejects.toMatchObject({ code: 'log_key' });
	});

	it('builds tree paths that lead to the root', () => {
		const leaves = [core.leaf(1, S), core.leaf(1, '0x' + '0'.repeat(63) + '1'), core.leaf(1, '0x' + '0'.repeat(63) + '2')];
		const p = core.treePath(20, leaves, 2);
		expect(p.path).toHaveLength(20);
		expect(wasm.root_of(leaves[2], 2, JSON.stringify(p.path))).toBe(p.root);
		expect(p.root).toBe(core.treeRoot(20, leaves));
	});

	it('seals tlock ballots in node (getrandom 0.4 through wasm_js)', () => {
		const chain = JSON.parse(wasm.dev_tlock_chain(3, 100)) as { public_key: string; signature: string };
		const poll = {
			v: 1, id: 8, version: 1, registry: 1, title: 't',
			kind: { type: 'choice', options: ['Oui', 'Non'], blank: false },
			encryption: { mode: 'tlock', chain: 'c', public_key: chain.public_key, period: 3, genesis: 0, round: 100 },
			publish: { mode: 'closed' }, revote: 'none', opens: 0, closes: 2_000_000_000,
			circuit: { name: 'choice4_tlock_linked_d20', vk_hash: '0x' + '0'.repeat(64) }
		};
		const leaves = [core.leaf(1, S)];
		const p = core.treePath(20, leaves, 0);
		const d = core.draftBallot({ poll, setup_seq: 2, member: { root: p.root, path: p.path, index: 0 }, s: S, choice: { pick: 1 }, revoting: { seq: 0 } });
		const payload = wasm.dev_tlock_open(chain.signature, d.body.blob as string);
		expect(payload).toContain('"values":[0,1,0,0]');
		expect(d.inputs.bhash).toMatch(/^0x/);
	});

	it('moves to the next relay when an ack does not come', async () => {
		const relays = new FakeRelays(['wss://x', 'wss://y']);
		const ingest = '99'.repeat(32);
		const ingestPub = core.regPubkey(ingest);
		relays.subscribe('wss://y', { kinds: [core.kinds.ballot] }, (e) => {
			const ack = core.canonical({ v: 1, of: e.id, hash: core.bodyHash(e.content), outcome: 'accepted', checkpoint: 1 });
			void relays.publish('wss://y', core.signEvent(ingest, 1, core.kinds.ack, [['e', e.id]], ack));
		});
		const ev = core.signEvent('', 1, core.kinds.ballot, [], '{"v":1}');
		const seen: string[] = [];
		const r = await postWithAck(core, relays, ['wss://x', 'wss://y'], ev, ingestPub, { ackTimeoutMs: 50, onPosted: (u) => seen.push(u) });
		expect(r.relay).toBe('wss://y');
		expect(seen).toEqual(['wss://x', 'wss://y']);
		// A forged ack (another key) does not count.
		const relays2 = new FakeRelays(['wss://z']);
		relays2.subscribe('wss://z', { kinds: [core.kinds.ballot] }, (e) => {
			const ack = core.canonical({ v: 1, of: e.id, hash: core.bodyHash(e.content), outcome: 'accepted', checkpoint: 1 });
			void relays2.publish('wss://z', core.signEvent('98'.repeat(32), 1, core.kinds.ack, [['e', e.id]], ack));
		});
		await expect(postWithAck(core, relays2, ['wss://z'], ev, ingestPub, { ackTimeoutMs: 50 })).rejects.toMatchObject({ code: 'no_ack' });
	});
});

describe('the browser build', () => {
	it('loads from bytes and runs', async () => {
		const { readFileSync } = await import('node:fs');
		const { loadWasm } = await import('../src/wasm.js');
		const w = await loadWasm(readFileSync(new URL('../wasm/web/isoloir_wasm_bg.wasm', import.meta.url)));
		expect(w.protocol()).toBe('isoloir/1');
		expect(w.new_reg_secret()).toMatch(/^[0-9a-f]{64}$/);
	});
});
