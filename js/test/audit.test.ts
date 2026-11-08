import { describe, expect, it } from 'vitest';
import { audit } from '../src/audit.js';
import { StubProver, wasm, world } from './fakes.js';
import { voter } from './helpers.js';

// The audit's replay against real proofs is tested in Rust
// (crates/zk/tests/e2e.rs, browser_audit): the fake ingest here signs
// notes the real state machine does not reproduce. What stays here: the
// key is pinned.
describe('audit', () => {
	// An audit over a fake world: the files read and the result.
	const run = async (w: ReturnType<typeof world>, opts: { verifyProof?: () => Promise<boolean> } = {}) => {
		w.mirror.reads = [];
		const r = await audit(wasm as never, {
			text: async (p) => {
				w.mirror.reads.push(p);
				return w.mirror.files.get(p) ?? null;
			},
			logKey: wasm.dev_verifier(w.ingest.logSeed, 'test.example/isoloir'),
			verifyProof: opts.verifyProof ?? (async () => true),
			verifyPassport: async () => null
		});
		return { r, reads: w.mirror.reads };
	};

	it('reads the windows, and the checkpoint files only where no window holds a checkpoint', async () => {
		const w = world();
		const { s } = await voter(w, { prover: new StubProver() });
		await s.cast({ pick: 0 });
		for (let i = 0; i < 9; i++) w.ingest.checkpoint();
		// Windows of 4: every one full but the last, open.
		const n = w.ingest.index;
		const windows = Math.ceil(n / 4);
		expect(n).toBeGreaterThan(8);
		expect(w.mirror.files.has(`windows/${windows - 1}.json`)).toBe(true);
		expect(w.mirror.files.has(`windows/${windows}.json`)).toBe(false);
		const { r, reads } = await run(w);
		expect(r.upto).toBe(n);
		// Every window once, and no probe for a next one: the last window reaches the newest checkpoint.
		expect(reads.filter((p) => p.startsWith('windows/'))).toEqual(Array.from({ length: windows }, (_, k) => `windows/${k}.json`));
		expect(reads.filter((p) => p.startsWith('checkpoints/') || p.startsWith('entries/'))).toEqual([]);

		// The replay reads nothing: the first pass is kept.
		expect(reads.filter((p) => p === 'windows/0.json')).toHaveLength(1);

		// Checkpoint 4 taken out of window 0 (a gap) and the last window
		// removed: the gap and the tail come from the checkpoint files, in order.
		const w0 = JSON.parse(w.mirror.files.get('windows/0.json')!) as { to: number; checkpoints: { index: number }[] };
		w0.checkpoints = w0.checkpoints.filter((c) => c.index !== 4);
		w0.to = 3;
		w.mirror.put('windows/0.json', w0);
		w.mirror.files.delete(`windows/${windows - 1}.json`);
		const again = await run(w);
		expect(again.r.upto).toBe(n);
		const tail = Array.from({ length: n - (windows - 1) * 4 }, (_, i) => `checkpoints/${(windows - 1) * 4 + 1 + i}.txt`);
		expect(again.reads.filter((p) => p.startsWith('checkpoints/'))).toEqual(['checkpoints/4.txt', ...tail]);
	});

	it('a mirror without windows is read from the checkpoint files', async () => {
		const w = world();
		// The setup's checkpoints wrote a window: a mirror of an earlier version has none.
		for (const p of [...w.mirror.files.keys()]) if (p.startsWith('windows/')) w.mirror.files.delete(p);
		w.ingest.noWindows = true;
		const { s } = await voter(w, { prover: new StubProver() });
		await s.cast({ pick: 0 });
		w.ingest.checkpoint();
		const { r, reads } = await run(w);
		expect(r.upto).toBe(w.ingest.index);
		expect(reads.filter((p) => p.startsWith('windows/'))).toEqual(['windows/0.json']);
		expect(reads.filter((p) => p.startsWith('checkpoints/')).length).toBe(w.ingest.index);
	});

	it('a window whose checkpoints are not its range fails the audit', async () => {
		const w = world();
		const { s } = await voter(w, { prover: new StubProver() });
		await s.cast({ pick: 0 });
		w.ingest.checkpoint();
		const w0 = JSON.parse(w.mirror.files.get('windows/0.json')!) as { to: number };
		w0.to += 1;
		w.mirror.put('windows/0.json', w0);
		await expect(run(w)).rejects.toThrow(/windows\/0.json/);
	});

	it("a note that is not the pinned log key's fails the audit", async () => {
		const w = world();
		const { s } = await voter(w, { prover: new StubProver() });
		await s.cast({ pick: 0 });
		w.ingest.checkpoint();
		await expect(
			audit(wasm as never, {
				text: async (p) => w.mirror.files.get(p) ?? null,
				logKey: wasm.dev_verifier('33'.repeat(32), 'test.example/isoloir'),
				verifyProof: async () => true,
				verifyPassport: async () => null
			})
		).rejects.toThrow(/checkpoint note/);
	});
});
