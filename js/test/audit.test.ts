import { describe, expect, it } from 'vitest';
import { audit } from '../src/audit.js';
import { StubProver, wasm, world } from './fakes.js';
import { voter } from './helpers.js';

// The audit's replay against real proofs is tested in Rust
// (crates/zk/tests/e2e.rs, browser_audit): the fake ingest here signs
// notes the real state machine does not reproduce. What stays here: the
// key is pinned.
describe('audit', () => {
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
