// One real ballot, proven in Node by bb.js with the SRS given by URL and
// SHA-256 (served by a local HTTP server), verified by bb.js. Opt-in:
//   ISOLOIR_CIRCUITS=<circuits/build, compiled with nargo>
//   ISOLOIR_SRS_DIR=<g1_compressed.dat (2^17 points), g2.dat, grumpkin_g1_v2.dat>
//   npx vitest run test/prove.e2e.test.ts

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { backendFor, LocalProver, type ProofResult, type Prover, type ProverOptions } from '../src/prover.js';
import { world } from './fakes.js';
import { voter } from './helpers.js';

const circuits = process.env.ISOLOIR_CIRCUITS;
const srsDir = process.env.ISOLOIR_SRS_DIR;
const FILES = ['g1_compressed.dat', 'g2.dat', 'grumpkin_g1_v2.dat'];

describe.skipIf(!circuits || !srsDir)('a ballot proven with the SRS by URL', () => {
	let server: Server;
	let options: ProverOptions;
	const artifact = async (name: string) => readFileSync(`${circuits}/${name}/target/${name}.json`, 'utf8');

	let bare: ProverOptions;

	beforeAll(async () => {
		// No native bb: bb.js proves in its wasm, as in a browser (and reads no SRS of its own).
		process.env.BB_BINARY_PATH = '/nonexistent';
		const files = new Map(FILES.map((f) => [`/${f}`, readFileSync(`${srsDir}/${f}`)]));
		server = createServer((req, res) => {
			const b = files.get(req.url ?? '');
			res.writeHead(b ? 200 : 404).end(b);
		});
		await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
		const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
		const pin = (f: string) => ({ url: `${base}/${f}`, sha256: createHash('sha256').update(files.get(`/${f}`)!).digest('hex') });
		options = { srs: { g1: pin(FILES[0]), g2: pin(FILES[1]), grumpkin: pin(FILES[2]) } };
		bare = { srs: { g1: options.srs!.g1, g2: options.srs!.g2 } };
	});
	afterAll(() => server?.close());

	/** Casts a ballot through a session with a LocalProver on `opts`, then verifies its proof with bb.js. */
	async function castAndVerify(opts: ProverOptions, pick: number): Promise<void> {
		const local = new LocalProver(artifact, opts);
		let made: { circuit: string; result: ProofResult } | null = null;
		const prover: Prover = {
			prove: async (circuit, inputs) => {
				const result = await local.prove(circuit, inputs);
				made = { circuit, result };
				return result;
			}
		};
		const w = world();
		const { s } = await voter(w, { prover });
		await s.cast({ pick });
		expect(s.state().prover).toBe('ready');
		expect(made).not.toBeNull();
		const { circuit, result } = made!;
		const { backend } = (await backendFor(circuit, artifact, opts)) as unknown as {
			backend: { verifyProof(p: { proof: Uint8Array; publicInputs: string[] }, o: { verifierTarget: string }): Promise<boolean> };
		};
		expect(await backend.verifyProof({ proof: result.proof, publicInputs: result.publicInputs! }, { verifierTarget: 'noir-recursive' })).toBe(true);
	}

	it('proves, the session finds its public inputs, bb.js verifies it', () => castAndVerify(options, 1), 600_000);

	it('needs no Grumpkin points for an UltraHonk ballot', () => castAndVerify(bare, 0), 600_000);
});
