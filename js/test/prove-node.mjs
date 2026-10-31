// Proves a circuit's inputs in Node the way the browser worker does
// (noir_js, then bb.js UltraHonk, target noir-recursive): the Rust test
// crates/zk/tests/browser_proof.rs checks the proof with the server's bb.
// Usage: node prove-node.mjs <artifact.json> <inputs.json> <proof out>
import { readFileSync, writeFileSync } from 'node:fs';
import { Noir } from '@noir-lang/noir_js';
import { Barretenberg, UltraHonkBackend } from '@aztec/bb.js';

const [artifact, inputs, out] = process.argv.slice(2);
const circuit = JSON.parse(readFileSync(artifact, 'utf8'));
const noir = new Noir(circuit);
const api = await Barretenberg.new({ threads: 4 });
const backend = new UltraHonkBackend(circuit.bytecode, api);
const { witness } = await noir.execute(JSON.parse(readFileSync(inputs, 'utf8')));
const p = await backend.generateProof(witness, { verifierTarget: 'noir-recursive' });
writeFileSync(out, p.proof);
await api.destroy?.();
process.exit(0);
