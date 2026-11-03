// The prover's Web Worker: executes and proves off the page's thread.
// Messages: WorkerRequest in, WorkerResponse out (prover.ts).

import { backendFor, proveHere, workerFailure, type WorkerRequest, type WorkerResponse } from './prover.js';

interface WorkerScope {
	onmessage: ((ev: { data: WorkerRequest }) => void) | null;
	postMessage(m: WorkerResponse): void;
}

const scope = globalThis as unknown as WorkerScope;

scope.onmessage = (ev) => {
	const req = ev.data;
	const artifact = () => Promise.resolve(req.artifact);
	const run = async (): Promise<WorkerResponse> => {
		if (req.op === 'warm') {
			await backendFor(req.circuit, artifact, req.options);
			return { id: req.id, ok: true };
		}
		const r = await proveHere(req.circuit, req.inputs, artifact, req.options);
		return { id: req.id, ok: true, proof: r.proof, publicInputs: r.publicInputs };
	};
	run().then(
		(r) => scope.postMessage(r),
		(e: unknown) => scope.postMessage(workerFailure(req.id, e))
	);
};
