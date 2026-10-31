// The prover (SPEC §9.1): noir_js executes the circuit on the inputs the
// wasm core drafted, bb.js proves it (UltraHonk, the noir-recursive
// target the ingest verifies with bb). In a Web Worker, so the page stays
// responsive for the tens of seconds a phone takes. The session only
// needs the Prover interface: the proof bytes are opaque to it.

export interface ProofResult {
	proof: Uint8Array;
	/** The public inputs bb.js reports, checked against the body's. */
	publicInputs?: string[];
}

export interface Prover {
	/** Loads the circuit and the proving key ahead of the vote (optional). */
	warm?(circuit: string): Promise<void>;
	prove(circuit: string, inputs: Record<string, unknown>): Promise<ProofResult>;
}

/** Gives the compiled circuit's JSON (circuits/<name>/artifact.json on the mirror). */
export type ArtifactLoader = (circuit: string) => Promise<string>;

export interface CompiledCircuit {
	bytecode: string;
	abi: unknown;
}

// bb.js takes the SRS in blocks of 2^17 points; the ballot circuits fit.
const SRS_POINTS = 1 << 17;

interface Backend {
	noir: { execute(inputs: unknown): Promise<{ witness: Uint8Array }> };
	backend: {
		getVerificationKey(o: { verifierTarget: 'noir-recursive' }): Promise<Uint8Array>;
		generateProof(w: Uint8Array, o: { verifierTarget: 'noir-recursive' }): Promise<{ proof: Uint8Array; publicInputs: string[] }>;
	};
}

const backends = new Map<string, Promise<Backend>>();

/** How many threads bb.js may use: the cores up to 8 when cross-origin isolated, else one. */
export function proverThreads(): number {
	const g = globalThis as { crossOriginIsolated?: boolean; navigator?: { hardwareConcurrency?: number } };
	if (!g.crossOriginIsolated) return 1;
	return Math.min(g.navigator?.hardwareConcurrency || 1, 8);
}

/** Loads noir_js and bb.js for a circuit once; the first call fetches the SRS and sets up the key. */
export function backendFor(circuit: string, artifact: ArtifactLoader): Promise<Backend> {
	let b = backends.get(circuit);
	if (b) return b;
	b = (async () => {
		const compiled = JSON.parse(await artifact(circuit)) as CompiledCircuit;
		const [{ Noir }, { Barretenberg, UltraHonkBackend }] = await Promise.all([import('@noir-lang/noir_js'), import('@aztec/bb.js')]);
		const noir = new Noir(compiled as never);
		const api = await Barretenberg.new({ threads: proverThreads(), srsSize: SRS_POINTS } as never);
		const backend = new UltraHonkBackend(compiled.bytecode, api);
		await backend.getVerificationKey({ verifierTarget: 'noir-recursive' });
		return { noir: noir as unknown as Backend['noir'], backend: backend as unknown as Backend['backend'] };
	})();
	b.catch(() => backends.delete(circuit));
	backends.set(circuit, b);
	return b;
}

/** Proves in the current thread (what the worker runs; usable directly in tests or tools). */
export async function proveHere(circuit: string, inputs: Record<string, unknown>, artifact: ArtifactLoader): Promise<ProofResult> {
	const { noir, backend } = await backendFor(circuit, artifact);
	const { witness } = await noir.execute(inputs);
	const p = await backend.generateProof(witness, { verifierTarget: 'noir-recursive' });
	return { proof: p.proof, publicInputs: p.publicInputs };
}

/** In-thread prover. */
export class LocalProver implements Prover {
	constructor(private readonly artifact: ArtifactLoader) {}
	async warm(circuit: string): Promise<void> {
		await backendFor(circuit, this.artifact);
	}
	prove(circuit: string, inputs: Record<string, unknown>): Promise<ProofResult> {
		return proveHere(circuit, inputs, this.artifact);
	}
}

/** The messages between the page and the worker. */
export type WorkerRequest =
	| { id: number; op: 'warm'; circuit: string; artifact: string }
	| { id: number; op: 'prove'; circuit: string; artifact: string; inputs: Record<string, unknown> };

export type WorkerResponse = { id: number; ok: true; proof?: Uint8Array; publicInputs?: string[] } | { id: number; ok: false; error: string };

/** The subset of Worker the prover uses. */
export interface WorkerLike {
	postMessage(m: WorkerRequest): void;
	onmessage: ((ev: { data: WorkerResponse }) => void) | null;
	onerror: ((ev: unknown) => void) | null;
	terminate(): void;
}

/**
 * Proves in a Web Worker (prove.worker.js of this package). The artifact
 * is fetched on the page (from the mirror) and handed to the worker.
 *
 *   new WorkerProver(() => new Worker(new URL('@isoloir/web/prove.worker', import.meta.url), { type: 'module' }), loader)
 */
export class WorkerProver implements Prover {
	private worker: WorkerLike | null = null;
	private next = 1;
	private readonly waiting = new Map<number, { resolve: (r: WorkerResponse) => void; reject: (e: Error) => void }>();
	private readonly artifacts = new Map<string, Promise<string>>();

	constructor(
		private readonly spawn: () => WorkerLike,
		private readonly artifact: ArtifactLoader
	) {}

	private get w(): WorkerLike {
		if (this.worker) return this.worker;
		const w = this.spawn();
		w.onmessage = (ev) => {
			const p = this.waiting.get(ev.data.id);
			if (!p) return;
			this.waiting.delete(ev.data.id);
			p.resolve(ev.data);
		};
		w.onerror = (ev) => {
			const msg = ev && typeof ev === 'object' && 'message' in ev ? String((ev as { message: unknown }).message) : 'worker failed';
			for (const p of this.waiting.values()) p.reject(new Error(msg));
			this.waiting.clear();
			this.worker = null;
			w.terminate();
		};
		this.worker = w;
		return w;
	}

	private load(circuit: string): Promise<string> {
		let a = this.artifacts.get(circuit);
		if (!a) {
			a = this.artifact(circuit);
			a.catch(() => this.artifacts.delete(circuit));
			this.artifacts.set(circuit, a);
		}
		return a;
	}

	private call(req: WorkerRequest extends infer T ? (T extends { id: number } ? Omit<T, 'id'> : never) : never): Promise<WorkerResponse> {
		const id = this.next++;
		return new Promise((resolve, reject) => {
			this.waiting.set(id, { resolve, reject });
			this.w.postMessage({ ...req, id } as WorkerRequest);
		});
	}

	async warm(circuit: string): Promise<void> {
		const r = await this.call({ op: 'warm', circuit, artifact: await this.load(circuit) });
		if (!r.ok) throw new Error(r.error);
	}

	async prove(circuit: string, inputs: Record<string, unknown>): Promise<ProofResult> {
		const r = await this.call({ op: 'prove', circuit, artifact: await this.load(circuit), inputs });
		if (!r.ok) throw new Error(r.error);
		if (!r.proof) throw new Error('the worker returned no proof');
		return { proof: r.proof, publicInputs: r.publicInputs };
	}

	terminate(): void {
		this.worker?.terminate();
		this.worker = null;
	}
}
