// The proof of work of an envelope (SPEC §11.1). With the ledger's `pow`
// d > 0, every envelope to the ingest carries ["pow", t, nonce] such that
//
//   SHA-256("isoloir/1/pow\n" ‖ origin ‖ "\n" ‖ pubkey ‖ "\n" ‖ t ‖ "\n" ‖ nonce)
//
// starts with d zero bits, t within [now − 7200, now + 300] at the ingest.
// The work is bound to the envelope's throwaway key and a time, never to
// the body, so it is done before the body exists: the session draws the
// key and mines while the passport is scanned or the ballot proven, in
// slices that leave the page responsive (the hashing is the wasm core's).
// Every envelope takes its own key, so a key never carries two bodies and
// an attempt on the next channel is a fresh envelope (a new id): the
// ingest answers the same body under any key with the same outcome.

import type { Core } from './wasm.js';

/** How far back the ingest takes t (SPEC §11.1). */
export const POW_PAST = 7200;
/** How far ahead the ingest takes t. */
export const POW_FUTURE = 300;
/** A key's work is used up to this long before it expires: the margin for clocks and a slow post. */
export const POW_MARGIN = 900;

/** A throwaway key and its work. */
export interface WorkKey {
	/** The key's secret (hex): it signs the envelopes of one body. */
	secret: string;
	/** Its x-only public key, the envelopes' pubkey. */
	pubkey: string;
	/** The difficulty mined for (0: no work, no tag). */
	bits: number;
	/** The time the work is bound to (unix seconds) and the nonce; absent when bits is 0. */
	t?: number;
	nonce?: string;
}

export interface MineOptions {
	/** Hashes per slice at the start (default 2048); the slice then grows to about `sliceMs`. */
	chunk?: number;
	/** The time a slice may take before the page gets the thread back (default 8 ms). */
	sliceMs?: number;
	/** Gives the thread back between slices (default: a macrotask). */
	yieldTo?: () => Promise<void>;
	signal?: AbortSignal;
	/** How many hashes were tried, at the end (diagnostics, benchmarks). */
	onDone?: (tries: number, ms: number) => void;
}

/** A macrotask: MessageChannel where there is one (no 4 ms clamp), else setTimeout. */
export function nextTask(): Promise<void> {
	if (typeof MessageChannel !== 'undefined') {
		return new Promise((resolve) => {
			const ch = new MessageChannel();
			ch.port1.onmessage = () => {
				ch.port1.close();
				resolve();
			};
			ch.port2.postMessage(0);
		});
	}
	return new Promise((resolve) => setTimeout(resolve, 0));
}

/** Finds a nonce for a key and a time, slice by slice. */
export async function mine(core: Core, origin: string, pubkey: string, t: number, bits: number, opts: MineOptions = {}): Promise<string> {
	const yieldTo = opts.yieldTo ?? nextTask;
	const sliceMs = opts.sliceMs ?? 8;
	let chunk = opts.chunk ?? 2048;
	let start = 0;
	const t0 = Date.now();
	for (;;) {
		opts.signal?.throwIfAborted();
		const s0 = Date.now();
		const nonce = core.powMine(origin, pubkey, t, bits, start, chunk);
		start += chunk;
		if (nonce !== null) {
			opts.onDone?.(Number(nonce) + 1, Date.now() - t0);
			return nonce;
		}
		const took = Date.now() - s0;
		if (took < sliceMs / 2 && chunk < 1 << 20) chunk *= 2;
		else if (took > sliceMs * 2 && chunk > 256) chunk = Math.floor(chunk / 2);
		await yieldTo();
	}
}

/** A fresh throwaway key with its work for `bits` at time `t` (unix seconds). */
export async function workKey(core: Core, origin: string, bits: number, t: number, opts?: MineOptions): Promise<WorkKey> {
	const secret = core.newRegSecret();
	const pubkey = core.regPubkey(secret);
	if (bits <= 0) return { secret, pubkey, bits: 0 };
	const nonce = await mine(core, origin, pubkey, t, bits, opts);
	return { secret, pubkey, bits, t, nonce };
}

/** Whether a key's work is enough for `bits` and still inside the ingest's window at `now` (unix seconds). */
export function workUsable(k: WorkKey, bits: number, now: number): boolean {
	if (bits <= 0) return true;
	if (k.bits < bits || k.t === undefined || k.nonce === undefined) return false;
	return k.t >= now - POW_PAST + POW_MARGIN && k.t <= now + POW_FUTURE;
}

/** The tag of a key's work, none when it did none. */
export function powTags(k: WorkKey): string[][] {
	return k.bits > 0 && k.t !== undefined && k.nonce !== undefined ? [['pow', String(k.t), k.nonce]] : [];
}

/**
 * The keys of a session's envelopes: one mined ahead (start()), taken by
 * the next envelope, the next one mined as soon as it is taken.
 */
export class WorkPool {
	private spare: Promise<WorkKey> | null = null;
	private spareFor = 0;

	constructor(
		private readonly core: Core,
		private readonly origin: string,
		/** The ledger's difficulty now. */
		private readonly bits: () => number,
		/** The server's time, unix seconds. */
		private readonly now: () => number,
		private readonly opts: MineOptions = {}
	) {}

	/** Mines a key ahead, unless one is being mined or ready for the current difficulty. */
	start(): Promise<WorkKey> {
		const bits = this.bits();
		if (this.spare && this.spareFor >= bits) return this.spare;
		this.spareFor = bits;
		const p = workKey(this.core, this.origin, bits, this.now(), this.opts);
		this.spare = p;
		// A failed mine (aborted) leaves room for the next start.
		p.catch(() => {
			if (this.spare === p) this.spare = null;
		});
		return p;
	}

	/** Whether a key is mined (or being mined) for the next body. */
	get started(): boolean {
		return this.spare !== null;
	}

	/**
	 * The key of one envelope: the spare (waited for while it is mined),
	 * and the next spare starts. Every envelope takes its own, so an
	 * attempt on the next channel is a fresh envelope (a new id) and a key
	 * never carries two bodies.
	 */
	async take(): Promise<WorkKey> {
		const bits = this.bits();
		for (let i = 0; i < 3; i++) {
			// Taken at once: two envelopes never wait for the same key.
			const p = this.start();
			this.spare = null;
			const k = await p;
			if (!workUsable(k, bits, this.now())) continue;
			void this.start().catch(() => undefined);
			return k;
		}
		throw new Error('no usable proof of work');
	}
}
