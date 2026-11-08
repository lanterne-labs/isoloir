// A small typed emitter: the session's events for the app.

export type Listener<T> = (value: T) => void;

export class Emitter<E extends object> {
	private readonly listeners = new Map<keyof E, Set<Listener<never>>>();

	on<K extends keyof E>(event: K, fn: Listener<E[K]>): () => void {
		let set = this.listeners.get(event);
		if (!set) {
			set = new Set();
			this.listeners.set(event, set);
		}
		set.add(fn as Listener<never>);
		return () => set.delete(fn as Listener<never>);
	}

	emit<K extends keyof E>(event: K, value: E[K]): void {
		for (const fn of this.listeners.get(event) ?? []) {
			try {
				(fn as Listener<E[K]>)(value);
			} catch {
				// a listener's failure is the app's, not the session's
			}
		}
	}
}

/** The server's clock, learned from checkpoints (SPEC §4: each carries the ingest's time). */
export class ServerClock {
	private bound: number | null = null;
	private live: number | null = null;

	constructor(private readonly local: () => number) {}

	/**
	 * A checkpoint is read after it was signed, never before: its time minus
	 * the local time is a lower bound of the offset (it corrects a clock
	 * that is behind). One that arrived on a relay was signed moments ago,
	 * or minutes ago when the relay kept it and hands it to a new
	 * subscription: the freshest one seen is the offset, so the largest is
	 * kept. (Taking the last one let a stale checkpoint set the clock back
	 * minutes: envelopes then looked old, and relays dropped them as expired
	 * ephemeral events.)
	 */
	note(unixSeconds: number, isLive = false): void {
		const o = unixSeconds * 1000 - this.local();
		this.bound = this.bound === null ? o : Math.max(this.bound, o);
		if (isLive) this.live = this.live === null ? o : Math.max(this.live, o);
	}

	/** The server's now, in milliseconds. */
	now(): number {
		return this.local() + (this.live ?? Math.max(0, this.bound ?? 0));
	}
}
