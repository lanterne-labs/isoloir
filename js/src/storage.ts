// Where the session keeps the voter's key and what it posted: one small
// synchronous key-value interface, localStorage by default. The app may
// give its own (an encrypted store, IndexedDB behind a cache). The secret
// lives here and nowhere else: never in logs, never in events.

export interface KeyValueStore {
	get(key: string): string | null;
	set(key: string, value: string): void;
	remove(key: string): void;
	/**
	 * Asks that the data survive storage pressure; says how it is kept:
	 * persistent (the browser granted it), best-effort (it may be evicted),
	 * memory (lost with the page). A store without it is best-effort.
	 */
	persist?(): Promise<StorageMode>;
}

export type StorageMode = 'persistent' | 'best-effort' | 'memory';

export class MemoryStore implements KeyValueStore {
	private readonly m = new Map<string, string>();
	get(key: string): string | null {
		return this.m.get(key) ?? null;
	}
	set(key: string, value: string): void {
		this.m.set(key, value);
	}
	remove(key: string): void {
		this.m.delete(key);
	}
	async persist(): Promise<StorageMode> {
		return 'memory';
	}
}

/** The browser's localStorage, or memory where there is none. */
export function defaultStore(): KeyValueStore {
	try {
		const ls = (globalThis as { localStorage?: Storage }).localStorage;
		if (ls) {
			const probe = '__isoloir_probe__';
			ls.setItem(probe, '1');
			ls.removeItem(probe);
			return {
				get: (k) => ls.getItem(k),
				set: (k, v) => ls.setItem(k, v),
				remove: (k) => ls.removeItem(k),
				persist: async () => {
					try {
						const st = (globalThis as { navigator?: { storage?: { persist?: () => Promise<boolean>; persisted?: () => Promise<boolean> } } }).navigator?.storage;
						if (!st?.persist) return 'best-effort';
						if (st.persisted && (await st.persisted())) return 'persistent';
						return (await st.persist()) ? 'persistent' : 'best-effort';
					} catch {
						return 'best-effort';
					}
				}
			};
		}
	} catch {
		// Storage blocked (a private window, a policy): memory only.
	}
	return new MemoryStore();
}

export function readJSON<T>(store: KeyValueStore, key: string): T | null {
	const raw = store.get(key);
	if (!raw) return null;
	try {
		return JSON.parse(raw) as T;
	} catch {
		return null;
	}
}

export function writeJSON(store: KeyValueStore, key: string, value: unknown): void {
	if (value === null || value === undefined) store.remove(key);
	else store.set(key, JSON.stringify(value));
}
