// Nostr relays (SPEC §11.1) over plain WebSockets, no library. The nostr
// channel (channel.ts) wraps a RelayTransport; tests give an in-memory one.

import type { NostrEvent } from './types.js';

export interface Filter {
	ids?: string[];
	kinds?: number[];
	authors?: string[];
	since?: number;
	limit?: number;
	'#e'?: string[];
	'#t'?: string[];
}

export interface SubscribeOptions {
	/** The relay sent its stored events (EOSE). */
	onEose?: () => void;
	/** The relay failed three times in a row or refused the subscription. */
	onDown?: () => void;
}

export interface RelayTransport {
	/** Posts an event; resolves when the relay accepted it (OK true). */
	publish(url: string, event: NostrEvent, timeoutMs: number): Promise<void>;
	/** Reads events, stored then live, until the returned stop is called. */
	subscribe(url: string, filter: Filter, onEvent: (e: NostrEvent) => void, opts?: SubscribeOptions): () => void;
}

/** The subset of WebSocket the transport uses. */
export interface SocketLike {
	onopen: ((ev: unknown) => void) | null;
	onmessage: ((ev: { data: unknown }) => void) | null;
	onerror: ((ev: unknown) => void) | null;
	onclose: ((ev: unknown) => void) | null;
	send(data: string): void;
	close(): void;
}

export type SocketFactory = (url: string) => SocketLike;

const defaultSocket: SocketFactory = (url) => new WebSocket(url) as unknown as SocketLike;

/** Nostr over WebSockets: one socket per publish, one per subscription. */
export class WebSocketTransport implements RelayTransport {
	constructor(private readonly socket: SocketFactory = defaultSocket) {}

	publish(url: string, event: NostrEvent, timeoutMs: number): Promise<void> {
		return new Promise((resolve, reject) => {
			let ws: SocketLike | null = null;
			let settled = false;
			const done = (err?: string) => {
				if (settled) return;
				settled = true;
				clearTimeout(timer);
				try {
					ws?.close();
				} catch {
					// already closed
				}
				if (err) reject(new Error(err));
				else resolve();
			};
			const timer = setTimeout(() => done(`${url}: no answer`), timeoutMs);
			try {
				ws = this.socket(url);
			} catch (e) {
				done(`${url}: ${String(e)}`);
				return;
			}
			ws.onopen = () => ws?.send(JSON.stringify(['EVENT', event]));
			ws.onmessage = (m) => {
				try {
					const msg = JSON.parse(String(m.data)) as unknown[];
					if (msg[0] === 'OK' && msg[1] === event.id) done(msg[2] ? undefined : `${url} refused: ${String(msg[3] ?? '')}`);
				} catch {
					// not a message of ours
				}
			};
			ws.onerror = () => done(`${url}: connection failed`);
			ws.onclose = () => done(`${url}: closed`);
		});
	}

	subscribe(url: string, filter: Filter, onEvent: (e: NostrEvent) => void, opts: SubscribeOptions = {}): () => void {
		let ws: SocketLike | null = null;
		let stopped = false;
		let retry = 1000;
		let failures = 0;
		let served = false;
		let timer: ReturnType<typeof setTimeout> | null = null;
		const sub = 's' + Math.random().toString(36).slice(2, 10);
		const refused = () => {
			failures = Math.max(failures, 2);
			try {
				ws?.close();
			} catch {
				// already closed
			}
		};
		const open = () => {
			if (stopped) return;
			served = false;
			try {
				ws = this.socket(url);
			} catch {
				schedule();
				return;
			}
			ws.onopen = () => {
				retry = 1000;
				ws?.send(JSON.stringify(['REQ', sub, filter]));
			};
			ws.onmessage = (m) => {
				let msg: unknown[];
				try {
					msg = JSON.parse(String(m.data)) as unknown[];
				} catch {
					return;
				}
				if (msg[0] === 'EVENT' && msg[1] === sub && msg[2]) {
					served = true;
					failures = 0;
					onEvent(msg[2] as NostrEvent);
				} else if (msg[0] === 'EOSE' && msg[1] === sub) {
					served = true;
					failures = 0;
					opts.onEose?.();
				} else if (msg[0] === 'CLOSED' && msg[1] === sub) refused();
				else if (msg[0] === 'NOTICE' && !served) refused();
			};
			ws.onclose = () => schedule();
			ws.onerror = () => ws?.close();
		};
		const schedule = () => {
			if (stopped) return;
			if (++failures === 3) opts.onDown?.();
			if (stopped) return;
			timer = setTimeout(open, retry);
			retry = Math.min(retry * 2, 30_000);
		};
		open();
		return () => {
			stopped = true;
			if (timer) clearTimeout(timer);
			try {
				ws?.close();
			} catch {
				// already closed
			}
		};
	}
}
