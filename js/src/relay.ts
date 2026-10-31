// The relays (SPEC §11): Nostr over plain WebSockets, no library. The
// session depends on RelayTransport only; tests give an in-memory one.
//
// postWithAck is the one way a message leaves the device: the signed
// event is posted to a relay, the ingest's signed ack is awaited there
// for 60 s, then the next relay of the key's ranking gets the same event
// (same id: the ingest judges a message once).

import { IsoloirError } from './errors.js';
import type { Ack, NostrEvent } from './types.js';
import type { Core } from './wasm.js';

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

/** Where a post stands, for the page. */
export interface PostProgress {
	relay: string;
	n: number;
	of: number;
	stage: 'posting' | 'waiting';
}

export interface PostOptions {
	ackTimeoutMs: number;
	publishTimeoutMs?: number;
	onPosted?: (relay: string) => void;
	onProgress?: (p: PostProgress) => void;
}

export interface Acked {
	relay: string;
	ack: Ack;
	ackEvent: NostrEvent;
}

/**
 * Posts a signed event to the relays in turn and waits for the ingest's
 * ack on each (SPEC §11.1, §11.2): an ack counts only when the ingest's
 * key signed it, it names the event and the body's hash. Throws no_relay
 * when no relay took the event, no_ack when some did and none answered.
 */
export async function postWithAck(core: Core, transport: RelayTransport, relays: string[], event: NostrEvent, ingest: string, opts: PostOptions): Promise<Acked> {
	const hash = core.bodyHash(event.content);
	let posted = 0;
	let lastErr = 'no relay';
	let n = 0;
	for (const relay of relays) {
		n++;
		opts.onProgress?.({ relay, n, of: relays.length, stage: 'posting' });
		let resolveAck: (a: Acked | null) => void = () => {};
		const got = new Promise<Acked | null>((r) => (resolveAck = r));
		// Listen first: an ack may come before the relay's OK.
		const stop = transport.subscribe(relay, { kinds: [core.kinds.ack], authors: [ingest], '#e': [event.id] }, (e) => {
			try {
				const ack = core.readAck(e, ingest);
				if (ack.of !== event.id || ack.hash !== hash) return;
				resolveAck({ relay, ack, ackEvent: e });
			} catch {
				// not an ack of the ingest's: a relay may serve anything
			}
		});
		try {
			await transport.publish(relay, event, opts.publishTimeoutMs ?? 10_000);
		} catch (e) {
			stop();
			lastErr = e instanceof Error ? e.message : String(e);
			continue;
		}
		posted++;
		opts.onPosted?.(relay);
		opts.onProgress?.({ relay, n, of: relays.length, stage: 'waiting' });
		const timer = setTimeout(() => resolveAck(null), opts.ackTimeoutMs);
		const acked = await got;
		clearTimeout(timer);
		stop();
		if (acked) return acked;
		lastErr = `${relay}: no acknowledgement`;
	}
	throw new IsoloirError(posted > 0 ? 'no_ack' : 'no_relay', lastErr);
}
