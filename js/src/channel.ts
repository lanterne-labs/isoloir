// The ways to the ingest (SPEC §11.1): the ledger lists channels, each a
// Nostr relay or the ingest's own HTTP endpoint ("direct"). Every channel
// carries the same signed envelopes (Nostr events) and brings back the
// same signed acks (kind 7102, the ingest's key, tag e = the envelope id),
// so the session never cares which one it uses: it ranks them by the
// key, posts to the first, waits for the ack, moves to the next.
//
//   nostr   publish the event, read the ack by subscribing to 7102 #e
//   direct  POST {url}/v1/messages: 200 the ack, 202 {pending} (judged
//           later); GET {url}/v1/acks/{id}: 200 the ack, 404 none yet

import { IsoloirError } from './errors.js';
import { withTimeout } from './mirror.js';
import { WebSocketTransport, type Filter, type RelayTransport, type SubscribeOptions } from './relay.js';
import type { Ack, Channel, NostrEvent } from './types.js';
import type { Core } from './wasm.js';

/** What an ack must be to count: signed by the ingest, naming the envelope and its body hash. */
export interface AckMatch {
	/** The ack kind (7102). */
	kind: number;
	/** The ingest's key. */
	ingest: string;
	/** Whether an event is this envelope's ack (the signature checked). */
	accept(e: NostrEvent): boolean;
}

export interface SendOptions {
	/** How long the ack is awaited once the channel took the envelope. */
	waitMs: number;
	match: AckMatch;
	/** The channel took the envelope (the ack may still come). */
	onPosted?: () => void;
}

/** One way to the ingest. */
export interface IngestChannel {
	readonly type: Channel['type'];
	readonly url: string;
	/**
	 * Posts an envelope and waits for its ack: the ack event, or null when
	 * the channel took the envelope and no ack came in time. Throws when the
	 * channel did not take it.
	 */
	send(event: NostrEvent, opts: SendOptions): Promise<NostrEvent | null>;
	/** The ack of an envelope posted before (a missed ack, a reload), or null. */
	ackOf(eventId: string, opts: { waitMs: number; match: AckMatch }): Promise<NostrEvent | null>;
	/** Posts without waiting for an ack (complaints, device links). */
	publish(event: NostrEvent): Promise<void>;
	/** Reads events, stored then live (relays only). */
	subscribe?(filter: Filter, onEvent: (e: NostrEvent) => void, opts?: SubscribeOptions): () => void;
}

/** Builds the channel of a ledger entry (the default: WebSockets and fetch). */
export type ChannelFactory = (c: Channel) => IngestChannel;

// ------------------------------------------------------------ nostr

export class NostrChannel implements IngestChannel {
	readonly type = 'nostr' as const;

	constructor(
		readonly url: string,
		private readonly transport: RelayTransport = new WebSocketTransport(),
		private readonly publishTimeoutMs = 10_000
	) {}

	private waitAck(eventId: string, match: AckMatch, onEose?: () => void): { got: Promise<NostrEvent | null>; settle: (e: NostrEvent | null) => void; stop: () => void } {
		let settle: (e: NostrEvent | null) => void = () => {};
		const got = new Promise<NostrEvent | null>((r) => (settle = r));
		const stop = this.transport.subscribe(
			this.url,
			{ kinds: [match.kind], authors: [match.ingest], '#e': [eventId] },
			(e) => {
				if (match.accept(e)) settle(e);
			},
			{ onEose, onDown: () => settle(null) }
		);
		return { got, settle, stop };
	}

	async send(event: NostrEvent, opts: SendOptions): Promise<NostrEvent | null> {
		// Listen first: an ack may come before the relay's OK.
		const w = this.waitAck(event.id, opts.match);
		try {
			await this.transport.publish(this.url, event, this.publishTimeoutMs);
		} catch (e) {
			w.stop();
			throw e;
		}
		opts.onPosted?.();
		const timer = setTimeout(() => w.settle(null), opts.waitMs);
		const ack = await w.got;
		clearTimeout(timer);
		w.stop();
		return ack;
	}

	async ackOf(eventId: string, opts: { waitMs: number; match: AckMatch }): Promise<NostrEvent | null> {
		// The relay sends what it holds, then EOSE: no ack by then, none stored.
		let w: ReturnType<NostrChannel['waitAck']> | null = null;
		w = this.waitAck(eventId, opts.match, () => w?.settle(null));
		const timer = setTimeout(() => w?.settle(null), opts.waitMs);
		const ack = await w.got;
		clearTimeout(timer);
		w.stop();
		return ack;
	}

	publish(event: NostrEvent): Promise<void> {
		return this.transport.publish(this.url, event, this.publishTimeoutMs);
	}

	subscribe(filter: Filter, onEvent: (e: NostrEvent) => void, opts?: SubscribeOptions): () => void {
		return this.transport.subscribe(this.url, filter, onEvent, opts);
	}
}

// ------------------------------------------------------------ direct

export interface HttpResponse {
	status: number;
	ok: boolean;
	text(): Promise<string>;
}

export type HttpFetch = (url: string, init?: { method?: string; headers?: Record<string, string>; body?: string; credentials?: string; cache?: string; signal?: AbortSignal }) => Promise<HttpResponse>;

const defaultFetch: HttpFetch = (url, init) => fetch(url, init as RequestInit);

export interface DirectOptions {
	/** How often a pending envelope's ack is asked for (GET). */
	pollMs?: number;
	/** How long a publish (no ack awaited) waits for the response. */
	publishTimeoutMs?: number;
	/** How long a GET may take (default 10 s); a POST may take the ack wait plus this. */
	requestTimeoutMs?: number;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export class DirectChannel implements IngestChannel {
	readonly type = 'direct' as const;
	private readonly base: string;
	private readonly pollMs: number;
	private readonly publishTimeoutMs: number;
	private readonly requestTimeoutMs: number;

	constructor(
		readonly url: string,
		private readonly http: HttpFetch = defaultFetch,
		opts: DirectOptions = {}
	) {
		this.base = url.replace(/\/$/, '');
		this.pollMs = opts.pollMs ?? 2000;
		this.publishTimeoutMs = opts.publishTimeoutMs ?? 10_000;
		this.requestTimeoutMs = opts.requestTimeoutMs ?? 10_000;
	}

	/** POST /v1/messages; the endpoint holds it up to 55 s while the ingest judges. */
	private post(event: NostrEvent, timeoutMs: number): Promise<{ status: number; text: string }> {
		return withTimeout(timeoutMs, async (signal) => {
			const r = await this.http(`${this.base}/v1/messages`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(event), credentials: 'omit', signal });
			return { status: r.status, text: await r.text().catch(() => '') };
		});
	}

	/** GET /v1/acks/{id}: the ack, or null (404). */
	private get(eventId: string): Promise<NostrEvent | null> {
		return withTimeout(this.requestTimeoutMs, async (signal) => {
			const r = await this.http(`${this.base}/v1/acks/${eventId}`, { credentials: 'omit', cache: 'no-store', signal });
			if (r.status === 404) return null;
			if (r.status !== 200) throw new Error(`${this.url}: HTTP ${r.status}`);
			return JSON.parse(await r.text()) as NostrEvent;
		});
	}

	private async getMatching(eventId: string, match: AckMatch): Promise<NostrEvent | null> {
		try {
			const a = await this.get(eventId);
			return a && match.accept(a) ? a : null;
		} catch {
			return null;
		}
	}

	async send(event: NostrEvent, opts: SendOptions): Promise<NostrEvent | null> {
		const deadline = Date.now() + opts.waitMs;
		let res: { status: number; text: string };
		try {
			res = await this.post(event, opts.waitMs + this.requestTimeoutMs);
		} catch (e) {
			// The response was lost, not necessarily the message: ask for its ack.
			const ack = await this.getMatching(event.id, opts.match);
			if (ack) {
				opts.onPosted?.();
				return ack;
			}
			throw new Error(`${this.url}: ${e instanceof Error ? e.message : String(e)}`);
		}
		if (res.status === 200) {
			opts.onPosted?.();
			try {
				const ack = JSON.parse(res.text) as NostrEvent;
				if (opts.match.accept(ack)) return ack;
			} catch {
				// not an ack: ask again below
			}
		} else if (res.status === 202) {
			// Judged later (a deferred check): the ack comes by GET.
			opts.onPosted?.();
		} else {
			throw new Error(`${this.url} refused: HTTP ${res.status} ${res.text}`.trim());
		}
		while (Date.now() < deadline) {
			await sleep(Math.max(0, Math.min(this.pollMs, deadline - Date.now())));
			const ack = await this.getMatching(event.id, opts.match);
			if (ack) return ack;
		}
		return null;
	}

	ackOf(eventId: string, opts: { waitMs: number; match: AckMatch }): Promise<NostrEvent | null> {
		return this.getMatching(eventId, opts.match);
	}

	async publish(event: NostrEvent): Promise<void> {
		// The endpoint holds a request it does not acknowledge (a complaint)
		// for up to a minute: once sent, the message is there.
		let timer: ReturnType<typeof setTimeout> | undefined;
		const sent = this.post(event, 60_000 + this.requestTimeoutMs).then((r) => {
			if (r.status !== 200 && r.status !== 202) throw new Error(`${this.url} refused: HTTP ${r.status}`);
		});
		sent.catch(() => undefined);
		const waited = new Promise<void>((r) => (timer = setTimeout(r, this.publishTimeoutMs)));
		try {
			await Promise.race([sent, waited]);
		} finally {
			clearTimeout(timer);
		}
	}
}

/** The default channels: WebSockets for relays, fetch for the direct endpoint. */
export function defaultChannelFactory(opts: { transport?: RelayTransport; http?: HttpFetch; publishTimeoutMs?: number; directPollMs?: number } = {}): ChannelFactory {
	const transport = opts.transport ?? new WebSocketTransport();
	return (c) =>
		c.type === 'nostr'
			? new NostrChannel(c.url, transport, opts.publishTimeoutMs)
			: new DirectChannel(c.url, opts.http ?? defaultFetch, { pollMs: opts.directPollMs, publishTimeoutMs: opts.publishTimeoutMs });
}

// ------------------------------------------------------------ posting

/** Where a post stands, for the page. */
export interface PostProgress {
	channel: string;
	type: Channel['type'];
	n: number;
	of: number;
	stage: 'posting' | 'waiting';
}

export interface PostOptions {
	ackTimeoutMs: number;
	/** A channel took this envelope (keep it: its ack may come later). */
	onPosted?: (channel: string, envelope: NostrEvent) => void;
	onProgress?: (p: PostProgress) => void;
}

export interface Acked {
	channel: string;
	ack: Ack;
	ackEvent: NostrEvent;
	/** The envelope the ack names. */
	envelope: NostrEvent;
}

/** Makes an envelope of a body: a fresh throwaway key and the current time. */
export type Envelope = () => NostrEvent;

/** The match of an envelope's ack: the ingest's signature, the envelope id, the body's hash. */
export function ackMatch(core: Core, event: NostrEvent, ingest: string): AckMatch {
	const hash = core.bodyHash(event.content);
	return {
		kind: core.kinds.ack,
		ingest,
		accept: (e) => {
			try {
				const a = core.readAck(e, ingest);
				return a.of === event.id && a.hash === hash;
			} catch {
				return false;
			}
		}
	};
}

/**
 * Posts a body to the channels in turn and waits for the ingest's ack on
 * each (SPEC §11.1, §11.2): `ackTimeoutMs` (60 s) on one, then the next.
 * Every attempt wraps the body in a fresh envelope (a new key, the time
 * of the attempt): relays and the ingest read by `since`, so an envelope
 * dated minutes ago would never be seen; the ingest answers the same body
 * under any envelope with the same outcome. Acks are matched by the
 * envelope's id and the body's hash. Throws no_relay when no channel took
 * it, no_ack when some did and none answered.
 */
export async function postWithAck(core: Core, channels: IngestChannel[], envelope: Envelope, ingest: string, opts: PostOptions): Promise<Acked> {
	let posted = 0;
	let lastErr = 'no channel';
	let n = 0;
	for (const ch of channels) {
		n++;
		const at = { channel: ch.url, type: ch.type, n, of: channels.length };
		opts.onProgress?.({ ...at, stage: 'posting' });
		const event = envelope();
		const match = ackMatch(core, event, ingest);
		let ack: NostrEvent | null;
		try {
			ack = await ch.send(event, {
				waitMs: opts.ackTimeoutMs,
				match,
				onPosted: () => {
					posted++;
					opts.onPosted?.(ch.url, event);
					opts.onProgress?.({ ...at, stage: 'waiting' });
				}
			});
		} catch (e) {
			lastErr = e instanceof Error ? e.message : String(e);
			continue;
		}
		if (ack) return { channel: ch.url, ack: core.readAck(ack, ingest), ackEvent: ack, envelope: event };
		lastErr = `${ch.url}: no acknowledgement`;
	}
	throw new IsoloirError(posted > 0 ? 'no_ack' : 'no_relay', lastErr);
}

/** The ack of an envelope posted before, asked of the channel that took it. */
export async function findAck(core: Core, channel: IngestChannel, events: NostrEvent[], ingest: string, waitMs: number): Promise<Acked | null> {
	for (const event of events) {
		const ack = await channel.ackOf(event.id, { waitMs, match: ackMatch(core, event, ingest) }).catch(() => null);
		if (ack) return { channel: channel.url, ack: core.readAck(ack, ingest), ackEvent: ack, envelope: event };
	}
	return null;
}
