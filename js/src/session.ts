// The voter's session for one ledger, one registry and (optionally) one
// poll: everything a page shows comes from here. It reads the mirror and
// posts through the ledger's channels (Nostr relays, the ingest's direct
// endpoint: channel.ts), as the ledger setup on the mirror lists them;
// every protocol rule is the wasm core's. TypeScript only orchestrates:
//
//   setups     the ledger, the registry, the poll and every tally are
//              used only once proven in the signed log (mirror.ts)
//   key        a passkey's PRF (synced passkeys only), 12 words, or a
//              device link the receiver confirmed (SPEC §14); no
//              registration and no ballot before a backup
//   register   the registration key is drawn before the passport scan,
//              the proof waits for the key, then the body is signed and
//              posted (SPEC §6)
//   post       the body in a fresh envelope on the key's channel, the
//              ingest's signed ack awaited 60 s, then the next channel
//              (SPEC §11.1); the body and the ack are kept, so a missed
//              ack is a resend, never a lost message
//   receipt    the entries of every checkpoint since the post, read in
//              order (a window that does not depend on the ack); an acked
//              body missing from the checkpoint its ack named is a
//              complaint (SPEC §11.3)
//   ballot     drafted by wasm against a checkpoint at most 30 minutes
//              old, proven by the Prover, re-votes for linked and delta
//              polls (SPEC §7.4)
//   results    the latest tally, proven in the log and verified by wasm
//
// One rule above the others: the voter is never stuck. Every wait is a
// named state, every failure a code (errors.ts) with a next step.

import { Emitter, ServerClock } from './events.js';
import { IsoloirError, reasonOf, toIsoloirError } from './errors.js';
import { Mirror, dirSource, type Fetcher, type MirrorSource } from './mirror.js';
import { createPrf, assertPrf, prfInput, type PasskeyOptions } from './passkey.js';
import type { Prover } from './prover.js';
import { defaultChannelFactory, findAck, postWithAck, type Acked, type ChannelFactory, type IngestChannel, type PostProgress } from './channel.js';
import { defaultStore, readJSON, writeJSON, type KeyValueStore, type StorageMode } from './storage.js';
import type {
	Channel,
	Checkpoint,
	Choice,
	Entry,
	KindInfo,
	LedgerSetup,
	NostrEvent,
	PassportProof,
	PollSetup,
	RegistrationRequest,
	RegistrySetup,
	Setup,
	TallyVerdict
} from './types.js';
import { Core, messageOf, type IsoloirWasm, type TreePath } from './wasm.js';

// ------------------------------------------------------------ config

export interface SessionConfig {
	/** The wasm core: the module (loadWasm()) or a Core. */
	core: Core | IsoloirWasm;
	/** The ledger's origin (SPEC §4). */
	origin: string;
	/** The pinned C2SP verifier key of the ledger's log key: every checkpoint is checked under it. */
	verifierKey: string;
	registry: number;
	poll?: number;
	/** Mirror sources, or the base URL of a directory. */
	mirror: MirrorSource[] | string;
	fetch?: Fetcher;
	store?: KeyValueStore;
	/**
	 * How a channel of the ledger is reached. The session builds its
	 * channels from the ledger setup on the mirror; the default factory
	 * (WebSockets for relays, fetch for the direct endpoint) is what an app
	 * wants: this is for tests and fakes.
	 */
	channels?: ChannelFactory;
	prover?: Prover;
	/** WebAuthn options; the names shown default to the registry's name. */
	passkey?: PasskeyOptions;
	/** The word list of the 12 words: 'en' (default) or 'fr'. */
	wordsLang?: string;
	/** How long an ack is awaited on a channel before the next one (SPEC §11.1: 60 s). */
	ackTimeoutMs?: number;
	publishTimeoutMs?: number;
	/** How often the direct endpoint is asked for a pending ack (default 2 s). */
	directPollMs?: number;
	/** How long a mirror file may take (default 15 s). */
	mirrorTimeoutMs?: number;
	/** The oldest checkpoint a ballot is drafted against, by the local clock (default 30 min). */
	maxCheckpointAgeMs?: number;
	/** How often the mirror is read (0: never; the app calls refresh()). */
	refreshMs?: number;
	/** Follow the ingest's checkpoint events on a relay, when the ledger has one (default true). */
	watchRelays?: boolean;
	/** The local clock, ms (tests). */
	now?: () => number;
	/** Diagnostics: never given a secret. */
	log?: (level: 'debug' | 'warn' | 'error', msg: string, fields?: Record<string, unknown>) => void;
}

// ------------------------------------------------------------ records

export type PostState = 'kept' | 'sent' | 'acked' | 'verified' | 'missing' | 'rejected';

/** A message as the device keeps it: the body (resent in fresh envelopes), the ack, the receipt. */
export interface PostRecord {
	/** The body as signed and logged. */
	body: string;
	hash: string;
	state: PostState;
	/** The last envelope posted, and every envelope a channel took (their acks may come later). */
	event: NostrEvent;
	envelopes?: NostrEvent[];
	/** The channel (its URL) that took it, then the one that acked it. */
	channel?: string;
	sentAt?: number;
	/** The newest checkpoint when it was first posted: its receipt is looked for after it. */
	since?: number;
	ack?: { event: NostrEvent; checkpoint: number | null };
	reason?: string;
	/** Where the body was found: its log seq and checkpoint. */
	logSeq?: number;
	foundIn?: number;
	/** Found under a later checkpoint than the ack named. */
	late?: boolean;
	complaints?: string[];
}

export interface RegistrationRecord extends PostRecord {
	proofDate: number;
	/** A registration that replaced an earlier one of the same key (a stale proof scanned again). */
	replaced?: boolean;
}

export interface BallotRecord extends PostRecord {
	choice: Choice;
	root: string;
	/** Linked and none: the ballot's seq. */
	ballotSeq?: number;
	/** Delta: the ballot's number in the chain and its ballot tree leaf. */
	i?: number;
	leaf?: string;
}

export interface DeltaRecord {
	next: number;
	previous?: { choice: Choice; leaf?: string; index?: number };
}

export interface PollRecord {
	/** Linked: the last seq acked. */
	seq?: number;
	/** Delta: the chain, with the previous ballot's choice (needed to correct it). */
	delta?: DeltaRecord;
	ballot?: BallotRecord;
}

export type KeySource = 'passkey' | 'words' | 'link';

export interface StoredKey {
	v: 1;
	secret: string;
	source: KeySource;
	words?: string;
	credentialId?: string;
	/** What copies of the key exist: confirmed words, a synced passkey, devices that confirmed a link. */
	backups: { words: boolean; passkey: boolean; linked: number };
	leaf: string;
	position: number;
	regSecret?: string;
	registration?: RegistrationRecord;
	polls: Record<string, PollRecord>;
}

interface ScanRecord {
	regSecret: string;
	uid?: string;
	proof?: unknown;
	proofDate?: number;
}

/** What a device link carries (sealed end to end). */
interface LinkPayload {
	v: 1;
	origin: string;
	registry: number;
	secret: string;
	source: KeySource;
	words?: string;
	position: number;
	polls: Record<string, { seq?: number; delta?: DeltaRecord }>;
	/** The sender's reply key: the receiver confirms the adoption sealed for it. */
	reply?: string;
}

interface LinkConfirmation {
	v: 1;
	confirm: string;
	leaf: string;
}

// ------------------------------------------------------------ state

export type Phase = 'loading' | 'no-key' | 'unregistered' | 'registering' | 'joining' | 'ready' | 'error';

export interface RegistrationView {
	state: 'none' | 'scanned' | 'posting' | 'sent' | 'acked' | 'verified' | 'missing' | 'rejected' | 'failed';
	progress?: PostProgress;
	checkpoint?: number | null;
	reason?: string;
	detail?: string;
	/** The proof is too old to post: scan again (the same registration key). */
	stale?: boolean;
}

export interface BallotView {
	state: 'idle' | 'drafting' | 'proving' | 'posting' | 'sent' | 'acked' | 'verified' | 'missing' | 'rejected' | 'failed';
	choice?: Choice;
	progress?: PostProgress;
	checkpoint?: number | null;
	hash?: string;
	reason?: string;
	detail?: string;
	late?: boolean;
	complaints?: string[];
	/** A proven ballot waits for an ack: resendBallot() posts it again. */
	kept?: boolean;
}

/** The answer to a check of the words: `wrong` the 1-based positions that do not match. */
export interface WordsConfirmation {
	ok: boolean;
	wrong: number[];
}

export interface SessionState {
	phase: Phase;
	error: { code: string; detail: string } | null;
	ledger: LedgerSetup | null;
	registry: RegistrySetup | null;
	poll: PollSetup | null;
	kind: KindInfo | null;
	pollStatus: 'none' | 'upcoming' | 'open' | 'closed';
	checkpoint: Checkpoint | null;
	/** How old the newest checkpoint is by the local clock, seconds; past 30 minutes no ballot is drafted (stale_mirror). */
	checkpointAge: number | null;
	key: {
		leaf: string;
		source: KeySource;
		backedUp: boolean;
		hasWords: boolean;
		position: number | null;
	} | null;
	registration: RegistrationView;
	ballot: BallotView;
	/** The poll's last ballot from this device, as remembered (linked: its seq; delta: the chain). */
	revote: { seq: number | null; next: number | null; previousChoice: Choice | null };
	/** The last tally that verified (never replaced by one that does not). */
	tally: TallyVerdict | null;
	/** A newer tally that did not verify, or could not be proven in the log, and why. */
	tallyUnverified: { verdict: TallyVerdict | null; error: string } | null;
	prover: 'idle' | 'loading' | 'ready' | 'failed';
	/** The ledger's active channels. */
	channels: Channel[];
	/** Whether a device link can be made (it needs a Nostr relay among the channels). */
	linkAvailable: boolean;
	/** How the key is kept by the browser. */
	storage: StorageMode;
}

export interface SessionEvents {
	state: SessionState;
	checkpoint: Checkpoint;
	receipt: { what: 'registration' | 'ballot'; checkpoint: number; logSeq: number; late: boolean };
	complaint: { what: 'registration' | 'ballot'; checkpoint: number | null; events: string[] };
	'link-offer': { code: string };
	tally: TallyVerdict;
}

/** A device waiting for a key (SPEC §14): show `publicKey` (as a QR code), confirm the code, `answer`. */
export interface LinkReceiver {
	publicKey: string;
	/** The six digits of the payload that arrived, once one did. */
	offer(): string | null;
	answer(ok: boolean): void;
	stop(): void;
	done: Promise<void>;
}

/** A key sent to another device: the code to show, and whether the receiver adopted it. */
export interface LinkSender {
	code: string;
	/** True once the receiver confirmed (the link then counts as a backup); false after 15 minutes or stop(). */
	confirmed: Promise<boolean>;
	stop(): void;
}

const LINK_TIMEOUT = 15 * 60_000;
const LATE_SEARCH = 16;
const WINDOW_MAX = 64;
const ENVELOPES_KEPT = 8;

// ------------------------------------------------------------ session

export class Session {
	readonly core: Core;
	readonly mirror: Mirror;
	private readonly events = new Emitter<SessionEvents>();
	private readonly store: KeyValueStore;
	private readonly channelFactory: ChannelFactory;
	private channels: IngestChannel[] = [];
	private readonly clock: ServerClock;
	private readonly local: () => number;
	private readonly keyName: string;
	private readonly scanName: string;
	private readonly cursorName: string;
	private readonly ackTimeoutMs: number;

	private ledger: Setup<LedgerSetup> | null = null;
	private registry: Setup<RegistrySetup> | null = null;
	private poll: Setup<PollSetup> | null = null;
	private kind: KindInfo | null = null;
	private cp: Checkpoint | null = null;
	private phaseOverride: Phase | null = null;
	private error: { code: string; detail: string } | null = null;
	private registration: RegistrationView = { state: 'none' };
	private ballot: BallotView = { state: 'idle' };
	private tally: TallyVerdict | null = null;
	private tallyUnverified: SessionState['tallyUnverified'] = null;
	private proverState: SessionState['prover'] = 'idle';
	private storageMode: StorageMode = 'best-effort';
	private member: TreePath | null = null;
	private seqFloor = -1;
	private dupRetried = false;
	private timer: ReturnType<typeof setInterval> | null = null;
	private stopWatch: (() => void) | null = null;
	private refreshing: Promise<void> | null = null;
	private queued: Promise<void> | null = null;

	constructor(private readonly config: SessionConfig) {
		this.core = config.core instanceof Core ? config.core : new Core(config.core);
		const sources = typeof config.mirror === 'string' ? [dirSource(config.mirror)] : config.mirror;
		this.mirror = new Mirror(this.core, sources, config.verifierKey, config.fetch, config.mirrorTimeoutMs);
		this.store = config.store ?? defaultStore();
		this.channelFactory = config.channels ?? defaultChannelFactory({ publishTimeoutMs: config.publishTimeoutMs, directPollMs: config.directPollMs });
		this.local = config.now ?? (() => Date.now());
		this.clock = new ServerClock(this.local);
		this.keyName = `isoloir/${config.origin}/${config.registry}/key`;
		this.scanName = `isoloir/${config.origin}/${config.registry}/scan`;
		this.cursorName = `isoloir/${config.origin}/${config.registry}/cursor`;
		this.ackTimeoutMs = config.ackTimeoutMs ?? 60_000;
	}

	// ------------------------------------------------------- the API

	on<K extends keyof SessionEvents>(event: K, fn: (v: SessionEvents[K]) => void): () => void {
		return this.events.on(event, fn);
	}

	/** Calls fn with the state now and at every change. */
	subscribe(fn: (s: SessionState) => void): () => void {
		fn(this.state());
		return this.events.on('state', fn);
	}

	state(): SessionState {
		const k = this.key();
		const rec = this.pollRecord();
		return {
			phase: this.phase(),
			error: this.error,
			ledger: this.ledger?.body ?? null,
			registry: this.registry?.body ?? null,
			poll: this.poll?.body ?? null,
			kind: this.kind,
			pollStatus: this.pollStatus(),
			checkpoint: this.cp,
			checkpointAge: this.cp ? Math.max(0, Math.floor(this.local() / 1000) - this.cp.time) : null,
			key: k
				? { leaf: k.leaf, source: k.source, backedUp: this.backedUp(k), hasWords: !!k.words, position: k.position >= 0 ? k.position : null }
				: null,
			registration: this.registration,
			ballot: this.ballot,
			revote: {
				seq: rec?.seq ?? null,
				next: rec?.delta?.next ?? null,
				previousChoice: rec?.delta?.previous?.choice ?? null
			},
			tally: this.tally,
			tallyUnverified: this.tallyUnverified,
			prover: this.proverState,
			channels: (this.ledger?.body.channels ?? []).filter((c) => c.state === 'active'),
			linkAvailable: this.relays().length > 0,
			storage: this.storageMode
		};
	}

	/** The server's time, ms (from the checkpoints): the proof date of a scan is this. */
	serverNow(): number {
		return this.clock.now();
	}

	/** Reads the setups (each proven in the log) and the latest checkpoint, then resumes whatever this device left pending. */
	async init(): Promise<void> {
		this.phaseOverride = 'loading';
		this.error = null;
		this.emit();
		try {
			this.storageMode = this.store.persist ? await this.store.persist().catch(() => 'best-effort' as const) : 'best-effort';
			const ledger = await this.mirror.setup<LedgerSetup>('setup/ledger.json', 'ledger');
			if (!ledger) throw new IsoloirError('no_setup', 'setup/ledger.json');
			if (ledger.body.origin !== this.config.origin) throw new IsoloirError('no_setup', `the mirror is of ${ledger.body.origin}`);
			if (ledger.body.log_key !== this.config.verifierKey) throw new IsoloirError('log_key', 'the ledger names another log key');
			this.ledger = ledger;
			this.channels = ledger.body.channels.filter((c) => c.state === 'active').map((c) => this.channelFactory(c));
			if (this.channels.length === 0) throw new IsoloirError('no_setup', 'the ledger has no active channel');
			const registry = await this.mirror.setup<RegistrySetup>(`registries/${this.config.registry}.json`, 'registry');
			if (!registry) throw new IsoloirError('no_setup', `registries/${this.config.registry}.json`);
			if (registry.body.id !== this.config.registry) throw new IsoloirError('no_setup', 'another registry');
			this.registry = registry;
			if (this.config.poll !== undefined) {
				const poll = await this.mirror.setup<PollSetup>(`polls/${this.config.poll}.json`, 'poll');
				if (!poll) throw new IsoloirError('no_setup', `polls/${this.config.poll}.json`);
				if (poll.body.id !== this.config.poll || poll.body.registry !== this.config.registry) throw new IsoloirError('no_setup', 'the poll is of another registry');
				this.poll = poll;
				this.kind = this.core.kindInfo(poll.body);
			}
			const cp = await this.mirror.latest();
			if (cp) this.takeCheckpoint(cp, false);
			this.phaseOverride = null;
			this.resume();
			this.emit();
			await this.recoverAcks();
			await this.refresh();
			this.start();
		} catch (e) {
			const err = toIsoloirError(e, 'mirror');
			this.error = { code: err.code, detail: err.detail };
			this.phaseOverride = 'error';
			this.log('error', 'init', { code: err.code });
			this.emit();
			throw err;
		}
	}

	/** Stops the timers and subscriptions. */
	destroy(): void {
		if (this.timer) clearInterval(this.timer);
		this.timer = null;
		this.stopWatch?.();
		this.stopWatch = null;
	}

	/** Removes this device's key (the vote stays counted). */
	forgetKey(): void {
		this.store.remove(this.keyName);
		this.store.remove(this.scanName);
		this.store.remove(this.cursorName);
		this.registration = { state: 'none' };
		this.ballot = { state: 'idle' };
		this.member = null;
		this.emit();
	}

	// --------------------------------------------------- registration

	/**
	 * What the passport request must bind (SPEC §6, step 1): the custom
	 * data of a registration key drawn now, before any voter key exists,
	 * and kept until the registration is posted.
	 */
	registrationRequest(): RegistrationRequest {
		const reg = this.requireRegistry();
		const k = this.key();
		let scan = readJSON<ScanRecord>(this.store, this.scanName);
		if (!scan || (k?.regSecret && scan.regSecret !== k.regSecret)) {
			scan = { regSecret: k?.regSecret ?? this.core.newRegSecret() };
			writeJSON(this.store, this.scanName, scan);
		}
		const pub = this.core.regPubkey(scan.regSecret);
		const e = reg.eligibility;
		return { registry: reg.id, customData: this.core.registrationBinding(reg.id, pub), domain: e.domain, scope: e.scope, eligibility: e, validity: reg.validity, key: pub };
	}

	/**
	 * The scan: `obtain` runs the passport app (ZKPassport's SDK is the
	 * app's business) for the request and returns the proof, which the
	 * session keeps until the key exists and the registration is posted.
	 */
	async scanPassport(obtain: (req: RegistrationRequest) => Promise<PassportProof>): Promise<void> {
		const req = this.registrationRequest();
		const p = await obtain(req);
		if (!p || typeof p.uid !== 'string' || !p.uid || typeof p.proofDate !== 'number' || !Number.isInteger(p.proofDate)) {
			throw new IsoloirError('bad_proof', 'the passport app returned no uid or proof date');
		}
		const scan = readJSON<ScanRecord>(this.store, this.scanName) ?? { regSecret: this.core.newRegSecret() };
		writeJSON(this.store, this.scanName, { ...scan, uid: p.uid, proof: p.proof, proofDate: p.proofDate });
		this.registration = { state: 'scanned' };
		this.emit();
	}

	/** Whether a scanned proof is waiting and still fresh enough to post. */
	scanReady(): boolean {
		const s = readJSON<ScanRecord>(this.store, this.scanName);
		return !!s?.proof && !!s.uid && s.proofDate !== undefined && this.proofFresh(s.proofDate);
	}

	/** A new key from 12 fresh words; returns them (show them, then confirmWords). */
	createKeyFromWords(): string {
		this.requireNoKey();
		const lang = this.lang();
		const words = this.core.newWords(lang);
		const key = this.newKey(this.core.secretFromWords(words, lang), 'words');
		key.words = words;
		this.saveKey(key);
		this.emit();
		return words;
	}

	/** The words of this key, to show again. */
	words(): string | null {
		return this.key()?.words ?? null;
	}

	/** Three (or n) distinct random 1-based positions to ask the voter for. */
	wordChallenge(n = 3): number[] {
		const all = Array.from({ length: 12 }, (_, i) => i + 1);
		const r = crypto.getRandomValues(new Uint32Array(12));
		for (let i = all.length - 1; i > 0; i--) {
			const j = r[i] % (i + 1);
			[all[i], all[j]] = [all[j], all[i]];
		}
		return all.slice(0, Math.min(n, 12)).sort((a, b) => a - b);
	}

	/**
	 * The voter typed the words back: all twelve, or the words at the
	 * 1-based positions asked (wordChallenge). Case and accents do not
	 * matter. The backup is confirmed when every one matches.
	 */
	confirmWords(words: string): WordsConfirmation;
	confirmWords(positions: number[], answers: string[]): WordsConfirmation;
	confirmWords(a: string | number[], answers?: string[]): WordsConfirmation {
		const k = this.key();
		if (!k?.words) return { ok: false, wrong: [] };
		const mine = k.words.split(' ');
		const lang = this.lang();
		const positions = typeof a === 'string' ? mine.map((_, i) => i + 1) : a;
		const given = typeof a === 'string' ? a.trim().split(/\s+/) : (answers ?? []);
		const wrong: number[] = [];
		positions.forEach((p, i) => {
			const w = given[i] !== undefined ? this.core.canonicalWord(given[i], lang) : null;
			if (!Number.isInteger(p) || p < 1 || p > 12 || w !== mine[p - 1]) wrong.push(p);
		});
		const ok = positions.length > 0 && wrong.length === 0 && (typeof a !== 'string' || given.length === 12);
		if (ok) {
			k.backups.words = true;
			this.saveKey(k);
			this.emit();
		}
		return { ok, wrong };
	}

	/**
	 * A new key from a new passkey's PRF output. Only a synced passkey
	 * (backup state set) is a backup: otherwise nothing is kept and
	 * passkey_not_backed_up asks for the words instead.
	 */
	async createKeyWithPasskey(): Promise<void> {
		this.requireNoKey();
		const reg = this.requireRegistry();
		const { prf, credentialId, backedUp } = await createPrf(prfInput(this.config.origin, this.config.registry), { rpName: reg.name, userName: reg.name, ...this.config.passkey });
		// A passkey the platform reports as not synced is not a backup: the
		// words are. A platform that does not report (older authenticators)
		// is taken at its word, as the approved flow does; the app may ask
		// for the words too.
		if (backedUp === false) throw new IsoloirError('passkey_not_backed_up', 'the passkey is not synced');
		const key = this.newKey(this.core.secretFromPrf(prf), 'passkey');
		key.credentialId = credentialId;
		key.backups.passkey = true;
		this.saveKey(key);
		this.emit();
	}

	/**
	 * Signs and posts the registration with the scanned proof (SPEC §6,
	 * step 3), once the key is backed up. The body is kept before it is
	 * posted: a missed ack is a resend (resendRegistration), never a burnt
	 * passport. A kept registration whose proof went stale is replaced by
	 * one of a fresh scan of the same registration key.
	 */
	async submitRegistration(): Promise<void> {
		const reg = this.requireRegistry();
		const k = this.requireKey();
		if (k.position >= 0) return;
		if (!this.backedUp(k)) throw new IsoloirError('backup_required');
		const r = k.registration;
		if (r && r.state !== 'rejected') {
			if (r.state === 'kept' || r.state === 'sent') return this.resendRegistration();
			return;
		}
		const scan = readJSON<ScanRecord>(this.store, this.scanName);
		if (!scan?.proof || !scan.uid || scan.proofDate === undefined) throw new IsoloirError('not_ready', 'no passport proof');
		if (!this.proofFresh(scan.proofDate)) {
			this.registration = { state: 'failed', reason: 'stale_proof', stale: true };
			this.emit();
			throw new IsoloirError('stale_proof');
		}
		this.recordRegistration(k, reg, scan, false);
		await this.postRegistration();
	}

	/**
	 * The scan, the key, its backup and the post in one call. A words key
	 * needs `confirm`: it is given the words and the positions to ask, and
	 * returns the voter's answers. Returns the words of a words key.
	 */
	async register(opts: {
		obtainProof: (req: RegistrationRequest) => Promise<PassportProof>;
		key: 'passkey' | 'words';
		confirm?: (c: { words: string; positions: number[] }) => Promise<string[]>;
	}): Promise<{ words?: string }> {
		await this.scanPassport(opts.obtainProof);
		let words: string | undefined;
		if (!this.key()) {
			if (opts.key === 'passkey') await this.createKeyWithPasskey();
			else words = this.createKeyFromWords();
		}
		const k = this.requireKey();
		if (!this.backedUp(k)) {
			if (!k.words || !opts.confirm) throw new IsoloirError('backup_required');
			const positions = this.wordChallenge();
			const c = this.confirmWords(positions, await opts.confirm({ words: k.words, positions }));
			if (!c.ok) throw new IsoloirError('bad_words', 'the words typed back do not match', { wrong: c.wrong });
		}
		await this.submitRegistration();
		return { words };
	}

	/**
	 * Posts the kept registration again (the same body, a fresh envelope)
	 * while its proof is fresh; with a stale proof and a fresh scan of the
	 * same registration key, a new registration replaces it.
	 */
	async resendRegistration(): Promise<void> {
		const k = this.requireKey();
		if (!this.backedUp(k)) throw new IsoloirError('backup_required');
		const r = k.registration;
		if (!r || (r.state !== 'kept' && r.state !== 'sent')) throw new IsoloirError('not_ready', 'no registration waits');
		if (!this.proofFresh(r.proofDate)) {
			const scan = readJSON<ScanRecord>(this.store, this.scanName);
			if (scan?.proof && scan.uid && scan.proofDate !== undefined && this.proofFresh(scan.proofDate) && scan.regSecret === k.regSecret) {
				this.recordRegistration(k, this.requireRegistry(), scan, true);
			} else {
				this.registration = { state: 'failed', reason: 'stale_proof', stale: true };
				this.emit();
				throw new IsoloirError('stale_proof');
			}
		}
		await this.postRegistration();
	}

	// ------------------------------------------------- restore and link

	/** The key of 12 words, found again: registered, it votes from this device. */
	async restoreFromWords(words: string): Promise<void> {
		this.requireNoKey();
		const lang = this.lang();
		const check = this.core.checkWords(words, lang);
		if (!check.ok || !check.words) {
			throw new IsoloirError('bad_words', check.unknown.length ? `not on the list at ${check.unknown.join(', ')}` : check.count !== 12 ? `${check.count} words` : 'the checksum does not hold', {
				unknown: check.unknown,
				count: check.count,
				checksum: check.checksum
			});
		}
		const key = this.newKey(this.core.secretFromWords(check.words, lang), 'words');
		key.words = check.words;
		key.backups.words = true;
		await this.adopt(key, null);
	}

	/** The key of a passkey of this site (any device of the ecosystem). */
	async restoreWithPasskey(): Promise<void> {
		this.requireNoKey();
		const reg = this.requireRegistry();
		const prf = await assertPrf(prfInput(this.config.origin, this.config.registry), { rpName: reg.name, userName: reg.name, ...this.config.passkey });
		const key = this.newKey(this.core.secretFromPrf(prf), 'passkey');
		key.backups.passkey = true;
		await this.adopt(key, null);
	}

	/**
	 * Waits for a key from another device (SPEC §14): show `publicKey`;
	 * when a payload arrives, its six digits come as a 'link-offer' event;
	 * the voter compares them with the sender's and `answer(true)` adopts
	 * the key, then confirms it to the sender. Ends after 15 minutes.
	 * Needs a Nostr relay among the ledger's channels (link_unavailable).
	 */
	receiveLink(): LinkReceiver {
		const relays = this.relays();
		if (relays.length === 0) throw new IsoloirError('link_unavailable', 'the ledger has no Nostr relay');
		this.requireNoKey();
		const r = this.core.linkReceiver();
		const tag = linkTag(r.public);
		const stops: (() => void)[] = [];
		const stopAll = () => stops.splice(0).forEach((s) => s());
		let pending: { payload: LinkPayload; code: string } | null = null;
		let taken = false;
		let settle = { resolve: () => {}, reject: (_: Error) => {} };
		const done = new Promise<void>((resolve, reject) => (settle = { resolve, reject }));
		const expiry = setTimeout(() => {
			stopAll();
			settle.reject(new IsoloirError('link_expired'));
		}, LINK_TIMEOUT);
		const since = Math.floor(this.clock.now() / 1000) - 600;
		for (const relay of relays) {
			stops.push(
				relay.subscribe!({ kinds: [this.core.kinds.link], '#t': [tag], since }, (e) => {
					if (taken || pending) return;
					try {
						const got = this.core.linkOpen(r.secret, e.content);
						const payload = JSON.parse(got.payload) as LinkPayload;
						if (payload.v !== 1 || payload.origin !== this.config.origin || payload.registry !== this.config.registry || typeof payload.secret !== 'string') return;
						pending = { payload, code: got.code };
						this.events.emit('link-offer', { code: got.code });
					} catch {
						// not sealed for this key
					}
				})
			);
		}
		return {
			publicKey: r.public,
			offer: () => pending?.code ?? null,
			answer: (ok) => {
				const p = pending;
				pending = null;
				if (!ok || !p || taken) return;
				taken = true;
				clearTimeout(expiry);
				stopAll();
				this.adoptLinked(p.payload)
					.then(() => this.confirmLink(p.payload, p.code))
					.then(settle.resolve, (e: unknown) => settle.reject(toIsoloirError(e)));
			},
			stop: () => {
				clearTimeout(expiry);
				stopAll();
				settle.reject(new IsoloirError('stopped'));
			},
			done
		};
	}

	/**
	 * Sends this device's key to a device that shows `receiverPublic`
	 * (33-byte compressed key, hex). Show `code` for the voter to compare;
	 * `confirmed` resolves true once the receiver adopted the key: only
	 * then does the link count as a backup.
	 */
	async sendKeyTo(receiverPublic: string): Promise<LinkSender> {
		const k = this.requireKey();
		const relays = this.ranking(k, 'nostr');
		if (relays.length === 0) throw new IsoloirError('link_unavailable', 'the ledger has no Nostr relay');
		if (typeof receiverPublic !== 'string' || !/^0[23][0-9a-f]{64}$/.test(receiverPublic)) throw new IsoloirError('bad_link_key', 'not a compressed secp256k1 public key');
		const reply = this.core.linkReceiver();
		const polls: LinkPayload['polls'] = {};
		for (const [id, p] of Object.entries(k.polls)) polls[id] = { seq: p.seq, delta: p.delta };
		const payload: LinkPayload = { v: 1, origin: this.config.origin, registry: this.config.registry, secret: k.secret, source: k.source, words: k.words, position: k.position, polls, reply: reply.public };
		let sealed: { sealed: string; code: string };
		try {
			sealed = this.core.linkSeal(receiverPublic, JSON.stringify(payload));
		} catch (e) {
			throw new IsoloirError('bad_link_key', messageOf(e));
		}
		// Listen for the confirmation before the key leaves.
		const stops: (() => void)[] = [];
		let resolve: (ok: boolean) => void = () => {};
		const confirmed = new Promise<boolean>((r) => (resolve = r));
		const finish = (ok: boolean) => {
			clearTimeout(expiry);
			stops.splice(0).forEach((s) => s());
			resolve(ok);
		};
		const expiry = setTimeout(() => finish(false), LINK_TIMEOUT);
		const since = Math.floor(this.clock.now() / 1000) - 600;
		for (const relay of this.relays()) {
			stops.push(
				relay.subscribe!({ kinds: [this.core.kinds.link], '#t': [linkTag(reply.public)], since }, (e) => {
					try {
						const got = this.core.linkOpen(reply.secret, e.content);
						const c = JSON.parse(got.payload) as LinkConfirmation;
						if (c.v !== 1 || c.confirm !== sealed.code || c.leaf !== k.leaf) return;
						const kk = this.key();
						if (kk && kk.leaf === k.leaf) {
							kk.backups.linked++;
							this.saveKey(kk);
							this.emit();
						}
						finish(true);
					} catch {
						// not for this link
					}
				})
			);
		}
		const event = this.signEvent(this.core.kinds.link, sealed.sealed, [['t', linkTag(receiverPublic)]]);
		let lastErr = 'no relay';
		for (const relay of relays) {
			try {
				await relay.publish(event);
				return { code: sealed.code, confirmed, stop: () => finish(false) };
			} catch (e) {
				lastErr = messageOf(e);
			}
		}
		finish(false);
		throw new IsoloirError('no_relay', lastErr);
	}

	// ------------------------------------------------------- ballots

	/**
	 * Casts a choice: drafts it with the wasm core against the latest
	 * checkpoint (at most 30 minutes old), proves it, keeps it, posts it
	 * and waits for the ack. A re-vote continues the key's chain (linked:
	 * the next seq; delta: the correction of the previous ballot).
	 */
	async cast(choice: Choice): Promise<void> {
		const k = this.requireKey();
		const poll = this.requirePoll();
		if (k.position < 0) throw new IsoloirError('not_registered');
		if (!this.backedUp(k)) throw new IsoloirError('backup_required');
		if (!this.config.prover) throw new IsoloirError('prover', 'no prover');
		const status = this.pollStatus();
		if (status === 'upcoming') throw new IsoloirError('not_open');
		if (status === 'closed') throw new IsoloirError('closed');
		try {
			this.core.choiceValues(poll.body, choice);
		} catch (e) {
			throw new IsoloirError('bad_choice', messageOf(e));
		}
		const rec0 = this.pollRecord(k);
		if (rec0.ballot && (rec0.ballot.state === 'kept' || rec0.ballot.state === 'sent')) throw new IsoloirError('pending', 'a ballot waits for its ack: resendBallot()');
		this.seqFloor = -1;
		this.dupRetried = false;
		try {
			for (let attempt = 0; attempt < 3; attempt++) {
				this.ballot = { state: 'drafting', choice };
				this.emit();
				await this.refreshCheckpoint();
				const cp = this.requireCheckpoint();
				// A mirror serving an old root would single the voter out.
				const age = this.local() - cp.time * 1000;
				if (age > (this.config.maxCheckpointAgeMs ?? 30 * 60_000)) throw new IsoloirError('stale_mirror', `the newest checkpoint is ${Math.round(age / 60_000)} minutes old`);
				const kk = this.requireKey();
				const member = await this.memberPath(cp, kk);
				const rec = this.pollRecord(kk);
				const revoting = await this.revoting(cp, kk, rec);
				const draft = this.core.draftBallot({ poll: poll.body, setup_seq: poll.seq, member: { root: member.root, path: member.path, index: member.index }, s: kk.secret, choice, revoting });
				this.ballot = { state: 'proving', choice };
				this.proverState = 'loading';
				this.emit();
				let proof: Awaited<ReturnType<Prover['prove']>>;
				try {
					proof = await this.config.prover.prove(draft.circuit, draft.inputs);
					this.proverState = 'ready';
				} catch (e) {
					this.proverState = 'failed';
					throw new IsoloirError('prover', messageOf(e));
				}
				const body = this.core.finishBallot(draft.body, proof.proof);
				if (proof.publicInputs) {
					const want = this.core.publicInputs(body, poll.body);
					const got = proof.publicInputs.map(fieldHex);
					if (got.length !== want.length || got.some((x, i) => x !== want[i])) throw new IsoloirError('prover_mismatch', 'the proof is not of the ballot drafted');
				}
				const record: BallotRecord = { body, event: this.signEvent(this.core.kinds.ballot, body), hash: this.core.bodyHash(body), state: 'kept', choice, root: member.root, since: cp.index };
				if ('seq' in revoting) record.ballotSeq = revoting.seq;
				else {
					record.i = revoting.i;
					const b = draft.body as { ident: string; cmt: string };
					record.leaf = this.core.deltaLeaf(b.ident, b.cmt);
				}
				rec.ballot = record;
				this.saveKey(kk);
				if ((await this.submitBallot()) === 'done') return;
			}
			throw new IsoloirError('cast_retries');
		} catch (e) {
			const err = toIsoloirError(e);
			const s = this.ballot.state;
			if (s === 'drafting' || s === 'proving' || s === 'posting' || s === 'sent') {
				const kept = this.pollRecord()?.ballot;
				this.ballot = { state: 'failed', choice, reason: err.code, detail: err.detail, kept: !!kept && (kept.state === 'kept' || kept.state === 'sent') };
				this.emit();
			}
			throw err;
		}
	}

	/** Posts the kept ballot again (the same body in a fresh envelope: the ingest answers a body once). */
	async resendBallot(): Promise<void> {
		const rec = this.pollRecord();
		const b = rec?.ballot;
		if (!b || (b.state !== 'kept' && b.state !== 'sent')) throw new IsoloirError('not_ready', 'no ballot waits');
		this.dupRetried = false;
		const verdict = await this.submitBallot();
		if (verdict === 'retry') await this.cast(b.choice);
	}

	/** Drops a kept ballot no channel acknowledged (to cast another choice). */
	discardKeptBallot(): void {
		const k = this.key();
		const rec = k ? this.pollRecord(k) : null;
		if (!k || !rec?.ballot || (rec.ballot.state !== 'kept' && rec.ballot.state !== 'sent')) return;
		delete rec.ballot;
		this.saveKey(k);
		this.ballot = { state: 'idle' };
		this.emit();
	}

	// ------------------------------------------------------- reading

	/**
	 * Reads the mirror: the latest checkpoint, then whatever waits on it
	 * (a registration's position, a ballot's receipt, a complaint), then
	 * the latest tally.
	 */
	refresh(): Promise<void> {
		// One read at a time; a call during a read runs once more after it,
		// so what the caller just caused (a checkpoint, an ack) is read.
		if (this.queued) return this.queued;
		if (this.refreshing) {
			this.queued = this.refreshing.then(() => {
				this.queued = null;
				return this.refresh();
			});
			return this.queued;
		}
		this.refreshing = this.readMirror().finally(() => {
			this.refreshing = null;
		});
		return this.refreshing;
	}

	private async readMirror(): Promise<void> {
		try {
			await this.refreshCheckpoint();
			const cp = this.cp;
			if (!cp) return;
			const k = this.key();
			if (k) await this.readReceipts(cp, k);
			if (this.poll) await this.refreshTally();
		} catch (e) {
			const err = toIsoloirError(e, 'mirror');
			this.log('warn', 'refresh', { code: err.code });
			if (err.code === 'log_key') {
				this.error = { code: err.code, detail: err.detail };
				this.phaseOverride = 'error';
			}
		} finally {
			this.emit();
		}
	}

	/**
	 * The latest tally of the poll, proven in the log and verified by the
	 * wasm core. The state keeps the last one that verified; a newer one
	 * that does not (or a tlock tally, whose openings only an auditor can
	 * check) goes to `tallyUnverified`.
	 */
	async refreshTally(): Promise<TallyVerdict | null> {
		const poll = this.requirePoll();
		let verdict: TallyVerdict;
		try {
			const t = await this.mirror.latestTally(poll.body.id, this.token());
			if (t === null) return null;
			verdict = this.core.verifyTally(poll.body, t.body);
		} catch (e) {
			const err = toIsoloirError(e);
			if (err.code === 'mirror') throw err;
			this.tallyUnverified = { verdict: null, error: err.detail || err.code };
			this.log('warn', 'tally refused', { code: err.code });
			this.emit();
			return null;
		}
		if (verdict.ok) {
			const changed = this.tally?.tally.upto !== verdict.tally.upto;
			this.tally = verdict;
			this.tallyUnverified = null;
			if (changed) {
				this.events.emit('tally', verdict);
				this.emit();
			}
		} else {
			this.log('error', 'the tally does not verify', { error: verdict.error });
			this.tallyUnverified = { verdict, error: verdict.error ?? 'unverified' };
			this.emit();
		}
		return verdict;
	}

	// ======================================================= internals

	private log(level: 'debug' | 'warn' | 'error', msg: string, fields?: Record<string, unknown>) {
		this.config.log?.(level, msg, fields);
	}

	private emit() {
		this.events.emit('state', this.state());
	}

	private lang(): string {
		return this.config.wordsLang ?? 'en';
	}

	private key(): StoredKey | null {
		return readJSON<StoredKey>(this.store, this.keyName);
	}

	private saveKey(k: StoredKey) {
		writeJSON(this.store, this.keyName, k);
	}

	private requireKey(): StoredKey {
		const k = this.key();
		if (!k) throw new IsoloirError('not_ready', 'no key');
		return k;
	}

	private requireNoKey() {
		if (this.key()) throw new IsoloirError('key_exists');
	}

	private requireRegistry(): RegistrySetup {
		if (!this.registry) throw new IsoloirError('not_ready', 'init first');
		return this.registry.body;
	}

	private requirePoll(): Setup<PollSetup> {
		if (!this.poll) throw new IsoloirError('not_ready', 'no poll');
		return this.poll;
	}

	private requireCheckpoint(): Checkpoint {
		if (!this.cp) throw new IsoloirError('not_ready', 'no checkpoint');
		return this.cp;
	}

	private token(): string {
		return this.cp?.mirror ?? '';
	}

	private phase(): Phase {
		if (this.phaseOverride) return this.phaseOverride;
		const k = this.key();
		if (!k) return 'no-key';
		if (k.position >= 0) return 'ready';
		const r = k.registration;
		if (!r || r.state === 'rejected') return 'unregistered';
		if (r.state === 'kept' || r.state === 'sent') return this.registration.state === 'posting' ? 'registering' : 'unregistered';
		return 'joining';
	}

	private pollStatus(): SessionState['pollStatus'] {
		if (!this.poll) return 'none';
		const now = Math.floor(this.clock.now() / 1000);
		if (now < this.poll.body.opens) return 'upcoming';
		if (now >= this.poll.body.closes) return 'closed';
		return 'open';
	}

	private backedUp(k: StoredKey): boolean {
		return k.backups.passkey || k.backups.words || k.backups.linked > 0 || k.source === 'link';
	}

	private pollRecord(k: StoredKey): PollRecord;
	private pollRecord(): PollRecord | null;
	private pollRecord(k?: StoredKey): PollRecord | null {
		const key = k ?? this.key();
		if (!key || this.config.poll === undefined) return null;
		const id = String(this.config.poll);
		if (!key.polls[id]) key.polls[id] = {};
		return key.polls[id];
	}

	private newKey(secret: string, source: KeySource): StoredKey {
		const scan = readJSON<ScanRecord>(this.store, this.scanName);
		return {
			v: 1,
			secret,
			source,
			backups: { words: false, passkey: false, linked: 0 },
			leaf: this.core.leaf(this.config.registry, secret),
			position: -1,
			regSecret: scan?.regSecret,
			polls: {}
		};
	}

	/** The active Nostr relays (live reads, device links). */
	private relays(): IngestChannel[] {
		return this.channels.filter((c) => c.type === 'nostr' && c.subscribe);
	}

	/**
	 * The key's order of the channels it posts to (SPEC §11.1):
	 * relay_ranking over their URLs. The relays when the ledger has some
	 * (the direct endpoint shows the operator the voter's address), the
	 * direct endpoints when it has none.
	 */
	private ranking(k: StoredKey, only?: 'nostr'): IngestChannel[] {
		const relays = this.relays();
		const pool = only === 'nostr' || relays.length > 0 ? relays : this.channels;
		const order = this.core.relayRanking(k.secret, pool.map((c) => c.url));
		return order.map((u) => pool.find((c) => c.url === u)!);
	}

	/** Ballots go to the key's channels after the first, never to the registration's, unless there is only one. */
	private ballotChannels(k: StoredKey): IngestChannel[] {
		const r = this.ranking(k);
		return r.length > 1 ? r.slice(1) : r;
	}

	/** The relay that serves live checkpoints: neither the registration's nor the ballots' when there are three or more. */
	private watchRelays(k: StoredKey | null): IngestChannel[] {
		if (!k) return this.relays();
		const r = this.ranking(k, 'nostr');
		return r.length >= 3 ? r.slice(2) : r.slice(-1);
	}

	private ingest(): string {
		const i = this.ledger?.body.ingest;
		if (!i) throw new IsoloirError('not_ready', 'no ledger');
		return i;
	}

	/** An envelope of a fresh throwaway key, dated to the minute on the server's clock. */
	private signEvent(kind: number, content: string, extraTags: string[][] = []): NostrEvent {
		const createdAt = Math.floor(this.clock.now() / 60_000) * 60;
		return this.core.signEvent('', createdAt, kind, [['t', `isoloir/1/${this.config.origin}`], ...extraTags], content);
	}

	private proofFresh(proofDate: number): boolean {
		const validity = this.registry?.body.validity ?? 0;
		return Math.abs(Math.floor(this.clock.now() / 1000) - proofDate) <= validity;
	}

	private takeCheckpoint(cp: Checkpoint, live: boolean): boolean {
		if (cp.origin !== this.config.origin) throw new IsoloirError('log_key', `a checkpoint of ${cp.origin}`);
		this.clock.note(cp.time, live);
		if (this.cp && cp.index <= this.cp.index) return false;
		this.cp = cp;
		this.events.emit('checkpoint', cp);
		return true;
	}

	private async refreshCheckpoint(): Promise<void> {
		const cp = await this.mirror.latest();
		if (cp) this.takeCheckpoint(cp, false);
	}

	/** Sets the views from the records a previous visit left. */
	private resume() {
		const k = this.key();
		if (!k) {
			this.registration = this.scanReady() ? { state: 'scanned' } : { state: 'none' };
			this.ballot = { state: 'idle' };
			return;
		}
		const r = k.registration;
		if (k.position >= 0) this.registration = { state: 'verified', checkpoint: r?.ack?.checkpoint ?? null };
		else if (!r) this.registration = this.scanReady() ? { state: 'scanned' } : { state: 'none' };
		else if (r.state === 'kept' || r.state === 'sent') this.registration = { state: 'failed', reason: 'no_ack', stale: !this.proofFresh(r.proofDate) };
		else this.registration = { state: r.state, checkpoint: r.ack?.checkpoint ?? null, reason: r.reason };
		const b = this.pollRecord()?.ballot;
		if (!b) this.ballot = { state: 'idle' };
		else if (b.state === 'kept' || b.state === 'sent') this.ballot = { state: 'failed', choice: b.choice, reason: 'no_ack', kept: true, hash: b.hash };
		else this.ballot = this.ballotView(b);
	}

	private ballotView(b: BallotRecord): BallotView {
		return { state: b.state === 'kept' ? 'failed' : b.state, choice: b.choice, checkpoint: b.ack?.checkpoint ?? null, hash: b.hash, reason: b.reason, late: b.late, complaints: b.complaints };
	}

	private start() {
		// Without a relay to watch, the timer is the only way checkpoints come.
		const ms = this.config.refreshMs ?? (this.relays().length > 0 ? 30_000 : 15_000);
		if (ms > 0 && !this.timer) this.timer = setInterval(() => void this.refresh(), ms);
		if (this.config.watchRelays !== false) this.watchCheckpoints(0);
	}

	/** Follows the ingest's checkpoint events on a relay; a relay that fails gives way to the next. */
	private watchCheckpoints(skip: number) {
		const relays = this.watchRelays(this.key());
		if (relays.length === 0) return;
		const relay = relays[skip % relays.length];
		this.stopWatch?.();
		const since = Math.floor(this.clock.now() / 1000) - 600;
		this.stopWatch = relay.subscribe!(
			{ kinds: [this.core.kinds.checkpoint], authors: [this.ingest()], since },
			(e) => {
				if (!this.core.verifyEvent(e)) return;
				try {
					const cp = this.mirror.verify(e.content);
					if (this.takeCheckpoint(cp, true)) void this.refresh();
				} catch {
					// a note the pinned key refuses: dropped (the mirror's is authoritative)
				}
			},
			{ onDown: () => this.watchCheckpoints(skip + 1) }
		);
	}

	/** Keeps a posted envelope with its record. */
	private keepEnvelope(r: PostRecord, channel: string, env: NostrEvent) {
		if (r.state === 'kept') r.state = 'sent';
		r.channel = channel;
		r.event = env;
		r.sentAt ??= this.local();
		r.envelopes = [...(r.envelopes ?? []), env].slice(-ENVELOPES_KEPT);
	}

	// ----------------------------------------------- registration flow

	private recordRegistration(k: StoredKey, reg: RegistrySetup, scan: ScanRecord, replacing: boolean) {
		const body = this.core.registerBody({ registry: reg.id, s: k.secret, uid: scan.uid!, proof: scan.proof, proof_date: scan.proofDate!, reg_secret: scan.regSecret });
		const old = k.registration;
		k.regSecret = scan.regSecret;
		k.registration = {
			body,
			event: this.signEvent(this.core.kinds.register, body),
			hash: this.core.bodyHash(body),
			state: 'kept',
			proofDate: scan.proofDate!,
			since: old?.since ?? this.cp?.index ?? 0,
			replaced: replacing || old?.replaced || undefined,
			sentAt: replacing ? old?.sentAt : undefined,
			envelopes: replacing ? old?.envelopes : undefined
		};
		this.saveKey(k);
		// The key holds the request now; the scan served.
		this.store.remove(this.scanName);
	}

	private async postRegistration(): Promise<void> {
		const k = this.requireKey();
		const r = k.registration;
		if (!r) throw new IsoloirError('not_ready');
		const resend = r.sentAt !== undefined || !!r.replaced;
		this.registration = { state: 'posting' };
		this.emit();
		try {
			const res = await postWithAck(this.core, this.ranking(k), () => this.signEvent(this.core.kinds.register, r.body), this.ingest(), {
				ackTimeoutMs: this.ackTimeoutMs,
				onPosted: (channel, env) => {
					const kk = this.requireKey();
					if (kk.registration) {
						this.keepEnvelope(kk.registration, channel, env);
						this.saveKey(kk);
					}
				},
				onProgress: (progress) => {
					this.registration = { state: 'posting', progress };
					this.emit();
				}
			});
			await this.applyRegistrationAck(res, resend);
		} catch (e) {
			const err = toIsoloirError(e);
			if (!err.code.startsWith('reg:')) {
				const kk = this.key();
				this.registration = { state: 'failed', reason: err.code, detail: err.detail, stale: !!kk?.registration && !this.proofFresh(kk.registration.proofDate) };
				this.emit();
			}
			throw err;
		}
	}

	/** Keeps a registration's ack and acts on its outcome. */
	private async applyRegistrationAck(res: Acked, resend: boolean): Promise<void> {
		const kk = this.requireKey();
		const rec = kk.registration!;
		rec.channel = res.channel;
		rec.event = res.envelope;
		rec.ack = { event: res.ackEvent, checkpoint: res.ack.checkpoint ?? null };
		if (res.ack.outcome === 'accepted') rec.state = 'acked';
		else if (resend && (res.ack.reason === 'uid_used' || res.ack.reason === 'id_used')) {
			// A registration of this key the ingest took before (an earlier
			// body): the entries say where the leaf is.
			rec.state = 'acked';
			rec.ack.checkpoint = null;
		} else {
			rec.state = 'rejected';
			rec.reason = reasonOf(res.ack.reason);
		}
		this.saveKey(kk);
		this.registration = { state: rec.state === 'rejected' ? 'rejected' : 'acked', checkpoint: rec.ack.checkpoint, reason: rec.reason };
		this.emit();
		if (rec.state === 'rejected') throw new IsoloirError(`reg:${reasonOf(rec.reason)}`);
		await this.refresh();
	}

	/**
	 * Messages a previous visit posted and never saw acked: their acks are
	 * asked of the channel that took them only (a relay's stored events,
	 * the direct endpoint's GET), so a closed tab does not leave them
	 * waiting and no other channel learns of them.
	 */
	private async recoverAcks(): Promise<void> {
		const k = this.key();
		if (!k) return;
		const wait = Math.min(this.ackTimeoutMs, 5000);
		const holder = (url?: string) => this.channels.find((c) => c.url === url);
		try {
			const r = k.registration;
			const rc = holder(r?.channel);
			if (r && r.state === 'sent' && k.position < 0 && rc) {
				const res = await findAck(this.core, rc, [...(r.envelopes ?? [])].reverse(), this.ingest(), wait);
				if (res) await this.applyRegistrationAck(res, true).catch(() => undefined);
			}
			const b = this.pollRecord(k)?.ballot;
			const bc = holder(b?.channel);
			if (b && b.state === 'sent' && bc) {
				const res = await findAck(this.core, bc, [...(b.envelopes ?? [])].reverse(), this.ingest(), wait);
				if (res && res.ack.outcome === 'accepted') this.applyBallotAck(res);
			}
		} catch (e) {
			this.log('warn', 'recovering acks', { detail: messageOf(e) });
		}
	}

	// -------------------------------------------------- ballot flow

	private async submitBallot(): Promise<'done' | 'retry'> {
		const k = this.requireKey();
		const rec = this.pollRecord(k);
		const b = rec.ballot;
		if (!b) throw new IsoloirError('not_ready');
		this.ballot = { state: 'posting', choice: b.choice, hash: b.hash };
		this.emit();
		let res: Acked;
		try {
			res = await postWithAck(this.core, this.ballotChannels(k), () => this.signEvent(this.core.kinds.ballot, b.body), this.ingest(), {
				ackTimeoutMs: this.ackTimeoutMs,
				onPosted: (channel, env) => {
					const kk = this.requireKey();
					const bb = this.pollRecord(kk).ballot;
					if (bb) {
						this.keepEnvelope(bb, channel, env);
						this.saveKey(kk);
					}
					this.ballot = { ...this.ballot, state: 'sent' };
					this.emit();
				},
				onProgress: (progress) => {
					this.ballot = { ...this.ballot, progress };
					this.emit();
				}
			});
		} catch (e) {
			const err = toIsoloirError(e);
			this.ballot = { state: 'failed', choice: b.choice, hash: b.hash, reason: err.code, detail: err.detail, kept: true };
			this.emit();
			throw err;
		}
		const kk = this.requireKey();
		const r = this.pollRecord(kk);
		const bb = r.ballot!;
		const reason = res.ack.reason;
		if (res.ack.outcome === 'accepted') {
			this.applyBallotAck(res);
			void this.refresh();
			return 'done';
		}
		const delta = this.requirePoll().body.revote === 'delta';
		if (reason === 'duplicate' && delta && !this.dupRetried) {
			// The chain moved on without this device (a discarded ballot that
			// was logged, another device): find it again in the ballot tree.
			this.dupRetried = true;
			delete r.delta;
			delete r.ballot;
			this.saveKey(kk);
			return 'retry';
		}
		if (reason === 'stale_seq' || reason === 'old_root') {
			// Another device voted since, or the anchor aged: draft again.
			if (reason === 'stale_seq' && bb.ballotSeq !== undefined) {
				this.seqFloor = Math.max(this.seqFloor, bb.ballotSeq);
				delete r.seq;
			}
			delete r.ballot;
			this.saveKey(kk);
			this.member = null;
			return 'retry';
		}
		bb.state = 'rejected';
		bb.reason = reasonOf(reason);
		bb.ack = { event: res.ackEvent, checkpoint: res.ack.checkpoint ?? null };
		this.saveKey(kk);
		this.ballot = this.ballotView(bb);
		this.emit();
		throw new IsoloirError(reasonOf(reason));
	}

	/** Keeps an accepted ballot's ack and moves the key's chain on. */
	private applyBallotAck(res: Acked) {
		const kk = this.requireKey();
		const r = this.pollRecord(kk);
		const bb = r.ballot;
		if (!bb) return;
		bb.state = 'acked';
		bb.channel = res.channel;
		bb.event = res.envelope;
		bb.ack = { event: res.ackEvent, checkpoint: res.ack.checkpoint ?? null };
		if (bb.ballotSeq !== undefined) r.seq = Math.max(r.seq ?? -1, bb.ballotSeq);
		if (bb.i !== undefined) r.delta = { next: bb.i + 1, previous: { choice: bb.choice, leaf: bb.leaf } };
		this.saveKey(kk);
		this.ballot = this.ballotView(bb);
		this.emit();
	}

	/** The key's place in the registry tree at a checkpoint, rebuilt from the mirror's leaves. */
	private async memberPath(cp: Checkpoint, k: StoredKey): Promise<TreePath> {
		const reg = cp.registries.find((r) => r.id === this.config.registry);
		if (!reg || reg.size <= k.position) throw new IsoloirError('no_path', 'the checkpoint does not hold the leaf yet');
		if (this.member && this.member.root === reg.root && this.member.index === k.position) return this.member;
		const leaves = await this.mirror.leaves(`registries/${this.config.registry}/leaves`, reg.size, this.token());
		if (leaves[k.position] !== k.leaf) throw new IsoloirError('no_path', 'the mirror does not hold the leaf at its position');
		const p = this.core.treePath(this.requireRegistry().depth, leaves, k.position);
		if (p.root !== reg.root) throw new IsoloirError('no_path', 'the mirror and the checkpoint disagree on the registry root');
		this.member = p;
		return p;
	}

	/** Where the ballot stands in the key's chain (SPEC §7.4). */
	private async revoting(cp: Checkpoint, k: StoredKey, rec: PollRecord): Promise<{ seq: number } | { i: number; previous: { choice: Choice; path: string[]; index: number } | null; broot: string }> {
		const poll = this.requirePoll().body;
		if (poll.revote !== 'delta') {
			// The device's record first; the pseudonym shard only on a device without one.
			let last = rec.seq ?? -1;
			if (rec.seq === undefined) {
				const nullifier = this.core.nullifier(poll.id, k.secret);
				last = (await this.mirror.pseudonymSeq(poll.id, nullifier, this.token())) ?? -1;
			}
			last = Math.max(last, this.seqFloor);
			if (poll.revote === 'none' && last >= 0) throw new IsoloirError('revote_off');
			return { seq: last + 1 };
		}
		const depth = poll.ballot_depth;
		if (!depth) throw new IsoloirError('no_setup', 'a delta poll without a ballot depth');
		const line = cp.ballots.find((b) => b.poll === poll.id);
		const size = line?.size ?? 0;
		const broot = line?.root ?? this.core.treeRoot(depth, []);
		let chain = rec.delta;
		let leaves: string[] | null = null;
		const loadLeaves = async () => (leaves ??= await this.mirror.leaves(`polls/${poll.id}/ballots`, size, this.token()));
		if (!chain) {
			// No record on this device: the chain is found in the ballot tree from the secret.
			const found = this.core.deltaRecover(poll, k.secret, await loadLeaves());
			chain = { next: found.next, previous: found.previous ? { choice: found.previous.choice, index: found.previous.index } : undefined };
			rec.delta = chain;
			this.saveKey(k);
		}
		if (chain.next === 0 || !chain.previous) return { i: 0, previous: null, broot };
		const all = await loadLeaves();
		const index = chain.previous.leaf ? all.indexOf(chain.previous.leaf) : (chain.previous.index ?? -1);
		if (index < 0) throw new IsoloirError('previous_pending', 'the previous ballot is not in the ballot tree yet');
		const p = this.core.treePath(depth, all, index);
		if (p.root !== broot) throw new IsoloirError('no_path', 'the mirror and the checkpoint disagree on the ballot tree');
		return { i: chain.next, previous: { choice: chain.previous.choice, path: p.path, index }, broot };
	}

	// ------------------------------------------------------ receipts

	/** Whether a record still looks for its receipt. */
	private waiting(r: PostRecord | undefined, k: StoredKey, what: 'registration' | 'ballot'): r is PostRecord {
		if (!r || (r.state !== 'acked' && r.state !== 'missing')) return false;
		if (what === 'registration' && k.position >= 0) return false;
		if (r.state === 'missing' && r.ack?.checkpoint != null && (this.cursor() ?? 0) > r.ack.checkpoint + LATE_SEARCH) return false;
		return true;
	}

	private cursor(): number | null {
		return readJSON<number>(this.store, this.cursorName);
	}

	/**
	 * Reads the entries of every checkpoint since the last one read, in
	 * order, while a registration or a ballot waits for its receipt: the
	 * same files whatever the ack said, so what is fetched reveals nothing
	 * about which checkpoint holds the voter's message. A registration's
	 * position comes from the entries too (the registry's size at its
	 * checkpoint, its rank among the registrations there).
	 */
	private async readReceipts(cp: Checkpoint, k: StoredKey) {
		const reg = k.registration;
		const bal = this.pollRecord(k).ballot;
		const regWaits = this.waiting(reg, k, 'registration');
		const balWaits = this.waiting(bal, k, 'ballot');
		if (!regWaits && !balWaits) return;
		const since = Math.min(regWaits ? (reg!.since ?? 0) : Infinity, balWaits ? (bal!.since ?? 0) : Infinity);
		const start = Math.max((this.cursor() ?? 0) + 1, since + 1);
		for (let i = start; i <= cp.index && i < start + WINDOW_MAX; i++) {
			const entries = await this.mirror.entries(i, this.token());
			if (entries === null) break;
			const kr = this.requireKey();
			const r = kr.registration;
			if (r && this.waiting(r, kr, 'registration')) {
				const mine = entries.find((e) => e.kind === 'register' && isLeaf(e.body, this.config.registry, kr.leaf));
				if (mine) await this.registrationFound(kr, r as RegistrationRecord, i, entries, mine);
			}
			const kb = this.requireKey();
			const b = this.pollRecord(kb).ballot;
			if (b && this.waiting(b, kb, 'ballot')) {
				const mine = entries.find((e) => e.kind === 'ballot' && this.core.bodyHash(e.body) === b.hash);
				if (mine) this.ballotFound(kb, b, i, mine);
			}
			writeJSON(this.store, this.cursorName, i);
			// The checkpoint the ack named was read without the body: a complaint.
			const kc = this.requireKey();
			const rc = kc.registration;
			if (rc && rc.state === 'acked' && kc.position < 0 && rc.ack?.checkpoint === i) await this.complain('registration', kc, rc);
			const kd = this.requireKey();
			const bc = this.pollRecord(kd).ballot;
			if (bc && bc.state === 'acked' && bc.ack?.checkpoint === i) await this.complain('ballot', kd, bc);
		}
	}

	private async registrationFound(k: StoredKey, r: RegistrationRecord, index: number, entries: Entry[], mine: Entry) {
		const note = await this.mirror.checkpoint(index, this.token());
		const size = note?.registries.find((x) => x.id === this.config.registry)?.size;
		if (size === undefined) return;
		const regs = entries.filter((e) => e.kind === 'register' && isLeaf(e.body, this.config.registry, null));
		const pos = size - regs.length + regs.indexOf(mine);
		const late = r.ack?.checkpoint != null && index > r.ack.checkpoint;
		Object.assign(r, { logSeq: mine.seq, foundIn: index, late: late || undefined, state: 'verified' });
		k.position = pos;
		this.saveKey(k);
		this.registration = { state: 'verified', checkpoint: r.ack?.checkpoint ?? null };
		this.events.emit('receipt', { what: 'registration', checkpoint: index, logSeq: mine.seq, late });
		this.emit();
	}

	private ballotFound(k: StoredKey, b: BallotRecord, index: number, mine: Entry) {
		const late = b.ack?.checkpoint != null && index > b.ack.checkpoint;
		Object.assign(b, { state: 'verified', logSeq: mine.seq, foundIn: index, late: late || undefined });
		this.saveKey(k);
		this.ballot = this.ballotView(b);
		this.events.emit('receipt', { what: 'ballot', checkpoint: index, logSeq: mine.seq, late });
		this.emit();
	}

	/**
	 * The ack named a checkpoint whose entries lack the body (SPEC §11.3):
	 * the complaint, the signed ack and the body, goes to every active
	 * relay, where anyone can read it, and the message itself is posted
	 * there again; on a ledger without relays, to the direct endpoints. It
	 * stays with the device too (the record's complaints and ack).
	 */
	private async complain(what: 'registration' | 'ballot', k: StoredKey, r: PostRecord) {
		if (!r.ack) return;
		const content = this.core.complaintBody(r.ack.event, r.body);
		const event = this.signEvent(this.core.kinds.complaint, content);
		const ids: string[] = [];
		const relays = this.relays();
		for (const ch of relays.length > 0 ? relays : this.channels) {
			try {
				await ch.publish(event);
				ids.push(`${ch.url} ${event.id}`);
				if (ch.type === 'nostr') await ch.publish(this.signEvent(r.event.kind, r.body)).catch(() => undefined);
			} catch (e) {
				this.log('warn', 'complaint not posted', { channel: ch.url, detail: messageOf(e) });
			}
		}
		r.state = 'missing';
		r.complaints = [...(r.complaints ?? []), event.id];
		this.saveKey(k);
		if (what === 'ballot') this.ballot = this.ballotView(r as BallotRecord);
		else this.registration = { state: 'missing', checkpoint: r.ack.checkpoint };
		this.log('warn', 'acked and missing from its checkpoint: complaint posted', { what, checkpoint: r.ack.checkpoint, channels: ids.length });
		this.events.emit('complaint', { what, checkpoint: r.ack.checkpoint, events: [event.id] });
		this.emit();
	}

	// --------------------------------------------------- restore flow

	private async adopt(key: StoredKey, hint: LinkPayload | null): Promise<void> {
		await this.refreshCheckpoint();
		// A new device: the positions shard (by the leaf's prefix) is the only way.
		const pos = hint && hint.position >= 0 ? null : await this.mirror.position(this.config.registry, key.leaf, this.token());
		const known = hint?.position ?? -1;
		if (pos === null && known < 0) throw new IsoloirError('not_registered');
		key.position = pos ?? known;
		if (hint) for (const [id, p] of Object.entries(hint.polls)) key.polls[id] = { seq: p.seq, delta: p.delta };
		this.saveKey(key);
		this.store.remove(this.scanName);
		if (this.cp) writeJSON(this.store, this.cursorName, this.cp.index);
		this.registration = { state: 'verified' };
		this.ballot = { state: 'idle' };
		this.member = null;
		this.emit();
		void this.refresh();
	}

	private async adoptLinked(p: LinkPayload): Promise<void> {
		const key = this.newKey(p.secret, 'link');
		key.backups.linked = 1;
		if (p.words) {
			key.words = p.words;
			key.backups.words = true;
		}
		if (p.source === 'passkey') key.backups.passkey = true;
		await this.adopt(key, p);
	}

	/** Tells the sender the key was adopted (sealed for its reply key). */
	private async confirmLink(p: LinkPayload, code: string): Promise<void> {
		if (!p.reply) return;
		const leaf = this.core.leaf(this.config.registry, p.secret);
		let sealed: { sealed: string; code: string };
		try {
			sealed = this.core.linkSeal(p.reply, JSON.stringify({ v: 1, confirm: code, leaf } satisfies LinkConfirmation));
		} catch {
			return;
		}
		const event = this.signEvent(this.core.kinds.link, sealed.sealed, [['t', linkTag(p.reply)]]);
		for (const relay of this.relays()) await relay.publish(event).catch(() => undefined);
	}
}

/** Whether a register body is of the registry (and, given, of the leaf). */
function isLeaf(body: string, registry: number, leaf: string | null): boolean {
	try {
		const b = JSON.parse(body) as { registry?: number; id?: string };
		return b.registry === registry && (leaf === null || b.id === leaf);
	} catch {
		return false;
	}
}

function linkTag(receiverPublic: string): string {
	return `isoloir/1/link/${receiverPublic}`;
}

/** A field as bb.js writes a public input, in the core's spelling. */
function fieldHex(x: string): string {
	const h = x.startsWith('0x') ? x.slice(2) : BigInt(x).toString(16);
	return '0x' + h.toLowerCase().padStart(64, '0');
}
