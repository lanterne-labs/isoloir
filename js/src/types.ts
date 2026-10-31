// The protocol's shapes as the browser reads them (SPEC.md). The bodies
// are checked by the wasm core; these types only name their fields.

export type Hex = string;

/**
 * A way to the ingest (SPEC §11.1): a Nostr relay (ws:// or wss://) or the
 * ingest's own HTTP endpoint ("direct"). Retired channels are read, not
 * written.
 */
export interface Channel {
	type: 'nostr' | 'direct';
	url: string;
	state: 'active' | 'retired';
}

/** The `ledger` entry (SPEC §4.1). */
export interface LedgerSetup {
	v: 1;
	version: number;
	origin: string;
	log_key: string;
	ingest: string;
	channels: Channel[];
	checkpoint_period: number;
	anchor_age: number;
}

export interface Eligibility {
	provider: string;
	domain: string;
	scope: string;
	min_age?: number;
	nationality?: string[];
	document_type?: string;
	require_expiry?: boolean;
}

/** The `registry` entry (SPEC §5). */
export interface RegistrySetup {
	v: 1;
	id: number;
	version: number;
	name: string;
	eligibility: Eligibility;
	validity: number;
	depth: number;
}

export type KindSpec =
	| { type: 'choice'; options: string[]; blank: boolean }
	| { type: 'ranked'; options: string[]; blank: boolean; depth: number; margins: boolean };

export type Encryption =
	| { mode: 'elgamal'; pk: Hex; authority: { type: 'single'; sign_key: string } }
	| { mode: 'tlock'; chain: string; public_key: string; period: number; genesis: number; round: number };

export type Publish = { mode: 'open'; k_real: number; min_gap: number; coin: boolean } | { mode: 'closed' };

export type Revote = 'none' | 'linked' | 'delta';

/** The `poll` entry (SPEC §7). */
export interface PollSetup {
	v: 1;
	id: number;
	version: number;
	registry: number;
	title: string;
	kind: KindSpec;
	encryption: Encryption;
	publish: Publish;
	revote: Revote;
	opens: number;
	closes: number;
	blackouts?: { from: number; to: number }[];
	circuit: { name: string; vk_hash: string };
	ballot_depth?: number;
}

/** A logged entry as the mirror serves it, with its inclusion proof in checkpoint `checkpoint`'s log. */
export interface Logged {
	seq: number;
	/** The body's text, as logged. */
	body: string;
	checkpoint: number;
	/** The log size the proof is for: the checkpoint's. */
	size: number;
	/** The RFC 6962 inclusion proof, 64 hex digits per hash. */
	path: string[];
}

/** A setup proven in the log: the body, the seq of its entry, the checkpoint that proves it. */
export interface Setup<T> {
	seq: number;
	body: T;
	/** The body's canonical text (what the log holds). */
	text: string;
	checkpoint: number;
}

/** A voter's choice: one slot or none (single choice), or a ranking. */
export type Choice = { pick: number | null } | { rank: number[] };

export interface Variant {
	name: string;
	family: 'choice' | 'ranked' | 'rankedm';
	slots: number;
	enc: 'elgamal' | 'tlock';
	chain: 'linked' | 'delta';
	depth: number;
	ballot_depth: number | null;
	values: number;
	chunks: number;
}

/** What a page needs to show a poll's ballot. */
export interface KindInfo {
	class: 'single' | 'multiple';
	slots: number;
	mask: number;
	options: string[];
	blank: boolean;
	blank_slot: number | null;
	rank_depth: number;
	revote: Revote;
	variant: Variant;
}

/** A verified checkpoint (SPEC §4). */
export interface Checkpoint {
	origin: string;
	size: number;
	root: string;
	index: number;
	time: number;
	registries: { id: number; size: number; root: Hex }[];
	ballots: { poll: number; size: number; root: Hex }[];
	mirror: string | null;
}

/** A Nostr event (NIP-01). */
export interface NostrEvent {
	id: string;
	pubkey: string;
	created_at: number;
	kind: number;
	tags: string[][];
	content: string;
	sig: string;
}

/** An acknowledgement (SPEC §11.2). */
export interface Ack {
	v: 1;
	of: string;
	hash: Hex;
	outcome: 'accepted' | 'rejected';
	reason?: string;
	checkpoint?: number;
}

/** One entry of a checkpoint on the mirror (SPEC §15). */
export interface Entry {
	seq: number;
	kind: string;
	/** The body exactly as logged. */
	body: string;
}

export interface ChoiceResults {
	type: 'choice';
	counted: number;
	slots: { slot: number; label: string | null; blank: boolean; count: number }[];
	blank: number | null;
	/** voters (none, linked: one counted ballot each) or corrections (delta: `counted` counts corrections). */
	ballots: 'voters' | 'corrections';
	/** Counted ballots that pick no slot (withdrawals); null in delta polls, where it is unknown. */
	none: number | null;
}

export interface RankedResults {
	type: 'ranked';
	counted: number;
	ballots: 'voters' | 'corrections';
	slots: { slot: number; label: string | null; blank: boolean; first: number; ranked: number }[];
	/** margins[i][j]: ballots ranking i before j minus those ranking j before i. */
	margins?: number[][];
	condorcet?: number | null;
}

export type Results = ChoiceResults | RankedResults;

/** A tally as the wasm core verified it. */
export interface TallyVerdict {
	ok: boolean;
	/** shares: signature, decryption proofs and values (ElGamal); beacon: the drand beacon only (tlock). */
	checked: 'shares' | 'beacon';
	/** tlock: whether the beacon is the round's (ok stays false: the openings are an auditor's to check). */
	beacon_ok: boolean;
	error: string | null;
	tally: {
		v: 1;
		poll: number;
		upto: number;
		final: boolean;
		values: number[];
		counted: number;
		checkpoint?: number;
		void?: number[];
	};
	results: Results;
}

/** A ballot drafted by the wasm core: the body without its proof, the circuit's inputs. */
export interface Draft {
	body: Record<string, unknown>;
	inputs: Record<string, unknown>;
	circuit: string;
}

/** What the passport app returns to the session (SPEC §6). */
export interface PassportProof {
	uid: string;
	proof: unknown;
	/** Unix seconds. */
	proofDate: number;
}

/** What the passport request binds (SPEC §6, step 1). */
export interface RegistrationRequest {
	registry: number;
	customData: Hex;
	domain: string;
	scope: string;
	eligibility: Eligibility;
	validity: number;
	/** The registration key's x-only public key (informative). */
	key: string;
}
