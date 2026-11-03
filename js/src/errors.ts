// What went wrong, named: every failure the session meets carries a code
// the app translates, a detail for the curious (never a secret), and for
// some codes structured data (the positions of wrong words).

/** The ingest's reasons (SPEC §12), in acks. */
export type IngestReason =
	| 'malformed'
	| 'version'
	| 'unknown'
	| 'not_open'
	| 'closed'
	| 'bad_sig'
	| 'stale_date'
	| 'uid_used'
	| 'id_used'
	| 'full'
	| 'bad_proof'
	| 'old_root'
	| 'revote_off'
	| 'stale_seq'
	| 'seq_gap'
	/** A re-vote within the ledger's revote_gap of the pseudonym's newest ballot (SPEC §7.4): data.retryAt, data.waitSeconds. */
	| 'too_soon'
	| 'duplicate'
	| 'not_due'
	| 'bad_tally'
	| 'bad_setup'
	| 'rejected';

/** The session's own codes. */
export type SessionErrorCode =
	/** Called before init(), or without what the call needs. */
	| 'not_ready'
	/** The mirror has no usable setup (missing, malformed, of another origin). */
	| 'no_setup'
	/** A setup or a tally the mirror serves is not proven in the signed log. */
	| 'unproven'
	/** A checkpoint does not verify under the pinned key, or the ledger names another log key. */
	| 'log_key'
	/** The mirror cannot be read (network, HTTP, timeout). */
	| 'mirror'
	/** The newest checkpoint is older than 30 minutes: no ballot is drafted against it. */
	| 'stale_mirror'
	/** No channel took the message. */
	| 'no_relay'
	/** Channels took it, none acknowledged it. */
	| 'no_ack'
	/** The proof of work of an envelope could not be made (SPEC §11.1). */
	| 'pow'
	/** The scanned proof is too old: scan again (the same registration key). */
	| 'stale_proof'
	| 'not_registered'
	/** The mirror and the checkpoint disagree on a tree. */
	| 'no_path'
	/** A delta correction waits for its previous ballot in the ballot tree. */
	| 'previous_pending'
	/** No registration and no ballot before a backup is confirmed. */
	| 'backup_required'
	| 'bad_choice'
	| 'prover'
	| 'prover_mismatch'
	/** A file the prover pins (the SRS, bb.js's wasm) is not the one pinned: its SHA-256 differs (data: url, expected, actual). */
	| 'pin_mismatch'
	/** A ballot waits for its ack: resend or discard it first. */
	| 'pending'
	| 'cast_retries'
	| 'key_exists'
	| 'passkey_cancelled'
	| 'passkey_unsupported'
	| 'passkey_noprf'
	/** The passkey is not synced (backup state 0): it is no backup, use the words. */
	| 'passkey_not_backed_up'
	| 'passkey_failed'
	/** Words not on the list (data.unknown: 1-based positions), not twelve, or a bad checksum. */
	| 'bad_words'
	/** The ledger has no Nostr relay: no device link. */
	| 'link_unavailable'
	/** A device link code that is not a public key. */
	| 'bad_link_key'
	| 'link_expired'
	| 'stopped';

export type IsoloirErrorCode = SessionErrorCode | IngestReason | `reg:${IngestReason}`;

export class IsoloirError extends Error {
	constructor(
		readonly code: IsoloirErrorCode,
		readonly detail = '',
		readonly data?: Record<string, unknown>
	) {
		super(detail ? `${code}: ${detail}` : code);
		this.name = 'IsoloirError';
	}
}

export function toIsoloirError(e: unknown, fallback: IsoloirErrorCode = 'unknown'): IsoloirError {
	if (e instanceof IsoloirError) return e;
	const msg = e instanceof Error ? e.message : String(e);
	return new IsoloirError(fallback, msg);
}

const REASONS: readonly string[] = ['malformed', 'version', 'unknown', 'not_open', 'closed', 'bad_sig', 'stale_date', 'uid_used', 'id_used', 'full', 'bad_proof', 'old_root', 'revote_off', 'stale_seq', 'seq_gap', 'too_soon', 'duplicate', 'not_due', 'bad_tally', 'bad_setup', 'rejected'];

/** An ack's reason as a code (an unknown one is 'rejected'). */
export function reasonOf(r: string | undefined): IngestReason {
	return (r && REASONS.includes(r) ? r : 'rejected') as IngestReason;
}
