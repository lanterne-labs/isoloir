// What went wrong, named: every failure the session meets carries a code
// the app translates, and a detail for the curious (never a secret).
//
// Codes of the session: not_ready, no_setup, log_key (the mirror's
// checkpoint does not verify under the pinned key), mirror, no_relay
// (no relay took the message), no_ack (relays took it, none answered),
// stale_proof (scan the passport again), not_registered, no_path (the
// mirror and the checkpoint disagree on the tree), previous_pending
// (a delta correction waits for its previous ballot in the tree),
// backup_required, bad_choice, prover, prover_mismatch, not_open, closed,
// passkey_cancelled, passkey_unsupported, passkey_noprf, passkey_failed,
// bad_words, link_expired, stopped. A refusal by the ingest is its reason
// (SPEC §12), prefixed `reg:` for registrations.

export class IsoloirError extends Error {
	constructor(
		readonly code: string,
		readonly detail = ''
	) {
		super(detail ? `${code}: ${detail}` : code);
		this.name = 'IsoloirError';
	}
}

export function toIsoloirError(e: unknown, fallback = 'unknown'): IsoloirError {
	if (e instanceof IsoloirError) return e;
	const msg = e instanceof Error ? e.message : String(e);
	return new IsoloirError(fallback, msg);
}
