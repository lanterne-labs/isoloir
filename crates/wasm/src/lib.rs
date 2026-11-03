//! isoloir for the browser (SPEC §6, §9, §11, §14, §15): the voter's side
//! of the protocol compiled to WebAssembly. Every function takes and
//! returns strings (JSON, hex, base64) or bytes, and throws an `Error`
//! with a message on a refusal. `@isoloir/web` orchestrates; the rules
//! are all here, in the same Rust the ingest and the auditor run.

pub mod api;
pub mod audit;
#[cfg(feature = "dev")]
pub mod dev;
pub mod link;
pub mod pow;
pub mod results;
pub mod words;

/// The Nostr kinds of SPEC §11.1: ephemeral (NIP-16), relays keep none.
pub const KIND_REGISTER: u32 = 27100;
pub const KIND_BALLOT: u32 = 27101;
pub const KIND_ACK: u32 = 27102;
pub const KIND_CHECKPOINT: u32 = 27103;
pub const KIND_LINK: u32 = 27104;
pub const KIND_TALLY: u32 = 27105;
pub const KIND_COMPLAINT: u32 = 27106;
/// The kinds of clients written before (7100–7106, stored by relays): an
/// ingest of this version still reads them and answers in the same range.
pub const LEGACY_OFFSET: u32 = 20000;

/// Whether `k` is `kind` in either range.
pub fn is_kind(k: u32, kind: u32) -> bool {
    k == kind || k + LEGACY_OFFSET == kind
}

mod bind {
    use crate::{api, link, words};
    use wasm_bindgen::prelude::*;

    type Out = Result<String, JsError>;

    fn js(r: api::R<String>) -> Out {
        r.map_err(|e| JsError::new(&e))
    }

    fn u64_of(x: f64, what: &str) -> Result<u64, JsError> {
        if x.is_finite() && x >= 0.0 && x.fract() == 0.0 && x <= 9_007_199_254_740_991.0 {
            Ok(x as u64)
        } else {
            Err(JsError::new(&format!("{what}: a non-negative integer")))
        }
    }

    // The audit (audit.rs): runs kept by id between calls.
    thread_local! {
        static RUNS: std::cell::RefCell<(u32, std::collections::HashMap<u32, crate::audit::Run>)> = Default::default();
    }

    /// Starts an audit pass; `log_key` "" for the key the log names;
    /// `allow_dev` accepts the dev passport provider (local trials). Returns its id.
    #[wasm_bindgen]
    pub fn audit_start(log_key: &str, verdicts_json: &str, allow_dev: bool) -> Result<u32, JsError> {
        let run = crate::audit::Run::new((!log_key.is_empty()).then_some(log_key), verdicts_json, allow_dev).map_err(|e| JsError::new(&e))?;
        Ok(RUNS.with(|r| {
            let mut r = r.borrow_mut();
            r.0 += 1;
            let id = r.0;
            r.1.insert(id, run);
            id
        }))
    }

    fn with_run<T>(id: u32, f: impl FnOnce(&mut crate::audit::Run) -> api::R<T>) -> Result<T, JsError> {
        RUNS.with(|r| match r.borrow_mut().1.get_mut(&id) {
            Some(run) => f(run).map_err(|e| JsError::new(&e)),
            None => Err(JsError::new(&format!("no audit {id}"))),
        })
    }

    /// Feeds one checkpoint (its signed note, its entries file).
    #[wasm_bindgen]
    pub fn audit_checkpoint(id: u32, note: &str, entries_json: &str) -> Out {
        with_run(id, |run| run.checkpoint(note, entries_json))
    }

    /// Ends the pass: the report.
    #[wasm_bindgen]
    pub fn audit_finish(id: u32) -> Out {
        with_run(id, |run| run.finish())
    }

    /// A pass that only builds the state (no request for the logged proofs).
    #[wasm_bindgen]
    pub fn audit_quiet(id: u32, on: bool) -> Result<(), JsError> {
        with_run(id, |run| {
            run.quiet(on);
            Ok(())
        })
    }

    /// More verdicts for a pass (the answers to a rejudge's requests).
    #[wasm_bindgen]
    pub fn audit_answer(id: u32, verdicts_json: &str) -> Result<(), JsError> {
        with_run(id, |run| run.answer(verdicts_json))
    }

    /// Judges a message again against the state fed so far (a complaint of a refusal).
    #[wasm_bindgen]
    pub fn audit_rejudge(id: u32, kind: &str, body: &str, times_json: &str, pending_json: &str) -> Out {
        with_run(id, |run| run.rejudge(kind, body, times_json, pending_json))
    }

    /// Reads a complaint, its event or its body (SPEC §11.3).
    #[wasm_bindgen]
    pub fn read_complaint(text: &str, ingest_keys_json: &str) -> Out {
        js(api::read_complaint(text, ingest_keys_json))
    }

    /// Forgets a pass.
    #[wasm_bindgen]
    pub fn audit_drop(id: u32) {
        RUNS.with(|r| {
            r.borrow_mut().1.remove(&id);
        });
    }

    #[wasm_bindgen]
    pub fn protocol() -> String {
        api::protocol()
    }

    /// The Nostr kinds: `{register, ballot, ack, checkpoint, link, tally,
    /// complaint}` (ephemeral) and `legacy`, the same names in 7100–7106.
    #[wasm_bindgen]
    pub fn kinds() -> String {
        let set = |o: u32| {
            serde_json::json!({
                "register": crate::KIND_REGISTER - o, "ballot": crate::KIND_BALLOT - o, "ack": crate::KIND_ACK - o,
                "checkpoint": crate::KIND_CHECKPOINT - o, "link": crate::KIND_LINK - o, "tally": crate::KIND_TALLY - o,
                "complaint": crate::KIND_COMPLAINT - o,
            })
        };
        let mut k = set(0);
        k["legacy"] = set(crate::LEGACY_OFFSET);
        k.to_string()
    }

    /// The first nonce in `start … start + count − 1` whose work has `bits`
    /// leading zero bits (SPEC §11.1), or "" when none does.
    #[wasm_bindgen]
    pub fn pow_mine(origin: &str, pubkey: &str, t: f64, bits: u32, start: f64, count: u32) -> Result<String, JsError> {
        Ok(crate::pow::mine(origin, pubkey, u64_of(t, "t")?, bits, u64_of(start, "start")?, count).unwrap_or_default())
    }

    /// Whether a nonce does the work of `bits` bits for a key and a time.
    #[wasm_bindgen]
    pub fn pow_check(origin: &str, pubkey: &str, t: f64, nonce: &str, bits: u32) -> Result<bool, JsError> {
        Ok(crate::pow::check(origin, pubkey, u64_of(t, "t")?, nonce, bits))
    }

    #[wasm_bindgen]
    pub fn canonical(json: &str) -> Out {
        js(api::canonical(json))
    }

    #[wasm_bindgen]
    pub fn body_hash(body: &str) -> String {
        api::body_hash(body)
    }

    #[wasm_bindgen]
    pub fn decode_body(kind: &str, text: &str) -> Out {
        js(api::decode_body(kind, text))
    }

    #[wasm_bindgen]
    pub fn leaf(registry: u32, s: &str) -> Out {
        js(api::leaf(registry, s))
    }

    #[wasm_bindgen]
    pub fn nullifier(poll: u32, s: &str) -> Out {
        js(api::nullifier(poll, s))
    }

    #[wasm_bindgen]
    pub fn ident(poll: u32, s: &str, i: u32) -> Out {
        js(api::ident(poll, s, i))
    }

    #[wasm_bindgen]
    pub fn delta_leaf(ident: &str, cmt: &str) -> Out {
        js(api::delta_leaf(ident, cmt))
    }

    #[wasm_bindgen]
    pub fn secret_from_prf(prf_hex: &str) -> Out {
        js(api::secret_from_prf(prf_hex))
    }

    #[wasm_bindgen]
    pub fn new_words(lang: &str) -> Out {
        js(words::new_words(lang))
    }

    #[wasm_bindgen]
    pub fn normalize_words(words: &str, lang: &str) -> Out {
        js(words::normalize_words(words, lang))
    }

    #[wasm_bindgen]
    pub fn secret_from_words(words: &str, lang: &str) -> Out {
        js(words::secret_from_words(words, lang))
    }

    #[wasm_bindgen]
    pub fn check_words(words: &str, lang: &str) -> Out {
        js(words::check_words(words, lang))
    }

    /// One word in the list's spelling, or an empty string when it is not on the list.
    #[wasm_bindgen]
    pub fn canonical_word(word: &str, lang: &str) -> Out {
        js(words::canonical_word(word, lang).map(|w| w.unwrap_or_default()))
    }

    #[wasm_bindgen]
    pub fn verify_logged(seq: f64, kind: &str, body: &str, path_json: &str, size: f64, root_b64: &str) -> Result<bool, JsError> {
        api::verify_logged(u64_of(seq, "seq")?, kind, body, path_json, u64_of(size, "size")?, root_b64).map_err(|e| JsError::new(&e))
    }

    #[wasm_bindgen]
    pub fn relay_ranking(s: &str, urls_json: &str) -> Out {
        js(api::relay_ranking(s, urls_json))
    }

    #[wasm_bindgen]
    pub fn new_reg_secret() -> String {
        api::new_reg_secret()
    }

    #[wasm_bindgen]
    pub fn reg_pubkey(sk_hex: &str) -> Out {
        js(api::reg_pubkey(sk_hex))
    }

    #[wasm_bindgen]
    pub fn registration_binding(registry: u32, pubkey_hex: &str) -> Out {
        js(api::registration_binding(registry, pubkey_hex))
    }

    #[wasm_bindgen]
    pub fn register_body(req_json: &str) -> Out {
        js(api::register_body(req_json))
    }

    #[wasm_bindgen]
    pub fn verify_register(body: &str) -> Out {
        js(api::verify_register(body))
    }

    #[wasm_bindgen]
    pub fn kind_info(poll_json: &str) -> Out {
        js(api::kind_info(poll_json))
    }

    #[wasm_bindgen]
    pub fn choice_values(poll_json: &str, choice_json: &str) -> Out {
        js(api::choice_values(poll_json, choice_json))
    }

    #[wasm_bindgen]
    pub fn draft_ballot(req_json: &str) -> Out {
        js(api::draft_ballot(req_json))
    }

    #[wasm_bindgen]
    pub fn finish_ballot(draft_body_json: &str, proof: &[u8]) -> Out {
        js(api::finish_ballot(draft_body_json, proof))
    }

    #[wasm_bindgen]
    pub fn public_inputs(body: &str, poll_json: &str) -> Out {
        js(api::public_inputs(body, poll_json))
    }

    #[wasm_bindgen]
    pub fn delta_recover(poll_json: &str, s: &str, leaves_json: &str) -> Out {
        js(api::delta_recover(poll_json, s, leaves_json))
    }

    #[wasm_bindgen]
    pub fn tree_root(depth: u32, leaves_json: &str) -> Out {
        js(api::tree_root(depth, leaves_json))
    }

    #[wasm_bindgen]
    pub fn tree_path(depth: u32, leaves_json: &str, position: u32) -> Out {
        js(api::tree_path(depth, leaves_json, position))
    }

    #[wasm_bindgen]
    pub fn root_of(leaf: &str, position: u32, path_json: &str) -> Out {
        js(api::root_of(leaf, position, path_json))
    }

    #[wasm_bindgen]
    pub fn verify_note(note: &str, verifier_key: &str) -> Out {
        js(api::verify_note(note, verifier_key))
    }

    #[wasm_bindgen]
    pub fn sign_event(sk_hex: &str, created_at: f64, kind: u32, tags_json: &str, content: &str) -> Out {
        js(api::sign_event(sk_hex, u64_of(created_at, "created_at")?, kind, tags_json, content))
    }

    #[wasm_bindgen]
    pub fn verify_event(event_json: &str) -> bool {
        api::verify_event(event_json)
    }

    #[wasm_bindgen]
    pub fn decode_ack(content: &str) -> Out {
        js(api::decode_ack(content))
    }

    #[wasm_bindgen]
    pub fn read_ack(event_json: &str, ingest_pubkey: &str) -> Out {
        js(api::read_ack(event_json, ingest_pubkey))
    }

    #[wasm_bindgen]
    pub fn complaint_body(ack_event_json: &str, body: &str) -> Out {
        js(api::complaint_body(ack_event_json, body))
    }

    #[wasm_bindgen]
    pub fn verify_tally(poll_json: &str, tally: &str) -> Out {
        js(api::verify_tally(poll_json, tally))
    }

    #[wasm_bindgen]
    pub fn tally_results(poll_json: &str, values_json: &str, counted: f64) -> Out {
        js(api::tally_results(poll_json, values_json, u64_of(counted, "counted")?))
    }

    #[wasm_bindgen]
    pub fn aggregate(cts_json: &str) -> Out {
        js(api::aggregate(cts_json))
    }

    #[wasm_bindgen]
    pub fn link_receiver() -> String {
        link::receiver()
    }

    #[wasm_bindgen]
    pub fn link_seal(receiver_public: &str, payload: &str) -> Out {
        js(link::seal(receiver_public, payload))
    }

    #[wasm_bindgen]
    pub fn link_open(receiver_secret: &str, sealed: &str) -> Out {
        js(link::open(receiver_secret, sealed))
    }

    #[cfg(feature = "dev")]
    mod dev_bind {
        use super::*;
        use crate::dev;

        #[wasm_bindgen]
        pub fn dev_verifier(seed: &str, origin: &str) -> Out {
            js(dev::verifier(seed, origin))
        }

        #[wasm_bindgen]
        pub fn dev_sign_checkpoint(seed: &str, checkpoint_json: &str) -> Out {
            js(dev::sign_checkpoint(seed, checkpoint_json))
        }

        #[wasm_bindgen]
        pub fn dev_authority(seed: &str) -> Out {
            js(dev::authority(seed))
        }

        #[wasm_bindgen]
        pub fn dev_ed25519_public(seed: &str) -> Out {
            js(dev::ed25519_public(seed))
        }

        #[wasm_bindgen]
        pub fn dev_tlock_chain(seed: u32, round: u32) -> String {
            dev::tlock_chain(seed, round)
        }

        #[wasm_bindgen]
        pub fn dev_tlock_open(signature: &str, blob: &str) -> Out {
            js(dev::tlock_open(signature, blob))
        }

        #[wasm_bindgen]
        pub fn dev_log_proof(entries_json: &str, i: u32, n: u32) -> Out {
            js(dev::log_proof(entries_json, i, n))
        }

        #[wasm_bindgen]
        pub fn dev_build_tally(req_json: &str) -> Out {
            js(dev::build_tally(req_json))
        }
    }
}

#[cfg(test)]
mod tests;
