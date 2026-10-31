//! isoloir for the browser (SPEC §6, §9, §11, §14, §15): the voter's side
//! of the protocol compiled to WebAssembly. Every function takes and
//! returns strings (JSON, hex, base64) or bytes, and throws an `Error`
//! with a message on a refusal. `@isoloir/web` orchestrates; the rules
//! are all here, in the same Rust the ingest and the auditor run.

pub mod api;
#[cfg(feature = "dev")]
pub mod dev;
pub mod link;
pub mod results;
pub mod words;

/// The Nostr kinds of SPEC §11.1.
pub const KIND_REGISTER: u32 = 7100;
pub const KIND_BALLOT: u32 = 7101;
pub const KIND_ACK: u32 = 7102;
pub const KIND_CHECKPOINT: u32 = 7103;
pub const KIND_LINK: u32 = 7104;
pub const KIND_TALLY: u32 = 7105;
pub const KIND_COMPLAINT: u32 = 7106;

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

    #[wasm_bindgen]
    pub fn protocol() -> String {
        api::protocol()
    }

    /// The Nostr kinds: `{register, ballot, ack, checkpoint, link, tally, complaint}`.
    #[wasm_bindgen]
    pub fn kinds() -> String {
        serde_json::json!({
            "register": crate::KIND_REGISTER, "ballot": crate::KIND_BALLOT, "ack": crate::KIND_ACK,
            "checkpoint": crate::KIND_CHECKPOINT, "link": crate::KIND_LINK, "tally": crate::KIND_TALLY,
            "complaint": crate::KIND_COMPLAINT,
        })
        .to_string()
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
        pub fn dev_decrypter(seed: &str) -> Out {
            js(dev::decrypter(seed))
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
