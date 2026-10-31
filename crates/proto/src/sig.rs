//! Signatures in bodies: the registration key's BIP340 signature (SPEC
//! §6), the decrypter's Ed25519 signature on a tally (SPEC §10.3), and
//! Nostr events (SPEC §11.1), which the browser and the server both make
//! and check.

use isoloir_core::{canonical, encoding, field, poseidon2, tags, Fr};
use k256::schnorr::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

const REGISTER_PREFIX: &[u8] = b"isoloir/1/register\n";
const TALLY_PREFIX: &[u8] = b"isoloir/1/tally\n";

fn prehash(prefix: &[u8], body_without_sig: &[u8]) -> [u8; 32] {
    let mut m = prefix.to_vec();
    m.extend_from_slice(body_without_sig);
    encoding::sha256(&m)
}

/// The custom data a passport proof binds for a registration key:
/// `H(T_reg, registry, key_lo, key_hi)`, hex.
pub fn registration_binding(registry: u32, key: &[u8; 32]) -> String {
    let (lo, hi) = field::limbs(key);
    field::to_hex(&poseidon2::hash(&[tags::reg(), Fr::from(registry as u64), lo, hi]))
}

/// Checks a registration body's signature under its key; returns the key.
pub fn verify_register(body: &[u8]) -> Result<[u8; 32], String> {
    let v = canonical::parse(body).map_err(|e| e.to_string())?;
    let key_hex = v.get("key").and_then(|k| k.as_str()).ok_or("no key")?;
    let sig_hex = v.get("sig").and_then(|k| k.as_str()).ok_or("no sig")?;
    let key: [u8; 32] = hex::decode(key_hex).ok().and_then(|b| b.try_into().ok()).ok_or("key: 32 bytes of hex")?;
    if hex::encode(key) != key_hex {
        return Err("key: lower-case hex".into());
    }
    let sig_bytes: [u8; 64] = hex::decode(sig_hex).ok().and_then(|b| b.try_into().ok()).ok_or("sig: 64 bytes of hex")?;
    if hex::encode(sig_bytes) != sig_hex {
        return Err("sig: lower-case hex".into());
    }
    let vk = VerifyingKey::from_bytes(&key).map_err(|_| "key: not a point")?;
    let sig = Signature::try_from(&sig_bytes[..]).map_err(|_| "sig: malformed")?;
    let msg = prehash(REGISTER_PREFIX, &canonical::without(body, "sig").map_err(|e| e.to_string())?);
    vk.verify_prehash(&msg, &sig).map_err(|_| "sig: does not verify")?;
    Ok(key)
}

/// Signs a registration body (without `sig`, with `key`): the browser's
/// part, also used by tests and tools. Returns the hex signature.
pub fn sign_register(sk: &[u8; 32], body_without_sig: &[u8]) -> String {
    let sk = SigningKey::from_bytes(sk).expect("a secp256k1 secret");
    let sig: Signature = sk.sign_prehash(&prehash(REGISTER_PREFIX, body_without_sig)).expect("signing");
    hex::encode(sig.to_bytes())
}

/// The x-only public key of a secp256k1 secret.
pub fn xonly(sk: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(sk).expect("a secp256k1 secret").verifying_key().to_bytes().into()
}

/// Signs a tally body (without `sig`) with the decrypter's Ed25519 seed.
pub fn sign_tally(seed: &[u8; 32], body_without_sig: &[u8]) -> String {
    use ed25519_dalek::Signer;
    let k = ed25519_dalek::SigningKey::from_bytes(seed);
    hex::encode(k.sign(&prehash(TALLY_PREFIX, body_without_sig)).to_bytes())
}

/// The Ed25519 public key of a seed, hex.
pub fn ed25519_public(seed: &[u8; 32]) -> String {
    hex::encode(ed25519_dalek::SigningKey::from_bytes(seed).verifying_key().to_bytes())
}

/// Checks a tally body's `sig` under the decrypter's key.
pub fn verify_tally(sign_key: &str, body: &[u8]) -> Result<(), String> {
    use ed25519_dalek::Verifier;
    let pk: [u8; 32] = hex::decode(sign_key).ok().and_then(|b| b.try_into().ok()).ok_or("sign_key")?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).map_err(|e| e.to_string())?;
    let v = canonical::parse(body).map_err(|e| e.to_string())?;
    let sig: [u8; 64] = v.get("sig").and_then(|s| s.as_str()).and_then(|s| hex::decode(s).ok()).and_then(|b| b.try_into().ok()).ok_or("sig")?;
    let msg = prehash(TALLY_PREFIX, &canonical::without(body, "sig").map_err(|e| e.to_string())?);
    vk.verify(&msg, &ed25519_dalek::Signature::from_bytes(&sig)).map_err(|_| "the tally's signature does not verify".to_string())
}

/// A Nostr event (NIP-01).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

/// The id of an event: SHA-256 of `[0, pubkey, created_at, kind, tags, content]`.
pub fn event_id(pubkey: &str, created_at: u64, kind: u32, tags: &[Vec<String>], content: &str) -> [u8; 32] {
    let serial = serde_json::to_string(&serde_json::json!([0, pubkey, created_at, kind, tags, content])).expect("json");
    encoding::sha256(serial.as_bytes())
}

impl Event {
    /// Signs an event with a secp256k1 secret.
    pub fn sign(sk: &[u8; 32], created_at: u64, kind: u32, tags: Vec<Vec<String>>, content: String) -> Event {
        let pubkey = hex::encode(xonly(sk));
        let id = event_id(&pubkey, created_at, kind, &tags, &content);
        let k = SigningKey::from_bytes(sk).expect("a secp256k1 secret");
        let sig: Signature = k.sign_prehash(&id).expect("signing");
        Event { id: hex::encode(id), pubkey, created_at, kind, tags, content, sig: hex::encode(sig.to_bytes()) }
    }

    /// Checks the id and the signature.
    pub fn verify(&self) -> bool {
        let id = event_id(&self.pubkey, self.created_at, self.kind, &self.tags, &self.content);
        if hex::encode(id) != self.id {
            return false;
        }
        let Some(pk) = hex::decode(&self.pubkey).ok().and_then(|b| <[u8; 32]>::try_from(b).ok()) else { return false };
        let Some(sig) = hex::decode(&self.sig).ok().and_then(|b| Signature::try_from(&b[..]).ok()) else { return false };
        VerifyingKey::from_bytes(&pk).map(|vk| vk.verify_prehash(&id, &sig).is_ok()).unwrap_or(false)
    }

    /// The first value of a tag.
    pub fn tag(&self, name: &str) -> Option<&str> {
        self.tags.iter().find(|t| t.first().map(String::as_str) == Some(name)).and_then(|t| t.get(1)).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_signature() {
        let sk = [0x11u8; 32];
        let key = hex::encode(xonly(&sk));
        let unsigned = format!(r#"{{"id":"0x01","key":"{key}","registry":1,"v":1}}"#);
        let sig = sign_register(&sk, unsigned.as_bytes());
        let body = format!(r#"{{"id":"0x01","key":"{key}","registry":1,"sig":"{sig}","v":1}}"#);
        assert_eq!(verify_register(body.as_bytes()).unwrap(), xonly(&sk));
        let forged = body.replace(r#""id":"0x01""#, r#""id":"0x02""#);
        assert!(verify_register(forged.as_bytes()).is_err());
    }

    #[test]
    fn events() {
        let e = Event::sign(&[0x22u8; 32], 1_761_900_000, 7101, vec![vec!["t".into(), "isoloir/1/x".into()]], "{}".into());
        assert!(e.verify());
        assert_eq!(e.tag("t"), Some("isoloir/1/x"));
        let mut bad = e.clone();
        bad.content = "{ }".into();
        assert!(!bad.verify());
    }

    #[test]
    fn tally_signature() {
        let seed = [5u8; 32];
        let unsigned = br#"{"poll":1,"v":1}"#;
        let sig = sign_tally(&seed, unsigned);
        let body = format!(r#"{{"poll":1,"sig":"{sig}","v":1}}"#);
        assert!(verify_tally(&ed25519_public(&seed), body.as_bytes()).is_ok());
        assert!(verify_tally(&ed25519_public(&[6u8; 32]), body.as_bytes()).is_err());
    }
}
