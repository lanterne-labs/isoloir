//! The device link (SPEC §14): the voter's secret goes from a device that
//! holds it to a new one through a relay, end-to-end encrypted. The new
//! device shows an ephemeral secp256k1 public key; the old one seals the
//! payload for it with a fresh key of its own (ECDH, the x coordinate
//! hashed with a domain tag, XChaCha20-Poly1305). Both derive a six-digit
//! code from the shared key; the receiver adopts the payload only once the
//! voter confirms the code shown on the sender, so that whoever saw the
//! public key (or runs the relay) cannot push their own secret.
//!
//! Sealed: `sender public key (33, compressed) ‖ nonce (24) ‖ ciphertext`,
//! base64.

use crate::api::{err, R};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use isoloir_core::encoding;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use serde_json::json;

const KEY_TAG: &[u8] = b"isoloir/1/link";
const CODE_TAG: &[u8] = b"isoloir/1/link-code";

fn shared(sk: &SecretKey, pk: &PublicKey) -> [u8; 32] {
    let s = k256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    let mut m = KEY_TAG.to_vec();
    m.extend_from_slice(s.raw_secret_bytes());
    encoding::sha256(&m)
}

/// The six digits both devices show.
pub fn code(key: &[u8; 32]) -> String {
    let mut m = key.to_vec();
    m.extend_from_slice(CODE_TAG);
    let d = encoding::sha256(&m);
    let n = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
    format!("{:06}", n % 1_000_000)
}

fn public_hex(pk: &PublicKey) -> String {
    hex::encode(pk.to_encoded_point(true).as_bytes())
}

fn secret(hex_sk: &str) -> R<SecretKey> {
    let b = hex::decode(hex_sk).map_err(err)?;
    SecretKey::from_slice(&b).map_err(|_| "not a secp256k1 secret".to_string())
}

/// The receiver's ephemeral key: `{secret, public}` (public compressed).
pub fn receiver() -> String {
    let sk = SecretKey::random(&mut OsRng);
    json!({ "secret": hex::encode(sk.to_bytes()), "public": public_hex(&sk.public_key()) }).to_string()
}

/// Seals a payload for a receiver's public key: `{sealed, code}`.
pub fn seal(receiver_public: &str, payload: &str) -> R<String> {
    let pk = PublicKey::from_sec1_bytes(&hex::decode(receiver_public).map_err(err)?).map_err(|_| "not a public key".to_string())?;
    let sk = SecretKey::random(&mut OsRng);
    let key = shared(&sk, &pk);
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ct = XChaCha20Poly1305::new((&key).into()).encrypt(XNonce::from_slice(&nonce), payload.as_bytes()).map_err(|_| "seal".to_string())?;
    let mut out = sk.public_key().to_encoded_point(true).as_bytes().to_vec();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(json!({ "sealed": STANDARD.encode(out), "code": code(&key) }).to_string())
}

/// Opens a sealed payload with the receiver's secret: `{payload, code}`.
pub fn open(receiver_secret: &str, sealed: &str) -> R<String> {
    let sk = secret(receiver_secret)?;
    let raw = STANDARD.decode(sealed).map_err(err)?;
    if raw.len() < 33 + 24 + 16 {
        return Err("too short".into());
    }
    let pk = PublicKey::from_sec1_bytes(&raw[..33]).map_err(|_| "not a sender key".to_string())?;
    let key = shared(&sk, &pk);
    let plain = XChaCha20Poly1305::new((&key).into())
        .decrypt(XNonce::from_slice(&raw[33..57]), &raw[57..])
        .map_err(|_| "not sealed for this key".to_string())?;
    let payload = String::from_utf8(plain).map_err(err)?;
    Ok(json!({ "payload": payload, "code": code(&key) }).to_string())
}
