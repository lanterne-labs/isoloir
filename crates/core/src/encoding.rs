//! Bytes in bodies: base64 (standard, padded) and SHA-256 in hex.

use crate::{Error, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

pub fn b64(b: &[u8]) -> String {
    STANDARD.encode(b)
}

/// Decodes base64 that must be in its one canonical spelling.
pub fn unb64(s: &str) -> Result<Vec<u8>> {
    let b = STANDARD.decode(s).map_err(|e| Error::Encoding(format!("base64: {e}")))?;
    if STANDARD.encode(&b) != s {
        return Err(Error::Encoding("base64: not canonical".into()));
    }
    Ok(b)
}

pub fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// `0x` + the hex of SHA-256: how a body's hash is written.
pub fn body_hash(b: &[u8]) -> String {
    format!("0x{}", hex::encode(sha256(b)))
}
