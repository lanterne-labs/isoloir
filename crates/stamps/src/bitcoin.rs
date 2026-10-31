//! Verification of the Bitcoin attestations against block headers.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use crate::error::{Error, Result};
use crate::ots::{Attestation, Ots};

/// What verification needs of a block: its Merkle root, in the byte order
/// of the header (the order OpenTimestamps commits to: the reverse of the
/// hex the explorers show), and its time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeader {
    pub merkle_root: [u8; 32],
    pub time: u32,
}

impl BlockHeader {
    /// Reads an 80-byte serialized header: version(4) prev(32) merkle(32)
    /// time(4) bits(4) nonce(4).
    pub fn from_raw(raw: &[u8]) -> Option<BlockHeader> {
        if raw.len() != 80 {
            return None;
        }
        Some(BlockHeader {
            merkle_root: raw[36..68].try_into().ok()?,
            time: u32::from_le_bytes(raw[68..72].try_into().ok()?),
        })
    }
}

/// The block hash of a serialized header, as explorers show it.
pub fn block_hash(raw: &[u8]) -> String {
    let h = Sha256::digest(Sha256::digest(raw));
    let mut b = h.to_vec();
    b.reverse();
    hex::encode(b)
}

/// A source of Bitcoin block headers by height.
pub trait BlockHeaders {
    fn header(&self, height: u64) -> Result<BlockHeader>;
}

/// Checks a proof of `digest`: every Bitcoin attestation must attest the
/// Merkle root of its block. It returns the (height, block time) of each,
/// in the order of the file; a proof with no Bitcoin attestation (still
/// pending) is an error.
pub fn verify(ots: &Ots, digest: [u8; 32], headers: &dyn BlockHeaders) -> Result<Vec<(u64, u32)>> {
    if ots.digest != digest {
        return Err(Error::DigestMismatch {
            proof: hex::encode(ots.digest),
            expected: hex::encode(digest),
        });
    }
    let mut out = Vec::new();
    for a in ots.attestations() {
        let Attestation::Bitcoin { height } = *a.attestation else {
            continue;
        };
        let header = headers.header(height)?;
        if a.commitment != header.merkle_root {
            return Err(Error::MerkleRootMismatch {
                height,
                commitment: hex::encode(a.commitment),
                merkle_root: hex::encode(header.merkle_root),
            });
        }
        debug!(height, time = header.time, "Bitcoin attestation verified");
        out.push((height, header.time));
    }
    if out.is_empty() {
        return Err(Error::NoBitcoinAttestation);
    }
    Ok(out)
}

/// Block headers read from public Esplora instances (blockstream.info,
/// then mempool.space): the hash at the height, then the raw header (or,
/// failing that, the block's JSON, from which the header is rebuilt). The
/// header is checked against the block hash.
pub struct Esplora {
    agent: ureq::Agent,
    bases: Vec<String>,
    cache: Mutex<HashMap<u64, BlockHeader>>,
}

impl Default for Esplora {
    fn default() -> Self {
        Esplora::new(vec![
            "https://blockstream.info/api".into(),
            "https://mempool.space/api".into(),
        ])
    }
}

impl Esplora {
    /// Instances by their API base (e.g. `https://mempool.space/api`).
    pub fn new(bases: Vec<String>) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(20)))
            .http_status_as_error(false)
            .build()
            .into();
        Esplora {
            agent,
            bases,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn get(&self, url: &str) -> Result<String> {
        let err = |reason: String| Error::Http {
            url: url.to_string(),
            reason,
        };
        let mut resp = self.agent.get(url).call().map_err(|e| err(e.to_string()))?;
        let status = resp.status().as_u16();
        if status != 200 {
            return Err(err(format!("HTTP {status}")));
        }
        let body = resp
            .body_mut()
            .with_config()
            .limit(100_000)
            .read_to_string()
            .map_err(|e| err(e.to_string()))?;
        Ok(body.trim().to_string())
    }

    fn header_at(&self, base: &str, height: u64) -> Result<BlockHeader> {
        let bad = |reason: String| Error::BlockHeader { height, reason };
        let hash = self.get(&format!("{base}/block-height/{height}"))?;
        if hash.len() != 64 || hex::decode(&hash).is_err() {
            return Err(bad(format!("{base}: a block hash {hash:?}")));
        }
        let raw = match self.get(&format!("{base}/block/{hash}/header")) {
            Ok(h) => hex::decode(&h).map_err(|e| bad(format!("{base}: header: {e}")))?,
            Err(e) => {
                debug!(base, error = %e, "no raw header, reading the block");
                let json = self.get(&format!("{base}/block/{hash}"))?;
                header_from_json(&json).map_err(|r| bad(format!("{base}: {r}")))?
            }
        };
        if block_hash(&raw) != hash {
            return Err(bad(format!("{base}: the header does not hash to {hash}")));
        }
        BlockHeader::from_raw(&raw)
            .ok_or_else(|| bad(format!("{base}: a header of {} bytes", raw.len())))
    }
}

/// Rebuilds the 80-byte header from an Esplora block JSON.
pub(crate) fn header_from_json(json: &str) -> std::result::Result<Vec<u8>, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let num = |k: &str| v[k].as_u64().ok_or_else(|| format!("no {k}"));
    let hash = |k: &str| -> std::result::Result<Vec<u8>, String> {
        let s = v[k].as_str().ok_or_else(|| format!("no {k}"))?;
        let mut b = hex::decode(s).map_err(|e| format!("{k}: {e}"))?;
        if b.len() != 32 {
            return Err(format!("{k}: {} bytes", b.len()));
        }
        b.reverse();
        Ok(b)
    };
    let mut raw = Vec::with_capacity(80);
    raw.extend_from_slice(&(num("version")? as u32).to_le_bytes());
    // The genesis block has no previous block.
    match v["previousblockhash"].as_str() {
        Some(_) => raw.extend_from_slice(&hash("previousblockhash")?),
        None => raw.extend_from_slice(&[0; 32]),
    }
    raw.extend_from_slice(&hash("merkle_root")?);
    raw.extend_from_slice(&(num("timestamp")? as u32).to_le_bytes());
    raw.extend_from_slice(&(num("bits")? as u32).to_le_bytes());
    raw.extend_from_slice(&(num("nonce")? as u32).to_le_bytes());
    Ok(raw)
}

impl BlockHeaders for Esplora {
    fn header(&self, height: u64) -> Result<BlockHeader> {
        if let Some(h) = self.cache.lock().expect("cache lock").get(&height) {
            return Ok(*h);
        }
        let mut reasons = Vec::new();
        for base in &self.bases {
            match self.header_at(base, height) {
                Ok(h) => {
                    self.cache.lock().expect("cache lock").insert(height, h);
                    return Ok(h);
                }
                Err(e) => {
                    warn!(base = %base, height, error = %e, "block explorer failed");
                    reasons.push(e.to_string());
                }
            }
        }
        Err(Error::BlockHeader {
            height,
            reason: reasons.join("; "),
        })
    }
}
