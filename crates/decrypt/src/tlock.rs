//! Time-locked ballots (SPEC §7.2): a blob is `len (2 bytes, big-endian)
//! ‖ tlock(key) ‖ ChaCha20-Poly1305(payload)` where `key` is 16 random
//! bytes time-locked to the poll's round with drand IBE (the `tlock`
//! crate), and the payload is sealed under `SHA-256("isoloir/1/tlock" ‖
//! key)` with a zero nonce (the key is used once).

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use isoloir_proto::body::{Beacon, Encryption};
use isoloir_proto::tally::Tlock;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

fn aead_key(key: &[u8; 16]) -> Key {
    let mut h = Sha256::new();
    h.update(b"isoloir/1/tlock");
    h.update(key);
    let k: [u8; 32] = h.finalize().into();
    Key::from(k)
}

/// The group key and round of a tlock poll.
pub fn params(e: &Encryption) -> Option<(Vec<u8>, u64)> {
    match e {
        Encryption::Tlock { public_key, round, .. } => Some((hex::decode(public_key).ok()?, *round)),
        _ => None,
    }
}

/// Seals a payload to a round.
pub fn seal<R: RngCore + CryptoRng>(public_key: &[u8], round: u64, payload: &[u8], rng: &mut R) -> Result<Vec<u8>, String> {
    let mut key = [0u8; 16];
    rng.fill_bytes(&mut key);
    let mut locked = vec![];
    tlock::encrypt(&mut locked, &key[..], public_key, round).map_err(|e| format!("tlock: {e}"))?;
    let sealed = ChaCha20Poly1305::new(&aead_key(&key)).encrypt(&Nonce::default(), payload).map_err(|e| format!("seal: {e}"))?;
    let len = u16::try_from(locked.len()).map_err(|_| "tlock ciphertext too long")?;
    let mut blob = len.to_be_bytes().to_vec();
    blob.extend_from_slice(&locked);
    blob.extend_from_slice(&sealed);
    Ok(blob)
}

/// Opens a blob with the round's beacon signature, or None.
pub fn open(signature: &[u8], blob: &[u8]) -> Option<Vec<u8>> {
    let len = u16::from_be_bytes(blob.get(..2)?.try_into().ok()?) as usize;
    let locked = blob.get(2..2 + len)?;
    let sealed = blob.get(2 + len..)?;
    // tlock panics (an assert) on a ciphertext that does not open, and
    // any voter writes their own blob: contain it.
    let key = std::panic::catch_unwind(|| {
        let mut key = vec![];
        tlock::decrypt(&mut key, locked, signature).ok().map(|_| key)
    })
    .ok()??;
    let mut key = key;
    // tlock strips trailing zero bytes from what it decrypts: put them back.
    if key.len() > 16 {
        return None;
    }
    key.resize(16, 0);
    let key: [u8; 16] = key.try_into().ok()?;
    ChaCha20Poly1305::new(&aead_key(&key)).decrypt(&Nonce::default(), sealed).ok()
}

/// The opener the judge and the auditor use.
pub struct DrandTlock;

impl Tlock for DrandTlock {
    fn verify_beacon(&self, encryption: &Encryption, beacon: &Beacon) -> bool {
        let Some((pk, round)) = params(encryption) else { return false };
        let Ok(sig) = hex::decode(&beacon.signature) else { return false };
        beacon.round == round && crate::bls::verify_round(&pk, round, &sig)
    }

    fn open(&self, beacon: &Beacon, blob: &[u8]) -> Option<Vec<u8>> {
        open(&hex::decode(&beacon.signature).ok()?, blob)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::TestChain;
    use rand::SeedableRng;

    #[test]
    fn seal_and_open() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        let chain = TestChain::new(3);
        for i in 0..20 {
            let payload = format!(r#"{{"salt":"0x{i:064x}","values":[1,0,0,0]}}"#);
            let blob = seal(&chain.public_key(), 100, payload.as_bytes(), &mut rng).unwrap();
            assert_eq!(open(&chain.sign(100), &blob).as_deref(), Some(payload.as_bytes()));
            assert_eq!(open(&chain.sign(101), &blob), None);
            let mut garbled = blob.clone();
            garbled[10] ^= 1;
            assert_eq!(open(&chain.sign(100), &garbled), None);
        }
    }
}
