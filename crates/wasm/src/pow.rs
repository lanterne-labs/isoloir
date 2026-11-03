//! The proof of work of an envelope (SPEC §11.1): a tag
//! `["pow","<t>","<nonce>"]` such that
//! `SHA-256("isoloir/1/pow\n" ‖ origin ‖ "\n" ‖ pubkey ‖ "\n" ‖ t ‖ "\n" ‖ nonce)`
//! starts with `bits` zero bits. The work is bound to the envelope's key
//! and a time, never to its content, so a device does it before the body
//! exists. Nonces here are decimal counters (at most 20 characters).
//! The ingest checks with `isoloir_proto::pow`; this miner gives the same
//! hashes, from the SHA-256 state of the preimage's fixed prefix (about
//! six times faster than hashing it whole at every try).

use sha2::{Digest, Sha256};

/// The longest nonce the ingest takes (SPEC §11.1).
pub const MAX_NONCE: usize = 32;

fn prefix(origin: &str, pubkey: &str, t: u64) -> Sha256 {
    let mut h = Sha256::new();
    h.update(b"isoloir/1/pow\n");
    h.update(origin.as_bytes());
    h.update(b"\n");
    h.update(pubkey.as_bytes());
    h.update(b"\n");
    h.update(t.to_string().as_bytes());
    h.update(b"\n");
    h
}

/// The number of leading zero bits of a hash.
pub fn leading_zeros(h: &[u8]) -> u32 {
    let mut n = 0;
    for b in h {
        if *b == 0 {
            n += 8;
        } else {
            return n + b.leading_zeros();
        }
    }
    n
}

/// The work's hash of a nonce.
pub fn hash(origin: &str, pubkey: &str, t: u64, nonce: &str) -> [u8; 32] {
    let mut h = prefix(origin, pubkey, t);
    h.update(nonce.as_bytes());
    h.finalize().into()
}

/// Whether a nonce does the work, as the ingest checks it
/// (`isoloir_proto::pow`): 1 to 32 ASCII characters, a hash with `bits`
/// leading zero bits. The time window is the caller's.
pub fn check(origin: &str, pubkey: &str, t: u64, nonce: &str, bits: u32) -> bool {
    !nonce.is_empty() && nonce.len() <= MAX_NONCE && nonce.is_ascii() && isoloir_proto::pow::zeros(&isoloir_proto::pow::work(origin, pubkey, t, nonce)) >= bits
}

/// Tries the nonces `start` … `start + count − 1` (decimal); the first
/// that does the work, or None. A caller mines in slices of `count`, so
/// a page never blocks for long.
pub fn mine(origin: &str, pubkey: &str, t: u64, bits: u32, start: u64, count: u32) -> Option<String> {
    let base = prefix(origin, pubkey, t);
    let mut buf = itoa_buf();
    for n in start..start.saturating_add(count as u64) {
        let s = itoa(n, &mut buf);
        let mut h = base.clone();
        h.update(s);
        let d: [u8; 32] = h.finalize().into();
        if leading_zeros(&d) >= bits {
            return Some(String::from_utf8(s.to_vec()).expect("ascii"));
        }
    }
    None
}

fn itoa_buf() -> [u8; 20] {
    [0u8; 20]
}

fn itoa(mut n: u64, buf: &mut [u8; 20]) -> &[u8] {
    let mut i = buf.len();
    loop {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    &buf[i..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mined_nonces_check() {
        let pk = "ab".repeat(32);
        let n = mine("vote.example/isoloir", &pk, 1_761_900_000, 12, 0, 1 << 20).expect("a nonce");
        assert!(check("vote.example/isoloir", &pk, 1_761_900_000, &n, 12));
        assert!(leading_zeros(&hash("vote.example/isoloir", &pk, 1_761_900_000, &n)) >= 12);
        // Bound to the key, the time and the origin.
        let other = "cd".repeat(32);
        let bound = [
            check("vote.example/isoloir", &other, 1_761_900_000, &n, 12),
            check("vote.example/isoloir", &pk, 1_761_900_001, &n, 12),
            check("other/isoloir", &pk, 1_761_900_000, &n, 12),
        ];
        assert!(bound.iter().filter(|b| **b).count() <= 1, "a 12-bit nonce rarely holds elsewhere");
        assert!(check("x", &pk, 1, "anything", 0));
        // The ingest's own check takes it, at its time.
        let tag = vec!["pow".to_string(), "1761900000".into(), n.clone()];
        assert_eq!(isoloir_proto::pow::check("vote.example/isoloir", &pk, &tag, 12, 1_761_900_000), Some(1_761_900_000));
        assert!(!check("x", &pk, 1, &"9".repeat(33), 0));
    }

    #[test]
    fn the_preimage_is_the_specs() {
        let pk = "ab".repeat(32);
        let want: [u8; 32] = Sha256::digest(format!("isoloir/1/pow\nvote.example/isoloir\n{pk}\n1761900000\n42").as_bytes()).into();
        assert_eq!(hash("vote.example/isoloir", &pk, 1_761_900_000, "42"), want);
        assert_eq!(isoloir_proto::pow::work("vote.example/isoloir", &pk, 1_761_900_000, "42"), want);
        assert_eq!(itoa(0, &mut itoa_buf()), b"0");
        assert_eq!(itoa(u64::MAX, &mut itoa_buf()), u64::MAX.to_string().as_bytes());
        assert_eq!(leading_zeros(&[0, 0x10]), 11);
    }
}
