//! The proof of work of an envelope (SPEC §11.1): bound to the envelope's
//! key and a time, not to its id, so that a device does it in advance,
//! while it proves the ballot.

use isoloir_core::encoding;

/// How far in the past and the future a work's time may be.
pub const PAST: u64 = 7_200;
pub const AHEAD: u64 = 300;

/// `SHA-256("isoloir/1/pow\n" ‖ origin ‖ "\n" ‖ pubkey ‖ "\n" ‖ t ‖ "\n" ‖ nonce)`.
pub fn work(origin: &str, pubkey: &str, t: u64, nonce: &str) -> [u8; 32] {
    encoding::sha256(format!("{}/pow\n{origin}\n{pubkey}\n{t}\n{nonce}", crate::PROTOCOL).as_bytes())
}

/// The leading zero bits of a hash.
pub fn zeros(h: &[u8]) -> u32 {
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

/// A nonce (decimal) for a key and a time.
pub fn solve(origin: &str, pubkey: &str, t: u64, bits: u32) -> String {
    (0u64..).map(|n| n.to_string()).find(|nonce| zeros(&work(origin, pubkey, t, nonce)) >= bits).expect("a nonce")
}

/// Checks a `pow` tag (`["pow", t, nonce]`) at time `now`; returns its time.
pub fn check(origin: &str, pubkey: &str, tag: &[String], bits: u32, now: u64) -> Option<u64> {
    let (t, nonce) = (tag.get(1)?, tag.get(2)?);
    let t: u64 = t.parse().ok().filter(|n: &u64| n.to_string() == *t)?;
    if nonce.is_empty() || nonce.len() > 32 || !nonce.is_ascii() || t + PAST < now || t > now + AHEAD {
        return None;
    }
    (zeros(&work(origin, pubkey, t, nonce)) >= bits).then_some(t)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solve_and_check() {
        let pk = "ab".repeat(32);
        let n = solve("o.example/isoloir", &pk, 1000, 10);
        let tag = vec!["pow".to_string(), "1000".into(), n.clone()];
        assert_eq!(check("o.example/isoloir", &pk, &tag, 10, 1000), Some(1000));
        assert_ne!(work("other/isoloir", &pk, 1000, &tag[2]), work("o.example/isoloir", &pk, 1000, &tag[2]));
        assert_eq!(check("o.example/isoloir", &pk, &tag, 10, 1000 + PAST + 1), None);
        assert_eq!(check("o.example/isoloir", &pk, &["pow".into(), "01000".into(), n], 10, 1000), None);
        assert_eq!(zeros(&[0, 0x10]), 11);
    }
}
