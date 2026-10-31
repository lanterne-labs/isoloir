//! The BN254 scalar field F and its encodings (SPEC §3).

use crate::{Error, Result};
use ark_ff::{BigInteger, PrimeField};

/// An element of F, the BN254 scalar field (Grumpkin's base field).
pub type Fr = ark_bn254::Fr;

/// The `0x` + 64 lower-case hex digits of an element.
pub fn to_hex(x: &Fr) -> String {
    format!("0x{}", hex::encode(to_bytes(x)))
}

/// The 32 big-endian bytes of an element.
pub fn to_bytes(x: &Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&x.into_bigint().to_bytes_be());
    out
}

/// Parses `0x` + 64 lower-case hex digits of a value below r: one element
/// has one spelling, so the strings can key pseudonyms and leaves.
pub fn from_hex(s: &str) -> Result<Fr> {
    let b = hex32(s)?;
    from_bytes_strict(&b).ok_or_else(|| Error::Encoding(format!("field element {s}: not below the field order")))
}

/// The element of 32 big-endian bytes, when below r.
pub fn from_bytes_strict(b: &[u8; 32]) -> Option<Fr> {
    let x = Fr::from_be_bytes_mod_order(b);
    (to_bytes(&x) == *b).then_some(x)
}

/// The element of big-endian bytes reduced modulo r.
pub fn from_bytes_mod(b: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(b)
}

/// The element of a signed integer (negative as r − |x|).
pub fn from_i64(x: i64) -> Fr {
    if x >= 0 { Fr::from(x as u64) } else { -Fr::from(x.unsigned_abs()) }
}

/// The signed integer an element stands for, when within ±2^62.
pub fn to_i64(x: &Fr) -> Option<i64> {
    let small = |y: &Fr| -> Option<u64> {
        let b = y.into_bigint();
        let limbs = b.as_ref();
        (limbs[1..].iter().all(|l| *l == 0) && limbs[0] < (1 << 62)).then_some(limbs[0])
    };
    if let Some(v) = small(x) {
        return Some(v as i64);
    }
    small(&-*x).map(|v| -(v as i64))
}

/// Parses `0x` + 64 lower-case hex digits into 32 bytes.
pub fn hex32(s: &str) -> Result<[u8; 32]> {
    let digits = s.strip_prefix("0x").ok_or_else(|| Error::Encoding(format!("{s}: no 0x prefix")))?;
    if digits.len() != 64 || digits.bytes().any(|c| !matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(Error::Encoding(format!("{s}: not 64 lower-case hex digits")));
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(digits, &mut out).map_err(|e| Error::Encoding(e.to_string()))?;
    Ok(out)
}

/// The two 16-byte big-endian limbs of 32 bytes, as field elements (lo is
/// the first half): how 256-bit values enter circuits.
pub fn limbs(b: &[u8; 32]) -> (Fr, Fr) {
    (from_bytes_mod(&b[..16]), from_bytes_mod(&b[16..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip_and_strictness() {
        let x = Fr::from(42u64);
        let h = to_hex(&x);
        assert_eq!(h, format!("0x{}2a", "0".repeat(62)));
        assert_eq!(from_hex(&h).unwrap(), x);
        assert!(from_hex(&h.to_uppercase().replacen("0X", "0x", 1)).is_err());
        assert!(from_hex(&format!("0x{}", "f".repeat(64))).is_err());
        assert!(from_hex("2a").is_err());
    }

    #[test]
    fn signed_integers() {
        for v in [0i64, 1, -1, 1 << 40, -(1 << 40)] {
            assert_eq!(to_i64(&from_i64(v)), Some(v));
        }
        assert_eq!(to_i64(&Fr::from(1u64 << 63)), None);
    }
}
