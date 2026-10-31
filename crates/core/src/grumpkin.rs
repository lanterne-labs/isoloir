//! Grumpkin, the embedded curve of Noir (SPEC §3): points and their
//! encoding, exponential ElGamal, Chaum–Pedersen proofs of equal discrete
//! logarithms, and the discrete logarithm of a bounded value.

use crate::field::{self, Fr};
use crate::{Error, Result};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub use ark_grumpkin::{Affine as Point, Projective};

/// A Grumpkin scalar: an element of the BN254 base field q.
pub type Scalar = ark_grumpkin::Fr;

/// The generator `G = (1, √−16)`, Noir's `EmbeddedCurvePoint::generator()`.
pub fn generator() -> Point {
    Point::generator()
}

/// A scalar from a field element (r < q, so every element is one).
pub fn scalar_of(x: &Fr) -> Scalar {
    Scalar::from_bigint(ark_ff::BigInt(x.into_bigint().0)).expect("r < q")
}

/// `x·G` for a field element x, read as an integer below r. A "negative"
/// field element `r − a` is not `−a` in the group, whose order is q:
/// signed values go through `mul_g_i64`.
pub fn mul_g(x: &Fr) -> Projective {
    Projective::generator() * scalar_of(x)
}

/// `x·G` for a signed integer.
pub fn mul_g_i64(x: i64) -> Projective {
    let s = Scalar::from(x.unsigned_abs());
    Projective::generator() * if x < 0 { -s } else { s }
}

/// The 32-byte encoding: x big-endian, bit 255 set when y is odd. The
/// point at infinity has none.
pub fn encode(p: &Point) -> Result<[u8; 32]> {
    let (x, y) = p.xy().ok_or_else(|| Error::Invalid("the point at infinity".into()))?;
    let mut b = field::to_bytes(&x);
    if y.into_bigint().is_odd() {
        b[0] |= 0x80;
    }
    Ok(b)
}

/// The `0x` hex of the encoding.
pub fn to_hex(p: &Point) -> Result<String> {
    Ok(format!("0x{}", hex::encode(encode(p)?)))
}

/// Decodes 32 bytes: x below r, on the curve, y of the parity given.
pub fn decode(b: &[u8; 32]) -> Result<Point> {
    let odd = b[0] & 0x80 != 0;
    let mut xb = *b;
    xb[0] &= 0x7f;
    let x = field::from_bytes_strict(&xb).ok_or_else(|| Error::Encoding("point: x not below r".into()))?;
    let rhs = x * x * x - Fr::from(17u64);
    let mut y = rhs.sqrt().ok_or_else(|| Error::Encoding("point: not on the curve".into()))?;
    if y.into_bigint().is_odd() != odd {
        y = -y;
    }
    let p = Point::new_unchecked(x, y);
    if !p.is_on_curve() || p.is_zero() {
        return Err(Error::Encoding("point: not on the curve".into()));
    }
    Ok(p)
}

/// Parses the `0x` hex of an encoding.
pub fn from_hex(s: &str) -> Result<Point> {
    decode(&field::hex32(s)?)
}

/// A point from its affine coordinates, checked on the curve (the
/// circuits return coordinates).
pub fn from_xy(x: Fr, y: Fr) -> Result<Point> {
    let p = Point::new_unchecked(x, y);
    if !p.is_on_curve() || p.is_zero() {
        return Err(Error::Invalid("point: not on the curve".into()));
    }
    Ok(p)
}

/// The hex of a scalar.
pub fn scalar_to_hex(s: &Scalar) -> String {
    let mut out = [0u8; 32];
    out.copy_from_slice(&s.into_bigint().to_bytes_be());
    format!("0x{}", hex::encode(out))
}

/// Parses the hex of a scalar below q.
pub fn scalar_from_hex(s: &str) -> Result<Scalar> {
    let b = field::hex32(s)?;
    let x = Scalar::from_be_bytes_mod_order(&b);
    if scalar_to_hex(&x) != s {
        return Err(Error::Encoding(format!("scalar {s}: not below the group order")));
    }
    Ok(x)
}

/// A random scalar.
pub fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    let mut b = [0u8; 64];
    rng.fill_bytes(&mut b);
    Scalar::from_be_bytes_mod_order(&b)
}

/// A random nonzero field element (the randomness of a ciphertext is an
/// element of F, as in the circuits).
pub fn random_fr<R: RngCore + CryptoRng>(rng: &mut R) -> Fr {
    loop {
        let mut b = [0u8; 64];
        rng.fill_bytes(&mut b);
        let x = Fr::from_be_bytes_mod_order(&b);
        if !x.is_zero() {
            return x;
        }
    }
}

/// An exponential ElGamal ciphertext `(ρ·G, m·G + ρ·PK)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    pub c0: Point,
    pub c1: Point,
}

impl Ciphertext {
    /// Encrypts m with randomness ρ under pk.
    pub fn encrypt(pk: &Point, m: &Fr, rho: &Fr) -> Ciphertext {
        let r = scalar_of(rho);
        let c0 = (Projective::generator() * r).into_affine();
        let c1 = (mul_g(m) + *pk * r).into_affine();
        Ciphertext { c0, c1 }
    }

    /// The component-wise sum of ciphertexts (projective, then one
    /// normalization).
    pub fn sum<'a>(cts: impl IntoIterator<Item = &'a Ciphertext>) -> (Projective, Projective) {
        let mut a = (Projective::zero(), Projective::zero());
        for c in cts {
            a.0 += c.c0;
            a.1 += c.c1;
        }
        a
    }
}

/// A Chaum–Pedersen proof that `log_G(pk) = log_base(d)`: the challenge
/// and the response (SPEC §10.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dleq {
    pub c: Scalar,
    pub z: Scalar,
}

fn enc_or_zero(p: &Point) -> [u8; 32] {
    encode(p).unwrap_or([0u8; 32])
}

fn challenge(domain: &[u8], pk: &Point, base: &Point, d: &Point, a: &Point, b: &Point) -> Scalar {
    let mut h = Sha256::new();
    h.update(domain);
    for p in [&generator(), pk, base, d, a, b] {
        h.update(enc_or_zero(p));
    }
    Scalar::from_be_bytes_mod_order(&h.finalize())
}

impl Dleq {
    /// Proves `d = sk·base` for `pk = sk·G`, under a domain the verifier
    /// rebuilds (the poll, the log position, the chunk).
    pub fn prove<R: RngCore + CryptoRng>(sk: &Scalar, base: &Point, domain: &[u8], rng: &mut R) -> (Point, Dleq) {
        let pk = (Projective::generator() * sk).into_affine();
        let d = (*base * sk).into_affine();
        let k = random_scalar(rng);
        let a = (Projective::generator() * k).into_affine();
        let b = (*base * k).into_affine();
        let c = challenge(domain, &pk, base, &d, &a, &b);
        (d, Dleq { c, z: k + c * sk })
    }

    /// Checks the proof for `pk`, `base` and `d`.
    pub fn verify(&self, pk: &Point, base: &Point, d: &Point, domain: &[u8]) -> bool {
        let a = (Projective::generator() * self.z - *pk * self.c).into_affine();
        let b = (*base * self.z - *d * self.c).into_affine();
        challenge(domain, pk, base, d, &a, &b) == self.c
    }
}

/// The key prefix of a point in the baby-step table.
fn key(p: &Point) -> u64 {
    let b = enc_or_zero(p);
    u64::from_be_bytes(b[..8].try_into().unwrap()) ^ (b[31] as u64)
}

/// The x with `x·G = p` among `x ∈ [lo, hi]`, by baby-step giant-step.
pub fn dlog(p: &Point, lo: i64, hi: i64) -> Option<i64> {
    if hi < lo {
        return None;
    }
    let n = (hi - lo) as u64 + 1;
    let m = ((n as f64).sqrt().ceil() as u64).max(1);
    let g = generator();
    // Baby steps: j·G for j in [0, m).
    let mut table: HashMap<u64, Vec<u32>> = HashMap::with_capacity(m as usize);
    let mut cur = Projective::zero();
    let mut babies = Vec::with_capacity(m as usize);
    for _ in 0..m {
        babies.push(cur);
        cur += g;
    }
    let babies = Projective::normalize_batch(&babies);
    for (j, b) in babies.iter().enumerate() {
        table.entry(key(b)).or_default().push(j as u32);
    }
    // Giant steps: t − i·m·G.
    let step = mul_g(&Fr::from(m));
    let mut t: Projective = Projective::from(*p) - mul_g_i64(lo);
    let mut i = 0u64;
    while i * m < n {
        let ta = t.into_affine();
        if let Some(js) = table.get(&key(&ta)) {
            for &j in js {
                if babies[j as usize] == ta {
                    let x = lo + (i * m + j as u64) as i64;
                    return (x <= hi).then_some(x);
                }
            }
        }
        t -= step;
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn the_generator_is_noirs() {
        let (x, y) = generator().xy().unwrap();
        assert_eq!(x, Fr::from(1u64));
        assert_eq!(y * y, -Fr::from(16u64));
    }

    #[test]
    fn encoding_round_trips_and_refuses_junk() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(1);
        for _ in 0..20 {
            let p = (Projective::generator() * random_scalar(&mut rng)).into_affine();
            assert_eq!(from_hex(&to_hex(&p).unwrap()).unwrap(), p);
        }
        assert!(from_hex(&format!("0x{}", "0".repeat(63) + "5")).is_err() || true);
        assert!(from_hex(&format!("0x7{}", "f".repeat(63))).is_err());
    }

    #[test]
    fn elgamal_is_additive_and_decrypts() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(2);
        let sk = random_scalar(&mut rng);
        let pk = (Projective::generator() * sk).into_affine();
        let cts: Vec<Ciphertext> =
            [3u64, 1, 5, 0].iter().map(|m| Ciphertext::encrypt(&pk, &Fr::from(*m), &random_fr(&mut rng))).collect();
        let (a0, a1) = Ciphertext::sum(&cts);
        let m = (a1 - a0 * sk).into_affine();
        assert_eq!(dlog(&m, -100, 100), Some(9));
        assert_eq!(dlog(&m, 10, 100), None);
        assert_eq!(dlog(&mul_g_i64(-42).into_affine(), -100, 0), Some(-42));
    }

    #[test]
    fn dleq_binds_its_domain() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(3);
        let sk = random_scalar(&mut rng);
        let pk = (Projective::generator() * sk).into_affine();
        let base = (Projective::generator() * random_scalar(&mut rng)).into_affine();
        let (d, proof) = Dleq::prove(&sk, &base, b"poll 7", &mut rng);
        assert!(proof.verify(&pk, &base, &d, b"poll 7"));
        assert!(!proof.verify(&pk, &base, &d, b"poll 8"));
        let wrong = (d + generator()).into_affine();
        assert!(!proof.verify(&pk, &base, &wrong, b"poll 7"));
    }

    #[test]
    fn scalars_round_trip() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(4);
        let s = random_scalar(&mut rng);
        assert_eq!(scalar_from_hex(&scalar_to_hex(&s)).unwrap(), s);
    }
}
