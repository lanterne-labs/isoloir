//! BLS signatures of drand's unchained schemes on BLS12-381: the beacon of
//! round n is the signature of `SHA-256(n as 8 big-endian bytes)`.
//! `bls-unchained-g1-rfc9380` (quicknet: signatures on G1, the group key
//! on G2) and `bls-unchained-on-g1` style keys on G1 with signatures on G2.

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective, g1, g2};
use ark_ec::hashing::curve_maps::wb::WBMap;
use ark_ec::hashing::map_to_curve_hasher::MapToCurveBasedHasher;
use ark_ec::hashing::HashToCurve;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::{Digest, Sha256};

/// The domain of signatures on G1 (quicknet).
pub const DST_G1: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
/// The domain of signatures on G2.
pub const DST_G2: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

/// The message of an unchained round.
pub fn round_message(round: u64) -> [u8; 32] {
    Sha256::digest(round.to_be_bytes()).into()
}

fn hash_g1(msg: &[u8]) -> Option<G1Affine> {
    MapToCurveBasedHasher::<G1Projective, DefaultFieldHasher<Sha256, 128>, WBMap<g1::Config>>::new(DST_G1).ok()?.hash(msg).ok()
}

fn hash_g2(msg: &[u8]) -> Option<G2Affine> {
    MapToCurveBasedHasher::<G2Projective, DefaultFieldHasher<Sha256, 128>, WBMap<g2::Config>>::new(DST_G2).ok()?.hash(msg).ok()
}

/// Whether `signature` is the group's signature of `round`: the size of
/// the public key says the scheme (96 bytes: key on G2, signature on G1).
pub fn verify_round(public_key: &[u8], round: u64, signature: &[u8]) -> bool {
    let m = round_message(round);
    match (public_key.len(), signature.len()) {
        (96, 48) => {
            let (Ok(pk), Ok(sig), Some(h)) = (G2Affine::deserialize_compressed(public_key), G1Affine::deserialize_compressed(signature), hash_g1(&m)) else { return false };
            // e(sig, g2) == e(h, pk)
            Bls12_381::multi_pairing([sig, (-h.into_group()).into_affine()], [G2Affine::generator(), pk]).is_zero()
        }
        (48, 96) => {
            let (Ok(pk), Ok(sig), Some(h)) = (G1Affine::deserialize_compressed(public_key), G2Affine::deserialize_compressed(signature), hash_g2(&m)) else { return false };
            Bls12_381::multi_pairing([G1Affine::generator(), (-pk.into_group()).into_affine()], [sig, h]).is_zero()
        }
        _ => false,
    }
}

use ark_ff::Zero;

/// A test chain: a group key on G2 and its signatures on G1, as quicknet.
pub struct TestChain {
    sk: Fr,
}

impl TestChain {
    pub fn new(seed: u64) -> Self {
        TestChain { sk: Fr::from(seed.wrapping_mul(0x9e3779b97f4a7c15) | 1) }
    }

    /// The group key, compressed (96 bytes).
    pub fn public_key(&self) -> Vec<u8> {
        let mut out = vec![];
        (G2Projective::generator() * self.sk).into_affine().serialize_compressed(&mut out).expect("serialize");
        out
    }

    /// The beacon of a round (48 bytes).
    pub fn sign(&self, round: u64) -> Vec<u8> {
        let mut out = vec![];
        (hash_g1(&round_message(round)).expect("hash") * self.sk).into_affine().serialize_compressed(&mut out).expect("serialize");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_test_chain_verifies() {
        let c = TestChain::new(1);
        let pk = c.public_key();
        assert!(verify_round(&pk, 10, &c.sign(10)));
        assert!(!verify_round(&pk, 11, &c.sign(10)));
        assert!(!verify_round(&TestChain::new(2).public_key(), 10, &c.sign(10)));
    }

    /// A real quicknet beacon (drand's public endpoint, round 1).
    #[test]
    fn quicknet() {
        let pk = hex::decode("83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a").unwrap();
        let sig = hex::decode("b55e7cb2d5c613ee0b2e28d6750aabbb78c39dcc96bd9d38c2c2e12198df95571de8e8e402a0cc48871c7089a2b3af4b").unwrap();
        assert!(verify_round(&pk, 1, &sig));
        assert!(!verify_round(&pk, 2, &sig));
    }
}
