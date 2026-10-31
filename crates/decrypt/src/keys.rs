//! The keys of a single ElGamal authority (SPEC §7.2, §10.3): the
//! committee key (a Grumpkin scalar and its public point) and the Ed25519
//! seed that signs its tallies. Made once, kept offline; the public half
//! goes into polls, which may share it.

use isoloir_core::grumpkin::{self, Projective, Scalar};
use isoloir_proto::sig;
use ark_ec::CurveGroup;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// The authority's secret file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityKeys {
    pub v: u32,
    pub sk: String,
    pub pk: String,
    pub sign_seed: String,
    pub sign_key: String,
}

/// What goes into a poll.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityPublic {
    pub pk: String,
    pub sign_key: String,
}

impl AuthorityKeys {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let sk = grumpkin::random_scalar(rng);
        let pk = (Projective::from(grumpkin::generator()) * sk).into_affine();
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        AuthorityKeys {
            v: 1,
            sk: grumpkin::scalar_to_hex(&sk),
            pk: grumpkin::to_hex(&pk).expect("a nonzero key"),
            sign_seed: hex::encode(seed),
            sign_key: sig::ed25519_public(&seed),
        }
    }

    /// The scalar and the seed, checked against their public halves.
    pub fn secrets(&self) -> Result<(Scalar, [u8; 32]), String> {
        let sk = grumpkin::scalar_from_hex(&self.sk).map_err(|e| e.to_string())?;
        let seed: [u8; 32] = hex::decode(&self.sign_seed).ok().and_then(|b| b.try_into().ok()).ok_or("sign_seed")?;
        let pk = grumpkin::to_hex(&(Projective::from(grumpkin::generator()) * sk).into_affine()).map_err(|e| e.to_string())?;
        if pk != self.pk || sig::ed25519_public(&seed) != self.sign_key {
            return Err("the secrets do not match their public keys".into());
        }
        Ok((sk, seed))
    }

    pub fn public(&self) -> AuthorityPublic {
        AuthorityPublic { pk: self.pk.clone(), sign_key: self.sign_key.clone() }
    }
}
