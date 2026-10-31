//! The arithmetic of isoloir (SPEC §3): the BN254 scalar field, Poseidon2
//! with Barretenberg's parameters, the domain tags, the fixed-depth Merkle
//! trees, Grumpkin points and exponential ElGamal, Chaum–Pedersen proofs,
//! the discrete logarithm of a bounded value, the packing of values into
//! chunks, and canonical JSON. Everything here is shared by the server,
//! the auditor and the browser (through WebAssembly).

pub mod canonical;
pub mod encoding;
pub mod field;
pub mod grumpkin;
pub mod pack;
pub mod poseidon2;
mod poseidon2_params;
pub mod tags;
pub mod tree;

pub use field::Fr;

/// The errors of decoding and checking.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("{0}")]
    Encoding(String),
    #[error("not canonical JSON")]
    NotCanonical,
    #[error("out of range: {0}")]
    Range(String),
    #[error("{0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, Error>;
