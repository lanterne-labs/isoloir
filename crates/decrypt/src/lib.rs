//! Decryption in isoloir (SPEC §7.2, §10): drand time-lock for closed
//! single-choice polls, and the keys of a single ElGamal decrypter. The
//! sealing half of tlock is what browsers need (pure Rust, WebAssembly);
//! opening needs the round's beacon, which only exists after the round.

pub mod bls;
pub mod keys;
pub mod tlock;
