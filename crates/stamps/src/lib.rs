//! OpenTimestamps for isoloir (SPEC §4 "Stamps"): the SHA-256 of every
//! checkpoint note is submitted to public calendars, the pending proofs are
//! upgraded until they carry a Bitcoin attestation, and a proof is verified
//! against the Bitcoin block headers.
//!
//! ```no_run
//! use isoloir_stamps::{default_calendars, submit, upgrade, verify, Esplora};
//! let digest = [0u8; 32];
//! let ots = submit(digest, &default_calendars())?;
//! // Hours later:
//! let (ots, changed) = upgrade(&ots)?;
//! if ots.is_complete() {
//!     let blocks = verify(&ots, digest, &Esplora::default())?;
//! }
//! # Ok::<(), isoloir_stamps::Error>(())
//! ```

mod bitcoin;
mod calendar;
mod error;
mod ots;

pub use bitcoin::{BlockHeader, BlockHeaders, Esplora, block_hash, verify};
pub use calendar::{Client, DEFAULT_CALENDARS, default_calendars, submit, upgrade};
pub use error::{Error, Result};
pub use ots::{
    Attestation, AttestationAt, Item, MAGIC, Op, Ots, Timestamp, VERSION, attestations, is_complete,
};

#[cfg(test)]
mod tests {
    #[test]
    fn header_from_json_rebuilds_the_header() {
        let json = include_str!("../tests/fixtures/block-358391.json");
        let raw = crate::bitcoin::header_from_json(json).unwrap();
        let want = include_str!("../tests/fixtures/block-358391.header.hex");
        assert_eq!(hex::encode(&raw), want.trim());
        assert_eq!(
            crate::block_hash(&raw),
            "000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319"
        );
    }
}
