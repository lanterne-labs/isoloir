use thiserror::Error;

/// The errors of the crate.
#[derive(Debug, Error)]
pub enum Error {
    /// The bytes are not an OpenTimestamps proof (bad magic).
    #[error("ots: not an OpenTimestamps proof")]
    BadMagic,
    /// A major version other than 1.
    #[error("ots: unsupported major version {0}")]
    UnsupportedVersion(u64),
    /// A file hash operation other than SHA-256.
    #[error("ots: unsupported file hash operation 0x{0:02x} (only SHA-256 is)")]
    UnsupportedFileHash(u8),
    /// The proof ends in the middle of a value.
    #[error("ots: truncated")]
    Truncated,
    /// Bytes follow the timestamp.
    #[error("ots: {0} bytes after the timestamp")]
    TrailingBytes(usize),
    /// Any other malformed content.
    #[error("ots: {0}")]
    Malformed(String),

    /// An HTTP exchange with a calendar or a block explorer failed.
    #[error("{url}: {reason}")]
    Http { url: String, reason: String },
    /// No calendar accepted the digest, or none could be asked for an upgrade.
    #[error("calendars: {}", .0.join("; "))]
    Calendars(Vec<String>),

    /// The proof is of another digest.
    #[error("ots: the proof is of digest {proof}, not {expected}")]
    DigestMismatch { proof: String, expected: String },
    /// The proof has no Bitcoin attestation (still pending).
    #[error("ots: no Bitcoin attestation")]
    NoBitcoinAttestation,
    /// A Bitcoin attestation does not lead to the block's Merkle root.
    #[error(
        "block {height}: the proof leads to {commitment}, the block's Merkle root is {merkle_root}"
    )]
    MerkleRootMismatch {
        height: u64,
        commitment: String,
        merkle_root: String,
    },
    /// A block header could not be obtained or is inconsistent.
    #[error("block {height}: {reason}")]
    BlockHeader { height: u64, reason: String },
}

/// The crate's result.
pub type Result<T> = std::result::Result<T, Error>;
