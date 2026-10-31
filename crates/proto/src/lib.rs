//! The isoloir protocol (SPEC.md): the bodies and their versions, the
//! kinds of ballots, the matrix of allowed polls and the rules of setup
//! succession, the log and its checkpoints, the policy that says when a
//! tally is due, and the ledger state machine that the ingest and the
//! auditor share: one implementation of every rule.

pub mod body;
pub mod client;
pub mod judge;

pub mod kinds;
pub mod log;
pub mod matrix;
pub mod note;
pub mod policy;

pub mod sig;
pub mod state;
pub mod statement;
pub mod tally;



pub use body::Reason;

/// The protocol version, in leaf prefixes, notes and relay tags.
pub const PROTOCOL: &str = "isoloir/1";
