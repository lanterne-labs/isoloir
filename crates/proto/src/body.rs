//! The bodies of the log's entries (SPEC §4–§11), version 1. A body is
//! canonical JSON (SPEC §3) and decodes only in its one spelling: unknown
//! fields, absent required fields, a field set to null, a version this
//! code does not know are all refusals.

use isoloir_core::canonical;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Why a message was refused (SPEC §12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    Malformed,
    Version,
    Unknown,
    NotOpen,
    Closed,
    BadSig,
    StaleDate,
    UidUsed,
    IdUsed,
    BadProof,
    OldRoot,
    RevoteOff,
    StaleSeq,
    Duplicate,
    NotDue,
    BadTally,
    /// The registry's or the poll's tree is full.
    Full,
    /// A linked seq more than `SEQ_GAP` above the pseudonym's last (or
    /// above it for a first ballot): a seq is a counter, not a lock.
    SeqGap,
}

impl Reason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Reason::Malformed => "malformed",
            Reason::Version => "version",
            Reason::Unknown => "unknown",
            Reason::NotOpen => "not_open",
            Reason::Closed => "closed",
            Reason::BadSig => "bad_sig",
            Reason::StaleDate => "stale_date",
            Reason::UidUsed => "uid_used",
            Reason::IdUsed => "id_used",
            Reason::BadProof => "bad_proof",
            Reason::OldRoot => "old_root",
            Reason::RevoteOff => "revote_off",
            Reason::StaleSeq => "stale_seq",
            Reason::Duplicate => "duplicate",
            Reason::NotDue => "not_due",
            Reason::BadTally => "bad_tally",
            Reason::Full => "full",
            Reason::SeqGap => "seq_gap",
        }
    }

    /// The reasons that depend on the time of judgment.
    pub fn time_sensitive(&self) -> bool {
        matches!(self, Reason::NotOpen | Reason::Closed | Reason::StaleDate | Reason::OldRoot | Reason::NotDue)
    }
}

/// The kinds of entries (SPEC §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    Ledger,
    Registry,
    Register,
    Poll,
    Ballot,
    Reject,
    Tally,
    Close,
}

impl EntryKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EntryKind::Ledger => "ledger",
            EntryKind::Registry => "registry",
            EntryKind::Register => "register",
            EntryKind::Poll => "poll",
            EntryKind::Ballot => "ballot",
            EntryKind::Reject => "reject",
            EntryKind::Tally => "tally",
            EntryKind::Close => "close",
        }
    }

    pub fn parse(s: &str) -> Option<EntryKind> {
        Some(match s {
            "ledger" => EntryKind::Ledger,
            "registry" => EntryKind::Registry,
            "register" => EntryKind::Register,
            "poll" => EntryKind::Poll,
            "ballot" => EntryKind::Ballot,
            "reject" => EntryKind::Reject,
            "tally" => EntryKind::Tally,
            "close" => EntryKind::Close,
            _ => return None,
        })
    }
}

/// `v` of every body this code writes.
pub const V1: u32 = 1;

// ---------------------------------------------------------------- setups

/// The `ledger` entry (SPEC §4.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerSetup {
    pub v: u32,
    pub version: u32,
    pub origin: String,
    pub log_key: String,
    pub ingest: String,
    /// How messages reach the ingest and acknowledgements come back
    /// (SPEC §11): any number of channels, of any type.
    pub channels: Vec<Channel>,
    pub checkpoint_period: u64,
    pub anchor_age: u64,
}

/// A way to the ingest (SPEC §11.1). Every channel carries the same
/// signed envelopes and the same signed acknowledgements; what differs is
/// who sees the messages pass and who keeps a copy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Channel {
    /// A public Nostr relay (`ws://` or `wss://`).
    Nostr { url: String, state: ChannelState },
    /// The ingest's own HTTP endpoint (`https://`).
    Direct { url: String, state: ChannelState },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelState {
    Active,
    Retired,
}

impl Channel {
    pub fn url(&self) -> &str {
        match self {
            Channel::Nostr { url, .. } | Channel::Direct { url, .. } => url,
        }
    }

    pub fn state(&self) -> ChannelState {
        match self {
            Channel::Nostr { state, .. } | Channel::Direct { state, .. } => *state,
        }
    }

    pub fn is_active(&self) -> bool {
        self.state() == ChannelState::Active
    }
}

impl LedgerSetup {
    /// The Nostr relays (active ones only, or all).
    pub fn nostr(&self, active_only: bool) -> Vec<String> {
        self.channels.iter().filter(|c| matches!(c, Channel::Nostr { .. }) && (!active_only || c.is_active())).map(|c| c.url().to_string()).collect()
    }

    /// The direct endpoints (active ones only, or all).
    pub fn direct(&self, active_only: bool) -> Vec<String> {
        self.channels.iter().filter(|c| matches!(c, Channel::Direct { .. }) && (!active_only || c.is_active())).map(|c| c.url().to_string()).collect()
    }
}

/// The `registry` entry (SPEC §5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrySetup {
    pub v: u32,
    pub id: u32,
    pub version: u32,
    pub name: String,
    pub eligibility: Eligibility,
    pub validity: u64,
    pub depth: u32,
}

/// Who may register (SPEC §5): the provider and its rules.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Eligibility {
    pub provider: String,
    pub domain: String,
    pub scope: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_age: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nationality: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document_type: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub require_expiry: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}


/// The `poll` entry (SPEC §7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PollSetup {
    pub v: u32,
    pub id: u32,
    pub version: u32,
    pub registry: u32,
    pub title: String,
    pub kind: KindSpec,
    pub encryption: Encryption,
    pub publish: Publish,
    pub revote: Revote,
    pub opens: u64,
    pub closes: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blackouts: Vec<Blackout>,
    pub circuit: CircuitRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ballot_depth: Option<u32>,
}

/// What a ballot is (SPEC §7.1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum KindSpec {
    Choice { options: Vec<String>, blank: bool },
    Ranked { options: Vec<String>, blank: bool, depth: u32, margins: bool },
}

/// How ballots are encrypted (SPEC §7.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Encryption {
    Elgamal { pk: String, authority: Authority },
    Tlock { chain: String, public_key: String, period: u64, genesis: u64, round: u64 },
}

/// Who decrypts an ElGamal poll. Threshold committees come in a later
/// version of the body (SPEC §9.4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Authority {
    Single { sign_key: String },
}

/// When results are published (SPEC §7.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Publish {
    Open { k_real: u32, min_gap: u64, coin: bool },
    Closed,
}

/// Re-votes (SPEC §7.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Revote {
    None,
    Linked,
    Delta,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Blackout {
    pub from: u64,
    pub to: u64,
}

/// The circuit ballots prove against: its name (circuits/gen.py) and the
/// SHA-256 of its verification key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitRef {
    pub name: String,
    pub vk_hash: String,
}

// ------------------------------------------------------------- messages

/// A registration (SPEC §6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Register {
    pub v: u32,
    pub registry: u32,
    pub id: String,
    pub uid: String,
    pub proof: Value,
    pub proof_date: u64,
    pub key: String,
    pub sig: String,
}

/// A ballot (SPEC §9.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ballot {
    pub v: u32,
    pub poll: u32,
    pub setup: u64,
    pub root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nullifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ident: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broot: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ct: Option<Vec<[String; 2]>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vcmt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob: Option<String>,
    pub proof: String,
}

/// A refusal (SPEC §11.4): the message's event id, its body hash, the
/// reason and, up to 16 KiB, the raw body so that an auditor can judge it
/// again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reject {
    pub v: u32,
    pub of: String,
    pub hash: String,
    pub reason: Reason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

/// The largest body a message may have; a refusal keeps it whole (up to
/// this size) so that an auditor can judge it again.
pub const REJECT_RAW_MAX: usize = 256 * 1024;

/// A result (SPEC §10.3, §10.4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tally {
    pub v: u32,
    pub poll: u32,
    pub upto: u64,
    #[serde(rename = "final")]
    pub is_final: bool,
    pub values: Vec<i64>,
    pub counted: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<u64>,
    /// ElGamal: the aggregate of each chunk over the counted ballots, so
    /// that a reader can check the shares without the whole log.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aggregate: Option<Vec<[String; 2]>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shares: Option<Vec<Share>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beacon: Option<Beacon>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub void: Option<Vec<u64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

/// One authority's decryption shares, one per chunk, with their proofs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Share {
    pub authority: u32,
    pub d: Vec<String>,
    pub proofs: Vec<[String; 2]>,
}

/// The drand beacon that opens a tlock poll.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Beacon {
    pub round: u64,
    pub signature: String,
}

/// The close of a poll (SPEC §10.5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Close {
    pub v: u32,
    pub poll: u32,
    pub at: u64,
    pub last: u64,
}

/// An acknowledgement (SPEC §11.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ack {
    pub v: u32,
    pub of: String,
    pub hash: String,
    pub outcome: Outcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Accepted,
    Rejected,
}

// -------------------------------------------------------------- decoding

/// A decoded body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    Ledger(LedgerSetup),
    Registry(RegistrySetup),
    Register(Register),
    Poll(PollSetup),
    Ballot(Ballot),
    Reject(Reject),
    Tally(Tally),
    Close(Close),
}

impl Body {
    pub fn kind(&self) -> EntryKind {
        match self {
            Body::Ledger(_) => EntryKind::Ledger,
            Body::Registry(_) => EntryKind::Registry,
            Body::Register(_) => EntryKind::Register,
            Body::Poll(_) => EntryKind::Poll,
            Body::Ballot(_) => EntryKind::Ballot,
            Body::Reject(_) => EntryKind::Reject,
            Body::Tally(_) => EntryKind::Tally,
            Body::Close(_) => EntryKind::Close,
        }
    }

    /// The canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        let r = match self {
            Body::Ledger(b) => canonical::to_vec(b),
            Body::Registry(b) => canonical::to_vec(b),
            Body::Register(b) => canonical::to_vec(b),
            Body::Poll(b) => canonical::to_vec(b),
            Body::Ballot(b) => canonical::to_vec(b),
            Body::Reject(b) => canonical::to_vec(b),
            Body::Tally(b) => canonical::to_vec(b),
            Body::Close(b) => canonical::to_vec(b),
        };
        r.expect("bodies serialize")
    }
}

/// Decodes a body of a kind: canonical, of a known version, in its one
/// spelling. The version is read first, so a body of a later version is
/// refused as `version`, not as `malformed`.
pub fn decode(kind: EntryKind, bytes: &[u8]) -> Result<Body, Reason> {
    let value = canonical::parse(bytes).map_err(|_| Reason::Malformed)?;
    let v = value.get("v").and_then(Value::as_u64).ok_or(Reason::Malformed)?;
    if v != V1 as u64 {
        return Err(Reason::Version);
    }
    fn one<T: serde::de::DeserializeOwned + Serialize>(value: Value, bytes: &[u8]) -> Result<T, Reason> {
        let t: T = serde_json::from_value(value).map_err(|_| Reason::Malformed)?;
        // One spelling: a default written out, a null, all refused.
        if canonical::to_vec(&t).map_err(|_| Reason::Malformed)? != bytes {
            return Err(Reason::Malformed);
        }
        Ok(t)
    }
    Ok(match kind {
        EntryKind::Ledger => Body::Ledger(one(value, bytes)?),
        EntryKind::Registry => Body::Registry(one(value, bytes)?),
        EntryKind::Register => Body::Register(one(value, bytes)?),
        EntryKind::Poll => Body::Poll(one(value, bytes)?),
        EntryKind::Ballot => Body::Ballot(one(value, bytes)?),
        EntryKind::Reject => Body::Reject(one(value, bytes)?),
        EntryKind::Tally => Body::Tally(one(value, bytes)?),
        EntryKind::Close => Body::Close(one(value, bytes)?),
    })
}

/// Decodes a body with serde's own message on failure (operators' tools;
/// the ingest answers a reason, never a message).
pub fn decode_verbose(kind: EntryKind, bytes: &[u8]) -> Result<Body, String> {
    let value = canonical::parse(bytes).map_err(|e| format!("not canonical JSON: {e} (sorted keys, no spaces, integers, defaults left out)"))?;
    let v = value.get("v").and_then(Value::as_u64).ok_or("no \"v\"")?;
    if v != V1 as u64 {
        return Err(format!("v {v}: this code knows v 1"));
    }
    fn one<T: serde::de::DeserializeOwned + Serialize>(value: Value, bytes: &[u8]) -> Result<T, String> {
        let t: T = serde_json::from_value(value).map_err(|e| e.to_string())?;
        let again = canonical::to_vec(&t).map_err(|e| e.to_string())?;
        if again != bytes {
            return Err(format!("not in its one spelling: a field at its default is left out; the spelling is {}", String::from_utf8_lossy(&again)));
        }
        Ok(t)
    }
    Ok(match kind {
        EntryKind::Ledger => Body::Ledger(one(value, bytes)?),
        EntryKind::Registry => Body::Registry(one(value, bytes)?),
        EntryKind::Register => Body::Register(one(value, bytes)?),
        EntryKind::Poll => Body::Poll(one(value, bytes)?),
        EntryKind::Ballot => Body::Ballot(one(value, bytes)?),
        EntryKind::Reject => Body::Reject(one(value, bytes)?),
        EntryKind::Tally => Body::Tally(one(value, bytes)?),
        EntryKind::Close => Body::Close(one(value, bytes)?),
    })
}

/// Decodes an acknowledgement.
pub fn decode_ack(bytes: &[u8]) -> Result<Ack, Reason> {
    let value = canonical::parse(bytes).map_err(|_| Reason::Malformed)?;
    if value.get("v").and_then(Value::as_u64) != Some(V1 as u64) {
        return Err(Reason::Version);
    }
    let a: Ack = serde_json::from_value(value).map_err(|_| Reason::Malformed)?;
    if canonical::to_vec(&a).map_err(|_| Reason::Malformed)? != bytes {
        return Err(Reason::Malformed);
    }
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close() -> Close {
        Close { v: 1, poll: 7, at: 100, last: 42 }
    }

    #[test]
    fn round_trip() {
        let b = Body::Close(close());
        assert_eq!(decode(EntryKind::Close, &b.encode()), Ok(b));
    }

    #[test]
    fn one_spelling() {
        assert_eq!(decode(EntryKind::Close, br#"{"at":100,"last":42,"poll":7,"v":1,"x":0}"#), Err(Reason::Malformed));
        assert_eq!(decode(EntryKind::Close, br#"{"at":100, "last":42,"poll":7,"v":1}"#), Err(Reason::Malformed));
        assert_eq!(decode(EntryKind::Close, br#"{"at":100,"last":42,"poll":7,"v":2}"#), Err(Reason::Version));
        let ballot = br#"{"poll":1,"proof":"","root":"0x","seq":null,"setup":1,"v":1}"#;
        assert_eq!(decode(EntryKind::Ballot, ballot), Err(Reason::Malformed));
    }

    #[test]
    fn tagged_enums() {
        let k = KindSpec::Choice { options: vec!["Oui".into(), "Non".into()], blank: true };
        assert_eq!(canonical::to_string(&k).unwrap(), r#"{"blank":true,"options":["Oui","Non"],"type":"choice"}"#);
        let p = Publish::Closed;
        assert_eq!(canonical::to_string(&p).unwrap(), r#"{"mode":"closed"}"#);
    }
}
