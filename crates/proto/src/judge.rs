//! The judge (SPEC §6.4, §9.3, §10): every check a message goes through
//! before the ingest logs it, and that the auditor runs again. The proof
//! verifier, the passport verifier and the tlock opener are supplied by
//! the caller; their infrastructure failures defer a message, they never
//! refuse it.

use crate::body::{self, Body, CircuitRef, Eligibility, EntryKind, Encryption, Revote, Tally};
use crate::policy;
use crate::sig;
use crate::state::State;
use crate::statement;
use crate::tally::{self, Tlock};
use crate::Reason;
use isoloir_core::{encoding, field};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

/// Verifies ballot proofs (bb).
pub trait Proofs {
    /// Ok(true) verifies, Ok(false) does not, Err the verifier could not run.
    fn verify(&self, circuit: &CircuitRef, proof: &[u8], inputs: &[[u8; 32]]) -> Result<bool, String>;
}

/// Verifies passport proofs (the ZKPassport verifier).
pub trait Passports {
    /// Ok(Some(uid)) verified, Ok(None) refused, Err the verifier could not run.
    fn verify(&self, eligibility: &Eligibility, proof: &Value, custom_data: &str, proof_date: u64) -> Result<Option<String>, String>;
}

/// The verifiers a judge needs.
pub struct Checkers<'a> {
    pub proofs: &'a dyn Proofs,
    pub passports: &'a dyn Passports,
    pub tlock: Option<&'a dyn Tlock>,
}

/// A judgment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Reject(Reason),
    /// The message could not be judged now (an infrastructure failure):
    /// neither acknowledged nor refused, judged again later.
    Defer(String),
}

/// What the accepted, not yet logged messages claim: the judge counts
/// them as logged.
#[derive(Clone, Debug, Default)]
pub struct Pending {
    pub uids: HashSet<(u32, String)>,
    pub ids: HashSet<(u32, String)>,
    pub nullifiers: HashMap<(u32, String), u32>,
    pub idents: HashSet<(u32, String)>,
    pub tallies: HashSet<(u32, u64)>,
}

impl Pending {
    /// Records the claims of an accepted message.
    pub fn admit(&mut self, kind: EntryKind, bytes: &[u8]) {
        match body::decode(kind, bytes) {
            Ok(Body::Register(r)) => {
                self.uids.insert((r.registry, r.uid));
                self.ids.insert((r.registry, r.id));
            }
            Ok(Body::Ballot(b)) => {
                if let (Some(n), Some(s)) = (b.nullifier, b.seq) {
                    let e = self.nullifiers.entry((b.poll, n)).or_insert(s);
                    *e = (*e).max(s);
                }
                if let Some(i) = b.ident {
                    self.idents.insert((b.poll, i));
                }
            }
            Ok(Body::Tally(t)) => {
                self.tallies.insert((t.poll, t.checkpoint.unwrap_or(0)));
            }
            _ => {}
        }
    }

    pub fn clear(&mut self) {
        *self = Pending::default();
    }
}

fn reject<T>(r: Reason) -> Result<T, Verdict> {
    Err(Verdict::Reject(r))
}

/// Judges a message from a relay (a registration, a ballot, a tally) at
/// time `now`.
pub fn judge(state: &State, pending: &Pending, kind: EntryKind, bytes: &[u8], now: u64, c: &Checkers) -> Verdict {
    let r = match kind {
        EntryKind::Register => register(state, pending, bytes, now, c),
        EntryKind::Ballot => ballot(state, pending, bytes, now, c),
        EntryKind::Tally => tally_msg(state, pending, bytes, c),
        _ => Err(Verdict::Reject(Reason::Malformed)),
    };
    r.err().unwrap_or(Verdict::Accept)
}

/// Judges a setup entry (from the operator) at time `now`.
pub fn judge_setup(state: &State, kind: EntryKind, bytes: &[u8], now: u64) -> Result<(), String> {
    let b = body::decode(kind, bytes).map_err(|r| r.as_str().to_string())?;
    state.check_setup(&b, now)
}

fn register(state: &State, pending: &Pending, bytes: &[u8], now: u64, c: &Checkers) -> Result<(), Verdict> {
    let Body::Register(r) = body::decode(EntryKind::Register, bytes).map_err(Verdict::Reject)? else { unreachable!() };
    if field::from_hex(&r.id).is_err() {
        return reject(Reason::Malformed);
    }
    let Some(reg) = state.registries.get(&r.registry) else { return reject(Reason::Unknown) };
    let setup = reg.current();
    let Ok(key) = sig::verify_register(bytes) else { return reject(Reason::BadSig) };
    if r.proof_date.abs_diff(now) > setup.validity + 300 {
        return reject(Reason::StaleDate);
    }
    if reg.uids.contains_key(&r.uid) || pending.uids.contains(&(r.registry, r.uid.clone())) {
        return reject(Reason::UidUsed);
    }
    if reg.ids.contains_key(&r.id) || pending.ids.contains(&(r.registry, r.id.clone())) {
        return reject(Reason::IdUsed);
    }
    let binding = sig::registration_binding(r.registry, &key);
    match c.passports.verify(&setup.eligibility, &r.proof, &binding, r.proof_date) {
        Ok(Some(uid)) if uid == r.uid => Ok(()),
        Ok(_) => reject(Reason::BadProof),
        Err(e) => Err(Verdict::Defer(format!("passport verifier: {e}"))),
    }
}

fn ballot(state: &State, pending: &Pending, bytes: &[u8], now: u64, c: &Checkers) -> Result<(), Verdict> {
    let Body::Ballot(b) = body::decode(EntryKind::Ballot, bytes).map_err(Verdict::Reject)? else { unreachable!() };
    let Some(ledger) = state.ledger() else { return reject(Reason::Unknown) };
    let Some(p) = state.polls.get(&b.poll) else { return reject(Reason::Unknown) };
    let Some(setup) = p.setup_in_force(b.setup, now) else { return reject(Reason::Unknown) };
    if now < setup.opens {
        return reject(Reason::NotOpen);
    }
    if p.close.is_some() || now >= p.current().closes {
        return reject(Reason::Closed);
    }
    // The shape and every encoding, through the public inputs.
    let inputs = statement::inputs(&b, setup, &p.variant).map_err(Verdict::Reject)?;
    let reg = state.registries.get(&setup.registry).expect("a poll's registry exists");
    let root = field::from_hex(&b.root).map_err(|_| Verdict::Reject(Reason::Malformed))?;
    if !reg.root_fresh(&root, now, ledger.anchor_age) {
        return reject(Reason::OldRoot);
    }
    match setup.revote {
        Revote::None | Revote::Linked => {
            let n = b.nullifier.clone().expect("shape");
            let s = b.seq.expect("shape");
            let last = p.latest.get(&n).map(|(s, _)| *s).into_iter().chain(pending.nullifiers.get(&(b.poll, n)).copied()).max();
            if let Some(last) = last {
                if setup.revote == Revote::None {
                    return reject(Reason::RevoteOff);
                }
                if s <= last {
                    return reject(Reason::StaleSeq);
                }
            }
        }
        Revote::Delta => {
            let broot = field::from_hex(b.broot.as_deref().expect("shape")).map_err(|_| Verdict::Reject(Reason::Malformed))?;
            if !p.broot_fresh(&broot, now, ledger.anchor_age) {
                return reject(Reason::OldRoot);
            }
            let i = b.ident.clone().expect("shape");
            if p.idents.contains(&i) || pending.idents.contains(&(b.poll, i)) {
                return reject(Reason::Duplicate);
            }
        }
    }
    let Ok(proof) = encoding::unb64(&b.proof) else { return reject(Reason::Malformed) };
    match c.proofs.verify(&setup.circuit, &proof, &inputs) {
        Ok(true) => Ok(()),
        Ok(false) => reject(Reason::BadProof),
        Err(e) => Err(Verdict::Defer(format!("proof verifier: {e}"))),
    }
}

fn tally_msg(state: &State, pending: &Pending, bytes: &[u8], c: &Checkers) -> Result<(), Verdict> {
    let Body::Tally(t) = body::decode(EntryKind::Tally, bytes).map_err(Verdict::Reject)? else { unreachable!() };
    let Some(p) = state.polls.get(&t.poll) else { return reject(Reason::Unknown) };
    let Some(cp) = t.checkpoint else { return reject(Reason::Malformed) };
    if pending.tallies.contains(&(t.poll, cp)) || pending.tallies.iter().any(|(poll, _)| *poll == t.poll && t.is_final) {
        return reject(Reason::Duplicate);
    }
    let Some(due) = policy::due_at(state, t.poll, cp) else { return reject(Reason::NotDue) };
    let ok = match &p.current().encryption {
        Encryption::Elgamal { .. } => tally::verify_elgamal(p, &t, bytes, &due),
        Encryption::Tlock { .. } => match c.tlock {
            Some(opener) => tally::verify_tlock(p, &t, &due, opener),
            None => return Err(Verdict::Defer("no tlock opener".into())),
        },
    };
    ok.map_err(|_| Verdict::Reject(Reason::BadTally))
}

/// Re-judges a logged tally (the auditor): the reason it would be refused.
pub fn tally_problem(state: &State, t: &Tally, bytes: &[u8], c: &Checkers) -> Option<String> {
    let p = state.polls.get(&t.poll)?;
    let due = policy::due_at(state, t.poll, t.checkpoint?)?;
    match &p.current().encryption {
        Encryption::Elgamal { .. } => tally::verify_elgamal(p, t, bytes, &due).err(),
        Encryption::Tlock { .. } => c.tlock.and_then(|o| tally::verify_tlock(p, t, &due, o).err()),
    }
}
