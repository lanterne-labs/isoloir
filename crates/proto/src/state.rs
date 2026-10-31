//! The ledger's state (SPEC §4–§10): what the log holds, replayed entry by
//! entry. The ingest appends through it, the auditor replays through it:
//! one implementation of the trees, the pseudonyms, the counted ballots
//! and the setups in force.

use crate::body::{self, Body, Close, EntryKind, LedgerSetup, PollSetup, RegistrySetup, Revote, Tally};
use crate::kinds::Variant;
use crate::log::{self, Hash, Log};
use crate::matrix;
use crate::note::Checkpoint;
use crate::statement;
use isoloir_core::grumpkin::Ciphertext;
use isoloir_core::tree::Tree;
use isoloir_core::{encoding, field, Fr};
use std::collections::{BTreeMap, HashMap, HashSet};

/// How long the previous setup of a poll stays in force after its
/// successor is logged (SPEC §13).
pub const SETUP_GRACE: u64 = 86_400;

/// A ballot's pseudonym.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pseudonym {
    Linked { nullifier: String, seq: u32 },
    Delta { ident: String },
}

/// A logged ballot.
#[derive(Clone, Debug)]
pub struct LoggedBallot {
    pub seq: u64,
    pub hash: String,
    pub pseudonym: Pseudonym,
    pub ct: Vec<Ciphertext>,
    pub vcmt: Option<Fr>,
    pub blob: Option<Vec<u8>>,
}

/// A tree root as a checkpoint named it.
#[derive(Clone, Copy, Debug)]
pub struct Root {
    pub index: u64,
    pub time: u64,
    pub size: u64,
    pub root: Fr,
}

#[derive(Clone, Debug)]
pub struct RegistryState {
    pub setups: Vec<(u64, RegistrySetup)>,
    pub tree: Tree,
    pub uids: HashMap<String, u64>,
    pub ids: HashMap<String, u64>,
    pub roots: Vec<Root>,
    latest_root: HashMap<Fr, u64>,
}

impl RegistryState {
    pub fn current(&self) -> &RegistrySetup {
        &self.setups.last().expect("a registry has a setup").1
    }

    /// Whether `root` is a checkpoint root at most `age` old at `now`.
    pub fn root_fresh(&self, root: &Fr, now: u64, age: u64) -> bool {
        self.latest_root.get(root).is_some_and(|t| t + age >= now)
    }
}

#[derive(Clone, Debug)]
pub struct PollState {
    /// Entry seq, the time it was logged, the setup.
    pub setups: Vec<(u64, u64, PollSetup)>,
    pub variant: Variant,
    pub ballots: Vec<LoggedBallot>,
    /// Linked: the last ballot of each nullifier (its seq and index).
    pub latest: HashMap<String, (u32, usize)>,
    pub idents: HashSet<String>,
    pub btree: Option<Tree>,
    pub broots: Vec<Root>,
    latest_broot: HashMap<Fr, u64>,
    pub tallies: Vec<(u64, Tally)>,
    pub close: Option<(u64, Close)>,
}

impl PollState {
    pub fn current(&self) -> &PollSetup {
        &self.setups.last().expect("a poll has a setup").2
    }

    /// The setup a ballot names, when in force at `now`.
    pub fn setup_in_force(&self, seq: u64, now: u64) -> Option<&PollSetup> {
        let i = self.setups.iter().position(|(s, _, _)| *s == seq)?;
        if i + 1 == self.setups.len() {
            return Some(&self.setups[i].2);
        }
        if i + 2 == self.setups.len() && now < self.setups[i + 1].1 + SETUP_GRACE {
            return Some(&self.setups[i].2);
        }
        None
    }

    pub fn broot_fresh(&self, root: &Fr, now: u64, age: u64) -> bool {
        self.latest_broot.get(root).is_some_and(|t| t + age >= now)
    }

    /// The ballots that count up to a log position (SPEC §10.2).
    pub fn counted(&self, upto: u64) -> Vec<&LoggedBallot> {
        match self.current().revote {
            Revote::Delta => self.ballots.iter().filter(|b| b.seq <= upto).collect(),
            Revote::None | Revote::Linked => {
                let mut last: HashMap<&str, &LoggedBallot> = HashMap::new();
                for b in self.ballots.iter().filter(|b| b.seq <= upto) {
                    if let Pseudonym::Linked { nullifier, seq } = &b.pseudonym {
                        let replace = match last.get(nullifier.as_str()) {
                            Some(prev) => matches!(&prev.pseudonym, Pseudonym::Linked { seq: s, .. } if s < seq),
                            None => true,
                        };
                        if replace {
                            last.insert(nullifier, b);
                        }
                    }
                }
                let mut v: Vec<&LoggedBallot> = last.into_values().collect();
                v.sort_by_key(|b| b.seq);
                v
            }
        }
    }

    /// The pseudonyms whose counted ballot changed in `(after, upto]`
    /// (delta: the ballots).
    pub fn changed(&self, after: Option<u64>, upto: u64) -> u64 {
        let range = self.ballots.iter().filter(|b| after.is_none_or(|a| b.seq > a) && b.seq <= upto);
        match self.current().revote {
            Revote::Delta => range.count() as u64,
            _ => range
                .filter_map(|b| match &b.pseudonym {
                    Pseudonym::Linked { nullifier, .. } => Some(nullifier.as_str()),
                    Pseudonym::Delta { .. } => None,
                })
                .collect::<HashSet<_>>()
                .len() as u64,
        }
    }

    /// The last tally logged.
    pub fn last_tally(&self) -> Option<&Tally> {
        self.tallies.last().map(|(_, t)| t)
    }
}

/// A checkpoint as the state recorded it.
#[derive(Clone, Debug)]
pub struct CheckpointRec {
    pub index: u64,
    pub time: u64,
    pub size: u64,
    pub root: Hash,
}

/// The ledger's state.
#[derive(Clone, Debug, Default)]
pub struct State {
    /// Entry seq, time, setup.
    pub ledger: Vec<(u64, u64, LedgerSetup)>,
    pub registries: BTreeMap<u32, RegistryState>,
    pub polls: BTreeMap<u32, PollState>,
    pub log: Log,
    pub checkpoints: Vec<CheckpointRec>,
    /// Every logged body's hash, to its seq.
    pub hashes: HashMap<String, u64>,
    /// The event ids of logged rejects.
    pub rejected: HashSet<String>,
    /// Every entry's kind and body, by seq.
    pub entries: Vec<(EntryKind, Vec<u8>)>,
}

impl State {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ledger(&self) -> Option<&LedgerSetup> {
        self.ledger.last().map(|(_, _, l)| l)
    }

    /// The seq the next entry takes.
    pub fn next_seq(&self) -> u64 {
        self.log.len()
    }

    pub fn last_checkpoint(&self) -> Option<&CheckpointRec> {
        self.checkpoints.last()
    }

    /// The checkpoint covering an entry: the first whose size exceeds it.
    pub fn checkpoint_of(&self, seq: u64) -> Option<&CheckpointRec> {
        self.checkpoints.iter().find(|c| c.size > seq)
    }

    /// Checks a setup entry against the state, at time `time`, without
    /// changing it.
    pub fn check_setup(&self, body: &Body, time: u64) -> Result<(), String> {
        match body {
            Body::Ledger(l) => {
                matrix::check_ledger(l)?;
                match self.ledger() {
                    None if self.next_seq() == 0 && l.version == 1 => Ok(()),
                    None => Err("the first entry is the ledger's, version 1".into()),
                    Some(old) => matrix::ledger_successor(old, l),
                }
            }
            _ if self.ledger.is_empty() => Err("the first entry is the ledger's".into()),
            Body::Registry(r) => {
                matrix::check_registry(r)?;
                match self.registries.get(&r.id) {
                    None if r.version == 1 => Ok(()),
                    None => Err(format!("registry {}: version 1 first", r.id)),
                    Some(st) => matrix::registry_successor(st.current(), r),
                }
            }
            Body::Poll(p) => {
                let reg = self.registries.get(&p.registry).ok_or("poll: unknown registry")?;
                matrix::check_poll(p, reg.current())?;
                match self.polls.get(&p.id) {
                    None if p.version == 1 => Ok(()),
                    None => Err(format!("poll {}: version 1 first", p.id)),
                    Some(st) if st.close.is_some() => Err(format!("poll {}: closed", p.id)),
                    Some(st) => matrix::poll_successor(st.current(), p, time),
                }
            }
            _ => Err("not a setup".into()),
        }
    }

    /// Appends an entry judged acceptable, at the time of the checkpoint
    /// that logs it, and returns its seq. An error is an inconsistency: the
    /// entry contradicts the state (the auditor reports it; the ingest
    /// never logs it).
    pub fn apply(&mut self, kind: EntryKind, bytes: &[u8], time: u64) -> Result<u64, String> {
        let seq = self.next_seq();
        let body = body::decode(kind, bytes).map_err(|r| format!("entry {seq}: {}", r.as_str()))?;
        if matches!(body, Body::Ledger(_) | Body::Registry(_) | Body::Poll(_)) {
            self.check_setup(&body, time)?;
        }
        match body {
            Body::Ledger(l) => self.ledger.push((seq, time, l)),
            _ if self.ledger.is_empty() => return Err("the first entry is the ledger's".into()),
            Body::Registry(r) => {
                match self.registries.get_mut(&r.id) {
                    None => {
                        self.registries.insert(
                            r.id,
                            RegistryState {
                                tree: Tree::new(r.depth as usize),
                                setups: vec![(seq, r)],
                                uids: HashMap::new(),
                                ids: HashMap::new(),
                                roots: vec![],
                                latest_root: HashMap::new(),
                            },
                        );
                    }
                    Some(st) => st.setups.push((seq, r)),
                }
            }
            Body::Register(r) => {
                let st = self.registries.get_mut(&r.registry).ok_or("register: unknown registry")?;
                if st.uids.contains_key(&r.uid) || st.ids.contains_key(&r.id) {
                    return Err(format!("register {seq}: passport or leaf registered twice"));
                }
                let leaf = field::from_hex(&r.id).map_err(|e| e.to_string())?;
                let pos = st.tree.push(leaf).map_err(|e| e.to_string())? as u64;
                st.uids.insert(r.uid.clone(), seq);
                st.ids.insert(r.id.clone(), pos);
            }
            Body::Poll(p) => {
                let reg = self.registries.get(&p.registry).ok_or("poll: unknown registry")?;
                let variant = matrix::check_poll(&p, reg.current())?;
                match self.polls.get_mut(&p.id) {
                    None => {
                        let btree = p.ballot_depth.map(|d| Tree::new(d as usize));
                        self.polls.insert(
                            p.id,
                            PollState {
                                setups: vec![(seq, time, p)],
                                variant,
                                ballots: vec![],
                                latest: HashMap::new(),
                                idents: HashSet::new(),
                                btree,
                                broots: vec![],
                                latest_broot: HashMap::new(),
                                tallies: vec![],
                                close: None,
                            },
                        );
                    }
                    Some(st) => st.setups.push((seq, time, p)),
                }
            }
            Body::Ballot(b) => {
                let st = self.polls.get_mut(&b.poll).ok_or("ballot: unknown poll")?;
                if st.close.is_some() {
                    return Err(format!("ballot {seq} after the close"));
                }
                let variant = st.variant;
                statement::shape(&b, &variant).map_err(|_| format!("ballot {seq}: malformed"))?;
                let pseudonym = match (&b.nullifier, b.seq, &b.ident) {
                    (Some(n), Some(s), None) => Pseudonym::Linked { nullifier: n.clone(), seq: s },
                    (None, None, Some(i)) => Pseudonym::Delta { ident: i.clone() },
                    _ => return Err(format!("ballot {seq}: malformed")),
                };
                let ct = if b.ct.is_some() { statement::ciphertexts(&b, &variant).map_err(|_| format!("ballot {seq}: ciphertexts"))? } else { vec![] };
                let vcmt = b.vcmt.as_deref().map(field::from_hex).transpose().map_err(|e| e.to_string())?;
                let blob = b.blob.as_deref().map(encoding::unb64).transpose().map_err(|e| e.to_string())?;
                let idx = st.ballots.len();
                match &pseudonym {
                    Pseudonym::Linked { nullifier, seq: s } => {
                        // Within a checkpoint entries are in body-hash order,
                        // not arrival order: keep the highest seq.
                        match st.latest.get(nullifier) {
                            Some(_) if st.current().revote == Revote::None => {
                                return Err(format!("ballot {seq}: a second ballot in a poll without re-votes"));
                            }
                            Some((last, _)) if last == s => return Err(format!("ballot {seq}: seq {s} used twice")),
                            Some((last, _)) if last > s => {}
                            _ => {
                                st.latest.insert(nullifier.clone(), (*s, idx));
                            }
                        }
                    }
                    Pseudonym::Delta { ident } => {
                        // Every check before any change: a refused entry
                        // leaves the state as it was.
                        if st.idents.contains(ident) {
                            return Err(format!("ballot {seq}: ident used twice"));
                        }
                        let cmt = field::from_hex(b.cmt.as_deref().unwrap_or("")).map_err(|e| e.to_string())?;
                        let leaf = delta_leaf(&field::from_hex(ident).map_err(|e| e.to_string())?, &cmt);
                        st.btree.as_mut().ok_or("delta ballot in a poll without a ballot tree")?.push(leaf).map_err(|e| e.to_string())?;
                        st.idents.insert(ident.clone());
                    }
                }
                st.ballots.push(LoggedBallot { seq, hash: encoding::body_hash(bytes), pseudonym, ct, vcmt, blob });
            }
            Body::Reject(r) => {
                self.rejected.insert(r.of.clone());
            }
            Body::Tally(t) => {
                let st = self.polls.get_mut(&t.poll).ok_or("tally: unknown poll")?;
                st.tallies.push((seq, t));
            }
            Body::Close(c) => {
                let st = self.polls.get_mut(&c.poll).ok_or("close: unknown poll")?;
                if st.close.is_some() {
                    return Err(format!("poll {}: closed twice", c.poll));
                }
                st.close = Some((seq, c));
            }
        }
        self.log.push(log::leaf_hash(&log::leaf_data(seq, kind.as_str(), bytes)));
        self.hashes.insert(encoding::body_hash(bytes), seq);
        self.entries.push((kind, bytes.to_vec()));
        Ok(seq)
    }

    /// The checkpoint the state calls for now (SPEC §4).
    pub fn checkpoint(&self, index: u64, time: u64, mirror: Option<String>) -> Checkpoint {
        Checkpoint {
            origin: self.ledger().map(|l| l.origin.clone()).unwrap_or_default(),
            size: self.log.len(),
            root: self.log.root(),
            index,
            time,
            registries: self.registries.iter().map(|(id, r)| (*id, r.tree.len() as u64, r.tree.root())).collect(),
            ballots: self
                .polls
                .iter()
                .filter_map(|(id, p)| p.btree.as_ref().map(|t| (*id, t.len() as u64, t.root())))
                .collect(),
            mirror,
        }
    }

    /// Records a checkpoint: it must be the one the state calls for, with
    /// the next index and a time not before the previous one.
    pub fn record(&mut self, cp: &Checkpoint) -> Result<(), String> {
        let want = self.checkpoint(cp.index, cp.time, cp.mirror.clone());
        if *cp != want {
            return Err(format!("checkpoint {}: not the log's (size {} root, trees)", cp.index, cp.size));
        }
        let index = self.checkpoints.last().map(|c| c.index + 1).unwrap_or(1);
        if cp.index != index {
            return Err(format!("checkpoint {}: expected index {index}", cp.index));
        }
        if self.checkpoints.last().is_some_and(|c| c.time > cp.time) {
            return Err(format!("checkpoint {}: time goes back", cp.index));
        }
        for (id, size, root) in &cp.registries {
            let r = self.registries.get_mut(id).expect("checked above");
            r.roots.push(Root { index: cp.index, time: cp.time, size: *size, root: *root });
            r.latest_root.insert(*root, cp.time);
        }
        for (id, size, root) in &cp.ballots {
            let p = self.polls.get_mut(id).expect("checked above");
            p.broots.push(Root { index: cp.index, time: cp.time, size: *size, root: *root });
            p.latest_broot.insert(*root, cp.time);
        }
        self.checkpoints.push(CheckpointRec { index: cp.index, time: cp.time, size: cp.size, root: cp.root });
        Ok(())
    }
}

/// The ballot tree leaf of a delta ballot: `H(T_bleaf, ident, cmt)`.
pub fn delta_leaf(ident: &Fr, cmt: &Fr) -> Fr {
    isoloir_core::poseidon2::hash(&[isoloir_core::tags::bleaf(), *ident, *cmt])
}
