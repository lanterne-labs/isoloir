//! The audit (SPEC §16): the log replayed checkpoint by checkpoint
//! through the same state machine and judge as the ingest. The trustee
//! replays the same way before it decrypts anything: a decrypter only
//! decrypts aggregates of ballots it verified itself.

use crate::body::{self, Body, EntryKind, Publish};
use crate::judge::{self, Checkers, Pending, Verdict};
use crate::note::{self, Checkpoint};
use crate::policy;
use crate::state::State;
use isoloir_core::encoding;

/// What an audit found.
#[derive(Clone, Debug, Default)]
pub struct Report {
    pub problems: Vec<String>,
    pub warnings: Vec<String>,
    pub checkpoints: u64,
    pub entries: u64,
    pub registrations: u64,
    pub ballots: u64,
    pub rejects: u64,
    pub tallies: u64,
}

impl Report {
    fn problem(&mut self, s: String) {
        self.problems.push(s);
    }
}

/// The auditor.
pub struct Auditor<'a> {
    pub state: State,
    verifier: Option<note::Verifier>,
    pinned: bool,
    checkers: Checkers<'a>,
    pub report: Report,
}

impl<'a> Auditor<'a> {
    /// An auditor; `log_key` pins the ledger's key (else the key the
    /// ledger entry names is taken, which proves only that the notes are
    /// consistent with it).
    pub fn new(log_key: Option<&str>, checkers: Checkers<'a>) -> Result<Self, String> {
        let verifier = log_key.map(note::Verifier::parse).transpose()?;
        Ok(Auditor { state: State::new(), pinned: verifier.is_some(), verifier, checkers, report: Report::default() })
    }

    /// Feeds one checkpoint: its signed note and its entries in log order.
    pub fn checkpoint(&mut self, signed: &str, entries: &[(EntryKind, Vec<u8>)]) -> Result<Checkpoint, String> {
        if self.verifier.is_none() {
            // The first note: the key comes from the ledger entry it covers.
            let (EntryKind::Ledger, b) = entries.first().ok_or("the first checkpoint has no entry")? else {
                return Err("the first entry is not the ledger's".into());
            };
            let Ok(Body::Ledger(l)) = body::decode(EntryKind::Ledger, b) else { return Err("the ledger entry does not decode".into()) };
            self.verifier = Some(note::Verifier::parse(&l.log_key)?);
            self.report.warnings.push("the log key was not pinned: the notes are only checked against the key the log names".into());
        }
        let text = self.verifier.as_ref().unwrap().open(signed).map_err(|e| format!("checkpoint note: {e}"))?;
        let cp = Checkpoint::parse(text)?;
        let index = cp.index;
        let prev_time = self.state.last_checkpoint().map(|c| c.time);
        let start = self.state.next_seq();
        if cp.size != start + entries.len() as u64 {
            return Err(format!("checkpoint {index}: size {} but {} entries before and {} given", cp.size, start, entries.len()));
        }
        // Body-hash order within a checkpoint (SPEC §4).
        let hashes: Vec<String> = entries.iter().map(|(_, b)| encoding::body_hash(b)).collect();
        if hashes.windows(2).any(|w| w[0] > w[1]) {
            self.report.problem(format!("checkpoint {index}: entries not in body-hash order"));
        }
        // Accepted messages, judged against the state at the start of the
        // checkpoint: at its time, or at the previous one's (the window of
        // arrival) for time-dependent rules.
        let before = self.state.clone();
        let judge_at = |kind: EntryKind, b: &[u8], st: &State, checkers: &Checkers| -> Verdict {
            let v = judge::judge(st, &Pending::default(), kind, b, cp.time, checkers);
            match (&v, prev_time) {
                (Verdict::Reject(r), Some(pt)) if r.time_sensitive() => judge::judge(st, &Pending::default(), kind, b, pt, checkers),
                _ => v,
            }
        };
        for (i, (kind, b)) in entries.iter().enumerate() {
            let seq = start + i as u64;
            match kind {
                EntryKind::Register | EntryKind::Ballot => match judge_at(*kind, b, &before, &self.checkers) {
                    Verdict::Accept => {}
                    Verdict::Reject(r) => self.report.problem(format!("entry {seq} ({}): logged, but {}", kind.as_str(), r.as_str())),
                    Verdict::Defer(e) => self.report.warnings.push(format!("entry {seq}: not checked ({e})")),
                },
                EntryKind::Tally => {
                    if let Ok(Body::Tally(t)) = body::decode(EntryKind::Tally, b) {
                        match t.checkpoint.and_then(|c| policy::due_at(&before, t.poll, c)) {
                            None => self.report.problem(format!("entry {seq}: a tally that was not due")),
                            Some(_) => {
                                if let Some(e) = judge::tally_problem(&before, &t, b, &self.checkers) {
                                    self.report.problem(format!("entry {seq}: tally: {e}"));
                                }
                            }
                        }
                    }
                }
                EntryKind::Ledger | EntryKind::Registry | EntryKind::Poll => {
                    if let Err(e) = judge::judge_setup(&before, *kind, b, cp.time) {
                        self.report.problem(format!("entry {seq}: setup: {e}"));
                    }
                }
                EntryKind::Close => {
                    if let Ok(Body::Close(c)) = body::decode(EntryKind::Close, b) {
                        match before.polls.get(&c.poll) {
                            None => self.report.problem(format!("entry {seq}: close of an unknown poll")),
                            Some(p) => {
                                let closes = p.current().closes;
                                if c.at != closes || cp.time < closes || prev_time.is_some_and(|t| t >= closes) {
                                    self.report.problem(format!("entry {seq}: the close is not at the first checkpoint after {closes}"));
                                }
                                let last = p.ballots.last().map(|b| b.seq);
                                if last.is_some_and(|l| l != c.last) {
                                    self.report.problem(format!("entry {seq}: close names ballot {} as the last, the log {:?}", c.last, last));
                                }
                            }
                        }
                    }
                }
                EntryKind::Reject => {}
            }
        }
        // Apply: conflicts between entries of the same checkpoint show here.
        for (kind, b) in entries {
            if let Err(e) = self.state.apply(*kind, b, cp.time) {
                self.report.problem(e);
            }
            match kind {
                EntryKind::Register => self.report.registrations += 1,
                EntryKind::Ballot => self.report.ballots += 1,
                EntryKind::Reject => self.report.rejects += 1,
                EntryKind::Tally => self.report.tallies += 1,
                _ => {}
            }
        }
        // Refusals, judged again against the state at the end of the
        // checkpoint (a conflicting message may be logged in it).
        for (i, (kind, b)) in entries.iter().enumerate() {
            if *kind != EntryKind::Reject {
                continue;
            }
            let Ok(Body::Reject(r)) = body::decode(EntryKind::Reject, b) else { continue };
            let (Some(raw), Some(k)) = (r.raw.as_deref().and_then(|x| encoding::unb64(x).ok()), r.kind.as_deref().and_then(EntryKind::parse)) else { continue };
            if encoding::body_hash(&raw) != r.hash {
                self.report.problem(format!("entry {}: a reject whose raw body is not its hash", start + i as u64));
                continue;
            }
            let v = judge_at(k, &raw, &self.state, &self.checkers);
            if v == Verdict::Accept {
                self.report.problem(format!("entry {}: refused as {}, but the message is valid", start + i as u64, r.reason.as_str()));
            }
        }
        if let Err(e) = self.state.record(&cp) {
            self.report.problem(e);
            return Err(format!("checkpoint {index}: the state diverged from the note"));
        }
        self.report.checkpoints += 1;
        self.report.entries = self.state.next_seq();
        Ok(cp)
    }

    /// Ends the audit: what is due and not published.
    pub fn finish(mut self) -> (State, Report) {
        for (id, p) in &self.state.polls {
            if let Some(due) = policy::next_due(&self.state, *id) {
                let what = if due.is_final { "the final tally" } else { "a tally" };
                let mode = matches!(p.current().publish, Publish::Open { .. });
                self.report.warnings.push(format!("poll {id}: {what} is due since checkpoint {} (open: {mode})", due.checkpoint));
            }
        }
        if !self.pinned {
            self.report.warnings.dedup();
        }
        (self.state, self.report)
    }
}
