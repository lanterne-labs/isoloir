//! The audit (SPEC §16): the log replayed checkpoint by checkpoint
//! through the same state machine and judge as the ingest. The authority
//! replays the same way before it decrypts anything: an authority only
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
    /// Refusals covered by `rejects` entries (counted in `rejects` once
    /// their list was read).
    pub summarized: u64,
    /// Refusals not judged again: the log keeps their hash, and the audit
    /// was given no copy of their body.
    pub unjudged: u64,
    /// Refusals of `rejects` entries whose list the audit did not read.
    pub unlisted: u64,
}

impl Report {
    fn problem(&mut self, s: String) {
        self.problems.push(s);
    }
}

/// A refused message's body as the audit got it: from a relay (a verified
/// event, so with its author) or from the ingest (`GET /v1/refused/<id>`).
#[derive(Clone, Debug)]
pub struct Copy {
    pub author: Option<String>,
    pub body: Vec<u8>,
}

/// The auditor.
pub struct Auditor<'a> {
    pub state: State,
    verifier: Option<note::Verifier>,
    pinned: bool,
    checkers: Checkers<'a>,
    pub report: Report,
    /// The bodies of refused messages, by event id: the log keeps only
    /// their hash (SPEC §11.4).
    pub copies: std::collections::HashMap<String, Copy>,
    /// The lists of the `rejects` entries, by checkpoint index: the
    /// `reject` bodies, in body-hash order.
    pub lists: std::collections::HashMap<u64, Vec<Vec<u8>>>,
}

type Recheck = Vec<(String, EntryKind, Vec<u8>, crate::Reason)>;

impl<'a> Auditor<'a> {
    /// An auditor; `log_key` pins the ledger's key (else the key the
    /// ledger entry names is taken, which proves only that the notes are
    /// consistent with it).
    pub fn new(log_key: Option<&str>, checkers: Checkers<'a>) -> Result<Self, String> {
        let verifier = log_key.map(note::Verifier::parse).transpose()?;
        Ok(Auditor { state: State::new(), pinned: verifier.is_some(), verifier, checkers, report: Report::default(), copies: Default::default(), lists: Default::default() })
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
        // Body-hash order within a checkpoint, closes last (SPEC §4).
        let closes_from = entries.iter().rposition(|(k, _)| *k != EntryKind::Close).map(|i| i + 1).unwrap_or(0);
        if entries[..closes_from].iter().any(|(k, _)| *k == EntryKind::Close) {
            self.report.problem(format!("checkpoint {index}: a close entry before other entries"));
        }
        let hashes: Vec<String> = entries[..closes_from].iter().map(|(_, b)| encoding::body_hash(b)).collect();
        if hashes.windows(2).any(|w| w[0] > w[1]) {
            self.report.problem(format!("checkpoint {index}: entries not in body-hash order"));
        }
        // Messages are judged against the state at the start of the
        // checkpoint (what the ingest saw when it judged them: at its
        // time, or at the previous one's for time-dependent rules). The
        // state is not cloned: the judge reads it, and nothing is applied
        // before every entry was judged.
        //
        // Refusals the pre-checkpoint state would accept: judged again
        // after the checkpoint's entries (a rule such as the seq gap
        // depends on what arrived first, which the log does not say).
        let mut recheck: Recheck = vec![];
        let mut listed: Vec<usize> = vec![];
        for (i, (kind, b)) in entries.iter().enumerate() {
            let seq = start + i as u64;
            match kind {
                EntryKind::Register | EntryKind::Ballot => match judge_at(*kind, b, &self.state, &self.checkers, cp.time, prev_time) {
                    Verdict::Accept => {}
                    Verdict::Reject(r) => self.report.problem(format!("entry {seq} ({}): logged, but {}", kind.as_str(), r.as_str())),
                    // A check that could not run is not a pass.
                    Verdict::Defer(e) => self.report.problem(format!("entry {seq}: not checked ({e})")),
                },
                EntryKind::Tally => {
                    if let Ok(Body::Tally(t)) = body::decode(EntryKind::Tally, b) {
                        match t.checkpoint.and_then(|c| policy::due_at(&self.state, t.poll, c)) {
                            None => self.report.problem(format!("entry {seq}: a tally that was not due")),
                            Some(_) => {
                                if let Some(e) = judge::tally_problem(&self.state, &t, b, &self.checkers) {
                                    self.report.problem(format!("entry {seq}: tally: {e}"));
                                }
                            }
                        }
                    }
                }
                EntryKind::Ledger | EntryKind::Registry | EntryKind::Poll => {
                    if let Err(e) = judge::judge_setup(&self.state, *kind, b, cp.time) {
                        self.report.problem(format!("entry {seq}: setup: {e}"));
                    }
                }
                EntryKind::Reject => {
                    let Ok(Body::Reject(r)) = body::decode(EntryKind::Reject, b) else { continue };
                    self.refusal(&format!("entry {seq}"), &r, cp.time, prev_time, &mut recheck);
                }
                EntryKind::Rejects => {
                    let Ok(Body::Rejects(sum)) = body::decode(EntryKind::Rejects, b) else { continue };
                    self.report.summarized += sum.count;
                    let Some(list) = self.lists.get(&index).cloned() else {
                        self.report.unlisted += sum.count;
                        continue;
                    };
                    let what = format!("entry {seq} (the refusals of checkpoint {index})");
                    if list.len() as u64 != sum.count || body::rejects_root(&list) != sum.root {
                        self.report.problem(format!("{what}: the list given is not the one the log names ({} refusals, root {})", sum.count, sum.root));
                        self.report.unlisted += sum.count;
                        continue;
                    }
                    if list.windows(2).any(|w| encoding::body_hash(&w[0]) >= encoding::body_hash(&w[1])) {
                        self.report.problem(format!("{what}: not in body-hash order"));
                    }
                    let mut size = 0;
                    for (j, rb) in list.iter().enumerate() {
                        match body::decode(EntryKind::Reject, rb) {
                            Ok(Body::Reject(r)) if r.raw.is_none() && r.size.is_some() => {
                                size += r.size.unwrap_or(0);
                                self.state.rejected.insert(r.of.clone());
                                self.refusal(&format!("{what}, refusal {j}"), &r, cp.time, prev_time, &mut recheck);
                            }
                            _ => self.report.problem(format!("{what}: refusal {j} is not a reject body")),
                        }
                    }
                    if size != sum.size {
                        self.report.problem(format!("{what}: {size} bytes listed, the log says {}", sum.size));
                    }
                    self.report.rejects += sum.count;
                    listed.push(i);
                }
                EntryKind::Close => {}
            }
        }
        // Apply: conflicts between entries of the same checkpoint show here.
        for (i, (kind, b)) in entries.iter().enumerate() {
            if let (EntryKind::Close, Ok(Body::Close(c))) = (kind, body::decode(EntryKind::Close, b)) {
                let seq = start + i as u64;
                match self.state.polls.get(&c.poll) {
                    None => self.report.problem(format!("entry {seq}: close of an unknown poll")),
                    Some(p) => {
                        let closes = p.current().closes;
                        if c.at != closes || cp.time < closes || prev_time.is_some_and(|t| t >= closes) {
                            self.report.problem(format!("entry {seq}: the close is not at the first checkpoint after {closes}"));
                        }
                        let last = p.ballots.last().map(|b| b.seq).unwrap_or(0);
                        if last != c.last {
                            self.report.problem(format!("entry {seq}: close names ballot {} as the last, the log {last}", c.last));
                        }
                    }
                }
            }
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
        for i in listed {
            let seq = start + i as u64;
            if let Some(s) = self.state.summaries.iter_mut().find(|(s, _)| *s == seq) {
                s.1 = true;
            }
        }
        for (what, k, raw, reason) in recheck {
            if judge_at(k, &raw, &self.state, &self.checkers, cp.time, prev_time) == Verdict::Accept {
                self.report.problem(format!("{what}: refused as {}, but the message is valid", reason.as_str()));
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

    /// One refusal: its body from the log (the earlier form), or from a
    /// copy, hashed against the log and judged again; without a body, it
    /// is counted as not judged.
    fn refusal(&mut self, what: &str, r: &crate::body::Reject, time: u64, prev_time: Option<u64>, recheck: &mut Recheck) {
        let k = r.kind.as_deref().and_then(EntryKind::parse);
        let raw = match (&r.raw, self.copies.get(&r.of)) {
            (Some(x), _) => match encoding::unb64(x) {
                Ok(b) => Some(b),
                Err(_) => {
                    self.report.problem(format!("{what}: a reject whose raw body is not base64"));
                    return;
                }
            },
            (None, Some(c)) => {
                if let (Some(a), Some(b)) = (&r.author, &c.author) {
                    if a != b {
                        self.report.problem(format!("{what}: a refusal of {} by {a}, the event is by {b}", r.of));
                        return;
                    }
                }
                Some(c.body.clone())
            }
            (None, None) => None,
        };
        let Some(raw) = raw else {
            // The earlier form kept the body below 256 KiB: without it, the
            // refusal can only be of an oversized message.
            if r.size.is_none() && r.reason != crate::Reason::Malformed {
                self.report.problem(format!("{what}: a refusal ({}) without its raw body", r.reason.as_str()));
            } else {
                self.report.unjudged += 1;
            }
            return;
        };
        if encoding::body_hash(&raw) != r.hash {
            self.report.problem(format!("{what}: a reject whose body is not its hash"));
            return;
        }
        if r.size.is_some_and(|n| n != raw.len() as u64) {
            self.report.problem(format!("{what}: a reject whose size is not its body's"));
            return;
        }
        let Some(k) = k else {
            if r.reason != crate::Reason::Malformed {
                self.report.problem(format!("{what}: a refusal ({}) of no kind", r.reason.as_str()));
            }
            return;
        };
        match judge_at(k, &raw, &self.state, &self.checkers, time, prev_time) {
            Verdict::Accept => recheck.push((what.to_string(), k, raw, r.reason)),
            Verdict::Defer(e) => self.report.problem(format!("{what}: a refusal not checked ({e})")),
            Verdict::Reject(_) => {}
        }
    }

    /// Ends the audit: what is due and not published.
    pub fn finish(mut self) -> (State, Report) {
        // A check that could not run is said (SPEC §16).
        if self.report.unjudged > 0 {
            self.report.warnings.push(format!(
                "{} refusals not judged again: the log keeps their hash, not their body, and no relay or ingest copy was given (--relays, --ledger)",
                self.report.unjudged
            ));
        }
        if self.report.unlisted > 0 {
            self.report.warnings.push(format!(
                "{} refusals are only summed up in `rejects` entries and their lists were not read (--ledger): they are not judged again, and a relay event they cover cannot be told from a withheld one",
                self.report.unlisted
            ));
        }
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

/// A message judged against the state at the start of its checkpoint: at
/// the checkpoint's time, or at the previous one's for time-dependent
/// rules (what the ingest saw when it judged it).
fn judge_at(kind: EntryKind, b: &[u8], st: &State, checkers: &Checkers, time: u64, prev_time: Option<u64>) -> Verdict {
    let v = judge::judge(st, &Pending::default(), kind, b, time, checkers);
    match (&v, prev_time) {
        (Verdict::Reject(r), Some(pt)) if r.time_sensitive() => judge::judge(st, &Pending::default(), kind, b, pt, checkers),
        _ => v,
    }
}

/// Withholding (SPEC §11.3, §16): with what the relays hold for this
/// ledger, every message was judged (logged, or refused in the log), and
/// every message acknowledged as accepted is logged by the checkpoint its
/// acknowledgement named. Messages younger than `grace` seconds before
/// the last checkpoint may still be pending.
pub fn check_relays(state: &State, events: &[crate::sig::Event], ingest: &str, grace: u64) -> Vec<String> {
    check_relays_report(state, events, ingest, grace).0
}

/// [`check_relays`], with the warnings: the events that a `rejects` entry
/// whose list was not read may cover (neither judged nor withheld for
/// sure).
pub fn check_relays_report(state: &State, events: &[crate::sig::Event], ingest: &str, grace: u64) -> (Vec<String>, Vec<String>) {
    use crate::body::{decode_ack, Outcome};
    let mut problems = vec![];
    let mut warnings = vec![];
    let Some(last) = state.last_checkpoint() else { return (problems, warnings) };
    let judged = |e: &crate::sig::Event| state.hashes.contains_key(&encoding::body_hash(e.content.as_bytes())) || state.rejected.contains(&e.id);
    // The times of the checkpoints with an unread list of refusals: an
    // event may be one of them if it was posted before such a checkpoint.
    let unread: Vec<u64> = state.summaries.iter().filter(|(_, listed)| !listed).filter_map(|(seq, _)| state.checkpoint_of(*seq).map(|c| c.time)).collect();
    let mut maybe = 0;
    for e in events {
        if !matches!(e.kind, 7100 | 7101 | 7105) || !e.verify() || e.created_at + grace > last.time {
            continue;
        }
        if !judged(e) {
            if unread.iter().any(|t| *t + grace >= e.created_at) {
                maybe += 1;
            } else {
                problems.push(format!("event {} (kind {}) is on a relay and was never judged", e.id, e.kind));
            }
        }
    }
    if maybe > 0 {
        warnings.push(format!("{maybe} events on the relays are not in the log, and may be among the refusals of `rejects` entries whose lists were not read (--ledger)"));
    }
    // Acks found on the relays, and those voters attached to complaints.
    let from_complaints: Vec<crate::sig::Event> = events
        .iter()
        .filter(|e| e.kind == 7106 && e.verify())
        .filter_map(|e| serde_json::from_str::<serde_json::Value>(&e.content).ok())
        .filter_map(|v| serde_json::from_value::<crate::sig::Event>(v.get("ack")?.clone()).ok())
        .collect();
    let mut seen = std::collections::HashSet::new();
    for a in events.iter().chain(from_complaints.iter()).filter(|e| e.kind == 7102 && e.pubkey == ingest && e.verify()) {
        if !seen.insert(a.id.clone()) {
            continue;
        }
        let Ok(ack) = decode_ack(a.content.as_bytes()) else { continue };
        if ack.outcome != Outcome::Accepted {
            continue;
        }
        let Some(c) = ack.checkpoint else { continue };
        if c > last.index {
            continue;
        }
        match state.hashes.get(&ack.hash) {
            Some(seq) if state.checkpoint_of(*seq).is_some_and(|cp| cp.index <= c) => {}
            _ => problems.push(format!("the ingest acknowledged {} for checkpoint {c} and did not log it there", ack.of)),
        }
    }
    (problems, warnings)
}
