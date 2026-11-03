//! The ingest (SPEC §11): reads its channels, judges every message (the
//! cheap checks at once, the proofs from a queue that serves fresh
//! identifiers first), records it before acknowledging it, logs the
//! accepted ones at the next checkpoint in one transaction (a refusal is
//! its signed ack, never an entry), closes polls on time, writes the
//! mirror (pushed in the background) and posts the checkpoint notes.

use crate::mirror::Mirror;
use crate::store::{PendingRow, Store};
use isoloir_core::{canonical, encoding};
use isoloir_proto::body::{self, Ack, Body, Close, EntryKind, Outcome, V1};
use isoloir_proto::judge::{self, Checkers, Passports, Pending, Proofs, Verdict};
use isoloir_proto::note;
use isoloir_proto::sig::Event;
use isoloir_proto::state::State;
use isoloir_proto::tally::Tlock;
use std::collections::{BinaryHeap, HashMap};
use std::cmp::Reverse;
use std::sync::Arc;

/// Nostr kinds (SPEC §11.1): ephemeral, relays keep none.
pub mod kinds {
    pub const REGISTER: u32 = 27100;
    pub const BALLOT: u32 = 27101;
    pub const ACK: u32 = 27102;
    pub const CHECKPOINT: u32 = 27103;
    pub const LINK: u32 = 27104;
    pub const TALLY: u32 = 27105;
    pub const COMPLAINT: u32 = 27106;
    /// The kinds of clients written before (stored by relays): still read,
    /// and answered in the same range.
    pub const LEGACY: u32 = 20000;

    /// The entry kind of a message kind, and whether it is a legacy kind.
    pub fn message(kind: u32) -> Option<(isoloir_proto::body::EntryKind, bool)> {
        use isoloir_proto::body::EntryKind;
        let (k, legacy) = if kind < LEGACY { (kind + LEGACY, true) } else { (kind, false) };
        Some((
            match k {
                REGISTER => EntryKind::Register,
                BALLOT => EntryKind::Ballot,
                TALLY => EntryKind::Tally,
                _ => return None,
            },
            legacy,
        ))
    }

    /// Every message kind the ingest reads.
    pub fn read() -> Vec<u32> {
        vec![REGISTER, BALLOT, TALLY, REGISTER - LEGACY, BALLOT - LEGACY, TALLY - LEGACY]
    }
}

/// How long refused bodies are kept (SPEC §11.4).
pub const REFUSED_KEPT: u64 = 30 * 86_400;

/// The window of a proof of work's time (SPEC §11.1).
pub use isoloir_proto::pow::{AHEAD as POW_AHEAD, PAST as POW_PAST};

/// The most messages waiting for their proof check; beyond, a message is
/// dropped unanswered (its device retries).
pub const QUEUE_MAX: usize = 100_000;

/// The proof of work of an envelope (SPEC §11.1); returns its time.
pub fn pow_check(origin: &str, ev: &Event, bits: u32, now: u64) -> Option<u64> {
    let tag = ev.tags.iter().find(|t| t.first().map(String::as_str) == Some("pow"))?;
    isoloir_proto::pow::check(origin, &ev.pubkey, tag, bits, now)
}

/// Finds a nonce for a key (tests, the CLI's voter).
pub fn pow_solve(origin: &str, pubkey: &str, t: u64, bits: u32) -> String {
    isoloir_proto::pow::solve(origin, pubkey, t, bits)
}

/// The identifier a message claims (SPEC §11.2: the queue's order).
fn claim(kind: EntryKind, bytes: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    match kind {
        EntryKind::Register => Some(format!("u{}:{}", v["registry"], v["uid"].as_str()?)),
        EntryKind::Ballot => Some(format!("b{}:{}", v["poll"], v["nullifier"].as_str().or(v["ident"].as_str())?)),
        _ => None,
    }
}

/// The checkers of the cheap pass: every proof check is left for later.
struct Later;
const LATER: &str = "the proof check comes later";
impl isoloir_proto::judge::Proofs for Later {
    fn verify(&self, _: &isoloir_proto::body::CircuitRef, _: &[u8], _: &[[u8; 32]]) -> Result<bool, String> {
        Err(LATER.into())
    }
}
impl Passports for Later {
    fn verify(&self, _: &isoloir_proto::body::Eligibility, _: &serde_json::Value, _: &str, _: u64) -> Result<Option<String>, String> {
        Err(LATER.into())
    }
}

/// The relay tag of a ledger (Nostr channels).
pub fn tag(origin: &str) -> String {
    format!("{}/{origin}", isoloir_proto::PROTOCOL)
}

/// The way back to the channels.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Answers on one channel (the one a message came by).
    async fn publish(&self, origin: &str, event: &Event) -> Result<(), String>;
    /// Posts an event to every channel that has an audience (the relays).
    async fn publish_all(&self, event: &Event);
}

/// A message from a channel.
#[derive(Clone, Debug)]
pub struct Incoming {
    /// The channel it came by: a relay's URL, or a direct endpoint's.
    pub origin: String,
    pub event: Event,
}

pub struct Config {
    /// The ledger's log key seed (Ed25519).
    pub log_seed: [u8; 32],
    /// The ingest's Nostr key.
    pub nostr_sk: [u8; 32],
}

pub struct Ingest {
    pub store: Store,
    pub state: State,
    pending: Pending,
    rows: Vec<PendingRow>,
    /// Accepted submissions waiting for the checkpoint: id, kind, body.
    subs: Vec<(i64, EntryKind, Vec<u8>)>,
    deferred: HashMap<String, Incoming>,
    signer: note::Signer,
    nostr_sk: [u8; 32],
    tag: String,
    pub transport: Arc<dyn Transport>,
    pub proofs: Box<dyn Proofs + Send + Sync>,
    pub passports: Box<dyn Passports + Send + Sync>,
    pub tlock: Option<Box<dyn Tlock + Send + Sync>>,
    pub mirror: Option<Arc<Mirror>>,
    /// OpenTimestamps calendars; empty: no stamps (tests, local trials).
    pub calendars: Vec<String>,
    last_upgrade: u64,
    last_purge: u64,
    /// Messages past the cheap checks, waiting for their proof check:
    /// (when their identifier was last claimed + 1, 0 for never; arrival).
    queue: BinaryHeap<Reverse<(u64, u64)>>,
    queued: HashMap<u64, Incoming>,
    queued_ids: std::collections::HashSet<String>,
    arrivals: u64,
    last_claimed: HashMap<String, u64>,
    /// The keys a proof of work was spent on: body hash and work time.
    pow_keys: HashMap<String, (String, u64)>,
}

/// The longest time between two checkpoints, even on a quiet ledger.
pub const HEARTBEAT: u64 = 600;

/// How often incomplete stamps are upgraded.
const UPGRADE_EVERY: u64 = 3_600;

/// How often the refused bodies past REFUSED_KEPT are purged.
const PURGE_EVERY: u64 = 3_600;

impl Ingest {
    /// Loads the ledger from the store: the log is replayed into the state,
    /// the pending messages are claimed again.
    #[allow(clippy::too_many_arguments)]
    pub async fn load(
        store: Store,
        config: Config,
        transport: Arc<dyn Transport>,
        proofs: Box<dyn Proofs + Send + Sync>,
        passports: Box<dyn Passports + Send + Sync>,
        tlock: Option<Box<dyn Tlock + Send + Sync>>,
        mirror: Option<Mirror>,
    ) -> anyhow::Result<Ingest> {
        let mirror = mirror.map(Arc::new);
        let mut state = State::new();
        let entries = store.entries().await?;
        let notes = store.checkpoints().await?;
        let mut it = entries.into_iter().peekable();
        let mut origin = String::new();
        // A mirror behind the database (lost, wiped, or the genesis) is
        // written again as the log is replayed; a mirror that cannot be
        // written never stops the log.
        let mirrored = mirror.as_ref().map(|m| m.last_index()).unwrap_or(u64::MAX);
        for (idx, signed) in &notes {
            let from = state.next_seq();
            while let Some((_, kind, body, _)) = it.next_if(|(_, _, _, c)| c == idx) {
                let time = note_time(signed)?;
                state.apply(kind, &body, time).map_err(|e| anyhow::anyhow!("replay: {e}"))?;
            }
            let text = signed.split("\n\n").next().unwrap_or_default().to_string() + "\n";
            let cp = note::Checkpoint::parse(&text).map_err(|e| anyhow::anyhow!("checkpoint {idx}: {e}"))?;
            origin = cp.origin.clone();
            state.record(&cp).map_err(|e| anyhow::anyhow!("replay: {e}"))?;
            if let (Some(m), true) = (&mirror, (*idx as u64) > mirrored) {
                if let Err(e) = m.write_checkpoint(&state, *idx as u64, from, signed) {
                    tracing::error!(error = %e, index = idx, "mirror during the replay");
                }
            }
        }
        if it.next().is_some() {
            anyhow::bail!("log entries beyond the last checkpoint");
        }
        let signer = note::Signer::new(&origin, &config.log_seed);
        let mut ingest = Ingest {
            store,
            pending: Pending::default(),
            rows: vec![],
            subs: vec![],
            deferred: HashMap::new(),
            tag: tag(&origin),
            signer,
            nostr_sk: config.nostr_sk,
            state,
            transport,
            proofs,
            passports,
            tlock,
            mirror,
            calendars: vec![],
            last_upgrade: 0,
            last_purge: 0,
            queue: BinaryHeap::new(),
            queued: HashMap::new(),
            queued_ids: Default::default(),
            arrivals: 0,
            last_claimed: HashMap::new(),
            pow_keys: HashMap::new(),
        };
        if let Some(m) = &ingest.mirror {
            m.start();
        }
        if let Some(l) = ingest.state.ledger() {
            if l.log_key != ingest.signer.verifier() {
                anyhow::bail!("the log key given is not the ledger's");
            }
            if l.ingest != hex::encode(isoloir_proto::sig::xonly(&ingest.nostr_sk)) {
                anyhow::bail!("the Nostr key given is not the ledger's ingest key ({}): voters would ignore every ack", l.ingest);
            }
        }
        for r in ingest.store.pending().await? {
            if r.outcome == "accepted" {
                ingest.pending.admit(r.kind, &r.body);
                ingest.rows.push(r);
            }
        }
        Ok(ingest)
    }

    /// Starts a new ledger: its first entry is the ledger setup, its first
    /// checkpoint logs it (the origin comes from the setup).
    pub async fn genesis(store: &Store, config: &Config, ledger: &isoloir_proto::body::LedgerSetup, now: u64) -> anyhow::Result<()> {
        if !store.checkpoints().await?.is_empty() {
            anyhow::bail!("this database already holds a ledger");
        }
        let signer = note::Signer::new(&ledger.origin, &config.log_seed);
        if ledger.log_key != signer.verifier() {
            anyhow::bail!("ledger.log_key is not the key of the seed given");
        }
        let mut state = State::new();
        let bytes = Body::Ledger(ledger.clone()).encode();
        state.apply(EntryKind::Ledger, &bytes, now).map_err(|e| anyhow::anyhow!(e))?;
        let cp = state.checkpoint(1, now, None);
        let signed = signer.sign(&cp.text());
        store.checkpoint(&[(0, EntryKind::Ledger, bytes.clone(), encoding::body_hash(&bytes))], 1, &signed, now, 1, &[], &[]).await
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    fn checkers(&self) -> Checkers<'_> {
        Checkers { proofs: self.proofs.as_ref(), passports: self.passports.as_ref(), tlock: self.tlock.as_deref().map(|t| t as &dyn Tlock) }
    }

    fn next_index(&self) -> u64 {
        self.state.last_checkpoint().map(|c| c.index + 1).unwrap_or(1)
    }

    #[allow(clippy::too_many_arguments)]
    fn ack_event(&self, of: &str, hash: &str, outcome: Outcome, reason: Option<isoloir_proto::Reason>, checkpoint: Option<u64>, legacy: bool, now: u64) -> Event {
        let ack = Ack { v: V1, of: of.to_string(), hash: hash.to_string(), outcome, reason, checkpoint };
        let kind = if legacy { kinds::ACK - kinds::LEGACY } else { kinds::ACK };
        // To the minute: an ack is public, and its time would date the
        // entry it names to the second (SPEC §11.2).
        Event::sign(&self.nostr_sk, now / 60 * 60, kind, vec![vec!["t".into(), self.tag.clone()], vec!["e".into(), of.to_string()]], canonical::to_string(&ack).expect("ack"))
    }

    async fn send_ack(&self, origin: &str, ev: &Event) {
        match self.transport.publish(origin, ev).await {
            Ok(()) => {
                if let Err(e) = self.store.ack_posted(ev.tag("e").unwrap_or_default()).await {
                    tracing::error!(error = %e, "recording a posted ack");
                }
            }
            Err(e) => tracing::warn!(origin, error = %e, "ack not posted; retried later"),
        }
    }

    /// Handles one message from a channel: the envelope, then the cheap
    /// checks; a message that passes them waits for its proof check in the
    /// queue ([`Ingest::work`]).
    pub async fn handle(&mut self, inc: Incoming, now: u64) -> anyhow::Result<()> {
        let ev = &inc.event;
        let Some((kind, _)) = kinds::message(ev.kind) else { return Ok(()) };
        if ev.tag("t") != Some(self.tag.as_str()) || !ev.verify() {
            return Ok(());
        }
        // Judged before: the same ack again, on this relay too.
        if let Some((_, ack, _)) = self.store.seen(&ev.id).await? {
            let ack: Event = serde_json::from_value(ack)?;
            self.send_ack(&inc.origin, &ack).await;
            return Ok(());
        }
        if self.queued_ids.contains(&ev.id) {
            return Ok(());
        }
        // The proof of work, bound to the key (SPEC §11.1): junk without it
        // is dropped unanswered.
        let bits = self.state.ledger().map(|l| l.pow).unwrap_or(0);
        if bits > 0 && kind != EntryKind::Tally {
            let hash = encoding::body_hash(ev.content.as_bytes());
            let origin = self.state.ledger().map(|l| l.origin.clone()).unwrap_or_default();
            let Some(t) = pow_check(&origin, ev, bits, now) else { return Ok(()) };
            match self.pow_keys.get(&ev.pubkey) {
                Some((h, _)) if *h != hash => return Ok(()),
                _ => {
                    self.pow_keys.insert(ev.pubkey.clone(), (hash, t));
                }
            }
        }
        if let Some(c) = claim(kind, ev.content.as_bytes()) {
            let last = self.last_claimed.insert(c, now);
            if self.decide(&inc, kind, now, true).await? {
                return Ok(());
            }
            if self.queued.len() >= QUEUE_MAX {
                tracing::warn!(id = %ev.id, "the queue is full: message dropped");
                return Ok(());
            }
            self.arrivals += 1;
            self.queue.push(Reverse((last.map(|t| t + 1).unwrap_or(0), self.arrivals)));
            self.queued.insert(self.arrivals, inc.clone());
            self.queued_ids.insert(ev.id.clone());
            return Ok(());
        }
        // Tallies (and what claims nothing): judged whole at once.
        self.decide(&inc, kind, now, false).await?;
        Ok(())
    }

    /// Whether messages wait for their proof check.
    pub fn has_work(&self) -> bool {
        !self.queue.is_empty()
    }

    /// Judges the first message of the queue: never-claimed identifiers
    /// first, then the longest unclaimed.
    pub async fn work(&mut self, now: u64) -> anyhow::Result<()> {
        let Some(Reverse((_, n))) = self.queue.pop() else { return Ok(()) };
        let Some(inc) = self.queued.remove(&n) else { return Ok(()) };
        self.queued_ids.remove(&inc.event.id);
        let Some((kind, _)) = kinds::message(inc.event.kind) else { return Ok(()) };
        self.decide(&inc, kind, now, false).await?;
        Ok(())
    }

    /// Judges the whole queue (tests, and before a checkpoint in a trial).
    pub async fn drain(&mut self, now: u64) -> anyhow::Result<()> {
        while self.has_work() {
            self.work(now).await?;
        }
        Ok(())
    }

    /// Judges a message (`cheap`: up to its proof check) and answers it.
    /// Returns false when the cheap pass leaves it for the proof check.
    async fn decide(&mut self, inc: &Incoming, kind: EntryKind, now: u64, cheap: bool) -> anyhow::Result<bool> {
        let ev = &inc.event;
        let legacy = ev.kind < kinds::LEGACY;
        let bytes = ev.content.as_bytes().to_vec();
        let hash = encoding::body_hash(&bytes);
        // The same body under another event (a repost): the same outcome.
        let logged = self.state.hashes.get(&hash).copied();
        let pending_same = self.rows.iter().any(|r| r.hash == hash);
        let (outcome, reason, checkpoint) = if let Some(seq) = logged.filter(|s| self.state.entries[*s as usize].0 == kind) {
            (Outcome::Accepted, None, self.state.checkpoint_of(seq).map(|c| c.index))
        } else if pending_same {
            (Outcome::Accepted, None, Some(self.next_index()))
        } else {
            let verdict = if cheap {
                let later = Later;
                let c = Checkers { proofs: &later, passports: &later, tlock: self.tlock.as_deref().map(|t| t as &dyn Tlock) };
                judge::judge(&self.state, &self.pending, kind, &bytes, now, &c)
            } else {
                judge::judge(&self.state, &self.pending, kind, &bytes, now, &self.checkers())
            };
            match verdict {
                Verdict::Accept => (Outcome::Accepted, None, Some(self.next_index())),
                Verdict::Reject(r) => (Outcome::Rejected, Some(r), None),
                Verdict::Defer(why) if cheap && why.contains(LATER) => return Ok(false),
                Verdict::Defer(why) => {
                    if !self.deferred.contains_key(&ev.id) {
                        tracing::warn!(id = %ev.id, why, deferred = self.deferred.len() + 1, "message deferred");
                    }
                    self.deferred.insert(ev.id.clone(), inc.clone());
                    return Ok(true);
                }
            }
        };
        let ack = self.ack_event(&ev.id, &hash, outcome, reason, checkpoint, legacy, now);
        let ack_json = serde_json::to_value(&ack)?;
        let fresh = logged.is_none() && !pending_same;
        let row = PendingRow {
            event_id: ev.id.clone(),
            kind,
            body: bytes.clone(),
            hash: hash.clone(),
            relay: inc.origin.clone(),
            received: now as i64,
            outcome: if outcome == Outcome::Accepted { "accepted".into() } else { "rejected".into() },
            reason: reason.map(|r| r.as_str().to_string()),
            author: Some(ev.pubkey.clone()),
        };
        match (fresh, outcome) {
            (true, Outcome::Accepted) => {
                // Durable before the ack: an accepted message is never lost.
                self.store.judged(&row, &ack_json).await?;
                self.pending.admit(kind, &bytes);
                self.rows.push(row);
            }
            // A refusal is its ack (SPEC §11.4): the body is kept a while
            // for debugging, never logged.
            (true, Outcome::Rejected) => self.store.refused(&row, &ack_json).await?,
            (false, _) => self.store.seen_only(&ev.id, &inc.origin, &ack_json).await?,
        }
        self.deferred.remove(&ev.id);
        self.send_ack(&inc.origin, &ack).await;
        Ok(true)
    }

    /// The periodic work: deferred messages, unposted acks, submissions,
    /// closes, and the checkpoint when one is due. Returns the checkpoint
    /// index written, if any.
    pub async fn tick(&mut self, now: u64) -> anyhow::Result<Option<u64>> {
        let deferred: Vec<Incoming> = self.deferred.values().cloned().collect();
        for inc in deferred {
            self.handle(inc, now).await?;
        }
        for (_, relay, ack) in self.store.unposted().await? {
            let ev: Event = serde_json::from_value(ack)?;
            self.send_ack(&relay, &ev).await;
        }
        self.take_submissions(now).await?;
        self.upgrade_stamps(now).await?;
        if now >= self.last_purge + PURGE_EVERY {
            self.last_purge = now;
            match self.store.purge_refused(now.saturating_sub(REFUSED_KEPT) as i64).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(purged = n, "refused bodies past their time"),
                Err(e) => tracing::error!(error = %e, "purging refused bodies"),
            }
            self.pow_keys.retain(|_, (_, t)| *t + POW_PAST + POW_AHEAD >= now);
            self.last_claimed.retain(|_, t| *t + 86_400 >= now);
        }
        let Some(ledger) = self.state.ledger().cloned() else { return Ok(None) };
        let closes: Vec<u32> = self.state.polls.iter().filter(|(_, p)| p.close.is_none() && now >= p.current().closes).map(|(id, _)| *id).collect();
        let last = self.state.last_checkpoint().map(|c| c.time).unwrap_or(0);
        let due = now >= last + ledger.checkpoint_period;
        // A heartbeat when nothing happened: readers refuse stale
        // checkpoints, so a mirror cannot single one out with an old root.
        let heartbeat = now >= last + HEARTBEAT;
        if (due && (!self.rows.is_empty() || !self.subs.is_empty() || !closes.is_empty())) || heartbeat {
            return Ok(Some(self.checkpoint(now, &closes).await?));
        }
        Ok(None)
    }

    /// Timestamps a checkpoint note (SPEC §4): its SHA-256 goes to the
    /// calendars; the pending proof is stored and published, and upgraded
    /// hourly until it carries a Bitcoin attestation. A calendar outage is
    /// logged, never fatal.
    async fn stamp(&self, index: u64, signed: &str, now: u64) {
        if self.calendars.is_empty() {
            return;
        }
        let digest = encoding::sha256(signed.as_bytes());
        let calendars = self.calendars.clone();
        match tokio::task::spawn_blocking(move || isoloir_stamps::submit(digest, &calendars)).await {
            Ok(Ok(ots)) => {
                let bytes = ots.to_bytes();
                if let Err(e) = self.store.put_stamp(index, &bytes, false, now).await {
                    tracing::error!(error = %e, index, "storing a stamp");
                }
                if let Some(m) = &self.mirror {
                    if let Err(e) = m.write_stamp(index, &bytes) {
                        tracing::error!(error = %e, index, "mirror stamp");
                    }
                }
            }
            Ok(Err(e)) => tracing::warn!(error = %e, index, "no calendar took the checkpoint"),
            Err(e) => tracing::error!(error = %e, "stamp task"),
        }
    }

    /// Upgrades the incomplete stamps (hourly).
    async fn upgrade_stamps(&mut self, now: u64) -> anyhow::Result<()> {
        if self.calendars.is_empty() || now < self.last_upgrade + UPGRADE_EVERY {
            return Ok(());
        }
        self.last_upgrade = now;
        for (idx, bytes) in self.store.incomplete_stamps().await? {
            let upgraded = tokio::task::spawn_blocking(move || -> Result<_, isoloir_stamps::Error> {
                let ots = isoloir_stamps::Ots::parse(&bytes)?;
                isoloir_stamps::upgrade(&ots)
            })
            .await?;
            match upgraded {
                Ok((ots, true)) => {
                    let b = ots.to_bytes();
                    let complete = isoloir_stamps::is_complete(&ots);
                    self.store.put_stamp(idx as u64, &b, complete, now).await?;
                    if let Some(m) = &self.mirror {
                        m.write_stamp(idx as u64, &b)?;
                    }
                    tracing::info!(index = idx, complete, "stamp upgraded");
                }
                Ok((_, false)) => {}
                Err(e) => tracing::warn!(error = %e, index = idx, "stamp upgrade"),
            }
        }
        Ok(())
    }

    async fn take_submissions(&mut self, now: u64) -> anyhow::Result<()> {
        for s in self.store.submissions().await? {
            if self.subs.iter().any(|(id, _, _)| *id == s.id) {
                continue;
            }
            let verdict = match s.kind {
                EntryKind::Ledger | EntryKind::Registry | EntryKind::Poll => {
                    // One setup of a kind and id per checkpoint.
                    let key = setup_key(s.kind, &s.body);
                    if self.subs.iter().any(|(_, k, b)| setup_key(*k, b) == key) {
                        continue;
                    }
                    judge::judge_setup(&self.state, s.kind, &s.body, now).map_err(|e| e.to_string())
                }
                EntryKind::Tally => match judge::judge(&self.state, &self.pending, s.kind, &s.body, now, &self.checkers()) {
                    Verdict::Accept => Ok(()),
                    Verdict::Reject(r) => Err(r.as_str().to_string()),
                    Verdict::Defer(_) => continue,
                },
                _ => Err("not a submission kind".into()),
            };
            match verdict {
                Ok(()) => {
                    self.store.submission_status(s.id, "accepted", None).await?;
                    if s.kind == EntryKind::Tally {
                        self.pending.admit(s.kind, &s.body);
                    }
                    self.subs.push((s.id, s.kind, s.body));
                }
                Err(e) => {
                    tracing::warn!(id = s.id, error = %e, "submission refused");
                    self.store.submission_status(s.id, "rejected", Some(&e)).await?;
                }
            }
        }
        Ok(())
    }

    /// Writes a checkpoint: the accepted messages ordered by body hash,
    /// then the closes; the note; the store, in one transaction; then the
    /// mirror's files and the relays.
    pub async fn checkpoint(&mut self, now: u64, closes: &[u32]) -> anyhow::Result<u64> {
        let index = self.next_index();
        let from = self.state.next_seq();
        let mut entries: Vec<(EntryKind, Vec<u8>)> = self.rows.iter().map(|r| (r.kind, r.body.clone())).collect();
        for (_, k, b) in &self.subs {
            entries.push((*k, b.clone()));
        }
        entries.sort_by_key(|(_, b)| encoding::body_hash(b));
        // Applied in place: cloning the state per checkpoint costs the
        // whole log. An entry that does not apply leaves the state as it
        // was (apply checks before it changes anything), and is left out.
        let mut logged = vec![];
        let mut left_out: Vec<String> = vec![];
        for (k, b) in entries {
            match self.state.apply(k, &b, now) {
                Ok(seq) => logged.push((seq, k, b.clone(), encoding::body_hash(&b))),
                Err(e) => {
                    tracing::error!(error = %e, kind = k.as_str(), "an accepted entry does not apply; left out");
                    left_out.push(encoding::body_hash(&b));
                }
            }
        }
        let state = &mut self.state;
        for poll in closes {
            let last = state.polls[poll].ballots.last().map(|b| b.seq).unwrap_or(0);
            let c = Body::Close(Close { v: V1, poll: *poll, at: state.polls[poll].current().closes, last }).encode();
            let seq = state.apply(EntryKind::Close, &c, now).map_err(|e| anyhow::anyhow!(e))?;
            logged.push((seq, EntryKind::Close, c.clone(), encoding::body_hash(&c)));
        }
        // The newest pushed commit: a checkpoint never waits for the push.
        let token = self.mirror.as_ref().and_then(|m| m.token());
        let cp = state.checkpoint(index, now, token);
        let signed = self.signer.sign(&cp.text());
        state.record(&cp).map_err(|e| anyhow::anyhow!(e))?;
        let pending_ids: Vec<String> = self.rows.iter().map(|r| r.event_id.clone()).collect();
        // A setup left out is refused, not logged.
        let mut sub_ids = vec![];
        for (id, _, b) in &self.subs {
            if left_out.contains(&encoding::body_hash(b)) {
                self.store.submission_status(*id, "rejected", Some("it no longer applied at the checkpoint")).await?;
            } else {
                sub_ids.push(*id);
            }
        }
        if let Err(e) = self.store.checkpoint(&logged, index, &signed, now, cp.size, &pending_ids, &sub_ids).await {
            // The database did not take the checkpoint: the state in memory
            // is ahead of it. Stop; a restart replays the database.
            anyhow::bail!("checkpoint {index} not stored ({e}); restart to replay the log");
        }
        self.rows.clear();
        self.subs.clear();
        self.pending.clear();
        if let Some(m) = &self.mirror {
            if let Err(e) = m.write_checkpoint(&self.state, index, from, &signed) {
                tracing::error!(error = %e, index, "mirror (the log goes on; a restart writes it again)");
            }
        }
        let ev = Event::sign(&self.nostr_sk, now, kinds::CHECKPOINT, vec![vec!["t".into(), self.tag.clone()]], signed.clone());
        self.transport.publish_all(&ev).await;
        self.stamp(index, &signed, now).await;
        tracing::info!(index, size = cp.size, entries = logged.len(), "checkpoint");
        Ok(index)
    }
}

fn setup_key(kind: EntryKind, b: &[u8]) -> (EntryKind, u32) {
    let id = match body::decode(kind, b) {
        Ok(Body::Registry(r)) => r.id,
        Ok(Body::Poll(p)) => p.id,
        _ => 0,
    };
    (kind, id)
}

fn note_time(signed: &str) -> anyhow::Result<u64> {
    signed
        .lines()
        .find_map(|l| l.strip_prefix("time ").and_then(|t| t.parse().ok()))
        .ok_or_else(|| anyhow::anyhow!("a checkpoint note without time"))
}
