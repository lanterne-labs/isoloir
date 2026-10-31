//! The ingest (SPEC §11): reads the relays, judges every message, records
//! it before acknowledging it, logs the accepted ones and the refusals at
//! the next checkpoint in one transaction, closes polls on time, writes
//! the mirror and posts the checkpoint notes.

use crate::mirror::Mirror;
use crate::store::{PendingRow, Store};
use isoloir_core::{canonical, encoding};
use isoloir_proto::body::{self, Ack, Body, Close, EntryKind, Outcome, Reject, REJECT_RAW_MAX, V1};
use isoloir_proto::judge::{self, Checkers, Passports, Pending, Proofs, Verdict};
use isoloir_proto::note;
use isoloir_proto::sig::Event;
use isoloir_proto::state::State;
use isoloir_proto::tally::Tlock;
use std::collections::HashMap;
use std::sync::Arc;

/// Nostr kinds (SPEC §11.1).
pub mod kinds {
    pub const REGISTER: u32 = 7100;
    pub const BALLOT: u32 = 7101;
    pub const ACK: u32 = 7102;
    pub const CHECKPOINT: u32 = 7103;
    pub const LINK: u32 = 7104;
    pub const TALLY: u32 = 7105;
    pub const COMPLAINT: u32 = 7106;
}

/// The relay tag of a ledger.
pub fn tag(origin: &str) -> String {
    format!("{}/{origin}", isoloir_proto::PROTOCOL)
}

/// The way out to the relays.
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    /// Posts an event to one relay.
    async fn publish(&self, relay: &str, event: &Event) -> Result<(), String>;
    /// Posts an event to every relay of the ledger.
    async fn publish_all(&self, event: &Event);
}

/// A message from a relay.
#[derive(Clone, Debug)]
pub struct Incoming {
    pub relay: String,
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
    pub mirror: Option<Mirror>,
    /// OpenTimestamps calendars; empty: no stamps (tests, local trials).
    pub calendars: Vec<String>,
    last_upgrade: u64,
}

/// How often incomplete stamps are upgraded.
const UPGRADE_EVERY: u64 = 3_600;

impl Ingest {
    /// Loads the ledger from the store: the log is replayed into the state,
    /// the pending messages are claimed again.
    pub async fn load(
        store: Store,
        config: Config,
        transport: Arc<dyn Transport>,
        proofs: Box<dyn Proofs + Send + Sync>,
        passports: Box<dyn Passports + Send + Sync>,
        tlock: Option<Box<dyn Tlock + Send + Sync>>,
        mirror: Option<Mirror>,
    ) -> anyhow::Result<Ingest> {
        let mut state = State::new();
        let entries = store.entries().await?;
        let notes = store.checkpoints().await?;
        let mut it = entries.into_iter().peekable();
        let mut origin = String::new();
        // A mirror behind the database (lost, wiped, or the genesis) is
        // written again as the log is replayed.
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
                m.write_data(&state, *idx as u64, from)?;
                m.write_note(*idx as u64, signed)?;
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
        };
        if let Some(l) = ingest.state.ledger() {
            if l.log_key != ingest.signer.verifier() {
                anyhow::bail!("the log key given is not the ledger's");
            }
        }
        for r in ingest.store.pending().await? {
            if r.outcome == "accepted" {
                ingest.pending.admit(r.kind, &r.body);
            }
            ingest.rows.push(r);
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

    fn ack_event(&self, of: &str, hash: &str, outcome: Outcome, reason: Option<isoloir_proto::Reason>, checkpoint: Option<u64>, now: u64) -> Event {
        let ack = Ack { v: V1, of: of.to_string(), hash: hash.to_string(), outcome, reason, checkpoint };
        Event::sign(&self.nostr_sk, now, kinds::ACK, vec![vec!["t".into(), self.tag.clone()], vec!["e".into(), of.to_string()]], canonical::to_string(&ack).expect("ack"))
    }

    async fn send_ack(&self, relay: &str, ev: &Event) {
        match self.transport.publish(relay, ev).await {
            Ok(()) => {
                if let Err(e) = self.store.ack_posted(ev.tag("e").unwrap_or_default()).await {
                    tracing::error!(error = %e, "recording a posted ack");
                }
            }
            Err(e) => tracing::warn!(relay, error = %e, "ack not posted; retried later"),
        }
    }

    /// Handles one message from a relay.
    pub async fn handle(&mut self, inc: Incoming, now: u64) -> anyhow::Result<()> {
        let ev = &inc.event;
        let kind = match ev.kind {
            kinds::REGISTER => EntryKind::Register,
            kinds::BALLOT => EntryKind::Ballot,
            kinds::TALLY => EntryKind::Tally,
            _ => return Ok(()),
        };
        if ev.tag("t") != Some(self.tag.as_str()) || !ev.verify() {
            return Ok(());
        }
        // Judged before: the same ack again, on this relay too.
        if let Some((_, ack, _)) = self.store.seen(&ev.id).await? {
            let ack: Event = serde_json::from_value(ack)?;
            self.send_ack(&inc.relay, &ack).await;
            return Ok(());
        }
        let bytes = ev.content.as_bytes().to_vec();
        let hash = encoding::body_hash(&bytes);
        // The same body under another event (a repost): the same outcome.
        let logged = self.state.hashes.get(&hash).copied();
        let pending_same = self.rows.iter().any(|r| r.hash == hash && r.outcome == "accepted");
        let (outcome, reason, checkpoint) = if let Some(seq) = logged.filter(|s| self.state.entries[*s as usize].0 == kind) {
            (Outcome::Accepted, None, self.state.checkpoint_of(seq).map(|c| c.index))
        } else if pending_same {
            (Outcome::Accepted, None, Some(self.next_index()))
        } else {
            match judge::judge(&self.state, &self.pending, kind, &bytes, now, &self.checkers()) {
                Verdict::Accept => (Outcome::Accepted, None, Some(self.next_index())),
                Verdict::Reject(r) => (Outcome::Rejected, Some(r), None),
                Verdict::Defer(why) => {
                    tracing::warn!(id = %ev.id, why, "message deferred");
                    self.deferred.insert(ev.id.clone(), inc.clone());
                    return Ok(());
                }
            }
        };
        let ack = self.ack_event(&ev.id, &hash, outcome, reason, checkpoint, now);
        let fresh = logged.is_none() && !pending_same;
        let row = PendingRow {
            event_id: ev.id.clone(),
            kind,
            body: bytes.clone(),
            hash: hash.clone(),
            relay: inc.relay.clone(),
            received: now as i64,
            outcome: if outcome == Outcome::Accepted { "accepted".into() } else { "rejected".into() },
            reason: reason.map(|r| r.as_str().to_string()),
        };
        if fresh {
            // Durable before the ack: an accepted message is never lost.
            self.store.judged(&row, &serde_json::to_value(&ack)?).await?;
            if outcome == Outcome::Accepted {
                self.pending.admit(kind, &bytes);
            }
            self.rows.push(row);
        } else {
            self.store.seen_only(&ev.id, &inc.relay, &serde_json::to_value(&ack)?).await?;
        }
        self.deferred.remove(&ev.id);
        self.send_ack(&inc.relay, &ack).await;
        Ok(())
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
        let Some(ledger) = self.state.ledger().cloned() else { return Ok(None) };
        let closes: Vec<u32> = self.state.polls.iter().filter(|(_, p)| p.close.is_none() && now >= p.current().closes).map(|(id, _)| *id).collect();
        let last = self.state.last_checkpoint().map(|c| c.time).unwrap_or(0);
        let due = now >= last + ledger.checkpoint_period;
        if due && (!self.rows.is_empty() || !self.subs.is_empty() || !closes.is_empty()) {
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

    /// Writes a checkpoint: the accepted messages and the refusals ordered
    /// by body hash, then the closes; the note; the store, in one
    /// transaction; then the mirror and the relays.
    pub async fn checkpoint(&mut self, now: u64, closes: &[u32]) -> anyhow::Result<u64> {
        let index = self.next_index();
        let from = self.state.next_seq();
        let mut entries: Vec<(EntryKind, Vec<u8>)> = vec![];
        for r in &self.rows {
            if r.outcome == "accepted" {
                entries.push((r.kind, r.body.clone()));
            } else {
                let reject = Reject {
                    v: V1,
                    of: r.event_id.clone(),
                    hash: r.hash.clone(),
                    reason: r.reason.as_deref().and_then(|s| serde_json::from_value(serde_json::Value::String(s.into())).ok()).unwrap_or(isoloir_proto::Reason::Malformed),
                    kind: Some(r.kind.as_str().to_string()),
                    raw: (r.body.len() <= REJECT_RAW_MAX).then(|| encoding::b64(&r.body)),
                };
                entries.push((EntryKind::Reject, Body::Reject(reject).encode()));
            }
        }
        for (_, k, b) in &self.subs {
            entries.push((*k, b.clone()));
        }
        entries.sort_by_key(|(_, b)| encoding::body_hash(b));
        let mut state = self.state.clone();
        let mut logged = vec![];
        for (k, b) in entries {
            match state.apply(k, &b, now) {
                Ok(seq) => logged.push((seq, k, b.clone(), encoding::body_hash(&b))),
                // A judged entry that no longer applies is a bug: keep it
                // out of the log and say so.
                Err(e) => tracing::error!(error = %e, kind = k.as_str(), "an accepted entry does not apply; left out"),
            }
        }
        for poll in closes {
            let last = state.polls[poll].ballots.last().map(|b| b.seq).unwrap_or(0);
            let c = Body::Close(Close { v: V1, poll: *poll, at: state.polls[poll].current().closes, last }).encode();
            let seq = state.apply(EntryKind::Close, &c, now).map_err(|e| anyhow::anyhow!(e))?;
            logged.push((seq, EntryKind::Close, c.clone(), encoding::body_hash(&c)));
        }
        let token = match &self.mirror {
            Some(m) => m.write_data(&state, index, from)?,
            None => None,
        };
        let cp = state.checkpoint(index, now, token);
        let signed = self.signer.sign(&cp.text());
        state.record(&cp).map_err(|e| anyhow::anyhow!(e))?;
        let pending_ids: Vec<String> = self.rows.iter().map(|r| r.event_id.clone()).collect();
        let sub_ids: Vec<i64> = self.subs.iter().map(|(id, _, _)| *id).collect();
        self.store.checkpoint(&logged, index, &signed, now, cp.size, &pending_ids, &sub_ids).await?;
        self.state = state;
        self.rows.clear();
        self.subs.clear();
        self.pending.clear();
        if let Some(m) = &self.mirror {
            if let Err(e) = m.write_note(index, &signed) {
                tracing::error!(error = %e, index, "mirror");
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
