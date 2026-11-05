//! A database behind its own mirror (SPEC §15): the database was lost or
//! restored from an older backup, while the mirror still holds every
//! checkpoint signed since. The missing checkpoints are read back from the
//! mirror's files, each note checked against the log key and each entry
//! replayed, so the state must give the very note the mirror holds; only
//! then is the checkpoint written to the database. The log goes on from
//! there as if nothing had happened: no checkpoint is signed twice.
//!
//! What the mirror does not hold stays lost: the acks already posted (a
//! repost of a logged message gets its ack again, from the log), the bodies
//! of refused messages, and the messages judged after the last checkpoint
//! (the relays' cursors go back a heartbeat before it, so they come again).

use crate::ingest::HEARTBEAT;
use crate::mirror::{parse_entries, Mirror};
use crate::store::Store;
use isoloir_core::encoding;
use isoloir_proto::note;
use isoloir_proto::state::State;
use serde_json::Value;

/// The origin of the mirror's ledger: the first line of its first note.
pub fn origin(mirror: &Mirror) -> anyhow::Result<String> {
    let note = std::fs::read_to_string(mirror.dir.join("checkpoints/1.txt"))?;
    Ok(note.lines().next().unwrap_or_default().to_string())
}

fn note_time(text: &str) -> anyhow::Result<u64> {
    text.lines()
        .find_map(|l| l.strip_prefix("time ").and_then(|t| t.parse().ok()))
        .ok_or_else(|| anyhow::anyhow!("a checkpoint note without time"))
}

/// Writes to the store the checkpoints the mirror holds beyond it, checked
/// against the log key `verifier`. Returns how many were restored.
pub async fn restore(store: &Store, mirror: &Mirror, verifier: &str, now: u64) -> anyhow::Result<u64> {
    let last = mirror.last_index();
    let notes = store.checkpoints().await?;
    let have = notes.len() as u64;
    if last <= have {
        return Ok(0);
    }
    let key = note::Verifier::parse(verifier).map_err(|e| anyhow::anyhow!("log key: {e}"))?;
    let dir = &mirror.dir;
    // The store's own checkpoints, replayed; each must be the mirror's.
    let mut state = State::new();
    let mut it = store.entries().await?.into_iter().peekable();
    for (idx, signed) in &notes {
        let theirs = std::fs::read_to_string(dir.join(format!("checkpoints/{idx}.txt")))?;
        if theirs != *signed {
            anyhow::bail!("checkpoint {idx}: the database and the mirror differ");
        }
        let time = note_time(signed)?;
        while let Some((_, kind, body, _)) = it.next_if(|(_, _, _, c)| c == idx) {
            state.apply(kind, &body, time).map_err(|e| anyhow::anyhow!("replay: {e}"))?;
        }
        let text = key.open(signed).map_err(|e| anyhow::anyhow!("checkpoint {idx}: {e}"))?;
        let cp = note::Checkpoint::parse(text).map_err(|e| anyhow::anyhow!("checkpoint {idx}: {e}"))?;
        state.record(&cp).map_err(|e| anyhow::anyhow!("replay: {e}"))?;
    }
    tracing::warn!(database = have, mirror = last, "the database is behind its mirror: restoring the checkpoints it lacks");
    let mut time = 0;
    for idx in have + 1..=last {
        let signed = std::fs::read_to_string(dir.join(format!("checkpoints/{idx}.txt")))?;
        let text = key.open(&signed).map_err(|e| anyhow::anyhow!("checkpoint {idx}: {e}"))?;
        let cp = note::Checkpoint::parse(text).map_err(|e| anyhow::anyhow!("checkpoint {idx}: {e}"))?;
        let v: Value = serde_json::from_slice(&std::fs::read(dir.join(format!("entries/{idx}.json")))?)?;
        let mut logged = vec![];
        for (seq, kind, body) in parse_entries(&v)? {
            if seq != state.next_seq() {
                anyhow::bail!("checkpoint {idx}: entry {seq} out of order");
            }
            state.apply(kind, &body, cp.time).map_err(|e| anyhow::anyhow!("checkpoint {idx}, entry {seq}: {e}"))?;
            let hash = encoding::body_hash(&body);
            logged.push((seq, kind, body, hash));
        }
        state.record(&cp).map_err(|e| anyhow::anyhow!("restore: {e}"))?;
        store.checkpoint(&logged, idx, &signed, cp.time, cp.size, &[], &[]).await?;
        if let Ok(ots) = std::fs::read(dir.join(format!("stamps/{idx}.ots"))) {
            match isoloir_stamps::Ots::parse(&ots) {
                Ok(o) => store.put_stamp(idx, &ots, isoloir_stamps::is_complete(&o), now).await?,
                Err(e) => tracing::warn!(index = idx, error = %e, "a stamp of the mirror does not parse"),
            }
        }
        time = cp.time;
    }
    // The messages after the last checkpoint come again from the relays.
    if let Some(l) = state.ledger() {
        for relay in l.nostr(false) {
            store.set_cursor(&relay, time.saturating_sub(HEARTBEAT) as i64).await?;
        }
    }
    tracing::warn!(restored = last - have, last, "database restored from the mirror");
    Ok(last - have)
}
