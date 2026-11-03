//! The ingest's channels (SPEC §11.1): the relay pool (isoloir-relay) and
//! the direct endpoints behind one `Transport` that answers each message
//! by the channel it came from; the reading loop of the relays, with its
//! cursors kept in the store.

use crate::direct::DirectHub;
use crate::ingest::{kinds, Incoming, Transport};
use crate::store::Store;
use isoloir_proto::sig::Event;
use isoloir_relay::{Filter, Pool};
use std::sync::Arc;
use std::time::Duration;

/// Every channel of a ledger.
pub struct Channels {
    pub pool: Option<Pool>,
    pub direct: Vec<Arc<DirectHub>>,
}

#[async_trait::async_trait]
impl Transport for Channels {
    async fn publish(&self, origin: &str, event: &Event) -> Result<(), String> {
        if let Some(h) = self.direct.iter().find(|h| h.origin == origin) {
            h.deliver(event);
            return Ok(());
        }
        match &self.pool {
            Some(p) => p.publish(origin, event, Duration::from_secs(10)).await.map_err(|e| e.to_string()),
            None => Err(format!("no channel {origin}")),
        }
    }

    /// Checkpoint notes and tallies: to every relay (a direct endpoint has
    /// no audience; its readers read the mirror).
    async fn publish_all(&self, event: &Event) {
        if let Some(p) = &self.pool {
            for r in p.relays() {
                if let Err(e) = p.publish(&r, event, Duration::from_secs(10)).await {
                    tracing::warn!(relay = %r, error = %e, "publish");
                }
            }
        }
    }
}

/// Subscribes to the ledger's messages on the relays, from the cursors in
/// the store, into `tx`.
pub async fn subscribe(pool: &Pool, store: &Store, tag: &str, tx: tokio::sync::mpsc::Sender<Incoming>) -> anyhow::Result<()> {
    for (relay, since) in store.cursors().await? {
        pool.set_since(&relay, since as u64);
    }
    let mut rx = pool.subscribe(Filter { kinds: kinds::read(), t: Some(tag.to_string()), ..Default::default() });
    tokio::spawn(async move {
        while let Some(d) = rx.recv().await {
            if tx.send(Incoming { origin: d.relay, event: d.event }).await.is_err() {
                break;
            }
        }
    });
    Ok(())
}

/// Saves the pool's cursors (after each checkpoint).
pub async fn save_cursors(pool: &Pool, store: &Store) -> anyhow::Result<()> {
    for (relay, since) in pool.cursors() {
        store.set_cursor(&relay, since as i64).await?;
    }
    Ok(())
}
