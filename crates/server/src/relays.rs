//! The ingest's and the trustee's way to the relays: the relay pool
//! (isoloir-relay) behind the `Transport` trait, and the ingest's reading
//! loop with its cursors kept in the store.

use crate::ingest::{kinds, Incoming, Transport};
use crate::store::Store;
use isoloir_proto::sig::Event;
use isoloir_relay::{Filter, Pool};
use std::time::Duration;

pub struct PoolTransport {
    pub pool: Pool,
}

#[async_trait::async_trait]
impl Transport for PoolTransport {
    async fn publish(&self, relay: &str, event: &Event) -> Result<(), String> {
        self.pool.publish(relay, event, Duration::from_secs(10)).await.map_err(|e| e.to_string())
    }

    async fn publish_all(&self, event: &Event) {
        for r in self.pool.relays() {
            if let Err(e) = self.pool.publish(&r, event, Duration::from_secs(10)).await {
                tracing::warn!(relay = %r, error = %e, "publish");
            }
        }
    }
}

/// Subscribes to the ledger's messages from the cursors in the store.
pub async fn subscribe(pool: &Pool, store: &Store, tag: &str) -> anyhow::Result<tokio::sync::mpsc::Receiver<Incoming>> {
    for (relay, since) in store.cursors().await? {
        pool.set_since(&relay, since as u64);
    }
    let mut rx = pool.subscribe(Filter { kinds: vec![kinds::REGISTER, kinds::BALLOT, kinds::TALLY], t: Some(tag.to_string()), ..Default::default() });
    let (tx, out) = tokio::sync::mpsc::channel(1024);
    tokio::spawn(async move {
        while let Some(d) = rx.recv().await {
            if tx.send(Incoming { relay: d.relay, event: d.event }).await.is_err() {
                break;
            }
        }
    });
    Ok(out)
}

/// Saves the pool's cursors (after each checkpoint: what is logged is
/// read again at most once).
pub async fn save_cursors(pool: &Pool, store: &Store) -> anyhow::Result<()> {
    for (relay, since) in pool.cursors() {
        store.set_cursor(&relay, since as i64).await?;
    }
    Ok(())
}
