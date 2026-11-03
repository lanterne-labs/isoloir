//! The ingest's storage (Postgres): the log, the checkpoints, the pending
//! messages, the acknowledgements, the operator's submissions, the relay
//! cursors, the stamps. Migrations are numbered and embedded: the server
//! refuses to start on a schema newer than it knows (SPEC §13).

use crate::packed;
use isoloir_proto::body::EntryKind;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::{Postgres, Row, Transaction};

pub type Tx<'a> = Transaction<'a, Postgres>;

/// The lease key: one ingest per database.
const LEASE: i64 = 0x150_1012;

#[derive(Clone)]
pub struct Store {
    pub pool: PgPool,
}

/// A judged message waiting for its checkpoint.
#[derive(Clone, Debug)]
pub struct PendingRow {
    pub event_id: String,
    pub kind: EntryKind,
    pub body: Vec<u8>,
    pub hash: String,
    pub relay: String,
    pub received: i64,
    pub outcome: String,
    pub reason: Option<String>,
    /// The envelope's pubkey (absent on rows judged before it was kept).
    pub author: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Submission {
    pub id: i64,
    pub kind: EntryKind,
    pub body: Vec<u8>,
}

/// A body as a row holds it: packed, or as it is (rows from before 0003).
fn body_of(r: &sqlx::postgres::PgRow, col: &str) -> anyhow::Result<Vec<u8>> {
    let b: Vec<u8> = r.get(col);
    if r.get::<bool, _>("packed") {
        packed::unpack(&b)
    } else {
        Ok(b)
    }
}

/// An ack as a row holds it: packed (`ack_bin`), or JSONB (rows from
/// before 0003).
fn ack_of(r: &sqlx::postgres::PgRow) -> anyhow::Result<serde_json::Value> {
    match r.get::<Option<Vec<u8>>, _>("ack_bin") {
        Some(b) => Ok(serde_json::from_slice(&packed::unpack(&b)?)?),
        None => r.get::<Option<serde_json::Value>, _>("ack").ok_or_else(|| anyhow::anyhow!("a seen row without its ack")),
    }
}

fn ack_bin(ack: &serde_json::Value) -> anyhow::Result<Vec<u8>> {
    Ok(packed::pack(&serde_json::to_vec(ack)?))
}

fn kind(s: &str) -> anyhow::Result<EntryKind> {
    EntryKind::parse(s).ok_or_else(|| anyhow::anyhow!("unknown entry kind {s}"))
}

impl Store {
    /// Connects and applies the migrations.
    pub async fn connect(url: &str) -> anyhow::Result<Store> {
        let pool = PgPoolOptions::new().max_connections(8).connect(url).await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Store { pool })
    }

    /// Takes the ingest's lease on a dedicated connection, held for the
    /// life of the process; a second ingest on the same database fails.
    pub async fn lease(&self) -> anyhow::Result<sqlx::pool::PoolConnection<Postgres>> {
        let mut c = self.pool.acquire().await?;
        let got: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)").bind(LEASE).fetch_one(&mut *c).await?;
        if !got {
            anyhow::bail!("another ingest holds this ledger");
        }
        Ok(c)
    }

    /// Takes the lease, waiting up to `wait` for the ingest that holds it
    /// to stop: a deploy starts the new process before the old one is
    /// gone, and a new process that gave up at once would crash-loop.
    pub async fn lease_wait(&self, wait: std::time::Duration) -> anyhow::Result<sqlx::pool::PoolConnection<Postgres>> {
        let until = tokio::time::Instant::now() + wait;
        let mut said = false;
        loop {
            match self.lease().await {
                Ok(c) => {
                    if said {
                        tracing::info!("lease taken");
                    }
                    return Ok(c);
                }
                Err(e) if tokio::time::Instant::now() < until && e.to_string().contains("another ingest") => {
                    if !said {
                        tracing::warn!("another ingest holds this ledger: waiting for it to stop");
                        said = true;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// The whole log, in order.
    pub async fn entries(&self) -> anyhow::Result<Vec<(i64, EntryKind, Vec<u8>, i64)>> {
        let rows = sqlx::query("SELECT seq, kind, body, packed, checkpoint FROM isoloir_log ORDER BY seq").fetch_all(&self.pool).await?;
        rows.iter().map(|r| Ok((r.get("seq"), kind(r.get("kind"))?, body_of(r, "body")?, r.get("checkpoint")))).collect()
    }

    /// Every checkpoint note, in order.
    pub async fn checkpoints(&self) -> anyhow::Result<Vec<(i64, String)>> {
        let rows = sqlx::query("SELECT idx, note FROM isoloir_checkpoints ORDER BY idx").fetch_all(&self.pool).await?;
        Ok(rows.iter().map(|r| (r.get("idx"), r.get("note"))).collect())
    }

    pub async fn pending(&self) -> anyhow::Result<Vec<PendingRow>> {
        let rows = sqlx::query("SELECT event_id, kind, body, hash, relay, received, outcome, reason, author FROM isoloir_pending ORDER BY received, event_id")
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|r| {
                Ok(PendingRow {
                    event_id: r.get("event_id"),
                    kind: kind(r.get("kind"))?,
                    body: r.get("body"),
                    hash: r.get("hash"),
                    relay: r.get("relay"),
                    received: r.get("received"),
                    outcome: r.get("outcome"),
                    reason: r.get("reason"),
                    author: r.get("author"),
                })
            })
            .collect()
    }

    /// Records a judged message and its ack in one transaction, before the
    /// ack is posted (SPEC §11.2).
    pub async fn judged(&self, p: &PendingRow, ack: &serde_json::Value) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("INSERT INTO isoloir_pending (event_id, kind, body, hash, relay, received, outcome, reason, author) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING")
            .bind(&p.event_id)
            .bind(p.kind.as_str())
            .bind(&p.body)
            .bind(&p.hash)
            .bind(&p.relay)
            .bind(p.received)
            .bind(&p.outcome)
            .bind(&p.reason)
            .bind(&p.author)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO isoloir_seen (event_id, relay, ack_bin) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING")
            .bind(&p.event_id)
            .bind(&p.relay)
            .bind(ack_bin(ack)?)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Records the ack of a repost (a body already judged under another
    /// event id): no new pending message.
    pub async fn seen_only(&self, event_id: &str, relay: &str, ack: &serde_json::Value) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO isoloir_seen (event_id, relay, ack_bin) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING")
            .bind(event_id)
            .bind(relay)
            .bind(ack_bin(ack)?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// The ack of a message already judged.
    pub async fn seen(&self, event_id: &str) -> anyhow::Result<Option<(String, serde_json::Value, bool)>> {
        let r = sqlx::query("SELECT relay, ack, ack_bin, posted FROM isoloir_seen WHERE event_id = $1").bind(event_id).fetch_optional(&self.pool).await?;
        r.map(|r| Ok((r.get("relay"), ack_of(&r)?, r.get("posted")))).transpose()
    }

    pub async fn ack_posted(&self, event_id: &str) -> anyhow::Result<()> {
        sqlx::query("UPDATE isoloir_seen SET posted = true WHERE event_id = $1").bind(event_id).execute(&self.pool).await?;
        Ok(())
    }

    /// Acks not yet posted (a crash between the record and the post).
    pub async fn unposted(&self) -> anyhow::Result<Vec<(String, String, serde_json::Value)>> {
        let rows = sqlx::query("SELECT event_id, relay, ack, ack_bin FROM isoloir_seen WHERE NOT posted").fetch_all(&self.pool).await?;
        rows.iter().map(|r| Ok((r.get("event_id"), r.get("relay"), ack_of(r)?))).collect()
    }

    /// Writes a checkpoint: its entries, its note, the removal of the
    /// pending rows and submissions it logs, in one transaction.
    #[allow(clippy::too_many_arguments)]
    pub async fn checkpoint(&self, entries: &[(u64, EntryKind, Vec<u8>, String)], idx: u64, note: &str, time: u64, size: u64, pending: &[String], submissions: &[i64]) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        for (seq, k, body, hash) in entries {
            sqlx::query("INSERT INTO isoloir_log (seq, kind, body, hash, checkpoint, packed) VALUES ($1,$2,$3,$4,$5,true)")
                .bind(*seq as i64)
                .bind(k.as_str())
                .bind(packed::pack(body))
                .bind(hash)
                .bind(idx as i64)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query("INSERT INTO isoloir_checkpoints (idx, note, time, size) VALUES ($1,$2,$3,$4)")
            .bind(idx as i64)
            .bind(note)
            .bind(time as i64)
            .bind(size as i64)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM isoloir_pending WHERE event_id = ANY($1)").bind(pending).execute(&mut *tx).await?;
        sqlx::query("UPDATE isoloir_submissions SET status = 'logged', body = NULL WHERE id = ANY($1)").bind(submissions).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Records a refused message and its ack in one transaction, before the
    /// ack is posted: the body is kept REFUSED_KEPT for debugging (SPEC
    /// §11.4), never logged.
    pub async fn refused(&self, p: &PendingRow, ack: &serde_json::Value) -> anyhow::Result<()> {
        let mut tx = self.pool.begin().await?;
        let body = (p.body.len() <= isoloir_proto::body::MAX_BODY).then(|| packed::pack(&p.body));
        sqlx::query("INSERT INTO isoloir_refused (event_id, body, packed, received, kind, reason, author, relay) VALUES ($1,$2,true,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING")
            .bind(&p.event_id)
            .bind(body)
            .bind(p.received)
            .bind(p.kind.as_str())
            .bind(&p.reason)
            .bind(&p.author)
            .bind(&p.relay)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO isoloir_seen (event_id, relay, ack_bin) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING")
            .bind(&p.event_id)
            .bind(&p.relay)
            .bind(ack_bin(ack)?)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Deletes the refused bodies received before `before`.
    pub async fn purge_refused(&self, before: i64) -> anyhow::Result<u64> {
        Ok(sqlx::query("DELETE FROM isoloir_refused WHERE received < $1").bind(before).execute(&self.pool).await?.rows_affected())
    }

    /// The refusals a checkpoint's `rejects` entry sums up: their `reject`
    /// bodies, in body-hash order (its leaves).
    pub async fn summed(&self, idx: u64) -> anyhow::Result<Vec<Vec<u8>>> {
        let rows = sqlx::query("SELECT entry FROM isoloir_refused WHERE checkpoint = $1 AND NOT listed").bind(idx as i64).fetch_all(&self.pool).await?;
        let mut v: Vec<Vec<u8>> = rows.iter().map(|r| r.get("entry")).collect();
        v.sort_by_cached_key(|b| isoloir_core::encoding::body_hash(b));
        Ok(v)
    }

    /// A refused message's body: None when the ledger has no such refusal,
    /// Some(None) when it was over the size limit and not kept.
    pub async fn refused_body(&self, event_id: &str) -> anyhow::Result<Option<Option<Vec<u8>>>> {
        let r = sqlx::query("SELECT body, packed FROM isoloir_refused WHERE event_id = $1").bind(event_id).fetch_optional(&self.pool).await?;
        r.map(|r| match r.get::<Option<Vec<u8>>, _>("body") {
            Some(_) => body_of(&r, "body").map(Some),
            None => Ok(None),
        })
        .transpose()
    }

    pub async fn submit(&self, kind: EntryKind, body: &[u8], now: u64) -> anyhow::Result<i64> {
        Ok(sqlx::query_scalar("INSERT INTO isoloir_submissions (kind, body, submitted) VALUES ($1,$2,$3) RETURNING id")
            .bind(kind.as_str())
            .bind(body)
            .bind(now as i64)
            .fetch_one(&self.pool)
            .await?)
    }

    pub async fn submissions(&self) -> anyhow::Result<Vec<Submission>> {
        let rows = sqlx::query("SELECT id, kind, body FROM isoloir_submissions WHERE status IN ('pending', 'accepted') ORDER BY id").fetch_all(&self.pool).await?;
        rows.iter().map(|r| Ok(Submission { id: r.get("id"), kind: kind(r.get("kind"))?, body: r.get("body") })).collect()
    }

    pub async fn submission_status(&self, id: i64, status: &str, error: Option<&str>) -> anyhow::Result<()> {
        sqlx::query("UPDATE isoloir_submissions SET status = $2, error = $3 WHERE id = $1").bind(id).bind(status).bind(error).execute(&self.pool).await?;
        Ok(())
    }

    pub async fn submission(&self, id: i64) -> anyhow::Result<Option<(String, Option<String>)>> {
        let r = sqlx::query("SELECT status, error FROM isoloir_submissions WHERE id = $1").bind(id).fetch_optional(&self.pool).await?;
        Ok(r.map(|r| (r.get("status"), r.get("error"))))
    }

    pub async fn cursors(&self) -> anyhow::Result<Vec<(String, i64)>> {
        let rows = sqlx::query("SELECT relay, since FROM isoloir_cursors").fetch_all(&self.pool).await?;
        Ok(rows.iter().map(|r| (r.get("relay"), r.get("since"))).collect())
    }

    pub async fn set_cursor(&self, relay: &str, since: i64) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO isoloir_cursors (relay, since) VALUES ($1,$2) ON CONFLICT (relay) DO UPDATE SET since = GREATEST(isoloir_cursors.since, $2)")
            .bind(relay)
            .bind(since)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn put_stamp(&self, idx: u64, ots: &[u8], complete: bool, now: u64) -> anyhow::Result<()> {
        sqlx::query("INSERT INTO isoloir_stamps (idx, ots, complete, updated) VALUES ($1,$2,$3,$4) ON CONFLICT (idx) DO UPDATE SET ots = $2, complete = $3, updated = $4")
            .bind(idx as i64)
            .bind(ots)
            .bind(complete)
            .bind(now as i64)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn incomplete_stamps(&self) -> anyhow::Result<Vec<(i64, Vec<u8>)>> {
        let rows = sqlx::query("SELECT idx, ots FROM isoloir_stamps WHERE NOT complete ORDER BY idx").fetch_all(&self.pool).await?;
        Ok(rows.iter().map(|r| (r.get("idx"), r.get("ots"))).collect())
    }
}
