//! The direct channel (SPEC §11.1): the ingest's own HTTP endpoint. A
//! voter POSTs the signed envelope and gets the signed acknowledgement in
//! the response; after a dropped connection, it GETs it again. Same
//! envelopes, same acknowledgements as on the relays: only the path
//! differs, and so does who sees it (the operator sees the voter's
//! address; on a relay, the relay does).

use crate::ingest::Incoming;
use crate::store::Store;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use isoloir_proto::sig::Event;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// How long a POST waits for its acknowledgement before answering 202.
pub const ACK_WAIT: Duration = Duration::from_secs(55);
/// The largest envelope.
pub const MAX_BODY: usize = 512 * 1024;

/// The waiting requests of a direct channel.
pub struct DirectHub {
    /// The channel's URL, as the ledger lists it.
    pub origin: String,
    waiting: Mutex<HashMap<String, oneshot::Sender<Event>>>,
}

impl DirectHub {
    pub fn new(origin: &str) -> Arc<DirectHub> {
        Arc::new(DirectHub { origin: origin.to_string(), waiting: Mutex::new(HashMap::new()) })
    }

    /// Hands an acknowledgement to the request waiting for it, if any (the
    /// store keeps it for a later GET either way).
    pub fn deliver(&self, ack: &Event) {
        if let Some(id) = ack.tag("e") {
            if let Some(tx) = self.waiting.lock().unwrap().remove(id) {
                let _ = tx.send(ack.clone());
            }
        }
    }
}

#[derive(Clone)]
struct Ctx {
    hub: Arc<DirectHub>,
    inbound: mpsc::Sender<Incoming>,
    store: Store,
}

/// Health only (a ledger without a direct channel): `GET /v1/health`
/// answers 200 with the last checkpoint's index and time, 503 when the
/// store does not answer.
pub fn health_router(store: Store) -> Router {
    Router::new().route("/v1/health", get(health)).with_state(Ctx { hub: DirectHub::new(""), inbound: mpsc::channel(1).0, store })
}

async fn health(State(c): State<Ctx>) -> Response {
    match c.store.checkpoints().await {
        Ok(cps) => {
            let last = cps.last().map(|(i, n)| serde_json::json!({"index": i, "time": n.lines().find_map(|l| l.strip_prefix("time ").and_then(|t| t.parse::<u64>().ok()))}));
            Json(serde_json::json!({"ok": true, "checkpoint": last})).into_response()
        }
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, e.to_string()).into_response(),
    }
}

/// The routes: `POST /v1/messages`, `GET /v1/acks/{id}`, `GET /v1/health`.
pub fn router(hub: Arc<DirectHub>, inbound: mpsc::Sender<Incoming>, store: Store) -> Router {
    Router::new()
        .route("/v1/messages", post(message))
        .route("/v1/acks/{id}", get(ack))
        .route("/v1/health", get(health))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(MAX_BODY))
        // Browsers post from the app's origin.
        .layer(tower_http::cors::CorsLayer::permissive())
        .with_state(Ctx { hub, inbound, store })
}

async fn message(State(c): State<Ctx>, Json(ev): Json<Event>) -> Response {
    if !ev.verify() {
        return (StatusCode::BAD_REQUEST, "the envelope's signature does not verify").into_response();
    }
    let (tx, rx) = oneshot::channel();
    c.hub.waiting.lock().unwrap().insert(ev.id.clone(), tx);
    if c.inbound.send(Incoming { origin: c.hub.origin.clone(), event: ev.clone() }).await.is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, "the ingest is stopping").into_response();
    }
    match tokio::time::timeout(ACK_WAIT, rx).await {
        Ok(Ok(ack)) => Json(ack).into_response(),
        _ => {
            c.hub.waiting.lock().unwrap().remove(&ev.id);
            // Judged later (a deferred check): GET /v1/acks/{id}.
            (StatusCode::ACCEPTED, Json(serde_json::json!({"pending": ev.id}))).into_response()
        }
    }
}

async fn ack(State(c): State<Ctx>, Path(id): Path<String>) -> Response {
    match c.store.seen(&id).await {
        Ok(Some((_, ack, _))) => Json(ack).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "acks");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Posts an envelope to a direct channel and returns its acknowledgement
/// (waiting with GETs if the ingest answered 202). For voters in Rust.
pub async fn post_direct(url: &str, ev: &Event, wait: Duration) -> anyhow::Result<Event> {
    let c = reqwest::Client::new();
    let r = c.post(format!("{url}/v1/messages")).json(ev).send().await?;
    if r.status() == reqwest::StatusCode::OK {
        return Ok(r.json().await?);
    }
    if r.status() != reqwest::StatusCode::ACCEPTED {
        anyhow::bail!("{}: {}", r.status(), r.text().await.unwrap_or_default());
    }
    let until = tokio::time::Instant::now() + wait;
    while tokio::time::Instant::now() < until {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let r = c.get(format!("{url}/v1/acks/{}", ev.id)).send().await?;
        if r.status() == reqwest::StatusCode::OK {
            return Ok(r.json().await?);
        }
    }
    anyhow::bail!("no acknowledgement")
}
