//! The relay client (SPEC §11): a pool of Nostr relay connections.
//!
//! One background task per relay keeps its WebSocket open and reconnects
//! with a capped exponential backoff (1 s to 60 s); a relay that is down
//! never holds up the others. On top of the pool:
//!
//! - [`Pool::subscribe`] streams the events that match a filter from every
//!   relay, verified and deduplicated, and resubscribes after each
//!   reconnect from the relay's cursor (the newest `created_at` it
//!   delivered, minus [`RESUBSCRIBE_OVERLAP`]);
//! - [`Pool::publish`] / [`Pool::publish_any`] post an event and wait for
//!   the relay's `OK`;
//! - [`Pool::fetch`] reads the stored events of one relay until `EOSE`;
//! - [`Pool::wait_for`] waits for the first matching event on any relay
//!   (a voter waiting for its ack).

pub mod local;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
pub use isoloir_proto::sig::Event;
use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};

/// How far before its cursor a relay is asked again after a reconnect.
pub const RESUBSCRIBE_OVERLAP: u64 = 120;
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const PING_EVERY: Duration = Duration::from_secs(30);
/// A connection that has received nothing (not even a pong) for this long is dead.
const SILENCE_LIMIT: Duration = Duration::from_secs(90);
/// How many event ids a subscription remembers to drop duplicates.
const SEEN_CAPACITY: usize = 50_000;
const SUBSCRIPTION_BUFFER: usize = 1024;

/// A NIP-01 filter, limited to what isoloir asks for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Filter {
    pub kinds: Vec<u32>,
    /// The `#t` tag value (`isoloir/1/<origin>`).
    pub t: Option<String>,
    pub since: Option<u64>,
    /// The `#e` tag values.
    pub e: Vec<String>,
    pub limit: Option<u32>,
}

impl Filter {
    /// The filter as a REQ filter object, with `since` in place of the filter's own.
    pub fn to_json(&self, since: Option<u64>) -> Value {
        let mut m = serde_json::Map::new();
        if !self.kinds.is_empty() {
            m.insert("kinds".into(), json!(self.kinds));
        }
        if let Some(t) = &self.t {
            m.insert("#t".into(), json!([t]));
        }
        if !self.e.is_empty() {
            m.insert("#e".into(), json!(self.e));
        }
        if let Some(s) = since {
            m.insert("since".into(), json!(s));
        }
        if let Some(l) = self.limit {
            m.insert("limit".into(), json!(l));
        }
        Value::Object(m)
    }

    /// Whether an event matches (kinds, tags, since; `limit` does not apply).
    pub fn matches(&self, ev: &Event) -> bool {
        let has_tag = |name: &str, values: &[String]| {
            ev.tags.iter().any(|t| t.first().map(String::as_str) == Some(name) && t.get(1).is_some_and(|v| values.contains(v)))
        };
        (self.kinds.is_empty() || self.kinds.contains(&ev.kind))
            && self.t.as_ref().is_none_or(|t| has_tag("t", std::slice::from_ref(t)))
            && (self.e.is_empty() || has_tag("e", &self.e))
            && self.since.is_none_or(|s| ev.created_at >= s)
    }
}

/// An event and the relay it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivered {
    pub relay: String,
    pub event: Event,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PublishError {
    #[error("relay {0} is not in the pool")]
    UnknownRelay(String),
    #[error("not connected to the relay")]
    NotConnected,
    #[error("the relay refused the event: {0}")]
    Refused(String),
    #[error("no OK from the relay in time")]
    Timeout,
    #[error("no relay accepted the event: {0:?}")]
    AllFailed(Vec<(String, PublishError)>),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FetchError {
    #[error("relay {0} is not in the pool")]
    UnknownRelay(String),
    #[error("not connected to the relay")]
    NotConnected,
    #[error("the relay closed the request: {0}")]
    Closed(String),
    #[error("no EOSE from the relay in time")]
    Timeout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Connecting,
    Connected,
    Disconnected,
}

/// The ids a subscription has delivered, bounded: the oldest are forgotten.
struct Seen {
    set: HashSet<String>,
    order: VecDeque<String>,
}

impl Seen {
    fn new() -> Seen {
        Seen { set: HashSet::new(), order: VecDeque::new() }
    }

    /// True when the id is new.
    fn insert(&mut self, id: &str) -> bool {
        if self.set.contains(id) {
            return false;
        }
        if self.order.len() >= SEEN_CAPACITY
            && let Some(old) = self.order.pop_front()
        {
            self.set.remove(&old);
        }
        self.set.insert(id.to_string());
        self.order.push_back(id.to_string());
        true
    }
}

enum OnceMsg {
    Event(Event),
    Eose,
    Closed(String),
}

enum SubKind {
    /// A subscription kept across reconnects, shared by every relay.
    Live { tx: mpsc::Sender<Delivered>, seen: Arc<Mutex<Seen>>, cursor: bool },
    /// A one-off request on one relay (fetch), dropped on disconnect.
    Once { tx: mpsc::UnboundedSender<OnceMsg> },
}

struct Sub {
    filter: Filter,
    kind: SubKind,
}

#[derive(Default)]
struct State {
    /// The writer of the open connection, if any.
    out: Option<mpsc::UnboundedSender<Message>>,
    subs: HashMap<String, Sub>,
    /// Publishes waiting for an OK, by event id.
    pending: HashMap<String, Vec<oneshot::Sender<(bool, String)>>>,
    /// The newest `created_at` delivered by a cursor subscription.
    cursor: Option<u64>,
}

struct Relay {
    url: String,
    state: Mutex<State>,
    status: watch::Sender<Status>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn req_frame(sub_id: &str, filter: &Value) -> Message {
    Message::text(json!(["REQ", sub_id, filter]).to_string())
}

fn close_frame(sub_id: &str) -> Message {
    Message::text(json!(["CLOSE", sub_id]).to_string())
}

impl Relay {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The `since` a subscription is (re)sent with on this relay.
    fn since_for(state: &State, sub: &Sub) -> Option<u64> {
        match (&sub.kind, state.cursor) {
            (SubKind::Live { cursor: true, .. }, Some(c)) => {
                let s = c.saturating_sub(RESUBSCRIBE_OVERLAP);
                Some(sub.filter.since.map_or(s, |f| f.max(s)))
            }
            _ => sub.filter.since,
        }
    }

    /// Registers a subscription and sends its REQ when connected.
    fn add_sub(&self, id: String, sub: Sub) {
        let mut st = self.lock();
        if let Some(out) = &st.out {
            let since = Relay::since_for(&st, &sub);
            let _ = out.send(req_frame(&id, &sub.filter.to_json(since)));
        }
        st.subs.insert(id, sub);
    }

    fn remove_sub(&self, id: &str) {
        let mut st = self.lock();
        if st.subs.remove(id).is_some()
            && let Some(out) = &st.out
        {
            let _ = out.send(close_frame(id));
        }
    }

    /// Waits until the relay is connected, or known down, or the deadline.
    async fn ready(&self, deadline: Instant) -> bool {
        let mut rx = self.status.subscribe();
        loop {
            match *rx.borrow_and_update() {
                Status::Connected => return true,
                Status::Disconnected => return false,
                Status::Connecting => {}
            }
            match tokio::time::timeout_at(deadline, rx.changed()).await {
                Ok(Ok(())) => {}
                _ => return false,
            }
        }
    }

    /// The connection is up: install its writer and (re)send the live subscriptions.
    fn on_connect(&self, out: mpsc::UnboundedSender<Message>) {
        let mut st = self.lock();
        for (id, sub) in &st.subs {
            let since = Relay::since_for(&st, sub);
            debug!(relay = %self.url, sub = %id, since = ?since, "subscribing");
            let _ = out.send(req_frame(id, &sub.filter.to_json(since)));
        }
        st.out = Some(out);
        drop(st);
        self.status.send_replace(Status::Connected);
    }

    /// The connection is gone: fail the waiting publishes and fetches.
    fn on_disconnect(&self) {
        let mut st = self.lock();
        st.out = None;
        st.pending.clear();
        st.subs.retain(|_, s| matches!(s.kind, SubKind::Live { .. }));
        drop(st);
        self.status.send_replace(Status::Disconnected);
    }

    async fn run(self: Arc<Self>) {
        let mut backoff = BACKOFF_MIN;
        loop {
            self.status.send_replace(Status::Connecting);
            match tokio::time::timeout(CONNECT_TIMEOUT, tokio_tungstenite::connect_async(self.url.as_str())).await {
                Ok(Ok((ws, _))) => {
                    info!(relay = %self.url, "connected");
                    backoff = BACKOFF_MIN;
                    self.connection(ws).await;
                    info!(relay = %self.url, "disconnected");
                }
                Ok(Err(e)) => warn!(relay = %self.url, error = %e, retry_in = ?backoff, "connect failed"),
                Err(_) => warn!(relay = %self.url, retry_in = ?backoff, "connect timed out"),
            }
            self.on_disconnect();
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(BACKOFF_MAX);
        }
    }

    async fn connection<S>(&self, ws: tokio_tungstenite::WebSocketStream<S>)
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let (mut sink, mut stream) = ws.split();
        let (tx, mut rx) = mpsc::unbounded_channel();
        self.on_connect(tx);
        let mut ping = tokio::time::interval_at(Instant::now() + PING_EVERY, PING_EVERY);
        let mut last_rx = Instant::now();
        loop {
            tokio::select! {
                m = rx.recv() => {
                    let Some(m) = m else { break };
                    if let Err(e) = sink.send(m).await {
                        warn!(relay = %self.url, error = %e, "send failed");
                        break;
                    }
                }
                m = stream.next() => {
                    last_rx = Instant::now();
                    match m {
                        Some(Ok(Message::Text(t))) => self.handle(t.as_str()).await,
                        Some(Ok(Message::Close(f))) => {
                            debug!(relay = %self.url, frame = ?f, "close frame");
                            break;
                        }
                        Some(Ok(_)) => {}
                        Some(Err(e)) => {
                            warn!(relay = %self.url, error = %e, "read failed");
                            break;
                        }
                        None => break,
                    }
                }
                _ = ping.tick() => {
                    if last_rx.elapsed() > SILENCE_LIMIT {
                        warn!(relay = %self.url, "relay silent, reconnecting");
                        break;
                    }
                    if let Err(e) = sink.send(Message::Ping(Default::default())).await {
                        warn!(relay = %self.url, error = %e, "ping failed");
                        break;
                    }
                }
            }
        }
        let _ = sink.close().await;
    }

    /// One message from the relay. Malformed messages are logged and dropped.
    async fn handle(&self, text: &str) {
        let Ok(Value::Array(msg)) = serde_json::from_str::<Value>(text) else {
            warn!(relay = %self.url, message = %truncate(text), "malformed relay message");
            return;
        };
        let s = |i: usize| msg.get(i).and_then(Value::as_str);
        match s(0) {
            Some("EVENT") => {
                let (Some(sub), Some(ev)) = (s(1), msg.get(2)) else {
                    warn!(relay = %self.url, message = %truncate(text), "malformed EVENT");
                    return;
                };
                match serde_json::from_value::<Event>(ev.clone()) {
                    Ok(ev) => self.on_event(sub, ev).await,
                    Err(e) => warn!(relay = %self.url, error = %e, "malformed event"),
                }
            }
            Some("OK") => {
                let (Some(id), Some(ok)) = (s(1), msg.get(2).and_then(Value::as_bool)) else {
                    warn!(relay = %self.url, message = %truncate(text), "malformed OK");
                    return;
                };
                let text = s(3).unwrap_or("").to_string();
                debug!(relay = %self.url, id, ok, message = %text, "OK");
                for w in self.lock().pending.remove(id).unwrap_or_default() {
                    let _ = w.send((ok, text.clone()));
                }
            }
            Some("EOSE") => {
                let Some(sub) = s(1) else { return };
                debug!(relay = %self.url, sub, "EOSE");
                if let Some(Sub { kind: SubKind::Once { tx }, .. }) = self.lock().subs.get(sub) {
                    let _ = tx.send(OnceMsg::Eose);
                }
            }
            Some("CLOSED") => {
                let Some(sub) = s(1) else { return };
                let reason = s(2).unwrap_or("").to_string();
                warn!(relay = %self.url, sub, reason = %reason, "subscription closed by the relay");
                // A live subscription is sent again on the next connection.
                let mut st = self.lock();
                if let Some(Sub { kind: SubKind::Once { tx }, .. }) = st.subs.get(sub) {
                    let _ = tx.send(OnceMsg::Closed(reason));
                    st.subs.remove(sub);
                }
            }
            Some("NOTICE") => info!(relay = %self.url, notice = s(1).unwrap_or(""), "relay notice"),
            Some("AUTH") => debug!(relay = %self.url, "AUTH challenge ignored"),
            _ => warn!(relay = %self.url, message = %truncate(text), "unknown relay message"),
        }
    }

    async fn on_event(&self, sub_id: &str, ev: Event) {
        if !ev.verify() {
            warn!(relay = %self.url, id = %ev.id, "event dropped: id or signature does not verify");
            return;
        }
        let target = {
            let st = self.lock();
            let Some(sub) = st.subs.get(sub_id) else {
                debug!(relay = %self.url, sub = sub_id, "event for an unknown subscription");
                return;
            };
            if !sub.filter.matches(&ev) {
                debug!(relay = %self.url, id = %ev.id, "event does not match the filter");
                return;
            }
            match &sub.kind {
                SubKind::Once { tx } => {
                    let _ = tx.send(OnceMsg::Event(ev));
                    return;
                }
                SubKind::Live { tx, seen, cursor } => (tx.clone(), seen.clone(), *cursor),
            }
        };
        let (tx, seen, cursor) = target;
        if !seen.lock().unwrap_or_else(|p| p.into_inner()).insert(&ev.id) {
            return;
        }
        let created_at = ev.created_at;
        if tx.send(Delivered { relay: self.url.clone(), event: ev }).await.is_err() {
            self.remove_sub(sub_id);
            return;
        }
        if cursor {
            // A date in the future does not move the cursor past now.
            let c = created_at.min(now());
            let mut st = self.lock();
            st.cursor = Some(st.cursor.map_or(c, |old| old.max(c)));
        }
    }
}

fn truncate(s: &str) -> &str {
    match s.char_indices().nth(200) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

struct Inner {
    relays: Vec<Arc<Relay>>,
    tasks: Vec<JoinHandle<()>>,
    next_sub: AtomicU64,
}

impl Drop for Inner {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// A set of relay connections. Cloning shares the connections; they close
/// when the last clone is dropped.
#[derive(Clone)]
pub struct Pool {
    inner: Arc<Inner>,
}

impl Pool {
    /// Starts one background connection per relay and returns at once.
    /// Must be called within a tokio runtime.
    pub fn connect(urls: Vec<String>) -> Pool {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut seen = HashSet::new();
        let relays: Vec<Arc<Relay>> = urls
            .into_iter()
            .filter(|u| seen.insert(u.clone()))
            .map(|url| Arc::new(Relay { url, state: Mutex::new(State::default()), status: watch::Sender::new(Status::Connecting) }))
            .collect();
        let tasks = relays.iter().map(|r| tokio::spawn(r.clone().run())).collect();
        Pool { inner: Arc::new(Inner { relays, tasks, next_sub: AtomicU64::new(0) }) }
    }

    /// The relays of the pool, in the order given.
    pub fn relays(&self) -> Vec<String> {
        self.inner.relays.iter().map(|r| r.url.clone()).collect()
    }

    /// Whether the relay's connection is open now.
    pub fn is_connected(&self, relay: &str) -> bool {
        self.relay(relay).is_some_and(|r| *r.status.borrow() == Status::Connected)
    }

    fn relay(&self, url: &str) -> Option<&Arc<Relay>> {
        self.inner.relays.iter().find(|r| r.url == url)
    }

    fn sub_id(&self) -> String {
        format!("isoloir-{}", self.inner.next_sub.fetch_add(1, Ordering::Relaxed))
    }

    /// Restores a relay's cursor (the newest `created_at` delivered, as read
    /// with [`Pool::cursor`]). Subscriptions sent from then on ask the relay
    /// for `since = cursor - RESUBSCRIBE_OVERLAP`; call it before
    /// [`Pool::subscribe`]. Returns false for a relay not in the pool.
    pub fn set_since(&self, relay: &str, since: u64) -> bool {
        let Some(r) = self.relay(relay) else { return false };
        r.lock().cursor = Some(since);
        true
    }

    /// The newest `created_at` a subscription delivered from the relay.
    pub fn cursor(&self, relay: &str) -> Option<u64> {
        self.relay(relay).and_then(|r| r.lock().cursor)
    }

    /// The cursors of every relay that has one.
    pub fn cursors(&self) -> HashMap<String, u64> {
        self.inner.relays.iter().filter_map(|r| r.lock().cursor.map(|c| (r.url.clone(), c))).collect()
    }

    /// Streams the events that match the filter on every relay, verified
    /// and deduplicated by id. The subscription survives reconnects and
    /// ends when the receiver is dropped.
    pub fn subscribe(&self, filter: Filter) -> mpsc::Receiver<Delivered> {
        self.live(filter, true)
    }

    fn live(&self, filter: Filter, cursor: bool) -> mpsc::Receiver<Delivered> {
        let (tx, rx) = mpsc::channel(SUBSCRIPTION_BUFFER);
        let id = self.sub_id();
        let seen = Arc::new(Mutex::new(Seen::new()));
        for r in &self.inner.relays {
            let kind = SubKind::Live { tx: tx.clone(), seen: seen.clone(), cursor };
            r.add_sub(id.clone(), Sub { filter: filter.clone(), kind });
        }
        // CLOSE everywhere once the receiver is gone.
        let relays = self.inner.relays.clone();
        tokio::spawn(async move {
            tx.closed().await;
            for r in &relays {
                r.remove_sub(&id);
            }
        });
        rx
    }

    /// Posts an event to one relay and waits for its `OK`. A relay still
    /// connecting is waited for within the timeout; one known down fails at once.
    pub async fn publish(&self, relay: &str, event: &Event, timeout: Duration) -> Result<(), PublishError> {
        let r = self.relay(relay).ok_or_else(|| PublishError::UnknownRelay(relay.to_string()))?;
        let deadline = Instant::now() + timeout;
        if !r.ready(deadline).await {
            return Err(PublishError::NotConnected);
        }
        let (wtx, wrx) = oneshot::channel();
        {
            let mut st = r.lock();
            let out = st.out.clone().ok_or(PublishError::NotConnected)?;
            st.pending.entry(event.id.clone()).or_default().push(wtx);
            let frame = json!(["EVENT", event]).to_string();
            if out.send(Message::text(frame)).is_err() {
                st.pending.remove(&event.id);
                return Err(PublishError::NotConnected);
            }
        }
        match tokio::time::timeout_at(deadline, wrx).await {
            Ok(Ok((true, _))) => {
                debug!(relay, id = %event.id, kind = event.kind, "published");
                Ok(())
            }
            Ok(Ok((false, msg))) => Err(PublishError::Refused(msg)),
            Ok(Err(_)) => Err(PublishError::NotConnected),
            Err(_) => {
                let mut st = r.lock();
                if let Some(w) = st.pending.get_mut(&event.id) {
                    w.retain(|s| !s.is_closed());
                    if w.is_empty() {
                        st.pending.remove(&event.id);
                    }
                }
                Err(PublishError::Timeout)
            }
        }
    }

    /// Tries the relays in order until one accepts; returns that relay.
    pub async fn publish_any(&self, relays_in_order: &[String], event: &Event, timeout: Duration) -> Result<String, PublishError> {
        let mut failures = Vec::new();
        for relay in relays_in_order {
            match self.publish(relay, event, timeout).await {
                Ok(()) => return Ok(relay.clone()),
                Err(e) => {
                    warn!(relay = %relay, id = %event.id, error = %e, "publish failed, trying the next relay");
                    failures.push((relay.clone(), e));
                }
            }
        }
        Err(PublishError::AllFailed(failures))
    }

    /// Reads one relay's stored events that match the filter, until `EOSE`.
    pub async fn fetch(&self, relay: &str, filter: Filter, timeout: Duration) -> Result<Vec<Event>, FetchError> {
        let r = self.relay(relay).ok_or_else(|| FetchError::UnknownRelay(relay.to_string()))?;
        let deadline = Instant::now() + timeout;
        if !r.ready(deadline).await {
            return Err(FetchError::NotConnected);
        }
        let (tx, mut rx) = mpsc::unbounded_channel();
        let id = self.sub_id();
        r.add_sub(id.clone(), Sub { filter, kind: SubKind::Once { tx } });
        let mut events = Vec::new();
        let mut ids = HashSet::new();
        let result = loop {
            match tokio::time::timeout_at(deadline, rx.recv()).await {
                Ok(Some(OnceMsg::Event(ev))) => {
                    if ids.insert(ev.id.clone()) {
                        events.push(ev);
                    }
                }
                Ok(Some(OnceMsg::Eose)) => break Ok(events),
                Ok(Some(OnceMsg::Closed(m))) => break Err(FetchError::Closed(m)),
                Ok(None) => break Err(FetchError::NotConnected),
                Err(_) => break Err(FetchError::Timeout),
            }
        };
        r.remove_sub(&id);
        result
    }

    /// Waits for the first event that matches the filter on any relay.
    pub async fn wait_for(&self, filter: Filter, timeout: Duration) -> Option<Delivered> {
        let mut rx = self.live(filter, false);
        tokio::time::timeout(timeout, rx.recv()).await.ok().flatten()
    }
}

#[cfg(test)]
mod tests;
