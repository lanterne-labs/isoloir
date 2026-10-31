//! Tests against an in-process fake relay.

use super::*;
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::broadcast;

const TAG: &str = "isoloir/1/test";
const T: Duration = Duration::from_secs(5);

fn ev(created_at: u64, kind: u32, content: &str) -> Event {
    Event::sign(&[0x22u8; 32], created_at, kind, vec![vec!["t".into(), TAG.into()]], content.into())
}

fn filter() -> Filter {
    Filter { kinds: vec![7100, 7101], t: Some(TAG.into()), ..Filter::default() }
}

/// A minimal NIP-01 relay: stores events, answers REQ with the stored
/// matches then EOSE, forwards new matches live, refuses content "refuse".
/// Every connection also gets a NOTICE and a malformed frame first.
struct FakeRelay {
    port: u16,
    store: Arc<Mutex<Vec<Event>>>,
    reqs: Arc<Mutex<Vec<Value>>>,
    closes: Arc<Mutex<Vec<String>>>,
    live: broadcast::Sender<Event>,
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

fn fake_matches(f: &Value, e: &Event) -> bool {
    let strs = |k: &str| f.get(k).and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>());
    let tag_ok = |name: &str, key: &str| {
        strs(key).is_none_or(|vals| e.tags.iter().any(|t| t.first().map(String::as_str) == Some(name) && t.get(1).is_some_and(|v| vals.contains(v))))
    };
    f.get("kinds").and_then(Value::as_array).is_none_or(|k| k.iter().any(|k| k.as_u64() == Some(e.kind as u64)))
        && f.get("since").and_then(Value::as_u64).is_none_or(|s| e.created_at >= s)
        && tag_ok("t", "#t")
        && tag_ok("e", "#e")
}

impl FakeRelay {
    async fn start() -> FakeRelay {
        FakeRelay::start_on(0, Arc::default()).await
    }

    async fn start_on(port: u16, store: Arc<Mutex<Vec<Event>>>) -> FakeRelay {
        let sock = TcpSocket::new_v4().unwrap();
        sock.set_reuseaddr(true).unwrap();
        sock.bind(([127, 0, 0, 1], port).into()).unwrap();
        let listener: TcpListener = sock.listen(64).unwrap();
        let port = listener.local_addr().unwrap().port();
        let (live, _) = broadcast::channel(256);
        let relay = FakeRelay { port, store, reqs: Arc::default(), closes: Arc::default(), live, tasks: Arc::default() };
        let (store, reqs, closes, live, tasks) =
            (relay.store.clone(), relay.reqs.clone(), relay.closes.clone(), relay.live.clone(), relay.tasks.clone());
        let accept = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (store, reqs, closes, live) = (store.clone(), reqs.clone(), closes.clone(), live.clone());
                let conn = tokio::spawn(async move {
                    let Ok(ws) = tokio_tungstenite::accept_async(tcp).await else { return };
                    serve(ws, store, reqs, closes, live).await;
                });
                tasks.lock().unwrap().push(conn);
            }
        });
        relay.tasks.lock().unwrap().push(accept);
        relay
    }

    fn url(&self) -> String {
        format!("ws://127.0.0.1:{}", self.port)
    }

    /// Kills the listener and every connection; the store survives.
    fn stop(&self) {
        for t in self.tasks.lock().unwrap().drain(..) {
            t.abort();
        }
    }

    fn add(&self, e: Event) {
        self.store.lock().unwrap().push(e.clone());
        let _ = self.live.send(e);
    }

    fn reqs(&self) -> Vec<Value> {
        self.reqs.lock().unwrap().clone()
    }
}

async fn serve(
    ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    store: Arc<Mutex<Vec<Event>>>,
    reqs: Arc<Mutex<Vec<Value>>>,
    closes: Arc<Mutex<Vec<String>>>,
    live: broadcast::Sender<Event>,
) {
    let (mut sink, mut stream) = ws.split();
    let mut live_rx = live.subscribe();
    let mut subs: HashMap<String, Value> = HashMap::new();
    let send = |v: Value| Message::text(v.to_string());
    let _ = sink.send(send(json!(["NOTICE", "welcome"]))).await;
    let _ = sink.send(Message::text("this is not json")).await;
    let _ = sink.send(send(json!(["AUTH", "challenge"]))).await;
    loop {
        tokio::select! {
            m = stream.next() => {
                let Some(Ok(Message::Text(t))) = m else {
                    if matches!(m, Some(Ok(_))) { continue }
                    return;
                };
                let Ok(Value::Array(msg)) = serde_json::from_str::<Value>(t.as_str()) else { continue };
                match msg.first().and_then(Value::as_str) {
                    Some("REQ") => {
                        let id = msg[1].as_str().unwrap().to_string();
                        let f = msg[2].clone();
                        reqs.lock().unwrap().push(f.clone());
                        let stored: Vec<Event> = store.lock().unwrap().iter().filter(|e| fake_matches(&f, e)).cloned().collect();
                        for e in stored {
                            let _ = sink.send(send(json!(["EVENT", id, e]))).await;
                        }
                        let _ = sink.send(send(json!(["EOSE", id]))).await;
                        subs.insert(id, f);
                    }
                    Some("CLOSE") => {
                        let id = msg[1].as_str().unwrap().to_string();
                        closes.lock().unwrap().push(id.clone());
                        subs.remove(&id);
                    }
                    Some("EVENT") => {
                        let e: Event = serde_json::from_value(msg[1].clone()).unwrap();
                        if e.content == "refuse" {
                            let _ = sink.send(send(json!(["OK", e.id, false, "blocked: refused"]))).await;
                        } else {
                            store.lock().unwrap().push(e.clone());
                            let _ = live.send(e.clone());
                            let _ = sink.send(send(json!(["OK", e.id, true, ""]))).await;
                        }
                    }
                    _ => {}
                }
            }
            e = live_rx.recv() => {
                let Ok(e) = e else { continue };
                for (id, f) in &subs {
                    if fake_matches(f, &e) {
                        let _ = sink.send(send(json!(["EVENT", id, e]))).await;
                    }
                }
            }
        }
    }
}

/// A local URL nothing listens on.
async fn dead_url() -> String {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    format!("ws://127.0.0.1:{port}")
}

async fn recv(rx: &mut mpsc::Receiver<Delivered>) -> Delivered {
    tokio::time::timeout(T, rx.recv()).await.expect("an event in time").expect("open channel")
}

async fn nothing_more(rx: &mut mpsc::Receiver<Delivered>) {
    if let Ok(Some(d)) = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await {
        panic!("unexpected delivery: {d:?}");
    }
}

#[tokio::test]
async fn publish_ok() {
    let relay = FakeRelay::start().await;
    let pool = Pool::connect(vec![relay.url()]);
    let e = ev(now(), 7101, "{}");
    pool.publish(&relay.url(), &e, T).await.unwrap();
    assert_eq!(relay.store.lock().unwrap().as_slice(), &[e]);
    assert!(pool.is_connected(&relay.url()));
}

#[tokio::test]
async fn publish_refused() {
    let relay = FakeRelay::start().await;
    let pool = Pool::connect(vec![relay.url()]);
    let e = ev(now(), 7101, "refuse");
    assert_eq!(pool.publish(&relay.url(), &e, T).await, Err(PublishError::Refused("blocked: refused".into())));
    assert_eq!(
        pool.publish("ws://elsewhere", &e, T).await,
        Err(PublishError::UnknownRelay("ws://elsewhere".into()))
    );
}

#[tokio::test]
async fn publish_not_connected() {
    let dead = dead_url().await;
    let pool = Pool::connect(vec![dead.clone()]);
    assert_eq!(pool.publish(&dead, &ev(now(), 7101, "{}"), T).await, Err(PublishError::NotConnected));
}

#[tokio::test]
async fn subscribe_stored_and_live() {
    let relay = FakeRelay::start().await;
    let stored = ev(now() - 100, 7100, "stored");
    relay.add(stored.clone());
    relay.add(ev(now() - 100, 7103, "other kind"));
    let pool = Pool::connect(vec![relay.url()]);
    let mut rx = pool.subscribe(filter());
    let d = recv(&mut rx).await;
    assert_eq!(d, Delivered { relay: relay.url(), event: stored.clone() });

    let live = ev(now() - 50, 7101, "live");
    pool.publish(&relay.url(), &live, T).await.unwrap();
    assert_eq!(recv(&mut rx).await.event, live);
    nothing_more(&mut rx).await;
    assert_eq!(pool.cursor(&relay.url()), Some(live.created_at));
}

#[tokio::test]
async fn reconnect_resubscribes_from_cursor() {
    let relay = FakeRelay::start().await;
    let a = ev(now() - 1000, 7101, "a");
    relay.add(a.clone());
    let pool = Pool::connect(vec![relay.url()]);
    let mut rx = pool.subscribe(filter());
    assert_eq!(recv(&mut rx).await.event, a);
    assert_eq!(relay.reqs()[0].get("since"), None);

    // The relay goes down; an event lands while the client is away.
    relay.stop();
    let b = ev(now() - 1000 + 30, 7101, "b");
    relay.store.lock().unwrap().push(b.clone());
    tokio::time::sleep(Duration::from_millis(300)).await;
    let restarted = FakeRelay::start_on(relay.port, relay.store.clone()).await;

    // a is sent again (inside the overlap) but not delivered twice.
    assert_eq!(recv(&mut rx).await.event, b);
    nothing_more(&mut rx).await;
    let reqs = restarted.reqs();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0]["since"], json!(a.created_at - RESUBSCRIBE_OVERLAP));
    assert_eq!(pool.cursor(&relay.url()), Some(b.created_at));

    // Live events still flow on the new connection.
    let c = ev(now(), 7100, "c");
    restarted.add(c.clone());
    assert_eq!(recv(&mut rx).await.event, c);
}

#[tokio::test]
async fn restored_cursor_sets_since() {
    let relay = FakeRelay::start().await;
    let old = ev(now() - 10_000, 7101, "old");
    let recent = ev(now() - 100, 7101, "recent");
    relay.add(old);
    relay.add(recent.clone());
    let pool = Pool::connect(vec![relay.url()]);
    assert!(pool.set_since(&relay.url(), now() - 200));
    let mut rx = pool.subscribe(filter());
    assert_eq!(recv(&mut rx).await.event, recent);
    nothing_more(&mut rx).await;
    assert_eq!(pool.cursors(), HashMap::from([(relay.url(), recent.created_at)]));
}

#[tokio::test]
async fn fetch_until_eose() {
    let relay = FakeRelay::start().await;
    let events: Vec<Event> = (0..3).map(|i| ev(now() - 100 + i, 7101, &format!("{i}"))).collect();
    for e in &events {
        relay.add(e.clone());
    }
    relay.add(ev(now(), 7105, "tally"));
    let pool = Pool::connect(vec![relay.url()]);
    let got = pool.fetch(&relay.url(), filter(), T).await.unwrap();
    assert_eq!(got, events);
    // The request is closed once EOSE came.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(relay.closes.lock().unwrap().len(), 1);
    // A fetch does not move the cursor.
    assert_eq!(pool.cursor(&relay.url()), None);
}

#[tokio::test]
async fn publish_any_skips_dead_relay() {
    let dead = dead_url().await;
    let relay = FakeRelay::start().await;
    let pool = Pool::connect(vec![dead.clone(), relay.url()]);
    let e = ev(now(), 7101, "{}");
    let used = pool.publish_any(&[dead.clone(), relay.url()], &e, T).await.unwrap();
    assert_eq!(used, relay.url());
    let err = pool.publish_any(std::slice::from_ref(&dead),&e, T).await.unwrap_err();
    assert_eq!(err, PublishError::AllFailed(vec![(dead, PublishError::NotConnected)]));
}

#[tokio::test]
async fn invalid_signature_dropped() {
    let relay = FakeRelay::start().await;
    let mut forged = ev(now() - 100, 7101, "forged");
    forged.content = "tampered".into();
    let mut bad_sig = ev(now() - 100, 7101, "bad sig");
    bad_sig.sig = ev(now() - 100, 7101, "other").sig;
    let good = ev(now() - 50, 7101, "good");
    relay.add(forged);
    relay.add(bad_sig);
    relay.add(good.clone());
    let pool = Pool::connect(vec![relay.url()]);
    let mut rx = pool.subscribe(filter());
    assert_eq!(recv(&mut rx).await.event, good);
    nothing_more(&mut rx).await;
}

#[tokio::test]
async fn wait_for_ack() {
    let r1 = FakeRelay::start().await;
    let r2 = FakeRelay::start().await;
    let pool = Pool::connect(vec![r1.url(), r2.url()]);
    let ballot = ev(now(), 7101, "{}");
    let ack = Event::sign(
        &[0x33u8; 32],
        now(),
        7102,
        vec![vec!["t".into(), TAG.into()], vec!["e".into(), ballot.id.clone()]],
        "{}".into(),
    );
    let f = Filter { kinds: vec![7102], e: vec![ballot.id.clone()], ..Filter::default() };
    let r2c = r2.live.clone();
    let store = r2.store.clone();
    let ack2 = ack.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        store.lock().unwrap().push(ack2.clone());
        let _ = r2c.send(ack2);
    });
    let got = pool.wait_for(f.clone(), T).await.expect("the ack");
    assert_eq!(got, Delivered { relay: r2.url(), event: ack });
    // Nothing for another id.
    let other = Filter { kinds: vec![7102], e: vec!["00".repeat(32)], ..Filter::default() };
    assert_eq!(pool.wait_for(other, Duration::from_millis(300)).await, None);
}

#[test]
fn filter_json() {
    let f = Filter { kinds: vec![7102], t: Some(TAG.into()), since: Some(5), e: vec!["ab".into()], limit: Some(10) };
    assert_eq!(f.to_json(f.since), json!({"kinds":[7102],"#t":[TAG],"#e":["ab"],"since":5,"limit":10}));
    assert_eq!(Filter::default().to_json(None), json!({}));
}
