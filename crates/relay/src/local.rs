//! A local relay for trials and tests: in memory, NIP-01 only (REQ,
//! EVENT, CLOSE; OK, EOSE), signatures checked. Not for production: it
//! keeps everything in memory and forgets it on exit.

use futures_util::{SinkExt, StreamExt};
use isoloir_proto::sig::Event;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio_tungstenite::tungstenite::Message;

fn matches(f: &Value, e: &Event) -> bool {
    let strs = |k: &str| f.get(k).and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect::<Vec<_>>());
    let tag_ok = |name: &str, key: &str| {
        strs(key).is_none_or(|vals| e.tags.iter().any(|t| t.first().map(String::as_str) == Some(name) && t.get(1).is_some_and(|v| vals.contains(v))))
    };
    f.get("kinds").and_then(Value::as_array).is_none_or(|k| k.iter().any(|k| k.as_u64() == Some(e.kind as u64)))
        && f.get("since").and_then(Value::as_u64).is_none_or(|s| e.created_at >= s)
        && strs("ids").is_none_or(|ids| ids.contains(&e.id))
        && tag_ok("t", "#t")
        && tag_ok("e", "#e")
}

/// Serves a local relay until the task is dropped; returns its address.
pub async fn serve(addr: SocketAddr) -> std::io::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind(addr).await?;
    let local = listener.local_addr()?;
    let store: Arc<Mutex<Vec<Event>>> = Arc::default();
    let (live, _) = broadcast::channel::<Event>(4096);
    let task = tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (store, live) = (store.clone(), live.clone());
            tokio::spawn(async move {
                let Ok(ws) = tokio_tungstenite::accept_async(tcp).await else { return };
                let (mut sink, mut stream) = ws.split();
                let mut live_rx = live.subscribe();
                let mut subs: HashMap<String, Value> = HashMap::new();
                let text = |v: Value| Message::text(v.to_string());
                loop {
                    tokio::select! {
                        m = stream.next() => {
                            let t = match m {
                                Some(Ok(Message::Text(t))) => t,
                                Some(Ok(_)) => continue,
                                _ => return,
                            };
                            let Ok(Value::Array(msg)) = serde_json::from_str::<Value>(t.as_str()) else { continue };
                            match msg.first().and_then(Value::as_str) {
                                Some("REQ") if msg.len() >= 3 => {
                                    let Some(id) = msg[1].as_str().map(String::from) else { continue };
                                    let f = msg[2].clone();
                                    let mut found: Vec<Event> = store.lock().unwrap().iter().filter(|e| matches(&f, e)).cloned().collect();
                                    if let Some(l) = f.get("limit").and_then(Value::as_u64) {
                                        let skip = found.len().saturating_sub(l as usize);
                                        found.drain(..skip);
                                    }
                                    for e in found {
                                        let _ = sink.send(text(json!(["EVENT", id, e]))).await;
                                    }
                                    let _ = sink.send(text(json!(["EOSE", id]))).await;
                                    subs.insert(id, f);
                                }
                                Some("CLOSE") => {
                                    if let Some(id) = msg.get(1).and_then(Value::as_str) {
                                        subs.remove(id);
                                    }
                                }
                                Some("EVENT") => {
                                    let Some(e) = msg.get(1).and_then(|v| serde_json::from_value::<Event>(v.clone()).ok()) else { continue };
                                    if !e.verify() {
                                        let _ = sink.send(text(json!(["OK", e.id, false, "invalid: signature"]))).await;
                                        continue;
                                    }
                                    let fresh = {
                                        let mut s = store.lock().unwrap();
                                        let fresh = !s.iter().any(|x| x.id == e.id);
                                        if fresh {
                                            s.push(e.clone());
                                        }
                                        fresh
                                    };
                                    if fresh {
                                        let _ = live.send(e.clone());
                                    }
                                    let _ = sink.send(text(json!(["OK", e.id, true, if fresh { "" } else { "duplicate:" }]))).await;
                                }
                                _ => {}
                            }
                        }
                        e = live_rx.recv() => {
                            let Ok(e) = e else { continue };
                            for (id, f) in &subs {
                                if matches(f, &e) {
                                    let _ = sink.send(text(json!(["EVENT", id, e]))).await;
                                }
                            }
                        }
                    }
                }
            });
        }
    });
    Ok((local, task))
}
