//! A reference voter: reads the mirror, proves with nargo and bb, posts to
//! the relays and waits for the ingest's acknowledgement. For trials and
//! tests of a deployment; browsers use @isoloir/web.

use anyhow::{bail, Context, Result};
use isoloir_core::{field, Fr};
use isoloir_proto::body::{self, decode_ack, Body, EntryKind, LedgerSetup, PollSetup};
use isoloir_proto::client::{self, Member, Revoting};
use isoloir_proto::kinds::{Choice, Variant};
use isoloir_proto::sig::Event;
use isoloir_relay::{Filter, Pool};
use isoloir_zk::{Circuits, Prover, Tools};
use std::path::Path;
use std::time::Duration;

fn read(dir: &Path, p: &str) -> Result<serde_json::Value> {
    Ok(serde_json::from_slice(&std::fs::read(dir.join(p)).with_context(|| format!("mirror: {p}"))?)?)
}

fn ledger(dir: &Path) -> Result<LedgerSetup> {
    let v = read(dir, "setup/ledger.json")?;
    match body::decode(EntryKind::Ledger, v["body"].as_str().unwrap_or("").as_bytes()) {
        Ok(Body::Ledger(l)) => Ok(l),
        _ => bail!("mirror: setup/ledger.json"),
    }
}

/// The poll's current setup and its seq.
fn poll(dir: &Path, id: u32) -> Result<(u64, PollSetup)> {
    let v = read(dir, &format!("polls/{id}.json"))?;
    let last = v["setups"].as_array().and_then(|a| a.last()).context("no poll setup")?;
    match body::decode(EntryKind::Poll, last["body"].as_str().unwrap_or("").as_bytes()) {
        Ok(Body::Poll(p)) => Ok((last["seq"].as_u64().context("seq")?, p)),
        _ => bail!("mirror: polls/{id}.json"),
    }
}

/// The registry tree from its leaf shards, and the voter's place in it.
fn member(dir: &Path, registry: u32, depth: usize, s: &Fr) -> Result<Member> {
    let mut tree = isoloir_core::tree::Tree::new(depth);
    for k in 0.. {
        let Ok(v) = read(dir, &format!("registries/{registry}/leaves/{k}.json")) else { break };
        for l in v.as_array().context("leaves")? {
            tree.push(field::from_hex(l.as_str().context("leaf")?)?)?;
        }
    }
    let leaf = client::leaf(registry, s);
    let index = (0..tree.len()).find(|i| tree.leaf(*i) == Some(leaf)).context("not registered (yet): wait for the checkpoint")?;
    Ok(Member { root: tree.root(), path: tree.path(index)?, index: index as u64 })
}

fn registry_depth(dir: &Path, id: u32) -> Result<usize> {
    let v = read(dir, &format!("registries/{id}.json"))?;
    let last = v["setups"].as_array().and_then(|a| a.last()).context("no registry setup")?;
    match body::decode(EntryKind::Registry, last["body"].as_str().unwrap_or("").as_bytes()) {
        Ok(Body::Registry(r)) => Ok(r.depth as usize),
        _ => bail!("mirror: registries/{id}.json"),
    }
}

/// Posts a body by the ledger's first active channel and waits for its
/// ack; prints it.
async fn post(dir: &Path, kind: u32, body: Vec<u8>) -> Result<()> {
    let l = ledger(dir)?;
    let sk: [u8; 32] = rand::random();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let tag = format!("{}/{}", isoloir_proto::PROTOCOL, l.origin);
    let ev = Event::sign(&sk, now, kind, vec![vec!["t".into(), tag.clone()]], String::from_utf8(body)?);
    let channel = l.channels.iter().find(|c| c.is_active()).context("no active channel")?;
    let ack = match channel {
        isoloir_proto::body::Channel::Direct { url, .. } => {
            println!("posting {} to {url}", ev.id);
            isoloir_server::direct::post_direct(url, &ev, Duration::from_secs(90)).await?
        }
        isoloir_proto::body::Channel::Nostr { .. } => {
            let relays = l.nostr(true);
            let pool = Pool::connect(relays.clone());
            let waiter = {
                let pool = pool.clone();
                let id = ev.id.clone();
                tokio::spawn(async move { pool.wait_for(Filter { kinds: vec![7102], e: vec![id], ..Default::default() }, Duration::from_secs(90)).await })
            };
            tokio::time::sleep(Duration::from_millis(300)).await;
            let relay = pool.publish_any(&relays, &ev, Duration::from_secs(10)).await.map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("posted {} to {relay}", ev.id);
            waiter.await?.context("no acknowledgement within 90 s")?.event
        }
    };
    if ack.pubkey != l.ingest || !ack.verify() || ack.tag("e") != Some(ev.id.as_str()) {
        bail!("an acknowledgement not signed by the ingest, or for another message");
    }
    let ack = decode_ack(ack.content.as_bytes()).map_err(|r| anyhow::anyhow!("ack: {}", r.as_str()))?;
    println!("{}", serde_json::to_string(&ack)?);
    Ok(())
}

pub async fn register(dir: &Path, registry: u32, secret: &str, uid: &str) -> Result<()> {
    let s = field::from_hex(secret)?;
    let reg_sk: [u8; 32] = rand::random();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    // The dev provider: the proof bundle names the passport.
    let body = client::register_body(registry, &s, uid, serde_json::json!({"uid": uid}), now, &reg_sk);
    post(dir, 7100, body).await
}

pub async fn vote(dir: &Path, circuits: &Path, poll_id: u32, secret: &str, choice: &str, seq: u32) -> Result<()> {
    let s = field::from_hex(secret)?;
    let (setup_seq, p) = poll(dir, poll_id)?;
    let variant = Variant::parse(&p.circuit.name).context("circuit")?;
    let m = member(dir, p.registry, registry_depth(dir, p.registry)?, &s)?;
    let choice = match choice {
        "none" => Choice::Pick(None),
        c if c.contains(',') => Choice::Rank(c.split(',').map(|x| x.parse()).collect::<Result<_, _>>()?),
        c if matches!(p.kind, isoloir_proto::body::KindSpec::Ranked { .. }) => Choice::Rank(vec![c.parse()?]),
        c => Choice::Pick(Some(c.parse()?)),
    };
    if p.revote == isoloir_proto::body::Revote::Delta {
        bail!("delta polls need the previous ballot's place in the ballot tree: use @isoloir/web");
    }
    let d = client::draft(&p, setup_seq, &variant, &m, &s, &choice, &Revoting::Linked { seq }, None, &mut rand::rngs::OsRng).map_err(|e| anyhow::anyhow!(e))?;
    let prover = Prover::new(Tools::find()?, Circuits::new(circuits));
    let t0 = std::time::Instant::now();
    let proof = prover.prove(&p.circuit.name, &d.inputs)?;
    println!("proved in {} ms", t0.elapsed().as_millis());
    post(dir, 7101, d.finish(&proof.proof)).await
}
