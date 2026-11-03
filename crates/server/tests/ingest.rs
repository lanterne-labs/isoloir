//! The ingest end to end on Postgres (ISOLOIR_TEST_DATABASE, a server URL
//! without a database name: a fresh database is made per run), an
//! in-memory relay transport and real proofs.

use isoloir_core::grumpkin::{self, Projective};
use isoloir_core::{canonical, field, Fr};
use isoloir_decrypt::keys::AuthorityKeys;
use isoloir_decrypt::tlock::DrandTlock;
use isoloir_proto::audit::Auditor;
use isoloir_proto::body::*;
use isoloir_proto::client::{self, Member, Revoting};
use isoloir_proto::judge::Checkers;
use isoloir_proto::kinds::{Choice, Variant};
use isoloir_proto::note;
use isoloir_proto::sig::Event;
use isoloir_server::eligibility::Verifiers;
use isoloir_server::ingest::{kinds, Config, Incoming, Ingest, Transport};
use isoloir_server::mirror::Mirror;
use isoloir_server::source::{LogSource, MirrorSource};
use isoloir_server::store::Store;
use isoloir_server::authority::{Keys, Output, Service};
use isoloir_zk::{BbProofs, Circuits, Prover, Tools};
use rand::SeedableRng;
use serde_json::json;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Mem {
    posted: Mutex<Vec<(String, Event)>>,
}

#[async_trait::async_trait]
impl Transport for Mem {
    async fn publish(&self, relay: &str, event: &Event) -> Result<(), String> {
        self.posted.lock().unwrap().push((relay.to_string(), event.clone()));
        Ok(())
    }
    async fn publish_all(&self, event: &Event) {
        self.posted.lock().unwrap().push(("*".into(), event.clone()));
    }
}

impl Mem {
    fn ack_of(&self, id: &str) -> Ack {
        let p = self.posted.lock().unwrap();
        let (_, ev) = p.iter().rev().find(|(_, e)| (e.kind == kinds::ACK || e.kind == kinds::ACK - kinds::LEGACY) && e.tag("e") == Some(id)).expect("an ack");
        decode_ack(ev.content.as_bytes()).unwrap()
    }
}

async fn fresh_db() -> String {
    let server = std::env::var("ISOLOIR_TEST_DATABASE").unwrap_or_else(|_| "postgresql://postgres@127.0.0.1:55433".into());
    let name = format!("isoloir_test_{}", rand::random::<u32>());
    let pool = sqlx::PgPool::connect(&format!("{server}/postgres")).await.expect("a Postgres for tests (ISOLOIR_TEST_DATABASE)");
    sqlx::query(&format!("CREATE DATABASE {name}")).execute(&pool).await.unwrap();
    format!("{server}/{name}")
}

fn event(kind: u32, tag: &str, body: &[u8], now: u64) -> Event {
    let sk: [u8; 32] = rand::random();
    Event::sign(&sk, now, kind, vec![vec!["t".into(), tag.into()]], String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_ingest_on_postgres() {
    let tools = Tools::find().expect("nargo and bb");
    let circuits = Circuits::repo();
    let name = "choice4_single_linked_d20";
    let built = circuits.build(&tools, name).unwrap();
    let mirror_dir = tempfile::tempdir().unwrap();
    let mirror = Mirror::new(mirror_dir.path().to_path_buf(), None);
    mirror.install_circuit(name, &built.artifact, &built.vk).unwrap();
    let vk_dir = mirror_dir.path().join("circuits");
    let prover = Prover::new(tools.clone(), circuits);
    let mut rng = rand::rngs::StdRng::seed_from_u64(21);

    let url = fresh_db().await;
    let store = Store::connect(&url).await.unwrap();
    let config = Config { log_seed: [11u8; 32], nostr_sk: [12u8; 32] };
    let origin = "test.example/isoloir";
    let signer = note::Signer::new(origin, &config.log_seed);
    let mut now = 1_800_000_000u64;
    let ledger = LedgerSetup {
        v: 1,
        version: 1,
        origin: origin.into(),
        log_key: signer.verifier(),
        ingest: hex::encode(isoloir_proto::sig::xonly(&config.nostr_sk)),
        channels: vec![Channel::Nostr { url: "wss://a.test".into(), state: ChannelState::Active }],
        checkpoint_period: 20,
        anchor_age: 86_400,
        revote_gap: 0,
        pow: 0,
    };
    Ingest::genesis(&store, &config, &ledger, now).await.unwrap();
    assert!(Ingest::genesis(&store, &config, &ledger, now).await.is_err(), "one ledger per database");

    let mem = Arc::new(Mem::default());
    let load = |store: Store, mem: Arc<Mem>| {
        let config = Config { log_seed: [11u8; 32], nostr_sk: [12u8; 32] };
        let proofs = Box::new(BbProofs::new(tools.bb.clone(), vk_dir.clone()));
        let passports = Box::new(Verifiers { zkpassport: None, rpc_url: None, allow_dev: true });
        let mirror = Mirror::new(mirror_dir.path().to_path_buf(), None);
        Ingest::load(store, config, mem, proofs, passports, Some(Box::new(DrandTlock)), Some(mirror))
    };
    let mut ingest = load(store.clone(), mem.clone()).await.unwrap();
    let tag = ingest.tag().to_string();
    let _lease = store.lease().await.unwrap();
    assert!(store.lease().await.is_err(), "a second ingest is refused");
    let t = std::time::Instant::now();
    assert!(store.lease_wait(std::time::Duration::from_secs(3)).await.is_err(), "a second ingest waits, then gives up");
    assert!(t.elapsed() >= std::time::Duration::from_secs(3));

    // The registry, submitted by the operator.
    let registry = RegistrySetup {
        v: 1,
        id: 1,
        version: 1,
        name: "test".into(),
        eligibility: Eligibility { provider: "dev".into(), domain: "test.example".into(), scope: "t".into(), min_age: None, nationality: vec![], document_type: None, require_expiry: false, oprf_key: None },
        validity: 3600,
        depth: 20,
    };
    store.submit(EntryKind::Registry, &Body::Registry(registry).encode(), now).await.unwrap();
    now += 30;
    assert_eq!(ingest.tick(now).await.unwrap(), Some(2));

    // Two registrations through the relays, one refused.
    let voters: Vec<Fr> = (0..2).map(|_| grumpkin::random_fr(&mut rng)).collect();
    let mut reg_events = vec![];
    for (i, s) in voters.iter().enumerate() {
        let b = client::register_body(1, s, &format!("p{i}"), json!({"uid": format!("p{i}")}), now, &[0x20 + i as u8; 32]);
        let ev = event(kinds::REGISTER, &tag, &b, now);
        ingest.handle(Incoming { origin: "wss://a.test".into(), event: ev.clone() }, now).await.unwrap();
        ingest.drain(now).await.unwrap();
        assert_eq!(mem.ack_of(&ev.id).outcome, Outcome::Accepted);
        assert_eq!(mem.ack_of(&ev.id).checkpoint, Some(3));
        reg_events.push(ev);
    }
    let dup = client::register_body(1, &grumpkin::random_fr(&mut rng), "p0", json!({"uid": "p0"}), now, &[0x30; 32]);
    let dup_ev = event(kinds::REGISTER, &tag, &dup, now);
    ingest.handle(Incoming { origin: "wss://a.test".into(), event: dup_ev.clone() }, now).await.unwrap();
    ingest.drain(now).await.unwrap();
    assert_eq!(mem.ack_of(&dup_ev.id).reason, Some(isoloir_proto::Reason::UidUsed));
    // A crash before the checkpoint: the accepted messages are not lost.
    drop(ingest);
    let mut ingest = load(store.clone(), mem.clone()).await.unwrap();
    // The same event again: the same ack, nothing new.
    let n = mem.posted.lock().unwrap().len();
    ingest.handle(Incoming { origin: "wss://b.test".into(), event: reg_events[0].clone() }, now).await.unwrap();
    ingest.drain(now).await.unwrap();
    assert_eq!(mem.posted.lock().unwrap().len(), n + 1);
    assert_eq!(mem.ack_of(&reg_events[0].id).checkpoint, Some(3));
    now += 30;
    assert_eq!(ingest.tick(now).await.unwrap(), Some(3));
    assert_eq!(ingest.state.registries[&1].tree.len(), 2);

    // The poll, with a single authority.
    let keys = AuthorityKeys::generate(&mut rng);
    let poll = PollSetup {
        v: 1,
        id: 5,
        version: 1,
        registry: 1,
        title: "Oui ou non ?".into(),
        kind: KindSpec::Choice { options: vec!["Oui".into(), "Non".into()], blank: true },
        encryption: Encryption::Elgamal { pk: keys.pk.clone(), authority: Authority::Single { sign_key: keys.sign_key.clone() } },
        publish: Publish::Open { k_real: 1, min_gap: 0, coin: false },
        revote: Revote::Linked,
        opens: now,
        closes: now + 3_600,
        blackouts: vec![],
        circuit: CircuitRef { name: name.into(), vk_hash: built.vk_hash.clone() },
        ballot_depth: None,
    };
    store.submit(EntryKind::Poll, &Body::Poll(poll.clone()).encode(), now).await.unwrap();
    now += 30;
    assert_eq!(ingest.tick(now).await.unwrap(), Some(4));
    let setup_seq = ingest.state.polls[&5].setups[0].0;
    let variant = Variant::parse(name).unwrap();

    // Ballots: yes and no.
    for (s, pick) in voters.iter().zip([0u32, 1]) {
        let reg = &ingest.state.registries[&1];
        let index = reg.ids[&field::to_hex(&client::leaf(1, s))];
        let m = Member { root: reg.tree.root(), path: reg.tree.path(index as usize).unwrap(), index };
        let d = client::draft(&poll, setup_seq, &variant, &m, s, &Choice::Pick(Some(pick)), &Revoting::Linked { seq: 0 }, None, &mut rng).unwrap();
        let p = prover.prove(name, &d.inputs).unwrap();
        let ev = event(kinds::BALLOT, &tag, &d.finish(&p.proof), now);
        ingest.handle(Incoming { origin: "wss://a.test".into(), event: ev.clone() }, now).await.unwrap();
        ingest.drain(now).await.unwrap();
        assert_eq!(mem.ack_of(&ev.id).outcome, Outcome::Accepted, "{:?}", mem.ack_of(&ev.id));
    }
    now += 30;
    let cp = ingest.tick(now).await.unwrap().unwrap();

    // The authority: reads the database, verifies, decrypts, submits.
    let (sk, seed) = keys.secrets().unwrap();
    let mut authority = Service::new(
        Box::new(store.clone()),
        Some(&signer.verifier()),
        Box::new(BbProofs::new(tools.bb.clone(), vk_dir.clone())),
        Box::new(Verifiers { zkpassport: None, rpc_url: None, allow_dev: true }),
        Some(Keys { pk: keys.pk.clone(), sk, sign_seed: seed }),
        None,
        Output::Store(store.clone()),
    )
    .unwrap();
    assert_eq!(authority.step(now).await.unwrap(), 1);
    assert_eq!(authority.step(now).await.unwrap(), 0, "published once");
    now += 30;
    ingest.tick(now).await.unwrap().unwrap();
    let (_, t) = ingest.state.polls[&5].tallies.last().unwrap();
    assert_eq!(t.values, vec![1, 1, 0, 0]);
    assert_eq!(t.checkpoint, Some(cp));

    // The mirror, audited from its files alone.
    let src = MirrorSource::parse(mirror_dir.path().to_str().unwrap());
    let proofs = BbProofs::new(tools.bb.clone(), vk_dir.clone());
    let passports = Verifiers { zkpassport: None, rpc_url: None, allow_dev: true };
    let mut a = Auditor::new(Some(&signer.verifier()), Checkers { proofs: &proofs, passports: &passports, tlock: Some(&DrandTlock) }).unwrap();
    for (n, es) in src.from(1).await.unwrap() {
        a.checkpoint(&n, &es).unwrap();
    }
    let (state, report) = a.finish();
    assert!(report.problems.is_empty(), "{:#?}", report.problems);
    assert_eq!(report.rejects, 0, "refusals are not logged");
    assert_eq!(state.log.root(), ingest.state.log.root());
    // The files a browser needs are there.
    for f in ["checkpoint.txt", "registries/1/leaves/0.json", "polls/5.json", "polls/5/tallies/latest.json", "setup/ledger.json"] {
        assert!(mirror_dir.path().join(f).is_file(), "{f}");
    }
    let latest: serde_json::Value = serde_json::from_slice(&std::fs::read(mirror_dir.path().join("polls/5/tallies/latest.json")).unwrap()).unwrap();
    let body: Tally = canonical::from_slice(latest["body"].as_str().unwrap().as_bytes()).unwrap();
    // A browser checks the tally from itself.
    let agg: Vec<_> = body.aggregate.as_ref().unwrap().iter().map(|[a, b]| (grumpkin::from_hex(a).unwrap(), grumpkin::from_hex(b).unwrap())).collect();
    isoloir_proto::tally::verify_shares(&poll.encryption, &body, latest["body"].as_str().unwrap().as_bytes(), variant.values(), variant.chunks(), variant.per as usize, &agg).unwrap();
    let _ = Projective::default();

}

/// A ledger whose only channel is the ingest's own HTTP endpoint.
#[tokio::test(flavor = "multi_thread")]
async fn the_direct_channel() {
    use isoloir_server::direct::{self, DirectHub};
    use isoloir_server::relays::Channels;
    let url = fresh_db().await;
    let store = Store::connect(&url).await.unwrap();
    let config = Config { log_seed: [13u8; 32], nostr_sk: [14u8; 32] };
    let origin = "direct.example/isoloir";
    let signer = note::Signer::new(origin, &config.log_seed);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let mut now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let ledger = LedgerSetup {
        v: 1,
        version: 1,
        origin: origin.into(),
        log_key: signer.verifier(),
        ingest: hex::encode(isoloir_proto::sig::xonly(&config.nostr_sk)),
        channels: vec![Channel::Direct { url: endpoint.clone(), state: ChannelState::Active }],
        checkpoint_period: 20,
        anchor_age: 86_400,
        revote_gap: 0,
        pow: 0,
    };
    Ingest::genesis(&store, &config, &ledger, now).await.unwrap();
    let hub = DirectHub::new(&endpoint);
    let transport = Arc::new(Channels { pool: None, direct: vec![hub.clone()] });
    let tools = Tools::find().expect("bb");
    let mut ingest = Ingest::load(
        store.clone(),
        config,
        transport,
        Box::new(BbProofs::new(tools.bb.clone(), std::env::temp_dir())),
        Box::new(Verifiers { zkpassport: None, rpc_url: None, allow_dev: true }),
        None,
        None,
    )
    .await
    .unwrap();
    let registry = RegistrySetup {
        v: 1,
        id: 1,
        version: 1,
        name: "test".into(),
        eligibility: Eligibility { provider: "dev".into(), domain: "d".into(), scope: "s".into(), min_age: None, nationality: vec![], document_type: None, require_expiry: false, oprf_key: None },
        validity: 3600,
        depth: 20,
    };
    store.submit(EntryKind::Registry, &Body::Registry(registry).encode(), now).await.unwrap();
    now += 30;
    ingest.tick(now).await.unwrap().unwrap();

    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let app = direct::router(hub, tx, store.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    // A voter posts over HTTP; the ingest answers in the response.
    let tag = ingest.tag().to_string();
    let mut rng = rand::rngs::StdRng::seed_from_u64(41);
    let s = grumpkin::random_fr(&mut rng);
    let body = client::register_body(1, &s, "alice", json!({"uid": "alice"}), now, &[0x44; 32]);
    let ev = event(kinds::REGISTER, &tag, &body, now);
    let again = event(kinds::REGISTER, &tag, &client::register_body(1, &grumpkin::random_fr(&mut rng), "alice", json!({"uid": "alice"}), now, &[0x45; 32]), now);
    let (e1, e2, ep) = (ev.clone(), again.clone(), endpoint.clone());
    let voter = tokio::spawn(async move {
        let a = direct::post_direct(&ep, &e1, std::time::Duration::from_secs(30)).await.unwrap();
        let b = direct::post_direct(&ep, &e2, std::time::Duration::from_secs(30)).await.unwrap();
        (a, b)
    });
    for _ in 0..2 {
        let inc = rx.recv().await.unwrap();
        assert_eq!(inc.origin, endpoint);
        ingest.handle(inc, now).await.unwrap();
        ingest.drain(now).await.unwrap();
    }
    let (a, b) = voter.await.unwrap();
    let ingest_pk = hex::encode(isoloir_proto::sig::xonly(&[14u8; 32]));
    assert!(a.verify() && a.pubkey == ingest_pk);
    assert_eq!(decode_ack(a.content.as_bytes()).unwrap().outcome, Outcome::Accepted);
    assert_eq!(decode_ack(b.content.as_bytes()).unwrap().reason, Some(isoloir_proto::Reason::UidUsed));
    // After a dropped connection: the same ack by GET.
    let got: Event = reqwest::get(format!("{endpoint}/v1/acks/{}", ev.id)).await.unwrap().json().await.unwrap();
    assert_eq!(got, a);
    assert_eq!(reqwest::get(format!("{endpoint}/v1/acks/{}", "00".repeat(32))).await.unwrap().status(), 404);
    now += 30;
    ingest.tick(now).await.unwrap().unwrap();
    assert_eq!(ingest.state.registries[&1].tree.len(), 1);
}

/// A refusal is its signed ack: nothing in the log or the mirror, the body
/// kept in the purgeable table; legacy kinds are answered in their range.
#[tokio::test(flavor = "multi_thread")]
async fn refusals_are_not_logged() {
    let (store, mut ingest, mem, mirror_dir, now) = small_ledger(0, 0).await;
    let tag = ingest.tag().to_string();
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let ok = event(kinds::REGISTER, &tag, &client::register_body(1, &grumpkin::random_fr(&mut rng), "bob", json!({"uid": "bob"}), now, &[0x51; 32]), now);
    let dup = event(kinds::REGISTER - kinds::LEGACY, &tag, &client::register_body(1, &grumpkin::random_fr(&mut rng), "bob", json!({"uid": "bob"}), now, &[0x52; 32]), now);
    let junk = event(kinds::BALLOT, &tag, b"junk", now);
    for ev in [&ok, &dup, &junk] {
        ingest.handle(Incoming { origin: "wss://a.test".into(), event: ev.clone() }, now).await.unwrap();
        ingest.drain(now).await.unwrap();
    }
    assert_eq!(mem.ack_of(&dup.id).reason, Some(isoloir_proto::Reason::UidUsed));
    assert_eq!(mem.ack_of(&junk.id).reason, Some(isoloir_proto::Reason::Malformed));
    let kind_of = |id: &str| mem.posted.lock().unwrap().iter().rev().find(|(_, e)| e.tag("e") == Some(id)).unwrap().1.kind;
    assert_eq!(kind_of(&dup.id), kinds::ACK - kinds::LEGACY, "a legacy message is answered in its range");
    assert_eq!(kind_of(&ok.id), kinds::ACK);
    let cp = ingest.tick(now + 30).await.unwrap().unwrap();
    let entries: serde_json::Value = serde_json::from_slice(&std::fs::read(mirror_dir.path().join(format!("entries/{cp}.json"))).unwrap()).unwrap();
    assert_eq!(entries.as_array().unwrap().iter().map(|e| e["kind"].as_str().unwrap()).collect::<Vec<_>>(), vec!["register"]);
    let refused: i64 = sqlx::query_scalar("SELECT count(*) FROM isoloir_refused WHERE received IS NOT NULL").fetch_one(&store.pool).await.unwrap();
    assert_eq!(refused, 2);
    assert_eq!(store.refused_body(&dup.id).await.unwrap(), Some(Some(dup.content.as_bytes().to_vec())));
    // The same event again: the same ack, from the store.
    ingest.handle(Incoming { origin: "wss://b.test".into(), event: junk.clone() }, now + 40).await.unwrap();
    assert_eq!(mem.ack_of(&junk.id).reason, Some(isoloir_proto::Reason::Malformed));
    // Past 30 days, purged.
    assert_eq!(store.purge_refused((now + 1) as i64).await.unwrap(), 2);
}

/// The envelope's proof of work and the queue's order (fresh identifiers
/// first).
#[tokio::test(flavor = "multi_thread")]
async fn pow_and_queue() {
    use isoloir_server::ingest::{pow_solve, POW_PAST};
    let bits = 8;
    let (_store, mut ingest, mem, _dir, start) = small_ledger(bits, 3600).await;
    let now = start;
    let tag = ingest.tag().to_string();
    let origin = "small.example/isoloir";
    let signed = |body: &[u8], t: u64, bits: u32, sk: [u8; 32]| {
        let pk = hex::encode(isoloir_proto::sig::xonly(&sk));
        let nonce = pow_solve(origin, &pk, t, bits);
        Event::sign(&sk, t.max(1_800_000_000), kinds::REGISTER, vec![vec!["t".into(), tag.clone()], vec!["pow".into(), t.to_string(), nonce]], String::from_utf8(body.to_vec()).unwrap())
    };
    let mut rng = rand::rngs::StdRng::seed_from_u64(71);
    let t0 = now;
    let body = |uid: &str, rng: &mut rand::rngs::StdRng| client::register_body(1, &grumpkin::random_fr(rng), uid, json!({"uid": uid}), t0, &rand::random());
    let answered = |id: &str| mem.posted.lock().unwrap().iter().any(|(_, e)| e.tag("e") == Some(id));
    // No work, too little, too old: dropped unanswered.
    let none = event(kinds::REGISTER, &tag, &body("a", &mut rng), now);
    let weak = loop {
        let e = signed(&body("a", &mut rng), now, 0, rand::random());
        if isoloir_server::ingest::pow_check(origin, &e, bits, now).is_none() {
            break e;
        }
    };
    let old = signed(&body("a", &mut rng), now - POW_PAST - 10, bits, rand::random());
    for e in [&none, &weak, &old] {
        ingest.handle(Incoming { origin: "wss://a.test".into(), event: e.clone() }, now).await.unwrap();
        ingest.drain(now).await.unwrap();
        assert!(!answered(&e.id), "{}", e.id);
    }
    // One key, one body.
    let sk: [u8; 32] = rand::random();
    let first = signed(&body("k", &mut rng), now, bits, sk);
    let second = signed(&body("l", &mut rng), now, bits, sk);
    for e in [&first, &second] {
        ingest.handle(Incoming { origin: "wss://a.test".into(), event: e.clone() }, now).await.unwrap();
    }
    ingest.drain(now).await.unwrap();
    assert_eq!(mem.ack_of(&first.id).outcome, Outcome::Accepted);
    assert!(!answered(&second.id));

    // The queue: a uid claimed before (by a message refused at once, a
    // stale proof date) waits behind a fresh one.
    let stale = signed(&client::register_body(1, &grumpkin::random_fr(&mut rng), "z", json!({"uid": "z"}), now - 86_400, &rand::random()), now, bits, rand::random());
    ingest.handle(Incoming { origin: "wss://a.test".into(), event: stale.clone() }, now).await.unwrap();
    assert_eq!(mem.ack_of(&stale.id).reason, Some(isoloir_proto::Reason::StaleDate));
    let again = signed(&body("z", &mut rng), now, bits, rand::random());
    let fresh = signed(&body("m", &mut rng), now, bits, rand::random());
    ingest.handle(Incoming { origin: "wss://a.test".into(), event: again.clone() }, now).await.unwrap();
    ingest.handle(Incoming { origin: "wss://a.test".into(), event: fresh.clone() }, now).await.unwrap();
    assert!(!answered(&again.id) && !answered(&fresh.id), "both wait for the proof check");
    ingest.work(now).await.unwrap();
    assert!(answered(&fresh.id) && !answered(&again.id), "the fresh uid first");
    ingest.drain(now).await.unwrap();
    assert_eq!(mem.ack_of(&again.id).outcome, Outcome::Accepted);
    let now = now + 30;
    ingest.tick(now).await.unwrap().unwrap();
    assert_eq!(ingest.state.registries[&1].tree.len(), 3);
    // A cheap refusal is answered without waiting for the queue.
    let used = signed(&client::register_body(1, &grumpkin::random_fr(&mut rng), "m", json!({"uid": "m"}), now, &rand::random()), now, bits, rand::random());
    ingest.handle(Incoming { origin: "wss://a.test".into(), event: used.clone() }, now).await.unwrap();
    assert!(!ingest.has_work());
    assert_eq!(mem.ack_of(&used.id).reason, Some(isoloir_proto::Reason::UidUsed));
}

/// A small dev ledger (pow bits, revote gap) with its registry.
async fn small_ledger(pow: u32, revote_gap: u64) -> (Store, Ingest, Arc<Mem>, tempfile::TempDir, u64) {
    small_ledger_with(pow, revote_gap, None).await
}

async fn small_ledger_with(pow: u32, revote_gap: u64, proofs: Option<Box<dyn isoloir_proto::judge::Proofs + Send + Sync>>) -> (Store, Ingest, Arc<Mem>, tempfile::TempDir, u64) {
    let url = fresh_db().await;
    let store = Store::connect(&url).await.unwrap();
    let config = Config { log_seed: [15u8; 32], nostr_sk: [16u8; 32] };
    let origin = "small.example/isoloir";
    let signer = note::Signer::new(origin, &config.log_seed);
    let mut now = 1_800_000_000u64;
    let ledger = LedgerSetup {
        v: 1,
        version: 1,
        origin: origin.into(),
        log_key: signer.verifier(),
        ingest: hex::encode(isoloir_proto::sig::xonly(&config.nostr_sk)),
        channels: vec![Channel::Nostr { url: "wss://a.test".into(), state: ChannelState::Active }],
        checkpoint_period: 20,
        anchor_age: 86_400,
        revote_gap,
        pow,
    };
    Ingest::genesis(&store, &config, &ledger, now).await.unwrap();
    let tools = Tools::find().expect("bb");
    let mirror_dir = tempfile::tempdir().unwrap();
    let mem = Arc::new(Mem::default());
    let mut ingest = Ingest::load(
        store.clone(),
        config,
        mem.clone(),
        proofs.unwrap_or_else(|| Box::new(BbProofs::new(tools.bb.clone(), std::env::temp_dir()))),
        Box::new(Verifiers { zkpassport: None, rpc_url: None, allow_dev: true }),
        None,
        Some(Mirror::new(mirror_dir.path().to_path_buf(), None)),
    )
    .await
    .unwrap();
    let registry = RegistrySetup {
        v: 1,
        id: 1,
        version: 1,
        name: "test".into(),
        eligibility: Eligibility { provider: "dev".into(), domain: "d".into(), scope: "s".into(), min_age: None, nationality: vec![], document_type: None, require_expiry: false, oprf_key: None },
        validity: 3600,
        depth: 20,
    };
    store.submit(EntryKind::Registry, &Body::Registry(registry).encode(), now).await.unwrap();
    now += 30;
    ingest.tick(now).await.unwrap().unwrap();
    (store, ingest, mem, mirror_dir, now)
}

/// Rows written before the compact form (migration 0003) are read as they
/// are: a log body unpacked, a JSONB ack.
#[tokio::test(flavor = "multi_thread")]
async fn earlier_rows_are_read() {
    let url = fresh_db().await;
    let store = Store::connect(&url).await.unwrap();
    let body = br#"{"v":1,"x":"0x00ff"}"#.to_vec();
    sqlx::query("INSERT INTO isoloir_log (seq, kind, body, hash, checkpoint) VALUES (0, 'ledger', $1, 'h', 1)").bind(&body).execute(&store.pool).await.unwrap();
    let ack = json!({"id": "ab".repeat(32), "content": "{}"});
    sqlx::query("INSERT INTO isoloir_seen (event_id, relay, ack) VALUES ('e1', 'wss://a', $1)").bind(&ack).execute(&store.pool).await.unwrap();
    assert_eq!(store.entries().await.unwrap()[0].2, body);
    assert_eq!(store.seen("e1").await.unwrap().unwrap().1, ack);
    // And the new rows, packed, read back the same.
    store.seen_only("e2", "wss://a", &ack).await.unwrap();
    assert_eq!(store.seen("e2").await.unwrap().unwrap().1, ack);
    assert_eq!(store.unposted().await.unwrap().len(), 2);
}

/// Migration 0003 on a database written by the code before it: logged
/// submissions and refusals logged on their own lose their copy of a log
/// body, everything else stays.
#[tokio::test(flavor = "multi_thread")]
async fn compact_migration_on_earlier_rows() {
    let url = fresh_db().await;
    let pool = sqlx::PgPool::connect(&url).await.unwrap();
    let mut before = sqlx::migrate!("./migrations");
    before.migrations = std::borrow::Cow::Owned(before.migrations.iter().filter(|m| m.version < 3).cloned().collect());
    before.run(&pool).await.unwrap();
    sqlx::query("INSERT INTO isoloir_submissions (kind, body, submitted, status) VALUES ('poll', 'a', 1, 'logged'), ('poll', 'b', 1, 'pending')").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO isoloir_refused (event_id, checkpoint, entry, listed, body) VALUES ('x', 1, 'r1', true, 'junk'), ('y', 1, 'r2', false, 'junk')").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO isoloir_log (seq, kind, body, hash, checkpoint) VALUES (0, 'ledger', '{\"v\":1}', 'h', 1)").execute(&pool).await.unwrap();
    let store = Store::connect(&url).await.unwrap();
    let subs: Vec<Option<Vec<u8>>> = sqlx::query_scalar("SELECT body FROM isoloir_submissions ORDER BY id").fetch_all(&store.pool).await.unwrap();
    assert_eq!(subs, vec![None, Some(b"b".to_vec())]);
    assert_eq!(store.submissions().await.unwrap().len(), 1);
    assert_eq!(store.summed(1).await.unwrap(), vec![b"r2".to_vec()]);
    assert_eq!(store.refused_body("x").await.unwrap(), Some(Some(b"junk".to_vec())));
    assert_eq!(store.entries().await.unwrap()[0].2, b"{\"v\":1}".to_vec());
}

struct Yes;
impl isoloir_proto::judge::Proofs for Yes {
    fn verify(&self, _: &CircuitRef, _: &[u8], _: &[[u8; 32]]) -> Result<bool, String> {
        Ok(true)
    }
}

/// The re-vote rate (SPEC §7.4): a second ballot of a pseudonym is
/// too_soon while the first is pending or logged less than the gap ago;
/// the audit replays the log without a problem.
#[tokio::test(flavor = "multi_thread")]
async fn revote_gap() {
    let gap = 3600;
    let (store, mut ingest, mem, _dir, start) = small_ledger_with(0, gap, Some(Box::new(Yes))).await;
    let mut now = start;
    let tag = ingest.tag().to_string();
    let mut rng = rand::rngs::StdRng::seed_from_u64(81);
    let s = grumpkin::random_fr(&mut rng);
    let reg = event(kinds::REGISTER, &tag, &client::register_body(1, &s, "v", json!({"uid": "v"}), now, &[0x61; 32]), now);
    ingest.handle(Incoming { origin: "wss://a.test".into(), event: reg }, now).await.unwrap();
    ingest.drain(now).await.unwrap();
    now += 30;
    ingest.tick(now).await.unwrap().unwrap();
    let keys = AuthorityKeys::generate(&mut rng);
    let poll = PollSetup {
        v: 1,
        id: 5,
        version: 1,
        registry: 1,
        title: "t".into(),
        kind: KindSpec::Choice { options: vec!["a".into(), "b".into()], blank: true },
        encryption: Encryption::Elgamal { pk: keys.pk.clone(), authority: Authority::Single { sign_key: keys.sign_key.clone() } },
        publish: Publish::Open { k_real: 1, min_gap: 0, coin: false },
        revote: Revote::Linked,
        opens: now,
        closes: now + 86_400,
        blackouts: vec![],
        circuit: CircuitRef { name: "choice4_single_linked_d20".into(), vk_hash: format!("0x{}", "11".repeat(32)) },
        ballot_depth: None,
    };
    store.submit(EntryKind::Poll, &Body::Poll(poll.clone()).encode(), now).await.unwrap();
    now += 30;
    ingest.tick(now).await.unwrap().unwrap();
    let setup_seq = ingest.state.polls[&5].setups[0].0;
    let variant = Variant::parse(&poll.circuit.name).unwrap();
    let ballot = |ingest: &Ingest, seq: u32, rng: &mut rand::rngs::StdRng, now: u64| {
        let reg = &ingest.state.registries[&1];
        let index = reg.ids[&field::to_hex(&client::leaf(1, &s))];
        let m = Member { root: reg.tree.root(), path: reg.tree.path(index as usize).unwrap(), index };
        let d = client::draft(&poll, setup_seq, &variant, &m, &s, &Choice::Pick(Some(seq % 2)), &Revoting::Linked { seq }, None, rng).unwrap();
        event(kinds::BALLOT, &tag, &d.finish(&[7u8; 64]), now)
    };
    let post = async |ingest: &mut Ingest, ev: &Event, now: u64| {
        ingest.handle(Incoming { origin: "wss://a.test".into(), event: ev.clone() }, now).await.unwrap();
        ingest.drain(now).await.unwrap();
        mem.ack_of(&ev.id)
    };
    let b0 = ballot(&ingest, 0, &mut rng, now);
    assert_eq!(post(&mut ingest, &b0, now).await.outcome, Outcome::Accepted);
    let b1 = ballot(&ingest, 1, &mut rng, now);
    assert_eq!(post(&mut ingest, &b1, now).await.reason, Some(isoloir_proto::Reason::TooSoon), "the first is pending");
    now += 30;
    ingest.tick(now).await.unwrap().unwrap();
    let logged_at = now;
    let b1 = ballot(&ingest, 1, &mut rng, now + 600);
    assert_eq!(post(&mut ingest, &b1, now + 600).await.reason, Some(isoloir_proto::Reason::TooSoon), "logged 10 minutes ago");
    now = logged_at + gap;
    let b1 = ballot(&ingest, 1, &mut rng, now);
    assert_eq!(post(&mut ingest, &b1, now).await.outcome, Outcome::Accepted, "a gap later");
    now += 30;
    ingest.tick(now).await.unwrap().unwrap();
    assert_eq!(ingest.state.polls[&5].ballots.len(), 2);

    let signer = note::Signer::new("small.example/isoloir", &[15u8; 32]);
    let passports = Verifiers { zkpassport: None, rpc_url: None, allow_dev: true };
    let mut a = Auditor::new(Some(&signer.verifier()), Checkers { proofs: &Yes, passports: &passports, tlock: None }).unwrap();
    for (n, es) in LogSource::from(&store, 1).await.unwrap() {
        a.checkpoint(&n, &es).unwrap();
    }
    let (_, report) = a.finish();
    assert!(report.problems.is_empty(), "{:#?}", report.problems);
    assert_eq!(report.ballots, 2);
}
