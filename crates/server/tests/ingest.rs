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
        let (_, ev) = p.iter().rev().find(|(_, e)| e.kind == kinds::ACK && e.tag("e") == Some(id)).expect("an ack");
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
        assert_eq!(mem.ack_of(&ev.id).outcome, Outcome::Accepted);
        assert_eq!(mem.ack_of(&ev.id).checkpoint, Some(3));
        reg_events.push(ev);
    }
    let dup = client::register_body(1, &grumpkin::random_fr(&mut rng), "p0", json!({"uid": "p0"}), now, &[0x30; 32]);
    let dup_ev = event(kinds::REGISTER, &tag, &dup, now);
    ingest.handle(Incoming { origin: "wss://a.test".into(), event: dup_ev.clone() }, now).await.unwrap();
    assert_eq!(mem.ack_of(&dup_ev.id).reason, Some(isoloir_proto::Reason::UidUsed));
    // A crash before the checkpoint: the accepted messages are not lost.
    drop(ingest);
    let mut ingest = load(store.clone(), mem.clone()).await.unwrap();
    // The same event again: the same ack, nothing new.
    let n = mem.posted.lock().unwrap().len();
    ingest.handle(Incoming { origin: "wss://b.test".into(), event: reg_events[0].clone() }, now).await.unwrap();
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
    assert_eq!(report.rejects, 1);
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

    // Withholding: what the relays hold against the log.
    let mut events: Vec<Event> = mem.posted.lock().unwrap().iter().map(|(_, e)| e.clone()).collect();
    events.extend(reg_events.iter().cloned());
    events.push(dup_ev.clone());
    let ingest_pk = hex::encode(isoloir_proto::sig::xonly(&[12u8; 32]));
    assert!(isoloir_proto::audit::check_relays(&state, &events, &ingest_pk, 0).is_empty());
    // An accepted message the ingest never logged.
    let lost = event(kinds::BALLOT, &tag, b"{\"v\":1}", now - 200);
    let ack = Ack { v: 1, of: lost.id.clone(), hash: isoloir_core::encoding::body_hash(lost.content.as_bytes()), outcome: Outcome::Accepted, reason: None, checkpoint: Some(3) };
    let ack_ev = Event::sign(&[12u8; 32], now - 200, kinds::ACK, vec![vec!["t".into(), tag.clone()], vec!["e".into(), lost.id.clone()]], canonical::to_string(&ack).unwrap());
    events.push(lost);
    events.push(ack_ev);
    let problems = isoloir_proto::audit::check_relays(&state, &events, &ingest_pk, 0);
    assert_eq!(problems.len(), 2, "{problems:?}");
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

/// Junk refused in bulk: no body in the log, at most REJECTS_LOGGED
/// refusals of their own per checkpoint and one `rejects` entry for the
/// rest, the bodies and the list in the store and served; the audit reads
/// the new form, with and without the copies.
#[tokio::test(flavor = "multi_thread")]
async fn refusals_are_bounded() {
    use isoloir_server::direct;
    use isoloir_server::source::Refusals;
    let url = fresh_db().await;
    let store = Store::connect(&url).await.unwrap();
    let config = Config { log_seed: [15u8; 32], nostr_sk: [16u8; 32] };
    let origin = "junk.example/isoloir";
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
    };
    Ingest::genesis(&store, &config, &ledger, now).await.unwrap();
    let tools = Tools::find().expect("bb");
    let mirror_dir = tempfile::tempdir().unwrap();
    let mem = Arc::new(Mem::default());
    let mut ingest = Ingest::load(
        store.clone(),
        config,
        mem.clone(),
        Box::new(BbProofs::new(tools.bb.clone(), std::env::temp_dir())),
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
    let tag = ingest.tag().to_string();

    // A registration, its second try under another key (uid_used), and junk.
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let ok = event(kinds::REGISTER, &tag, &client::register_body(1, &grumpkin::random_fr(&mut rng), "bob", json!({"uid": "bob"}), now, &[0x51; 32]), now);
    let dup = event(kinds::REGISTER, &tag, &client::register_body(1, &grumpkin::random_fr(&mut rng), "bob", json!({"uid": "bob"}), now, &[0x52; 32]), now);
    let mut posted = vec![ok.clone(), dup.clone()];
    let junk = REJECTS_LOGGED + 24;
    for i in 0..junk {
        let body = if i == 0 { vec![b'x'; MAX_BODY + 1] } else { format!("junk {i}").into_bytes() };
        posted.push(event(if i % 2 == 0 { kinds::REGISTER } else { kinds::BALLOT }, &tag, &body, now));
    }
    for ev in &posted {
        ingest.handle(Incoming { origin: "wss://a.test".into(), event: ev.clone() }, now).await.unwrap();
    }
    assert_eq!(mem.ack_of(&dup.id).reason, Some(isoloir_proto::Reason::UidUsed));
    now += 30;
    let cp = ingest.tick(now).await.unwrap().unwrap();

    // The log: REJECTS_LOGGED refusals of their own, the dup among them
    // (arrival order), one summary for the rest; no body anywhere.
    let entries: serde_json::Value = serde_json::from_slice(&std::fs::read(mirror_dir.path().join(format!("entries/{cp}.json"))).unwrap()).unwrap();
    let kinds_of = |k: &str| entries.as_array().unwrap().iter().filter(|e| e["kind"] == k).count();
    assert_eq!(kinds_of("reject"), REJECTS_LOGGED);
    assert_eq!(kinds_of("rejects"), 1);
    assert_eq!(kinds_of("register"), 1);
    assert!(!entries.to_string().contains("\\\"raw\\\""), "a reject carries a body");
    let rejects: Vec<Reject> = entries.as_array().unwrap().iter().filter(|e| e["kind"] == "reject").map(|e| canonical::from_slice(e["body"].as_str().unwrap().as_bytes()).unwrap()).collect();
    let d = rejects.iter().find(|r| r.of == dup.id).expect("the dup is logged on its own");
    assert_eq!((d.author.as_deref(), d.size), (Some(dup.pubkey.as_str()), Some(dup.content.len() as u64)));
    assert_eq!(d.hash, isoloir_core::encoding::body_hash(dup.content.as_bytes()));
    let sum = entries.as_array().unwrap().iter().find(|e| e["kind"] == "rejects").unwrap();
    let sum: Rejects = canonical::from_slice(sum["body"].as_str().unwrap().as_bytes()).unwrap();
    let summed = junk + 1 - REJECTS_LOGGED;
    assert_eq!(sum.count, summed as u64);
    let list = store.summed(cp).await.unwrap();
    assert_eq!(list.len(), summed);
    assert_eq!(rejects_root(&list), sum.root);
    // The oversized body is not kept; the others are.
    assert_eq!(store.refused_body(&posted[2].id).await.unwrap(), Some(None));
    assert_eq!(store.refused_body(&posted[3].id).await.unwrap(), Some(Some(posted[3].content.as_bytes().to_vec())));
    assert_eq!(store.refused_body(&ok.id).await.unwrap(), None);

    // Served over HTTP.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = direct::health_router(store.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let got = reqwest::get(format!("{base}/v1/refused/{}", dup.id)).await.unwrap();
    assert_eq!(got.bytes().await.unwrap().as_ref(), dup.content.as_bytes());
    assert_eq!(reqwest::get(format!("{base}/v1/refused/{}", posted[2].id)).await.unwrap().status(), 410);
    assert_eq!(reqwest::get(format!("{base}/v1/refused/{}", ok.id)).await.unwrap().status(), 404);

    // The audit from the mirror alone: nothing wrong, nothing judged again
    // for lack of bodies, said as warnings.
    let src = MirrorSource::parse(mirror_dir.path().to_str().unwrap());
    let read = src.from(1).await.unwrap();
    let proofs = BbProofs::new(tools.bb.clone(), std::env::temp_dir());
    let passports = Verifiers { zkpassport: None, rpc_url: None, allow_dev: true };
    let audit = |r: &mut Refusals| {
        let mut a = Auditor::new(Some(&signer.verifier()), Checkers { proofs: &proofs, passports: &passports, tlock: None }).unwrap();
        a.copies = r.copies.clone();
        a.lists = r.lists.clone();
        for (n, es) in &read {
            a.checkpoint(n, es).unwrap();
        }
        a.finish()
    };
    let ingest_pk = hex::encode(isoloir_proto::sig::xonly(&[16u8; 32]));
    let (state, report) = audit(&mut Refusals::default());
    assert!(report.problems.is_empty(), "{:#?}", report.problems);
    assert_eq!((report.rejects, report.unjudged, report.unlisted, report.summarized), (REJECTS_LOGGED as u64, REJECTS_LOGGED as u64, summed as u64, summed as u64));
    assert_eq!(report.warnings.len(), 2, "{:#?}", report.warnings);
    // The relays' copies of the summed refusals cannot be told from
    // withheld messages without the list: warnings, not problems.
    let (problems, warnings) = isoloir_proto::audit::check_relays_report(&state, &posted, &ingest_pk, 0);
    assert!(problems.is_empty(), "{problems:?}");
    assert_eq!(warnings.len(), 1);

    // With the relays' copies and the ingest's list: every refusal judged.
    let mut r = Refusals::default();
    r.add_events(&posted[..3]);
    r.ask_ledger(&base, &read).await;
    assert!(r.warnings.is_empty(), "{:?}", r.warnings);
    let (state, report) = audit(&mut r);
    assert!(report.problems.is_empty(), "{:#?}", report.problems);
    assert_eq!((report.rejects, report.unjudged, report.unlisted), ((junk + 1) as u64, 0, 0));
    let (problems, warnings) = isoloir_proto::audit::check_relays_report(&state, &posted, &ingest_pk, 0);
    assert!(problems.is_empty() && warnings.is_empty(), "{problems:?} {warnings:?}");

    // A copy that is not the refused body, a list that is not the logged
    // one: problems.
    let mut bad = Refusals::default();
    bad.copies.insert(dup.id.clone(), isoloir_proto::audit::Copy { author: None, body: b"other".to_vec() });
    bad.lists.insert(cp, list[1..].to_vec());
    let (_, report) = audit(&mut bad);
    assert!(report.problems.iter().any(|p| p.contains("not its hash")), "{:#?}", report.problems);
    assert!(report.problems.iter().any(|p| p.contains("not the one the log names")), "{:#?}", report.problems);
}
