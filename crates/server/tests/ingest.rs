//! The ingest end to end on Postgres (ISOLOIR_TEST_DATABASE, a server URL
//! without a database name: a fresh database is made per run), an
//! in-memory relay transport and real proofs.

use isoloir_core::grumpkin::{self, Projective};
use isoloir_core::{canonical, field, Fr};
use isoloir_decrypt::keys::DecrypterKeys;
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
use isoloir_server::trustee::{Keys, Output, Trustee};
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
    let name = "choice4_elgamal_linked_d20";
    let built = circuits.build(&tools, name).unwrap();
    let mirror_dir = tempfile::tempdir().unwrap();
    let mirror = Mirror { dir: mirror_dir.path().to_path_buf(), git: None };
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
        relays: vec![Relay { url: "wss://a.test".into(), state: RelayState::Active }],
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
        let mirror = Mirror { dir: mirror_dir.path().to_path_buf(), git: None };
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
        eligibility: Eligibility { provider: "dev".into(), domain: "test.example".into(), scope: "t".into(), min_age: None, nationality: vec![], document_type: None, require_expiry: false },
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
        ingest.handle(Incoming { relay: "wss://a.test".into(), event: ev.clone() }, now).await.unwrap();
        assert_eq!(mem.ack_of(&ev.id).outcome, Outcome::Accepted);
        assert_eq!(mem.ack_of(&ev.id).checkpoint, Some(3));
        reg_events.push(ev);
    }
    let dup = client::register_body(1, &grumpkin::random_fr(&mut rng), "p0", json!({"uid": "p0"}), now, &[0x30; 32]);
    let dup_ev = event(kinds::REGISTER, &tag, &dup, now);
    ingest.handle(Incoming { relay: "wss://a.test".into(), event: dup_ev.clone() }, now).await.unwrap();
    assert_eq!(mem.ack_of(&dup_ev.id).reason, Some(isoloir_proto::Reason::UidUsed));
    // A crash before the checkpoint: the accepted messages are not lost.
    drop(ingest);
    let mut ingest = load(store.clone(), mem.clone()).await.unwrap();
    // The same event again: the same ack, nothing new.
    let n = mem.posted.lock().unwrap().len();
    ingest.handle(Incoming { relay: "wss://b.test".into(), event: reg_events[0].clone() }, now).await.unwrap();
    assert_eq!(mem.posted.lock().unwrap().len(), n + 1);
    assert_eq!(mem.ack_of(&reg_events[0].id).checkpoint, Some(3));
    now += 30;
    assert_eq!(ingest.tick(now).await.unwrap(), Some(3));
    assert_eq!(ingest.state.registries[&1].tree.len(), 2);

    // The poll, with a single decrypter.
    let keys = DecrypterKeys::generate(&mut rng);
    let poll = PollSetup {
        v: 1,
        id: 5,
        version: 1,
        registry: 1,
        title: "Oui ou non ?".into(),
        kind: KindSpec::Choice { options: vec!["Oui".into(), "Non".into()], blank: true },
        encryption: Encryption::Elgamal { pk: keys.pk.clone(), decrypter: Decrypter::Single { sign_key: keys.sign_key.clone() } },
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
        ingest.handle(Incoming { relay: "wss://a.test".into(), event: ev.clone() }, now).await.unwrap();
        assert_eq!(mem.ack_of(&ev.id).outcome, Outcome::Accepted, "{:?}", mem.ack_of(&ev.id));
    }
    now += 30;
    let cp = ingest.tick(now).await.unwrap().unwrap();

    // The trustee: reads the database, verifies, decrypts, submits.
    let (sk, seed) = keys.secrets().unwrap();
    let mut trustee = Trustee::new(
        Box::new(store.clone()),
        Some(&signer.verifier()),
        Box::new(BbProofs::new(tools.bb.clone(), vk_dir.clone())),
        Box::new(Verifiers { zkpassport: None, rpc_url: None, allow_dev: true }),
        Some(Keys { pk: keys.pk.clone(), sk, sign_seed: seed }),
        None,
        Output::Store(store.clone()),
    )
    .unwrap();
    assert_eq!(trustee.step(now).await.unwrap(), 1);
    assert_eq!(trustee.step(now).await.unwrap(), 0, "published once");
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
    isoloir_proto::tally::verify_shares(&poll.encryption, &body, latest["body"].as_str().unwrap().as_bytes(), variant.values(), variant.chunks(), &agg).unwrap();
    let _ = Projective::default();
}
