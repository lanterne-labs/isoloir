//! The ingest's storage per ballot (ignored: a measure, not a check). Runs
//! a dev ledger on a fresh database (ISOLOIR_TEST_DATABASE): N voters
//! register and vote on a ranked poll shaped like the presidential one
//! (rankedm12, 7 options and the blank, margins), a fifth vote again;
//! proofs are random bytes of a real proof's size, accepted by a stub
//! verifier. Prints each table's pg_total_relation_size per ballot.
//!
//!     ISOLOIR_STORAGE_VOTERS=3000 cargo test -p isoloir-server --test storage -- --ignored --nocapture

use isoloir_core::{field, grumpkin, Fr};
use isoloir_decrypt::keys::AuthorityKeys;
use isoloir_proto::body::*;
use isoloir_proto::client::{self, Member, Revoting};
use isoloir_proto::judge::Proofs;
use isoloir_proto::kinds::{Choice, Variant};
use isoloir_proto::note;
use isoloir_proto::sig::Event;
use isoloir_server::eligibility::Verifiers;
use isoloir_server::ingest::{kinds, Config, Incoming, Ingest, Transport};
use isoloir_server::store::Store;
use rand::{Rng, SeedableRng};
use serde_json::json;
use sqlx::Row;
use std::sync::Arc;

struct Quiet;
#[async_trait::async_trait]
impl Transport for Quiet {
    async fn publish(&self, _: &str, _: &Event) -> Result<(), String> {
        Ok(())
    }
    async fn publish_all(&self, _: &Event) {}
}

struct Yes;
impl Proofs for Yes {
    fn verify(&self, _: &CircuitRef, _: &[u8], _: &[[u8; 32]]) -> Result<bool, String> {
        Ok(true)
    }
}

/// The size of a rankedm12 UltraHonk proof (458 fields).
const PROOF: usize = 14_656;

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn storage_per_ballot() {
    let voters: usize = std::env::var("ISOLOIR_STORAGE_VOTERS").ok().and_then(|n| n.parse().ok()).unwrap_or(3000);
    let server = std::env::var("ISOLOIR_TEST_DATABASE").unwrap_or_else(|_| "postgresql://postgres@127.0.0.1:55433".into());
    let name = format!("isoloir_storage_{}", rand::random::<u32>());
    let admin = sqlx::PgPool::connect(&format!("{server}/postgres")).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {name}")).execute(&admin).await.unwrap();
    let store = Store::connect(&format!("{server}/{name}")).await.unwrap();
    let config = Config { log_seed: [21u8; 32], nostr_sk: [22u8; 32] };
    let origin = "storage.example/isoloir";
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
        anchor_age: 86_400 * 30,
        revote_gap: 0,
        pow: 0,
    };
    Ingest::genesis(&store, &config, &ledger, now).await.unwrap();
    let mut ingest = Ingest::load(store.clone(), config, Arc::new(Quiet), Box::new(Yes), Box::new(Verifiers { zkpassport: None, rpc_url: None, allow_dev: true }), None, None).await.unwrap();
    let tag = ingest.tag().to_string();
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
    let mut rng = rand::rngs::StdRng::seed_from_u64(61);
    let post = |kind: u32, body: Vec<u8>, now: u64| {
        let sk: [u8; 32] = rand::random();
        Incoming { origin: "wss://a.test".into(), event: Event::sign(&sk, now, kind, vec![vec!["t".into(), tag.clone()]], String::from_utf8(body).unwrap()) }
    };
    let secrets: Vec<Fr> = (0..voters).map(|_| grumpkin::random_fr(&mut rng)).collect();
    for (i, s) in secrets.iter().enumerate() {
        let b = client::register_body(1, s, &format!("p{i}"), json!({"uid": format!("p{i}")}), now, &rand::random());
        ingest.handle(post(kinds::REGISTER, b, now), now).await.unwrap();
        ingest.drain(now).await.unwrap();
        if i % 500 == 499 {
            now += 30;
            ingest.tick(now).await.unwrap();
        }
    }
    now += 30;
    ingest.tick(now).await.unwrap();

    let keys = AuthorityKeys::generate(&mut rng);
    let poll = PollSetup {
        v: 1,
        id: 5,
        version: 1,
        registry: 1,
        title: "Test".into(),
        kind: KindSpec::Ranked { options: (1..=7).map(|i| format!("Candidate {i}")).collect(), blank: true, depth: 3, margins: true },
        encryption: Encryption::Elgamal { pk: keys.pk.clone(), authority: Authority::Single { sign_key: keys.sign_key.clone() } },
        publish: Publish::Open { k_real: 1, min_gap: 0, coin: false },
        revote: Revote::Linked,
        opens: now,
        closes: now + 86_400 * 30,
        blackouts: vec![],
        circuit: CircuitRef { name: "rankedm12_single_linked_d20".into(), vk_hash: format!("0x{}", "11".repeat(32)) },
        ballot_depth: None,
    };
    store.submit(EntryKind::Poll, &Body::Poll(poll.clone()).encode(), now).await.unwrap();
    now += 30;
    ingest.tick(now).await.unwrap().unwrap();
    let setup_seq = ingest.state.polls[&5].setups[0].0;
    let variant = Variant::parse(&poll.circuit.name).unwrap();
    let mut ballots = 0;
    for round in 0..2u32 {
        for (i, s) in secrets.iter().enumerate() {
            if round == 1 && i % 5 != 0 {
                continue;
            }
            let reg = &ingest.state.registries[&1];
            let index = reg.ids[&field::to_hex(&client::leaf(1, s))];
            let m = Member { root: reg.tree.root(), path: reg.tree.path(index as usize).unwrap(), index };
            let pick: Vec<u32> = vec![rng.gen_range(0..4), rng.gen_range(4..6), 6];
            let d = client::draft(&poll, setup_seq, &variant, &m, s, &Choice::Rank(pick), &Revoting::Linked { seq: round }, None, &mut rng).unwrap();
            let proof: Vec<u8> = (0..PROOF).map(|_| rng.r#gen()).collect();
            ingest.handle(post(kinds::BALLOT, d.finish(&proof), now), now).await.unwrap();
            ingest.drain(now).await.unwrap();
            ballots += 1;
            if ballots % 500 == 0 {
                now += 30;
                ingest.tick(now).await.unwrap();
            }
        }
        now += 30;
        ingest.tick(now).await.unwrap();
    }
    assert_eq!(ingest.state.polls[&5].ballots.len(), ballots, "every ballot logged");
    sqlx::query("VACUUM ANALYZE").execute(&store.pool).await.unwrap();
    let rows = sqlx::query("SELECT relname::text AS t, pg_total_relation_size(c.oid) AS n FROM pg_class c JOIN pg_namespace s ON s.oid = c.relnamespace WHERE s.nspname = 'public' AND c.relkind = 'r' ORDER BY n DESC")
        .fetch_all(&store.pool)
        .await
        .unwrap();
    let total: i64 = rows.iter().map(|r| r.get::<i64, _>("n")).sum();
    println!("{voters} voters, {ballots} ballots, database {name}");
    for r in &rows {
        let n: i64 = r.get("n");
        println!("{:<24} {:>12} B  {:>8.0} B/ballot", r.get::<String, _>("t"), n, n as f64 / ballots as f64);
    }
    println!("{:<24} {:>12} B  {:>8.0} B/ballot", "total", total, total as f64 / ballots as f64);
    let body: i64 = sqlx::query_scalar("SELECT COALESCE(SUM(octet_length(body)), 0)::bigint FROM isoloir_log WHERE kind = 'ballot'").fetch_one(&store.pool).await.unwrap();
    println!("ballot bodies as stored: {:.0} B each", body as f64 / ballots as f64);
}
