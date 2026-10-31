//! Native tests of the exported functions (the same code wasm runs).

use crate::{api, link, words};
use isoloir_decrypt::bls::TestChain;
use isoloir_proto::note::Signer;
use serde_json::{json, Value};

fn v(s: &str) -> Value {
    serde_json::from_str(s).unwrap()
}

const S: &str = "0x0000000000000000000000000000000000000000000000000000000000001234";

fn elgamal_poll(revote: &str, circuit: &str, ballot_depth: Option<u32>) -> (Value, Value) {
    let keys = isoloir_decrypt::keys::DecrypterKeys::generate(&mut <rand_chacha::ChaCha20Rng as rand_core::SeedableRng>::from_seed([9; 32]));
    let mut p = json!({
        "v": 1, "id": 7, "version": 1, "registry": 1, "title": "t",
        "kind": {"type": "choice", "options": ["Oui", "Non"], "blank": true},
        "encryption": {"mode": "elgamal", "pk": keys.pk, "decrypter": {"type": "single", "sign_key": keys.sign_key}},
        "publish": {"mode": "closed"}, "revote": revote, "opens": 0, "closes": 2_000_000_000u64,
        "circuit": {"name": circuit, "vk_hash": format!("0x{}", "0".repeat(64))},
    });
    if let Some(b) = ballot_depth {
        p["ballot_depth"] = json!(b);
    }
    (p, serde_json::to_value(&keys).unwrap())
}

fn member(registry: u32, s: &str) -> Value {
    let me = api::leaf(registry, s).unwrap();
    let leaves = json!([api::leaf(registry, "0x0000000000000000000000000000000000000000000000000000000000000001").unwrap(), me]).to_string();
    let p = v(&api::tree_path(20, &leaves, 1).unwrap());
    json!({"root": p["root"], "path": p["path"], "index": 1})
}

#[test]
fn words_and_prf() {
    let w = words::new_words("en").unwrap();
    assert_eq!(w.split(' ').count(), 12);
    let s1 = words::secret_from_words(&w, "en").unwrap();
    let s2 = words::secret_from_words(&format!("  {}  ", w.to_uppercase()), "english").unwrap();
    assert_eq!(s1, s2);
    assert!(words::secret_from_words("abandon abandon", "en").is_err());
    // The all-zero entropy, a fixed vector of the derivation.
    let zero = words::words_of_entropy(&[0u8; 16], "en").unwrap();
    assert!(zero.starts_with("abandon abandon"));
    assert_eq!(words::secret_from_words(&zero, "en").unwrap(), api::secret_from_entropy(&[0u8; 16]).unwrap());
    let fr = words::new_words("fr").unwrap();
    assert!(words::secret_from_words(&fr, "fr").is_ok());
    let a = api::secret_from_prf(&"11".repeat(32)).unwrap();
    assert_ne!(a, api::secret_from_prf(&"12".repeat(32)).unwrap());
}

#[test]
fn registration() {
    let sk = api::new_reg_secret();
    let pk = api::reg_pubkey(&sk).unwrap();
    assert!(api::registration_binding(1, &pk).unwrap().starts_with("0x"));
    let req = json!({"registry": 1, "s": S, "uid": "u1", "proof": {"a": 1}, "proof_date": 1_761_900_000u64, "reg_secret": sk});
    let body = api::register_body(&req.to_string()).unwrap();
    assert_eq!(api::verify_register(&body).unwrap(), pk);
    assert!(api::decode_body("register", &body).is_ok());
    assert_eq!(v(&body)["id"], json!(api::leaf(1, S).unwrap()));
}

#[test]
fn device_link() {
    let r = v(&link::receiver());
    let sealed = v(&link::seal(r["public"].as_str().unwrap(), r#"{"secret":"x"}"#).unwrap());
    let opened = v(&link::open(r["secret"].as_str().unwrap(), sealed["sealed"].as_str().unwrap()).unwrap());
    assert_eq!(opened["payload"], json!(r#"{"secret":"x"}"#));
    assert_eq!(opened["code"], sealed["code"]);
    assert_eq!(sealed["code"].as_str().unwrap().len(), 6);
    let other = v(&link::receiver());
    assert!(link::open(other["secret"].as_str().unwrap(), sealed["sealed"].as_str().unwrap()).is_err());
}

#[test]
fn relays_and_trees() {
    let urls = json!(["wss://a", "wss://b", "wss://c"]).to_string();
    let r1: Vec<String> = serde_json::from_str(&api::relay_ranking(S, &urls).unwrap()).unwrap();
    let mut sorted = r1.clone();
    sorted.sort();
    assert_eq!(sorted, vec!["wss://a", "wss://b", "wss://c"]);
    assert_eq!(r1, serde_json::from_str::<Vec<String>>(&api::relay_ranking(S, &urls).unwrap()).unwrap());
    let m = member(1, S);
    let root = api::root_of(&api::leaf(1, S).unwrap(), 1, &m["path"].to_string()).unwrap();
    assert_eq!(json!(root), m["root"]);
    assert_eq!(api::tree_root(4, "[]").unwrap(), api::tree_root(4, "[]").unwrap());
}

#[test]
fn notes_and_events() {
    let s = Signer::new("example.org/isoloir", &[7u8; 32]);
    let text = "example.org/isoloir\n3\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nindex 2\ntime 100\nregistry 1 2 0x0000000000000000000000000000000000000000000000000000000000000005\nmirror abc\n";
    let note = s.sign(text);
    let c = v(&api::verify_note(&note, &s.verifier()).unwrap());
    assert_eq!(c["index"], json!(2));
    assert_eq!(c["registries"][0]["size"], json!(2));
    assert_eq!(c["mirror"], json!("abc"));
    let other = Signer::new("example.org/isoloir", &[8u8; 32]);
    assert!(api::verify_note(&note, &other.verifier()).is_err());

    let ingest = "33".repeat(32);
    let ingest_pk = api::reg_pubkey(&ingest).unwrap();
    let ack = r#"{"checkpoint":4,"hash":"0x00","of":"abcd","outcome":"accepted","v":1}"#;
    let e = api::sign_event(&ingest, 100, 7102, r#"[["e","abcd"]]"#, ack).unwrap();
    assert!(api::verify_event(&e));
    assert_eq!(v(&api::read_ack(&e, &ingest_pk).unwrap())["checkpoint"], json!(4));
    assert!(api::read_ack(&e, &api::reg_pubkey(&"44".repeat(32)).unwrap()).is_err());
    let throwaway = v(&api::sign_event("", 100, 7101, r#"[["t","isoloir/1/x"]]"#, "{}").unwrap());
    assert_ne!(throwaway["pubkey"], json!(ingest_pk));
    let c = api::complaint_body(&e, r#"{"a":1}"#).unwrap();
    assert!(c.starts_with(r#"{"ack":{"#) && c.ends_with(r#""body":{"a":1},"v":1}"#));
}

#[test]
fn a_linked_ballot_and_its_tally() {
    let (poll, keys) = elgamal_poll("linked", "choice4_single_linked_d20", None);
    let info = v(&api::kind_info(&poll.to_string()).unwrap());
    assert_eq!(info["slots"], json!(3));
    assert_eq!(info["mask"], json!(7));
    let mut bodies = vec![];
    for (k, pick) in [Some(0u32), Some(0), Some(2)].iter().enumerate() {
        let s = format!("0x{:064x}", 100 + k);
        let req = json!({
            "poll": poll, "setup_seq": 3, "member": member(1, &s), "s": s,
            "choice": {"pick": pick}, "revoting": {"seq": 0}, "seed": "07".repeat(32),
        });
        let d = v(&api::draft_ballot(&req.to_string()).unwrap());
        assert_eq!(d["inputs"]["seq"], json!(0));
        assert_eq!(d["body"]["proof"], json!(""));
        let body = api::finish_ballot(&d["body"].to_string(), b"proof").unwrap();
        assert!(api::decode_body("ballot", &body).is_ok());
        let pi: Vec<String> = serde_json::from_str(&api::public_inputs(&body, &poll.to_string()).unwrap()).unwrap();
        // registry, poll, setup, mask, root, nullifier, seq, pk.x, pk.y, 1 chunk × 4
        // (a single decrypter: seven values per chunk).
        assert_eq!(pi.len(), 4 + 1 + 2 + 2 + 4);
        bodies.push(body);
    }
    // A choice outside the mask is refused.
    let bad = json!({"poll": poll, "setup_seq": 3, "member": member(1, S), "s": S, "choice": {"pick": 3}, "revoting": {"seq": 0}});
    assert!(api::draft_ballot(&bad.to_string()).is_err());

    #[cfg(feature = "dev")]
    {
        let req = json!({
            "poll": poll, "upto": 40, "checkpoint": 5, "final": true, "ballots": bodies,
            "sk": keys["sk"], "sign_seed": keys["sign_seed"], "seed": "05".repeat(32),
        });
        let t = crate::dev::build_tally(&req.to_string()).unwrap();
        let r = v(&api::verify_tally(&poll.to_string(), &t).unwrap());
        assert_eq!(r["ok"], json!(true), "{r}");
        assert_eq!(r["results"]["slots"][0]["count"], json!(2));
        assert_eq!(r["results"]["blank"], json!(1));
        // A forged count fails.
        let forged = t.replacen(r#""values":[2,0,1,0]"#, r#""values":[1,1,1,0]"#, 1);
        assert_ne!(forged, t);
        let r = v(&api::verify_tally(&poll.to_string(), &forged).unwrap());
        assert_eq!(r["ok"], json!(false));
    }
    let _ = (keys, bodies);
}

#[test]
fn a_tlock_ballot() {
    let chain = TestChain::new(3);
    let poll = json!({
        "v": 1, "id": 8, "version": 1, "registry": 1, "title": "t",
        "kind": {"type": "choice", "options": ["Oui", "Non"], "blank": false},
        "encryption": {"mode": "tlock", "chain": "c", "public_key": hex::encode(chain.public_key()), "period": 3, "genesis": 0, "round": 100},
        "publish": {"mode": "closed"}, "revote": "none", "opens": 0, "closes": 2_000_000_000u64,
        "circuit": {"name": "choice4_tlock_linked_d20", "vk_hash": format!("0x{}", "0".repeat(64))},
    });
    let req = json!({"poll": poll, "setup_seq": 3, "member": member(1, S), "s": S, "choice": {"pick": 1}, "revoting": {"seq": 0}});
    let d = v(&api::draft_ballot(&req.to_string()).unwrap());
    let blob = isoloir_core::encoding::unb64(d["body"]["blob"].as_str().unwrap()).unwrap();
    let payload = isoloir_decrypt::tlock::open(&chain.sign(100), &blob).unwrap();
    assert!(String::from_utf8(payload).unwrap().contains(r#""values":[0,1,0,0]"#));
    let req = json!({"poll": poll, "setup_seq": 3, "member": member(1, S), "s": S, "choice": {"pick": 1}, "revoting": {"seq": 1}});
    assert!(api::draft_ballot(&req.to_string()).is_err(), "one ballot per voter");
}

#[test]
fn a_delta_chain_is_recovered() {
    let (poll, _) = elgamal_poll("delta", "choice4_single_delta_d20_b22", Some(22));
    let ps = poll.to_string();
    let empty = api::tree_root(22, "[]").unwrap();
    // Ballot 0: pick 1.
    let r0 = json!({"poll": poll, "setup_seq": 3, "member": member(1, S), "s": S, "choice": {"pick": 1}, "revoting": {"i": 0, "previous": null, "broot": empty}});
    let d0 = v(&api::draft_ballot(&r0.to_string()).unwrap());
    let l0 = api::delta_leaf(d0["body"]["ident"].as_str().unwrap(), d0["body"]["cmt"].as_str().unwrap()).unwrap();
    let other = "0x0000000000000000000000000000000000000000000000000000000000000abc".to_string();
    let leaves = json!([other, l0]).to_string();
    let rec = v(&api::delta_recover(&ps, S, &leaves).unwrap());
    assert_eq!(rec["next"], json!(1));
    assert_eq!(rec["previous"]["choice"], json!({"pick": 1}));
    assert_eq!(rec["previous"]["index"], json!(1));
    // Ballot 1 corrects it to pick 0.
    let bp = v(&api::tree_path(22, &leaves, 1).unwrap());
    let r1 = json!({"poll": poll, "setup_seq": 3, "member": member(1, S), "s": S, "choice": {"pick": 0},
        "revoting": {"i": 1, "previous": {"choice": {"pick": 1}, "path": bp["path"], "index": 1}, "broot": bp["root"]}});
    let d1 = v(&api::draft_ballot(&r1.to_string()).unwrap());
    assert_eq!(d1["inputs"]["i"], json!(1));
    let l1 = api::delta_leaf(d1["body"]["ident"].as_str().unwrap(), d1["body"]["cmt"].as_str().unwrap()).unwrap();
    let rec = v(&api::delta_recover(&ps, S, &json!([other, l0, l1]).to_string()).unwrap());
    assert_eq!(rec["next"], json!(2));
    assert_eq!(rec["previous"]["choice"], json!({"pick": 0}));
    let none = v(&api::delta_recover(&ps, S, "[]").unwrap());
    assert_eq!(none["next"], json!(0));
    assert_eq!(none["previous"], Value::Null);
}

#[test]
fn ranked_results() {
    let poll = json!({
        "v": 1, "id": 9, "version": 1, "registry": 1, "title": "t",
        "kind": {"type": "ranked", "options": ["a", "b"], "blank": true, "depth": 3, "margins": true},
        "encryption": {"mode": "elgamal", "pk": "0x00", "decrypter": {"type": "single", "sign_key": "00"}},
        "publish": {"mode": "closed"}, "revote": "linked", "opens": 0, "closes": 1,
        "circuit": {"name": "rankedm12_single_linked_d20", "vk_hash": "0x00"},
    })
    .to_string();
    let vals: Vec<i64> = serde_json::from_str(&api::choice_values(&poll, r#"{"rank":[1,0]}"#).unwrap()).unwrap();
    let r = v(&api::tally_results(&poll, &serde_json::to_string(&vals).unwrap(), 1).unwrap());
    assert_eq!(r["slots"][1]["first"], json!(1));
    assert_eq!(r["slots"][0]["ranked"], json!(1));
    assert_eq!(r["margins"][1][0], json!(1));
    assert_eq!(r["margins"][0][1], json!(-1));
    assert_eq!(r["condorcet"], json!(1));
}

#[cfg(feature = "dev")]
#[test]
fn logged_entries() {
    let entries = json!([["ledger", "{\"a\":1}"], ["poll", "{\"b\":2}"], ["tally", "{\"c\":3}"]]).to_string();
    for n in 1..=3u32 {
        for i in 0..n {
            let p = v(&crate::dev::log_proof(&entries, i, n).unwrap());
            let kinds = ["ledger", "poll", "tally"];
            let bodies = ["{\"a\":1}", "{\"b\":2}", "{\"c\":3}"];
            let (root, path) = (p["root"].as_str().unwrap(), p["path"].to_string());
            assert!(api::verify_logged(i as u64, kinds[i as usize], bodies[i as usize], &path, n as u64, root).unwrap(), "{i} of {n}");
            assert!(!api::verify_logged(i as u64, kinds[i as usize], "{\"x\":0}", &path, n as u64, root).unwrap());
            assert!(!api::verify_logged(i as u64, "close", bodies[i as usize], &path, n as u64, root).unwrap());
        }
    }
}

#[test]
fn delta_results_do_not_count_withdrawals() {
    let (poll, _) = elgamal_poll("delta", "choice4_single_delta_d20_b22", Some(22));
    let r = v(&api::tally_results(&poll.to_string(), "[1,0,0,0]", 3).unwrap());
    assert_eq!(r["none"], Value::Null);
    assert_eq!(r["ballots"], json!("corrections"));
    let (poll, _) = elgamal_poll("linked", "choice4_single_linked_d20", None);
    let r = v(&api::tally_results(&poll.to_string(), "[1,0,0,0]", 3).unwrap());
    assert_eq!(r["none"], json!(2));
}

#[test]
fn a_tlock_tally_is_never_ok_in_the_browser() {
    let chain = TestChain::new(3);
    let poll = json!({
        "v": 1, "id": 8, "version": 1, "registry": 1, "title": "t",
        "kind": {"type": "choice", "options": ["Oui", "Non"], "blank": false},
        "encryption": {"mode": "tlock", "chain": "c", "public_key": hex::encode(chain.public_key()), "period": 3, "genesis": 0, "round": 100},
        "publish": {"mode": "closed"}, "revote": "none", "opens": 0, "closes": 2_000_000_000u64,
        "circuit": {"name": "choice4_tlock_linked_d20", "vk_hash": format!("0x{}", "0".repeat(64))},
    });
    let tally = |sig: Vec<u8>| {
        isoloir_core::canonical::to_string(&json!({"v": 1, "poll": 8, "upto": 5, "final": true, "values": [0, 1, 0, 0], "counted": 1,
            "beacon": {"round": 100, "signature": hex::encode(sig)}, "void": []})).unwrap()
    };
    let r = v(&api::verify_tally(&poll.to_string(), &tally(chain.sign(100))).unwrap());
    assert_eq!((r["ok"].clone(), r["checked"].clone(), r["beacon_ok"].clone()), (json!(false), json!("beacon"), json!(true)));
    let r = v(&api::verify_tally(&poll.to_string(), &tally(chain.sign(101))).unwrap());
    assert_eq!((r["ok"].clone(), r["beacon_ok"].clone()), (json!(false), json!(false)));
}
