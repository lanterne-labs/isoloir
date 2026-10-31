//! End to end with real proofs (nargo and bb): a ledger, a registry, two
//! voters, a yes/no poll, ballots and a re-vote, a tally decrypted by a
//! single decrypter, each step through the judge and the state machine
//! that the ingest and the auditor share. Needs nargo and bb (Tools::find).

use isoloir_core::grumpkin::{self, Projective, Scalar};
use isoloir_core::{canonical, field, Fr};
use isoloir_proto::body::*;
use isoloir_proto::client::{self, Member, Previous, Revoting};
use isoloir_proto::judge::{self, Checkers, Passports, Pending, Verdict};
use isoloir_proto::kinds::{Choice, Variant};
use isoloir_proto::note;
use isoloir_proto::policy;
use isoloir_proto::state::State;
use isoloir_proto::tally;
use isoloir_proto::Reason;
use isoloir_zk::{BbProofs, Circuits, Prover, Tools};
use rand::SeedableRng;
use serde_json::{json, Value};

struct DevPassports;
impl Passports for DevPassports {
    fn verify(&self, _: &Eligibility, proof: &Value, _: &str, _: u64) -> Result<Option<String>, String> {
        Ok(proof.get("uid").and_then(Value::as_str).map(String::from))
    }
}

struct Ledger {
    state: State,
    pending: Pending,
    queue: Vec<(EntryKind, Vec<u8>)>,
    now: u64,
    signer: note::Signer,
}

impl Ledger {
    fn new(now: u64) -> Self {
        let signer = note::Signer::new("test.example/isoloir", &[9u8; 32]);
        let mut l = Ledger { state: State::new(), pending: Pending::default(), queue: vec![], now, signer };
        let ledger = LedgerSetup {
            v: 1,
            version: 1,
            origin: "test.example/isoloir".into(),
            log_key: l.signer.verifier(),
            ingest: hex::encode([2u8; 32]),
            relays: vec![Relay { url: "wss://relay.test".into(), state: RelayState::Active }],
            checkpoint_period: 20,
            anchor_age: 86_400,
        };
        l.setup(Body::Ledger(ledger));
        l.checkpoint();
        l
    }

    fn setup(&mut self, b: Body) {
        let bytes = b.encode();
        judge::judge_setup(&self.state, b.kind(), &bytes, self.now).unwrap();
        self.queue.push((b.kind(), bytes));
    }

    fn post(&mut self, kind: EntryKind, bytes: Vec<u8>, c: &Checkers) -> Verdict {
        let v = judge::judge(&self.state, &self.pending, kind, &bytes, self.now, c);
        if v == Verdict::Accept {
            self.pending.admit(kind, &bytes);
            self.queue.push((kind, bytes));
        }
        v
    }

    /// Logs the queue, ordered by body hash, and checkpoints.
    fn checkpoint(&mut self) -> note::Checkpoint {
        self.now += 20;
        let mut q = std::mem::take(&mut self.queue);
        q.sort_by_key(|(_, b)| isoloir_core::encoding::body_hash(b));
        // Setups first: what they define is used by the rest.
        q.sort_by_key(|(k, _)| !matches!(k, EntryKind::Ledger | EntryKind::Registry | EntryKind::Poll));
        for (k, b) in q {
            self.state.apply(k, &b, self.now).unwrap();
        }
        self.pending.clear();
        let index = self.state.checkpoints.len() as u64 + 1;
        let cp = self.state.checkpoint(index, self.now, None);
        let signed = self.signer.sign(&cp.text());
        let text = note::Verifier::parse(&self.signer.verifier()).unwrap().open(&signed).unwrap().to_string();
        let parsed = note::Checkpoint::parse(&text).unwrap();
        self.state.record(&parsed).unwrap();
        parsed
    }
}

fn member(state: &State, registry: u32, s: &Fr) -> Member {
    let reg = &state.registries[&registry];
    let leaf = field::to_hex(&client::leaf(registry, s));
    let index = reg.ids[&leaf];
    Member { root: reg.tree.root(), path: reg.tree.path(index as usize).unwrap(), index }
}

#[test]
fn a_yes_no_poll_end_to_end() {
    let tools = Tools::find().expect("nargo and bb");
    let circuits = Circuits::repo();
    let name = "choice4_elgamal_linked_d20";
    let built = circuits.build(&tools, name).unwrap();
    let vkdir = tempfile::tempdir().unwrap();
    isoloir_zk::install(&built, vkdir.path()).unwrap();
    let proofs = BbProofs::new(tools.bb.clone(), vkdir.path().to_path_buf());
    let prover = Prover::new(tools, circuits);
    let checkers = Checkers { proofs: &proofs, passports: &DevPassports, tlock: None };
    let mut rng = rand::rngs::StdRng::seed_from_u64(7);

    let mut l = Ledger::new(1_800_000_000);
    l.setup(Body::Registry(RegistrySetup {
        v: 1,
        id: 1,
        version: 1,
        name: "test".into(),
        eligibility: Eligibility { provider: "dev".into(), domain: "test.example".into(), scope: "t".into(), min_age: None, nationality: vec![], document_type: None, require_expiry: false },
        validity: 3600,
        depth: 20,
    }));
    l.checkpoint();

    // Two registrations, and the same passport again.
    let voters: Vec<Fr> = (0..2).map(|_| grumpkin::random_fr(&mut rng)).collect();
    for (i, s) in voters.iter().enumerate() {
        let body = client::register_body(1, s, &format!("passport-{i}"), json!({"uid": format!("passport-{i}")}), l.now, &[0x40 + i as u8; 32]);
        assert_eq!(l.post(EntryKind::Register, body, &checkers), Verdict::Accept);
    }
    let again = client::register_body(1, &grumpkin::random_fr(&mut rng), "passport-0", json!({"uid": "passport-0"}), l.now, &[0x50; 32]);
    assert_eq!(l.post(EntryKind::Register, again, &checkers), Verdict::Reject(Reason::UidUsed));
    let mut forged = String::from_utf8(client::register_body(1, &grumpkin::random_fr(&mut rng), "passport-9", json!({"uid": "passport-9"}), l.now, &[0x51; 32])).unwrap();
    forged = forged.replacen("passport-9", "passport-8", 2);
    assert_eq!(l.post(EntryKind::Register, forged.into_bytes(), &checkers), Verdict::Reject(Reason::BadSig));
    l.checkpoint();
    assert_eq!(l.state.registries[&1].tree.len(), 2);

    // The poll: yes / no / blank, open results, linked re-votes.
    let sk: Scalar = grumpkin::random_scalar(&mut rng);
    let pk = grumpkin::to_hex(&(Projective::from(grumpkin::generator()) * sk).into()).unwrap();
    let seed = [3u8; 32];
    let poll = PollSetup {
        v: 1,
        id: 7,
        version: 1,
        registry: 1,
        title: "Oui ou non ?".into(),
        kind: KindSpec::Choice { options: vec!["Oui".into(), "Non".into()], blank: true },
        encryption: Encryption::Elgamal { pk, decrypter: Decrypter::Single { sign_key: isoloir_proto::sig::ed25519_public(&seed) } },
        publish: Publish::Open { k_real: 1, min_gap: 0, coin: false },
        revote: Revote::Linked,
        opens: l.now,
        closes: l.now + 86_400,
        blackouts: vec![],
        circuit: CircuitRef { name: name.into(), vk_hash: built.vk_hash.clone() },
        ballot_depth: None,
    };
    l.setup(Body::Poll(poll.clone()));
    l.checkpoint();
    let setup_seq = l.state.polls[&7].setups[0].0;
    let variant = Variant::parse(name).unwrap();

    let cast = |l: &mut Ledger, s: &Fr, pick: Option<u32>, seq: u32, rng: &mut rand::rngs::StdRng| -> (Verdict, Vec<u8>) {
        let m = member(&l.state, 1, s);
        let d = client::draft(&poll, setup_seq, &variant, &m, s, &Choice::Pick(pick), &Revoting::Linked { seq }, None, rng).unwrap();
        let p = prover.prove(name, &d.inputs).unwrap();
        let body = d.finish(&p.proof);
        // The inputs the judge rebuilds are the ones the prover saw.
        let Body::Ballot(b) = decode(EntryKind::Ballot, &body).unwrap() else { panic!() };
        assert_eq!(isoloir_proto::statement::inputs(&b, &poll, &variant).unwrap(), p.public_inputs);
        (l.post(EntryKind::Ballot, body.clone(), &checkers), body)
    };
    // Voter 0 votes yes, voter 1 no; voter 0 changes to blank.
    assert_eq!(cast(&mut l, &voters[0], Some(0), 0, &mut rng).0, Verdict::Accept);
    assert_eq!(cast(&mut l, &voters[1], Some(1), 0, &mut rng).0, Verdict::Accept);
    l.checkpoint();
    assert_eq!(cast(&mut l, &voters[0], Some(2), 1, &mut rng).0, Verdict::Accept);
    let (stale, _) = cast(&mut l, &voters[0], Some(0), 1, &mut rng);
    assert_eq!(stale, Verdict::Reject(Reason::StaleSeq));
    // A ballot whose ciphertext was changed: the proof no longer holds.
    let m = member(&l.state, 1, &voters[1]);
    let d = client::draft(&poll, setup_seq, &variant, &m, &voters[1], &Choice::Pick(Some(0)), &Revoting::Linked { seq: 1 }, None, &mut rng).unwrap();
    let p = prover.prove(name, &d.inputs).unwrap();
    let mut tampered = d.clone();
    tampered.body.ct.as_mut().unwrap().swap(0, 1);
    assert_eq!(l.post(EntryKind::Ballot, tampered.finish(&p.proof), &checkers), Verdict::Reject(Reason::BadProof));
    let cp = l.checkpoint();

    // The tally due at this checkpoint, decrypted and verified.
    let due = policy::due_at(&l.state, 7, cp.index).expect("a tally is due");
    let t = tally::build_elgamal(&l.state.polls[&7], &due, &sk, &seed, &mut rng).unwrap();
    assert_eq!(t.values, vec![0, 1, 1, 0], "no yes, one no, one blank");
    assert_eq!(t.counted, 2);
    let body = canonical::to_vec(&t).unwrap();
    assert_eq!(l.post(EntryKind::Tally, body, &checkers), Verdict::Accept);
    // A tally with other values is refused.
    let mut wrong = t.clone();
    wrong.values = vec![1, 1, 0, 0];
    wrong.sig = None;
    wrong.sig = Some(isoloir_proto::sig::sign_tally(&seed, &canonical::to_vec(&wrong).unwrap()));
    let mut pending = Pending::default();
    std::mem::swap(&mut pending, &mut l.pending);
    assert_eq!(judge::judge(&l.state, &Pending::default(), EntryKind::Tally, &canonical::to_vec(&wrong).unwrap(), l.now, &checkers), Verdict::Reject(Reason::BadTally));
    std::mem::swap(&mut pending, &mut l.pending);
    l.checkpoint();
    assert_eq!(l.state.polls[&7].tallies.len(), 1);
}

#[test]
fn delta_re_votes_end_to_end() {
    let tools = Tools::find().expect("nargo and bb");
    let circuits = Circuits::repo();
    let name = "choice4_elgamal_delta_d20_b22";
    let built = circuits.build(&tools, name).unwrap();
    let vkdir = tempfile::tempdir().unwrap();
    isoloir_zk::install(&built, vkdir.path()).unwrap();
    let proofs = BbProofs::new(tools.bb.clone(), vkdir.path().to_path_buf());
    let prover = Prover::new(tools, circuits);
    let checkers = Checkers { proofs: &proofs, passports: &DevPassports, tlock: None };
    let mut rng = rand::rngs::StdRng::seed_from_u64(8);

    let mut l = Ledger::new(1_800_000_000);
    l.setup(Body::Registry(RegistrySetup {
        v: 1,
        id: 1,
        version: 1,
        name: "test".into(),
        eligibility: Eligibility { provider: "dev".into(), domain: "test.example".into(), scope: "t".into(), min_age: None, nationality: vec![], document_type: None, require_expiry: false },
        validity: 3600,
        depth: 20,
    }));
    l.checkpoint();
    let s = grumpkin::random_fr(&mut rng);
    let other = grumpkin::random_fr(&mut rng);
    for (i, v) in [s, other].iter().enumerate() {
        let body = client::register_body(1, v, &format!("p{i}"), json!({"uid": format!("p{i}")}), l.now, &[0x60 + i as u8; 32]);
        assert_eq!(l.post(EntryKind::Register, body, &checkers), Verdict::Accept);
    }
    let sk = grumpkin::random_scalar(&mut rng);
    let pk = grumpkin::to_hex(&(Projective::from(grumpkin::generator()) * sk).into()).unwrap();
    let seed = [4u8; 32];
    let poll = PollSetup {
        v: 1,
        id: 9,
        version: 1,
        registry: 1,
        title: "delta".into(),
        kind: KindSpec::Choice { options: vec!["Oui".into(), "Non".into()], blank: false },
        encryption: Encryption::Elgamal { pk, decrypter: Decrypter::Single { sign_key: isoloir_proto::sig::ed25519_public(&seed) } },
        publish: Publish::Closed,
        revote: Revote::Delta,
        opens: l.now,
        closes: l.now + 86_400,
        blackouts: vec![],
        circuit: CircuitRef { name: name.into(), vk_hash: built.vk_hash.clone() },
        ballot_depth: Some(22),
    };
    l.setup(Body::Poll(poll.clone()));
    l.checkpoint();
    let setup_seq = l.state.polls[&9].setups[0].0;
    let variant = Variant::parse(name).unwrap();
    let broot = |l: &Ledger| l.state.polls[&9].btree.as_ref().unwrap().root();

    let vote = |l: &mut Ledger, s: &Fr, choice: Choice, i: u32, previous: Option<Previous>, rng: &mut rand::rngs::StdRng| {
        let m = member(&l.state, 1, s);
        let r = Revoting::Delta { i, previous, broot: broot(l) };
        let d = client::draft(&poll, setup_seq, &variant, &m, s, &choice, &r, None, rng).unwrap();
        let p = prover.prove(name, &d.inputs).unwrap();
        l.post(EntryKind::Ballot, d.finish(&p.proof), &checkers)
    };
    // The voter says yes, the other voter no.
    assert_eq!(vote(&mut l, &s, Choice::Pick(Some(0)), 0, None, &mut rng), Verdict::Accept);
    assert_eq!(vote(&mut l, &other, Choice::Pick(Some(1)), 0, None, &mut rng), Verdict::Accept);
    // A second first ballot is the same identifier.
    assert_eq!(vote(&mut l, &s, Choice::Pick(Some(1)), 0, None, &mut rng), Verdict::Reject(Reason::Duplicate));
    l.checkpoint();
    // The voter changes to no: a correction proven against ballot 0.
    let leaf0 = isoloir_proto::state::delta_leaf(&client::ident(9, &s, 0), &client::delta_cmt(&variant, 9, &s, 0, &Choice::Pick(Some(0))));
    let tree = l.state.polls[&9].btree.as_ref().unwrap();
    let index = (0..tree.len()).find(|i| tree.leaf(*i) == Some(leaf0)).unwrap();
    let prev = Previous { choice: Choice::Pick(Some(0)), path: tree.path(index).unwrap(), index: index as u64 };
    assert_eq!(vote(&mut l, &s, Choice::Pick(Some(1)), 1, Some(prev.clone()), &mut rng), Verdict::Accept);
    // Claiming another old choice than the logged one: the proof fails.
    let liar = Previous { choice: Choice::Pick(Some(1)), ..prev };
    let m = member(&l.state, 1, &s);
    let d = client::draft(&poll, setup_seq, &variant, &m, &s, &Choice::Pick(Some(0)), &Revoting::Delta { i: 1, previous: Some(liar), broot: broot(&l) }, None, &mut rng).unwrap();
    assert!(prover.prove(name, &d.inputs).is_err(), "the circuit refuses a chain that does not hold");
    l.checkpoint();

    // Close, then the final tally: two "no", nothing else.
    l.now = poll.closes;
    l.queue.push((EntryKind::Close, Body::Close(Close { v: 1, poll: 9, at: poll.closes, last: l.state.polls[&9].ballots.last().unwrap().seq }).encode()));
    let cp = l.checkpoint();
    let due = policy::due_at(&l.state, 9, cp.index).expect("the final tally is due");
    assert!(due.is_final);
    let t = tally::build_elgamal(&l.state.polls[&9], &due, &sk, &seed, &mut rng).unwrap();
    assert_eq!(&t.values[..2], &[0, 2]);
    assert_eq!(t.counted, 3, "every delta ballot counts");
    assert_eq!(l.post(EntryKind::Tally, canonical::to_vec(&t).unwrap(), &checkers), Verdict::Accept);
}
