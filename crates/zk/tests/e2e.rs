//! End to end with real proofs (nargo and bb): a ledger, a registry, two
//! voters, a yes/no poll, ballots and a re-vote, a tally decrypted by a
//! single authority, each step through the judge and the state machine
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

mod isoloir_server_free {
    pub type Read = (String, Vec<(isoloir_proto::body::EntryKind, Vec<u8>)>);
}

struct Ledger {
    state: State,
    pending: Pending,
    queue: Vec<(EntryKind, Vec<u8>)>,
    now: u64,
    signer: note::Signer,
    /// Each checkpoint's signed note and entries, for the auditor.
    notes: Vec<isoloir_server_free::Read>,
    posted: u64,
}

impl Ledger {
    fn new(now: u64) -> Self {
        let signer = note::Signer::new("test.example/isoloir", &[9u8; 32]);
        let mut l = Ledger { state: State::new(), pending: Pending::default(), queue: vec![], now, signer, notes: vec![], posted: 0 };
        let ledger = LedgerSetup {
            v: 1,
            version: 1,
            origin: "test.example/isoloir".into(),
            log_key: l.signer.verifier(),
            ingest: hex::encode([2u8; 32]),
            channels: vec![Channel::Nostr { url: "wss://relay.test".into(), state: ChannelState::Active }],
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
        match v {
            Verdict::Accept => {
                self.pending.admit(kind, &bytes);
                self.queue.push((kind, bytes));
            }
            // Every refusal is logged, with the raw body (SPEC §11.4).
            Verdict::Reject(reason) => {
                self.posted += 1;
                let r = Reject {
                    v: 1,
                    of: format!("{:064x}", self.posted),
                    hash: isoloir_core::encoding::body_hash(&bytes),
                    reason,
                    kind: Some(kind.as_str().into()),
                    raw: Some(isoloir_core::encoding::b64(&bytes)),
                };
                self.queue.push((EntryKind::Reject, Body::Reject(r).encode()));
            }
            Verdict::Defer(_) => {}
        }
        v
    }

    /// Replays the whole log through an auditor with the same checkers.
    fn audit(&self, c: Checkers) {
        let mut a = isoloir_proto::audit::Auditor::new(Some(&self.signer.verifier()), c).unwrap();
        for (note, entries) in &self.notes {
            a.checkpoint(note, entries).unwrap();
        }
        let (_, report) = a.finish();
        assert!(report.problems.is_empty(), "audit problems: {:#?}", report.problems);
    }

    /// Logs the queue, ordered by body hash, and checkpoints.
    fn checkpoint(&mut self) -> note::Checkpoint {
        self.now += 20;
        let mut q = std::mem::take(&mut self.queue);
        q.sort_by_key(|(k, b)| (*k == EntryKind::Close, isoloir_core::encoding::body_hash(b)));
        for (k, b) in &q {
            self.state.apply(*k, b, self.now).unwrap();
        }
        self.pending.clear();
        let index = self.state.checkpoints.len() as u64 + 1;
        let cp = self.state.checkpoint(index, self.now, None);
        let signed = self.signer.sign(&cp.text());
        let text = note::Verifier::parse(&self.signer.verifier()).unwrap().open(&signed).unwrap().to_string();
        let parsed = note::Checkpoint::parse(&text).unwrap();
        self.state.record(&parsed).unwrap();
        self.notes.push((signed, q));
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
    let name = "choice4_single_linked_d20";
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
        encryption: Encryption::Elgamal { pk, authority: Authority::Single { sign_key: isoloir_proto::sig::ed25519_public(&seed) } },
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
    // One chunk now (seven values per chunk): swap its two halves.
    let c = &mut tampered.body.ct.as_mut().unwrap()[0];
    c.swap(0, 1);
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
    l.audit(Checkers { proofs: &proofs, passports: &DevPassports, tlock: None });

    // A log changed after the fact: one refusal turned into the valid
    // ballot of another voter, under the same signed notes. The replay
    // diverges from the notes.
    let mut tampered = l.notes.clone();
    let (ci, ei) = tampered
        .iter()
        .enumerate()
        .find_map(|(ci, (_, es))| es.iter().position(|(k, _)| *k == EntryKind::Reject).map(|ei| (ci, ei)))
        .unwrap();
    let ballot = tampered.iter().flat_map(|(_, es)| es.iter()).find(|(k, _)| *k == EntryKind::Ballot).unwrap().clone();
    tampered[ci].1[ei] = ballot;
    let mut a = isoloir_proto::audit::Auditor::new(Some(&l.signer.verifier()), Checkers { proofs: &proofs, passports: &DevPassports, tlock: None }).unwrap();
    let diverged = tampered.iter().any(|(n, es)| a.checkpoint(n, es).is_err());
    assert!(diverged || !a.report.problems.is_empty(), "the auditor saw nothing");
}

#[test]
fn delta_re_votes_end_to_end() {
    let tools = Tools::find().expect("nargo and bb");
    let circuits = Circuits::repo();
    let name = "choice4_single_delta_d20_b22";
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
        encryption: Encryption::Elgamal { pk, authority: Authority::Single { sign_key: isoloir_proto::sig::ed25519_public(&seed) } },
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
    l.queue.push((EntryKind::Close, Body::Close(Close { v: 1, poll: 9, at: poll.closes, last: l.state.polls[&9].ballots.last().map(|b| b.seq).unwrap_or(0) }).encode()));
    let cp = l.checkpoint();
    let due = policy::due_at(&l.state, 9, cp.index).expect("the final tally is due");
    assert!(due.is_final);
    let t = tally::build_elgamal(&l.state.polls[&9], &due, &sk, &seed, &mut rng).unwrap();
    assert_eq!(&t.values[..2], &[0, 2]);
    assert_eq!(t.counted, 3, "every delta ballot counts");
    assert_eq!(l.post(EntryKind::Tally, canonical::to_vec(&t).unwrap(), &checkers), Verdict::Accept);
    l.checkpoint();
    l.audit(Checkers { proofs: &proofs, passports: &DevPassports, tlock: None });
}

#[test]
fn a_tlock_poll_end_to_end() {
    use isoloir_decrypt::bls::TestChain;
    use isoloir_decrypt::tlock::{self as tl, DrandTlock};
    let tools = Tools::find().expect("nargo and bb");
    let circuits = Circuits::repo();
    let name = "choice4_tlock_linked_d20";
    let built = circuits.build(&tools, name).unwrap();
    let vkdir = tempfile::tempdir().unwrap();
    isoloir_zk::install(&built, vkdir.path()).unwrap();
    let proofs = BbProofs::new(tools.bb.clone(), vkdir.path().to_path_buf());
    let prover = Prover::new(tools, circuits);
    let opener = DrandTlock;
    let checkers = Checkers { proofs: &proofs, passports: &DevPassports, tlock: Some(&opener) };
    let mut rng = rand::rngs::StdRng::seed_from_u64(9);

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
    let voters: Vec<Fr> = (0..3).map(|_| grumpkin::random_fr(&mut rng)).collect();
    for (i, s) in voters.iter().enumerate() {
        let body = client::register_body(1, s, &format!("t{i}"), json!({"uid": format!("t{i}")}), l.now, &[0x70 + i as u8; 32]);
        assert_eq!(l.post(EntryKind::Register, body, &checkers), Verdict::Accept);
    }
    l.checkpoint();
    // A test chain standing for drand: genesis now, a round every 3 s.
    let chain = TestChain::new(42);
    let (genesis, period) = (l.now, 3u64);
    let closes = l.now + 3_600;
    let round = (closes - genesis) / period + 1;
    let poll = PollSetup {
        v: 1,
        id: 11,
        version: 1,
        registry: 1,
        title: "tlock".into(),
        kind: KindSpec::Choice { options: vec!["Oui".into(), "Non".into()], blank: true },
        encryption: Encryption::Tlock { chain: hex::encode([1u8; 32]), public_key: hex::encode(chain.public_key()), period, genesis, round },
        publish: Publish::Closed,
        revote: Revote::None,
        opens: l.now,
        closes,
        blackouts: vec![],
        circuit: CircuitRef { name: name.into(), vk_hash: built.vk_hash.clone() },
        ballot_depth: None,
    };
    // tlock with re-votes, or open results, is refused (SPEC §8).
    for bad in [PollSetup { revote: Revote::Linked, ..poll.clone() }, PollSetup { publish: Publish::Open { k_real: 1, min_gap: 0, coin: false }, ..poll.clone() }] {
        assert!(judge::judge_setup(&l.state, EntryKind::Poll, &Body::Poll(bad).encode(), l.now).is_err());
    }
    l.setup(Body::Poll(poll.clone()));
    l.checkpoint();
    let setup_seq = l.state.polls[&11].setups[0].0;
    let variant = Variant::parse(name).unwrap();
    let (pk, r) = tl::params(&poll.encryption).unwrap();
    let mut seal_rng = rand::rngs::StdRng::seed_from_u64(10);
    let seal = move |p: &[u8]| tl::seal(&pk, r, p, &mut seal_rng);
    let seal = std::cell::RefCell::new(seal);
    let sealer = |p: &[u8]| (seal.borrow_mut())(p);

    let draft = |l: &Ledger, s: &Fr, pick: Option<u32>, rng: &mut rand::rngs::StdRng| {
        let m = member(&l.state, 1, s);
        client::draft(&poll, setup_seq, &variant, &m, s, &Choice::Pick(pick), &Revoting::Linked { seq: 0 }, Some(&sealer), rng).unwrap()
    };
    // Two honest ballots: yes, no.
    for (s, pick) in [(&voters[0], 0), (&voters[1], 1)] {
        let d = draft(&l, s, Some(pick), &mut rng);
        let p = prover.prove(name, &d.inputs).unwrap();
        assert_eq!(l.post(EntryKind::Ballot, d.finish(&p.proof), &checkers), Verdict::Accept);
    }
    // A relay swaps a blob: the proof binds it, the ballot is refused.
    let d = draft(&l, &voters[2], Some(0), &mut rng);
    let p = prover.prove(name, &d.inputs).unwrap();
    let mut swapped = d.clone();
    let mut blob = isoloir_core::encoding::unb64(swapped.body.blob.as_ref().unwrap()).unwrap();
    blob[40] ^= 1;
    swapped.body.blob = Some(isoloir_core::encoding::b64(&blob));
    assert_eq!(l.post(EntryKind::Ballot, swapped.finish(&p.proof), &checkers), Verdict::Reject(Reason::BadProof));
    // The third voter's own blob is garbage, proven as such: void at the round.
    let m = member(&l.state, 1, &voters[2]);
    let junk = |_: &[u8]| Ok(vec![0u8; 200]);
    let d = client::draft(&poll, setup_seq, &variant, &m, &voters[2], &Choice::Pick(Some(0)), &Revoting::Linked { seq: 0 }, Some(&junk), &mut rng).unwrap();
    let p = prover.prove(name, &d.inputs).unwrap();
    assert_eq!(l.post(EntryKind::Ballot, d.finish(&p.proof), &checkers), Verdict::Accept);
    // One ballot per voter.
    let again = draft(&l, &voters[0], Some(1), &mut rng);
    let p = prover.prove(name, &again.inputs).unwrap();
    assert_eq!(l.post(EntryKind::Ballot, again.finish(&p.proof), &checkers), Verdict::Reject(Reason::RevoteOff));
    l.checkpoint();

    // The close, then the opening with the round's beacon.
    l.now = closes;
    l.queue.push((EntryKind::Close, Body::Close(Close { v: 1, poll: 11, at: closes, last: l.state.polls[&11].ballots.last().unwrap().seq }).encode()));
    let cp = l.checkpoint();
    let due = policy::due_at(&l.state, 11, cp.index).unwrap();
    let wrong = Beacon { round, signature: hex::encode(TestChain::new(43).sign(round)) };
    assert!(tally::build_tlock(&l.state.polls[&11], &due, &wrong, &opener).is_err(), "another chain's beacon");
    let beacon = Beacon { round, signature: hex::encode(chain.sign(round)) };
    let t = tally::build_tlock(&l.state.polls[&11], &due, &beacon, &opener).unwrap();
    assert_eq!(t.values, vec![1, 1, 0, 0]);
    assert_eq!(t.counted, 2);
    assert_eq!(t.void.as_ref().unwrap().len(), 1);
    assert_eq!(l.post(EntryKind::Tally, canonical::to_vec(&t).unwrap(), &checkers), Verdict::Accept);
    let mut lie = t.clone();
    lie.values = vec![2, 0, 0, 0];
    assert_eq!(judge::judge(&l.state, &Pending::default(), EntryKind::Tally, &canonical::to_vec(&lie).unwrap(), l.now, &checkers), Verdict::Reject(Reason::BadTally));
    l.checkpoint();
    l.audit(Checkers { proofs: &proofs, passports: &DevPassports, tlock: Some(&opener) });
}

/// Ranked ballots with margins: the circuit's values and the Rust ones
/// agree, through a decrypted tally.
#[test]
fn a_ranked_poll_with_margins() {
    let tools = Tools::find().expect("nargo and bb");
    let circuits = Circuits::repo();
    let name = "rankedm12_single_linked_d20";
    let built = circuits.build(&tools, name).unwrap();
    let vkdir = tempfile::tempdir().unwrap();
    isoloir_zk::install(&built, vkdir.path()).unwrap();
    let proofs = BbProofs::new(tools.bb.clone(), vkdir.path().to_path_buf());
    let prover = Prover::new(tools, circuits);
    let checkers = Checkers { proofs: &proofs, passports: &DevPassports, tlock: None };
    let mut rng = rand::rngs::StdRng::seed_from_u64(12);
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
    let voters: Vec<Fr> = (0..3).map(|_| grumpkin::random_fr(&mut rng)).collect();
    for (i, s) in voters.iter().enumerate() {
        let body = client::register_body(1, s, &format!("r{i}"), json!({"uid": format!("r{i}")}), l.now, &[0x30 + i as u8; 32]);
        assert_eq!(l.post(EntryKind::Register, body, &checkers), Verdict::Accept);
    }
    let sk = grumpkin::random_scalar(&mut rng);
    let pk = grumpkin::to_hex(&(Projective::from(grumpkin::generator()) * sk).into()).unwrap();
    let seed = [6u8; 32];
    let options: Vec<String> = ["A", "B", "C", "D", "E"].iter().map(|s| s.to_string()).collect();
    let kind = KindSpec::Ranked { options, blank: true, depth: 3, margins: true };
    let poll = PollSetup {
        v: 1,
        id: 3,
        version: 1,
        registry: 1,
        title: "ranked".into(),
        kind: kind.clone(),
        encryption: Encryption::Elgamal { pk, authority: Authority::Single { sign_key: isoloir_proto::sig::ed25519_public(&seed) } },
        publish: Publish::Closed,
        revote: Revote::Linked,
        opens: l.now,
        closes: l.now + 86_400,
        blackouts: vec![],
        circuit: CircuitRef { name: name.into(), vk_hash: built.vk_hash.clone() },
        ballot_depth: None,
    };
    l.setup(Body::Poll(poll.clone()));
    l.checkpoint();
    let setup_seq = l.state.polls[&3].setups[0].0;
    let variant = Variant::parse(name).unwrap();
    // B > A > blank; C; D > E > A. The blank is slot 5.
    let rankings = [vec![1u32, 0, 5], vec![2], vec![3, 4, 0]];
    let mut want = vec![0i64; variant.values()];
    for (s, r) in voters.iter().zip(&rankings) {
        let choice = Choice::Rank(r.clone());
        want.iter_mut().zip(isoloir_proto::kinds::values(&kind, &variant, &choice).unwrap()).for_each(|(a, v)| *a += v);
        let m = member(&l.state, 1, s);
        let d = client::draft(&poll, setup_seq, &variant, &m, s, &choice, &Revoting::Linked { seq: 0 }, None, &mut rng).unwrap();
        let p = prover.prove(name, &d.inputs).unwrap();
        assert_eq!(l.post(EntryKind::Ballot, d.finish(&p.proof), &checkers), Verdict::Accept);
    }
    // The blank before another option is refused by the circuit.
    let m = member(&l.state, 1, &voters[0]);
    let bad = Choice::Rank(vec![5, 1]);
    assert!(isoloir_proto::kinds::values(&kind, &variant, &bad).is_err());
    l.checkpoint();
    l.now = poll.closes;
    l.queue.push((EntryKind::Close, Body::Close(Close { v: 1, poll: 3, at: poll.closes, last: l.state.polls[&3].ballots.last().unwrap().seq }).encode()));
    let cp = l.checkpoint();
    let due = policy::due_at(&l.state, 3, cp.index).unwrap();
    let t = tally::build_elgamal(&l.state.polls[&3], &due, &sk, &seed, &mut rng).unwrap();
    assert_eq!(t.values, want);
    // first: A 0, B 1, C 1, D 1; margins: A before B? (0,1) = −1 +0... checked through want.
    assert_eq!(&t.values[..6], &[0, 1, 1, 1, 0, 0]);
    assert_eq!(l.post(EntryKind::Tally, canonical::to_vec(&t).unwrap(), &checkers), Verdict::Accept);
    l.checkpoint();
    l.audit(Checkers { proofs: &proofs, passports: &DevPassports, tlock: None });
    let _ = m;
}

/// The rules the review added: a seq far above the last is refused, a
/// full tree refuses, k_real cannot be lowered, and an audit that cannot
/// check a proof fails instead of passing.
#[test]
fn review_rules() {
    use isoloir_proto::judge::{Proofs, SEQ_GAP};
    let tools = Tools::find().expect("nargo and bb");
    let circuits = Circuits::repo();
    let name = "choice4_single_linked_d20";
    let built = circuits.build(&tools, name).unwrap();
    let vkdir = tempfile::tempdir().unwrap();
    isoloir_zk::install(&built, vkdir.path()).unwrap();
    let proofs = BbProofs::new(tools.bb.clone(), vkdir.path().to_path_buf());
    let prover = Prover::new(tools, circuits);
    let checkers = Checkers { proofs: &proofs, passports: &DevPassports, tlock: None };
    let mut rng = rand::rngs::StdRng::seed_from_u64(51);
    let mut l = Ledger::new(1_800_000_000);
    // A registry of depth 1: two leaves, then full.
    l.setup(Body::Registry(RegistrySetup {
        v: 1,
        id: 1,
        version: 1,
        name: "tiny".into(),
        eligibility: Eligibility { provider: "dev".into(), domain: "d".into(), scope: "s".into(), min_age: None, nationality: vec![], document_type: None, require_expiry: false },
        validity: 3600,
        depth: 1,
    }));
    l.checkpoint();
    let voters: Vec<Fr> = (0..3).map(|_| grumpkin::random_fr(&mut rng)).collect();
    let verdicts: Vec<Verdict> = voters
        .iter()
        .enumerate()
        .map(|(i, s)| l.post(EntryKind::Register, client::register_body(1, s, &format!("f{i}"), json!({"uid": format!("f{i}")}), l.now, &[0x80 + i as u8; 32]), &checkers))
        .collect();
    assert_eq!(verdicts, vec![Verdict::Accept, Verdict::Accept, Verdict::Reject(Reason::Full)]);
    l.checkpoint();
    // The poll's circuit variant must match the registry depth: d1.
    let name1 = "choice4_single_linked_d1";
    let built1 = l_build(&prover, name1);
    isoloir_zk::install(&built1, vkdir.path()).unwrap();
    let sk = grumpkin::random_scalar(&mut rng);
    let pk = grumpkin::to_hex(&(Projective::from(grumpkin::generator()) * sk).into()).unwrap();
    let seed = [8u8; 32];
    let poll = PollSetup {
        v: 1,
        id: 4,
        version: 1,
        registry: 1,
        title: "rules".into(),
        kind: KindSpec::Choice { options: vec!["Oui".into(), "Non".into()], blank: false },
        encryption: Encryption::Elgamal { pk, authority: Authority::Single { sign_key: isoloir_proto::sig::ed25519_public(&seed) } },
        publish: Publish::Open { k_real: 5, min_gap: 60, coin: true },
        revote: Revote::Linked,
        opens: l.now,
        closes: l.now + 86_400,
        blackouts: vec![],
        circuit: CircuitRef { name: name1.into(), vk_hash: built1.vk_hash.clone() },
        ballot_depth: None,
    };
    l.setup(Body::Poll(poll.clone()));
    l.checkpoint();
    // Lowering k_real or min_gap, or changing the coin: refused.
    for bad in [
        PollSetup { version: 2, publish: Publish::Open { k_real: 4, min_gap: 60, coin: true }, ..poll.clone() },
        PollSetup { version: 2, publish: Publish::Open { k_real: 5, min_gap: 0, coin: true }, ..poll.clone() },
        PollSetup { version: 2, publish: Publish::Open { k_real: 5, min_gap: 60, coin: false }, ..poll.clone() },
    ] {
        assert!(judge::judge_setup(&l.state, EntryKind::Poll, &Body::Poll(bad).encode(), l.now).is_err());
    }
    assert!(judge::judge_setup(&l.state, EntryKind::Poll, &Body::Poll(PollSetup { version: 2, publish: Publish::Open { k_real: 50, min_gap: 600, coin: true }, ..poll.clone() }).encode(), l.now).is_ok());
    let setup_seq = l.state.polls[&4].setups[0].0;
    let variant = Variant::parse(name1).unwrap();
    let cast = |l: &mut Ledger, s: &Fr, seq: u32, rng: &mut rand::rngs::StdRng| {
        let m = member(&l.state, 1, s);
        let d = client::draft(&poll, setup_seq, &variant, &m, s, &Choice::Pick(Some(0)), &Revoting::Linked { seq }, None, rng).unwrap();
        let p = prover.prove(name1, &d.inputs).unwrap();
        l.post(EntryKind::Ballot, d.finish(&p.proof), &checkers)
    };
    // A first ballot with a huge seq, then within the gap.
    assert_eq!(cast(&mut l, &voters[0], u32::MAX, &mut rng), Verdict::Reject(Reason::SeqGap));
    assert_eq!(cast(&mut l, &voters[0], SEQ_GAP as u32, &mut rng), Verdict::Accept);
    l.checkpoint();
    assert_eq!(cast(&mut l, &voters[0], SEQ_GAP as u32 * 2 + 2, &mut rng), Verdict::Reject(Reason::SeqGap));
    assert_eq!(cast(&mut l, &voters[0], SEQ_GAP as u32 + 1, &mut rng), Verdict::Accept);
    l.checkpoint();
    l.audit(Checkers { proofs: &proofs, passports: &DevPassports, tlock: None });
    // An auditor without the verification key cannot pass the log.
    struct NoKeys;
    impl Proofs for NoKeys {
        fn verify(&self, _: &CircuitRef, _: &[u8], _: &[[u8; 32]]) -> Result<bool, String> {
            Err("no vk".into())
        }
    }
    let mut a = isoloir_proto::audit::Auditor::new(Some(&l.signer.verifier()), Checkers { proofs: &NoKeys, passports: &DevPassports, tlock: None }).unwrap();
    for (n, es) in &l.notes {
        a.checkpoint(n, es).unwrap();
    }
    let (_, report) = a.finish();
    assert!(report.problems.iter().any(|p| p.contains("not checked")), "{:?}", report.problems);
}

fn l_build(prover: &Prover, name: &str) -> isoloir_zk::Built {
    prover.circuits.build(&prover.tools, name).unwrap()
}
