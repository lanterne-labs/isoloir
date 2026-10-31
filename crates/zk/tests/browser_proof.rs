//! A proof made as the browser makes it (noir_js and bb.js, through
//! js/test/prove-node.mjs) verifies with the server's bb against the
//! public inputs the judge rebuilds. Needs node and js/node_modules:
//! `cargo test -p isoloir-zk --test browser_proof -- --ignored`.

use isoloir_core::grumpkin::{self, Projective};
use isoloir_proto::body::*;
use isoloir_proto::client::{self, Member, Revoting};
use isoloir_proto::judge::Proofs;
use isoloir_proto::kinds::{Choice, Variant};
use isoloir_zk::{BbProofs, Circuits, Tools};
use rand::SeedableRng;
use std::path::Path;

#[test]
#[ignore]
fn a_browser_proof_verifies_on_the_server() {
    let tools = Tools::find().expect("nargo and bb");
    let name = "choice4_single_linked_d20";
    let built = Circuits::repo().build(&tools, name).unwrap();
    let mut rng = rand::rngs::StdRng::seed_from_u64(31);
    let s = grumpkin::random_fr(&mut rng);
    let mut tree = isoloir_core::tree::Tree::new(20);
    tree.push(isoloir_core::Fr::from(7u64)).unwrap();
    tree.push(client::leaf(1, &s)).unwrap();
    let m = Member { root: tree.root(), path: tree.path(1).unwrap(), index: 1 };
    let sk = grumpkin::random_scalar(&mut rng);
    let pk = grumpkin::to_hex(&(Projective::from(grumpkin::generator()) * sk).into()).unwrap();
    let poll = PollSetup {
        v: 1,
        id: 2,
        version: 1,
        registry: 1,
        title: "t".into(),
        kind: KindSpec::Choice { options: vec!["Oui".into(), "Non".into()], blank: true },
        encryption: Encryption::Elgamal { pk, authority: Authority::Single { sign_key: hex::encode([1u8; 32]) } },
        publish: Publish::Closed,
        revote: Revote::Linked,
        opens: 0,
        closes: 1,
        blackouts: vec![],
        circuit: CircuitRef { name: name.into(), vk_hash: built.vk_hash.clone() },
        ballot_depth: None,
    };
    let variant = Variant::parse(name).unwrap();
    let d = client::draft(&poll, 3, &variant, &m, &s, &Choice::Pick(Some(1)), &Revoting::Linked { seq: 0 }, None, &mut rng).unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("inputs.json"), serde_json::to_vec(&d.inputs).unwrap()).unwrap();
    let js = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../js");
    let status = std::process::Command::new("node")
        .arg(js.join("test/prove-node.mjs"))
        .arg(&built.artifact)
        .arg(dir.path().join("inputs.json"))
        .arg(dir.path().join("proof"))
        .current_dir(&js)
        .status()
        .unwrap();
    assert!(status.success());
    let proof = std::fs::read(dir.path().join("proof")).unwrap();
    let body = d.finish(&proof);
    let Ok(Body::Ballot(b)) = decode(EntryKind::Ballot, &body) else { panic!() };
    let inputs = isoloir_proto::statement::inputs(&b, &poll, &variant).unwrap();
    let vks = tempfile::tempdir().unwrap();
    isoloir_zk::install(&built, vks.path()).unwrap();
    let bb = BbProofs::new(tools.bb, vks.path().to_path_buf());
    assert_eq!(bb.verify(&poll.circuit, &proof, &inputs), Ok(true));
    let mut other = inputs.clone();
    other[4][31] ^= 1;
    assert_eq!(bb.verify(&poll.circuit, &proof, &other), Ok(false));
}
