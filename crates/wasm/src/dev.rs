//! Helpers for tests and fakes only (feature `dev`): a checkpoint signer
//! and a single decrypter, so that a fake ingest in JavaScript writes the
//! same notes and tallies the real one does.

use crate::api::{self, err, fr, R};
use ark_ec::CurveGroup as _;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use isoloir_core::grumpkin::{self, Dleq, Projective};
use isoloir_core::{canonical, pack, Fr};
use isoloir_decrypt::keys::DecrypterKeys;
use isoloir_proto::body::{self, EntryKind, Share, Tally, V1};
use isoloir_proto::kinds;
use isoloir_proto::note::{Checkpoint, Signer};
use isoloir_proto::{sig, statement, tally};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Deserialize;

fn seed32(s: &str) -> R<[u8; 32]> {
    hex::decode(s).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| "seed: 32 bytes of hex".to_string())
}

/// The verifier key of a log key seed.
pub fn verifier(seed: &str, origin: &str) -> R<String> {
    Ok(Signer::new(origin, &seed32(seed)?).verifier())
}

#[derive(Deserialize)]
struct Named {
    #[serde(alias = "poll")]
    id: u32,
    size: u64,
    root: String,
}

#[derive(Deserialize)]
struct CheckpointJ {
    origin: String,
    size: u64,
    root: String,
    index: u64,
    time: u64,
    #[serde(default)]
    registries: Vec<Named>,
    #[serde(default)]
    ballots: Vec<Named>,
    #[serde(default)]
    mirror: Option<String>,
}

/// Signs a checkpoint (the JSON `verify_note` returns) with a log key seed.
pub fn sign_checkpoint(seed: &str, checkpoint_json: &str) -> R<String> {
    let c: CheckpointJ = serde_json::from_str(checkpoint_json).map_err(err)?;
    let root: [u8; 32] = STANDARD.decode(&c.root).ok().and_then(|b| b.try_into().ok()).ok_or("root: 32 bytes of base64")?;
    let named = |l: Vec<Named>| -> R<Vec<(u32, u64, Fr)>> { l.into_iter().map(|n| Ok((n.id, n.size, fr(&n.root)?))).collect() };
    let cp = Checkpoint {
        origin: c.origin.clone(),
        size: c.size,
        root,
        index: c.index,
        time: c.time,
        registries: named(c.registries)?,
        ballots: named(c.ballots)?,
        mirror: c.mirror,
    };
    Ok(Signer::new(&c.origin, &seed32(seed)?).sign(&cp.text()))
}

/// A single decrypter's keys from a seed.
pub fn decrypter(seed: &str) -> R<String> {
    let k = DecrypterKeys::generate(&mut ChaCha20Rng::from_seed(seed32(seed)?));
    serde_json::to_string(&k).map_err(err)
}

/// The Ed25519 public key of a seed.
pub fn ed25519_public(seed: &str) -> R<String> {
    Ok(sig::ed25519_public(&seed32(seed)?))
}

#[derive(Deserialize)]
struct TallyReq {
    poll: isoloir_proto::body::PollSetup,
    upto: u64,
    checkpoint: u64,
    #[serde(rename = "final")]
    is_final: bool,
    /// The counted ballots' bodies.
    ballots: Vec<String>,
    sk: String,
    sign_seed: String,
    seed: String,
}

/// The tally a single decrypter publishes over the ballots given (the
/// counted ones), as `isoloir_proto::tally::build_elgamal` builds it.
pub fn build_tally(req_json: &str) -> R<String> {
    let r: TallyReq = serde_json::from_str(req_json).map_err(err)?;
    let v = api::variant_named(&r.poll, None)?;
    let sk = grumpkin::scalar_from_hex(&r.sk).map_err(err)?;
    let mut rng = ChaCha20Rng::from_seed(seed32(&r.seed)?);
    let mut cts = Vec::new();
    for b in &r.ballots {
        let body::Body::Ballot(b) = body::decode(EntryKind::Ballot, b.as_bytes()).map_err(|e| e.as_str().to_string())? else { unreachable!() };
        cts.push(statement::ciphertexts(&b, &v).map_err(|e| e.as_str().to_string())?);
    }
    let n = cts.len() as u64;
    let mut values = vec![0i64; v.values()];
    let mut share = Share { trustee: 1, d: vec![], proofs: vec![] };
    let mut agg = vec![];
    if n > 0 {
        let mut sums = vec![];
        for j in 0..v.chunks() {
            let (a0, a1) = grumpkin::Ciphertext::sum(cts.iter().map(|c| &c[j]));
            let (a0, a1) = (a0.into_affine(), a1.into_affine());
            let (d, proof) = Dleq::prove(&sk, &a0, &tally::domain(r.poll.id, r.upto, j), &mut rng);
            let m = (Projective::from(a1) - d).into_affine();
            sums.push(pack::dlog_chunk(&m, n, kinds::value_bound(n)).ok_or("a chunk does not decrypt")?);
            share.d.push(grumpkin::to_hex(&d).map_err(err)?);
            share.proofs.push([grumpkin::scalar_to_hex(&proof.c), grumpkin::scalar_to_hex(&proof.z)]);
            agg.push([grumpkin::to_hex(&a0).map_err(err)?, grumpkin::to_hex(&a1).map_err(err)?]);
        }
        values = pack::values_of(&pack::unpack(&sums), v.values(), n);
    }
    let mut t = Tally {
        v: V1,
        poll: r.poll.id,
        upto: r.upto,
        is_final: r.is_final,
        values,
        counted: n,
        checkpoint: Some(r.checkpoint),
        aggregate: Some(agg),
        shares: Some(if n > 0 { vec![share] } else { vec![] }),
        beacon: None,
        void: None,
        sig: None,
    };
    t.sig = Some(sig::sign_tally(&seed32(&r.sign_seed)?, &canonical::to_vec(&t).map_err(err)?));
    canonical::to_string(&t).map_err(err)
}

/// A test drand chain: its group key and the beacon of a round.
pub fn tlock_chain(seed: u32, round: u32) -> String {
    let c = isoloir_decrypt::bls::TestChain::new(seed as u64);
    serde_json::json!({ "public_key": hex::encode(c.public_key()), "signature": hex::encode(c.sign(round as u64)) }).to_string()
}

/// Opens a tlock blob with a beacon signature: the payload text.
pub fn tlock_open(signature_hex: &str, blob_b64: &str) -> R<String> {
    let sig = hex::decode(signature_hex).map_err(err)?;
    let blob = isoloir_core::encoding::unb64(blob_b64).map_err(err)?;
    let p = isoloir_decrypt::tlock::open(&sig, &blob).ok_or("the blob does not open")?;
    String::from_utf8(p).map_err(err)
}
