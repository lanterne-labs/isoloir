//! The voter's side (SPEC §6, §7.4, §9): the leaf, the pseudonyms, the
//! registration body, and the draft of a ballot: its body without the
//! proof and the inputs the circuit executes on (noir_js in the browser,
//! nargo in tests and tools). Shared with the browser through WebAssembly.

use crate::body::{Ballot, Encryption, KindSpec, PollSetup, Register, Revote, V1};
use crate::kinds::{self, Chain, Choice, Enc, Family, Variant};
use crate::{sig, tally};
use ark_ec::AffineRepr;
use isoloir_core::grumpkin::{self, Ciphertext};
use isoloir_core::{canonical, encoding, field, pack, poseidon2, tags, Fr};
use rand_core::{CryptoRng, RngCore};
use serde_json::{json, Map, Value};

/// `H(T_id, registry, s)`.
pub fn leaf(registry: u32, s: &Fr) -> Fr {
    poseidon2::hash(&[tags::id(), Fr::from(registry as u64), *s])
}

/// `H(T_null, poll, s)`.
pub fn nullifier(poll: u32, s: &Fr) -> Fr {
    poseidon2::hash(&[tags::null(), Fr::from(poll as u64), *s])
}

/// `H(T_bnull, poll, s, i)`.
pub fn ident(poll: u32, s: &Fr, i: u32) -> Fr {
    poseidon2::hash(&[tags::bnull(), Fr::from(poll as u64), *s, Fr::from(i as u64)])
}

/// `H(T_salt, poll, s, i)`.
pub fn salt(poll: u32, s: &Fr, i: u32) -> Fr {
    poseidon2::hash(&[tags::salt(), Fr::from(poll as u64), *s, Fr::from(i as u64)])
}

/// The commitment of ballot i's choice in the delta chain.
pub fn delta_cmt(variant: &Variant, poll: u32, s: &Fr, i: u32, choice: &Choice) -> Fr {
    poseidon2::hash(&[tags::cmt(), salt(poll, s, i), kinds::choice_hash(variant, choice)])
}

/// A registration body, signed by the registration key `reg_sk` the
/// passport proof bound.
pub fn register_body(registry: u32, s: &Fr, uid: &str, proof: Value, proof_date: u64, reg_sk: &[u8; 32]) -> Vec<u8> {
    let mut r = Register {
        v: V1,
        registry,
        id: field::to_hex(&leaf(registry, s)),
        uid: uid.to_string(),
        proof,
        proof_date,
        key: hex::encode(sig::xonly(reg_sk)),
        sig: String::new(),
    };
    let mut unsigned = serde_json::to_value(&r).expect("json");
    unsigned.as_object_mut().expect("object").remove("sig");
    r.sig = sig::sign_register(reg_sk, &canonical::to_vec(&unsigned).expect("canonical"));
    canonical::to_vec(&r).expect("canonical")
}

/// The voter's place in the registry tree, at a checkpoint root.
#[derive(Clone, Debug)]
pub struct Member {
    pub root: Fr,
    pub path: Vec<Fr>,
    pub index: u64,
}

/// The previous ballot of a delta chain: its choice and its place in the
/// ballot tree at a checkpoint root.
#[derive(Clone, Debug)]
pub struct Previous {
    pub choice: Choice,
    pub path: Vec<Fr>,
    pub index: u64,
}

/// Where the ballot stands among the voter's ballots.
#[derive(Clone, Debug)]
pub enum Revoting {
    /// None and linked polls: the sequence number (0 first).
    Linked { seq: u32 },
    /// Delta polls: the ballot's number, the previous ballot (none for
    /// the first), and a ballot tree root from a checkpoint (it must hold
    /// the previous ballot; any fresh one for the first).
    Delta { i: u32, previous: Option<Previous>, broot: Fr },
}

/// A ballot ready to prove: its body (proof empty) and the circuit's
/// inputs.
#[derive(Clone, Debug)]
pub struct Draft {
    pub body: Ballot,
    pub inputs: Map<String, Value>,
}

impl Draft {
    /// The body with its proof.
    pub fn finish(mut self, proof: &[u8]) -> Vec<u8> {
        self.body.proof = encoding::b64(proof);
        canonical::to_vec(&self.body).expect("canonical")
    }
}

fn hexf(x: &Fr) -> Value {
    Value::String(field::to_hex(x))
}

fn choice_inputs(variant: &Variant, choice: &Choice, prefix: &str, m: &mut Map<String, Value>) -> Result<(), String> {
    match (variant.family, choice) {
        (Family::Choice, Choice::Pick(p)) => {
            m.insert(format!("{prefix}pick"), json!(p.unwrap_or(variant.slots)));
        }
        (Family::Ranked | Family::RankedMargins, Choice::Rank(r)) => {
            let mut slots = r.clone();
            slots.resize(kinds::RANK_DEPTH as usize, 0);
            m.insert(format!("{prefix}len"), json!(r.len()));
            m.insert(format!("{prefix}slots"), json!(slots));
        }
        _ => return Err("the choice is not of the poll's kind".into()),
    }
    Ok(())
}

/// The empty choice of a kind (the "old" choice of a first delta ballot).
pub fn no_choice(kind: &KindSpec) -> Choice {
    match kind {
        KindSpec::Choice { .. } => Choice::Pick(None),
        KindSpec::Ranked { .. } => Choice::Rank(vec![]),
    }
}

/// A sealer of tlock payloads (isoloir-decrypt).
pub type Seal<'a> = &'a dyn Fn(&[u8]) -> Result<Vec<u8>, String>;

/// Drafts a ballot. `seal` time-locks a tlock payload (isoloir-decrypt).
#[allow(clippy::too_many_arguments)]
pub fn draft<R: RngCore + CryptoRng>(
    poll: &PollSetup,
    setup_seq: u64,
    variant: &Variant,
    member: &Member,
    s: &Fr,
    choice: &Choice,
    revoting: &Revoting,
    seal: Option<Seal>,
    rng: &mut R,
) -> Result<Draft, String> {
    let new_values = kinds::values(&poll.kind, variant, choice)?;
    let mut m = Map::new();
    let mut body = Ballot {
        v: V1,
        poll: poll.id,
        setup: setup_seq,
        root: field::to_hex(&member.root),
        nullifier: None,
        seq: None,
        ident: None,
        broot: None,
        cmt: None,
        ct: None,
        vcmt: None,
        blob: None,
        proof: String::new(),
    };
    m.insert("registry".into(), hexf(&Fr::from(poll.registry as u64)));
    m.insert("poll".into(), hexf(&Fr::from(poll.id as u64)));
    m.insert("setup".into(), hexf(&Fr::from(setup_seq)));
    m.insert("mask".into(), json!(kinds::mask(&poll.kind)));
    if variant.family != Family::Choice {
        m.insert("blank".into(), json!(kinds::blank_slot(&poll.kind, variant.slots)));
    }
    m.insert("root".into(), hexf(&member.root));
    m.insert("s".into(), hexf(s));
    m.insert("path".into(), Value::Array(member.path.iter().map(hexf).collect()));
    m.insert("index".into(), json!(member.index));
    choice_inputs(variant, choice, "", &mut m)?;
    let values = match (variant.chain, revoting) {
        (Chain::Linked, Revoting::Linked { seq }) => {
            if poll.revote == Revote::None && *seq != 0 {
                return Err("one ballot per voter in this poll".into());
            }
            let n = nullifier(poll.id, s);
            body.nullifier = Some(field::to_hex(&n));
            body.seq = Some(*seq);
            m.insert("nullifier".into(), hexf(&n));
            m.insert("seq".into(), json!(seq));
            new_values
        }
        (Chain::Delta, Revoting::Delta { i, previous, broot }) => {
            let id = ident(poll.id, s, *i);
            let c = delta_cmt(variant, poll.id, s, *i, choice);
            body.ident = Some(field::to_hex(&id));
            body.broot = Some(field::to_hex(broot));
            body.cmt = Some(field::to_hex(&c));
            m.insert("ident".into(), hexf(&id));
            m.insert("broot".into(), hexf(broot));
            m.insert("cmt".into(), hexf(&c));
            m.insert("i".into(), json!(i));
            let bd = variant.ballot_depth.expect("a delta variant has a ballot depth") as usize;
            let (old_choice, old_values, bpath, bindex) = match (i, previous) {
                (0, None) => (no_choice(&poll.kind), None, vec![Fr::from(0u64); bd], 0),
                (i, Some(p)) if *i > 0 => {
                    if p.path.len() != bd {
                        return Err("the previous ballot's path has the wrong depth".into());
                    }
                    (p.choice.clone(), Some(kinds::values(&poll.kind, variant, &p.choice)?), p.path.clone(), p.index)
                }
                _ => return Err("a first ballot has no previous one, a later one has".into()),
            };
            choice_inputs(variant, &old_choice, "old_", &mut m)?;
            m.insert("bpath".into(), Value::Array(bpath.iter().map(hexf).collect()));
            m.insert("bindex".into(), json!(bindex));
            kinds::correction(&new_values, old_values.as_deref())
        }
        _ => return Err("the re-vote mode is not the poll's".into()),
    };
    match (&poll.encryption, variant.enc) {
        (Encryption::Elgamal { pk, .. }, Enc::Elgamal) => {
            let pk = grumpkin::from_hex(pk).map_err(|e| e.to_string())?;
            let (x, y) = pk.xy().ok_or("pk at infinity")?;
            m.insert("pk_x".into(), hexf(&x));
            m.insert("pk_y".into(), hexf(&y));
            let chunks = pack::pack(&values).map_err(|e| e.to_string())?;
            let rho: Vec<Fr> = chunks.iter().map(|_| grumpkin::random_fr(rng)).collect();
            let ct: Vec<[String; 2]> = chunks
                .iter()
                .zip(&rho)
                .map(|(c, r)| {
                    let e = Ciphertext::encrypt(&pk, c, r);
                    [grumpkin::to_hex(&e.c0).expect("finite"), grumpkin::to_hex(&e.c1).expect("finite")]
                })
                .collect();
            body.ct = Some(ct);
            m.insert("rho".into(), Value::Array(rho.iter().map(hexf).collect()));
        }
        (Encryption::Tlock { .. }, Enc::Tlock) => {
            let seal = seal.ok_or("a tlock poll needs a sealer")?;
            let salt = grumpkin::random_fr(rng);
            let vcmt = tally::value_commitment(&salt, &values);
            let payload = canonical::to_vec(&tally::Payload { salt: field::to_hex(&salt), values: values.clone() }).map_err(|e| e.to_string())?;
            let blob = seal(&payload)?;
            body.vcmt = Some(field::to_hex(&vcmt));
            body.blob = Some(encoding::b64(&blob));
            m.insert("vcmt".into(), hexf(&vcmt));
            m.insert("bhash".into(), hexf(&crate::statement::blob_hash(&blob)));
            m.insert("salt".into(), hexf(&salt));
        }
        _ => return Err("the encryption is not the poll's".into()),
    }
    Ok(Draft { body, inputs: m })
}
