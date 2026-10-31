//! The voter's side of isoloir, JSON in and JSON out: every function here
//! is a thin layer over isoloir-core, isoloir-proto and isoloir-decrypt,
//! so the browser and the server share one implementation of every rule.
//! `bind` exports them to JavaScript; the tests call them natively.

use crate::results;
use ark_ec::CurveGroup as _;
use isoloir_core::grumpkin::{self, Point};
use isoloir_core::tree::{self, Tree};
use isoloir_core::{canonical, encoding, field, poseidon2, tags, Fr};
use isoloir_proto::body::{self, Ballot, EntryKind, Encryption, PollSetup, Tally};
use isoloir_proto::client::{self, Member, Previous, Revoting};
use isoloir_proto::kinds::{self, Chain, Choice, Family, Variant};
use isoloir_proto::note::{Checkpoint, Verifier};
use isoloir_proto::{sig, statement, state};
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, RngCore, SeedableRng};
use serde::Deserialize;
use serde_json::{json, Value};
use std::cell::RefCell;

pub type R<T> = Result<T, String>;

pub(crate) fn err<E: ToString>(e: E) -> String {
    e.to_string()
}

/// The protocol version string.
pub fn protocol() -> String {
    isoloir_proto::PROTOCOL.to_string()
}

// ------------------------------------------------------------ encodings

pub(crate) fn fr(s: &str) -> R<Fr> {
    field::from_hex(s).map_err(|e| format!("{s}: {e}"))
}

pub(crate) fn hexf(x: &Fr) -> String {
    field::to_hex(x)
}

fn bytes32(s: &str, what: &str) -> R<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| format!("{what}: 32 bytes of hex"))
}

fn parse<T: serde::de::DeserializeOwned>(json: &str, what: &str) -> R<T> {
    serde_json::from_str(json).map_err(|e| format!("{what}: {e}"))
}

fn out(v: &Value) -> String {
    serde_json::to_string(v).expect("json")
}

/// The canonical text of any JSON text (SPEC §3).
pub fn canonical(json: &str) -> R<String> {
    let v: Value = parse(json, "json")?;
    canonical::to_string(&v).map_err(err)
}

/// `0x` + SHA-256 of a body's bytes, as acks and entries name it.
pub fn body_hash(body: &str) -> String {
    encoding::body_hash(body.as_bytes())
}

/// Decodes a body of a kind (canonical, of a known version, in its one
/// spelling) and returns it as JSON, or the reason it is refused.
pub fn decode_body(kind: &str, text: &str) -> R<String> {
    let k = EntryKind::parse(kind).ok_or_else(|| format!("unknown kind {kind}"))?;
    let b = body::decode(k, text.as_bytes()).map_err(|r| r.as_str().to_string())?;
    let v: Value = serde_json::from_slice(&b.encode()).map_err(err)?;
    Ok(out(&v))
}

// ------------------------------------------------------------ the voter

/// `H(T_id, registry, s)`.
pub fn leaf(registry: u32, s: &str) -> R<String> {
    Ok(hexf(&client::leaf(registry, &fr(s)?)))
}

/// `H(T_null, poll, s)`.
pub fn nullifier(poll: u32, s: &str) -> R<String> {
    Ok(hexf(&client::nullifier(poll, &fr(s)?)))
}

/// `H(T_bnull, poll, s, i)`.
pub fn ident(poll: u32, s: &str, i: u32) -> R<String> {
    Ok(hexf(&client::ident(poll, &fr(s)?, i)))
}

/// The ballot tree leaf `H(T_bleaf, ident, cmt)`.
pub fn delta_leaf(ident: &str, cmt: &str) -> R<String> {
    Ok(hexf(&state::delta_leaf(&fr(ident)?, &fr(cmt)?)))
}

/// A secret from 32 bytes reduced modulo r, never zero.
fn secret_of(b: &[u8; 32]) -> Fr {
    let x = field::from_bytes_mod(b);
    if x == Fr::from(0u64) { Fr::from(1u64) } else { x }
}

/// The voter secret from a passkey's 32-byte PRF output (SPEC §14):
/// `s = H(T_prf, lo, hi)`.
pub fn secret_from_prf(prf_hex: &str) -> R<String> {
    let b = bytes32(prf_hex, "prf")?;
    let (lo, hi) = field::limbs(&b);
    Ok(hexf(&poseidon2::hash(&[tags::prf(), lo, hi])))
}

/// The voter secret of 16 bytes of entropy (the 12 words):
/// `SHA-256("isoloir/1/words" ‖ entropy) mod r`, nonzero.
pub fn secret_from_entropy(entropy: &[u8]) -> R<String> {
    if entropy.len() != 16 {
        return Err("the words carry 16 bytes".into());
    }
    let mut m = b"isoloir/1/words".to_vec();
    m.extend_from_slice(entropy);
    Ok(hexf(&secret_of(&encoding::sha256(&m))))
}

/// The order of the relays for a key (SPEC §11.1): by
/// `H(T_relay, s, SHA-256(url) mod r)`, lowest first.
pub fn relay_ranking(s: &str, urls_json: &str) -> R<String> {
    let s = fr(s)?;
    let urls: Vec<String> = parse(urls_json, "urls")?;
    let mut scored: Vec<([u8; 32], String)> = urls
        .into_iter()
        .map(|u| {
            let h = field::from_bytes_mod(&encoding::sha256(u.as_bytes()));
            (field::to_bytes(&poseidon2::hash(&[tags::relay(), s, h])), u)
        })
        .collect();
    scored.sort();
    Ok(out(&json!(scored.into_iter().map(|(_, u)| u).collect::<Vec<_>>())))
}

// ------------------------------------------------------- registration

/// A fresh registration key: a secp256k1 secret, hex.
pub fn new_reg_secret() -> String {
    hex::encode(k256::schnorr::SigningKey::random(&mut OsRng).to_bytes())
}

fn reg_sk(sk_hex: &str) -> R<[u8; 32]> {
    let b = bytes32(sk_hex, "registration key")?;
    k256::schnorr::SigningKey::from_bytes(&b).map_err(|_| "not a secp256k1 secret")?;
    Ok(b)
}

/// The x-only public key of a registration secret, hex.
pub fn reg_pubkey(sk_hex: &str) -> R<String> {
    Ok(hex::encode(sig::xonly(&reg_sk(sk_hex)?)))
}

/// The custom data a passport proof binds: `H(T_reg, registry, R_lo, R_hi)`.
pub fn registration_binding(registry: u32, pubkey_hex: &str) -> R<String> {
    Ok(sig::registration_binding(registry, &bytes32(pubkey_hex, "public key")?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterReq {
    registry: u32,
    s: String,
    uid: String,
    proof: Value,
    proof_date: u64,
    reg_secret: String,
}

/// The signed `register` body (SPEC §6).
pub fn register_body(req_json: &str) -> R<String> {
    let r: RegisterReq = parse(req_json, "register request")?;
    let b = client::register_body(r.registry, &fr(&r.s)?, &r.uid, r.proof, r.proof_date, &reg_sk(&r.reg_secret)?);
    String::from_utf8(b).map_err(err)
}

/// Checks a `register` body's signature; returns its key.
pub fn verify_register(body: &str) -> R<String> {
    sig::verify_register(body.as_bytes()).map(hex::encode)
}

// ------------------------------------------------------------- kinds

pub(crate) fn choice_from(v: &Value) -> R<Choice> {
    let o = v.as_object().ok_or("a choice is {\"pick\": n|null} or {\"rank\": [...]}")?;
    match (o.get("pick"), o.get("rank"), o.len()) {
        (Some(p), None, 1) => {
            if p.is_null() {
                Ok(Choice::Pick(None))
            } else {
                let n = p.as_u64().filter(|n| *n <= u32::MAX as u64).ok_or("pick: a slot number")?;
                Ok(Choice::Pick(Some(n as u32)))
            }
        }
        (None, Some(r), 1) => {
            let r = r.as_array().ok_or("rank: an array")?;
            r.iter()
                .map(|x| x.as_u64().filter(|n| *n <= u32::MAX as u64).map(|n| n as u32).ok_or_else(|| "rank: slot numbers".to_string()))
                .collect::<R<Vec<u32>>>()
                .map(Choice::Rank)
        }
        _ => Err("a choice is {\"pick\": n|null} or {\"rank\": [...]}".into()),
    }
}

pub(crate) fn choice_json(c: &Choice) -> Value {
    match c {
        Choice::Pick(p) => json!({ "pick": p }),
        Choice::Rank(r) => json!({ "rank": r }),
    }
}

pub(crate) fn poll_of(poll_json: &str) -> R<PollSetup> {
    parse(poll_json, "poll")
}

pub(crate) fn variant_named(poll: &PollSetup, circuit: Option<&str>) -> R<Variant> {
    let name = circuit.unwrap_or(&poll.circuit.name);
    Variant::parse(name).ok_or_else(|| format!("circuit {name}: not a variant name"))
}

fn variant_json(v: &Variant) -> Value {
    json!({
        "name": v.name(),
        "family": match v.family { Family::Choice => "choice", Family::Ranked => "ranked", Family::RankedMargins => "rankedm" },
        "slots": v.slots,
        "enc": match v.enc { kinds::Enc::Elgamal => "elgamal", kinds::Enc::Tlock => "tlock" },
        "chain": match v.chain { Chain::Linked => "linked", Chain::Delta => "delta" },
        "depth": v.depth,
        "ballot_depth": v.ballot_depth,
        "values": v.values(),
        "chunks": v.chunks(),
    })
}

/// What a page needs to show a poll's ballot: the class, the slots, the
/// mask, the blank's slot, and the circuit variant.
pub fn kind_info(poll_json: &str) -> R<String> {
    let p = poll_of(poll_json)?;
    let v = variant_named(&p, None)?;
    let (options, blank, depth) = match &p.kind {
        body::KindSpec::Choice { options, blank } => (options.clone(), *blank, 1),
        body::KindSpec::Ranked { options, blank, depth, .. } => (options.clone(), *blank, (*depth).min(kinds::RANK_DEPTH)),
    };
    Ok(out(&json!({
        "class": match kinds::class(&p.kind) { kinds::Class::Single => "single", kinds::Class::Multiple => "multiple" },
        "slots": kinds::slots(&p.kind),
        "mask": kinds::mask(&p.kind),
        "options": options,
        "blank": blank,
        "blank_slot": if blank { Some(options.len()) } else { None },
        "rank_depth": depth,
        "revote": p.revote,
        "variant": variant_json(&v),
    })))
}

/// The values of a choice, or why it is not valid for the poll.
pub fn choice_values(poll_json: &str, choice_json_text: &str) -> R<String> {
    let p = poll_of(poll_json)?;
    let v = variant_named(&p, None)?;
    let c = choice_from(&parse(choice_json_text, "choice")?)?;
    Ok(out(&json!(kinds::values(&p.kind, &v, &c)?)))
}

// ------------------------------------------------------------ ballots

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberJ {
    root: String,
    path: Vec<String>,
    index: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviousJ {
    choice: Value,
    path: Vec<String>,
    index: u64,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RevotingJ {
    Linked {
        seq: u32,
    },
    Delta {
        i: u32,
        #[serde(default)]
        previous: Option<PreviousJ>,
        broot: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftReq {
    poll: PollSetup,
    setup_seq: u64,
    #[serde(default)]
    circuit: Option<String>,
    member: MemberJ,
    s: String,
    choice: Value,
    revoting: RevotingJ,
    /// 32 bytes of hex: a deterministic draft (tests). Absent: the
    /// system's randomness.
    #[serde(default)]
    seed: Option<String>,
}

fn rngs(seed: Option<&str>) -> R<(ChaCha20Rng, ChaCha20Rng)> {
    match seed {
        Some(s) => {
            let b = bytes32(s, "seed")?;
            let mut s2 = b.to_vec();
            s2.extend_from_slice(b"/seal");
            Ok((ChaCha20Rng::from_seed(b), ChaCha20Rng::from_seed(encoding::sha256(&s2))))
        }
        None => {
            let mut a = [0u8; 32];
            let mut b = [0u8; 32];
            OsRng.fill_bytes(&mut a);
            OsRng.fill_bytes(&mut b);
            Ok((ChaCha20Rng::from_seed(a), ChaCha20Rng::from_seed(b)))
        }
    }
}

type Sealer<'a> = &'a dyn Fn(&[u8]) -> R<Vec<u8>>;

fn frs(v: &[String]) -> R<Vec<Fr>> {
    v.iter().map(|x| fr(x)).collect()
}

/// Drafts a ballot (SPEC §9): `{body, inputs}`, the body without its
/// proof and the inputs the circuit executes on. A tlock poll's payload
/// is sealed to its round here.
pub fn draft_ballot(req_json: &str) -> R<String> {
    let r: DraftReq = parse(req_json, "draft request")?;
    let member = Member { root: fr(&r.member.root)?, path: frs(&r.member.path)?, index: r.member.index };
    let variant = match &r.circuit {
        Some(c) => Variant::parse(c).ok_or_else(|| format!("circuit {c}: not a variant name"))?,
        None => kinds::variant_of(&r.poll, member.path.len() as u32)?,
    };
    if member.path.len() != variant.depth as usize {
        return Err(format!("the path has {} levels, the circuit {}", member.path.len(), variant.depth));
    }
    let s = fr(&r.s)?;
    let choice = choice_from(&r.choice)?;
    let revoting = match r.revoting {
        RevotingJ::Linked { seq } => Revoting::Linked { seq },
        RevotingJ::Delta { i, previous, broot } => Revoting::Delta {
            i,
            previous: previous
                .map(|p| -> R<Previous> { Ok(Previous { choice: choice_from(&p.choice)?, path: frs(&p.path)?, index: p.index }) })
                .transpose()?,
            broot: fr(&broot)?,
        },
    };
    let (mut rng, seal_rng) = rngs(r.seed.as_deref())?;
    let seal_rng = RefCell::new(seal_rng);
    let tl = isoloir_decrypt::tlock::params(&r.poll.encryption);
    let sealer = |payload: &[u8]| -> R<Vec<u8>> {
        let (pk, round) = tl.as_ref().ok_or("not a tlock poll")?;
        isoloir_decrypt::tlock::seal(pk, *round, payload, &mut *seal_rng.borrow_mut())
    };
    let seal: Option<Sealer> = if tl.is_some() { Some(&sealer) } else { None };
    let d = client::draft(&r.poll, r.setup_seq, &variant, &member, &s, &choice, &revoting, seal, &mut rng)?;
    let body: Value = serde_json::to_value(&d.body).map_err(err)?;
    Ok(out(&json!({ "body": body, "inputs": Value::Object(d.inputs), "circuit": variant.name() })))
}

/// The body of a drafted ballot with its proof: the bytes to post.
pub fn finish_ballot(draft_body_json: &str, proof: &[u8]) -> R<String> {
    let mut b: Ballot = parse(draft_body_json, "ballot")?;
    b.proof = encoding::b64(proof);
    canonical::to_string(&b).map_err(err)
}

/// The public inputs of a ballot, rebuilt from its body and its poll as
/// the ingest does (SPEC §9.1): a check of what the prover returned.
pub fn public_inputs(body_text: &str, poll_json: &str) -> R<String> {
    let p = poll_of(poll_json)?;
    let v = variant_named(&p, None)?;
    let b = match body::decode(EntryKind::Ballot, body_text.as_bytes()).map_err(|r| r.as_str().to_string())? {
        body::Body::Ballot(b) => b,
        _ => unreachable!(),
    };
    let f = statement::inputs(&b, &p, &v).map_err(|r| r.as_str().to_string())?;
    Ok(out(&json!(f.iter().map(|x| format!("0x{}", hex::encode(x))).collect::<Vec<_>>())))
}

/// Finds a voter's delta chain in a poll's ballot tree (SPEC §7.4) from
/// the secret alone: the ballots `i = 0, 1, …` whose leaf the tree holds,
/// trying every choice of the kind. Returns the next `i` and the last
/// ballot found (its choice and position), so a voter who lost the
/// device's record can correct their ballot.
pub fn delta_recover(poll_json: &str, s: &str, leaves_json: &str) -> R<String> {
    let p = poll_of(poll_json)?;
    let v = variant_named(&p, None)?;
    if v.chain != Chain::Delta {
        return Err("not a delta poll".into());
    }
    let s = fr(s)?;
    let leaves: Vec<String> = parse(leaves_json, "leaves")?;
    let index: std::collections::HashMap<&str, usize> = leaves.iter().enumerate().map(|(i, l)| (l.as_str(), i)).collect();
    let candidates = all_choices(&p, &v);
    let mut last: Option<(u32, Choice, usize)> = None;
    let mut i = 0u32;
    'chain: loop {
        let id = client::ident(p.id, &s, i);
        for c in &candidates {
            let cmt = client::delta_cmt(&v, p.id, &s, i, c);
            let l = hexf(&state::delta_leaf(&id, &cmt));
            if let Some(pos) = index.get(l.as_str()) {
                last = Some((i, c.clone(), *pos));
                i += 1;
                continue 'chain;
            }
        }
        break;
    }
    Ok(out(&json!({
        "next": i,
        "previous": last.map(|(i, c, pos)| json!({ "i": i, "choice": choice_json(&c), "index": pos })),
    })))
}

/// Every valid choice of a poll (the empty one included).
fn all_choices(p: &PollSetup, v: &Variant) -> Vec<Choice> {
    let active = kinds::slots(&p.kind);
    let mut out = vec![client::no_choice(&p.kind)];
    match &p.kind {
        body::KindSpec::Choice { .. } => out.extend((0..active).map(|k| Choice::Pick(Some(k)))),
        body::KindSpec::Ranked { depth, .. } => {
            let d = (*depth).min(kinds::RANK_DEPTH) as usize;
            let mut stack: Vec<Vec<u32>> = vec![vec![]];
            while let Some(cur) = stack.pop() {
                if cur.len() == d {
                    continue;
                }
                for k in 0..active {
                    if cur.contains(&k) {
                        continue;
                    }
                    let mut n = cur.clone();
                    n.push(k);
                    let c = Choice::Rank(n.clone());
                    if kinds::values(&p.kind, v, &c).is_ok() {
                        out.push(c);
                        stack.push(n);
                    }
                }
            }
        }
    }
    out
}

// -------------------------------------------------------------- trees

fn tree_of(depth: u32, leaves_json: &str) -> R<Tree> {
    if !(1..=32).contains(&depth) {
        return Err(format!("depth {depth}"));
    }
    let leaves: Vec<String> = parse(leaves_json, "leaves")?;
    let mut t = Tree::new(depth as usize);
    for l in &leaves {
        t.push(fr(l)?).map_err(err)?;
    }
    Ok(t)
}

/// The root of a tree of fixed depth holding these leaves.
pub fn tree_root(depth: u32, leaves_json: &str) -> R<String> {
    Ok(hexf(&tree_of(depth, leaves_json)?.root()))
}

/// The root and the siblings of a position, from the leaf up.
pub fn tree_path(depth: u32, leaves_json: &str, position: u32) -> R<String> {
    let t = tree_of(depth, leaves_json)?;
    let path = t.path(position as usize).map_err(err)?;
    Ok(out(&json!({
        "root": hexf(&t.root()),
        "leaf": hexf(&t.leaf(position as usize).expect("in the tree")),
        "index": position,
        "path": path.iter().map(hexf).collect::<Vec<_>>(),
    })))
}

/// The root a leaf, a position and its siblings lead to.
pub fn root_of(leaf: &str, position: u32, path_json: &str) -> R<String> {
    let path: Vec<String> = parse(path_json, "path")?;
    Ok(hexf(&tree::root_of(&fr(leaf)?, position as u64, &frs(&path)?)))
}

// --------------------------------------------------------- checkpoints

pub(crate) fn checkpoint_json(c: &Checkpoint) -> Value {
    use base64::Engine;
    json!({
        "origin": c.origin,
        "size": c.size,
        "root": base64::engine::general_purpose::STANDARD.encode(c.root),
        "index": c.index,
        "time": c.time,
        "registries": c.registries.iter().map(|(id, n, r)| json!({ "id": id, "size": n, "root": hexf(r) })).collect::<Vec<_>>(),
        "ballots": c.ballots.iter().map(|(id, n, r)| json!({ "poll": id, "size": n, "root": hexf(r) })).collect::<Vec<_>>(),
        "mirror": c.mirror,
    })
}

/// Verifies a checkpoint note under the pinned verifier key and parses
/// it; the note's origin must be the key's name.
pub fn verify_note(note: &str, verifier_key: &str) -> R<String> {
    let v = Verifier::parse(verifier_key)?;
    let text = v.open(note)?;
    let c = Checkpoint::parse(text)?;
    if c.origin != v.name {
        return Err(format!("the note is of {}, the key of {}", c.origin, v.name));
    }
    Ok(out(&checkpoint_json(&c)))
}

// -------------------------------------------------------------- nostr

/// Signs a Nostr event. An empty `sk_hex` signs with a fresh throwaway key
/// (SPEC §11.1).
pub fn sign_event(sk_hex: &str, created_at: u64, kind: u32, tags_json: &str, content: &str) -> R<String> {
    let sk = if sk_hex.is_empty() { bytes32(&new_reg_secret(), "key")? } else { reg_sk(sk_hex)? };
    let tags: Vec<Vec<String>> = parse(tags_json, "tags")?;
    let e = sig::Event::sign(&sk, created_at, kind, tags, content.to_string());
    serde_json::to_string(&e).map_err(err)
}

/// Whether an event's id and signature hold.
pub fn verify_event(event_json: &str) -> bool {
    serde_json::from_str::<sig::Event>(event_json).map(|e| e.verify()).unwrap_or(false)
}

/// Decodes an ack's content (SPEC §11.2).
pub fn decode_ack(content: &str) -> R<String> {
    let a = body::decode_ack(content.as_bytes()).map_err(|r| r.as_str().to_string())?;
    serde_json::to_string(&a).map_err(err)
}

/// Reads an ack event: of kind 7102, signed by the ingest's key, its
/// content an ack. Returns the ack.
pub fn read_ack(event_json: &str, ingest_pubkey: &str) -> R<String> {
    let e: sig::Event = parse(event_json, "event")?;
    if e.kind != crate::KIND_ACK {
        return Err(format!("kind {}: not an ack", e.kind));
    }
    if e.pubkey != ingest_pubkey {
        return Err("not signed by the ingest".into());
    }
    if !e.verify() {
        return Err("the event's signature does not verify".into());
    }
    let a = body::decode_ack(e.content.as_bytes()).map_err(|r| r.as_str().to_string())?;
    if e.tag("e") != Some(a.of.as_str()) {
        return Err("the ack's e tag is not the event it acknowledges".into());
    }
    serde_json::to_string(&a).map_err(err)
}

/// The body of a complaint (SPEC §11.3): the signed ack and the body it
/// acknowledged, canonical.
pub fn complaint_body(ack_event_json: &str, body_text: &str) -> R<String> {
    let e: sig::Event = parse(ack_event_json, "ack event")?;
    let b = canonical::parse(body_text.as_bytes()).map_err(|_| "the body is not canonical JSON")?;
    canonical::to_string(&json!({ "v": 1, "ack": e, "body": b })).map_err(err)
}

// ------------------------------------------------------------ tallies

pub(crate) fn tally_of(text: &str) -> R<Tally> {
    match body::decode(EntryKind::Tally, text.as_bytes()).map_err(|r| format!("tally: {}", r.as_str()))? {
        body::Body::Tally(t) => Ok(t),
        _ => unreachable!(),
    }
}

/// Verifies a tally from itself (SPEC §10.3): for ElGamal, the decrypter's
/// signature, the shares' proofs and the values against the aggregates the
/// tally names (the auditor checks that they are the log's); for tlock,
/// the beacon (the openings need the log). Returns `{ok, checked, error,
/// tally, results}`, `results` mapped to the poll's kind.
pub fn verify_tally(poll_json: &str, tally_text: &str) -> R<String> {
    let p = poll_of(poll_json)?;
    let v = variant_named(&p, None)?;
    let t = tally_of(tally_text)?;
    if t.poll != p.id {
        return Err(format!("a tally of poll {}, not {}", t.poll, p.id));
    }
    let (checked, verdict) = match &p.encryption {
        Encryption::Elgamal { .. } => ("shares", check_elgamal(&p, &v, &t, tally_text)),
        Encryption::Tlock { .. } => {
            use isoloir_proto::tally::Tlock as _;
            let ok = match &t.beacon {
                Some(b) => isoloir_decrypt::tlock::DrandTlock.verify_beacon(&p.encryption, b),
                None => false,
            };
            ("beacon", if ok { Ok(()) } else { Err("the beacon does not verify".to_string()) })
        }
    };
    let res = results::of(&p, &v, &t.values, t.counted)?;
    let tv: Value = serde_json::from_str(tally_text).map_err(err)?;
    Ok(out(&json!({
        "ok": verdict.is_ok(),
        "checked": checked,
        "error": verdict.err(),
        "tally": tv,
        "results": res,
    })))
}

fn check_elgamal(p: &PollSetup, v: &Variant, t: &Tally, text: &str) -> R<()> {
    let agg = t.aggregate.as_ref().ok_or("no aggregate")?;
    let agg: Vec<(Point, Point)> = agg
        .iter()
        .map(|[a, b]| Ok((grumpkin::from_hex(a).map_err(err)?, grumpkin::from_hex(b).map_err(err)?)))
        .collect::<R<_>>()?;
    isoloir_proto::tally::verify_shares(&p.encryption, t, text.as_bytes(), v.values(), v.chunks(), &agg)
}

/// The results of a vector of values, mapped to the poll's kind.
pub fn tally_results(poll_json: &str, values_json: &str, counted: u64) -> R<String> {
    let p = poll_of(poll_json)?;
    let v = variant_named(&p, None)?;
    let values: Vec<i64> = parse(values_json, "values")?;
    Ok(out(&results::of(&p, &v, &values, counted)?))
}

/// The sum of ElGamal ciphertext chunks (an auditor's aggregate, useful
/// to check a tally's against ballots one holds).
pub fn aggregate(cts_json: &str) -> R<String> {
    let cts: Vec<Vec<[String; 2]>> = parse(cts_json, "ciphertexts")?;
    let chunks = cts.first().map(|c| c.len()).unwrap_or(0);
    let mut sums = Vec::with_capacity(chunks);
    for j in 0..chunks {
        let mut list = Vec::with_capacity(cts.len());
        for c in &cts {
            let [a, b] = c.get(j).ok_or("ballots of different sizes")?;
            list.push(grumpkin::Ciphertext { c0: grumpkin::from_hex(a).map_err(err)?, c1: grumpkin::from_hex(b).map_err(err)? });
        }
        let (a0, a1) = grumpkin::Ciphertext::sum(list.iter());
        sums.push([grumpkin::to_hex(&a0.into_affine()).map_err(err)?, grumpkin::to_hex(&a1.into_affine()).map_err(err)?]);
    }
    Ok(out(&json!(sums)))
}
