//! Tallies (SPEC §10.3, §10.4): built by a decrypter, verified by the
//! ingest before it logs one and by every auditor and browser after.

use crate::body::{Beacon, Encryption, Share, Tally, V1};
use crate::kinds;
use crate::policy::Due;
use crate::sig;
use crate::state::{LoggedBallot, PollState};
use ark_ec::CurveGroup;
use isoloir_core::grumpkin::{self, Ciphertext, Dleq, Point, Projective, Scalar};
use isoloir_core::pack::{self, OFFSET};
use isoloir_core::{canonical, field, poseidon2, tags, Fr};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// The domain of the Chaum–Pedersen proof of chunk j (SPEC §10.3).
pub fn domain(poll: u32, upto: u64, j: usize) -> Vec<u8> {
    let mut d = b"isoloir/1/dleq".to_vec();
    d.extend_from_slice(&(poll as u64).to_be_bytes());
    d.extend_from_slice(&upto.to_be_bytes());
    d.extend_from_slice(&(j as u64).to_be_bytes());
    d
}

/// The aggregate of each chunk over the counted ballots.
pub fn aggregate(ballots: &[&LoggedBallot], chunks: usize) -> Vec<(Point, Point)> {
    (0..chunks)
        .map(|j| {
            let (a0, a1) = Ciphertext::sum(ballots.iter().map(|b| &b.ct[j]));
            (a0.into_affine(), a1.into_affine())
        })
        .collect()
}

fn digit_sums(values: &[i64], n: u64, chunks: usize) -> Result<Vec<(u64, u64)>, String> {
    let mut d: Vec<i128> = values.iter().map(|v| *v as i128 + n as i128 * OFFSET as i128).collect();
    while d.len() < chunks * pack::PER_CHUNK {
        d.push(n as i128 * OFFSET as i128);
    }
    if d.iter().any(|x| *x < 0 || *x >= 1i128 << pack::DIGIT_BITS) {
        return Err("a value out of range".into());
    }
    Ok(d.chunks(2).map(|c| (c[0] as u64, c[1] as u64)).collect())
}

/// Builds the tally a single decrypter publishes: decryption shares with
/// their proofs, the values found by discrete logarithm, the signature.
pub fn build_elgamal<R: RngCore + CryptoRng>(
    poll: &PollState,
    due: &Due,
    sk: &Scalar,
    sign_seed: &[u8; 32],
    rng: &mut R,
) -> Result<Tally, String> {
    let variant = poll.variant;
    let counted = poll.counted(due.upto);
    let n = counted.len() as u64;
    let mut values = vec![0i64; variant.values()];
    let mut share = Share { trustee: 1, d: vec![], proofs: vec![] };
    let agg = if n > 0 { aggregate(&counted, variant.chunks()) } else { vec![] };
    if n > 0 {
        let mut sums = Vec::new();
        let table = pack::DlogTable::new(n, kinds::value_bound(n));
        for (j, (a0, a1)) in agg.iter().enumerate() {
            let (d, proof) = Dleq::prove(sk, a0, &domain(poll.current().id, due.upto, j), rng);
            let m = (Projective::from(*a1) - d).into_affine();
            let (d0, d1) = table.find(&m).ok_or("a chunk does not decrypt within its bound")?;
            sums.push((d0, d1));
            share.d.push(grumpkin::to_hex(&d).map_err(|e| e.to_string())?);
            share.proofs.push([grumpkin::scalar_to_hex(&proof.c), grumpkin::scalar_to_hex(&proof.z)]);
        }
        values = pack::values_of(&pack::unpack(&sums), variant.values(), n);
    }
    let mut t = Tally {
        v: V1,
        poll: poll.current().id,
        upto: due.upto,
        is_final: due.is_final,
        values,
        counted: n,
        checkpoint: Some(due.checkpoint),
        aggregate: Some(agg.iter().map(|(a, b)| [grumpkin::to_hex(a).expect("finite"), grumpkin::to_hex(b).expect("finite")]).collect()),
        shares: Some(if n > 0 { vec![share] } else { vec![] }),
        beacon: None,
        void: None,
        sig: None,
    };
    t.sig = Some(sig::sign_tally(sign_seed, &canonical::to_vec(&t).map_err(|e| e.to_string())?));
    Ok(t)
}

fn check_due(t: &Tally, due: &Due) -> Result<(), String> {
    if t.poll != due.poll || t.upto != due.upto || t.is_final != due.is_final {
        return Err("not the tally due".into());
    }
    Ok(())
}

/// Verifies an ElGamal tally against the log (SPEC §10.3).
pub fn verify_elgamal(poll: &PollState, t: &Tally, body: &[u8], due: &Due) -> Result<(), String> {
    check_due(t, due)?;
    if t.checkpoint != Some(due.checkpoint) || t.beacon.is_some() || t.void.is_some() {
        return Err("the fields of an ElGamal tally".into());
    }
    // The aggregates the tally names are the log's.
    let counted_now = poll.counted(due.upto);
    if t.counted != counted_now.len() as u64 {
        return Err(format!("counted {} (the log: {})", t.counted, counted_now.len()));
    }
    let agg = if counted_now.is_empty() { vec![] } else { aggregate(&counted_now, poll.variant.chunks()) };
    let named: Vec<[String; 2]> = agg.iter().map(|(a, b)| [grumpkin::to_hex(a).unwrap_or_default(), grumpkin::to_hex(b).unwrap_or_default()]).collect();
    if t.aggregate.as_ref() != Some(&named) {
        return Err("the aggregates are not the log's".into());
    }
    verify_shares(&poll.current().encryption, t, body, poll.variant.values(), poll.variant.chunks(), &agg)
}

/// Checks an ElGamal tally against the aggregates it names: the
/// signature, the shares' proofs, the values. A browser runs this with
/// the aggregates from the tally itself; the auditor and the ingest with
/// the aggregates they recomputed from the log.
pub fn verify_shares(encryption: &Encryption, t: &Tally, body: &[u8], n_values: usize, chunks: usize, agg: &[(Point, Point)]) -> Result<(), String> {
    let Encryption::Elgamal { pk, decrypter } = encryption else { return Err("not an ElGamal poll".into()) };
    let crate::body::Decrypter::Single { sign_key } = decrypter;
    sig::verify_tally(sign_key, body)?;
    let pk = grumpkin::from_hex(pk).map_err(|e| e.to_string())?;
    let n = t.counted;
    if t.values.len() != n_values {
        return Err(format!("{} values", t.values.len()));
    }
    let shares = t.shares.as_ref().ok_or("no shares")?;
    if n == 0 {
        return if shares.is_empty() && agg.is_empty() && t.values.iter().all(|v| *v == 0) { Ok(()) } else { Err("no ballot: no share, zero values".into()) };
    }
    if agg.len() != chunks {
        return Err("one aggregate per chunk".into());
    }
    let [share] = shares.as_slice() else { return Err("one share: a single decrypter".into()) };
    if share.trustee != 1 || share.d.len() != chunks || share.proofs.len() != chunks {
        return Err("the share's shape".into());
    }
    let sums = digit_sums(&t.values, n, chunks)?;
    for (j, (a0, a1)) in agg.iter().enumerate() {
        let d = grumpkin::from_hex(&share.d[j]).map_err(|e| e.to_string())?;
        let proof = Dleq {
            c: grumpkin::scalar_from_hex(&share.proofs[j][0]).map_err(|e| e.to_string())?,
            z: grumpkin::scalar_from_hex(&share.proofs[j][1]).map_err(|e| e.to_string())?,
        };
        if !proof.verify(&pk, a0, &d, &domain(t.poll, t.upto, j)) {
            return Err(format!("chunk {j}: the decryption proof does not verify"));
        }
        let m = (Projective::from(*a1) - d).into_affine();
        let want = grumpkin::mul_g(&Fr::from(pack::chunk_of(sums[j].0, sums[j].1))).into_affine();
        if m != want {
            return Err(format!("chunk {j}: the values do not match the decryption"));
        }
    }
    Ok(())
}

/// What a tlock blob holds (SPEC §7.2).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub salt: String,
    pub values: Vec<i64>,
}

/// `vcmt = H(T_cmt, salt, H(values))`.
pub fn value_commitment(salt: &Fr, values: &[i64]) -> Fr {
    let vs: Vec<Fr> = values.iter().map(|v| field::from_i64(*v)).collect();
    poseidon2::hash(&[tags::cmt(), *salt, poseidon2::hash(&vs)])
}

/// Opening tlock blobs: the beacon check and the decryption, supplied by
/// the server and the auditor (isoloir-decrypt), not by the browser.
pub trait Tlock {
    /// Whether the beacon is the chain's signature for the poll's round.
    fn verify_beacon(&self, encryption: &Encryption, beacon: &Beacon) -> bool;
    /// The payload bytes of a blob, or None when it does not open.
    fn open(&self, beacon: &Beacon, blob: &[u8]) -> Option<Vec<u8>>;
}

/// The value of one opened ballot, or None when it is void.
fn opened(poll: &PollState, b: &LoggedBallot, beacon: &Beacon, opener: &dyn Tlock) -> Option<Vec<i64>> {
    let bytes = opener.open(beacon, b.blob.as_ref()?)?;
    let p: Payload = canonical::from_slice(&bytes).ok()?;
    let salt = field::from_hex(&p.salt).ok()?;
    if p.values.len() != poll.variant.values() || value_commitment(&salt, &p.values) != b.vcmt? {
        return None;
    }
    Some(p.values)
}

/// Builds a tlock poll's tally once the beacon is out.
pub fn build_tlock(poll: &PollState, due: &Due, beacon: &Beacon, opener: &dyn Tlock) -> Result<Tally, String> {
    if !due.is_final {
        return Err("a tlock poll has one tally, at the close".into());
    }
    if !opener.verify_beacon(&poll.current().encryption, beacon) {
        return Err("the beacon does not verify".into());
    }
    let mut values = vec![0i64; poll.variant.values()];
    let (mut counted, mut void) = (0u64, vec![]);
    for b in poll.counted(due.upto) {
        match opened(poll, b, beacon, opener) {
            Some(v) => {
                counted += 1;
                values.iter_mut().zip(v).for_each(|(a, x)| *a += x);
            }
            None => void.push(b.seq),
        }
    }
    Ok(Tally {
        v: V1,
        poll: poll.current().id,
        upto: due.upto,
        is_final: true,
        values,
        counted,
        checkpoint: Some(due.checkpoint),
        aggregate: None,
        shares: None,
        beacon: Some(beacon.clone()),
        void: Some(void),
        sig: None,
    })
}

/// Verifies a tlock tally by opening every counted ballot again.
pub fn verify_tlock(poll: &PollState, t: &Tally, due: &Due, opener: &dyn Tlock) -> Result<(), String> {
    check_due(t, due)?;
    let beacon = t.beacon.as_ref().ok_or("no beacon")?;
    let Encryption::Tlock { round, .. } = &poll.current().encryption else { return Err("not a tlock poll".into()) };
    if beacon.round != *round {
        return Err("the beacon of another round".into());
    }
    let want = build_tlock(poll, due, beacon, opener)?;
    if *t != want {
        return Err("the tally is not the opening of the log's ballots".into());
    }
    Ok(())
}
