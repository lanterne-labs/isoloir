//! A ballot's public inputs (SPEC §9.1), in the order of the circuits
//! (circuits/gen.py): rebuilt from the body, the poll and its variant,
//! never taken from the ballot's sender.

use crate::body::{Ballot, Encryption, PollSetup};
use crate::kinds::{self, Chain, Enc, Family, Variant};
use crate::Reason;
use ark_ec::AffineRepr;
use isoloir_core::{encoding, field, grumpkin, Fr};

/// The ciphertexts of an ElGamal ballot.
pub fn ciphertexts(b: &Ballot, variant: &Variant) -> Result<Vec<grumpkin::Ciphertext>, Reason> {
    let ct = b.ct.as_ref().ok_or(Reason::Malformed)?;
    if ct.len() != variant.chunks() {
        return Err(Reason::Malformed);
    }
    ct.iter()
        .map(|[c0, c1]| {
            Ok(grumpkin::Ciphertext {
                c0: grumpkin::from_hex(c0).map_err(|_| Reason::Malformed)?,
                c1: grumpkin::from_hex(c1).map_err(|_| Reason::Malformed)?,
            })
        })
        .collect()
}

/// `bhash`: SHA-256 of a blob, big-endian, modulo r.
pub fn blob_hash(blob: &[u8]) -> Fr {
    field::from_bytes_mod(&encoding::sha256(blob))
}

/// The largest tlock blob.
pub const BLOB_MAX: usize = 4096;

/// Checks that a ballot has exactly the fields of its poll's modes.
pub fn shape(b: &Ballot, variant: &Variant) -> Result<(), Reason> {
    let linked = b.nullifier.is_some() && b.seq.is_some() && b.ident.is_none() && b.broot.is_none() && b.cmt.is_none();
    let delta = b.nullifier.is_none() && b.seq.is_none() && b.ident.is_some() && b.broot.is_some() && b.cmt.is_some();
    let elgamal = b.ct.is_some() && b.vcmt.is_none() && b.blob.is_none();
    let tlock = b.ct.is_none() && b.vcmt.is_some() && b.blob.is_some();
    let ok = match (variant.chain, variant.enc) {
        (Chain::Linked, Enc::Elgamal) => linked && elgamal,
        (Chain::Linked, Enc::Tlock) => linked && tlock,
        (Chain::Delta, Enc::Elgamal) => delta && elgamal,
        (Chain::Delta, Enc::Tlock) => false,
    };
    if ok { Ok(()) } else { Err(Reason::Malformed) }
}

fn fe(s: &Option<String>) -> Result<Fr, Reason> {
    field::from_hex(s.as_deref().ok_or(Reason::Malformed)?).map_err(|_| Reason::Malformed)
}

/// The public inputs, as 32-byte big-endian fields.
pub fn inputs(b: &Ballot, poll: &PollSetup, variant: &Variant) -> Result<Vec<[u8; 32]>, Reason> {
    shape(b, variant)?;
    let mut f: Vec<Fr> = vec![
        Fr::from(poll.registry as u64),
        Fr::from(poll.id as u64),
        Fr::from(b.setup),
        Fr::from(kinds::mask(&poll.kind) as u64),
    ];
    if variant.family != Family::Choice {
        f.push(Fr::from(kinds::blank_slot(&poll.kind, variant.slots) as u64));
    }
    f.push(field::from_hex(&b.root).map_err(|_| Reason::Malformed)?);
    match variant.chain {
        Chain::Linked => {
            f.push(fe(&b.nullifier)?);
            f.push(Fr::from(b.seq.ok_or(Reason::Malformed)? as u64));
        }
        Chain::Delta => {
            f.push(fe(&b.ident)?);
            f.push(fe(&b.broot)?);
            f.push(fe(&b.cmt)?);
        }
    }
    match (&poll.encryption, variant.enc) {
        (Encryption::Elgamal { pk, .. }, Enc::Elgamal) => {
            let pk = grumpkin::from_hex(pk).map_err(|_| Reason::Malformed)?;
            let (x, y) = pk.xy().ok_or(Reason::Malformed)?;
            f.push(x);
            f.push(y);
            for c in ciphertexts(b, variant)? {
                for p in [c.c0, c.c1] {
                    let (x, y) = p.xy().ok_or(Reason::Malformed)?;
                    f.push(x);
                    f.push(y);
                }
            }
        }
        (Encryption::Tlock { .. }, Enc::Tlock) => {
            f.push(fe(&b.vcmt)?);
            let blob = encoding::unb64(b.blob.as_deref().ok_or(Reason::Malformed)?).map_err(|_| Reason::Malformed)?;
            if blob.is_empty() || blob.len() > BLOB_MAX {
                return Err(Reason::Malformed);
            }
            f.push(blob_hash(&blob));
        }
        _ => return Err(Reason::Malformed),
    }
    Ok(f.iter().map(field::to_bytes).collect())
}
