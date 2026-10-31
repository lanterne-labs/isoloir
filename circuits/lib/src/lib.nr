// The ballot statement of isoloir (SPEC §9.1), as functions the circuits
// of each variant call: membership in a registry, the pseudonyms, the
// delta chain, the values of each kind, the packing, the encryption and
// the commitments. Every hash is Poseidon2 (SPEC §3) and starts with a tag.

use poseidon::poseidon2::Poseidon2;
use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul, multi_scalar_mul};

pub mod tags;
use tags::{T_BLEAF, T_BNULL, T_CMT, T_ID, T_NODE, T_NULL, T_SALT};

/// 2^32: the weight of a chunk's second digit (SPEC §7.1).
global DIGIT: Field = 4294967296;
/// The offset of a digit: a value v is written v + 2.
global OFFSET: Field = 2;

pub fn h2(a: Field, b: Field) -> Field {
    Poseidon2::hash([a, b], 2)
}

pub fn h3(a: Field, b: Field, c: Field) -> Field {
    Poseidon2::hash([a, b, c], 3)
}

pub fn h4(a: Field, b: Field, c: Field, d: Field) -> Field {
    Poseidon2::hash([a, b, c, d], 4)
}

/// H over an array (no tag: only ever inside a tagged hash).
pub fn hn<let N: u32>(xs: [Field; N]) -> Field {
    Poseidon2::hash(xs, N)
}

/// The root of the tree holding `leaf` at `index`, from its siblings; bit
/// i of the index (least significant first) says whether the node at
/// level i is a right child. The index must fit D bits.
pub fn merkle_root<let D: u32>(leaf: Field, path: [Field; D], index: u32) -> Field {
    let bits: [bool; D] = (index as Field).to_le_bits();
    let mut cur = leaf;
    for i in 0..D {
        let (l, r) = if bits[i] { (path[i], cur) } else { (cur, path[i]) };
        cur = h3(T_NODE, l, r);
    }
    cur
}

/// The voter is in the registry: `H(T_id, registry, s)` is under `root`.
pub fn member<let D: u32>(registry: Field, s: Field, path: [Field; D], index: u32, root: Field) {
    assert(merkle_root(h3(T_ID, registry, s), path, index) == root);
}

/// The linked pseudonym `H(T_null, poll, s)`.
pub fn nullifier(poll: Field, s: Field) -> Field {
    h3(T_NULL, poll, s)
}

/// The delta chain (SPEC §7.4) for ballot `i` of a voter: its identifier
/// and the commitment of its choice are the public `ident` and `cmt`;
/// for i > 0, the leaf of ballot i − 1, which commits to the old choice,
/// is under the ballot tree root `broot`. Returns whether there is an
/// old ballot.
pub fn chain<let BD: u32>(
    poll: Field,
    s: Field,
    i: u32,
    ident: Field,
    cmt: Field,
    new_choice: Field,
    old_choice: Field,
    bpath: [Field; BD],
    bindex: u32,
    broot: Field,
) -> bool {
    let fi = i as Field;
    assert(ident == h4(T_BNULL, poll, s, fi));
    assert(cmt == h3(T_CMT, h4(T_SALT, poll, s, fi), new_choice));
    let has_old = i > 0;
    if has_old {
        let pi = fi - 1;
        let leaf = h3(T_BLEAF, h4(T_BNULL, poll, s, pi), h3(T_CMT, h4(T_SALT, poll, s, pi), old_choice));
        assert(merkle_root(leaf, bpath, bindex) == broot);
    }
    has_old
}

/// The values of a single choice among M slots (SPEC §7.1): 1 for the
/// slot picked, `pick == M` for none (a withdrawal). The slot must be
/// active in the mask.
pub fn choice_values<let M: u32>(pick: u32, mask: u32) -> [Field; M] {
    assert(pick <= M);
    if pick < M {
        assert(((mask >> pick) & 1) == 1);
    }
    let mut v: [Field; M] = [0; M];
    for k in 0..M {
        if pick == k {
            v[k] = 1;
        }
    }
    v
}

/// The rank of each slot in a ranking of up to K distinct active slots,
/// K when unranked; the blank, when ranked, is last. Unused slots of the
/// ranking hold 0.
pub fn ranks<let M: u32, let K: u32>(len: u32, slots: [u32; K], mask: u32, blank: u32) -> [u32; M] {
    assert(len <= K);
    let mut pos: [u32; M] = [K; M];
    for k in 0..K {
        let o = slots[k];
        if k < len {
            assert(o < M);
            assert(((mask >> o) & 1) == 1);
            for j in 0..K {
                if j < k {
                    assert(slots[j] != o);
                }
            }
            if o == blank {
                assert(k == len - 1);
            }
            for c in 0..M {
                if o == c {
                    pos[c] = k;
                }
            }
        } else {
            assert(o == 0);
        }
    }
    pos
}

/// The values of a ranking: first[M] then ranked[M] (NV = 2M).
pub fn ranked_values<let M: u32, let K: u32, let NV: u32>(len: u32, slots: [u32; K], pos: [u32; M]) -> [Field; NV] {
    assert(NV == 2 * M);
    let mut v: [Field; NV] = [0; NV];
    for c in 0..M {
        if (len >= 1) & (slots[0] == c) {
            v[c] = 1;
        }
        if pos[c] < K {
            v[M + c] = 1;
        }
    }
    v
}

/// The values of a ranking with its pairwise margins: first[M], ranked[M],
/// then for i < j: +1 when i is ranked before j, −1 when after, else 0
/// (NV = 2M + M(M−1)/2).
pub fn ranked_margin_values<let M: u32, let K: u32, let NV: u32>(len: u32, slots: [u32; K], pos: [u32; M]) -> [Field; NV] {
    assert(NV == 2 * M + (M * (M - 1)) / 2);
    let mut v: [Field; NV] = [0; NV];
    for c in 0..M {
        if (len >= 1) & (slots[0] == c) {
            v[c] = 1;
        }
        if pos[c] < K {
            v[M + c] = 1;
        }
    }
    let mut n = 2 * M;
    for i in 0..M {
        for j in 0..M {
            if i < j {
                v[n] = if pos[i] < pos[j] {
                    1
                } else if pos[j] < pos[i] {
                    -1
                } else {
                    0
                };
                n += 1;
            }
        }
    }
    v
}

/// The correction new − old, or new when there is no old ballot.
pub fn correction<let NV: u32>(new: [Field; NV], old: [Field; NV], has_old: bool) -> [Field; NV] {
    let mut d = new;
    if has_old {
        for k in 0..NV {
            d[k] = new[k] - old[k];
        }
    }
    d
}

/// The chunks of values (SPEC §7.1): digits v + 2, P per chunk (2 or 7),
/// `Σ d_k·2^(32k)`; a missing digit is the digit of 0.
pub fn pack<let NV: u32, let NC: u32, let P: u32>(values: [Field; NV]) -> [Field; NC] {
    assert(NC == (NV + P - 1) / P);
    let mut p: [Field; NC] = [0; NC];
    for j in 0..NC {
        let mut acc: Field = 0;
        let mut w: Field = 1;
        for k in 0..P {
            let i = P * j + k;
            let d = if i < NV { values[i] + OFFSET } else { OFFSET };
            acc += d * w;
            w *= DIGIT;
        }
        p[j] = acc;
    }
    p
}

/// Exponential ElGamal of each chunk under PK with its own randomness:
/// `(ρ_j·G, m_j·G + ρ_j·PK)`, returned as c0.x, c0.y, c1.x, c1.y per chunk
/// (NO = 4·NC).
pub fn encrypt<let NC: u32, let NO: u32>(chunks: [Field; NC], rho: [Field; NC], pk_x: Field, pk_y: Field) -> [Field; NO] {
    assert(NO == 4 * NC);
    let pk = EmbeddedCurvePoint { x: pk_x, y: pk_y };
    let g = EmbeddedCurvePoint::generator();
    let mut out: [Field; NO] = [0; NO];
    for j in 0..NC {
        assert(rho[j] != 0);
        let r = EmbeddedCurveScalar::from_field(rho[j]);
        let c0 = fixed_base_scalar_mul(r);
        let c1 = multi_scalar_mul([g, pk], [EmbeddedCurveScalar::from_field(chunks[j]), r]);
        assert(!c0.is_infinite());
        assert(!c1.is_infinite());
        out[4 * j] = c0.x;
        out[4 * j + 1] = c0.y;
        out[4 * j + 2] = c1.x;
        out[4 * j + 3] = c1.y;
    }
    out
}

/// The commitment to values a tlock blob holds: `H(T_cmt, salt, H(values))`.
pub fn commit<let NV: u32>(salt: Field, values: [Field; NV]) -> Field {
    h3(T_CMT, salt, hn(values))
}

mod tests {
    use super::{choice_values, h3, merkle_root, pack, ranked_margin_values, ranks};
    use super::tags::T_NODE;

    #[test]
    fn poseidon2_vector() {
        assert(h3(1, 2, 3) == 0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8);
    }

    #[test]
    fn membership() {
        let mut zero: [Field; 4] = [0; 4];
        for i in 1..4 {
            zero[i] = h3(T_NODE, zero[i - 1], zero[i - 1]);
        }
        let mut path = zero;
        path[0] = 11;
        path[1] = h3(T_NODE, 33, 0);
        let root = merkle_root(22, path, 1);
        assert(merkle_root(22, path, 1) == root);
        assert(merkle_root(22, path, 0) != root);
    }

    #[test]
    fn a_choice() {
        let v = choice_values::<4>(2, 7);
        assert(v == [0, 0, 1, 0]);
        let none = choice_values::<4>(4, 7);
        assert(none == [0, 0, 0, 0]);
    }

    #[test(should_fail)]
    fn an_inactive_slot() {
        let _ = choice_values::<4>(3, 7);
    }

    #[test]
    fn a_ranking_and_its_margins() {
        // 3 slots, blank = 2: ranking 1 > 0.
        let pos = ranks::<3, 2>(2, [1, 0], 7, 2);
        let v: [Field; 9] = ranked_margin_values::<3, 2, 9>(2, [1, 0], pos);
        // first: slot 1; ranked: 0 and 1; margins (0,1) = −1, (0,2) = +1, (1,2) = +1.
        assert(v == [0, 1, 0, 1, 1, 0, -1, 1, 1]);
    }

    #[test(should_fail)]
    fn blank_must_be_last() {
        let _ = ranks::<3, 2>(2, [2, 0], 7, 2);
    }

    #[test(should_fail)]
    fn distinct_slots() {
        let _ = ranks::<3, 2>(2, [1, 1], 7, 2);
    }

    #[test]
    fn packing() {
        let p: [Field; 2] = pack::<3, 2, 2>([1, -1, 0]);
        assert(p[0] == 3 + 1 * 4294967296);
        assert(p[1] == 2 + 2 * 4294967296);
        let q: [Field; 1] = pack::<3, 1, 7>([1, -1, 0]);
        let w: Field = 4294967296;
        assert(q[0] == 3 + 1 * w + 2 * w * w + 2 * w * w * w + 2 * w * w * w * w + 2 * w * w * w * w * w + 2 * w * w * w * w * w * w);
    }
}
