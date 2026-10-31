//! Poseidon2 of Barretenberg over F (SPEC §3): the permutation with t = 4,
//! 8 external and 56 internal rounds, and the sponge of noir-lang/poseidon
//! (rate 3, IV = len · 2^64 in the capacity, one permutation per full
//! block and one more when the input is empty or ends in a partial
//! block). It reproduces `Poseidon2::hash(input, len)` in Noir and
//! `poseidon2Hash` of bb.js.

use crate::field::Fr;
use crate::poseidon2_params::{DIAG_MINUS_ONE, ROUND_CONSTANTS};
use ark_ff::{AdditiveGroup, Field, PrimeField};
use std::sync::OnceLock;

const WIDTH: usize = 4;
const RATE: usize = 3;
const ROUNDS_F: usize = 8;
const ROUNDS_P: usize = 56;

struct Params {
    diag: [Fr; WIDTH],
    rc: Vec<[Fr; WIDTH]>,
}

fn parse(h: &str) -> Fr {
    Fr::from_be_bytes_mod_order(&hex::decode(h.trim_start_matches("0x")).expect("constant"))
}

fn params() -> &'static Params {
    static P: OnceLock<Params> = OnceLock::new();
    P.get_or_init(|| Params {
        diag: DIAG_MINUS_ONE.map(parse),
        rc: ROUND_CONSTANTS.iter().map(|r| r.map(parse)).collect(),
    })
}

fn sbox(x: &mut Fr) {
    let x2 = x.square();
    *x *= x2.square();
}

/// The circulant MDS matrix of Poseidon2 for t = 4.
fn external(s: &mut [Fr; WIDTH]) {
    let t0 = s[0] + s[1];
    let t1 = s[2] + s[3];
    let t2 = s[1].double() + t1;
    let t3 = s[3].double() + t0;
    let t4 = t1.double().double() + t3;
    let t5 = t0.double().double() + t2;
    let t6 = t3 + t5;
    let t7 = t2 + t4;
    *s = [t6, t5, t7, t4];
}

/// x_i ← (D_i − 1)·x_i + Σ x.
#[allow(clippy::needless_range_loop)]
fn internal(s: &mut [Fr; WIDTH], diag: &[Fr; WIDTH]) {
    let sum: Fr = s.iter().sum();
    for i in 0..WIDTH {
        s[i] = s[i] * diag[i] + sum;
    }
}

/// The Poseidon2 permutation on a state of four elements.
#[allow(clippy::needless_range_loop)]
pub fn permutation(mut s: [Fr; WIDTH]) -> [Fr; WIDTH] {
    let p = params();
    external(&mut s);
    for r in 0..ROUNDS_F / 2 {
        for i in 0..WIDTH {
            s[i] += p.rc[r][i];
            sbox(&mut s[i]);
        }
        external(&mut s);
    }
    for r in ROUNDS_F / 2..ROUNDS_F / 2 + ROUNDS_P {
        s[0] += p.rc[r][0];
        sbox(&mut s[0]);
        internal(&mut s, &p.diag);
    }
    for r in ROUNDS_F / 2 + ROUNDS_P..ROUNDS_F + ROUNDS_P {
        for i in 0..WIDTH {
            s[i] += p.rc[r][i];
            sbox(&mut s[i]);
        }
        external(&mut s);
    }
    s
}

/// H(inputs): the sponge, as the circuits' `Poseidon2::hash`.
pub fn hash(inputs: &[Fr]) -> Fr {
    let mut s = [Fr::from(0u64); WIDTH];
    s[RATE] = Fr::from(inputs.len() as u64) * Fr::from(1u128 << 64);
    let full = inputs.len() / RATE;
    for c in 0..full {
        for i in 0..RATE {
            s[i] += inputs[c * RATE + i];
        }
        s = permutation(s);
    }
    for (i, x) in inputs[full * RATE..].iter().enumerate() {
        s[i] += x;
    }
    if inputs.is_empty() || !inputs.len().is_multiple_of(RATE) {
        s = permutation(s);
    }
    s[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{from_hex, to_hex};
    use crate::poseidon2_params::{TEST_INPUT, TEST_OUTPUT};

    #[test]
    fn barretenberg_permutation_vector() {
        let out = permutation(TEST_INPUT.map(|h| from_hex(h).unwrap()));
        assert_eq!(out.map(|x| to_hex(&x)), TEST_OUTPUT);
    }

    /// The value Noir's `Poseidon2::hash([1, 2, 3], 3)` gives.
    #[test]
    fn matches_the_circuit() {
        let h = hash(&[Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)]);
        assert_eq!(to_hex(&h), "0x23864adb160dddf590f1d3303683ebcb914f828e2635f6e85a32f0a1aecd3dd8");
    }

    #[test]
    fn lengths_do_not_collide() {
        let mut seen = std::collections::HashSet::new();
        for n in 0..8u64 {
            let input: Vec<Fr> = (1..=n).map(Fr::from).collect();
            assert!(seen.insert(to_hex(&hash(&input))));
        }
    }
}
