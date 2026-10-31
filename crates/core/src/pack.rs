//! The packing of a ballot's values into chunks (SPEC §7.1).
//!
//! A value is a small signed integer, `|v| ≤ OFFSET`; it is written as the
//! digit `v + OFFSET ≥ 0`, P digits per chunk: `chunk = Σ d_k·2^(32k)`.
//! P is 2 where the aggregate is decrypted (threshold decryption: a
//! two-digit discrete logarithm), 7 where a single decrypter opens each
//! ballot (a ballot's digits are in [0, 2·OFFSET]: one table lookup).
//! Plaintexts are non-negative integers below r and q, so that sums of
//! ciphertexts are sums of values. A sum over N ballots has digits
//! `Σv + 2N`, below 2^32 for N < 2^30 (so `depth ≤ 30`).

use crate::field::Fr;
use crate::grumpkin::{self, Point};
use crate::{Error, Result};
use std::collections::HashMap;

/// Bits per digit.
pub const DIGIT_BITS: u32 = 32;
/// The largest absolute value of one ballot's value (a correction of a
/// margin, −1 → +1, is 2).
pub const OFFSET: i64 = 2;
/// The number of chunks of n values, `per` to a chunk.
pub fn chunks(n: usize, per: usize) -> usize {
    n.div_ceil(per)
}

/// The digits of one ballot's values, padded to whole chunks.
pub fn digits(values: &[i64], per: usize) -> Result<Vec<u64>> {
    let mut d = Vec::with_capacity(chunks(values.len(), per) * per);
    for v in values {
        if v.abs() > OFFSET {
            return Err(Error::Range(format!("value {v}")));
        }
        d.push((v + OFFSET) as u64);
    }
    while d.len() % per != 0 {
        d.push(OFFSET as u64);
    }
    Ok(d)
}

/// The weight of digit k: 2^(32k).
fn weight(k: usize) -> Fr {
    Fr::from(1u128 << (DIGIT_BITS as usize * k.min(3))) * if k > 3 { Fr::from(1u128 << (DIGIT_BITS as usize * (k - 3))) } else { Fr::from(1u64) }
}

/// The chunk of its digits.
pub fn chunk_of(digits: &[u64]) -> Fr {
    digits.iter().enumerate().map(|(k, d)| Fr::from(*d) * weight(k)).sum()
}

/// The chunks of one ballot's values, as field elements.
pub fn pack(values: &[i64], per: usize) -> Result<Vec<Fr>> {
    Ok(digits(values, per)?.chunks(per).map(chunk_of).collect())
}

/// The values summed over `n` ballots, from the digit sums.
pub fn values_of(digit_sums: &[u64], n_values: usize, n_ballots: u64) -> Vec<i64> {
    digit_sums.iter().take(n_values).map(|d| *d as i64 - n_ballots as i64 * OFFSET).collect()
}

/// The two digit sums of a chunk point `M = chunk·G` over `n` ballots
/// (two values per chunk), each value sum bounded by `bound` in absolute
/// value: digits in `[n·OFFSET − bound, n·OFFSET + bound]`.
pub fn dlog_chunk(m: &Point, n: u64, bound: u64) -> Option<(u64, u64)> {
    DlogTable::new(n, bound).find(m)
}

/// The table of one tally's digit range (two values per chunk), built
/// once and used for every chunk.
pub struct DlogTable {
    lo: u64,
    hi: u64,
    table: BabyTable,
    step: grumpkin::Projective,
}

impl DlogTable {
    pub fn new(n: u64, bound: u64) -> Self {
        let center = n * OFFSET as u64;
        let lo = center.saturating_sub(bound);
        let hi = center + bound;
        DlogTable { lo, hi, table: BabyTable::new(lo, hi), step: grumpkin::mul_g(&weight(1)) }
    }

    /// The two digits of a chunk point.
    pub fn find(&self, m: &Point) -> Option<(u64, u64)> {
        use ark_ec::CurveGroup;
        let mut target = grumpkin::Projective::from(*m) - grumpkin::mul_g(&(Fr::from(self.lo) * weight(1)));
        for d1 in self.lo..=self.hi {
            if let Some(d0) = self.table.find(&target.into_affine()) {
                return Some((d0, d1));
            }
            target -= self.step;
        }
        None
    }
}

struct BabyTable {
    lo: u64,
    index: HashMap<[u8; 32], u32>,
}

impl BabyTable {
    fn new(lo: u64, hi: u64) -> Self {
        use ark_ec::{AffineRepr, CurveGroup};
        let n = (hi - lo + 1) as usize;
        let mut cur = grumpkin::mul_g(&Fr::from(lo));
        let g = grumpkin::generator();
        let mut proj = Vec::with_capacity(n);
        for _ in 0..n {
            proj.push(cur);
            cur += g;
        }
        let mut index = HashMap::with_capacity(n);
        for (i, p) in grumpkin::Projective::normalize_batch(&proj).iter().enumerate() {
            if !p.is_zero() {
                index.insert(grumpkin::encode(p).unwrap(), i as u32);
            }
        }
        BabyTable { lo, index }
    }

    fn find(&self, p: &Point) -> Option<u64> {
        use ark_ec::AffineRepr;
        if p.is_zero() {
            return (self.lo == 0).then_some(0);
        }
        self.index.get(&grumpkin::encode(p).ok()?).map(|i| self.lo + *i as u64)
    }
}

/// The digits of one ballot's chunk: every tuple of `per` digits in
/// `[0, 2·OFFSET]`, by its point. 5^7 entries for seven per chunk.
pub struct BallotTable {
    per: usize,
    index: HashMap<[u8; 32], Vec<u8>>,
}

impl BallotTable {
    pub fn new(per: usize) -> Self {
        use ark_ec::{AffineRepr, CurveGroup};
        let base = (2 * OFFSET + 1) as usize;
        let n = base.pow(per as u32);
        let gs: Vec<grumpkin::Projective> = (0..per).map(|k| grumpkin::mul_g(&weight(k))).collect();
        let mut proj = Vec::with_capacity(n);
        let mut tuples = Vec::with_capacity(n);
        for i in 0..n {
            let mut t = Vec::with_capacity(per);
            let mut x = i;
            let mut p = grumpkin::Projective::default();
            for g in &gs {
                let d = (x % base) as u8;
                x /= base;
                t.push(d);
                p += *g * grumpkin::Scalar::from(d as u64);
            }
            proj.push(p);
            tuples.push(t);
        }
        let mut index = HashMap::with_capacity(n);
        for (p, t) in grumpkin::Projective::normalize_batch(&proj).iter().zip(tuples) {
            if !p.is_zero() {
                index.insert(grumpkin::encode(p).unwrap(), t);
            }
        }
        BallotTable { per, index }
    }

    /// The digits of a chunk point, or None when it is not a ballot's.
    pub fn find(&self, m: &Point) -> Option<Vec<u64>> {
        use ark_ec::AffineRepr;
        if m.is_zero() {
            return Some(vec![0; self.per]);
        }
        self.index.get(&grumpkin::encode(m).ok()?).map(|t| t.iter().map(|d| *d as u64).collect())
    }
}

/// The digit sums of a set of ballots, unpacked from their chunk sums.
pub fn unpack(chunk_sums: &[(u64, u64)]) -> Vec<u64> {
    chunk_sums.iter().flat_map(|(a, b)| [*a, *b]).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::CurveGroup;

    #[test]
    fn digits_are_offset() {
        assert_eq!(digits(&[0, 1, -1], 2).unwrap(), vec![2, 3, 1, 2]);
        assert_eq!(digits(&[0, 1, -1], 7).unwrap(), vec![2, 3, 1, 2, 2, 2, 2]);
        assert!(digits(&[3], 2).is_err());
    }

    #[test]
    fn sums_decode() {
        // Three ballots over three values: (1,0,-1), (0,1,1), (1,1,0).
        let ballots = [[1i64, 0, -1], [0, 1, 1], [1, 1, 0]];
        // Sum chunk by chunk in the group.
        let mut chunk_points = vec![grumpkin::Projective::default(); chunks(3, 2)];
        for b in &ballots {
            for (j, c) in pack(b, 2).unwrap().iter().enumerate() {
                chunk_points[j] += grumpkin::mul_g(c);
            }
        }
        let mut digit_sums = Vec::new();
        for p in &chunk_points {
            let (d0, d1) = dlog_chunk(&p.into_affine(), 3, 3).unwrap();
            digit_sums.push((d0, d1));
        }
        assert_eq!(values_of(&unpack(&digit_sums), 3, 3), vec![2, 2, 0]);
    }

    #[test]
    fn out_of_bound_is_not_found() {
        let p = grumpkin::mul_g(&pack(&[2, 0], 2).unwrap()[0]).into_affine();
        assert!(dlog_chunk(&p, 1, 2).is_some());
        assert!(dlog_chunk(&p, 1, 1).is_none());
    }
}

#[cfg(test)]
mod ballot_table_tests {
    use super::*;
    use ark_ec::CurveGroup;

    #[test]
    fn seven_digits_of_a_ballot() {
        let t = BallotTable::new(7);
        for v in [[1i64, -1, 0, 2, -2, 1, 0], [0, 0, 0, 0, 0, 0, 0], [2, 2, 2, 2, 2, 2, 2]] {
            let c = pack(&v, 7).unwrap()[0];
            let m = grumpkin::mul_g(&c).into_affine();
            let d = t.find(&m).unwrap();
            assert_eq!(values_of(&d, 7, 1), v.to_vec());
        }
        // Not a ballot's chunk (a digit of 7).
        let m = grumpkin::mul_g(&chunk_of(&[7, 0, 0, 0, 0, 0, 0])).into_affine();
        assert!(t.find(&m).is_none());
    }
}
