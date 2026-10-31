//! The packing of a ballot's values into chunks (SPEC §7.1).
//!
//! A value is a small signed integer, `|v| ≤ OFFSET`; it is written as the
//! digit `v + OFFSET ≥ 0`, two digits per chunk:
//! `chunk = d0 + d1·2^32`. Plaintexts are non-negative integers far below
//! both r and q, so that sums of ciphertexts are sums of integers: a
//! "negative" field element would not be negative in the group, whose
//! order is q. A sum of N ballots' chunks has digits `Σv + N·OFFSET`, in
//! `[0, 2·OFFSET·N]`, below 2^32 for N < 2^30.

use crate::field::Fr;
use crate::grumpkin::{self, Point};
use crate::{Error, Result};

/// Bits per digit.
pub const DIGIT_BITS: u32 = 32;
/// Digits per chunk.
pub const PER_CHUNK: usize = 2;
/// The largest absolute value of one ballot's value (a correction of a
/// margin, −1 → +1, is 2).
pub const OFFSET: i64 = 2;

/// The number of chunks of n values.
pub fn chunks(n: usize) -> usize {
    n.div_ceil(PER_CHUNK)
}

/// The digits of one ballot's values, padded to whole chunks.
pub fn digits(values: &[i64]) -> Result<Vec<u64>> {
    let mut d = Vec::with_capacity(chunks(values.len()) * PER_CHUNK);
    for v in values {
        if v.abs() > OFFSET {
            return Err(Error::Range(format!("value {v}")));
        }
        d.push((v + OFFSET) as u64);
    }
    while d.len() % PER_CHUNK != 0 {
        d.push(OFFSET as u64);
    }
    Ok(d)
}

/// The chunk of two digits.
pub fn chunk_of(d0: u64, d1: u64) -> u128 {
    d0 as u128 + ((d1 as u128) << DIGIT_BITS)
}

/// The chunks of one ballot's values, as field elements.
pub fn pack(values: &[i64]) -> Result<Vec<Fr>> {
    Ok(digits(values)?.chunks(PER_CHUNK).map(|c| Fr::from(chunk_of(c[0], c[1]))).collect())
}

/// The values summed over `n` ballots, from the digit sums.
pub fn values_of(digit_sums: &[u64], n_values: usize, n_ballots: u64) -> Vec<i64> {
    digit_sums.iter().take(n_values).map(|d| *d as i64 - n_ballots as i64 * OFFSET).collect()
}

/// The two digit sums of a chunk point `M = chunk·G` over `n` ballots,
/// each value sum bounded by `bound` in absolute value: digits in
/// `[n·OFFSET − bound, n·OFFSET + bound]`. A baby-step table over the
/// first digit, reused for each candidate second digit: about
/// `2·bound + 1` table entries and as many additions.
pub fn dlog_chunk(m: &Point, n: u64, bound: u64) -> Option<(u64, u64)> {
    DlogTable::new(n, bound).find(m)
}

/// The table of one tally's digit range, built once and used for every
/// chunk (a ranked poll with margins has dozens).
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
        DlogTable { lo, hi, table: BabyTable::new(lo, hi), step: grumpkin::mul_g(&Fr::from(1u128 << DIGIT_BITS)) }
    }

    /// The two digits of a chunk point.
    pub fn find(&self, m: &Point) -> Option<(u64, u64)> {
        use ark_ec::CurveGroup;
        // target = M − d1·2^32·G, from d1 = lo up.
        let mut target = grumpkin::Projective::from(*m) - grumpkin::mul_g(&Fr::from((self.lo as u128) << DIGIT_BITS));
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
    index: std::collections::HashMap<[u8; 32], u32>,
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
        let mut index = std::collections::HashMap::with_capacity(n);
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
        assert_eq!(digits(&[0, 1, -1]).unwrap(), vec![2, 3, 1, 2]);
        assert!(digits(&[3]).is_err());
    }

    #[test]
    fn sums_decode() {
        // Three ballots over three values: (1,0,-1), (0,1,1), (1,1,0).
        let ballots = [[1i64, 0, -1], [0, 1, 1], [1, 1, 0]];
        // Sum chunk by chunk in the group.
        let mut chunk_points = vec![grumpkin::Projective::default(); chunks(3)];
        for b in &ballots {
            for (j, c) in pack(b).unwrap().iter().enumerate() {
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
        let p = grumpkin::mul_g(&pack(&[2, 0]).unwrap()[0]).into_affine();
        assert!(dlog_chunk(&p, 1, 2).is_some());
        assert!(dlog_chunk(&p, 1, 1).is_none());
    }
}
