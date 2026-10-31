//! The log (SPEC §4): RFC 6962 Merkle tree hashing over the leaves
//! `"isoloir/1\n" ‖ seq ‖ "\n" ‖ kind ‖ "\n" ‖ body`.

use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

/// The data of a leaf.
pub fn leaf_data(seq: u64, kind: &str, body: &[u8]) -> Vec<u8> {
    let mut d = format!("{}\n{seq}\n{kind}\n", crate::PROTOCOL).into_bytes();
    d.extend_from_slice(body);
    d
}

/// `SHA-256(0x00 ‖ data)`.
pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(data);
    h.finalize().into()
}

/// `SHA-256(0x01 ‖ l ‖ r)`.
pub fn node_hash(l: &Hash, r: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// The root of no leaves: `SHA-256("")`.
pub fn empty_root() -> Hash {
    Sha256::digest([]).into()
}

/// The RFC 6962 root of a list of leaf hashes, by its definition (tests
/// and audits of small ranges).
pub fn root_of(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = 1usize << (usize::BITS - 1 - (n - 1).leading_zeros());
            node_hash(&root_of(&leaves[..k]), &root_of(&leaves[k..]))
        }
    }
}

/// A log's hashes: every leaf hash, and the peaks of its perfect subtrees
/// so that the root is O(log n).
#[derive(Clone, Debug, Default)]
pub struct Log {
    leaves: Vec<Hash>,
    peaks: Vec<(u32, Hash)>,
}

impl Log {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    pub fn leaves(&self) -> &[Hash] {
        &self.leaves
    }

    /// Appends a leaf hash.
    pub fn push(&mut self, leaf: Hash) {
        self.leaves.push(leaf);
        let mut cur = (0u32, leaf);
        while let Some(&(h, l)) = self.peaks.last() {
            if h != cur.0 {
                break;
            }
            self.peaks.pop();
            cur = (h + 1, node_hash(&l, &cur.1));
        }
        self.peaks.push(cur);
    }

    /// The root: the peaks folded from the right.
    pub fn root(&self) -> Hash {
        let mut it = self.peaks.iter().rev();
        match it.next() {
            None => empty_root(),
            Some(&(_, last)) => it.fold(last, |acc, (_, p)| node_hash(p, &acc)),
        }
    }

    /// The inclusion proof of leaf `i` in the first `n` leaves (RFC 6962
    /// §2.1.1), for browsers that check one entry against a checkpoint.
    pub fn inclusion(&self, i: usize, n: usize) -> Vec<Hash> {
        fn path(leaves: &[Hash], i: usize) -> Vec<Hash> {
            let n = leaves.len();
            if n <= 1 {
                return vec![];
            }
            let k = 1usize << (usize::BITS - 1 - (n - 1).leading_zeros());
            if i < k {
                let mut p = path(&leaves[..k], i);
                p.push(root_of(&leaves[k..]));
                p
            } else {
                let mut p = path(&leaves[k..], i - k);
                p.push(root_of(&leaves[..k]));
                p
            }
        }
        path(&self.leaves[..n], i)
    }
}

/// Checks an inclusion proof (RFC 9162 §2.1.3.2).
pub fn verify_inclusion(leaf: &Hash, i: u64, n: u64, proof: &[Hash], root: &Hash) -> bool {
    if i >= n {
        return false;
    }
    let (mut fnn, mut sn) = (i, n - 1);
    let mut r = *leaf;
    for p in proof {
        if sn == 0 {
            return false;
        }
        if fnn & 1 == 1 || fnn == sn {
            r = node_hash(p, &r);
            if fnn & 1 == 0 {
                loop {
                    fnn >>= 1;
                    sn >>= 1;
                    if fnn & 1 == 1 || fnn == 0 {
                        break;
                    }
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fnn >>= 1;
        sn >>= 1;
    }
    sn == 0 && r == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peaks_match_the_definition() {
        let mut log = Log::new();
        assert_eq!(log.root(), empty_root());
        for i in 0..70u64 {
            log.push(leaf_hash(&leaf_data(i, "close", b"{}")));
            assert_eq!(log.root(), root_of(log.leaves()), "{i}");
        }
    }

    #[test]
    fn inclusion_proofs() {
        let mut log = Log::new();
        for i in 0..23u64 {
            log.push(leaf_hash(&i.to_be_bytes()));
        }
        for n in [1usize, 2, 7, 16, 23] {
            let root = root_of(&log.leaves()[..n]);
            for i in 0..n {
                let p = log.inclusion(i, n);
                assert!(verify_inclusion(&log.leaves()[i], i as u64, n as u64, &p, &root), "{i} of {n}");
                if n > 1 {
                    assert!(!verify_inclusion(&log.leaves()[(i + 1) % n], i as u64, n as u64, &p, &root));
                }
            }
        }
    }
}
