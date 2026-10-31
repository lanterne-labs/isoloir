//! The fixed-depth append-only Merkle trees of registries and ballots
//! (SPEC §5, §7.4): empty leaves are 0, a node is `H(T_node, left, right)`,
//! and bit i of a position (least significant first) says whether the
//! node at level i is a right child.

use crate::field::Fr;
use crate::{Error, Result, poseidon2, tags};

/// `H(T_node, l, r)`.
pub fn node(l: &Fr, r: &Fr) -> Fr {
    poseidon2::hash(&[tags::node(), *l, *r])
}

/// The roots of empty subtrees: `zeros[0] = 0`, `zeros[i+1] = node(zeros[i], zeros[i])`.
pub fn zeros(depth: usize) -> Vec<Fr> {
    let mut z = vec![Fr::from(0u64)];
    for i in 0..depth {
        z.push(node(&z[i], &z[i]));
    }
    z
}

/// A tree of fixed depth holding its leaves in order.
#[derive(Clone, Debug)]
pub struct Tree {
    depth: usize,
    zeros: Vec<Fr>,
    // levels[0] the leaves, levels[i] the nodes at height i that have at
    // least one non-empty leaf below them.
    levels: Vec<Vec<Fr>>,
}

impl Tree {
    /// An empty tree of the depth given (at most 32).
    pub fn new(depth: usize) -> Self {
        assert!((1..=32).contains(&depth), "depth {depth}");
        Tree { depth, zeros: zeros(depth), levels: vec![Vec::new(); depth + 1] }
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    /// The number of leaves.
    pub fn len(&self) -> usize {
        self.levels[0].len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The leaf at a position.
    pub fn leaf(&self, i: usize) -> Option<Fr> {
        self.levels[0].get(i).copied()
    }

    /// Appends a leaf and returns its position.
    pub fn push(&mut self, leaf: Fr) -> Result<usize> {
        let pos = self.len();
        if pos as u64 >= 1u64 << self.depth {
            return Err(Error::Range(format!("tree full at {pos} leaves")));
        }
        self.levels[0].push(leaf);
        let mut i = pos;
        for h in 0..self.depth {
            let parent = i / 2;
            let l = self.at(h, parent * 2);
            let r = self.at(h, parent * 2 + 1);
            let n = node(&l, &r);
            if self.levels[h + 1].len() == parent {
                self.levels[h + 1].push(n);
            } else {
                self.levels[h + 1][parent] = n;
            }
            i = parent;
        }
        Ok(pos)
    }

    fn at(&self, h: usize, i: usize) -> Fr {
        self.levels[h].get(i).copied().unwrap_or(self.zeros[h])
    }

    /// The root.
    pub fn root(&self) -> Fr {
        self.at(self.depth, 0)
    }

    /// The siblings of a position, from the leaf up.
    pub fn path(&self, pos: usize) -> Result<Vec<Fr>> {
        if pos >= self.len() {
            return Err(Error::Range(format!("no leaf at {pos}")));
        }
        Ok((0..self.depth).map(|h| self.at(h, (pos >> h) ^ 1)).collect())
    }

    /// The root the tree had when it held its first `n` leaves.
    pub fn root_at(&self, n: usize) -> Result<Fr> {
        if n > self.len() {
            return Err(Error::Range(format!("{n} leaves, the tree holds {}", self.len())));
        }
        let mut t = Tree::new(self.depth);
        for l in &self.levels[0][..n] {
            t.push(*l)?;
        }
        Ok(t.root())
    }
}

/// The root of the tree holding `leaf` at `pos` with these siblings.
pub fn root_of(leaf: &Fr, pos: u64, path: &[Fr]) -> Fr {
    let mut cur = *leaf;
    for (h, sib) in path.iter().enumerate() {
        cur = if (pos >> h) & 1 == 1 { node(sib, &cur) } else { node(&cur, sib) };
    }
    cur
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_lead_to_the_root() {
        let mut t = Tree::new(8);
        assert_eq!(t.root(), zeros(8)[8]);
        for i in 0..37u64 {
            t.push(Fr::from(1000 + i)).unwrap();
        }
        for i in [0usize, 1, 17, 36] {
            let p = t.path(i).unwrap();
            assert_eq!(root_of(&t.leaf(i).unwrap(), i as u64, &p), t.root());
            assert_ne!(root_of(&t.leaf(i).unwrap(), (i ^ 1) as u64, &p), t.root());
        }
        let r20 = t.root_at(20).unwrap();
        let mut u = Tree::new(8);
        for i in 0..20u64 {
            u.push(Fr::from(1000 + i)).unwrap();
        }
        assert_eq!(u.root(), r20);
    }

    #[test]
    fn a_full_tree_refuses() {
        let mut t = Tree::new(2);
        for i in 0..4u64 {
            t.push(Fr::from(i)).unwrap();
        }
        assert!(t.push(Fr::from(9u64)).is_err());
    }
}
