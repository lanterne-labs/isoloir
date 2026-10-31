//! The kinds of ballots (SPEC §7.1) and the circuit variants that prove
//! them (SPEC §9.1, circuits/gen.py). The values computed here are those
//! the circuits compute, so a browser can build a ballot and an auditor
//! can check an opened one.

use crate::body::{Encryption, KindSpec, PollSetup, Revote};
use isoloir_core::Fr;
use isoloir_core::poseidon2;

/// The depth of a ranking the circuits support.
pub const RANK_DEPTH: u32 = 3;

/// Single choice or multiple choices (SPEC §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Single,
    Multiple,
}

/// The circuit family of a kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Choice,
    Ranked,
    RankedMargins,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Enc {
    Elgamal,
    Tlock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chain {
    Linked,
    Delta,
}

/// A circuit variant, parsed from its name: `choice4_elgamal_linked_d20`,
/// `ranked12_elgamal_delta_d20_b22`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Variant {
    pub family: Family,
    pub slots: u32,
    pub enc: Enc,
    pub chain: Chain,
    pub depth: u32,
    pub ballot_depth: Option<u32>,
}

impl Variant {
    pub fn parse(name: &str) -> Option<Variant> {
        let parts: Vec<&str> = name.split('_').collect();
        if parts.len() < 4 {
            return None;
        }
        let (family, slots) = if let Some(n) = parts[0].strip_prefix("rankedm") {
            (Family::RankedMargins, n)
        } else if let Some(n) = parts[0].strip_prefix("ranked") {
            (Family::Ranked, n)
        } else if let Some(n) = parts[0].strip_prefix("choice") {
            (Family::Choice, n)
        } else {
            return None;
        };
        let slots: u32 = slots.parse().ok().filter(|m| (2..=32).contains(m))?;
        let enc = match parts[1] {
            "elgamal" => Enc::Elgamal,
            "tlock" => Enc::Tlock,
            _ => return None,
        };
        let chain = match parts[2] {
            "linked" => Chain::Linked,
            "delta" => Chain::Delta,
            _ => return None,
        };
        let depth: u32 = parts[3].strip_prefix('d')?.parse().ok().filter(|d| (1..=30).contains(d))?;
        let ballot_depth = match (chain, parts.get(4)) {
            (Chain::Delta, Some(b)) if parts.len() == 5 => Some(b.strip_prefix('b')?.parse().ok().filter(|d| (1..=32).contains(d))?),
            (Chain::Linked, None) if parts.len() == 4 => None,
            _ => return None,
        };
        if enc == Enc::Tlock && (family != Family::Choice || chain != Chain::Linked) {
            return None;
        }
        let v = Variant { family, slots, enc, chain, depth, ballot_depth };
        (v.name() == name).then_some(v)
    }

    pub fn name(&self) -> String {
        let f = match self.family {
            Family::Choice => "choice",
            Family::Ranked => "ranked",
            Family::RankedMargins => "rankedm",
        };
        let e = match self.enc {
            Enc::Elgamal => "elgamal",
            Enc::Tlock => "tlock",
        };
        let c = match self.chain {
            Chain::Linked => "linked",
            Chain::Delta => "delta",
        };
        let mut s = format!("{f}{}_{e}_{c}_d{}", self.slots, self.depth);
        if let Some(b) = self.ballot_depth {
            s.push_str(&format!("_b{b}"));
        }
        s
    }

    /// The number of values a ballot carries.
    pub fn values(&self) -> usize {
        let m = self.slots as usize;
        match self.family {
            Family::Choice => m,
            Family::Ranked => 2 * m,
            Family::RankedMargins => 2 * m + m * (m - 1) / 2,
        }
    }

    /// The number of chunks.
    pub fn chunks(&self) -> usize {
        isoloir_core::pack::chunks(self.values())
    }
}

/// A voter's choice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Choice {
    /// One slot, or none (a withdrawal).
    Pick(Option<u32>),
    /// Up to `RANK_DEPTH` distinct slots, best first.
    Rank(Vec<u32>),
}

/// The slots of a kind: its options, then the blank.
pub fn slots(kind: &KindSpec) -> u32 {
    match kind {
        KindSpec::Choice { options, blank } | KindSpec::Ranked { options, blank, .. } => options.len() as u32 + *blank as u32,
    }
}

/// The mask of active slots (SPEC §7.1).
pub fn mask(kind: &KindSpec) -> u32 {
    let n = slots(kind);
    if n >= 32 { u32::MAX } else { (1u32 << n) - 1 }
}

/// The blank's slot, or the circuit's slot count when there is none (a
/// slot that can never be picked).
pub fn blank_slot(kind: &KindSpec, circuit_slots: u32) -> u32 {
    match kind {
        KindSpec::Choice { options, blank } | KindSpec::Ranked { options, blank, .. } => {
            if *blank { options.len() as u32 } else { circuit_slots }
        }
    }
}

/// The class of a kind (SPEC §8).
pub fn class(kind: &KindSpec) -> Class {
    match kind {
        KindSpec::Choice { .. } => Class::Single,
        KindSpec::Ranked { .. } => Class::Multiple,
    }
}

/// The family a kind is proven by.
pub fn family(kind: &KindSpec) -> Family {
    match kind {
        KindSpec::Choice { .. } => Family::Choice,
        KindSpec::Ranked { margins: false, .. } => Family::Ranked,
        KindSpec::Ranked { margins: true, .. } => Family::RankedMargins,
    }
}

/// The variant a poll names, checked against the poll: the family of its
/// kind, enough slots, its encryption and re-vote mode, the registry's
/// depth and, for delta, the ballot tree's.
pub fn variant_of(poll: &PollSetup, registry_depth: u32) -> Result<Variant, String> {
    let v = Variant::parse(&poll.circuit.name).ok_or_else(|| format!("circuit {}: not a variant name", poll.circuit.name))?;
    if v.family != family(&poll.kind) {
        return Err("the circuit is of another kind".into());
    }
    if v.slots < slots(&poll.kind) {
        return Err(format!("the circuit has {} slots, the poll {}", v.slots, slots(&poll.kind)));
    }
    let enc = match poll.encryption {
        Encryption::Elgamal { .. } => Enc::Elgamal,
        Encryption::Tlock { .. } => Enc::Tlock,
    };
    if v.enc != enc {
        return Err("the circuit encrypts otherwise".into());
    }
    let chain = if poll.revote == Revote::Delta { Chain::Delta } else { Chain::Linked };
    if v.chain != chain {
        return Err("the circuit's re-vote mode is not the poll's".into());
    }
    if v.depth != registry_depth {
        return Err(format!("the circuit's registry depth is {}, the registry's {}", v.depth, registry_depth));
    }
    if v.ballot_depth != poll.ballot_depth {
        return Err("the circuit's ballot tree depth is not the poll's".into());
    }
    Ok(v)
}

/// The values of a choice, as the circuit computes them, or why the
/// choice is not valid for the kind.
pub fn values(kind: &KindSpec, variant: &Variant, choice: &Choice) -> Result<Vec<i64>, String> {
    let m = variant.slots;
    let active = slots(kind);
    match (kind, choice) {
        (KindSpec::Choice { .. }, Choice::Pick(p)) => {
            let mut v = vec![0i64; m as usize];
            if let Some(p) = p {
                if *p >= active {
                    return Err(format!("slot {p} is not active"));
                }
                v[*p as usize] = 1;
            }
            Ok(v)
        }
        (KindSpec::Ranked { blank, options, margins, .. }, Choice::Rank(r)) => {
            if r.len() > RANK_DEPTH as usize {
                return Err("too many ranks".into());
            }
            let mut pos = vec![RANK_DEPTH; m as usize];
            for (k, o) in r.iter().enumerate() {
                if *o >= active {
                    return Err(format!("slot {o} is not active"));
                }
                if pos[*o as usize] != RANK_DEPTH {
                    return Err(format!("slot {o} ranked twice"));
                }
                if *blank && *o == options.len() as u32 && k + 1 != r.len() {
                    return Err("the blank must be last".into());
                }
                pos[*o as usize] = k as u32;
            }
            let mut v = vec![0i64; variant.values()];
            for c in 0..m as usize {
                if r.first() == Some(&(c as u32)) {
                    v[c] = 1;
                }
                if pos[c] < RANK_DEPTH {
                    v[m as usize + c] = 1;
                }
            }
            if *margins {
                let mut n = 2 * m as usize;
                for i in 0..m as usize {
                    for j in i + 1..m as usize {
                        v[n] = (pos[i] < pos[j]) as i64 - (pos[j] < pos[i]) as i64;
                        n += 1;
                    }
                }
            }
            Ok(v)
        }
        _ => Err("the choice is not of the poll's kind".into()),
    }
}

/// The fields a choice's hash covers in the delta chain (SPEC §7.4):
/// `[pick]` (the circuit's slot count for none), or `[len, s0, s1, s2]`.
pub fn choice_fields(variant: &Variant, choice: &Choice) -> Vec<Fr> {
    match choice {
        Choice::Pick(p) => vec![Fr::from(p.unwrap_or(variant.slots) as u64)],
        Choice::Rank(r) => {
            let mut f = vec![Fr::from(r.len() as u64)];
            for k in 0..RANK_DEPTH as usize {
                f.push(Fr::from(r.get(k).copied().unwrap_or(0) as u64));
            }
            f
        }
    }
}

/// `H(choice fields)`: what a delta commitment covers.
pub fn choice_hash(variant: &Variant, choice: &Choice) -> Fr {
    poseidon2::hash(&choice_fields(variant, choice))
}

/// The correction new − old (old absent: new).
pub fn correction(new: &[i64], old: Option<&[i64]>) -> Vec<i64> {
    match old {
        None => new.to_vec(),
        Some(o) => new.iter().zip(o).map(|(a, b)| a - b).collect(),
    }
}

/// The bound of a value summed over `n` counted ballots, used to decrypt:
/// counts and margins never exceed the number of ballots.
pub fn value_bound(n: u64) -> u64 {
    n.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variant_names() {
        for n in ["choice4_elgamal_linked_d20", "ranked12_elgamal_delta_d20_b22", "rankedm12_elgamal_linked_d20", "choice4_tlock_linked_d20"] {
            assert_eq!(Variant::parse(n).unwrap().name(), n);
        }
        for n in ["ranked12_tlock_linked_d20", "choice4_tlock_delta_d20_b22", "choice4_elgamal_delta_d20", "choice4_elgamal_linked_d20_b22", "choice1_elgamal_linked_d20", "choice04_elgamal_linked_d20"] {
            assert!(Variant::parse(n).is_none(), "{n}");
        }
        assert_eq!(Variant::parse("rankedm12_elgamal_linked_d20").unwrap().values(), 90);
    }

    #[test]
    fn ranked_values_match_the_circuit_test() {
        // The Noir test a_ranking_and_its_margins: 3 slots, blank = 2, 1 > 0.
        let kind = KindSpec::Ranked { options: vec!["a".into(), "b".into()], blank: true, depth: 3, margins: true };
        let var = Variant { family: Family::RankedMargins, slots: 3, enc: Enc::Elgamal, chain: Chain::Linked, depth: 20, ballot_depth: None };
        assert_eq!(values(&kind, &var, &Choice::Rank(vec![1, 0])).unwrap(), vec![0, 1, 0, 1, 1, 0, -1, 1, 1]);
        assert!(values(&kind, &var, &Choice::Rank(vec![2, 0])).is_err());
        assert!(values(&kind, &var, &Choice::Rank(vec![1, 1])).is_err());
    }

    #[test]
    fn choices() {
        let kind = KindSpec::Choice { options: vec!["Oui".into(), "Non".into()], blank: true };
        let var = Variant::parse("choice4_elgamal_linked_d20").unwrap();
        assert_eq!(mask(&kind), 0b111);
        assert_eq!(values(&kind, &var, &Choice::Pick(Some(2))).unwrap(), vec![0, 0, 1, 0]);
        assert_eq!(values(&kind, &var, &Choice::Pick(None)).unwrap(), vec![0, 0, 0, 0]);
        assert!(values(&kind, &var, &Choice::Pick(Some(3))).is_err());
    }
}
