//! The matrix of allowed polls (SPEC §8), the checks of a setup on its
//! own, and the rules of setup succession (SPEC §13).

use crate::body::{Channel, ChannelState, Decrypter, Encryption, KindSpec, LedgerSetup, PollSetup, Publish, RegistrySetup, Revote};
use crate::kinds::{self, Class};
use isoloir_core::grumpkin;

/// Whether a combination is allowed, and why not.
pub fn allowed(encryption: &Encryption, publish: &Publish, revote: Revote, class: Class) -> Result<(), &'static str> {
    match (encryption, publish, class, revote) {
        (Encryption::Elgamal { .. }, _, _, _) => Ok(()),
        (Encryption::Tlock { .. }, Publish::Open { .. }, _, _) => Err("tlock opens nothing before its round: no open poll"),
        (Encryption::Tlock { .. }, Publish::Closed, Class::Multiple, _) => {
            Err("tlock opens every ballot at the round: a ranking is a receipt (SPEC §8)")
        }
        (Encryption::Tlock { .. }, Publish::Closed, Class::Single, Revote::Linked) => {
            Err("tlock with linked re-votes opens each pseudonym's history (SPEC §8)")
        }
        (Encryption::Tlock { .. }, Publish::Closed, Class::Single, Revote::Delta) => {
            Err("tlock with delta re-votes: a voter could void a first ballot and count a correction against others' votes (SPEC §8)")
        }
        (Encryption::Tlock { .. }, Publish::Closed, Class::Single, Revote::None) => Ok(()),
    }
}

/// The checks of a ledger setup on its own.
pub fn check_ledger(l: &LedgerSetup) -> Result<(), String> {
    if l.v != 1 || l.version == 0 {
        return Err("v 1, version from 1".into());
    }
    if l.origin.is_empty() || l.origin.contains(char::is_whitespace) || !l.origin.is_ascii() {
        return Err("origin: ASCII, no spaces".into());
    }
    if !l.channels.iter().any(Channel::is_active) {
        return Err("at least one active channel".into());
    }
    for c in &l.channels {
        let u = c.url();
        let local = |rest: &str| rest.starts_with("127.0.0.1") || rest.starts_with("localhost") || rest.starts_with("[::1]");
        let ok = match c {
            Channel::Nostr { .. } => u.starts_with("wss://") || u.strip_prefix("ws://").is_some_and(local),
            Channel::Direct { .. } => u.starts_with("https://") || u.strip_prefix("http://").is_some_and(local),
        };
        if !ok || u.ends_with('/') {
            return Err(format!("channel {u}: nostr is wss://, direct https:// (ws:// and http:// on this machine only), no trailing slash"));
        }
    }
    let mut urls: Vec<&str> = l.channels.iter().map(Channel::url).collect();
    urls.sort();
    if urls.windows(2).any(|w| w[0] == w[1]) {
        return Err("a channel listed twice".into());
    }
    if l.checkpoint_period == 0 || l.anchor_age < l.checkpoint_period {
        return Err("checkpoint_period > 0, anchor_age ≥ checkpoint_period".into());
    }
    if hex::decode(&l.ingest).map(|b| b.len()) != Ok(32) {
        return Err("ingest: an x-only public key, 32 bytes of hex".into());
    }
    crate::note::Verifier::parse(&l.log_key).map_err(|e| format!("log_key: {e}"))?;
    Ok(())
}

/// The checks of a registry setup on its own.
pub fn check_registry(r: &RegistrySetup) -> Result<(), String> {
    if r.v != 1 || r.version == 0 {
        return Err("v 1, version from 1".into());
    }
    if !(1..=30).contains(&r.depth) {
        return Err("depth: 1 to 30".into());
    }
    match r.eligibility.provider.as_str() {
        "zkpassport" => {
            if r.eligibility.domain.is_empty() || r.eligibility.scope.is_empty() {
                return Err("zkpassport: a domain and a scope".into());
            }
        }
        "dev" => {}
        p => return Err(format!("provider {p}: unknown")),
    }
    if r.validity == 0 {
        return Err("validity > 0".into());
    }
    Ok(())
}

/// The checks of a poll setup on its own and against its registry.
pub fn check_poll(p: &PollSetup, registry: &RegistrySetup) -> Result<kinds::Variant, String> {
    if p.v != 1 || p.version == 0 {
        return Err("v 1, version from 1".into());
    }
    if p.registry != registry.id {
        return Err("another registry".into());
    }
    match &p.kind {
        KindSpec::Choice { options, .. } => {
            if options.len() < 2 && kinds::slots(&p.kind) < 2 {
                return Err("at least two slots".into());
            }
        }
        KindSpec::Ranked { options, depth, .. } => {
            if options.len() < 2 {
                return Err("at least two options".into());
            }
            if *depth != kinds::RANK_DEPTH {
                return Err(format!("depth {}: the circuits rank {}", depth, kinds::RANK_DEPTH));
            }
        }
    }
    if kinds::slots(&p.kind) > 32 {
        return Err("at most 32 slots".into());
    }
    if p.closes <= p.opens {
        return Err("closes after opens".into());
    }
    if p.blackouts.iter().any(|b| b.to <= b.from) {
        return Err("a blackout ends after it starts".into());
    }
    match &p.encryption {
        Encryption::Elgamal { pk, decrypter, per_chunk } => {
            let _ = grumpkin::from_hex(pk).map_err(|e| format!("pk: {e}"))?;
            if !isoloir_core::pack::PER_CHUNK_CHOICES.contains(&(*per_chunk as usize)) {
                return Err("per_chunk: 2 or 7".into());
            }
            match decrypter {
                Decrypter::Single { sign_key } => {
                    if hex::decode(sign_key).map(|b| b.len()) != Ok(32) {
                        return Err("sign_key: 32 bytes of hex".into());
                    }
                }
            }
        }
        Encryption::Tlock { chain, public_key, period, genesis, round } => {
            if hex::decode(chain).map(|b| b.len()) != Ok(32) || hex::decode(public_key).is_err() {
                return Err("tlock: a chain hash and a public key in hex".into());
            }
            if *period == 0 {
                return Err("tlock: period > 0".into());
            }
            // The round must come at or after the close.
            let at = genesis + (round.saturating_sub(1)) * period;
            if at < p.closes {
                return Err(format!("tlock: round {round} comes at {at}, before the close {}", p.closes));
            }
        }
    }
    if let Publish::Open { k_real, .. } = p.publish {
        if k_real == 0 {
            return Err("k_real ≥ 1".into());
        }
    }
    if (p.revote == Revote::Delta) != p.ballot_depth.is_some() {
        return Err("a ballot_depth with delta re-votes, and only then".into());
    }
    if hex::decode(p.circuit.vk_hash.trim_start_matches("0x")).map(|b| b.len()) != Ok(32) || !p.circuit.vk_hash.starts_with("0x") {
        return Err("circuit.vk_hash: 0x + SHA-256".into());
    }
    allowed(&p.encryption, &p.publish, p.revote, kinds::class(&p.kind)).map_err(String::from)?;
    kinds::variant_of(p, registry.depth)
}

/// What a later ledger entry may change.
pub fn ledger_successor(old: &LedgerSetup, new: &LedgerSetup) -> Result<(), String> {
    if new.version != old.version + 1 {
        return Err("version + 1".into());
    }
    if new.origin != old.origin || new.log_key != old.log_key {
        return Err("origin and log_key never change".into());
    }
    // Channels: kept in order, retired ones stay retired; new ones appended.
    if new.channels.len() < old.channels.len() {
        return Err("channels are never removed, only retired".into());
    }
    for (o, n) in old.channels.iter().zip(&new.channels) {
        let same = std::mem::discriminant(o) == std::mem::discriminant(n) && o.url() == n.url();
        if !same || (o.state() == ChannelState::Retired && n.state() == ChannelState::Active) {
            return Err("channels keep their place and type, and a retired channel stays retired".into());
        }
    }
    Ok(())
}

/// What a later registry entry may change.
pub fn registry_successor(old: &RegistrySetup, new: &RegistrySetup) -> Result<(), String> {
    if new.version != old.version + 1 || new.id != old.id {
        return Err("same id, version + 1".into());
    }
    if new.eligibility != old.eligibility || new.depth != old.depth {
        return Err("eligibility and depth never change".into());
    }
    Ok(())
}

/// What a later poll entry may change, at time `now`.
pub fn poll_successor(old: &PollSetup, new: &PollSetup, now: u64) -> Result<(), String> {
    if new.version != old.version + 1 || new.id != old.id {
        return Err("same id, version + 1".into());
    }
    if new.registry != old.registry || new.kind != old.kind || new.encryption != old.encryption || new.revote != old.revote || new.opens != old.opens {
        return Err("registry, kind, encryption, revote and opens never change".into());
    }
    if new.ballot_depth != old.ballot_depth {
        return Err("ballot_depth never changes".into());
    }
    if now >= old.closes {
        return Err("the poll is closed".into());
    }
    if new.closes < old.closes || new.closes <= now {
        return Err("closes: later only, and in the future".into());
    }
    match (&old.publish, &new.publish) {
        (Publish::Open { k_real: a, min_gap: g, coin: c }, Publish::Open { k_real: b, min_gap: h, coin: d }) => {
            // Lowering them mid-poll would let the operator isolate ballots.
            if b < a || h < g || c != d {
                return Err("k_real and min_gap only rise, coin never changes".into());
            }
        }
        (Publish::Closed, Publish::Closed) => {}
        _ => return Err("publish.mode never changes".into()),
    }
    // Past and current blackouts stay as they were.
    let fixed = |b: &&crate::body::Blackout| b.from <= now;
    if old.blackouts.iter().filter(fixed).ne(new.blackouts.iter().filter(fixed)) {
        return Err("blackouts that started never change".into());
    }
    let (ov, nv) = (kinds::Variant::parse(&old.circuit.name), kinds::Variant::parse(&new.circuit.name));
    if ov != nv {
        return Err("a new circuit proves the same variant".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elgamal() -> Encryption {
        Encryption::Elgamal { pk: String::new(), decrypter: Decrypter::Single { sign_key: String::new() }, per_chunk: 2 }
    }
    fn tlock() -> Encryption {
        Encryption::Tlock { chain: String::new(), public_key: String::new(), period: 3, genesis: 0, round: 1 }
    }
    fn open() -> Publish {
        Publish::Open { k_real: 1, min_gap: 0, coin: true }
    }

    /// The table of SPEC §8, cell by cell.
    #[test]
    fn the_matrix() {
        for enc in [elgamal(), tlock()] {
            for publish in [open(), Publish::Closed] {
                for class in [Class::Single, Class::Multiple] {
                    for revote in [Revote::None, Revote::Linked, Revote::Delta] {
                        let want = match (&enc, &publish, class, revote) {
                            (Encryption::Elgamal { .. }, _, _, _) => true,
                            (_, Publish::Open { .. }, _, _) => false,
                            (_, _, Class::Multiple, _) => false,
                            (_, _, Class::Single, Revote::None) => true,
                            _ => false,
                        };
                        assert_eq!(allowed(&enc, &publish, revote, class).is_ok(), want, "{enc:?} {publish:?} {class:?} {revote:?}");
                    }
                }
            }
        }
    }
}
