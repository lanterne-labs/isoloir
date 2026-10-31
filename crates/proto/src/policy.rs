//! When a tally is due (SPEC §10.1): a function of the log alone, so that
//! any authority and any auditor agree without talking.

use crate::body::Publish;
use crate::log::Hash;
use crate::state::{PollState, State};
use isoloir_core::encoding;

/// A tally that is due: the checkpoint it is computed at, the last log
/// position it covers, and whether it is the final one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Due {
    pub poll: u32,
    pub checkpoint: u64,
    pub upto: u64,
    pub is_final: bool,
}

/// The coin of a checkpoint: the low bit of `SHA-256("isoloir/1/coin" ‖ root)`.
pub fn coin(root: &Hash) -> bool {
    let mut m = b"isoloir/1/coin".to_vec();
    m.extend_from_slice(root);
    encoding::sha256(&m)[31] & 1 == 1
}

fn in_blackout(p: &PollState, t: u64) -> bool {
    p.current().blackouts.iter().any(|b| b.from <= t && t < b.to)
}

/// The tally due for a poll at a checkpoint, if any.
pub fn due_at(state: &State, poll: u32, cp_index: u64) -> Option<Due> {
    let p = state.polls.get(&poll)?;
    let cp = state.checkpoints.iter().find(|c| c.index == cp_index)?;
    if p.tallies.iter().any(|(_, t)| t.is_final || t.checkpoint.is_some_and(|c| c >= cp_index)) {
        return None;
    }
    // The final tally, at the checkpoint that logs the close.
    if let Some((cseq, _)) = &p.close {
        let covering = state.checkpoint_of(*cseq)?;
        return (covering.index == cp_index).then_some(Due { poll, checkpoint: cp_index, upto: *cseq, is_final: true });
    }
    let Publish::Open { k_real, min_gap, coin: with_coin } = p.current().publish else { return None };
    let upto = cp.size.checked_sub(1)?;
    let last = p.last_tally();
    if p.changed(last.map(|t| t.upto), upto) < k_real as u64 {
        return None;
    }
    if let Some(prev) = last.and_then(|t| t.checkpoint).and_then(|c| state.checkpoints.iter().find(|x| x.index == c)) {
        if cp.time < prev.time + min_gap {
            return None;
        }
    }
    if in_blackout(p, cp.time) || (with_coin && !coin(&cp.root)) {
        return None;
    }
    Some(Due { poll, checkpoint: cp_index, upto, is_final: false })
}

/// The newest tally due for a poll: what an authority publishes next.
pub fn next_due(state: &State, poll: u32) -> Option<Due> {
    let p = state.polls.get(&poll)?;
    let after = p.tallies.iter().filter_map(|(_, t)| t.checkpoint).max().unwrap_or(0);
    state.checkpoints.iter().rev().take_while(|c| c.index > after).find_map(|c| due_at(state, poll, c.index))
}
