//! A tally's values read as the poll's kind says (SPEC §7.1): counts per
//! slot for single choice; first places, ranked counts and, with margins,
//! the pairwise margins (and a Condorcet winner when there is one) for
//! ranked polls. Inactive slots of the circuit are dropped.

use crate::api::R;
use isoloir_proto::body::{KindSpec, PollSetup};
use isoloir_proto::kinds::{self, Chain, Family, Variant};
use serde_json::{json, Value};

fn label(options: &[String], slot: usize) -> Value {
    options.get(slot).map(|s| Value::String(s.clone())).unwrap_or(Value::Null)
}

/// The results of a poll's values summed over `counted` ballots.
#[allow(clippy::needless_range_loop)]
pub fn of(p: &PollSetup, v: &Variant, values: &[i64], counted: u64) -> R<Value> {
    if values.len() != v.values() {
        return Err(format!("{} values, the circuit has {}", values.len(), v.values()));
    }
    let m = v.slots as usize;
    let active = kinds::slots(&p.kind) as usize;
    match &p.kind {
        KindSpec::Choice { options, blank } => {
            let slots: Vec<Value> = (0..active)
                .map(|k| json!({ "slot": k, "label": label(options, k), "blank": *blank && k == options.len(), "count": values[k] }))
                .collect();
            let picked: i64 = values[..active].iter().sum();
            // Linked: one counted ballot per voter, so those that pick no
            // slot are counted − picked. Delta: `counted` counts the
            // corrections, not the voters: the withdrawals are unknown.
            let none = match v.chain {
                Chain::Linked => Some(counted as i64 - picked),
                Chain::Delta => None,
            };
            Ok(json!({
                "type": "choice",
                "counted": counted,
                "ballots": if v.chain == Chain::Delta { "corrections" } else { "voters" },
                "slots": slots,
                "blank": if *blank { Some(values[options.len()]) } else { None },
                "none": none,
            }))
        }
        KindSpec::Ranked { options, blank, .. } => {
            let slots: Vec<Value> = (0..active)
                .map(|k| json!({ "slot": k, "label": label(options, k), "blank": *blank && k == options.len(), "first": values[k], "ranked": values[m + k] }))
                .collect();
            let mut res = json!({ "type": "ranked", "counted": counted, "ballots": if v.chain == Chain::Delta { "corrections" } else { "voters" }, "slots": slots });
            if v.family == Family::RankedMargins {
                // margin[i][j] for i < j, in the circuit's slot order.
                let mut mat = vec![vec![0i64; active]; active];
                let mut n = 2 * m;
                for i in 0..m {
                    for j in i + 1..m {
                        if i < active && j < active {
                            mat[i][j] = values[n];
                            mat[j][i] = -values[n];
                        }
                        n += 1;
                    }
                }
                let winner = (0..active).find(|&i| (0..active).all(|j| j == i || mat[i][j] > 0));
                res["margins"] = json!(mat);
                res["condorcet"] = json!(winner);
            }
            Ok(res)
        }
    }
}
