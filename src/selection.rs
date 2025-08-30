use crate::errors::PcwError;
use sv::messages::OutPoint; // From rust-sv
use std::collections::{HashMap, HashSet};
use std::cmp::Ordering;

/// UTXO struct for snapshot (§6.1).
#[derive(Clone, Debug)]
pub struct Utxo {
    pub outpoint: OutPoint,
    pub value: u64,
    pub script_pubkey: Vec<u8>, // For signing
}

/// Reservation table: i -> disjoint S_i (§6.1).
pub type Reservation = HashMap<usize, Vec<Utxo>>;

/// Build disjoint reservations per §6: Deterministic orders, stages A-D, optional fan-out.
pub fn build_reservations(u0: &[Utxo], split: &[u64], feerate_floor: u64, dust: u64, k_max: usize, m_max: usize, fanout_allowed: bool) -> Result<Reservation, PcwError> {
    let mut u_sorted = u0.to_vec();
    u_sorted.sort_by(|a, b| {
        a.value.cmp(&b.value)
            .then_with(|| a.outpoint.txid.cmp(&b.outpoint.txid))
            .then_with(|| a.outpoint.vout.cmp(&b.outpoint.vout))
    }); // Asc value, txid, vout §6.2
    let mut note_indices = (0..split.len()).collect::<Vec<_>>();
    note_indices.sort_by(|&i, &j| split[j].cmp(&split[i]).then_with(|| i.cmp(&j))); // Desc amount, asc i §6.2
    let mut used = HashSet::new();
    let mut r = HashMap::new();
    let mut fanout_done = false;

    'outer: loop {
        for &i in &note_indices {
            let target = split[i];
            if let Some(s_i) = select_inputs(&u_sorted, &used, target, feerate_floor, dust, k_max, m_max) {
                r.insert(i, s_i.clone());
                for utxo in &s_i {
                    used.insert(utxo.outpoint.clone());
                }
            } else {
                if fanout_allowed && !fanout_done {
                    // Impl fan_out: Consolidate to new payer addrs (§6.8)
                    let fan_out = fan_out(&u_sorted, &used, split, feerate_floor, dust)?;
                    // Assume fan_out.success and confirmed; refresh u_sorted
                    u_sorted = fan_out.outputs; // Simplified; in real, append new UTXOs after broadcast/confirm
                    used.clear();
                    r.clear();
                    fanout_done = true;
                    continue 'outer;
                } else {
                    return Err(PcwError::Other("Insufficient granularity §6.7".to_string()));
                }
            }
        }
        break;
    }
    Ok(r)
}

/// Select disjoint inputs for target per stages A-D (§6.4).
fn select_inputs(u: &[Utxo], used: &HashSet<OutPoint>, target: u64, feerate: u64, dust: u64, k_max: usize, m_max: usize) -> Option<Vec<Utxo>> {
    let available = u.iter().filter(|utxo| !used.contains(&utxo.outpoint)).collect::<Vec<_>>();
    // Stage A: Exact single
    for utxo in &available {
        let m = 1;
        let n = 1;
        let fee = feerate * size_est(m, n);
        if utxo.value == target + fee {
            return Some(vec![utxo.clone()]);
        }
    }
    // Stage B: Exact few (subset sum up to k_max)
    for card in 2..=k_max {
        // Impl subset sum search (greedy or exact for small card); return if exact
    }
    // Stage C: Single near-over with change >= dust
    let mut best_single = None;
    let mut min_change = u64::MAX;
    for utxo in &available {
        let m = 1;
        let n = 2;
        let fee = feerate * size_est(m, n);
        if utxo.value > target + fee {
            let change = utxo.value - target - fee;
            if change >= dust && change < min_change {
                min_change = change;
                best_single = Some(vec![utxo.clone()]);
            }
        }
    }
    if let Some(bs) = best_single {
        return Some(bs);
    }
    // Stage D: Fewest inputs minimal overshoot (greedy knapsack for m=2..m_max)
    let mut best_few = None;
    let mut min_m = usize::MAX;
    let mut min_over = u64::MAX;
    for m in 2..=m_max {
        // Impl greedy select for m; compute overshoot = sum - target - fee(m,2)
        // If overshoot == 0 or >= dust, and m < min_m or (m == min_m and overshoot < min_over), update
    }
    best_few
}

/// Size est per P2PKH (§6.3, §7.3).
fn size_est(m: usize, n: usize) -> u64 {
    10 + 148 * m as u64 + 34 * n as u64
}

/// Fan-out consolidation (§6.8): Simplified stub; impl to create smaller payer UTXOs.
fn fan_out(u: &[Utxo], used: &HashSet<OutPoint>, split: &[u64], feerate: u64, dust: u64) -> Result<FanOutResult, PcwError> {
    // Logic to consolidate into outputs near v_max/mid; broadcast and confirm
    // Return new outputs as Utxo vec
    unimplemented!(); // For v1; return dummy for tests
}

struct FanOutResult {
    outputs: Vec<Utxo>,
}

#[cfg(test)]
mod tests {
    use super::*;
    // Tests for disjoint, preferences, fan-out trigger
}
