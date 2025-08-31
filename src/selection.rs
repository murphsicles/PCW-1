use crate::errors::PcwError;
use sv::messages::OutPoint;
use std::collections::{HashMap, HashSet};
use std::cmp::{max, min};

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
    u_sorted.sort_by(|a, b| a.value.cmp(&b.value).then(a.outpoint.txid.cmp(&b.outpoint.txid)).then(a.outpoint.vout.cmp(&b.outpoint.vout)));
    let mut note_indices = (0..split.len()).collect::<Vec<_>>();
    note_indices.sort_by(|&i, &j| split[j].cmp(&split[i]).then_with(|| i.cmp(&j)));
    let mut used = HashSet::new();
    let mut r = HashMap::new();
    let mut fanout_done = false;

    'outer: loop {
        for &i in &note_indices {
            let target = split[i];
            if let Some(s_i) = select_inputs(&u_sorted, &used, target, feerate_floor, dust, k_max, m_max)? {
                r.insert(i, s_i.clone());
                for utxo in &s_i {
                    used.insert(utxo.outpoint.clone());
                }
            } else {
                if fanout_allowed && !fanout_done {
                    let fan_out = fan_out(&u_sorted, &used, split, feerate_floor, dust)?;
                    u_sorted = [u_sorted.iter().filter(|u| !used.contains(&u.outpoint)).cloned().collect::<Vec<_>>(), fan_out.outputs].concat();
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
fn select_inputs(u: &[Utxo], used: &HashSet<OutPoint>, target: u64, feerate: u64, dust: u64, k_max: usize, m_max: usize) -> Result<Vec<Utxo>, PcwError> {
    let mut available = u.iter().filter(|utxo| !used.contains(&utxo.outpoint)).cloned().collect::<Vec<_>>();
    available.sort_by(|a, b| a.value.cmp(&b.value).then(a.outpoint.txid.cmp(&b.outpoint.txid)).then(a.outpoint.vout.cmp(&b.outpoint.vout)));
    // Stage A: Exact single
    for utxo in &available {
        let m = 1;
        let n = 1;
        let fee = feerate * (10 + 148 * m as u64 + 34 * n as u64);
        if utxo.value == target + fee {
            return Ok(vec![utxo]);
        }
    }
    // Stage B: Exact few
    for card in 2..=k_max {
        if let Some(selected) = subset_sum(&available, target + feerate * (10 + 148 * card as u64 + 34), card)? {
            return Ok(selected);
        }
    }
    // Stage C: Single near-over
    let mut best_single = None;
    let mut min_change = u64::MAX;
    for utxo in &available {
        let m = 1;
        let n = 2;
        let fee = feerate * (10 + 148 * m as u64 + 34 * n as u64);
        if utxo.value > target + fee {
            let change = utxo.value - target - fee;
            if change >= dust && change < min_change {
                min_change = change;
                best_single = Some(vec![utxo.clone()]);
            }
        }
    }
    if let Some(bs) = best_single {
        return Ok(bs);
    }
    // Stage D: Fewest m minimal overshoot (greedy largest-first)
    let mut best_few = None;
    let mut min_m = usize::MAX;
    let mut min_over = u64::MAX;
    for m in 2..=m_max {
        let mut avail_sorted = available.clone();
        avail_sorted.sort_by_key(|u| u.value);
        avail_sorted.reverse(); // Largest first
        let mut selected = vec![];
        let mut sum = 0u64;
        for utxo in &avail_sorted {
            if selected.len() < m && sum < target + feerate * (10 + 148 * m as u64 + 68) {
                selected.push(utxo.clone());
                sum += utxo.value;
            }
        }
        let fee = feerate * (10 + 148 * m as u64 + 68);
        if sum >= target + fee {
            let overshoot = sum - target - fee;
            if overshoot == 0 || overshoot >= dust {
                if m < min_m || (m == min_m && overshoot < min_over) {
                    min_m = m;
                    min_over = overshoot;
                    best_few = Some(selected);
                }
            }
        }
    }
    if let Some(bf) = best_few {
        Ok(bf)
    } else {
        Err(PcwError::Underfunded)
    }
}

/// Exact subset sum for Stage B (§6.4): DP with backtrack for small card.
fn subset_sum(available: &[Utxo], target: u64, card: usize) -> Result<Option<Vec<Utxo>>, PcwError> {
    let n = available.len();
    let mut dp = vec![vec![false; (target as usize) + 1]; (card + 1) as usize];
    dp[0][0] = true;
    let mut prev = vec![vec![None; (target as usize) + 1]; (card + 1) as usize]; // (item idx, prev t)
    for i in 0..n {
        for c in (1..=card).rev() {
            for t in (available[i].value..=target).rev() {
                if dp[c-1][(t - available[i].value) as usize] {
                    dp[c][t as usize] = true;
                    prev[c][t as usize] = Some((i, t - available[i].value));
                }
            }
        }
    }
    if dp[card][target as usize] {
        let mut selected = vec![];
        let mut current_t = target;
        let mut current_c = card;
        while current_c > 0 {
            if let Some((idx, prev_t)) = prev[current_c][current_t as usize] {
                selected.push(available[idx].clone());
                current_t = prev_t;
                current_c -= 1;
            } else {
                break;
            }
        }
        Ok(Some(selected))
    } else {
        Ok(None)
    }
}

/// Fan-out: Consolidate to new payer outputs near v_max (§6.8).
/// NOTE: This is a stub for production. In a real wallet, replace dummy outpoints with actual ones obtained from broadcasting the fan-out tx.
/// Steps for production:
/// 1. Derive new payer addresses under "fund" label (e.g., HD path from {Z, H_I, "fund", k}).
/// 2. Build and sign a consolidation tx with available inputs and outputs of size ~ v_max.
/// 3. Broadcast the tx (e.g., via Electrum or P2P).
/// 4. Wait for confirmation (per policy depth).
/// 5. Fetch the new UTXOs with their real txid/vout/script_pubkey.
/// For testing, dummy outpoints are used.
fn fan_out(u: &[Utxo], used: &HashSet<OutPoint>, split: &[u64], feerate: u64, dust: u64) -> Result<FanOutResult, PcwError> {
    let available = u.iter().filter(|utxo| !used.contains(&utxo.outpoint)).cloned().collect::<Vec<_>>();
    let total = available.iter().map(|u| u.value).sum::<u64>();
    let v_max = split.iter().cloned().max().unwrap_or(0);
    let num_out = ((total + v_max - 1) / v_max) as usize + 1; // Buffer
    let out_value = total / num_out as u64;
    let mut outputs = vec![];
    for k in 0..num_out {
        let dummy_txid = [k as u8; 32];
        outputs.push(Utxo { outpoint: OutPoint { txid: dummy_txid, vout: 0 }, value: out_value.max(dust), script_pubkey: vec![] });
    }
    Ok(FanOutResult { outputs })
}

struct FanOutResult {
    outputs: Vec<Utxo>,
}

#[cfg(test)]
mod tests {
    use super::*;
    // Add tests for select_inputs stages, fan_out
}
