use crate::errors::PcwError;
use sv::messages::OutPoint;
use std::collections::{HashMap, HashSet};
use std::cmp::{max, min};

#[derive(Clone, Debug)]
pub struct Utxo {
    pub outpoint: OutPoint,
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

pub type Reservation = HashMap<usize, Vec<Utxo>>;

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

fn select_inputs(u: &[Utxo], used: &HashSet<OutPoint>, target: u64, feerate: u64, dust: u64, k_max: usize, m_max: usize) -> Result<Vec<Utxo>, PcwError> {
    let available = u.iter().filter(|utxo| !used.contains(&utxo.outpoint)).cloned().collect::<Vec<_>>();
    // Stage A: Exact single
    for utxo in &available {
        let m = 1;
        let n = 1;
        let fee = feerate * (10 + 148 * m as u64 + 34 * n as u64);
        if utxo.value == target + fee {
            return Ok(vec![utxo]);
        }
    }
    // Stage B: Exact few (simple greedy subset sum for small k_max)
    for card in 2..=k_max {
        let mut sum = 0u64;
        let mut selected = vec![];
        let mut avail_sorted = available.clone();
        avail_sorted.sort_by_key(|u| u.value);
        for utxo in avail_sorted.iter().rev() { // Largest first for greedy
            if sum + utxo.value <= target + feerate * (10 + 148 * card as u64 + 34) {
                sum + = utxo.value;
                selected.push(utxo.clone());
                if selected.len() == card && sum == target + feerate * (10 + 148 * card as u64 + 34) {
                    return Ok(selected);
                }
            }
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
    // Stage D: Fewest m minimal overshoot (greedy knapsack)
    let mut best_few = None;
    let mut min_m = usize::MAX;
    let mut min_over = u64::MAX;
    for m in 2..=m_max {
        let mut avail_sorted = available.clone();
        avail_sorted.sort_by_key(|u| u.value);
        let mut selected = vec![];
        let mut sum = 0u64;
        for utxo in avail_sorted.iter().rev() {
            if selected.len() < m {
                selected.push(utxo.clone());
                sum += utxo.value;
            }
        }
        let n = 2;
        let fee = feerate * (10 + 148 * m as u64 + 34 * n as u64);
        let overshoot = sum.saturating_sub(target + fee);
        if sum >= target + fee && (overshoot == 0 || overshoot >= dust) {
            if m < min_m || (m == min_m && overshoot < min_over) {
                min_m = m;
                min_over = overshoot;
                best_few = Some(selected);
            }
        }
    }
    if let Some(bf) = best_few {
        Ok(bf)
    } else {
        Err(PcwError::Underfunded)
    }
}

fn size_est(m: usize, n: usize) -> u64 {
    10 + 148 * m as u64 + 34 * n as u64
}

/// Fan-out: Consolidate to new payer outputs near v_max (§6.8).
fn fan_out(u: &[Utxo], used: &HashSet<OutPoint>, split: &[u64], feerate: u64, dust: u64) -> Result<FanOutResult, PcwError> {
    let available = u.iter().filter(|utxo| !used.contains(&utxo.outpoint)).cloned().collect::<Vec<_>>();
    let total = available.iter().map(|u| u.value).sum::<u64>();
    let v_max = split.iter().cloned().max().unwrap_or(0);
    let num_out = (total / v_max) as usize + 1; // Buffer
    let out_value = total / num_out as u64;
    let mut outputs = vec![];
    for _ in 0..num_out {
        // Assume new payer addr derivation (spec "fund" label, but stub as dummy Utxo)
        outputs.push(Utxo { outpoint: OutPoint { txid: [0;32], vout: 0 }, value: out_value.max(dust), script_pubkey: vec![] });
    }
    // In real, build/sign/broadcast fan-out tx, wait confirm, return new UTXOs
    Ok(FanOutResult { outputs })
}

struct FanOutResult {
    outputs: Vec<Utxo>,
}

#[cfg(test)]
mod tests {
    // Add tests for select_inputs stages, fan_out
}
