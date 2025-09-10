//! Module for UTXO selection and reservation in the PCW-1 protocol.
//!
//! This module implements the UTXO selection and reservation logic as per §6, including
//! `build_reservations` with stages A-D (§6.4), deterministic ordering, and optional fan-out (§6.8).
//! It manages disjoint input sets (S_i) for each note in a payment, ensuring privacy and auditability.
use crate::errors::PcwError;
use crate::utils::{sha256, le32};
use crate::addressing::derive_address;
use crate::scope::Scope;
use secp256k1::{PublicKey, Secp256k1};
use std::cmp::max;
use std::collections::{HashMap, HashSet};
use sv::messages::OutPoint;
use sv::util::Hash160;

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
pub fn build_reservations(
    u0: &[Utxo],
    split: &[u64],
    feerate_floor: u64,
    dust: u64,
    k_max: usize,
    m_max: usize,
    fanout_allowed: bool,
    scope: &Scope,
    sender_anchor: &PublicKey,
) -> Result<Reservation, PcwError> {
    let mut u_sorted = u0.to_vec();
    u_sorted.sort_by(|a, b| {
        a.value
            .cmp(&b.value)
            .then(a.outpoint.hash.cmp(&b.outpoint.hash))
            .then(a.outpoint.index.cmp(&b.outpoint.index))
    });
    let mut note_indices = (0..split.len()).collect::<Vec<_>>();
    note_indices.sort_by(|&i, &j| split[j].cmp(&split[i]).then_with(|| i.cmp(&j)));
    let mut used = HashSet::new();
    let mut r = HashMap::new();
    let mut fanout_done = false;
    'outer: loop {
        for &i in &note_indices {
            let target = split[i];
            let base_fee = feerate_floor * 10; // Base tx size (approx. 10 bytes)
            let s_i = select_inputs(
                &u_sorted,
                &used,
                target,
                base_fee,
                feerate_floor,
                dust,
                k_max,
                m_max,
            )?;
            match s_i {
                Some(s_i) => {
                    let m = s_i.len();
                    let n = if s_i.iter().map(|u| u.value).sum::<u64>() == target + base_fee + feerate_floor * (148 * m as u64 + 34) {
                        1
                    } else {
                        2
                    };
                    let adjusted_fee = base_fee + feerate_floor * (148 * m as u64 + 34 * n); // Adjust for inputs and outputs
                    let total_value: u64 = s_i.iter().map(|u| u.value).sum();
                    if total_value < target + adjusted_fee {
                        continue; // Retry with next stage if underfunded
                    }
                    // Tag reservation with NoteID (§6.6)
                    let note_id = sha256(&[scope.h_i.clone(), le32(i as u32)].concat());
                    r.insert(i, s_i.clone());
                    for utxo in &s_i {
                        used.insert(utxo.outpoint.clone());
                    }
                }
                None => {
                    if fanout_allowed && !fanout_done {
                        let fan_out = fan_out(&u_sorted, &used, split, feerate_floor, dust, scope, sender_anchor)?;
                        u_sorted = [
                            u_sorted
                                .iter()
                                .filter(|u| !used.contains(&u.outpoint))
                                .cloned()
                                .collect::<Vec<_>>(),
                            fan_out.outputs,
                        ]
                        .concat();
                        used.clear();
                        r.clear();
                        fanout_done = true;
                        continue 'outer;
                    } else {
                        return Err(PcwError::Other("Insufficient granularity §6.7".to_string()));
                    }
                }
            }
        }
        break;
    }
    Ok(r)
}

/// Result struct for fan-out operation.
struct FanOutResult {
    outputs: Vec<Utxo>,
}

/// Select disjoint inputs for target per stages A-D (§6.4).
fn select_inputs(
    u: &[Utxo],
    used: &HashSet<OutPoint>,
    target: u64,
    base_fee: u64,
    feerate: u64,
    dust: u64,
    k_max: usize,
    m_max: usize,
) -> Result<Option<Vec<Utxo>>, PcwError> {
    let mut available = u
        .iter()
        .filter(|utxo| !used.contains(&utxo.outpoint))
        .cloned()
        .collect::<Vec<_>>();
    available.sort_by(|a, b| {
        a.value
            .cmp(&b.value)
            .then(a.outpoint.hash.cmp(&b.outpoint.hash))
            .then(a.outpoint.index.cmp(&b.outpoint.index))
    });
    // Stage A: Exact single
    for utxo in &available {
        let m = 1;
        let fee = base_fee + feerate * (148 * m as u64 + 34); // 148 bytes per input, 34 for one output
        if utxo.value == target + fee {
            return Ok(Some(vec![utxo.clone()]));
        }
    }
    // Stage B: Exact few
    for card in 2..=k_max {
        if let Some(selected) = subset_sum(
            &available,
            target + base_fee + feerate * (148 * card as u64 + 34),
            card,
        )? {
            return Ok(Some(selected));
        }
    }
    // Stage C: Single near-over
    let mut best_single = None;
    let mut min_change = u64::MAX;
    for utxo in &available {
        let m = 1;
        let fee = base_fee + feerate * (148 * m as u64 + 34 * 2); // Two outputs (target + change)
        if utxo.value > target + fee {
            let change = utxo.value - target - fee;
            if change >= dust && change < min_change {
                min_change = change;
                best_single = Some(vec![utxo.clone()]);
            }
        }
    }
    if let Some(bs) = best_single {
        return Ok(Some(bs));
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
            if selected.len() < m && sum < target + base_fee + feerate * (148 * m as u64 + 34 * 2) {
                selected.push(utxo.clone());
                sum += utxo.value;
            }
        }
        let fee = base_fee + feerate * (148 * m as u64 + 34 * 2); // 68 for two outputs
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
    Ok(best_few)
}

/// Exact subset sum for Stage B (§6.4): DP with backtrack for small card.
fn subset_sum(available: &[Utxo], target: u64, card: usize) -> Result<Option<Vec<Utxo>>, PcwError> {
    let n = available.len();
    let target_usize = (target as usize).min(usize::MAX);
    let mut dp = vec![vec![false; target_usize + 1]; card + 1];
    dp[0][0] = true;
    let mut prev = vec![vec![None; target_usize + 1]; card + 1]; // (item idx, prev t)
    for i in 0..n {
        for c in (1..=card).rev() {
            for t in (available[i].value as usize..=target_usize).rev() {
                if dp[c - 1][t - available[i].value as usize] {
                    dp[c][t] = true;
                    prev[c][t] = Some((i, t - available[i].value as usize));
                }
            }
        }
    }
    if dp[card][target as usize] {
        let mut selected = vec![];
        let mut current_t = target as usize;
        let mut current_c = card;
        while current_c > 0 {
            if let Some((idx, prev_t)) = prev[current_c][current_t] {
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
/// NOTE: This is a stub for production. In a real wallet, replace dummy outpoints with actual ones
/// obtained from broadcasting the fan-out tx. Steps for production:
/// 1. Derive new payer addresses under "fund" label using scope and sender anchor.
/// 2. Build and sign a consolidation tx with available inputs and outputs of size ~ v_max.
/// 3. Broadcast the tx (e.g., via Electrum or P2P).
/// 4. Wait for confirmation (per policy depth).
/// 5. Fetch the new UTXOs with their real hash/index/script_pubkey.
/// For testing, dummy outpoints are used.
fn fan_out(
    u: &[Utxo],
    used: &HashSet<OutPoint>,
    split: &[u64],
    feerate: u64,
    dust: u64,
    scope: &Scope,
    sender_anchor: &PublicKey,
) -> Result<FanOutResult, PcwError> {
    let secp = Secp256k1::new();
    let available = u
        .iter()
        .filter(|utxo| !used.contains(&utxo.outpoint))
        .cloned()
        .collect::<Vec<_>>();
    let total = available.iter().map(|u| u.value).sum::<u64>();
    let v_max = split.iter().cloned().max().unwrap_or(0);
    let num_out = ((total + v_max - 1) / v_max) as usize + 1; // Buffer
    let out_value = max(total / num_out as u64, dust); // Ensure above dust
    let mut outputs = vec![];
    for k in 0..num_out {
        // Derive address under "fund" label (§6.8)
        let fund_addr = derive_address(&secp, scope, "fund", k as u32, sender_anchor)?;
        let script_pubkey = sv::transaction::p2pkh::create_lock_script(&Hash160(fund_addr.1));
        outputs.push(Utxo {
            outpoint: OutPoint {
                hash: [k as u8; 32], // Dummy for testing
                index: 0,
            },
            value: out_value,
            script_pubkey: script_pubkey.into_bytes(),
        });
    }
    Ok(FanOutResult { outputs })
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{PublicKey, SecretKey, Secp256k1};
    use sv::util::hash::Sha256;

    #[test]
    fn test_select_inputs_stage_a() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        let scope = Scope {
            z: vec![0; 32],
            h_i: Sha256([0; 32]).into(),
        };
        let anchor = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1; 32])?);
        let utxos = vec![Utxo {
            outpoint: OutPoint {
                hash: [0; 32],
                index: 0,
            },
            value: 150,
            script_pubkey: vec![],
        }];
        let used = HashSet::new();
        let selected = select_inputs(&utxos, &used, 100, 10, 1, 50, 5, 10)?;
        assert!(selected.is_some());
        let selected = selected.unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].value, 150);
        Ok(())
    }

    #[test]
    fn test_select_inputs_stage_c() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        let scope = Scope {
            z: vec![0; 32],
            h_i: Sha256([0; 32]).into(),
        };
        let anchor = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1; 32])?);
        let utxos = vec![Utxo {
            outpoint: OutPoint {
                hash: [0; 32],
                index: 0,
            },
            value: 200,
            script_pubkey: vec![],
        }];
        let used = HashSet::new();
        let selected = select_inputs(&utxos, &used, 100, 10, 1, 50, 5, 10)?;
        assert!(selected.is_some());
        let selected = selected.unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].value, 200);
        Ok(())
    }

    #[test]
    fn test_build_reservations_with_fanout() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        let scope = Scope {
            z: vec![0; 32],
            h_i: Sha256([0; 32]).into(),
        };
        let anchor = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1; 32])?);
        let utxos = vec![Utxo {
            outpoint: OutPoint {
                hash: [0; 32],
                index: 0,
            },
            value: 100,
            script_pubkey: vec![],
        }];
        let split = [150];
        let r = build_reservations(&utxos, &split, 1, 50, 5, 10, true, &scope, &anchor)?;
        assert_eq!(r.len(), 1);
        assert!(r[&0].len() > 0);
        Ok(())
    }

    #[test]
    fn test_fan_out_basic() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        let scope = Scope {
            z: vec![0; 32],
            h_i: Sha256([0; 32]).into(),
        };
        let anchor = PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[1; 32])?);
        let utxos = vec![Utxo {
            outpoint: OutPoint {
                hash: [0; 32],
                index: 0,
            },
            value: 300,
            script_pubkey: vec![],
        }];
        let used = HashSet::new();
        let split = [200];
        let fan_out = fan_out(&utxos, &used, &split, 1, 50, &scope, &anchor)?;
        assert_eq!(fan_out.outputs.len(), 2); // Should split into ~2 outputs
        assert!(fan_out.outputs[0].value >= 50); // Above dust
        Ok(())
    }
}
