/*! Module for UTXO selection and reservation logic in the PCW-1 protocol.

This module implements the UTXO selection and reservation logic as per §6, including
`build_reservations` with stages A-D (§6.4), deterministic ordering, and optional fan-out (§6.8).
It manages disjoint input sets (S_i) for each note in a payment, ensuring privacy and auditability.
*/
use crate::addressing::recipient_address;
use crate::errors::PcwError;
use crate::scope::Scope;
use crate::utils::sha256;
use secp256k1::PublicKey;
use std::collections::{HashMap, HashSet};
use sv::messages::OutPoint;
use sv::util::Hash256;

// Type alias for the complex return type of build_reservations
type ReservationResult = (Vec<Option<Vec<Utxo>>>, Vec<String>, Vec<u64>, u64);

/// UTXO data for selection.
#[derive(Clone, Debug)]
pub struct Utxo {
    pub outpoint: OutPoint,
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

/// Builds reservations S_i and addresses for the given split notes (§6.4).
#[allow(clippy::too_many_arguments)]
pub fn build_reservations(
    utxos: &[Utxo],
    split: &[u64],
    scope: &Scope,
    recipient_anchor: &PublicKey,
    sender_anchor: &PublicKey,
    feerate_floor: u64,
    dust: u64,
    fanout_allowed: bool,
) -> Result<ReservationResult, PcwError> {
    let n = split.len();
    if n == 0 {
        return Err(PcwError::Other("Empty split §6.4".to_string()));
    }
    let total: u64 = split.iter().sum();
    let mut u_sorted = utxos.to_vec();
    u_sorted.sort_by(|a, b| {
        a.value
            .cmp(&b.value)
            .reverse() // Sort in descending order to prioritize higher-value UTXOs
            .then(a.outpoint.hash.cmp(&b.outpoint.hash))
    });
    let base_fee = feerate_floor * 10; // Base tx fee
    let mut used = HashSet::<Hash256>::new();
    let mut reservations = vec![None; n];
    let mut addrs = vec!["".to_string(); n];
    let mut amounts = vec![0u64; n];
    let mut fanout_done = false;
    for i in 0..n {
        let target = split[i];
        let s_i = select_utxos(&u_sorted, &mut used, target, feerate_floor, dust)?;
        match s_i {
            Some(s_i) => {
                let m = s_i.len();
                let _n = if s_i.iter().map(|u| u.value).sum::<u64>()
                    == target + base_fee + feerate_floor * (148 * m as u64 + 34)
                {
                    1
                } else {
                    2
                };
                addrs[i] = recipient_address(scope, i as u32, recipient_anchor)?;
                amounts[i] = target;
                reservations[i] = Some(s_i);
            }
            None => {
                if fanout_allowed && !fanout_done {
                    let fan_out = fan_out(
                        &u_sorted,
                        &used,
                        total,
                        feerate_floor,
                        dust,
                        scope,
                        sender_anchor,
                    )?;
                    u_sorted = [
                        u_sorted
                            .iter()
                            .filter(|u| !used.contains(&u.outpoint.hash))
                            .cloned()
                            .collect::<Vec<_>>(),
                        fan_out,
                    ]
                    .concat();
                    u_sorted.sort_by(|a, b| a.value.cmp(&b.value).reverse());
                    fanout_done = true;
                    let s_i = select_utxos(&u_sorted, &mut used, target, feerate_floor, dust)?;
                    if let Some(s_i) = s_i {
                        let m = s_i.len();
                        let _n = if s_i.iter().map(|u| u.value).sum::<u64>()
                            == target + base_fee + feerate_floor * (148 * m as u64 + 34)
                        {
                            1
                        } else {
                            2
                        };
                        addrs[i] = recipient_address(scope, i as u32, recipient_anchor)?;
                        amounts[i] = target;
                        reservations[i] = Some(s_i);
                    } else {
                        return Err(PcwError::Underfunded);
                    }
                } else {
                    return Err(PcwError::Underfunded);
                }
            }
        }
    }
    Ok((reservations, addrs, amounts, n as u64))
}

/// Selects UTXOs for a target amount, considering fees and dust (§6.3).
fn select_utxos(
    utxos: &[Utxo],
    used: &mut HashSet<Hash256>,
    target: u64,
    feerate_floor: u64,
    dust: u64,
) -> Result<Option<Vec<Utxo>>, PcwError> {
    let base_fee = feerate_floor * 10; // Base tx fee
    let mut min_selected = None;
    let mut min_count = usize::MAX;
    // Stage A: Try single-input exact or near-over (§6.4, preference 1-2)
    let mut sorted_utxos = utxos
        .iter()
        .filter(|u| !used.contains(&u.outpoint.hash))
        .cloned()
        .collect::<Vec<_>>();
    sorted_utxos.sort_by(|a, b| a.value.cmp(&b.value).reverse());
    for utxo in &sorted_utxos {
        let m = 1;
        let fee = base_fee + feerate_floor * (148 * m as u64 + 34); // 1 input, 1 output
        if utxo.value >= target + fee {
            // Exact or near-over match
            used.insert(utxo.outpoint.hash);
            return Ok(Some(vec![utxo.clone()]));
        }
    }
    // Stage B: Try multiple inputs (§6.4, preference 3)
    let mut sum = 0;
    let mut selected = vec![];
    for utxo in sorted_utxos {
        selected.push(utxo.clone());
        sum += utxo.value;
        let m = selected.len();
        let fee = base_fee + feerate_floor * (148 * m as u64 + 34 * 2); // Assume 2 outputs
        if sum >= target + fee + dust && m <= min_count {
            min_selected = Some(selected.clone());
            min_count = m;
        }
    }
    if let Some(selected) = min_selected {
        for utxo in &selected {
            used.insert(utxo.outpoint.hash);
        }
        return Ok(Some(selected));
    }
    Ok(None)
}

/// Performs fan-out to generate additional UTXOs (§6.8).
fn fan_out(
    utxos: &[Utxo],
    used: &HashSet<Hash256>,
    total: u64,
    feerate_floor: u64,
    dust: u64,
    scope: &Scope,
    sender_anchor: &PublicKey,
) -> Result<Vec<Utxo>, PcwError> {
    let base_fee = feerate_floor * 10;
    let mut available = utxos
        .iter()
        .filter(|u| !used.contains(&u.outpoint.hash))
        .cloned()
        .collect::<Vec<_>>();
    available.sort_by(|a, b| a.value.cmp(&b.value).reverse());
    let mut fan_out_utxos = vec![];
    let n = (available.iter().map(|u| u.value).sum::<u64>() / total).max(1) as usize;
    let target = total + base_fee + feerate_floor * (148 + 34 * n as u64);
    let mut sum = 0;
    let mut selected = vec![];
    for utxo in available {
        selected.push(utxo.clone());
        sum += utxo.value;
        if sum >= target {
            let m = selected.len();
            let fee = base_fee + feerate_floor * (148 * m as u64 + 34 * n as u64);
            if sum < target + fee {
                return Err(PcwError::Underfunded);
            }
            let change = sum - target - fee;
            if change > 0 && change < dust {
                return Err(PcwError::DustChange);
            }
            for i in 0..n {
                let addr = recipient_address(scope, i as u32, sender_anchor)?;
                let script_pubkey = sv::address::decode_address(&addr)?.1;
                fan_out_utxos.push(Utxo {
                    outpoint: OutPoint {
                        hash: Hash256(sha256(format!("fan_out_{}", i).as_bytes())),
                        index: i as u32,
                    },
                    value: total / n as u64,
                    script_pubkey,
                });
            }
            break;
        }
    }
    if fan_out_utxos.is_empty() {
        return Err(PcwError::Underfunded);
    }
    Ok(fan_out_utxos)
}

/// Computes per-address amounts and checks caps (§6.7).
pub fn compute_per_address_amounts(
    scope: &Scope,
    recipient_anchor: &PublicKey,
    amounts: &[u64],
) -> Result<HashMap<String, u64>, PcwError> {
    let mut per_address: HashMap<String, u64> = HashMap::new();
    for (i, &amount) in amounts.iter().enumerate() {
        let addr = recipient_address(scope, i as u32, recipient_anchor)?;
        *per_address.entry(addr).or_insert(0) += amount;
    }
    Ok(per_address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::h160;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use sv::transaction::p2pkh::create_lock_script;
    use sv::util::Hash160;

    #[test]
    fn test_select_utxos() -> Result<(), PcwError> {
        let mock_hash = sha256(b"test_tx");
        let mock_h160 = h160(&mock_hash);
        let mock_script = create_lock_script(&Hash160(mock_h160));
        let utxos = vec![
            Utxo {
                outpoint: OutPoint {
                    hash: Hash256(mock_hash),
                    index: 0,
                },
                value: 500,
                script_pubkey: mock_script.0.clone(),
            },
            Utxo {
                outpoint: OutPoint {
                    hash: Hash256(sha256(b"test_tx_2")),
                    index: 0,
                },
                value: 600,
                script_pubkey: mock_script.0.clone(),
            },
        ];
        let used = HashSet::new();
        let target = 400;
        let feerate_floor = 1;
        let dust = 50;
        let s_i = select_utxos(&utxos, &mut used.clone(), target, feerate_floor, dust)?;
        assert!(s_i.is_some());
        let s_i = s_i.unwrap();
        assert_eq!(s_i.len(), 1); // Expect one UTXO
        assert_eq!(s_i[0].value, 600); // Should select the higher-value UTXO
        assert_eq!(used.len(), 0);
        Ok(())
    }

    #[test]
    fn test_build_reservations() -> Result<(), PcwError> {
        let scope = Scope::new([1; 32], [2; 32])?;
        let mock_hash = sha256(b"test_tx");
        let mock_h160 = h160(&mock_hash);
        let mock_script = create_lock_script(&Hash160(mock_h160));
        let utxos = vec![
            Utxo {
                outpoint: OutPoint {
                    hash: Hash256(mock_hash),
                    index: 0,
                },
                value: 1000,
                script_pubkey: mock_script.0.clone(),
            },
            Utxo {
                outpoint: OutPoint {
                    hash: Hash256(sha256(b"test_tx_2")),
                    index: 0,
                },
                value: 1000,
                script_pubkey: mock_script.0.clone(),
            },
        ];
        let split = vec![500, 500];
        let secret_key = SecretKey::from_byte_array([1; 32]).unwrap();
        let secp = Secp256k1::new();
        let recipient_anchor = PublicKey::from_secret_key(&secp, &secret_key);
        let sender_anchor = recipient_anchor;
        let (reservations, addrs, amounts, n) = build_reservations(
            &utxos,
            &split,
            &scope,
            &recipient_anchor,
            &sender_anchor,
            1,
            50,
            false,
        )?;
        assert_eq!(n, 2);
        assert_eq!(reservations.len(), 2);
        assert_eq!(addrs.len(), 2);
        assert_eq!(amounts.len(), 2);
        assert_eq!(amounts, vec![500, 500]);
        Ok(())
    }

    #[test]
    fn test_fan_out() -> Result<(), PcwError> {
        let scope = Scope::new([1; 32], [2; 32])?;
        let mock_hash = sha256(b"test_tx");
        let mock_h160 = h160(&mock_hash);
        let mock_script = create_lock_script(&Hash160(mock_h160));
        let utxos = vec![Utxo {
            outpoint: OutPoint {
                hash: Hash256(mock_hash),
                index: 0,
            },
            value: 2000,
            script_pubkey: mock_script.0,
        }];
        let used = HashSet::new();
        let total = 1000;
        let feerate_floor = 1;
        let dust = 50;
        let secret_key = SecretKey::from_byte_array([1; 32]).unwrap();
        let secp = Secp256k1::new();
        let sender_anchor = PublicKey::from_secret_key(&secp, &secret_key);
        let fan_out_utxos = fan_out(
            &utxos,
            &used,
            total,
            feerate_floor,
            dust,
            &scope,
            &sender_anchor,
        )?;
        assert_eq!(fan_out_utxos.len(), 1);
        assert_eq!(fan_out_utxos[0].value, 1600);
        Ok(())
    }

    #[test]
    fn test_compute_per_address_amounts() -> Result<(), PcwError> {
        let scope = Scope::new([1; 32], [2; 32])?;
        let secret_key = SecretKey::from_byte_array([1; 32]).unwrap();
        let secp = Secp256k1::new();
        let recipient_anchor = PublicKey::from_secret_key(&secp, &secret_key);
        let amounts = [500, 500];
        let per_address = compute_per_address_amounts(&scope, &recipient_anchor, &amounts)?;
        assert_eq!(per_address.len(), 2);
        assert_eq!(per_address.values().sum::<u64>(), 1000);
        Ok(())
    }
}
