//! Module for transaction management in the PCW-1 protocol.
//!
//! This module implements the note transaction building and signing logic as per §7-§8,
//! including the creation of `NoteTx` and `NoteMeta` structures. It handles the construction
//! of standard P2PKH transactions with deterministic addressing, signing, and metadata logging.
use crate::addressing::{recipient_address, sender_change_address};
use crate::errors::PcwError;
use crate::scope::{Scope, derive_scalar};
use crate::selection::Utxo;
use crate::utils::{base58check, h160, le32, point_add, scalar_mul, ser_p, sha256};
use chrono::Utc;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, ecdsa::Signature};
use serde::{Deserialize, Serialize};
use sv::messages::Tx;
use sv::script::Script;
use sv::script::op_codes::*;
use sv::transaction::p2pkh::{create_lock_script, create_unlock_script};
use sv::transaction::sighash::{SIGHASH_ALL, SIGHASH_FORKID, SigHashCache, sighash};
use sv::util::{Hash160, Hash256};

/// NoteMeta per §8.3: Canonical fields for log/audit.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NoteMeta {
    pub i: u32,
    pub note_id: String,
    pub invoice_hash: String,
    pub addr: String,
    pub amount: u64,
    pub txid: String,
    pub change_addr: String,
    pub change_amount: u64,
    pub size_bytes: u64,
    pub fee: u64,
    pub feerate_used: u64,
    pub inputs: Vec<InputMeta>,
    pub outputs: Vec<OutputMeta>,
    pub sig_alg: String,
    pub created_at: String,
    pub status: String,
}

/// InputMeta for NoteMeta.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InputMeta {
    pub hash: String,
    pub index: u32,
    pub value: u64,
    pub script_pubkey: String,
}

/// OutputMeta for NoteMeta.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OutputMeta {
    pub addr: String,
    pub value: u64,
}

/// Note transaction wrapper.
#[derive(Clone, Debug)]
pub struct NoteTx(pub Tx);

/// Build and sign note tx per §7-§8.
pub fn build_note_tx(
    scope: &Scope,
    i: u32,
    s_i: &[Utxo],
    amount: u64,
    anchor_b: &PublicKey,
    anchor_a: &PublicKey,
    feerate_floor: u64,
    dust: u64,
    priv_keys: &[[u8; 32]],
) -> Result<(NoteTx, NoteMeta), PcwError> {
    if s_i.len() != priv_keys.len() {
        return Err(PcwError::Other("Mismatched inputs/priv_keys".to_string()));
    }
    let secp = Secp256k1::new();
    let addr_b = recipient_address(&secp, scope, i, anchor_b)?;
    let t_i = scalar_mul(&derive_scalar(scope, "recv", i)?, &secp)?;
    let p_bi = point_add(anchor_b, &t_i)?;
    let h160_b = h160(&ser_p(&p_bi));
    let h160_b_hash = Hash160(h160_b);
    let m = s_i.len();
    let mut s_i_sorted = s_i.to_vec();
    s_i_sorted.sort_by(|a, b| {
        a.value
            .cmp(&b.value)
            .then(a.outpoint.hash.cmp(&b.outpoint.hash))
            .then(a.outpoint.index.cmp(&b.outpoint.index))
    });
    let sum_in: u64 = s_i_sorted.iter().map(|u| u.value).sum();
    let base_size = 10 + 148 * m as u64; // Base tx size without outputs (§7.3)
    let mut tx = Tx {
        version: 1,
        inputs: vec![],
        outputs: vec![],
        lock_time: 0,
    };
    // Initial fee estimate with one output
    let mut fee = ((feerate_floor * (base_size + 34)) + 999) / 1000; // 34 bytes for one output
    let mut change = sum_in.saturating_sub(amount + fee);
    let mut n = 1;
    if change > 0 && change < dust {
        return Err(PcwError::DustChange);
    }
    if sum_in < amount + fee {
        return Err(PcwError::Underfunded);
    }
    // Add recipient output
    let lock_b = create_lock_script(&h160_b_hash);
    tx.outputs.push(sv::messages::TxOut {
        satoshis: amount as i64,
        lock_script: lock_b,
    });
    // Determine if change output is needed
    let mut addr_a = String::new();
    let mut h160_a = [0; 20];
    if change > 0 {
        n = 2;
        fee = ((feerate_floor * (base_size + 68)) + 999) / 1000; // 68 bytes for two outputs
        change = sum_in.saturating_sub(amount + fee);
        if change > 0 && change >= dust {
            addr_a = sender_change_address(&secp, scope, i, anchor_a)?;
            let s_i_scalar = derive_scalar(scope, "snd", i)?;
            let tweak_a = scalar_mul(&s_i_scalar, &secp)?;
            let p_ai = point_add(anchor_a, &tweak_a)?;
            h160_a = h160(&ser_p(&p_ai));
            let h160_a_hash = Hash160(h160_a);
            let lock_a = create_lock_script(&h160_a_hash);
            tx.outputs.push(sv::messages::TxOut {
                satoshis: change as i64,
                lock_script: lock_a,
            });
        } else if change > 0 {
            return Err(PcwError::DustChange);
        }
    }
    // Add inputs
    for utxo in &s_i_sorted {
        tx.inputs.push(sv::messages::TxIn {
            prev_output: utxo.outpoint.clone(),
            unlock_script: Script::new(vec![]),
            sequence: 0xFFFFFFFF,
        });
    }
    // Sign transactions
    let mut cache = SigHashCache::new();
    for j in 0..m {
        let sighash = sighash(
            &tx,
            j,
            &s_i_sorted[j].script_pubkey,
            s_i_sorted[j].value.try_into().unwrap(),
            SIGHASH_ALL | SIGHASH_FORKID,
            &mut cache,
        )?;
        let msg = Message::from_digest(sighash.0);
        let secp = Secp256k1::new();
        let sig = secp.sign_ecdsa(&msg, &SecretKey::from_byte_array(priv_keys[j])?);
        let pub_key = PublicKey::from_secret_key(&secp, &SecretKey::from_byte_array(priv_keys[j])?);
        tx.inputs[j].unlock_script = create_unlock_script(&sig, &ser_p(&pub_key));
    }
    // Finalize metadata
    let tx_bytes = tx.to_bytes();
    let txid_hash = sha256(&sha256(&tx_bytes));
    let txid = hex::encode(txid_hash);
    let note_id = hex::encode(sha256(&[scope.h_i, le32(i)].concat()));
    let meta = NoteMeta {
        i,
        note_id,
        invoice_hash: hex::encode(scope.h_i),
        addr: addr_b,
        amount,
        txid,
        change_addr: addr_a,
        change_amount: change,
        size_bytes: tx_bytes.len() as u64,
        fee,
        feerate_used: feerate_floor,
        inputs: s_i_sorted
            .iter()
            .map(|u| InputMeta {
                hash: hex::encode(u.outpoint.hash.into_inner()),
                index: u.outpoint.index,
                value: u.value,
                script_pubkey: hex::encode(&u.script_pubkey),
            })
            .collect(),
        outputs: tx
            .outputs
            .iter()
            .map(|o| OutputMeta {
                addr: reverse_base58(&o.lock_script).unwrap_or_default(),
                value: o.satoshis as u64,
            })
            .collect(),
        sig_alg: "secp256k1-sha256".to_string(),
        created_at: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        status: "signed".to_string(),
    };
    Ok((NoteTx(tx), meta))
}

/// Reverse P2PKH lock to base58 addr (§8.3 optional, for meta).
fn reverse_base58(lock: &Vec<u8>) -> Option<String> {
    if lock.len() == 25
        && lock[0] == OP_DUP
        && lock[1] == OP_HASH160
        && lock[2] == 0x14
        && lock[23] == OP_EQUALVERIFY
        && lock[24] == OP_CHECKSIG
    {
        let h160 = &lock[3..23];
        base58check(0x00, h160).ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selection::Utxo;
    use secp256k1::SecretKey;
    use sv::messages::OutPoint;

    #[test]
    fn test_build_note_tx_no_change() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        let scope = Scope::new([1; 32], [2; 32])?;
        let utxo = Utxo {
            outpoint: OutPoint {
                hash: Hash256([0; 32]),
                index: 0,
            },
            value: 150,
            script_pubkey: vec![],
        };
        let priv_key = [1u8; 32];
        let anchor_b = PublicKey::from_secret_key(&secp, &SecretKey::from_byte_array(&priv_key)?);
        let anchor_a = anchor_b.clone(); // For testing
        let (tx, meta) = build_note_tx(
            &scope,
            0,
            &[utxo],
            100,
            &anchor_b,
            &anchor_a,
            1,
            50,
            &[priv_key],
        )?;
        assert_eq!(tx.0.outputs.len(), 1);
        assert_eq!(meta.amount, 100);
        assert_eq!(meta.change_amount, 0);
        assert!(meta.txid.len() > 0);
        Ok(())
    }

    #[test]
    fn test_build_note_tx_with_change() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        let scope = Scope::new([1; 32], [2; 32])?;
        let utxo = Utxo {
            outpoint: OutPoint {
                hash: Hash256([0; 32]),
                index: 0,
            },
            value: 200,
            script_pubkey: vec![],
        };
        let priv_key = [1u8; 32];
        let anchor_b = PublicKey::from_secret_key(&secp, &SecretKey::from_byte_array(&priv_key)?);
        let anchor_a = anchor_b.clone(); // For testing
        let (tx, meta) = build_note_tx(
            &scope,
            0,
            &[utxo],
            100,
            &anchor_b,
            &anchor_a,
            1,
            50,
            &[priv_key],
        )?;
        assert_eq!(tx.0.outputs.len(), 2);
        assert_eq!(meta.amount, 100);
        assert!(meta.change_amount >= 50); // Change should be at least dust
        assert!(meta.txid.len() > 0);
        Ok(())
    }

    #[test]
    fn test_build_note_tx_dust_reject() {
        let secp = Secp256k1::new();
        let scope = Scope::new([1; 32], [2; 32]).expect("Valid scope");
        let utxo = Utxo {
            outpoint: OutPoint {
                hash: Hash256([0; 32]),
                index: 0,
            },
            value: 151,
            script_pubkey: vec![],
        };
        let priv_key = [1u8; 32];
        let anchor_b = PublicKey::from_secret_key(&secp, &SecretKey::from_byte_array(&priv_key)?);
        let anchor_a = anchor_b.clone();
        let result = build_note_tx(
            &scope,
            0,
            &[utxo],
            100,
            &anchor_b,
            &anchor_a,
            1,
            50,
            &[priv_key],
        );
        assert!(result.is_err()); // Should fail due to dust change
    }

    #[test]
    fn test_build_note_tx_underfunded() {
        let secp = Secp256k1::new();
        let scope = Scope::new([1; 32], [2; 32]).expect("Valid scope");
        let utxo = Utxo {
            outpoint: OutPoint {
                hash: Hash256([0; 32]),
                index: 0,
            },
            value: 50,
            script_pubkey: vec![],
        };
        let priv_key = [1u8; 32];
        let anchor_b = PublicKey::from_secret_key(&secp, &SecretKey::from_byte_array(&priv_key)?);
        let anchor_a = anchor_b.clone();
        let result = build_note_tx(
            &scope,
            0,
            &[utxo],
            100,
            &anchor_b,
            &anchor_a,
            1,
            50,
            &[priv_key],
        );
        assert!(result.is_err()); // Should fail due to underfunding
    }

    #[test]
    fn test_reverse_base58_valid() {
        let lock_script = vec![
            OP_DUP,
            OP_HASH160,
            0x14,
            0x12,
            0x56,
            0x78,
            0x9a,
            0xbc,
            0xde,
            0xf0,
            0x12,
            0x34,
            0x56,
            0x78,
            0x9a,
            0xbc,
            0xde,
            0xf0,
            0x12,
            0x34,
            0x56,
            0x78,
            0x9a,
            OP_EQUALVERIFY,
            OP_CHECKSIG,
        ];
        let addr = reverse_base58(&lock_script).unwrap();
        assert!(addr.len() > 0); // Valid P2PKH should return a base58 address
    }

    #[test]
    fn test_reverse_base58_invalid() {
        let lock_script = vec![OP_DUP]; // Invalid script
        let addr = reverse_base58(&lock_script);
        assert!(addr.is_none()); // Should return None for invalid script
    }
}
