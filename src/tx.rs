/*! Module for transaction management in the PCW-1 protocol.
This module implements the note transaction building and signing logic as per §7-§8,
including the creation of `NoteTx` and `NoteMeta` structures. It handles the construction
of standard P2PKH transactions with deterministic addressing, signing, and metadata logging.
*/
use crate::addressing::{recipient_address, sender_change_address};
use crate::errors::PcwError;
use crate::scope::Scope;
use crate::selection::Utxo;
use crate::utils::{base58check, h160, le32, point_add, scalar_mul, ser_p, sha256};
use chrono::Utc;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use std::io::Write;
use sv::messages::{Tx, TxIn, TxOut};
use sv::script::Script;
use sv::script::op_codes::*;
use sv::transaction::p2pkh::{create_lock_script, create_unlock_script};
use sv::transaction::sighash::{SIGHASH_ALL, SIGHASH_FORKID, SigHashCache, sighash};
use sv::util::Hash160;

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

/// Build and sign note transaction (T_i) per §7-§8.
#[allow(clippy::too_many_arguments)]
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
    let _secp = Secp256k1::new();
    // Validate anchor_b and anchor_a (§4.9, §7.7)
    if anchor_b.serialize().len() != 33 || anchor_a.serialize().len() != 33 {
        return Err(PcwError::Other("Invalid anchor public key §7".to_string()));
    }
    if s_i.len() != priv_keys.len() {
        return Err(PcwError::Other(
            "Mismatched inputs/priv_keys §8".to_string(),
        ));
    }
    let addr_b = recipient_address(scope, i, anchor_b)?;
    let t_i = scalar_mul(&scope.derive_scalar("recv", i)?)?;
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
    // Fee estimate with one output (§7.3)
    let fee = (base_size + 34) * feerate_floor; // 34 bytes for one output
    let change = sum_in
        .checked_sub(amount)
        .and_then(|x| x.checked_sub(fee))
        .ok_or(PcwError::Underfunded)?;
    if change > 0 && change < dust {
        return Err(PcwError::DustChange);
    }
    // Add recipient output
    let lock_b = create_lock_script(&h160_b_hash);
    tx.outputs.push(TxOut {
        satoshis: amount as i64,
        lock_script: lock_b,
    });
    // Determine if change output is needed
    let mut addr_a = String::new();
    let mut change_amount = 0;
    if change > 0 {
        let fee_two_outputs = (base_size + 68) * feerate_floor; // 68 bytes for two outputs
        let change_two_outputs = sum_in
            .checked_sub(amount)
            .and_then(|x| x.checked_sub(fee_two_outputs))
            .ok_or(PcwError::Underfunded)?;
        if change_two_outputs > 0 && change_two_outputs >= dust {
            addr_a = sender_change_address(scope, i, anchor_a)?;
            let s_i_scalar = scope.derive_scalar("snd", i)?;
            let tweak_a = scalar_mul(&s_i_scalar)?;
            let p_ai = point_add(anchor_a, &tweak_a)?;
            let h160_a = h160(&ser_p(&p_ai));
            let h160_a_hash = Hash160(h160_a);
            let lock_a = create_lock_script(&h160_a_hash);
            tx.outputs.push(TxOut {
                satoshis: change_two_outputs as i64,
                lock_script: lock_a,
            });
            change_amount = change_two_outputs;
        } else if change_two_outputs > 0 {
            return Err(PcwError::DustChange);
        }
    }
    // Add inputs
    for utxo in &s_i_sorted {
        tx.inputs.push(TxIn {
            prev_output: utxo.outpoint.clone(),
            unlock_script: Script::new(),
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
        let sig = secp.sign_ecdsa(msg, &SecretKey::from_byte_array(priv_keys[j])?);
        let pub_key = PublicKey::from_secret_key(&secp, &SecretKey::from_byte_array(priv_keys[j])?);
        tx.inputs[j].unlock_script = create_unlock_script(&sig.serialize_der(), &ser_p(&pub_key));
    }
    // Finalize metadata
    let mut tx_bytes = Vec::new();
    {
        let writer = &mut tx_bytes;
        writer.write_all(&tx.version.to_le_bytes())?;
        let input_count = tx.inputs.len() as u64;
        writer.write_all(&input_count.to_le_bytes())?;
        for input in &tx.inputs {
            writer.write_all(&input.prev_output.hash.0)?;
            writer.write_all(&input.prev_output.index.to_le_bytes())?;
            writer.write_all(&input.unlock_script.0)?;
            writer.write_all(&input.sequence.to_le_bytes())?;
        }
        let output_count = tx.outputs.len() as u64;
        writer.write_all(&output_count.to_le_bytes())?;
        for output in &tx.outputs {
            writer.write_all(&output.satoshis.to_le_bytes())?;
            writer.write_all(&output.lock_script.0)?;
        }
        writer.write_all(&tx.lock_time.to_le_bytes())?;
    }
    let txid_hash = sha256(&sha256(&tx_bytes));
    let txid = hex::encode(txid_hash);
    let note_id = hex::encode(sha256(&[scope.h_i.to_vec(), le32(i).to_vec()].concat()));
    let meta = NoteMeta {
        i,
        note_id,
        invoice_hash: hex::encode(scope.h_i),
        addr: addr_b,
        amount,
        txid,
        change_addr: addr_a,
        change_amount,
        size_bytes: tx_bytes.len() as u64,
        fee: if tx.outputs.len() == 1 { fee } else { fee + 34 * feerate_floor },
        feerate_used: feerate_floor,
        inputs: s_i_sorted
            .iter()
            .map(|u| InputMeta {
                hash: hex::encode(u.outpoint.hash.0),
                index: u.outpoint.index,
                value: u.value,
                script_pubkey: hex::encode(&u.script_pubkey),
            })
            .collect(),
        outputs: tx
            .outputs
            .iter()
            .map(|o| {
                let addr = reverse_base58(&o.lock_script.0)?;
                Ok(OutputMeta {
                    addr,
                    value: o.satoshis as u64,
                })
            })
            .collect::<Result<Vec<OutputMeta>, PcwError>>()?,
        sig_alg: "secp256k1-sha256".to_string(),
        created_at: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        status: "signed".to_string(),
    };
    Ok((NoteTx(tx), meta))
}

/// Reverse P2PKH lock to base58 address (Addr_B,i or Addr_A,i) (§8.3 optional, for meta).
fn reverse_base58(lock: &[u8]) -> Result<String, PcwError> {
    if lock.len() != 25 {
        return Err(PcwError::Other(
            "Invalid script length for P2PKH §8.3".to_string(),
        ));
    }
    if lock[0] != OP_DUP
        || lock[1] != OP_HASH160
        || lock[2] != 0x14
        || lock[23] != OP_EQUALVERIFY
        || lock[24] != OP_CHECKSIG
    {
        return Err(PcwError::Other(
            "Invalid script format for P2PKH §8.3".to_string(),
        ));
    }
    let h160 = &lock[3..23];
    base58check(0x00, h160)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selection::Utxo;
    use secp256k1::SecretKey;
    use sv::messages::OutPoint;
    use sv::util::{Hash160, Hash256};

    #[test]
    fn test_build_note_tx_no_change() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        let scope = Scope::new([1; 32], [2; 32])?;
        let mock_hash = sha256(b"test_tx");
        let mock_h160 = h160(&mock_hash);
        let mock_script = create_lock_script(&Hash160(mock_h160));
        let utxo = Utxo {
            outpoint: OutPoint {
                hash: Hash256(mock_hash),
                index: 0,
            },
            value: 383,
            script_pubkey: mock_script.0,
        };
        let priv_key = [1u8; 32];
        let anchor_b = PublicKey::from_secret_key(&secp, &SecretKey::from_byte_array(priv_key)?);
        let anchor_a = anchor_b; // For testing
        let (tx, meta) = build_note_tx(
            &scope,
            0,
            &[utxo],
            191,
            &anchor_b,
            &anchor_a,
            1,
            50,
            &[priv_key],
        )?;
        assert_eq!(tx.0.outputs.len(), 1);
        assert_eq!(meta.amount, 191);
        assert_eq!(meta.change_amount, 0);
        assert!(meta.txid.len() > 0);
        Ok(())
    }

    #[test]
    fn test_build_note_tx_with_change() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        let scope = Scope::new([1; 32], [2; 32])?;
        let mock_hash = sha256(b"test_tx");
        let mock_h160 = h160(&mock_hash);
        let mock_script = create_lock_script(&Hash160(mock_h160));
        let utxo = Utxo {
            outpoint: OutPoint {
                hash: Hash256(mock_hash),
                index: 0,
            },
            value: 376,
            script_pubkey: mock_script.0,
        };
        let priv_key = [1u8; 32];
        let anchor_b = PublicKey::from_secret_key(&secp, &SecretKey::from_byte_array(priv_key)?);
        let anchor_a = anchor_b; // For testing
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
    fn test_build_note_tx_dust_reject() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        let scope = Scope::new([1; 32], [2; 32])?;
        let mock_hash = sha256(b"test_tx");
        // Use a fixed h160 to match ripemd output
        let mock_h160 = hex::decode("b472a266d0bd89c13706a4132ccfb16f7c3b9fcb")
            .unwrap()
            .try_into()
            .unwrap();
        let mock_script = create_lock_script(&Hash160(mock_h160));
        let utxo = Utxo {
            outpoint: OutPoint {
                hash: Hash256(mock_hash),
                index: 0,
            },
            value: 258, // Triggers DustChange: 258 - 100 - 226 = 32 < 50
            script_pubkey: mock_script.0,
        };
        let priv_key = [1u8; 32];
        let anchor_b = PublicKey::from_secret_key(&secp, &SecretKey::from_byte_array(priv_key)?);
        let anchor_a = anchor_b;
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
        if let Err(PcwError::DustChange) = result {
            Ok(())
        } else {
            // Debug assertions to diagnose failure
            let sum_in: u64 = 258;
            let base_size = 10 + 148 * 1;
            let fee_one_output = (base_size + 34) * 1;
            let change_one_output = sum_in
                .checked_sub(100)
                .and_then(|x| x.checked_sub(fee_one_output))
                .unwrap_or(0);
            let fee_two_outputs = (base_size + 68) * 1;
            let change_two_outputs = sum_in
                .checked_sub(100)
                .and_then(|x| x.checked_sub(fee_two_outputs))
                .unwrap_or(0);
            panic!(
                "Expected DustChange, got {:?}. sum_in={}, fee_one_output={}, change_one_output={}, fee_two_outputs={}, change_two_outputs={}",
                result, sum_in, fee_one_output, change_one_output, fee_two_outputs, change_two_outputs
            );
        }
    }

    #[test]
    fn test_build_note_tx_underfunded() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        let scope = Scope::new([1; 32], [2; 32])?;
        let mock_hash = sha256(b"test_tx");
        let mock_h160 = h160(&mock_hash);
        let mock_script = create_lock_script(&Hash160(mock_h160));
        let utxo = Utxo {
            outpoint: OutPoint {
                hash: Hash256(mock_hash),
                index: 0,
            },
            value: 50,
            script_pubkey: mock_script.0,
        };
        let priv_key = [1u8; 32];
        let anchor_b = PublicKey::from_secret_key(&secp, &SecretKey::from_byte_array(priv_key)?);
        let anchor_a = anchor_b;
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
        assert!(matches!(result, Err(PcwError::Underfunded)));
        Ok(())
    }

    #[test]
    fn test_reverse_base58_valid() -> Result<(), PcwError> {
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
        let addr = reverse_base58(&lock_script)?;
        assert!(addr.len() > 0); // Valid P2PKH should return a base58 address
        Ok(())
    }

    #[test]
    fn test_reverse_base58_invalid() -> Result<(), PcwError> {
        let lock_script = vec![OP_DUP]; // Invalid script
        let result = reverse_base58(&lock_script);
        assert!(
            matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid script length"))
        );
        Ok(())
    }

    #[test]
    fn test_reverse_base58_non_standard() -> Result<(), PcwError> {
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
            OP_EQUAL, // Non-standard opcode
            OP_CHECKSIG,
        ];
        let result = reverse_base58(&lock_script);
        assert!(
            matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid script format"))
        );
        Ok(())
    }
}
