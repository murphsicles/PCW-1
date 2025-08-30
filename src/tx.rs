use crate::errors::PcwError;
use crate::scope::Scope;
use crate::utils::{h160, le32, sha256, ser_p};
use crate::addressing::{recipient_address, sender_change_address};
use sv::messages::{OutPoint, Tx, TxIn, TxOut};
use sv::script::op_codes::*;
use sv::transaction::generate_signature;
use sv::transaction::p2pkh::{create_lock_script, create_unlock_script};
use sv::transaction::sighash::{sighash, SigHashCache, SIGHASH_ALL, SIGHASH_FORKID};
use sv::util::Hash256;
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

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
    pub txid: String,
    pub vout: u32,
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
    priv_keys: &[[u8;32]],
) -> Result<(NoteTx, NoteMeta), PcwError> {
    if s_i.len() != priv_keys.len() {
        return Err(PcwError::Other("Mismatched inputs/priv_keys".to_string()));
    }
    let addr_b = recipient_address(scope, i, anchor_b)?;
    let m = s_i.len();
    let sum_in = s_i.iter().map(|u| u.value).sum::<u64>();
    let size1 = 10 + 148 * m as u64 + 34;
    let fee1 = ((feerate_floor * size1) + 999) / 1000; // ceil
    let n = if sum_in == amount + fee1 {
        1
    } else {
        let size2 = 10 + 148 * m as u64 + 68;
        let fee2 = ((feerate_floor * size2) + 999) / 1000;
        let change = sum_in.saturating_sub(amount + fee2);
        if change < dust && change > 0 {
            return Err(PcwError::DustChange);
        } if sum_in < amount + fee2 {
            return Err(PcwError::Underfunded);
        }
        2
    };
    let fee = if n == 1 { fee1 } else { ((feerate_floor * (10 + 148 * m as u64 + 34 * n as u64)) + 999) / 1000 };
    let change = sum_in - amount - fee;
    let addr_a = if n == 2 { sender_change_address(scope, i, anchor_a)? } else { "".to_string() };
    // Sort inputs: value asc, txid asc, vout asc §8.4
    let mut s_i_sorted = s_i.to_vec();
    s_i_sorted.sort_by(|a, b| a.value.cmp(&b.value).then(a.outpoint.txid.cmp(&b.outpoint.txid)).then(a.outpoint.vout.cmp(&b.outpoint.vout)));
    let mut tx = Tx::new(1, vec![], vec![], 0);
    for utxo in &s_i_sorted {
        tx.inputs.push(TxIn::new(utxo.outpoint.clone(), vec![], 0xFFFFFFFF));
    }
    let lock_b = create_lock_script(&h160(&ser_p(anchor_b))); // Wait, for Addr_B,i: h160 of P_B,i
    let p_bi = // Compute P_B,i as in addressing
    let h160_b = h160(&ser_p(&p_bi));
    let lock_b = create_lock_script(&h160_b);
    tx.outputs.push(TxOut::new(amount, lock_b));
    if n == 2 {
        let p_ai = // Compute P_A,i
        let h160_a = h160(&ser_p(&p_ai));
        let lock_a = create_lock_script(&h160_a);
        tx.outputs.push(TxOut::new(change, lock_a));
    }
    // Sign each input SIGHASH_ALL §8.5
    let mut cache = SigHashCache::new();
    for j in 0..m {
        let sighash = sighash(&tx, j, &s_i_sorted[j].script_pubkey, s_i_sorted[j].value, SIGHASH_ALL | SIGHASH_FORKID)?;
        let sig = generate_signature(&priv_keys[j], &Hash256(sighash.0), SIGHASH_ALL | SIGHASH_FORKID)?;
        let pub_key = PublicKey::from_secret_key(SECP256K1, &SecretKey::from_slice(&priv_keys[j])?);
        tx.inputs[j].unlock_script = create_unlock_script(&sig, &ser_p(&pub_key));
    }
    let tx_bytes = tx.serialize();
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
        size_bytes: tx_bytes.len() as u64, // Actual size
        fee,
        feerate_used: feerate_floor,
        inputs: s_i_sorted.iter().map(|u| InputMeta { txid: hex::encode(u.outpoint.txid), vout: u.outpoint.vout, value: u.value, script_pubkey: hex::encode(&u.script_pubkey) }).collect(),
        outputs: tx.outputs.iter().map(|o| OutputMeta { addr: "todo: reverse to base58", value: o.value }).collect(), // Impl reverse addr from lock
        sig_alg: "secp256k1-sha256".to_string(),
        created_at: Utc::now().to_rfc3339(),
        status: "unsigned".to_string(),
    };
    Ok((NoteTx(tx), meta))
}

#[cfg(test)]
mod tests {
    // Full test for tx build, sig, fee/change, reject cases
}
