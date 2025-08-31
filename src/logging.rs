use crate::errors::PcwError;
use crate::json::canonical_json;
use crate::keys::IdentityKeypair;
use crate::utils::sha256;
use chrono::prelude::*;
use serde::Serialize;
use secp256k1::{Message, Secp256k1};
use std::collections::HashMap;

/// Trait for signed, append-only logs (§13.6-§13.7).
pub trait LogRecord: Serialize {
    fn sign(&mut self, key: &IdentityKeypair) -> Result<(), PcwError>;
    fn verify(&self) -> Result<(), PcwError>;
    fn prev_hash(&self) -> String;
    fn seq(&self) -> u64;
}

/// Reissue record (§11.6).
#[derive(Serialize, Clone, Debug)]
pub struct ReissueRecord {
    pub invoice_hash: String,
    pub i: u32,
    pub note_id: String,
    pub event: String, // "reissue"
    pub version: u64,
    pub supersedes: String,
    pub txid_new: String,
    pub addr_recv: String,
    pub addr_change: String,
    pub fee: u64,
    pub feerate_used: u64,
    pub at: String,
    pub by: String,
    pub sig_alg: String,
    pub sig: String,
    pub prev_hash: String,
    pub seq: u64,
}

impl LogRecord for ReissueRecord {
    fn sign(&mut self, key: &IdentityKeypair) -> Result<(), PcwError> {
        self.by = hex::encode(key.pub_key.serialize());
        self.sig_alg = "secp256k1-sha256".to_string();
        let mut unsigned = self.clone();
        unsigned.sig = "".to_string();
        unsigned.by = "".to_string();
        unsigned.sig_alg = "".to_string();
        let bytes = canonical_json(&unsigned)?;
        let hash = sha256(&bytes);
        let msg = Message::from_slice(&hash)?;
        let secp = Secp256k1::new();
        let sig = secp.sign_ecdsa(&msg, &SecretKey::from_slice(&key.priv_key)?);
        self.sig = hex::encode(sig.serialize_der());
        Ok(())
    }

    fn verify(&self) -> Result<(), PcwError> {
        let mut unsigned = self.clone();
        unsigned.sig = "".to_string();
        unsigned.by = "".to_string();
        unsigned.sig_alg = "".to_string();
        let bytes = canonical_json(&unsigned)?;
        let hash = sha256(&bytes);
        let msg = Message::from_slice(&hash)?;
        let pub_key = PublicKey::from_slice(&hex::decode(&self.by)?)?;
        let sig = ecdsa::Signature::from_der(&hex::decode(&self.sig)?)?;
        let secp = Secp256k1::new();
        secp.verify_ecdsa(&msg, &sig, &pub_key)?;
        Ok(())
    }

    fn prev_hash(&self) -> String {
        self.prev_hash.clone()
    }

    fn seq(&self) -> u64 {
        self.seq
    }
}

/// Cancel record (§11.6).
#[derive(Serialize, Clone, Debug)]
pub struct CancelRecord {
    pub invoice_hash: String,
    pub i: u32,
    pub note_id: String,
    pub event: String, // "cancel"
    pub reason: String,
    pub version: u64,
    pub at: String,
    pub by: String,
    pub sig_alg: String,
    pub sig: String,
    pub prev_hash: String,
    pub seq: u64,
}

impl LogRecord for CancelRecord {
    fn sign(&mut self, key: &IdentityKeypair) -> Result<(), PcwError> {
        self.by = hex::encode(key.pub_key.serialize());
        self.sig_alg = "secp256k1-sha256".to_string();
        let mut unsigned = self.clone();
        unsigned.sig = "".to_string();
        unsigned.by = "".to_string();
        unsigned.sig_alg = "".to_string();
        let bytes = canonical_json(&unsigned)?;
        let hash = sha256(&bytes);
        let msg = Message::from_slice(&hash)?;
        let secp = Secp256k1::new();
        let sig = secp.sign_ecdsa(&msg, &SecretKey::from_slice(&key.priv_key)?);
        self.sig = hex::encode(sig.serialize_der());
        Ok(())
    }

    fn verify(&self) -> Result<(), PcwError> {
        let mut unsigned = self.clone();
        unsigned.sig = "".to_string();
        unsigned.by = "".to_string();
        unsigned.sig_alg = "".to_string();
        let bytes = canonical_json(&unsigned)?;
        let hash = sha256(&bytes);
        let msg = Message::from_slice(&hash)?;
        let pub_key = PublicKey::from_slice(&hex::decode(&self.by)?)?;
        let sig = ecdsa::Signature::from_der(&hex::decode(&self.sig)?)?;
        let secp = Secp256k1::new();
        secp.verify_ecdsa(&msg, &sig, &pub_key)?;
        Ok(())
    }

    fn prev_hash(&self) -> String {
        self.prev_hash.clone()
    }

    fn seq(&self) -> u64 {
        self.seq
    }
}

/// Conflict record (§11.6).
#[derive(Serialize, Clone, Debug)]
pub struct ConflictRecord {
    pub invoice_hash: String,
    pub i: u32,
    pub note_id: String,
    pub event: String, // "conflict_external"
    pub outpoint: OutpointMeta,
    pub at: String,
    pub by: String,
    pub sig_alg: String,
    pub sig: String,
    pub prev_hash: String,
    pub seq: u64,
}

#[derive(Serialize, Clone, Debug)]
pub struct OutpointMeta {
    pub txid: String,
    pub vout: u32,
}

impl LogRecord for ConflictRecord {
    fn sign(&mut self, key: &IdentityKeypair) -> Result<(), PcwError> {
        self.by = hex::encode(key.pub_key.serialize());
        self.sig_alg = "secp256k1-sha256".to_string();
        let mut unsigned = self.clone();
        unsigned.sig = "".to_string();
        unsigned.by = "".to_string();
        unsigned.sig_alg = "".to_string();
        let bytes = canonical_json(&unsigned)?;
        let hash = sha256(&bytes);
        let msg = Message::from_slice(&hash)?;
        let secp = Secp256k1::new();
        let sig = secp.sign_ecdsa(&msg, &SecretKey::from_slice(&key.priv_key)?);
        self.sig = hex::encode(sig.serialize_der());
        Ok(())
    }

    fn verify(&self) -> Result<(), PcwError> {
        let mut unsigned = self.clone();
        unsigned.sig = "".to_string();
        unsigned.by = "".to_string();
        unsigned.sig_alg = "".to_string();
        let bytes = canonical_json(&unsigned)?;
        let hash = sha256(&bytes);
        let msg = Message::from_slice(&hash)?;
        let pub_key = PublicKey::from_slice(&hex::decode(&self.by)?)?;
        let sig = ecdsa::Signature::from_der(&hex::decode(&self.sig)?)?;
        let secp = Secp256k1::new();
        secp.verify_ecdsa(&msg, &sig, &pub_key)?;
        Ok(())
    }

    fn prev_hash(&self) -> String {
        self.prev_hash.clone()
    }

    fn seq(&self) -> u64 {
        self.seq
    }
}

/// Orphaned record (§11.6).
#[derive(Serialize, Clone, Debug)]
pub struct OrphanedRecord {
    pub invoice_hash: String,
    pub i: u32,
    pub note_id: String,
    pub event: String, // "orphaned"
    pub txid: String,
    pub rebroadcast: bool,
    pub at: String,
    pub by: String,
    pub sig_alg: String,
    pub sig: String,
    pub prev_hash: String,
    pub seq: u64,
}

impl LogRecord for OrphanedRecord {
    fn sign(&mut self, key: &IdentityKeypair) -> Result<(), PcwError> {
        self.by = hex::encode(key.pub_key.serialize());
        self.sig_alg = "secp256k1-sha256".to_string();
        let mut unsigned = self.clone();
        unsigned.sig = "".to_string();
        unsigned.by = "".to_string();
        unsigned.sig_alg = "".to_string();
        let bytes = canonical_json(&unsigned)?;
        let hash = sha256(&bytes);
        let msg = Message::from_slice(&hash)?;
        let secp = Secp256k1::new();
        let sig = secp.sign_ecdsa(&msg, &SecretKey::from_slice(&key.priv_key)?);
        self.sig = hex::encode(sig.serialize_der());
        Ok(())
    }

    fn verify(&self) -> Result<(), PcwError> {
        let mut unsigned = self.clone();
        unsigned.sig = "".to_string();
        unsigned.by = "".to_string();
        unsigned.sig_alg = "".to_string();
        let bytes = canonical_json(&unsigned)?;
        let hash = sha256(&bytes);
        let msg = Message::from_slice(&hash)?;
        let pub_key = PublicKey::from_slice(&hex::decode(&self.by)?)?;
        let sig = ecdsa::Signature::from_der(&hex::decode(&self.sig)?)?;
        let secp = Secp256k1::new();
        secp.verify_ecdsa(&msg, &sig, &pub_key)?;
        Ok(())
    }

    fn prev_hash(&self) -> String {
        self.prev_hash.clone()
    }

    fn seq(&self) -> u64 {
        self.seq
    }
}

/// Append to log with chaining (§13.7).
pub fn append_to_log<T: LogRecord>(log: &mut Vec<T>, mut record: T, prev: Option<&T>) -> Result<(), PcwError> {
    if let Some(p) = prev {
        let mut p_unsigned = p.clone();
        // Remove sig triplet for preimage
        let p_bytes = canonical_json(&p_unsigned)?;
        record.prev_hash = hex::encode(sha256(&p_bytes));
    } else {
        record.prev_hash = "".to_string();
    }
    record.seq = log.len() as u64 + 1;
    log.push(record);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // Tests for sign/verify each record, append chaining
}
