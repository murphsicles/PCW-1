//! Module for logging in the PCW-1 protocol.
//!
//! This module provides a signed, append-only logging system as per §13.6-§13.7,
//! with record types for reissues, cancellations, conflicts, and orphaned notes.
//! Logs are chained via previous hashes and signed with identity keypairs.
use crate::errors::PcwError;
use crate::json::canonical_json;
use crate::keys::IdentityKeypair;
use crate::utils::sha256;
use chrono::{DateTime, Utc};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, ecdsa::Signature};
use serde::Serialize;
use std::collections::HashMap;

/// Trait for signed, append-only logs (§13.6-§13.7).
pub trait LogRecord: Serialize + Clone {
    /// Sign the record with the provided identity keypair.
    fn sign(&mut self, key: &IdentityKeypair) -> Result<(), PcwError>;
    /// Verify the record's signature.
    fn verify(&self) -> Result<(), PcwError>;
    /// Get the previous hash for chaining.
    fn prev_hash(&self) -> String;
    /// Set the previous hash for chaining.
    fn set_prev_hash(&mut self, hash: String);
    /// Get the sequence number of the record.
    fn seq(&self) -> u64;
    /// Set the sequence number of the record.
    fn set_seq(&mut self, seq: u64);
    /// Set the timestamp of the record.
    fn set_at(&mut self, at: String);
    /// Set the signature fields (by, sig_alg, sig).
    fn set_signature(&mut self, by: String, sig_alg: String, sig: String);
}

/// Metadata for a conflicted outpoint.
#[derive(Serialize, Clone, Debug)]
pub struct OutpointMeta {
    pub hash: String,
    pub index: u32,
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
        let by = hex::encode(key.pub_key.serialize());
        let sig_alg = "secp256k1-sha256".to_string();
        let mut unsigned = self.clone();
        unsigned.set_signature("".to_string(), "".to_string(), "".to_string());
        let bytes = canonical_json(&unsigned)?;
        let hash = sha256(&bytes);
        let msg = Message::from_digest(hash);
        let secp = Secp256k1::new();
        let sig = secp.sign_ecdsa(msg, &SecretKey::from_byte_array(key.priv_key)?);
        let sig_hex = hex::encode(sig.serialize_der());
        self.set_signature(by, sig_alg, sig_hex);
        Ok(())
    }

    fn verify(&self) -> Result<(), PcwError> {
        let mut unsigned = self.clone();
        unsigned.set_signature("".to_string(), "".to_string(), "".to_string());
        let bytes = canonical_json(&unsigned)?;
        let hash = sha256(&bytes);
        let msg = Message::from_digest(hash);
        let pub_key = PublicKey::from_slice(&hex::decode(&self.by)?)?;
        let sig = Signature::from_der(&hex::decode(&self.sig)?)?;
        let secp = Secp256k1::new();
        secp.verify_ecdsa(msg, &sig, &pub_key)?;
        Ok(())
    }

    fn prev_hash(&self) -> String {
        self.prev_hash.clone()
    }

    fn set_prev_hash(&mut self, hash: String) {
        self.prev_hash = hash;
    }

    fn seq(&self) -> u64 {
        self.seq
    }

    fn set_seq(&mut self, seq: u64) {
        self.seq = seq;
    }

    fn set_at(&mut self, at: String) {
        self.at = at;
    }

    fn set_signature(&mut self, by: String, sig_alg: String, sig: String) {
        self.by = by;
        self.sig_alg = sig_alg;
        self.sig = sig;
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
        let by = hex::encode(key.pub_key.serialize());
        let sig_alg = "secp256k1-sha256".to_string();
        let mut unsigned = self.clone();
        unsigned.set_signature("".to_string(), "".to_string(), "".to_string());
        let bytes = canonical_json(&unsigned)?;
        let hash = sha256(&bytes);
        let msg = Message::from_digest(hash);
        let secp = Secp256k1::new();
        let sig = secp.sign_ecdsa(msg, &SecretKey::from_byte_array(key.priv_key)?);
        let sig_hex = hex::encode(sig.serialize_der());
        self.set_signature(by, sig_alg, sig_hex);
        Ok(())
    }

    fn verify(&self) -> Result<(), PcwError> {
        let mut unsigned = self.clone();
        unsigned.set_signature("".to_string(), "".to_string(), "".to_string());
        let bytes = canonical_json(&unsigned)?;
        let hash = sha256(&bytes);
        let msg = Message::from_digest(hash);
        let pub_key = PublicKey::from_slice(&hex::decode(&self.by)?)?;
        let sig = Signature::from_der(&hex::decode(&self.sig)?)?;
        let secp = Secp256k1::new();
        secp.verify_ecdsa(msg, &sig, &pub_key)?;
        Ok(())
    }

    fn prev_hash(&self) -> String {
        self.prev_hash.clone()
    }

    fn set_prev_hash(&mut self, hash: String) {
        self.prev_hash = hash;
    }

    fn seq(&self) -> u64 {
        self.seq
    }

    fn set_seq(&mut self, seq: u64) {
        self.seq = seq;
    }

    fn set_at(&mut self, at: String) {
        self.at = at;
    }

    fn set_signature(&mut self, by: String, sig_alg: String, sig: String) {
        self.by = by;
        self.sig_alg = sig_alg;
        self.sig = sig;
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

impl LogRecord for ConflictRecord {
    fn sign(&mut self, key: &IdentityKeypair) -> Result<(), PcwError> {
        let by = hex::encode(key.pub_key.serialize());
        let sig_alg = "secp256k1-sha256".to_string();
        let mut unsigned = self.clone();
        unsigned.set_signature("".to_string(), "".to_string(), "".to_string());
        let bytes = canonical_json(&unsigned)?;
        let hash = sha256(&bytes);
        let msg = Message::from_digest(hash);
        let secp = Secp256k1::new();
        let sig = secp.sign_ecdsa(msg, &SecretKey::from_byte_array(key.priv_key)?);
        let sig_hex = hex::encode(sig.serialize_der());
        self.set_signature(by, sig_alg, sig_hex);
        Ok(())
    }

    fn verify(&self) -> Result<(), PcwError> {
        let mut unsigned = self.clone();
        unsigned.set_signature("".to_string(), "".to_string(), "".to_string());
        let bytes = canonical_json(&unsigned)?;
        let hash = sha256(&bytes);
        let msg = Message::from_digest(hash);
        let pub_key = PublicKey::from_slice(&hex::decode(&self.by)?)?;
        let sig = Signature::from_der(&hex::decode(&self.sig)?)?;
        let secp = Secp256k1::new();
        secp.verify_ecdsa(msg, &sig, &pub_key)?;
        Ok(())
    }

    fn prev_hash(&self) -> String {
        self.prev_hash.clone()
    }

    fn set_prev_hash(&mut self, hash: String) {
        self.prev_hash = hash;
    }

    fn seq(&self) -> u64 {
        self.seq
    }

    fn set_seq(&mut self, seq: u64) {
        self.seq = seq;
    }

    fn set_at(&mut self, at: String) {
        self.at = at;
    }

    fn set_signature(&mut self, by: String, sig_alg: String, sig: String) {
        self.by = by;
        self.sig_alg = sig_alg;
        self.sig = sig;
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
        let by = hex::encode(key.pub_key.serialize());
        let sig_alg = "secp256k1-sha256".to_string();
        let mut unsigned = self.clone();
        unsigned.set_signature("".to_string(), "".to_string(), "".to_string());
        let bytes = canonical_json(&unsigned)?;
        let hash = sha256(&bytes);
        let msg = Message::from_digest(hash);
        let secp = Secp256k1::new();
        let sig = secp.sign_ecdsa(msg, &SecretKey::from_byte_array(key.priv_key)?);
        let sig_hex = hex::encode(sig.serialize_der());
        self.set_signature(by, sig_alg, sig_hex);
        Ok(())
    }

    fn verify(&self) -> Result<(), PcwError> {
        let mut unsigned = self.clone();
        unsigned.set_signature("".to_string(), "".to_string(), "".to_string());
        let bytes = canonical_json(&unsigned)?;
        let hash = sha256(&bytes);
        let msg = Message::from_digest(hash);
        let pub_key = PublicKey::from_slice(&hex::decode(&self.by)?)?;
        let sig = Signature::from_der(&hex::decode(&self.sig)?)?;
        let secp = Secp256k1::new();
        secp.verify_ecdsa(msg, &sig, &pub_key)?;
        Ok(())
    }

    fn prev_hash(&self) -> String {
        self.prev_hash.clone()
    }

    fn set_prev_hash(&mut self, hash: String) {
        self.prev_hash = hash;
    }

    fn seq(&self) -> u64 {
        self.seq
    }

    fn set_seq(&mut self, seq: u64) {
        self.seq = seq;
    }

    fn set_at(&mut self, at: String) {
        self.at = at;
    }

    fn set_signature(&mut self, by: String, sig_alg: String, sig: String) {
        self.by = by;
        self.sig_alg = sig_alg;
        self.sig = sig;
    }
}

/// Append to log with chaining (§13.7).
pub fn append_to_log<T: LogRecord>(
    log: &mut Vec<T>,
    mut record: T,
    prev: Option<&T>,
) -> Result<(), PcwError> {
    if let Some(p) = prev {
        let mut p_unsigned = p.clone();
        p_unsigned.set_signature("".to_string(), "".to_string(), "".to_string());
        let p_bytes = canonical_json(&p_unsigned)?;
        record.set_prev_hash(hex::encode(sha256(&p_bytes)));
    } else {
        record.set_prev_hash("".to_string());
    }
    record.set_seq(log.len() as u64 + 1);
    record.set_at(Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string());
    log.push(record);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentityKeypair;

    #[test]
    fn test_reissue_record_sign_verify() -> Result<(), PcwError> {
        let priv_k = [1; 32];
        let key = IdentityKeypair::new(priv_k)?;
        let mut record = ReissueRecord {
            invoice_hash: "test".to_string(),
            i: 0,
            note_id: "note".to_string(),
            event: "reissue".to_string(),
            version: 1,
            supersedes: "old".to_string(),
            txid_new: "new".to_string(),
            addr_recv: "addr_b".to_string(),
            addr_change: "addr_a".to_string(),
            fee: 100,
            feerate_used: 1,
            at: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            by: "".to_string(),
            sig_alg: "".to_string(),
            sig: "".to_string(),
            prev_hash: "".to_string(),
            seq: 1,
        };
        record.sign(&key)?;
        record.verify()?;
        Ok(())
    }

    #[test]
    fn test_cancel_record_sign_verify() -> Result<(), PcwError> {
        let priv_k = [1; 32];
        let key = IdentityKeypair::new(priv_k)?;
        let mut record = CancelRecord {
            invoice_hash: "test".to_string(),
            i: 0,
            note_id: "note".to_string(),
            event: "cancel".to_string(),
            reason: "test".to_string(),
            version: 1,
            at: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            by: "".to_string(),
            sig_alg: "".to_string(),
            sig: "".to_string(),
            prev_hash: "".to_string(),
            seq: 1,
        };
        record.sign(&key)?;
        record.verify()?;
        Ok(())
    }

    #[test]
    fn test_conflict_record_sign_verify() -> Result<(), PcwError> {
        let priv_k = [1; 32];
        let key = IdentityKeypair::new(priv_k)?;
        let mut record = ConflictRecord {
            invoice_hash: "test".to_string(),
            i: 0,
            note_id: "note".to_string(),
            event: "conflict_external".to_string(),
            outpoint: OutpointMeta {
                hash: "tx".to_string(),
                index: 0,
            },
            at: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            by: "".to_string(),
            sig_alg: "".to_string(),
            sig: "".to_string(),
            prev_hash: "".to_string(),
            seq: 1,
        };
        record.sign(&key)?;
        record.verify()?;
        Ok(())
    }

    #[test]
    fn test_orphaned_record_sign_verify() -> Result<(), PcwError> {
        let priv_k = [1; 32];
        let key = IdentityKeypair::new(priv_k)?;
        let mut record = OrphanedRecord {
            invoice_hash: "test".to_string(),
            i: 0,
            note_id: "note".to_string(),
            event: "orphaned".to_string(),
            txid: "tx".to_string(),
            rebroadcast: true,
            at: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            by: "".to_string(),
            sig_alg: "".to_string(),
            sig: "".to_string(),
            prev_hash: "".to_string(),
            seq: 1,
        };
        record.sign(&key)?;
        record.verify()?;
        Ok(())
    }

    #[test]
    fn test_append_to_log() -> Result<(), PcwError> {
        let mut log: Vec<ReissueRecord> = Vec::new();
        let priv_k = [1; 32];
        let key = IdentityKeypair::new(priv_k)?;
        // Create and sign first record
        let mut record1 = ReissueRecord {
            invoice_hash: "test1".to_string(),
            i: 0,
            note_id: "note1".to_string(),
            event: "reissue".to_string(),
            version: 1,
            supersedes: "old1".to_string(),
            txid_new: "new1".to_string(),
            addr_recv: "addr_b1".to_string(),
            addr_change: "addr_a1".to_string(),
            fee: 100,
            feerate_used: 1,
            at: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            by: "".to_string(),
            sig_alg: "".to_string(),
            sig: "".to_string(),
            prev_hash: "".to_string(),
            seq: 0, // Will be set by append_to_log
        };
        record1.sign(&key)?;
        append_to_log(&mut log, record1, None)?;
        // Create and sign second record
        let mut record2 = ReissueRecord {
            invoice_hash: "test2".to_string(),
            i: 1,
            note_id: "note2".to_string(),
            event: "reissue".to_string(),
            version: 1,
            supersedes: "old2".to_string(),
            txid_new: "new2".to_string(),
            addr_recv: "addr_b2".to_string(),
            addr_change: "addr_a2".to_string(),
            fee: 200,
            feerate_used: 2,
            at: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            by: "".to_string(),
            sig_alg: "".to_string(),
            sig: "".to_string(),
            prev_hash: "".to_string(),
            seq: 0, // Will be set by append_to_log
        };
        record2.sign(&key)?;
        append_to_log(&mut log, record2, Some(&log[0]))?;
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].seq, 1);
        assert_eq!(log[1].seq, 2);
        let mut r = log[0].clone();
        r.set_signature("".to_string(), "".to_string(), "".to_string());
        assert_eq!(log[1].prev_hash, hex::encode(sha256(&canonical_json(&r)?)));
        Ok(())
    }
}
