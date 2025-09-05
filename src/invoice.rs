//! Module for invoice management in the PCW-1 protocol.
//!
//! This module defines the `Invoice` struct and its methods for creation, signing,
//! verification, and hash computation as per §§3.4 and 14.2 of the spec.

use crate::errors::PcwError;
use crate::json::canonical_json;
use crate::keys::IdentityKeypair;
use crate::utils::sha256;
use chrono::prelude::*;
use secp256k1::{Message, ecdsa::Signature, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use hex;

/// Invoice struct per §3.4, §14.2: Canonical fields, sorted order.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Invoice {
    pub invoice_number: String,
    pub terms: String,
    pub unit: String,
    pub total: u64,
    pub policy_hash: String,  // hex H_policy
    pub expiry: String,       // ISO-8601 UTC, optional but recommended
    pub sig_key: String,
    pub sig_alg: String,
    pub sig: String,
}

impl Invoice {
    /// Create new Invoice without sig; expiry optional but future if set.
    pub fn new(
        invoice_number: String,
        terms: String,
        unit: String,
        total: u64,
        policy_hash: String,
        expiry: Option<Utc>,
    ) -> Result<Self, PcwError> {
        if total == 0 {
            return Err(PcwError::Other("Total must be >0 §3.4".to_string()));
        }
        let expiry_str = if let Some(e) = expiry {
            if e <= Utc::now() {
                return Err(PcwError::InvoiceExpired);
            }
            e.to_rfc3339_opts(SecondsFormat::Secs, true)
        } else {
            "".to_string()
        };
        Ok(Self {
            invoice_number,
            terms,
            unit,
            total,
            policy_hash,
            expiry: expiry_str,
            sig_key: "".to_string(),
            sig_alg: "secp256k1-sha256".to_string(),
            sig: "".to_string(),
        })
    }

    /// Sign invoice with identity key (§3.4).
    pub fn sign(&mut self, key: &IdentityKeypair) -> Result<(), PcwError> {
        self.sig_key = hex::encode(key.pub_key.serialize());
        self.sig_alg = "secp256k1-sha256".to_string();
        let mut unsigned = self.clone();
        unsigned.sig = "".to_string();
        unsigned.sig_key = "".to_string();
        unsigned.sig_alg = "".to_string();
        let bytes = canonical_json(&unsigned)?;
        let hash = sha256(&bytes);
        let msg = Message::from_slice(&hash)?;
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&key.priv_key)?;
        let sig = secp.sign_ecdsa(&msg, &secret_key);
        self.sig = hex::encode(sig.serialize_der());
        Ok(())
    }

    /// Verify invoice signature and policy_hash match (§3.4).
    pub fn verify(&self, expected_policy_hash: &[u8; 32]) -> Result<(), PcwError> {
        if hex::decode(&self.policy_hash)? != expected_policy_hash.to_vec() {
            return Err(PcwError::Other("Policy hash mismatch §3.4".to_string()));
        }
        let mut unsigned = self.clone();
        unsigned.sig = "".to_string();
        unsigned.sig_key = "".to_string();
        unsigned.sig_alg = "".to_string();
        let bytes = canonical_json(&unsigned)?;
        let hash = sha256(&bytes);
        let msg = Message::from_slice(&hash)?;
        let pub_key = PublicKey::from_slice(&hex::decode(&self.sig_key)?)?;
        let sig = Signature::from_der(&hex::decode(&self.sig)?)?;
        let secp = Secp256k1::new();
        secp.verify_ecdsa(&msg, &sig, &pub_key)?;
        if !self.expiry.is_empty() {
            let expiry = Utc::parse_from_rfc3339(&self.expiry)?;
            if expiry <= Utc::now() {
                return Err(PcwError::InvoiceExpired);
            }
        }
        Ok(())
    }

    /// Compute H_I over canonical with sig (§3.4).
    pub fn h_i(&self) -> [u8; 32] {
        let bytes = canonical_json(self).unwrap();
        sha256(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_invoice_sig_verify() -> Result<(), PcwError> {
        let priv_k = [1; 32];
        let key = IdentityKeypair::new(priv_k)?;
        let policy_hash = [0; 32];
        let mut invoice = Invoice::new(
            "inv1".to_string(),
            "terms".to_string(),
            "sat".to_string(),
            1000,
            hex::encode(policy_hash),
            None,
        )?;
        invoice.sign(&key)?;
        invoice.verify(&policy_hash)?;
        Ok(())
    }

    #[test]
    fn test_invoice_expired() -> Result<(), PcwError> {
        let priv_k = [1; 32];
        let key = IdentityKeypair::new(priv_k)?;
        let policy_hash = [0; 32];
        let past = Utc::now() - chrono::Duration::days(1);
        let mut invoice = Invoice::new(
            "inv2".to_string(),
            "terms".to_string(),
            "sat".to_string(),
            1000,
            hex::encode(policy_hash),
            Some(past),
        )?;
        invoice.sign(&key)?;
        assert!(invoice.verify(&policy_hash).is_err());
        Ok(())
    }
}
