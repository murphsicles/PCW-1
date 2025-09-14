//! Module for invoice management in the PCW-1 protocol.
//!
//! This module implements the invoice structure and signing as per §3.4, including
//! fields for invoice details, policy hash, and signatures. Invoices are signed and
//! verified using secp256k1 ECDSA, with validation for policy compliance.
use crate::errors::PcwError;
use crate::json::canonical_json;
use crate::keys::IdentityKeypair;
use crate::utils::sha256;
use chrono::{DateTime, Utc};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, ecdsa::Signature};
use serde::{Deserialize, Serialize};

/// Invoice structure per §3.4.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Invoice {
    pub id: String,
    pub terms: String,
    pub unit: String,
    pub amount: u64,
    pub policy_hash: String,
    pub expiry: Option<DateTime<Utc>>,
    pub by: String,
    pub sig_alg: String,
    pub sig: String,
}

impl Invoice {
    /// Create new invoice with validation (§3.4).
    pub fn new(
        id: String,
        terms: String,
        unit: String,
        amount: u64,
        policy_hash: String,
        expiry: Option<DateTime<Utc>>,
    ) -> Result<Self, PcwError> {
        if id.is_empty() {
            return Err(PcwError::Other("Empty invoice id §3.4".to_string()));
        }
        if unit.is_empty() {
            return Err(PcwError::Other("Empty unit §3.4".to_string()));
        }
        if amount == 0 {
            return Err(PcwError::Other("Zero amount §3.4".to_string()));
        }
        // Validate policy_hash format (64-character hex)
        if policy_hash.len() != 64 || !hex::decode(&policy_hash).is_ok() {
            return Err(PcwError::Other(
                "Invalid policy_hash format §3.4".to_string(),
            ));
        }
        if let Some(exp) = expiry {
            if exp < Utc::now() {
                return Err(PcwError::Other("Expiry in the past §3.4".to_string()));
            }
        }
        Ok(Self {
            id,
            terms,
            unit,
            amount,
            policy_hash,
            expiry,
            by: "".to_string(),
            sig_alg: "".to_string(),
            sig: "".to_string(),
        })
    }

    /// Sign invoice with identity keypair (§3.4).
    pub fn sign(&mut self, key: &IdentityKeypair) -> Result<(), PcwError> {
        let by = hex::encode(key.pub_key.serialize());
        let sig_alg = "secp256k1-sha256".to_string();
        let mut unsigned = self.clone();
        unsigned.by = "".to_string();
        unsigned.sig_alg = "".to_string();
        unsigned.sig = "".to_string();
        let bytes = canonical_json(&unsigned)?;
        let hash = sha256(&bytes);
        let msg = Message::from_digest(hash);
        let secp = Secp256k1::new();
        let sig = secp.sign_ecdsa(msg, &SecretKey::from_byte_array(key.priv_key)?);
        self.by = by;
        self.sig_alg = sig_alg;
        self.sig = hex::encode(sig.serialize_der());
        Ok(())
    }

    /// Verify invoice signature and constraints (§3.4).
    pub fn verify(&self, expected_policy_hash: &[u8; 32]) -> Result<(), PcwError> {
        if self.policy_hash != hex::encode(expected_policy_hash) {
            return Err(PcwError::Other("Policy hash mismatch §3.4".to_string()));
        }
        if let Some(exp) = self.expiry {
            if Utc::now() > exp {
                return Err(PcwError::Other("Invoice expired §3.4".to_string()));
            }
        }
        let mut unsigned = self.clone();
        unsigned.by = "".to_string();
        unsigned.sig_alg = "".to_string();
        unsigned.sig = "".to_string();
        let bytes = canonical_json(&unsigned)?;
        let hash = sha256(&bytes);
        let msg = Message::from_digest(hash);
        let pub_key = PublicKey::from_slice(&hex::decode(&self.by)?)?;
        let sig = Signature::from_der(&hex::decode(&self.sig)?)?;
        let secp = Secp256k1::new();
        secp.verify_ecdsa(msg, &sig, &pub_key)?;
        Ok(())
    }

    /// Compute invoice hash H_I (§3.4).
    pub fn h_i(&self) -> [u8; 32] {
        let mut unsigned = self.clone();
        unsigned.by = "".to_string();
        unsigned.sig_alg = "".to_string();
        unsigned.sig = "".to_string();
        let bytes = canonical_json(&unsigned).unwrap_or_default();
        sha256(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentityKeypair;

    #[test]
    fn test_invoice_new_sign_verify() -> Result<(), PcwError> {
        let priv_k = [1; 32];
        let key = IdentityKeypair::new(priv_k)?;
        let policy_hash = [2; 32];
        let expiry = Some(Utc::now() + chrono::Duration::days(1));
        let mut invoice = Invoice::new(
            "test".to_string(),
            "terms".to_string(),
            "sat".to_string(),
            1000,
            hex::encode(policy_hash),
            expiry,
        )?;
        invoice.sign(&key)?;
        invoice.verify(&policy_hash)?;
        let h_i = invoice.h_i();
        assert_eq!(h_i.len(), 32);
        Ok(())
    }

    #[test]
    fn test_invoice_invalid_policy_hash() -> Result<(), PcwError> {
        let expiry = Some(Utc::now() + chrono::Duration::days(1));
        // Non-hex policy hash
        let result = Invoice::new(
            "test".to_string(),
            "terms".to_string(),
            "sat".to_string(),
            1000,
            "invalid".to_string(),
            expiry,
        );
        assert!(
            matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid policy_hash format")),
        );
        // Wrong length policy hash
        let result = Invoice::new(
            "test".to_string(),
            "terms".to_string(),
            "sat".to_string(),
            1000,
            "0".repeat(60),
            expiry,
        );
        assert!(
            matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid policy_hash format")),
        );
        Ok(())
    }

    #[test]
    fn test_invoice_expired() -> Result<(), PcwError> {
        let priv_k = [1; 32];
        let key = IdentityKeypair::new(priv_k)?;
        let policy_hash = [2; 32];
        let expiry = Some(Utc::now() - chrono::Duration::days(1)); // Past expiry
        let mut invoice = Invoice::new(
            "test".to_string(),
            "terms".to_string(),
            "sat".to_string(),
            1000,
            hex::encode(policy_hash),
            expiry,
        )?;
        invoice.sign(&key)?;
        let result = invoice.verify(&policy_hash);
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invoice expired")));
        Ok(())
    }

    #[test]
    fn test_invoice_invalid_signature() -> Result<(), PcwError> {
        let priv_k = [1; 32];
        let key = IdentityKeypair::new(priv_k)?;
        let policy_hash = [2; 32];
        let expiry = Some(Utc::now() + chrono::Duration::days(1));
        let mut invoice = Invoice::new(
            "test".to_string(),
            "terms".to_string(),
            "sat".to_string(),
            1000,
            hex::encode(policy_hash),
            expiry,
        )?;
        invoice.sign(&key)?;
        // Tamper with signature
        invoice.sig = "invalid".to_string();
        let result = invoice.verify(&policy_hash);
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid signature")));
        // Tamper with invoice field
        let mut tampered = invoice.clone();
        tampered.amount = 2000;
        let result = tampered.verify(&policy_hash);
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid signature")));
        Ok(())
    }

    #[test]
    fn test_invoice_serialization() -> Result<(), PcwError> {
        let priv_k = [1; 32];
        let key = IdentityKeypair::new(priv_k)?;
        let policy_hash = [2; 32];
        let expiry = Some(Utc::now() + chrono::Duration::days(1));
        let mut invoice = Invoice::new(
            "test".to_string(),
            "terms".to_string(),
            "sat".to_string(),
            1000,
            hex::encode(policy_hash),
            expiry,
        )?;
        invoice.sign(&key)?;
        let serialized = canonical_json(&invoice)?;
        let expected = format!(
            "{{\"id\":\"test\",\"terms\":\"terms\",\"unit\":\"sat\",\"amount\":1000,\"policy_hash\":\"{}\",\"expiry\":\"{}\",\"by\":\"{}\",\"sig_alg\":\"secp256k1-sha256\",\"sig\":\"{}\"}}",
            hex::encode(policy_hash),
            expiry.unwrap().format("%Y-%m-%dT%H:%M:%SZ"),
            hex::encode(key.pub_key.serialize()),
            invoice.sig
        );
        assert_eq!(String::from_utf8(serialized)?, expected);
        Ok(())
    }

    #[test]
    fn test_invoice_invalid_inputs() -> Result<(), PcwError> {
        let policy_hash = [2; 32];
        let expiry = Some(Utc::now() + chrono::Duration::days(1));
        // Empty id
        let result = Invoice::new(
            "".to_string(),
            "terms".to_string(),
            "sat".to_string(),
            1000,
            hex::encode(policy_hash),
            expiry,
        );
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Empty invoice id")));
        // Empty unit
        let result = Invoice::new(
            "test".to_string(),
            "terms".to_string(),
            "".to_string(),
            1000,
            hex::encode(policy_hash),
            expiry,
        );
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Empty unit")));
        // Zero amount
        let result = Invoice::new(
            "test".to_string(),
            "terms".to_string(),
            "sat".to_string(),
            0,
            hex::encode(policy_hash),
            expiry,
        );
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Zero amount")));
        // Expired invoice at creation
        let result = Invoice::new(
            "test".to_string(),
            "terms".to_string(),
            "sat".to_string(),
            1000,
            hex::encode(policy_hash),
            Some(Utc::now() - chrono::Duration::days(1)),
        );
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Expiry in the past")));
        Ok(())
    }
}
