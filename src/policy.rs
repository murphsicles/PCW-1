//! Module for policy management in the PCW-1 protocol.
//!
//! This module implements the policy structure and validation logic as per §3.3,
//! including serialization, signing, and verification of policies.
use crate::errors::PcwError;
use crate::json::canonical_json;
use crate::keys::IdentityKeypair;
use crate::utils::sha256;
use chrono::{DateTime, Utc};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, ecdsa::Signature};
use serde::{Deserialize, Serialize};

/// Policy structure per §3.3.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Policy {
    pub pub_key: String,
    pub vmin: u64,
    pub vmax: u64,
    pub per_address_cap: u64,
    pub feerate: u64,
    pub expiry: DateTime<Utc>,
    pub by: String,
    pub sig_alg: String,
    pub sig: String,
}

impl Policy {
    /// Create a new policy with validation (§3.3).
    pub fn new(
        pub_key: String,
        vmin: u64,
        vmax: u64,
        per_address_cap: u64,
        feerate: u64,
        expiry: DateTime<Utc>,
    ) -> Result<Self, PcwError> {
        if vmin == 0 {
            return Err(PcwError::Other("Zero vmin §3.3".to_string()));
        }
        if vmax < vmin {
            return Err(PcwError::Other("vmax < vmin §3.3".to_string()));
        }
        if per_address_cap < vmin || per_address_cap > vmax {
            return Err(PcwError::Other("Invalid per_address_cap §3.3".to_string()));
        }
        if feerate == 0 {
            return Err(PcwError::Other("Zero feerate §3.3".to_string()));
        }
        if expiry < Utc::now() {
            return Err(PcwError::Other("Expiry in the past §3.3".to_string()));
        }
        // Validate pub_key format (66-character hex for compressed public key)
        if pub_key.len() != 66 || !hex::decode(&pub_key).is_ok() {
            return Err(PcwError::Other("Invalid pub_key format §3.3".to_string()));
        }
        Ok(Self {
            pub_key,
            vmin,
            vmax,
            per_address_cap,
            feerate,
            expiry,
            by: "".to_string(),
            sig_alg: "".to_string(),
            sig: "".to_string(),
        })
    }

    /// Compute policy hash H_P (§3.3).
    pub fn h_policy(&self) -> [u8; 32] {
        let mut unsigned = self.clone();
        unsigned.by = "".to_string();
        unsigned.sig_alg = "".to_string();
        unsigned.sig = "".to_string();
        let value = serde_json::to_value(&unsigned).expect("Serialization should not fail");
        let bytes = canonical_json(&value).expect("Canonical JSON should not fail");
        sha256(&bytes)
    }

    /// Sign policy with identity keypair (§3.3).
    pub fn sign(&mut self, key: &IdentityKeypair) -> Result<(), PcwError> {
        let by = hex::encode(key.pub_key.serialize());
        let sig_alg = "secp256k1-sha256".to_string();
        let mut unsigned = self.clone();
        unsigned.by = "".to_string();
        unsigned.sig_alg = "".to_string();
        unsigned.sig = "".to_string();
        let value = serde_json::to_value(&unsigned)?;
        let bytes = canonical_json(&value)?;
        let hash = sha256(&bytes);
        let msg = Message::from_digest(hash);
        let secp = Secp256k1::new();
        let sig = secp.sign_ecdsa(msg, &SecretKey::from_byte_array(key.priv_key)?);
        self.by = by;
        self.sig_alg = sig_alg;
        self.sig = hex::encode(sig.serialize_der());
        Ok(())
    }

    /// Verify policy signature and constraints (§3.3).
    pub fn verify(&self) -> Result<(), PcwError> {
        if self.expiry < Utc::now() {
            return Err(PcwError::Other("Policy expired §3.3".to_string()));
        }
        let mut unsigned = self.clone();
        unsigned.by = "".to_string();
        unsigned.sig_alg = "".to_string();
        unsigned.sig = "".to_string();
        let value = serde_json::to_value(&unsigned)?;
        let bytes = canonical_json(&value)?;
        let hash = sha256(&bytes);
        let msg = Message::from_digest(hash);
        let secp = Secp256k1::new();
        let pub_key = PublicKey::from_slice(&hex::decode(&self.by)?)?;
        let sig = Signature::from_der(&hex::decode(&self.sig)?)?;
        secp.verify_ecdsa(msg, &sig, &pub_key)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentityKeypair;

    #[test]
    fn test_policy_sign_verify() -> Result<(), PcwError> {
        let priv_k = [1; 32];
        let key = IdentityKeypair::new(priv_k)?;
        let pub_key = hex::encode(key.pub_key.serialize());
        let expiry = Utc::now() + chrono::Duration::days(1);
        let mut policy = Policy::new(pub_key, 100, 1000, 500, 1, expiry)?;
        policy.sign(&key)?;
        policy.verify()?;
        let h_p = policy.h_policy();
        assert_eq!(h_p.len(), 32);
        Ok(())
    }

    #[test]
    fn test_policy_invalid_expiry() -> Result<(), PcwError> {
        let priv_k = [1; 32];
        let key = IdentityKeypair::new(priv_k)?;
        let pub_key = hex::encode(key.pub_key.serialize());
        let expiry = Utc::now() - chrono::Duration::days(1);
        let mut policy = Policy::new(pub_key, 100, 1000, 500, 1, expiry)?;
        policy.sign(&key)?;
        let result = policy.verify();
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Policy expired")));
        Ok(())
    }

    #[test]
    fn test_policy_invalid_inputs() -> Result<(), PcwError> {
        let pub_key = "02".to_string() + &"0".repeat(64);
        let expiry = Utc::now() + chrono::Duration::days(1);
        // Zero vmin
        let result = Policy::new(pub_key.clone(), 0, 1000, 500, 1, expiry);
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Zero vmin")));
        // vmax < vmin
        let result = Policy::new(pub_key.clone(), 1000, 500, 500, 1, expiry);
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("vmax < vmin")));
        // Invalid per_address_cap
        let result = Policy::new(pub_key.clone(), 100, 1000, 50, 1, expiry);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid per_address_cap"))
        );
        // Zero feerate
        let result = Policy::new(pub_key.clone(), 100, 1000, 500, 0, expiry);
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Zero feerate")));
        // Invalid pub_key format
        let result = Policy::new("invalid".to_string(), 100, 1000, 500, 1, expiry);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid pub_key format"))
        );
        Ok(())
    }

    #[test]
    fn test_policy_serialization() -> Result<(), PcwError> {
        let priv_k = [1; 32];
        let key = IdentityKeypair::new(priv_k)?;
        let pub_key = hex::encode(key.pub_key.serialize());
        let expiry = Utc::now() + chrono::Duration::days(1);
        let mut policy = Policy::new(pub_key, 100, 1000, 500, 1, expiry)?;
        policy.sign(&key)?;
        let serialized = canonical_json(&policy)?;
        let expected = format!(
            "{{\"pub_key\":\"{}\",\"vmin\":100,\"vmax\":1000,\"per_address_cap\":500,\"feerate\":1,\"expiry\":\"{}\",\"by\":\"{}\",\"sig_alg\":\"secp256k1-sha256\",\"sig\":\"{}\"}}",
            hex::encode(key.pub_key.serialize()),
            expiry.format("%Y-%m-%dT%H:%M:%SZ"),
            hex::encode(key.pub_key.serialize()),
            policy.sig
        );
        assert_eq!(String::from_utf8(serialized)?, expected);
        Ok(())
    }
}
