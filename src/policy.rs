//! Module for policy management in the PCW-1 protocol.
//!
//! This module implements the policy structure and validation logic as per §3.3,
//! including serialization, signing, and verification of policies.
use crate::errors::PcwError;
use crate::json::canonical_json;
use crate::keys::IdentityKeypair;
use crate::utils::sha256;
use chrono::{DateTime, Utc};
use hex;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, ecdsa::Signature};
use serde::{Deserialize, Serialize};
use serde_json;

/// Policy structure per §3.3.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Policy {
    pub pk_anchor: String,
    pub vmin: u64,
    pub vmax: u64,
    pub per_address_cap: u64,
    pub feerate_floor: u64,
    pub expiry: DateTime<Utc>,
    pub sig_key: String,
    pub sig_alg: String,
    pub sig: String,
}

impl Policy {
    /// Create a new policy with validation (§3.3).
    pub fn new(
        pk_anchor: String,
        vmin: u64,
        vmax: u64,
        per_address_cap: u64,
        feerate_floor: u64,
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
        if feerate_floor == 0 {
            return Err(PcwError::Other("Zero feerate §3.3".to_string()));
        }
        if expiry < Utc::now() {
            return Err(PcwError::Other("Expiry in the past §3.3".to_string()));
        }
        // Validate pk_anchor format (66-character hex for compressed public key)
        if hex::decode(&pk_anchor).is_err() || pk_anchor.len() != 66 {
            return Err(PcwError::Other("Invalid pk_anchor format §3.3".to_string()));
        }
        Ok(Self {
            pk_anchor,
            vmin,
            vmax,
            per_address_cap,
            feerate_floor,
            expiry,
            sig_key: "".to_string(),
            sig_alg: "".to_string(),
            sig: "".to_string(),
        })
    }

    /// Compute policy hash H_policy (§3.3).
    pub fn h_policy(&self) -> [u8; 32] {
        let value = serde_json::to_value(self).expect("Serialization should not fail");
        let bytes = canonical_json(&value).expect("Canonical JSON should not fail");
        sha256(&bytes)
    }

    /// Sign policy with identity keypair (§3.3).
    pub fn sign(&mut self, key: &IdentityKeypair) -> Result<(), PcwError> {
        let sig_key = hex::encode(key.pub_key.serialize());
        let sig_alg = "secp256k1-sha256".to_string();
        let mut unsigned = self.clone();
        unsigned.sig_key = "".to_string();
        unsigned.sig_alg = "".to_string();
        unsigned.sig = "".to_string();
        let value = serde_json::to_value(&unsigned)?;
        let bytes = canonical_json(&value)?;
        let hash = sha256(&bytes);
        let msg = Message::from_digest(hash);
        let secp = Secp256k1::new();
        let sig = secp.sign_ecdsa(&msg, &SecretKey::from_slice(&key.priv_key)?);
        self.sig_key = sig_key;
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
        unsigned.sig_key = "".to_string();
        unsigned.sig_alg = "".to_string();
        unsigned.sig = "".to_string();
        let value = serde_json::to_value(&unsigned)?;
        let bytes = canonical_json(&value)?;
        let hash = sha256(&bytes);
        let msg = Message::from_digest(hash);
        let secp = Secp256k1::new();
        let pub_key = PublicKey::from_slice(&hex::decode(&self.sig_key)?)
            .map_err(|_| PcwError::Other("Invalid signature".to_string()))?;
        let sig = Signature::from_der(&hex::decode(&self.sig)?)
            .map_err(|_| PcwError::Other("Invalid signature".to_string()))?;
        secp.verify_ecdsa(&msg, &sig, &pub_key)
            .map_err(|_| PcwError::Other("Invalid signature".to_string()))?;
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
        let pk_anchor = hex::encode(key.pub_key.serialize());
        let expiry = Utc::now() + chrono::Duration::days(1);
        let mut policy = Policy::new(pk_anchor, 100, 1000, 500, 1, expiry)?;
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
        let pk_anchor = hex::encode(key.pub_key.serialize());
        let expiry = Utc::now() - chrono::Duration::days(1);
        let result = Policy::new(pk_anchor, 100, 1000, 500, 1, expiry);
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Expiry in the past")));
        Ok(())
    }

    #[test]
    fn test_policy_invalid_inputs() -> Result<(), PcwError> {
        let priv_k = [1; 32];
        let key = IdentityKeypair::new(priv_k)?;
        let pk_anchor = hex::encode(key.pub_key.serialize());
        let expiry = Utc::now() + chrono::Duration::days(1);
        // Zero vmin
        let result = Policy::new(pk_anchor.clone(), 0, 1000, 500, 1, expiry);
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Zero vmin")));
        // vmax < vmin
        let result = Policy::new(pk_anchor.clone(), 1000, 500, 500, 1, expiry);
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("vmax < vmin")));
        // Invalid per_address_cap
        let result = Policy::new(pk_anchor.clone(), 100, 1000, 50, 1, expiry);
        assert!(
            matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid per_address_cap"))
        );
        // Zero feerate_floor
        let result = Policy::new(pk_anchor.clone(), 100, 1000, 500, 0, expiry);
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Zero feerate")));
        // Invalid pk_anchor format
        let result = Policy::new("invalid".to_string(), 100, 1000, 500, 1, expiry);
        assert!(
            matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid pk_anchor format"))
        );
        Ok(())
    }

    #[test]
    fn test_policy_serialization() -> Result<(), PcwError> {
        let priv_k = [1; 32];
        let key = IdentityKeypair::new(priv_k)?;
        let pk_anchor = hex::encode(key.pub_key.serialize());
        let expiry = Utc::now() + chrono::Duration::days(1);
        let mut policy = Policy::new(pk_anchor, 100, 1000, 500, 1, expiry)?;
        policy.sign(&key)?;
        let value = serde_json::to_value(&policy)?;
        let serialized = canonical_json(&value)?;
        let expected = serde_json::to_string(&value)?;
        assert_eq!(String::from_utf8(serialized)?, expected);
        Ok(())
    }
}
