//! Module for policy management in the PCW-1 protocol.
//!
//! This module implements the policy structure and signing as per §3.3, including
//! fields for anchor public key, amount bounds, and broadcast constraints. Policies
//! are signed and verified using secp256k1 ECDSA.
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
    pub anchor_pubkey: String,
    pub vmin: u64,
    pub vmax: u64,
    pub per_address_cap: u64,
    pub feerate_floor: u64,
    pub expiry: DateTime<Utc>,
    pub by: String,
    pub sig_alg: String,
    pub sig: String,
}

impl Policy {
    /// Create new policy with validation (§3.3).
    pub fn new(
        anchor_pubkey: String,
        vmin: u64,
        vmax: u64,
        per_address_cap: u64,
        feerate_floor: u64,
        expiry: DateTime<Utc>,
    ) -> Result<Self, PcwError> {
        if vmin == 0 || vmax < vmin {
            return Err(PcwError::Other("Invalid vmin or vmax §3.3".to_string()));
        }
        if per_address_cap < vmin || per_address_cap > vmax {
            return Err(PcwError::Other(
                "per_address_cap out of bounds §3.3".to_string(),
            ));
        }
        if feerate_floor == 0 {
            return Err(PcwError::Other("Zero feerate_floor §3.3".to_string()));
        }
        // Validate anchor_pubkey format
        if anchor_pubkey.len() != 66 || !anchor_pubkey.starts_with("02") || !hex::decode(&anchor_pubkey).is_ok() {
            return Err(PcwError::Other("Invalid anchor_pubkey format §3.3".to_string()));
        }
        let pubkey_bytes = hex::decode(&anchor_pubkey)?;
        PublicKey::from_slice(&pubkey_bytes)
            .map_err(|e| PcwError::Other(format!("Invalid anchor_pubkey: {} §3.3", e)))?;
        Ok(Self {
            anchor_pubkey,
            vmin,
            vmax,
            per_address_cap,
            feerate_floor,
            expiry,
            by: "".to_string(),
            sig_alg: "".to_string(),
            sig: "".to_string(),
        })
    }

    /// Sign policy with identity keypair (§3.3).
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

    /// Verify policy signature and constraints (§3.3).
    pub fn verify(&self) -> Result<(), PcwError> {
        if Utc::now() > self.expiry {
            return Err(PcwError::Other("Policy expired §3.3".to_string()));
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

    /// Compute policy hash H_P (§3.3).
    pub fn h_policy(&self) -> [u8; 32] {
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
    fn test_policy_new_sign_verify() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        let priv_k = [1; 32];
        let key = IdentityKeypair::new(priv_k)?;
        let anchor_pubkey = hex::encode(key.pub_key.serialize());
        let expiry = Utc::now() + chrono::Duration::days(1);
        let mut policy = Policy::new(anchor_pubkey, 100, 1000, 500, 1, expiry)?;
        policy.sign(&key)?;
        policy.verify()?;
        let h_policy = policy.h_policy();
        assert_eq!(h_policy.len(), 32);
        Ok(())
    }

    #[test]
    fn test_policy_invalid_pubkey() -> Result<(), PcwError> {
        let expiry = Utc::now() + chrono::Duration::days(1);
        // Non-hex pubkey
        let result = Policy::new("invalid".to_string(), 100, 1000, 500, 1, expiry);
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid anchor_pubkey format")));
        // Wrong length pubkey
        let result = Policy::new("02".to_string() + &"0".repeat(60), 100, 1000, 500, 1, expiry);
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid anchor_pubkey")));
        Ok(())
    }

    #[test]
    fn test_policy_expired() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        let priv_k = [1; 32];
        let key = IdentityKeypair::new(priv_k)?;
        let anchor_pubkey = hex::encode(key.pub_key.serialize());
        let expiry = Utc::now() - chrono::Duration::days(1); // Past expiry
        let mut policy = Policy::new(anchor_pubkey, 100, 1000, 500, 1, expiry)?;
        policy.sign(&key)?;
        let result = policy.verify();
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Policy expired")));
        Ok(())
    }

    #[test]
    fn test_policy_invalid_signature() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        let priv_k = [1; 32];
        let key = IdentityKeypair::new(priv_k)?;
        let anchor_pubkey = hex::encode(key.pub_key.serialize());
        let expiry = Utc::now() + chrono::Duration::days(1);
        let mut policy = Policy::new(anchor_pubkey, 100, 1000, 500, 1, expiry)?;
        policy.sign(&key)?;
        // Tamper with signature
        policy.sig = "invalid".to_string();
        let result = policy.verify();
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid signature")));
        // Tamper with policy field
        let mut tampered = policy.clone();
        tampered.vmin = 200;
        let result = tampered.verify();
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid signature")));
        Ok(())
    }

    #[test]
    fn test_policy_serialization() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        let priv_k = [1; 32];
        let key = IdentityKeypair::new(priv_k)?;
        let anchor_pubkey = hex::encode(key.pub_key.serialize());
        let expiry = Utc::now() + chrono::Duration::days(1);
        let mut policy = Policy::new(anchor_pubkey.clone(), 100, 1000, 500, 1, expiry)?;
        policy.sign(&key)?;
        let serialized = canonical_json(&policy)?;
        let expected = format!(
            "{{\"anchor_pubkey\":\"{}\",\"vmin\":100,\"vmax\":1000,\"per_address_cap\":500,\"feerate_floor\":1,\"expiry\":\"{}\",\"by\":\"{}\",\"sig_alg\":\"secp256k1-sha256\",\"sig\":\"{}\"}}",
            anchor_pubkey,
            expiry.format("%Y-%m-%dT%H:%M:%SZ"),
            hex::encode(key.pub_key.serialize()),
            policy.sig
        );
        assert_eq!(String::from_utf8(serialized)?, expected);
        Ok(())
    }

    #[test]
    fn test_policy_invalid_bounds() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        let priv_k = [1; 32];
        let key = IdentityKeypair::new(priv_k)?;
        let anchor_pubkey = hex::encode(key.pub_key.serialize());
        let expiry = Utc::now() + chrono::Duration::days(1);
        // vmin = 0
        let result = Policy::new(anchor_pubkey.clone(), 0, 1000, 500, 1, expiry);
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid vmin or vmax")));
        // vmax < vmin
        let result = Policy::new(anchor_pubkey.clone(), 1000, 100, 500, 1, expiry);
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid vmin or vmax")));
        // per_address_cap < vmin
        let result = Policy::new(anchor_pubkey.clone(), 100, 1000, 50, 1, expiry);
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("per_address_cap out of bounds")));
        // feerate_floor = 0
        let result = Policy::new(anchor_pubkey, 100, 1000, 500, 0, expiry);
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Zero feerate_floor")));
        Ok(())
    }
}
