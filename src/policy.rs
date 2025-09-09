//! Module for policy management in the PCW-1 protocol.
//!
//! This module defines the `Policy` struct and its methods for creation, signing,
//! verification, and hash computation as per §§3.3 and 14.1 of the spec. A policy
//! defines constraints for note splitting, fee rates, and expiration, signed by
//! an identity keypair.

use crate::errors::PcwError;
use crate::json::canonical_json;
use crate::keys::IdentityKeypair;
use crate::utils::sha256;
use chrono::prelude::*;
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey, ecdsa::Signature};
use serde::{Deserialize, Serialize};
use sv::network::Network; // For potential extensions, but spec is agnostic

/// Policy struct per §3.3, §14.1: Canonical fields, sorted order.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Policy {
    pub pk_anchor: String,    // hex(serP(B)), 66 chars
    pub vmin: u64,            // min per-note amount
    pub vmax: u64,            // max per-note amount
    pub per_address_cap: u64, // cap per addr [vmin, vmax]
    pub feerate_floor: u64,   // min fee-rate units/byte
    pub expiry: String,       // ISO-8601 UTC
    pub sig_key: String,      // hex(serP(P_B))
    pub sig_alg: String,      // "secp256k1-sha256"
    pub sig: String,          // hex(ECDSA over canonical without sig fields)
}

impl Policy {
    /// Create new Policy without sig; expiry must be future.
    pub fn new(
        pk_anchor: String,
        vmin: u64,
        vmax: u64,
        per_address_cap: u64,
        feerate_floor: u64,
        expiry: Utc,
    ) -> Result<Self, PcwError> {
        if vmin == 0
            || vmax < vmin
            || per_address_cap < vmin
            || per_address_cap > vmax
            || feerate_floor == 0
        {
            return Err(PcwError::Other("Invalid bounds/floor §3.3".to_string()));
        }
        if expiry <= Utc::now() {
            return Err(PcwError::PolicyExpired);
        }
        Ok(Self {
            pk_anchor,
            vmin,
            vmax,
            per_address_cap,
            feerate_floor,
            expiry: expiry.to_rfc3339_opts(SecondsFormat::Secs, true),
            sig_key: "".to_string(),
            sig_alg: "secp256k1-sha256".to_string(),
            sig: "".to_string(),
        })
    }

    /// Sign policy with identity key; sets sig_key/alg/sig (§3.3).
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
        let sig = secp.sign_ecdsa(&msg, &SecretKey::from_slice(&key.priv_key)?);
        self.sig = hex::encode(sig.serialize_der());
        Ok(())
    }

    /// Verify policy signature and constraints (§3.3).
    pub fn verify(&self) -> Result<(), PcwError> {
        let mut unsigned = self.clone();
        unsigned.sig = "".to_string();
        unsigned.sig_key = "".to_string();
        unsigned.sig_alg = "".to_string();
        let bytes = canonical_json(&unsigned)?;
        let hash = sha256(&bytes);
        let msg = Message::from_slice(&hash)?;
        let pub_key = PublicKey::from_slice(&hex::decode(&self.sig_key)?)?;
        let sig = secp256k1::ecdsa::Signature::from_der(&hex::decode(&self.sig)?)?;
        let secp = Secp256k1::new();
        secp.verify_ecdsa(&msg, &sig, &pub_key)?;
        // Check constraints
        if self.vmin == 0
            || self.vmax < self.vmin
            || self.per_address_cap < self.vmin
            || self.per_address_cap > self.vmax
            || self.feerate_floor == 0
        {
            return Err(PcwError::Other("Invalid bounds/floor §3.3".to_string()));
        }
        let expiry = Utc::parse_from_rfc3339(&self.expiry)?;
        if expiry <= Utc::now() {
            return Err(PcwError::PolicyExpired);
        }
        Ok(())
    }

    /// Compute H_policy over canonical with sig (§3.3).
    pub fn h_policy(&self) -> [u8; 32] {
        let bytes = canonical_json(self).unwrap();
        sha256(&bytes)
    }
}

/// Convenience function to create a new policy.
pub fn new_policy(
    pk_anchor: String,
    vmin: u64,
    vmax: u64,
    per_address_cap: u64,
    feerate_floor: u64,
    expiry: Utc,
) -> Result<Policy, PcwError> {
    Policy::new(
        pk_anchor,
        vmin,
        vmax,
        per_address_cap,
        feerate_floor,
        expiry,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentityKeypair;
    use hex;

    #[test]
    fn test_policy_sig_verify() -> Result<(), PcwError> {
        let priv_k = [1; 32];
        let key = IdentityKeypair::new(priv_k)?;
        let expiry = Utc::now() + chrono::Duration::days(1);
        let mut policy = Policy::new(
            "02".to_string() + &"0".repeat(64), // Valid 66-char hex public key
            100,
            1000,
            500,
            1,
            expiry,
        )?;
        policy.sign(&key)?;
        policy.verify()?;
        assert_eq!(policy.sig_alg, "secp256k1-sha256");
        Ok(())
    }

    #[test]
    fn test_policy_expired() -> Result<(), PcwError> {
        let priv_k = [1; 32];
        let key = IdentityKeypair::new(priv_k)?;
        let past = Utc::now() - chrono::Duration::days(1);
        let mut policy = Policy::new("02".to_string() + &"0".repeat(64), 100, 1000, 500, 1, past)?;
        policy.sign(&key)?;
        assert!(policy.verify().is_err()); // Should fail due to expiration
        Ok(())
    }

    #[test]
    fn test_policy_invalid_bounds() -> Result<(), PcwError> {
        let priv_k = [1; 32];
        let key = IdentityKeypair::new(priv_k)?;
        let expiry = Utc::now() + chrono::Duration::days(1);
        let result = Policy::new(
            "02".to_string() + &"0".repeat(64),
            0, // Invalid vmin
            1000,
            500,
            1,
            expiry,
        );
        assert!(result.is_err()); // Should fail due to vmin == 0
        Ok(())
    }
}
