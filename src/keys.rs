//! Module for key management in the PCW-1 protocol.
//!
//! This module provides keypair structs for anchor and identity keys, along with ECDH
//! shared secret computation as per §3.1 and §3.2 of the spec.
use crate::errors::PcwError;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

/// Anchor keypair for address derivation (§3.1).
#[derive(Clone, Debug)]
pub struct AnchorKeypair {
    pub priv_key: [u8; 32],
    pub pub_key: PublicKey,
}

/// Identity keypair for signing (§3.1).
#[derive(Clone, Debug)]
pub struct IdentityKeypair {
    pub priv_key: [u8; 32],
    pub pub_key: PublicKey,
}

impl AnchorKeypair {
    /// Create new anchor keypair from priv_key bytes (§3.1).
    pub fn new(priv_key: [u8; 32]) -> Result<Self, PcwError> {
        if priv_key == [0; 32] {
            return Err(PcwError::Other("Zero private key §3.1".to_string()));
        }
        let secp = Secp256k1::new();
        let sec_key = SecretKey::from_byte_array(priv_key)
            .map_err(|e| PcwError::Other(format!("Invalid private key: {}", e)))?;
        let pub_key = PublicKey::from_secret_key(&secp, &sec_key);
        Ok(Self { priv_key, pub_key })
    }

    /// Compute ECDH shared secret (§3.2).
    pub fn ecdh(&self, their_pub: &PublicKey) -> Result<[u8; 32], PcwError> {
        let secp = Secp256k1::new();
        let sec_key = SecretKey::from_byte_array(self.priv_key)
            .map_err(|e| PcwError::Other(format!("Invalid private key: {}", e)))?;
        let scalar = Scalar::from(sec_key);
        let shared_point = their_pub.mul_tweak(&secp, &scalar)?;
        let shared_bytes = shared_point.serialize();
        let z: [u8; 32] = shared_bytes[1..33]
            .try_into()
            .map_err(|_| PcwError::Other("Invalid ECDH point §3.2".to_string()))?;
        Ok(z)
    }
}

impl IdentityKeypair {
    /// Create new identity keypair from priv_key bytes (§3.1).
    pub fn new(priv_key: [u8; 32]) -> Result<Self, PcwError> {
        if priv_key == [0; 32] {
            return Err(PcwError::Other("Zero private key §3.1".to_string()));
        }
        let secp = Secp256k1::new();
        let sec_key = SecretKey::from_byte_array(priv_key)
            .map_err(|e| PcwError::Other(format!("Invalid private key: {}", e)))?;
        let pub_key = PublicKey::from_secret_key(&secp, &sec_key);
        Ok(Self { priv_key, pub_key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anchor_keypair() -> Result<(), PcwError> {
        let priv_key = [1u8; 32];
        let keypair = AnchorKeypair::new(priv_key)?;
        assert_eq!(keypair.priv_key, priv_key);
        assert!(AnchorKeypair::new([0u8; 32]).is_err());
        Ok(())
    }

    #[test]
    fn test_identity_keypair() -> Result<(), PcwError> {
        let priv_key = [1u8; 32];
        let keypair = IdentityKeypair::new(priv_key)?;
        assert_eq!(keypair.priv_key, priv_key);
        assert!(IdentityKeypair::new([0u8; 32]).is_err());
        Ok(())
    }

    #[test]
    fn test_ecdh() -> Result<(), PcwError> {
        let priv_key1 = [1u8; 32];
        let priv_key2 = [2u8; 32];
        let keypair1 = AnchorKeypair::new(priv_key1)?;
        let keypair2 = AnchorKeypair::new(priv_key2)?;
        let z1 = keypair1.ecdh(&keypair2.pub_key)?;
        let z2 = keypair2.ecdh(&keypair1.pub_key)?;
        assert_eq!(z1, z2); // ECDH symmetry
        Ok(())
    }
}
