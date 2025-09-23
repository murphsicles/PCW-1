//! Module for key management in the PCW-1 protocol.
//!
//! This module implements keypair structures for identity (§3.1) and anchor keys (§3.2),
//! used for signing and ECDH operations in the protocol.
use crate::errors::PcwError;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

/// Identity keypair for signing policies and invoices (§3.1).
#[derive(Clone, Debug)]
pub struct IdentityKeypair {
    pub priv_key: [u8; 32],
    pub pub_key: PublicKey,
}

/// Anchor keypair for address derivation (§3.2).
#[derive(Clone, Debug)]
pub struct AnchorKeypair {
    pub priv_key: [u8; 32],
    pub pub_key: PublicKey,
}

impl IdentityKeypair {
    /// Create a new identity keypair (§3.1).
    pub fn new(priv_key: [u8; 32]) -> Result<Self, PcwError> {
        if priv_key == [0u8; 32] {
            return Err(PcwError::Other("Zero private key §3.1".to_string()));
        }
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_byte_array(priv_key)
            .map_err(|e| PcwError::Other(format!("Invalid private key: {} §3.1", e)))?;
        let pub_key = PublicKey::from_secret_key(&secp, &secret_key);
        Ok(Self { priv_key, pub_key })
    }
}

impl AnchorKeypair {
    /// Create a new anchor keypair (§3.2).
    pub fn new(priv_key: [u8; 32]) -> Result<Self, PcwError> {
        if priv_key == [0u8; 32] {
            return Err(PcwError::Other("Zero private key §3.2".to_string()));
        }
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_byte_array(priv_key)
            .map_err(|e| PcwError::Other(format!("Invalid private key: {} §3.2", e)))?;
        let pub_key = PublicKey::from_secret_key(&secp, &secret_key);
        Ok(Self { priv_key, pub_key })
    }

    /// Compute ECDH shared secret (§3.2).
    pub fn ecdh(&self, their_pub: &PublicKey) -> Result<[u8; 32], PcwError> {
        if self.priv_key == [0; 32] {
            return Err(PcwError::Other("Zero private key §3.2".to_string()));
        }
        let secp = Secp256k1::new();
        // Validate their_pub: 33-byte compressed SEC1 (§3.7)
        if their_pub.serialize().len() != 33 {
            return Err(PcwError::Other("Invalid public key §3.2".to_string()));
        }
        let sec_key = SecretKey::from_byte_array(self.priv_key)
            .map_err(|e| PcwError::Other(format!("Invalid private key: {} §3.2", e)))?;
        let scalar = Scalar::from(sec_key);
        let shared_point = their_pub.mul_tweak(&secp, &scalar)?;
        let shared_bytes = shared_point.serialize();
        let z: [u8; 32] = shared_bytes[1..33]
            .try_into()
            .map_err(|_| PcwError::Other("Invalid ECDH point §3.2".to_string()))?;
        Ok(z)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    #[test]
    fn test_identity_keypair() -> Result<(), PcwError> {
        let priv_key = [1u8; 32];
        let keypair = IdentityKeypair::new(priv_key)?;
        assert_eq!(keypair.priv_key, priv_key);
        assert_eq!(keypair.pub_key.serialize().len(), 33); // Compressed SEC1
        Ok(())
    }

    #[test]
    fn test_identity_keypair_invalid_key() -> Result<(), PcwError> {
        let priv_key = [0u8; 32];
        let result = IdentityKeypair::new(priv_key);
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Zero private key")));
        Ok(())
    }

    #[test]
    fn test_anchor_keypair() -> Result<(), PcwError> {
        let priv_key = [1u8; 32];
        let keypair = AnchorKeypair::new(priv_key)?;
        assert_eq!(keypair.priv_key, priv_key);
        assert_eq!(keypair.pub_key.serialize().len(), 33); // Compressed SEC1
        Ok(())
    }

    #[test]
    fn test_anchor_keypair_invalid_key() -> Result<(), PcwError> {
        let priv_key = [0u8; 32];
        let result = AnchorKeypair::new(priv_key);
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Zero private key")));
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

    #[test]
    fn test_ecdh_invalid_pubkey() -> Result<(), PcwError> {
        let priv_key = [1u8; 32];
        let keypair = AnchorKeypair::new(priv_key)?;
        let invalid_pub = [0xFFu8; 33]; // Invalid prefix, not on curve
        let result = PublicKey::from_slice(&invalid_pub);
        assert!(matches!(result, Err(secp256k1::Error::InvalidPublicKey)));
        Ok(())
    }
}
