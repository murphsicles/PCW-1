//! Module for key management in the PCW-1 protocol.
//!
//! This module provides keypair structs for anchor and identity keys, along with ECDH
//! shared secret computation as per §3.1 and §3.2 of the spec.
use crate::errors::PcwError;
use crate::json::canonical_json;
use secp256k1::{PublicKey, Secp256k1, SecretKey, constants::SECRET_KEY_SIZE};

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
            .map_err(|e| PcwError::Other(format!("Invalid private key: {} §3.1", e)))?;
        let pub_key = PublicKey::from_secret_key(&secp, &sec_key);
        Ok(Self { priv_key, pub_key })
    }

    /// Compute ECDH shared secret (§3.2).
    pub fn ecdh(&self, their_pub: &PublicKey) -> Result<[u8; 32], PcwError> {
        let secp = Secp256k1::new();
        let sec_key = SecretKey::from_byte_array(self.priv_key)
            .map_err(|e| PcwError::Other(format!("Invalid private key: {} §3.2", e)))?;
        // Verify their_pub is valid
        if their_pub.is_zero() {
            return Err(PcwError::Other("Invalid public key §3.2".to_string()));
        }
        // Compute shared point: their_pub * priv_key
        let shared_point = their_pub.mul_tweak(&secp, &sec_key)?;
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
            .map_err(|e| PcwError::Other(format!("Invalid private key: {} §3.1", e)))?;
        let pub_key = PublicKey::from_secret_key(&secp, &sec_key);
        Ok(Self { priv_key, pub_key })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Note: For production, use secure random keys with `rand::rngs::OsRng` (§3.1).
    // Example: `let mut rng = OsRng; let priv_key = SecretKey::new(&mut rng).to_bytes();`

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

    #[test]
    fn test_anchor_keypair_invalid_key() -> Result<(), PcwError> {
        // Non-32-byte key (simulated by using an invalid key)
        let invalid_key = [255u8; 32]; // Out of curve order
        let result = AnchorKeypair::new(invalid_key);
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid private key")));
        Ok(())
    }

    #[test]
    fn test_identity_keypair_invalid_key() -> Result<(), PcwError> {
        // Non-32-byte key (simulated by using an invalid key)
        let invalid_key = [255u8; 32]; // Out of curve order
        let result = IdentityKeypair::new(invalid_key);
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid private key")));
        Ok(())
    }

    #[test]
    fn test_ecdh_invalid_pubkey() -> Result<(), PcwError> {
        let priv_key = [1u8; 32];
        let keypair = AnchorKeypair::new(priv_key)?;
        let secp = Secp256k1::new();
        // Create an invalid (zero) public key
        let invalid_pub = PublicKey::from_slice(&[0u8; 33]).unwrap_or_else(|_| {
            PublicKey::from_secret_key(&secp, &SecretKey::from_byte_array([0; 32]).unwrap())
        });
        let result = keypair.ecdh(&invalid_pub);
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid public key")));
        Ok(())
    }

    #[test]
    fn test_keypair_serialization() -> Result<(), PcwError> {
        let priv_key = [1u8; 32];
        let keypair = AnchorKeypair::new(priv_key)?;
        let serialized = canonical_json(&keypair)?;
        // Check that serialization includes priv_key and pub_key
        let expected = format!(
            "{{\"priv_key\":\"{}\",\"pub_key\":\"{}\"}}",
            hex::encode(priv_key),
            hex::encode(keypair.pub_key.serialize())
        );
        assert_eq!(String::from_utf8(serialized)?, expected);
        Ok(())
    }
}
