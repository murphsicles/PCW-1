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
        let sec_key = SecretKey::from_slice(&priv_key)
            .map_err(|e| PcwError::Other(format!("Invalid private key: {} §3.1", e)))?;
        let pub_key = PublicKey::from_secret_key(&secp, &sec_key);
        Ok(Self { priv_key, pub_key })
    }

    /// Compute ECDH shared secret Z (§3.2).
    pub fn ecdh(&self, their_pub: &PublicKey) -> Result<[u8; 32], PcwError> {
        let secp = Secp256k1::new();
        // Validate their_pub: 33-byte compressed SEC1, not x-only, on-curve (§3.7)
        if their_pub.serialize().len() != 33
            || their_pub.is_xonly()
            || !secp.verify_point(their_pub).is_ok()
        {
            return Err(PcwError::Other("Invalid public key §3.2".to_string()));
        }
        let sec_key = SecretKey::from_slice(&self.priv_key)
            .map_err(|e| PcwError::Other(format!("Invalid private key: {} §3.2", e)))?;
        // Convert SecretKey to Scalar for mul_tweak
        let scalar = Scalar::from(sec_key);
        // Compute shared point: their_pub * priv_key
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
        let sec_key = SecretKey::from_slice(&priv_key)
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
        // Invalid private key (out of curve order)
        let invalid_key = [0xFFu8; 32];
        let result = AnchorKeypair::new(invalid_key);
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid private key")));
        Ok(())
    }

    #[test]
    fn test_identity_keypair_invalid_key() -> Result<(), PcwError> {
        // Invalid private key (out of curve order)
        let invalid_key = [0xFFu8; 32];
        let result = IdentityKeypair::new(invalid_key);
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid private key")));
        Ok(())
    }

    #[test]
    fn test_ecdh_invalid_pubkey() -> Result<(), PcwError> {
        let priv_key = [1u8; 32];
        let keypair = AnchorKeypair::new(priv_key)?;
        // Invalid public key (incorrect 33-byte array)
        let invalid_pub = [0xFFu8; 33]; // Invalid prefix, not on curve
        let result = keypair.ecdh(&PublicKey::from_slice(&invalid_pub)?);
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid public key")));
        Ok(())
    }
}
