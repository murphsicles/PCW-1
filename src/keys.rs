//! Module for key management in the PCW-1 protocol.
//!
//! This module provides `IdentityKeypair` and `AnchorKeypair` structs for off-chain
//! authentication and on-chain derivations (§§3.1, 13.1), along with an `ecdh_z` function
//! for ECDH key derivation (§3.2) using the secp256k1 curve.

use crate::errors::PcwError;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

/// Identity keypair for off-chain authentication (§§3.1, 13.1).
/// Never used on-chain to maintain privacy.
#[derive(Clone, Debug)]
pub struct IdentityKeypair {
    pub priv_key: [u8; 32],
    pub pub_key: PublicKey,
}

/// Anchor keypair for on-chain derivations (§§3.1, 13.1).
/// Separate from identity keys to ensure security.
#[derive(Clone, Debug)]
pub struct AnchorKeypair {
    pub priv_key: [u8; 32],
    pub pub_key: PublicKey,
}

impl IdentityKeypair {
    /// Generate from secret (mock for tests; prod use secure rand).
    pub fn new(priv_key: [u8; 32]) -> Result<Self, PcwError> {
        let secp = Secp256k1::new();
        let sec_key = SecretKey::from_slice(&priv_key)?;
        let pub_key = PublicKey::from_secret_key(&secp, &sec_key);
        Ok(Self { priv_key, pub_key })
    }
}

impl AnchorKeypair {
    /// Generate from secret (mock for tests; prod use secure rand).
    pub fn new(priv_key: [u8; 32]) -> Result<Self, PcwError> {
        let secp = Secp256k1::new();
        let sec_key = SecretKey::from_slice(&priv_key)?;
        let pub_key = PublicKey::from_secret_key(&secp, &sec_key);
        Ok(Self { priv_key, pub_key })
    }
}

/// Compute ECDH Z: x-coordinate of priv * their_pub (§3.2).
pub fn ecdh_z(my_priv: &[u8; 32], their_pub: &PublicKey) -> Result<[u8; 32], PcwError> {
    let secp = Secp256k1::new();
    let sec_key = SecretKey::from_slice(my_priv)?;
    let shared_point = their_pub.mul_tweak(&secp, &sec_key.scalar())?;
    let serialized = shared_point.serialize();
    let mut z = [0u8; 32];
    z.copy_from_slice(&serialized[1..33]); // x-coordinate, big-endian §2
    Ok(z)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::constants::SECRET_KEY_SIZE;

    #[test]
    fn test_ecdh_z() -> Result<(), PcwError> {
        let priv1 = [1u8; SECRET_KEY_SIZE];
        let priv2 = [2u8; SECRET_KEY_SIZE];
        let key1 = IdentityKeypair::new(priv1)?;
        let key2 = IdentityKeypair::new(priv2)?;
        let z1 = ecdh_z(&priv1, &key2.pub_key)?;
        let z2 = ecdh_z(&priv2, &key1.pub_key)?;
        assert_eq!(z1, z2); // Symmetric property of ECDH
        Ok(())
    }

    #[test]
    fn test_keypair_creation() -> Result<(), PcwError> {
        let priv_key = [1u8; SECRET_KEY_SIZE];
        let key = IdentityKeypair::new(priv_key)?;
        assert!(key.pub_key.serialize().len() > 0); // Ensure public key is generated
        Ok(())
    }

    #[test]
    fn test_invalid_key() {
        let invalid_priv = [0u8; SECRET_KEY_SIZE]; // Zero key is invalid
        let result = IdentityKeypair::new(invalid_priv);
        assert!(result.is_err()); // Should fail due to invalid secret key
    }
}
