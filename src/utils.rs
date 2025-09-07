//! Module for utility functions in the PCW-1 protocol.
//!
//! This module provides cryptographic and encoding utilities as per §2 and §4.3, including
//! hashing (SHA-256, H160), address encoding (Base58Check), and elliptic curve operations
//! (point addition, scalar multiplication). These functions support the deterministic and
//! secure construction of transactions and addresses.

use crate::errors::PcwError;
use sha2::{Digest, Sha256};
use ripemd::Ripemd160;
use base58::ToBase58;
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use unicode_normalization::UnicodeNormalization;

/// SHA-256 hash (§2).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// H160: RIPEMD160(SHA256(data)) (§2).
pub fn h160(data: &[u8]) -> [u8; 20] {
    let mut hasher = Ripemd160::new();
    hasher.update(sha256(data));
    hasher.finalize().into()
}

/// serP: Compressed SEC1 public key encoding (§2).
pub fn ser_p(pk: &PublicKey) -> [u8; 33] {
    pk.serialize()
}

/// LE32: Little-endian 4-byte u32 (§2).
pub fn le32(val: u32) -> [u8; 4] {
    val.to_le_bytes()
}

/// LE8: Little-endian 8-byte u64 (§10.2).
pub fn le8(val: u64) -> [u8; 8] {
    val.to_le_bytes()
}

/// Base58Check: Version || payload || checksum (§2).
pub fn base58check(version: u8, payload: &[u8]) -> Result<String, PcwError> {
    let mut data = vec![version];
    data.extend_from_slice(payload);
    let checksum = &sha256(&sha256(&data))[0..4];
    data.extend_from_slice(checksum);
    Ok(data.to_base58())
}

/// Point add: P1 + P2 using secp256k1 (§4.3).
pub fn point_add(p1: &PublicKey, p2: &PublicKey) -> Result<PublicKey, PcwError> {
    let secp = secp256k1::Secp256k1::new();
    let p1_point = p1.clone().into();
    let p2_point = p2.clone().into();
    let combined = p1_point.combine(&p2_point)?;
    Ok(PublicKey::from_combination(&secp, &combined))
}

/// Scalar mul: scalar * G (§4.3).
pub fn scalar_mul(
    scalar: &[u8; 32],
    _g: &secp256k1::constants::GENERATOR,
) -> Result<PublicKey, PcwError> {
    let secp = secp256k1::Secp256k1::new();
    let secret_key = SecretKey::from_slice(scalar)
        .map_err(|e| PcwError::Other(format!("Invalid scalar: {}", e)))?;
    Ok(PublicKey::from_secret_key(&secp, &secret_key))
}

/// NFC normalize string (§2).
/// NOTE: This function is included for completeness but may not be required in PCW-1 unless
/// explicitly used for invoice JSON normalization. Consider removing if unused.
pub fn nfc_normalize(s: &str) -> String {
    s.nfc().collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{SecretKey, PublicKey};

    #[test]
    fn test_sha256() {
        let data = b"test";
        let hash = sha256(data);
        assert_eq!(hash.len(), 32);
        assert_ne!(hash, [0u8; 32]); // Non-zero output
    }

    #[test]
    fn test_h160() {
        let data = b"test";
        let h160 = h160(data);
        assert_eq!(h160.len(), 20);
        assert_ne!(h160, [0u8; 20]); // Non-zero output
    }

    #[test]
    fn test_base58check() -> Result<(), PcwError> {
        let payload = [0x12, 0x34, 0x56, 0x78];
        let addr = base58check(0x00, &payload)?;
        assert!(addr.len() > 0); // Valid base58 string
        Ok(())
    }

    #[test]
    fn test_le32() {
        let val = 0x12345678;
        let bytes = le32(val);
        assert_eq!(bytes, [0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_le8() {
        let val = 0x123456789abcdef0;
        let bytes = le8(val);
        assert_eq!(bytes, [0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_point_add() -> Result<(), PcwError> {
        let secp = secp256k1::Secp256k1::new();
        let sk1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let pk1 = PublicKey::from_secret_key(&secp, &sk1);
        let sk2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pk2 = PublicKey::from_secret_key(&secp, &sk2);
        let _sum = point_add(&pk1, &pk2)?; // Should not panic
        Ok(())
    }

    #[test]
    fn test_scalar_mul() -> Result<(), PcwError> {
        let scalar = [1u8; 32];
        let _pk = scalar_mul(&scalar, &secp256k1::constants::GENERATOR)?; // Should not panic
        Ok(())
    }

    #[test]
    fn test_scalar_mul_invalid() {
        let scalar = [0u8; 32]; // Invalid scalar (zero)
        let result = scalar_mul(&scalar, &secp256k1::constants::GENERATOR);
        assert!(result.is_err()); // Should fail due to invalid scalar
    }

    #[test]
    fn test_nfc_normalize() {
        let s = "café";
        let normalized = nfc_normalize(s);
        assert_eq!(normalized, "café"); // Should preserve NFC
    }
}
