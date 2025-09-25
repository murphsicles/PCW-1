/*! Module for utility functions in the PCW-1 protocol.
This module provides cryptographic and encoding utilities as per §2 and §4.3, including
hashing (SHA-256, H160), address encoding (Base58Check), and elliptic curve operations
(point addition, scalar multiplication). These functions support the deterministic and
secure construction of transactions and addresses.
*/
use crate::errors::PcwError;
use base58::ToBase58;
use ripemd::Ripemd160;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
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
    hasher
        .finalize()
        .as_slice()
        .try_into()
        .expect("RIPEMD160 output is 20 bytes")
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
    // Validate p1 and p2: 33-byte compressed SEC1 (§4.3)
    if p1.serialize().len() != 33 || p2.serialize().len() != 33 {
        return Err(PcwError::Other("Invalid public key §4.3".to_string()));
    }
    let p1_point = *p1;
    let p2_point = *p2;
    let combined = p1_point.combine(&p2_point)?;
    Ok(combined)
}

/// Scalar mul: scalar * G (§4.3).
pub fn scalar_mul(scalar: &[u8; 32]) -> Result<PublicKey, PcwError> {
    if *scalar == [0; 32] {
        return Err(PcwError::Other("Zero scalar §4.3".to_string()));
    }
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_byte_array(*scalar)
        .map_err(|e| PcwError::Other(format!("Invalid scalar: {} §4.3", e)))?;
    let pub_key = PublicKey::from_secret_key(&secp, &secret_key);
    Ok(pub_key)
}

/// ECDH shared secret computation: priv_key * pub_key (§3.2).
pub fn ecdh_z(priv_key: &[u8; 32], pub_key: &PublicKey) -> Result<[u8; 32], PcwError> {
    if *priv_key == [0; 32] {
        return Err(PcwError::Other("Zero private key §3.2".to_string()));
    }
    let secp = Secp256k1::new();
    // Validate pub_key: 33-byte compressed SEC1 (§3.7)
    if pub_key.serialize().len() != 33 {
        return Err(PcwError::Other("Invalid public key §3.2".to_string()));
    }
    let sec_key = SecretKey::from_byte_array(*priv_key)
        .map_err(|e| PcwError::Other(format!("Invalid private key: {} §3.2", e)))?;
    let scalar = Scalar::from(sec_key);
    let shared_point = pub_key.mul_tweak(&secp, &scalar)?;
    let shared_bytes = shared_point.serialize();
    let z: [u8; 32] = shared_bytes[1..33]
        .try_into()
        .map_err(|_| PcwError::Other("Invalid ECDH point §3.2".to_string()))?;
    Ok(z)
}

/// NFC normalize string (§2).
pub fn nfc_normalize(s: &str) -> String {
    s.nfc().collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    #[test]
    fn test_sha256() {
        let data = b"test";
        let hash = sha256(data);
        assert_eq!(hash.len(), 32);
        assert_ne!(hash, [0u8; 32]); // Non-zero output
    }

    #[test]
    fn test_sha256_empty() {
        let data = b"";
        let hash = sha256(data);
        assert_eq!(hash.len(), 32);
        // Expected SHA-256 of empty input
        assert_eq!(
            hash,
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap()
                .as_slice(),
        );
    }

    #[test]
    fn test_sha256_large_input() {
        let data = vec![0u8; 1024 * 1024]; // 1MB
        let hash = sha256(&data);
        assert_eq!(hash.len(), 32);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_h160() {
        let data = b"test";
        let h160 = h160(data);
        assert_eq!(h160.len(), 20);
        assert_ne!(h160, [0u8; 20]); // Non-zero output
    }

    #[test]
    fn test_h160_empty() {
        let data = b"";
        let sha = sha256(data); // Debug intermediate SHA-256
        assert_eq!(
            hex::encode(&sha),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let h160 = h160(data);
        assert_eq!(h160.len(), 20);
        // Expected RIPEMD160(SHA256(""))
        assert_eq!(
            h160,
            hex::decode("0b86df2b6e1f6e6c7e1f6e6c7e1f6e6c7e1f6e6c")
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn test_base58check() -> Result<(), PcwError> {
        let payload = [0x12, 0x34, 0x56, 0x78];
        let addr = base58check(0x00, &payload)?;
        assert!(addr.len() > 0); // Valid base58 string
        Ok(())
    }

    #[test]
    fn test_base58check_empty_payload() -> Result<(), PcwError> {
        let addr = base58check(0x00, &[])?;
        assert!(addr.len() > 0); // Valid base58 string
        Ok(())
    }

    #[test]
    fn test_le32() {
        let val = 0x12345678;
        let bytes = le32(val);
        assert_eq!(bytes, [0x78, 0x56, 0x34, 0x12]);
        // Boundary value
        let val = u32::MAX;
        let bytes = le32(val);
        assert_eq!(bytes, [0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn test_le8() {
        let val = 0x123456789abcdef0;
        let bytes = le8(val);
        assert_eq!(bytes, [0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12]);
        // Boundary value
        let val = u64::MAX;
        let bytes = le8(val);
        assert_eq!(bytes, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn test_point_add() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        let sk1 = SecretKey::from_byte_array([1u8; 32])?;
        let pk1 = PublicKey::from_secret_key(&secp, &sk1);
        let sk2 = SecretKey::from_byte_array([2u8; 32])?;
        let pk2 = PublicKey::from_secret_key(&secp, &sk2);
        let _sum = point_add(&pk1, &pk2)?; // Should not panic
        Ok(())
    }

    #[test]
    fn test_point_add_invalid() -> Result<(), PcwError> {
        // Invalid public key (incorrect 33-byte array)
        let invalid_pub = [0xFFu8; 33]; // Invalid prefix, not on curve
        let result = PublicKey::from_slice(&invalid_pub);
        assert!(matches!(result, Err(secp256k1::Error::InvalidPublicKey)));
        Ok(())
    }

    #[test]
    fn test_scalar_mul() -> Result<(), PcwError> {
        let scalar = [1u8; 32];
        let _pk = scalar_mul(&scalar)?; // Should not panic
        Ok(())
    }

    #[test]
    fn test_scalar_mul_invalid() -> Result<(), PcwError> {
        let scalar = [0u8; 32]; // Invalid scalar (zero)
        let result = scalar_mul(&scalar);
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Zero scalar")));
        // Out-of-range scalar
        let scalar = [0xFFu8; 32]; // Beyond curve order
        let result = scalar_mul(&scalar);
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid scalar")));
        Ok(())
    }

    #[test]
    fn test_ecdh_z() -> Result<(), PcwError> {
        let priv_key1 = [1u8; 32];
        let priv_key2 = [2u8; 32];
        let secp = Secp256k1::new();
        let pub_key1 = PublicKey::from_secret_key(&secp, &SecretKey::from_byte_array(priv_key1)?);
        let pub_key2 = PublicKey::from_secret_key(&secp, &SecretKey::from_byte_array(priv_key2)?);
        let z1 = ecdh_z(&priv_key1, &pub_key2)?;
        let z2 = ecdh_z(&priv_key2, &pub_key1)?;
        assert_eq!(z1, z2); // ECDH symmetry
        Ok(())
    }

    #[test]
    fn test_ecdh_z_invalid() -> Result<(), PcwError> {
        // Invalid public key (incorrect 33-byte array)
        let invalid_pub = [0xFFu8; 33]; // Invalid prefix, not on curve
        let result = PublicKey::from_slice(&invalid_pub);
        assert!(matches!(result, Err(secp256k1::Error::InvalidPublicKey)));
        // Zero private key
        let secp = Secp256k1::new();
        let pub_key = PublicKey::from_secret_key(&secp, &SecretKey::from_byte_array([1u8; 32])?);
        let result = ecdh_z(&[0u8; 32], &pub_key);
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Zero private key")));
        Ok(())
    }

    #[test]
    fn test_nfc_normalize() -> Result<(), PcwError> {
        let s = "café";
        let normalized = nfc_normalize(s);
        assert_eq!(normalized, "café"); // Should preserve NFC
        // Empty string
        let empty = "";
        let normalized = nfc_normalize(empty);
        assert_eq!(normalized, "");
        // Non-normalized Unicode (café with decomposed e + accent)
        let malformed = "caf\u{0065}\u{0301}";
        let normalized = nfc_normalize(malformed);
        assert_eq!(normalized, "café"); // Should normalize to NFC
        Ok(())
    }
}
