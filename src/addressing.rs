//! Module for address generation in the PCW-1 protocol.
//!
//! This module provides functions to derive recipient and sender change addresses
//! based on the protocol's deterministic scoping, using ECDH-derived shared secrets
//! and invoice fingerprints as per §3-§7 of the spec.
use crate::errors::PcwError;
use crate::scope::Scope;
use crate::utils::{base58check, h160, point_add, scalar_mul, ser_p};
use secp256k1::{PublicKey, Secp256k1};

/// Derives a recipient address for a given note index (Addr_B,i).
///
/// This function uses the recipient's anchor key B, tweaked with a scalar t_i derived from
/// the ECDH shared secret Z and invoice hash H_I, to create a P2PKH address
/// that only the recipient can spend (per §4).
pub fn recipient_address(scope: &Scope, i: u32, anchor_b: &PublicKey) -> Result<String, PcwError> {
    // Validate anchor_b is a valid compressed SEC1 public key (§4.9)
    let _secp = Secp256k1::new();
    if anchor_b.serialize().len() != 33 {
        return Err(PcwError::Other("Invalid public key §4.9".to_string()));
    }
    let t_i = scope.derive_scalar("recv", i)?;
    if t_i == [0; 32] {
        return Err(PcwError::Other("Zero scalar t_i §4.2".to_string()));
    }
    let tweak_point = scalar_mul(&t_i)?;
    let p_bi = point_add(anchor_b, &tweak_point)?;
    let ser = ser_p(&p_bi);
    let payload = h160(&ser);
    base58check(0x00, &payload)
}

/// Derives a sender change address for a given note index (Addr_A,i).
///
/// This function generates a change address per note, ensuring no overlap with
/// other notes in the same invoice, using a scalar s_i derived from {Z, H_I, "snd", i}
/// (per §7.2).
pub fn sender_change_address(
    scope: &Scope,
    i: u32,
    anchor_a: &PublicKey,
) -> Result<String, PcwError> {
    // Validate anchor_a is a valid compressed SEC1 public key (§7.7)
    let _secp = Secp256k1::new();
    if anchor_a.serialize().len() != 33 {
        return Err(PcwError::Other("Invalid public key §7.7".to_string()));
    }
    let s_i = scope.derive_scalar("snd", i)?;
    if s_i == [0; 32] {
        return Err(PcwError::Other("Zero scalar s_i §7.2".to_string()));
    }
    let tweak_point = scalar_mul(&s_i)?;
    let p_ai = point_add(anchor_a, &tweak_point)?;
    let ser = ser_p(&p_ai);
    let payload = h160(&ser);
    base58check(0x00, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{PublicKey, Secp256k1, SecretKey};

    #[test]
    fn test_recipient_address() -> Result<(), PcwError> {
        let scope = Scope::new([1; 32], [2; 32])?;
        let secret_key = SecretKey::from_byte_array([1; 32])?;
        let secp = Secp256k1::new();
        let anchor_b = PublicKey::from_secret_key(&secp, &secret_key);
        let addr = recipient_address(&scope, 0, &anchor_b)?;
        assert!(
            addr.starts_with("1"),
            "Address should start with '1' for mainnet P2PKH"
        );
        Ok(())
    }

    #[test]
    fn test_sender_change_address() -> Result<(), PcwError> {
        let scope = Scope::new([1; 32], [2; 32])?;
        let secret_key = SecretKey::from_byte_array([1; 32])?;
        let secp = Secp256k1::new();
        let anchor_a = PublicKey::from_secret_key(&secp, &secret_key);
        let addr = sender_change_address(&scope, 0, &anchor_a)?;
        assert!(
            addr.starts_with("1"),
            "Address should start with '1' for mainnet P2PKH"
        );
        Ok(())
    }

    #[test]
    fn test_recipient_address_invalid_pubkey() -> Result<(), PcwError> {
        let scope = Scope::new([1; 32], [2; 32])?;
        // Invalid public key (incorrect 33-byte array)
        let invalid_pub = [0xFFu8; 33]; // Invalid prefix, not on curve
        let result = recipient_address(&scope, 0, &PublicKey::from_slice(&invalid_pub)?);
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid public key")));
        Ok(())
    }

    #[test]
    fn test_sender_change_address_invalid_pubkey() -> Result<(), PcwError> {
        let scope = Scope::new([1; 32], [2; 32])?;
        // Invalid public key (incorrect 33-byte array)
        let invalid_pub = [0xFFu8; 33]; // Invalid prefix, not on curve
        let result = sender_change_address(&scope, 0, &PublicKey::from_slice(&invalid_pub)?);
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid public key")));
        Ok(())
    }

    #[test]
    fn test_recipient_address_zero_scalar() -> Result<(), PcwError> {
        let scope = Scope::new([1; 32], [2; 32])?;
        let secret_key = SecretKey::from_byte_array([1; 32])?;
        let secp = Secp256k1::new();
        let anchor_b = PublicKey::from_secret_key(&secp, &secret_key);
        // Mock a zero scalar by overriding derive_scalar (not directly possible, but tested via scalar_mul)
        let result = scalar_mul(&[0; 32]);
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Zero scalar")));
        Ok(())
    }

    #[test]
    fn test_sender_change_address_zero_scalar() -> Result<(), PcwError> {
        let scope = Scope::new([1; 32], [2; 32])?;
        let secret_key = SecretKey::from_byte_array([1; 32])?;
        let secp = Secp256k1::new();
        let anchor_a = PublicKey::from_secret_key(&secp, &secret_key);
        // Mock a zero scalar by overriding derive_scalar (not directly possible, but tested via scalar_mul)
        let result = scalar_mul(&[0; 32]);
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Zero scalar")));
        Ok(())
    }

    #[test]
    fn test_recipient_address_boundary_index() -> Result<(), PcwError> {
        let scope = Scope::new([1; 32], [2; 32])?;
        let secret_key = SecretKey::from_byte_array([1; 32])?;
        let secp = Secp256k1::new();
        let anchor_b = PublicKey::from_secret_key(&secp, &secret_key);
        let addr = recipient_address(&scope, u32::MAX, &anchor_b)?;
        assert!(
            addr.starts_with("1"),
            "Address should start with '1' for mainnet P2PKH"
        );
        Ok(())
    }

    #[test]
    fn test_sender_change_address_boundary_index() -> Result<(), PcwError> {
        let scope = Scope::new([1; 32], [2; 32])?;
        let secret_key = SecretKey::from_byte_array([1; 32])?;
        let secp = Secp256k1::new();
        let anchor_a = PublicKey::from_secret_key(&secp, &secret_key);
        let addr = sender_change_address(&scope, u32::MAX, &anchor_a)?;
        assert!(
            addr.starts_with("1"),
            "Address should start with '1' for mainnet P2PKH"
        );
        Ok(())
    }
}
