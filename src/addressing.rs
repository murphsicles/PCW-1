//! Module for address generation in the PCW-1 protocol.
//!
//! This module provides functions to derive recipient and sender change addresses
//! based on the protocol's deterministic scoping, using ECDH-derived shared secrets
//! and invoice fingerprints as per §§3-6 of the spec.

use crate::errors::PcwError;
use crate::scope::Scope;
use crate::utils::{base58check, h160, point_add, scalar_mul, ser_p};
use secp256k1::{PublicKey, SecretKey, Secp256k1};

/// Derives a recipient address for a given note index.
///
/// This function uses the recipient's anchor key, tweaked with a scalar derived from
/// the ECDH shared secret (Z) and invoice hash (H_I), to create a P2PKH address
/// that only the recipient can spend (per §5).
pub fn recipient_address(scope: &Scope, i: u32, anchor_b: &PublicKey) -> Result<String, PcwError> {
    let t_i = derive_scalar(scope, "recv", i)?;
    let tweak_point = scalar_mul(&t_i, &secp256k1::constants::GENERATOR)?;
    let p_bi = point_add(anchor_b, &tweak_point)?;
    let ser = ser_p(&p_bi);
    let payload = h160(&ser);
    base58check(0x00, &payload)
}

/// Derives a sender change address for a given note index.
///
/// This function generates a change address per note, ensuring no overlap with
/// other notes in the same invoice, using a scalar derived from {Z, H_I, "snd", i}
/// (per §6).
pub fn sender_change_address(scope: &Scope, i: u32, anchor_a: &PublicKey) -> Result<String, PcwError> {
    let s_i = derive_scalar(scope, "snd", i)?;
    let tweak_point = scalar_mul(&s_i, &secp256k1::constants::GENERATOR)?;
    let p_ai = point_add(anchor_a, &tweak_point)?;
    let ser = ser_p(&p_ai);
    let payload = h160(&ser);
    base58check(0x00, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{PublicKey, SecretKey, Secp256k1};

    #[test]
    fn test_recipient_address() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        let scope = Scope::new([0; 32], [0; 32]);
        let secret_key = SecretKey::from_slice(&[1; 32]).expect("32 bytes, within curve order");
        let anchor_b = PublicKey::from_secret_key(&secp, &secret_key);
        let addr = recipient_address(&scope, 0, &anchor_b)?;
        assert!(addr.starts_with("1"), "Address should start with '1' for mainnet P2PKH");
        Ok(())
    }
}
