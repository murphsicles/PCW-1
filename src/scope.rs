//! Module for scope management in the PCW-1 protocol.
//!
//! This module implements the `Scope` struct and `derive_scalar` function as per §3.2, §4.2, and §7.2.
//! The scope defines a per-invoice context {Z, H_I} for deterministic derivations, while `derive_scalar`
//! generates scalars for specific domains (e.g., "recv", "snd") and indices, with a reject-zero bump
//! mechanism to ensure non-zero outputs.

use crate::errors::PcwError;
use crate::utils::{le32, sha256};
use proptest::prelude::*;

/// Per-invoice scope {Z, H_I} (§3.2).
#[derive(Clone, Debug)]
pub struct Scope {
    pub z: [u8; 32], // Shared secret from ECDH
    pub h_i: [u8; 32], // Hash of canonical invoice JSON
}

impl Scope {
    /// Create a new Scope instance.
    pub fn new(z: [u8; 32], h_i: [u8; 32]) -> Self {
        Self { z, h_i }
    }
}

/// Derive scalar for domain ("recv"/"snd") and i, with reject-zero bump (§4.2, §7.2).
pub fn derive_scalar(scope: &Scope, domain: &str, i: u32) -> Result<[u8; 32], PcwError> {
    if domain.is_empty() || domain.len() > 255 {
        return Err(PcwError::Other("Domain must be 1-255 bytes §4.2".to_string()));
    }
    let mut preimage = vec![];
    preimage.extend_from_slice(&scope.z);
    preimage.extend_from_slice(&scope.h_i);
    preimage.extend_from_slice(domain.as_bytes());
    preimage.extend_from_slice(&le32(i));
    let mut scalar = sha256(&preimage);
    let mut ctr = 0u32;
    while scalar == [0u8; 32] { // Reject-zero
        ctr += 1;
        let mut bump_preimage = preimage.clone();
        bump_preimage.extend_from_slice(&le32(ctr));
        scalar = sha256(&bump_preimage);
        if ctr > 1000 { // Safety bound, theoretical
            return Err(PcwError::ZeroScalar("Exhausted bump ctr".to_string()));
        }
    }
    Ok(scalar)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_scalar_basic() {
        let scope = Scope::new([1u8; 32], [2u8; 32]);
        let scalar = derive_scalar(&scope, "recv", 0).unwrap();
        assert_ne!(scalar, [0u8; 32]);
    }

    #[test]
    fn test_derive_scalar_different_i() {
        let scope = Scope::new([1u8; 32], [2u8; 32]);
        let scalar1 = derive_scalar(&scope, "recv", 0).unwrap();
        let scalar2 = derive_scalar(&scope, "recv", 1).unwrap();
        assert_ne!(scalar1, scalar2);
    }

    #[test]
    fn test_derive_scalar_different_domain() {
        let scope = Scope::new([1u8; 32], [2u8; 32]);
        let scalar1 = derive_scalar(&scope, "recv", 0).unwrap();
        let scalar2 = derive_scalar(&scope, "snd", 0).unwrap();
        assert_ne!(scalar1, scalar2);
    }

    #[test]
    fn test_derive_scalar_invalid_domain() {
        let scope = Scope::new([1u8; 32], [2u8; 32]);
        let result = derive_scalar(&scope, "", 0); // Empty domain
        assert!(result.is_err());
        let result = derive_scalar(&scope, &"x".repeat(256), 0); // Too long
        assert!(result.is_err());
    }

    proptest! {
        #[test]
        fn prop_derive_scalar_non_zero(
            z in prop::array::uniform32(0u8..),
            h_i in prop::array::uniform32(0u8..),
            i in 0u32..1000u32,
        ) {
            let scope = Scope::new(z, h_i);
            let scalar = derive_scalar(&scope, "recv", i).unwrap();
            prop_assert_ne!(scalar, [0u8; 32]);
        }
    }
}
