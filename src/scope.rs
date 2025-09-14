//! Module for deterministic scoping in the PCW-1 protocol.
//!
//! This module provides `Scope` for deterministic derivations using ECDH shared secrets
//! (Z) and invoice fingerprints (H_I) as per §3.2 and §4.2 of the spec.
use crate::errors::PcwError;
use crate::utils::{le32, sha256};

/// Scope as per §3.2: Z (ECDH shared secret) and H_I (invoice fingerprint).
#[derive(Clone, Debug)]
pub struct Scope {
    pub z: [u8; 32],   // ECDH shared secret (§3.2)
    pub h_i: [u8; 32], // Invoice fingerprint (§3.4)
}

impl Scope {
    /// Create new Scope, reject if Z or H_I is all-zero (§3.2).
    pub fn new(z: [u8; 32], h_i: [u8; 32]) -> Result<Self, PcwError> {
        if z == [0; 32] || h_i == [0; 32] {
            return Err(PcwError::ScopeMisuse("Zero Z or H_I §3.2".to_string()));
        }
        Ok(Self { z, h_i })
    }

    /// Derive scalar for domain ("recv"/"snd") and i, with reject-zero bump (§4.2, §7.2).
    pub fn derive_scalar(&self, domain: &str, i: u32) -> Result<[u8; 32], PcwError> {
        if domain.is_empty() || domain.len() > 255 {
            return Err(PcwError::Other(
                "Domain must be 1-255 bytes §4.2".to_string(),
            ));
        }
        let mut preimage = vec![];
        preimage.extend_from_slice(&self.z);
        preimage.extend_from_slice(&self.h_i);
        preimage.extend_from_slice(domain.as_bytes());
        preimage.extend_from_slice(&le32(i));
        let mut h = sha256(&preimage);
        let mut ctr = 0u32;
        while h == [0; 32] {
            ctr += 1;
            preimage = vec![];
            preimage.extend_from_slice(&self.z);
            preimage.extend_from_slice(&self.h_i);
            preimage.extend_from_slice(domain.as_bytes());
            preimage.extend_from_slice(&le32(i));
            preimage.extend_from_slice(&le32(ctr));
            h = sha256(&preimage);
        }
        Ok(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_scope() -> Result<(), PcwError> {
        let z = [1u8; 32];
        let h_i = [2u8; 32];
        let scope = Scope::new(z, h_i)?;
        assert_eq!(scope.z, z);
        assert_eq!(scope.h_i, h_i);
        assert!(Scope::new([0u8; 32], h_i).is_err());
        Ok(())
    }

    #[test]
    fn test_derive_scalar() -> Result<(), PcwError> {
        let z = [1u8; 32];
        let h_i = [2u8; 32];
        let scope = Scope::new(z, h_i)?;
        let scalar1 = scope.derive_scalar("recv", 0)?;
        let scalar2 = scope.derive_scalar("recv", 0)?;
        assert_eq!(scalar1, scalar2); // Deterministic
        assert_ne!(scalar1, [0u8; 32]); // Non-zero
        assert!(scope.derive_scalar("", 0).is_err()); // Empty domain
        Ok(())
    }
}
