use crate::errors::PcwError;
use crate::utils::{le32, sha256};

/// Per-invoice scope {Z, H_I} (§3.2).
#[derive(Clone, Debug)]
pub struct Scope {
    pub z: [u8; 32],
    pub h_i: [u8; 32],
}

impl Scope {
    pub fn new(z: [u8; 32], h_i: [u8; 32]) -> Self {
        Self { z, h_i }
    }
}

/// Derive scalar for domain ("recv"/"snd") and i, with reject-zero bump (§4.2, §7.2).
pub fn derive_scalar(scope: &Scope, domain: &str, i: u32) -> Result<[u8; 32], PcwError> {
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
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_derive_scalar_non_zero(z in prop::array::uniform32(0u8..), h_i in prop::array::uniform32(0u8..), i in 0u32..) {
            let scope = Scope::new(z, h_i);
            let scalar = derive_scalar(&scope, "recv", i).unwrap();
            prop_assert_ne!(scalar, [0u8; 32]);
        }
    }
}
