use crate::errors::PcwError;
use secp256k1::{PublicKey, SecretKey, SECP256K1};

/// Identity keypair for off-chain auth (§3.1, §13.1). Never on-chain.
#[derive(Clone, Debug)]
pub struct IdentityKeypair {
    pub priv_key: [u8; 32],
    pub pub_key: PublicKey,
}

/// Anchor keypair for on-chain derivations (§3.1, §13.1). Separate from identity.
#[derive(Clone, Debug)]
pub struct AnchorKeypair {
    pub priv_key: [u8; 32],
    pub pub_key: PublicKey,
}

impl IdentityKeypair {
    /// Generate from secret (mock for tests; prod use secure rand).
    pub fn new(priv_key: [u8; 32]) -> Result<Self, PcwError> {
        let sec_key = SecretKey::from_slice(&priv_key)?;
        let pub_key = PublicKey::from_secret_key(SECP256K1, &sec_key);
        Ok(Self { priv_key, pub_key })
    }
}

impl AnchorKeypair {
    pub fn new(priv_key: [u8; 32]) -> Result<Self, PcwError> {
        let sec_key = SecretKey::from_slice(&priv_key)?;
        let pub_key = PublicKey::from_secret_key(SECP256K1, &sec_key);
        Ok(Self { priv_key, pub_key })
    }
}

/// Compute ECDH Z: x-coordinate of priv * their_pub (§3.2).
pub fn ecdh_z(my_priv: &[u8; 32], their_pub: &PublicKey) -> Result<[u8; 32], PcwError> {
    let sec_key = SecretKey::from_slice(my_priv)?;
    let point = their_pub.mul_tweak(SECP256K1, &sec_key.scalar())?; // ECDH
    let serialized = point.serialize();
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
        assert_eq!(z1, z2); // Symmetric
        Ok(())
    }
}
