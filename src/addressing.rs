use crate::errors::PcwError;
use crate::scope::Scope;
use crate::utils::{base58check, h160, point_add, scalar_mul, ser_p};
use secp256k1::PublicKey;

/// Recipient address per §4: Tweak anchor_b with t_i.
pub fn recipient_address(scope: &Scope, i: u32, anchor_b: &PublicKey) -> Result<String, PcwError> {
    let t_i = derive_scalar(scope, "recv", i)?;
    let tweak_point = scalar_mul(&t_i, &secp256k1::G);
    let p_bi = point_add(anchor_b, &tweak_point)?;
    let ser = ser_p(&p_bi);
    let payload = h160(&ser);
    base58check(0x00, &payload)
}

/// Sender change address per §7: Tweak anchor_a with s_i.
pub fn sender_change_address(scope: &Scope, i: u32, anchor_a: &PublicKey) -> Result<String, PcwError> {
    let s_i = derive_scalar(scope, "snd", i)?;
    let tweak_point = scalar_mul(&s_i, &secp256k1::G);
    let p_ai = point_add(anchor_a, &tweak_point)?;
    let ser = ser_p(&p_ai);
    let payload = h160(&ser);
    base58check(0x00, &payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::PublicKey;

    #[test]
    fn test_recipient_address() -> Result<(), PcwError> {
        let scope = Scope::new([0;32], [0;32]);
        let anchor_b = PublicKey::from_secret_key(&secp256k1::SECP256k1, &SecretKey::from_slice(&[1;32])?);
        let addr = recipient_address(&scope, 0, &anchor_b)?;
        assert!(addr.starts_with("1"));
        Ok(())
    }
}
