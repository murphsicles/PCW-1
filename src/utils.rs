use crate::errors::PcwError;
use sha2::{Digest, Sha256};
use ripemd::Ripemd160;
use base58::ToBase58;
use secp256k1::PublicKey;
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
    let mut res = *p1;
    res.add_exp_assign(&secp256k1::SECP256K1, &p2.into())?; // Wait, secp has add_exp, but for point + point, use combine
    Ok(res.combine(p2)?)
}

/// Scalar mul: scalar * G (§4.3).
pub fn scalar_mul(scalar: &[u8; 32], g: &secp256k1::G) -> PublicKey {
    PublicKey::from_secret_key(&secp256k1::SECP256K1, &SecretKey::from_slice(scalar).unwrap())
}

/// NFC normalize string (§2).
pub fn nfc_normalize(s: &str) -> String {
    s.nfc().collect::<String>()
}
