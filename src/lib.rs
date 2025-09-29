/*! Peer Cash Wallet Protocol (PCW-1): IP-to-IP BSV settlement protocol per spec.
This crate implements the PCW-1 protocol as defined in §1-§17, providing modules
for key management, address derivation, transaction building, logging, and more.
It ensures deterministic, secure, and auditable payment processing.
*/
pub mod addressing;
pub mod broadcast;
pub mod errors;
pub mod failure;
pub mod invoice;
pub mod json;
pub mod keys;
pub mod logging;
pub mod policy;
pub mod protocol;
pub mod receipts;
pub mod scope;
pub mod selection;
pub mod split;
pub mod tx;
pub mod utils;
pub use addressing::{recipient_address, sender_change_address};
pub use broadcast::{BroadcastPolicy, pacing_schedule};
pub use errors::PcwError;
pub use failure::{Event, InvoiceState, NoteState};
pub use invoice::Invoice;
pub use json::canonical_json;
pub use keys::{AnchorKeypair, IdentityKeypair};
pub use logging::{LogRecord, append_to_log};
pub use policy::Policy;
pub use protocol::{exchange_invoice, exchange_policy, handshake};
pub use receipts::{
    Entry, Manifest, Proof, compute_leaves, generate_proof, merkle_root, verify_proof,
};
pub use scope::Scope;
pub use selection::{Utxo, build_reservations};
pub use split::bounded_split;
pub use tx::{NoteMeta, NoteTx, build_note_tx};
pub use utils::ecdh_z;
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use serde_json::Value;
    use sv::messages::OutPoint;
    use sv::transaction::p2pkh::create_lock_script;
    use sv::util::{Hash160, Hash256};
    #[test]
    fn test_protocol_integration() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        // Create mock keys
        let priv_a = [1u8; 32];
        let identity_a = IdentityKeypair::new(priv_a)?;
        let priv_b = [2u8; 32];
        let identity_b = IdentityKeypair::new(priv_b)?;
        let anchor_a = AnchorKeypair::new([3u8; 32])?;
        let anchor_b = AnchorKeypair::new([4u8; 32])?;
        // Create mock UTXO private key
        let utxo_priv = [5u8; 32];
        let utxo_pub = PublicKey::from_secret_key(&secp, &SecretKey::from_byte_array(utxo_priv)?);
        // Create and sign policy
        let expiry = Utc::now() + Duration::days(1);
        let mut policy = Policy::new(
            hex::encode(anchor_b.pub_key.serialize()),
            2000,  // available
            500,   // vmin
            1000,  // vmax
            1000,  // per_address_cap
            expiry,
        )?;
        policy.sign(&identity_b)?;
        policy.verify()?;
        let h_policy = policy.h_policy();
        // Create and sign invoice
        let mut invoice = Invoice::new(
            "test".to_string(),
            "terms".to_string(),
            "sat".to_string(),
            1000,
            hex::encode(h_policy),
            Some(expiry),
        )?;
        invoice.sign(&identity_a)?;
        invoice.verify(&h_policy)?;
        let h_i = invoice.h_i();
        // Create scope
        let z = ecdh_z(&priv_a, &identity_b.pub_key)?;
        let scope = Scope::new(z, h_i)?;
        // Derive addresses
        let addr_b = recipient_address(&scope, 0, &anchor_b.pub_key)?;
        let addr_a = sender_change_address(&scope, 0, &anchor_a.pub_key)?;
        assert!(addr_b.starts_with("1"));
        assert!(addr_a.starts_with("1"));
        // Split amount
        let split = bounded_split(&scope, 1000, 100, 1000)?;
        assert_eq!(split.iter().sum::<u64>(), 1000);
        // Create mock UTXO
        let mock_hash = utils::sha256(b"test_tx");
        let mock_h160 = utils::h160(&utils::ser_p(&utxo_pub));
        let mock_script = create_lock_script(&Hash160(mock_h160));
        let utxo = Utxo {
            outpoint: OutPoint {
                hash: Hash256(mock_hash),
                index: 0,
            },
            value: 100000000, // Increased to cover total + fees for multiple notes
            script_pubkey: mock_script.0.clone(),
        };
        // Build reservations
        let total = split.iter().sum::<u64>();
        let (reservations, _addrs, _amounts, _n) = build_reservations(
            &[utxo],
            total,
            &scope,
            &anchor_b.pub_key,
            &anchor_a.pub_key,
            1,
            50,
            false,
        )?;
        let s_i = reservations.get(0).unwrap().as_ref().unwrap();
        // Build transaction
        let priv_keys = vec![utxo_priv];
        let (_note_tx, meta) = build_note_tx(
            &scope,
            0,
            s_i,
            split[0],
            &anchor_b.pub_key,
            &anchor_a.pub_key,
            1,
            50,
            &priv_keys,
        )?;
        assert_eq!(meta.amount, split[0]);
        assert!(meta.txid.len() > 0);
        // Create receipt
        let amounts = split;
        let addr_payloads: Vec<[u8; 21]> = amounts
            .iter()
            .enumerate()
            .map(|(i, _)| {
                let _addr = recipient_address(&scope, i as u32, &anchor_b.pub_key)?;
                let lock_script =
                    create_lock_script(&Hash160(utils::h160(&utils::ser_p(&utils::point_add(
                        &anchor_b.pub_key,
                        &utils::scalar_mul(&scope.derive_scalar("recv", i as u32)?)?,
                    )?))));
                Ok(lock_script.0[0..21].try_into().unwrap())
            })
            .collect::<Result<Vec<_>, PcwError>>()?;
        let mut entries = vec![];
        for j in 0..amounts.len() {
            entries.push(Entry {
                i: j as u32,
                txid: format!("{:064}", j),
            });
        }
        let mut manifest = Manifest {
            invoice_hash: hex::encode(h_i),
            merkle_root: "".to_string(),
            count: amounts.len(),
            entries,
        };
        let leaves = compute_leaves(&manifest, &amounts, &addr_payloads)?;
        let root = merkle_root(&leaves)?;
        manifest.merkle_root = hex::encode(root);
        let proof = generate_proof(&leaves, 0, &manifest, &amounts, &addr_payloads)?;
        verify_proof(&proof, &manifest)?;
        Ok(())
    }
    #[test]
    fn test_invalid_keys() -> Result<(), PcwError> {
        // Test invalid private key
        let result = IdentityKeypair::new([0u8; 32]);
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Zero private key")));
        // Test invalid public key in ECDH
        let invalid_pub = [0xFFu8; 33]; // Invalid prefix, not on curve
        let result = PublicKey::from_slice(&invalid_pub);
        assert!(matches!(result, Err(secp256k1::Error::InvalidPublicKey)));
        Ok(())
    }
    #[test]
    fn test_malformed_json() -> Result<(), PcwError> {
        let priv_b = [2u8; 32];
        let identity_b = IdentityKeypair::new(priv_b)?;
        let anchor_b = AnchorKeypair::new([4u8; 32])?;
        let expiry = Utc::now() + Duration::days(1);
        // Malformed policy JSON (floating-point vmin)
        let malformed_policy: Value = serde_json::from_str(
            r#"{"pk_anchor":"02","vmin":1.5,"vmax":1000,"per_address_cap":500,"feerate_floor":1,"expiry":"2025-09-15T19:28:00Z","sig_key":"","sig_alg":"","sig":""}"#,
        )?;
        let result = canonical_json(&malformed_policy);
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Non-integer numbers")));
        // Valid policy for invoice
        let mut policy = Policy::new(
            hex::encode(anchor_b.pub_key.serialize()),
            100,
            500,   // vmin
            1000,  // vmax
            1000,  // per_address_cap
            expiry,
        )?;
        policy.sign(&identity_b)?;
        let h_policy = policy.h_policy();
        // Malformed invoice JSON (zero total)
        let result = Invoice::new(
            "test".to_string(),
            "terms".to_string(),
            "sat".to_string(),
            0,
            hex::encode(h_policy),
            Some(expiry),
        );
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Zero amount")));
        Ok(())
    }
    #[test]
    fn test_large_inputs() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        let priv_a = [1u8; 32];
        let identity_a = IdentityKeypair::new(priv_a)?;
        let priv_b = [2u8; 32];
        let identity_b = IdentityKeypair::new(priv_b)?;
        let anchor_a = AnchorKeypair::new([3u8; 32])?;
        let anchor_b = AnchorKeypair::new([4u8; 32])?;
        let utxo_priv = [5u8; 32];
        let utxo_pub = PublicKey::from_secret_key(&secp, &SecretKey::from_byte_array(utxo_priv)?);
        let expiry = Utc::now() + Duration::days(1);
        // Create policy
        let mut policy = Policy::new(
            hex::encode(anchor_b.pub_key.serialize()),
            20000,  // available
            500,    // vmin
            1000,   // vmax
            1000,   // per_address_cap
            expiry,
        )?;
        policy.sign(&identity_b)?;
        let h_policy = policy.h_policy();
        // Create invoice
        let mut invoice = Invoice::new(
            "test".to_string(),
            "terms".to_string(),
            "sat".to_string(),
            10000,
            hex::encode(h_policy),
            Some(expiry),
        )?;
        invoice.sign(&identity_a)?;
        let h_i = invoice.h_i();
        // Create scope
        let z = ecdh_z(&priv_a, &identity_b.pub_key)?;
        let scope = Scope::new(z, h_i)?;
        // Large split (10 notes)
        let split = bounded_split(&scope, 10000, 100, 1000)?;
        assert!(split.len() >= 10 && split.len() <= 100);
        assert_eq!(split.iter().sum::<u64>(), 10000);
        // Large UTXO set (100 UTXOs)
        let mock_h160 = utils::h160(&utils::ser_p(&utxo_pub));
        let mock_script = create_lock_script(&Hash160(mock_h160));
        let mut utxos = vec![];
        for i in 0..100 {
            utxos.push(Utxo {
                outpoint: OutPoint {
                    hash: Hash256(utils::sha256(&format!("test_tx_{}", i).as_bytes())),
                    index: i as u32,
                },
                value: 10000,
                script_pubkey: mock_script.0.clone(),
            });
        }
        // Build reservations
        let total = split.iter().sum::<u64>();
        let (reservations, _addrs, _amounts, _n) = build_reservations(
            &utxos,
            total,
            &scope,
            &anchor_b.pub_key,
            &anchor_a.pub_key,
            1,
            50,
            false,
        )?;
        assert!(reservations.len() <= utxos.len(), "reservations.len()={} vs utxos.len()={}", reservations.len(), utxos.len());
        // Build transaction for first note
        let s_i = reservations.get(0).unwrap().as_ref().unwrap();
        let priv_keys = vec![utxo_priv; s_i.len()];
        let (_note_tx, meta) = build_note_tx(
            &scope,
            0,
            s_i,
            split[0],
            &anchor_b.pub_key,
            &anchor_a.pub_key,
            1,
            50,
            &priv_keys,
        )?;
        assert_eq!(meta.amount, split[0]);
        // Create receipt for large set
        let amounts = split;
        let addr_payloads: Vec<[u8; 21]> = amounts
            .iter()
            .enumerate()
            .map(|(i, _)| {
                let _addr = recipient_address(&scope, i as u32, &anchor_b.pub_key)?;
                let lock_script =
                    create_lock_script(&Hash160(utils::h160(&utils::ser_p(&utils::point_add(
                        &anchor_b.pub_key,
                        &utils::scalar_mul(&scope.derive_scalar("recv", i as u32)?)?,
                    )?))));
                Ok(lock_script.0[0..21].try_into().unwrap())
            })
            .collect::<Result<Vec<_>, PcwError>>()?;
        let mut entries = vec![];
        for j in 0..amounts.len() {
            entries.push(Entry {
                i: j as u32,
                txid: format!("{:064}", j),
            });
        }
        let mut manifest = Manifest {
            invoice_hash: hex::encode(h_i),
            merkle_root: "".to_string(),
            count: amounts.len(),
            entries,
        };
        let leaves = compute_leaves(&manifest, &amounts, &addr_payloads)?;
        let root = merkle_root(&leaves)?;
        manifest.merkle_root = hex::encode(root);
        let proof = generate_proof(&leaves, 0, &manifest, &amounts, &addr_payloads)?;
        verify_proof(&proof, &manifest)?;
        Ok(())
    }
    #[test]
    fn test_failure_cases() -> Result<(), PcwError> {
        let secp = Secp256k1::new();
        let priv_a = [1u8; 32];
        let identity_a = IdentityKeypair::new(priv_a)?;
        let priv_b = [2u8; 32];
        let identity_b = IdentityKeypair::new(priv_b)?;
        let anchor_a = AnchorKeypair::new([3u8; 32])?;
        let anchor_b = AnchorKeypair::new([4u8; 32])?;
        let utxo_priv = [5u8; 32];
        let utxo_pub = PublicKey::from_secret_key(&secp, &SecretKey::from_byte_array(utxo_priv)?);
        let expiry = Utc::now() + Duration::days(1);
        // Create policy
        let mut policy = Policy::new(
            hex::encode(anchor_b.pub_key.serialize()),
            100,
            500,   // vmin
            1000,  // vmax
            1000,  // per_address_cap
            expiry,
        )?;
        policy.sign(&identity_b)?;
        let h_policy = policy.h_policy();
        // Create invoice
        let mut invoice = Invoice::new(
            "test".to_string(),
            "terms".to_string(),
            "sat".to_string(),
            1000,
            hex::encode(h_policy),
            Some(expiry),
        )?;
        invoice.sign(&identity_a)?;
        let h_i = invoice.h_i();
        // Create scope
        let z = ecdh_z(&priv_a, &identity_b.pub_key)?;
        let scope = Scope::new(z, h_i)?;
        // Test Underfunded
        let mock_hash = utils::sha256(b"test_tx");
        let mock_h160 = utils::h160(&utils::ser_p(&utxo_pub));
        let mock_script = create_lock_script(&Hash160(mock_h160));
        let utxo = Utxo {
            outpoint: OutPoint {
                hash: Hash256(mock_hash),
                index: 0,
            },
            value: 50, // Too low
            script_pubkey: mock_script.0.clone(),
        };
        let split = bounded_split(&scope, 1000, 100, 1000)?;
        let total = split.iter().sum::<u64>();
        let result = build_reservations(
            &[utxo],
            total,
            &scope,
            &anchor_b.pub_key,
            &anchor_a.pub_key,
            1,
            50,
            false,
        );
        assert!(matches!(result, Err(PcwError::Underfunded)));
        // Test DustChange
        let utxo = Utxo {
            outpoint: OutPoint {
                hash: Hash256(mock_hash),
                index: 0,
            },
            value: 341, // Adjusted to trigger DustChange: 341 - 100 - 192 = 49 < 50
            script_pubkey: mock_script.0.clone(),
        };
        let priv_keys = vec![utxo_priv];
        let result = build_note_tx(
            &scope,
            0,
            &[utxo],
            100,
            &anchor_b.pub_key,
            &anchor_a.pub_key,
            1,
            50,
            &priv_keys,
        );
        assert!(matches!(result, Err(PcwError::DustChange)));
        // Test InfeasibleSplit
        let result = bounded_split(&scope, 99, 100, 500);
        assert!(matches!(result, Err(PcwError::InfeasibleSplit)));
        // Test invalid state transition
        let state = NoteState::Signed;
        let result = state.transition(&Event::Supersede);
        assert!(
            matches!(result, Err(PcwError::Other(msg)) if msg.contains("Invalid note state transition")),
        );
        Ok(())
    }
}
