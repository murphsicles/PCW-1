//! Peer Cash Wallet Protocol (PCW-1): IP-to-IP BSV settlement protocol per spec.
//!
//! This crate implements the PCW-1 protocol as defined in §1-§17, providing modules
//! for key management, address derivation, transaction building, logging, and more.
//! It ensures deterministic, secure, and auditable payment processing.

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
pub use broadcast::{pacing_schedule, BroadcastPolicy};
pub use errors::PcwError;
pub use failure::{Event, InvoiceState, NoteState};
pub use invoice::Invoice;
pub use json::canonical_json;
pub use keys::{AnchorKeypair, IdentityKeypair};
pub use logging::{append_to_log, LogRecord};
pub use policy::Policy;
pub use protocol::{ecdh_z, exchange_invoice, exchange_policy, handshake};
pub use receipts::{compute_leaves, generate_proof, merkle_root, verify_proof, Entry, Manifest, Proof};
pub use scope::Scope;
pub use selection::{Utxo, build_reservations};
pub use split::bounded_split;
pub use tx::{build_note_tx, NoteMeta, NoteTx};

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
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

        // Create and sign policy
        let expiry = Utc::now() + Duration::days(1);
        let mut policy = Policy::new(
            hex::encode(anchor_b.pub_key.serialize()),
            100,
            1000,
            500,
            1,
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
        let addr_b = recipient_address(&secp, &scope, 0, &anchor_b.pub_key)?;
        let addr_a = sender_change_address(&secp, &scope, 0, &anchor_a.pub_key)?;
        assert!(addr_b.starts_with("1"));
        assert!(addr_a.starts_with("1"));

        // Split amount
        let split = bounded_split(&scope, 1000, 100, 1000)?;
        assert_eq!(split.iter().sum::<u64>(), 1000);

        // Create mock UTXO
        let mock_hash = sha256(b"test_tx");
        let mock_h160 = h160(&mock_hash);
        let mock_script = create_lock_script(&Hash160(mock_h160));
        let utxo = Utxo {
            outpoint: OutPoint {
                hash: Hash256(mock_hash),
                index: 0,
            },
            value: 1500,
            script_pubkey: mock_script.to_bytes(),
        };

        // Build reservations
        let reservations = build_reservations(&[utxo], &split, 1, 1, 3, 5, false)?;
        let s_i = reservations.get(&0).unwrap_or(&vec![]);

        // Build transaction
        let priv_keys = vec![[5u8; 32]; s_i.len()];
        let (note_tx, meta) = build_note_tx(
            &scope,
            0,
            s_i,
            split[0],
            &anchor_b.pub_key,
            &anchor_a.pub_key,
            1,
            1,
            &priv_keys,
        )?;
        assert_eq!(meta.amount, split[0]);
        assert!(meta.txid.len() > 0);

        // Create receipt
        let amounts = split;
        let addr_payloads = vec![[0u8; 21]; amounts.len()];
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
}
