use pcw_protocol::errors::PcwError;
use pcw_protocol::invoice::Invoice;
use pcw_protocol::keys::{AnchorKeypair, IdentityKeypair};
use pcw_protocol::policy::Policy;
use pcw_protocol::receipts::{compute_leaves, Entry, generate_proof, Manifest, merkle_root, verify_proof};
use pcw_protocol::scope::Scope;
use pcw_protocol::selection::{build_reservations, Utxo};
use pcw_protocol::split::bounded_split;
use pcw_protocol::tx::build_note_tx;
use pcw_protocol::utils::{ecdh_z, h160, sha256};
use chrono::{Duration, Utc};
use hex;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sv::messages::OutPoint;
use sv::transaction::p2pkh::create_lock_script;
use sv::util::{Hash160, Hash256};

#[test]
fn test_full_protocol_flow() -> Result<(), PcwError> {
    let _secp = Secp256k1::new();
    // Mock keys
    let priv_a = [1; 32];
    let identity_a = IdentityKeypair::new(priv_a)?;
    let priv_b = [2; 32];
    let identity_b = IdentityKeypair::new(priv_b)?;
    let anchor_a = AnchorKeypair::new([3; 32])?;
    let anchor_b = AnchorKeypair::new([4; 32])?;
    // Policy
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
    // Invoice
    let mut invoice = Invoice::new(
        "inv1".to_string(),
        "terms".to_string(),
        "sat".to_string(),
        2000,
        hex::encode(h_policy),
        Some(expiry),
    )?;
    invoice.sign(&identity_a)?;
    invoice.verify(&h_policy)?;
    let h_i = invoice.h_i();
    // Scope
    let z = ecdh_z(&priv_a, &identity_b.pub_key)?;
    let scope = Scope::new(z, h_i)?;
    // Split
    let split = bounded_split(&scope, 2000, 100, 1000)?;
    assert_eq!(split.iter().sum::<u64>(), 2000);
    // Mock UTXOs
    let mock_hash = sha256(b"test_tx");
    let mock_h160 = h160(&mock_hash);
    let mock_script = create_lock_script(&Hash160(mock_h160));
    let u0 = vec![
        Utxo {
            outpoint: OutPoint {
                hash: Hash256(mock_hash),
                index: 0,
            },
            value: 1500,
            script_pubkey: mock_script.0.clone(),
        },
        Utxo {
            outpoint: OutPoint {
                hash: Hash256(sha256(b"test_tx_2")),
                index: 1,
            },
            value: 1500,
            script_pubkey: mock_script.0.clone(),
        },
    ];
    let total = split.iter().sum::<u64>();
    let (r, _addrs, _amounts, _n) = build_reservations(&u0, total, &scope, &anchor_b.pub_key, &anchor_a.pub_key, 1, 50, false)?;
    assert_eq!(r.len(), split.len());
    // Build tx for i=0
    let i = 0u32;
    let s_i = r.get(i as usize).unwrap().as_ref().unwrap();
    let priv_keys = vec![[5; 32]; s_i.len()];
    let (_note_tx, meta) = build_note_tx(
        &scope,
        i,
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
    // Receipts
    let amounts = split.clone();
    let addr_payloads = vec![[0; 21]; split.len()];
    let mut entries = vec![];
    for j in 0..split.len() {
        entries.push(Entry {
            i: j as u32,
            txid: format!("{:064}", j),
        });
    }
    let mut manifest = Manifest {
        invoice_hash: hex::encode(h_i),
        merkle_root: "".to_string(),
        count: split.len(),
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
fn test_infeasible_split() -> Result<(), PcwError> {
    let scope = Scope::new([1; 32], [2; 32])?;
    let result = bounded_split(&scope, 99, 100, 500);
    assert!(result.is_err());
    assert!(matches!(result, Err(PcwError::InfeasibleSplit)));
    Ok(())
}

#[test]
fn test_dust_change() -> Result<(), PcwError> {
    let secp = Secp256k1::new();
    let scope = Scope::new([1; 32], [2; 32])?;
    let secret_key = SecretKey::from_byte_array([1; 32]).unwrap();
    let anchor_b = PublicKey::from_secret_key(&secp, &secret_key);
    let anchor_a = anchor_b.clone();
    let mock_hash = sha256(b"test_tx");
    let mock_h160 = h160(&mock_hash);
    let mock_script = create_lock_script(&Hash160(mock_h160));
    let u0 = vec![Utxo {
        outpoint: OutPoint {
            hash: Hash256(mock_hash),
            index: 0,
        },
        value: 101,
        script_pubkey: mock_script.0.clone(),
    }];
    let split = vec![100];
    let priv_keys = vec![[5; 32]];
    let result = build_note_tx(
        &scope,
        0,
        &u0,
        split[0],
        &anchor_b,
        &anchor_a,
        1,
        50,
        &priv_keys,
    );
    assert!(result.is_err());
    assert!(matches!(result, Err(PcwError::DustChange)));
    Ok(())
}

fn main() {
    // This is a test binary, main is empty
}
