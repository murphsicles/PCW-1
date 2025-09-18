use chrono::Utc;
use hex;
use pcw_protocol::{
    AnchorKeypair, Entry, IdentityKeypair, Invoice, Manifest, PcwError, Policy, Scope, Utxo,
    addressing::{recipient_address, sender_change_address},
    bounded_split, build_note_tx, build_reservations, compute_leaves, ecdh_z, generate_proof,
    merkle_root, utils::{h160, sha256}, verify_proof,
};
use sv::messages::OutPoint;
use sv::transaction::p2pkh::create_lock_script;
use sv::util::{Hash160, Hash256};

fn main() -> Result<(), PcwError> {
    // Mock keys
    let priv_a = [1u8; 32];
    let priv_b = [2u8; 32];
    let identity_a = IdentityKeypair::new(priv_a)?;
    let identity_b = IdentityKeypair::new(priv_b)?;
    let anchor_a = AnchorKeypair::new([3u8; 32])?;
    let anchor_b = AnchorKeypair::new([4u8; 32])?;

    // Create and sign policy
    let expiry = Utc::now() + chrono::Duration::days(1);
    let mut policy = Policy::new(
        hex::encode(anchor_b.pub_key.serialize()),
        100,
        1000,
        500,
        1,
        expiry,
    )?;
    policy.sign(&identity_b)?;
    let h_policy = policy.h_policy();

    // Create and sign invoice
    let mut invoice = Invoice::new(
        "inv1".to_string(),
        "terms".to_string(),
        "sat".to_string(),
        1000,
        hex::encode(h_policy),
        Some(expiry),
    )?;
    invoice.sign(&identity_a)?;
    let h_i = invoice.h_i();

    // Create scope and derive address
    let z = ecdh_z(&priv_a, &identity_b.pub_key)?;
    let scope = Scope::new(z, h_i)?;
    let addr_b = recipient_address(&scope, 0, &anchor_b.pub_key)?;
    let addr_a = sender_change_address(&scope, 0, &anchor_a.pub_key)?;

    // Split amount
    let split = bounded_split(&scope, 1000, 100, 1000)?;
    let amounts = split;

    // Create mock UTXO
    let mock_hash = sha256(b"test_tx");
    let mock_h160 = h160(&mock_hash);
    let mock_script = create_lock_script(&Hash160(mock_h160));
    let u0 = vec![Utxo {
        outpoint: OutPoint {
            hash: Hash256(mock_hash),
            index: 0,
        },
        value: 1500,
        script_pubkey: mock_script.0,
    }];

    // Build reservations
    let total = amounts.iter().sum::<u64>();
    let (reservations, _addrs, _amounts, _n) = build_reservations(
        &u0,
        total,
        &scope,
        &anchor_b.pub_key,
        &anchor_a.pub_key,
        1,   // feerate_floor
        50,  // dust
        false, // fanout_allowed
    )?;

    // Access reservations
    let s_i = reservations.0.get(0).unwrap().as_ref().unwrap();

    // Build transaction
    let priv_keys = vec![[5u8; 32]; s_i.len()];
    let (note_tx, meta) = build_note_tx(
        &scope,
        0,
        s_i,
        amounts[0],
        &anchor_b.pub_key,
        &anchor_a.pub_key,
        1,
        1,
        &priv_keys,
    )?;

    // Generate receipt
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

    // Print results (example)
    println!("Recipient address: {}", addr_b);
    println!("Sender change address: {}", addr_a);
    println!("Selected UTXOs: {:?}", s_i);
    println!("Note transaction: {:?}", note_tx);
    println!("Transaction metadata: {:?}", meta);

    Ok(())
}
