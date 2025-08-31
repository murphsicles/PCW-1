use chrono::prelude::*;
use hex;
use pcw_protocol::{
    AnchorKeypair, Entry, IdentityKeypair, Invoice, Manifest, Policy, Scope, bounded_split,
    build_note_tx, build_reservations, compute_leaves, generate_proof, merkle_root, verify_proof,
};
use sv::messages::OutPoint;
use sv::util::Hash256;

fn main() -> Result<(), PcwError> {
    // Mock keys
    let priv_a = [1u8; 32];
    let identity_a = IdentityKeypair::new(priv_a)?;
    let priv_b = [2u8; 32];
    let identity_b = IdentityKeypair::new(priv_b)?;
    let anchor_a = AnchorKeypair::new([3u8; 32])?;
    let anchor_b = AnchorKeypair::new([4u8; 32])?;

    // Policy
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
    let scope = Scope::new(z, h_i);

    // Split
    let split = bounded_split(&scope, 2000, 100, 1000)?;
    println!("Split: {:?}", split);

    // Mock UTXOs
    let mut u0 = vec![];
    for i in 0..5 {
        u0.push(Utxo {
            outpoint: OutPoint {
                hash: Hash256([i; 32]),
                index: i as u32,
            },
            value: 500,
            script_pubkey: vec![],
        });
    }
    let r = build_reservations(&u0, &split, 1, 1, 3, 5, true)?;
    println!("Reservation: {:?}", r);

    // Build tx for i=0
    let i = 0;
    let s_i = r.get(&i).unwrap_or(&vec![]);
    let priv_keys = vec![[5u8; 32]; s_i.len()];
    let (note_tx, meta) = build_note_tx(
        &scope,
        i,
        s_i,
        split[0],
        &anchor_b.pub_key,
        &anchor_a.pub_key,
        1,
        1,
        &priv_keys,
    )?;
    println!("Note Tx: {:?}", note_tx);
    println!("Meta: {:?}", meta);

    // Receipts mock
    let amounts = split;
    let addr_payloads = vec![[0u8; 21]; amounts.len()];
    let mut entries = vec![];
    for j in 0..amounts.len() {
        entries.push(Entry {
            i: j as u32,
            txid: "mock_txid_".to_string() + &j.to_string(),
        });
    }
    let mut manifest = Manifest {
        invoice_hash: hex::encode(h_i),
        merkle_root: "".to_string(),
        count: amounts.len(),
        entries,
    };
    let leaves = compute_leaves(&manifest, &amounts, &addr_payloads)?;
    let root = merkle_root(leaves.clone());
    manifest.merkle_root = hex::encode(root);
    let proof = generate_proof(&leaves, 0, &manifest, &amounts, &addr_payloads)?;
    verify_proof(&proof, &manifest)?;
    println!("Proof verified");

    Ok(())
}
