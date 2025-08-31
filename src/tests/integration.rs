#[cfg(test)]
use pcw_protocol::*;
use sv::network::Network;

#[test]
fn test_full_protocol_flow() -> Result<(), PcwError> {
    // Mock keys
    let priv_a = [1; 32];
    let identity_a = IdentityKeypair::new(priv_a)?;
    let priv_b = [2; 32];
    let identity_b = IdentityKeypair::new(priv_b)?;
    let anchor_a = AnchorKeypair::new([3; 32])?;
    let anchor_b = AnchorKeypair::new([4; 32])?;

    // Policy
    let expiry = Utc::now() + chrono::Duration::days(1);
    let mut policy = Policy::new(hex::encode(anchor_b.pub_key.serialize()), 100, 1000, 500, 1, expiry)?;
    policy.sign(&identity_b)?;
    policy.verify()?;
    let h_policy = policy.h_policy();

    // Invoice
    let mut invoice = Invoice::new("inv1".to_string(), "terms".to_string(), "sat".to_string(), 2000, hex::encode(h_policy), Some(expiry))?;
    invoice.sign(&identity_a)?;
    invoice.verify(&h_policy)?;
    let h_i = invoice.h_i();

    // Scope
    let z = ecdh_z(&priv_a, &identity_b.pub_key)?;
    let scope = Scope::new(z, h_i);

    // Split
    let split = bounded_split(&scope, 2000, 100, 1000)?;
    assert_eq!(split.iter().sum::<u64>(), 2000);

    // Mock UTXOs
    let u0 = vec![ /* mock Utxo with values summing > 2000 + fees */ ];
    let r = build_reservations(&u0, &split, 1, 1, 3, 5, true)?;
    assert_eq!(r.len(), split.len());

    // Build tx for i=0
    let i = 0;
    let s_i = r.get(&i).unwrap();
    let priv_keys = vec![[5; 32]; s_i.len()];
    let (note_tx, meta) = build_note_tx(&scope, i, s_i, split[0], &anchor_b.pub_key, &anchor_a.pub_key, 1, 1, &priv_keys)?;
    // Verify tx structure, meta

    // Receipts
    let amounts = split;
    let addr_payloads = vec![[0; 21]; split.len()];
    let mut entries = vec![];
    for j in 0..split.len() {
        entries.push(Entry { i: j as u32, txid: "mock_txid".to_string() });
    }
    let mut manifest = Manifest {
        invoice_hash: hex::encode(h_i),
        merkle_root: "".to_string(),
        count: split.len(),
        entries,
    };
    let leaves = compute_leaves(&manifest, &amounts, &addr_payloads)?;
    let root = merkle_root(leaves.clone());
    manifest.merkle_root = hex::encode(root);
    let proof = generate_proof(&leaves, 0, &manifest, &amounts, &addr_payloads)?;
    verify_proof(&proof, &manifest)?;
    Ok(())
}

// Additional integration tests for failure paths (e.g., infeasible split, dust), logging append/sign
