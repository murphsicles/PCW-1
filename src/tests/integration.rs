#[cfg(test)]
use pcw_protocol::*;
use sv::network::Network;

#[test]
fn test_full_protocol_flow() -> Result<(), PcwError> {
    // Mock keys, policy, invoice
    let priv_a = [1; 32];
    let identity_a = IdentityKeypair::new(priv_a)?;
    let priv_b = [2; 32];
    let identity_b = IdentityKeypair::new(priv_b)?;
    let anchor_a = AnchorKeypair::new([3; 32])?;
    let anchor_b = AnchorKeypair::new([4; 32])?;
    let z = ecdh_z(&priv_a, &identity_b.pub_key)?;
    let expiry = Utc::now() + chrono::Duration::days(1);
    let mut policy = Policy::new(hex::encode(anchor_b.pub_key.serialize()), 100, 1000, 500, 1, expiry)?;
    policy.sign(&identity_b)?;
    policy.verify()?;
    let h_policy = policy.h_policy();
    let mut invoice = Invoice::new("inv1".to_string(), "terms".to_string(), "sat".to_string(), 2000, hex::encode(h_policy), Some(expiry))?;
    invoice.sign(&identity_a)?;
    invoice.verify(&h_policy)?;
    let h_i = invoice.h_i();
    let scope = Scope::new(z, h_i);
    let split = bounded_split(&scope, 2000, 100, 1000)?;
    assert_eq!(split.iter().sum::<u64>(), 2000);
    // Mock UTXOs, build reservation
    let u0 = vec![ /* mock Utxo */ ];
    let r = build_reservations(&u0, &split, 1, 1, 3, 5, true)?;
    // For one i, build tx
    let i = 0;
    let s_i = r.get(&i).unwrap();
    let priv_keys = vec![[5; 32]; s_i.len()];
    let (note_tx, meta) = build_note_tx(&scope, i, s_i, split[0], &anchor_b.pub_key, &anchor_a.pub_key, 1, 1, &priv_keys)?;
    // Receipts
    // Mock for all i
    let amounts = split;
    let addr_payloads = vec![[0; 21]; split.len()];
    let leaves = compute_leaves(&manifest, &amounts, &addr_payloads)?; // Assume manifest
    let root = merkle_root(leaves.clone());
    let proof = generate_proof(&leaves, 0, &manifest, &amounts, &addr_payloads)?;
    verify_proof(&proof, &manifest)?;
    Ok(())
}

// Additional integration tests for failure paths, logging append/sign
