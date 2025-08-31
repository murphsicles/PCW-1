use pcw_protocol::*;
use sv::network::Network;
use chrono::prelude::*;
use hex;

fn main() -> Result<(), PcwError> {
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
    println!("Split: {:?}", split);

    // Mock UTXOs and build reservation
    // ... (omit for brevity)

    // Build tx, receipts, etc.

    Ok(())
}
