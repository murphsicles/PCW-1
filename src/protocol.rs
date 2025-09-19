//! Module for protocol handling in the PCW-1 protocol.
//!
//! This module implements the async protocol functions for handshake (§3.5), policy exchange
//! (§3.5, §14.1), and invoice exchange (§3.5, §14.2) over TCP streams. It uses Tokio for
//! asynchronous I/O and serde_json for serialization/deserialization.
use crate::errors::PcwError;
use crate::invoice::Invoice;
use crate::json::canonical_json;
use crate::keys::IdentityKeypair;
use crate::policy::Policy;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Compute ECDH shared secret Z (§3.2).
pub fn ecdh_z(my_priv: &[u8; 32], their_pub: &PublicKey) -> Result<[u8; 32], PcwError> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_byte_array(*my_priv)?;
    // Convert SecretKey to Scalar for mul_tweak
    let scalar = Scalar::from(secret_key);
    let shared_point = their_pub.mul_tweak(&secp, &scalar)?;
    shared_point
        .serialize()
        .get(1..33)
        .ok_or_else(|| PcwError::Other("Invalid ECDH point".to_string()))?
        .try_into()
        .map_err(|_| PcwError::Other("Invalid ECDH point".to_string()))
}

/// Async handshake: Exchange pubs, compute Z (§3.5).
pub async fn handshake(
    stream: &mut TcpStream,
    my_identity: &IdentityKeypair,
) -> Result<[u8; 32], PcwError> {
    // Send my public key
    let my_pub = my_identity.pub_key.serialize();
    stream
        .write_all(&my_pub)
        .await
        .map_err(|e| PcwError::Io(format!("Failed to send public key: {}", e)))?;
    // Read their public key
    let mut their_pub_buf = [0u8; 33];
    stream
        .read_exact(&mut their_pub_buf)
        .await
        .map_err(|e| PcwError::Io(format!("Failed to read public key: {}", e)))?;
    let their_pub = PublicKey::from_slice(&their_pub_buf)?;
    // Compute shared secret Z
    ecdh_z(&my_identity.priv_key, &their_pub)
}

/// Exchange policy: Sender (Bob) sends, receiver (Alice) receives/verify (§3.5, §14.1).
pub async fn exchange_policy(
    stream: &mut TcpStream,
    policy: Option<Policy>,
) -> Result<Policy, PcwError> {
    if let Some(p) = policy {
        let value = serde_json::to_value(&p)?;
        let bytes = canonical_json(&value)?;
        let len = (bytes.len() as u32).to_le_bytes();
        stream
            .write_all(&len)
            .await
            .map_err(|e| PcwError::Io(format!("Failed to send policy length: {}", e)))?;
        stream
            .write_all(&bytes)
            .await
            .map_err(|e| PcwError::Io(format!("Failed to send policy: {}", e)))?;
        Ok(p)
    } else {
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| PcwError::Io(format!("Failed to read policy length: {}", e)))?;
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut bytes = vec![0u8; len];
        stream
            .read_exact(&mut bytes)
            .await
            .map_err(|e| PcwError::Io(format!("Failed to read policy data: {}", e)))?;
        let p: Policy = serde_json::from_slice(&bytes)?;
        p.verify()?;
        Ok(p)
    }
}

/// Exchange invoice: Sender (Alice) sends, receiver (Bob) receives/verify (§3.5, §14.2).
pub async fn exchange_invoice(
    stream: &mut TcpStream,
    invoice: Option<Invoice>,
    expected_policy_hash: &[u8; 32],
) -> Result<Invoice, PcwError> {
    if let Some(inv) = invoice {
        let value = serde_json::to_value(&inv)?;
        let bytes = canonical_json(&value)?;
        let len = (bytes.len() as u32).to_le_bytes();
        stream
            .write_all(&len)
            .await
            .map_err(|e| PcwError::Io(format!("Failed to send invoice length: {}", e)))?;
        stream
            .write_all(&bytes)
            .await
            .map_err(|e| PcwError::Io(format!("Failed to send invoice: {}", e)))?;
        Ok(inv)
    } else {
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| PcwError::Io(format!("Failed to read invoice length: {}", e)))?;
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut bytes = vec![0u8; len];
        stream
            .read_exact(&mut bytes)
            .await
            .map_err(|e| PcwError::Io(format!("Failed to read invoice data: {}", e)))?;
        let inv: Invoice = serde_json::from_slice(&bytes)?;
        inv.verify(expected_policy_hash)?;
        Ok(inv)
    }
}

#[cfg(test)]
#[allow(unused_imports)]
mod tests {
    use super::*;
    use crate::keys::IdentityKeypair;
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn test_handshake_symmetry() -> Result<(), PcwError> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| PcwError::Io(format!("Bind failed: {}", e)))?;
        let addr = listener
            .local_addr()
            .map_err(|e| PcwError::Io(format!("Get local addr failed: {}", e)))?;
        let t1 = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .map_err(|e| PcwError::Io(format!("Accept failed: {}", e)))?;
            let priv_k1 = [1; 32];
            let key1 = IdentityKeypair::new(priv_k1)?;
            handshake(&mut stream, &key1).await
        });
        let t2 = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr)
                .await
                .map_err(|e| PcwError::Io(format!("Connect failed: {}", e)))?;
            let priv_k2 = [2; 32];
            let key2 = IdentityKeypair::new(priv_k2)?;
            handshake(&mut stream, &key2).await
        });
        let z1 = t1
            .await
            .map_err(|e| PcwError::Other(format!("Task 1 failed: {}", e)))??;
        let z2 = t2
            .await
            .map_err(|e| PcwError::Other(format!("Task 2 failed: {}", e)))??;
        assert_eq!(z1, z2); // ECDH symmetry
        Ok(())
    }

    #[tokio::test]
    async fn test_exchange_policy() -> Result<(), PcwError> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| PcwError::Io(format!("Bind failed: {}", e)))?;
        let addr = listener
            .local_addr()
            .map_err(|e| PcwError::Io(format!("Get local addr failed: {}", e)))?;
        let t1 = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .map_err(|e| PcwError::Io(format!("Accept failed: {}", e)))?;
            let expiry = chrono::Utc::now() + chrono::Duration::days(1);
            let policy = Policy::new(
                "02".to_string() + &"0".repeat(64),
                100,
                1000,
                500,
                1,
                expiry,
            )?;
            exchange_policy(&mut stream, Some(policy)).await
        });
        let t2 = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr)
                .await
                .map_err(|e| PcwError::Io(format!("Connect failed: {}", e)))?;
            exchange_policy(&mut stream, None).await
        });
        let p1 = t1
            .await
            .map_err(|e| PcwError::Other(format!("Task 1 failed: {}", e)))??;
        let p2 = t2
            .await
            .map_err(|e| PcwError::Other(format!("Task 2 failed: {}", e)))??;
        assert_eq!(p1.h_policy(), p2.h_policy());
        Ok(())
    }

    #[tokio::test]
    async fn test_exchange_invoice() -> Result<(), PcwError> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| PcwError::Io(format!("Bind failed: {}", e)))?;
        let addr = listener
            .local_addr()
            .map_err(|e| PcwError::Io(format!("Get local addr failed: {}", e)))?;
        let t1 = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .map_err(|e| PcwError::Io(format!("Accept failed: {}", e)))?;
            let expiry = chrono::Utc::now() + chrono::Duration::days(1);
            let policy = Policy::new(
                "02".to_string() + &"0".repeat(64),
                100,
                1000,
                500,
                1,
                expiry,
            )?;
            let policy_hash = policy.h_policy();
            let invoice = Invoice::new(
                "test".to_string(),
                "terms".to_string(),
                "sat".to_string(),
                1000,
                hex::encode(policy_hash),
                None,
            )?;
            exchange_invoice(&mut stream, Some(invoice), &policy_hash).await
        });
        let t2 = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr)
                .await
                .map_err(|e| PcwError::Io(format!("Connect failed: {}", e)))?;
            let expiry = chrono::Utc::now() + chrono::Duration::days(1);
            let policy = Policy::new(
                "02".to_string() + &"0".repeat(64),
                100,
                1000,
                500,
                1,
                expiry,
            )?;
            let policy_hash = policy.h_policy();
            exchange_invoice(&mut stream, None, &policy_hash).await
        });
        let i1 = t1
            .await
            .map_err(|e| PcwError::Other(format!("Task 1 failed: {}", e)))??;
        let i2 = t2
            .await
            .map_err(|e| PcwError::Other(format!("Task 2 failed: {}", e)))??;
        assert_eq!(i1.h_i(), i2.h_i());
        Ok(())
    }
}
