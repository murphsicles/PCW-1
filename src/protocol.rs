//! Module for protocol handling in the PCW-1 protocol.
//!
//! This module implements the async protocol functions for handshake (§3.5), policy exchange
//! (§3.5, §14.1), and invoice exchange (§3.5, §14.2) over TCP streams. It uses Tokio for
//! asynchronous I/O and serde_json for serialization/deserialization.

use crate::errors::PcwError;
use crate::invoice::Invoice;
use crate::keys::IdentityKeypair;
use crate::policy::Policy;
use crate::scope::Scope;
use crate::utils::ecdh_z;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use serde_json;
use secp256k1::PublicKey;

/// Async handshake: Exchange pubs, compute Z (§3.5).
pub async fn handshake(stream: &mut TcpStream, my_identity: &IdentityKeypair) -> Result<[u8; 32], PcwError> {
    // Send my public key
    let my_pub = my_identity.pub_key.serialize();
    stream.write_all(&my_pub).await?;
    if stream.write_all(&my_pub).await.is_err() {
        return Err(PcwError::Io("Failed to send public key".to_string()));
    }

    // Read their public key
    let mut their_pub_buf = [0u8; 33];
    stream.read_exact(&mut their_pub_buf).await?;
    if stream.read_exact(&mut their_pub_buf).await.is_err() {
        return Err(PcwError::Io("Failed to read public key".to_string()));
    }
    let their_pub = PublicKey::from_slice(&their_pub_buf)?;

    // Compute shared secret Z
    ecdh_z(&my_identity.priv_key, &their_pub)
}

/// Exchange policy: Sender (Bob) sends, receiver (Alice) receives/verify (§3.5, §14.1).
pub async fn exchange_policy(stream: &mut TcpStream, policy: Option<Policy>) -> Result<Policy, PcwError> {
    if let Some(p) = policy {
        let bytes = serde_json::to_vec(&p)?;
        let len = (bytes.len() as u32).to_le_bytes();
        stream.write_all(&len).await?;
        if stream.write_all(&bytes).await.is_err() {
            return Err(PcwError::Io("Failed to send policy".to_string()));
        }
        Ok(p)
    } else {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        if stream.read_exact(&mut len_buf).await.is_err() {
            return Err(PcwError::Io("Failed to read policy length".to_string()));
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut bytes = vec![0u8; len];
        stream.read_exact(&mut bytes).await?;
        if stream.read_exact(&mut bytes).await.is_err() {
            return Err(PcwError::Io("Failed to read policy data".to_string()));
        }
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
        let bytes = serde_json::to_vec(&inv)?;
        let len = (bytes.len() as u32).to_le_bytes();
        stream.write_all(&len).await?;
        if stream.write_all(&bytes).await.is_err() {
            return Err(PcwError::Io("Failed to send invoice".to_string()));
        }
        Ok(inv)
    } else {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        if stream.read_exact(&mut len_buf).await.is_err() {
            return Err(PcwError::Io("Failed to read invoice length".to_string()));
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut bytes = vec![0u8; len];
        stream.read_exact(&mut bytes).await?;
        if stream.read_exact(&mut bytes).await.is_err() {
            return Err(PcwError::Io("Failed to read invoice data".to_string()));
        }
        let inv: Invoice = serde_json::from_slice(&bytes)?;
        inv.verify(expected_policy_hash)?;
        Ok(inv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::IdentityKeypair;
    use secp256k1::Secp256k1;
    use tokio::net::TcpListener;
    use std::io::Read;
    use std::net::TcpStream as StdTcpStream;

    #[tokio::test]
    async fn test_handshake_symmetry() -> Result<(), PcwError> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let t1 = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let priv_k1 = [1; 32];
            let key1 = IdentityKeypair::new(priv_k1)?;
            handshake(&mut stream, &key1).await
        });

        let t2 = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await?;
            let priv_k2 = [2; 32];
            let key2 = IdentityKeypair::new(priv_k2)?;
            handshake(&mut stream, &key2).await
        });

        let z1 = t1.await??;
        let z2 = t2.await??;
        assert_eq!(z1, z2); // ECDH symmetry
        Ok(())
    }

    #[tokio::test]
    async fn test_exchange_policy() -> Result<(), PcwError> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let t1 = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let expiry = Utc::now() + chrono::Duration::days(1);
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
            let mut stream = TcpStream::connect(addr).await?;
            exchange_policy(&mut stream, None).await
        });

        let p1 = t1.await??;
        let p2 = t2.await??;
        assert_eq!(p1.h_policy(), p2.h_policy());
        Ok(())
    }

    #[tokio::test]
    async fn test_exchange_invoice() -> Result<(), PcwError> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let t1 = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let expiry = Utc::now() + chrono::Duration::days(1);
            let policy = Policy::new(
                "02".to_string() + &"0".repeat(64),
                100,
                1000,
                500,
                1,
                expiry,
            )?;
            let policy_hash = policy.h_policy();
            let invoice = Invoice::new("test", 1000, &policy_hash)?;
            exchange_invoice(&mut stream, Some(invoice), &policy_hash).await
        });

        let t2 = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await?;
            let expiry = Utc::now() + chrono::Duration::days(1);
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

        let i1 = t1.await??;
        let i2 = t2.await??;
        assert_eq!(i1.h_invoice(), i2.h_invoice());
        Ok(())
    }
}
