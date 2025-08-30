use crate::errors::PcwError;
use crate::invoice::Invoice;
use crate::keys::IdentityKeypair;
use crate::policy::Policy;
use crate::scope::Scope;
use crate::utils::ecdh_z;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use serde_json;

/// Async handshake: Exchange pubs, compute Z (§3.5).
pub async fn handshake(stream: &mut TcpStream, my_identity: &IdentityKeypair) -> Result<[u8; 32], PcwError> {
    // Send my pub
    let my_pub = my_identity.pub_key.serialize();
    stream.write_all(&my_pub).await?;
    // Read their pub
    let mut their_pub_buf = [0u8; 33];
    stream.read_exact(&mut their_pub_buf).await?;
    let their_pub = PublicKey::from_slice(&their_pub_buf)?;
    // Compute Z
    ecdh_z(&my_identity.priv_key, &their_pub)
}

/// Exchange policy: Sender (Bob) sends, receiver (Alice) receives/verify (§3.5, §14.1).
pub async fn exchange_policy(stream: &mut TcpStream, policy: Option<Policy>) -> Result<Policy, PcwError> {
    if let Some(p) = policy {
        let bytes = serde_json::to_vec(&p)?;
        stream.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
        stream.write_all(&bytes).await?;
        Ok(p)
    } else {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut bytes = vec![0u8; len];
        stream.read_exact(&mut bytes).await?;
        let p: Policy = serde_json::from_slice(&bytes)?;
        p.verify()?;
        Ok(p)
    }
}

/// Exchange invoice: Sender (Alice) sends, receiver (Bob) receives/verify (§3.5, §14.2).
pub async fn exchange_invoice(stream: &mut TcpStream, invoice: Option<Invoice>, expected_policy_hash: &[u8; 32]) -> Result<Invoice, PcwError> {
    if let Some(inv) = invoice {
        let bytes = serde_json::to_vec(&inv)?;
        stream.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
        stream.write_all(&bytes).await?;
        Ok(inv)
    } else {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_le_bytes(len_buf) as usize;
        let mut bytes = vec![0u8; len];
        stream.read_exact(&mut bytes).await?;
        let inv: Invoice = serde_json::from_slice(&bytes)?;
        inv.verify(expected_policy_hash)?;
        Ok(inv)
    }
}

#[cfg(test)]
mod tests {
    // Async tests for handshake (Z symmetry), policy/invoice exchange/verify
}
