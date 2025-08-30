use crate::errors::PcwError;
use crate::utils::{le32, le8, sha256};
use hex;
use serde::{Deserialize, Serialize};

/// Manifest per §10.4.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Manifest {
    pub invoice_hash: String,
    pub merkle_root: String,
    pub count: usize,
    pub entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Entry {
    pub i: u32,
    pub txid: String,
}

/// Compute leaves per §10.2.
pub fn compute_leaves(manifest: &Manifest, amounts: &[u64], addr_payloads: &[[u8; 21]]) -> Result<Vec<[u8; 32]>, PcwError> {
    if manifest.count != amounts.len() || manifest.count != addr_payloads.len() || manifest.count != manifest.entries.len() {
        return Err(PcwError::Other("Mismatched lengths §10.2".to_string()));
    }
    let mut leaves = vec![[0; 32]; manifest.count];
    for (idx, entry) in manifest.entries.iter().enumerate() {
        let mut preimage = b"leaf".to_vec();
        preimage.extend_from_slice(&le32(entry.i));
        let txid_bytes = hex::decode(&entry.txid).map_err(|_| PcwError::Other("Invalid txid hex §10.2".to_string()))?;
        if txid_bytes.len() != 32 {
            return Err(PcwError::Other("Txid not 32 bytes §10.2".to_string()));
        }
        preimage.extend_from_slice(&txid_bytes);
        preimage.extend_from_slice(&le8(amounts[idx]));
        preimage.extend_from_slice(&addr_payloads[idx]);
        leaves[idx] = sha256(&preimage);
    }
    Ok(leaves)
}

/// Merkle root per §10.3: Binary SHA256(left || right), dup odd leaf.
pub fn merkle_root(mut leaves: Vec<[u8; 32]>) -> [u8; 32] {
    if leaves.is_empty() {
        return [0; 32];
    }
    while leaves.len() > 1 {
        let mut next = vec![];
        for i in (0..leaves.len()).step_by(2) {
            let left = leaves[i];
            let right = if i + 1 < leaves.len() { leaves[i + 1] } else { left }; // Dup odd
            let mut concat = left.to_vec();
            concat.extend_from_slice(&right);
            next.push(sha256(&concat));
        }
        leaves = next;
    }
    leaves[0]
}

/// Proof for single leaf §10.5.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Proof {
    pub invoice_hash: String,
    pub merkle_root: String,
    pub leaf: Leaf,
    pub path: Vec<PathElement>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Leaf {
    pub i: u32,
    pub txid: String,
    pub amount: u64,
    pub addr_payload: String, // hex 21-byte
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PathElement {
    pub pos: String, // "L" or "R"
    pub hash: String, // hex 32-byte
}

/// Generate single proof for i (§10.5).
pub fn generate_proof(leaves: &[[u8; 32]], i: usize, manifest: &Manifest, amounts: &[u64], addr_payloads: &[[u8; 21]]) -> Result<Proof, PcwError> {
    if i >= leaves.len() {
        return Err(PcwError::Other("Index out of bounds §10.5".to_string()));
    }
    let mut path = vec![];
    let mut current = leaves.to_vec();
    let mut index = i;
    while current.len() > 1 {
        let is_left = index % 2 == 0;
        let sibling_idx = if is_left { index + 1 } else { index - 1 };
        let sibling = if sibling_idx >= current.len() { current[index] } else { current[sibling_idx] }; // Dup odd
        path.push(PathElement { pos: if is_left { "L".to_string() } else { "R".to_string() }, hash: hex::encode(sibling) });
        let mut next = vec![];
        for j in (0..current.len()).step_by(2) {
            let left = current[j];
            let right = if j + 1 < current.len() { current[j + 1] } else { left };
            let mut concat = left.to_vec();
            concat.extend_from_slice(&right);
            next.push(sha256(&concat));
        }
        index /= 2;
        current = next;
    }
    let root = hex::encode(current[0]);
    let leaf = Leaf {
        i: manifest.entries[i].i,
        txid: manifest.entries[i].txid.clone(),
        amount: amounts[i],
        addr_payload: hex::encode(addr_payloads[i]),
    };
    Ok(Proof {
        invoice_hash: manifest.invoice_hash.clone(),
        merkle_root: root,
        leaf,
        path,
    })
}

/// Verify proof (§10.5).
pub fn verify_proof(proof: &Proof, manifest: &Manifest) -> Result<(), PcwError> {
    let entry = manifest.entries.iter().find(|e| e.i == proof.leaf.i).ok_or(PcwError::Other("Invalid i §10.5".to_string()))?;
    if entry.txid != proof.leaf.txid {
        return Err(PcwError::Other("Txid mismatch §10.5".to_string()));
    }
    let mut preimage = b"leaf".to_vec();
    preimage.extend_from_slice(&le32(proof.leaf.i));
    let txid_bytes = hex::decode(&proof.leaf.txid)?;
    preimage.extend_from_slice(&txid_bytes);
    preimage.extend_from_slice(&le8(proof.leaf.amount));
    let addr_bytes = hex::decode(&proof.leaf.addr_payload)?;
    if addr_bytes.len() != 21 {
        return Err(PcwError::Other("Addr payload not 21 bytes §10.2".to_string()));
    }
    preimage.extend_from_slice(&addr_bytes);
    let mut l = sha256(&preimage);
    for elem in &proof.path {
        let s = hex::decode(&elem.hash)?;
        let mut concat = if elem.pos == "L" { [l, s.try_into()?].concat() } else { [s.try_into()?, l].concat() };
        l = sha256(&concat);
    }
    if hex::encode(l) != proof.merkle_root {
        return Err(PcwError::InvalidProof);
    }
    if proof.invoice_hash != manifest.invoice_hash {
        return Err(PcwError::Other("Invoice hash mismatch §10.5".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // Test leaves, root with odd dup, proof gen/verify, reject invalid
}
