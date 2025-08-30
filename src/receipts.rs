use crate::errors::PcwError;
use crate::utils::{le32, le8, sha256};
use merlin::Transcript; // Or simple binary tree impl with sha256(x || y)
use serde::{Deserialize, Serialize};

/// Manifest per §10.4: Invoice commitment.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Manifest {
    pub invoice_hash: String, // hex H_I
    pub merkle_root: String, // hex M
    pub count: usize,
    pub entries: Vec<Entry>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Entry {
    pub i: u32,
    pub txid: String, // hex 32-byte
}

/// Compute leaves per §10.2: "leaf" || LE32(i) || txid || amount_LE8 || addr_payload.
pub fn compute_leaves(manifest: &Manifest, amounts: &[u64], addr_payloads: &[[u8; 21]]) -> Result<Vec<[u8; 32]>, PcwError> {
    let mut leaves = vec![];
    for entry in &manifest.entries {
        let mut preimage = b"leaf".to_vec();
        preimage.extend_from_slice(&le32(entry.i));
        preimage.extend_from_slice(&hex::decode(&entry.txid)?);
        preimage.extend_from_slice(&le8(amounts[entry.i as usize]));
        preimage.extend_from_slice(addr_payloads[entry.i as usize]);
        leaves.push(sha256(&preimage));
    }
    Ok(leaves)
}

/// Merkle root with binary SHA256(x || y), dup odd (§10.3).
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0; 32];
    }
    let mut current = leaves.to_vec();
    while current.len() > 1 {
        let mut next = vec![];
        for chunk in current.chunks(2) {
            let left = chunk[0];
            let right = if chunk.len() == 2 { chunk[1] } else { left }; // Dup odd
            let mut concat = left.to_vec();
            concat.extend_from_slice(&right);
            next.push(sha256(&concat));
        }
        current = next;
    }
    current[0]
}

/// Proof for single leaf (§10.5).
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

/// Generate single proof for i.
pub fn generate_proof(leaves: &[[u8; 32]], i: usize, manifest: &Manifest, amounts: &[u64], addr_payloads: &[[u8; 21]]) -> Result<Proof, PcwError> {
    // Build tree, extract path for leaf i
    // ...
}

/// Verify proof recomputes root (§10.5).
pub fn verify_proof(proof: &Proof, manifest: &Manifest) -> Result<(), PcwError> {
    // Recompute preimage from leaf, L = sha256(preimage)
    // Fold path: if "L" sha256(L || s) else sha256(s || L)
    // Check equals proof.merkle_root
    // ...
}

#[cfg(test)]
mod tests {
    // Tests for leaves/root, proof gen/verify, odd dup
}
