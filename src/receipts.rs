//! Module for receipt management in the PCW-1 protocol.
//!
//! This module implements the receipt system as per §10.2-§10.5, including manifest
//! handling, leaf computation, Merkle root generation, proof generation, and verification.
//! Receipts provide auditable, private proof of payment via Merkle trees.
use crate::errors::PcwError;
use crate::utils::{le8, le32, sha256};
use serde::{Deserialize, Serialize};

/// Manifest per §10.4.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Manifest {
    pub invoice_hash: String,
    pub merkle_root: String,
    pub count: usize,
    pub entries: Vec<Entry>,
}

/// Entry within a manifest (§10.4).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Entry {
    pub i: u32,
    pub txid: String,
}

/// Compute leaves per §10.2.
pub fn compute_leaves(
    manifest: &Manifest,
    amounts: &[u64],
    addr_payloads: &[[u8; 21]],
) -> Result<Vec<[u8; 32]>, PcwError> {
    if manifest.count != amounts.len()
        || manifest.count != addr_payloads.len()
        || manifest.count != manifest.entries.len()
    {
        return Err(PcwError::Other("Mismatched lengths §10.2".to_string()));
    }
    let mut leaves = vec![[0; 32]; manifest.count];
    for (idx, entry) in manifest.entries.iter().enumerate() {
        let mut preimage = b"leaf".to_vec();
        preimage.extend_from_slice(&le32(entry.i));
        let txid_bytes = hex::decode(&entry.txid)?;
        if txid_bytes.len() != 32 {
            return Err(PcwError::Other("Txid not 32 bytes".to_string()));
        }
        preimage.extend_from_slice(&txid_bytes);
        preimage.extend_from_slice(&le8(amounts[idx]));
        preimage.extend_from_slice(&addr_payloads[idx]);
        leaves[idx] = sha256(&preimage);
    }
    Ok(leaves)
}

/// Merkle root per §10.3: Binary SHA256(left || right), duplicate odd leaf.
pub fn merkle_root(leaves: &[[u8; 32]]) -> Result<[u8; 32], PcwError> {
    if leaves.is_empty() {
        return Err(PcwError::Other("Empty leaves §10.3".to_string()));
    }
    let mut current = leaves.to_vec();
    while current.len() > 1 {
        let mut next = vec![];
        for i in (0..current.len()).step_by(2) {
            let left = current[i];
            let right = if i + 1 < current.len() {
                current[i + 1]
            } else {
                left
            }; // Duplicate odd
            let mut concat = left.to_vec();
            concat.extend_from_slice(&right);
            next.push(sha256(&concat));
        }
        current = next;
    }
    Ok(current[0])
}

/// Proof for single leaf (§10.5).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Proof {
    pub invoice_hash: String,
    pub merkle_root: String,
    pub leaf: Leaf,
    pub path: Vec<PathElement>,
}

/// Leaf data for a proof (§10.5).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Leaf {
    pub i: u32,
    pub txid: String,
    pub amount: u64,
    pub addr_payload: String, // hex 21-byte
}

/// Path element in a Merkle proof (§10.5).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PathElement {
    pub pos: String,  // "L" or "R"
    pub hash: String, // hex 32-byte
}

/// Generate single proof for i (§10.5).
pub fn generate_proof(
    leaves: &[[u8; 32]],
    i: usize,
    manifest: &Manifest,
    amounts: &[u64],
    addr_payloads: &[[u8; 21]],
) -> Result<Proof, PcwError> {
    if i >= leaves.len() {
        return Err(PcwError::Other("Index out of bounds §10.5".to_string()));
    }
    let mut path = vec![];
    let mut current = leaves.to_vec();
    let mut index = i;
    while current.len() > 1 {
        let is_left = index % 2 == 0;
        let sibling_idx = if is_left { index + 1 } else { index - 1 };
        let sibling = if sibling_idx >= current.len() {
            current[index]
        } else {
            current[sibling_idx]
        };
        path.push(PathElement {
            pos: if is_left {
                "L".to_string()
            } else {
                "R".to_string()
            },
            hash: hex::encode(sibling),
        });
        let mut next = vec![];
        for j in (0..current.len()).step_by(2) {
            let left = current[j];
            let right = if j + 1 < current.len() {
                current[j + 1]
            } else {
                left
            };
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
    let entry = manifest
        .entries
        .iter()
        .find(|e| e.i == proof.leaf.i)
        .ok_or(PcwError::Other("Invalid i §10.5".to_string()))?;
    if entry.txid != proof.leaf.txid {
        return Err(PcwError::Other("Txid mismatch §10.5".to_string()));
    }
    let mut preimage = b"leaf".to_vec();
    preimage.extend_from_slice(&le32(proof.leaf.i));
    let txid_bytes = hex::decode(&proof.leaf.txid)?;
    if txid_bytes.len() != 32 {
        return Err(PcwError::Other("Txid not 32 bytes".to_string()));
    }
    preimage.extend_from_slice(&txid_bytes);
    preimage.extend_from_slice(&le8(proof.leaf.amount));
    let addr_bytes = hex::decode(&proof.leaf.addr_payload)?;
    if addr_bytes.len() != 21 {
        return Err(PcwError::Other(
            "Addr payload not 21 bytes §10.2".to_string(),
        ));
    }
    preimage.extend_from_slice(&addr_bytes);
    let mut l = sha256(&preimage);
    for elem in &proof.path {
        let s = hex::decode(&elem.hash)?;
        let s_arr: [u8; 32] = s
            .try_into()
            .map_err(|_| PcwError::Other("Sibling not 32 bytes".to_string()))?;
        let concat = if elem.pos == "L" {
            [l, s_arr].concat()
        } else {
            [s_arr, l].concat()
        };
        l = sha256(&concat);
    }
    if hex::encode(l) != proof.merkle_root {
        return Err(PcwError::InvalidProof {
            msg: "Merkle root mismatch".to_string(),
        });
    }
    if proof.invoice_hash != manifest.invoice_hash {
        return Err(PcwError::Other("Invoice hash mismatch".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_leaves() -> Result<(), PcwError> {
        let manifest = Manifest {
            invoice_hash: "test_hash".to_string(),
            merkle_root: "".to_string(),
            count: 2,
            entries: vec![
                Entry {
                    i: 0,
                    txid: "0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                },
                Entry {
                    i: 1,
                    txid: "1111111111111111111111111111111111111111111111111111111111111111"
                        .to_string(),
                },
            ],
        };
        let amounts = [100, 200];
        let addr_payloads = [[0; 21], [1; 21]];
        let leaves = compute_leaves(&manifest, &amounts, &addr_payloads)?;
        assert_eq!(leaves.len(), 2);
        assert_ne!(leaves[0], leaves[1]);
        Ok(())
    }

    #[test]
    fn test_merkle_root_empty() {
        let leaves: Vec<[u8; 32]> = vec![];
        let result = merkle_root(&leaves);
        assert!(result.is_err());
        assert!(matches!(result, Err(PcwError::Other(msg)) if msg.contains("Empty leaves")));
    }

    #[test]
    fn test_merkle_root_even() {
        let leaves = vec![[0; 32], [1; 32]];
        let root = merkle_root(&leaves).unwrap();
        assert_ne!(root, [0; 32]);
    }

    #[test]
    fn test_merkle_root_odd() {
        let manifest = Manifest {
            invoice_hash: "test_hash".to_string(),
            merkle_root: "".to_string(),
            count: 1,
            entries: vec![Entry {
                i: 0,
                txid: "0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            }],
        };
        let amounts = [100];
        let addr_payloads = [[0; 21]];
        let leaves = compute_leaves(&manifest, &amounts, &addr_payloads).unwrap();
        let root = merkle_root(&leaves).unwrap();
        assert_eq!(root, leaves[0]); // Root should be the leaf for N=1
    }

    #[test]
    fn test_generate_verify_proof() -> Result<(), PcwError> {
        let manifest = Manifest {
            invoice_hash: "test_hash".to_string(),
            merkle_root: "".to_string(),
            count: 1,
            entries: vec![Entry {
                i: 0,
                txid: "0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            }],
        };
        let amounts = [100];
        let addr_payloads = [[0; 21]];
        let leaves = compute_leaves(&manifest, &amounts, &addr_payloads)?;
        let proof = generate_proof(&leaves, 0, &manifest, &amounts, &addr_payloads)?;
        verify_proof(&proof, &manifest)?;
        Ok(())
    }

    #[test]
    fn test_verify_invalid_txid() {
        let proof = Proof {
            invoice_hash: "test_hash".to_string(),
            merkle_root: "root".to_string(),
            leaf: Leaf {
                i: 0,
                txid: "wrong_txid".to_string(),
                amount: 100,
                addr_payload: hex::encode([0; 21]),
            },
            path: vec![],
        };
        let manifest = Manifest {
            invoice_hash: "test_hash".to_string(),
            merkle_root: "root".to_string(),
            count: 1,
            entries: vec![Entry {
                i: 0,
                txid: "correct_txid".to_string(),
            }],
        };
        assert!(verify_proof(&proof, &manifest).is_err());
    }

    #[test]
    fn test_verify_mismatched_lengths() -> Result<(), PcwError> {
        let manifest = Manifest {
            invoice_hash: "test_hash".to_string(),
            merkle_root: "".to_string(),
            count: 2,
            entries: vec![
                Entry {
                    i: 0,
                    txid: "0000000000000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                },
                Entry {
                    i: 1,
                    txid: "1111111111111111111111111111111111111111111111111111111111111111"
                        .to_string(),
                },
            ],
        };
        let amounts = [100]; // Mismatched length
        let addr_payloads = [[0; 21], [1; 21]];
        assert!(compute_leaves(&manifest, &amounts, &addr_payloads).is_err());
        Ok(())
    }

    #[test]
    fn test_verify_invalid_hex() {
        let proof = Proof {
            invoice_hash: "test_hash".to_string(),
            merkle_root: "root".to_string(),
            leaf: Leaf {
                i: 0,
                txid: "invalid".to_string(), // Invalid hex
                amount: 100,
                addr_payload: hex::encode([0; 21]),
            },
            path: vec![],
        };
        let manifest = Manifest {
            invoice_hash: "test_hash".to_string(),
            merkle_root: "root".to_string(),
            count: 1,
            entries: vec![Entry {
                i: 0,
                txid: "correct_txid".to_string(),
            }],
        };
        assert!(verify_proof(&proof, &manifest).is_err());
    }

    #[test]
    fn test_verify_wrong_root() {
        let proof = Proof {
            invoice_hash: "test_hash".to_string(),
            merkle_root: "wrong_root".to_string(),
            leaf: Leaf {
                i: 0,
                txid: "0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
                amount: 100,
                addr_payload: hex::encode([0; 21]),
            },
            path: vec![],
        };
        let manifest = Manifest {
            invoice_hash: "test_hash".to_string(),
            merkle_root: "correct_root".to_string(),
            count: 1,
            entries: vec![Entry {
                i: 0,
                txid: "0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            }],
        };
        assert!(verify_proof(&proof, &manifest).is_err());
    }
}
