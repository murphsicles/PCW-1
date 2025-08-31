# Peer Cash Wallet Protocol (PCW-1) 🚀

![Rust](https://img.shields.io/badge/rust-edition%202024-orange) ![Dependencies](https://img.shields.io/badge/deps-up%20to%20date-green) ![License](https://img.shields.io/badge/license-MIT-blue) ![CI](https://github.com/murphsicles/PCW-1/workflows/Rust%20CI/badge.svg)

A Rust library implementing the Peer Cash Wallet Protocol for IP-to-IP BSV settlement, verbatim from the spec. This crate provides structs, functions, and traits for deterministic derivations, bounded splitting, disjoint coin selection, transaction formation, broadcast strategies, receipts, and failure handling.

## Features ✨

- Deterministic per-invoice scope and derivations (§3-§4, §7)
- Bounded note splitting with permutation (§5)
- Disjoint UTXO reservation and fan-out (§6)
- P2PKH transaction building and signing using rust-sv (§8)
- Broadcast pacing and either-side authority (§9)
- Merkle receipts with selective proofs (§10)
- State machines for failure handling (§11)
- Canonical JSON serialization (§2, §14)
- Signed append-only logging (§13)

## Installation 📦

Add to Cargo.toml:

```toml
[dependencies]
pcw_protocol = "0.1.0"
```

## Usage Example 💻

```rust
use pcw_protocol::*;
use sv::network::Network; // From rust-sv

// Assume keys, policy, invoice loaded
let scope = Scope::new(z, h_i);
let split = split::bounded_split(&scope, total, v_min, v_max).unwrap();
// Derive address
let addr_b = addressing::recipient_address(&scope, 0, &anchor_b).unwrap();
// etc.
```

## Spec Mapping 📚

- Keys & Scope: §3, §13
- Policy & Invoice: §3.3-§3.4, §14.1-§14.2
- Split: §5
- Selection: §6
- Addressing: §4, §7
- Tx: §7-§8
- Protocol: §1, §3.5, §9, §14
- Broadcast: §9
- Receipts: §10
- Failure: §11
- Logging: §13
- Utils: §2

## State Machine Diagram 📊

![Failure Handling & Exact Behaviors](failure-handling-diagram.png)

## Testing 🧪

Comprehensive tests cover properties (§17.3), negatives (§17.4), and golden vectors (§17.6). Run `cargo test`.

## License 📄

MIT - See [LICENSE](./LICENSE) for details.
