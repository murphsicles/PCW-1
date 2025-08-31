# PCW-1 Documentation

This documentation provides a comprehensive guide to using the `pcw_protocol` crate. It covers all public structs, enums, traits, functions, and their usage, with examples. The crate implements the Peer Cash Wallet Protocol verbatim from the spec, enabling deterministic IP-to-IP BSV settlement.

## Getting Started

Add to your `Cargo.toml`:

```toml
[dependencies]
pcw_protocol = "0.1.0"
```

Import in your code:

```rust
use pcw_protocol::*;
```

## Modules and Key Components

The crate is organized into modules corresponding to spec sections. Below is an overview of major types and functions.

### errors.rs

- **PcwError**: Enum for all protocol errors (e.g., `InfeasibleSplit`, `DustChange`).
  - Usage: Handle with `Result<_, PcwError>` in functions.

### json.rs

- **canonical_json<T: Serialize>(t: &T) -> Result<Vec<u8>, PcwError>**: Serializes to canonical JSON per §2 (sorted keys, NFC, compact).
  - Example:
    ```rust
    use serde_json::json;
    let obj = json!({"b": 2, "a": 1});
    let bytes = canonical_json(&obj).unwrap();
    assert_eq!(String::from_utf8(bytes).unwrap(), r#"{"a":1,"b":2}"#);
    ```

### keys.rs

- **IdentityKeypair**: Struct for off-chain identity keys (§3.1).
  - **new(priv_key: [u8; 32]) -> Result<Self, PcwError>**: Create from private key.
- **AnchorKeypair**: Struct for on-chain anchors.
  - **new(priv_key: [u8; 32]) -> Result<Self, PcwError>**.
- **ecdh_z(my_priv: &[u8; 32], their_pub: &PublicKey) -> Result<[u8; 32], PcwError>**: Compute shared Z (§3.2).
  - Example:
    ```rust
    let priv1 = [1u8; 32];
    let key1 = IdentityKeypair::new(priv1)?;
    let priv2 = [2u8; 32];
    let key2 = IdentityKeypair::new(priv2)?;
    let z1 = ecdh_z(&priv1, &key2.pub_key)?;
    let z2 = ecdh_z(&priv2, &key1.pub_key)?;
    assert_eq!(z1, z2);
    ```

### scope.rs

- **Scope**: Struct for {Z, H_I} (§3.2).
  - **new(z: [u8; 32], h_i: [u8; 32]) -> Self**.
- **derive_scalar(scope: &Scope, domain: &str, i: u32) -> Result<[u8; 32], PcwError>**: Derive tweak scalar with bump (§4.2).
  - Example:
    ```rust
    let scope = Scope::new([0;32], [0;32]);
    let t_i = derive_scalar(&scope, "recv", 0)?;
    assert_ne!(t_i, [0;32]);
    ```

### policy.rs

- **Policy**: Struct for payee policy (§3.3).
  - **new(pk_anchor: String, vmin: u64, vmax: u64, per_address_cap: u64, feerate_floor: u64, expiry: Utc) -> Result<Self, PcwError>**.
  - **sign(&mut self, key: &IdentityKeypair) -> Result<(), PcwError>**.
  - **verify(&self) -> Result<(), PcwError>**.
  - **h_policy(&self) -> [u8; 32]**.
  - Example:
    ```rust
    let expiry = Utc::now() + chrono::Duration::days(1);
    let mut policy = Policy::new("02...".to_string(), 100, 1000, 500, 1, expiry)?;
    policy.sign(&identity_b)?;
    policy.verify()?;
    ```

### invoice.rs

- **Invoice**: Struct for payer invoice (§3.4).
  - **new(invoice_number: String, terms: String, unit: String, total: u64, policy_hash: String, expiry: Option<Utc>) -> Result<Self, PcwError>**.
  - **sign(&mut self, key: &IdentityKeypair) -> Result<(), PcwError>**.
  - **verify(&self, expected_policy_hash: &[u8; 32]) -> Result<(), PcwError>**.
  - **h_i(&self) -> [u8; 32]**.

### split.rs

- **bounded_split(scope: &Scope, t: u64, v_min: u64, v_max: u64) -> Result<Vec<u64>, PcwError>**: Deterministic split (§5).
  - Example:
    ```rust
    let scope = Scope::new([0;32], [0;32]);
    let split = bounded_split(&scope, 2000, 100, 1000)?;
    assert_eq!(split.iter().sum::<u64>(), 2000);
    ```

### selection.rs

- **Utxo**: Struct for UTXO (§6.1).
- **Reservation**: HashMap<usize, Vec<Utxo>> (§6.1).
- **build_reservations(u0: &[Utxo], split: &[u64], feerate_floor: u64, dust: u64, k_max: usize, m_max: usize, fanout_allowed: bool) -> Result<Reservation, PcwError>**: Build reservations (§6).
  - Note: fan_out is stubbed for prod customization—see doc comments.

### addressing.rs

- **recipient_address(scope: &Scope, i: u32, anchor_b: &PublicKey) -> Result<String, PcwError>**: Recipient addr (§4).
- **sender_change_address(scope: &Scope, i: u32, anchor_a: &PublicKey) -> Result<String, PcwError>**: Change addr (§7).

### tx.rs

- **NoteMeta**: Struct for note metadata (§8.3).
- **NoteTx**: Wrapper for Tx (§8).
- **build_note_tx(scope: &Scope, i: u32, s_i: &[Utxo], amount: u64, anchor_b: &PublicKey, anchor_a: &PublicKey, feerate_floor: u64, dust: u64, priv_keys: &[[u8;32]]) -> Result<(NoteTx, NoteMeta), PcwError>**: Build/sign note (§7-§8).

### protocol.rs

- **handshake(stream: &mut TcpStream, my_identity: &IdentityKeypair) -> Result<[u8; 32], PcwError>**: Async handshake (§3.5).
- **exchange_policy(stream: &mut TcpStream, policy: Option<Policy>) -> Result<Policy, PcwError>**.
- **exchange_invoice(stream: &mut TcpStream, invoice: Option<Invoice>, expected_policy_hash: &[u8; 32]) -> Result<Invoice, PcwError>**.

### broadcast.rs

- **BroadcastPolicy**: Struct for broadcast params (§9.3).
- **pacing_schedule(scope: &Scope, n: usize, policy: &BroadcastPolicy) -> Vec<Duration>**: Schedule (§9.5).
- **Broadcaster**: Async trait for submit/rebroadcast (§9).

### receipts.rs

- **Manifest**: Struct for manifest (§10.4).
- **Entry**: For manifest entries.
- **compute_leaves(manifest: &Manifest, amounts: &[u64], addr_payloads: &[[u8; 21]]) -> Result<Vec<[u8; 32]>, PcwError>**: Leaves (§10.2).
- **merkle_root(leaves: Vec<[u8; 32]>) -> [u8; 32]**: Root (§10.3).
- **Proof**: Struct for proof (§10.5).
- **Leaf**: For proof leaf.
- **PathElement**: For proof path.
- **generate_proof(leaves: &[[u8; 32]], i: usize, manifest: &Manifest, amounts: &[u64], addr_payloads: &[[u8; 21]]) -> Result<Proof, PcwError>**.
- **verify_proof(proof: &Proof, manifest: &Manifest) -> Result<(), PcwError>**.

### failure.rs

- **NoteState**: Enum for note states (§11.2).
- **InvoiceState**: Enum for invoice states (§11.3).
- **Event**: Enum for events (§11.2).
- **NoteState::transition(&self, event: Event) -> Result<Self, PcwError>**: Transition (§11.2).

### logging.rs

- **LogRecord**: Trait for logs (§13).
- **ReissueRecord**: Struct/impl (§11.6).
- **CancelRecord**: Struct/impl (§11.6).
- **ConflictRecord**: Struct/impl (§11.6).
- **OrphanedRecord**: Struct/impl (§11.6).
- **append_to_log<T: LogRecord>(log: &mut Vec<T>, record: T, prev: Option<&T>) -> Result<(), PcwError>**: Append (§13.7).

### utils.rs

- Utility fns for hashes, ser_p, le32/le8, base58check, point_add, scalar_mul, nfc_normalize (§2).

## Full Protocol Flow Example

See examples/main.rs for a runnable demo with mocks.

## Customization

- For production fan_out (§6.8), replace dummy outpoints with real broadcast/confirm logic (e.g., integrate with network client).

## Testing & Benchmarks

Run `cargo test` for unit/integration tests (§17).
Run `cargo bench` for perf benchmarks.

See bible.md for full spec reference.
