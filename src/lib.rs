//! Peer Cash Wallet Protocol (PCW-1): IP-to-IP BSV settlement protocol per spec.
//!
//! This library implements the full protocol verbatim from §§1-17, providing deterministic logic for
//! invoice-scoped settlements using BSV primitives via rust-sv.

pub use errors::PcwError;
pub use json::canonical_json;
pub use keys::{AnchorKeypair, IdentityKeypair, ecdh_z};
pub use scope::{Scope, derive_scalar};
pub use policy::{Policy, new_policy};
pub use invoice::{Invoice, new_invoice};
pub use split::bounded_split;
pub use selection::{Utxo, Reservation, build_reservations};
pub use addressing::{recipient_address, sender_change_address};
pub use tx::{NoteMeta, NoteTx, build_note_tx};
pub use protocol::{handshake, exchange_policy, exchange_invoice};
pub use broadcast::{BroadcastPolicy, pacing_schedule, Broadcaster};
pub use receipts::{Manifest, Entry, compute_leaves, merkle_root, Proof, Leaf, PathElement, generate_proof, verify_proof};
pub use failure::{NoteState, InvoiceState, Event};
pub use logging::{LogRecord, ReissueRecord, CancelRecord, ConflictRecord, OrphanedRecord, append_to_log};
pub use utils::{sha256, h160, ser_p, le32, le8, base58check, point_add, scalar_mul, nfc_normalize};
