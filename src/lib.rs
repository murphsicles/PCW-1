//! Peer Cash Wallet Protocol (PCW-1): IP-to-IP BSV settlement protocol per spec.
//!
//! This library implements the full protocol verbatim from §§1-17, providing deterministic logic for
//! invoice-scoped settlements using BSV primitives via rust-sv. All public APIs are re-exported
//! from submodules for convenience, maintaining the separation of concerns outlined in the spec.

// Declare internal modules
mod addressing;
mod broadcast;
mod errors; // Placeholder: Implement PcwError and related error types
mod failure;
mod invoice;
mod json; // Placeholder: Implement canonical_json for §14
mod keys;
mod logging;
mod policy;
mod protocol;
mod receipts;
mod scope;
mod selection; // Placeholder: Implement Utxo, Reservation, build_reservations for §7
mod split; // Placeholder: Implement bounded_split for §4
mod tx; // Placeholder: Implement NoteMeta, NoteTx, build_note_tx for §8
mod utils; // Placeholder: Implement base58check, h160, etc. for §5

// Re-export public items
pub use addressing::{recipient_address, sender_change_address};
pub use broadcast::{BroadcastPolicy, Broadcaster, pacing_schedule};
pub use errors::PcwError;
pub use failure::{Event, InvoiceState, NoteState};
pub use invoice::Invoice;
pub use json::canonical_json;
pub use keys::{AnchorKeypair, IdentityKeypair, ecdh_z};
pub use logging::{
    CancelRecord, ConflictRecord, LogRecord, OrphanedRecord, OutpointMeta, ReissueRecord, append_to_log,
};
pub use policy::{new_policy, Policy};
pub use protocol::{exchange_invoice, exchange_policy, handshake};
pub use receipts::{
    Entry, Leaf, Manifest, PathElement, Proof, compute_leaves, generate_proof, merkle_root,
    verify_proof,
};
pub use scope::{derive_scalar, Scope};
pub use selection::{Utxo, build_reservations};
pub use split::bounded_split;
pub use tx::{build_note_tx, NoteMeta, NoteTx};
pub use utils::{
    base58check, h160, le32, le8, nfc_normalize, point_add, scalar_mul, ser_p, sha256,
};
