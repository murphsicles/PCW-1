//! Peer Cash Wallet Protocol (PCW-1): IP-to-IP BSV settlement protocol per spec.
//!
//! This library implements the full protocol verbatim from §§1-17, providing deterministic logic for
//! invoice-scoped settlements using BSV primitives via rust-sv. All public APIs are re-exported
//! from submodules for convenience, maintaining the separation of concerns outlined in the spec.

pub use addressing::{recipient_address, sender_change_address};
pub use broadcast::{BroadcastPolicy, Broadcaster, pacing_schedule};
pub use errors::PcwError;
pub use failure::{Event, InvoiceState, NoteState};
pub use invoice::{Invoice, new_invoice};
pub use json::canonical_json;
pub use keys::{AnchorKeypair, IdentityKeypair, ecdh_z};
pub use logging::{
    CancelRecord, ConflictRecord, LogRecord, OrphanedRecord, ReissueRecord, append_to_log,
};
pub use policy::{Policy, new_policy};
pub use protocol::{exchange_invoice, exchange_policy, handshake};
pub use receipts::{
    Entry, Leaf, Manifest, PathElement, Proof, compute_leaves, generate_proof, merkle_root,
    verify_proof,
};
pub use scope::{Scope, derive_scalar};
pub use selection::{Reservation, Utxo, build_reservations};
pub use split::bounded_split;
pub use tx::{NoteMeta, NoteTx, build_note_tx};
pub use utils::{
    base58check, h160, le8, le32, nfc_normalize, point_add, scalar_mul, ser_p, sha256,
};
