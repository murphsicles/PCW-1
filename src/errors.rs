//! Module for error handling in the PCW-1 protocol.
//!
//! This module defines the `PcwError` enum, which encapsulates all possible errors
//! encountered during protocol execution, with references to specific sections of
//! the PCW-1 spec (e.g., §§5.1, 7.3, 10.5).

use thiserror::Error;

/// PCW-1 Errors: Rejections and failures per spec.
#[derive(Error, Debug)]
pub enum PcwError {
    /// Error when the split is infeasible due to N_min > N_max (§5.1).
    #[error("Infeasible split: N_min > N_max §5.1")]
    InfeasibleSplit,

    /// Error when change is dust (0 < change < dust threshold) (§7.3).
    #[error("Dust change: 0 < change < dust §7.3")]
    DustChange,

    /// Error when a note is underfunded (change <= 0) (§7.3).
    #[error("Underfunded note: change <= 0 §7.3")]
    Underfunded,

    /// Error when canonical JSON validation fails (§2).
    #[error("Canonical JSON violation: {0} §2")]
    CanonicalJson(String),

    /// Error when a scalar is zero before bumping (§4.2).
    #[error("Zero scalar before bump: {0} §4.2")]
    ZeroScalar(String),

    /// Error when reserved inputs overlap, violating disjointness (§6).
    #[error("Reservation overlap: inputs not disjoint §6")]
    ReservationOverlap,

    /// Error when the fee is below the required floor (§7.3).
    #[error("Fee below floor: fee < floor * size §7.3")]
    FeeBelowFloor,

    /// Error when a signature is invalid (§§3.3-3.4).
    #[error("Signature invalid: {0} §3.3-§3.4")]
    InvalidSignature(String),

    /// Error when a policy has expired (t >= expiry) (§3.3).
    #[error("Policy expired: t >= expiry §3.3")]
    PolicyExpired,

    /// Error when an invoice has expired (t >= expiry) (§3.4).
    #[error("Invoice expired: t >= expiry §3.4")]
    InvoiceExpired,

    /// Error when the scope is misused (wrong domain or missing {Z, H_I}) (§3.2).
    #[error("Scope misuse: wrong domain or missing {Z, H_I} §3.2")]
    ScopeMisuse,

    /// Error when a Merkle proof is invalid (recomputed root mismatch) (§10.5).
    #[error("Merkle proof invalid: recomputed root mismatch §10.5")]
    InvalidProof,

    /// Error when an external conflict occurs (reserved input spent) (§11.4 C).
    #[error("External conflict: reserved input spent §11.4 C")]
    ExternalConflict,

    /// Error when a transaction is superseded (version < current) (§9.9).
    #[error("Superseded tx: version < current §9.9")]
    SupersededTx,

    /// Error propagated from rust-sv utilities.
    #[error("rust-sv error: {0}")]
    SvError(#[from] sv::util::Error),

    /// Error propagated from secp256k1 library.
    #[error("secp256k1 error: {0}")]
    SecpError(#[from] secp256k1::Error),

    /// Error propagated from serde JSON parsing.
    #[error("serde error: {0}")]
    SerdeError(#[from] serde_json::Error),

    /// Error propagated from chrono parsing.
    #[error("chrono error: {0}")]
    ChronoError(#[from] chrono::ParseError),

    /// Catch-all for other unspecified errors.
    #[error("Other: {0}")]
    Other(String),
}
