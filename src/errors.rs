use thiserror::Error;

/// PCW-1 Errors: Rejections and failures per spec.
#[derive(Error, Debug)]
pub enum PcwError {
    #[error("Infeasible split: N_min > N_max §5.1")]
    InfeasibleSplit,
    #[error("Dust change: 0 < change < dust §7.3")]
    DustChange,
    #[error("Underfunded note: change <= 0 §7.3")]
    Underfunded,
    #[error("Canonical JSON violation: {0} §2")]
    CanonicalJson(String),
    #[error("Zero scalar before bump: {0} §4.2")]
    ZeroScalar(String),
    #[error("Reservation overlap: inputs not disjoint §6")]
    ReservationOverlap,
    #[error("Fee below floor: fee < floor * size §7.3")]
    FeeBelowFloor,
    #[error("Signature invalid: {0} §3.3-§3.4")]
    InvalidSignature(String),
    #[error("Policy expired: t >= expiry §3.3")]
    PolicyExpired,
    #[error("Invoice expired: t >= expiry §3.4")]
    InvoiceExpired,
    #[error("Scope misuse: wrong domain or missing {Z, H_I} §3.2")]
    ScopeMisuse,
    #[error("Merkle proof invalid: recomputed root mismatch §10.5")]
    InvalidProof,
    #[error("External conflict: reserved input spent §11.4 C")]
    ExternalConflict,
    #[error("Superseded tx: version < current §9.9")]
    SupersededTx,
    #[error("rust-sv error: {0}")]
    SvError(#[from] sv::util::Error),
    #[error("secp256k1 error: {0}")]
    SecpError(#[from] secp256k1::Error),
    #[error("serde error: {0}")]
    SerdeError(#[from] serde_json::Error),
    #[error("chrono error: {0}")]
    ChronoError(#[from] chrono::ParseError),
    #[error("Other: {0}")]
    Other(String),
}
