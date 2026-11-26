#![forbid(unsafe_code)]
//! **Praetor Core** — Cryptographic Cluster Node Registry, Replay-Bounded `Ed25519` Wake
//! Envelopes, `BLAKE3` + `XChaCha20-Poly1305` Persistence Baselines, and `Sextant`/`SigNET`
//! Forensic Eviction Capsules for **NodeAlpha**, **NodeBeta**, **NodeDelta**, and **NodeGamma**.

pub mod baseline;
pub mod envelope;
pub mod forensics;
pub mod nodes;

use thiserror::Error;

/// Unified error taxonomy across Praetor interception, verification, and eviction surfaces.
#[derive(Debug, Error)]
pub enum PraetorError {
    #[error("unknown or unauthorized cluster node '{0}'")]
    UnknownNode(String),

    #[error("sender IP '{actual}' is not authorized for cluster node '{node}'")]
    UnauthorizedNodeIp { node: String, actual: String },

    #[error("invalid Ed25519 envelope format or base64url payload: {0}")]
    MalformedEnvelope(String),

    #[error("Ed25519 signature verification failed for node '{0}'")]
    SignatureInvalid(String),

    #[error(
        "wake envelope expired or outside clock skew window (issued={issued}, expires={expires}, now={now})"
    )]
    EnvelopeExpired { issued: i64, expires: i64, now: i64 },

    #[error("replay detected: envelope nonce '{0}' has already been consumed")]
    ReplayDetected(String),

    #[error("HTTP request body BLAKE3 digest mismatch against signed envelope claim")]
    BodyDigestMismatch,

    #[error("HTTP method or path mismatch against signed envelope claim")]
    EndpointMismatch,

    #[error("cross-origin request from '{0}' blocked by CSRF perimeter")]
    CrossOriginBlocked(String),

    #[error("integrity baseline tamper or sealing error: {0}")]
    BaselineTamper(String),

    #[error("cryptographic key error: {0}")]
    KeyError(String),

    #[error("SQLite WAL ledger error: {0}")]
    LedgerError(String),

    #[error("Sextant provenance error: {0}")]
    Sextant(#[from] sextant_core::SextantError),

    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Crate-wide result alias.
pub type PraetorResult<T> = Result<T, PraetorError>;
