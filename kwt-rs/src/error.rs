// ============================================================================
// kwt/src/error.rs
// ============================================================================

use thiserror::Error;

#[derive(Debug, Error)]
pub enum KwtError {
    // Structural errors
    #[error("malformed token: {0}")]
    MalformedToken(String),

    #[error("unknown version prefix: {0}")]
    UnknownVersion(String),

    #[error("base64 decode failed: {0}")]
    Base64Error(String),

    // Cryptographic errors — intentionally opaque to callers
    #[error("authentication failed")]
    AuthenticationFailed,

    #[error("key derivation failed")]
    KeyDerivationFailed,

    // Payload errors
    #[error("payload parse error: {0}")]
    PayloadError(String),

    #[error("token expired")]
    Expired,

    #[error("audience mismatch: expected {expected}, got {got}")]
    AudienceMismatch { expected: String, got: String },

    #[error("missing required claim: {0}")]
    MissingClaim(String),

    #[error("invalid claim value: {0}")]
    InvalidClaim(String),

    #[error("token replayed (jti already seen)")]
    Replayed,
}
