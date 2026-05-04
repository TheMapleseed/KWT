// ============================================================================
// kwt/src/error.rs
// ============================================================================

use thiserror::Error;

/// Rich validation errors for logging and debugging.
///
/// The [`Display`](std::fmt::Display) output and thiserror messages may include lengths,
/// version strings, or audience values — **do not** send them verbatim to untrusted HTTP
/// clients or broad production logs. For user-facing responses, use [`KwtError::public_message`].
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

    /// `issued_at` is beyond the allowed clock skew into the future (JWT `iat`-style bound).
    #[error("token not yet valid")]
    NotYetValid,

    #[error("audience mismatch: expected {expected}, got {got}")]
    AudienceMismatch { expected: String, got: String },

    #[error("missing required claim: {0}")]
    MissingClaim(String),

    #[error("invalid claim value: {0}")]
    InvalidClaim(String),

    #[error("token replayed (jti already seen)")]
    Replayed,

    /// OS monotonic clock is before the Unix epoch (should not occur on supported hosts).
    #[error("system clock unavailable")]
    SystemTime,

    /// OS CSPRNG could not supply random bytes (e.g. misconfiguration or early boot).
    #[error("random number generator unavailable")]
    EntropyUnavailable,
}

impl KwtError {
    /// Opaque message safe for HTTP 401/403 bodies and external APIs (no claim or key material).
    pub fn public_message(&self) -> &'static str {
        match self {
            KwtError::MalformedToken(_)
            | KwtError::UnknownVersion(_)
            | KwtError::Base64Error(_)
            | KwtError::AuthenticationFailed
            | KwtError::KeyDerivationFailed
            | KwtError::PayloadError(_)
            | KwtError::AudienceMismatch { .. }
            | KwtError::MissingClaim(_)
            | KwtError::InvalidClaim(_)
            | KwtError::Replayed => "invalid token",
            KwtError::Expired => "token expired",
            KwtError::NotYetValid => "token not yet valid",
            KwtError::SystemTime | KwtError::EntropyUnavailable => "service unavailable",
        }
    }
}
