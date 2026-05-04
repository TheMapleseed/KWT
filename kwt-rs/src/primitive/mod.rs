//! In-tree cryptographic primitives for KWT v1 — local implementations, not re-exports
//! from `chacha20poly1305` / `sha2` / `hkdf`.
//!
//! | Submodule | Specification |
//! |-----------|----------------|
//! | [`sha256`] | FIPS 180-4 SHA-256 |
//! | [`hkdf`] | RFC 5869 HKDF (HMAC-SHA256 extract + expand) |
//! | [`xchacha20poly1305`] | RFC 8439 AEAD + XChaCha extended nonce (draft-arciszewski-xchacha-03) |
//!
//! Unit tests include the draft XChaCha test vector and NIST SHA-256 empty-string digest.

pub(crate) mod hkdf;
pub(crate) mod sha256;
pub(crate) mod xchacha20poly1305;
