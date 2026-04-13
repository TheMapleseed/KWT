// ============================================================================
// kwt/src/lib.rs
//
// KWT (KDL Web Token) — Reference Implementation
//
// Protocol summary:
//   Token format:  v{N}.{base64url(nonce)}.{base64url(ciphertext+tag)}
//   v1:            XChaCha20-Poly1305 + HKDF-SHA256
//   v2:            AES-256-GCM        + HKDF-SHA256
//
// The canonical binary payload is a sequence of typed opcodes, serialized
// in ascending opcode order, terminated with the END marker (0x80).
// Field names are never transmitted — the opcode is the field identity.
//
// Encryption key = HKDF-SHA256(ikm=master_key, salt=nonce[0..32], info="kwt-v1-encryption")
// This ensures nonce reuse cannot recover the master key.
// ============================================================================

pub mod codec;
pub mod crypto;
pub mod error;
pub mod token;

pub use codec::{Claims, Role, Scope};
pub use codec::encode as codec_encode;
pub use error::KwtError;
pub use token::{KwtToken, Version};
