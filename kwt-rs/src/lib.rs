#![forbid(unsafe_code)]

//! KWT (KDL Web Token) — production-oriented Rust implementation.
//!
//! ## Token cryptography (v1)
//!
//! All v1 cryptographic primitives are **implemented in this repository** in the
//! private `primitive` module (`sha256`, `hkdf`, `xchacha20poly1305`): SHA-256,
//! HKDF-SHA256, and XChaCha20-Poly1305
//! (RFC 8439 + extended nonce per draft-arciszewski-xchacha-03). Random nonces and
//! master-key material use the OS via [`getrandom`](https://docs.rs/getrandom).
//! There is **no** `alg`, `typ`, or JOSE header — the only version signal is the
//! `v1.` wire prefix parsed in [`token`].
//!
//! ## Payload layout (not JWT “flags”)
//!
//! KWT does **not** embed JWT/JOSE header flags (`alg`, `crit`, `kid`, …). Claims are
//! a **canonical binary opcode stream** (typed fields, ascending order, `END`) defined
//! and documented in [`codec`]. That is stricter than typical JWT: closed
//! enums for roles/scopes, mandatory AEAD, and no per-token algorithm negotiation.
//!
//! Informal JWT Registered Claims → KWT analogues: `sub` → subject, `aud` → audience,
//! `iat` / `exp` → issued_at / expires_at, `jti` → jti (UUID v7). Anything else
//! (issuer, not-before, custom headers) is **out of scope** for this crate unless added
//! as new protocol opcodes.
//!
//! ## Performance at token scale (bounded caps)
//!
//! KWT targets **small opaque tokens**, not bulk payloads. Public caps
//! ([`MAX_TOKEN_WIRE_BYTES`], [`MAX_CIPHERTEXT_BYTES`], [`MAX_PAYLOAD_BYTES`]) bound
//! worst-case work and allocation per `issue` / `validate`. Typical tokens are on the
//! order of **hundreds of bytes** on the wire; a few short-lived `Vec` allocations per
//! request are normal and dwarfed by AEAD + base64 at that size. For extreme QPS,
//! pooling or custom buffers live at the **application** layer — the protocol stays
//! intentionally compact.
//!
//! ## Security at bounded size
//!
//! Decrypt path follows **MAC-then-use**: Poly1305 is verified over the ciphertext
//! **before** plaintext is returned from [`crypto::decrypt`]. Caps
//! limit how much memory or CPU a single malformed wire string can induce; they do
//! not replace **rate limiting** at the edge, but they keep per-token cost in a
//! predictable range for high-traffic services.
//!
//! Use [`error::KwtError::public_message`] for external responses; [`std::fmt::Display`]
//! on errors may include operational detail. In-tree AEAD (see `primitive`) follows
//! published test vectors but should still receive periodic expert review like any
//! custom cryptography.
//!
//! ## Versions
//!
//! - **v1** — implemented end-to-end (this crate). This is the **default** profile:
//!   a compact bearer token sized for **JWT replacement** (`Authorization`, session
//!   credentials, API gates) — **single-shot** AEAD over one canonical payload.
//! - **v2** (e.g. AES-256-GCM + HKDF) — described in the whitepaper / roadmap only;
//!   **not implemented** here yet; do not assume `Version::V2` exists.
//! - **Streaming / chunked AEAD (optional, non-default)** — for **large or
//!   streaming** ciphertexts, a **separate** wire framing and version entry may be
//!   specified later (chunk MAC order, limits, rekeying). It will remain **opt-in**
//!   and **disjoint** from the default three-segment token path so common validators
//!   keep treating KWT as a small header-sized object. Not implemented in this crate
//!   until that profile is specified.

// ============================================================================
// kwt/src/lib.rs — see crate-level `//!` docs above for protocol vs JWT summary.
// ============================================================================

mod primitive;

pub mod codec;
pub mod crypto;
pub mod error;
pub mod token;

pub use codec::{
    encode as codec_encode, Claims, Role, Scope, MAX_AUDIENCE_BYTES, MAX_PAYLOAD_BYTES,
    MAX_SUBJECT_BYTES,
};
pub use error::KwtError;
pub use token::{
    KwtToken, Version, MAX_CIPHERTEXT_BYTES, MAX_TOKEN_WIRE_BYTES,
};
