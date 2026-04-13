# KWT Reference Implementation (Rust)

## Prerequisites
- Rust 1.75+ (stable)
- `cargo`

## Build & Run
```bash
cd kwt-rs
cargo build
cargo run       # runs the demo in src/main.rs
cargo test      # runs all unit tests across all modules
```

## File Structure
```
kwt-rs/
├── Cargo.toml          # Dependencies: chacha20poly1305, hkdf, sha2, uuid, zeroize, base64ct
└── src/
    ├── lib.rs           # Crate root and re-exports
    ├── error.rs         # KwtError enum
    ├── codec.rs         # Canonical binary encoder/decoder (the information density layer)
    ├── crypto.rs        # HKDF key derivation + XChaCha20-Poly1305 AEAD
    ├── token.rs         # KwtToken::issue() and KwtToken::validate()
    └── main.rs          # Demo binary with size comparison output
```

## Security Notes
- Never log or serialize the MasterKey
- Load MasterKey from a secrets manager in production (Vault, AWS SSM, etc.)
- Implement JTI bloom filter in Redis before deploying to production
- This is a reference implementation — get it audited before production use
