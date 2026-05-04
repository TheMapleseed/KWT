# KWT — Rust implementation

**Crate version: 0.2.1** — see [What you must still do](#what-you-must-still-do-operational-security) for breaking/API guidance when upgrading from 0.1.x.

## Prerequisites
- Rust 1.85+ (stable; edition 2024)
- `cargo`

## Build & Run

From the **repository root** (virtual workspace; recommended):

```bash
cargo build -p kwt
cargo run -p kwt    # example binary in src/main.rs
cargo test -p kwt
cargo publish -p kwt --dry-run
```

From **`kwt-rs/`** only (Cargo still finds the parent workspace):

```bash
cd kwt-rs
cargo build
cargo run
cargo test
```

## File Structure
```
kwt-rs/
├── Cargo.toml          # getrandom, uuid, zeroize, base64ct, thiserror (+ dev hex-literal for tests)
├── LICENSE             # GPL-3.0-or-later (full text)
└── src/
    ├── lib.rs           # Crate root and re-exports
    ├── error.rs         # KwtError enum (+ public_message for client-safe errors)
    ├── codec.rs         # Canonical binary encoder/decoder (the information density layer)
    ├── crypto.rs        # HKDF-SHA256 + XChaCha20-Poly1305 (calls primitive/)
    ├── primitive/       # In-tree SHA-256, HKDF, XChaCha20-Poly1305 (no AEAD crates)
    ├── token.rs         # KwtToken::issue() and KwtToken::validate()
    └── main.rs          # Example binary (issue/validate + size comparison)
```

## What you must still do (operational security)

This crate implements **v1 KWT**: bounded symmetric tokens suitable as a **JWT replacement** for `Authorization`-style credentials. **Correct use in production** still depends on the integrating application and host environment.

| Responsibility | Why it matters |
|------------------|----------------|
| **Master key** | Generate with strong entropy; load from a **secrets manager** (Vault, AWS Secrets Manager, SSM, etc.); **never** log, serialize, or commit the key; plan **rotation** and dual-key validation during rollover. |
| **Transport** | Tokens are not a substitute for **TLS** (or equivalent). Anyone who can read headers in clear text can steal a bearer token. |
| **Replay (`jti`)** | Implement **`validate_with`** (or an outer filter) so each **`jti`** is accepted at most once within your replay window (e.g. Redis `SETNX`, durable store). The crate does not ship a global replay database. |
| **Client-facing errors** | Use **`KwtError::public_message()`** for HTTP bodies and external APIs. Do **not** send **`Display`** / full error strings to untrusted clients — they can leak parse details or audience values. |
| **Logs and support dumps** | **`Claims`** redacts **`Debug`** for common fields, but avoid logging **raw token strings** or full decoded claims in production unless policy allows it. |
| **Rate limiting** | Wire and ciphertext **caps** bound memory per token; they do **not** stop an attacker from sending **many** valid-sized requests. Enforce limits at the **edge** and on validate endpoints. |
| **Clock** | Validation uses wall clock for **`issued_at`** / **`expires_at`**. Keep hosts on **accurate time** (NTP); handle **`SystemTime`** / **`EntropyUnavailable`** as infrastructure failures, not “bad tokens.” |
| **Authorization** | KWT proves **who** the token was issued for (claims) and that it was **minted by someone with the master key**. **What that principal may do** in your API remains your **authorization** layer. |
| **Supply chain** | Pin dependencies in your app; run **`cargo audit`** in CI; review lockfile updates. |
| **Cryptographic assurance** | Primitives are **in-tree** and tested against **published vectors**; for high-assurance deployments, budget **independent expert review** of `primitive/` like any custom crypto. |

## Security Notes (quick checklist)

- Never log or serialize the `MasterKey`.
- Prefer **`MasterKey::from_bytes`** from your secret store over ad-hoc env parsing in untrusted shells.
- **`crypto::decrypt`** returns **`Zeroizing<Vec<u8>>`** — treat plaintext as sensitive until you have finished parsing; do not log it.

## License

This crate is **GNU General Public License v3.0 or later** (**`GPL-3.0-or-later`**). See [`LICENSE`](LICENSE) for the full text. If you need a different license for linking or distribution, that is a separate legal decision; the published crate is GPLv3+.

## Upgrading from 0.1.x

- **`crypto::decrypt`** now returns **`Zeroizing<Vec<u8>>`** instead of **`Vec<u8>`** — use **`.as_slice()`** or deref where you pass bytes to decoders.
- New validation: **`issued_at`** must not be more than **~60 seconds** in the future relative to the validator clock (**`NotYetValid`**).
- Use **`KwtError::public_message()`** for external responses; review any code that matched on error strings from **`Display`**.
