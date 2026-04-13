# KWT (KDL Web Token)

This repository contains the **technical white paper** ([`kwt_whitepaper.tex`](kwt_whitepaper.tex)) for **KWT** — a compact, versioned, always-encrypted authentication token format — and a **Rust reference implementation** in [`kwt-rs/`](kwt-rs/). This document summarizes the **mathematics** and **control flow** described in the white paper.

---

## Information density (the core metric)

The paper defines **information density** $D$ as meaningful claim bits per byte on the wire:

$$
D = \frac{S}{W}
$$

- **$S$** — bits needed for a **minimum lossless** encoding of claim **values** only (field names and structural noise are excluded).
- **$W$** — total **transmitted** byte length of the token.

Higher $D$ means more semantic payload per byte. For a **benchmark payload** (subject, `iat`, `exp`, audience, two roles), the paper estimates **$S \approx 232$** bits (~29 bytes of semantic content).

Illustrative densities from the paper:

| Encoding | Role | Approx. $D$ (bits/byte) |
|----------|------|-------------------------|
| JWT payload after base64url | JSON claims | **~1.55** |
| KDL text after base64url | Human-readable KDL | **~1.90** |
| KWT canonical binary → AEAD → base64url ciphertext segment | Wire-efficient | **~2.94** |
| Theoretical floor | Perfect packing | **~3.57** |

The paper argues KWT’s canonical binary form (opcodes, varints, closed enums) keeps density high **through the encryption boundary**; the benchmark binary payload is on the order of **~43 bytes** before encrypt, with full tokens on the order of **~105–160 bytes** depending on version and overhead.

### Compounding cost model

Let:

- $T$ — daily token volume  
- $B(f)$ — bytes per token for format $f$  
- $C_s$ — storage cost per GB-month  
- $C_t$ — transmission cost per GB  
- $C_e$ — CPU/energy cost per byte decrypted  

**Daily savings** (storage + transmission + decrypt-related compute, in aggregate):

$$
\text{Daily savings} = T \cdot \bigl(B(\text{JWT}) - B(\text{KWT})\bigr) \cdot (C_s + C_t + C_e)
$$

Example in the paper: $T = 10^8$/day, JWT ~400 B vs KWT ~120 B ⇒ **~28 GB/day** payload reduction before other factors.

---

## Cryptographic math

### Session key (HKDF)

The **master key** is not used directly as the AEAD key. Per version, a **per-token session key** is derived with **HKDF-SHA256** (RFC 5869). The white paper gives the v1 form:

$$
K_{\text{session}} = \mathrm{HKDF}\bigl(
  \text{IKM} = K_{\text{master}},\;
  \text{salt} = \text{nonce}[0{:}32],\;
  \text{info} = \text{kwt-v1-encryption}
\bigr)
$$

Rationale: binding derivation to (a prefix of) the nonce limits cross-token key reuse and means nonce mishandling does not trivially collapse to “same key every time.” **v2** uses the same HKDF pattern with a version-specific `info` string (e.g. `kwt-v2-encryption` in the Web Crypto example in the paper).

### AEAD

- **v1:** XChaCha20-Poly1305 (192-bit nonce; CSPRNG-generated).  
- **v2:** AES-256-GCM (12-byte IV in the browser-oriented discussion).  
- **v3 (specified):** XChaCha20-Poly1305 with **X25519 + HKDF** for asymmetric envelope (encrypt with public material, decrypt with private).

Ciphertext includes the **Poly1305 / GCM authentication tag** (16 bytes).

### Nonce collision (order of magnitude)

For v1-style **random nonces**, the paper cites collision probability on the order of **$2^{-128}$** over **$2^{32}$** tokens under the same key — treated as negligible in practice. **Counter nonces** are discouraged unless the implementation can guarantee strict monotonicity across distributed processes.

---

## Token shape (wire format)

No separate JWT-style header blob. Structure:

```text
v{N}.<base64url(nonce)>.<base64url(ciphertext || tag)>
```

The **`v{N}` prefix is the only algorithm selector**: fixed registry, not attacker-controlled JSON.

---

## Control flow

### Design rules (global)

1. **No crypto negotiation in the token** — version fixes the algorithm suite.  
2. **Payload is always encrypted** — no “signed but plaintext” mode.  
3. **Strict parsing** — unknown opcodes, bad ranges, malformed layout → **hard errors** (no silent ignore).

### Issuance (logical pipeline)

1. Build claims (conceptually aligned with KDL field semantics).  
2. **Serialize to canonical binary**: opcodes in **ascending** order, no duplicate opcodes, UTF-8 strings **NFC-normalized**, time ordering constraints (e.g. `expires > issued`), trailing **`0x80` END** marker.  
3. Draw a fresh nonce from a **CSPRNG** (size per version).  
4. **HKDF** from `K_master` + salt/info → `K_session`.  
5. **AEAD-encrypt** canonical payload → ciphertext ‖ tag.  
6. Emit `v{N}` + base64url(nonce) + base64url(ciphertext+tag).

**Opcode families** (summary): subject / timestamps / audience / roles / scopes / JTI (UUID v7) / custom extension ranges, plus mandatory END.

### Validation (ordered steps)

Validators must follow this order; failures should surface as a **generic 401** without leaking which check failed:

1. Parse **`v{N}`**; reject unknown versions.  
2. **Base64url-decode** the two segments; reject malformed encoding.  
3. **JTI bloom filter** check **before** any decryption (replay flood / DoS mitigation).  
4. **HKDF** → session key.  
5. **AEAD decrypt + verify tag**; reject on failure.  
6. **Parse canonical binary**; reject invalid opcodes/structure.  
7. **Time check:** not expired (paper recommends small clock **leeway**, e.g. 30–60 s).  
8. **Audience** matches the service’s registered audience.  
9. **Insert JTI** into the bloom filter; return validated claims.

Replay control is **mandated** via a **counting Bloom filter** (e.g. Redis): check before decrypt, TTL aligned with max token lifetime; bounded false-positive rate trades rare valid rejections for replay safety.

---

## Version registry (from the paper)

| Version | Encryption      | KDF / keying        | Notes                          |
|--------:|-----------------|---------------------|--------------------------------|
| v1      | XChaCha20-Poly1305 | HKDF-SHA256      | Default symmetric story        |
| v2      | AES-256-GCM        | HKDF-SHA256      | **Web Crypto–friendly** (browsers) |
| v3      | XChaCha20-Poly1305 | X25519 + HKDF    | Public encrypt, private decrypt |

---

## Canonical binary details (short)

- **Varints:** protobuf-style — 7 data bits per byte, high bit = continuation.  
- **Canonicalization:** ascending opcode order, no duplicates, valid UTF-8 + NFC, `expires_at > issued_at`, END byte last.

---

## Related files

- **Full specification and rationale:** [`kwt_whitepaper.tex`](kwt_whitepaper.tex) (Draft 1.0).  
- **Rust reference crate:** [`kwt-rs/README.md`](kwt-rs/README.md).

The white paper stresses that KWT is a **design target**: fuzzing, professional audit, and staged rollout are recommended before relying on it for primary authentication.
