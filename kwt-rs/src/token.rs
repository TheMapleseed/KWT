// ============================================================================
// kwt/src/token.rs
//
// Top-level token operations: issue and validate.
//
// Token wire format (ASCII, dot-separated):
//   v1.{base64url(nonce)}.{base64url(ciphertext_with_tag)}
//
// Full round-trip:
//   Issue:
//     1. Build Claims struct
//     2. Encode to canonical binary (codec::encode)
//     3. Encrypt with HKDF-derived key (crypto::encrypt)
//     4. base64url-encode nonce and ciphertext
//     5. Prefix with version string "v1."
//
//   Validate:
//     1. Split on '.' and parse version prefix
//     2. base64url-decode nonce and ciphertext
//     3. Decrypt and authenticate (crypto::decrypt); plaintext buffer is zeroized on drop
//     4. Parse canonical binary payload (codec::decode)
//     5. Wall-clock: issued_at not too far in the future; expiry with leeway
//     6. Optional JTI replay callback
//     7. Check audience against expected value
//     8. Return Claims (all checks passed)
// ============================================================================

use base64ct::{Base64UrlUnpadded, Encoding};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::{
    codec::{self, Claims},
    crypto::{self, MasterKey, NONCE_SIZE},
    error::KwtError,
};

/// Maximum UTF-8 length of the full `v1.{nonce}.{ciphertext}` token (rejects huge strings before base64 decode).
///
/// Must cover `v1.` + base64url(24-byte nonce) + base64url(ciphertext) at
/// [`MAX_CIPHERTEXT_BYTES`], with additional slack so [`KwtToken::issue`] and
/// [`KwtToken::validate`] share the same ceiling on all hosts. (Roughly: base64
/// expands ciphertext by ~4/3; this cap leaves room beyond
/// [`crate::codec::MAX_PAYLOAD_BYTES`] + tag.)
pub const MAX_TOKEN_WIRE_BYTES: usize = 128 * 1024;

/// Maximum decoded ciphertext (including Poly1305 tag) accepted in [`KwtToken::validate`].
///
/// Includes margin above the largest plaintext allowed by [`crate::codec::MAX_PAYLOAD_BYTES`]
/// plus the AEAD tag (16 bytes) and rounding headroom.
pub const MAX_CIPHERTEXT_BYTES: usize = 640 * 1024;

fn now_unix_secs() -> Result<u64, KwtError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| KwtError::SystemTime)
        .map(|d| d.as_secs())
}

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

/// Supported KWT **compact token** versions (JWT-style, single-shot AEAD).
///
/// A future **opt-in** streaming or chunked-AEAD profile (large bodies, not header
/// tokens) would use a **different** wire prefix and API surface; it is **not** the
/// default and is **not** represented here until specified and implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    /// Default: XChaCha20-Poly1305 + HKDF-SHA256, bounded three-segment wire form.
    V1,
}

impl Version {
    fn prefix(&self) -> &'static str {
        match self {
            Version::V1 => "v1",
        }
    }

    fn from_prefix(s: &str) -> Result<Self, KwtError> {
        match s {
            "v1" => Ok(Version::V1),
            other => Err(KwtError::UnknownVersion(other.to_owned())),
        }
    }
}

// ---------------------------------------------------------------------------
// KwtToken — the main API surface
// ---------------------------------------------------------------------------

/// A fully validated KWT token with its decoded claims.
/// Constructing this type guarantees that:
///   - Cryptographic authentication succeeded
///   - The payload parsed successfully
///   - Any [`KwtToken::validate_with`] JTI callback succeeded
///   - The token is not expired
///   - The audience matches the expected value
#[derive(Debug, Clone)]
pub struct KwtToken {
    pub version: Version,
    pub claims: Claims,
}

impl KwtToken {
    // -----------------------------------------------------------------------
    // Issue
    // -----------------------------------------------------------------------

    /// Encode and encrypt a Claims struct into a KWT token string.
    ///
    /// # Arguments
    /// * `claims` — the claims to encode. Use `codec::new_claims` for a skeleton.
    /// * `master_key` — the server's master key. Must be 32 bytes.
    ///
    /// # Returns
    /// A dot-separated ASCII token string ready for transmission.
    ///
    /// # Example
    /// ```rust
    /// use kwt::{codec, crypto::MasterKey, token::{KwtToken, Version}};
    ///
    /// let key = MasterKey::generate().unwrap();
    /// let mut claims = codec::new_claims("user_882", "api.example.com", 3600).unwrap();
    /// claims.roles.push(kwt::Role::Admin);
    ///
    /// let token_str = KwtToken::issue(&claims, &key).unwrap();
    /// println!("{}", token_str);
    /// // → "v1.{base64url_nonce}.{base64url_ciphertext}"
    /// ```
    pub fn issue(claims: &Claims, master_key: &MasterKey) -> Result<String, KwtError> {
        // Step 1: canonical binary encoding
        let plaintext = codec::encode(claims)?;

        // Step 2: encrypt
        let (nonce, ciphertext) = crypto::encrypt(&plaintext, master_key)?;

        // Step 3: base64url encode
        let nonce_b64 = Base64UrlUnpadded::encode_string(&nonce);
        let ct_b64    = Base64UrlUnpadded::encode_string(&ciphertext);

        // Step 4: assemble (same wire cap as validate — avoids issuing unusable tokens)
        let token = format!("{}.{}.{}", Version::V1.prefix(), nonce_b64, ct_b64);
        if token.len() > MAX_TOKEN_WIRE_BYTES {
            return Err(KwtError::MalformedToken(format!(
                "issued token exceeds maximum wire size {} (got {})",
                MAX_TOKEN_WIRE_BYTES,
                token.len()
            )));
        }
        Ok(token)
    }

    // -----------------------------------------------------------------------
    // Validate
    // -----------------------------------------------------------------------

    /// Decode, decrypt, and fully validate a KWT token string.
    ///
    /// All validation steps are performed in the order specified in the
    /// protocol specification (Section 3.7). For HTTP responses, prefer
    /// [`KwtError::public_message`] over [`Display`](std::fmt::Display) so clients never see
    /// internal parse details or audience strings.
    ///
    /// # Arguments
    /// * `token_str` — the raw token string as received on the wire.
    /// * `master_key` — the server's master key.
    /// * `expected_audience` — the audience this server expects.
    ///   The token's audience claim must exactly match this value.
    ///
    /// # Returns
    /// A `KwtToken` with fully validated claims, or a `KwtError`.
    ///
    /// # Example
    /// ```rust
    /// use kwt::{codec, crypto::MasterKey, token::KwtToken};
    ///
    /// let key = MasterKey::generate().unwrap();
    /// let claims = codec::new_claims("user_882", "api.example.com", 3600).unwrap();
    /// let token_str = KwtToken::issue(&claims, &key).unwrap();
    /// let validated = KwtToken::validate(&token_str, &key, "api.example.com").unwrap();
    /// assert_eq!(validated.claims.subject, "user_882");
    /// ```
    pub fn validate(
        token_str: &str,
        master_key: &MasterKey,
        expected_audience: &str,
    ) -> Result<Self, KwtError> {
        Self::validate_with(token_str, master_key, expected_audience, |_| Ok(()))
    }

    /// Like [`validate`](Self::validate), but runs `check_jti` after successful decrypt
    /// and payload parse so you can reject replayed `jti` values (e.g. Redis `SETNX`,
    /// bloom filter) before accepting the token. Return [`KwtError::Replayed`] when the
    /// `jti` was already seen.
    ///
    /// Validation order: wire shape → decrypt → decode → **clock** (`issued_at` /
    /// `expires_at`) → **`check_jti`** → audience.
    /// For lowest decrypt cost on hot paths, maintain a bloom filter *before* calling this
    /// if you can index by a truncated hash of the wire token; `check_jti` still covers
    /// cryptographic binding to claims.
    pub fn validate_with<F>(
        token_str: &str,
        master_key: &MasterKey,
        expected_audience: &str,
        check_jti: F,
    ) -> Result<Self, KwtError>
    where
        F: FnOnce(&Uuid) -> Result<(), KwtError>,
    {
        if token_str.len() > MAX_TOKEN_WIRE_BYTES {
            return Err(KwtError::MalformedToken(format!(
                "token exceeds maximum wire size {} (got {})",
                MAX_TOKEN_WIRE_BYTES,
                token_str.len()
            )));
        }

        // Step 1: split and parse version
        let parts: Vec<&str> = token_str.splitn(3, '.').collect();
        if parts.len() != 3 {
            return Err(KwtError::MalformedToken(
                "expected 3 dot-separated segments".into(),
            ));
        }
        let version = Version::from_prefix(parts[0])?;

        // Step 2: decode base64url segments
        let nonce_bytes = Base64UrlUnpadded::decode_vec(parts[1])
            .map_err(|e| KwtError::Base64Error(e.to_string()))?;
        let ciphertext = Base64UrlUnpadded::decode_vec(parts[2])
            .map_err(|e| KwtError::Base64Error(e.to_string()))?;

        if ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(KwtError::MalformedToken(format!(
                "ciphertext exceeds maximum decoded size {}",
                MAX_CIPHERTEXT_BYTES
            )));
        }

        if nonce_bytes.len() != NONCE_SIZE {
            return Err(KwtError::MalformedToken(format!(
                "nonce must be {} bytes, got {}",
                NONCE_SIZE,
                nonce_bytes.len()
            )));
        }
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&nonce_bytes);

        // Step 3: decrypt and authenticate
        let plaintext = crypto::decrypt(&ciphertext, &nonce, master_key)?;

        // Step 4: parse canonical binary payload (`plaintext` zeroizes when dropped)
        let claims = codec::decode(plaintext.as_slice())?;

        let now = now_unix_secs()?;
        // Skew: accept slightly "future" `issued_at` from client clocks; reject gross abuse.
        const ISSUED_AT_FUTURE_LEEWAY_SECS: u64 = 60;
        if (claims.issued_at as u64) > now.saturating_add(ISSUED_AT_FUTURE_LEEWAY_SECS) {
            return Err(KwtError::NotYetValid);
        }
        // Expiry: allow a small leeway for clock skew (validator behind issuer).
        const EXPIRY_LEEWAY_SECS: u64 = 30;
        if (claims.expires_at as u64).saturating_add(EXPIRY_LEEWAY_SECS) < now {
            return Err(KwtError::Expired);
        }

        check_jti(&claims.jti)?;

        // Step 5: check audience
        if claims.audience != expected_audience {
            return Err(KwtError::AudienceMismatch {
                expected: expected_audience.to_owned(),
                got: claims.audience.clone(),
            });
        }

        Ok(KwtToken { version, claims })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{new_claims, Role, Scope};

    fn make_key() -> MasterKey {
        MasterKey::generate().unwrap()
    }

    fn make_claims() -> Claims {
        let mut c = new_claims("user_882", "api.example.com", 3600).unwrap();
        c.roles  = vec![Role::Admin, Role::Editor];
        c.scopes = vec![Scope::ReadStats, Scope::WriteLogs];
        c
    }

    #[test]
    fn issue_and_validate() {
        let key    = make_key();
        let claims = make_claims();

        let token_str = KwtToken::issue(&claims, &key).expect("issue failed");
        println!("Token: {}", token_str);
        println!("Token length: {} bytes", token_str.len());

        let validated = KwtToken::validate(&token_str, &key, "api.example.com")
            .expect("validate failed");

        assert_eq!(validated.claims.subject,  "user_882");
        assert_eq!(validated.claims.audience, "api.example.com");
        assert_eq!(validated.claims.roles,    vec![Role::Admin, Role::Editor]);
        assert_eq!(validated.claims.scopes,   vec![Scope::ReadStats, Scope::WriteLogs]);
        assert_eq!(validated.version, Version::V1);
    }

    #[test]
    fn wrong_audience_rejected() {
        let key       = make_key();
        let claims    = make_claims();
        let token_str = KwtToken::issue(&claims, &key).unwrap();

        let result = KwtToken::validate(&token_str, &key, "api.other-service.com");
        assert!(matches!(result, Err(KwtError::AudienceMismatch { .. })));
    }

    #[test]
    fn expired_token_rejected() {
        let key   = make_key();
        let mut c = new_claims("user_882", "api.example.com", 1).unwrap(); // 1-second TTL

        // Manually set the token to already be expired
        c.issued_at  = 1_000_000;  // far in the past
        c.expires_at = 1_000_001;  // 1 second later, also far in the past

        let token_str = KwtToken::issue(&c, &key).unwrap();
        let result    = KwtToken::validate(&token_str, &key, "api.example.com");
        assert!(matches!(result, Err(KwtError::Expired)));
    }

    #[test]
    fn issued_at_far_future_rejected() {
        let key = make_key();
        let mut c = make_claims();
        c.issued_at = 4_000_000_000;
        c.expires_at = 4_000_000_600;
        let token_str = KwtToken::issue(&c, &key).unwrap();
        let result = KwtToken::validate(&token_str, &key, "api.example.com");
        assert!(matches!(result, Err(KwtError::NotYetValid)));
    }

    #[test]
    fn public_message_is_opaque() {
        assert_eq!(
            KwtError::AudienceMismatch {
                expected: "secret".into(),
                got: "leak".into(),
            }
            .public_message(),
            "invalid token"
        );
        assert_eq!(KwtError::NotYetValid.public_message(), "token not yet valid");
        assert_eq!(KwtError::Expired.public_message(), "token expired");
    }

    #[test]
    fn tampered_token_rejected() {
        let key       = make_key();
        let claims    = make_claims();
        let token_str = KwtToken::issue(&claims, &key).unwrap();

        // Corrupt the last character of the ciphertext segment
        let mut tampered = token_str.clone();
        let last = tampered.pop().unwrap();
        // Replace with a different character
        let replacement = if last == 'A' { 'B' } else { 'A' };
        tampered.push(replacement);

        let result = KwtToken::validate(&tampered, &key, "api.example.com");
        assert!(result.is_err(), "tampered token should be rejected");
    }

    #[test]
    fn token_size_is_compact() {
        let key       = make_key();
        let claims    = make_claims();
        let token_str = KwtToken::issue(&claims, &key).unwrap();

        println!("Full KWT token size: {} bytes", token_str.len());

        // A JWT with the same payload would be ~380-420 bytes.
        // KWT target: under 180 bytes.
        assert!(
            token_str.len() < 200,
            "token too large: {} bytes (target <200)",
            token_str.len()
        );
    }

    #[test]
    fn malformed_token_rejected() {
        let key = make_key();
        let bad_tokens = vec![
            "",
            "notavalidtoken",
            "v1.onlytwoparts",
            "v99.aaaa.bbbb",                // unknown version
            "v1.!!!.ccc",                   // invalid base64
        ];
        for bad in bad_tokens {
            let result = KwtToken::validate(bad, &key, "api.example.com");
            assert!(result.is_err(), "should reject malformed token: '{}'", bad);
        }
    }

    #[test]
    fn validate_with_propagates_jti_callback_error() {
        let key = make_key();
        let claims = make_claims();
        let token_str = KwtToken::issue(&claims, &key).unwrap();
        let r = KwtToken::validate_with(&token_str, &key, "api.example.com", |_| {
            Err(KwtError::Replayed)
        });
        assert!(matches!(r, Err(KwtError::Replayed)));
    }

    #[test]
    fn validate_with_ok_when_jti_allowed() {
        let key = make_key();
        let claims = make_claims();
        let token_str = KwtToken::issue(&claims, &key).unwrap();
        let r = KwtToken::validate_with(&token_str, &key, "api.example.com", |_| Ok(()));
        assert!(r.is_ok());
    }

    #[test]
    fn oversized_wire_token_rejected() {
        let key = make_key();
        let huge = "v1.".to_string() + &"a".repeat(super::MAX_TOKEN_WIRE_BYTES);
        assert!(KwtToken::validate(&huge, &key, "api.example.com").is_err());
    }
}
