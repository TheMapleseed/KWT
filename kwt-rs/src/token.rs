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
//     3. Decrypt and authenticate (crypto::decrypt)
//     4. Parse canonical binary payload (codec::decode)
//     5. Check expiry against current time
//     6. Check audience against expected value
//     7. Return Claims (all checks passed)
// ============================================================================

use base64ct::{Base64UrlUnpadded, Encoding};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::{
    codec::{self, Claims},
    crypto::{self, MasterKey, NONCE_SIZE},
    error::KwtError,
};

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

/// Supported KWT versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V1, // XChaCha20-Poly1305 + HKDF-SHA256
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
    /// let key = MasterKey::generate();
    /// let mut claims = codec::new_claims("user_882", "api.example.com", 3600);
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

        // Step 4: assemble
        Ok(format!("{}.{}.{}", Version::V1.prefix(), nonce_b64, ct_b64))
    }

    // -----------------------------------------------------------------------
    // Validate
    // -----------------------------------------------------------------------

    /// Decode, decrypt, and fully validate a KWT token string.
    ///
    /// All validation steps are performed in the order specified in the
    /// protocol specification (Section 3.7). Any failure returns a generic
    /// error type — callers should not expose internal failure reasons to
    /// end users.
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
    /// let validated = KwtToken::validate(&token_str, &key, "api.example.com").unwrap();
    /// println!("Subject: {}", validated.claims.subject);
    /// ```
    pub fn validate(
        token_str: &str,
        master_key: &MasterKey,
        expected_audience: &str,
    ) -> Result<Self, KwtError> {
        // Step 1: split and parse version
        let parts: Vec<&str> = token_str.splitn(3, '.').collect();
        if parts.len() != 3 {
            return Err(KwtError::MalformedToken(
                "expected 3 dot-separated segments".into()
            ));
        }
        let version = Version::from_prefix(parts[0])?;

        // Step 2: decode base64url segments
        let nonce_bytes = Base64UrlUnpadded::decode_vec(parts[1])
            .map_err(|e| KwtError::Base64Error(e.to_string()))?;
        let ciphertext = Base64UrlUnpadded::decode_vec(parts[2])
            .map_err(|e| KwtError::Base64Error(e.to_string()))?;

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
        // (In production, check JTI bloom filter BEFORE this step
        //  to avoid paying decrypt cost for replayed tokens.)
        let plaintext = crypto::decrypt(&ciphertext, &nonce, master_key)?;

        // Step 4: parse canonical binary payload
        let claims = codec::decode(&plaintext)?;

        // Step 5: check expiry
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_secs() as u64;

        // Allow a 30-second clock skew leeway
        const LEEWAY_SECONDS: u64 = 30;
        if (claims.expires_at as u64) + LEEWAY_SECONDS < now {
            return Err(KwtError::Expired);
        }

        // Step 6: check audience
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
        MasterKey::generate()
    }

    fn make_claims() -> Claims {
        let mut c = new_claims("user_882", "api.example.com", 3600);
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
        let mut c = new_claims("user_882", "api.example.com", 1); // 1-second TTL

        // Manually set the token to already be expired
        c.issued_at  = 1_000_000;  // far in the past
        c.expires_at = 1_000_001;  // 1 second later, also far in the past

        let token_str = KwtToken::issue(&c, &key).unwrap();
        let result    = KwtToken::validate(&token_str, &key, "api.example.com");
        assert!(matches!(result, Err(KwtError::Expired)));
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
}
