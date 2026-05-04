// ============================================================================
// kwt/src/crypto.rs
//
// Cryptographic operations for KWT v1 (XChaCha20-Poly1305 + HKDF-SHA256).
//
// Primitives are implemented locally under `crate::primitive` (no crates.io
// AEAD / SHA / HKDF stack).
//
// Key hierarchy:
//   master_key (256-bit, long-lived, kept in secrets manager)
//       |
//       v
//   HKDF-SHA256(ikm=master_key, salt=nonce[0..32], info="kwt-v1-encryption")
//       |
//       v
//   session_key (256-bit, per-token, derived fresh for each encrypt/decrypt)
//       |
//       v
//   XChaCha20-Poly1305(key=session_key, nonce=nonce[0..24])
//
// Nonce is 24 bytes (192 bits), generated via CSPRNG on every encryption.
// The first 32 bytes of nonce are used as HKDF salt (nonce is only 24 bytes,
// so we pad to 32 with zeros for the HKDF call — nonce is still the unique
// value that prevents key reuse).
//
// The 16-byte Poly1305 authentication tag is appended to the ciphertext.
// On decryption, the tag is verified before any plaintext is returned.
// ============================================================================

use getrandom::getrandom;
use zeroize::Zeroizing;

use crate::error::KwtError;
use crate::primitive::hkdf::hkdf_sha256;
use crate::primitive::xchacha20poly1305;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// HKDF info string for v1 tokens.
/// Changing this invalidates all existing v1 tokens — treat as permanent.
const HKDF_INFO_V1: &[u8] = b"kwt-v1-encryption";

/// Size of the master key and derived session key (256 bits).
pub const KEY_SIZE: usize = 32;

/// XChaCha20 nonce size (192 bits — large enough for random generation).
pub const NONCE_SIZE: usize = 24;

// ---------------------------------------------------------------------------
// Key types (newtype wrappers with Zeroize to clear on drop)
// ---------------------------------------------------------------------------

/// A 256-bit master key. Keep in a secrets manager; never log or serialize.
#[derive(Clone)]
pub struct MasterKey(pub Zeroizing<[u8; KEY_SIZE]>);

impl MasterKey {
    /// Create a MasterKey from raw bytes.
    /// For production, load from an environment variable or secrets manager.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, KwtError> {
        if bytes.len() != KEY_SIZE {
            return Err(KwtError::InvalidClaim(format!(
                "master key must be exactly {} bytes, got {}",
                KEY_SIZE,
                bytes.len()
            )));
        }
        let mut arr = [0u8; KEY_SIZE];
        arr.copy_from_slice(bytes);
        Ok(MasterKey(Zeroizing::new(arr)))
    }

    /// Generate a fresh random master key (for key rotation or testing).
    pub fn generate() -> Result<Self, KwtError> {
        let mut key = Zeroizing::new([0u8; KEY_SIZE]);
        getrandom(key.as_mut()).map_err(|_| KwtError::EntropyUnavailable)?;
        Ok(MasterKey(key))
    }
}

// ---------------------------------------------------------------------------
// HKDF key derivation
// ---------------------------------------------------------------------------

/// Derive a per-token session key from the master key and the nonce.
///
/// Using the nonce as HKDF salt ensures that even if the same nonce were
/// reused (which CSPRNG makes astronomically unlikely), the session keys
/// would still be distinct from different master keys.
fn derive_session_key(
    master_key: &MasterKey,
    nonce: &[u8; NONCE_SIZE],
) -> Result<Zeroizing<[u8; KEY_SIZE]>, KwtError> {
    // Pad 24-byte nonce to 32 bytes for use as HKDF salt
    let mut salt = [0u8; KEY_SIZE];
    salt[..NONCE_SIZE].copy_from_slice(nonce);

    let mut session_key = Zeroizing::new([0u8; KEY_SIZE]);
    if !hkdf_sha256(&salt, master_key.0.as_ref(), HKDF_INFO_V1, session_key.as_mut()) {
        return Err(KwtError::KeyDerivationFailed);
    }

    Ok(session_key)
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

/// Encrypt a canonical binary payload.
///
/// Returns `(nonce, ciphertext_with_tag)`.
/// The ciphertext includes the 16-byte Poly1305 authentication tag appended
/// by the AEAD — do not strip it before storage/transmission.
///
/// # Security
/// Nonce is generated from the OS CSPRNG on every call.
/// A fresh session key is derived per-nonce via HKDF.
pub fn encrypt(
    plaintext: &[u8],
    master_key: &MasterKey,
) -> Result<([u8; NONCE_SIZE], Vec<u8>), KwtError> {
    let mut nonce = [0u8; NONCE_SIZE];
    getrandom(&mut nonce).map_err(|_| KwtError::EntropyUnavailable)?;

    let session_key = derive_session_key(master_key, &nonce)?;
    let sk: &[u8; KEY_SIZE] = &session_key;

    let ciphertext = xchacha20poly1305::seal(sk, &nonce, &[], plaintext)
        .ok_or(KwtError::AuthenticationFailed)?;

    Ok((nonce, ciphertext))
}

// ---------------------------------------------------------------------------
// Decrypt
// ---------------------------------------------------------------------------

/// Decrypt and authenticate a ciphertext.
///
/// `ciphertext` must include the 16-byte authentication tag.
/// Returns the plaintext only if the authentication tag is valid.
/// Any modification to the ciphertext, nonce, or tag will cause this to fail.
///
/// The buffer is wrapped in [`Zeroizing`] so it is cleared on drop (defense in depth;
/// callers should still avoid logging decrypted bytes).
pub fn decrypt(
    ciphertext: &[u8],
    nonce: &[u8; NONCE_SIZE],
    master_key: &MasterKey,
) -> Result<Zeroizing<Vec<u8>>, KwtError> {
    if ciphertext.len() < 16 {
        return Err(KwtError::MalformedToken(
            "ciphertext too short to contain authentication tag".into(),
        ));
    }

    let session_key = derive_session_key(master_key, nonce)?;
    let sk: &[u8; KEY_SIZE] = &session_key;

    let pt = xchacha20poly1305::open(sk, nonce, &[], ciphertext).ok_or(KwtError::AuthenticationFailed)?;
    Ok(Zeroizing::new(pt))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = MasterKey::generate().unwrap();
        let plaintext = b"hello from kwt crypto layer";

        let (nonce, ciphertext) = encrypt(plaintext, &key).expect("encrypt failed");
        let recovered = decrypt(&ciphertext, &nonce, &key).expect("decrypt failed");

        assert_eq!(plaintext.as_slice(), recovered.as_slice());
    }

    #[test]
    fn wrong_key_fails_auth() {
        let key1 = MasterKey::generate().unwrap();
        let key2 = MasterKey::generate().unwrap();
        let plaintext = b"sensitive token payload";

        let (nonce, ciphertext) = encrypt(plaintext, &key1).expect("encrypt failed");

        let result = decrypt(&ciphertext, &nonce, &key2);
        assert!(result.is_err(), "decryption with wrong key should fail");
    }

    #[test]
    fn tampered_ciphertext_fails_auth() {
        let key = MasterKey::generate().unwrap();
        let plaintext = b"sensitive token payload";

        let (nonce, mut ciphertext) = encrypt(plaintext, &key).expect("encrypt failed");

        let mid = ciphertext.len() / 2;
        ciphertext[mid] ^= 0xFF;

        let result = decrypt(&ciphertext, &nonce, &key);
        assert!(result.is_err(), "tampered ciphertext should fail auth");
    }

    #[test]
    fn tampered_nonce_fails_auth() {
        let key = MasterKey::generate().unwrap();
        let plaintext = b"sensitive token payload";

        let (mut nonce, ciphertext) = encrypt(plaintext, &key).expect("encrypt failed");
        nonce[0] ^= 0x01;

        let result = decrypt(&ciphertext, &nonce, &key);
        assert!(result.is_err(), "wrong nonce should cause auth failure");
    }

    #[test]
    fn each_encryption_uses_different_nonce() {
        let key = MasterKey::generate().unwrap();
        let plaintext = b"same plaintext every time";

        let (nonce1, ct1) = encrypt(plaintext, &key).unwrap();
        let (nonce2, ct2) = encrypt(plaintext, &key).unwrap();

        assert_ne!(nonce1, nonce2, "nonces should be random and unique");
        assert_ne!(ct1, ct2, "ciphertexts should differ even for same plaintext");
    }

    #[test]
    fn key_derivation_is_deterministic() {
        let key = MasterKey::generate().unwrap();
        let nonce = [0x42u8; NONCE_SIZE];

        let k1 = derive_session_key(&key, &nonce).unwrap();
        let k2 = derive_session_key(&key, &nonce).unwrap();
        assert_eq!(k1.as_ref(), k2.as_ref());

        let nonce2 = [0x43u8; NONCE_SIZE];
        let k3 = derive_session_key(&key, &nonce2).unwrap();
        assert_ne!(k1.as_ref(), k3.as_ref());
    }

    #[test]
    fn empty_plaintext_round_trip() {
        let key = MasterKey::generate().unwrap();
        let (nonce, ciphertext) = encrypt(b"", &key).expect("encrypt empty");
        assert_eq!(ciphertext.len(), 16, "AEAD output is tag only for empty plaintext");
        let recovered = decrypt(&ciphertext, &nonce, &key).expect("decrypt empty");
        assert!(recovered.is_empty());
    }
}
