// ============================================================================
// kwt/src/crypto.rs
//
// Cryptographic operations for KWT v1 (XChaCha20-Poly1305 + HKDF-SHA256).
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

use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;
use crate::error::KwtError;

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
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut key = Zeroizing::new([0u8; KEY_SIZE]);
        OsRng.fill_bytes(key.as_mut());
        MasterKey(key)
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

    let hk = Hkdf::<Sha256>::new(Some(&salt), master_key.0.as_ref());
    let mut session_key = Zeroizing::new([0u8; KEY_SIZE]);
    hk.expand(HKDF_INFO_V1, session_key.as_mut())
        .map_err(|_| KwtError::KeyDerivationFailed)?;

    Ok(session_key)
}

// ---------------------------------------------------------------------------
// Encrypt
// ---------------------------------------------------------------------------

/// Encrypt a canonical binary payload.
///
/// Returns `(nonce, ciphertext_with_tag)`.
/// The ciphertext includes the 16-byte Poly1305 authentication tag appended
/// by the AEAD library — do not strip it before storage/transmission.
///
/// # Security
/// Nonce is generated from the OS CSPRNG on every call.
/// A fresh session key is derived per-nonce via HKDF.
pub fn encrypt(
    plaintext: &[u8],
    master_key: &MasterKey,
) -> Result<([u8; NONCE_SIZE], Vec<u8>), KwtError> {
    // Generate a fresh random nonce
    let nonce_generic = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&nonce_generic);

    // Derive per-token session key
    let session_key = derive_session_key(master_key, &nonce)?;

    // Construct cipher with derived key
    let cipher = XChaCha20Poly1305::new_from_slice(session_key.as_ref())
        .map_err(|_| KwtError::KeyDerivationFailed)?;

    // Encrypt — output is ciphertext || 16-byte Poly1305 tag
    let ciphertext = cipher
        .encrypt(&nonce_generic, plaintext)
        .map_err(|_| KwtError::AuthenticationFailed)?;

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
/// # Timing
/// Authentication tag comparison is constant-time (XChaCha20-Poly1305
/// in the RustCrypto implementation uses subtle::ConstantTimeEq).
pub fn decrypt(
    ciphertext: &[u8],
    nonce: &[u8; NONCE_SIZE],
    master_key: &MasterKey,
) -> Result<Vec<u8>, KwtError> {
    use chacha20poly1305::aead::generic_array::GenericArray;

    // Minimum size: 16-byte tag means ciphertext must be at least 17 bytes
    if ciphertext.len() < 17 {
        return Err(KwtError::MalformedToken(
            "ciphertext too short to contain authentication tag".into()
        ));
    }

    // Derive the same session key using the provided nonce
    let session_key = derive_session_key(master_key, nonce)?;

    // Reconstruct the cipher
    let cipher = XChaCha20Poly1305::new_from_slice(session_key.as_ref())
        .map_err(|_| KwtError::KeyDerivationFailed)?;

    let nonce_ga = GenericArray::from_slice(nonce);

    // Decrypt and verify — returns Err if tag check fails
    let plaintext = cipher
        .decrypt(nonce_ga, ciphertext)
        .map_err(|_| KwtError::AuthenticationFailed)?;

    Ok(plaintext)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = MasterKey::generate();
        let plaintext = b"hello from kwt crypto layer";

        let (nonce, ciphertext) = encrypt(plaintext, &key).expect("encrypt failed");
        let recovered = decrypt(&ciphertext, &nonce, &key).expect("decrypt failed");

        assert_eq!(plaintext.as_ref(), recovered.as_slice());
    }

    #[test]
    fn wrong_key_fails_auth() {
        let key1 = MasterKey::generate();
        let key2 = MasterKey::generate();
        let plaintext = b"sensitive token payload";

        let (nonce, ciphertext) = encrypt(plaintext, &key1).expect("encrypt failed");

        // Decrypting with a different key must fail (auth tag mismatch)
        let result = decrypt(&ciphertext, &nonce, &key2);
        assert!(result.is_err(), "decryption with wrong key should fail");
    }

    #[test]
    fn tampered_ciphertext_fails_auth() {
        let key = MasterKey::generate();
        let plaintext = b"sensitive token payload";

        let (nonce, mut ciphertext) = encrypt(plaintext, &key).expect("encrypt failed");

        // Flip a bit in the middle of the ciphertext
        let mid = ciphertext.len() / 2;
        ciphertext[mid] ^= 0xFF;

        let result = decrypt(&ciphertext, &nonce, &key);
        assert!(result.is_err(), "tampered ciphertext should fail auth");
    }

    #[test]
    fn tampered_nonce_fails_auth() {
        let key = MasterKey::generate();
        let plaintext = b"sensitive token payload";

        let (mut nonce, ciphertext) = encrypt(plaintext, &key).expect("encrypt failed");
        nonce[0] ^= 0x01; // flip one bit in nonce

        // Wrong nonce → wrong session key → wrong decryption → tag mismatch
        let result = decrypt(&ciphertext, &nonce, &key);
        assert!(result.is_err(), "wrong nonce should cause auth failure");
    }

    #[test]
    fn each_encryption_uses_different_nonce() {
        let key = MasterKey::generate();
        let plaintext = b"same plaintext every time";

        let (nonce1, ct1) = encrypt(plaintext, &key).unwrap();
        let (nonce2, ct2) = encrypt(plaintext, &key).unwrap();

        // Nonces must be different (CSPRNG)
        assert_ne!(nonce1, nonce2, "nonces should be random and unique");
        // Ciphertexts should also differ (different nonce → different keystream)
        assert_ne!(ct1, ct2, "ciphertexts should differ even for same plaintext");
    }

    #[test]
    fn key_derivation_is_deterministic() {
        let key = MasterKey::generate();
        let nonce = [0x42u8; NONCE_SIZE];

        // Same inputs must produce same session key
        let k1 = derive_session_key(&key, &nonce).unwrap();
        let k2 = derive_session_key(&key, &nonce).unwrap();
        assert_eq!(k1.as_ref(), k2.as_ref());

        // Different nonce must produce different session key
        let nonce2 = [0x43u8; NONCE_SIZE];
        let k3 = derive_session_key(&key, &nonce2).unwrap();
        assert_ne!(k1.as_ref(), k3.as_ref());
    }
}
