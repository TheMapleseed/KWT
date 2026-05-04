//! HKDF-SHA256 (RFC 5869) — extract + expand, used for per-token session keys.

use super::sha256::{sha256_digest, Sha256};

const SHA256_LEN: usize = 32;
const BLOCK: usize = 64;

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; SHA256_LEN] {
    let key = if key.len() > BLOCK {
        sha256_digest(key).to_vec()
    } else {
        key.to_vec()
    };

    let mut ipad = [0u8; BLOCK];
    let mut opad = [0u8; BLOCK];
    ipad[..key.len()].copy_from_slice(&key);
    opad[..key.len()].copy_from_slice(&key);
    for b in ipad.iter_mut() {
        *b ^= 0x36;
    }
    for b in opad.iter_mut() {
        *b ^= 0x5c;
    }

    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(msg);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize()
}

fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; SHA256_LEN] {
    let salt_key = if salt.is_empty() {
        [0u8; SHA256_LEN].to_vec()
    } else {
        salt.to_vec()
    };
    hmac_sha256(&salt_key, ikm)
}

fn hkdf_expand(prk: &[u8; SHA256_LEN], info: &[u8], okm: &mut [u8]) -> bool {
    let l = okm.len();
    if l > 255 * SHA256_LEN {
        return false;
    }

    let mut n: u8 = 0;
    let mut pos = 0;
    let mut t_prev = [0u8; SHA256_LEN];
    let mut t_len = 0usize;

    while pos < l {
        n = n.wrapping_add(1);
        let mut h = Sha256::new();
        h.update(prk);
        if t_len > 0 {
            h.update(&t_prev[..t_len]);
        }
        h.update(info);
        h.update(&[n]);
        let t = h.finalize();
        let take = (l - pos).min(SHA256_LEN);
        okm[pos..pos + take].copy_from_slice(&t[..take]);
        t_prev = t;
        t_len = SHA256_LEN;
        pos += take;
    }
    true
}

/// HKDF-Extract(salt, IKM) then HKDF-Expand(PRK, info, L = okm.len()).
pub(crate) fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) -> bool {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, okm)
}
