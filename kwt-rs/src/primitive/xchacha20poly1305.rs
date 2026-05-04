//! XChaCha20-Poly1305 AEAD (RFC 8439 + extended nonce per draft-arciszewski-xchacha-03).
//! Local implementation — no `chacha20poly1305` crate.

// Poly1305 soft state machine derives from RustCrypto / poly1305-donna lineage
// (Apache-2.0 / MIT). ChaCha quarter rounds follow RFC 8439 / Bernstein.

const CHACHA_CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
const STATE_WORDS: usize = 16;
const ROUNDS: usize = 10; // 20 ChaCha rounds (10 double-rounds)

#[inline(always)]
fn qr(a: usize, b: usize, c: usize, d: usize, s: &mut [u32; STATE_WORDS]) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

fn quarter_rounds(s: &mut [u32; STATE_WORDS]) {
    qr(0, 4, 8, 12, s);
    qr(1, 5, 9, 13, s);
    qr(2, 6, 10, 14, s);
    qr(3, 7, 11, 15, s);
    qr(0, 5, 10, 15, s);
    qr(1, 6, 11, 12, s);
    qr(2, 7, 8, 13, s);
    qr(3, 4, 9, 14, s);
}

fn chacha20_block(mut state: [u32; STATE_WORDS]) -> [u8; 64] {
    let orig = state;
    for _ in 0..ROUNDS {
        quarter_rounds(&mut state);
    }
    for i in 0..STATE_WORDS {
        state[i] = state[i].wrapping_add(orig[i]);
    }
    let mut out = [0u8; 64];
    for (i, w) in state.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// HChaCha20: 32-byte subkey from root key + first 16 bytes of X nonce.
pub(crate) fn hchacha20(key: &[u8; 32], nonce16: &[u8; 16]) -> [u8; 32] {
    let mut st = [0u32; STATE_WORDS];
    st[..4].copy_from_slice(&CHACHA_CONSTANTS);
    for i in 0..8 {
        st[4 + i] = u32::from_le_bytes(key[i * 4..(i + 1) * 4].try_into().unwrap());
    }
    for i in 0..4 {
        st[12 + i] = u32::from_le_bytes(nonce16[i * 4..(i + 1) * 4].try_into().unwrap());
    }
    for _ in 0..ROUNDS {
        quarter_rounds(&mut st);
    }
    let mut out = [0u8; 32];
    for (chunk, val) in out[..16].chunks_exact_mut(4).zip(&st[..4]) {
        chunk.copy_from_slice(&val.to_le_bytes());
    }
    for (chunk, val) in out[16..].chunks_exact_mut(4).zip(&st[12..16]) {
        chunk.copy_from_slice(&val.to_le_bytes());
    }
    out
}

fn ietf_state(key: &[u8; 32], nonce12: &[u8; 12], counter: u32) -> [u32; STATE_WORDS] {
    let mut s = [0u32; STATE_WORDS];
    s[..4].copy_from_slice(&CHACHA_CONSTANTS);
    for i in 0..8 {
        s[4 + i] = u32::from_le_bytes(key[i * 4..(i + 1) * 4].try_into().unwrap());
    }
    s[12] = counter;
    for i in 0..3 {
        s[13 + i] = u32::from_le_bytes(nonce12[i * 4..(i + 1) * 4].try_into().unwrap());
    }
    s
}

fn xor_chacha20(key: &[u8; 32], nonce12: &[u8; 12], start_counter: u32, buf: &mut [u8]) -> Option<()> {
    if buf.len() / 64 > u32::MAX as usize {
        return None;
    }
    let mut ctr = start_counter;
    let mut pos = 0;
    while pos < buf.len() {
        let st = ietf_state(key, nonce12, ctr);
        let ks = chacha20_block(st);
        let take = (buf.len() - pos).min(64);
        for i in 0..take {
            buf[pos + i] ^= ks[i];
        }
        pos += take;
        ctr = ctr.checked_add(1)?;
    }
    Some(())
}

// --- Poly1305 ----------------------------------------------------------------

#[derive(Clone, Default)]
struct Poly1305St {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
}

impl Poly1305St {
    fn new(key32: &[u8; 32]) -> Self {
        let mut p = Poly1305St::default();
        p.r[0] = u32::from_le_bytes(key32[0..4].try_into().unwrap()) & 0x3ff_ffff;
        p.r[1] = (u32::from_le_bytes(key32[3..7].try_into().unwrap()) >> 2) & 0x3ff_ff03;
        p.r[2] = (u32::from_le_bytes(key32[6..10].try_into().unwrap()) >> 4) & 0x3ff_c0ff;
        p.r[3] = (u32::from_le_bytes(key32[9..13].try_into().unwrap()) >> 6) & 0x3f0_3fff;
        p.r[4] = (u32::from_le_bytes(key32[12..16].try_into().unwrap()) >> 8) & 0x00f_ffff;
        for i in 0..4 {
            p.pad[i] = u32::from_le_bytes(key32[16 + i * 4..20 + i * 4].try_into().unwrap());
        }
        p
    }

    fn compute_block(&mut self, block: &[u8; 16], partial: bool) {
        let hibit = if partial { 0 } else { 1 << 24 };
        let r0 = self.r[0];
        let r1 = self.r[1];
        let r2 = self.r[2];
        let r3 = self.r[3];
        let r4 = self.r[4];
        let s1 = r1 * 5;
        let s2 = r2 * 5;
        let s3 = r3 * 5;
        let s4 = r4 * 5;

        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];

        h0 += u32::from_le_bytes(block[0..4].try_into().unwrap()) & 0x3ff_ffff;
        h1 += (u32::from_le_bytes(block[3..7].try_into().unwrap()) >> 2) & 0x3ff_ffff;
        h2 += (u32::from_le_bytes(block[6..10].try_into().unwrap()) >> 4) & 0x3ff_ffff;
        h3 += (u32::from_le_bytes(block[9..13].try_into().unwrap()) >> 6) & 0x3ff_ffff;
        h4 += (u32::from_le_bytes(block[12..16].try_into().unwrap()) >> 8) | hibit;

        let d0 = u64::from(h0) * u64::from(r0)
            + u64::from(h1) * u64::from(s4)
            + u64::from(h2) * u64::from(s3)
            + u64::from(h3) * u64::from(s2)
            + u64::from(h4) * u64::from(s1);
        let mut d1 = u64::from(h0) * u64::from(r1)
            + u64::from(h1) * u64::from(r0)
            + u64::from(h2) * u64::from(s4)
            + u64::from(h3) * u64::from(s3)
            + u64::from(h4) * u64::from(s2);
        let mut d2 = u64::from(h0) * u64::from(r2)
            + u64::from(h1) * u64::from(r1)
            + u64::from(h2) * u64::from(r0)
            + u64::from(h3) * u64::from(s4)
            + u64::from(h4) * u64::from(s3);
        let mut d3 = u64::from(h0) * u64::from(r3)
            + u64::from(h1) * u64::from(r2)
            + u64::from(h2) * u64::from(r1)
            + u64::from(h3) * u64::from(r0)
            + u64::from(h4) * u64::from(s4);
        let mut d4 = u64::from(h0) * u64::from(r4)
            + u64::from(h1) * u64::from(r3)
            + u64::from(h2) * u64::from(r2)
            + u64::from(h3) * u64::from(r1)
            + u64::from(h4) * u64::from(r0);

        let mut c: u32;
        c = (d0 >> 26) as u32;
        h0 = d0 as u32 & 0x3ff_ffff;
        d1 += u64::from(c);
        c = (d1 >> 26) as u32;
        h1 = d1 as u32 & 0x3ff_ffff;
        d2 += u64::from(c);
        c = (d2 >> 26) as u32;
        h2 = d2 as u32 & 0x3ff_ffff;
        d3 += u64::from(c);
        c = (d3 >> 26) as u32;
        h3 = d3 as u32 & 0x3ff_ffff;
        d4 += u64::from(c);
        c = (d4 >> 26) as u32;
        h4 = d4 as u32 & 0x3ff_ffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x3ff_ffff;
        h1 += c;

        self.h[0] = h0;
        self.h[1] = h1;
        self.h[2] = h2;
        self.h[3] = h3;
        self.h[4] = h4;
    }

    fn update_padded(&mut self, data: &[u8]) {
        let mut chunks = data.chunks_exact(16);
        for ch in chunks.by_ref() {
            self.compute_block(ch.try_into().unwrap(), false);
        }
        let tail = chunks.remainder();
        if !tail.is_empty() {
            let mut b = [0u8; 16];
            b[..tail.len()].copy_from_slice(tail);
            self.compute_block(&b, false);
        }
    }

    fn feed_lengths(&mut self, aad_len: usize, ct_len: usize) -> Option<()> {
        let a: u64 = aad_len.try_into().ok()?;
        let m: u64 = ct_len.try_into().ok()?;
        let mut block = [0u8; 16];
        block[..8].copy_from_slice(&a.to_le_bytes());
        block[8..].copy_from_slice(&m.to_le_bytes());
        self.compute_block(&block, false);
        Some(())
    }

    fn finalize_tag(self) -> [u8; 16] {
        let mut h0 = self.h[0];
        let mut h1 = self.h[1];
        let mut h2 = self.h[2];
        let mut h3 = self.h[3];
        let mut h4 = self.h[4];
        let mut c: u32;
        c = h1 >> 26;
        h1 &= 0x3ff_ffff;
        h2 += c;
        c = h2 >> 26;
        h2 &= 0x3ff_ffff;
        h3 += c;
        c = h3 >> 26;
        h3 &= 0x3ff_ffff;
        h4 += c;
        c = h4 >> 26;
        h4 &= 0x3ff_ffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x3ff_ffff;
        h1 += c;

        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= 0x3ff_ffff;
        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= 0x3ff_ffff;
        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= 0x3ff_ffff;
        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= 0x3ff_ffff;
        let mut g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        let mut mask = (g4 >> (32 - 1)).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        g4 &= mask;
        mask = !mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        h0 |= h1 << 26;
        h1 = (h1 >> 6) | (h2 << 20);
        h2 = (h2 >> 12) | (h3 << 14);
        h3 = (h3 >> 18) | (h4 << 8);

        let mut tag = [0u8; 16];
        let mut f: u64;
        f = u64::from(h0) + u64::from(self.pad[0]);
        h0 = f as u32;
        f = u64::from(h1) + u64::from(self.pad[1]) + (f >> 32);
        h1 = f as u32;
        f = u64::from(h2) + u64::from(self.pad[2]) + (f >> 32);
        h2 = f as u32;
        f = u64::from(h3) + u64::from(self.pad[3]) + (f >> 32);
        h3 = f as u32;
        tag[0..4].copy_from_slice(&h0.to_le_bytes());
        tag[4..8].copy_from_slice(&h1.to_le_bytes());
        tag[8..12].copy_from_slice(&h2.to_le_bytes());
        tag[12..16].copy_from_slice(&h3.to_le_bytes());
        tag
    }
}

fn ct_eq16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut d = 0u8;
    for i in 0..16 {
        d |= a[i] ^ b[i];
    }
    d == 0
}

/// AEAD seal: returns `ciphertext || tag` (tag = 16 bytes). `aad` may be empty.
pub(crate) fn seal(key: &[u8; 32], nonce24: &[u8; 24], aad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
    if plaintext.len() / 64 > u32::MAX as usize {
        return None;
    }
    let nonce16: [u8; 16] = nonce24[..16].try_into().ok()?;
    let subkey = hchacha20(key, &nonce16);
    let mut inner_nonce = [0u8; 12];
    inner_nonce[4..12].copy_from_slice(&nonce24[16..24]);

    let st0 = ietf_state(&subkey, &inner_nonce, 0);
    let b0 = chacha20_block(st0);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&b0[..32]);

    let mut ct = vec![0u8; plaintext.len()];
    ct.copy_from_slice(plaintext);
    xor_chacha20(&subkey, &inner_nonce, 1, &mut ct)?;

    let mut poly = Poly1305St::new(&poly_key);
    poly.update_padded(aad);
    poly.update_padded(&ct);
    poly.feed_lengths(aad.len(), ct.len())?;
    let tag = poly.finalize_tag();
    ct.extend_from_slice(&tag);
    Some(ct)
}

/// AEAD open: `buf` is `ciphertext || tag`. Returns plaintext or `None` on auth failure.
pub(crate) fn open(key: &[u8; 32], nonce24: &[u8; 24], aad: &[u8], buf: &[u8]) -> Option<Vec<u8>> {
    if buf.len() < 16 {
        return None;
    }
    let (ct, tag) = buf.split_at(buf.len() - 16);
    if ct.len() / 64 > u32::MAX as usize {
        return None;
    }

    let nonce16: [u8; 16] = nonce24[..16].try_into().ok()?;
    let subkey = hchacha20(key, &nonce16);
    let mut inner_nonce = [0u8; 12];
    inner_nonce[4..12].copy_from_slice(&nonce24[16..24]);

    let st0 = ietf_state(&subkey, &inner_nonce, 0);
    let b0 = chacha20_block(st0);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&b0[..32]);

    let mut poly = Poly1305St::new(&poly_key);
    poly.update_padded(aad);
    poly.update_padded(ct);
    poly.feed_lengths(aad.len(), ct.len())?;
    let calc = poly.finalize_tag();
    let expected: [u8; 16] = tag.try_into().ok()?;
    if !ct_eq16(&calc, &expected) {
        return None;
    }

    let mut pt = ct.to_vec();
    xor_chacha20(&subkey, &inner_nonce, 1, &mut pt)?;
    Some(pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hchacha_vector() {
        const KEY: [u8; 32] = hex_literal::hex!(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        const INPUT: [u8; 16] = hex_literal::hex!("000000090000004a0000000031415927");
        const OUTPUT: [u8; 32] = hex_literal::hex!(
            "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
        );
        assert_eq!(hchacha20(&KEY, &INPUT), OUTPUT);
    }

    /// draft-arciszewski-xchacha-03 Appendix A.1 (vectors from chacha20poly1305 crate tests).
    #[test]
    fn draft_xchacha_vector() {
        const KEY: [u8; 32] = hex_literal::hex!(
            "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
        );
        const NONCE: [u8; 24] = [
            0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
            0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        ];
        const AAD: [u8; 12] = hex_literal::hex!("50515253c0c1c2c3c4c5c6c7");
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        const EXPECTED_CT: &[u8] = &[
            0xbd, 0x6d, 0x17, 0x9d, 0x3e, 0x83, 0xd4, 0x3b, 0x95, 0x76, 0x57, 0x94, 0x93, 0xc0, 0xe9,
            0x39, 0x57, 0x2a, 0x17, 0x00, 0x25, 0x2b, 0xfa, 0xcc, 0xbe, 0xd2, 0x90, 0x2c, 0x21, 0x39,
            0x6c, 0xbb, 0x73, 0x1c, 0x7f, 0x1b, 0x0b, 0x4a, 0xa6, 0x44, 0x0b, 0xf3, 0xa8, 0x2f, 0x4e,
            0xda, 0x7e, 0x39, 0xae, 0x64, 0xc6, 0x70, 0x8c, 0x54, 0xc2, 0x16, 0xcb, 0x96, 0xb7, 0x2e,
            0x12, 0x13, 0xb4, 0x52, 0x2f, 0x8c, 0x9b, 0xa4, 0x0d, 0xb5, 0xd9, 0x45, 0xb1, 0x1b, 0x69,
            0xb9, 0x82, 0xc1, 0xbb, 0x9e, 0x3f, 0x3f, 0xac, 0x2b, 0xc3, 0x69, 0x48, 0x8f, 0x76, 0xb2,
            0x38, 0x35, 0x65, 0xd3, 0xff, 0xf9, 0x21, 0xf9, 0x66, 0x4c, 0x97, 0x63, 0x7d, 0xa9, 0x76,
            0x88, 0x12, 0xf6, 0x15, 0xc6, 0x8b, 0x13, 0xb5, 0x2e,
        ];
        const EXPECTED_TAG: [u8; 16] =
            hex_literal::hex!("c0875924c1c7987947deafd8780acf49");

        let ct = seal(&KEY, &NONCE, &AAD, pt).unwrap();
        assert_eq!(ct.len(), EXPECTED_CT.len() + EXPECTED_TAG.len());
        assert_eq!(&ct[..EXPECTED_CT.len()], EXPECTED_CT);
        assert_eq!(&ct[EXPECTED_CT.len()..], EXPECTED_TAG);
        let back = open(&KEY, &NONCE, &AAD, &ct).unwrap();
        assert_eq!(back.as_slice(), pt.as_slice());
    }
}
