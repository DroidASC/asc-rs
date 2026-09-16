//! Adler-32 checksum and SHA-1 signature used by the DEX header.

/// Adler-32 over `data` (the DEX checksum covers bytes `12..`).
pub fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += byte as u32;
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

/// One SHA-1 compression round over a 64-byte block.
fn sha1_block(h: &mut [u32; 5], block: &[u8]) {
    debug_assert_eq!(block.len(), 64);
    let mut w = [0u32; 80];
    for (i, word) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }
    let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
    for (i, &wi) in w.iter().enumerate() {
        let (f, k) = match i {
            0..=19 => ((b & c) | (!b & d), 0x5A827999),
            20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
            _ => (b ^ c ^ d, 0xCA62C1D6),
        };
        let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(wi);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
}

/// SHA-1 digest (the DEX signature covers bytes `32..`).
///
/// Whole 64-byte blocks are hashed straight from `data`; only the padded tail
/// (at most two blocks) goes through a stack buffer, so no copy of the input
/// is made.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut blocks = data.chunks_exact(64);
    for block in &mut blocks {
        sha1_block(&mut h, block);
    }
    let rem = blocks.remainder();
    // Padding: 0x80, zeros up to 56 mod 64, then the 64-bit big-endian bit length.
    let mut tail = [0u8; 128];
    tail[..rem.len()].copy_from_slice(rem);
    tail[rem.len()] = 0x80;
    let tail_len = if rem.len() < 56 { 64 } else { 128 };
    let bit_len = (data.len() as u64).wrapping_mul(8);
    tail[tail_len - 8..tail_len].copy_from_slice(&bit_len.to_be_bytes());
    for block in tail[..tail_len].chunks_exact(64) {
        sha1_block(&mut h, block);
    }
    let mut out = [0u8; 20];
    for (i, v) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
    }
    out
}

/// Fill in the signature and checksum of a complete DEX buffer in place.
pub fn seal(dex: &mut [u8]) {
    if dex.len() < 32 {
        return;
    }
    let sig = sha1(&dex[32..]);
    dex[12..32].copy_from_slice(&sig);
    let sum = adler32(&dex[12..]);
    dex[8..12].copy_from_slice(&sum.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vectors() {
        assert_eq!(adler32(b"Wikipedia"), 0x11E60398);
        let d = sha1(b"abc");
        assert_eq!(d[..4], [0xA9, 0x99, 0x3E, 0x36]);
        assert_eq!(sha1(b"")[..4], [0xDA, 0x39, 0xA3, 0xEE]);
    }

    #[test]
    fn sha1_padding_boundaries() {
        fn hex(d: [u8; 20]) -> String {
            d.iter().map(|b| format!("{b:02x}")).collect()
        }
        // 55 bytes: padding fits in one block; 56 and 64 bytes: needs a second block.
        assert_eq!(hex(sha1(&[b'a'; 55])), "c1c8bbdc22796e28c0e15163d20899b65621d65a");
        assert_eq!(hex(sha1(&[b'a'; 56])), "c2db330f6083854c99d4b5bfb6e8f29f201be699");
        assert_eq!(hex(sha1(&[b'a'; 64])), "0098ba824b5c16427bd7a1122a5a442a25ec644d");
        assert_eq!(hex(sha1(&[b'a'; 1000])), "291e9a6c66994949b57ba5e650361e98fc36b1ba");
        assert_eq!(hex(sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")), "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    }
}
