//! The BLAKE2b compression behind the VOS precompile (`ecalli 100`) that Refine serves
//! to its outer program: one 12-round compression, as RFC 7693 defines it.

const IV: [u64; 8] = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// Compress the 128-byte block `m` into the 64-byte little-endian state `h`, with the
/// low 64 bits of the byte counter `t` and the finalization flag `last`.
pub fn compress(h: &mut [u8; 64], m: &[u8; 128], t: u64, last: bool) {
    let mut v = [0u64; 16];
    let mut w = [0u64; 16];
    for i in 0..8 {
        v[i] = u64::from_le_bytes(h[8 * i..8 * i + 8].try_into().expect("8 bytes"));
    }
    for i in 0..16 {
        w[i] = u64::from_le_bytes(m[8 * i..8 * i + 8].try_into().expect("8 bytes"));
    }
    let start = v;
    v[8..].copy_from_slice(&IV);
    v[12] ^= t;
    if last {
        v[14] = !v[14];
    }
    let mut g = |v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64| {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
        v[d] = (v[d] ^ v[a]).rotate_right(32);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(24);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(63);
    };
    for round in 0..12 {
        let s = &SIGMA[round % 10];
        g(&mut v, 0, 4, 8, 12, w[s[0]], w[s[1]]);
        g(&mut v, 1, 5, 9, 13, w[s[2]], w[s[3]]);
        g(&mut v, 2, 6, 10, 14, w[s[4]], w[s[5]]);
        g(&mut v, 3, 7, 11, 15, w[s[6]], w[s[7]]);
        g(&mut v, 0, 5, 10, 15, w[s[8]], w[s[9]]);
        g(&mut v, 1, 6, 11, 12, w[s[10]], w[s[11]]);
        g(&mut v, 2, 7, 8, 13, w[s[12]], w[s[13]]);
        g(&mut v, 3, 4, 9, 14, w[s[14]], w[s[15]]);
    }
    for i in 0..8 {
        let word = start[i] ^ v[i] ^ v[i + 8];
        h[8 * i..8 * i + 8].copy_from_slice(&word.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BLAKE2b-512("abc"), RFC 7693 appendix A, through one finalizing compression.
    #[test]
    fn rfc7693_abc() {
        let mut h = [0u8; 64];
        for i in 0..8 {
            let mut word = IV[i];
            if i == 0 {
                word ^= 0x0101_0040;
            }
            h[8 * i..8 * i + 8].copy_from_slice(&word.to_le_bytes());
        }
        let mut m = [0u8; 128];
        m[..3].copy_from_slice(b"abc");
        compress(&mut h, &m, 3, true);
        assert_eq!(h[..8], [0xBA, 0x80, 0xA5, 0x3F, 0x98, 0x1C, 0x4D, 0x0D]);
    }
}
