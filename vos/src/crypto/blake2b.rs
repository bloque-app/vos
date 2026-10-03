//! blake2b precompile.
//!
//! Public API is just `blake2b_hash::<N>(domain, parts)`. On
//! `target_arch = "riscv64"` (PVM actors) it streams blocks
//! through the `ECALL_BLAKE2B_COMPRESS` host trap so the host
//! does the actual work via the SIMD `blake2b_simd` impl. On
//! every other target (workers, host code, wasm guests) it
//! goes straight through `blake2b_simd` itself — same bytes
//! either path, no in-tree reference for actor consumers to
//! depend on.
//!
//! The PVM protocol ABI uses ID 100 with `φ[7]=h_ptr (64B)`,
//! `φ[8]=m_ptr (128B)`, `φ[9]=t_low`, and `φ[10]=f`. When the
//! proof chip is enabled, the same actor binary uses
//! the chip path with no source changes.
//!
//! **ABI limit**: only the low 64 bits of the blake2b byte
//! counter are passed (`t_low`). Inputs ≥ 2^64 bytes per hash
//! would silently lose the high half and produce a divergent
//! digest. Not a practical concern — matches `vos-pvm-precompiles`.

#[cfg(all(target_arch = "riscv64", not(feature = "agent-runtime")))]
use crate::abi::pvm::ecall::VOS_OBJECT_CAP;

/// Blake2b compression precompile. Its ID matches `vos-pvm-precompiles`,
/// so the same actor binary uses the constrained path during proving.
pub const ECALL_BLAKE2B_COMPRESS: u32 = 100;

/// High-level streaming hash. Produces an `OUT_LEN`-byte digest
/// of `domain || parts.concat()` matching
/// `blake2::Blake2b<UN>::default()` for output length `N` (no
/// key, fanout = 1, depth = 1, …).
///
/// On riscv64 actors this drives the host's blake2b per
/// 128-byte block via `ECALL_BLAKE2B_COMPRESS`. On every other
/// target it dispatches straight to `blake2b_simd`. No
/// in-tree reference impl is reachable from this path.
pub fn blake2b_hash<const OUT_LEN: usize>(domain: &[u8], parts: &[&[u8]]) -> [u8; OUT_LEN] {
    assert!(OUT_LEN >= 1 && OUT_LEN <= 64);
    #[cfg(all(target_arch = "riscv64", not(feature = "agent-runtime")))]
    {
        hash_via_ecall::<OUT_LEN>(domain, parts)
    }
    // The infrastructure runtime deliberately has no private outer-host ABI.
    // Hashing here is ordinary deterministic guest computation so its only
    // outer host calls are standard PVM machine management (9..=14).
    #[cfg(not(target_arch = "riscv64"))]
    {
        hash_via_simd::<OUT_LEN>(domain, parts)
    }
    // The runtime guest hashes with the protocol crate's riscv64em compression (or,
    // where its host serves it, the precompile): the same digest as `blake2b_simd`.
    #[cfg(all(target_arch = "riscv64", feature = "agent-runtime"))]
    {
        vos_protocol::blake2b::digest::<OUT_LEN>(domain, parts)
    }
}

/// Path: feed bytes through `blake2b_simd`'s state machine.
/// Used by every non-riscv64 caller — workers, host code,
/// wasm guests — and (transitively) by the host kernel
/// handler for the riscv64 ECALL.
#[cfg(not(target_arch = "riscv64"))]
fn hash_via_simd<const N: usize>(domain: &[u8], parts: &[&[u8]]) -> [u8; N] {
    let mut state = blake2b_simd::Params::new().hash_length(N).to_state();
    state.update(domain);
    for p in parts {
        state.update(p);
    }
    let h = state.finalize();
    let mut out = [0u8; N];
    out.copy_from_slice(h.as_bytes());
    out
}

/// Path: drive the host through per-block ecalls. The actor
/// keeps the blake2b chaining state on its stack; each 128B
/// message block is handed to the host with the current
/// counter and finalize flag.
#[cfg(all(target_arch = "riscv64", not(feature = "agent-runtime")))]
fn hash_via_ecall<const N: usize>(domain: &[u8], parts: &[&[u8]]) -> [u8; N] {
    // Parameter block: byte 0 = digest_length, byte 1 = key_length (0),
    // byte 2 = fanout (1), byte 3 = depth (1), bytes 4–7 = leaf_length (0).
    // h[0] = IV[0] ⊕ param_lo.
    let param_lo: u64 = 0x0101_0000 | (N as u64);
    let mut h_words = BLAKE2B_IV;
    h_words[0] ^= param_lo;

    let mut h = [0u8; 64];
    for i in 0..8 {
        h[i * 8..i * 8 + 8].copy_from_slice(&h_words[i].to_le_bytes());
    }

    let mut buf = [0u8; 128];
    let mut buf_len = 0usize;
    let mut t: u128 = 0;

    let feed =
        |bytes: &[u8], buf: &mut [u8; 128], buf_len: &mut usize, h: &mut [u8; 64], t: &mut u128| {
            let mut i = 0;
            while i < bytes.len() {
                // Compress only when the buffer is FULL and there's at
                // least one more byte to come — the final block needs
                // the finalize flag, set below.
                if *buf_len == 128 {
                    *t += 128;
                    ecall_compress(h, buf, *t, false);
                    *buf_len = 0;
                }
                let take = (128 - *buf_len).min(bytes.len() - i);
                buf[*buf_len..*buf_len + take].copy_from_slice(&bytes[i..i + take]);
                *buf_len += take;
                i += take;
            }
        };

    feed(domain, &mut buf, &mut buf_len, &mut h, &mut t);
    for p in parts {
        feed(p, &mut buf, &mut buf_len, &mut h, &mut t);
    }

    // Final block: zero-pad, set finalize flag.
    for i in buf_len..128 {
        buf[i] = 0;
    }
    t += buf_len as u128;
    ecall_compress(&mut h, &buf, t, true);

    let mut out = [0u8; N];
    out.copy_from_slice(&h[..N]);
    out
}

#[cfg(all(target_arch = "riscv64", not(feature = "agent-runtime")))]
fn ecall_compress(h: &mut [u8; 64], m: &[u8; 128], t: u128, f: bool) {
    let h_ptr = h.as_mut_ptr() as u64;
    let m_ptr = m.as_ptr() as u64;
    let t_low = t as u64;
    let f_flag: u64 = if f { 1 } else { 0 };
    // Keep this at the point where the borrowed buffers are live. Routing it
    // through the generic Rust wrapper lets LLVM treat the wrapper's `a0`
    // argument as the still-live allocation pointer after the protocol
    // boundary when the result is unused. PVM resumes by overwriting a0/a1,
    // so that optimization turns the following drop into a load through
    // HOST_OK. Declaring both late outputs here makes the suspension boundary
    // explicit to the code that owns the buffers. The outputs are deliberately
    // discarded: the proof tracer and refine-pure Task host implement this
    // precompile as a memory transform and leave the input registers in place;
    // the digest bytes written through `h_ptr` are the only portable result.
    unsafe {
        core::arch::asm!(
            "csrw 0x801, zero",
            "ecall",
            in("t0") ECALL_BLAKE2B_COMPRESS as u64,
            inlateout("a0") h_ptr => _,
            inlateout("a1") m_ptr => _,
            in("a2") t_low,
            in("a3") f_flag,
            in("a4") 0u64,
            in("a5") VOS_OBJECT_CAP,
            options(nostack),
        );
    }
}

// ── Host kernel handler: per-block compress for the ECALL ──
//
// `blake2b_simd`'s public API is whole-buffer streaming; it
// doesn't expose a single-block compress primitive. The host
// kernel handler in `vos::runtime` needs exactly that to
// service riscv64 actors' per-block ECALLs, so we keep a
// portable compress here as an internal impl detail. It's
// only reachable from inside the vos crate (`pub(crate)`)
// and never from actor code — actors only ever see
// `blake2b_hash`.

#[cfg(any(
    all(not(target_arch = "riscv64"), feature = "std"),
    feature = "agent-runtime"
))]
const BLAKE2B_IV: [u64; 8] = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
];

// On riscv64 the param-block init in `hash_via_ecall` needs
// the IV constants too.
#[cfg(all(target_arch = "riscv64", not(feature = "agent-runtime")))]
const BLAKE2B_IV: [u64; 8] = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
];

/// One blake2b compression: in-place update of `h` (8 × u64 LE
/// = 64 bytes) by mixing in message block `m` (16 × u64 LE =
/// 128 bytes) with byte counter `t` and finalize flag `f`.
///
/// Visible only inside the vos crate. The runtime's
/// ECALL_BLAKE2B_COMPRESS handler is the one and only caller;
/// every other path goes through `blake2b_hash` and uses
/// `blake2b_simd` directly.
#[cfg(any(
    all(not(target_arch = "riscv64"), feature = "std"),
    feature = "agent-runtime"
))]
pub(crate) fn host_compress_block(h: &mut [u8; 64], m: &[u8; 128], t: u128, f: bool) {
    let mut h_words = [0u64; 8];
    for i in 0..8 {
        h_words[i] = u64::from_le_bytes(h[i * 8..i * 8 + 8].try_into().unwrap());
    }
    // In the runtime guest, an actor's precompile call is served by the protocol crate's
    // riscv64em compression rather than the portable loop below.
    #[cfg(all(target_arch = "riscv64", feature = "agent-runtime"))]
    {
        unsafe { vos_protocol::blake2b::compress(&mut h_words, m.as_ptr(), t as u64, f) };
        for i in 0..8 {
            h[i * 8..i * 8 + 8].copy_from_slice(&h_words[i].to_le_bytes());
        }
        return;
    }
    #[allow(unreachable_code)]
    let mut m_words = [0u64; 16];
    for i in 0..16 {
        m_words[i] = u64::from_le_bytes(m[i * 8..i * 8 + 8].try_into().unwrap());
    }
    let result = compress_inner(&h_words, &m_words, t, f);
    for i in 0..8 {
        h[i * 8..i * 8 + 8].copy_from_slice(&result[i].to_le_bytes());
    }
}

#[cfg(any(
    all(not(target_arch = "riscv64"), feature = "std"),
    feature = "agent-runtime"
))]
fn compress_inner(h: &[u64; 8], m: &[u64; 16], t: u128, f: bool) -> [u64; 8] {
    const SIGMA: [[usize; 16]; 12] = [
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
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    ];
    fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, mx: u64, my: u64) {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(mx);
        v[d] = (v[d] ^ v[a]).rotate_right(32);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(24);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(my);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(63);
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&BLAKE2B_IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if f {
        v[14] = !v[14];
    }
    for s in &SIGMA {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    let mut result = [0u64; 8];
    for i in 0..8 {
        result[i] = h[i] ^ v[i] ^ v[i + 8];
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake2::digest::{
        Digest,
        consts::{U32, U64},
    };

    type Blake2b512 = blake2::Blake2b<U64>;
    type Blake2b256 = blake2::Blake2b<U32>;

    #[test]
    fn empty_input_matches_blake2_crate() {
        let ours: [u8; 64] = blake2b_hash(b"", &[]);
        let theirs = Blake2b512::new().finalize_reset();
        assert_eq!(&ours[..], &theirs[..]);
    }

    #[test]
    fn single_block_matches_blake2_crate() {
        let ours: [u8; 64] = blake2b_hash(b"vos/test", &[b"hello world"]);
        let mut h = Blake2b512::new();
        h.update(b"vos/test");
        h.update(b"hello world");
        assert_eq!(&ours[..], &h.finalize()[..]);
    }

    #[test]
    fn multi_block_matches_blake2_crate() {
        let part1 = vec![0xa5u8; 100];
        let part2 = vec![0x5au8; 100];
        let part3 = vec![0x33u8; 100];
        let ours: [u8; 64] = blake2b_hash(b"DOMAIN", &[&part1, &part2, &part3]);
        let mut h = Blake2b512::new();
        h.update(b"DOMAIN");
        h.update(&part1);
        h.update(&part2);
        h.update(&part3);
        assert_eq!(&ours[..], &h.finalize()[..]);
    }

    #[test]
    fn shorter_digest_matches_blake2_crate() {
        let ours: [u8; 32] = blake2b_hash(b"hash-test", &[b"a", b"b", b"c"]);
        let mut h = Blake2b256::new();
        h.update(b"hash-test");
        h.update(b"a");
        h.update(b"b");
        h.update(b"c");
        assert_eq!(&ours[..], &h.finalize()[..]);
    }

    #[test]
    fn exactly_one_block_boundary() {
        // 128 bytes total → exactly one compression block; finalize
        // flag must still fire on the trailing zero-padded block.
        let data = vec![0x42u8; 128];
        let ours: [u8; 64] = blake2b_hash(b"", &[&data]);
        let mut h = Blake2b512::new();
        h.update(&data);
        assert_eq!(&ours[..], &h.finalize()[..]);
    }

    #[test]
    fn small_digest_matches_blake2_crate_n2() {
        // `instance_service_id` uses blake2b_hash<2> to derive the
        // 16-bit local id from a name. host (blake2b_simd) and
        // PVM (per-block ECALL → host_compress_block) must produce
        // identical 2-byte outputs for the same input.
        use blake2::digest::consts::U2;
        type Blake2b16 = blake2::Blake2b<U2>;
        let ours: [u8; 2] = blake2b_hash(b"vos-instance-svc-id", &[&[0u8], b"bridge-b"]);
        let mut h = Blake2b16::new();
        h.update(b"vos-instance-svc-id");
        h.update([0u8]);
        h.update(b"bridge-b");
        let theirs = h.finalize();
        assert_eq!(
            &ours[..],
            &theirs[..],
            "blake2b_hash<2> diverges from blake2 reference for N=2"
        );
    }

    #[test]
    fn emulated_ecall_path_matches_blake2_n2() {
        // Emulate `hash_via_ecall<2>` on the host (uses host_compress_block
        // directly, the same primitive the ECALL handler delegates to).
        // If this matches the blake2 reference, then host and PVM are
        // algorithmically identical for the 2-byte-output path. If they
        // diverge from blake2_simd on PVM, the bug is elsewhere (e.g.
        // memory marshalling in the ECALL kernel handler).
        const N: usize = 2;
        let param_lo: u64 = 0x0101_0000 | (N as u64);
        let mut h_words = BLAKE2B_IV;
        h_words[0] ^= param_lo;
        let mut h = [0u8; 64];
        for i in 0..8 {
            h[i * 8..i * 8 + 8].copy_from_slice(&h_words[i].to_le_bytes());
        }
        // Single block of 22+1+8 = 31 bytes, zero-padded to 128.
        let domain = b"vos-instance-svc-id";
        let sep = b"\0";
        let payload = b"bridge-b";
        let mut buf = [0u8; 128];
        buf[..domain.len()].copy_from_slice(domain);
        buf[domain.len()..domain.len() + 1].copy_from_slice(sep);
        buf[domain.len() + 1..domain.len() + 1 + payload.len()].copy_from_slice(payload);
        let total = domain.len() + 1 + payload.len();
        host_compress_block(&mut h, &buf, total as u128, true);
        let emulated: [u8; 2] = [h[0], h[1]];

        let direct: [u8; 2] = blake2b_hash(b"vos-instance-svc-id", &[&[0u8], b"bridge-b"]);

        assert_eq!(
            emulated, direct,
            "emulated ECALL path diverges from direct blake2b_hash<2>",
        );
    }

    #[test]
    fn host_compress_matches_blake2_crate_one_block() {
        // The host kernel handler's per-block compress is what
        // riscv64 actors hit via the ECALL. Sanity-check it
        // against the blake2 reference for one finalized block.
        let param_lo: u64 = 0x0101_0000 | 64u64;
        let mut h_words = BLAKE2B_IV;
        h_words[0] ^= param_lo;
        let mut h = [0u8; 64];
        for i in 0..8 {
            h[i * 8..i * 8 + 8].copy_from_slice(&h_words[i].to_le_bytes());
        }
        let mut m = [0u8; 128];
        m[..11].copy_from_slice(b"hello world");
        host_compress_block(&mut h, &m, 11, true);

        let mut reference = Blake2b512::new();
        reference.update(b"hello world");
        assert_eq!(&h[..], &reference.finalize()[..]);
    }
}
