//! BLAKE2b for VOS identities and content references.
//!
//! Hosts use `blake2b_simd`. A standard PVM guest (`riscv64`) streams blocks through
//! one of two compressions with identical results:
//!
//! - by default, `blake2b_rv64em.S`: a register-scheduled compression for the
//!   13-register PVM. The PVM gas model charges a load or store 25 cycles on one of
//!   four ALU slots, so the schedule keeps ten of the sixteen working words in
//!   registers under an offline-optimal replacement over the fixed G order and runs
//!   the whole compression as one basic block. It is about half the gas of the
//!   portable `blake2b_simd` compression at the runtime's `opt-level = "s"`.
//! - with `outer-blake2b-precompile`, the VOS BLAKE2b precompile (`ecalli 100`), served
//!   natively by the outer Refine host. Only an infrastructure runtime whose host
//!   services that call may enable it.
//!
//! Whole blocks are compressed straight from the input; only the domain prefix and the
//! final partial block are buffered.

#[cfg(target_arch = "riscv64")]
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

/// The scheduled compression (`blake2b_rv64em.S`): a naked function, so its symbol is
/// Rust's own and two copies of this crate in one LTO module never collide.
#[cfg(all(target_arch = "riscv64", not(feature = "outer-blake2b-precompile")))]
#[unsafe(naked)]
unsafe extern "C" fn vos_protocol_blake2b_compress(h: *mut u64, m: *const u8, t: u64, last: u64) {
    core::arch::naked_asm!(include_str!("blake2b_rv64em.S"))
}

/// One BLAKE2b compression of the 128 bytes at `block` into `h`, with byte counter `t`
/// (inputs below 2^64 bytes) and the finalization flag.
///
/// # Safety
///
/// `block` must be readable for 128 bytes.
#[cfg(target_arch = "riscv64")]
#[inline(always)]
pub unsafe fn compress(h: &mut [u64; 8], block: *const u8, t: u64, last: bool) {
    #[cfg(not(feature = "outer-blake2b-precompile"))]
    unsafe {
        vos_protocol_blake2b_compress(h.as_mut_ptr(), block, t, last as u64)
    }
    #[cfg(feature = "outer-blake2b-precompile")]
    unsafe {
        // VOS precompile 100: a0 = h (64 bytes in/out), a1 = m (128 bytes), a2 = t,
        // a3 = f. A memory transform: the argument registers are preserved.
        core::arch::asm!(
            "csrw 0x801, zero",
            "ecall",
            in("t0") 100u64,
            inlateout("a0") h.as_mut_ptr() as u64 => _,
            inlateout("a1") block as u64 => _,
            in("a2") t,
            in("a3") last as u64,
            in("a4") 0u64,
            in("a5") 65u64,
            options(nostack),
        );
    }
}

/// BLAKE2b with an `N`-byte digest (no key) of `domain` followed by `parts`.
pub fn digest<const N: usize>(domain: &[u8], parts: &[&[u8]]) -> [u8; N] {
    #[cfg(not(target_arch = "riscv64"))]
    {
        let mut state = blake2b_simd::Params::new().hash_length(N).to_state();
        state.update(domain);
        for part in parts {
            state.update(part);
        }
        let hash = state.finalize();
        let mut output = [0; N];
        output.copy_from_slice(hash.as_bytes());
        output
    }
    #[cfg(target_arch = "riscv64")]
    {
        assert!(N >= 1 && N <= 64);
        let mut h = IV;
        h[0] ^= 0x0101_0000 ^ N as u64;
        let mut buffer = [0u8; 128];
        let mut buffered = 0usize;
        let mut counter = 0u64;
        for bytes in core::iter::once(domain).chain(parts.iter().copied()) {
            let mut rest = bytes;
            while !rest.is_empty() {
                if buffered == 128 {
                    counter = counter.wrapping_add(128);
                    unsafe { compress(&mut h, buffer.as_ptr(), counter, false) };
                    buffered = 0;
                }
                if buffered == 0 && rest.len() > 128 {
                    // A whole block with more input after it: compress it in place.
                    counter = counter.wrapping_add(128);
                    unsafe { compress(&mut h, rest.as_ptr(), counter, false) };
                    rest = &rest[128..];
                    continue;
                }
                let take = (128 - buffered).min(rest.len());
                buffer[buffered..buffered + take].copy_from_slice(&rest[..take]);
                buffered += take;
                rest = &rest[take..];
            }
        }
        buffer[buffered..].fill(0);
        counter = counter.wrapping_add(buffered as u64);
        unsafe { compress(&mut h, buffer.as_ptr(), counter, true) };
        let mut output = [0u8; N];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = (h[index / 8] >> (8 * (index % 8))) as u8;
        }
        output
    }
}
