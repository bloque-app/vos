//! Bundled VOS agent-runtime guest.
//!
//! `_start` is the stable clean-generation entry. The node supplies exactly
//! one canonical [`RuntimeWork`](vos::agent_sdk::RuntimeWork) and receives a
//! canonical [`RuntimeTransition`](vos::agent_sdk::RuntimeTransition). The
//! host persists the returned lane components without interpreting them.
//!
//! The opt-in `experimental-state-blocks` build instead accepts XSW2 external
//! work. Create, Install, ACK, non-yielding Invoke for non-Merge actors, and
//! read-only management inspection are implemented;
//! unsupported operations trap. It is built separately and is not bundled.

#[cfg(target_arch = "riscv64")]
mod guest {
    extern crate alloc;

    use core::arch::global_asm;

    #[cfg(not(feature = "experimental-state-blocks"))]
    use vos::agent_sdk::wire::CanonicalWire as _;

    const PVM_HALT_ADDR: u64 = 0xffff_0000;

    global_asm!(
        ".global _start",
        ".type _start, @function",
        "_start:",
        "j vos_agent_manage",
    );

    #[unsafe(no_mangle)]
    extern "C" fn vos_agent_manage(arguments: *const u8, arguments_len: usize) -> ! {
        // SAFETY: the standard PVM loader maps the complete argument window
        // read-only and supplies its base/length in a0/a1.
        let input = unsafe { core::slice::from_raw_parts(arguments, arguments_len) };
        // The standard build commits its public I/O to the work by reference:
        // the decoder has authenticated every availability preimage, so the
        // reference form binds the same bytes without hashing them again.
        #[cfg(not(feature = "experimental-state-blocks"))]
        let (output, public_io) = {
            let (transition, work) = vos::agent::wire::apply_standard_runtime_input_committed(input)
                .unwrap_or_else(|_| fail_closed());
            let output = transition.encode().unwrap_or_else(|_| fail_closed());
            let public_io =
                vos::agent_sdk::runtime_transition_public_io_by_reference(work, &output);
            (output, public_io)
        };
        #[cfg(feature = "experimental-state-blocks")]
        let output = vos::agent::wire::apply_standard_external_runtime_input(input)
            .unwrap_or_else(|_| fail_closed());
        #[cfg(feature = "experimental-state-blocks")]
        let public_io = vos::agent_sdk::runtime_transition_public_io(input, &output);
        halt_with_output_bound(&output, public_io.as_bytes())
    }

    fn halt_with_output_bound(output: &[u8], public_io: &[u8; 32]) -> ! {
        let mut words = [0u64; 4];
        for (word, bytes) in words.iter_mut().zip(public_io.chunks_exact(8)) {
            *word = u64::from_le_bytes(bytes.try_into().expect("exact hash word"));
        }
        // SAFETY: terminal standard-PVM halt. The output allocation remains
        // live, a0/a1 designate its exact bytes, and a2..a5 carry the public
        // commitment captured by the proof's final register state.
        unsafe {
            core::arch::asm!(
                "jr t0",
                in("a0") output.as_ptr() as u64,
                in("a1") output.len() as u64,
                in("a2") words[0],
                in("a3") words[1],
                in("a4") words[2],
                in("a5") words[3],
                in("t0") PVM_HALT_ADDR,
                options(noreturn),
            )
        }
    }

    fn fail_closed() -> ! {
        // An invalid management call is a deterministic guest trap, never an
        // empty or partially decoded success.
        unsafe { core::arch::asm!("ebreak", options(noreturn, nostack)) }
    }
}
