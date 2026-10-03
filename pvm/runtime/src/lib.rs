//! Join-Accumulate VM (JAVM) — PVM implementation for JAM (Appendix A).
//!
//! The PVM is a register-based virtual machine with:
//! - 13 general-purpose 64-bit registers (φ₀..φ₁₂)
//! - 32-bit pageable memory address space
//! - Gas metering for bounded execution
//! - Host-call interface for system interactions

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

pub mod args;
pub mod backend;
#[cfg(feature = "std")]
pub mod backing;
pub mod blake2b;
pub mod cap;
pub mod gas_cost;
pub mod gas_sim;
pub mod inner;
pub mod instruction;
pub mod interpreter;
#[cfg(feature = "std")]
pub mod kernel;
pub mod program;
pub mod refine;
pub mod refine_host;
#[cfg(feature = "std")]
pub mod snapshot;
pub mod spi;
pub mod vm_pool;
// Real JIT recompiler on Linux x86-64.
#[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
pub mod recompiler;

pub use backend::PvmBackend;
pub use interpreter::Interpreter;
#[cfg(feature = "std")]
pub use kernel::CodeCache;

/// Standard PVM specification version implemented by the portable path.
pub const STANDARD_PVM_SPEC_VERSION: &str = "0.8.0";

/// Exact upstream specification commit used for the standard PVM contract.
pub const STANDARD_PVM_SPEC_REVISION: &str = "07f041dabd073f9018b418e9ee72e79dd2185401";

// --- PVM types ---

/// Exit reason for PVM execution (ε values, eq A.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitReason {
    /// ∎: Normal halt.
    Halt,
    /// Deliberate trap (opcode 0) in the transitional capability/JAR profile.
    /// Standard Gray Paper v0.8 execution classifies opcode 0 as [`Self::Panic`].
    Trap,
    /// ☇: Panic / runtime error (bad djump, invalid opcode).
    Panic,
    /// ∞: Out of gas.
    OutOfGas,
    /// ×: Page fault at the given page address.
    PageFault(u32),
    /// h̵: Host-call with the given identifier (ecalli).
    HostCall(u64),
    /// Management op or dynamic CALL (ecall). φ\[11\]=op, φ\[12\]=subject|object.
    Ecall,
}

// --- PVM constants (Gray Paper Appendix A / I.4.4) ---

/// Gas type: NG = N_{2^64} (eq 4.23).
pub type Gas = u64;

/// A host call that has been surfaced but not yet acknowledged by the host.
///
/// Standard execution keeps the architectural instruction counter at
/// `cause_pc` until the host explicitly commits the call.  `resume_pc` is the
/// sequential successor selected by the decoded `ecalli`; keeping both values
/// is necessary for deterministic retry and portable continuations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingHostCall {
    pub id: u64,
    pub cause_pc: u32,
    pub resume_pc: u32,
}

/// ZP = 2^12 = 4096: PVM memory page size.
pub const PVM_PAGE_SIZE: u32 = 1 << 12;

/// The dynamic-jump halt address: 2^32 − 2^16 (GP eq A.18).
///
/// A djump to this address is a normal halt (∎). The kernel initializes the
/// root VM's ω\[0\] (RA) to it, so `ret` from an entry point halts the VM.
pub const PVM_HALT_ADDR: u64 = (1 << 32) - (1 << 16);

/// ISA profile the VM executes under.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum IsaMode {
    /// Full jar surface: opcode 3 (`Ecall`) dispatches capability-kernel
    /// management ops / dynamic CALL.
    #[default]
    Jar,
    /// Graypaper-strict: opcode 3 is not a valid instruction and panics
    /// when executed (GP conformance; the cap kernel is a jar extension).
    Conformance,
}

/// Gas metering model the VM charges under (the gas analogue of [`IsaMode`]).
///
/// The historical `gp072_*` vectors use flat per-instruction charging. Gray
/// Paper v0.8.0 and the capability runtime charge a whole pipeline-simulated
/// basic block at entry. Only the interpreter implements both; the recompiler
/// and capability kernel always execute a block model.
///
/// The interpreter's pre-decoded instruction stream caches per-instruction
/// gas labels, so the model is installed via
/// [`Interpreter::set_gas_model`], which re-derives the cached labels —
/// never by mutating a field directly. Cached
/// [`backend::InterpreterProgram`]s (CODE caps / the kernel's `CodeCache`)
/// always carry block-model labels.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum GasModel {
    /// A per-basic-block pipeline cost, charged once on gas-block entry
    /// ({0} ∪ post-terminator). Under [`IsaMode::Conformance`] this is the
    /// exact Gray Paper v0.8.0 ROB model; [`IsaMode::Jar`] retains the frozen
    /// capability-manifest gas contract.
    #[default]
    BlockPipeline,
    /// GP 0.7.2: a flat 1 gas per instruction. The out-of-gas check
    /// precedes execution (a VM with 0 gas exits `OutOfGas` before doing
    /// anything, even at an invalid instruction position), and the exiting
    /// instruction — halt, trap, panic, fault, or host call — is itself
    /// charged. Mirrors the Lean oracle `Jar.JAVM.run` (per-instruction
    /// branch) exactly.
    PerInstruction,
}

/// ZI = 2^24: Standard PVM program initialization input data size.
pub const PVM_INIT_INPUT_SIZE: u32 = 1 << 24;

/// ZZ = 2^16 = 65536: Standard PVM program initialization zone size.
pub const PVM_ZONE_SIZE: u32 = 1 << 16;

/// Number of registers in the PVM.
pub const PVM_REGISTER_COUNT: usize = 13;

/// Gas cost per page for initial memory allocation and retype.
pub const GAS_PER_PAGE: u64 = 1500;

/// Fixed load/store latency from Gray Paper v0.8.0 equation A.58.
pub const STANDARD_MEM_CYCLES: u8 = 25;

/// Compute the capability/JAR-profile memory tier from accessible pages.
///
/// This tier is a VOS service-runtime extension. Standard Gray Paper v0.8.0
/// execution must use [`STANDARD_MEM_CYCLES`] regardless of program size.
pub fn compute_mem_cycles(total_pages: u32) -> u8 {
    match total_pages {
        0..=2048 => 25,     // ≤ 8MB: L2 baseline
        2049..=8192 => 50,  // ≤ 32MB: L3
        8193..=65536 => 75, // ≤ 256MB: DRAM
        _ => 100,           // > 256MB: DRAM saturated
    }
}

/// Select the profile-bound memory latency used by block-gas metering.
///
/// Keeping this normalization at construction and compilation boundaries
/// prevents a caller-provided JAR tier from changing standard v0.8.0 gas.
#[inline]
pub const fn mem_cycles_for_mode(jar_mem_cycles: u8, isa_mode: IsaMode) -> u8 {
    match isa_mode {
        IsaMode::Jar => jar_mem_cycles,
        IsaMode::Conformance => STANDARD_MEM_CYCLES,
    }
}
