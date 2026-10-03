//! Standard inner-machine host-call dispatcher for Refine programs.

use alloc::vec::Vec;

use crate::inner::{
    InnerError, InnerExit, InnerMachineIdentity, InnerMachineObservation, InnerMachines,
    InvokeState, MAX_INNER_MACHINES, PageMode, gas, host_call,
};
use crate::refine::{Invocation, Machine, MachineObservation, MemoryModel, RefineError};
use crate::{ExitReason, Gas, PVM_REGISTER_COUNT, PvmBackend};

/// Standard host result constants used by the inner-machine calls.
pub mod result {
    pub const OK: u64 = 0;
    pub const OOB: u64 = u64::MAX - 2;
    pub const WHO: u64 = u64::MAX - 3;
    pub const FULL: u64 = u64::MAX - 4;
    pub const HUH: u64 = u64::MAX - 8;
}

enum Dispatch {
    Continue,
    Exit(ExitReason),
    Backend,
}

/// Aggregate timings only; instruction observation would distort the path
/// being measured. Inner create includes decoding/preparation, and inner invoke
/// includes its frame/refund handling. Neither is a queue or quorum benchmark.
#[cfg(feature = "std")]
#[derive(Default)]
struct ExecutionTimings {
    outer_us: u64,
    inner_create_us: u64,
    inner_invoke_us: u64,
    host_us: u64,
    outer_slices: u64,
}

#[cfg(feature = "std")]
impl Drop for ExecutionTimings {
    fn drop(&mut self) {
        tracing::debug!(
            outer_execution_us = self.outer_us,
            inner_create_us = self.inner_create_us,
            inner_invoke_us = self.inner_invoke_us,
            host_dispatch_us = self.host_us,
            outer_slices = self.outer_slices,
            "Refine execution phases"
        );
    }
}

/// Stable identity of a machine participating in one nested Refine run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RefineMachineIdentity {
    Outer,
    Inner(InnerMachineIdentity),
}

/// Phase of an outer-runtime host-call dispatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefineHostPhase {
    Before,
    After,
}

/// Read-only nested execution events used by proof and diagnostic tracers.
///
/// `MachineEnter` exposes the exact code and sparse memory image before the
/// first instruction of that slice. `Instruction` is emitted by the sole
/// interpreter execution path. Host boundaries surround all state changes
/// made by calls 9 through 14, including an intervening inner invocation.
pub enum RefineObservation<'a> {
    MachineEnter {
        identity: RefineMachineIdentity,
        machine: &'a crate::interpreter::Interpreter,
    },
    Instruction {
        identity: RefineMachineIdentity,
        instruction: crate::interpreter::InstructionObservation<'a>,
    },
    MachineExit {
        identity: RefineMachineIdentity,
        exit: ExitReason,
        machine: &'a crate::interpreter::Interpreter,
    },
    HostCall {
        phase: RefineHostPhase,
        id: u64,
        outer: &'a Machine,
        inner: &'a InnerMachines,
    },
}

/// A standard outer PVM plus its per-invocation inner-machine dictionary.
pub struct RefineContext {
    outer: Machine,
    inner: InnerMachines,
}

impl RefineContext {
    pub fn load(program: &[u8], args: &[u8], gas: Gas) -> Result<Self, RefineError> {
        Self::load_with(program, args, gas, MemoryModel::Auto)
    }

    pub fn load_with(
        program: &[u8],
        args: &[u8],
        gas: Gas,
        model: MemoryModel,
    ) -> Result<Self, RefineError> {
        Ok(Self {
            outer: Machine::load_with(program, args, gas, model)?,
            inner: InnerMachines::new(),
        })
    }

    /// Explicit execution backend for both the outer runtime and its inner
    /// actors. Use [`Self::try_run`] (or [`Self::try_run_with_host`]) so backend
    /// failures remain host errors, never signed guest outcomes or retries on
    /// another backend.
    pub fn load_with_backend(
        program: &[u8],
        args: &[u8],
        gas: Gas,
        model: MemoryModel,
        backend: PvmBackend,
    ) -> Result<Self, RefineError> {
        let outer = Machine::load_with_backend(program, args, gas, model, backend)?;
        let inner = InnerMachines::with_backend(outer.backend());
        Ok(Self { outer, inner })
    }

    /// Reuse validated program preparation, never per-invocation machines.
    pub fn load_prepared(
        program: &crate::refine::PreparedProgram,
        args: &[u8],
        gas: Gas,
        model: MemoryModel,
    ) -> Result<Self, RefineError> {
        let outer = Machine::load_prepared(program, args, gas, model)?;
        let inner = InnerMachines::with_backend(outer.backend());
        Ok(Self { outer, inner })
    }

    /// Run the outer program, transparently servicing host calls 9 through
    /// 14. Other host calls are returned to the embedder unchanged.
    pub fn run(self) -> Invocation {
        self.run_with_host(|id, _| Err(ExitReason::HostCall(id)))
    }

    /// Execute the selected backend, preserving backend errors separately from
    /// a completed guest invocation. No execution fault triggers a fallback.
    pub fn try_run(self) -> Result<Invocation, RefineError> {
        self.try_run_with_host(|id, _| Err(ExitReason::HostCall(id)))
    }

    /// Service embedder-owned outer calls without restarting this execution or
    /// discarding its inner-machine dictionary. Built-in calls 9 through 14
    /// remain exclusively owned by Refine. Returning Ok advances past exactly
    /// the pending host call; an error stops at that call's counter.
    ///
    /// The embedder must admit the call, validate memory ranges and charge gas
    /// and its own I/O budgets before doing work. This is not a storage ABI or
    /// an authorization grant. The observed/proof runner does not yet support
    /// external handlers and must not silently substitute for this path.
    pub fn run_with_host(
        self,
        host: impl FnMut(u64, &mut Machine) -> Result<(), ExitReason>,
    ) -> Invocation {
        self.try_run_with_host(host)
            .expect("reference Refine execution; selected backends must use try_run_with_host")
    }

    /// Fallible counterpart of [`Self::run_with_host`] for a selected backend.
    pub fn try_run_with_host(
        mut self,
        mut host: impl FnMut(u64, &mut Machine) -> Result<(), ExitReason>,
    ) -> Result<Invocation, RefineError> {
        #[cfg(feature = "std")]
        let mut timings = ExecutionTimings::default();
        loop {
            #[cfg(feature = "std")]
            let started = std::time::Instant::now();
            let exit = self.outer.try_resume();
            #[cfg(feature = "std")]
            {
                timings.outer_us += started.elapsed().as_micros() as u64;
                timings.outer_slices += 1;
            }
            let exit = exit?;
            let ExitReason::HostCall(id) = exit else {
                return Ok(self.outer.finish(exit));
            };
            #[cfg(feature = "std")]
            let started = std::time::Instant::now();
            let dispatch = self.dispatch(id);
            #[cfg(feature = "std")]
            {
                let elapsed = started.elapsed().as_micros() as u64;
                match id {
                    id if id == u64::from(host_call::MACHINE) => timings.inner_create_us += elapsed,
                    id if id == u64::from(host_call::INVOKE) => timings.inner_invoke_us += elapsed,
                    _ => timings.host_us += elapsed,
                }
            }
            match dispatch {
                Dispatch::Continue => {}
                Dispatch::Exit(ExitReason::HostCall(call)) => {
                    #[cfg(feature = "std")]
                    let started = std::time::Instant::now();
                    let result = host(call, &mut self.outer);
                    #[cfg(feature = "std")]
                    {
                        timings.host_us += started.elapsed().as_micros() as u64;
                    }
                    if let Err(exit) = result {
                        return Ok(self.outer.finish(exit));
                    }
                }
                Dispatch::Exit(exit) => return Ok(self.outer.finish(exit)),
                Dispatch::Backend => return Err(RefineError::Backend),
            }
        }
    }

    /// Run the same nested Refine state machine as [`Self::run`] while
    /// reporting immutable machine and host-dispatch boundaries.
    ///
    /// This selects reference interpreter instructions, not new memory or
    /// preparation. A context loaded for the recompiler retains native backing
    /// and prepares its inner programs for that backend. Proof/snapshot callers
    /// must explicitly load `ForceInterpreter` with [`MemoryModel::Sparse`] to
    /// keep value-image inspection proportional to touched pages.
    pub fn run_observed(
        self,
        mut observer: impl for<'a> FnMut(RefineObservation<'a>),
    ) -> Invocation {
        self.run_with_observer(&mut observer)
    }

    fn run_with_observer(
        mut self,
        observer: &mut dyn for<'a> FnMut(RefineObservation<'a>),
    ) -> Invocation {
        loop {
            let exit = self.outer.resume_observed(|event| match event {
                MachineObservation::Enter(machine) => {
                    observer(RefineObservation::MachineEnter {
                        identity: RefineMachineIdentity::Outer,
                        machine,
                    });
                }
                MachineObservation::Instruction(instruction) => {
                    observer(RefineObservation::Instruction {
                        identity: RefineMachineIdentity::Outer,
                        instruction,
                    });
                }
            });
            observer(RefineObservation::MachineExit {
                identity: RefineMachineIdentity::Outer,
                exit: exit.clone(),
                machine: self.outer.interpreter(),
            });
            let ExitReason::HostCall(id) = exit else {
                return self.outer.finish(exit);
            };
            observer(RefineObservation::HostCall {
                phase: RefineHostPhase::Before,
                id,
                outer: &self.outer,
                inner: &self.inner,
            });
            let dispatch = self.dispatch_observed(id, observer);
            observer(RefineObservation::HostCall {
                phase: RefineHostPhase::After,
                id,
                outer: &self.outer,
                inner: &self.inner,
            });
            match dispatch {
                Dispatch::Continue => {}
                Dispatch::Exit(exit) => return self.outer.finish(exit),
                Dispatch::Backend => {
                    panic!("observed Refine execution requires the reference backend")
                }
            }
        }
    }

    pub fn inner(&self) -> &InnerMachines {
        &self.inner
    }

    fn dispatch(&mut self, id: u64) -> Dispatch {
        match id {
            value if value == u64::from(host_call::MACHINE) => self.machine(),
            value if value == u64::from(host_call::PEEK) => self.peek(),
            value if value == u64::from(host_call::POKE) => self.poke(),
            value if value == u64::from(host_call::PAGES) => self.pages(),
            value if value == u64::from(host_call::INVOKE) => self.invoke(None),
            value if value == u64::from(host_call::EXPUNGE) => self.expunge(),
            value if value == u64::from(host_call::BLAKE2B_COMPRESS) => self.blake2b_compress(),
            #[cfg(feature = "std")]
            value
                if (u64::from(host_call::CURVE_FIRST)..=u64::from(host_call::CURVE_LAST))
                    .contains(&value) =>
            {
                self.curve(value)
            }
            _ => Dispatch::Exit(ExitReason::HostCall(id)),
        }
    }

    fn dispatch_observed(
        &mut self,
        id: u64,
        observer: &mut dyn for<'a> FnMut(RefineObservation<'a>),
    ) -> Dispatch {
        match id {
            value if value == u64::from(host_call::MACHINE) => self.machine(),
            value if value == u64::from(host_call::PEEK) => self.peek(),
            value if value == u64::from(host_call::POKE) => self.poke(),
            value if value == u64::from(host_call::PAGES) => self.pages(),
            value if value == u64::from(host_call::INVOKE) => self.invoke(Some(observer)),
            value if value == u64::from(host_call::EXPUNGE) => self.expunge(),
            value if value == u64::from(host_call::BLAKE2B_COMPRESS) => self.blake2b_compress(),
            #[cfg(feature = "std")]
            value
                if (u64::from(host_call::CURVE_FIRST)..=u64::from(host_call::CURVE_LAST))
                    .contains(&value) =>
            {
                self.curve(value)
            }
            _ => Dispatch::Exit(ExitReason::HostCall(id)),
        }
    }

    fn charge(&mut self, amount: Gas) -> Result<(), Dispatch> {
        if self.outer.charge(amount) {
            Ok(())
        } else {
            Err(Dispatch::Exit(ExitReason::OutOfGas))
        }
    }

    fn machine(&mut self) -> Dispatch {
        let registers = *self.outer.registers();
        let (address, len, initial_pc) = (registers[7], registers[8], registers[9]);
        let cost = gas::MACHINE_BASE.saturating_add(gas::memory(gas::MACHINE_PER_KIB, len));
        if let Err(exit) = self.charge(cost) {
            return exit;
        }
        // Gray Paper v0.8.0 checks the invocation-wide machine limit before
        // inspecting the caller-supplied program range. At capacity even an
        // unreadable outer pointer therefore returns FULL, rather than
        // panicking while trying to read a program that cannot be installed.
        if self.inner.len() >= MAX_INNER_MACHINES {
            self.outer.registers_mut()[7] = result::FULL;
            return Dispatch::Continue;
        }
        let Some(program) = self.read_outer(address, len, false) else {
            return Dispatch::Exit(ExitReason::Panic);
        };
        let result = match u32::try_from(initial_pc) {
            Ok(pc) => match self.inner.create(&program, pc) {
                Ok(id) => id as u64,
                Err(InnerError::Full) => result::FULL,
                Err(InnerError::Backend) => return Dispatch::Backend,
                Err(_) => result::HUH,
            },
            Err(_) => result::HUH,
        };
        self.outer.registers_mut()[7] = result;
        Dispatch::Continue
    }

    fn peek(&mut self) -> Dispatch {
        let registers = *self.outer.registers();
        let (id, outer_address, inner_address, len) =
            (registers[7], registers[8], registers[9], registers[10]);
        let cost = gas::PEEK_BASE.saturating_add(gas::memory(gas::PEEK_PER_KIB, len));
        if let Err(exit) = self.charge(cost) {
            return exit;
        }
        let Some((outer_address, len)) = self.outer_range(outer_address, len, true) else {
            return Dispatch::Exit(ExitReason::Panic);
        };
        let status = match u32::try_from(id) {
            Ok(id) if self.inner.contains(id) => match (len == 0)
                .then_some(0)
                .or_else(|| u32::try_from(inner_address).ok())
            {
                Some(inner_address) => match self.inner.peek(id, inner_address, len) {
                    Ok(bytes) => {
                        if !self
                            .outer
                            .memory_mut()
                            .write_bytes_checked(outer_address, &bytes)
                        {
                            return Dispatch::Exit(ExitReason::Panic);
                        }
                        result::OK
                    }
                    Err(InnerError::Unknown) => result::WHO,
                    Err(InnerError::OutOfBounds) => result::OOB,
                    Err(InnerError::Backend) => return Dispatch::Backend,
                    Err(_) => result::HUH,
                },
                None => result::OOB,
            },
            _ => result::WHO,
        };
        self.outer.registers_mut()[7] = status;
        Dispatch::Continue
    }

    fn poke(&mut self) -> Dispatch {
        let registers = *self.outer.registers();
        let (id, outer_address, inner_address, len) =
            (registers[7], registers[8], registers[9], registers[10]);
        let cost = gas::POKE_BASE.saturating_add(gas::memory(gas::POKE_PER_KIB, len));
        if let Err(exit) = self.charge(cost) {
            return exit;
        }
        let Some(bytes) = self.read_outer(outer_address, len, false) else {
            return Dispatch::Exit(ExitReason::Panic);
        };
        let status = match u32::try_from(id) {
            Ok(id) if self.inner.contains(id) => match bytes
                .is_empty()
                .then_some(0)
                .or_else(|| u32::try_from(inner_address).ok())
            {
                Some(inner_address) => match self.inner.poke(id, inner_address, &bytes) {
                    Ok(()) => result::OK,
                    Err(InnerError::Unknown) => result::WHO,
                    Err(InnerError::OutOfBounds) => result::OOB,
                    Err(InnerError::Backend) => return Dispatch::Backend,
                    Err(_) => result::HUH,
                },
                None => result::OOB,
            },
            _ => result::WHO,
        };
        self.outer.registers_mut()[7] = status;
        Dispatch::Continue
    }

    fn pages(&mut self) -> Dispatch {
        let registers = *self.outer.registers();
        let (id, first, count, mode) = (registers[7], registers[8], registers[9], registers[10]);
        let cost = match mode {
            0 => {
                gas::PAGES_FREE_BASE.saturating_add(count.saturating_mul(gas::PAGES_FREE_PER_PAGE))
            }
            1 | 2 => gas::PAGES_ALLOC_BASE
                .saturating_add(count.saturating_mul(gas::PAGES_ALLOC_PER_PAGE)),
            3 | 4 => gas::PAGES_SET_MODE_BASE
                .saturating_add(count.saturating_mul(gas::PAGES_SET_MODE_PER_PAGE)),
            _ => gas::PAGES_INVALID,
        };
        if let Err(exit) = self.charge(cost) {
            return exit;
        }
        let status = match u32::try_from(id) {
            Ok(id) if self.inner.contains(id) => match (
                u32::try_from(first),
                u32::try_from(count),
                PageMode::try_from(mode),
            ) {
                (Ok(first), Ok(count), Ok(mode)) => {
                    match self.inner.pages(id, first, count, mode) {
                        Ok(()) => result::OK,
                        Err(InnerError::Unknown) => result::WHO,
                        Err(InnerError::Backend) => return Dispatch::Backend,
                        Err(_) => result::HUH,
                    }
                }
                _ => result::HUH,
            },
            _ => result::WHO,
        };
        self.outer.registers_mut()[7] = status;
        Dispatch::Continue
    }

    fn invoke(
        &mut self,
        observer: Option<&mut dyn for<'a> FnMut(RefineObservation<'a>)>,
    ) -> Dispatch {
        let registers = *self.outer.registers();
        let (id, frame_address) = (registers[7], registers[8]);
        let Some((frame_address, _)) = self.outer_range(frame_address, 112, true) else {
            if let Err(exit) = self.charge(gas::INVOKE_BASE) {
                return exit;
            }
            return Dispatch::Exit(ExitReason::Panic);
        };
        let mut frame = [0u8; 112];
        if !self
            .outer
            .memory()
            .read_bytes_checked(frame_address, &mut frame)
        {
            return Dispatch::Exit(ExitReason::Panic);
        }
        let requested_gas = u64::from_le_bytes(frame[..8].try_into().expect("eight bytes"));
        let total = gas::INVOKE_BASE.saturating_add(requested_gas);
        if let Err(exit) = self.charge(total) {
            return exit;
        }
        let mut inner_registers = [0u64; PVM_REGISTER_COUNT];
        for (i, register) in inner_registers.iter_mut().enumerate() {
            let start = 8 + i * 8;
            *register = u64::from_le_bytes(
                frame[start..start + 8]
                    .try_into()
                    .expect("register frame is complete"),
            );
        }
        let Ok(id) = u32::try_from(id) else {
            self.outer.registers_mut()[7] = result::WHO;
            return Dispatch::Continue;
        };
        let state = InvokeState {
            gas: requested_gas,
            registers: inner_registers,
        };
        let outcome = match observer {
            Some(observer) => self.inner.invoke_observed(id, state, |event| match event {
                InnerMachineObservation::Enter { identity, machine } => {
                    observer(RefineObservation::MachineEnter {
                        identity: RefineMachineIdentity::Inner(identity),
                        machine,
                    });
                }
                InnerMachineObservation::Instruction {
                    identity,
                    instruction,
                } => {
                    observer(RefineObservation::Instruction {
                        identity: RefineMachineIdentity::Inner(identity),
                        instruction,
                    });
                }
                InnerMachineObservation::Exit {
                    identity,
                    exit,
                    machine,
                } => {
                    observer(RefineObservation::MachineExit {
                        identity: RefineMachineIdentity::Inner(identity),
                        exit: inner_exit_reason(exit),
                        machine,
                    });
                }
            }),
            None => self.inner.invoke(id, state),
        };
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(InnerError::Unknown) => {
                self.outer.registers_mut()[7] = result::WHO;
                return Dispatch::Continue;
            }
            Err(InnerError::Backend) => return Dispatch::Backend,
            Err(_) => {
                self.outer.registers_mut()[7] = result::HUH;
                return Dispatch::Continue;
            }
        };
        self.outer.credit(outcome.state.gas);
        frame[..8].copy_from_slice(&outcome.state.gas.to_le_bytes());
        for (i, register) in outcome.state.registers.iter().enumerate() {
            let start = 8 + i * 8;
            frame[start..start + 8].copy_from_slice(&register.to_le_bytes());
        }
        if !self
            .outer
            .memory_mut()
            .write_bytes_checked(frame_address, &frame)
        {
            return Dispatch::Exit(ExitReason::Panic);
        }
        let (status, detail) = match outcome.exit {
            InnerExit::Halt => (0, None),
            InnerExit::Panic => (1, None),
            InnerExit::Fault(address) => (2, Some(address as u64)),
            InnerExit::Host(id) => (3, Some(id)),
            InnerExit::OutOfGas => (4, None),
        };
        let registers = self.outer.registers_mut();
        registers[7] = status;
        if let Some(detail) = detail {
            registers[8] = detail;
        }
        Dispatch::Continue
    }

    /// Precompile 100: φ7 = h (64 bytes, read-write), φ8 = m (128 bytes), φ9 = the low
    /// 64 bits of the byte counter, φ10 = the finalization flag. A memory transform:
    /// registers are unchanged. An inaccessible range panics, as `peek` does.
    fn blake2b_compress(&mut self) -> Dispatch {
        let registers = *self.outer.registers();
        if let Err(exit) = self.charge(gas::BLAKE2B_COMPRESS) {
            return exit;
        }
        let (Some(h_range), Some(m)) = (
            self.outer_range(registers[7], 64, true),
            self.read_outer(registers[8], 128, false),
        ) else {
            return Dispatch::Exit(ExitReason::Panic);
        };
        let Some(h) = self.read_outer(registers[7], 64, true) else {
            return Dispatch::Exit(ExitReason::Panic);
        };
        let mut state: [u8; 64] = h.try_into().expect("64 bytes");
        let block: [u8; 128] = m.try_into().expect("128 bytes");
        crate::blake2b::compress(&mut state, &block, registers[9], registers[10] != 0);
        if !self
            .outer
            .memory_mut()
            .write_bytes_checked(h_range.0, &state)
        {
            return Dispatch::Exit(ExitReason::Panic);
        }
        Dispatch::Continue
    }

    /// Precompiles 110-114, natively, as memory transforms with the shims'
    /// semantics (`vos_pvm_precompiles`): 110 `φ9 ← φ7 · φ8` (scalar, point),
    /// 111 `φ9 ← φ7 + φ8` (points), 112 `φ8 ← wide(φ7)` (64 bytes), 113 and
    /// 114 `φ9 ← φ7 × / + φ8 mod l`. A non-canonical scalar or an invalid
    /// point encoding gives the all-zero sentinel. Registers are unchanged.
    #[cfg(feature = "std")]
    fn curve(&mut self, id: u64) -> Dispatch {
        use curve25519_dalek::ristretto::CompressedRistretto;
        use curve25519_dalek::scalar::Scalar;

        let index = (id - u64::from(host_call::CURVE_FIRST)) as usize;
        if let Err(exit) = self.charge(gas::CURVE[index]) {
            return exit;
        }
        let registers = *self.outer.registers();
        let read32 = |this: &Self, address: u64| -> Option<[u8; 32]> {
            this.read_outer(address, 32, false)?.try_into().ok()
        };
        let scalar = |bytes: [u8; 32]| Scalar::from_canonical_bytes(bytes).into_option();
        let point = |bytes: [u8; 32]| {
            CompressedRistretto::from_slice(&bytes)
                .ok()
                .and_then(|compressed| compressed.decompress())
        };
        let result = match id {
            110 => read32(self, registers[7]).zip(read32(self, registers[8])).map(|(k, p)| {
                let out = match (scalar(k), point(p)) {
                    (Some(k), Some(p)) => (k * p).compress().to_bytes(),
                    _ => [0u8; 32],
                };
                (registers[9], out)
            }),
            111 => read32(self, registers[7]).zip(read32(self, registers[8])).map(|(p, q)| {
                let out = match (point(p), point(q)) {
                    (Some(p), Some(q)) => (p + q).compress().to_bytes(),
                    _ => [0u8; 32],
                };
                (registers[9], out)
            }),
            112 => self.read_outer(registers[7], 64, false).map(|wide| {
                let wide: [u8; 64] = wide.try_into().expect("64 bytes");
                (registers[8], Scalar::from_bytes_mod_order_wide(&wide).to_bytes())
            }),
            _ => read32(self, registers[7]).zip(read32(self, registers[8])).map(|(a, b)| {
                let out = match (scalar(a), scalar(b)) {
                    (Some(a), Some(b)) if id == 113 => (a * b).to_bytes(),
                    (Some(a), Some(b)) => (a + b).to_bytes(),
                    _ => [0u8; 32],
                };
                (registers[9], out)
            }),
        };
        let Some((output, bytes)) = result else {
            return Dispatch::Exit(ExitReason::Panic);
        };
        let Some((address, _)) = self.outer_range(output, 32, true) else {
            return Dispatch::Exit(ExitReason::Panic);
        };
        if !self.outer.memory_mut().write_bytes_checked(address, &bytes) {
            return Dispatch::Exit(ExitReason::Panic);
        }
        Dispatch::Continue
    }

    fn expunge(&mut self) -> Dispatch {
        if let Err(exit) = self.charge(gas::EXPUNGE) {
            return exit;
        }
        let id = self.outer.registers()[7];
        let result = u32::try_from(id)
            .ok()
            .and_then(|id| self.inner.expunge(id).ok())
            .map_or(result::WHO, u64::from);
        self.outer.registers_mut()[7] = result;
        Dispatch::Continue
    }

    fn read_outer(&self, address: u64, len: u64, writable: bool) -> Option<Vec<u8>> {
        let (address, len) = self.outer_range(address, len, writable)?;
        let mut bytes = alloc::vec![0u8; len];
        if self.outer.memory().read_bytes_checked(address, &mut bytes) {
            Some(bytes)
        } else {
            None
        }
    }

    fn outer_range(&self, address: u64, len: u64, writable: bool) -> Option<(u32, usize)> {
        let len = usize::try_from(len).ok()?;
        if len == 0 {
            return Some((0, 0));
        }
        let address = u32::try_from(address).ok()?;
        let accessible = if writable {
            self.outer.memory().is_writable(address, len)
        } else {
            self.outer.memory().is_readable(address, len)
        };
        accessible.then_some((address, len))
    }
}

/// Serve Gray Paper v0.8.0 Refine `historical_lookup` (call 7) for an embedder whose
/// preimage source has verified every preimage natively against its hash, as JAM's
/// state guarantees `h = H(d)` for the preimages it holds.
///
/// φ7 selects the service (`2^64 - 1`, this one, is the only one served), φ8 = h (a
/// 32-byte hash in memory), φ9 = o (output), φ10 = f (offset), φ11 = z (most bytes to
/// write). Charges `600 + 248 per KiB of z`, then writes `v[f..f + l]` and returns
/// `|v|` in φ7, or NONE if the preimage is unknown. An unreadable hash or unwritable
/// output panics.
pub fn serve_historical_lookup<'p>(
    machine: &mut Machine,
    preimage: impl FnOnce(&[u8; 32]) -> Option<&'p [u8]>,
) -> Result<(), ExitReason> {
    const NONE: u64 = u64::MAX;
    let registers = *machine.registers();
    let (service, h, o, f, z) = (
        registers[7],
        registers[8],
        registers[9],
        registers[10],
        registers[11],
    );
    let cost =
        gas::HISTORICAL_LOOKUP_BASE.saturating_add(gas::memory(gas::HISTORICAL_LOOKUP_PER_KIB, z));
    if !machine.charge(cost) {
        return Err(ExitReason::OutOfGas);
    }
    let mut hash = [0u8; 32];
    let readable = u32::try_from(h)
        .ok()
        .is_some_and(|h| machine.memory().read_bytes_checked(h, &mut hash));
    if !readable {
        return Err(ExitReason::Panic);
    }
    let value = (service == NONE).then(|| preimage(&hash)).flatten();
    let Some(value) = value else {
        machine.registers_mut()[7] = NONE;
        return Ok(());
    };
    let start = usize::try_from(f).unwrap_or(usize::MAX).min(value.len());
    let length = usize::try_from(z)
        .unwrap_or(usize::MAX)
        .min(value.len() - start);
    if length > 0 {
        let writable = u32::try_from(o).ok().is_some_and(|o| {
            machine
                .memory_mut()
                .write_bytes_checked(o, &value[start..start + length])
        });
        if !writable {
            return Err(ExitReason::Panic);
        }
    }
    machine.registers_mut()[7] = value.len() as u64;
    Ok(())
}

fn inner_exit_reason(exit: InnerExit) -> ExitReason {
    match exit {
        InnerExit::Halt => ExitReason::Halt,
        InnerExit::Panic => ExitReason::Panic,
        InnerExit::Fault(address) => ExitReason::PageFault(address),
        InnerExit::Host(id) => ExitReason::HostCall(id),
        InnerExit::OutOfGas => ExitReason::OutOfGas,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos_pvm_program::{CodeBlob, build_compact_code_blob};

    fn standard_program(args_code: &[u8], starts: &[usize]) -> Vec<u8> {
        standard_program_with_rw(args_code, starts, &[])
    }

    fn standard_program_with_rw(args_code: &[u8], starts: &[usize], rw_data: &[u8]) -> Vec<u8> {
        let mut packed = alloc::vec![0u8; args_code.len().div_ceil(8)];
        for &i in starts {
            packed[i / 8] |= 1 << (i % 8);
        }
        let mut code_blob = alloc::vec![0, 1, args_code.len() as u8];
        code_blob.extend_from_slice(args_code);
        code_blob.extend_from_slice(&packed);

        let mut blob = Vec::new();
        blob.extend_from_slice(&[0; 3]);
        blob.extend_from_slice(&(rw_data.len() as u32).to_le_bytes()[..3]);
        blob.extend_from_slice(&0u16.to_le_bytes());
        blob.extend_from_slice(&4096u32.to_le_bytes()[..3]);
        blob.extend_from_slice(rw_data);
        blob.extend_from_slice(&(code_blob.len() as u32).to_le_bytes());
        blob.extend_from_slice(&code_blob);
        blob
    }

    fn inner_program() -> Vec<u8> {
        // host(42), then trap.
        vec![0, 1, 3, 10, 42, 0, 0b0000_0101]
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum ObservedEvent {
        Enter(RefineMachineIdentity, u32),
        Instruction(RefineMachineIdentity, u32),
        Exit(RefineMachineIdentity, ExitReason),
        Host(RefineHostPhase, u64),
    }

    #[test]
    fn observed_nested_run_preserves_semantics_and_machine_identity() {
        const RW_BASE: u32 = 2 * crate::PVM_ZONE_SIZE;
        let mut frame = [0u8; 112];
        frame[..8].copy_from_slice(&100_000u64.to_le_bytes());
        let [b0, b1, b2, _] = RW_BASE.to_le_bytes();
        // machine(args), r8 <- RW_BASE, invoke(machine 0, frame), halt.
        let code = [10, 9, 51, 8, b0, b1, b2, 10, 13, 50, 0];
        let outer = standard_program_with_rw(&code, &[0, 2, 7, 9], &frame);
        let args = inner_program();
        let expected = RefineContext::load_with(&outer, &args, 1_000_000, MemoryModel::Sparse)
            .unwrap()
            .run();
        let prepared = crate::refine::PreparedProgram::new(&outer).unwrap();
        for _ in 0..2 {
            let reused =
                RefineContext::load_prepared(&prepared, &args, 1_000_000, MemoryModel::Sparse)
                    .unwrap()
                    .run();
            assert_eq!(reused.exit, expected.exit);
            assert_eq!(reused.pc, expected.pc);
            assert_eq!(reused.registers, expected.registers);
            assert_eq!(reused.gas_used, expected.gas_used);
            let mut cold_frame = [0; 112];
            let mut reused_frame = [0; 112];
            expected.memory().read_bytes(RW_BASE, &mut cold_frame);
            reused.memory().read_bytes(RW_BASE, &mut reused_frame);
            assert_eq!(reused_frame, cold_frame);
        }

        // Use real nested host dispatch with both machines recompiled. Exact
        // gas includes outer initialization, host charges and the inner refund.
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        {
            let native = crate::refine::PreparedProgram::new_with_backend(
                &outer,
                PvmBackend::ForceRecompiler,
            )
            .unwrap();
            for _ in 0..2 {
                let context =
                    RefineContext::load_prepared(&native, &args, 1_000_000, MemoryModel::Auto)
                        .unwrap();
                assert_eq!(context.outer.backend(), PvmBackend::ForceRecompiler);
                let actual = context.try_run().unwrap();
                assert_eq!(actual.exit, expected.exit);
                assert_eq!(actual.pc, expected.pc);
                assert_eq!(actual.registers, expected.registers);
                assert_eq!(actual.gas_used, expected.gas_used);
                let mut actual_frame = [0; 112];
                let mut expected_frame = [0; 112];
                actual.memory().read_bytes(RW_BASE, &mut actual_frame);
                expected.memory().read_bytes(RW_BASE, &mut expected_frame);
                assert_eq!(actual_frame, expected_frame);
            }
        }

        let mut events = Vec::new();
        let observed = RefineContext::load_with(&outer, &args, 1_000_000, MemoryModel::Sparse)
            .unwrap()
            .run_observed(|event| match event {
                RefineObservation::MachineEnter { identity, machine } => {
                    assert!(
                        machine.memory().allocated_bytes() < 16 << 20,
                        "observation must retain the sparse 4 GiB image"
                    );
                    events.push(ObservedEvent::Enter(identity, machine.pc));
                }
                RefineObservation::Instruction {
                    identity,
                    instruction,
                } => events.push(ObservedEvent::Instruction(identity, instruction.pc_before)),
                RefineObservation::MachineExit { identity, exit, .. } => {
                    events.push(ObservedEvent::Exit(identity, exit));
                }
                RefineObservation::HostCall { phase, id, .. } => {
                    events.push(ObservedEvent::Host(phase, id));
                }
            });

        assert_eq!(observed.exit, expected.exit);
        assert_eq!(observed.pc, expected.pc);
        assert_eq!(observed.registers, expected.registers);
        assert_eq!(observed.gas_used, expected.gas_used);
        assert_eq!(
            observed.output_bounded(crate::PVM_PAGE_SIZE as usize),
            expected.output_bounded(crate::PVM_PAGE_SIZE as usize)
        );
        let inner = RefineMachineIdentity::Inner(InnerMachineIdentity {
            slot: 0,
            generation: 0,
        });
        assert!(events.contains(&ObservedEvent::Enter(inner, 0)));
        assert!(events.contains(&ObservedEvent::Instruction(inner, 0)));
        assert!(events.contains(&ObservedEvent::Exit(inner, ExitReason::HostCall(42))));
        assert_eq!(
            events
                .iter()
                .filter_map(|event| match event {
                    ObservedEvent::Enter(RefineMachineIdentity::Outer, pc) => Some(*pc),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            [0, 2, 9],
            "each outer trace slice starts after the prior handled call"
        );
        assert_eq!(
            events
                .iter()
                .filter_map(|event| match event {
                    ObservedEvent::Host(phase, id) => Some((*phase, *id)),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            [
                (RefineHostPhase::Before, 9),
                (RefineHostPhase::After, 9),
                (RefineHostPhase::Before, 13),
                (RefineHostPhase::After, 13),
            ]
        );
    }

    #[test]
    fn outer_machine_create_and_expunge_run_to_halt() {
        // machine(9), expunge(14), jump_ind r0 to the halt address.
        let outer = standard_program(&[10, 9, 10, 14, 50, 0], &[0, 2, 4]);
        let invocation = RefineContext::load(&outer, &inner_program(), 1_000_000)
            .unwrap()
            .run();
        assert_eq!(invocation.exit, ExitReason::Halt);
        assert_eq!(invocation.registers[7], 0, "expunge returned entry PC");
        assert!(invocation.gas_used > 0);
    }

    #[test]
    fn machine_rejects_runtime_only_opcode_three_as_huh() {
        let runtime_only = build_compact_code_blob(&CodeBlob {
            jump_table: Vec::new(),
            code: vec![3],
            bitmask: vec![1],
        })
        .unwrap();
        // machine(9), then jump_ind r0 to the halt address.
        let outer = standard_program(&[10, 9, 50, 0], &[0, 2]);
        let invocation = RefineContext::load(&outer, &runtime_only, 1_000_000)
            .unwrap()
            .run();

        assert_eq!(invocation.exit, ExitReason::Halt);
        assert_eq!(invocation.registers[7], result::HUH);
    }

    #[test]
    fn unknown_host_call_is_returned_to_the_embedder() {
        let outer = standard_program(&[51, 2, 9, 10, 77, 0], &[0, 3, 5]);
        let invocation = RefineContext::load(&outer, &[], 1_000_000).unwrap().run();
        assert_eq!(invocation.exit, ExitReason::HostCall(77));
        assert_eq!(invocation.pc, 3, "unknown host call stays on its cause");
        assert_eq!(invocation.registers[2], 9);
    }

    #[test]
    fn embedder_calls_resume_without_reexecuting_prior_instructions() {
        // r2 <- 9; external(77); external(77); halt.
        let outer = standard_program(&[51, 2, 9, 10, 77, 10, 77, 50, 0], &[0, 3, 5, 7]);
        let mut calls = 0;
        let invocation = RefineContext::load(&outer, &[], 1_000_000)
            .unwrap()
            .run_with_host(|id, machine| {
                assert_eq!(id, 77);
                calls += 1;
                if !machine.charge(50) {
                    return Err(ExitReason::OutOfGas);
                }
                machine.registers_mut()[2] += 1;
                Ok(())
            });
        assert_eq!(calls, 2);
        assert_eq!(invocation.exit, ExitReason::Halt);
        assert_eq!(invocation.registers[2], 11);
        assert!(invocation.gas_used >= 100);
    }

    #[test]
    fn embedder_refusal_keeps_exact_call_counter_and_stops_execution() {
        let outer = standard_program(&[51, 2, 9, 10, 77, 10, 77, 50, 0], &[0, 3, 5, 7]);
        let mut calls = 0;
        let invocation = RefineContext::load(&outer, &[], 1_000_000)
            .unwrap()
            .run_with_host(|id, _| {
                calls += 1;
                Err(ExitReason::HostCall(id))
            });
        assert_eq!(calls, 1);
        assert_eq!(invocation.exit, ExitReason::HostCall(77));
        assert_eq!(invocation.pc, 3);
        assert_eq!(invocation.registers[2], 9);
    }

    #[test]
    fn embedder_calls_preserve_inner_machines_and_cannot_intercept_builtins() {
        const RW_BASE: u32 = 2 * crate::PVM_ZONE_SIZE;
        let mut frame = [0u8; 112];
        frame[..8].copy_from_slice(&100_000u64.to_le_bytes());
        let [b0, b1, b2, _] = RW_BASE.to_le_bytes();
        let baseline = standard_program_with_rw(
            &[10, 9, 51, 8, b0, b1, b2, 10, 13, 50, 0],
            &[0, 2, 7, 9],
            &frame,
        );
        let expected = RefineContext::load(&baseline, &inner_program(), 1_000_000)
            .unwrap()
            .run();
        let outer = standard_program_with_rw(
            &[10, 9, 10, 77, 51, 8, b0, b1, b2, 10, 13, 10, 77, 50, 0],
            &[0, 2, 4, 9, 11, 13],
            &frame,
        );
        let mut calls = 0;
        let invocation = RefineContext::load(&outer, &inner_program(), 1_000_000)
            .unwrap()
            .run_with_host(|id, _| {
                assert_eq!(id, 77);
                calls += 1;
                Ok(())
            });
        assert_eq!(calls, 2);
        assert_eq!(expected.exit, ExitReason::Halt);
        assert_eq!(invocation.exit, expected.exit);
        let mut expected_frame = [0; 112];
        let mut actual_frame = [0; 112];
        expected.memory().read_bytes(RW_BASE, &mut expected_frame);
        invocation.memory().read_bytes(RW_BASE, &mut actual_frame);
        assert_eq!(actual_frame, expected_frame);
        assert_ne!(
            actual_frame, frame,
            "the retained inner machine must actually execute"
        );
    }

    #[test]
    fn failed_host_dispatch_does_not_advance_the_outer_counter() {
        // Load an unmapped source range, then call machine(9) at pc 8.
        // Dispatch fails before Continue, so the owner must retain that
        // ecalli counter rather than exposing its pc-10 successor.
        let outer = standard_program(&[51, 7, 0, 0, 3, 51, 8, 1, 10, 9, 0], &[0, 5, 8, 10]);
        let invocation = RefineContext::load(&outer, &[], 1_000_000).unwrap().run();
        assert_eq!(invocation.exit, ExitReason::Panic);
        assert_eq!(invocation.pc, 8);
    }

    #[test]
    fn sixty_third_machine_is_admitted_and_sixty_fourth_is_full_before_read() {
        let outer = standard_program(&[0], &[0]);
        let mut context = RefineContext::load(&outer, &[], 10_000_000).unwrap();
        let inner = inner_program();
        for expected in 0..MAX_INNER_MACHINES as u32 {
            assert_eq!(context.inner.create(&inner, 0), Ok(expected));
        }
        assert_eq!(context.inner.len(), 63);
        let registers = context.outer.registers_mut();
        registers[7] = u64::MAX;
        registers[8] = 1;
        registers[9] = 0;

        assert!(matches!(context.machine(), Dispatch::Continue));
        assert_eq!(context.outer.registers()[7], result::FULL);
    }

    #[test]
    fn peek_and_poke_report_unknown_machine_before_inner_address_overflow() {
        let outer = standard_program(&[0], &[0]);
        let mut context = RefineContext::load(&outer, &[], 10_000_000).unwrap();
        let outer_address = context.outer.registers()[1] - 1;

        for operation in [RefineContext::peek, RefineContext::poke] {
            let registers = context.outer.registers_mut();
            registers[7] = 0; // no machine zero exists
            registers[8] = outer_address;
            registers[9] = u64::MAX;
            registers[10] = 1;

            assert!(matches!(operation(&mut context), Dispatch::Continue));
            assert_eq!(context.outer.registers()[7], result::WHO);
        }
    }

    #[test]
    fn peek_and_poke_accept_empty_inner_range_above_u32_max() {
        let outer = standard_program(&[0], &[0]);
        let mut context = RefineContext::load(&outer, &[], 10_000_000).unwrap();
        let id = context.inner.create(&inner_program(), 0).unwrap();

        for operation in [RefineContext::peek, RefineContext::poke] {
            let registers = context.outer.registers_mut();
            registers[7] = u64::from(id);
            registers[8] = u64::MAX;
            registers[9] = u64::from(u32::MAX) + 1;
            registers[10] = 0;

            assert!(matches!(operation(&mut context), Dispatch::Continue));
            assert_eq!(context.outer.registers()[7], result::OK);
        }
    }
}
