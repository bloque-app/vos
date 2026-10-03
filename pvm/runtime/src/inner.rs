//! Standard Refine inner-machine management.
//!
//! This module implements the portable `machine`, `peek`, `poke`, `pages`,
//! `invoke`, and `expunge` substrate from Gray Paper v0.8.0. It has no
//! capability-kernel dependency and is available in `no_std` builds.

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use crate::backend::{PreparedExecution, PvmBackend};
use crate::interpreter::{Interpreter, PERM_NONE, PERM_RO, PERM_RW};
use crate::spi::deblob;
use crate::{ExitReason, Gas, IsaMode, PVM_PAGE_SIZE, PVM_REGISTER_COUNT};

/// Maximum live inner machines in one Refine invocation.
pub const MAX_INNER_MACHINES: usize = 63;

/// Number of pages in the 32-bit PVM address space.
pub const INNER_ADDRESS_PAGES: usize = (1u64 << 32) as usize / PVM_PAGE_SIZE as usize;

/// The first page an inner machine may map.
pub const INNER_FIRST_MAPPABLE_PAGE: u32 = 16;

/// Only immutable preparation is retained between invocations: one exact
/// compact program per worker thread, with a bounded admission size. This is
/// not a program limit; larger programs continue through uncached preparation.
#[cfg(feature = "std")]
const MAX_CACHED_INNER_PROGRAM_BYTES: usize = 4 << 20;

#[cfg(feature = "std")]
struct CachedInnerPreparation {
    program: Vec<u8>,
    backend: PvmBackend,
    execution: PreparedExecution,
}

#[cfg(feature = "std")]
std::thread_local! {
    static INNER_PREPARATION: core::cell::RefCell<Option<CachedInnerPreparation>> =
        const { core::cell::RefCell::new(None) };
}

fn prepare_inner_program(
    program_blob: &[u8],
    program: &crate::program::ParsedCodeBlob,
    backend: PvmBackend,
) -> Result<PreparedExecution, InnerError> {
    let prepare = || {
        PreparedExecution::new_standard(
            &program.code,
            &program.bitmask,
            &program.jump_table,
            backend,
        )
        .map_err(|_| InnerError::Backend)
    };
    #[cfg(feature = "std")]
    if program_blob.len() <= MAX_CACHED_INNER_PROGRAM_BYTES
        // Do not cache the environment-dependent Default selection. Refine
        // contexts pass their already resolved outer backend to this layer.
        && backend != PvmBackend::Default
    {
        return INNER_PREPARATION.with(|cached| {
            if let Some(entry) = cached.borrow().as_ref()
                && entry.backend == backend
                && entry.program == program_blob
            {
                return Ok(entry.execution.clone());
            }
            let execution = prepare()?;
            *cached.borrow_mut() = Some(CachedInnerPreparation {
                program: program_blob.to_vec(),
                backend,
                execution: execution.clone(),
            });
            Ok(execution)
        });
    }
    #[cfg(not(feature = "std"))]
    let _ = program_blob;
    prepare()
}

/// Stable host-call identifiers for the standard inner-machine surface.
pub mod host_call {
    pub const MACHINE: u32 = 9;
    pub const PEEK: u32 = 10;
    pub const POKE: u32 = 11;
    pub const PAGES: u32 = 12;
    pub const INVOKE: u32 = 13;
    pub const EXPUNGE: u32 = 14;
}

/// v0.8.0 host-call gas constants.
pub mod gas {
    pub const MACHINE_BASE: u64 = 1_862;
    pub const MACHINE_PER_KIB: u64 = 112;
    pub const PEEK_BASE: u64 = 377;
    pub const PEEK_PER_KIB: u64 = 336;
    pub const POKE_BASE: u64 = 297;
    pub const POKE_PER_KIB: u64 = 224;
    pub const PAGES_FREE_BASE: u64 = 212;
    pub const PAGES_FREE_PER_PAGE: u64 = 118;
    pub const PAGES_ALLOC_BASE: u64 = 275;
    pub const PAGES_ALLOC_PER_PAGE: u64 = 121;
    pub const PAGES_SET_MODE_BASE: u64 = 130;
    pub const PAGES_SET_MODE_PER_PAGE: u64 = 29;
    pub const PAGES_INVALID: u64 = 80;
    pub const INVOKE_BASE: u64 = 968;
    pub const EXPUNGE: u64 = 335;

    /// The standard memory-sized gas function, `ceil(rate * bytes / 1024)`.
    pub const fn memory(rate: u64, bytes: u64) -> u64 {
        let Some(product) = rate.checked_mul(bytes) else {
            return u64::MAX;
        };
        let Some(rounded) = product.checked_add(1023) else {
            return u64::MAX;
        };
        rounded / 1024
    }
}

/// Result-code-shaped failures from an inner-machine operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InnerError {
    /// The 63-machine invocation limit has been reached.
    Full,
    /// The supplied program or page operation is invalid.
    Invalid,
    /// The machine index does not exist.
    Unknown,
    /// The requested inner-memory range is not accessible.
    OutOfBounds,
    /// The selected host backend could not prepare or execute the machine.
    /// This is not a guest result and must not be translated to HUH.
    Backend,
}

/// Page mutation requested through the standard `pages` operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PageMode {
    Free = 0,
    AllocateReadOnly = 1,
    AllocateReadWrite = 2,
    SetReadOnly = 3,
    SetReadWrite = 4,
}

impl TryFrom<u64> for PageMode {
    type Error = InnerError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Free),
            1 => Ok(Self::AllocateReadOnly),
            2 => Ok(Self::AllocateReadWrite),
            3 => Ok(Self::SetReadOnly),
            4 => Ok(Self::SetReadWrite),
            _ => Err(InnerError::Invalid),
        }
    }
}

/// Register and gas state passed through the standard `invoke` operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvokeState {
    pub gas: Gas,
    pub registers: [u64; PVM_REGISTER_COUNT],
}

/// Why an inner invocation returned to its outer machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InnerExit {
    Halt,
    Panic,
    Fault(u32),
    Host(u64),
    OutOfGas,
}

/// Result of invoking one inner machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvokeOutcome {
    pub exit: InnerExit,
    pub state: InvokeState,
}

/// Invocation-unique identity of one inner machine.
///
/// Slots are deliberately reusable after `expunge`; `generation` is not.
/// Proof traces use the pair so two different programs that occupied the
/// same dictionary slot can never be spliced together.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct InnerMachineIdentity {
    pub slot: u32,
    pub generation: u64,
}

/// Immutable dictionary view used by nested proof boundary tracers.
/// `machine` is absent until the lazily-created inner interpreter is first
/// needed; the canonical compact `program` and entry counter remain available
/// in either state.
pub struct InnerMachineView<'a> {
    pub identity: InnerMachineIdentity,
    pub program: &'a [u8],
    pub initial_pc: u32,
    pub machine: Option<&'a Interpreter>,
}

/// Read-only events emitted while an inner machine is invoked.
pub enum InnerMachineObservation<'a> {
    Enter {
        identity: InnerMachineIdentity,
        machine: &'a Interpreter,
    },
    Instruction {
        identity: InnerMachineIdentity,
        instruction: crate::interpreter::InstructionObservation<'a>,
    },
    Exit {
        identity: InnerMachineIdentity,
        exit: InnerExit,
        machine: &'a Interpreter,
    },
}

struct InnerMachine {
    generation: u64,
    program_blob: Vec<u8>,
    execution: PreparedExecution,
    initial_pc: u32,
    vm: Option<Interpreter>,
}

impl InnerMachine {
    fn vm(&mut self) -> Result<&mut Interpreter, InnerError> {
        if self.vm.is_none() {
            let mut memory = self
                .execution
                .allocate_memory(
                    1u64 << 32,
                    self.execution.backend() != PvmBackend::ForceRecompiler,
                )
                .map_err(|_| InnerError::Backend)?;
            memory.set_page_perms(vec![PERM_NONE; INNER_ADDRESS_PAGES]);
            let mut vm = Interpreter::from_predecoded(
                self.execution.interpreter_program().clone(),
                [0; PVM_REGISTER_COUNT],
                memory,
                0,
                crate::STANDARD_MEM_CYCLES,
                IsaMode::Conformance,
            );
            vm.set_pc(self.initial_pc);
            self.vm = Some(vm);
        }
        Ok(self.vm.as_mut().expect("initialized above"))
    }

    fn pc(&self) -> u32 {
        self.vm.as_ref().map_or(self.initial_pc, |vm| vm.pc)
    }
}

/// Per-Refine dictionary of standard inner machines.
pub struct InnerMachines {
    machines: BTreeMap<u32, InnerMachine>,
    next_generation: u64,
    backend: PvmBackend,
}

impl Default for InnerMachines {
    fn default() -> Self {
        Self::with_backend(PvmBackend::ForceInterpreter)
    }
}

impl InnerMachines {
    pub fn new() -> Self {
        Self::default()
    }

    /// Select execution for this invocation's dictionary. Each machine keeps
    /// independent memory, registers and gas; only preparation is immutable.
    pub fn with_backend(backend: PvmBackend) -> Self {
        Self {
            machines: BTreeMap::new(),
            next_generation: 0,
            backend,
        }
    }

    pub fn len(&self) -> usize {
        self.machines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.machines.is_empty()
    }

    /// Generation assigned to the next successfully created machine.
    ///
    /// Proof-side Refine context commitments bind this counter even when the
    /// live dictionary is empty, so expunge/recreate histories cannot alias.
    pub fn next_generation(&self) -> u64 {
        self.next_generation
    }

    pub fn contains(&self, id: u32) -> bool {
        self.machines.contains_key(&id)
    }

    /// Iterate the dictionary in slot order without initializing dormant
    /// machines or mutating execution state.
    pub fn views(&self) -> impl Iterator<Item = InnerMachineView<'_>> {
        self.machines
            .iter()
            .map(|(&slot, machine)| InnerMachineView {
                identity: InnerMachineIdentity {
                    slot,
                    generation: machine.generation,
                },
                program: &machine.program_blob,
                initial_pc: machine.initial_pc,
                machine: machine.vm.as_ref(),
            })
    }

    /// Create a machine from one canonical compact code blob.
    ///
    /// The lowest unused natural-number index is returned.
    pub fn create(&mut self, program_blob: &[u8], initial_pc: u32) -> Result<u32, InnerError> {
        if self.machines.len() >= MAX_INNER_MACHINES {
            return Err(InnerError::Full);
        }
        // Ω_M maps a failed deblob to HUH; unlike full Ψ it does not create
        // a machine which immediately panics.
        let program = deblob(program_blob, u64::from(initial_pc)).ok_or(InnerError::Invalid)?;
        let execution = prepare_inner_program(program_blob, &program, self.backend)?;
        let id = (0..MAX_INNER_MACHINES as u32)
            .find(|id| !self.machines.contains_key(id))
            .expect("a free ID exists below the machine limit");
        let generation = self.next_generation;
        self.next_generation = self
            .next_generation
            .checked_add(1)
            .expect("an invocation cannot create 2^64 inner machines");
        self.machines.insert(
            id,
            InnerMachine {
                generation,
                program_blob: program_blob.to_vec(),
                execution,
                initial_pc,
                vm: None,
            },
        );
        Ok(id)
    }

    /// Copy readable bytes out of an inner machine.
    pub fn peek(&mut self, id: u32, source: u32, len: usize) -> Result<Vec<u8>, InnerError> {
        let machine = self.machines.get_mut(&id).ok_or(InnerError::Unknown)?;
        let mut out = vec![0u8; len];
        if !machine.vm()?.memory().read_bytes_checked(source, &mut out) {
            return Err(InnerError::OutOfBounds);
        }
        Ok(out)
    }

    /// Copy bytes into writable inner-machine memory.
    pub fn poke(&mut self, id: u32, destination: u32, data: &[u8]) -> Result<(), InnerError> {
        let machine = self.machines.get_mut(&id).ok_or(InnerError::Unknown)?;
        if !machine
            .vm()?
            .memory_mut()
            .write_bytes_checked(destination, data)
        {
            return Err(InnerError::OutOfBounds);
        }
        Ok(())
    }

    /// Allocate, free, or change access on complete inner-memory pages.
    pub fn pages(
        &mut self,
        id: u32,
        first: u32,
        count: u32,
        mode: PageMode,
    ) -> Result<(), InnerError> {
        let machine = self.machines.get_mut(&id).ok_or(InnerError::Unknown)?;
        let end = first.checked_add(count).ok_or(InnerError::Invalid)?;
        if first < INNER_FIRST_MAPPABLE_PAGE || end as usize >= INNER_ADDRESS_PAGES {
            return Err(InnerError::Invalid);
        }

        let vm = machine.vm()?;
        let memory = vm.memory_mut();
        let first = first as usize;
        let count = count as usize;
        if matches!(mode, PageMode::SetReadOnly | PageMode::SetReadWrite)
            && memory.page_perms()[first..first + count].contains(&PERM_NONE)
        {
            return Err(InnerError::Invalid);
        }

        let permission = match mode {
            PageMode::Free => PERM_NONE,
            PageMode::AllocateReadOnly | PageMode::SetReadOnly => PERM_RO,
            PageMode::AllocateReadWrite | PageMode::SetReadWrite => PERM_RW,
        };
        if matches!(
            mode,
            PageMode::Free | PageMode::AllocateReadOnly | PageMode::AllocateReadWrite
        ) {
            // A native mapping's host zeroing operation can fail even though
            // this guest range is valid. Keep it distinct from guest HUH and
            // never continue execution with uncleared bytes.
            if !memory.clear_pages(first, count) {
                return Err(InnerError::Backend);
            }
        }
        assert!(memory.set_page_range(first, count, permission));
        Ok(())
    }

    /// Resume a machine with the supplied gas counter and register file.
    pub fn invoke(&mut self, id: u32, state: InvokeState) -> Result<InvokeOutcome, InnerError> {
        self.invoke_with_observer(id, state, None)
    }

    /// Resume a machine while exposing immutable entry, instruction, and
    /// exit observations. This follows [`Self::invoke`] exactly while keeping
    /// the observed path explicitly on the reference interpreter. Ordinary
    /// invocation uses the selected backend without per-instruction callbacks.
    /// A dictionary selected for native execution still retains native memory;
    /// proof/snapshot callers should construct it with `ForceInterpreter`,
    /// which uses sparse inner memory.
    pub fn invoke_observed(
        &mut self,
        id: u32,
        state: InvokeState,
        mut observer: impl for<'a> FnMut(InnerMachineObservation<'a>),
    ) -> Result<InvokeOutcome, InnerError> {
        self.invoke_with_observer(id, state, Some(&mut observer))
    }

    fn invoke_with_observer(
        &mut self,
        id: u32,
        state: InvokeState,
        observer: Option<&mut dyn for<'a> FnMut(InnerMachineObservation<'a>)>,
    ) -> Result<InvokeOutcome, InnerError> {
        let machine = self.machines.get_mut(&id).ok_or(InnerError::Unknown)?;
        let identity = InnerMachineIdentity {
            slot: id,
            generation: machine.generation,
        };
        // Clone immutable preparation, never invocation state. The compiled
        // program remains shared while the mutable architectural state is lent.
        let execution = machine.execution.clone();
        let vm = machine.vm()?;
        vm.gas = state.gas;
        vm.registers = state.registers;
        let mut observer = observer;
        let exit = match observer.as_deref_mut() {
            Some(observer) => {
                observer(InnerMachineObservation::Enter {
                    identity,
                    machine: vm,
                });
                vm.run_observed(|instruction| {
                    observer(InnerMachineObservation::Instruction {
                        identity,
                        instruction,
                    });
                })
                .0
            }
            None => execution.run(vm).map_err(|_| InnerError::Backend)?,
        };
        let exit = match exit {
            ExitReason::Halt => {
                vm.pc = 0;
                InnerExit::Halt
            }
            ExitReason::Trap | ExitReason::Panic | ExitReason::Ecall => {
                vm.pc = 0;
                InnerExit::Panic
            }
            ExitReason::OutOfGas => InnerExit::OutOfGas,
            ExitReason::PageFault(address) => InnerExit::Fault(address),
            ExitReason::HostCall(id) => {
                // Ω_K returns the host exit but persists the successor PC in
                // the inner machine immediately. Fault/OOG remain on cause.
                assert!(vm.resume_after_host_call());
                InnerExit::Host(id)
            }
        };
        if let Some(observer) = observer {
            observer(InnerMachineObservation::Exit {
                identity,
                exit,
                machine: vm,
            });
        }
        Ok(InvokeOutcome {
            exit,
            state: InvokeState {
                gas: vm.gas,
                registers: vm.registers,
            },
        })
    }

    /// Remove a machine and return its current instruction counter.
    pub fn expunge(&mut self, id: u32) -> Result<u32, InnerError> {
        self.machines
            .remove(&id)
            .map(|machine| machine.pc())
            .ok_or(InnerError::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PVM_HALT_ADDR;

    fn compact_blob(code: &[u8], starts: &[usize]) -> Vec<u8> {
        let mut packed = vec![0u8; code.len().div_ceil(8)];
        for &i in starts {
            packed[i / 8] |= 1 << (i % 8);
        }
        let mut blob = vec![0, 1, code.len() as u8];
        blob.extend_from_slice(code);
        blob.extend_from_slice(&packed);
        blob
    }

    fn host_then_trap() -> Vec<u8> {
        compact_blob(&[10, 42, 0], &[0, 2])
    }

    #[cfg(feature = "std")]
    #[test]
    fn preparation_cache_is_exact_worker_local_and_revalidates_each_entry() {
        INNER_PREPARATION.with(|entry| *entry.borrow_mut() = None);
        let blob = host_then_trap();
        let mut machines = InnerMachines::new();
        let first = machines.create(&blob, 0).unwrap();
        let first = machines.machines[&first].execution.clone();
        let second = machines.create(&blob, 2).unwrap();
        assert!(
            core::ptr::eq(
                first.interpreter_program(),
                machines.machines[&second].execution.interpreter_program()
            ),
            "valid different entry points share only immutable preparation"
        );
        assert_eq!(
            machines.create(&blob, 1),
            Err(InnerError::Invalid),
            "a cache hit must not bypass entry-point validation"
        );
        let different_blob = compact_blob(&[10, 43, 0], &[0, 2]);
        let different = machines.create(&different_blob, 0).unwrap();
        assert!(!core::ptr::eq(
            first.interpreter_program(),
            machines.machines[&different]
                .execution
                .interpreter_program()
        ));
        INNER_PREPARATION.with(|entry| {
            let entry = entry.borrow();
            assert_eq!(entry.as_ref().unwrap().program, different_blob);
        });
        let replaced = machines.create(&blob, 0).unwrap();
        let replaced = machines.machines[&replaced].execution.clone();
        assert!(
            !core::ptr::eq(first.interpreter_program(), replaced.interpreter_program()),
            "the cache retains only its latest admitted program"
        );
        let worker = std::thread::spawn(move || {
            let mut machines = InnerMachines::new();
            let id = machines.create(&blob, 0).unwrap();
            machines.machines[&id].execution.clone()
        })
        .join()
        .unwrap();
        assert!(
            !core::ptr::eq(worker.interpreter_program(), replaced.interpreter_program()),
            "another worker does not share a mutable/global cache"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn preparation_cache_cap_and_default_bypass_do_not_change_admission() {
        INNER_PREPARATION.with(|entry| *entry.borrow_mut() = None);
        let blob = host_then_trap();
        let mut machines = InnerMachines::new();
        let warm = machines.create(&blob, 0).unwrap();
        let warm = machines.machines[&warm].execution.clone();
        // A canonical program larger than the cache ceiling still creates
        // and executes. Sparse instruction starts keep this fixture modest.
        let code = vec![0; MAX_CACHED_INNER_PROGRAM_BYTES];
        let mut bitmask = vec![0; code.len()];
        for start in (0..code.len()).step_by(25) {
            bitmask[start] = 1;
        }
        let oversized = vos_pvm_program::build_compact_code_blob(&vos_pvm_program::CodeBlob {
            code,
            bitmask,
            jump_table: Vec::new(),
        })
        .unwrap();
        assert!(oversized.len() > MAX_CACHED_INNER_PROGRAM_BYTES);
        let large = machines.create(&oversized, 0).unwrap();
        assert_eq!(
            machines
                .invoke(
                    large,
                    InvokeState {
                        gas: 1_000_000,
                        registers: [0; PVM_REGISTER_COUNT],
                    }
                )
                .unwrap()
                .exit,
            InnerExit::Panic
        );
        let mut default = InnerMachines::with_backend(PvmBackend::Default);
        let id = default.create(&blob, 0).unwrap();
        assert!(
            !core::ptr::eq(
                warm.interpreter_program(),
                default.machines[&id].execution.interpreter_program()
            ),
            "environment-dependent backend selection must not hit the cache"
        );
        INNER_PREPARATION.with(|entry| {
            let entry = entry.borrow();
            let entry = entry.as_ref().unwrap();
            assert_eq!(entry.program, blob);
            assert_eq!(entry.backend, PvmBackend::ForceInterpreter);
            assert!(
                core::ptr::eq(
                    entry.execution.interpreter_program(),
                    warm.interpreter_program()
                ),
                "bypassed programs must not evict the admitted entry"
            );
        });
    }

    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn preparation_cache_binds_backend_and_never_retains_invocation_state() {
        INNER_PREPARATION.with(|entry| *entry.borrow_mut() = None);
        let blob = compact_blob(&[130, 2 + 16 * 3, 10, 42, 0], &[0, 2, 4]);
        let mut reference = InnerMachines::new();
        let reference_id = reference.create(&blob, 0).unwrap();
        let reference_prepared = reference.machines[&reference_id].execution.clone();
        let mut prior_prepared = None;
        for value in [37u8, 71] {
            let mut machines = InnerMachines::with_backend(PvmBackend::ForceRecompiler);
            let id = machines.create(&blob, 0).unwrap();
            let prepared = machines.machines[&id].execution.clone();
            assert_eq!(prepared.backend(), PvmBackend::ForceRecompiler);
            assert!(!core::ptr::eq(
                reference_prepared.interpreter_program(),
                prepared.interpreter_program()
            ));
            if let Some(prior) = &prior_prepared {
                let prior: &PreparedExecution = prior;
                assert!(core::ptr::eq(
                    prior.interpreter_program(),
                    prepared.interpreter_program()
                ));
            }
            prior_prepared = Some(prepared);
            let address = INNER_FIRST_MAPPABLE_PAGE * PVM_PAGE_SIZE;
            let mut registers = [0; PVM_REGISTER_COUNT];
            registers[3] = u64::from(address);
            let fault = machines
                .invoke(
                    id,
                    InvokeState {
                        gas: 100_000,
                        registers,
                    },
                )
                .unwrap();
            assert_eq!(
                fault.exit,
                InnerExit::Fault(address),
                "fresh memory has no cached mappings"
            );
            machines
                .pages(
                    id,
                    INNER_FIRST_MAPPABLE_PAGE,
                    1,
                    PageMode::AllocateReadWrite,
                )
                .unwrap();
            assert_eq!(
                machines.peek(id, address, 8).unwrap(),
                [0; 8],
                "no prior bytes survive"
            );
            machines.poke(id, address, &[value]).unwrap();
            let host = machines.invoke(id, fault.state).unwrap();
            assert_eq!(host.exit, InnerExit::Host(42));
            assert_eq!(host.state.registers[2], u64::from(value));
            let gas = host.state.gas;
            let terminal = machines.invoke(id, host.state).unwrap();
            assert_eq!(terminal.exit, InnerExit::Panic);
            assert_eq!(
                terminal.state.gas, gas,
                "cached preparation does not change funded host resume"
            );
            assert_eq!(machines.expunge(id), Ok(0));
        }
    }

    #[test]
    fn enforces_sixty_three_machine_limit_and_reuses_lowest_id() {
        let blob = host_then_trap();
        let mut machines = InnerMachines::new();
        for expected in 0..MAX_INNER_MACHINES as u32 {
            assert_eq!(machines.create(&blob, 0), Ok(expected));
        }
        assert_eq!(machines.create(&blob, 0), Err(InnerError::Full));
        assert_eq!(machines.expunge(7), Ok(0));
        assert_eq!(machines.create(&blob, 0), Ok(7));
    }

    #[test]
    fn rejects_malformed_programs_and_invalid_entry_points() {
        let blob = host_then_trap();
        let mut machines = InnerMachines::new();
        assert_eq!(machines.create(&[0xff], 0), Err(InnerError::Invalid));
        assert_eq!(machines.create(&blob, 1), Err(InnerError::Invalid));
        let mut trailing = blob.clone();
        trailing.push(0);
        assert_eq!(machines.create(&trailing, 0), Err(InnerError::Invalid));
    }

    #[test]
    fn pages_poke_and_peek_obey_access_modes_and_zero_allocation() {
        let mut machines = InnerMachines::new();
        let id = machines.create(&host_then_trap(), 0).unwrap();
        let page = INNER_FIRST_MAPPABLE_PAGE;
        let address = page * PVM_PAGE_SIZE + 11;

        assert_eq!(
            machines.poke(id, address, b"hello"),
            Err(InnerError::OutOfBounds)
        );
        machines
            .pages(id, page, 1, PageMode::AllocateReadWrite)
            .unwrap();
        machines.poke(id, address, b"hello").unwrap();
        assert_eq!(machines.peek(id, address, 5).unwrap(), b"hello");
        machines.pages(id, page, 1, PageMode::SetReadOnly).unwrap();
        assert_eq!(
            machines.poke(id, address, b"world"),
            Err(InnerError::OutOfBounds)
        );
        assert_eq!(machines.peek(id, address, 5).unwrap(), b"hello");

        machines
            .pages(id, page, 1, PageMode::AllocateReadWrite)
            .unwrap();
        assert_eq!(machines.peek(id, address, 5).unwrap(), [0; 5]);
        machines.pages(id, page, 1, PageMode::Free).unwrap();
        assert_eq!(machines.peek(id, address, 1), Err(InnerError::OutOfBounds));
        assert_eq!(
            machines.pages(id, 15, 1, PageMode::AllocateReadWrite),
            Err(InnerError::Invalid)
        );
    }

    #[test]
    fn invoke_resumes_after_host_call_then_panics_on_trap() {
        let mut machines = InnerMachines::new();
        let id = machines.create(&host_then_trap(), 0).unwrap();
        let state = InvokeState {
            gas: 100_000,
            registers: [0; PVM_REGISTER_COUNT],
        };
        let first = machines.invoke(id, state).unwrap();
        assert_eq!(first.exit, InnerExit::Host(42));
        assert!(first.state.gas < 100_000);
        assert_eq!(machines.expunge(id), Ok(2));

        let id = machines.create(&host_then_trap(), 0).unwrap();
        let first = machines
            .invoke(
                id,
                InvokeState {
                    gas: 100_000,
                    registers: [0; PVM_REGISTER_COUNT],
                },
            )
            .unwrap();
        let second = machines.invoke(id, first.state).unwrap();
        assert_eq!(second.exit, InnerExit::Panic);
        assert_eq!(machines.expunge(id), Ok(0));
    }

    #[test]
    fn observed_identity_does_not_alias_a_reused_slot() {
        let mut machines = InnerMachines::new();
        let state = InvokeState {
            gas: 100_000,
            registers: [0; PVM_REGISTER_COUNT],
        };
        let first_slot = machines.create(&host_then_trap(), 0).unwrap();
        let mut first_identity = None;
        machines
            .invoke_observed(first_slot, state.clone(), |event| {
                if let InnerMachineObservation::Enter { identity, .. } = event {
                    first_identity = Some(identity);
                }
            })
            .unwrap();
        machines.expunge(first_slot).unwrap();

        let second_slot = machines.create(&host_then_trap(), 0).unwrap();
        let mut second_identity = None;
        machines
            .invoke_observed(second_slot, state, |event| {
                if let InnerMachineObservation::Enter { identity, .. } = event {
                    second_identity = Some(identity);
                }
            })
            .unwrap();

        assert_eq!(first_slot, second_slot);
        assert_eq!(first_identity.unwrap().slot, second_identity.unwrap().slot);
        assert_ne!(first_identity, second_identity);
        assert_eq!(first_identity.unwrap().generation, 0);
        assert_eq!(second_identity.unwrap().generation, 1);
    }

    #[test]
    fn invoke_reports_halt_fault_and_out_of_gas() {
        let mut machines = InnerMachines::new();
        let halt = compact_blob(&[50, 0], &[0]);
        let id = machines.create(&halt, 0).unwrap();
        let mut registers = [0; PVM_REGISTER_COUNT];
        registers[0] = PVM_HALT_ADDR;
        assert_eq!(
            machines
                .invoke(
                    id,
                    InvokeState {
                        gas: 100_000,
                        registers,
                    },
                )
                .unwrap()
                .exit,
            InnerExit::Halt
        );

        let fault = compact_blob(&[130, 2 + 16 * 3, 0], &[0, 2]);
        let id = machines.create(&fault, 0).unwrap();
        let mut registers = [0; PVM_REGISTER_COUNT];
        registers[3] = (INNER_FIRST_MAPPABLE_PAGE * PVM_PAGE_SIZE) as u64;
        assert_eq!(
            machines
                .invoke(
                    id,
                    InvokeState {
                        gas: 100_000,
                        registers,
                    },
                )
                .unwrap()
                .exit,
            InnerExit::Fault(INNER_FIRST_MAPPABLE_PAGE * PVM_PAGE_SIZE)
        );

        let id = machines.create(&host_then_trap(), 0).unwrap();
        assert_eq!(
            machines
                .invoke(
                    id,
                    InvokeState {
                        gas: 0,
                        registers: [0; PVM_REGISTER_COUNT],
                    },
                )
                .unwrap()
                .exit,
            InnerExit::OutOfGas
        );
    }

    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn recompiled_inner_matches_reference_when_reusing_terminal_machines() {
        // A terminal exit resets the inner PC, but does not discard the
        // interpreter's funded gas block. Reusing the same machine must not
        // silently charge it again under a different execution backend.
        let cases = [
            ("host then trap", vec![10, 42, 0], vec![0, 2], 0),
            (
                "host then halt",
                vec![10, 42, 50, 0],
                vec![0, 2],
                crate::PVM_HALT_ADDR,
            ),
            ("trap", vec![0], vec![0], 0),
            ("halt", vec![50, 0], vec![0], crate::PVM_HALT_ADDR),
            ("invalid indirect jump", vec![50, 0], vec![0], 1),
            ("invalid static jump", vec![40, 1], vec![0], 0),
            ("final fallthrough", vec![1], vec![0], 0),
        ];
        for (name, code, starts, return_address) in cases {
            for initial_gas in [0, 1, 100, 1_000] {
                let run = |backend| {
                    let mut machines = InnerMachines::with_backend(backend);
                    let id = machines
                        .create(&compact_blob(&code, &starts), 0)
                        .unwrap_or_else(|error| panic!("{name}, {backend:?}: {error:?}"));
                    let mut registers = [0; PVM_REGISTER_COUNT];
                    registers[0] = return_address;
                    let mut state = InvokeState {
                        gas: initial_gas,
                        registers,
                    };
                    let mut observations = Vec::new();
                    for _ in 0..6 {
                        let outcome = machines.invoke(id, state).unwrap();
                        let vm = machines.machines[&id].vm.as_ref().unwrap();
                        observations.push((outcome.clone(), vm.pc, vm.gas_charged));
                        state = outcome.state;
                    }
                    (observations, machines.expunge(id).unwrap())
                };
                assert_eq!(
                    run(PvmBackend::ForceRecompiler),
                    run(PvmBackend::ForceInterpreter),
                    "{name}, initial gas {initial_gas}"
                );
            }
        }
    }

    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn recompiled_inner_invalid_entry_preserves_existing_funding() {
        for pc in [1, 4, u32::MAX] {
            for funded in [false, true] {
                for gas in [0, 1_000] {
                    let run = |backend| {
                        let mut machines = InnerMachines::with_backend(backend);
                        let id = machines.create(&host_then_trap(), 0).unwrap();
                        let vm = machines.machines.get_mut(&id).unwrap().vm().unwrap();
                        vm.pc = pc;
                        vm.restore_boundary_state(funded, None);
                        let mut state = InvokeState {
                            gas,
                            registers: [0; PVM_REGISTER_COUNT],
                        };
                        let mut observations = Vec::new();
                        for step in 0..3 {
                            let outcome = machines.invoke(id, state).unwrap();
                            let vm = machines.machines[&id].vm.as_ref().unwrap();
                            if step == 0 {
                                assert_eq!(outcome.exit, InnerExit::Panic);
                                assert_eq!(outcome.state.gas, gas);
                                assert_eq!(vm.gas_charged, funded);
                            }
                            observations.push((outcome.clone(), vm.pc, vm.gas_charged));
                            state = outcome.state;
                        }
                        observations
                    };
                    assert_eq!(
                        run(PvmBackend::ForceRecompiler),
                        run(PvmBackend::ForceInterpreter),
                        "invalid pc {pc}, funded {funded}, gas {gas}"
                    );
                }
            }
        }
    }

    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn recompiled_inner_matches_reference_across_fault_repair_host_resume_and_page_reuse() {
        fn run(backend: PvmBackend) -> (Vec<InvokeOutcome>, Vec<u32>, Vec<u8>) {
            let mut machines = InnerMachines::with_backend(backend);
            // Load r2 from r3, host(42), trap. Repair a fault without resetting
            // the funded gas block, then suspend/resume through the host call.
            let blob = compact_blob(&[130, 2 + 16 * 3, 10, 42, 0], &[0, 2, 4]);
            let id = machines.create(&blob, 0).unwrap();
            let page = INNER_FIRST_MAPPABLE_PAGE;
            let address = page * PVM_PAGE_SIZE;
            let mut registers = [0; PVM_REGISTER_COUNT];
            registers[3] = u64::from(address);
            let mut outcomes = Vec::new();
            let mut pcs = Vec::new();
            let fault = machines
                .invoke(
                    id,
                    InvokeState {
                        gas: 100_000,
                        registers,
                    },
                )
                .unwrap();
            assert_eq!(fault.exit, InnerExit::Fault(address));
            outcomes.push(fault.clone());
            pcs.push(machines.views().next().unwrap().machine.unwrap().pc);
            machines
                .pages(id, page, 1, PageMode::AllocateReadWrite)
                .unwrap();
            machines.poke(id, address, &[37]).unwrap();
            machines.pages(id, page, 1, PageMode::SetReadOnly).unwrap();
            assert_eq!(
                machines.poke(id, address, &[99]),
                Err(InnerError::OutOfBounds)
            );
            let resumed = machines.invoke(id, fault.state).unwrap();
            assert_eq!(resumed.exit, InnerExit::Host(42));
            assert_eq!(resumed.state.registers[2], 37);
            outcomes.push(resumed.clone());
            pcs.push(machines.views().next().unwrap().machine.unwrap().pc);
            outcomes.push(machines.invoke(id, resumed.state).unwrap());
            pcs.push(machines.expunge(id).unwrap());

            // A reused slot and a fresh machine must not retain the old bytes.
            let reused = machines.create(&blob, 0).unwrap();
            assert_eq!(reused, id);
            machines
                .pages(reused, page, 1, PageMode::AllocateReadWrite)
                .unwrap();
            let bytes = machines.peek(reused, address, 8).unwrap();
            assert_eq!(bytes, [0; 8]);
            machines.poke(reused, address, &[71]).unwrap();
            machines.pages(reused, page, 1, PageMode::Free).unwrap();
            assert_eq!(
                machines.peek(reused, address, 1),
                Err(InnerError::OutOfBounds)
            );
            machines
                .pages(reused, page, 1, PageMode::AllocateReadWrite)
                .unwrap();
            assert_eq!(machines.peek(reused, address, 8).unwrap(), [0; 8]);
            outcomes.push(
                machines
                    .invoke(reused, InvokeState { gas: 0, registers })
                    .unwrap(),
            );
            pcs.push(machines.expunge(reused).unwrap());
            (outcomes, pcs, bytes)
        }
        assert_eq!(
            run(PvmBackend::ForceRecompiler),
            run(PvmBackend::ForceInterpreter)
        );
    }

    #[test]
    fn pins_host_call_ids_and_gas_schedule() {
        assert_eq!(
            [
                host_call::MACHINE,
                host_call::PEEK,
                host_call::POKE,
                host_call::PAGES,
                host_call::INVOKE,
                host_call::EXPUNGE,
            ],
            [9, 10, 11, 12, 13, 14]
        );
        assert_eq!(gas::memory(112, 0), 0);
        assert_eq!(gas::memory(112, 1), 1);
        assert_eq!(gas::memory(112, 1024), 112);
        assert_eq!(gas::memory(112, 1025), 113);
    }
}
