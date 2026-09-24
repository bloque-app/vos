//! Portable actor-machine loader for guest agent runtimes.
//!
//! This module turns a signed standard-program blob into an inner machine
//! using only host calls 9–14. It is runtime policy-free: directory paging,
//! scheduling, state lanes, and host-call handling remain the agent runtime's
//! responsibility.

use alloc::vec::Vec;

pub use super::execution::{
    MAX_PORTABLE_MACHINE_MEMORY_BYTES, PortableMachineSnapshot, PortableMemoryRegion,
};
use crate::abi::pvm::inner;
use vos_pvm_program::{PAGE_SIZE, Region, StandardLayout, StandardProgram, StandardProgramRef};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadError {
    InvalidProgram,
    MachineLimit,
    InvalidLayout,
    InvalidSnapshot,
    SnapshotLimit,
    PageOperation,
    MemoryOperation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InnerExit {
    Halt,
    Panic,
    Fault(u32),
    Host(u64),
    OutOfGas,
    InvalidResult(u64),
}

/// One live actor machine owned by the current outer invocation.
pub struct ActorMachine {
    id: u32,
    frame: [u64; 14],
    writable_regions: Vec<Region>,
    live: bool,
    #[cfg(all(test, feature = "std", not(target_arch = "riscv64")))]
    test_machines: core::cell::RefCell<vos_pvm::inner::InnerMachines>,
}

impl ActorMachine {
    /// Parse, allocate, and initialize a standard actor program.
    pub fn load(blob: &[u8], args: &[u8]) -> Result<Self, LoadError> {
        Self::load_at(blob, args, 0, None)
    }

    /// Recreate a machine at the exact successor boundary captured by
    /// [`Self::capture`]. The authenticated program and arguments must
    /// reproduce the snapshot's complete mutable region map.
    pub fn restore(
        blob: &[u8],
        args: &[u8],
        snapshot: &PortableMachineSnapshot,
    ) -> Result<Self, LoadError> {
        if !snapshot.is_valid() {
            return Err(LoadError::InvalidSnapshot);
        }
        Self::load_at(blob, args, snapshot.pc, Some(snapshot))
    }

    fn load_at(
        blob: &[u8],
        args: &[u8],
        initial_pc: u32,
        snapshot: Option<&PortableMachineSnapshot>,
    ) -> Result<Self, LoadError> {
        // Validate in place and hand the program's own compact code blob to
        // `machine`. `StandardProgramRef` accepts exactly what
        // `parse_standard_program` accepts, and its code blob is byte-for-byte
        // what `compact_code` would rebuild, so the machine and the refusals
        // are unchanged; the guest just no longer copies the sections or
        // expands and re-packs the bitmask, work that grew with the program.
        let program = StandardProgramRef::parse(blob).ok_or(LoadError::InvalidProgram)?;
        if snapshot.is_some()
            && !usize::try_from(initial_pc).is_ok_and(|pc| program.is_instruction_start(pc))
        {
            return Err(LoadError::InvalidSnapshot);
        }
        let compact = program.code_blob();
        let layout = program.layout(args).ok_or(LoadError::InvalidLayout)?;
        let writable_regions: Vec<_> = [layout.rw, layout.stack]
            .into_iter()
            .filter(|region| region.size != 0)
            .collect();
        if let Some(snapshot) = snapshot {
            Self::validate_snapshot_regions(snapshot, &writable_regions)?;
        }
        #[cfg(all(test, feature = "std", not(target_arch = "riscv64")))]
        let (raw_id, test_machines) = {
            let mut machines = vos_pvm::inner::InnerMachines::new();
            let raw_id = match machines.create(compact, initial_pc) {
                Ok(id) => u64::from(id),
                Err(vos_pvm::inner::InnerError::Full) => inner::RESULT_FULL,
                Err(_) => inner::RESULT_HUH,
            };
            (raw_id, machines)
        };
        #[cfg(any(not(test), not(feature = "std"), target_arch = "riscv64"))]
        let raw_id = inner::machine(compact, initial_pc);
        if raw_id == inner::RESULT_FULL {
            return Err(LoadError::MachineLimit);
        }
        let id = u32::try_from(raw_id).map_err(|_| LoadError::InvalidProgram)?;
        let mut machine = Self {
            id,
            frame: [0; 14],
            writable_regions,
            live: true,
            #[cfg(all(test, feature = "std", not(target_arch = "riscv64")))]
            test_machines: core::cell::RefCell::new(test_machines),
        };
        machine.frame[1..].copy_from_slice(&layout.registers);

        if let Err(error) = machine.initialize(&layout) {
            return Err(error);
        }
        if let Some(snapshot) = snapshot {
            for region in &snapshot.memory {
                machine.write(region.base, &region.bytes)?;
            }
            machine.frame[0] = snapshot.gas_remaining;
            machine.frame[1..].copy_from_slice(&snapshot.registers);
        }
        Ok(machine)
    }

    fn validate_snapshot_regions(
        snapshot: &PortableMachineSnapshot,
        expected: &[Region],
    ) -> Result<(), LoadError> {
        if snapshot.memory.len() != expected.len() {
            return Err(LoadError::InvalidSnapshot);
        }
        for (actual, expected) in snapshot.memory.iter().zip(expected) {
            let base = u32::try_from(expected.base).map_err(|_| LoadError::InvalidLayout)?;
            let len = usize::try_from(expected.size).map_err(|_| LoadError::InvalidLayout)?;
            if actual.base != base || actual.bytes.len() != len {
                return Err(LoadError::InvalidSnapshot);
            }
        }
        Ok(())
    }

    pub const fn id(&self) -> u32 {
        self.id
    }

    pub fn registers(&self) -> &[u64; vos_pvm_program::REGISTER_COUNT] {
        self.frame[1..]
            .try_into()
            .expect("the invocation frame always contains thirteen registers")
    }

    pub fn registers_mut(&mut self) -> &mut [u64; vos_pvm_program::REGISTER_COUNT] {
        (&mut self.frame[1..])
            .try_into()
            .expect("the invocation frame always contains thirteen registers")
    }

    pub const fn gas_remaining(&self) -> u64 {
        self.frame[0]
    }

    /// Resume until the actor halts, faults, exhausts gas, or requests an
    /// actor ABI host operation.
    pub fn resume(&mut self, gas: u64) -> InnerExit {
        self.frame[0] = gas;
        #[cfg(all(test, feature = "std", not(target_arch = "riscv64")))]
        let [status, detail] = {
            let state = vos_pvm::inner::InvokeState {
                gas,
                registers: *self.registers(),
            };
            let outcome = match self.test_machines.borrow_mut().invoke(self.id, state) {
                Ok(outcome) => outcome,
                Err(_) => return InnerExit::InvalidResult(inner::RESULT_HUH),
            };
            self.frame[0] = outcome.state.gas;
            self.frame[1..].copy_from_slice(&outcome.state.registers);
            if matches!(
                outcome.exit,
                vos_pvm::inner::InnerExit::Fault(_) | vos_pvm::inner::InnerExit::Panic
            ) && std::env::var_os("VOS_TEST_INNER_DIAGNOSTICS").is_some()
            {
                for view in self.test_machines.borrow().views() {
                    if view.identity.slot == self.id {
                        std::eprintln!(
                            "inner fault pc={:?}",
                            view.machine.map(|machine| machine.pc)
                        );
                    }
                }
            }
            match outcome.exit {
                vos_pvm::inner::InnerExit::Halt => [0, 0],
                vos_pvm::inner::InnerExit::Panic => [1, 0],
                vos_pvm::inner::InnerExit::Fault(address) => [2, u64::from(address)],
                vos_pvm::inner::InnerExit::Host(id) => [3, id],
                vos_pvm::inner::InnerExit::OutOfGas => [4, 0],
            }
        };
        #[cfg(any(not(test), not(feature = "std"), target_arch = "riscv64"))]
        let [status, detail] = inner::invoke(self.id, &mut self.frame);
        match status {
            0 => InnerExit::Halt,
            1 => InnerExit::Panic,
            2 => u32::try_from(detail)
                .map(InnerExit::Fault)
                .unwrap_or(InnerExit::InvalidResult(status)),
            3 => InnerExit::Host(detail),
            4 => InnerExit::OutOfGas,
            other => InnerExit::InvalidResult(other),
        }
    }

    pub fn read(&self, address: u32, output: &mut [u8]) -> Result<(), LoadError> {
        #[cfg(all(test, feature = "std", not(target_arch = "riscv64")))]
        {
            let bytes = self
                .test_machines
                .borrow_mut()
                .peek(self.id, address, output.len())
                .map_err(|_| LoadError::MemoryOperation)?;
            output.copy_from_slice(&bytes);
            return Ok(());
        }
        #[cfg(any(not(test), not(feature = "std"), target_arch = "riscv64"))]
        match inner::peek(self.id, address, output) {
            inner::RESULT_OK => Ok(()),
            _ => Err(LoadError::MemoryOperation),
        }
    }

    pub fn write(&mut self, address: u32, input: &[u8]) -> Result<(), LoadError> {
        #[cfg(all(test, feature = "std", not(target_arch = "riscv64")))]
        {
            return self
                .test_machines
                .borrow_mut()
                .poke(self.id, address, input)
                .map_err(|_| LoadError::MemoryOperation);
        }
        #[cfg(any(not(test), not(feature = "std"), target_arch = "riscv64"))]
        match inner::poke(self.id, address, input) {
            inner::RESULT_OK => Ok(()),
            _ => Err(LoadError::MemoryOperation),
        }
    }

    /// Capture and expunge this live machine. A persisted continuation must
    /// consume no entry in the outer invocation's 63-machine dictionary.
    pub fn capture(mut self) -> Result<PortableMachineSnapshot, LoadError> {
        let memory_bytes = self
            .writable_regions
            .iter()
            .try_fold(0usize, |total, region| {
                let size = usize::try_from(region.size).ok()?;
                total.checked_add(size)
            })
            .filter(|total| *total <= MAX_PORTABLE_MACHINE_MEMORY_BYTES)
            .ok_or(LoadError::SnapshotLimit)?;
        let mut memory = Vec::new();
        memory
            .try_reserve_exact(self.writable_regions.len())
            .map_err(|_| LoadError::SnapshotLimit)?;
        let regions = self.writable_regions.clone();
        let mut captured = 0usize;
        for region in regions {
            let base = u32::try_from(region.base).map_err(|_| LoadError::InvalidLayout)?;
            let len = usize::try_from(region.size).map_err(|_| LoadError::InvalidLayout)?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(len)
                .map_err(|_| LoadError::SnapshotLimit)?;
            bytes.resize(len, 0);
            self.read(base, &mut bytes)?;
            captured = captured.checked_add(len).ok_or(LoadError::SnapshotLimit)?;
            memory.push(PortableMemoryRegion { base, bytes });
        }
        debug_assert_eq!(captured, memory_bytes);
        #[cfg(all(test, feature = "std", not(target_arch = "riscv64")))]
        let raw_pc = self
            .test_machines
            .borrow_mut()
            .expunge(self.id)
            .map(u64::from)
            .unwrap_or(inner::RESULT_WHO);
        #[cfg(any(not(test), not(feature = "std"), target_arch = "riscv64"))]
        let raw_pc = inner::expunge(self.id);
        let pc = decode_expunge_pc(raw_pc)?;
        self.live = false;
        let snapshot = PortableMachineSnapshot {
            pc,
            gas_remaining: self.frame[0],
            registers: *self.registers(),
            memory,
        };
        if !snapshot.is_valid() {
            return Err(LoadError::InvalidSnapshot);
        }
        Ok(snapshot)
    }

    fn initialize(&mut self, layout: &StandardLayout<'_>) -> Result<(), LoadError> {
        self.initialize_region(layout.ro, layout.ro_data)?;
        self.initialize_region(layout.rw, layout.rw_data)?;
        self.initialize_region(layout.stack, &[])?;
        self.initialize_region(layout.args, layout.args_data)?;
        Ok(())
    }

    fn initialize_region(&mut self, region: Region, data: &[u8]) -> Result<(), LoadError> {
        if region.size == 0 {
            return Ok(());
        }
        let first = u32::try_from(region.base / u64::from(PAGE_SIZE))
            .map_err(|_| LoadError::InvalidLayout)?;
        let count = u32::try_from(region.size / u64::from(PAGE_SIZE))
            .map_err(|_| LoadError::InvalidLayout)?;
        #[cfg(all(test, feature = "std", not(target_arch = "riscv64")))]
        self.test_machines
            .borrow_mut()
            .pages(
                self.id,
                first,
                count,
                vos_pvm::inner::PageMode::AllocateReadWrite,
            )
            .map_err(|_| LoadError::PageOperation)?;
        #[cfg(any(not(test), not(feature = "std"), target_arch = "riscv64"))]
        if inner::pages(self.id, first, count, 2) != inner::RESULT_OK {
            return Err(LoadError::PageOperation);
        }
        if !data.is_empty() {
            let address = u32::try_from(region.base).map_err(|_| LoadError::InvalidLayout)?;
            self.write(address, data)?;
        }
        if !region.writable {
            #[cfg(all(test, feature = "std", not(target_arch = "riscv64")))]
            self.test_machines
                .borrow_mut()
                .pages(self.id, first, count, vos_pvm::inner::PageMode::SetReadOnly)
                .map_err(|_| LoadError::PageOperation)?;
            #[cfg(any(not(test), not(feature = "std"), target_arch = "riscv64"))]
            if inner::pages(self.id, first, count, 3) != inner::RESULT_OK {
                return Err(LoadError::PageOperation);
            }
        }
        Ok(())
    }
}

/// EXPUNGE returns the successor instruction counter on success and a
/// high-valued standard result sentinel on failure. Never truncate a sentinel
/// into a plausible continuation PC.
fn decode_expunge_pc(raw: u64) -> Result<u32, LoadError> {
    u32::try_from(raw).map_err(|_| LoadError::MemoryOperation)
}

impl Drop for ActorMachine {
    fn drop(&mut self) {
        if self.live {
            #[cfg(all(test, feature = "std", not(target_arch = "riscv64")))]
            let _ = self.test_machines.borrow_mut().expunge(self.id);
            #[cfg(any(not(test), not(feature = "std"), target_arch = "riscv64"))]
            let _ = inner::expunge(self.id);
        }
    }
}

/// Compute the page mutations a loader must issue, independent of an
/// executor. Custom runtimes can use this to budget initialization work.
pub fn mapped_pages(program: &StandardProgram, args: &[u8]) -> Option<u32> {
    let layout = program.layout(args)?;
    [layout.ro, layout.rw, layout.stack, layout.args]
        .into_iter()
        .try_fold(0u32, |total, region| {
            let pages = u32::try_from(region.size / u64::from(PAGE_SIZE)).ok()?;
            total.checked_add(pages)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use vos_pvm_program::{CodeBlob, StandardProgram};

    #[test]
    fn page_budget_counts_declared_regions_without_instantiating() {
        let program = StandardProgram {
            ro_data: vec![1],
            rw_data: vec![2],
            heap_pages: 2,
            stack_size: PAGE_SIZE,
            code: CodeBlob {
                jump_table: Vec::new(),
                code: vec![0],
                bitmask: vec![1],
            },
        };
        // ro 1 + rw initialization/heap 3 + stack 1 + args 1.
        assert_eq!(mapped_pages(&program, &[3]), Some(6));
    }

    #[cfg(all(feature = "std", not(target_arch = "riscv64")))]
    #[test]
    fn native_test_backend_preserves_actor_machine_lifecycle() {
        use vos_pvm_compiler::assembler::{Assembler, Reg};

        let output = b"native-inner-done";
        let base = 2 * u64::from(vos_pvm_program::ZONE_SIZE);
        let blob = Assembler::new()
            .set_rw_data(output.to_vec())
            .load_imm_64(Reg::A0, base)
            .load_imm_64(Reg::A1, output.len() as u64)
            .jump_ind(Reg::RA, 0)
            .build_standard();
        let mut machine = ActorMachine::load(&blob, b"actor-args").unwrap();
        assert_eq!(machine.id(), 0);
        assert_eq!(machine.resume(100_000), InnerExit::Halt);
        assert!(machine.gas_remaining() < 100_000);
        let mut returned = vec![0; output.len()];
        machine
            .read(
                u32::try_from(machine.registers()[7]).unwrap(),
                &mut returned,
            )
            .unwrap();
        assert_eq!(returned, output);

        let snapshot = machine.capture().unwrap();
        let mut reopened = ActorMachine::restore(&blob, b"actor-args", &snapshot).unwrap();
        assert_eq!(reopened.resume(snapshot.gas_remaining), InnerExit::Halt);
        let mut returned = vec![0; output.len()];
        reopened
            .read(
                u32::try_from(reopened.registers()[7]).unwrap(),
                &mut returned,
            )
            .unwrap();
        assert_eq!(returned, output);
    }

    /// The loader hands `machine` the program's own compact code blob, the
    /// bytes a full parse would re-encode, and refuses exactly what the full
    /// parse refuses, including a snapshot counter that is not an instruction.
    #[cfg(all(feature = "std", not(target_arch = "riscv64")))]
    #[test]
    fn load_hands_machine_the_programs_own_code_blob() {
        use vos_pvm_compiler::assembler::{Assembler, Reg};

        let base = 2 * u64::from(vos_pvm_program::ZONE_SIZE);
        let blob = Assembler::new()
            .set_rw_data(b"own-code-blob".to_vec())
            .load_imm_64(Reg::A0, base)
            .load_imm_64(Reg::A1, 13)
            .jump_ind(Reg::RA, 0)
            .build_standard();
        let rebuilt = vos_pvm_program::parse_standard_program(&blob)
            .unwrap()
            .compact_code()
            .unwrap();
        let machine = ActorMachine::load(&blob, b"args").unwrap();
        let views: Vec<_> = machine
            .test_machines
            .borrow()
            .views()
            .map(|view| view.program.to_vec())
            .collect();
        assert_eq!(views, vec![rebuilt]);

        let mut trailing = blob.clone();
        trailing.push(0);
        assert!(vos_pvm_program::parse_standard_program(&trailing).is_none());
        assert_eq!(
            ActorMachine::load(&trailing, b"args").err(),
            Some(LoadError::InvalidProgram)
        );

        let mut machine = ActorMachine::load(&blob, b"args").unwrap();
        assert_eq!(machine.resume(100_000), InnerExit::Halt);
        let mut snapshot = machine.capture().unwrap();
        let code_len = vos_pvm_program::parse_standard_program(&blob)
            .unwrap()
            .code
            .code
            .len();
        let not_an_instruction = (0..code_len as u32 + 2)
            .find(|pc| {
                !vos_pvm_program::StandardProgramRef::parse(&blob)
                    .unwrap()
                    .is_instruction_start(*pc as usize)
            })
            .unwrap();
        snapshot.pc = not_an_instruction;
        assert_eq!(
            ActorMachine::restore(&blob, b"args", &snapshot).err(),
            Some(LoadError::InvalidSnapshot)
        );
    }

    #[test]
    fn snapshot_shape_rejects_unaligned_overlapping_and_oversized_regions() {
        let base = 16 * PAGE_SIZE;
        let snapshot = |memory| PortableMachineSnapshot {
            pc: 0,
            gas_remaining: 1,
            registers: [0; vos_pvm_program::REGISTER_COUNT],
            memory,
        };
        assert_eq!(
            snapshot(vec![PortableMemoryRegion {
                base: base + 1,
                bytes: vec![0; PAGE_SIZE as usize],
            }])
            .is_valid(),
            false
        );
        assert_eq!(
            snapshot(vec![
                PortableMemoryRegion {
                    base,
                    bytes: vec![0; (2 * PAGE_SIZE) as usize],
                },
                PortableMemoryRegion {
                    base: base + PAGE_SIZE,
                    bytes: vec![0; PAGE_SIZE as usize],
                },
            ])
            .is_valid(),
            false
        );
        assert_eq!(
            snapshot(vec![PortableMemoryRegion {
                base,
                bytes: vec![0; MAX_PORTABLE_MACHINE_MEMORY_BYTES + PAGE_SIZE as usize],
            }])
            .is_valid(),
            false
        );
    }

    #[test]
    fn restore_rejects_a_pc_which_is_not_an_instruction_boundary() {
        let program = StandardProgram {
            ro_data: vec![1],
            rw_data: vec![2],
            heap_pages: 0,
            stack_size: PAGE_SIZE,
            code: CodeBlob {
                jump_table: Vec::new(),
                code: vec![10, 42, 0],
                bitmask: vec![1, 0, 1],
            },
        };
        let blob = vos_pvm_program::build_standard_program(&program).unwrap();
        let layout = program.layout(&[]).unwrap();
        let memory = [layout.rw, layout.stack]
            .into_iter()
            .filter(|region| region.size != 0)
            .map(|region| PortableMemoryRegion {
                base: u32::try_from(region.base).unwrap(),
                bytes: vec![0; usize::try_from(region.size).unwrap()],
            })
            .collect();
        let snapshot = PortableMachineSnapshot {
            pc: 1,
            gas_remaining: 1,
            registers: [0; vos_pvm_program::REGISTER_COUNT],
            memory,
        };

        assert!(snapshot.is_valid());
        assert!(matches!(
            ActorMachine::restore(&blob, &[], &snapshot),
            Err(LoadError::InvalidSnapshot)
        ));
    }

    #[test]
    fn expunge_result_sentinels_never_become_continuation_pcs() {
        assert_eq!(
            decode_expunge_pc(inner::RESULT_WHO),
            Err(LoadError::MemoryOperation)
        );
        assert_eq!(
            decode_expunge_pc(inner::RESULT_HUH),
            Err(LoadError::MemoryOperation)
        );
        assert_eq!(
            decode_expunge_pc(inner::RESULT_FULL),
            Err(LoadError::MemoryOperation)
        );
        assert_eq!(decode_expunge_pc(u64::from(u32::MAX)), Ok(u32::MAX));
    }

    #[cfg(feature = "std")]
    fn physical_program() -> StandardProgram {
        StandardProgram {
            ro_data: vec![0xa5],
            rw_data: vec![0x11; 17],
            heap_pages: 1,
            stack_size: PAGE_SIZE,
            // ECALLI 42 followed by a trap. The first invoke must persist the
            // successor PC (2); recreating at that PC must execute the trap.
            code: CodeBlob {
                jump_table: Vec::new(),
                code: vec![10, 42, 0],
                bitmask: vec![1, 0, 1],
            },
        }
    }

    #[cfg(feature = "std")]
    fn initialize_physical_machine(
        machines: &mut vos_pvm::inner::InnerMachines,
        id: u32,
        program: &StandardProgram,
        args: &[u8],
    ) {
        use vos_pvm::inner::PageMode;

        let layout = program.layout(args).unwrap();
        for (region, data) in [
            (layout.ro, layout.ro_data),
            (layout.rw, layout.rw_data),
            (layout.stack, &[][..]),
            (layout.args, layout.args_data),
        ] {
            if region.size == 0 {
                continue;
            }
            let first = u32::try_from(region.base / u64::from(PAGE_SIZE)).unwrap();
            let count = u32::try_from(region.size / u64::from(PAGE_SIZE)).unwrap();
            machines
                .pages(id, first, count, PageMode::AllocateReadWrite)
                .unwrap();
            if !data.is_empty() {
                machines
                    .poke(id, u32::try_from(region.base).unwrap(), data)
                    .unwrap();
            }
            if !region.writable {
                machines
                    .pages(id, first, count, PageMode::SetReadOnly)
                    .unwrap();
            }
        }
    }

    #[cfg(feature = "std")]
    fn repeated_yield_program() -> StandardProgram {
        use vos_pvm_compiler::assembler::{Assembler, Reg};

        let yielded = [
            crate::actors::STATUS_YIELDED,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            1,
        ];
        let done = [
            crate::actors::STATUS_DONE,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            2,
        ];
        let mut rw = Vec::new();
        rw.extend_from_slice(&yielded);
        rw.extend_from_slice(&yielded);
        rw.extend_from_slice(&done);
        let base = 2 * u64::from(vos_pvm_program::ZONE_SIZE);

        // Instruction offsets are fixed by the assembler encodings:
        // ECALLI=5, branch-imm=10, and each return block=26 bytes.
        const FIRST_BRANCH: u32 = 5;
        const SECOND_BRANCH: u32 = 20;
        const FIRST_YIELD: u32 = 56;
        const SECOND_YIELD: u32 = 82;
        let mut actor = Assembler::new();
        actor
            .set_rw_data(rw)
            .ecalli(crate::abi::hostcall::SUSPEND)
            .branch_eq_imm(Reg::A0, 0, FIRST_YIELD - FIRST_BRANCH)
            .ecalli(crate::abi::hostcall::SUSPEND)
            .branch_eq_imm(Reg::A0, 0, SECOND_YIELD - SECOND_BRANCH)
            .load_imm_64(Reg::A0, base + (yielded.len() * 2) as u64)
            .load_imm_64(Reg::A1, done.len() as u64)
            .jump_ind(Reg::RA, 0);
        assert_eq!(actor.current_offset(), FIRST_YIELD);
        actor
            .load_imm_64(Reg::A0, base)
            .load_imm_64(Reg::A1, yielded.len() as u64)
            .jump_ind(Reg::RA, 0);
        assert_eq!(actor.current_offset(), SECOND_YIELD);
        actor
            .load_imm_64(Reg::A0, base + yielded.len() as u64)
            .load_imm_64(Reg::A1, yielded.len() as u64)
            .jump_ind(Reg::RA, 0);
        let blob = actor.build_standard();
        vos_pvm_program::parse_standard_program(&blob).unwrap()
    }

    #[cfg(feature = "std")]
    fn physical_snapshot(
        machines: &mut vos_pvm::inner::InnerMachines,
        id: u32,
        program: &StandardProgram,
        state: vos_pvm::inner::InvokeState,
    ) -> PortableMachineSnapshot {
        let layout = program.layout(&[]).unwrap();
        let memory = [layout.rw, layout.stack]
            .into_iter()
            .filter(|region| region.size != 0)
            .map(|region| PortableMemoryRegion {
                base: u32::try_from(region.base).unwrap(),
                bytes: machines
                    .peek(
                        id,
                        u32::try_from(region.base).unwrap(),
                        usize::try_from(region.size).unwrap(),
                    )
                    .unwrap(),
            })
            .collect();
        PortableMachineSnapshot {
            pc: machines.expunge(id).unwrap(),
            gas_remaining: state.gas,
            registers: state.registers,
            memory,
        }
    }

    #[cfg(feature = "std")]
    fn restore_physical_snapshot(
        machines: &mut vos_pvm::inner::InnerMachines,
        compact: &[u8],
        program: &StandardProgram,
        snapshot: &PortableMachineSnapshot,
    ) -> u32 {
        let id = machines.create(compact, snapshot.pc).unwrap();
        initialize_physical_machine(machines, id, program, &[]);
        for region in &snapshot.memory {
            machines.poke(id, region.base, &region.bytes).unwrap();
        }
        id
    }

    #[cfg(feature = "std")]
    fn invoke_snapshot_branch(
        machines: &mut vos_pvm::inner::InnerMachines,
        id: u32,
        snapshot: &PortableMachineSnapshot,
        resumed: bool,
    ) -> vos_pvm::inner::InvokeOutcome {
        let mut registers = snapshot.registers;
        registers[7] = u64::from(resumed);
        registers[8] = 0;
        machines
            .invoke(
                id,
                vos_pvm::inner::InvokeState {
                    gas: snapshot.gas_remaining,
                    registers,
                },
            )
            .unwrap()
    }

    #[cfg(feature = "std")]
    fn physical_output(
        machines: &mut vos_pvm::inner::InnerMachines,
        id: u32,
        state: &vos_pvm::inner::InvokeState,
    ) -> Vec<u8> {
        machines
            .peek(
                id,
                u32::try_from(state.registers[7]).unwrap(),
                usize::try_from(state.registers[8]).unwrap(),
            )
            .unwrap()
    }

    #[cfg(feature = "std")]
    #[test]
    fn physical_repeated_yield_persists_restarts_and_completes_exactly() {
        use vos_pvm::inner::{InnerExit as PhysicalExit, InnerMachines, InvokeState};

        let program = repeated_yield_program();
        let starts = vos_pvm::interpreter::compute_basic_block_starts(
            &program.code.code,
            &program.code.bitmask,
        );
        assert!(starts[15]);
        assert!(starts[56]);
        assert!(starts[82]);
        // Static branch operands are signed deltas from their instruction
        // counters, not absolute PCs.
        assert_eq!(&program.code.code[11..15], &51_u32.to_le_bytes());
        let compact = program.compact_code().unwrap();
        let mut machines = InnerMachines::new();
        let id = machines.create(&compact, 0).unwrap();
        initialize_physical_machine(&mut machines, id, &program, &[]);
        let first = machines
            .invoke(
                id,
                InvokeState {
                    gas: 1_000_000,
                    registers: program.layout(&[]).unwrap().registers,
                },
            )
            .unwrap();
        assert_eq!(
            first.exit,
            PhysicalExit::Host(u64::from(crate::abi::hostcall::SUSPEND))
        );
        let mut first_snapshot = physical_snapshot(&mut machines, id, &program, first.state);
        assert!(first_snapshot.is_valid());

        let finalizer =
            restore_physical_snapshot(&mut machines, &compact, &program, &first_snapshot);
        let first_yield = invoke_snapshot_branch(&mut machines, finalizer, &first_snapshot, false);
        assert_eq!(
            first_yield.state.registers[7],
            2 * u64::from(vos_pvm_program::ZONE_SIZE),
            "the finalized branch must publish the first yielded reply"
        );
        assert_eq!(
            first_yield.state.registers[0],
            vos_pvm_program::HALT_ADDRESS,
            "the persisted return address must survive restoration"
        );
        assert_eq!(first_yield.state.registers[8], 14);
        assert_eq!(first_yield.exit, PhysicalExit::Halt);
        assert_eq!(
            physical_output(&mut machines, finalizer, &first_yield.state)[0],
            crate::actors::STATUS_YIELDED
        );
        assert!(first_yield.state.gas < first_snapshot.gas_remaining);
        first_snapshot.gas_remaining = first_yield.state.gas;
        machines.expunge(finalizer).unwrap();

        // Recreate the complete machine from the persisted first image. It
        // reaches a second physical SUSPEND rather than replaying slice one.
        let resumed = restore_physical_snapshot(&mut machines, &compact, &program, &first_snapshot);
        let second = invoke_snapshot_branch(&mut machines, resumed, &first_snapshot, true);
        assert_eq!(
            second.exit,
            PhysicalExit::Host(u64::from(crate::abi::hostcall::SUSPEND))
        );
        let mut second_snapshot = physical_snapshot(&mut machines, resumed, &program, second.state);
        assert_ne!(second_snapshot.pc, first_snapshot.pc);
        assert!(second_snapshot.gas_remaining < first_snapshot.gas_remaining);

        let finalizer =
            restore_physical_snapshot(&mut machines, &compact, &program, &second_snapshot);
        let second_yield =
            invoke_snapshot_branch(&mut machines, finalizer, &second_snapshot, false);
        assert_eq!(second_yield.exit, PhysicalExit::Halt);
        assert_eq!(
            physical_output(&mut machines, finalizer, &second_yield.state)[0],
            crate::actors::STATUS_YIELDED
        );
        assert!(second_yield.state.gas < second_snapshot.gas_remaining);
        second_snapshot.gas_remaining = second_yield.state.gas;
        machines.expunge(finalizer).unwrap();

        let resumed =
            restore_physical_snapshot(&mut machines, &compact, &program, &second_snapshot);
        let completed = invoke_snapshot_branch(&mut machines, resumed, &second_snapshot, true);
        assert_eq!(completed.exit, PhysicalExit::Halt);
        let output = physical_output(&mut machines, resumed, &completed.state);
        assert_eq!(output[0], crate::actors::STATUS_DONE);
        assert_eq!(output.last(), Some(&2));
    }

    #[cfg(feature = "std")]
    #[test]
    fn physical_machine_snapshot_restores_exact_successor_registers_and_memory() {
        use vos_pvm::inner::{InnerExit as PhysicalExit, InnerMachines, InvokeState};

        let program = physical_program();
        let compact = program.compact_code().unwrap();
        let args = b"portable-continuation";
        let layout = program.layout(args).unwrap();
        let writable_regions: Vec<_> = [layout.rw, layout.stack]
            .into_iter()
            .filter(|region| region.size != 0)
            .collect();
        let mut machines = InnerMachines::new();
        let id = machines.create(&compact, 0).unwrap();
        initialize_physical_machine(&mut machines, id, &program, args);

        let rw_address = u32::try_from(layout.rw.base).unwrap() + 29;
        let stack_address = u32::try_from(layout.stack.base).unwrap() + 7;
        machines.poke(id, rw_address, b"rw-after-yield").unwrap();
        machines
            .poke(id, stack_address, b"stack-after-yield")
            .unwrap();
        let mut registers = layout.registers;
        registers[3] = 0xfeed_beef;
        let first = machines
            .invoke(
                id,
                InvokeState {
                    gas: 100_000,
                    registers,
                },
            )
            .unwrap();
        assert_eq!(first.exit, PhysicalExit::Host(42));

        let memory = writable_regions
            .iter()
            .map(|region| PortableMemoryRegion {
                base: u32::try_from(region.base).unwrap(),
                bytes: machines
                    .peek(
                        id,
                        u32::try_from(region.base).unwrap(),
                        usize::try_from(region.size).unwrap(),
                    )
                    .unwrap(),
            })
            .collect();
        let pc = machines.expunge(id).unwrap();
        let snapshot = PortableMachineSnapshot {
            pc,
            gas_remaining: first.state.gas,
            registers: first.state.registers,
            memory,
        };
        assert_eq!(snapshot.pc, 2);
        assert!(snapshot.is_valid());
        ActorMachine::validate_snapshot_regions(&snapshot, &writable_regions).unwrap();
        assert!(!machines.contains(id));

        let restored = machines.create(&compact, snapshot.pc).unwrap();
        initialize_physical_machine(&mut machines, restored, &program, args);
        for region in &snapshot.memory {
            machines.poke(restored, region.base, &region.bytes).unwrap();
            assert_eq!(
                machines
                    .peek(restored, region.base, region.bytes.len())
                    .unwrap(),
                region.bytes
            );
        }
        assert_eq!(
            machines
                .peek(restored, rw_address, b"rw-after-yield".len())
                .unwrap(),
            b"rw-after-yield"
        );
        assert_eq!(
            machines
                .peek(restored, stack_address, b"stack-after-yield".len())
                .unwrap(),
            b"stack-after-yield"
        );
        let resumed = machines
            .invoke(
                restored,
                InvokeState {
                    gas: snapshot.gas_remaining,
                    registers: snapshot.registers,
                },
            )
            .unwrap();
        assert_eq!(resumed.exit, PhysicalExit::Panic);
        assert_eq!(resumed.state.registers, snapshot.registers);
    }

    #[cfg(feature = "std")]
    #[test]
    fn sixty_fourth_machine_spills_and_fifo_restore_reuses_expunge_slots() {
        use vos_pvm::inner::{InnerError, InnerMachines, MAX_INNER_MACHINES};

        let compact = physical_program().compact_code().unwrap();
        let mut machines = InnerMachines::new();
        for expected in 0..MAX_INNER_MACHINES as u32 {
            assert_eq!(machines.create(&compact, 0), Ok(expected));
        }
        assert_eq!(machines.len(), 63);
        assert_eq!(machines.create(&compact, 0), Err(InnerError::Full));

        // Persisting the FIFO head expunges it; the formerly-64th actor can
        // now run in the released lowest slot while the snapshot is offline.
        assert_eq!(machines.expunge(0), Ok(0));
        assert_eq!(machines.create(&compact, 0), Ok(0));
        assert_eq!(machines.create(&compact, 0), Err(InnerError::Full));

        // Restoring the spilled head is deterministic once the next FIFO
        // machine yields and frees its own slot.
        assert_eq!(machines.expunge(1), Ok(0));
        assert_eq!(machines.create(&compact, 2), Ok(1));
        assert_eq!(machines.len(), 63);
    }
}
