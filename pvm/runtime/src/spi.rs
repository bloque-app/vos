//! Standard-PVM program loading for the executor.
//!
//! Portable byte parsing and memory layout live in `vos-pvm-program`, shared
//! with the compiler and guest agent runtimes. This module adds executor
//! opcode validation and exact static host-call admission for standard outer
//! runtimes. Standard programs are never projected through the legacy
//! capability-manifest kernel in production.

use alloc::vec::Vec;

use crate::args::{Args, decode_args};
use crate::instruction::Opcode;
use crate::program::ParsedCodeBlob;

pub use vos_pvm_program::{Region as SpiRegion, StandardLayout, StandardProgram, read_nat};

/// The complete host-call surface implemented by [`crate::refine_host`].
///
/// Runtime package admission uses this exact set to reject even unreachable
/// calls outside the standard inner-machine interface. Keeping the policy
/// next to the standard-program decoder prevents a caller from accidentally
/// inspecting a retired capability manifest under these rules.
/// Refine's standard machine calls (9 to 14). Profile runtimes may also use
/// [`REFINE_PROFILE_HOST_CALLS`].
pub const REFINE_HOST_CALL_ALLOWLIST: [u64; 6] = [9, 10, 11, 12, 13, 14];
/// Calls an agent-runtime profile may add: Gray Paper `historical_lookup` (7), served by
/// the embedder from natively verified preimages, and the VOS BLAKE2b (100) and curve
/// (110-114) precompiles, served by Refine itself.
pub const REFINE_PROFILE_HOST_CALLS: [u64; 7] = [7, 100, 110, 111, 112, 113, 114];

/// Failure while inspecting a standard program's complete static host-call
/// surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostCallInspectionError {
    /// The bytes are not one canonical, executor-valid standard program.
    InvalidProgram,
    /// An `ecalli` instruction names a call the selected host does not
    /// implement. The full decoded immediate is retained for diagnostics.
    UnsupportedHostCall(u64),
}

/// Decode the canonical compact code blob used by the standard `machine`
/// host call.
pub fn parse_compact_code_blob(data: &[u8]) -> Option<ParsedCodeBlob> {
    let code = vos_pvm_program::parse_compact_code_blob(data)?;
    Some(ParsedCodeBlob {
        jump_table: code.jump_table,
        code: code.code,
        bitmask: code.bitmask,
    })
}

/// Validate an executable code blob and its initial instruction counter.
///
/// The external counter is a full PVM register. Values outside the host's
/// index domain are invalid rather than truncated.
pub fn validate_code_blob(program: &ParsedCodeBlob, initial_pc: u64) -> bool {
    let code = &program.code;
    let bitmask = &program.bitmask;
    // Runtime counters are u32 even on a 64-bit host. Establish that domain
    // here so full Ψ remains total for arbitrarily large caller-provided
    // registers instead of relying on a later infallible conversion.
    let Ok(initial_pc) = u32::try_from(initial_pc) else {
        return false;
    };
    let initial_pc = initial_pc as usize;
    if code.is_empty()
        || bitmask.len() != code.len()
        || initial_pc >= code.len()
        || bitmask[initial_pc] != 1
        || Opcode::from_byte(code[initial_pc]).is_none()
    {
        return false;
    }

    let mut pc = 0usize;
    loop {
        if pc >= code.len() || bitmask[pc] != 1 {
            return false;
        }
        let Some(opcode) = Opcode::from_byte(code[pc]) else {
            return false;
        };
        let next = (1..=25)
            .map(|delta| pc + delta)
            .find(|&candidate| candidate >= code.len() || bitmask[candidate] == 1)
            .unwrap_or(pc + 25);
        if next > code.len() {
            return false;
        }
        if next == code.len() {
            return opcode.is_terminator();
        }
        pc = next;
    }
}

/// Full Gray Paper `deblob(program, initial_pc)` boundary.
///
/// This combines canonical compact decoding, whole-program validation and
/// initial-instruction validation. Callers implementing full Ψ must turn a
/// `None` result into a no-charge panic over the unchanged input state;
/// callers implementing Ω_M retain its specified `HUH` mapping.
pub fn deblob(data: &[u8], initial_pc: u64) -> Option<ParsedCodeBlob> {
    let program = parse_compact_code_blob(data)?;
    validate_code_blob(&program, initial_pc).then_some(program)
}

/// Parse and executor-validate a standard program.
pub fn parse_standard_program(blob: &[u8]) -> Option<StandardProgram> {
    let program = vos_pvm_program::parse_standard_program(blob)?;
    let executable = ParsedCodeBlob {
        jump_table: program.code.jump_table.clone(),
        code: program.code.code.clone(),
        bitmask: program.code.bitmask.clone(),
    };
    validate_code_blob(&executable, 0).then_some(program)
}

/// Return every statically present `ecalli` immediate in instruction order.
///
/// The scan covers unreachable blocks as well as the entry-reachable graph:
/// package admission must not let a later data-dependent branch expose a call
/// which was skipped by a representative run. Dynamic `ecall` cannot appear
/// because [`parse_standard_program`] rejects that non-standard opcode first.
pub fn inspect_standard_program_host_calls(
    blob: &[u8],
) -> Result<Vec<u64>, HostCallInspectionError> {
    let program = parse_standard_program(blob).ok_or(HostCallInspectionError::InvalidProgram)?;
    let code = &program.code.code;
    let bitmask = &program.code.bitmask;
    let mut calls = Vec::new();

    for pc in 0..code.len() {
        if bitmask[pc] != 1 {
            continue;
        }
        let opcode = Opcode::from_byte(code[pc]).ok_or(HostCallInspectionError::InvalidProgram)?;
        if opcode != Opcode::Ecalli {
            continue;
        }
        let next = ((pc + 1)..code.len())
            .find(|candidate| bitmask[*candidate] == 1)
            .unwrap_or(code.len());
        let skip = next
            .checked_sub(pc + 1)
            .ok_or(HostCallInspectionError::InvalidProgram)?;
        let Args::Imm { imm } = decode_args(code, pc, skip, opcode.category()) else {
            return Err(HostCallInspectionError::InvalidProgram);
        };
        calls.push(imm);
    }

    Ok(calls)
}

/// Require every static host call in a canonical standard program to belong
/// to `allowed`.
pub fn validate_standard_program_host_calls(
    blob: &[u8],
    allowed: &[u64],
) -> Result<(), HostCallInspectionError> {
    for call in inspect_standard_program_host_calls(blob)? {
        if !allowed.contains(&call) {
            return Err(HostCallInspectionError::UnsupportedHostCall(call));
        }
    }
    Ok(())
}

/// Validate a portable outer runtime against the exact host-call interface
/// serviced by [`crate::refine_host::RefineContext`].
pub fn validate_refine_host_calls(blob: &[u8]) -> Result<(), HostCallInspectionError> {
    validate_standard_program_host_calls(blob, &REFINE_HOST_CALL_ALLOWLIST)
}

/// [`validate_refine_host_calls`], also admitting [`REFINE_PROFILE_HOST_CALLS`].
pub fn validate_refine_profile_host_calls(blob: &[u8]) -> Result<(), HostCallInspectionError> {
    let mut allowed = alloc::vec::Vec::from(REFINE_HOST_CALL_ALLOWLIST);
    allowed.extend(REFINE_PROFILE_HOST_CALLS);
    validate_standard_program_host_calls(blob, &allowed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use vos_pvm_program::{CodeBlob, build_standard_program};

    fn standard_blob(
        ro: &[u8],
        rw: &[u8],
        heap_pages: u32,
        stack_size: u32,
        code: &[u8],
        bitmask: &[u8],
    ) -> Vec<u8> {
        build_standard_program(&StandardProgram {
            ro_data: ro.to_vec(),
            rw_data: rw.to_vec(),
            heap_pages,
            stack_size,
            code: CodeBlob {
                jump_table: Vec::new(),
                code: code.to_vec(),
                bitmask: bitmask.to_vec(),
            },
        })
        .unwrap()
    }

    fn host_call_program(calls: &[u32]) -> Vec<u8> {
        let mut code = Vec::new();
        let mut bitmask = Vec::new();
        for call in calls {
            code.push(Opcode::Ecalli as u8);
            bitmask.push(1);
            for byte in call.to_le_bytes() {
                code.push(byte);
                bitmask.push(0);
            }
        }
        code.push(Opcode::Trap as u8);
        bitmask.push(1);
        standard_blob(&[], &[], 0, 0, &code, &bitmask)
    }

    #[test]
    fn parser_adds_opcode_validation() {
        let valid = standard_blob(&[], &[], 0, 0, &[0], &[1]);
        assert!(parse_standard_program(&valid).is_some());
        let invalid = standard_blob(&[], &[], 0, 0, &[0xff], &[1]);
        assert!(parse_standard_program(&invalid).is_none());
        let runtime_extension = standard_blob(&[], &[], 0, 0, &[3], &[1]);
        assert!(
            parse_standard_program(&runtime_extension).is_none(),
            "opcode 3 is not in the Gray Paper v0.8.0 opcode set"
        );
        let retired_unary_number = standard_blob(&[], &[], 0, 0, &[111], &[1]);
        assert!(
            parse_standard_program(&retired_unary_number).is_none(),
            "opcode 111 is not in the Gray Paper v0.8.0 opcode set"
        );
    }

    #[test]
    fn whole_program_host_call_inspection_is_exact_and_ordered() {
        assert_eq!(
            REFINE_HOST_CALL_ALLOWLIST,
            [
                crate::inner::host_call::MACHINE as u64,
                crate::inner::host_call::PEEK as u64,
                crate::inner::host_call::POKE as u64,
                crate::inner::host_call::PAGES as u64,
                crate::inner::host_call::INVOKE as u64,
                crate::inner::host_call::EXPUNGE as u64,
            ]
        );
        let blob = host_call_program(&[14, 9, 14]);
        assert_eq!(
            inspect_standard_program_host_calls(&blob),
            Ok(vec![14, 9, 14])
        );
        assert_eq!(validate_refine_host_calls(&blob), Ok(()));
    }

    #[test]
    fn refine_allowlist_rejects_vos_only_and_unreachable_calls() {
        // A trap before the forbidden call makes the call unreachable from
        // entry, but package admission must still reject its static presence.
        let code = [
            Opcode::Trap as u8,
            Opcode::Ecalli as u8,
            118,
            0,
            0,
            0,
            Opcode::Trap as u8,
        ];
        let bitmask = [1, 1, 0, 0, 0, 0, 1];
        let blob = standard_blob(&[], &[], 0, 0, &code, &bitmask);
        assert_eq!(
            validate_refine_host_calls(&blob),
            Err(HostCallInspectionError::UnsupportedHostCall(118))
        );
    }

    #[test]
    fn inspection_rejects_non_programs_and_preserves_full_immediates() {
        assert_eq!(
            inspect_standard_program_host_calls(b"not a standard program"),
            Err(HostCallInspectionError::InvalidProgram)
        );
        let blob = host_call_program(&[u32::MAX]);
        assert_eq!(
            inspect_standard_program_host_calls(&blob),
            Ok(vec![u64::MAX])
        );
        assert_eq!(
            validate_standard_program_host_calls(&blob, &[u32::MAX as u64]),
            Err(HostCallInspectionError::UnsupportedHostCall(u64::MAX))
        );
    }

    #[test]
    fn validator_rejects_a_counter_outside_the_runtime_pc_domain() {
        let executable = ParsedCodeBlob {
            jump_table: Vec::new(),
            code: vec![0],
            bitmask: vec![1],
        };
        assert!(!validate_code_blob(&executable, u64::from(u32::MAX) + 1));
    }

    #[test]
    fn layout_places_regions_per_specification() {
        let ro = [0xaa; 40];
        let rw = [0xbb; 12];
        let blob = standard_blob(&ro, &rw, 3, 4096, &[0], &[1]);
        let program = parse_standard_program(&blob).unwrap();
        let layout = program.layout(&[0x11; 8]).unwrap();
        assert_eq!(layout.ro.base, u64::from(crate::PVM_ZONE_SIZE));
        assert!(!layout.ro.writable);
        assert!(layout.rw.writable);
        assert_eq!(layout.registers[0], crate::PVM_HALT_ADDR);
        assert_eq!(layout.registers[7], layout.args.base);
        assert_eq!(layout.registers[8], 8);
    }

    #[test]
    fn compact_parser_rejects_trailing_bytes() {
        let code = CodeBlob {
            jump_table: vec![],
            code: vec![0],
            bitmask: vec![1],
        };
        let mut bytes = vos_pvm_program::build_compact_code_blob(&code).unwrap();
        assert!(parse_compact_code_blob(&bytes).is_some());
        bytes.push(0);
        assert!(parse_compact_code_blob(&bytes).is_none());
    }
}
