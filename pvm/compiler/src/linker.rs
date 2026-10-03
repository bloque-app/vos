//! Linker-based RISC-V ELF to PVM transpilation.
//!
//! Unlike the basic `transpile_elf`, this module processes ELF relocations
//! to correctly handle data references in code. This is required for
//! real-world programs (like k256 crypto) that reference .rodata constants.
//!
//! Approach:
//! 1. Parse ELF sections and relocations
//! 2. Compute PVM memory layout (stack, ro_data, rw_data addresses)
//! 3. Build a relocation map: code_offset → resolved_address
//! 4. Translate RISC-V instructions, using relocation info to replace
//!    AUIPC+LO12 pairs with direct load_imm of the final PVM address

use crate::TranspileError;
use crate::emitter;
use crate::riscv::{OpcodeEncoding, TranslationContext, decode_b_imm, decode_j_imm};
use std::collections::{HashMap, HashSet};

/// RISC-V relocation types we care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelocType {
    /// R_RISCV_32 (1): Absolute 32-bit address
    Abs32,
    /// R_RISCV_64 (2): Absolute 64-bit address
    Abs64,
    /// R_RISCV_CALL_PLT (19): AUIPC+JALR pair for function calls
    CallPlt,
    /// R_RISCV_PCREL_HI20 (23): Upper 20 bits of PC-relative address (AUIPC)
    PcrelHi20,
    /// R_RISCV_PCREL_LO12_I (24): Lower 12 bits, I-type (load/addi)
    PcrelLo12I,
    /// R_RISCV_PCREL_LO12_S (25): Lower 12 bits, S-type (store)
    PcrelLo12S,
    /// R_RISCV_ADD32 (35): Add 32-bit (paired with SUB32 for relative jump tables)
    Add32,
    /// R_RISCV_SUB32 (39): Subtract 32-bit (paired with ADD32 for relative jump tables)
    Sub32,
}

impl RelocType {
    fn from_raw(r: u32) -> Option<Self> {
        match r {
            1 => Some(Self::Abs32),
            2 => Some(Self::Abs64),
            19 => Some(Self::CallPlt),
            23 => Some(Self::PcrelHi20),
            24 => Some(Self::PcrelLo12I),
            25 => Some(Self::PcrelLo12S),
            35 => Some(Self::Add32),
            39 => Some(Self::Sub32),
            _ => None,
        }
    }
}

/// Parsed ELF with relocation info for linking.
struct LinkedElf {
    is_64bit: bool,
    /// All code sections: (file_offset, vaddr, data)
    code_sections: Vec<(u64, u64, Vec<u8>)>,
    /// RO data blob and the vaddr its first byte is linked at
    /// (`stack_size`, the page-floored lowest ro section address).
    ro_data: Vec<u8>,
    ro_base: u64,
    /// RW data blob and the vaddr its first byte is linked at
    /// (`min(rw_pvm_base, lowest rw section address)`).
    rw_data: Vec<u8>,
    rw_base: u64,
    /// Lowest rw section vaddr (== `rw_base` when there are no rw sections).
    rw_min: u64,
    /// Stack size in bytes (= ro_base, so RO data is at the right PVM address)
    stack_size: u32,
    /// Value of a `__vos_stack_size` symbol, when the guest declares its
    /// standard-program stack explicitly (see [`spi_stack_size`]).
    declared_stack_size: Option<u64>,
    /// Heap pages
    heap_pages: u32,
    /// PCREL_HI20: AUIPC instruction vaddr → resolved data address.
    /// The AUIPC itself should emit load_imm with this address.
    hi20_targets: HashMap<u64, u64>,
    /// PCREL_LO12: instruction vaddr → resolved data address (looked up from paired HI20).
    /// These instructions should use the already-loaded address (from AUIPC/load_imm).
    lo12_targets: HashMap<u64, u64>,
    /// CALL_PLT: AUIPC instruction vaddr → target function RISC-V vaddr.
    call_targets: HashMap<u64, u64>,
    /// Absolute code pointers in data sections: (data_vaddr, target_code_vaddr, entry_size).
    /// entry_size is 4 for 32-bit or 8 for 64-bit entries.
    abs_code_ptrs: Vec<(u64, u64, u8)>,
    /// SUB32 relocations: (data_vaddr, subtracted_addr).
    /// For LLVM relative jump tables: entry = target - subtracted_addr.
    /// Combined with the resolved entry value, we can recover the target.
    sub32_relocs: Vec<(u64, u64)>,
    /// Bytes whose data-pointer interpretation is already defined by a
    /// relocation, including non-code targets. Never rescan as raw pointers.
    data_relocation_ranges: Vec<(u64, u64)>,
    /// Code section address ranges for detecting code pointers.
    code_ranges: Vec<(u64, u64)>,
    /// Every statically reachable RISC-V instruction address. Translation-time
    /// predecessor fusion must stop at these boundaries.
    control_flow_targets: HashSet<u64>,
    /// ELF entry point (e_entry) — the RISC-V vaddr of _start (refine entry).
    entry_vaddr: u64,
    /// RISC-V vaddr of the exported `accumulate` symbol, if the service
    /// defines one (the accumulate entry). `None` for refine-only blobs, whose
    /// IC-5 prologue slot becomes a trap.
    accumulate_vaddr: Option<u64>,
}

/// The container-independent result of transpiling an ELF: the code in GP
/// instruction encoding (plus bitmask and jump table) and the memory-section
/// blobs at their linked base addresses. Both containers — the `JAR\x02`
/// capability manifest ([`link_elf`]) and the GP standard program
/// ([`link_elf_spi`]) — are serializations of exactly these fields.
struct TranspiledElf {
    #[cfg(test)]
    address_map: HashMap<u64, u32>,
    code: Vec<u8>,
    bitmask: Vec<u8>,
    jump_table: Vec<u32>,
    /// RO data blob; its first byte is linked at `ro_base`.
    ro_data: Vec<u8>,
    ro_base: u64,
    /// RW data blob; its first byte is linked at `rw_base`.
    rw_data: Vec<u8>,
    rw_base: u64,
    /// Lowest rw section vaddr (real data starts here; `[rw_base, rw_min)`
    /// is zero padding).
    rw_min: u64,
    /// Stack byte capacity (= the page-floored lowest ro vaddr, min 16 KiB).
    stack_size: u32,
    /// The guest's explicit standard-program stack, if it declares one.
    declared_stack_size: Option<u64>,
    /// Zeroed heap pages beyond `rw_data`.
    heap_pages: u32,
}

/// Transpile an rv64em ELF into a JAR capability manifest PVM blob.
pub fn link_elf(elf_data: &[u8]) -> Result<Vec<u8>, TranspileError> {
    link_elf_with_argument_pages(elf_data, 1)
}

/// Transpile an ELF with an explicitly sized ordinary slot-0 argument DATA
/// capability. The default [`link_elf`] remains one page.
pub fn link_elf_with_argument_pages(
    elf_data: &[u8],
    argument_pages: u32,
) -> Result<Vec<u8>, TranspileError> {
    if argument_pages == 0 {
        return Err(TranspileError::InvalidSection(
            "argument DATA capability must contain at least one page".into(),
        ));
    }
    // The capability-manifest container is an already-pinned production
    // format. Keep its historical read-only code-pointer rewrite so changes
    // needed by standard programs cannot silently repin existing services.
    let t = transpile_elf(elf_data, false, OpcodeEncoding::CapabilityManifest)?;
    Ok(emitter::build_service_program_with_args_pages(
        &t.code,
        &t.bitmask,
        &t.jump_table,
        &t.ro_data,
        &t.rw_data,
        t.stack_size / 4096,
        t.heap_pages,
        t.heap_pages,
        argument_pages,
    ))
}

/// `Z_Z` — the GP initialization zone size (2¹⁶).
const Z_Z: u64 = vos_pvm::PVM_ZONE_SIZE as u64;

/// Round `x` up to a multiple of the zone size `Z_Z`.
fn zone_round(x: u64) -> u64 {
    x.div_ceil(Z_Z) * Z_Z
}

/// Transpile an rv64em ELF into a **GP standard-program (SPI) blob** — the
/// format `vos_pvm::spi::parse_standard_program` consumes and
/// `vos_pvm::refine::execute_with` runs. It shares instruction translation
/// with [`link_elf`], adds standard-program read-write code-pointer rewriting,
/// and uses the entry prologue IC 0 = refine, IC 5 = accumulate-or-trap.
///
/// Header-field derivation (manifest ↔ SPI mapping):
///
/// - **`s` (stack size, `E₃`)** = the linker's `stack_size` = the manifest's
///   `stack_pages × 4096` (the page-floored lowest ro section vaddr, minimum
///   16 KiB). The byte capacity is identical in both containers; only the
///   placement differs — the manifest maps the stack at `[0, s)` with
///   `φ1 = s`, while `StandardProgram::layout` maps `page_round(s)` bytes
///   just below the argument zone with `φ1 = 0xFEFE_0000`. `φ1` is
///   host-installed in both, so SP-relative guest code is placement-blind.
///   A guest that defines `__vos_stack_size` sets `s` directly instead, and
///   only in this container ([`spi_stack_size`]).
/// - **`z` (heap pages, `E₂`)** includes the manifest's explicit heap and
///   every trailing all-zero read-write page (normally `.bss`). Standard
///   programs distinguish initialized bytes from zero pages directly, so
///   encoding those pages in `w` would only inflate the artifact. The total
///   mapped read-write span remains identical page-for-page.
/// - **`o` (read-only data)** = the ro blob **re-based to the GP ro base
///   `Z_Z` = `0x1_0000`**: zero-prefix padding covers `[Z_Z, ro_base)`. An
///   ELF whose ro sections are linked below `Z_Z` is rejected — its embedded
///   absolute addresses could never resolve under the GP layout.
/// - **`w` (read-write data)** = the rw blob **re-based to the GP rw base
///   `2·Z_Z + zone_round(|o|)`** (leading zero padding stripped or added).
///   An ELF whose rw/bss sections are linked below that base is rejected.
///
/// Consequently `parse_standard_program(blob)?.layout(args)` lands every
/// data section at the vaddr it was linked at, so absolute data addresses
/// embedded in the translated code resolve identically. A guest targeting
/// this backend must therefore be linked against the GP map: `.rodata` at
/// `0x1_0000`, `.data`/`.bss` at `2·Z_Z + zone_round(|o|)` (`0x3_0000` when
/// `0 < |o| ≤ 64 KiB`, `0x2_0000` when there is no ro data). Code and stack
/// placement need no linker cooperation (code addresses are translated;
/// the stack is SP-relative).
pub fn link_elf_spi(elf_data: &[u8]) -> Result<Vec<u8>, TranspileError> {
    let t = transpile_elf(elf_data, true, OpcodeEncoding::Standard)?;

    // Re-base the ro blob from its linked base to the GP ro base Z_Z.
    let ro_data = if t.ro_data.is_empty() {
        Vec::new()
    } else if t.ro_base >= Z_Z {
        let mut v = vec![0u8; (t.ro_base - Z_Z) as usize];
        v.extend_from_slice(&t.ro_data);
        v
    } else {
        return Err(TranspileError::InvalidSection(format!(
            "SPI: read-only data linked at {:#x}, below the GP read-only base {Z_Z:#x}",
            t.ro_base,
        )));
    };

    // Re-base the rw blob to the GP rw base 2·Z_Z + zone_round(|o|).
    let rw_spi_base = 2 * Z_Z + zone_round(ro_data.len() as u64);
    let mut rw_data = if t.rw_data.is_empty() {
        Vec::new()
    } else if t.rw_min < rw_spi_base {
        return Err(TranspileError::InvalidSection(format!(
            "SPI: read-write data linked at {:#x}, below the GP read-write base {rw_spi_base:#x} \
             (= 2 * Z_Z + zone_round(ro_size))",
            t.rw_min,
        )));
    } else if t.rw_base >= rw_spi_base {
        let mut v = vec![0u8; (t.rw_base - rw_spi_base) as usize];
        v.extend_from_slice(&t.rw_data);
        v
    } else {
        // rw_base < rw_spi_base <= rw_min: everything stripped is the blob's
        // own leading zero padding, so the data keeps its linked vaddr.
        t.rw_data[(rw_spi_base - t.rw_base) as usize..].to_vec()
    };

    // Standard programs encode zero-initialized memory as heap pages. Fold
    // the read-write blob's trailing zero pages (principally ELF NOBITS
    // `.bss`) into `z` while preserving the exact total mapped page count.
    let page_size = vos_pvm::PVM_PAGE_SIZE as usize;
    let original_rw_pages = rw_data.len().div_ceil(page_size);
    let compact_len = rw_data
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |index| index + 1);
    rw_data.truncate(compact_len);
    let compact_rw_pages = compact_len.div_ceil(page_size);
    let reclaimed_zero_pages = original_rw_pages - compact_rw_pages;
    let heap_pages = t
        .heap_pages
        .checked_add(reclaimed_zero_pages as u32)
        .ok_or_else(|| TranspileError::InvalidSection("SPI: heap page count overflow".into()))?;

    // Wire-width guards: |o|, |w|, s are E₃-encoded; z is E₂-encoded.
    for (what, len) in [("read-only", ro_data.len()), ("read-write", rw_data.len())] {
        if len >= 1 << 24 {
            return Err(TranspileError::InvalidSection(format!(
                "SPI: {what} data spans {len:#x} bytes, exceeding the E3 field width",
            )));
        }
    }
    let stack_size = spi_stack_size(t.stack_size, t.declared_stack_size)?;
    let heap_pages = u16::try_from(heap_pages).map_err(|_| {
        TranspileError::InvalidSection(format!(
            "SPI: heap page count {heap_pages} exceeds the E2 field width",
        ))
    })?;

    let blob = crate::spi::build_spi_blob(
        &ro_data,
        &rw_data,
        heap_pages,
        stack_size,
        &t.code,
        &t.bitmask,
        &t.jump_table,
    );

    // Fail-early self-check: the blob must re-parse and its layout must fit
    // the 32-bit guest address space (GP eq A.42's total-size guard).
    let prog = vos_pvm::spi::parse_standard_program(&blob).ok_or_else(|| {
        TranspileError::InvalidSection("SPI: emitted blob does not re-parse".into())
    })?;
    prog.layout(&[]).ok_or_else(|| {
        TranspileError::InvalidSection(
            "SPI: memory layout exceeds the 32-bit guest address space".into(),
        )
    })?;

    Ok(blob)
}

/// Linker-script symbol whose value is a guest's standard-program stack size.
pub const SPI_STACK_SIZE_SYMBOL: &str = "__vos_stack_size";

/// The standard program's stack size `s`.
///
/// Without a declaration it is the page-floored lowest read-only address, as
/// it has always been: the linker script's read-only base doubles as the
/// stack size, which forces zero padding into the read-only blob whenever an
/// actor needs more than the scaffold's 64 KiB. A guest may instead declare
/// `__vos_stack_size` (whole pages, below the `E3` field width) and link its
/// read-only data at the standard base with no padding. Either way the value
/// is in the program's header, so it is part of the ProgramId.
fn spi_stack_size(layout_derived: u32, declared: Option<u64>) -> Result<u32, TranspileError> {
    let stack_size = match declared {
        None => u64::from(layout_derived),
        Some(declared) => {
            if declared == 0 || declared % vos_pvm::PVM_PAGE_SIZE as u64 != 0 {
                return Err(TranspileError::InvalidSection(format!(
                    "SPI: {SPI_STACK_SIZE_SYMBOL} {declared:#x} is not a nonzero whole number of pages",
                )));
            }
            declared
        }
    };
    if stack_size >= 1 << 24 {
        return Err(TranspileError::InvalidSection(format!(
            "SPI: stack size {stack_size:#x} exceeds the E3 field width",
        )));
    }
    Ok(stack_size as u32)
}

/// The shared ELF → GP-encoded-program translation both containers build on.
fn transpile_elf(
    elf_data: &[u8],
    rewrite_read_write_code_pointers: bool,
    opcode_encoding: OpcodeEncoding,
) -> Result<TranspiledElf, TranspileError> {
    let elf = parse_linked_elf(elf_data)?;
    let mut ctx = TranslationContext::with_opcode_encoding(elf.is_64bit, opcode_encoding);
    ctx.code_ranges = elf.code_ranges.clone();

    // Emit the two-slot GP entry prologue. ICs are byte offsets into the code,
    // and a plain jump (opcode 40 + imm32) is exactly 5 bytes, so the two
    // jumps land at IC 0 and IC 5 respectively — the entry points a GP host
    // selects by starting the instruction counter at 0 (refine / is-authorized)
    // or 5 (accumulate). SP is no longer initialized here: the host owns it
    // (kernel installs φ[1]=stack_top from the blob's container metadata). Each
    // jump ends its basic block, so IC 5 begins a fresh block. Both fixups are
    // resolved after translation in apply_fixups() (RISC-V vaddr → PVM PC).
    //
    // IC 0 → refine body = the ELF entry point (e_entry / _start).
    ctx.emit_jump(elf.entry_vaddr);
    // Hard assert (not debug): the accumulate entry MUST begin at IC 5, so the
    // refine jump has to occupy exactly bytes 0..5. This is a consensus-visible
    // GP layout invariant — a one-time cost per link, kept in release builds so
    // a future change to the jump encoding can't silently misplace IC 5.
    assert_eq!(ctx.code.len(), 5, "refine jump must occupy IC 0..5");
    // IC 5 → accumulate body = exported `accumulate` symbol, or a trap for a
    // refine-only blob (an accumulate invocation must fail loud, not fall
    // through into the refine body).
    match elf.accumulate_vaddr {
        Some(vaddr) => ctx.emit_jump(vaddr),
        None => {
            ctx.emit_inst(0); // trap
        }
    }

    for (_file_off, vaddr, data) in &elf.code_sections {
        translate_section_linked(&mut ctx, data, *vaddr, &elf)?;
    }
    ctx.apply_fixups();

    let mut ro_data = elf.ro_data.clone();
    let mut rw_data = elf.rw_data.clone();
    rewrite_data_code_ptrs(
        &elf,
        &mut ctx,
        &mut ro_data,
        &mut rw_data,
        rewrite_read_write_code_pointers,
    );

    crate::peephole_fuse_load_imm_alu(&mut ctx.code, &mut ctx.bitmask, &ctx.jump_table);
    crate::peephole_fuse_load_imm_memory(&mut ctx.code, &mut ctx.bitmask, &ctx.jump_table);
    crate::peephole_eliminate_dead_load_imm(&mut ctx.code, &mut ctx.bitmask, &ctx.jump_table);
    #[cfg(not(test))]
    crate::ensure_branch_targets_are_block_starts(
        &mut ctx.code,
        &mut ctx.bitmask,
        &mut ctx.jump_table,
    );
    #[cfg(test)]
    crate::ensure_branch_targets_with_pc_map(
        &mut ctx.code,
        &mut ctx.bitmask,
        &mut ctx.jump_table,
        |offsets| {
            for pc in ctx.address_map.values_mut() {
                *pc = offsets[*pc as usize];
            }
        },
    );

    Ok(TranspiledElf {
        #[cfg(test)]
        address_map: ctx.address_map,
        code: ctx.code,
        bitmask: ctx.bitmask,
        jump_table: ctx.jump_table,
        ro_data,
        ro_base: elf.ro_base,
        rw_data,
        rw_base: elf.rw_base,
        rw_min: elf.rw_min,
        stack_size: elf.stack_size,
        declared_stack_size: elf.declared_stack_size,
        heap_pages: elf.heap_pages,
    })
}

/// Parse ELF with full relocation info.
fn parse_linked_elf(data: &[u8]) -> Result<LinkedElf, TranspileError> {
    if data.len() < 64 || data[0..4] != [0x7F, b'E', b'L', b'F'] {
        return Err(TranspileError::ElfParse("not an ELF file".into()));
    }

    let is_64bit = match data[4] {
        1 => false,
        2 => true,
        _ => return Err(TranspileError::ElfParse("unsupported ELF class".into())),
    };

    if !is_64bit {
        return Err(TranspileError::ElfParse(
            "linker requires 64-bit ELF (rv64em)".into(),
        ));
    }

    // ELF64 header fields
    let e_entry = u64::from_le_bytes(data[24..32].try_into().unwrap());
    let e_shoff = u64::from_le_bytes(data[40..48].try_into().unwrap()) as usize;
    let e_shentsize = u16::from_le_bytes(data[58..60].try_into().unwrap()) as usize;
    let e_shnum = u16::from_le_bytes(data[60..62].try_into().unwrap()) as usize;
    let e_shstrndx = u16::from_le_bytes(data[62..64].try_into().unwrap()) as usize;

    // Section name string table
    let strtab = {
        let sh = e_shoff + e_shstrndx * e_shentsize;
        let off = u64::from_le_bytes(data[sh + 24..sh + 32].try_into().unwrap()) as usize;
        let sz = u64::from_le_bytes(data[sh + 32..sh + 40].try_into().unwrap()) as usize;
        &data[off..off + sz]
    };

    let get_name = |name_off: usize| -> &str {
        if name_off >= strtab.len() {
            return "";
        }
        let end = strtab[name_off..].iter().position(|&b| b == 0).unwrap_or(0);
        std::str::from_utf8(&strtab[name_off..name_off + end]).unwrap_or("")
    };

    // First pass: collect section metadata
    struct SectionInfo {
        name_off: usize,
        sh_type: u32,
        flags: u64,
        addr: u64,
        file_off: usize,
        size: usize,
        link: usize,
        _info: usize,
    }

    let mut sections = Vec::with_capacity(e_shnum);
    for i in 0..e_shnum {
        let sh = e_shoff + i * e_shentsize;
        if sh + e_shentsize > data.len() {
            break;
        }
        sections.push(SectionInfo {
            name_off: u32::from_le_bytes(data[sh..sh + 4].try_into().unwrap()) as usize,
            sh_type: u32::from_le_bytes(data[sh + 4..sh + 8].try_into().unwrap()),
            flags: u64::from_le_bytes(data[sh + 8..sh + 16].try_into().unwrap()),
            addr: u64::from_le_bytes(data[sh + 16..sh + 24].try_into().unwrap()),
            file_off: u64::from_le_bytes(data[sh + 24..sh + 32].try_into().unwrap()) as usize,
            size: u64::from_le_bytes(data[sh + 32..sh + 40].try_into().unwrap()) as usize,
            link: u32::from_le_bytes(data[sh + 40..sh + 44].try_into().unwrap()) as usize,
            _info: u32::from_le_bytes(data[sh + 44..sh + 48].try_into().unwrap()) as usize,
        });
    }

    // Collect code sections, ro sections, rw sections
    let mut code_sections = Vec::new();
    let mut ro_sections: Vec<(u64, usize, Vec<u8>)> = Vec::new();
    let mut rw_sections: Vec<(u64, usize, Option<Vec<u8>>)> = Vec::new();
    let mut rela_section_indices = Vec::new();
    let mut symtab_idx = None;

    for (i, s) in sections.iter().enumerate() {
        let name = get_name(s.name_off);
        let is_alloc = s.flags & 2 != 0;
        let is_exec = s.flags & 4 != 0;
        let is_write = s.flags & 1 != 0;

        if s.sh_type == 2 {
            // SYMTAB
            symtab_idx = Some(i);
        }
        if s.sh_type == 4 {
            // RELA
            rela_section_indices.push(i);
        }
        if !is_alloc || s.sh_type == 0 {
            continue;
        }

        if is_exec && s.file_off + s.size <= data.len() {
            code_sections.push((
                s.file_off as u64,
                s.addr,
                data[s.file_off..s.file_off + s.size].to_vec(),
            ));
        } else if !is_exec
            && (name.starts_with(".rodata")
                || name == ".srodata"
                || name.starts_with(".data.rel.ro"))
        {
            if s.file_off + s.size <= data.len() {
                ro_sections.push((
                    s.addr,
                    s.size,
                    data[s.file_off..s.file_off + s.size].to_vec(),
                ));
            }
        } else if is_write {
            if s.sh_type == 8 {
                // NOBITS (.bss)
                rw_sections.push((s.addr, s.size, None));
            } else if s.file_off + s.size <= data.len() {
                rw_sections.push((
                    s.addr,
                    s.size,
                    Some(data[s.file_off..s.file_off + s.size].to_vec()),
                ));
            }
        }
    }

    // Parse symbol table
    let mut symbols_by_idx: Vec<(String, u64)> = Vec::new();
    if let Some(si) = symtab_idx {
        let s = &sections[si];
        // Get associated string table
        let sym_strtab = {
            let ss = &sections[s.link];
            &data[ss.file_off..ss.file_off + ss.size]
        };
        // ELF64 symbol = 24 bytes
        let count = s.size / 24;
        for j in 0..count {
            let off = s.file_off + j * 24;
            if off + 24 > data.len() {
                break;
            }
            let st_name = u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as usize;
            let st_value = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());

            let name = {
                if st_name < sym_strtab.len() {
                    let end = sym_strtab[st_name..]
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(0);
                    std::str::from_utf8(&sym_strtab[st_name..st_name + end]).unwrap_or("")
                } else {
                    ""
                }
            };

            symbols_by_idx.push((name.to_string(), st_value));
        }
    }

    // Resolve the exported `accumulate` entry symbol (the GP IC-5 slot). A
    // defined symbol has a nonzero code vaddr; an undefined reference (value 0)
    // is treated as absent so the blob stays refine-only (IC 5 → trap).
    let accumulate_vaddr = symbols_by_idx
        .iter()
        .find(|(name, value)| name == "accumulate" && *value != 0)
        .map(|(_, value)| *value);
    // An explicit standard-program stack, from the guest's linker script
    // (`__vos_stack_size = 0x40000;`). Absent in every existing guest.
    let declared_stack_size = symbols_by_idx
        .iter()
        .find(|(name, _)| name == SPI_STACK_SIZE_SYMBOL)
        .map(|(_, value)| *value);

    // Compute PVM memory layout
    // PVM linear memory: [stack: 0..s) [ro: s..s+|o|) [rw: s+P(|o|)..] [heap...]
    // We set stack_size = minimum power-of-2 page boundary that contains all ro section addrs.
    let ro_min = ro_sections.iter().map(|(a, _, _)| *a).min().unwrap_or(0);
    let ro_max = ro_sections
        .iter()
        .map(|(a, sz, _)| *a + *sz as u64)
        .max()
        .unwrap_or(0);

    // Round ro_min down to page boundary for stack_size.
    // Minimum 4 pages (16KB) so the stack is usable even without rodata.
    let page_size: u64 = 4096;
    let stack_size = if ro_min > 0 {
        (ro_min / page_size) * page_size
    } else {
        4 * page_size
    };

    // Build ro_data blob: section data placed at (section_addr - stack_size) offset
    let ro_blob_size = if ro_max > stack_size {
        (ro_max - stack_size) as usize
    } else {
        0
    };
    let mut ro_data = vec![0u8; ro_blob_size];
    for (addr, sz, d) in &ro_sections {
        let off = (*addr - stack_size) as usize;
        if off + sz <= ro_data.len() {
            ro_data[off..off + sz].copy_from_slice(d);
        }
    }

    // RW data: placed after ro_data (with page rounding)
    let ro_pages = ro_data.len().div_ceil(page_size as usize);
    let rw_pvm_base = stack_size + (ro_pages as u64 * page_size);
    let mut rw_data = Vec::new();
    let mut rw_base = rw_pvm_base;
    let mut rw_min = rw_pvm_base;
    if !rw_sections.is_empty() {
        rw_min = rw_sections.iter().map(|(a, _, _)| *a).min().unwrap();
        let rw_max = rw_sections
            .iter()
            .map(|(a, sz, _)| *a + *sz as u64)
            .max()
            .unwrap();
        rw_base = rw_pvm_base.min(rw_min);
        let rw_blob_size = (rw_max - rw_base) as usize;
        rw_data = vec![0u8; rw_blob_size];
        for (addr, sz, d) in &rw_sections {
            let off = (*addr - rw_base) as usize;
            if let Some(d) = d
                && off + sz <= rw_data.len()
            {
                rw_data[off..off + sz].copy_from_slice(d);
            }
        }
    }

    // Parse relocations in two passes:
    // Pass 1: collect HI20 targets and CALL_PLT targets
    // Pass 2: resolve LO12 by looking up their paired HI20
    let mut hi20_targets: HashMap<u64, u64> = HashMap::new();
    let mut lo12_targets: HashMap<u64, u64> = HashMap::new();
    let mut call_targets: HashMap<u64, u64> = HashMap::new();

    // Temporary: collect LO12 entries for pass 2
    let mut lo12_entries: Vec<(u64, u64)> = Vec::new(); // (lo12_addr, hi20_addr)
    let mut abs64_relocs: Vec<(u64, u64, u8)> = Vec::new(); // (offset, target, entry_size)
    let mut sub32_relocs: Vec<(u64, u64)> = Vec::new();
    let mut data_relocation_ranges = Vec::new();
    // Code address ranges for detecting code pointers
    let code_ranges: Vec<(u64, u64)> = code_sections
        .iter()
        .map(|(_, vaddr, data)| (*vaddr, *vaddr + data.len() as u64))
        .collect();

    for &ri in &rela_section_indices {
        let rs = &sections[ri];
        let count = rs.size / 24;
        for j in 0..count {
            let off = rs.file_off + j * 24;
            if off + 24 > data.len() {
                break;
            }
            let r_offset = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
            let r_info = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap());
            let r_addend = i64::from_le_bytes(data[off + 16..off + 24].try_into().unwrap());
            let r_type = (r_info & 0xFFFFFFFF) as u32;
            let r_sym = (r_info >> 32) as usize;

            let rtype = match RelocType::from_raw(r_type) {
                Some(t) => t,
                None => continue,
            };

            let sym_value = if r_sym < symbols_by_idx.len() {
                symbols_by_idx[r_sym].1
            } else {
                0
            };

            let target_addr = (sym_value as i64 + r_addend) as u64;

            match rtype {
                RelocType::Abs32 | RelocType::Add32 | RelocType::Sub32 => {
                    data_relocation_ranges.push((r_offset, r_offset.saturating_add(4)));
                }
                RelocType::Abs64 => {
                    data_relocation_ranges.push((r_offset, r_offset.saturating_add(8)))
                }
                _ => {}
            }

            match rtype {
                RelocType::Abs32 => {
                    let is_code_ptr = code_ranges
                        .iter()
                        .any(|(lo, hi)| target_addr >= *lo && target_addr < *hi);
                    if is_code_ptr {
                        abs64_relocs.push((r_offset, target_addr, 4));
                    }
                }
                RelocType::Abs64 => {
                    let is_code_ptr = code_ranges
                        .iter()
                        .any(|(lo, hi)| target_addr >= *lo && target_addr < *hi);
                    if is_code_ptr {
                        abs64_relocs.push((r_offset, target_addr, 8));
                    }
                }
                RelocType::Add32 => {
                    let is_code_ptr = code_ranges
                        .iter()
                        .any(|(lo, hi)| target_addr >= *lo && target_addr < *hi);
                    if is_code_ptr {
                        abs64_relocs.push((r_offset, target_addr, 4));
                    }
                }
                RelocType::Sub32 => {
                    // R_RISCV_SUB32: the subtracted address (typically table base).
                    sub32_relocs.push((r_offset, target_addr));
                }
                RelocType::CallPlt => {
                    call_targets.insert(r_offset, target_addr);
                }
                RelocType::PcrelHi20 => {
                    // target_addr is the resolved data/function address
                    hi20_targets.insert(r_offset, target_addr);
                }
                RelocType::PcrelLo12I | RelocType::PcrelLo12S => {
                    // sym_value is the address of the paired HI20 instruction.
                    // r_offset is the address of this LO12 instruction.
                    lo12_entries.push((r_offset, sym_value));
                }
            }
        }
    }

    let data_relocation_ranges = merge_relocation_ranges(data_relocation_ranges);

    // Pass 2: resolve LO12 targets by looking up paired HI20
    for (lo12_addr, hi20_addr) in lo12_entries {
        if let Some(&data_addr) = hi20_targets.get(&hi20_addr) {
            lo12_targets.insert(lo12_addr, data_addr);
        }
    }

    let mut control_flow_targets = HashSet::new();
    control_flow_targets.insert(e_entry);
    control_flow_targets.extend(accumulate_vaddr);
    control_flow_targets.extend(
        symbols_by_idx
            .iter()
            .map(|(_, value)| *value)
            .filter(|value| code_ranges.iter().any(|(lo, hi)| value >= lo && value < hi)),
    );
    for (&call_site, &target) in &call_targets {
        control_flow_targets.insert(target);
        // CALL_PLT occupies AUIPC+JALR; execution resumes after both.
        control_flow_targets.insert(call_site + 8);
    }
    control_flow_targets.extend(abs64_relocs.iter().map(|(_, target, _)| *target));
    control_flow_targets.extend(hi20_targets.values().copied().filter(|target| {
        code_ranges
            .iter()
            .any(|(lo, hi)| target >= lo && target < hi)
    }));
    let is_code_target = |target: u64| {
        code_ranges
            .iter()
            .any(|(lo, hi)| target >= *lo && target < *hi)
    };

    // The data-pointer rewriter below accepts stripped linked ELFs whose only
    // reference to a function entry is a raw pointer or an orphan SUB32 table
    // value. Collect those exact accepted targets before translating code so
    // they receive the same predecessor-fusion barrier as symbolic entries.
    for &(data_vaddr, base_addr) in &sub32_relocs {
        if abs64_relocs
            .iter()
            .any(|(absolute_vaddr, _, _)| *absolute_vaddr == data_vaddr)
        {
            continue;
        }
        let bytes = data_vaddr
            .checked_sub(stack_size)
            .and_then(|offset| usize::try_from(offset).ok())
            .and_then(|offset| offset.checked_add(4).map(|end| (offset, end)))
            .and_then(|(offset, end)| ro_data.get(offset..end))
            .or_else(|| {
                let offset = usize::try_from(data_vaddr.checked_sub(rw_base)?).ok()?;
                let end = offset.checked_add(4)?;
                rw_data.get(offset..end)
            });
        if let Some(bytes) = bytes {
            let relative = i32::from_le_bytes(bytes.try_into().expect("four-byte slice"));
            let target = (base_addr as i64 + i64::from(relative)) as u64;
            if is_code_target(target) {
                control_flow_targets.insert(target);
            }
        }
    }
    for (base, data) in [(stack_size, &ro_data), (rw_base, &rw_data)] {
        for (index, bytes) in data.chunks_exact(8).enumerate() {
            if overlaps_data_relocation(&data_relocation_ranges, base + index as u64 * 8, 8) {
                continue;
            }
            let target = u64::from_le_bytes(bytes.try_into().expect("eight-byte chunk"));
            if is_code_target(target) {
                control_flow_targets.insert(target);
            }
        }
    }

    for (_, base, code) in &code_sections {
        for (index, bytes) in code.chunks_exact(4).enumerate() {
            let address = *base + (index * 4) as u64;
            let instruction = u32::from_le_bytes(bytes.try_into().expect("four-byte chunk"));
            if instruction & 0x7f == 0x17
                && let Some(next_bytes) = code.get(index * 4 + 4..index * 4 + 8)
            {
                let next = u32::from_le_bytes(
                    next_bytes
                        .try_into()
                        .expect("adjacent four-byte instruction"),
                );
                let auipc_rd = (instruction >> 7) & 0x1f;
                let jalr_rs1 = (next >> 15) & 0x1f;
                if next & 0x7f == 0x67 && (next >> 12) & 0x7 == 0 && auipc_rd == jalr_rs1 {
                    let upper = (instruction & 0xffff_f000) as i32;
                    let lower = (next as i32) >> 20;
                    let target = (address as i64 + i64::from(upper) + i64::from(lower)) as u64;
                    if is_code_target(target) {
                        control_flow_targets.insert(target);
                    }
                }
                let addi_rd = (next >> 7) & 0x1f;
                if next & 0x7f == 0x13
                    && (next >> 12) & 0x7 == 0
                    && auipc_rd != 0
                    && addi_rd == auipc_rd
                    && jalr_rs1 == auipc_rd
                {
                    let upper = (instruction & 0xffff_f000) as i32;
                    let lower = (next as i32) >> 20;
                    let target = (address as i64 + i64::from(upper) + i64::from(lower)) as u64;
                    if is_code_target(target) {
                        control_flow_targets.insert(target);
                    }
                }
            }
            match instruction & 0x7f {
                0x6f => {
                    control_flow_targets
                        .insert((address as i64 + i64::from(decode_j_imm(instruction))) as u64);
                    if (instruction >> 7) & 0x1f != 0 {
                        control_flow_targets.insert(address + 4);
                    }
                }
                0x63 => {
                    control_flow_targets
                        .insert((address as i64 + i64::from(decode_b_imm(instruction))) as u64);
                }
                0x67 if (instruction >> 7) & 0x1f != 0 => {
                    control_flow_targets.insert(address + 4);
                }
                _ => {}
            }
        }
    }

    let heap_pages = 16u32; // 64KB heap

    Ok(LinkedElf {
        is_64bit,
        code_sections,
        ro_data,
        ro_base: stack_size,
        rw_data,
        rw_base,
        rw_min,
        stack_size: stack_size as u32,
        declared_stack_size,
        heap_pages,
        hi20_targets,
        lo12_targets,
        call_targets,
        abs_code_ptrs: abs64_relocs,
        sub32_relocs,
        data_relocation_ranges,
        code_ranges,
        control_flow_targets,
        entry_vaddr: e_entry,
        accumulate_vaddr,
    })
}

/// Relocation metadata owns every byte it covers, including the other half of
/// an eight-byte heuristic candidate and relocations to non-code addresses.
fn merge_relocation_ranges(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut()
            && start <= last.1
        {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    merged
}

fn overlaps_data_relocation(ranges: &[(u64, u64)], address: u64, size: u8) -> bool {
    let end = address.saturating_add(u64::from(size));
    let index = ranges.partition_point(|&(start, _)| start < end);
    index != 0 && ranges[index - 1].1 > address
}

/// Rewrite code pointers in data sections (LLVM switch/jump tables, vtables).
///
/// Detects code pointers via:
/// 1. R_RISCV_32/64 absolute relocations targeting code sections
/// 2. R_RISCV_SUB32 relocations (relative jump table entries: value = target - table_base)
/// 3. Heuristic scan for 8-byte values in initialized data that match code addresses
///
/// Creates PVM jump table entries for each target and rewrites the data
/// so that the loaded values are valid PVM djump addresses.
fn rewrite_data_code_ptrs(
    elf: &LinkedElf,
    ctx: &mut TranslationContext,
    ro_data: &mut [u8],
    rw_data: &mut [u8],
    rewrite_read_write: bool,
) {
    let ro_base = if rewrite_read_write {
        elf.ro_base
    } else {
        // Preserve the established manifest-container translation exactly.
        elf.stack_size as u64
    };
    let rw_base = elf.rw_base;
    let is_code_addr = |addr: u64| -> bool {
        elf.code_ranges
            .iter()
            .any(|(lo, hi)| addr >= *lo && addr < *hi)
    };

    struct Entry {
        data_vaddr: u64,
        rv_target: u64,
        size: u8,
        table_base_rv: Option<u64>,
    }
    let mut entries: Vec<Entry> = Vec::new();

    // From absolute relocations (R_RISCV_32/64/ADD32).
    // If a matching SUB32 exists at the same offset, this is a relative entry
    // (ADD32/SUB32 pair for jump tables). Use the SUB32 target as table base.
    for &(vaddr, target, size) in &elf.abs_code_ptrs {
        let table_base = elf
            .sub32_relocs
            .iter()
            .find(|(v, _)| *v == vaddr)
            .map(|(_, base)| *base);
        entries.push(Entry {
            data_vaddr: vaddr,
            rv_target: target,
            size,
            table_base_rv: table_base,
        });
    }

    // SUB32 entries without matching ADD32 (shouldn't happen, but handle gracefully).
    for &(data_vaddr, base_addr) in &elf.sub32_relocs {
        if entries.iter().any(|e| e.data_vaddr == data_vaddr) {
            continue; // Already handled via ADD32 pairing above
        }
        let bytes = if data_vaddr >= ro_base {
            let off = (data_vaddr - ro_base) as usize;
            ro_data.get(off..off + 4)
        } else {
            None
        }
        .or_else(|| {
            if !rewrite_read_write {
                return None;
            }
            let off = data_vaddr.checked_sub(rw_base)? as usize;
            rw_data.get(off..off + 4)
        });
        if let Some(bytes) = bytes {
            let val = i32::from_le_bytes(bytes.try_into().unwrap());
            let target = (base_addr as i64 + val as i64) as u64;
            if is_code_addr(target) {
                entries.push(Entry {
                    data_vaddr,
                    rv_target: target,
                    size: 4,
                    table_base_rv: Some(base_addr),
                });
            }
        }
    }

    // Heuristic: 8-byte values in either initialized region that are code
    // addresses. Relocations normally cover these; the scan also supports
    // stripped-but-still-linked inputs.
    let initialized_regions = [(ro_base, &*ro_data), (rw_base, &*rw_data)];
    for (base, data) in initialized_regions
        .into_iter()
        .take(if rewrite_read_write { 2 } else { 1 })
    {
        let mut off = 0;
        while off + 8 <= data.len() {
            if overlaps_data_relocation(&elf.data_relocation_ranges, base + off as u64, 8) {
                off += 8;
                continue;
            }
            let val = u64::from_le_bytes(data[off..off + 8].try_into().unwrap());
            if is_code_addr(val) {
                let vaddr = base + off as u64;
                if !entries.iter().any(|e| e.data_vaddr == vaddr) {
                    entries.push(Entry {
                        data_vaddr: vaddr,
                        rv_target: val,
                        size: 8,
                        table_base_rv: None,
                    });
                }
            }
            off += 8;
        }
    }

    if entries.is_empty() {
        return;
    }

    let targets: std::collections::HashSet<u64> = entries.iter().map(|e| e.rv_target).collect();
    let rv_to_jt = ctx.build_function_pointer_map(&targets);

    for entry in &entries {
        let Some(&jt_addr) = rv_to_jt.get(&entry.rv_target) else {
            continue;
        };
        let replacement = match (entry.size, entry.table_base_rv) {
            (8, _) => (jt_addr as u64).to_le_bytes().to_vec(),
            (4, None) => jt_addr.to_le_bytes().to_vec(),
            (4, Some(rv_base)) => {
                // Relative entry: code does `lw off, table(idx); add target,
                // off, base; jr target`.
                let pvm_base = ctx
                    .address_map
                    .get(&rv_base)
                    .copied()
                    .unwrap_or(rv_base as u32);
                let value = (jt_addr as i64 - pvm_base as i64) as i32;
                value.to_le_bytes().to_vec()
            }
            _ => continue,
        };
        let size = replacement.len();
        if let Some(off) = entry
            .data_vaddr
            .checked_sub(ro_base)
            .and_then(|off| usize::try_from(off).ok())
            .filter(|off| off.saturating_add(size) <= ro_data.len())
        {
            ro_data[off..off + size].copy_from_slice(&replacement);
        } else if rewrite_read_write
            && let Some(off) = entry
                .data_vaddr
                .checked_sub(rw_base)
                .and_then(|off| usize::try_from(off).ok())
                .filter(|off| off.saturating_add(size) <= rw_data.len())
        {
            rw_data[off..off + size].copy_from_slice(&replacement);
        }
    }
}

fn translate_section_linked(
    ctx: &mut TranslationContext,
    data: &[u8],
    base_addr: u64,
    elf: &LinkedElf,
) -> Result<(), TranspileError> {
    let mut offset = 0;
    while offset < data.len() {
        let rv_addr = base_addr + offset as u64;
        ctx.begin_instruction(rv_addr, elf.control_flow_targets.contains(&rv_addr))?;

        if offset + 4 > data.len() {
            break;
        }

        let inst = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);

        // Skip non-instruction bytes
        if inst & 0x3 != 0x3 {
            // Compressed instruction — not supported for rv64em
            return Err(TranspileError::UnsupportedInstruction {
                offset: rv_addr as usize,
                detail: "compressed instruction in rv64em ELF".into(),
            });
        }

        let opcode = inst & 0x7f;

        // Check for relocation overrides
        if opcode == 0x17 {
            // AUIPC
            let rd = ((inst >> 7) & 0x1f) as u8;

            if let Some(&target_addr) = elf.call_targets.get(&rv_addr) {
                // CALL_PLT: AUIPC+JALR pair for function call
                // Peek at JALR to get link register
                if offset + 8 <= data.len() {
                    if elf.control_flow_targets.contains(&(rv_addr + 4)) {
                        return Err(TranspileError::InvalidSection(format!(
                            "control-flow target {:#x} splits a relocated AUIPC+JALR call pair at {rv_addr:#x}",
                            rv_addr + 4
                        )));
                    }
                    let jalr = u32::from_le_bytes([
                        data[offset + 4],
                        data[offset + 5],
                        data[offset + 6],
                        data[offset + 7],
                    ]);
                    let jalr_rd = ((jalr >> 7) & 0x1f) as u8;
                    let ret_addr = rv_addr + 8;

                    // This relocation override bypasses `translate_one`, so flush
                    // any LUI/AUIPC buffered by the linear predecessor before the
                    // call can transfer control. This also clears load-immediate
                    // fusion state: a later consumer must not fuse backwards across
                    // the emitted call and truncate its bytes.
                    ctx.flush_pending()?;
                    // Fused load_imm_jump: set return address and jump in one instruction
                    ctx.emit_call(jalr_rd, ret_addr, target_addr)?;
                    // Map the JALR address too
                    ctx.address_map.insert(rv_addr + 4, ctx.code.len() as u32);
                    offset += 8; // skip both AUIPC and JALR
                    continue;
                }
            }

            if let Some(&target_addr) = elf.hi20_targets.get(&rv_addr) {
                // PCREL_HI20: AUIPC for data reference.
                // Peek ahead: if the next instruction is a paired LO12 ADDI (nop),
                // skip it and set pending_load_imm to enable cascading fusion
                // with the instruction after (load_ind, store_ind, ALU, branch).
                let next_addr = rv_addr + 4;
                if offset + 8 <= data.len()
                    && let Some(&_) = elf.lo12_targets.get(&next_addr)
                {
                    if elf.control_flow_targets.contains(&next_addr) {
                        return Err(TranspileError::InvalidSection(
                            "control-flow target splits a relocated HI20+LO12 pair".into(),
                        ));
                    }
                    let next_inst = u32::from_le_bytes([
                        data[offset + 4],
                        data[offset + 5],
                        data[offset + 6],
                        data[offset + 7],
                    ]);
                    let next_opcode = next_inst & 0x7f;
                    let next_funct3 = (next_inst >> 12) & 0x7;
                    let next_rd = ((next_inst >> 7) & 0x1f) as u8;
                    let next_rs1 = ((next_inst >> 15) & 0x1f) as u8;

                    if next_opcode == 0x13 && next_funct3 == 0 && next_rs1 == rd {
                        // LO12 ADDI: address is already complete from HI20.
                        // Emit load_imm into the ADDI's destination register
                        // and set pending_load_imm for cascading fusion.
                        let dest = if next_rd != 0 { next_rd } else { rd };
                        let pos = ctx.code.len();
                        // If target is a code address (function pointer), load
                        // a jump table address instead of the raw RISC-V address.
                        let load_val = if ctx.is_code_addr(target_addr) {
                            let jt_idx = ctx.jump_table.len();
                            ctx.jump_table.push(0);
                            ctx.return_fixups.push((jt_idx, target_addr));
                            ((jt_idx + 1) * 2) as i64
                        } else {
                            target_addr as i64
                        };
                        ctx.emit_load_imm(dest, load_val)?;
                        ctx.pending_load_imm = Some((dest, load_val, pos));
                        ctx.address_map.insert(next_addr, ctx.code.len() as u32);
                        offset += 8; // skip both AUIPC and ADDI
                        continue;
                    }
                }

                // No paired LO12 ADDI next — emit load_imm with pending tracking.
                // This enables fusion with the next load/store/ALU/branch via
                // pending_load_imm even when the LO12 is a LOAD or STORE directly.
                let pos = ctx.code.len();
                // If target is a code address, use jump table address.
                let load_val = if ctx.is_code_addr(target_addr) {
                    let jt_idx = ctx.jump_table.len();
                    ctx.jump_table.push(0);
                    ctx.return_fixups.push((jt_idx, target_addr));
                    ((jt_idx + 1) * 2) as i64
                } else {
                    target_addr as i64
                };
                ctx.emit_load_imm(rd, load_val)?;
                ctx.pending_load_imm = Some((rd, load_val, pos));
                offset += 4;
                continue;
            }
        }

        // Check if this instruction has a PCREL_LO12 relocation.
        // If so, the rs1 register already contains the full resolved address
        // (loaded by the paired AUIPC/HI20 above). Override immediate to 0
        // and route through translate_load/translate_store to enable fusion
        // with the pending_load_imm set by the HI20 handler above.
        if let Some(&_data_addr) = elf.lo12_targets.get(&rv_addr) {
            let rd = ((inst >> 7) & 0x1f) as u8;
            let rs1 = ((inst >> 15) & 0x1f) as u8;
            let funct3 = (inst >> 12) & 0x7;

            if opcode == 0x13 && funct3 == 0 {
                // ADDI rd, rs1, lo12 → address already loaded by HI20.
                // This path is reached when the HI20 peek-ahead didn't consume
                // this ADDI (e.g., non-adjacent HI20/LO12 pair).
                if rd != rs1 && rd != 0 {
                    let pvm_src = ctx.require_reg(rs1)?;
                    let pvm_dst = ctx.require_reg(rd)?;
                    ctx.emit_inst(100); // move_reg
                    ctx.emit_data(pvm_dst | (pvm_src << 4));
                } else {
                    ctx.emit_inst(1); // fallthrough
                }
                offset += 4;
                continue;
            } else if opcode == 0x03 {
                // LOAD rd, lo12(rs1) → route through translate_load with imm=0.
                // If pending_load_imm is set (from HI20), this fuses into a
                // direct load (load_* rd, addr) — saving one instruction.
                ctx.translate_load(funct3, rd, rs1, 0, rv_addr)?;
                offset += 4;
                continue;
            } else if opcode == 0x23 {
                // STORE rs2, lo12(rs1) → route through translate_store with imm=0.
                let rs2 = ((inst >> 20) & 0x1f) as u8;
                ctx.translate_store(funct3, rs1, rs2, 0)?;
                offset += 4;
                continue;
            }
            // Fallthrough: translate normally (shouldn't happen for well-formed code)
        }

        // Normal instruction translation
        let consumed = ctx.translate_instruction(data, offset, base_addr)?;
        offset += consumed;
    }

    // Flush any pending LUI/AUIPC at section boundary
    ctx.flush_pending()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos_pvm::{ExitReason, refine};

    #[test]
    fn declared_stack_size_replaces_the_layout_derived_stack() {
        // No declaration: the read-only base, exactly as before.
        assert_eq!(spi_stack_size(0x1_0000, None).unwrap(), 0x1_0000);
        assert!(spi_stack_size(1 << 24, None).is_err());
        // A declared stack is independent of where read-only data is linked.
        assert_eq!(spi_stack_size(0x1_0000, Some(0x4_0000)).unwrap(), 0x4_0000);
        assert_eq!(spi_stack_size(0x4_0000, Some(0x1000)).unwrap(), 0x1000);
        for invalid in [0, 0x1001, 1 << 24] {
            assert!(
                spi_stack_size(0x1_0000, Some(invalid)).is_err(),
                "{invalid:#x}"
            );
        }
    }

    #[test]
    fn relocation_interval_index_matches_byte_overlap() {
        let original = vec![(20, 24), (4, 8), (6, 14), (24, 28), (4, 8), (40, 48)];
        let merged = merge_relocation_ranges(original.clone());
        assert_eq!(merged, vec![(4, 14), (20, 28), (40, 48)]);
        for address in 0..56 {
            for size in 1..=8u8 {
                let expected = original
                    .iter()
                    .any(|&(start, end)| address < end && start < address + u64::from(size));
                assert_eq!(overlaps_data_relocation(&merged, address, size), expected);
            }
        }
        assert!(!overlaps_data_relocation(&[], 4, 8));
    }

    /// Translate a preserved ELF and resolve observed PVM PCs without changing
    /// the production linker API or emitted program. Use only with exact-byte
    /// equality to the observed standard program.
    #[test]
    #[ignore = "diagnostic requires VOS_PROFILE_ELF, VOS_PROFILE_PVM and VOS_PROFILE_PCS"]
    fn resolve_observed_standard_program_pcs() {
        let elf = std::fs::read(std::env::var_os("VOS_PROFILE_ELF").unwrap()).unwrap();
        let expected = std::fs::read(std::env::var_os("VOS_PROFILE_PVM").unwrap()).unwrap();
        assert!(
            link_elf_spi(&elf).unwrap() == expected,
            "ELF does not reproduce the observed program"
        );
        let translated = transpile_elf(&elf, true, OpcodeEncoding::Standard).unwrap();
        let mut pcs: Vec<u32> = std::env::var("VOS_PROFILE_PCS")
            .unwrap()
            .split(',')
            .map(|value| value.parse().unwrap())
            .collect();
        if let Ok(returns) = std::env::var("VOS_PROFILE_RETURN_ADDRESSES") {
            for value in returns.split(',') {
                let address: usize = value.parse().unwrap();
                assert!(
                    address != 0 && address % 2 == 0,
                    "invalid indirect return address"
                );
                let pc = translated.jump_table[address / 2 - 1];
                eprintln!("return_address address={address} pc={pc}");
                pcs.push(pc);
            }
        }
        let mut addresses: Vec<_> = translated.address_map.into_iter().collect();
        addresses.sort_unstable_by_key(|&(rv, pc)| (pc, rv));
        for pc in pcs {
            assert!((pc as usize) < translated.code.len());
            assert_eq!(translated.bitmask[pc as usize], 1);
            let &(rv, mapped_pc) = addresses
                .iter()
                .rev()
                .find(|&&(_, mapped)| mapped <= pc)
                .unwrap();
            eprintln!("observed_pc pc={pc} mapped_pc={mapped_pc} riscv={rv:#x}");
        }
    }

    const TEXT_VADDR: u64 = 0x40_0000;
    const RA: u32 = 1;
    const SP: u32 = 2;
    const T0: u32 = 5;
    const T2: u32 = 7;
    const A0: u32 = 10;
    const A1: u32 = 11;
    const A2: u32 = 12;

    fn lui(rd: u32, imm20: u32) -> u32 {
        (imm20 << 12) | (rd << 7) | 0x37
    }

    fn addi(rd: u32, rs1: u32, imm: i32) -> u32 {
        ((imm as u32 & 0xfff) << 20) | (rs1 << 15) | (rd << 7) | 0x13
    }

    fn auipc(rd: u32) -> u32 {
        (rd << 7) | 0x17
    }

    fn jalr(rd: u32, rs1: u32) -> u32 {
        (rs1 << 15) | (rd << 7) | 0x67
    }

    fn sd(rs2: u32, rs1: u32, imm: i32) -> u32 {
        let imm = imm as u32 & 0xfff;
        ((imm >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (3 << 12) | ((imm & 0x1f) << 7) | 0x23
    }

    fn assemble(insts: &[u32]) -> Vec<u8> {
        insts.iter().flat_map(|inst| inst.to_le_bytes()).collect()
    }

    #[test]
    fn relocated_call_flushes_pending_lui_before_transfer() {
        const LIMIT: u64 = 8192;
        const CALL_SITE: u64 = TEXT_VADDR + 8;
        const RETURN_ADDR: u64 = TEXT_VADDR + 16;
        const CALLEE: u64 = TEXT_VADDR + 32;

        // The LUI is deliberately adjacent to the relocated AUIPC+JALR pair.
        // The callee snapshots A2 before the caller can execute another normal
        // instruction. If CALL_PLT bypasses the buffered-LUI flush, it observes
        // zero instead of LIMIT (the agent-runtime bytes_bounded failure mode).
        let text = assemble(&[
            addi(T2, RA, 0),  // preserve the host return address
            lui(A2, 2),       // buffered A2 = 8192
            auipc(T0),        // R_RISCV_CALL_PLT relocation lives here
            jalr(RA, T0),     // relocation override consumes this instruction
            addi(RA, T2, 0),  // restore the host return address
            addi(A0, SP, -8), // designate the callee's snapshot as output
            addi(A1, 0, 8),
            jalr(0, RA), // return to the host
            sd(A2, SP, -8),
            jalr(0, RA), // callee return
        ]);

        let elf = LinkedElf {
            is_64bit: true,
            code_sections: vec![(0, TEXT_VADDR, text.clone())],
            ro_data: Vec::new(),
            ro_base: 0x1_0000,
            rw_data: Vec::new(),
            rw_base: 0x2_0000,
            rw_min: 0x2_0000,
            stack_size: 0x1_0000,
            declared_stack_size: None,
            heap_pages: 0,
            hi20_targets: HashMap::new(),
            lo12_targets: HashMap::new(),
            call_targets: HashMap::from([(CALL_SITE, CALLEE)]),
            abs_code_ptrs: Vec::new(),
            sub32_relocs: Vec::new(),
            data_relocation_ranges: Vec::new(),
            code_ranges: vec![(TEXT_VADDR, TEXT_VADDR + text.len() as u64)],
            control_flow_targets: HashSet::from([TEXT_VADDR, RETURN_ADDR, CALLEE]),
            entry_vaddr: TEXT_VADDR,
            accumulate_vaddr: None,
        };

        let mut ctx = TranslationContext::with_opcode_encoding(true, OpcodeEncoding::Standard);
        ctx.code_ranges = elf.code_ranges.clone();
        ctx.emit_jump(elf.entry_vaddr);
        ctx.emit_inst(0); // unused accumulate entry
        translate_section_linked(&mut ctx, &text, TEXT_VADDR, &elf).expect("translates");
        ctx.apply_fixups();

        crate::peephole_fuse_load_imm_alu(&mut ctx.code, &mut ctx.bitmask, &ctx.jump_table);
        crate::peephole_fuse_load_imm_memory(&mut ctx.code, &mut ctx.bitmask, &ctx.jump_table);
        crate::peephole_eliminate_dead_load_imm(&mut ctx.code, &mut ctx.bitmask, &ctx.jump_table);
        crate::ensure_branch_targets_are_block_starts(
            &mut ctx.code,
            &mut ctx.bitmask,
            &mut ctx.jump_table,
        );

        let blob = crate::spi::build_spi_blob(
            &[],
            &[],
            elf.heap_pages as u16,
            elf.stack_size,
            &ctx.code,
            &ctx.bitmask,
            &ctx.jump_table,
        );
        let invocation = refine::execute(&blob, &[], 10_000_000).expect("executes");

        assert_eq!(invocation.exit, ExitReason::Halt);
        assert_eq!(
            invocation
                .output_bounded(core::mem::size_of::<u64>())
                .as_deref(),
            Some(&LIMIT.to_le_bytes()[..]),
            "the callee must observe the LUI value before control transfers"
        );
    }
}
