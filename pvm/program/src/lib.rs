#![no_std]

//! Portable standard-PVM program bytes and initial memory layout.
//!
//! This crate deliberately contains no executor. A compiler can emit the
//! format, a host can validate and execute it, and a guest runtime can create
//! inner machines from it through the standard PVM host calls.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

pub const PAGE_SIZE: u32 = 1 << 12;
pub const ZONE_SIZE: u32 = 1 << 16;
pub const INPUT_SIZE: u32 = 1 << 24;
pub const REGISTER_COUNT: usize = 13;
pub const HALT_ADDRESS: u64 = (1 << 32) - (1 << 16);

const ADDRESS_SPACE: u64 = 1 << 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeBlob {
    pub jump_table: Vec<u32>,
    pub code: Vec<u8>,
    /// One byte per code byte. Instruction starts are `1`.
    pub bitmask: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandardProgram {
    pub ro_data: Vec<u8>,
    pub rw_data: Vec<u8>,
    pub heap_pages: u32,
    pub stack_size: u32,
    pub code: CodeBlob,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Region {
    pub base: u64,
    pub size: u64,
    pub writable: bool,
}

#[derive(Debug, Clone)]
pub struct StandardLayout<'a> {
    pub ro: Region,
    pub rw: Region,
    pub stack: Region,
    pub args: Region,
    pub ro_data: &'a [u8],
    pub rw_data: &'a [u8],
    pub args_data: &'a [u8],
    pub heap_top: u64,
    pub registers: [u64; REGISTER_COUNT],
}

fn page_round(value: u64) -> Option<u64> {
    value
        .checked_add(u64::from(PAGE_SIZE) - 1)
        .map(|rounded| rounded / u64::from(PAGE_SIZE) * u64::from(PAGE_SIZE))
}

fn zone_round(value: u64) -> Option<u64> {
    value
        .checked_add(u64::from(ZONE_SIZE) - 1)
        .map(|rounded| rounded / u64::from(ZONE_SIZE) * u64::from(ZONE_SIZE))
}

impl StandardProgram {
    /// Compute the initial flat-memory layout and register file.
    pub fn layout<'a>(&'a self, args: &'a [u8]) -> Option<StandardLayout<'a>> {
        standard_layout(
            &self.ro_data,
            &self.rw_data,
            self.heap_pages,
            self.stack_size,
            args,
        )
    }

    /// Re-encode the program's executable portion for the `machine` host call.
    pub fn compact_code(&self) -> Option<Vec<u8>> {
        build_compact_code_blob(&self.code)
    }
}

fn standard_layout<'a>(
    ro_data: &'a [u8],
    rw_data: &'a [u8],
    heap_pages: u32,
    stack_size: u32,
    args: &'a [u8],
) -> Option<StandardLayout<'a>> {
    let ro_size = ro_data.len() as u64;
    let rw_size = rw_data.len() as u64;
    let stack_size = u64::from(stack_size);
    let args_size = args.len() as u64;
    if args_size > u64::from(INPUT_SIZE) {
        return None;
    }

    let ro_zone = zone_round(ro_size)?;
    let rw_total = rw_size.checked_add(u64::from(heap_pages) * u64::from(PAGE_SIZE))?;
    let rw_zone = zone_round(rw_total)?;
    let stack_zone = zone_round(stack_size)?;
    let total = 5u64
        .checked_mul(u64::from(ZONE_SIZE))?
        .checked_add(ro_zone)?
        .checked_add(rw_zone)?
        .checked_add(stack_zone)?
        .checked_add(u64::from(INPUT_SIZE))?;
    if total > ADDRESS_SPACE {
        return None;
    }

    let ro_base = u64::from(ZONE_SIZE);
    let rw_base = 2 * u64::from(ZONE_SIZE) + ro_zone;
    let stack_top = ADDRESS_SPACE - 2 * u64::from(ZONE_SIZE) - u64::from(INPUT_SIZE);
    let stack_bottom = stack_top.checked_sub(page_round(stack_size)?)?;
    let args_base = ADDRESS_SPACE - u64::from(ZONE_SIZE) - u64::from(INPUT_SIZE);
    let heap_top = rw_base.checked_add(page_round(rw_total)?)?;

    let mut registers = [0; REGISTER_COUNT];
    registers[0] = HALT_ADDRESS;
    registers[1] = stack_top;
    registers[7] = args_base;
    registers[8] = args_size;

    Some(StandardLayout {
        ro: Region {
            base: ro_base,
            size: page_round(ro_size)?,
            writable: false,
        },
        rw: Region {
            base: rw_base,
            size: page_round(rw_total)?,
            writable: true,
        },
        stack: Region {
            base: stack_bottom,
            size: page_round(stack_size)?,
            writable: true,
        },
        args: Region {
            base: args_base,
            size: page_round(args_size)?,
            writable: false,
        },
        ro_data,
        rw_data,
        args_data: args,
        heap_top,
        registers,
    })
}

/// A standard program validated in place, borrowing every section from its
/// canonical bytes.
///
/// [`Self::parse`] accepts exactly the blobs [`parse_standard_program`]
/// accepts: both run [`validate_compact_code_blob`]. It copies nothing and
/// never expands the instruction bitmask to one byte per code byte, and
/// [`Self::code_blob`] is the program's own compact code blob, byte-for-byte
/// what `parse_standard_program(blob)?.compact_code()` rebuilds. A guest that
/// hands a program to the `machine` host call needs nothing else, so its
/// work is independent of the program's size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StandardProgramRef<'a> {
    pub ro_data: &'a [u8],
    pub rw_data: &'a [u8],
    pub heap_pages: u32,
    pub stack_size: u32,
    code_blob: &'a [u8],
    code_len: usize,
    packed_bitmask: &'a [u8],
}

impl<'a> StandardProgramRef<'a> {
    pub fn parse(blob: &'a [u8]) -> Option<Self> {
        let header = parse_standard_header(blob)?;
        let code = validate_compact_code_blob(header.code_blob)?;
        Some(Self {
            ro_data: header.ro_data,
            rw_data: header.rw_data,
            heap_pages: header.heap_pages,
            stack_size: header.stack_size,
            code_blob: header.code_blob,
            code_len: code.code_len,
            packed_bitmask: &header.code_blob[code.packed_start..],
        })
    }

    /// The canonical compact code blob for the `machine` host call.
    pub const fn code_blob(&self) -> &'a [u8] {
        self.code_blob
    }

    pub const fn code_len(&self) -> usize {
        self.code_len
    }

    /// Whether `pc` starts an instruction, read from the packed bitmask.
    pub fn is_instruction_start(&self, pc: usize) -> bool {
        pc < self.code_len && (self.packed_bitmask[pc / 8] >> (pc % 8)) & 1 == 1
    }

    /// Compute the initial flat-memory layout and register file.
    pub fn layout<'b>(&'b self, args: &'b [u8]) -> Option<StandardLayout<'b>> {
        standard_layout(
            self.ro_data,
            self.rw_data,
            self.heap_pages,
            self.stack_size,
            args,
        )
    }
}

/// Decode a standard variable-length natural at `offset`.
pub fn read_nat(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    let header = *data.get(offset)?;
    let length = header.leading_ones() as usize;
    let (value, consumed) = if length == 0 {
        (u64::from(header), 1)
    } else if length >= 8 {
        let bytes = data.get(offset + 1..offset + 9)?;
        (u64::from_le_bytes(bytes.try_into().ok()?), 9)
    } else {
        let bytes = data.get(offset + 1..offset + 1 + length)?;
        let mut low = 0u64;
        for (index, byte) in bytes.iter().copied().enumerate() {
            low |= u64::from(byte) << (8 * index);
        }
        let top = u64::from(header) & ((1u64 << (8 - length)) - 1);
        (low | (top << (8 * length)), 1 + length)
    };

    // The wire has exactly one representation for each natural. Rejecting a
    // wider-than-necessary length class prevents distinct program bytes from
    // decoding to the same executable image.
    let canonical_length = (0usize..8)
        .find(|candidate| value < 1u64 << (7 * (*candidate as u32 + 1)))
        .unwrap_or(8);
    (length == canonical_length).then_some((value, consumed))
}

/// Encode a standard variable-length natural.
pub fn encode_nat(value: u64, output: &mut Vec<u8>) {
    let length = (0u8..8).find(|length| value < 1u64 << (7 * (u32::from(*length) + 1)));
    match length {
        Some(0) => output.push(value as u8),
        Some(length) => {
            output.push((256u64 - (256u64 >> length) + (value >> (8 * u32::from(length)))) as u8);
            output.extend_from_slice(&value.to_le_bytes()[..usize::from(length)]);
        }
        None => {
            output.push(0xff);
            output.extend_from_slice(&value.to_le_bytes());
        }
    }
}

fn read_le(data: &[u8], offset: usize, width: usize) -> Option<u64> {
    let bytes = data.get(offset..offset.checked_add(width)?)?;
    let mut value = 0u64;
    for (index, byte) in bytes.iter().copied().enumerate() {
        value |= u64::from(byte) << (8 * index);
    }
    Some(value)
}

fn entry_size(jump_table: &[u32]) -> u8 {
    match jump_table.iter().copied().max().unwrap_or(0) {
        0..=0xff => 1,
        0x100..=0xffff => 2,
        0x1_0000..=0xff_ffff => 3,
        _ => 4,
    }
}

fn pack_bitmask(bitmask: &[u8]) -> Vec<u8> {
    let mut packed = vec![0; bitmask.len().div_ceil(8)];
    for (index, bit) in bitmask.iter().copied().enumerate() {
        if bit != 0 {
            packed[index / 8] |= 1 << (index % 8);
        }
    }
    packed
}

fn copy_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    output.try_reserve_exact(bytes.len()).ok()?;
    output.extend_from_slice(bytes);
    Some(output)
}

/// Offsets of a validated compact code blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactCodeLayout {
    pub jump_len: usize,
    pub width: usize,
    /// Offset of the first jump-table entry.
    pub jump_start: usize,
    /// Offset of the first code byte.
    pub code_start: usize,
    pub code_len: usize,
    /// Offset of the packed bitmask, which runs to the end of the blob.
    pub packed_start: usize,
}

/// Validate a compact code blob in place: canonical naturals, the minimal
/// jump-entry width, exact length, and zero unused bitmask bits. This is the
/// complete acceptance rule of [`parse_compact_code_blob`], which then only
/// materializes. It reads each jump entry once and never the code bytes.
pub fn validate_compact_code_blob(data: &[u8]) -> Option<CompactCodeLayout> {
    let (jump_len, jump_nat_len) = read_nat(data, 0)?;
    let mut offset = jump_nat_len;
    let width = usize::from(*data.get(offset)?);
    offset += 1;
    if !(1..=4).contains(&width) {
        return None;
    }
    let (code_len, code_nat_len) = read_nat(data, offset)?;
    offset = offset.checked_add(code_nat_len)?;
    let jump_len = usize::try_from(jump_len).ok()?;
    let code_len = usize::try_from(code_len).ok()?;

    // Prove that every declared item is present before reserving from an
    // attacker-controlled count. In particular, a tiny blob declaring
    // u64::MAX jump entries must fail here rather than panic in the allocator.
    let jump_bytes = jump_len.checked_mul(width)?;
    let jump_start = offset;
    let jump_end = offset.checked_add(jump_bytes)?;
    let code_end = jump_end.checked_add(code_len)?;
    let packed_len = code_len.div_ceil(8);
    let packed_end = code_end.checked_add(packed_len)?;
    if packed_end != data.len() {
        return None;
    }

    let mut widest = 0u32;
    for _ in 0..jump_len {
        widest = widest.max(u32::try_from(read_le(data, offset, width)?).ok()?);
        offset = offset.checked_add(width)?;
    }
    if usize::from(entry_size(&[widest])) != width {
        return None;
    }
    let packed = data.get(code_end..)?;
    if let Some(last) = packed.last()
        && code_len % 8 != 0
        && last & !((1u8 << (code_len % 8)) - 1) != 0
    {
        return None;
    }
    Some(CompactCodeLayout {
        jump_len,
        width,
        jump_start,
        code_start: jump_end,
        code_len,
        packed_start: code_end,
    })
}

pub fn parse_compact_code_blob(data: &[u8]) -> Option<CodeBlob> {
    let layout = validate_compact_code_blob(data)?;
    let CompactCodeLayout {
        jump_len,
        width,
        jump_start,
        code_start,
        code_len,
        packed_start,
    } = layout;
    let mut jump_table = Vec::new();
    jump_table.try_reserve_exact(jump_len).ok()?;
    let mut offset = jump_start;
    for _ in 0..jump_len {
        jump_table.push(u32::try_from(read_le(data, offset, width)?).ok()?);
        offset = offset.checked_add(width)?;
    }
    let code = copy_bytes(data.get(code_start..packed_start)?)?;
    let packed = data.get(packed_start..)?;
    let mut bitmask = Vec::new();
    bitmask.try_reserve_exact(code_len).ok()?;
    bitmask.resize(code_len, 0);
    for index in 0..code_len {
        bitmask[index] = (packed[index / 8] >> (index % 8)) & 1;
    }

    Some(CodeBlob {
        jump_table,
        code,
        bitmask,
    })
}

pub fn build_compact_code_blob(code: &CodeBlob) -> Option<Vec<u8>> {
    if code.code.len() != code.bitmask.len() {
        return None;
    }
    let width = entry_size(&code.jump_table);
    let mut output = Vec::new();
    encode_nat(code.jump_table.len() as u64, &mut output);
    output.push(width);
    encode_nat(code.code.len() as u64, &mut output);
    for entry in &code.jump_table {
        output.extend_from_slice(&entry.to_le_bytes()[..usize::from(width)]);
    }
    output.extend_from_slice(&code.code);
    output.extend_from_slice(&pack_bitmask(&code.bitmask));
    Some(output)
}

struct StandardHeader<'a> {
    ro_data: &'a [u8],
    rw_data: &'a [u8],
    heap_pages: u32,
    stack_size: u32,
    code_blob: &'a [u8],
}

fn parse_standard_header(blob: &[u8]) -> Option<StandardHeader<'_>> {
    if blob.len() < 15 {
        return None;
    }
    let ro_size = usize::try_from(read_le(blob, 0, 3)?).ok()?;
    let rw_size = usize::try_from(read_le(blob, 3, 3)?).ok()?;
    let heap_pages = u32::try_from(read_le(blob, 6, 2)?).ok()?;
    let stack_size = u32::try_from(read_le(blob, 8, 3)?).ok()?;
    let mut offset = 11usize;
    let ro_end = offset.checked_add(ro_size)?;
    let ro_data = blob.get(offset..ro_end)?;
    offset = ro_end;
    let rw_end = offset.checked_add(rw_size)?;
    let rw_data = blob.get(offset..rw_end)?;
    offset = rw_end;
    let code_len = usize::try_from(read_le(blob, offset, 4)?).ok()?;
    offset = offset.checked_add(4)?;
    let code_end = offset.checked_add(code_len)?;
    if code_end != blob.len() {
        return None;
    }
    Some(StandardHeader {
        ro_data,
        rw_data,
        heap_pages,
        stack_size,
        code_blob: blob.get(offset..code_end)?,
    })
}

pub fn parse_standard_program(blob: &[u8]) -> Option<StandardProgram> {
    let header = parse_standard_header(blob)?;
    let code = parse_compact_code_blob(header.code_blob)?;
    Some(StandardProgram {
        ro_data: copy_bytes(header.ro_data)?,
        rw_data: copy_bytes(header.rw_data)?,
        heap_pages: header.heap_pages,
        stack_size: header.stack_size,
        code,
    })
}

pub fn build_standard_program(program: &StandardProgram) -> Option<Vec<u8>> {
    if program.ro_data.len() >= 1 << 24
        || program.rw_data.len() >= 1 << 24
        || program.stack_size >= 1 << 24
        || program.heap_pages > u32::from(u16::MAX)
    {
        return None;
    }
    let code = build_compact_code_blob(&program.code)?;
    let code_len = u32::try_from(code.len()).ok()?;
    let mut output = Vec::with_capacity(
        15usize
            .checked_add(program.ro_data.len())?
            .checked_add(program.rw_data.len())?
            .checked_add(code.len())?,
    );
    output.extend_from_slice(&(program.ro_data.len() as u32).to_le_bytes()[..3]);
    output.extend_from_slice(&(program.rw_data.len() as u32).to_le_bytes()[..3]);
    output.extend_from_slice(&(program.heap_pages as u16).to_le_bytes());
    output.extend_from_slice(&program.stack_size.to_le_bytes()[..3]);
    output.extend_from_slice(&program.ro_data);
    output.extend_from_slice(&program.rw_data);
    output.extend_from_slice(&code_len.to_le_bytes());
    output.extend_from_slice(&code);
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sample() -> StandardProgram {
        StandardProgram {
            ro_data: (0..=255).collect(),
            rw_data: vec![0xbb; 77],
            heap_pages: 3,
            stack_size: 8192,
            code: CodeBlob {
                jump_table: vec![0, 300, 70_000],
                code: vec![0, 1, 2],
                bitmask: vec![1, 1, 1],
            },
        }
    }

    #[test]
    fn complete_program_round_trips() {
        let program = sample();
        let bytes = build_standard_program(&program).unwrap();
        assert_eq!(parse_standard_program(&bytes), Some(program));
    }

    #[test]
    fn layout_matches_standard_addresses() {
        let program = sample();
        let layout = program.layout(&[1, 2, 3]).unwrap();
        assert_eq!(layout.ro.base, u64::from(ZONE_SIZE));
        assert_eq!(layout.rw.base, 3 * u64::from(ZONE_SIZE));
        assert_eq!(layout.registers[0], HALT_ADDRESS);
        assert_eq!(layout.registers[7], layout.args.base);
        assert_eq!(layout.registers[8], 3);
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = build_standard_program(&sample()).unwrap();
        bytes.push(0);
        assert!(parse_standard_program(&bytes).is_none());
    }

    #[test]
    fn obsolete_metadata_prefix_is_rejected() {
        let program = build_standard_program(&sample()).unwrap();
        let mut prefixed = vec![3, 1, 2, 3];
        prefixed.extend_from_slice(&program);
        assert!(parse_standard_program(&prefixed).is_none());
    }

    #[test]
    fn noncanonical_naturals_are_rejected() {
        assert_eq!(read_nat(&[0x80, 0x01], 0), None);
        assert_eq!(read_nat(&[0xff, 1, 0, 0, 0, 0, 0, 0, 0], 0), None);
    }

    #[test]
    fn impossible_jump_table_size_is_rejected_without_allocating() {
        let mut bytes = vec![0xff];
        bytes.extend_from_slice(&u64::MAX.to_le_bytes());
        bytes.extend_from_slice(&[1, 0]);
        assert!(parse_compact_code_blob(&bytes).is_none());
    }

    #[test]
    fn unused_bitmask_bits_are_rejected() {
        let code = CodeBlob {
            jump_table: Vec::new(),
            code: vec![0],
            bitmask: vec![1],
        };
        let mut bytes = build_compact_code_blob(&code).unwrap();
        *bytes.last_mut().unwrap() |= 0x80;
        assert!(parse_compact_code_blob(&bytes).is_none());
    }

    #[test]
    fn nonminimal_jump_entry_width_is_rejected() {
        // One jump-table entry with value 1 fits in one byte. Encoding it in
        // two bytes would otherwise decode to the same CodeBlob.
        let bytes = [1, 2, 1, 1, 0, 0, 1];
        assert!(parse_compact_code_blob(&bytes).is_none());
    }

    /// The borrowed view must agree with the owned parse on every input:
    /// same acceptance, the same `machine` blob, the same layout and the same
    /// instruction starts.
    fn assert_views_agree(bytes: &[u8]) {
        let owned = parse_standard_program(bytes);
        let borrowed = StandardProgramRef::parse(bytes);
        assert_eq!(owned.is_some(), borrowed.is_some(), "acceptance differs");
        let (Some(owned), Some(borrowed)) = (owned, borrowed) else {
            return;
        };
        assert_eq!(
            Some(borrowed.code_blob().to_vec()),
            owned.compact_code(),
            "the embedded code blob is the re-encoded one"
        );
        assert_eq!(borrowed.ro_data, owned.ro_data.as_slice());
        assert_eq!(borrowed.rw_data, owned.rw_data.as_slice());
        assert_eq!(borrowed.heap_pages, owned.heap_pages);
        assert_eq!(borrowed.stack_size, owned.stack_size);
        assert_eq!(borrowed.code_len(), owned.code.code.len());
        for pc in 0..owned.code.bitmask.len() + 9 {
            assert_eq!(
                borrowed.is_instruction_start(pc),
                owned.code.bitmask.get(pc) == Some(&1),
                "instruction start at {pc}"
            );
        }
        for args in [&[][..], &[7, 8, 9][..]] {
            let (a, b) = (owned.layout(args), borrowed.layout(args));
            assert_eq!(a.is_some(), b.is_some());
            if let (Some(a), Some(b)) = (a, b) {
                assert_eq!(
                    (a.ro, a.rw, a.stack, a.args, a.heap_top, a.registers),
                    (b.ro, b.rw, b.stack, b.args, b.heap_top, b.registers)
                );
                assert_eq!((a.ro_data, a.rw_data), (b.ro_data, b.rw_data));
            }
        }
    }

    #[test]
    fn borrowed_program_is_the_owned_program_without_copies() {
        let bytes = build_standard_program(&sample()).unwrap();
        assert_views_agree(&bytes);
        let program = StandardProgramRef::parse(&bytes).unwrap();
        // Zero-copy: every section points into the original bytes.
        let range = bytes.as_ptr_range();
        for section in [program.ro_data, program.rw_data, program.code_blob()] {
            assert!(range.contains(&section.as_ptr()));
        }
        assert!(bytes.ends_with(program.code_blob()));
    }

    #[test]
    fn borrowed_program_refuses_what_the_owned_parse_refuses() {
        let valid = build_standard_program(&sample()).unwrap();
        let mut trailing = valid.clone();
        trailing.push(0);
        let mut prefixed = vec![3, 1, 2, 3];
        prefixed.extend_from_slice(&valid);
        let code = CodeBlob {
            jump_table: Vec::new(),
            code: vec![0],
            bitmask: vec![1],
        };
        let mut unused_bits = build_standard_program(&StandardProgram {
            code: code.clone(),
            ..sample()
        })
        .unwrap();
        *unused_bits.last_mut().unwrap() |= 0x80;
        let code_blob_len = build_compact_code_blob(&code).unwrap().len();
        let mut wide_entry = build_standard_program(&StandardProgram { code, ..sample() }).unwrap();
        // Replace the code blob with one whose single jump entry (1) is
        // encoded two bytes wide.
        let blob = [1, 2, 1, 1, 0, 0, 1];
        wide_entry.truncate(wide_entry.len() - code_blob_len - 4);
        wide_entry.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        wide_entry.extend_from_slice(&blob);
        for bytes in [
            trailing,
            prefixed,
            unused_bits,
            wide_entry,
            Vec::new(),
            vec![0; 15],
        ] {
            assert!(StandardProgramRef::parse(&bytes).is_none());
            assert_views_agree(&bytes);
        }
    }

    fn arbitrary_program() -> impl Strategy<Value = StandardProgram> {
        (
            proptest::collection::vec(any::<u8>(), 0..64),
            proptest::collection::vec(any::<u8>(), 0..64),
            0u32..4,
            0u32..(1 << 16),
            proptest::collection::vec(any::<u32>(), 0..6),
            proptest::collection::vec(any::<bool>(), 0..40),
        )
            .prop_map(
                |(ro_data, rw_data, heap_pages, stack_size, jump_table, starts)| StandardProgram {
                    ro_data,
                    rw_data,
                    heap_pages,
                    stack_size,
                    code: CodeBlob {
                        jump_table: jump_table
                            .into_iter()
                            .map(|entry| entry >> (entry % 32))
                            .collect(),
                        code: starts.iter().map(|start| u8::from(*start) * 3).collect(),
                        bitmask: starts.iter().map(|start| u8::from(*start)).collect(),
                    },
                },
            )
    }

    proptest! {
        #[test]
        fn borrowed_and_owned_parses_agree_on_valid_programs(program in arbitrary_program()) {
            let bytes = build_standard_program(&program).unwrap();
            prop_assert_eq!(parse_standard_program(&bytes), Some(program));
            assert_views_agree(&bytes);
        }

        #[test]
        fn borrowed_and_owned_parses_agree_on_mutated_programs(
            program in arbitrary_program(),
            edits in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..4),
            cut in any::<usize>(),
        ) {
            let mut bytes = build_standard_program(&program).unwrap();
            for (at, value) in edits {
                let at = at % bytes.len();
                bytes[at] = value;
            }
            assert_views_agree(&bytes);
            bytes.truncate(cut % (bytes.len() + 1));
            assert_views_agree(&bytes);
        }

        #[test]
        fn borrowed_and_owned_parses_agree_on_arbitrary_bytes(
            bytes in proptest::collection::vec(any::<u8>(), 0..96),
        ) {
            assert_views_agree(&bytes);
        }

        #[test]
        fn naturals_round_trip(value: u64) {
            let mut bytes = Vec::new();
            encode_nat(value, &mut bytes);
            prop_assert_eq!(read_nat(&bytes, 0), Some((value, bytes.len())));
        }
    }
}
