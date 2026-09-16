//! Operand extraction for every instruction format.
//!
//! Mirrors ART's `dex_instruction-inl.h`: `VRegA`, `VRegB`, `VRegC`, `VRegH`
//! and the constant-pool index that always lives at `pc + 2`.
//!
//! Bounds policy: the `vreg_*` accessors and [`Instruction::decode`] are
//! bounds-safe and return `None` when the instruction does not fit in `code`.
//! The raw `fetch*`, `get_index`/`set_index` and `get_proto_index`/
//! `set_proto_index` helpers are the hot path of the rebuild writer and
//! **panic** on truncated input; callers must have checked
//! `pc + op.byte_len() <= code.len()` first (`walk` does this before handing
//! out a `Step`).

use crate::{opcode, Format, Opcode, FILL_ARRAY_DATA_PAYLOAD, PACKED_SWITCH_PAYLOAD, SPARSE_SWITCH_PAYLOAD};

/// Little-endian code unit `word` of the instruction at `pc`.
///
/// # Panics
///
/// Panics when `pc + word * 2 + 2 > code.len()`.
#[inline]
pub fn fetch16(code: &[u8], pc: usize, word: usize) -> u16 {
    let s = pc + word * 2;
    u16::from_le_bytes([code[s], code[s + 1]])
}

/// Two consecutive code units starting at `word`, as one little-endian `u32`.
///
/// # Panics
///
/// Panics when `pc + word * 2 + 4 > code.len()`.
#[inline]
fn fetch32(code: &[u8], pc: usize, word: usize) -> u32 {
    let s = pc + word * 2;
    u32::from_le_bytes([code[s], code[s + 1], code[s + 2], code[s + 3]])
}

/// Four consecutive code units starting at `word`, as one little-endian `u64`.
///
/// # Panics
///
/// Panics when `pc + word * 2 + 8 > code.len()`.
#[inline]
fn fetch64(code: &[u8], pc: usize, word: usize) -> u64 {
    let s = pc + word * 2;
    u64::from_le_bytes([code[s], code[s + 1], code[s + 2], code[s + 3], code[s + 4], code[s + 5], code[s + 6], code[s + 7]])
}

/// Whether the whole instruction `op` at `pc` lies inside `code`.
#[inline]
fn fits(code: &[u8], pc: usize, op: &Opcode) -> bool {
    pc.checked_add(op.byte_len()).is_some_and(|end| end <= code.len())
}

/// Constant-pool index carried by the instruction at `pc` (`pc + 2`; 32 bit
/// for `const-string/jumbo`, 16 bit otherwise).
///
/// # Panics
///
/// Panics when the instruction is truncated (`pc + op.byte_len() > code.len()`).
#[inline]
pub fn get_index(code: &[u8], pc: usize, op: &Opcode) -> u32 {
    if op.format == Format::K31c {
        fetch32(code, pc, 1)
    } else {
        fetch16(code, pc, 1) as u32
    }
}

/// Overwrite the constant-pool index of the instruction at `pc`.
///
/// # Panics
///
/// Panics when the instruction is truncated (`pc + op.byte_len() > code.len()`).
#[inline]
pub fn set_index(code: &mut [u8], pc: usize, op: &Opcode, idx: u32) {
    if op.format == Format::K31c {
        code[pc + 2..pc + 6].copy_from_slice(&idx.to_le_bytes());
    } else {
        code[pc + 2..pc + 4].copy_from_slice(&(idx as u16).to_le_bytes());
    }
}

/// Secondary index of `invoke-polymorphic[/range]` (`proto@HHHH`, word 3).
///
/// # Panics
///
/// Panics when `pc + 8 > code.len()`.
#[inline]
pub fn get_proto_index(code: &[u8], pc: usize) -> u16 {
    fetch16(code, pc, 3)
}

/// Overwrite the `proto@HHHH` operand of `invoke-polymorphic[/range]`.
///
/// # Panics
///
/// Panics when `pc + 8 > code.len()`.
#[inline]
pub fn set_proto_index(code: &mut [u8], pc: usize, idx: u16) {
    code[pc + 6..pc + 8].copy_from_slice(&idx.to_le_bytes());
}

/// `VRegA` as a sign-aware integer (`None` when the instruction is truncated).
pub fn vreg_a(code: &[u8], pc: usize, op: &Opcode) -> Option<i64> {
    if !fits(code, pc, op) {
        return None;
    }
    let w0 = fetch16(code, pc, 0);
    Some(match op.format {
        Format::K10t => ((w0 >> 8) as u8 as i8) as i64,
        Format::K10x
        | Format::K11x
        | Format::K21c
        | Format::K21h
        | Format::K21s
        | Format::K21t
        | Format::K22b
        | Format::K22x
        | Format::K23x
        | Format::K31c
        | Format::K31i
        | Format::K31t
        | Format::K3rc
        | Format::K51l
        | Format::K4rcc => (w0 >> 8) as i64,
        Format::K11n | Format::K12x | Format::K22c | Format::K22s | Format::K22t => ((w0 >> 8) & 0x0f) as i64,
        Format::K20t => (fetch16(code, pc, 1) as i16) as i64,
        Format::K30t => (fetch32(code, pc, 1) as i32) as i64,
        Format::K32x => fetch16(code, pc, 1) as i64,
        Format::K35c | Format::K45cc => (w0 >> 12) as i64,
    })
}

/// `VRegB` as a sign-aware integer (`None` when the format has no `B` operand
/// or the instruction is truncated).
pub fn vreg_b(code: &[u8], pc: usize, op: &Opcode) -> Option<i64> {
    if !fits(code, pc, op) {
        return None;
    }
    let w0 = fetch16(code, pc, 0);
    Some(match op.format {
        Format::K12x | Format::K22c | Format::K22s | Format::K22t => (w0 >> 12) as i64,
        Format::K11n => {
            let v = (w0 >> 12) as i64;
            if v > 7 {
                v - 16
            } else {
                v
            }
        }
        Format::K21c | Format::K21h | Format::K22x | Format::K35c | Format::K3rc | Format::K45cc | Format::K4rcc => {
            fetch16(code, pc, 1) as i64
        }
        Format::K23x | Format::K22b => (fetch16(code, pc, 1) & 0xff) as i64,
        Format::K21s | Format::K21t => (fetch16(code, pc, 1) as i16) as i64,
        Format::K31c => fetch32(code, pc, 1) as i64,
        Format::K31i | Format::K31t => (fetch32(code, pc, 1) as i32) as i64,
        Format::K32x => fetch16(code, pc, 2) as i64,
        Format::K51l => fetch64(code, pc, 1) as i64,
        _ => return None,
    })
}

/// `VRegC` as a sign-aware integer (`None` when the format has no `C` operand
/// or the instruction is truncated).
pub fn vreg_c(code: &[u8], pc: usize, op: &Opcode) -> Option<i64> {
    if !fits(code, pc, op) {
        return None;
    }
    Some(match op.format {
        Format::K23x => (fetch16(code, pc, 1) >> 8) as i64,
        Format::K22b => ((fetch16(code, pc, 1) >> 8) as u8 as i8) as i64,
        Format::K22c => fetch16(code, pc, 1) as i64,
        Format::K22s | Format::K22t => (fetch16(code, pc, 1) as i16) as i64,
        Format::K35c | Format::K45cc => (fetch16(code, pc, 2) & 0x0f) as i64,
        Format::K3rc | Format::K4rcc => fetch16(code, pc, 2) as i64,
        _ => return None,
    })
}

/// `VRegH` (only `invoke-polymorphic[/range]`; `None` otherwise or when the
/// instruction is truncated).
pub fn vreg_h(code: &[u8], pc: usize, op: &Opcode) -> Option<u16> {
    match op.format {
        Format::K45cc | Format::K4rcc if fits(code, pc, op) => Some(fetch16(code, pc, 3)),
        _ => None,
    }
}

/// Kind of data payload found at a `nop` with a pseudo-opcode identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    PackedSwitch,
    SparseSwitch,
    FillArrayData,
}

/// Decoded instruction with all operands materialised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub pc: usize,
    pub opcode: &'static Opcode,
    pub a: i64,
    pub b: i64,
    pub c: i64,
    pub h: u16,
    /// Argument registers of `35c`/`45cc` formats.
    pub regs: Vec<u16>,
    /// Length in code units (payloads report their full size).
    pub units: usize,
    pub payload: Option<PayloadKind>,
}

impl Instruction {
    /// Decode the instruction at `pc`. Returns `None` for undefined opcodes or
    /// truncated code (including payloads whose header or body does not fit).
    pub fn decode(code: &[u8], pc: usize) -> Option<Instruction> {
        let op = opcode(*code.get(pc)?)?;
        if !fits(code, pc, op) {
            return None;
        }
        // Payload pseudo-instructions share opcode 0x00.
        if op.value == 0 {
            let ident = fetch16(code, pc, 0);
            let remaining = code.len() - pc;
            let (payload, units): (Option<PayloadKind>, u64) = match ident {
                PACKED_SWITCH_PAYLOAD => {
                    if remaining < 4 {
                        return None;
                    }
                    let size = fetch16(code, pc, 1) as u64;
                    (Some(PayloadKind::PackedSwitch), 4 + size * 2)
                }
                SPARSE_SWITCH_PAYLOAD => {
                    if remaining < 4 {
                        return None;
                    }
                    let size = fetch16(code, pc, 1) as u64;
                    (Some(PayloadKind::SparseSwitch), 2 + size * 4)
                }
                FILL_ARRAY_DATA_PAYLOAD => {
                    if remaining < 8 {
                        return None;
                    }
                    let width = fetch16(code, pc, 1) as u64;
                    let size = fetch32(code, pc, 2) as u64;
                    (Some(PayloadKind::FillArrayData), 4 + (width * size).div_ceil(2))
                }
                _ => (None, 1),
            };
            if units.checked_mul(2).is_none_or(|bytes| bytes > remaining as u64) {
                return None;
            }
            return Some(Instruction { pc, opcode: op, a: 0, b: 0, c: 0, h: 0, regs: Vec::new(), units: units as usize, payload });
        }
        let a = vreg_a(code, pc, op).unwrap_or(0);
        let b = vreg_b(code, pc, op).unwrap_or(0);
        let c = vreg_c(code, pc, op).unwrap_or(0);
        let h = vreg_h(code, pc, op).unwrap_or(0);
        let regs = match op.format {
            Format::K35c | Format::K45cc => {
                let count = (a as usize).min(5);
                let w2 = fetch16(code, pc, 2);
                let mut regs = vec![(w2 & 0xf), (w2 >> 4) & 0xf, (w2 >> 8) & 0xf, (w2 >> 12) & 0xf, ((fetch16(code, pc, 0) >> 8) & 0xf)];
                regs.truncate(count);
                regs
            }
            Format::K3rc | Format::K4rcc => {
                let count = a as usize;
                let first = c as u16;
                (0..count).map(|i| first.wrapping_add(i as u16)).collect()
            }
            _ => Vec::new(),
        };
        Some(Instruction { pc, opcode: op, a, b, c, h, regs, units: op.len as usize, payload: None })
    }

    #[inline]
    pub fn byte_len(&self) -> usize {
        self.units * 2
    }

    /// Absolute branch/payload target for instructions with a relative offset
    /// in code units (`goto`, `if-*`, `packed-switch`, `fill-array-data`).
    pub fn target(&self) -> Option<usize> {
        let rel = match self.opcode.format {
            Format::K10t | Format::K20t | Format::K30t => self.a,
            Format::K21t | Format::K31t => self.b,
            Format::K22t => self.c,
            _ => return None,
        };
        let target = self.pc as i64 + rel * 2;
        (target >= 0).then_some(target as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_23x_and_22b_registers() {
        // aget-short v16, v18, v17  => 4a 10 12 11
        let i = Instruction::decode(&[0x4a, 0x10, 0x12, 0x11], 0).unwrap();
        assert_eq!((i.a, i.b, i.c), (16, 18, 17));
        // add-int/lit8 v17, v16, #-2 => d8 11 10 fe
        let i = Instruction::decode(&[0xd8, 0x11, 0x10, 0xfe], 0).unwrap();
        assert_eq!((i.a, i.b, i.c), (17, 16, -2));
        // const/4 v0, #-1 => 12 f0
        let i = Instruction::decode(&[0x12, 0xf0], 0).unwrap();
        assert_eq!((i.a, i.b), (0, -1));
        // if-eq v1, v2, +3 => 32 21 03 00
        let i = Instruction::decode(&[0x32, 0x21, 0x03, 0x00], 0).unwrap();
        assert_eq!((i.a, i.b, i.c), (1, 2, 3));
        assert_eq!(i.target(), Some(6));
        // invoke-virtual {v0, v1}, meth@5 => 6e 20 05 00 10 00
        let i = Instruction::decode(&[0x6e, 0x20, 0x05, 0x00, 0x10, 0x00], 0).unwrap();
        assert_eq!(i.regs, vec![0, 1]);
        assert_eq!(get_index(&[0x6e, 0x20, 0x05, 0x00, 0x10, 0x00], 0, i.opcode), 5);
    }

    #[test]
    fn truncated_payload_headers_do_not_panic() {
        // packed-switch / sparse-switch payload identifiers with no size word.
        assert_eq!(Instruction::decode(&[0x00, 0x01], 0), None);
        assert_eq!(Instruction::decode(&[0x00, 0x02], 0), None);
        assert_eq!(Instruction::decode(&[0x00, 0x01, 0x05], 0), None);
        // fill-array-data payload with a truncated header.
        assert_eq!(Instruction::decode(&[0x00, 0x03, 0x01, 0x00, 0x02, 0x00], 0), None);
        // Complete headers whose body does not fit.
        assert_eq!(Instruction::decode(&[0x00, 0x01, 0x01, 0x00], 0), None);
        assert_eq!(Instruction::decode(&[0x00, 0x03, 0x01, 0x00, 0xff, 0xff, 0xff, 0xff], 0), None);
        // A size-0 packed-switch payload is 4 units.
        let i = Instruction::decode(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 0).unwrap();
        assert_eq!((i.payload, i.units), (Some(PayloadKind::PackedSwitch), 4));
        let i = Instruction::decode(&[0x00, 0x02, 0x00, 0x00], 0).unwrap();
        assert_eq!((i.payload, i.units), (Some(PayloadKind::SparseSwitch), 2));
        // fill-array-data: width 1, size 3 => 4 + ceil(3/2) = 6 units.
        let mut fad = vec![0x00, 0x03, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00];
        fad.extend_from_slice(&[1, 2, 3, 0]);
        assert_eq!(Instruction::decode(&fad, 0).unwrap().units, 6);
        assert_eq!(Instruction::decode(&fad[..11], 0), None);
        // Plain nop and truncated regular instructions.
        assert_eq!(Instruction::decode(&[0x00, 0x00], 0).unwrap().units, 1);
        assert_eq!(Instruction::decode(&[0x1a, 0x00, 0x05], 0), None);
        assert_eq!(Instruction::decode(&[], 0), None);
        assert_eq!(Instruction::decode(&[0x0e], 0), None);
    }

    #[test]
    fn vreg_accessors_are_bounds_safe() {
        let op = opcode(0x1a).unwrap();
        assert_eq!(vreg_a(&[0x1a, 0x00, 0x05], 0, op), None);
        assert_eq!(vreg_b(&[0x1a, 0x00, 0x05], 0, op), None);
        assert_eq!(vreg_c(&[0x1a, 0x00, 0x05], 0, op), None);
        assert_eq!(vreg_h(&[0xfa, 0x20, 0x05, 0x00, 0x10, 0x00, 0x02], 0, opcode(0xfa).unwrap()), None);
        assert_eq!(vreg_a(&[0x0e, 0x00], usize::MAX, opcode(0x0e).unwrap()), None);
    }

    #[test]
    fn decodes_45cc_and_4rcc() {
        // invoke-polymorphic {v1, v2}, meth@0x0105, proto@0x0203
        // A=2 (count), G=0 => 0xfa 0x20 | BBBB=05 01 | F E D C = 0x0021 | HHHH = 03 02
        let code = [0xfa, 0x20, 0x05, 0x01, 0x21, 0x00, 0x03, 0x02];
        let i = Instruction::decode(&code, 0).unwrap();
        assert_eq!(i.opcode.format, Format::K45cc);
        assert_eq!((i.a, i.b, i.h), (2, 0x0105, 0x0203));
        assert_eq!(i.regs, vec![1, 2]);
        assert_eq!(i.units, 4);
        assert_eq!(get_index(&code, 0, i.opcode), 0x0105);
        assert_eq!(get_proto_index(&code, 0), 0x0203);
        assert_eq!(vreg_h(&code, 0, i.opcode), Some(0x0203));
        let mut copy = code;
        set_proto_index(&mut copy, 0, 0x0a0b);
        assert_eq!(get_proto_index(&copy, 0), 0x0a0b);
        set_index(&mut copy, 0, i.opcode, 0x0c0d);
        assert_eq!(get_index(&copy, 0, i.opcode), 0x0c0d);
        assert_eq!(&copy[4..6], &code[4..6]);

        // invoke-polymorphic/range {v16 .. v18}, meth@7, proto@9
        let code = [0xfb, 0x03, 0x07, 0x00, 0x10, 0x00, 0x09, 0x00];
        let i = Instruction::decode(&code, 0).unwrap();
        assert_eq!(i.opcode.format, Format::K4rcc);
        assert_eq!((i.a, i.b, i.c, i.h), (3, 7, 16, 9));
        assert_eq!(i.regs, vec![16, 17, 18]);
        assert_eq!(Instruction::decode(&code[..7], 0), None);
    }

    #[test]
    fn decodes_51l_and_31c() {
        // const-wide v2, #0x1122334455667788
        let code = [0x18, 0x02, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];
        let i = Instruction::decode(&code, 0).unwrap();
        assert_eq!((i.a, i.b, i.units), (2, 0x1122334455667788, 5));
        assert_eq!(Instruction::decode(&code[..9], 0), None);
        // const-wide with a negative literal.
        let code = [0x18, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(Instruction::decode(&code, 0).unwrap().b, -1);

        // const-string/jumbo v3, string@0x00012345
        let mut code = [0x1b, 0x03, 0x45, 0x23, 0x01, 0x00];
        let i = Instruction::decode(&code, 0).unwrap();
        assert_eq!((i.a, i.b, i.units), (3, 0x12345, 3));
        assert_eq!(get_index(&code, 0, i.opcode), 0x12345);
        set_index(&mut code, 0, i.opcode, 0x00fedcba);
        assert_eq!(get_index(&code, 0, i.opcode), 0x00fedcba);
        assert_eq!(&code[2..6], &[0xba, 0xdc, 0xfe, 0x00]);
        // Narrow set_index truncates to 16 bits and leaves the rest untouched.
        let mut code = [0x1a, 0x03, 0x45, 0x23, 0x0e, 0x00];
        set_index(&mut code, 0, opcode(0x1a).unwrap(), 0x0001_beef);
        assert_eq!(&code, &[0x1a, 0x03, 0xef, 0xbe, 0x0e, 0x00]);
    }

    #[test]
    fn decodes_3rc_registers() {
        // invoke-virtual/range {v256 .. v259}, meth@0x0102
        let code = [0x74, 0x04, 0x02, 0x01, 0x00, 0x01];
        let i = Instruction::decode(&code, 0).unwrap();
        assert_eq!((i.a, i.b, i.c), (4, 0x0102, 256));
        assert_eq!(i.regs, vec![256, 257, 258, 259]);
        // filled-new-array/range with zero registers.
        let i = Instruction::decode(&[0x25, 0x00, 0x01, 0x00, 0x00, 0x00], 0).unwrap();
        assert!(i.regs.is_empty());
        // 35c with all five registers.
        let i = Instruction::decode(&[0x6e, 0x54, 0x05, 0x00, 0x10, 0x32], 0).unwrap();
        assert_eq!(i.regs, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn negative_branch_targets() {
        // goto/16 -2 at pc 8 => target 4
        let code = [0x0e, 0x00, 0x0e, 0x00, 0x0e, 0x00, 0x0e, 0x00, 0x29, 0x00, 0xfe, 0xff];
        let i = Instruction::decode(&code, 8).unwrap();
        assert_eq!(i.a, -2);
        assert_eq!(i.target(), Some(4));
        // goto/32 -3 at pc 6 => target 0
        let code = [0x0e, 0x00, 0x0e, 0x00, 0x0e, 0x00, 0x2a, 0x00, 0xfd, 0xff, 0xff, 0xff];
        let i = Instruction::decode(&code, 6).unwrap();
        assert_eq!(i.a, -3);
        assert_eq!(i.target(), Some(0));
        // goto -1 at pc 0 => before the method start.
        let i = Instruction::decode(&[0x28, 0xff], 0).unwrap();
        assert_eq!(i.a, -1);
        assert_eq!(i.target(), None);
        // if-ltz v0, -4 at pc 8
        let code = [0x0e, 0x00, 0x0e, 0x00, 0x0e, 0x00, 0x0e, 0x00, 0x3a, 0x00, 0xfc, 0xff];
        let i = Instruction::decode(&code, 8).unwrap();
        assert_eq!((i.b, i.target()), (-4, Some(0)));
    }
}
