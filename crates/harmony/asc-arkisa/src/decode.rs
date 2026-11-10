//! Decoding one instruction and reading its operands.
//!
//! Field extraction mirrors upstream's `BytecodeInst::Read`: the bytes that
//! cover a field are assembled little-endian, shifted right by the field's
//! bit offset within its first byte and cut (or sign-extended) to its width.
//! Two 4-bit fields therefore share a byte with the first one in the low
//! nibble.

use std::fmt;

use crate::{flag, opcode, prefixed_opcode, Opcode, Operand, OperandKind, Prefix};

/// Why the bytes at an offset are not an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Undefined opcode byte, or undefined sub-opcode `sub` of the prefix byte `opcode`.
    Undefined { pc: usize, opcode: u8, sub: Option<u8> },
    /// The instruction at `pc` extends past the end of the code (also when
    /// `pc` itself is at or past the end).
    Truncated { pc: usize },
}

impl DecodeError {
    /// Offset of the offending instruction.
    pub const fn pc(&self) -> usize {
        match *self {
            Self::Undefined { pc, .. } | Self::Truncated { pc } => pc,
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Undefined { pc, opcode, sub: None } => write!(f, "undefined opcode {opcode:#04x} at offset {pc:#x}"),
            Self::Undefined { pc, opcode, sub: Some(sub) } => {
                write!(f, "undefined opcode {opcode:#04x} {sub:#04x} at offset {pc:#x}")
            }
            Self::Truncated { pc } => write!(f, "instruction at offset {pc:#x} runs past the end of the code"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// A decoded operand.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Value {
    Reg(u16),
    /// Signed or unsigned immediate, extended as the opcode says.
    Imm(i64),
    Float(f64),
    IcSlot(u16),
    /// Branch offset relative to the instruction; [`Instruction::jump_target`] resolves it.
    JumpOffset(i32),
    StringId(u32),
    MethodId(u32),
    LiteralArrayId(u32),
}

/// Consecutive registers read by a range instruction (`callrange`, `newobjrange`, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegRange {
    pub first: u16,
    pub count: u32,
}

/// One instruction inside a code slice.
#[derive(Debug, Clone, Copy)]
pub struct Instruction<'a> {
    /// Offset of the instruction in the code it was decoded from.
    pub pc: usize,
    pub opcode: &'static Opcode,
    /// Exactly `opcode.len` bytes.
    bytes: &'a [u8],
}

impl<'a> Instruction<'a> {
    /// Decode the instruction at `pc`.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Undefined`] for an opcode that is not in the table,
    /// [`DecodeError::Truncated`] when the instruction does not fit in `code`.
    pub fn decode(code: &'a [u8], pc: usize) -> Result<Self, DecodeError> {
        let truncated = DecodeError::Truncated { pc };
        let rest = code.get(pc..).ok_or(truncated)?;
        let &first = rest.first().ok_or(truncated)?;
        let opcode = match Prefix::from_byte(first) {
            None => opcode(first).ok_or(DecodeError::Undefined { pc, opcode: first, sub: None })?,
            Some(prefix) => {
                let &sub = rest.get(1).ok_or(truncated)?;
                prefixed_opcode(prefix, sub).ok_or(DecodeError::Undefined { pc, opcode: first, sub: Some(sub) })?
            }
        };
        let bytes = rest.get(..opcode.byte_len()).ok_or(truncated)?;
        Ok(Self { pc, opcode, bytes })
    }

    /// The encoded instruction.
    #[inline]
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Offset of the instruction that follows.
    #[inline]
    pub fn next_pc(&self) -> usize {
        self.pc + self.bytes.len()
    }

    /// Operand values in assembly order, parallel to `opcode.operands`.
    pub fn operands(&self) -> Operands<'a> {
        Operands { bytes: self.bytes, fields: self.opcode.operands.iter() }
    }

    /// The `index`-th operand in assembly order.
    pub fn operand(&self, index: usize) -> Option<Value> {
        self.opcode.operands.get(index).map(|field| read(self.bytes, field))
    }

    fn raw_of(&self, kind: OperandKind) -> Option<u64> {
        self.opcode.operand_of(kind).map(|field| raw(self.bytes, field))
    }

    /// The string id operand (`lda.str`, `ldobjbyname`, ...).
    pub fn string_id(&self) -> Option<u32> {
        self.raw_of(OperandKind::StringId).map(low_u32)
    }

    /// The method id operand (`definefunc`, `definemethod`, `defineclasswithbuffer`, ...).
    pub fn method_id(&self) -> Option<u32> {
        self.raw_of(OperandKind::MethodId).map(low_u32)
    }

    /// The literal-array id operand (`createarraywithbuffer`, `defineclasswithbuffer`, ...).
    pub fn literal_array_id(&self) -> Option<u32> {
        self.raw_of(OperandKind::LiteralArrayId).map(low_u32)
    }

    /// First inline-cache slot used by the instruction.
    pub fn ic_slot(&self) -> Option<u16> {
        self.raw_of(OperandKind::IcSlot).map(low_u16)
    }

    /// Signed branch offset in bytes, relative to `pc`.
    pub fn jump_offset(&self) -> Option<i32> {
        self.opcode.operand_of(OperandKind::JumpOffset).map(|field| low_i32(sign_extend(raw(self.bytes, field), field.width)))
    }

    /// Absolute offset a branch transfers to. `None` when this is not a
    /// branch or the target lies before offset 0; a target past the end of
    /// the code is returned as is and is the caller's to reject.
    pub fn jump_target(&self) -> Option<usize> {
        let offset = isize::try_from(self.jump_offset()?).ok()?;
        self.pc.checked_add_signed(offset)
    }

    /// The registers a range instruction reads: they start at the
    /// instruction's last register and their number is its last immediate,
    /// plus one for the opcodes that count `this` or the first argument
    /// separately (`range_1` in `isa.yaml`).
    ///
    /// `isa.yaml` tags the short `callthisrange` and `callthisrangewithname`
    /// `range_0`, yet like their `wide.` forms they read `this` and then the
    /// counted arguments (real code: `callthisrange 4, v6` passes v7..v10 to
    /// a method of v6), so those two get the extra register as well.
    pub fn reg_range(&self) -> Option<RegRange> {
        if !self.opcode.has_reg_range() {
            return None;
        }
        let last = |kind| self.opcode.operands.iter().rfind(|field| field.kind == kind).map(|field| raw(self.bytes, field));
        let first = low_u16(last(OperandKind::RegIn)?);
        let mistagged = matches!((self.opcode.prefix, self.opcode.value), (None, 0x31 | 0xe1));
        let extra = u32::from(mistagged || self.opcode.flags & flag::RANGE_1 != 0);
        Some(RegRange { first, count: low_u32(last(OperandKind::ImmUnsigned)?).saturating_add(extra) })
    }
}

/// Iterator over the operand values of an instruction.
#[derive(Debug, Clone)]
pub struct Operands<'a> {
    bytes: &'a [u8],
    fields: std::slice::Iter<'static, Operand>,
}

impl Iterator for Operands<'_> {
    type Item = Value;

    fn next(&mut self) -> Option<Value> {
        self.fields.next().map(|field| read(self.bytes, field))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.fields.size_hint()
    }
}

impl ExactSizeIterator for Operands<'_> {}

/// The field's bits, zero-extended. Bytes outside `bytes` read as zero; the
/// table tests guarantee every field lies inside its instruction.
fn raw(bytes: &[u8], field: &Operand) -> u64 {
    let start = usize::from(field.offset / 8);
    let shift = field.offset % 8;
    let covered = usize::from(shift + field.width).div_ceil(8);
    let mut le = [0u8; 8];
    for (dst, src) in le.iter_mut().zip(bytes.iter().skip(start).take(covered)) {
        *dst = *src;
    }
    let value = u64::from_le_bytes(le) >> shift;
    match field.width {
        64.. => value,
        width => value & ((1 << width) - 1),
    }
}

fn sign_extend(value: u64, width: u8) -> i64 {
    let unused = 64u32.saturating_sub(u32::from(width));
    // Same-width reinterpretation, then an arithmetic shift back.
    ((value << unused) as i64) >> unused
}

// `raw` masks to the field width and the table tests bound the width per
// operand kind, so these keep every significant bit.
fn low_u16(value: u64) -> u16 {
    value as u16
}

fn low_u32(value: u64) -> u32 {
    value as u32
}

fn low_i32(value: i64) -> i32 {
    value as i32
}

fn read(bytes: &[u8], field: &Operand) -> Value {
    let bits = raw(bytes, field);
    match field.kind {
        OperandKind::RegIn | OperandKind::RegOut => Value::Reg(low_u16(bits)),
        // At most 32 bits wide, so the value is non-negative as `i64`.
        OperandKind::ImmUnsigned => Value::Imm(i64::from(low_u32(bits))),
        OperandKind::ImmSigned => Value::Imm(sign_extend(bits, field.width)),
        OperandKind::ImmFloat => Value::Float(f64::from_bits(bits)),
        OperandKind::JumpOffset => Value::JumpOffset(low_i32(sign_extend(bits, field.width))),
        OperandKind::IcSlot => Value::IcSlot(low_u16(bits)),
        OperandKind::StringId => Value::StringId(low_u32(bits)),
        OperandKind::MethodId => Value::MethodId(low_u32(bits)),
        OperandKind::LiteralArrayId => Value::LiteralArrayId(low_u32(bits)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(code: &[u8]) -> Instruction<'_> {
        let insn = Instruction::decode(code, 0).unwrap();
        assert_eq!(insn.next_pc(), code.len(), "{}", insn.opcode.name);
        insn
    }

    fn values(code: &[u8]) -> (&'static str, Vec<Value>) {
        let insn = decode(code);
        (insn.opcode.name, insn.operands().collect())
    }

    #[test]
    fn plain_formats() {
        assert_eq!(values(&[0x00]), ("ldundefined", vec![]));
        assert_eq!(values(&[0x60, 0x07]), ("lda", vec![Value::Reg(7)]));
        assert_eq!(values(&[0x3e, 0x34, 0x12]), ("lda.str", vec![Value::StringId(0x1234)]));
        // op_imm_8_id_16 and its 16-bit-slot twin op_imm_16_id_16
        assert_eq!(values(&[0x42, 0x05, 0x34, 0x12]), ("ldobjbyname", vec![Value::IcSlot(5), Value::StringId(0x1234)]));
        assert_eq!(values(&[0x90, 0x05, 0x01, 0x34, 0x12]), ("ldobjbyname", vec![Value::IcSlot(0x105), Value::StringId(0x1234)]));
        // op_imm_8_v1_8_v2_8
        assert_eq!(values(&[0x2e, 0x09, 0x01, 0x02]), ("callthis1", vec![Value::IcSlot(9), Value::Reg(1), Value::Reg(2)]));
        // op_v1_16_v2_16
        assert_eq!(values(&[0x8f, 0x01, 0x02, 0x03, 0x04]), ("mov", vec![Value::Reg(0x201), Value::Reg(0x403)]));
    }

    #[test]
    fn nibble_packed_operands_put_the_first_in_the_low_nibble() {
        // op_v1_4_v2_4: mov v2, v10
        let mov = decode(&[0x44, 0xa2]);
        assert_eq!(mov.operands().collect::<Vec<_>>(), [Value::Reg(2), Value::Reg(10)]);
        assert_eq!(mov.opcode.operands[0].kind, OperandKind::RegOut);
        // op_imm1_4_imm2_4: ldlexvar level 3, slot 15
        assert_eq!(values(&[0x3c, 0xf3]), ("ldlexvar", vec![Value::Imm(3), Value::Imm(15)]));
        // pref_op_imm1_4_imm2_4_v_8
        assert_eq!(values(&[0xfc, 0x20, 0x21, 0x09]), ("deprecated.stlexvar", vec![Value::Imm(1), Value::Imm(2), Value::Reg(9)]));
    }

    #[test]
    fn immediates_follow_the_signature_type() {
        assert_eq!(values(&[0x62, 0xff, 0xff, 0xff, 0xff]), ("ldai", vec![Value::Imm(-1)]));
        assert_eq!(values(&[0x62, 0x42, 0x4b, 0x1d, 0x00]), ("ldai", vec![Value::Imm(1_919_810)]));
        // u8 stays unsigned: newlexenv 0xff
        assert_eq!(values(&[0x09, 0xff]), ("newlexenv", vec![Value::Imm(255)]));
        // u32 with the top bit set: wide.stobjbyindex v1, 0x80000000
        assert_eq!(
            values(&[0xfd, 0x09, 0x01, 0x00, 0x00, 0x00, 0x80]),
            ("wide.stobjbyindex", vec![Value::Reg(1), Value::Imm(0x8000_0000)])
        );

        let mut fldai = vec![0x63];
        fldai.extend_from_slice(&(-1.5f64).to_le_bytes());
        assert_eq!(values(&fldai), ("fldai", vec![Value::Float(-1.5)]));
        fldai[1..].copy_from_slice(&f64::NAN.to_le_bytes());
        assert!(matches!(decode(&fldai).operand(0), Some(Value::Float(v)) if v.is_nan()));
    }

    #[test]
    fn operands_come_in_signature_order() {
        // op_imm1_8_id_16_imm2_8: definefunc slot 1, method 0x0203, 4 formal parameters
        let definefunc = decode(&[0x33, 0x01, 0x03, 0x02, 0x04]);
        assert_eq!(definefunc.operands().collect::<Vec<_>>(), [Value::IcSlot(1), Value::MethodId(0x0203), Value::Imm(4)]);
        assert_eq!((definefunc.method_id(), definefunc.ic_slot(), definefunc.string_id()), (Some(0x0203), Some(1), None));

        // op_imm1_8_id1_16_id2_16_imm2_16_v_8
        let class = decode(&[0x35, 0x01, 0x11, 0x00, 0x22, 0x00, 0x02, 0x00, 0x07]);
        assert_eq!(class.opcode.name, "defineclasswithbuffer");
        assert_eq!((class.method_id(), class.literal_array_id()), (Some(0x11), Some(0x22)));
        assert_eq!(class.operand(3), Some(Value::Imm(2)));
        assert_eq!(class.operand(4), Some(Value::Reg(7)));
        assert_eq!(class.operand(5), None);

        // pref_op_id_32_v_8: the deprecated 32-bit id
        let old = decode(&[0xfc, 0x25, 0x78, 0x56, 0x34, 0x12, 0x03]);
        assert_eq!(old.opcode.name, "deprecated.ldobjbyname");
        assert_eq!(old.operands().collect::<Vec<_>>(), [Value::StringId(0x1234_5678), Value::Reg(3)]);
    }

    #[test]
    fn prefixed_and_wide() {
        assert_eq!(values(&[0xfe, 0x00]), ("throw", vec![]));
        assert_eq!(values(&[0xfe, 0x09, 0x34, 0x12]), ("throw.undefinedifholewithname", vec![Value::StringId(0x1234)]));
        assert_eq!(values(&[0xfb, 0x1b, 0x01, 0x02]), ("callruntime.wideldsendablelocalmodulevar", vec![Value::Imm(0x201)]));
        assert_eq!(values(&[0xfd, 0x11, 0x00, 0x01]), ("wide.ldexternalmodulevar", vec![Value::Imm(0x100)]));

        // pref_op_imm_16_v_8, range_0: wide.callrange 300 args from v4
        let callrange = decode(&[0xfd, 0x04, 0x2c, 0x01, 0x04]);
        assert_eq!(callrange.opcode.name, "wide.callrange");
        assert_eq!(callrange.reg_range(), Some(RegRange { first: 4, count: 300 }));
        assert_eq!(callrange.ic_slot(), None);
    }

    #[test]
    fn register_ranges() {
        // callthisrange slot, argc 2, v5: `this` in v5, then 2 arguments, despite its range_0 tag
        let callthisrange = decode(&[0x31, 0x00, 0x02, 0x05]);
        assert_eq!(callthisrange.opcode.name, "callthisrange");
        assert_eq!(callthisrange.reg_range(), Some(RegRange { first: 5, count: 3 }));
        // range_1: wide.callthisrange argc 2, v5 reads this + 2 arguments
        assert_eq!(decode(&[0xfd, 0x05, 0x02, 0x00, 0x05]).reg_range(), Some(RegRange { first: 5, count: 3 }));
        // range_1 with two registers: the run starts at the last one
        let excluded = decode(&[0xb3, 0x01, 0x03, 0x04]);
        assert_eq!(excluded.opcode.name, "createobjectwithexcludedkeys");
        assert_eq!(excluded.reg_range(), Some(RegRange { first: 4, count: 2 }));
        assert_eq!(decode(&[0x60, 0x01]).reg_range(), None);
    }

    #[test]
    fn jump_targets_are_absolute() {
        let code = [0x00, 0x00, 0x4d, 0xfe, 0x4f, 0x05, 0x98, 0xf0, 0xff, 0xff, 0xff, 0x5c, 0x02, 0x7f];
        let at = |pc| Instruction::decode(&code, pc).unwrap();
        // jmp -2 at 2
        assert_eq!((at(2).jump_offset(), at(2).jump_target()), (Some(-2), Some(0)));
        assert_eq!(at(2).operand(0), Some(Value::JumpOffset(-2)));
        // jeqz +5 at 4
        assert_eq!(at(4).jump_target(), Some(9));
        // jmp -16 at 6 points before the code
        assert_eq!((at(6).jump_offset(), at(6).jump_target()), (Some(-16), None));
        // jeq v2, +127 at 11 points past the end: returned, not validated
        assert_eq!(at(11).operands().collect::<Vec<_>>(), [Value::Reg(2), Value::JumpOffset(127)]);
        assert_eq!(at(11).jump_target(), Some(138));
        assert_eq!(at(0).jump_target(), None);
        // 16-bit offset: jnez -300
        assert_eq!(decode(&[0x9b, 0xd4, 0xfe]).jump_offset(), Some(-300));
    }

    #[test]
    fn undefined_and_truncated() {
        let undefined = |code: &[u8]| Instruction::decode(code, 0).unwrap_err();
        assert_eq!(undefined(&[0xe2]), DecodeError::Undefined { pc: 0, opcode: 0xe2, sub: None });
        assert_eq!(undefined(&[0xff, 0x00]), DecodeError::Undefined { pc: 0, opcode: 0xff, sub: None });
        assert_eq!(undefined(&[0xfe, 0x0a]), DecodeError::Undefined { pc: 0, opcode: 0xfe, sub: Some(0x0a) });
        assert_eq!(undefined(&[0xfb, 0xff, 0, 0]), DecodeError::Undefined { pc: 0, opcode: 0xfb, sub: Some(0xff) });
        assert_eq!(undefined(&[]), DecodeError::Truncated { pc: 0 });
        assert_eq!(undefined(&[0xfd]), DecodeError::Truncated { pc: 0 });
        assert_eq!(undefined(&[0x62, 1, 2, 3]), DecodeError::Truncated { pc: 0 });
        assert_eq!(Instruction::decode(&[0x00], 1).unwrap_err(), DecodeError::Truncated { pc: 1 });
        assert_eq!(Instruction::decode(&[0x00], usize::MAX).unwrap_err().pc(), usize::MAX);
        assert_eq!(undefined(&[0xfe, 0x0a]).to_string(), "undefined opcode 0xfe 0x0a at offset 0x0");
    }

    #[test]
    fn every_opcode_round_trips_through_its_fields() {
        // Encode a distinct bit pattern per field with an independent writer
        // (bit by bit) and read it back through `raw`.
        for op in crate::opcodes() {
            let mut code = vec![0u8; op.byte_len()];
            match op.prefix {
                None => code[0] = op.value,
                Some(prefix) => code[..2].copy_from_slice(&[prefix.byte(), op.value]),
            }
            let pattern = |index: usize, width: u8| (0x9e37_79b9_7f4a_7c15u64.rotate_left(index as u32 * 7)) >> (64 - u32::from(width));
            for (index, field) in op.operands.iter().enumerate() {
                let value = pattern(index, field.width);
                for bit in 0..usize::from(field.width) {
                    let at = usize::from(field.offset) + bit;
                    code[at / 8] |= u8::from(value >> bit & 1 == 1) << (at % 8);
                }
            }
            let insn = decode(&code);
            assert!(std::ptr::eq(insn.opcode, op), "{}", op.name);
            assert_eq!(insn.operands().len(), op.operands.len());
            for (index, field) in op.operands.iter().enumerate() {
                assert_eq!(raw(insn.bytes(), field), pattern(index, field.width), "{} operand {index}", op.name);
            }
        }
    }
}
