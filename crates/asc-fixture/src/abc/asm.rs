//! A small assembler for ArkCompiler dynamic bytecode: instructions by
//! mnemonic, symbolic string / method / literal array operands, labels.

use std::collections::HashMap;

use asc_arkisa::{Opcode, Operand, OperandKind};

use super::LiteralArrayId;

/// One instruction operand, in the assembly order of `isa.yaml` (the order
/// `asc_arkisa::Opcode::operands` lists them in).
#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    /// A register, an immediate, an inline-cache slot or a literal jump
    /// offset: whatever the opcode has at this position.
    Num(i64),
    /// The operand of `fldai`.
    Float(f64),
    /// A string, by content. The builder gives it a 16-bit id in the region
    /// of the function.
    Str(String),
    /// A function of the record the code belongs to, by raw name.
    Method(String),
    /// A function of another record.
    MethodIn { record: String, name: String },
    /// A literal array declared with `AbcBuilder::literal_array`.
    Literal(LiteralArrayId),
    /// A jump to a label of the same [`Asm`].
    Label(String),
    /// A raw 16-bit id, written as is: for ids that resolve to nothing.
    Id(u16),
}

impl Op {
    pub fn str(text: &str) -> Op {
        Op::Str(text.to_owned())
    }

    pub fn method(name: &str) -> Op {
        Op::Method(name.to_owned())
    }

    pub fn method_in(record: &str, name: &str) -> Op {
        Op::MethodIn { record: record.to_owned(), name: name.to_owned() }
    }

    pub fn label(name: &str) -> Op {
        Op::Label(name.to_owned())
    }

    /// Whether the builder has to assign this operand an id.
    fn is_symbolic_id(&self) -> bool {
        matches!(self, Op::Str(_) | Op::Method(_) | Op::MethodIn { .. } | Op::Literal(_))
    }

    /// Whether this operand can be encoded in `field`.
    fn fits(&self, field: &Operand) -> bool {
        match (self, field.kind) {
            (Op::Num(v), OperandKind::RegIn | OperandKind::RegOut | OperandKind::IcSlot | OperandKind::ImmUnsigned) => {
                fits_unsigned(*v, field.width)
            }
            (Op::Num(v), OperandKind::ImmSigned | OperandKind::JumpOffset) => fits_signed(*v, field.width),
            (Op::Float(_), OperandKind::ImmFloat) => field.width == 64,
            (Op::Str(_), OperandKind::StringId)
            | (Op::Method(_) | Op::MethodIn { .. }, OperandKind::MethodId)
            | (Op::Literal(_), OperandKind::LiteralArrayId)
            | (Op::Id(_), OperandKind::StringId | OperandKind::MethodId | OperandKind::LiteralArrayId) => field.width >= 16,
            // Any width is accepted here; `Asm::plan` widens the instruction until the offset fits.
            (Op::Label(_), OperandKind::JumpOffset) => true,
            _ => false,
        }
    }
}

macro_rules! op_from_integer {
    ($($ty:ty),*) => {$(
        impl From<$ty> for Op {
            fn from(value: $ty) -> Op {
                Op::Num(i64::from(value))
            }
        }
    )*};
}

op_from_integer!(u8, u16, u32, i32, i64);

impl From<f64> for Op {
    fn from(value: f64) -> Op {
        Op::Float(value)
    }
}

impl From<LiteralArrayId> for Op {
    fn from(id: LiteralArrayId) -> Op {
        Op::Literal(id)
    }
}

fn fits_unsigned(value: i64, width: u8) -> bool {
    value >= 0 && (width >= 63 || value < 1i64 << width)
}

fn fits_signed(value: i64, width: u8) -> bool {
    width >= 64 || (-(1i64 << (width - 1))..1i64 << (width - 1)).contains(&value)
}

/// A catch block attached to a label-delimited range of an [`Asm`].
/// Catches of the same try range end up in one try block, in the order
/// they were added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Catch {
    pub try_start: String,
    pub try_end: String,
    pub handler: String,
    pub handler_end: String,
    /// `None` catches everything (the only kind the ArkTS compiler emits).
    pub type_idx: Option<u32>,
}

impl Catch {
    /// A catch-all for the instructions in `[try_range.0, try_range.1)`,
    /// handled by the instructions in `[handler_range.0, handler_range.1)`
    /// (all four are label names).
    pub fn all(try_range: (&str, &str), handler_range: (&str, &str)) -> Catch {
        Catch {
            try_start: try_range.0.to_owned(),
            try_end: try_range.1.to_owned(),
            handler: handler_range.0.to_owned(),
            handler_end: handler_range.1.to_owned(),
            type_idx: None,
        }
    }

    /// The same catch, for the class at `type_idx` of the region's class table.
    #[must_use]
    pub fn typed(mut self, type_idx: u32) -> Catch {
        self.type_idx = Some(type_idx);
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Item {
    Insn {
        /// Encodings of the mnemonic that can hold the operands, shortest first.
        candidates: Vec<&'static Opcode>,
        operands: Vec<Op>,
    },
    Label(String),
    Raw(Vec<u8>),
}

/// The code of one function, as a list of instructions, labels and raw bytes.
///
/// ```
/// use asc_fixture::abc::{Asm, Op};
///
/// let mut asm = Asm::new();
/// asm.op("lda.str", [Op::str("hello")]).op("jeqz", [Op::label("done")]).op("ldai", [0x1d4b42.into()]);
/// asm.label("done").op("return", []);
/// ```
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Asm {
    items: Vec<Item>,
    catches: Vec<Catch>,
}

/// What [`Asm::assemble`] produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assembled {
    pub bytes: Vec<u8>,
    /// Offset of every label.
    pub labels: HashMap<String, u32>,
}

impl Assembled {
    /// Offset of `label`.
    ///
    /// # Panics
    /// When the code has no such label.
    pub fn label(&self, label: &str) -> u32 {
        *self.labels.get(label).unwrap_or_else(|| panic!("undefined label `{label}`"))
    }
}

impl Asm {
    pub fn new() -> Asm {
        Asm::default()
    }

    /// Append the instruction `mnemonic` (as `asc-arkisa` spells it:
    /// `lda.str`, `callruntime.definefieldbyvalue`, …). Of the encodings
    /// sharing the mnemonic, the shortest one that holds the operands is
    /// used; a jump to a label grows until its offset fits.
    ///
    /// # Panics
    /// When no encoding of `mnemonic` takes these operands.
    pub fn op(&mut self, mnemonic: &str, operands: impl IntoIterator<Item = Op>) -> &mut Asm {
        let operands: Vec<Op> = operands.into_iter().collect();
        let mut candidates: Vec<&'static Opcode> = asc_arkisa::opcodes()
            .filter(|opcode| opcode.name == mnemonic && opcode.operands.len() == operands.len())
            .filter(|opcode| operands.iter().zip(opcode.operands).all(|(operand, field)| operand.fits(field)))
            .collect();
        assert!(!candidates.is_empty(), "no encoding of `{mnemonic}` takes the operands {operands:?}");
        candidates.sort_by_key(|opcode| opcode.len);
        self.items.push(Item::Insn { candidates, operands });
        self
    }

    /// Append an instruction with exactly this encoding, for the variants
    /// [`Asm::op`] would not pick (16-bit inline-cache slots and the like).
    ///
    /// # Panics
    /// When the operands do not fit the encoding.
    pub fn insn(&mut self, opcode: &'static Opcode, operands: impl IntoIterator<Item = Op>) -> &mut Asm {
        let operands: Vec<Op> = operands.into_iter().collect();
        let fits =
            opcode.operands.len() == operands.len() && operands.iter().zip(opcode.operands).all(|(operand, field)| operand.fits(field));
        assert!(fits, "`{}` ({:?} {:#04x}) does not take the operands {operands:?}", opcode.name, opcode.prefix, opcode.value);
        self.items.push(Item::Insn { candidates: vec![opcode], operands });
        self
    }

    /// Define `name` at the current position.
    pub fn label(&mut self, name: &str) -> &mut Asm {
        self.items.push(Item::Label(name.to_owned()));
        self
    }

    /// Append bytes as they are (undefined opcodes, truncated instructions).
    pub fn raw(&mut self, bytes: &[u8]) -> &mut Asm {
        self.items.push(Item::Raw(bytes.to_vec()));
        self
    }

    /// Attach a catch block.
    pub fn catch(&mut self, catch: Catch) -> &mut Asm {
        self.catches.push(catch);
        self
    }

    pub fn catches(&self) -> &[Catch] {
        &self.catches
    }

    /// The operands the builder gives ids to ([`Op::Str`], [`Op::Method`],
    /// [`Op::MethodIn`], [`Op::Literal`]), in code order.
    pub fn symbolic_ids(&self) -> impl Iterator<Item = &Op> {
        self.items
            .iter()
            .filter_map(|item| if let Item::Insn { operands, .. } = item { Some(operands) } else { None })
            .flatten()
            .filter(|operand| operand.is_symbolic_id())
    }

    /// Pick an encoding for every instruction and place the labels.
    fn plan(&self) -> Plan {
        let mut choice = vec![0usize; self.items.len()];
        loop {
            let mut plan =
                Plan { opcodes: Vec::with_capacity(self.items.len()), pcs: Vec::with_capacity(self.items.len()), ..Plan::default() };
            let mut pc = 0usize;
            for (item, &chosen) in self.items.iter().zip(&choice) {
                plan.pcs.push(pc);
                let opcode = match item {
                    Item::Insn { candidates, .. } => {
                        pc += candidates[chosen].byte_len();
                        Some(candidates[chosen])
                    }
                    Item::Label(name) => {
                        let offset = u32::try_from(pc).expect("code offsets fit in 32 bits");
                        assert!(plan.labels.insert(name.clone(), offset).is_none(), "label `{name}` defined twice");
                        None
                    }
                    Item::Raw(bytes) => {
                        pc += bytes.len();
                        None
                    }
                };
                plan.opcodes.push(opcode);
            }
            plan.size = pc;

            // Widen every jump whose offset does not fit its field, then lay out again.
            let mut widened = false;
            for (index, item) in self.items.iter().enumerate() {
                let (Item::Insn { candidates, operands }, Some(opcode)) = (item, plan.opcodes[index]) else { continue };
                let fits = operands.iter().zip(opcode.operands).all(|(operand, field)| match operand {
                    Op::Label(label) => fits_signed(plan.jump_offset(label, plan.pcs[index]), field.width),
                    _ => true,
                });
                if !fits {
                    assert!(
                        choice[index] + 1 < candidates.len(),
                        "`{}` at {:#x}: no encoding reaches its label",
                        opcode.name,
                        plan.pcs[index]
                    );
                    choice[index] += 1;
                    widened = true;
                }
            }
            if !widened {
                return plan;
            }
        }
    }

    /// Size of the assembled code in bytes.
    pub fn size(&self) -> usize {
        self.plan().size
    }

    /// Encode the code. `resolve` supplies the 16-bit id of every symbolic
    /// operand ([`Op::Str`], [`Op::Method`], [`Op::MethodIn`], [`Op::Literal`]).
    ///
    /// # Panics
    /// On a jump to an undefined label or a label defined twice.
    pub fn assemble(&self, mut resolve: impl FnMut(&Op) -> u16) -> Assembled {
        let plan = self.plan();
        let mut bytes = Vec::with_capacity(plan.size);
        for (index, item) in self.items.iter().enumerate() {
            match (item, plan.opcodes[index]) {
                (Item::Insn { operands, .. }, Some(opcode)) => {
                    let start = bytes.len();
                    bytes.extend(opcode.prefix.map(|prefix| prefix.byte()));
                    bytes.push(opcode.value);
                    bytes.resize(start + opcode.byte_len(), 0);
                    for (operand, field) in operands.iter().zip(opcode.operands) {
                        let value = match operand {
                            // Two's complement, cut to the field width by `put_field`.
                            Op::Num(v) => u64::from_le_bytes(v.to_le_bytes()),
                            Op::Float(v) => v.to_bits(),
                            Op::Label(label) => u64::from_le_bytes(plan.jump_offset(label, plan.pcs[index]).to_le_bytes()),
                            Op::Id(id) => u64::from(*id),
                            Op::Str(_) | Op::Method(_) | Op::MethodIn { .. } | Op::Literal(_) => u64::from(resolve(operand)),
                        };
                        put_field(&mut bytes[start..], field, value);
                    }
                }
                (Item::Raw(raw), _) => bytes.extend_from_slice(raw),
                (Item::Label(_) | Item::Insn { .. }, _) => {}
            }
        }
        Assembled { bytes, labels: plan.labels }
    }
}

#[derive(Debug, Default)]
struct Plan {
    /// Parallel to the items: the chosen encoding of an instruction.
    opcodes: Vec<Option<&'static Opcode>>,
    /// Parallel to the items: where each one starts.
    pcs: Vec<usize>,
    labels: HashMap<String, u32>,
    size: usize,
}

impl Plan {
    /// Offset of `label` relative to the instruction at `pc`, which is what
    /// a jump stores.
    fn jump_offset(&self, label: &str, pc: usize) -> i64 {
        let target = *self.labels.get(label).unwrap_or_else(|| panic!("jump to undefined label `{label}`"));
        i64::from(target) - i64::try_from(pc).expect("code offsets fit in 63 bits")
    }
}

/// Store the low `field.width` bits of `value` at the field's bit offset.
/// The inverse of `asc-arkisa`'s operand read: little-endian, with two
/// 4-bit fields sharing a byte, the first in the low nibble.
fn put_field(insn: &mut [u8], field: &Operand, value: u64) {
    let masked = if field.width >= 64 { value } else { value & ((1u64 << field.width) - 1) };
    let shifted = u128::from(masked) << (field.offset % 8);
    let first = usize::from(field.offset / 8);
    let covered = usize::from(field.offset % 8 + field.width).div_ceil(8);
    for (byte, source) in insn[first..first + covered].iter_mut().zip(shifted.to_le_bytes()) {
        *byte |= source;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(asm: &Asm) -> Vec<u8> {
        asm.assemble(|operand| panic!("unexpected symbolic operand {operand:?}")).bytes
    }

    #[test]
    fn encodes_fields_like_the_decoder_reads_them() {
        let mut asm = Asm::new();
        asm.op("mov", [1.into(), 2.into()]).op("ldai", [(-2).into()]).op("fldai", [1.5.into()]);
        asm.op("mov", [0x12.into(), 3.into()]).op("callruntime.definefieldbyvalue", [1.into(), 2.into(), 3.into()]);
        let code = bytes(&asm);
        let mut expected = vec![0x44, 0x21, 0x62, 0xfe, 0xff, 0xff, 0xff, 0x63];
        expected.extend(1.5f64.to_le_bytes());
        expected.extend([0x45, 0x12, 0x03, 0xfb, 0x01, 0x01, 0x02, 0x03]);
        assert_eq!(code, expected);

        let decoded: Vec<Vec<asc_arkisa::Value>> = asc_arkisa::walk(&code).map(|insn| insn.unwrap().operands().collect()).collect();
        assert_eq!(decoded[0], [asc_arkisa::Value::Reg(1), asc_arkisa::Value::Reg(2)]);
        assert_eq!(decoded[1], [asc_arkisa::Value::Imm(-2)]);
        assert_eq!(decoded[2], [asc_arkisa::Value::Float(1.5)]);
    }

    #[test]
    fn symbolic_ids_go_through_the_resolver() {
        let mut asm = Asm::new();
        asm.op("lda.str", [Op::str("a")]).op("definefunc", [0.into(), Op::method("f"), 1.into()]);
        asm.op("createarraywithbuffer", [2.into(), LiteralArrayId(7).into()]).op("lda.str", [Op::Id(0xbeef)]);
        assert_eq!(asm.symbolic_ids().count(), 3);
        let code = asm.assemble(|operand| match operand {
            Op::Str(_) => 0x0102,
            Op::Method(_) => 0x0304,
            Op::Literal(id) => u16::try_from(id.0).unwrap(),
            other => panic!("{other:?}"),
        });
        assert_eq!(code.bytes, [0x3e, 0x02, 0x01, 0x33, 0x00, 0x04, 0x03, 0x01, 0x06, 0x02, 0x07, 0x00, 0x3e, 0xef, 0xbe]);
    }

    #[test]
    fn jumps_take_the_shortest_encoding_that_reaches() {
        let mut asm = Asm::new();
        asm.label("top").op("jeqz", [Op::label("end")]).op("jmp", [Op::label("top")]).label("end").op("returnundefined", []);
        let near = asm.assemble(|_| 0);
        assert_eq!(near.bytes, [0x4f, 0x04, 0x4d, 0xfe, 0x65]);
        assert_eq!((near.label("top"), near.label("end")), (0, 4));

        // 200 bytes in between: the forward jump needs 16 bits, and growing it pushes the backward one over too.
        let mut asm = Asm::new();
        asm.label("top").op("jeqz", [Op::label("end")]);
        for _ in 0..40 {
            asm.op("ldai", [7.into()]);
        }
        asm.op("jmp", [Op::label("top")]).label("end").op("returnundefined", []);
        let far = asm.assemble(|_| 0);
        assert_eq!(far.bytes[..3], [0x50, 0xce, 0x00]);
        assert_eq!(far.bytes[203..], [0x4e, 0x35, 0xff, 0x65]);
        assert_eq!((far.label("end"), asm.size()), (206, 207));
        for insn in asc_arkisa::walk(&far.bytes) {
            let insn = insn.unwrap();
            if let Some(target) = insn.jump_target() {
                assert!(target == 0 || target == 206, "{target}");
            }
        }
    }

    #[test]
    fn exact_encodings_and_raw_bytes() {
        let wide_ic = asc_arkisa::opcode(0x90).unwrap();
        let mut asm = Asm::new();
        asm.insn(wide_ic, [0x1234.into(), Op::Id(5)]).raw(&[0xe2, 0xff]);
        assert_eq!(bytes(&asm), [0x90, 0x34, 0x12, 0x05, 0x00, 0xe2, 0xff]);
    }

    #[test]
    #[should_panic(expected = "no encoding of `lda.str`")]
    fn rejects_operands_of_the_wrong_kind() {
        Asm::new().op("lda.str", [1.into()]);
    }

    #[test]
    #[should_panic(expected = "undefined label `nowhere`")]
    fn rejects_undefined_labels() {
        let mut asm = Asm::new();
        asm.op("jmp", [Op::label("nowhere")]);
        asm.assemble(|_| 0);
    }
}
