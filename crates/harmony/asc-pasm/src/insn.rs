//! One instruction as text: mnemonic, operands in `isa.yaml` order with ids
//! resolved, then `;` notes (restored function name, module binding,
//! register range).

use std::fmt::{self, Write};

use asc_abc::{Abc, AbcError, Method, Region};
use asc_arkisa::{Instruction, OperandKind, Value};

use crate::literal::{method_name, write_literal_array};
use crate::module::{ModuleOperand, ModuleText};
use crate::record::RecordInfo;
use crate::text::{write_error, write_f64, write_i32, write_imm, write_name, write_quoted};
use crate::Options;

/// Width in bits of the ids of the `deprecated.*` opcodes that predate the
/// 16-bit region index.
const WIDE_ID_BITS: u8 = 32;

/// Writes the label a branch to code offset `pc` refers to. The name is the
/// offset itself, as it appears in the listing's offset column, so a lone
/// instruction and a full listing agree without a pass over the code.
pub(crate) fn write_label<W: Write>(out: &mut W, pc: usize) -> fmt::Result {
    write!(out, "L_{pc:04x}")
}

/// Renders the instructions of one method. Everything that is the same for
/// the whole method (its region, its register count, its record) is looked
/// up once, here.
pub(crate) struct InsnPrinter<'r, 'a> {
    abc: &'r Abc<'a>,
    opts: &'r Options,
    record: &'r RecordInfo<'a>,
    region: Result<Region<'a>, AbcError>,
    /// Registers from this number on are arguments; `None` when the method
    /// has no readable code item to say.
    num_vregs: Option<u32>,
}

impl<'r, 'a> InsnPrinter<'r, 'a> {
    pub(crate) fn new(
        abc: &'r Abc<'a>,
        method: &Method<'a>,
        record: &'r RecordInfo<'a>,
        num_vregs: Option<u32>,
        opts: &'r Options,
    ) -> InsnPrinter<'r, 'a> {
        InsnPrinter { abc, opts, record, region: method.region(), num_vregs }
    }

    /// `v3` for a local register, `a0` for an argument (as pandasm does).
    fn write_reg<W: Write>(&self, out: &mut W, reg: u32) -> fmt::Result {
        match self.num_vregs.and_then(|vregs| reg.checked_sub(vregs)) {
            Some(arg) => write!(out, "a{arg}"),
            None => write!(out, "v{reg}"),
        }
    }

    /// File offset of the entity an id operand names.
    fn resolve(&self, id: u32, width: u8) -> Result<u32, AbcError> {
        match u16::try_from(id) {
            Ok(idx) => self.region.clone()?.entity_offset(idx),
            // Too large for an index: the 32-bit ids of old files can hold a file offset.
            Err(_) if width == WIDE_ID_BITS => Ok(id),
            Err(_) => Err(AbcError::IndexOutOfRange { what: "region method index", index: id, size: u32::from(u16::MAX) + 1 }),
        }
    }

    fn write_string<W: Write>(&self, out: &mut W, id: u32, width: u8) -> fmt::Result {
        match self.resolve(id, width).and_then(|off| self.abc.string(off)) {
            Ok(string) => write_quoted(out, &string.to_str(), self.opts.string_limit),
            Err(error) => write_error(out, format_args!("string id {id:#x}: {error}")),
        }
    }

    /// Writes the raw name of the method and returns its offset for the
    /// restored-name note.
    fn write_method<W: Write>(&self, out: &mut W, id: u32, width: u8) -> Result<Option<u32>, fmt::Error> {
        match self.resolve(id, width).and_then(|off| Ok((off, method_name(self.abc, off)?))) {
            Ok((off, name)) => write_name(out, &name).map(|()| Some(off)),
            Err(error) => write_error(out, format_args!("method id {id:#x}: {error}")).map(|()| None),
        }
    }

    fn write_literal_array<W: Write>(&self, out: &mut W, id: u32, width: u8) -> fmt::Result {
        match self.resolve(id, width) {
            Ok(off) => write_literal_array(out, self.abc, off, self.opts),
            Err(error) => write_error(out, format_args!("literal array id {id:#x}: {error}")),
        }
    }

    /// Write `insn` without offset or line break.
    pub(crate) fn write<W: Write>(&self, out: &mut W, insn: &Instruction<'_>) -> fmt::Result {
        let opcode = insn.opcode;
        out.write_str(opcode.name)?;

        let mut separator = " ";
        let mut defined_method = None;
        let mut module_index = None;
        for (field, value) in opcode.operands.iter().zip(insn.operands()) {
            if field.kind == OperandKind::IcSlot && !self.opts.ic_slots {
                continue;
            }
            out.write_str(separator)?;
            separator = ", ";
            match value {
                Value::Reg(reg) => self.write_reg(out, u32::from(reg))?,
                Value::Imm(imm) => {
                    module_index = module_index.or(usize::try_from(imm).ok());
                    match i32::try_from(imm) {
                        Ok(int) if field.kind == OperandKind::ImmSigned => write_i32(out, int)?,
                        Ok(_) | Err(_) => write_imm(out, imm)?,
                    }
                }
                Value::Float(float) => write_f64(out, float)?,
                Value::IcSlot(slot) => write!(out, "{slot:#x}")?,
                Value::JumpOffset(offset) => match insn.jump_target() {
                    Some(target) => write_label(out, target)?,
                    None => write_error(out, format_args!("jump by {offset} to before the code"))?,
                },
                Value::StringId(id) => self.write_string(out, id, field.width)?,
                Value::MethodId(id) => defined_method = self.write_method(out, id, field.width)?,
                Value::LiteralArrayId(id) => self.write_literal_array(out, id, field.width)?,
            }
        }

        let mut notes = Notes::default();
        if let Some(restored) = defined_method.and_then(|off| self.record.restored_method_name(self.abc, off)) {
            notes.begin(out)?;
            write_name(out, &restored)?;
        }
        if let (Some(operand), Some(index)) = (ModuleOperand::of(opcode), module_index) {
            notes.begin(out)?;
            match &self.record.module {
                Ok(Some(module)) => ModuleText { abc: self.abc, module }.write_operand(out, operand, index)?,
                Ok(None) => write_error(out, "the record has no module record")?,
                Err(error) => write_error(out, format_args!("module record: {error}"))?,
            }
        }
        if let Some(range) = insn.reg_range().filter(|range| range.count > 1) {
            notes.begin(out)?;
            let first = u32::from(range.first);
            self.write_reg(out, first)?;
            out.write_str("..")?;
            self.write_reg(out, first.saturating_add(range.count - 1))?;
        }
        Ok(())
    }
}

/// The `;` notes after an instruction: the first one opens the comment,
/// later ones are separated from it.
#[derive(Default)]
struct Notes {
    begun: bool,
}

impl Notes {
    fn begin<W: Write>(&mut self, out: &mut W) -> fmt::Result {
        out.write_str(if self.begun { "; " } else { "  ; " })?;
        self.begun = true;
        Ok(())
    }
}
