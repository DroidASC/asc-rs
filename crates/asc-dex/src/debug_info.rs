//! `debug_info_item` parsing and serialisation.

use crate::leb128::{read_sleb128, read_uleb128, read_uleb128p1, write_sleb128, write_uleb128, write_uleb128p1};
use crate::{DexError, Result};

/// Ends the state machine program.
pub const DBG_END_SEQUENCE: u8 = 0x00;
/// Advances the address register by a uleb128 amount (code units).
pub const DBG_ADVANCE_PC: u8 = 0x01;
/// Advances the line register by an sleb128 amount.
pub const DBG_ADVANCE_LINE: u8 = 0x02;
/// Introduces a local variable (register, name, type).
pub const DBG_START_LOCAL: u8 = 0x03;
/// Introduces a local variable with a generic signature.
pub const DBG_START_LOCAL_EXTENDED: u8 = 0x04;
/// Marks a local variable as out of scope.
pub const DBG_END_LOCAL: u8 = 0x05;
/// Re-introduces a previously ended local variable.
pub const DBG_RESTART_LOCAL: u8 = 0x06;
/// Marks the end of the method prologue.
pub const DBG_SET_PROLOGUE_END: u8 = 0x07;
/// Marks the start of the method epilogue.
pub const DBG_SET_EPILOGUE_BEGIN: u8 = 0x08;
/// Switches the source file name for subsequent entries.
pub const DBG_SET_FILE: u8 = 0x09;
/// First special opcode: higher opcodes advance both line and address and emit a position entry.
pub const DBG_FIRST_SPECIAL: u8 = 0x0a;
/// Smallest line adjustment a special opcode can encode.
pub const DBG_LINE_BASE: i32 = -4;
/// Number of distinct line adjustments a special opcode can encode.
pub const DBG_LINE_RANGE: u32 = 15;

/// One decoded instruction of the debug info state machine. String and type
/// operands are indexes into `string_ids` / `type_ids`, `None` for `NO_INDEX`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebugOp {
    /// `DBG_END_SEQUENCE`.
    EndSequence,
    /// `DBG_ADVANCE_PC`: address delta in code units.
    AdvancePc(u32),
    /// `DBG_ADVANCE_LINE`: line delta.
    AdvanceLine(i32),
    /// `DBG_START_LOCAL`.
    StartLocal {
        /// Register holding the local.
        reg: u32,
        /// Name, as a string index.
        name: Option<u32>,
        /// Type, as a type index.
        type_: Option<u32>,
    },
    /// `DBG_START_LOCAL_EXTENDED`.
    StartLocalExtended {
        /// Register holding the local.
        reg: u32,
        /// Name, as a string index.
        name: Option<u32>,
        /// Type, as a type index.
        type_: Option<u32>,
        /// Generic signature, as a string index.
        sig: Option<u32>,
    },
    /// `DBG_END_LOCAL`: the register whose local ends.
    EndLocal(u32),
    /// `DBG_RESTART_LOCAL`: the register whose local restarts.
    RestartLocal(u32),
    /// `DBG_SET_PROLOGUE_END`.
    SetPrologueEnd,
    /// `DBG_SET_EPILOGUE_BEGIN`.
    SetEpilogueBegin,
    /// `DBG_SET_FILE`: source file name, as a string index.
    SetFile(Option<u32>),
    /// A special opcode (`>= DBG_FIRST_SPECIAL`), kept raw.
    Special(u8),
}

/// Parsed `debug_info_item`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DebugInfo {
    /// `line_start`: initial value of the line register.
    pub line_start: u32,
    /// Parameter name string indexes (`None` for unnamed parameters).
    pub parameter_names: Vec<Option<u32>>,
    /// The state machine program, ending with [`DebugOp::EndSequence`].
    pub ops: Vec<DebugOp>,
}

impl DebugInfo {
    /// Parse the `debug_info_item` at `off`. Returns the item and its length in bytes.
    ///
    /// # Errors
    ///
    /// `Truncated` when the item runs past the end of `buf` before
    /// `DBG_END_SEQUENCE`.
    pub fn parse(buf: &[u8], off: usize) -> Result<(DebugInfo, usize)> {
        let (line_start, n) = read_uleb128(buf, off)?;
        let mut p = off + n;
        let (count, n) = read_uleb128(buf, p)?;
        p += n;
        let mut parameter_names = Vec::with_capacity(count.min(64) as usize);
        for _ in 0..count {
            let (v, n) = read_uleb128p1(buf, p)?;
            p += n;
            parameter_names.push(v);
        }
        let mut ops = Vec::new();
        loop {
            let op = *buf.get(p).ok_or(DexError::Truncated { what: "debug_info", offset: p })?;
            p += 1;
            let dop = match op {
                DBG_END_SEQUENCE => {
                    ops.push(DebugOp::EndSequence);
                    break;
                }
                DBG_ADVANCE_PC => {
                    let (v, n) = read_uleb128(buf, p)?;
                    p += n;
                    DebugOp::AdvancePc(v)
                }
                DBG_ADVANCE_LINE => {
                    let (v, n) = read_sleb128(buf, p)?;
                    p += n;
                    DebugOp::AdvanceLine(v)
                }
                DBG_START_LOCAL => {
                    let (reg, n) = read_uleb128(buf, p)?;
                    p += n;
                    let (name, n) = read_uleb128p1(buf, p)?;
                    p += n;
                    let (type_, n) = read_uleb128p1(buf, p)?;
                    p += n;
                    DebugOp::StartLocal { reg, name, type_ }
                }
                DBG_START_LOCAL_EXTENDED => {
                    let (reg, n) = read_uleb128(buf, p)?;
                    p += n;
                    let (name, n) = read_uleb128p1(buf, p)?;
                    p += n;
                    let (type_, n) = read_uleb128p1(buf, p)?;
                    p += n;
                    let (sig, n) = read_uleb128p1(buf, p)?;
                    p += n;
                    DebugOp::StartLocalExtended { reg, name, type_, sig }
                }
                DBG_END_LOCAL => {
                    let (reg, n) = read_uleb128(buf, p)?;
                    p += n;
                    DebugOp::EndLocal(reg)
                }
                DBG_RESTART_LOCAL => {
                    let (reg, n) = read_uleb128(buf, p)?;
                    p += n;
                    DebugOp::RestartLocal(reg)
                }
                DBG_SET_PROLOGUE_END => DebugOp::SetPrologueEnd,
                DBG_SET_EPILOGUE_BEGIN => DebugOp::SetEpilogueBegin,
                DBG_SET_FILE => {
                    let (name, n) = read_uleb128p1(buf, p)?;
                    p += n;
                    DebugOp::SetFile(name)
                }
                _ => DebugOp::Special(op),
            };
            ops.push(dop);
        }
        Ok((DebugInfo { line_start, parameter_names, ops }, p - off))
    }

    /// Serialise with remapped string/type indexes.
    pub fn write(&self, out: &mut Vec<u8>, map_string: &dyn Fn(u32) -> u32, map_type: &dyn Fn(u32) -> u32) {
        write_uleb128(out, self.line_start);
        write_uleb128(out, self.parameter_names.len() as u32);
        for name in &self.parameter_names {
            write_uleb128p1(out, name.map(map_string));
        }
        let mut ended = false;
        for op in &self.ops {
            match op {
                DebugOp::EndSequence => {
                    out.push(DBG_END_SEQUENCE);
                    ended = true;
                    break;
                }
                DebugOp::AdvancePc(v) => {
                    out.push(DBG_ADVANCE_PC);
                    write_uleb128(out, *v);
                }
                DebugOp::AdvanceLine(v) => {
                    out.push(DBG_ADVANCE_LINE);
                    write_sleb128(out, *v);
                }
                DebugOp::StartLocal { reg, name, type_ } => {
                    out.push(DBG_START_LOCAL);
                    write_uleb128(out, *reg);
                    write_uleb128p1(out, name.map(map_string));
                    write_uleb128p1(out, type_.map(map_type));
                }
                DebugOp::StartLocalExtended { reg, name, type_, sig } => {
                    out.push(DBG_START_LOCAL_EXTENDED);
                    write_uleb128(out, *reg);
                    write_uleb128p1(out, name.map(map_string));
                    write_uleb128p1(out, type_.map(map_type));
                    write_uleb128p1(out, sig.map(map_string));
                }
                DebugOp::EndLocal(reg) => {
                    out.push(DBG_END_LOCAL);
                    write_uleb128(out, *reg);
                }
                DebugOp::RestartLocal(reg) => {
                    out.push(DBG_RESTART_LOCAL);
                    write_uleb128(out, *reg);
                }
                DebugOp::SetPrologueEnd => out.push(DBG_SET_PROLOGUE_END),
                DebugOp::SetEpilogueBegin => out.push(DBG_SET_EPILOGUE_BEGIN),
                DebugOp::SetFile(name) => {
                    out.push(DBG_SET_FILE);
                    write_uleb128p1(out, name.map(map_string));
                }
                DebugOp::Special(op) => out.push(*op),
            }
        }
        if !ended {
            out.push(DBG_END_SEQUENCE);
        }
    }

    /// Visit every referenced string and type index.
    pub fn visit_refs(&self, strings: &mut dyn FnMut(u32), types: &mut dyn FnMut(u32)) {
        for name in self.parameter_names.iter().flatten() {
            strings(*name);
        }
        for op in &self.ops {
            match op {
                DebugOp::StartLocal { name, type_, .. } => {
                    if let Some(n) = name {
                        strings(*n);
                    }
                    if let Some(t) = type_ {
                        types(*t);
                    }
                }
                DebugOp::StartLocalExtended { name, type_, sig, .. } => {
                    if let Some(n) = name {
                        strings(*n);
                    }
                    if let Some(t) = type_ {
                        types(*t);
                    }
                    if let Some(s) = sig {
                        strings(*s);
                    }
                }
                DebugOp::SetFile(Some(n)) => strings(*n),
                _ => {}
            }
        }
    }

    /// Run the debug state machine and return `(address, line)` position
    /// entries in emission order.
    pub fn positions(&self) -> Vec<(u32, u32)> {
        let mut addr: u32 = 0;
        let mut line: i64 = self.line_start as i64;
        let mut out = Vec::new();
        for op in &self.ops {
            match op {
                DebugOp::EndSequence => break,
                DebugOp::AdvancePc(v) => addr = addr.wrapping_add(*v),
                DebugOp::AdvanceLine(v) => line += *v as i64,
                DebugOp::Special(op) => {
                    let adjusted = (*op - DBG_FIRST_SPECIAL) as u32;
                    line += DBG_LINE_BASE as i64 + (adjusted % DBG_LINE_RANGE) as i64;
                    addr = addr.wrapping_add(adjusted / DBG_LINE_RANGE);
                    out.push((addr, line.max(0) as u32));
                }
                _ => {}
            }
        }
        out
    }
}
