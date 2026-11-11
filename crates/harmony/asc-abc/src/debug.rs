//! Debug info: the first source line of a method, parameter names, and the
//! line number program (a DWARF-style state machine whose constants live in
//! a per-method constant pool so that programs can be shared).

use crate::reader::{Reader, entity_pos};
use crate::{Abc, AbcError, Result};

/// A `DebugInfo` item.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct DebugInfo<'a> {
    abc: Abc<'a>,
    off: u32,
    /// Initial value of the line register: the source line of the method's
    /// first instruction.
    pub line_start: u32,
    /// `num_params`: number of entries in [`DebugInfo::params`].
    pub num_params: u32,
    params_pos: usize,
    constant_pool: &'a [u8],
    constant_pool_pos: usize,
    /// Index into the file's line number program index.
    pub line_program_idx: u32,
}

impl<'a> DebugInfo<'a> {
    pub(crate) fn parse(abc: Abc<'a>, off: u32) -> Result<DebugInfo<'a>> {
        let buf = abc.bytes();
        let mut r = Reader::new(buf, entity_pos(buf, off, "debug info")?);
        let (line_start, num_params) = (r.uleb()?, r.uleb()?);
        let params_pos = r.pos();
        for _ in 0..num_params {
            r.uleb()?;
        }
        let pool_size = r.uleb()? as usize;
        let constant_pool_pos = r.pos();
        let constant_pool = r.take(pool_size, "debug constant pool")?;
        let line_program_idx = r.uleb()?;
        Ok(DebugInfo { abc, off, line_start, num_params, params_pos, constant_pool, constant_pool_pos, line_program_idx })
    }

    /// File offset of the debug info item.
    #[inline]
    pub fn offset(&self) -> u32 {
        self.off
    }

    /// String offsets of the parameter names; `0` for a nameless parameter.
    /// The list was validated when the item was parsed.
    pub fn params(&self) -> impl Iterator<Item = u32> + 'a + use<'a> {
        let mut r = Reader::new(self.abc.bytes(), self.params_pos);
        (0..self.num_params).map_while(move |_| r.uleb().ok())
    }

    /// The raw constant pool (uleb128 / sleb128 values consumed in order by
    /// the line number program).
    #[inline]
    pub fn constant_pool(&self) -> &'a [u8] {
        self.constant_pool
    }

    /// File offset of the line number program.
    ///
    /// # Errors
    /// `IndexOutOfRange` when `line_program_idx` is outside the file's index.
    pub fn line_program_off(&self) -> Result<u32> {
        let index = self.abc.line_program_index()?;
        index.get(self.line_program_idx).ok_or(AbcError::IndexOutOfRange {
            what: "line number program index",
            index: self.line_program_idx,
            size: index.len(),
        })
    }

    /// The decoded operations of the line number program.
    ///
    /// # Errors
    /// A bad line number program index or offset.
    pub fn line_ops(&self) -> Result<LineOps<'a>> {
        let buf = self.abc.bytes();
        let program = Reader::new(buf, entity_pos(buf, self.line_program_off()?, "line number program")?);
        // The pool reader is confined to the pool: a program asking for more
        // constants than the method provides must fail, not read on.
        let pool_end = self.constant_pool_pos + self.constant_pool.len();
        Ok(LineOps { program, pool: Reader::new(buf.get(..pool_end).unwrap_or(buf), self.constant_pool_pos), done: false })
    }

    /// The source line of the method's first instruction that has one:
    /// `line_start` when it is a real line, otherwise the first line table
    /// row that is. Compiler-generated instructions carry line `-1`, and
    /// methods often start with some. Lines are as the compiler stored
    /// them; `None` when the method has no real line at all.
    ///
    /// # Errors
    /// A malformed line number program.
    pub fn first_line(&self) -> Result<Option<u32>> {
        let is_real = |line: u32| i32::try_from(line).is_ok();
        if is_real(self.line_start) {
            return Ok(Some(self.line_start));
        }
        for row in self.line_rows()? {
            let row = row?;
            if is_real(row.line) {
                return Ok(Some(row.line));
            }
        }
        Ok(None)
    }

    /// The line table: one row per special opcode, i.e. per point where the
    /// program emits a line.
    ///
    /// # Errors
    /// A bad line number program index or offset.
    pub fn line_rows(&self) -> Result<LineRows<'a>> {
        Ok(LineRows { ops: self.line_ops()?, pc: 0, line: self.line_start, column: 0 })
    }

    /// The local variables the line number program declares, in the order
    /// it starts them. The parameters are not among them: their names are
    /// [`DebugInfo::params`].
    ///
    /// An `END_LOCAL` closes the latest variable of its register, a
    /// `RESTART_LOCAL` starts that variable anew; either is ignored when the
    /// register never had a variable.
    ///
    /// # Errors
    /// A malformed line number program.
    pub fn locals(&self) -> Result<Vec<LocalVar>> {
        let mut locals: Vec<LocalVar> = Vec::new();
        let mut pc = 0u32;
        for op in self.line_ops()? {
            match op? {
                LineOp::AdvancePc(delta) => pc = pc.wrapping_add(delta),
                LineOp::Special { pc_delta, .. } => pc = pc.wrapping_add(pc_delta),
                LineOp::StartLocal { reg, name_off, type_off } => {
                    locals.push(LocalVar { reg, name_off, type_off, signature_off: None, start_pc: pc, end_pc: None });
                }
                LineOp::StartLocalExtended { reg, name_off, type_off, signature_off } => {
                    locals.push(LocalVar { reg, name_off, type_off, signature_off: Some(signature_off), start_pc: pc, end_pc: None });
                }
                LineOp::EndLocal { reg } => {
                    if let Some(local) = locals.iter_mut().rfind(|local| local.reg == reg) {
                        local.end_pc = Some(pc);
                    }
                }
                LineOp::RestartLocal { reg } => {
                    if let Some(&local) = locals.iter().rfind(|local| local.reg == reg) {
                        locals.push(LocalVar { start_pc: pc, end_pc: None, ..local });
                    }
                }
                LineOp::AdvanceLine(_)
                | LineOp::SetPrologueEnd
                | LineOp::SetEpilogueBegin
                | LineOp::SetFile(_)
                | LineOp::SetSourceCode(_)
                | LineOp::SetColumn(_) => {}
            }
        }
        Ok(locals)
    }
}

/// A local variable: the code range in which a register holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LocalVar {
    /// The register; `-1` is the accumulator. Registers at or above the
    /// code item's `num_vregs` are arguments.
    pub reg: i32,
    /// String offset of the name.
    pub name_off: u32,
    /// String offset of the type descriptor.
    pub type_off: u32,
    /// String offset of the type signature, when the variable was started
    /// with one (`START_LOCAL_EXTENDED`).
    pub signature_off: Option<u32>,
    /// Code offset from which the register holds the variable.
    pub start_pc: u32,
    /// Code offset at which it stops doing so; `None` when the program never
    /// ends the variable, which then lives to the end of the code.
    pub end_pc: Option<u32>,
}

/// One operation of a line number program, with its constant pool
/// arguments already fetched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineOp {
    /// `ADVANCE_PC` (0x01): add the argument to the pc register.
    AdvancePc(u32),
    /// `ADVANCE_LINE` (0x02): add the argument to the line register.
    AdvanceLine(i32),
    /// A local variable comes into scope in register `reg` (`-1`: the
    /// accumulator); name and type are string offsets.
    StartLocal {
        /// Register; `-1` is the accumulator.
        reg: i32,
        /// String offset of the variable name.
        name_off: u32,
        /// String offset of the type descriptor.
        type_off: u32,
    },
    /// `START_LOCAL_EXTENDED` (0x04): [`LineOp::StartLocal`] with a type signature.
    StartLocalExtended {
        /// Register; `-1` is the accumulator.
        reg: i32,
        /// String offset of the variable name.
        name_off: u32,
        /// String offset of the type descriptor.
        type_off: u32,
        /// String offset of the type signature.
        signature_off: u32,
    },
    /// `END_LOCAL` (0x05): the variable in `reg` goes out of scope.
    EndLocal {
        /// Register; `-1` is the accumulator.
        reg: i32,
    },
    /// `RESTART_LOCAL` (0x06): the variable last ended in `reg` comes back into scope.
    RestartLocal {
        /// Register; `-1` is the accumulator.
        reg: i32,
    },
    /// `SET_PROLOGUE_END` (0x07): the next row is where the method body starts.
    SetPrologueEnd,
    /// `SET_EPILOGUE_BEGIN` (0x08): the next row is where the epilogue starts.
    SetEpilogueBegin,
    /// String offset of the source file name, or 0.
    SetFile(u32),
    /// String offset of the source code, or 0.
    SetSourceCode(u32),
    /// The column register is 32 bits wide; `u32::MAX` is the compiler's
    /// `-1`, "no column".
    SetColumn(u32),
    /// A special opcode: advance pc and line, then emit a row.
    Special {
        /// Added to the pc register, in bytes.
        pc_delta: u32,
        /// Added to the line register.
        line_delta: i32,
    },
}

/// Iterator over the operations of a line number program, up to its
/// `END_SEQUENCE`.
#[derive(Debug, Clone)]
pub struct LineOps<'a> {
    program: Reader<'a>,
    pool: Reader<'a>,
    done: bool,
}

impl LineOps<'_> {
    const OPCODE_BASE: u8 = 0x0c;
    const LINE_BASE: i32 = -4;
    const LINE_RANGE: u8 = 15;

    fn read(&mut self) -> Result<Option<LineOp>> {
        let (program, pool) = (&mut self.program, &mut self.pool);
        Ok(Some(match program.u8()? {
            0x00 => return Ok(None),
            0x01 => LineOp::AdvancePc(pool.uleb()?),
            0x02 => LineOp::AdvanceLine(pool.sleb()?),
            0x03 => LineOp::StartLocal { reg: program.sleb()?, name_off: pool.uleb()?, type_off: pool.uleb()? },
            0x04 => LineOp::StartLocalExtended {
                reg: program.sleb()?,
                name_off: pool.uleb()?,
                type_off: pool.uleb()?,
                signature_off: pool.uleb()?,
            },
            0x05 => LineOp::EndLocal { reg: program.sleb()? },
            0x06 => LineOp::RestartLocal { reg: program.sleb()? },
            0x07 => LineOp::SetPrologueEnd,
            0x08 => LineOp::SetEpilogueBegin,
            0x09 => LineOp::SetFile(pool.uleb()?),
            0x0a => LineOp::SetSourceCode(pool.uleb()?),
            0x0b => LineOp::SetColumn(pool.uleb()?),
            opcode => {
                let adjusted = opcode - Self::OPCODE_BASE;
                LineOp::Special {
                    pc_delta: u32::from(adjusted / Self::LINE_RANGE),
                    line_delta: i32::from(adjusted % Self::LINE_RANGE) + Self::LINE_BASE,
                }
            }
        }))
    }
}

impl Iterator for LineOps<'_> {
    type Item = Result<LineOp>;

    fn next(&mut self) -> Option<Result<LineOp>> {
        if self.done {
            return None;
        }
        let op = self.read().transpose();
        self.done = !matches!(op, Some(Ok(_)));
        op
    }
}

/// A row of the line table: instructions from `pc` on belong to `line`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineRow {
    /// Code offset of the first instruction of the row.
    pub pc: u32,
    /// Source line, as the line register holds it.
    pub line: u32,
    /// The last column set before this row; 0 when the program sets none.
    pub column: u32,
}

/// Iterator running the line number state machine.
#[derive(Debug, Clone)]
pub struct LineRows<'a> {
    ops: LineOps<'a>,
    pc: u32,
    line: u32,
    column: u32,
}

impl Iterator for LineRows<'_> {
    type Item = Result<LineRow>;

    fn next(&mut self) -> Option<Result<LineRow>> {
        loop {
            // Registers wrap like the runtime's unsigned arithmetic does.
            match self.ops.next()? {
                Err(err) => return Some(Err(err)),
                Ok(LineOp::AdvancePc(delta)) => self.pc = self.pc.wrapping_add(delta),
                Ok(LineOp::AdvanceLine(delta)) => self.line = self.line.wrapping_add_signed(delta),
                Ok(LineOp::SetColumn(column)) => self.column = column,
                Ok(LineOp::Special { pc_delta, line_delta }) => {
                    self.pc = self.pc.wrapping_add(pc_delta);
                    self.line = self.line.wrapping_add_signed(line_delta);
                    return Some(Ok(LineRow { pc: self.pc, line: self.line, column: self.column }));
                }
                Ok(
                    LineOp::StartLocal { .. }
                    | LineOp::StartLocalExtended { .. }
                    | LineOp::EndLocal { .. }
                    | LineOp::RestartLocal { .. }
                    | LineOp::SetPrologueEnd
                    | LineOp::SetEpilogueBegin
                    | LineOp::SetFile(_)
                    | LineOp::SetSourceCode(_),
                ) => {}
            }
        }
    }
}
