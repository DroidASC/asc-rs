//! Debug info: the first source line of a method, parameter names, and the
//! line number program (a DWARF-style state machine whose constants live in
//! a per-method constant pool so that programs can be shared).

use crate::reader::{entity_pos, Reader};
use crate::{Abc, AbcError, Result};

/// A `DebugInfo` item.
#[derive(Debug, Clone, Copy)]
pub struct DebugInfo<'a> {
    abc: Abc<'a>,
    off: u32,
    /// Initial value of the line register: the source line of the method's
    /// first instruction.
    pub line_start: u32,
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

    #[inline]
    pub fn offset(&self) -> u32 {
        self.off
    }

    /// String offsets of the parameter names; `0` for a nameless parameter.
    /// The list was validated when the item was parsed.
    pub fn params(&self) -> impl Iterator<Item = u32> + 'a {
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
}

/// One operation of a line number program, with its constant pool
/// arguments already fetched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineOp {
    AdvancePc(u32),
    AdvanceLine(i32),
    /// A local variable comes into scope in register `reg` (`-1`: the
    /// accumulator); name and type are string offsets.
    StartLocal {
        reg: i32,
        name_off: u32,
        type_off: u32,
    },
    StartLocalExtended {
        reg: i32,
        name_off: u32,
        type_off: u32,
        signature_off: u32,
    },
    EndLocal {
        reg: i32,
    },
    RestartLocal {
        reg: i32,
    },
    SetPrologueEnd,
    SetEpilogueBegin,
    /// String offset of the source file name, or 0.
    SetFile(u32),
    /// String offset of the source code, or 0.
    SetSourceCode(u32),
    SetColumn(u32),
    /// A special opcode: advance pc and line, then emit a row.
    Special {
        pc_delta: u32,
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
    pub pc: u32,
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
