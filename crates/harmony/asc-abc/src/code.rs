//! Code items: register counts, the instruction bytes and the try blocks.
//! Instructions are handed out raw; decoding them is `asc-arkisa`'s job.

use crate::Result;
use crate::reader::{Reader, entity_pos, file_off};

/// A `Code` item.
#[derive(Debug, Clone, Copy)]
pub struct Code<'a> {
    buf: &'a [u8],
    off: u32,
    /// Number of registers, not counting arguments.
    pub num_vregs: u32,
    pub num_args: u32,
    /// Number of try blocks.
    pub tries_size: u32,
    insns: &'a [u8],
    insns_pos: usize,
}

impl<'a> Code<'a> {
    pub(crate) fn parse(buf: &'a [u8], off: u32) -> Result<Code<'a>> {
        let mut r = Reader::new(buf, entity_pos(buf, off, "code")?);
        let (num_vregs, num_args, code_size, tries_size) = (r.uleb()?, r.uleb()?, r.uleb()?, r.uleb()?);
        let insns_pos = r.pos();
        let insns = r.take(code_size as usize, "instructions")?;
        Ok(Code { buf, off, num_vregs, num_args, tries_size, insns, insns_pos })
    }

    #[inline]
    pub fn offset(&self) -> u32 {
        self.off
    }

    /// The instruction bytes (`code_size` of them).
    #[inline]
    pub fn instructions(&self) -> &'a [u8] {
        self.insns
    }

    /// File offset of the first instruction.
    #[inline]
    pub fn instructions_off(&self) -> u32 {
        file_off(self.insns_pos)
    }

    /// The try blocks, in file order.
    pub fn try_blocks(&self) -> TryBlocks<'a> {
        TryBlocks { r: Reader::new(self.buf, self.insns_pos + self.insns.len()), remaining: self.tries_size }
    }
}

/// Iterator over the try blocks of a code item.
#[derive(Debug, Clone)]
pub struct TryBlocks<'a> {
    r: Reader<'a>,
    remaining: u32,
}

impl<'a> Iterator for TryBlocks<'a> {
    type Item = Result<TryBlock<'a>>;

    fn next(&mut self) -> Option<Result<TryBlock<'a>>> {
        if self.remaining == 0 {
            return None;
        }
        let block = TryBlock::read(&mut self.r);
        self.remaining = if block.is_ok() { self.remaining - 1 } else { 0 };
        Some(block)
    }
}

/// A try block: the pc range `[start_pc, start_pc + length)` and its
/// handlers.
#[derive(Debug, Clone, Copy)]
pub struct TryBlock<'a> {
    pub start_pc: u32,
    /// Length of the covered range in bytes.
    pub length: u32,
    pub num_catches: u32,
    catches: Reader<'a>,
}

impl<'a> TryBlock<'a> {
    /// Read a try block and move `r` past its catch blocks.
    fn read(r: &mut Reader<'a>) -> Result<TryBlock<'a>> {
        let (start_pc, length, num_catches) = (r.uleb()?, r.uleb()?, r.uleb()?);
        let block = TryBlock { start_pc, length, num_catches, catches: *r };
        for _ in 0..num_catches {
            CatchBlock::read(r)?;
        }
        Ok(block)
    }

    /// The catch blocks, in the order the runtime tries them. They were
    /// validated when the try block was read, so this cannot fail.
    pub fn catch_blocks(&self) -> impl Iterator<Item = CatchBlock> + 'a + use<'a> {
        let mut r = self.catches;
        (0..self.num_catches).map_while(move |_| CatchBlock::read(&mut r).ok())
    }
}

/// A catch block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CatchBlock {
    /// Index of the exception type in the region's class table; `None`
    /// catches everything (the file stores the index plus one).
    pub type_idx: Option<u32>,
    pub handler_pc: u32,
    /// Size of the handler in bytes.
    pub code_size: u32,
}

impl CatchBlock {
    fn read(r: &mut Reader<'_>) -> Result<CatchBlock> {
        Ok(CatchBlock { type_idx: r.uleb()?.checked_sub(1), handler_pc: r.uleb()?, code_size: r.uleb()? })
    }
}
