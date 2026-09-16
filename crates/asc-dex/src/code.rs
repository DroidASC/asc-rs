//! `code_item` parsing including tries and encoded catch handlers.

use crate::leb128::{read_sleb128, read_uleb128};
use crate::{u16_at, u32_at, DexError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TryItem {
    pub start_addr: u32,
    pub insn_count: u16,
    /// Byte offset of the handler inside the `encoded_catch_handler_list`.
    pub handler_off: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatchHandler {
    /// Byte offset of this handler inside the `encoded_catch_handler_list`.
    pub offset: u16,
    /// `(type_idx, handler_addr)` pairs.
    pub catches: Vec<(u32, u32)>,
    pub catch_all_addr: Option<u32>,
}

/// Parsed `code_item`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeItem<'a> {
    pub offset: usize,
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub tries_size: u16,
    pub debug_info_off: u32,
    /// Instruction bytes (`insns_size * 2`).
    pub insns: &'a [u8],
    pub tries: Vec<TryItem>,
    pub handlers: Vec<CatchHandler>,
    /// Offset just past the item.
    pub end: usize,
}

/// Upper bound for up-front reservations driven by counts read from the file.
const MAX_RESERVE: usize = 4096;

impl<'a> CodeItem<'a> {
    pub const HEADER_SIZE: usize = 16;

    pub fn parse(buf: &'a [u8], off: usize) -> Result<CodeItem<'a>> {
        let registers_size = u16_at(buf, off)?;
        let ins_size = u16_at(buf, off + 2)?;
        let outs_size = u16_at(buf, off + 4)?;
        let tries_size = u16_at(buf, off + 6)?;
        let debug_info_off = u32_at(buf, off + 8)?;
        let insns_size = u32_at(buf, off + 12)? as usize;
        let insn_start = off + Self::HEADER_SIZE;
        // `insns_size * 2` is bounded against the buffer before any slicing
        // (and computed with checked arithmetic for 32-bit targets).
        let insns = insns_size
            .checked_mul(2)
            .and_then(|len| insn_start.checked_add(len))
            .and_then(|end| buf.get(insn_start..end))
            .ok_or(DexError::BadRange { what: "code_item.insns", offset: off })?;
        let insn_end = insn_start + insns.len();
        let mut p = insn_end;
        let mut tries = Vec::new();
        let mut handlers = Vec::new();
        if tries_size > 0 {
            if p & 3 != 0 {
                p += 2; // padding when insns_size is odd
            }
            // Every try_item is 8 bytes: the table must fit in the buffer.
            let tries_len = tries_size as usize * 8;
            if p.checked_add(tries_len).is_none_or(|end| end > buf.len()) {
                return Err(DexError::BadRange { what: "code_item.tries", offset: p });
            }
            tries.reserve(tries_size as usize);
            for _ in 0..tries_size {
                tries.push(TryItem { start_addr: u32_at(buf, p)?, insn_count: u16_at(buf, p + 4)?, handler_off: u16_at(buf, p + 6)? });
                p += 8;
            }
            let list_base = p;
            let (count, n) = read_uleb128(buf, p)?;
            p += n;
            // Counts come from the file: cap the reservations by what could
            // physically fit in the remaining bytes (a handler is >= 1 byte,
            // a catch pair >= 2 bytes) and by a sane constant.
            let remaining = buf.len().saturating_sub(p);
            handlers.reserve((count as usize).min(remaining).min(MAX_RESERVE));
            for _ in 0..count {
                let offset = (p - list_base) as u16;
                let (size, n) = read_sleb128(buf, p)?;
                p += n;
                let remaining = buf.len().saturating_sub(p);
                let mut catches = Vec::with_capacity((size.unsigned_abs() as usize).min(remaining / 2).min(MAX_RESERVE));
                for _ in 0..size.unsigned_abs() {
                    let (t, n) = read_uleb128(buf, p)?;
                    p += n;
                    let (a, n) = read_uleb128(buf, p)?;
                    p += n;
                    catches.push((t, a));
                }
                let catch_all_addr = if size <= 0 {
                    let (a, n) = read_uleb128(buf, p)?;
                    p += n;
                    Some(a)
                } else {
                    None
                };
                handlers.push(CatchHandler { offset, catches, catch_all_addr });
            }
        }
        Ok(CodeItem { offset: off, registers_size, ins_size, outs_size, tries_size, debug_info_off, insns, tries, handlers, end: p })
    }

    /// Number of 16-bit code units.
    #[inline]
    pub fn insns_size(&self) -> usize {
        self.insns.len() / 2
    }

    /// Find the handler referenced by a try item.
    pub fn handler_for(&self, try_item: &TryItem) -> Option<&CatchHandler> {
        self.handlers.iter().find(|h| h.offset == try_item.handler_off)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(tries: u16, insns_size: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&1u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&tries.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&insns_size.to_le_bytes());
        v
    }

    #[test]
    fn parses_tries_and_handlers() {
        let mut v = header(1, 3);
        // 3 code units plus 2 bytes of padding to a 4-byte boundary.
        v.extend_from_slice(&[0x0e, 0x00, 0x0e, 0x00, 0x0e, 0x00, 0, 0]);
        // try_item: start_addr 0, insn_count 3, handler_off 1 (the first
        // handler sits right after the list size byte).
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&3u16.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes());
        // 2 handlers: size 0 => catch-all @5; size -1 => type 2 @4 and catch-all @6.
        v.extend_from_slice(&[2, 0x00, 0x05, 0x7f, 0x02, 0x04, 0x06]);
        let item = CodeItem::parse(&v, 0).unwrap();
        assert_eq!(item.insns_size(), 3);
        assert_eq!(item.tries.len(), 1);
        assert_eq!(item.handlers.len(), 2);
        assert_eq!(item.handlers[0].catch_all_addr, Some(5));
        assert!(item.handlers[0].catches.is_empty());
        assert_eq!(item.handlers[1].offset, 3);
        assert_eq!(item.handlers[1].catches, vec![(2, 4)]);
        assert_eq!(item.handlers[1].catch_all_addr, Some(6));
        assert_eq!(item.handler_for(&item.tries[0]).unwrap().offset, 1);
        assert_eq!(item.end, v.len());
    }

    #[test]
    fn malformed_sizes_error_without_huge_allocations() {
        // insns_size far beyond the buffer.
        let v = header(0, u32::MAX);
        assert_eq!(CodeItem::parse(&v, 0), Err(DexError::BadRange { what: "code_item.insns", offset: 0 }));
        // tries_size that cannot fit.
        let mut v = header(u16::MAX, 1);
        v.extend_from_slice(&[0x0e, 0x00, 0, 0]);
        assert_eq!(CodeItem::parse(&v, 0), Err(DexError::BadRange { what: "code_item.tries", offset: 20 }));
        // Huge handler count and catch count: parsing fails on truncation
        // instead of reserving gigabytes first.
        let mut v = header(1, 1);
        v.extend_from_slice(&[0x0e, 0x00, 0, 0]);
        v.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0]);
        v.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x0f]); // count = u32::MAX
        v.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x07]); // size = i32::MAX
        assert!(CodeItem::parse(&v, 0).is_err());
        let mut v = header(1, 1);
        v.extend_from_slice(&[0x0e, 0x00, 0, 0]);
        v.extend_from_slice(&[0, 0, 0, 0, 1, 0, 0, 0]);
        v.extend_from_slice(&[0x01, 0x80, 0x80, 0x80, 0x80, 0x78]); // size = i32::MIN
        assert!(CodeItem::parse(&v, 0).is_err());
    }
}
