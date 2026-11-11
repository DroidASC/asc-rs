//! Bounds-checked little-endian reads and a forward cursor.

use crate::{AbcError, HEADER_SIZE, Result, StringData, leb128};

fn array_at<const N: usize>(buf: &[u8], off: usize, what: &'static str) -> Result<[u8; N]> {
    off.checked_add(N)
        .and_then(|end| buf.get(off..end))
        .and_then(|b| <[u8; N]>::try_from(b).ok())
        .ok_or(AbcError::Truncated { what, offset: off })
}

/// Read a little-endian `u16` at `off`.
#[inline]
pub fn read_u16(buf: &[u8], off: usize) -> Result<u16> {
    array_at(buf, off, "u16").map(u16::from_le_bytes)
}

/// Read a little-endian `u32` at `off`.
#[inline]
pub fn read_u32(buf: &[u8], off: usize) -> Result<u32> {
    array_at(buf, off, "u32").map(u32::from_le_bytes)
}

/// Read a little-endian `u64` at `off`.
#[inline]
pub fn read_u64(buf: &[u8], off: usize) -> Result<u64> {
    array_at(buf, off, "u64").map(u64::from_le_bytes)
}

/// `buf[off..off + len]`, or `Truncated`.
#[inline]
pub(crate) fn slice_at<'a>(buf: &'a [u8], off: usize, len: usize, what: &'static str) -> Result<&'a [u8]> {
    off.checked_add(len).and_then(|end| buf.get(off..end)).ok_or(AbcError::Truncated { what, offset: off })
}

/// Position of the entity at file offset `off`. Like `File::GetSpanFromId`,
/// offsets inside the header or past the end are invalid.
#[inline]
pub(crate) fn entity_pos(buf: &[u8], off: u32, what: &'static str) -> Result<usize> {
    let pos = off as usize;
    if pos > HEADER_SIZE && pos < buf.len() { Ok(pos) } else { Err(AbcError::BadOffset { what, offset: off }) }
}

/// File offset of a position inside the buffer. ABC offsets are 32 bits; a
/// position past that (only possible in a buffer larger than 4 GiB) saturates
/// and is then rejected by the next bounds check.
#[inline]
pub(crate) fn file_off(pos: usize) -> u32 {
    u32::try_from(pos).unwrap_or(u32::MAX)
}

/// Forward cursor over the file buffer.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    #[inline]
    pub(crate) fn new(buf: &'a [u8], pos: usize) -> Reader<'a> {
        Reader { buf, pos }
    }

    #[inline]
    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    #[inline]
    pub(crate) fn u8(&mut self) -> Result<u8> {
        let b = *self.buf.get(self.pos).ok_or(AbcError::Truncated { what: "u8", offset: self.pos })?;
        self.pos += 1;
        Ok(b)
    }

    #[inline]
    pub(crate) fn u16(&mut self) -> Result<u16> {
        let v = read_u16(self.buf, self.pos)?;
        self.pos += 2;
        Ok(v)
    }

    #[inline]
    pub(crate) fn u32(&mut self) -> Result<u32> {
        let v = read_u32(self.buf, self.pos)?;
        self.pos += 4;
        Ok(v)
    }

    #[inline]
    pub(crate) fn u64(&mut self) -> Result<u64> {
        let v = read_u64(self.buf, self.pos)?;
        self.pos += 8;
        Ok(v)
    }

    #[inline]
    pub(crate) fn uleb(&mut self) -> Result<u32> {
        let (v, n) = leb128::read_uleb128(self.buf, self.pos)?;
        self.pos += n;
        Ok(v)
    }

    #[inline]
    pub(crate) fn sleb(&mut self) -> Result<i32> {
        let (v, n) = leb128::read_sleb128(self.buf, self.pos)?;
        self.pos += n;
        Ok(v)
    }

    /// The next `len` bytes.
    #[inline]
    pub(crate) fn take(&mut self, len: usize, what: &'static str) -> Result<&'a [u8]> {
        let bytes = slice_at(self.buf, self.pos, len, what)?;
        self.pos += len;
        Ok(bytes)
    }

    /// A `String` item: `uleb128 (utf16_len << 1 | is_ascii)`, MUTF-8 data, NUL.
    pub(crate) fn string(&mut self) -> Result<StringData<'a>> {
        let start = self.pos;
        let header = self.uleb()?;
        let rest = self.buf.get(self.pos..).unwrap_or_default();
        let len = memchr::memchr(0, rest).ok_or(AbcError::UnterminatedString(start))?;
        self.pos += len + 1;
        Ok(StringData { utf16_len: header >> 1, is_ascii: header & 1 != 0, bytes: &rest[..len] })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readers_report_truncation() {
        let buf = [1u8, 2, 3, 4, 5, 6, 7, 8, 9];
        assert_eq!(read_u16(&buf, 0).unwrap(), 0x0201);
        assert_eq!(read_u32(&buf, 1).unwrap(), 0x0504_0302);
        assert_eq!(read_u64(&buf, 1).unwrap(), 0x0908_0706_0504_0302);
        assert_eq!(read_u16(&buf, 8), Err(AbcError::Truncated { what: "u16", offset: 8 }));
        assert_eq!(read_u32(&buf, 6), Err(AbcError::Truncated { what: "u32", offset: 6 }));
        assert!(read_u32(&buf, usize::MAX - 1).is_err());
        assert!(slice_at(&buf, 4, usize::MAX, "x").is_err());
    }

    #[test]
    fn cursor_reads_strings() {
        // "hi" (ascii, 2 units), then an unterminated one.
        let buf = [0x05, b'h', b'i', 0, 0x03, b'x'];
        let mut r = Reader::new(&buf, 0);
        let s = r.string().unwrap();
        assert_eq!((s.utf16_len, s.is_ascii, s.bytes), (2, true, &b"hi"[..]));
        assert_eq!(r.pos(), 4);
        assert_eq!(r.string(), Err(AbcError::UnterminatedString(4)));
        assert!(Reader::new(&buf, 99).string().is_err());
        assert!(Reader::new(&buf, 99).take(1, "x").is_err());
    }
}
