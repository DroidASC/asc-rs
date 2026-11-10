//! Bounds-checked little-endian reads over the index bytes.

use super::ResourceIndexError;

type Result<T> = std::result::Result<T, ResourceIndexError>;

/// `u32` file quantities as `usize`; on a target where one does not fit,
/// the saturated value fails the next bounds check.
pub(super) fn widen(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// A cursor over `bytes[..end]`. Positions in errors are file offsets.
#[derive(Clone)]
pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Reader<'a> {
        Reader { bytes, pos: 0 }
    }

    /// A cursor at a file offset the index itself supplied.
    pub(super) fn at(bytes: &'a [u8], offset: u32, what: &'static str) -> Result<Reader<'a>> {
        let pos = widen(offset);
        if pos > bytes.len() {
            return Err(ResourceIndexError::OutOfBounds { what, offset, len: bytes.len() });
        }
        Ok(Reader { bytes, pos })
    }

    pub(super) fn pos(&self) -> usize {
        self.pos
    }

    pub(super) fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    pub(super) fn take(&mut self, len: usize, what: &'static str) -> Result<&'a [u8]> {
        let available = self.remaining();
        if len > available {
            return Err(ResourceIndexError::Truncated { what, offset: self.pos, needed: len, available });
        }
        let taken = &self.bytes[self.pos..self.pos + len];
        self.pos += len;
        Ok(taken)
    }

    /// The next `len` bytes as their own cursor, so a block that declares
    /// its size cannot be read past its end.
    pub(super) fn sub(&mut self, len: usize, what: &'static str) -> Result<Reader<'a>> {
        let start = self.pos;
        self.take(len, what)?;
        Ok(Reader { bytes: &self.bytes[..start + len], pos: start })
    }

    pub(super) fn u16(&mut self, what: &'static str) -> Result<u16> {
        let bytes = self.take(2, what)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub(super) fn u32(&mut self, what: &'static str) -> Result<u32> {
        let bytes = self.take(4, what)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(super) fn tag(&mut self, expected: &'static str) -> Result<()> {
        let offset = self.pos;
        let found = self.take(4, expected)?;
        if found != expected.as_bytes() {
            let found = [found[0], found[1], found[2], found[3]];
            return Err(ResourceIndexError::BadTag { expected, offset, found });
        }
        Ok(())
    }

    /// A `u32` count of items of `item_size` bytes each that follow. A
    /// count the rest of the block cannot hold is an error here, before
    /// anything is allocated for it.
    pub(super) fn count(&mut self, item_size: usize, what: &'static str) -> Result<usize> {
        let offset = self.pos;
        let count = widen(self.u32(what)?);
        let available = self.remaining();
        match count.checked_mul(item_size) {
            Some(needed) if needed <= available => Ok(count),
            _ => Err(ResourceIndexError::Truncated { what, offset, needed: count.saturating_mul(item_size), available }),
        }
    }

    /// A `u16` length and that many bytes.
    pub(super) fn sized16(&mut self, what: &'static str) -> Result<&'a [u8]> {
        let len = usize::from(self.u16(what)?);
        self.take(len, what)
    }
}
