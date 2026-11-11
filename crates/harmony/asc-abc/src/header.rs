use std::fmt;

use crate::reader::{read_u32, slice_at};
use crate::{AbcError, HEADER_SIZE, MAGIC, Result};

/// File format version, e.g. `12.0.6.0`. Ordered like the runtime orders it
/// (byte by byte from the major number).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version(pub [u8; 4]);

impl Version {
    /// Last version whose header still carries the literal array index
    /// (`LAST_CONTAINS_LITERAL_IN_HEADER_VERSION`).
    pub const LAST_WITH_LITERAL_INDEX: Version = Version([12, 0, 6, 0]);
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.0;
        write!(f, "{a}.{b}.{c}.{d}")
    }
}

/// Parsed file header (60 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Header {
    /// Adler-32 of everything after the checksum field (from offset 12).
    pub checksum: u32,
    /// `version`: bytecode version the file was compiled for.
    pub version: Version,
    /// `file_size`: total file size in bytes.
    pub file_size: u32,
    /// `foreign_off`: offset of the foreign region; see [`Header::is_foreign`].
    pub foreign_off: u32,
    /// `foreign_size`: size of the foreign region in bytes.
    pub foreign_size: u32,
    /// `num_classes`: entries in the class index.
    pub num_classes: u32,
    /// `class_idx_off`: offset of the class index, an array of `u32` class offsets.
    pub class_idx_off: u32,
    /// `num_lnps`: entries in the line-number-program index.
    pub num_lnps: u32,
    /// `lnp_idx_off`: offset of the line-number-program index, an array of `u32` offsets.
    pub lnp_idx_off: u32,
    /// `0xFFFF_FFFF` in files newer than [`Version::LAST_WITH_LITERAL_INDEX`].
    pub num_literalarrays: u32,
    /// `0xFFFF_FFFF` in files newer than [`Version::LAST_WITH_LITERAL_INDEX`].
    pub literalarray_idx_off: u32,
    /// `num_indexes`: number of [`RegionHeader`] entries in the region index.
    pub num_indexes: u32,
    /// `index_section_off`: offset of the region index, an array of [`RegionHeader`].
    pub index_section_off: u32,
}

impl Header {
    /// Parse the header at the start of `buf`. Only the magic is validated:
    /// no version is rejected and the checksum is not verified.
    ///
    /// # Errors
    /// `TooSmall` or `BadMagic`.
    pub fn parse(buf: &[u8]) -> Result<Header> {
        let head = buf.get(..HEADER_SIZE).ok_or(AbcError::TooSmall(buf.len()))?;
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&head[..8]);
        if magic != MAGIC {
            return Err(AbcError::BadMagic(magic));
        }
        let mut version = [0u8; 4];
        version.copy_from_slice(&head[12..16]);
        let word = |off: usize| read_u32(head, off);
        Ok(Header {
            checksum: word(8)?,
            version: Version(version),
            file_size: word(16)?,
            foreign_off: word(20)?,
            foreign_size: word(24)?,
            num_classes: word(28)?,
            class_idx_off: word(32)?,
            num_lnps: word(36)?,
            lnp_idx_off: word(40)?,
            num_literalarrays: word(44)?,
            literalarray_idx_off: word(48)?,
            num_indexes: word(52)?,
            index_section_off: word(56)?,
        })
    }

    /// Whether the header carries a literal array index. Decided by the
    /// version, as `ContainsLiteralArrayInHeader` does.
    pub fn has_literal_array_index(&self) -> bool {
        self.version <= Version::LAST_WITH_LITERAL_INDEX
    }

    /// Whether `off` lies in the foreign region (declarations of entities
    /// defined in other files).
    pub fn is_foreign(&self, off: u32) -> bool {
        off >= self.foreign_off && u64::from(off) < u64::from(self.foreign_off) + u64::from(self.foreign_size)
    }
}

/// One entry of the region index (`File::IndexHeader`, 40 bytes): the part
/// of the file `[start, end)` whose entities use this region's 16-bit index
/// tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RegionHeader {
    /// `start`: first file offset of the region.
    pub start: u32,
    /// `end`: file offset one past the end of the region.
    pub end: u32,
    /// `class_idx_size`: entries in the region's class index.
    pub class_idx_size: u32,
    /// `class_idx_off`: offset of the class index, an array of `u32` type offsets.
    pub class_idx_off: u32,
    /// `method_idx_size`: entries in the region's method index.
    pub method_idx_size: u32,
    /// `method_idx_off`: offset of the method index, an array of `u32` method offsets.
    pub method_idx_off: u32,
    /// `field_idx_size`: entries in the region's field index.
    pub field_idx_size: u32,
    /// `field_idx_off`: offset of the field index, an array of `u32` field offsets.
    pub field_idx_off: u32,
    /// `proto_idx_size`: entries in the region's proto index.
    pub proto_idx_size: u32,
    /// `proto_idx_off`: offset of the proto index, an array of `u32` proto offsets.
    pub proto_idx_off: u32,
}

impl RegionHeader {
    /// Encoded size in bytes.
    pub const SIZE: usize = 40;

    /// Parse the region header at `off`.
    ///
    /// # Errors
    /// `Truncated` when fewer than [`RegionHeader::SIZE`] bytes are left.
    pub fn parse(buf: &[u8], off: usize) -> Result<RegionHeader> {
        let raw = slice_at(buf, off, Self::SIZE, "region header")?;
        let word = |i: usize| read_u32(raw, i * 4);
        Ok(RegionHeader {
            start: word(0)?,
            end: word(1)?,
            class_idx_size: word(2)?,
            class_idx_off: word(3)?,
            method_idx_size: word(4)?,
            method_idx_off: word(5)?,
            field_idx_size: word(6)?,
            field_idx_off: word(7)?,
            proto_idx_size: word(8)?,
            proto_idx_off: word(9)?,
        })
    }

    /// Whether file offset `off` lies in `[start, end)`.
    #[inline]
    pub fn contains(&self, off: u32) -> bool {
        self.start <= off && off < self.end
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_small_buffers_and_bad_magic() {
        assert_eq!(Header::parse(&[]), Err(AbcError::TooSmall(0)));
        assert_eq!(Header::parse(&[0u8; HEADER_SIZE - 1]), Err(AbcError::TooSmall(HEADER_SIZE - 1)));
        let mut buf = [0u8; HEADER_SIZE];
        buf[..8].copy_from_slice(b"dex\n035\0");
        assert_eq!(Header::parse(&buf), Err(AbcError::BadMagic(*b"dex\n035\0")));
    }

    #[test]
    fn parses_fields_and_version() {
        let mut buf = [0u8; HEADER_SIZE];
        buf[..8].copy_from_slice(&MAGIC);
        buf[12..16].copy_from_slice(&[13, 0, 1, 0]);
        for (i, off) in (16..HEADER_SIZE).step_by(4).enumerate() {
            buf[off..off + 4].copy_from_slice(&(0x100 + i as u32).to_le_bytes());
        }
        let h = Header::parse(&buf).unwrap();
        assert_eq!(h.version.to_string(), "13.0.1.0");
        assert!(!h.has_literal_array_index());
        assert_eq!((h.file_size, h.foreign_off, h.foreign_size), (0x100, 0x101, 0x102));
        assert_eq!((h.num_classes, h.class_idx_off, h.num_lnps, h.lnp_idx_off), (0x103, 0x104, 0x105, 0x106));
        assert_eq!((h.num_literalarrays, h.literalarray_idx_off, h.num_indexes, h.index_section_off), (0x107, 0x108, 0x109, 0x10a));
        assert!(h.is_foreign(0x101) && h.is_foreign(0x202) && !h.is_foreign(0x203) && !h.is_foreign(0x100));

        assert!(Version([12, 0, 6, 0]) <= Version::LAST_WITH_LITERAL_INDEX);
        assert!(Version([9, 0, 0, 0]) < Version([12, 0, 2, 0]));
        assert!(Version([12, 0, 6, 1]) > Version::LAST_WITH_LITERAL_INDEX);
    }

    #[test]
    fn foreign_range_does_not_overflow() {
        let mut buf = [0u8; HEADER_SIZE];
        buf[..8].copy_from_slice(&MAGIC);
        buf[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        buf[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        let h = Header::parse(&buf).unwrap();
        assert!(h.is_foreign(u32::MAX) && !h.is_foreign(0));
    }
}
