use crate::{u32_at, DexError, Result, HEADER_SIZE};

/// An `(offset, size)` pair describing one id table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Section {
    pub off: u32,
    pub size: u32,
}

/// Parsed `header_item`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub magic: [u8; 8],
    pub checksum: u32,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_off: u32,
    pub map_off: u32,
    pub string_ids: Section,
    pub type_ids: Section,
    pub proto_ids: Section,
    pub field_ids: Section,
    pub method_ids: Section,
    pub class_defs: Section,
    pub data_size: u32,
    pub data_off: u32,
}

impl Header {
    /// Parse the header at the start of `buf`. Only the magic prefix `dex\n`
    /// is validated; checksums and signatures are never verified.
    pub fn parse(buf: &[u8]) -> Result<Header> {
        if buf.len() < HEADER_SIZE {
            return Err(DexError::TooSmall(buf.len()));
        }
        let mut magic = [0u8; 8];
        magic.copy_from_slice(&buf[..8]);
        if &magic[..4] != b"dex\n" {
            return Err(DexError::BadMagic(magic));
        }
        let mut signature = [0u8; 20];
        signature.copy_from_slice(&buf[12..32]);
        let sec = |size_off: usize| -> Result<Section> { Ok(Section { size: u32_at(buf, size_off)?, off: u32_at(buf, size_off + 4)? }) };
        Ok(Header {
            magic,
            checksum: u32_at(buf, 8)?,
            signature,
            file_size: u32_at(buf, 0x20)?,
            header_size: u32_at(buf, 0x24)?,
            endian_tag: u32_at(buf, 0x28)?,
            link_size: u32_at(buf, 0x2C)?,
            link_off: u32_at(buf, 0x30)?,
            map_off: u32_at(buf, 0x34)?,
            string_ids: sec(0x38)?,
            type_ids: sec(0x40)?,
            proto_ids: sec(0x48)?,
            field_ids: sec(0x50)?,
            method_ids: sec(0x58)?,
            class_defs: sec(0x60)?,
            data_size: u32_at(buf, 0x68)?,
            data_off: u32_at(buf, 0x6C)?,
        })
    }

    /// DEX format version parsed from the magic (`035`, `039`, `041`, ...);
    /// `0` when the version bytes are not three ASCII digits.
    pub fn version(&self) -> u32 {
        let v = &self.magic[4..7];
        if !v.iter().all(u8::is_ascii_digit) {
            return 0;
        }
        v.iter().fold(0u32, |acc, &c| acc * 10 + (c - b'0') as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_small_buffers_and_bad_magic() {
        assert_eq!(Header::parse(&[]), Err(DexError::TooSmall(0)));
        assert_eq!(Header::parse(&[0u8; HEADER_SIZE - 1]), Err(DexError::TooSmall(HEADER_SIZE - 1)));
        let mut buf = [0u8; HEADER_SIZE];
        buf[..8].copy_from_slice(b"dey\n035\0");
        assert_eq!(Header::parse(&buf), Err(DexError::BadMagic(*b"dey\n035\0")));
        buf[..8].copy_from_slice(b"PK\x03\x04\0\0\0\0");
        assert_eq!(Header::parse(&buf), Err(DexError::BadMagic(*b"PK\x03\x04\0\0\0\0")));
    }

    #[test]
    fn parses_fields_and_version() {
        let mut buf = [0u8; HEADER_SIZE + 4];
        buf[..8].copy_from_slice(b"dex\n039\0");
        buf[0x20..0x24].copy_from_slice(&0x1234u32.to_le_bytes());
        buf[0x34..0x38].copy_from_slice(&0x100u32.to_le_bytes());
        buf[0x38..0x3C].copy_from_slice(&6u32.to_le_bytes());
        buf[0x3C..0x40].copy_from_slice(&0x70u32.to_le_bytes());
        buf[0x6C..0x70].copy_from_slice(&0x200u32.to_le_bytes());
        let h = Header::parse(&buf).unwrap();
        assert_eq!(h.version(), 39);
        buf[..8].copy_from_slice(b"dex\n\xff\xff\xff\0");
        assert_eq!(Header::parse(&buf).unwrap().version(), 0);
        buf[..8].copy_from_slice(b"dex\n0a9\0");
        assert_eq!(Header::parse(&buf).unwrap().version(), 0);
        assert_eq!(h.file_size, 0x1234);
        assert_eq!(h.map_off, 0x100);
        assert_eq!(h.string_ids, Section { off: 0x70, size: 6 });
        assert_eq!(h.type_ids, Section::default());
        assert_eq!(h.data_off, 0x200);
    }
}
