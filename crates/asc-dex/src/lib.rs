//! Zero-copy DEX parsing primitives.
//!
//! The parser never builds global tables up front: every accessor computes the
//! item from the header offsets on demand, so opening a DEX costs a header read
//! and nothing else. Higher level crates (`asc-findrefs`, `asc-rebuild`,
//! `asc-smali`) build only the indexes they need.

pub mod annotations;
pub mod checksum;
pub mod class_data;
pub mod code;
pub mod container;
pub mod debug_info;
pub mod encoded;
pub mod error;
pub mod header;
pub mod leb128;
pub mod mutf8;
pub mod quick;

mod dex;

pub use dex::{ClassDef, Dex, FieldId, MapItem, MethodId, ProtoId, StringItem};
pub use error::{DexError, Result};
pub use header::{Header, Section};

/// Sentinel used by DEX for "no index" (superclass, source file, ...).
pub const NO_INDEX: u32 = 0xFFFF_FFFF;
/// Size of the DEX header in bytes.
pub const HEADER_SIZE: usize = 0x70;

/// Map list item type codes (`map_item.type`).
pub mod map_type {
    pub const HEADER: u16 = 0x0000;
    pub const STRING_ID: u16 = 0x0001;
    pub const TYPE_ID: u16 = 0x0002;
    pub const PROTO_ID: u16 = 0x0003;
    pub const FIELD_ID: u16 = 0x0004;
    pub const METHOD_ID: u16 = 0x0005;
    pub const CLASS_DEF: u16 = 0x0006;
    pub const CALL_SITE_ID: u16 = 0x0007;
    pub const METHOD_HANDLE: u16 = 0x0008;
    pub const MAP_LIST: u16 = 0x1000;
    pub const TYPE_LIST: u16 = 0x1001;
    pub const ANNOTATION_SET_REF_LIST: u16 = 0x1002;
    pub const ANNOTATION_SET: u16 = 0x1003;
    pub const CLASS_DATA: u16 = 0x2000;
    pub const CODE: u16 = 0x2001;
    pub const STRING_DATA: u16 = 0x2002;
    pub const DEBUG_INFO: u16 = 0x2003;
    pub const ANNOTATION: u16 = 0x2004;
    pub const ENCODED_ARRAY: u16 = 0x2005;
    pub const ANNOTATIONS_DIRECTORY: u16 = 0x2006;
    pub const HIDDENAPI_CLASS_DATA: u16 = 0xF000;
}

/// Access flag bits shared by classes, fields and methods.
pub mod access {
    pub const PUBLIC: u32 = 0x1;
    pub const PRIVATE: u32 = 0x2;
    pub const PROTECTED: u32 = 0x4;
    pub const STATIC: u32 = 0x8;
    pub const FINAL: u32 = 0x10;
    pub const SYNCHRONIZED: u32 = 0x20;
    pub const VOLATILE: u32 = 0x40;
    pub const BRIDGE: u32 = 0x40;
    pub const TRANSIENT: u32 = 0x80;
    pub const VARARGS: u32 = 0x80;
    pub const NATIVE: u32 = 0x100;
    pub const INTERFACE: u32 = 0x200;
    pub const ABSTRACT: u32 = 0x400;
    pub const STRICT: u32 = 0x800;
    pub const SYNTHETIC: u32 = 0x1000;
    pub const ANNOTATION: u32 = 0x2000;
    pub const ENUM: u32 = 0x4000;
    pub const CONSTRUCTOR: u32 = 0x10000;
    pub const DECLARED_SYNCHRONIZED: u32 = 0x20000;
}

/// Read a little-endian `u16` at `off`, returning an error when out of range.
#[inline]
pub fn read_u16(buf: &[u8], off: usize) -> Result<u16> {
    off.checked_add(2)
        .and_then(|end| buf.get(off..end))
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or(DexError::Truncated { what: "u16", offset: off })
}

/// Read a little-endian `u32` at `off`, returning an error when out of range.
#[inline]
pub fn read_u32(buf: &[u8], off: usize) -> Result<u32> {
    off.checked_add(4)
        .and_then(|end| buf.get(off..end))
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or(DexError::Truncated { what: "u32", offset: off })
}

// Short crate-internal aliases used by the parsers.
pub(crate) use read_u16 as u16_at;
pub(crate) use read_u32 as u32_at;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readers_report_truncation() {
        let buf = [1u8, 2, 3, 4, 5];
        assert_eq!(read_u16(&buf, 0).unwrap(), 0x0201);
        assert_eq!(read_u32(&buf, 1).unwrap(), 0x05040302);
        assert_eq!(read_u16(&buf, 4), Err(DexError::Truncated { what: "u16", offset: 4 }));
        assert_eq!(read_u32(&buf, 2), Err(DexError::Truncated { what: "u32", offset: 2 }));
        assert!(read_u32(&buf, usize::MAX - 1).is_err());
    }
}
