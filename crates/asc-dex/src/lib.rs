//! Zero-copy DEX parsing primitives.
//!
//! The parser never builds global tables up front: every accessor computes the
//! item from the header offsets on demand, so opening a DEX costs a header read
//! and nothing else. Higher level crates (`asc-findrefs`, `asc-rebuild`,
//! `asc-smali`) build only the indexes they need.

pub mod annotations;
pub mod call_site;
pub mod checksum;
pub mod class_data;
pub mod code;
pub mod container;
pub mod debug_info;
pub mod encoded;
pub mod error;
pub mod header;
pub mod leb128;
pub mod map;
pub mod mutf8;
pub mod quick;

mod dex;

pub use call_site::{CallSite, MethodHandle, MethodHandleKind};
pub use dex::{ClassDef, Dex, FieldId, MethodId, ProtoId, StringItem};
pub use error::{DexError, Result};
pub use header::{Header, Section};
pub use map::{MapItem, MapList};

/// Sentinel used by DEX for "no index" (superclass, source file, ...).
pub const NO_INDEX: u32 = 0xFFFF_FFFF;
/// Size of the DEX header in bytes.
pub const HEADER_SIZE: usize = 0x70;

/// Map list item type codes (`map_item.type`).
pub mod map_type {
    /// `header_item`.
    pub const HEADER: u16 = 0x0000;
    /// `string_id_item` table.
    pub const STRING_ID: u16 = 0x0001;
    /// `type_id_item` table.
    pub const TYPE_ID: u16 = 0x0002;
    /// `proto_id_item` table.
    pub const PROTO_ID: u16 = 0x0003;
    /// `field_id_item` table.
    pub const FIELD_ID: u16 = 0x0004;
    /// `method_id_item` table.
    pub const METHOD_ID: u16 = 0x0005;
    /// `class_def_item` table.
    pub const CLASS_DEF: u16 = 0x0006;
    /// `call_site_id_item` table.
    pub const CALL_SITE_ID: u16 = 0x0007;
    /// `method_handle_item` table.
    pub const METHOD_HANDLE: u16 = 0x0008;
    /// `map_list`.
    pub const MAP_LIST: u16 = 0x1000;
    /// `type_list` items.
    pub const TYPE_LIST: u16 = 0x1001;
    /// `annotation_set_ref_list` items.
    pub const ANNOTATION_SET_REF_LIST: u16 = 0x1002;
    /// `annotation_set_item`s.
    pub const ANNOTATION_SET: u16 = 0x1003;
    /// `class_data_item`s.
    pub const CLASS_DATA: u16 = 0x2000;
    /// `code_item`s.
    pub const CODE: u16 = 0x2001;
    /// `string_data_item`s.
    pub const STRING_DATA: u16 = 0x2002;
    /// `debug_info_item`s.
    pub const DEBUG_INFO: u16 = 0x2003;
    /// `annotation_item`s.
    pub const ANNOTATION: u16 = 0x2004;
    /// `encoded_array_item`s.
    pub const ENCODED_ARRAY: u16 = 0x2005;
    /// `annotations_directory_item`s.
    pub const ANNOTATIONS_DIRECTORY: u16 = 0x2006;
    /// `hiddenapi_class_data_item`.
    pub const HIDDENAPI_CLASS_DATA: u16 = 0xF000;
}

/// Access flag bits shared by classes, fields and methods.
pub mod access {
    /// `ACC_PUBLIC`: visible everywhere.
    pub const PUBLIC: u32 = 0x1;
    /// `ACC_PRIVATE`: visible only to the defining class.
    pub const PRIVATE: u32 = 0x2;
    /// `ACC_PROTECTED`: visible to the package and subclasses.
    pub const PROTECTED: u32 = 0x4;
    /// `ACC_STATIC`: static member, or a nested class without an outer `this`.
    pub const STATIC: u32 = 0x8;
    /// `ACC_FINAL`: not subclassable / overridable / reassignable.
    pub const FINAL: u32 = 0x10;
    /// `ACC_SYNCHRONIZED` (methods): lock acquired around calls (native methods only at runtime).
    pub const SYNCHRONIZED: u32 = 0x20;
    /// `ACC_VOLATILE` (fields): special access rules for thread safety.
    pub const VOLATILE: u32 = 0x40;
    /// `ACC_BRIDGE` (methods): compiler-generated bridge; shares its bit with `VOLATILE`.
    pub const BRIDGE: u32 = 0x40;
    /// `ACC_TRANSIENT` (fields): not saved by default serialization.
    pub const TRANSIENT: u32 = 0x80;
    /// `ACC_VARARGS` (methods): last argument is a rest argument; shares its bit with `TRANSIENT`.
    pub const VARARGS: u32 = 0x80;
    /// `ACC_NATIVE` (methods): implemented in native code.
    pub const NATIVE: u32 = 0x100;
    /// `ACC_INTERFACE` (classes): an interface.
    pub const INTERFACE: u32 = 0x200;
    /// `ACC_ABSTRACT`: not directly instantiable / not implemented by this class.
    pub const ABSTRACT: u32 = 0x400;
    /// `ACC_STRICT` (methods): strict floating point.
    pub const STRICT: u32 = 0x800;
    /// `ACC_SYNTHETIC`: not directly defined in source.
    pub const SYNTHETIC: u32 = 0x1000;
    /// `ACC_ANNOTATION` (classes): an annotation type.
    pub const ANNOTATION: u32 = 0x2000;
    /// `ACC_ENUM`: an enum type or enum constant.
    pub const ENUM: u32 = 0x4000;
    /// `ACC_CONSTRUCTOR` (methods): a constructor or class initializer.
    pub const CONSTRUCTOR: u32 = 0x10000;
    /// `ACC_DECLARED_SYNCHRONIZED` (methods): declared `synchronized` in source.
    pub const DECLARED_SYNCHRONIZED: u32 = 0x20000;
}

/// Read a little-endian `u16` at `off`, returning an error when out of range.
///
/// # Errors
///
/// [`DexError::Truncated`] when the u16 does not fit in `buf` at `off`.
#[inline]
pub fn read_u16(buf: &[u8], off: usize) -> Result<u16> {
    off.checked_add(2)
        .and_then(|end| buf.get(off..end))
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or(DexError::Truncated { what: "u16", offset: off })
}

/// Read a little-endian `u32` at `off`, returning an error when out of range.
///
/// # Errors
///
/// [`DexError::Truncated`] when the u32 does not fit in `buf` at `off`.
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
