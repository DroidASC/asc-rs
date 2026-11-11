//! Zero-copy reader for ArkCompiler ABC (Panda) files, dynamic / ECMAScript
//! flavour: the bytecode container of HarmonyOS applications.
//!
//! Nothing is indexed up front: [`Abc::parse`] reads the 60-byte header and
//! checks that the index tables are in bounds; every accessor then parses
//! the item it is asked for straight from the borrowed buffer. Every offset
//! and count comes from the file and is bounds-checked, so malformed or
//! obfuscated input produces an [`AbcError`], never a panic.
//!
//! Instructions are not decoded here: [`Code::instructions`] hands out the
//! raw bytes for `asc-arkisa`.

pub mod leb128;
pub mod mutf8;

mod abc;
mod annotation;
mod class;
mod code;
mod debug;
mod error;
mod header;
mod literal;
mod module;
mod name;
mod reader;
mod string;

pub use abc::{Abc, OffsetTable, Region, Regions};
pub use annotation::{Annotation, AnnotationElement, ElementValue};
pub use class::{
    access, record_field, unmerged, Class, ClassEntry, ClassTag, Field, FieldTag, FieldType, FieldValue, Fields, ForeignClass,
    FunctionKind, IndexList, Method, MethodTag, Methods, SourceLang,
};
pub use code::{CatchBlock, Code, TryBlock, TryBlocks};
pub use debug::{DebugInfo, LineOp, LineOps, LineRow, LineRows, LocalVar};
pub use error::{AbcError, Result};
pub use header::{Header, RegionHeader, Version};
pub use literal::{tag as literal_tag, Literal, LiteralArray, Literals};
pub use module::{IndirectExport, LocalExport, ModuleEntry, ModuleRecord, NamespaceImport, RegularImport, Section, StarExport};
pub use name::{FunctionName, RecordKind, RecordName, Scope, ScopeIdent, ScopeKind};
pub use reader::{read_u16, read_u32, read_u64};
pub use string::StringData;

/// File magic.
pub const MAGIC: [u8; 8] = *b"PANDA\0\0\0";
/// Size of the file header in bytes. No entity can start inside it.
pub const HEADER_SIZE: usize = 60;
/// "Absent" marker for header offsets and counts.
pub const INVALID_OFFSET: u32 = 0xFFFF_FFFF;
