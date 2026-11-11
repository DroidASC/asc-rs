//! The error type shared by every DEX reader in this crate.

use thiserror::Error;

/// Errors produced while reading DEX structures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DexError {
    /// The buffer is shorter than the DEX header; holds the buffer length in bytes.
    #[error("buffer too small for DEX header ({0} bytes)")]
    TooSmall(usize),
    /// The magic does not start with `dex\n`; holds the first eight bytes.
    #[error("bad DEX magic {0:?}")]
    BadMagic([u8; 8]),
    /// A read ran past the end of the buffer.
    #[error("truncated {what} at offset {offset:#x}")]
    Truncated {
        /// The structure being read.
        what: &'static str,
        /// Byte offset of the read that failed.
        offset: usize,
    },
    /// An index points past the end of its table.
    #[error("{what} index {index} out of range (size {size})")]
    IndexOutOfRange {
        /// The table being indexed (`string_ids`, `type_ids`, ...).
        what: &'static str,
        /// The offending index.
        index: u32,
        /// Number of entries in the table.
        size: u32,
    },
    /// A section or item extends outside the buffer (or its size overflows).
    #[error("bad {what} range at offset {offset:#x}")]
    BadRange {
        /// The section or item.
        what: &'static str,
        /// Start offset of the range.
        offset: usize,
    },
    /// A `string_data_item` has no NUL terminator; holds its offset.
    #[error("unterminated string_data_item at offset {0:#x}")]
    UnterminatedString(usize),
    /// A structure is in bounds but its contents violate the format.
    #[error("malformed {what} at offset {offset:#x}: {reason}")]
    Malformed {
        /// The structure being decoded.
        what: &'static str,
        /// Byte offset of the structure (or of the bad byte).
        offset: usize,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// No `class_def` has the requested descriptor; holds that descriptor.
    #[error("class {0} not found in DEX")]
    ClassNotFound(String),
}

/// `Result` with [`DexError`] as the error type.
pub type Result<T> = std::result::Result<T, DexError>;
