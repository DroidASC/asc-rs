use thiserror::Error;

/// Errors produced while reading DEX structures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DexError {
    #[error("buffer too small for DEX header ({0} bytes)")]
    TooSmall(usize),
    #[error("bad DEX magic {0:?}")]
    BadMagic([u8; 8]),
    #[error("truncated {what} at offset {offset:#x}")]
    Truncated { what: &'static str, offset: usize },
    #[error("{what} index {index} out of range (size {size})")]
    IndexOutOfRange { what: &'static str, index: u32, size: u32 },
    #[error("bad {what} range at offset {offset:#x}")]
    BadRange { what: &'static str, offset: usize },
    #[error("unterminated string_data_item at offset {0:#x}")]
    UnterminatedString(usize),
    #[error("malformed {what} at offset {offset:#x}: {reason}")]
    Malformed { what: &'static str, offset: usize, reason: &'static str },
    #[error("class {0} not found in DEX")]
    ClassNotFound(String),
}

pub type Result<T> = std::result::Result<T, DexError>;
