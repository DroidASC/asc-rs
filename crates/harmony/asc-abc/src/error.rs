use thiserror::Error;

/// Errors produced while reading ABC structures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AbcError {
    #[error("buffer too small for ABC header ({0} bytes)")]
    TooSmall(usize),
    #[error("bad ABC magic {0:?}")]
    BadMagic([u8; 8]),
    /// The header is plausible but everything after it is scrambled: the
    /// index tables point outside the file and the Adler-32 checksum does not
    /// match. This is what an encrypted `modules.abc` looks like.
    #[error("ABC body is encrypted or scrambled (checksum {stored:#010x}, computed {computed:#010x})")]
    Encrypted { stored: u32, computed: u32 },
    #[error("truncated {what} at offset {offset:#x}")]
    Truncated { what: &'static str, offset: usize },
    #[error("{what} offset {offset:#x} is outside the file body")]
    BadOffset { what: &'static str, offset: u32 },
    #[error("{what} index {index} out of range (size {size})")]
    IndexOutOfRange { what: &'static str, index: u32, size: u32 },
    #[error("no region covers offset {offset:#x}")]
    NoRegion { offset: u32 },
    #[error("unterminated string at offset {0:#x}")]
    UnterminatedString(usize),
    #[error("malformed {what} at offset {offset:#x}: {reason}")]
    Malformed { what: &'static str, offset: usize, reason: &'static str },
}

pub type Result<T> = std::result::Result<T, AbcError>;
