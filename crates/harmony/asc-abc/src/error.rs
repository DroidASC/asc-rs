use thiserror::Error;

/// Errors produced while reading ABC structures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AbcError {
    /// The buffer is shorter than the 60-byte header; holds the buffer length.
    #[error("buffer too small for ABC header ({0} bytes)")]
    TooSmall(usize),
    /// The first 8 bytes are not `PANDA\0\0\0`; holds the bytes found.
    #[error("bad ABC magic {0:?}")]
    BadMagic([u8; 8]),
    /// The header is plausible but everything after it is scrambled: the
    /// index tables point outside the file and the Adler-32 checksum does not
    /// match. This is what an encrypted `modules.abc` looks like.
    #[error("ABC body is encrypted or scrambled (checksum {stored:#010x}, computed {computed:#010x})")]
    Encrypted {
        /// Checksum stored in the header.
        stored: u32,
        /// Adler-32 computed over the body.
        computed: u32,
    },
    /// A structure runs past the end of the buffer.
    #[error("truncated {what} at offset {offset:#x}")]
    Truncated {
        /// Kind of structure being read.
        what: &'static str,
        /// Buffer offset where it starts.
        offset: usize,
    },
    /// An entity offset points into the header or past the end of the file.
    #[error("{what} offset {offset:#x} is outside the file body")]
    BadOffset {
        /// Kind of entity referenced.
        what: &'static str,
        /// The offending file offset.
        offset: u32,
    },
    /// An index into an index table (class, method, region, ...) is past its end.
    #[error("{what} index {index} out of range (size {size})")]
    IndexOutOfRange {
        /// Kind of index table.
        what: &'static str,
        /// The offending index.
        index: u32,
        /// Number of entries in the table.
        size: u32,
    },
    /// No region header covers an entity, so its 16-bit indexes cannot be resolved.
    #[error("no region covers offset {offset:#x}")]
    NoRegion {
        /// File offset of the entity.
        offset: u32,
    },
    /// A MUTF-8 string has no terminating NUL; holds the string's offset.
    #[error("unterminated string at offset {0:#x}")]
    UnterminatedString(usize),
    /// A structure is in bounds but its contents are invalid (bad tag, overlong LEB128, ...).
    #[error("malformed {what} at offset {offset:#x}: {reason}")]
    Malformed {
        /// Kind of structure being read.
        what: &'static str,
        /// Buffer offset of the bad data.
        offset: usize,
        /// What is wrong with it.
        reason: &'static str,
    },
}

/// [`std::result::Result`] with [`AbcError`].
pub type Result<T> = std::result::Result<T, AbcError>;
