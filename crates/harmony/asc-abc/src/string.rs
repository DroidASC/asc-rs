use std::borrow::Cow;

use crate::mutf8;

/// A `String` item: the bytes are borrowed from the file, without the
/// terminating NUL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringData<'a> {
    /// Declared length in UTF-16 code units.
    pub utf16_len: u32,
    /// Declared "all characters are ASCII" bit.
    pub is_ascii: bool,
    /// MUTF-8 data.
    pub bytes: &'a [u8],
}

impl<'a> StringData<'a> {
    /// Decoded text; borrowed unless the data needs MUTF-8 fix-ups.
    pub fn to_str(&self) -> Cow<'a, str> {
        mutf8::decode(self.bytes)
    }
}
