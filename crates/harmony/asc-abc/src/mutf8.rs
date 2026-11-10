//! Modified UTF-8 (MUTF-8) decoding for ABC string data.
//!
//! MUTF-8 differs from UTF-8 in two ways: `U+0000` is encoded as `C0 80`, and
//! supplementary characters are stored as two 3-byte encoded UTF-16
//! surrogates. Everything else, which is nearly every string in practice, is
//! already valid UTF-8 and is returned borrowed.

use std::borrow::Cow;

/// Decode MUTF-8 bytes. Borrows when the bytes are valid UTF-8; otherwise
/// decodes through UTF-16, replacing invalid sequences and unpaired
/// surrogates with `U+FFFD`.
pub fn decode(bytes: &[u8]) -> Cow<'_, str> {
    match std::str::from_utf8(bytes) {
        Ok(s) => Cow::Borrowed(s),
        Err(_) => Cow::Owned(String::from_utf16_lossy(&Units { bytes, pos: 0 }.collect::<Vec<u16>>())),
    }
}

/// UTF-16 code units of MUTF-8 bytes; an invalid byte yields `U+FFFD`.
struct Units<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Iterator for Units<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<u16> {
        let rest = self.bytes.get(self.pos..)?;
        let b0 = *rest.first()?;
        let cont = |k: usize| rest.get(k).copied().filter(|b| b & 0xC0 == 0x80).map(|b| u16::from(b & 0x3F));
        let (unit, len) = match b0 {
            0x00..=0x7F => (u16::from(b0), 1),
            0xC0..=0xDF => match cont(1) {
                Some(b1) => ((u16::from(b0 & 0x1F) << 6) | b1, 2),
                None => (0xFFFD, 1),
            },
            0xE0..=0xEF => match (cont(1), cont(2)) {
                (Some(b1), Some(b2)) => ((u16::from(b0 & 0x0F) << 12) | (b1 << 6) | b2, 3),
                _ => (0xFFFD, 1),
            },
            // A 4-byte sequence only gets here inside a string that is not
            // valid UTF-8 as a whole; treat its bytes as invalid.
            _ => (0xFFFD, 1),
        };
        self.pos += len;
        Some(unit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn borrows_plain_utf8() {
        assert!(matches!(decode(b"pages/Index"), Cow::Borrowed("pages/Index")));
        assert!(matches!(decode("遥遥领先".as_bytes()), Cow::Borrowed("遥遥领先")));
        assert!(matches!(decode(b""), Cow::Borrowed("")));
    }

    #[test]
    fn decodes_mutf8_specials() {
        assert_eq!(decode(b"a\xC0\x80b"), "a\0b");
        // U+1F600 as a surrogate pair D83D DE00, each 3-byte encoded.
        assert_eq!(decode(b"\xED\xA0\xBD\xED\xB8\x80"), "\u{1F600}");
        // Unpaired surrogate and stray bytes become U+FFFD.
        assert_eq!(decode(b"\xED\xA0\xBDx"), "\u{FFFD}x");
        assert_eq!(decode(b"\xFFok\xC3"), "\u{FFFD}ok\u{FFFD}");
        assert_eq!(decode(b"\xE4\xB8"), "\u{FFFD}\u{FFFD}");
    }
}
