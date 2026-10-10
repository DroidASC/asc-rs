//! Modified UTF-8 (MUTF-8) decoding as used by DEX string data.
//!
//! MUTF-8 differs from UTF-8 in two ways: `U+0000` is encoded as `C0 80`, and
//! supplementary characters are stored as two 3-byte encoded UTF-16 surrogates
//! (CESU-8 style). Decoding therefore works on UTF-16 code units.

/// Iterator over the UTF-16 code units of MUTF-8 bytes. Invalid sequences
/// produce `U+FFFD` for the offending byte and continue.
#[derive(Debug, Clone)]
pub struct Units<'a> {
    bytes: &'a [u8],
    i: usize,
    /// Low surrogate still owed for a 4-byte sequence.
    pending: Option<u16>,
}

impl<'a> Units<'a> {
    #[inline]
    pub fn new(bytes: &'a [u8]) -> Units<'a> {
        Units { bytes, i: 0, pending: None }
    }
}

impl Iterator for Units<'_> {
    type Item = u16;

    #[inline]
    fn next(&mut self) -> Option<u16> {
        if let Some(low) = self.pending.take() {
            return Some(low);
        }
        let (bytes, i) = (self.bytes, self.i);
        let b0 = *bytes.get(i)?;
        let cont = |k: usize| bytes.get(i + k).copied().filter(|b| b & 0xC0 == 0x80);
        let (unit, len) = if b0 < 0x80 {
            (b0 as u16, 1)
        } else if b0 & 0xE0 == 0xC0 {
            match cont(1) {
                Some(b1) => ((((b0 & 0x1F) as u16) << 6) | (b1 & 0x3F) as u16, 2),
                None => (0xFFFD, 1),
            }
        } else if b0 & 0xF0 == 0xE0 {
            match (cont(1), cont(2)) {
                (Some(b1), Some(b2)) => ((((b0 & 0x0F) as u16) << 12) | (((b1 & 0x3F) as u16) << 6) | (b2 & 0x3F) as u16, 3),
                _ => (0xFFFD, 1),
            }
        } else if b0 & 0xF8 == 0xF0 {
            // Plain UTF-8 4-byte sequence; not valid MUTF-8 but tolerate it.
            match (cont(1), cont(2), cont(3)) {
                (Some(b1), Some(b2), Some(b3)) => {
                    let cp = (((b0 & 0x07) as u32) << 18) | (((b1 & 0x3F) as u32) << 12) | (((b2 & 0x3F) as u32) << 6) | (b3 & 0x3F) as u32;
                    match char::from_u32(cp) {
                        Some(c) => {
                            let mut buf = [0u16; 2];
                            let units = c.encode_utf16(&mut buf);
                            self.pending = units.get(1).copied();
                            (units[0], 4)
                        }
                        None => (0xFFFD, 4),
                    }
                }
                _ => (0xFFFD, 1),
            }
        } else {
            (0xFFFD, 1)
        };
        self.i = i + len;
        Some(unit)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let rest = self.bytes.len().saturating_sub(self.i);
        let pending = self.pending.is_some() as usize;
        (rest.div_ceil(4) + pending, Some(rest + pending))
    }
}

/// Decode MUTF-8 bytes into UTF-16 code units. Invalid sequences produce
/// `U+FFFD` for the offending byte and continue.
pub fn to_utf16(bytes: &[u8]) -> Vec<u16> {
    let mut out = Vec::with_capacity(bytes.len());
    out.extend(Units::new(bytes));
    out
}

/// Compare two MUTF-8 strings by their UTF-16 code units, the order DEX
/// string tables are sorted in (ART's
/// `CompareModifiedUtf8ToModifiedUtf8AsUtf16CodePointValues`). Plain byte
/// order agrees except for `U+0000` (`C0 80`), which must sort first.
/// Allocation-free; only the code units from the first differing sequence
/// on are decoded.
pub fn cmp_utf16(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    let Some(mut i) = a.iter().zip(b).position(|(x, y)| x != y) else {
        return a.len().cmp(&b.len());
    };
    // Back up to the start of the sequence holding the first difference;
    // everything before `i` is shared.
    let is_cont = |s: &[u8], k: usize| s.get(k).is_some_and(|c| c & 0xC0 == 0x80);
    while i > 0 && (is_cont(a, i) || is_cont(b, i)) {
        i -= 1;
    }
    Units::new(&a[i..]).cmp(Units::new(&b[i..]))
}

/// Decode MUTF-8 bytes into a Rust string (lossy on unpaired surrogates).
pub fn decode(bytes: &[u8]) -> String {
    if bytes.is_ascii() {
        // Fast path: ASCII MUTF-8 is plain ASCII.
        // SAFETY-free: from_utf8 cannot fail on ASCII input.
        return String::from_utf8_lossy(bytes).into_owned();
    }
    String::from_utf16_lossy(&to_utf16(bytes))
}

/// Encode a Rust string as MUTF-8.
pub fn encode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for unit in s.encode_utf16() {
        encode_unit(&mut out, unit);
    }
    out
}

/// Encode a single UTF-16 code unit as MUTF-8.
#[inline]
pub fn encode_unit(out: &mut Vec<u8>, unit: u16) {
    if unit != 0 && unit < 0x80 {
        out.push(unit as u8);
    } else if unit < 0x800 {
        out.push(0xC0 | (unit >> 6) as u8);
        out.push(0x80 | (unit & 0x3F) as u8);
    } else {
        out.push(0xE0 | (unit >> 12) as u8);
        out.push(0x80 | ((unit >> 6) & 0x3F) as u8);
        out.push(0x80 | (unit & 0x3F) as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_and_nul() {
        assert_eq!(decode(b"hello"), "hello");
        assert_eq!(decode(&[0xC0, 0x80, b'a']), "\0a");
        assert_eq!(encode("\0a"), vec![0xC0, 0x80, b'a']);
    }

    #[test]
    fn surrogate_pairs() {
        let s = "a😀b";
        let enc = encode(s);
        assert_eq!(enc.len(), 1 + 6 + 1);
        assert_eq!(decode(&enc), s);
    }

    #[test]
    fn invalid_and_truncated_sequences_become_replacement_chars() {
        // Lone continuation byte.
        assert_eq!(to_utf16(&[0x80]), vec![0xFFFD]);
        // Two-byte lead with no continuation / truncated at the end.
        assert_eq!(to_utf16(&[0xC3, b'a']), vec![0xFFFD, b'a' as u16]);
        assert_eq!(to_utf16(&[0xC3]), vec![0xFFFD]);
        // Three-byte lead with only one continuation byte.
        assert_eq!(to_utf16(&[0xE2, 0x82]), vec![0xFFFD, 0xFFFD]);
        assert_eq!(to_utf16(&[0xE2, 0x82, b'x']), vec![0xFFFD, 0xFFFD, b'x' as u16]);
        // Four-byte lead truncated after two bytes.
        assert_eq!(to_utf16(&[0xF0, 0x9F, b'!']), vec![0xFFFD, 0xFFFD, b'!' as u16]);
        // Four-byte sequence that is not a valid scalar value (> U+10FFFF).
        assert_eq!(to_utf16(&[0xF7, 0xBF, 0xBF, 0xBF]), vec![0xFFFD]);
        // Bytes that can never start a sequence.
        assert_eq!(to_utf16(&[0xF8, 0xFF]), vec![0xFFFD, 0xFFFD]);
        // Valid text around the damage survives, and `decode` never panics.
        assert_eq!(decode(&[b'a', 0xC3, b'b']), "a\u{FFFD}b");
        assert_eq!(decode(&[0xE2, 0x82, 0xAC, 0xE2]), "\u{20AC}\u{FFFD}");
        // An unpaired surrogate decodes lossily instead of failing.
        assert_eq!(decode(&[0xED, 0xA0, 0x80]), "\u{FFFD}");
    }

    #[test]
    fn utf16_order() {
        use std::cmp::Ordering::*;
        let cmp = |a: &str, b: &str| cmp_utf16(&encode(a), &encode(b));
        // U+0000 sorts below every other unit, though `C0 80` > `/` as bytes.
        assert_eq!(cmp("La\0;", "La/;"), Less);
        assert_eq!(cmp("La/;", "La\0;"), Greater);
        // Surrogate pairs sort below U+E000..U+FFFF, as in UTF-16.
        assert_eq!(cmp("L\u{10000};", "L\u{E000};"), Less);
        // Differences inside a multi-byte sequence, and prefixes.
        assert_eq!(cmp("\u{6E1}", "\u{6E2}"), Less);
        assert_eq!(cmp("x\u{1A7B}y", "x\u{1A7B}z"), Less);
        assert_eq!(cmp("ab", "abc"), Less);
        assert_eq!(cmp("abc", "abc"), Equal);
        // A 4-byte UTF-8 sequence yields the same units as its surrogate pair.
        assert_eq!(Units::new("\u{1F600}".as_bytes()).collect::<Vec<_>>(), "\u{1F600}".encode_utf16().collect::<Vec<_>>());
        // Agrees with comparing the code units on a mixed sample.
        let words = [
            "",
            "\0",
            "a",
            "a\0",
            "ab",
            "\u{7F}",
            "\u{80}",
            "\u{7FF}",
            "\u{800}",
            "\u{D7FF}",
            "\u{E000}",
            "\u{FFFF}",
            "\u{10000}",
            "\u{10FFFF}",
        ];
        for x in words {
            for y in words {
                assert_eq!(cmp(x, y), x.encode_utf16().cmp(y.encode_utf16()), "{x:?} vs {y:?}");
            }
        }
    }
}
