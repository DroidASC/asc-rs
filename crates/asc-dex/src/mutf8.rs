//! Modified UTF-8 (MUTF-8) decoding as used by DEX string data.
//!
//! MUTF-8 differs from UTF-8 in two ways: `U+0000` is encoded as `C0 80`, and
//! supplementary characters are stored as two 3-byte encoded UTF-16 surrogates
//! (CESU-8 style). Decoding therefore works on UTF-16 code units.

/// Decode MUTF-8 bytes into UTF-16 code units. Invalid sequences produce
/// `U+FFFD` for the offending byte and continue.
pub fn to_utf16(bytes: &[u8]) -> Vec<u16> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i];
        if b0 < 0x80 {
            out.push(b0 as u16);
            i += 1;
        } else if b0 & 0xE0 == 0xC0 {
            match bytes.get(i + 1) {
                Some(&b1) if b1 & 0xC0 == 0x80 => {
                    out.push((((b0 & 0x1F) as u16) << 6) | (b1 & 0x3F) as u16);
                    i += 2;
                }
                _ => {
                    out.push(0xFFFD);
                    i += 1;
                }
            }
        } else if b0 & 0xF0 == 0xE0 {
            match (bytes.get(i + 1), bytes.get(i + 2)) {
                (Some(&b1), Some(&b2)) if b1 & 0xC0 == 0x80 && b2 & 0xC0 == 0x80 => {
                    out.push((((b0 & 0x0F) as u16) << 12) | (((b1 & 0x3F) as u16) << 6) | (b2 & 0x3F) as u16);
                    i += 3;
                }
                _ => {
                    out.push(0xFFFD);
                    i += 1;
                }
            }
        } else if b0 & 0xF8 == 0xF0 {
            // Plain UTF-8 4-byte sequence; not valid MUTF-8 but tolerate it.
            match (bytes.get(i + 1), bytes.get(i + 2), bytes.get(i + 3)) {
                (Some(&b1), Some(&b2), Some(&b3)) if b1 & 0xC0 == 0x80 && b2 & 0xC0 == 0x80 && b3 & 0xC0 == 0x80 => {
                    let cp = (((b0 & 0x07) as u32) << 18) | (((b1 & 0x3F) as u32) << 12) | (((b2 & 0x3F) as u32) << 6) | (b3 & 0x3F) as u32;
                    if let Some(c) = char::from_u32(cp) {
                        let mut buf = [0u16; 2];
                        out.extend_from_slice(c.encode_utf16(&mut buf));
                    } else {
                        out.push(0xFFFD);
                    }
                    i += 4;
                }
                _ => {
                    out.push(0xFFFD);
                    i += 1;
                }
            }
        } else {
            out.push(0xFFFD);
            i += 1;
        }
    }
    out
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
}
