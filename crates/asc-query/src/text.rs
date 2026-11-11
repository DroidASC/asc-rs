//! The text form of every tool: one record per line, ` | ` between columns,
//! strings of the program in JSON quotes.
//!
//! Strings come from the program under audit, so whatever could break a
//! line or change how it reads is escaped: control characters, the line and
//! paragraph separators, the bidirectional controls that reorder the text
//! around them, and the invisible format characters (zero-width spaces and
//! joiners, the byte order mark, tag characters). A row then shows exactly
//! the code points it holds, and reads back with any JSON parser.

use std::borrow::Cow;
use std::fmt::Write as _;

/// Whether `c` is written as a `\u` escape rather than as itself: a control
/// character, a line or paragraph separator, or a format character
/// (Unicode category Cf: bidirectional controls, zero-width characters,
/// the byte order mark, tag characters, and the rest).
pub fn must_escape(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00ad}'
                | '\u{0600}'..='\u{0605}'
                | '\u{061c}'
                | '\u{06dd}'
                | '\u{070f}'
                | '\u{0890}'..='\u{0891}'
                | '\u{08e2}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{206f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{110bd}'
                | '\u{110cd}'
                | '\u{13430}'..='\u{1343f}'
                | '\u{1bca0}'..='\u{1bca3}'
                | '\u{1d173}'..='\u{1d17a}'
                | '\u{e0001}'
                | '\u{e0020}'..='\u{e007f}'
        )
}

/// Append the `\u` escape of `c`: one per UTF-16 unit, as JSON writes a
/// character beyond the BMP.
pub fn push_unicode_escape(out: &mut String, c: char) {
    for unit in c.encode_utf16(&mut [0; 2]) {
        // Writing to a String cannot fail.
        let _ = write!(out, "\\u{unit:04x}");
    }
}

/// Append `s` in double quotes, escaped as JSON does (`\"`, `\\`, `\n`,
/// `\t`, `\r`) and every other character [`must_escape`] names as `\uXXXX`,
/// so it stays on one line and shows what it holds.
pub fn quote_into(out: &mut String, s: &str) {
    out.reserve(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if must_escape(c) => push_unicode_escape(out, c),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `s` in double quotes ([`quote_into`]).
pub fn quoted(s: &str) -> String {
    let mut out = String::new();
    quote_into(&mut out, s);
    out
}

/// The value of a `key=value` pair: as it is, or [`quoted`] when it is empty
/// or holds whitespace, a quote, a backslash, `=` or a character
/// [`must_escape`] names, which would otherwise blur where the pair ends or
/// what it says.
pub fn value(s: &str) -> Cow<'_, str> {
    let plain = !s.is_empty() && !s.chars().any(|c| c.is_whitespace() || must_escape(c) || matches!(c, '"' | '\\' | '='));
    if plain { Cow::Borrowed(s) } else { Cow::Owned(quoted(s)) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_strings_stay_on_one_line_and_parse_as_json() {
        let raw = "a\"b\\c\nd\te\r\u{1b}\u{7f}\u{85}é😀";
        let q = quoted(raw);
        assert_eq!(q, r#""a\"b\\c\nd\te\r\u001b\u007f\u0085é😀""#);
        assert_eq!(serde_json::from_str::<String>(&q).unwrap(), raw);
    }

    #[test]
    fn characters_that_disguise_a_row_are_escaped() {
        // Right-to-left override, isolates, zero-width space and joiner, BOM,
        // the line separator and a tag character.
        let raw = "pay\u{202e}lmth.exe\u{2066}x\u{2069}\u{200b}\u{200d}\u{feff}\u{2028}\u{e0041}";
        let q = quoted(raw);
        assert_eq!(q, r#""pay\u202elmth.exe\u2066x\u2069\u200b\u200d\ufeff\u2028\udb40\udc41""#);
        assert_eq!(serde_json::from_str::<String>(&q).unwrap(), raw);
        assert!(q.is_ascii());
        // Visible text of any script stays as it is.
        assert_eq!(quoted("登录 مرحبا ñ"), "\"登录 مرحبا ñ\"");
        for c in ['\u{2066}', '\u{2069}', '\u{202a}', '\u{200e}', '\u{061c}', '\u{00ad}', '\u{2060}'] {
            assert!(must_escape(c), "{:04x}", u32::from(c));
        }
        for c in ['a', ' ', '\u{a0}', '\u{2010}', '\u{2030}', '中'] {
            assert!(!must_escape(c), "{:04x}", u32::from(c));
        }
    }

    #[test]
    fn values_are_quoted_only_when_ambiguous() {
        assert_eq!(value("com.demo.Main"), "com.demo.Main");
        assert_eq!(value("signature|privileged"), "signature|privileged");
        assert_eq!(value("1.0 beta"), r#""1.0 beta""#);
        assert_eq!(value("a=b"), r#""a=b""#);
        assert_eq!(value(""), r#""""#);
        assert_eq!(value("a\u{200b}b"), r#""a\u200bb""#);
    }
}
