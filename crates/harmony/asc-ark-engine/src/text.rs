//! The text form of result rows: one record per line, ` | ` between columns,
//! strings quoted and escaped as JSON does. Same conventions as the DEX
//! engine's `text` module.

use std::borrow::Cow;
use std::fmt::Write as _;

/// Append `s` in double quotes, escaped so it stays on one line.
pub fn quote_into(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => {
                // Writing to a String cannot fail.
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `s` in double quotes, escaped so it stays on one line.
pub fn quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    quote_into(&mut out, s);
    out
}

/// The value of a `key=value` pair: as it is, or [`quoted`] when it is empty
/// or holds whitespace, a quote, a backslash, `=` or a control character,
/// which would otherwise blur where the pair ends.
pub fn value(s: &str) -> Cow<'_, str> {
    let plain = !s.is_empty() && !s.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\\' | '='));
    if plain {
        Cow::Borrowed(s)
    } else {
        Cow::Owned(quoted(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_stay_on_one_line() {
        assert_eq!(quoted("a\"b\\c\nd\te\r\u{1b}é"), r#""a\"b\\c\nd\te\r\u001bé""#);
        assert_eq!(value("entry/src/main/ets/pages/Index.ets"), "entry/src/main/ets/pages/Index.ets");
        assert_eq!(value("a b"), r#""a b""#);
        assert_eq!(value(""), r#""""#);
    }
}
