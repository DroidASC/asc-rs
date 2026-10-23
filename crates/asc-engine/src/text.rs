//! The text form shared by every tool: one record per line, `|` between
//! columns, strings quoted and escaped as JSON does ([`asc_arsc::quote`]).

use std::borrow::Cow;

/// `s` in double quotes, escaped so it stays on one line.
pub fn quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    asc_arsc::quote(s, &mut out);
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
    fn quoted_strings_stay_on_one_line_and_parse_as_json() {
        let raw = "a\"b\\c\nd\te\r\u{1b}\u{7f}\u{85}é😀";
        let q = quoted(raw);
        assert_eq!(q, r#""a\"b\\c\nd\te\r\u001b\u007f\u0085é😀""#);
        assert_eq!(serde_json::from_str::<String>(&q).unwrap(), raw);
    }

    #[test]
    fn values_are_quoted_only_when_ambiguous() {
        assert_eq!(value("com.demo.Main"), "com.demo.Main");
        assert_eq!(value("signature|privileged"), "signature|privileged");
        assert_eq!(value("1.0 beta"), r#""1.0 beta""#);
        assert_eq!(value("a=b"), r#""a=b""#);
        assert_eq!(value(""), r#""""#);
    }
}
