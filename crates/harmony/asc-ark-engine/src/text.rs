//! The text form of result rows: one record per line, ` | ` between columns,
//! strings quoted and escaped as on the DEX side ([`asc_query::text`]).

use std::borrow::Cow;
use std::fmt::Write as _;

pub use asc_query::text::{quote_into, quoted, value};

/// Most bytes of one string a result row shows: the limit of a string
/// literal in a listing.
pub const ROW_STRING_BYTES: usize = asc_pasm::Options::DEFAULT_STRING_LIMIT;
/// Bytes shown on each side of a match that lies beyond the part of a long
/// string a row shows.
const MATCH_CONTEXT_BYTES: usize = 96;
/// Most bytes of the match itself shown there.
const MATCH_SHOWN_BYTES: usize = 160;

/// The largest index up to `at` that is a character boundary of `text`.
fn floor_boundary(text: &str, at: usize) -> usize {
    let mut at = at.min(text.len());
    while !text.is_char_boundary(at) {
        at -= 1;
    }
    at
}

/// The smallest index from `at` on that is a character boundary of `text`.
fn ceil_boundary(text: &str, at: usize) -> usize {
    let mut at = at.min(text.len());
    while !text.is_char_boundary(at) {
        at += 1;
    }
    at
}

/// The bytes of `text` that [`quoted_cut`] shows under `limit`.
pub(crate) fn shown_bytes(text: &str, limit: usize) -> usize {
    floor_boundary(text, limit)
}

/// `text` in quotes on one line, at most `limit` bytes of it (cut back to a
/// character boundary), what was dropped counted after the closing quote:
/// `"abc"… (+120 bytes)`, as a listing cuts a string literal.
pub(crate) fn quoted_cut(text: &str, limit: usize) -> String {
    let end = shown_bytes(text, limit);
    let mut out = quoted(&text[..end]);
    if end < text.len() {
        // Writing to a String cannot fail.
        let _ = write!(out, "… (+{} bytes)", text.len() - end);
    }
    out
}

/// `text` as it is, or its first `limit` bytes and the count of the rest:
/// `abc… (+120 bytes)`. For values that are not shown in quotes (JSON).
pub fn cut(text: &str, limit: usize) -> Cow<'_, str> {
    let end = shown_bytes(text, limit);
    if end == text.len() { Cow::Borrowed(text) } else { Cow::Owned(format!("{}… (+{} bytes)", &text[..end], text.len() - end)) }
}

/// Where a match lies in a string too long to show whole, with the text
/// around it: `match at byte 51234: …"token=abc"…`. A `…` says that the
/// string goes on at that side.
pub(crate) fn match_excerpt(text: &str, matched: std::ops::Range<usize>) -> String {
    let start = floor_boundary(text, matched.start.saturating_sub(MATCH_CONTEXT_BYTES));
    let shown = matched.end.min(matched.start.saturating_add(MATCH_SHOWN_BYTES));
    let end = ceil_boundary(text, shown.saturating_add(MATCH_CONTEXT_BYTES));
    let mut out = format!("match at byte {}: ", matched.start);
    if start > 0 {
        out.push('…');
    }
    quote_into(&mut out, &text[start..end]);
    if end < text.len() {
        out.push('…');
    }
    out
}

/// The [`match_excerpt`] of a match (`matched`, a byte range of `text`)
/// that starts beyond the [`ROW_STRING_BYTES`] a row shows of `text`;
/// `None` when the match is in the part shown.
pub(crate) fn excerpt_beyond(text: &str, matched: Option<std::ops::Range<usize>>) -> Option<String> {
    let matched = matched.filter(|matched| matched.start >= shown_bytes(text, ROW_STRING_BYTES))?;
    Some(match_excerpt(text, matched))
}

/// A matched string for a result row: [`quoted_cut`] under
/// [`ROW_STRING_BYTES`], with the [`excerpt_beyond`] of its match behind it.
pub(crate) fn quoted_match(text: &str, matched: Option<std::ops::Range<usize>>) -> String {
    let mut out = quoted_cut(text, ROW_STRING_BYTES);
    if let Some(excerpt) = excerpt_beyond(text, matched) {
        out.push(' ');
        out.push_str(&excerpt);
    }
    out
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

    #[test]
    fn long_strings_are_cut_and_say_what_is_left_out() {
        assert_eq!(quoted_cut("a中b", 2), "\"a\"… (+4 bytes)");
        assert_eq!(quoted_cut("abc", 3), "\"abc\"");
        assert_eq!(cut("abcdef", 4), "abcd… (+2 bytes)");
        assert!(matches!(cut("abc", 3), Cow::Borrowed("abc")));

        // A string a row shows whole, or whose match is in the part shown, gets no excerpt.
        assert_eq!(quoted_match("see https://x", Some(4..12)), "\"see https://x\"");
        let head = format!("https://x {}", "a".repeat(ROW_STRING_BYTES));
        assert_eq!(quoted_match(&head, Some(0..8)), format!("\"{}\"… (+10 bytes)", &head[..ROW_STRING_BYTES]));
        // A match beyond it is shown with the text around it.
        let long = format!("{}中 token=1 {}", "a".repeat(5000), "b".repeat(5000));
        let at = long.find("token").unwrap();
        let shown = quoted_match(&long, Some(at..at + 7));
        let (cut_head, excerpt) = shown.split_once(" match at byte ").unwrap();
        assert_eq!(cut_head, format!("\"{}\"… (+{} bytes)", "a".repeat(ROW_STRING_BYTES), long.len() - ROW_STRING_BYTES));
        assert_eq!(excerpt, format!("{at}: …\"{}中 token=1 {}\"…", "a".repeat(92), "b".repeat(95)));
        assert!(shown.len() < ROW_STRING_BYTES + 400, "{}", shown.len());
        // At the end of the string nothing follows; a long match is cut too.
        assert!(quoted_match(&long, Some(long.len() - 1..long.len())).ends_with("b\""));
        let whole = match_excerpt(&long, 0..long.len());
        assert!(whole.starts_with("match at byte 0: \"aaa") && whole.ends_with("a\"…") && whole.len() < 400, "{whole}");
    }
}
