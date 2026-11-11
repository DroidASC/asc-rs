//! Leaf formatting: escaped text, numbers, registers and error markers.

use std::fmt::{self, Display, Write};

/// Marks text that was cut short; always followed by what was left out.
pub(crate) const ELLIPSIS: &str = "…";

/// Write the inline marker every failure is reported with. Listings are
/// searched for `<error` to tell whether anything went wrong; a quoted
/// string of the program may hold the same text (one of the samples has
/// `lda.str "<error: "`), so a hit inside quotes says nothing.
pub(crate) fn write_error<W: Write>(out: &mut W, error: impl Display) -> fmt::Result {
    write!(out, "<error: {error}>")
}

/// Write `text` with control characters (and the others
/// [`asc_query::text::must_escape`] names) escaped, so that it stays on one
/// line and shows what it holds. `quoted` text also escapes `"` and `\`.
fn write_escaped<W: Write>(out: &mut W, text: &str, quoted: bool) -> fmt::Result {
    // Runs of ordinary characters are written in one piece.
    let mut plain_from = 0;
    for (at, c) in text.char_indices() {
        let escape = match c {
            '"' if quoted => "\\\"",
            '\\' if quoted => "\\\\",
            '\n' => "\\n",
            '\r' => "\\r",
            '\t' => "\\t",
            // Also the line and paragraph separators, which break lines in
            // many viewers, and the characters that hide or reorder text.
            c if asc_query::text::must_escape(c) => "",
            _ => continue,
        };
        out.write_str(&text[plain_from..at])?;
        if escape.is_empty() {
            // One escape per UTF-16 unit, as JSON writes a character beyond the BMP.
            for unit in c.encode_utf16(&mut [0; 2]) {
                write!(out, "\\u{unit:04x}")?;
            }
        } else {
            out.write_str(escape)?;
        }
        plain_from = at + c.len_utf8();
    }
    out.write_str(&text[plain_from..])
}

/// Write a count with its noun: `1 param`, `2 params`.
pub(crate) fn write_count<W: Write>(out: &mut W, count: u32, noun: &str) -> fmt::Result {
    write!(out, "{count} {noun}{}", if count == 1 { "" } else { "s" })
}

/// Write a name (record, function, import binding) bare: control characters
/// escaped, everything else as is, so that it can be pasted into a query.
pub(crate) fn write_name<W: Write>(out: &mut W, name: &str) -> fmt::Result {
    write_escaped(out, name, false)
}

/// Write a double-quoted string literal. At most `limit` bytes of `text` are
/// shown (cut back to a character boundary); what was dropped is counted
/// after the closing quote: `"abc"… (+120 bytes)`.
pub(crate) fn write_quoted<W: Write>(out: &mut W, text: &str, limit: usize) -> fmt::Result {
    let mut end = limit.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    out.write_char('"')?;
    write_escaped(out, &text[..end], true)?;
    out.write_char('"')?;
    if end < text.len() {
        write!(out, "{ELLIPSIS} (+{} bytes)", text.len() - end)?;
    }
    Ok(())
}

/// Write an integer immediate: one digit as is, anything longer in hex with
/// the decimal value after it, `0x1d4b42 (1919810)`, so that nobody has to
/// convert by hand.
pub(crate) fn write_imm<W: Write>(out: &mut W, value: i64) -> fmt::Result {
    match value {
        -9..=9 => write!(out, "{value}"),
        10.. => write!(out, "{value:#x} ({value})"),
        _ => write!(out, "-{:#x} ({value})", value.unsigned_abs()),
    }
}

/// Write a signed 32-bit constant (`ldai`, `INTEGER` literals). A negative
/// one is shown in decimal with its bit pattern, `-1640531527 (u32
/// 0x9e3779b9)`: that is the form magic constants are recognised by.
pub(crate) fn write_i32<W: Write>(out: &mut W, value: i32) -> fmt::Result {
    match value {
        -9.. => write_imm(out, i64::from(value)),
        _ => write!(out, "{value} (u32 {:#x})", u32::from_le_bytes(value.to_le_bytes())),
    }
}

/// Largest magnitude below which every integral `f64` is exact (2^53).
const F64_EXACT_INTEGER_LIMIT: f64 = 9_007_199_254_740_992.0;

/// Write a double the way JavaScript source would spell it; integral values
/// of two digits or more also get their hex form, `4294967295.0
/// (0xffffffff)`.
pub(crate) fn write_f64<W: Write>(out: &mut W, value: f64) -> fmt::Result {
    if value.is_nan() {
        return out.write_str("NaN");
    }
    if value.is_infinite() {
        return out.write_str(if value > 0.0 { "Infinity" } else { "-Infinity" });
    }
    write!(out, "{value:?}")?;
    if value.fract() == 0.0 && (10.0..F64_EXACT_INTEGER_LIMIT).contains(&value) {
        // Integral and below 2^53: the cast is exact.
        write!(out, " ({:#x})", value as u64)?;
    }
    Ok(())
}

/// Write a single-precision literal value.
pub(crate) fn write_f32<W: Write>(out: &mut W, value: f32) -> fmt::Result {
    write_f64(out, f64::from(value))?;
    out.write_char('f')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(write: impl FnOnce(&mut String) -> fmt::Result) -> String {
        let mut out = String::new();
        write(&mut out).unwrap();
        out
    }

    #[test]
    fn immediates_show_hex_and_decimal() {
        let imm = |v| text(|out| write_imm(out, v));
        assert_eq!(imm(0), "0");
        assert_eq!(imm(9), "9");
        assert_eq!(imm(-9), "-9");
        assert_eq!(imm(10), "0xa (10)");
        assert_eq!(imm(1_919_810), "0x1d4b42 (1919810)");
        assert_eq!(imm(-128), "-0x80 (-128)");
        assert_eq!(imm(i64::from(u32::MAX)), "0xffffffff (4294967295)");
        assert_eq!(imm(i64::MIN), "-0x8000000000000000 (-9223372036854775808)");
        assert_eq!(imm(i64::MAX), "0x7fffffffffffffff (9223372036854775807)");
    }

    #[test]
    fn negative_i32_shows_its_bit_pattern() {
        let int = |v| text(|out| write_i32(out, v));
        assert_eq!(int(1_919_810), "0x1d4b42 (1919810)");
        assert_eq!(int(7), "7");
        assert_eq!(int(-1), "-1");
        assert_eq!(int(-10), "-10 (u32 0xfffffff6)");
        assert_eq!(int(-1_640_531_527), "-1640531527 (u32 0x9e3779b9)");
        assert_eq!(int(i32::MIN), "-2147483648 (u32 0x80000000)");
        assert_eq!(int(i32::MAX), "0x7fffffff (2147483647)");
    }

    #[test]
    fn doubles_read_like_source() {
        let double = |v| text(|out| write_f64(out, v));
        assert_eq!(double(0.0), "0.0");
        assert_eq!(double(-0.0), "-0.0");
        assert_eq!(double(1.5), "1.5");
        assert_eq!(double(9.0), "9.0");
        assert_eq!(double(10.0), "10.0 (0xa)");
        assert_eq!(double(4_294_967_295.0), "4294967295.0 (0xffffffff)");
        assert_eq!(double(-4_294_967_295.0), "-4294967295.0");
        assert_eq!(double(0.1), "0.1");
        assert_eq!(double(1e300), "1e300");
        assert_eq!(double(f64::NAN), "NaN");
        assert_eq!(double(f64::INFINITY), "Infinity");
        assert_eq!(double(f64::NEG_INFINITY), "-Infinity");
        assert_eq!(text(|out| write_f32(out, 2.5)), "2.5f");
    }

    #[test]
    fn strings_are_quoted_and_escaped() {
        let quoted = |s: &str| text(|out| write_quoted(out, s, usize::MAX));
        assert_eq!(quoted(""), r#""""#);
        assert_eq!(quoted("plain text"), r#""plain text""#);
        assert_eq!(quoted("say \"hi\"\\"), r#""say \"hi\"\\""#);
        assert_eq!(quoted("a\nb\rc\td"), r#""a\nb\rc\td""#);
        assert_eq!(quoted("\0\u{1b}[0m\u{7f}"), r#""\u0000\u001b[0m\u007f""#);
        assert_eq!(quoted("x\u{2028}y\u{85}"), r#""x\u2028y\u0085""#);
        assert_eq!(quoted("中文 ✓ 😀"), "\"中文 ✓ 😀\"");
        // A string cannot fake a comment or an error marker on its own line.
        assert_eq!(quoted("\n; <error: x>").lines().count(), 1);
    }

    #[test]
    fn long_strings_are_cut_at_a_character_boundary() {
        let cut = |s: &str, limit| text(|out| write_quoted(out, s, limit));
        assert_eq!(cut("abcdef", 6), r#""abcdef""#);
        assert_eq!(cut("abcdef", 4), "\"abcd\"… (+2 bytes)");
        assert_eq!(cut("abcdef", 0), "\"\"… (+6 bytes)");
        // `中` is three bytes: a cut inside it backs up to its start.
        assert_eq!(cut("a中b", 2), "\"a\"… (+4 bytes)");
        assert_eq!(cut("a中b", 4), "\"a中\"… (+1 bytes)");
    }

    #[test]
    fn names_stay_bare_and_on_one_line() {
        let name = |s: &str| text(|out| write_name(out, s));
        assert_eq!(name("#~@0>#build"), "#~@0>#build");
        assert_eq!(name("a\"b\\c"), "a\"b\\c");
        assert_eq!(name("two\nlines"), "two\\nlines");
        assert_eq!(text(|out| write_error(out, "boom")), "<error: boom>");
    }
}
