//! Textual rendering of descriptors, literals and encoded values.

use crate::Result;
use asc_dex::encoded::{EncodedValue, VALUE_BYTE, VALUE_CHAR, VALUE_DOUBLE, VALUE_FLOAT, VALUE_INT, VALUE_LONG, VALUE_SHORT};
use asc_dex::Dex;

/// Escape a string for a smali string literal.
pub fn escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// `(params)ret` for a proto index.
pub fn proto_descriptor(dex: &Dex<'_>, proto_idx: u32) -> Result<String> {
    let id = dex.proto_id(proto_idx)?;
    let mut s = String::from("(");
    for p in dex.type_list(id.parameters_off)? {
        s.push_str(&dex.type_descriptor(p as u32)?);
    }
    s.push(')');
    s.push_str(&dex.type_descriptor(id.return_type_idx)?);
    Ok(s)
}

/// `Lcls;->name(params)ret` for a method index.
pub fn method_signature(dex: &Dex<'_>, method_idx: u32) -> Result<String> {
    let id = dex.method_id(method_idx)?;
    Ok(format!(
        "{}->{}{}",
        dex.type_descriptor(id.class_idx as u32)?,
        dex.string(id.name_idx)?,
        proto_descriptor(dex, id.proto_idx as u32)?
    ))
}

/// `Lcls;->name:type` for a field index.
pub fn field_signature(dex: &Dex<'_>, field_idx: u32) -> Result<String> {
    let id = dex.field_id(field_idx)?;
    Ok(format!("{}->{}:{}", dex.type_descriptor(id.class_idx as u32)?, dex.string(id.name_idx)?, dex.type_descriptor(id.type_idx as u32)?))
}

/// Signed hex literal (`0x1a`, `-0x1a`).
pub fn hex_i64(v: i64) -> String {
    if v < 0 {
        format!("-0x{:x}", (v as i128).unsigned_abs())
    } else {
        format!("0x{v:x}")
    }
}

fn float_literal(f: f32) -> String {
    if f.is_nan() {
        "NaNf".into()
    } else if f.is_infinite() {
        if f > 0.0 {
            "Infinityf".into()
        } else {
            "-Infinityf".into()
        }
    } else if f.fract() == 0.0 && f.abs() < 1e16 {
        format!("{f:.1}f")
    } else {
        format!("{f}f")
    }
}

fn double_literal(f: f64) -> String {
    if f.is_nan() {
        "NaN".into()
    } else if f.is_infinite() {
        if f > 0.0 {
            "Infinity".into()
        } else {
            "-Infinity".into()
        }
    } else if f.fract() == 0.0 && f.abs() < 1e16 {
        format!("{f:.1}")
    } else {
        format!("{f}")
    }
}

/// Render an encoded value on one line (arrays/annotations use `depth`).
pub fn value(dex: &Dex<'_>, v: &EncodedValue) -> Result<String> {
    value_indented(dex, v, 0)
}

pub fn value_indented(dex: &Dex<'_>, v: &EncodedValue, depth: usize) -> Result<String> {
    Ok(match v {
        EncodedValue::Primitive { kind, .. } => match *kind {
            VALUE_BYTE => format!("{}t", hex_i64(v.as_i64().unwrap_or(0))),
            VALUE_SHORT => format!("{}s", hex_i64(v.as_i64().unwrap_or(0))),
            VALUE_CHAR => {
                let c = v.as_i64().unwrap_or(0) as u32;
                match char::from_u32(c) {
                    Some(ch) if (0x20..0x7f).contains(&c) && ch != '\'' && ch != '\\' => format!("'{ch}'"),
                    _ => format!("'\\u{c:04x}'"),
                }
            }
            VALUE_INT => hex_i64(v.as_i64().unwrap_or(0)),
            VALUE_LONG => format!("{}L", hex_i64(v.as_i64().unwrap_or(0))),
            VALUE_FLOAT => float_literal(v.as_f32().unwrap_or(0.0)),
            VALUE_DOUBLE => double_literal(v.as_f64().unwrap_or(0.0)),
            k => format!("<unknown value type {k:#x}>"),
        },
        EncodedValue::MethodType(p) => proto_descriptor(dex, *p)?,
        EncodedValue::MethodHandle(h) => format!("method_handle@{h}"),
        EncodedValue::String(s) => format!("\"{}\"", escape_string(&dex.string(*s)?)),
        EncodedValue::Type(t) => dex.type_descriptor(*t)?,
        EncodedValue::Field(f) => field_signature(dex, *f)?,
        EncodedValue::Method(m) => method_signature(dex, *m)?,
        EncodedValue::Enum(f) => format!(".enum {}", field_signature(dex, *f)?),
        EncodedValue::Null => "null".into(),
        EncodedValue::Boolean(b) => {
            if *b {
                "true".into()
            } else {
                "false".into()
            }
        }
        EncodedValue::Array(items) => {
            let indent = "    ".repeat(depth);
            let mut s = String::from("{\n");
            for (i, item) in items.iter().enumerate() {
                s.push_str(&indent);
                s.push_str("    ");
                s.push_str(&value_indented(dex, item, depth + 1)?);
                if i + 1 < items.len() {
                    s.push(',');
                }
                s.push('\n');
            }
            s.push_str(&indent);
            s.push('}');
            s
        }
        EncodedValue::Annotation(ann) => {
            let indent = "    ".repeat(depth);
            let mut s = format!(".subannotation {}\n", dex.type_descriptor(ann.type_idx)?);
            for (name, val) in &ann.elements {
                s.push_str(&indent);
                s.push_str("    ");
                s.push_str(&dex.string(*name)?);
                s.push_str(" = ");
                s.push_str(&value_indented(dex, val, depth + 1)?);
                s.push('\n');
            }
            s.push_str(&indent);
            s.push_str(".end subannotation");
            s
        }
    })
}
