//! `encoded_value`, `encoded_array` and `encoded_annotation` parsing/serialisation.

use crate::leb128::{read_uleb128, write_uleb128};
use crate::{DexError, Result};

pub const VALUE_BYTE: u8 = 0x00;
pub const VALUE_SHORT: u8 = 0x02;
pub const VALUE_CHAR: u8 = 0x03;
pub const VALUE_INT: u8 = 0x04;
pub const VALUE_LONG: u8 = 0x06;
pub const VALUE_FLOAT: u8 = 0x10;
pub const VALUE_DOUBLE: u8 = 0x11;
pub const VALUE_METHOD_TYPE: u8 = 0x15;
pub const VALUE_METHOD_HANDLE: u8 = 0x16;
pub const VALUE_STRING: u8 = 0x17;
pub const VALUE_TYPE: u8 = 0x18;
pub const VALUE_FIELD: u8 = 0x19;
pub const VALUE_METHOD: u8 = 0x1a;
pub const VALUE_ENUM: u8 = 0x1b;
pub const VALUE_ARRAY: u8 = 0x1c;
pub const VALUE_ANNOTATION: u8 = 0x1d;
pub const VALUE_NULL: u8 = 0x1e;
pub const VALUE_BOOLEAN: u8 = 0x1f;

/// Decoded `encoded_value`.
#[derive(Debug, Clone, PartialEq)]
pub enum EncodedValue {
    /// Numeric primitive kept in its raw little-endian form (`kind` is the
    /// value type, `raw` has `value_arg + 1` bytes).
    Primitive {
        kind: u8,
        raw: Vec<u8>,
    },
    MethodType(u32),
    MethodHandle(u32),
    String(u32),
    Type(u32),
    Field(u32),
    Method(u32),
    Enum(u32),
    Array(Vec<EncodedValue>),
    Annotation(EncodedAnnotation),
    Null,
    Boolean(bool),
}

/// Decoded `encoded_annotation`.
#[derive(Debug, Clone, PartialEq)]
pub struct EncodedAnnotation {
    pub type_idx: u32,
    /// `(name string idx, value)` pairs.
    pub elements: Vec<(u32, EncodedValue)>,
}

/// `annotation_item`.
#[derive(Debug, Clone, PartialEq)]
pub struct AnnotationItem {
    pub visibility: u8,
    pub annotation: EncodedAnnotation,
}

pub const VISIBILITY_BUILD: u8 = 0;
pub const VISIBILITY_RUNTIME: u8 = 1;
pub const VISIBILITY_SYSTEM: u8 = 2;

impl EncodedValue {
    /// Sign-extended integer view of `Primitive` byte/short/int/long values
    /// (char is zero-extended). Returns `None` for other variants.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            EncodedValue::Primitive { kind, raw } => match *kind {
                VALUE_BYTE | VALUE_SHORT | VALUE_INT | VALUE_LONG => {
                    let mut v: i64 = 0;
                    for (i, &b) in raw.iter().enumerate() {
                        v |= (b as i64) << (8 * i);
                    }
                    let bits = 8 * raw.len() as u32;
                    if bits < 64 {
                        let shift = 64 - bits;
                        v = (v << shift) >> shift;
                    }
                    Some(v)
                }
                VALUE_CHAR => {
                    let mut v: i64 = 0;
                    for (i, &b) in raw.iter().enumerate() {
                        v |= (b as i64) << (8 * i);
                    }
                    Some(v)
                }
                _ => None,
            },
            EncodedValue::Boolean(b) => Some(*b as i64),
            _ => None,
        }
    }

    /// Float value (float and double are stored left-justified, zero-extended
    /// to the right).
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            EncodedValue::Primitive { kind, raw } if *kind == VALUE_FLOAT => {
                let mut bytes = [0u8; 4];
                let start = 4 - raw.len().min(4);
                bytes[start..].copy_from_slice(&raw[..raw.len().min(4)]);
                Some(f32::from_le_bytes(bytes) as f64)
            }
            EncodedValue::Primitive { kind, raw } if *kind == VALUE_DOUBLE => {
                let mut bytes = [0u8; 8];
                let start = 8 - raw.len().min(8);
                bytes[start..].copy_from_slice(&raw[..raw.len().min(8)]);
                Some(f64::from_le_bytes(bytes))
            }
            _ => None,
        }
    }

    pub fn as_f32(&self) -> Option<f32> {
        match self {
            EncodedValue::Primitive { kind, .. } if *kind == VALUE_FLOAT => self.as_f64().map(|v| v as f32),
            _ => None,
        }
    }

    /// Value type code.
    pub fn kind(&self) -> u8 {
        match self {
            EncodedValue::Primitive { kind, .. } => *kind,
            EncodedValue::MethodType(_) => VALUE_METHOD_TYPE,
            EncodedValue::MethodHandle(_) => VALUE_METHOD_HANDLE,
            EncodedValue::String(_) => VALUE_STRING,
            EncodedValue::Type(_) => VALUE_TYPE,
            EncodedValue::Field(_) => VALUE_FIELD,
            EncodedValue::Method(_) => VALUE_METHOD,
            EncodedValue::Enum(_) => VALUE_ENUM,
            EncodedValue::Array(_) => VALUE_ARRAY,
            EncodedValue::Annotation(_) => VALUE_ANNOTATION,
            EncodedValue::Null => VALUE_NULL,
            EncodedValue::Boolean(_) => VALUE_BOOLEAN,
        }
    }
}

/// Maximum nesting of arrays / annotations inside an `encoded_value`. Real
/// DEX files nest a handful of levels; the cap keeps a hostile file from
/// overflowing the stack (each level recurses through `parse_value`).
pub const MAX_NESTING: usize = 64;

/// Parse one `encoded_value` at `pos`. Returns `(value, bytes consumed)`.
pub fn parse_value(buf: &[u8], pos: usize) -> Result<(EncodedValue, usize)> {
    parse_value_at(buf, pos, 0)
}

fn parse_value_at(buf: &[u8], pos: usize, depth: usize) -> Result<(EncodedValue, usize)> {
    let header = *buf.get(pos).ok_or(DexError::Truncated { what: "encoded_value", offset: pos })?;
    let kind = header & 0x1f;
    let arg = (header >> 5) as usize;
    let mut p = pos + 1;
    let read_idx = |p: &mut usize| -> Result<u32> {
        let size = arg + 1;
        let bytes = buf.get(*p..*p + size).ok_or(DexError::Truncated { what: "encoded_value.idx", offset: *p })?;
        let mut v = 0u32;
        for (i, &b) in bytes.iter().enumerate().take(4) {
            v |= (b as u32) << (8 * i);
        }
        *p += size;
        Ok(v)
    };
    let value = match kind {
        VALUE_METHOD_TYPE => EncodedValue::MethodType(read_idx(&mut p)?),
        VALUE_METHOD_HANDLE => EncodedValue::MethodHandle(read_idx(&mut p)?),
        VALUE_STRING => EncodedValue::String(read_idx(&mut p)?),
        VALUE_TYPE => EncodedValue::Type(read_idx(&mut p)?),
        VALUE_FIELD => EncodedValue::Field(read_idx(&mut p)?),
        VALUE_METHOD => EncodedValue::Method(read_idx(&mut p)?),
        VALUE_ENUM => EncodedValue::Enum(read_idx(&mut p)?),
        VALUE_ARRAY => {
            let (items, n) = parse_array_at(buf, p, depth + 1)?;
            p += n;
            EncodedValue::Array(items)
        }
        VALUE_ANNOTATION => {
            let (ann, n) = parse_annotation_at(buf, p, depth + 1)?;
            p += n;
            EncodedValue::Annotation(ann)
        }
        VALUE_NULL => EncodedValue::Null,
        VALUE_BOOLEAN => EncodedValue::Boolean(arg != 0),
        _ => {
            let size = arg + 1;
            let raw = buf.get(p..p + size).ok_or(DexError::Truncated { what: "encoded_value.primitive", offset: p })?.to_vec();
            p += size;
            EncodedValue::Primitive { kind, raw }
        }
    };
    Ok((value, p - pos))
}

/// Parse an `encoded_array` (uleb128 size followed by values).
pub fn parse_array(buf: &[u8], pos: usize) -> Result<(Vec<EncodedValue>, usize)> {
    parse_array_at(buf, pos, 0)
}

fn check_depth(what: &'static str, pos: usize, depth: usize) -> Result<()> {
    if depth > MAX_NESTING {
        return Err(DexError::Malformed { what, offset: pos, reason: "nesting too deep" });
    }
    Ok(())
}

fn parse_array_at(buf: &[u8], pos: usize, depth: usize) -> Result<(Vec<EncodedValue>, usize)> {
    check_depth("encoded_array", pos, depth)?;
    let (size, n) = read_uleb128(buf, pos)?;
    let mut p = pos + n;
    let mut out = Vec::with_capacity(size.min(256) as usize);
    for _ in 0..size {
        let (v, n) = parse_value_at(buf, p, depth)?;
        p += n;
        out.push(v);
    }
    Ok((out, p - pos))
}

/// Parse an `encoded_annotation`.
pub fn parse_annotation(buf: &[u8], pos: usize) -> Result<(EncodedAnnotation, usize)> {
    parse_annotation_at(buf, pos, 0)
}

fn parse_annotation_at(buf: &[u8], pos: usize, depth: usize) -> Result<(EncodedAnnotation, usize)> {
    check_depth("encoded_annotation", pos, depth)?;
    let (type_idx, n) = read_uleb128(buf, pos)?;
    let mut p = pos + n;
    let (size, n) = read_uleb128(buf, p)?;
    p += n;
    let mut elements = Vec::with_capacity(size.min(64) as usize);
    for _ in 0..size {
        let (name_idx, n) = read_uleb128(buf, p)?;
        p += n;
        let (v, n) = parse_value_at(buf, p, depth)?;
        p += n;
        elements.push((name_idx, v));
    }
    Ok((EncodedAnnotation { type_idx, elements }, p - pos))
}

/// Parse an `annotation_item` at `off`.
pub fn parse_annotation_item(buf: &[u8], off: usize) -> Result<(AnnotationItem, usize)> {
    let visibility = *buf.get(off).ok_or(DexError::Truncated { what: "annotation_item", offset: off })?;
    let (annotation, n) = parse_annotation(buf, off + 1)?;
    Ok((AnnotationItem { visibility, annotation }, n + 1))
}

/// Index remapping used when serialising encoded values into a new DEX.
pub trait IndexRemap {
    fn string(&self, idx: u32) -> u32;
    fn type_(&self, idx: u32) -> u32;
    fn field(&self, idx: u32) -> u32;
    fn method(&self, idx: u32) -> u32;
    fn proto(&self, idx: u32) -> u32 {
        idx
    }
    fn method_handle(&self, idx: u32) -> u32 {
        idx
    }
}

/// Identity remap (serialise with the original indexes).
pub struct Identity;
impl IndexRemap for Identity {
    fn string(&self, idx: u32) -> u32 {
        idx
    }
    fn type_(&self, idx: u32) -> u32 {
        idx
    }
    fn field(&self, idx: u32) -> u32 {
        idx
    }
    fn method(&self, idx: u32) -> u32 {
        idx
    }
}

fn write_idx(out: &mut Vec<u8>, kind: u8, idx: u32) {
    let mut size = 1usize;
    let mut tmp = idx;
    while tmp > 0xff {
        tmp >>= 8;
        size += 1;
    }
    out.push((((size - 1) as u8) << 5) | kind);
    let mut tmp = idx;
    for _ in 0..size {
        out.push((tmp & 0xff) as u8);
        tmp >>= 8;
    }
}

/// Serialise an encoded value with remapped indexes.
pub fn write_value(out: &mut Vec<u8>, value: &EncodedValue, map: &dyn IndexRemap) {
    match value {
        EncodedValue::Primitive { kind, raw } => {
            out.push((((raw.len().max(1) - 1) as u8) << 5) | kind);
            out.extend_from_slice(raw);
        }
        EncodedValue::MethodType(i) => write_idx(out, VALUE_METHOD_TYPE, map.proto(*i)),
        EncodedValue::MethodHandle(i) => write_idx(out, VALUE_METHOD_HANDLE, map.method_handle(*i)),
        EncodedValue::String(i) => write_idx(out, VALUE_STRING, map.string(*i)),
        EncodedValue::Type(i) => write_idx(out, VALUE_TYPE, map.type_(*i)),
        EncodedValue::Field(i) => write_idx(out, VALUE_FIELD, map.field(*i)),
        EncodedValue::Method(i) => write_idx(out, VALUE_METHOD, map.method(*i)),
        EncodedValue::Enum(i) => write_idx(out, VALUE_ENUM, map.field(*i)),
        EncodedValue::Array(items) => {
            out.push(VALUE_ARRAY);
            write_array(out, items, map);
        }
        EncodedValue::Annotation(ann) => {
            out.push(VALUE_ANNOTATION);
            write_annotation(out, ann, map);
        }
        EncodedValue::Null => out.push(VALUE_NULL),
        EncodedValue::Boolean(b) => out.push(((*b as u8) << 5) | VALUE_BOOLEAN),
    }
}

/// Serialise an `encoded_array`.
pub fn write_array(out: &mut Vec<u8>, items: &[EncodedValue], map: &dyn IndexRemap) {
    write_uleb128(out, items.len() as u32);
    for v in items {
        write_value(out, v, map);
    }
}

/// Serialise an `encoded_annotation`.
pub fn write_annotation(out: &mut Vec<u8>, ann: &EncodedAnnotation, map: &dyn IndexRemap) {
    write_uleb128(out, map.type_(ann.type_idx));
    write_uleb128(out, ann.elements.len() as u32);
    for (name, v) in &ann.elements {
        write_uleb128(out, map.string(*name));
        write_value(out, v, map);
    }
}

/// Serialise an `annotation_item`.
pub fn write_annotation_item(out: &mut Vec<u8>, item: &AnnotationItem, map: &dyn IndexRemap) {
    out.push(item.visibility);
    write_annotation(out, &item.annotation, map);
}

/// Visit every string/type/field/method/proto index referenced by a value.
pub fn visit_refs(value: &EncodedValue, visitor: &mut dyn FnMut(RefKind, u32)) {
    match value {
        EncodedValue::Primitive { .. } | EncodedValue::Null | EncodedValue::Boolean(_) => {}
        EncodedValue::MethodType(i) => visitor(RefKind::Proto, *i),
        EncodedValue::MethodHandle(i) => visitor(RefKind::MethodHandle, *i),
        EncodedValue::String(i) => visitor(RefKind::String, *i),
        EncodedValue::Type(i) => visitor(RefKind::Type, *i),
        EncodedValue::Field(i) | EncodedValue::Enum(i) => visitor(RefKind::Field, *i),
        EncodedValue::Method(i) => visitor(RefKind::Method, *i),
        EncodedValue::Array(items) => items.iter().for_each(|v| visit_refs(v, visitor)),
        EncodedValue::Annotation(ann) => visit_annotation_refs(ann, visitor),
    }
}

/// Visit every index referenced by an annotation.
pub fn visit_annotation_refs(ann: &EncodedAnnotation, visitor: &mut dyn FnMut(RefKind, u32)) {
    visitor(RefKind::Type, ann.type_idx);
    for (name, v) in &ann.elements {
        visitor(RefKind::String, *name);
        visit_refs(v, visitor);
    }
}

/// Kinds of index references found in encoded values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefKind {
    String,
    Type,
    Proto,
    Field,
    Method,
    MethodHandle,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_nesting_is_an_error_not_a_stack_overflow() {
        // `[[[[...]]]]`: each level is a one-element array (header 0x1c, arg 0 -> size 1).
        let mut buf = [0x1c, 0x01].repeat(100_000);
        buf.push(0x1e); // innermost VALUE_NULL
        let err = parse_value(&buf, 0).unwrap_err();
        assert!(matches!(err, DexError::Malformed { what: "encoded_array", reason: "nesting too deep", .. }), "{err:?}");
        // Annotations nest through the same path.
        let mut buf = Vec::new();
        for _ in 0..100_000 {
            buf.extend_from_slice(&[0x1d, 0x00, 0x01, 0x00]); // VALUE_ANNOTATION, type 0, one element named 0
        }
        buf.push(0x1e);
        let err = parse_value(&buf, 0).unwrap_err();
        assert!(matches!(err, DexError::Malformed { what: "encoded_annotation", reason: "nesting too deep", .. }), "{err:?}");
        // Moderate nesting (below the cap) still parses.
        let mut buf = [0x1c, 0x01].repeat(MAX_NESTING - 1);
        buf.push(0x1e);
        assert!(parse_value(&buf, 0).is_ok());
    }

    #[test]
    fn roundtrip_values() {
        let values = vec![
            EncodedValue::Primitive { kind: VALUE_INT, raw: vec![0x0b] },
            EncodedValue::Primitive { kind: VALUE_INT, raw: vec![0xff, 0xff] },
            EncodedValue::String(300),
            EncodedValue::Boolean(true),
            EncodedValue::Null,
            EncodedValue::Array(vec![EncodedValue::Type(2), EncodedValue::Field(70000)]),
            EncodedValue::Annotation(EncodedAnnotation { type_idx: 5, elements: vec![(1, EncodedValue::Enum(3))] }),
        ];
        let mut out = Vec::new();
        write_array(&mut out, &values, &Identity);
        let (parsed, n) = parse_array(&out, 0).unwrap();
        assert_eq!(n, out.len());
        assert_eq!(parsed, values);
        assert_eq!(parsed[0].as_i64(), Some(11));
        assert_eq!(parsed[1].as_i64(), Some(-1));
    }
}
