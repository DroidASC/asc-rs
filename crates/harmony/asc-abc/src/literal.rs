//! Literal arrays: `u32 num` (twice the number of items) followed by
//! unaligned `(u8 tag, value)` items.

use crate::reader::{Reader, entity_pos, file_off};
use crate::{AbcError, Result};

/// A literal array.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct LiteralArray<'a> {
    buf: &'a [u8],
    off: u32,
    /// The stored count: two per item (the tag and the value each count).
    pub num: u32,
}

impl<'a> LiteralArray<'a> {
    pub(crate) fn parse(buf: &'a [u8], off: u32) -> Result<LiteralArray<'a>> {
        let num = Reader::new(buf, entity_pos(buf, off, "literal array")?).u32()?;
        Ok(LiteralArray { buf, off, num })
    }

    /// File offset of the literal array.
    #[inline]
    pub fn offset(&self) -> u32 {
        self.off
    }

    /// Number of `(tag, value)` items.
    #[inline]
    pub fn len(&self) -> u32 {
        self.num.div_ceil(2)
    }

    /// Whether the array has no items.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.num == 0
    }

    /// The items, in file order.
    pub fn iter(&self) -> Literals<'a> {
        Literals { r: Reader::new(self.buf, self.off as usize + 4), remaining: self.len() }
    }

    /// Item `index`. Items are variable-length, so this walks from the
    /// start.
    ///
    /// # Errors
    /// A malformed item before `index`.
    pub fn get(&self, index: u32) -> Result<Option<Literal>> {
        self.iter().nth(index as usize).transpose()
    }
}

impl<'a> IntoIterator for &LiteralArray<'a> {
    type Item = Result<Literal>;
    type IntoIter = Literals<'a>;

    fn into_iter(self) -> Literals<'a> {
        self.iter()
    }
}

/// Iterator over the items of a literal array.
#[derive(Debug, Clone)]
pub struct Literals<'a> {
    r: Reader<'a>,
    remaining: u32,
}

impl Literals<'_> {
    /// File offset of the next item (after the last one: of the first byte
    /// past the array).
    pub fn offset(&self) -> u32 {
        file_off(self.r.pos())
    }
}

impl Iterator for Literals<'_> {
    type Item = Result<Literal>;

    fn next(&mut self) -> Option<Result<Literal>> {
        if self.remaining == 0 {
            return None;
        }
        let literal = Literal::read(&mut self.r);
        self.remaining = match literal {
            // A typed array takes up the rest of the literal array.
            Ok(Literal::TypedArray { .. }) | Err(_) => 0,
            Ok(_) => self.remaining - 1,
        };
        Some(literal)
    }
}

/// Tag byte values (`LiteralTag`).
pub mod tag {
    /// One-byte tag value (`INTEGER_8`).
    pub const TAGVALUE: u8 = 0x00;
    /// Boolean, one byte.
    pub const BOOL: u8 = 0x01;
    /// Integer, a `u32` read as `i32`.
    pub const INTEGER: u8 = 0x02;
    /// Single-precision float, 4 bytes.
    pub const FLOAT: u8 = 0x03;
    /// Double-precision float, 8 bytes.
    pub const DOUBLE: u8 = 0x04;
    /// Offset of a string.
    pub const STRING: u8 = 0x05;
    /// Offset of a method.
    pub const METHOD: u8 = 0x06;
    /// Offset of a generator method.
    pub const GENERATORMETHOD: u8 = 0x07;
    /// Accessor marker, one byte.
    pub const ACCESSOR: u8 = 0x08;
    /// `u16` formal parameter count of the preceding method.
    pub const METHODAFFILIATE: u8 = 0x09;
    /// First typed-array tag (`u1` elements).
    pub const ARRAY_U1: u8 = 0x0a;
    /// Last typed-array tag (string elements).
    pub const ARRAY_STRING: u8 = 0x15;
    /// Offset of an async generator method.
    pub const ASYNCGENERATORMETHOD: u8 = 0x16;
    /// `u32` literal buffer index.
    pub const LITERALBUFFERINDEX: u8 = 0x17;
    /// Offset of a nested literal array.
    pub const LITERALARRAY: u8 = 0x18;
    /// One-byte builtin type index.
    pub const BUILTINTYPEINDEX: u8 = 0x19;
    /// Offset of a getter method.
    pub const GETTER: u8 = 0x1a;
    /// Offset of a setter method.
    pub const SETTER: u8 = 0x1b;
    /// `u32` offset for an ArkTS `implements` entry.
    pub const ETS_IMPLEMENTS: u8 = 0x1c;
    /// Null, one padding byte.
    pub const NULLVALUE: u8 = 0xff;
}

/// One item of a literal array. Offsets are raw file offsets.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum Literal {
    /// Tag `0x00` (`TAGVALUE` / `INTEGER_8`): one byte.
    TagValue(u8),
    /// Tag `0x01`.
    Bool(bool),
    /// Tag `0x02`.
    Integer(i32),
    /// Tag `0x03`.
    Float(f32),
    /// Tag `0x04`.
    Double(f64),
    /// Offset of a string.
    String(u32),
    /// Offset of a method.
    Method(u32),
    /// Tag `0x07`: offset of a generator method.
    GeneratorMethod(u32),
    /// Tag `0x16`: offset of an async generator method.
    AsyncGeneratorMethod(u32),
    /// Tag `0x1a`: offset of a getter method.
    Getter(u32),
    /// Tag `0x1b`: offset of a setter method.
    Setter(u32),
    /// Tag `0x08`: accessor marker byte.
    Accessor(u8),
    /// Follows a method item: its number of formal parameters.
    MethodAffiliate(u16),
    /// Tag `0x17`: index of a literal buffer.
    LiteralBufferIndex(u32),
    /// Offset of another literal array.
    LiteralArray(u32),
    /// Tag `0x19`: index of a builtin type.
    BuiltinTypeIndex(u8),
    /// Tag `0x1c`: offset for an ArkTS `implements` entry.
    EtsImplements(u32),
    /// Tag `0xff`: null; holds the padding byte.
    Null(u8),
    /// Tags `0x0a`–`0x15`: a typed array of a static language. The elements
    /// start at `data_off` and take up the rest of the literal array;
    /// iteration ends here.
    TypedArray {
        /// The tag byte, which names the element type.
        tag: u8,
        /// File offset of the first element.
        data_off: u32,
    },
}

impl Literal {
    fn read(r: &mut Reader<'_>) -> Result<Literal> {
        let tag_pos = r.pos();
        Ok(match r.u8()? {
            tag::TAGVALUE => Literal::TagValue(r.u8()?),
            tag::BOOL => Literal::Bool(r.u8()? != 0),
            tag::INTEGER => Literal::Integer(i32::from_le_bytes(r.u32()?.to_le_bytes())),
            tag::FLOAT => Literal::Float(f32::from_bits(r.u32()?)),
            tag::DOUBLE => Literal::Double(f64::from_bits(r.u64()?)),
            tag::STRING => Literal::String(r.u32()?),
            tag::METHOD => Literal::Method(r.u32()?),
            tag::GENERATORMETHOD => Literal::GeneratorMethod(r.u32()?),
            tag::ASYNCGENERATORMETHOD => Literal::AsyncGeneratorMethod(r.u32()?),
            tag::GETTER => Literal::Getter(r.u32()?),
            tag::SETTER => Literal::Setter(r.u32()?),
            tag::ACCESSOR => Literal::Accessor(r.u8()?),
            tag::METHODAFFILIATE => Literal::MethodAffiliate(r.u16()?),
            tag::LITERALBUFFERINDEX => Literal::LiteralBufferIndex(r.u32()?),
            tag::LITERALARRAY => Literal::LiteralArray(r.u32()?),
            tag::BUILTINTYPEINDEX => Literal::BuiltinTypeIndex(r.u8()?),
            tag::ETS_IMPLEMENTS => Literal::EtsImplements(r.u32()?),
            tag::NULLVALUE => Literal::Null(r.u8()?),
            tag @ tag::ARRAY_U1..=tag::ARRAY_STRING => Literal::TypedArray { tag, data_off: file_off(r.pos()) },
            _ => return Err(AbcError::Malformed { what: "literal", offset: tag_pos, reason: "unknown tag" }),
        })
    }

    /// The tag byte this item was read from.
    pub fn tag(&self) -> u8 {
        match *self {
            Literal::TagValue(_) => tag::TAGVALUE,
            Literal::Bool(_) => tag::BOOL,
            Literal::Integer(_) => tag::INTEGER,
            Literal::Float(_) => tag::FLOAT,
            Literal::Double(_) => tag::DOUBLE,
            Literal::String(_) => tag::STRING,
            Literal::Method(_) => tag::METHOD,
            Literal::GeneratorMethod(_) => tag::GENERATORMETHOD,
            Literal::AsyncGeneratorMethod(_) => tag::ASYNCGENERATORMETHOD,
            Literal::Getter(_) => tag::GETTER,
            Literal::Setter(_) => tag::SETTER,
            Literal::Accessor(_) => tag::ACCESSOR,
            Literal::MethodAffiliate(_) => tag::METHODAFFILIATE,
            Literal::LiteralBufferIndex(_) => tag::LITERALBUFFERINDEX,
            Literal::LiteralArray(_) => tag::LITERALARRAY,
            Literal::BuiltinTypeIndex(_) => tag::BUILTINTYPEINDEX,
            Literal::EtsImplements(_) => tag::ETS_IMPLEMENTS,
            Literal::Null(_) => tag::NULLVALUE,
            Literal::TypedArray { tag, .. } => tag,
        }
    }

    /// The string offset of a `STRING` item.
    pub fn string_off(&self) -> Option<u32> {
        if let Literal::String(off) = *self { Some(off) } else { None }
    }

    /// The method offset of a method-like item (`METHOD`,
    /// `GENERATORMETHOD`, `ASYNCGENERATORMETHOD`, `GETTER`, `SETTER`).
    pub fn method_off(&self) -> Option<u32> {
        match *self {
            Literal::Method(off)
            | Literal::GeneratorMethod(off)
            | Literal::AsyncGeneratorMethod(off)
            | Literal::Getter(off)
            | Literal::Setter(off) => Some(off),
            Literal::TagValue(_)
            | Literal::Bool(_)
            | Literal::Integer(_)
            | Literal::Float(_)
            | Literal::Double(_)
            | Literal::String(_)
            | Literal::Accessor(_)
            | Literal::MethodAffiliate(_)
            | Literal::LiteralBufferIndex(_)
            | Literal::LiteralArray(_)
            | Literal::BuiltinTypeIndex(_)
            | Literal::EtsImplements(_)
            | Literal::Null(_)
            | Literal::TypedArray { .. } => None,
        }
    }

    /// The offset of a nested `LITERALARRAY` item.
    pub fn literal_array_off(&self) -> Option<u32> {
        if let Literal::LiteralArray(off) = *self { Some(off) } else { None }
    }
}
