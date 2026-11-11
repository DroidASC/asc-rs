//! Annotations: `u16 class_idx, u16 count`, `count` elements of
//! `(u32 name_off, u32 value)`, then `count` one-byte type tags.

use crate::reader::{Reader, entity_pos, read_u32, read_u64};
use crate::{Abc, AbcError, Result};

/// An annotation attached to a class, field or method.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Annotation<'a> {
    off: u32,
    /// Index of the annotation class in the region's class table.
    pub class_idx: u16,
    elements: &'a [u8],
    tags: &'a [u8],
}

/// One name-value pair of an annotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct AnnotationElement {
    /// `name_off`: file offset of the element name string.
    pub name_off: u32,
    /// The value itself for types up to 32 bits, otherwise the offset of
    /// the value (string, array, 64-bit number …).
    pub value: u32,
    /// Type tag character (`'7'` u32, `'C'` string, `'E'` method …, see
    /// "Tags description" in the format document).
    pub tag: u8,
}

/// What an annotation element holds, read by its type tag. The elements of
/// the compiler's own annotations are `u32`; the annotations of a program
/// (`@interface`, bytecode of API 20 and later) have numbers, strings,
/// booleans and arrays of them.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ElementValue {
    /// Tag `'1'`.
    Bool(bool),
    /// Tags `'2'` to `'7'`: an integer of up to 32 bits, as stored.
    Int(u32),
    /// Tag `'B'`.
    F64(f64),
    /// Tag `'C'`: the offset of a string.
    String(u32),
    /// Tags `'K'` to `'Z'` and `'#'`: the offset of the literal array that
    /// holds the items.
    Array(u32),
    /// Any other tag: the stored value as it is.
    Other(u32),
}

impl AnnotationElement {
    /// The value, read the way the type tag says.
    ///
    /// # Errors
    /// `BadOffset` or `Truncated` for a 64-bit value that is not in the file.
    pub fn typed(&self, abc: &Abc<'_>) -> Result<ElementValue> {
        Ok(match self.tag {
            b'1' => ElementValue::Bool(self.value != 0),
            b'2'..=b'7' => ElementValue::Int(self.value),
            b'B' => {
                let bits = read_u64(abc.bytes(), entity_pos(abc.bytes(), self.value, "annotation element value")?)?;
                ElementValue::F64(f64::from_bits(bits))
            }
            b'C' => ElementValue::String(self.value),
            b'K'..=b'Z' | b'#' => ElementValue::Array(self.value),
            _ => ElementValue::Other(self.value),
        })
    }
}

/// Bytes of one annotation element: name offset and value, a `u32` each.
const ELEMENT_SIZE: usize = 8;

impl<'a> Annotation<'a> {
    const ELEMENT_SIZE: usize = ELEMENT_SIZE;

    pub(crate) fn parse(buf: &'a [u8], off: u32) -> Result<Annotation<'a>> {
        let mut r = Reader::new(buf, entity_pos(buf, off, "annotation")?);
        let (class_idx, count) = (r.u16()?, usize::from(r.u16()?));
        let elements = r.take(count * Self::ELEMENT_SIZE, "annotation elements")?;
        let tags = r.take(count, "annotation element tags")?;
        Ok(Annotation { off, class_idx, elements, tags })
    }

    /// File offset of the annotation.
    #[inline]
    pub fn offset(&self) -> u32 {
        self.off
    }

    /// Number of elements.
    #[inline]
    pub fn len(&self) -> usize {
        self.tags.len()
    }

    /// Whether the annotation has no elements.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }

    /// The name-value pairs in file order.
    pub fn elements(&self) -> impl Iterator<Item = AnnotationElement> + 'a + use<'a> {
        self.elements
            .as_chunks::<ELEMENT_SIZE>()
            .0
            .iter()
            .zip(self.tags)
            .filter_map(|(raw, &tag)| Some(AnnotationElement { name_off: read_u32(raw, 0).ok()?, value: read_u32(raw, 4).ok()?, tag }))
    }

    /// Offset of the annotation class (e.g. `L_ESSlotNumberAnnotation;`).
    ///
    /// # Errors
    /// `NoRegion` or a `class_idx` outside the region's class table.
    pub fn class_off(&self, abc: &Abc<'a>) -> Result<u32> {
        let region = abc.region_of(self.off)?;
        let table = region.class_table()?;
        let idx = u32::from(self.class_idx);
        table.get(idx).ok_or(AbcError::IndexOutOfRange { what: "region class index", index: idx, size: table.len() })
    }
}
