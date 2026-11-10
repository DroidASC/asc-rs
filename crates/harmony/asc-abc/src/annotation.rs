//! Annotations: `u16 class_idx, u16 count`, `count` elements of
//! `(u32 name_off, u32 value)`, then `count` one-byte type tags.

use crate::reader::{entity_pos, read_u32, Reader};
use crate::{Abc, AbcError, Result};

/// An annotation attached to a class, field or method.
#[derive(Debug, Clone, Copy)]
pub struct Annotation<'a> {
    off: u32,
    /// Index of the annotation class in the region's class table.
    pub class_idx: u16,
    elements: &'a [u8],
    tags: &'a [u8],
}

/// One name-value pair of an annotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnnotationElement {
    pub name_off: u32,
    /// The value itself for types up to 32 bits, otherwise the offset of
    /// the value (string, array, 64-bit number …).
    pub value: u32,
    /// Type tag character (`'7'` u32, `'C'` string, `'E'` method …, see
    /// "Tags description" in the format document).
    pub tag: u8,
}

impl<'a> Annotation<'a> {
    const ELEMENT_SIZE: usize = 8;

    pub(crate) fn parse(buf: &'a [u8], off: u32) -> Result<Annotation<'a>> {
        let mut r = Reader::new(buf, entity_pos(buf, off, "annotation")?);
        let (class_idx, count) = (r.u16()?, usize::from(r.u16()?));
        let elements = r.take(count * Self::ELEMENT_SIZE, "annotation elements")?;
        let tags = r.take(count, "annotation element tags")?;
        Ok(Annotation { off, class_idx, elements, tags })
    }

    #[inline]
    pub fn offset(&self) -> u32 {
        self.off
    }

    /// Number of elements.
    #[inline]
    pub fn len(&self) -> usize {
        self.tags.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }

    pub fn elements(&self) -> impl Iterator<Item = AnnotationElement> + 'a {
        self.elements
            .chunks_exact(Self::ELEMENT_SIZE)
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
