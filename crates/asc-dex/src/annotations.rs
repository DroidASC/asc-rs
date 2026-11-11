//! `annotations_directory_item`, `annotation_set_item` and
//! `annotation_set_ref_list` parsing.

use crate::{DexError, Result, u32_at};

/// Parsed `annotations_directory_item`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnnotationsDirectory {
    /// `class_annotations_off`: offset of the class's `annotation_set_item`, `0` if none.
    pub class_annotations_off: u32,
    /// `(field_idx, annotation_set_off)`
    pub field_annotations: Vec<(u32, u32)>,
    /// `(method_idx, annotation_set_off)`
    pub method_annotations: Vec<(u32, u32)>,
    /// `(method_idx, annotation_set_ref_list_off)`
    pub parameter_annotations: Vec<(u32, u32)>,
}

impl AnnotationsDirectory {
    /// Parse the `annotations_directory_item` at `off`.
    ///
    /// # Errors
    ///
    /// `Truncated` when the header or any of the annotation lists runs past
    /// the end of `buf`.
    pub fn parse(buf: &[u8], off: usize) -> Result<AnnotationsDirectory> {
        let class_annotations_off = u32_at(buf, off)?;
        let fields = u32_at(buf, off + 4)? as usize;
        let methods = u32_at(buf, off + 8)? as usize;
        let params = u32_at(buf, off + 12)? as usize;
        let mut p = off + 16;
        let mut read_pairs = |count: usize| -> Result<Vec<(u32, u32)>> {
            let mut v = Vec::with_capacity(count.min(1024));
            for _ in 0..count {
                v.push((u32_at(buf, p)?, u32_at(buf, p + 4)?));
                p += 8;
            }
            Ok(v)
        };
        let field_annotations = read_pairs(fields)?;
        let method_annotations = read_pairs(methods)?;
        let parameter_annotations = read_pairs(params)?;
        Ok(AnnotationsDirectory { class_annotations_off, field_annotations, method_annotations, parameter_annotations })
    }
}

/// Parse an `annotation_set_item`: a list of `annotation_item` offsets.
///
/// # Errors
///
/// `Truncated` when the size word is out of `buf`, `BadRange` when the entries are.
pub fn parse_annotation_set(buf: &[u8], off: usize) -> Result<Vec<u32>> {
    let size = u32_at(buf, off)? as usize;
    let start = off + 4;
    let bytes = buf.get(start..start + size * 4).ok_or(DexError::BadRange { what: "annotation_set_item", offset: off })?;
    Ok(bytes.as_chunks::<4>().0.iter().map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect())
}

/// Parse an `annotation_set_ref_list`: a list of `annotation_set_item` offsets.
///
/// # Errors
///
/// Same as [`parse_annotation_set`]; both lists share one layout.
pub fn parse_annotation_set_ref_list(buf: &[u8], off: usize) -> Result<Vec<u32>> {
    parse_annotation_set(buf, off)
}
