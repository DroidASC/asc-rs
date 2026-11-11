//! `class_data_item` parsing.

use crate::Result;
use crate::leb128::{read_uleb128, uleb128_len};

/// One `encoded_field` of a `class_data_item`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedField {
    /// The field, as an index into `field_ids` (the on-disk delta already added up).
    pub field_idx: u32,
    /// `access_flags`: [`crate::access`] bits.
    pub access_flags: u32,
}

/// One `encoded_method` of a `class_data_item`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedMethod {
    /// The method, as an index into `method_ids` (the on-disk delta already added up).
    pub method_idx: u32,
    /// `access_flags`: [`crate::access`] bits.
    pub access_flags: u32,
    /// `code_off`: offset of the `code_item`, `0` for abstract and native methods.
    pub code_off: u32,
}

/// Fully decoded `class_data_item` (index deltas already resolved).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClassData {
    /// `static_fields`, in index order.
    pub static_fields: Vec<EncodedField>,
    /// `instance_fields`, in index order.
    pub instance_fields: Vec<EncodedField>,
    /// `direct_methods`: static, private and constructor methods.
    pub direct_methods: Vec<EncodedMethod>,
    /// `virtual_methods`: everything overridable.
    pub virtual_methods: Vec<EncodedMethod>,
    /// Offset just past the item (start of the next class_data_item when packed).
    pub end: usize,
}

impl ClassData {
    /// Parse the item at `off`. An offset of `0` yields an empty class.
    ///
    /// # Errors
    ///
    /// `Truncated` when the item runs past the end of `buf`.
    pub fn parse(buf: &[u8], off: usize) -> Result<ClassData> {
        let mut cd = ClassData::default();
        if off == 0 {
            return Ok(cd);
        }
        let mut p = off;
        let (sf, n) = read_uleb128(buf, p)?;
        p += n;
        let (inf, n) = read_uleb128(buf, p)?;
        p += n;
        let (dm, n) = read_uleb128(buf, p)?;
        p += n;
        let (vm, n) = read_uleb128(buf, p)?;
        p += n;

        // Counts come from the file: never reserve more than could fit in the
        // remaining bytes (a field is >= 2 bytes, a method >= 3 bytes).
        let read_fields = |count: u32, out: &mut Vec<EncodedField>, p: &mut usize| -> Result<()> {
            let mut idx = 0u32;
            out.reserve((count as usize).min(buf.len().saturating_sub(*p) / 2));
            for _ in 0..count {
                let (diff, n) = read_uleb128(buf, *p)?;
                *p += n;
                idx = idx.wrapping_add(diff);
                let (flags, n) = read_uleb128(buf, *p)?;
                *p += n;
                out.push(EncodedField { field_idx: idx, access_flags: flags });
            }
            Ok(())
        };
        read_fields(sf, &mut cd.static_fields, &mut p)?;
        read_fields(inf, &mut cd.instance_fields, &mut p)?;

        let read_methods = |count: u32, out: &mut Vec<EncodedMethod>, p: &mut usize| -> Result<()> {
            let mut idx = 0u32;
            out.reserve((count as usize).min(buf.len().saturating_sub(*p) / 3));
            for _ in 0..count {
                let (diff, n) = read_uleb128(buf, *p)?;
                *p += n;
                idx = idx.wrapping_add(diff);
                let (flags, n) = read_uleb128(buf, *p)?;
                *p += n;
                let (code_off, n) = read_uleb128(buf, *p)?;
                *p += n;
                out.push(EncodedMethod { method_idx: idx, access_flags: flags, code_off });
            }
            Ok(())
        };
        read_methods(dm, &mut cd.direct_methods, &mut p)?;
        read_methods(vm, &mut cd.virtual_methods, &mut p)?;
        cd.end = p;
        Ok(cd)
    }

    /// All fields, static first then instance.
    pub fn fields(&self) -> impl Iterator<Item = &EncodedField> {
        self.static_fields.iter().chain(self.instance_fields.iter())
    }

    /// All methods, direct first then virtual.
    pub fn methods(&self) -> impl Iterator<Item = &EncodedMethod> {
        self.direct_methods.iter().chain(self.virtual_methods.iter())
    }

    /// Whether the class declares no fields and no methods.
    pub fn is_empty(&self) -> bool {
        self.static_fields.is_empty()
            && self.instance_fields.is_empty()
            && self.direct_methods.is_empty()
            && self.virtual_methods.is_empty()
    }
}

/// Fast walk over the methods of a `class_data_item` without allocating.
/// Calls `f(method_idx, code_off)` for every direct and virtual method and
/// returns the offset just past the item.
///
/// # Errors
///
/// `Truncated` when the item runs past the end of `buf`; `f` may already
/// have been called for the methods before that point.
pub fn walk_methods(buf: &[u8], off: usize, mut f: impl FnMut(u32, u32)) -> Result<usize> {
    let mut p = off;
    let (sf, n) = read_uleb128(buf, p)?;
    p += n;
    let (inf, n) = read_uleb128(buf, p)?;
    p += n;
    let (dm, n) = read_uleb128(buf, p)?;
    p += n;
    let (vm, n) = read_uleb128(buf, p)?;
    p += n;
    for _ in 0..(sf as u64 + inf as u64) {
        p += uleb128_len(buf, p)?;
        p += uleb128_len(buf, p)?;
    }
    for count in [dm, vm] {
        let mut idx = 0u32;
        for _ in 0..count {
            let (diff, n) = read_uleb128(buf, p)?;
            p += n;
            idx = idx.wrapping_add(diff);
            p += uleb128_len(buf, p)?;
            let (code_off, n) = read_uleb128(buf, p)?;
            p += n;
            f(idx, code_off);
        }
    }
    Ok(p)
}
