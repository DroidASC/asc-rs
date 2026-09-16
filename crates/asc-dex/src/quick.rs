//! Cheap probes that answer questions about a DEX buffer without building
//! any parser state. Used on the APK scan hot path.

use crate::{u32_at, DexError, Result, HEADER_SIZE};

/// Skip a uleb128 (at most `leb128::MAX_LEN` bytes, like the readers).
fn skip_uleb128(buf: &[u8], off: usize) -> Result<usize> {
    Ok(off + crate::leb128::uleb128_len(buf, off)?)
}

fn string_data_bytes(buf: &[u8], str_off: usize) -> Result<&[u8]> {
    let ptr = skip_uleb128(buf, str_off)?;
    let rest = buf.get(ptr..).ok_or(DexError::Truncated { what: "string_data", offset: ptr })?;
    let end = rest.iter().position(|&b| b == 0).ok_or(DexError::UnterminatedString(str_off))?;
    Ok(&rest[..end])
}

/// Binary search the type table for `target` (raw descriptor bytes).
pub fn find_type_idx(buf: &[u8], target: &[u8]) -> Result<Option<u32>> {
    if buf.len() < HEADER_SIZE || &buf[..3] != b"dex" {
        return Ok(None);
    }
    let string_ids_size = u32_at(buf, 0x38)? as usize;
    let string_ids_off = u32_at(buf, 0x3C)? as usize;
    let type_ids_size = u32_at(buf, 0x40)? as usize;
    let type_ids_off = u32_at(buf, 0x44)? as usize;
    if string_ids_size == 0 || type_ids_size == 0 {
        return Ok(None);
    }
    if string_ids_off + string_ids_size * 4 > buf.len() {
        return Err(DexError::BadRange { what: "string_ids", offset: string_ids_off });
    }
    if type_ids_off + type_ids_size * 4 > buf.len() {
        return Err(DexError::BadRange { what: "type_ids", offset: type_ids_off });
    }
    let (mut left, mut right) = (0i64, type_ids_size as i64 - 1);
    while left <= right {
        let mid = ((left + right) >> 1) as usize;
        let str_idx = u32_at(buf, type_ids_off + mid * 4)? as usize;
        if str_idx >= string_ids_size {
            return Err(DexError::Malformed { what: "type_id", offset: type_ids_off + mid * 4, reason: "string idx out of range" });
        }
        let str_off = u32_at(buf, string_ids_off + str_idx * 4)? as usize;
        if str_off >= buf.len() {
            return Err(DexError::BadRange { what: "string_data_off", offset: str_off });
        }
        let cls = string_data_bytes(buf, str_off)?;
        match cls.cmp(target) {
            std::cmp::Ordering::Equal => return Ok(Some(mid as u32)),
            std::cmp::Ordering::Less => left = mid as i64 + 1,
            std::cmp::Ordering::Greater => right = mid as i64 - 1,
        }
    }
    Ok(None)
}

/// Whether any `class_def_item` has `class_idx == type_idx`.
pub fn class_defs_contain_type_idx(buf: &[u8], type_idx: u32) -> Result<bool> {
    let size = u32_at(buf, 0x60)? as usize;
    let off = u32_at(buf, 0x64)? as usize;
    if size == 0 {
        return Ok(false);
    }
    let end = off + (size << 5);
    if end > buf.len() {
        return Err(DexError::BadRange { what: "class_defs", offset: off });
    }
    let needle = type_idx.to_le_bytes();
    let region = &buf[off..end];
    Ok(region.chunks_exact(32).any(|c| c[..4] == needle))
}

/// Whether the DEX buffer *defines* (not merely references) the class with
/// descriptor `target`.
pub fn dex_defines_class(buf: &[u8], target: &[u8]) -> Result<bool> {
    match find_type_idx(buf, target)? {
        Some(idx) => class_defs_contain_type_idx(buf, idx),
        None => Ok(false),
    }
}

/// Number of leading bytes a class-definition probe needs: the id tables plus
/// every `string_data_item` referenced by the string table. `None` when the
/// prefix does not yet hold the header and the string/type/class tables.
pub fn probe_needed_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < HEADER_SIZE || &buf[..4] != b"dex\n" {
        return None;
    }
    let string_ids_size = u32_at(buf, 0x38).ok()? as usize;
    let string_ids_off = u32_at(buf, 0x3C).ok()? as usize;
    let type_ids_size = u32_at(buf, 0x40).ok()? as usize;
    let type_ids_off = u32_at(buf, 0x44).ok()? as usize;
    let class_defs_size = u32_at(buf, 0x60).ok()? as usize;
    let class_defs_off = u32_at(buf, 0x64).ok()? as usize;
    let string_ids_end = string_ids_off.checked_add(string_ids_size.checked_mul(4)?)?;
    let type_ids_end = type_ids_off.checked_add(type_ids_size.checked_mul(4)?)?;
    let class_defs_end = class_defs_off.checked_add(class_defs_size.checked_mul(32)?)?;
    let tables_end = string_ids_end.max(type_ids_end).max(class_defs_end);
    if tables_end > buf.len() {
        return None;
    }
    let mut needed = tables_end;
    for i in 0..string_ids_size {
        let off = u32_at(buf, string_ids_off + i * 4).ok()? as usize;
        needed = needed.max(off);
    }
    Some(needed)
}
