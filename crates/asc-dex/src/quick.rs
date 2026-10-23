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
    let end = memchr::memchr(0, rest).ok_or(DexError::UnterminatedString(str_off))?;
    Ok(&rest[..end])
}

/// Binary search the type table for `target` (MUTF-8 descriptor bytes,
/// compared in the table's UTF-16 order).
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
        match crate::mutf8::cmp_utf16(cls, target) {
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

/// The largest data offset among the first strings of the string table
/// (up to 64 of them), once the prefix holds the header and those ids:
/// a cheap first look at where the string data sits.
pub fn leading_string_data_off(buf: &[u8]) -> Option<usize> {
    const SAMPLE: usize = 64;
    if buf.len() < HEADER_SIZE || &buf[..4] != b"dex\n" {
        return None;
    }
    let count = (u32_at(buf, 0x38).ok()? as usize).min(SAMPLE);
    let off = u32_at(buf, 0x3C).ok()? as usize;
    if count == 0 || off.checked_add(count * 4)? > buf.len() {
        return None;
    }
    let mut max = 0;
    for i in 0..count {
        max = max.max(u32_at(buf, off + i * 4).ok()? as usize);
    }
    Some(max)
}

/// Like [`probe_needed_len`], for a reference-search probe: every id table
/// (strings, types, protos, fields, methods, class defs) plus the start of
/// the last `string_data_item`. The caller adds room for that string itself.
/// `None` while the prefix does not yet hold the header and those tables.
pub fn id_tables_needed_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < HEADER_SIZE || &buf[..4] != b"dex\n" {
        return None;
    }
    // (size, offset, item size) of every id table, as the header lists them.
    let tables = [(0x38, 4), (0x40, 4), (0x48, 12), (0x50, 8), (0x58, 8), (0x60, 32)];
    let mut tables_end = HEADER_SIZE;
    for (at, item) in tables {
        let size = u32_at(buf, at).ok()? as usize;
        let off = u32_at(buf, at + 4).ok()? as usize;
        tables_end = tables_end.max(off.checked_add(size.checked_mul(item)?)?);
    }
    if tables_end > buf.len() {
        return None;
    }
    let string_ids_size = u32_at(buf, 0x38).ok()? as usize;
    let string_ids_off = u32_at(buf, 0x3C).ok()? as usize;
    let mut needed = tables_end;
    for i in 0..string_ids_size {
        needed = needed.max(u32_at(buf, string_ids_off + i * 4).ok()? as usize);
    }
    Some(needed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_lengths_need_the_tables_and_string_offsets() {
        let data = asc_fixture::make_dex();
        let needed = id_tables_needed_len(&data).unwrap();
        // The fixture puts the string data right after the tables.
        let first = leading_string_data_off(&data).unwrap();
        assert!(first <= needed && needed < data.len());
        assert_eq!(id_tables_needed_len(&data[..0x70]), None, "tables not there yet");
        assert_eq!(leading_string_data_off(&data[..0x70]), None);
        assert_eq!(id_tables_needed_len(&[b'x'; 0x100]), None, "not a DEX");

        let late = asc_fixture::make_padded_dex(4096, 0);
        assert!(leading_string_data_off(&late).unwrap() >= 4096);
        assert_eq!(id_tables_needed_len(&late).unwrap(), needed + 4096);
    }
}
