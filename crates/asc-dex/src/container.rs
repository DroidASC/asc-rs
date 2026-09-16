//! DEX version 041 container handling.
//!
//! A `dex\n041` file may pack several logical DEX files back to back. Every
//! logical header stores absolute offsets into the container, so a logical DEX
//! can be exposed as "the full container bytes with this header at offset 0".

use crate::{u32_at, HEADER_SIZE};
use std::borrow::Cow;

pub const DEX041_MAGIC: &[u8; 8] = b"dex\n041\0";

/// Whether `data` starts with a version 041 container header.
pub fn is_dex041_container(data: &[u8]) -> bool {
    data.len() >= HEADER_SIZE && &data[..8] == DEX041_MAGIC
}

/// Offsets of every logical DEX header in a 041 container (`[0]` otherwise).
pub fn dex041_logical_offsets(data: &[u8]) -> Vec<usize> {
    if !is_dex041_container(data) {
        return vec![0];
    }
    let mut offsets = Vec::new();
    let mut off = 0usize;
    while off + HEADER_SIZE <= data.len() && &data[off..off + 8] == DEX041_MAGIC {
        let file_size = u32_at(data, off + 0x20).unwrap_or(0) as usize;
        if file_size < HEADER_SIZE || off + file_size > data.len() {
            break;
        }
        offsets.push(off);
        off += file_size;
    }
    if offsets.is_empty() {
        vec![0]
    } else {
        offsets
    }
}

/// Produce a buffer that exposes the logical DEX at `header_off` as a regular
/// DEX: the container bytes with the logical header copied to offset 0.
pub fn normalize_dex041_logical(data: &[u8], header_off: usize) -> Cow<'_, [u8]> {
    // An offset that does not leave room for a header cannot be normalised;
    // hand the container back unchanged rather than slicing out of bounds.
    if header_off == 0 || header_off.checked_add(HEADER_SIZE).is_none_or(|end| end > data.len()) {
        return Cow::Borrowed(data);
    }
    let mut header_size = u32_at(data, header_off + 0x24).unwrap_or(HEADER_SIZE as u32) as usize;
    if header_size < HEADER_SIZE || header_off.checked_add(header_size).is_none_or(|end| end > data.len()) {
        header_size = HEADER_SIZE;
    }
    let mut out = data.to_vec();
    out[..header_size].copy_from_slice(&data[header_off..header_off + header_size]);
    Cow::Owned(out)
}

/// Split a DEX entry into its logical DEX buffers, naming them
/// `name!classesN.dex` when the entry is a multi-DEX container.
pub fn logical_dex_buffers<'a>(name: &str, data: &'a [u8]) -> Vec<(String, Cow<'a, [u8]>)> {
    let offsets = dex041_logical_offsets(data);
    if offsets.len() <= 1 {
        return vec![(name.to_string(), Cow::Borrowed(data))];
    }
    offsets.into_iter().enumerate().map(|(i, off)| (format!("{name}!classes{}.dex", i + 1), normalize_dex041_logical(data, off))).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bare 041 header of `file_size` bytes (header + zero padding).
    fn logical(file_size: u32, header_size: u32) -> Vec<u8> {
        let mut v = vec![0u8; file_size as usize];
        v[..8].copy_from_slice(DEX041_MAGIC);
        v[0x20..0x24].copy_from_slice(&file_size.to_le_bytes());
        v[0x24..0x28].copy_from_slice(&header_size.to_le_bytes());
        v
    }

    #[test]
    fn non_container_has_single_logical_dex() {
        assert_eq!(dex041_logical_offsets(b"dex\n035\0"), vec![0]);
        assert_eq!(dex041_logical_offsets(&[]), vec![0]);
        let mut v = logical(0x80, 0x70);
        v[..8].copy_from_slice(b"dex\n039\0");
        assert!(!is_dex041_container(&v));
        assert_eq!(dex041_logical_offsets(&v), vec![0]);
        let bufs = logical_dex_buffers("classes.dex", &v);
        assert_eq!(bufs.len(), 1);
        assert_eq!(bufs[0].0, "classes.dex");
        assert!(matches!(bufs[0].1, Cow::Borrowed(_)));
    }

    #[test]
    fn two_logical_dex_files() {
        let mut data = logical(0x80, 0x70);
        let mut second = logical(0x90, 0x70);
        second[0x28] = 0xAB; // marker inside the second header
        data.extend_from_slice(&second);
        assert!(is_dex041_container(&data));
        assert_eq!(dex041_logical_offsets(&data), vec![0, 0x80]);
        let bufs = logical_dex_buffers("classes.dex", &data);
        assert_eq!(bufs.len(), 2);
        assert_eq!(bufs[0].0, "classes.dex!classes1.dex");
        assert_eq!(bufs[1].0, "classes.dex!classes2.dex");
        // The first logical DEX is borrowed; the second is the whole container
        // with the second header copied to offset 0.
        assert!(matches!(bufs[0].1, Cow::Borrowed(_)));
        assert!(matches!(bufs[1].1, Cow::Owned(_)));
        assert_eq!(bufs[1].1.len(), data.len());
        assert_eq!(bufs[1].1[0x28], 0xAB);
        assert_eq!(&bufs[1].1[0x20..0x24], &0x90u32.to_le_bytes());
        assert_eq!(&bufs[1].1[0x80..], &data[0x80..]);
    }

    #[test]
    fn normalize_with_out_of_range_header_offset_borrows_the_input() {
        let data = logical(0x80, 0x70);
        // No room for a header at the offset: the container comes back untouched.
        assert!(matches!(normalize_dex041_logical(&data, 0x78), Cow::Borrowed(_)));
        assert!(matches!(normalize_dex041_logical(&data, 0x100), Cow::Borrowed(_)));
        assert!(matches!(normalize_dex041_logical(&data, usize::MAX), Cow::Borrowed(_)));
        assert!(matches!(normalize_dex041_logical(&data, usize::MAX - 0x10), Cow::Borrowed(_)));
        // Exactly enough room still normalises.
        let mut data = logical(0x80, 0x70);
        data.extend_from_slice(&logical(0x70, 0x70));
        data[0x80 + 0x28] = 0xCD;
        let out = normalize_dex041_logical(&data, 0x80);
        assert!(matches!(out, Cow::Owned(_)));
        assert_eq!(out[0x28], 0xCD);
    }

    #[test]
    fn out_of_range_file_size_stops_the_walk() {
        // Second header claims more bytes than the container holds.
        let mut data = logical(0x80, 0x70);
        data.extend_from_slice(&logical(0x80, 0x70));
        data[0x80 + 0x20..0x80 + 0x24].copy_from_slice(&0x1000u32.to_le_bytes());
        assert_eq!(dex041_logical_offsets(&data), vec![0]);
        assert_eq!(logical_dex_buffers("c.dex", &data).len(), 1);
        // First header already out of range: fall back to a single logical DEX.
        let mut data = logical(0x80, 0x70);
        data[0x20..0x24].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(dex041_logical_offsets(&data), vec![0]);
        // file_size smaller than a header is rejected too.
        let mut data = logical(0x80, 0x70);
        data[0x20..0x24].copy_from_slice(&0x10u32.to_le_bytes());
        assert_eq!(dex041_logical_offsets(&data), vec![0]);
        // A trailing header that does not fit is ignored, earlier ones kept.
        let mut data = logical(0x80, 0x70);
        data.extend_from_slice(&logical(0x80, 0x70));
        data.truncate(0x80 + 0x70);
        assert_eq!(dex041_logical_offsets(&data), vec![0]);
        let mut data = logical(0x80, 0x70);
        data.extend_from_slice(&logical(0x80, 0x70));
        data.extend_from_slice(&logical(0x80, 0x70)[..0x60]);
        assert_eq!(dex041_logical_offsets(&data), vec![0, 0x80]);
    }

    #[test]
    fn normalize_tolerates_bad_header_size() {
        let mut data = logical(0x80, 0x70);
        let mut second = logical(0x80, 0xFFFF_FFFF);
        second[0x30] = 7;
        data.extend_from_slice(&second);
        let out = normalize_dex041_logical(&data, 0x80);
        assert_eq!(out[0x30], 7);
        assert_eq!(out.len(), data.len());
    }
}
