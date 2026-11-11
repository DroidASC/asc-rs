//! `map_list` parsing.

use crate::{DexError, HEADER_SIZE, Result, map_type, u32_at};
use std::ops::Range;

/// One entry of the map list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapItem {
    /// Item type code, see [`map_type`].
    pub kind: u16,
    /// Number of items of this type.
    pub size: u32,
    /// Offset of the first item from the start of the file.
    pub offset: u32,
}

impl MapItem {
    /// Size of a `map_item` in bytes.
    pub const SIZE: usize = 12;

    fn from_bytes(b: &[u8; MapItem::SIZE]) -> MapItem {
        // Bytes 2..4 are `unused` padding.
        MapItem {
            kind: u16::from_le_bytes([b[0], b[1]]),
            size: u32::from_le_bytes([b[4], b[5], b[6], b[7]]),
            offset: u32::from_le_bytes([b[8], b[9], b[10], b[11]]),
        }
    }

    /// Smallest encoding of one item of this type: the exact size for the
    /// fixed-size id tables, a lower bound for the variable-size data items
    /// and 0 for type codes this crate does not know.
    pub fn min_item_size(&self) -> usize {
        match self.kind {
            map_type::HEADER => HEADER_SIZE,
            map_type::STRING_ID | map_type::TYPE_ID | map_type::CALL_SITE_ID => 4,
            map_type::PROTO_ID => 12,
            map_type::FIELD_ID | map_type::METHOD_ID | map_type::METHOD_HANDLE => 8,
            map_type::CLASS_DEF => 32,
            // A size word, or (class data) four uleb128 counts.
            map_type::MAP_LIST
            | map_type::TYPE_LIST
            | map_type::ANNOTATION_SET_REF_LIST
            | map_type::ANNOTATION_SET
            | map_type::HIDDENAPI_CLASS_DATA
            | map_type::CLASS_DATA => 4,
            map_type::CODE | map_type::ANNOTATIONS_DIRECTORY => 16,
            // uleb128 length + NUL.
            map_type::STRING_DATA => 2,
            // Two uleb128 headers + DBG_END_SEQUENCE; visibility + two uleb128.
            map_type::DEBUG_INFO | map_type::ANNOTATION => 3,
            map_type::ENCODED_ARRAY => 1,
            _ => 0,
        }
    }

    /// Byte range the items occupy at minimum (see [`Self::min_item_size`]),
    /// or `None` when it does not fit in a file of `len` bytes.
    fn min_extent(&self, len: usize) -> Option<Range<usize>> {
        let start = self.offset as usize;
        let end = (self.size as usize).checked_mul(self.min_item_size())?.checked_add(start)?;
        (start <= len && end <= len).then_some(start..end)
    }
}

/// Zero-copy view of a validated `map_list`.
///
/// Every entry was checked on construction: the list itself lies inside the
/// file and so do the items of each entry (exactly for fixed-size tables, by
/// a per-item lower bound for data items).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapList<'a> {
    /// The raw `map_item` array (`len() * MapItem::SIZE` bytes).
    items: &'a [u8],
}

impl<'a> MapList<'a> {
    /// A list without entries (a DEX whose `map_off` is 0).
    pub const EMPTY: MapList<'static> = MapList { items: &[] };

    /// Parse and validate the `map_list` at `off` in `buf`.
    ///
    /// # Errors
    ///
    /// `Truncated` when the size word is out of the buffer, `BadRange` when
    /// the item array or one entry's items do not fit in `buf`.
    pub fn parse(buf: &'a [u8], off: usize) -> Result<MapList<'a>> {
        let size = u32_at(buf, off)? as usize;
        let items = size
            .checked_mul(MapItem::SIZE)
            .and_then(|len| off.checked_add(4)?.checked_add(len).map(|end| (off + 4)..end))
            .and_then(|range| buf.get(range))
            .ok_or(DexError::BadRange { what: "map_list", offset: off })?;
        let list = MapList { items };
        for (i, item) in list.iter().enumerate() {
            if item.min_extent(buf.len()).is_none() {
                return Err(DexError::BadRange { what: "map_item", offset: off + 4 + i * MapItem::SIZE });
            }
        }
        Ok(list)
    }

    /// Number of entries.
    #[inline]
    pub fn len(&self) -> usize {
        self.items.len() / MapItem::SIZE
    }

    /// Whether the map list has no entries.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Entry `i`, `None` past the end.
    pub fn get(&self, i: usize) -> Option<MapItem> {
        self.items.as_chunks::<{ MapItem::SIZE }>().0.get(i).map(MapItem::from_bytes)
    }

    /// Iterate over the entries in file order.
    pub fn iter(&self) -> impl Iterator<Item = MapItem> + 'a {
        let items = self.items;
        items.as_chunks::<{ MapItem::SIZE }>().0.iter().map(MapItem::from_bytes)
    }

    /// The first entry of type `kind` (see [`map_type`]).
    pub fn find(&self, kind: u16) -> Option<MapItem> {
        self.iter().find(|item| item.kind == kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map_bytes(prefix: usize, items: &[(u16, u32, u32)]) -> Vec<u8> {
        let mut buf = vec![0u8; prefix];
        buf.extend_from_slice(&(items.len() as u32).to_le_bytes());
        for &(kind, size, offset) in items {
            buf.extend_from_slice(&kind.to_le_bytes());
            buf.extend_from_slice(&[0, 0]);
            buf.extend_from_slice(&size.to_le_bytes());
            buf.extend_from_slice(&offset.to_le_bytes());
        }
        buf
    }

    #[test]
    fn parses_entries_in_order() {
        let buf = map_bytes(0x80, &[(map_type::HEADER, 1, 0), (map_type::METHOD_HANDLE, 2, 0x70), (map_type::MAP_LIST, 1, 0x80)]);
        let map = MapList::parse(&buf, 0x80).unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(map.get(1), Some(MapItem { kind: map_type::METHOD_HANDLE, size: 2, offset: 0x70 }));
        assert_eq!(map.get(3), None);
        assert_eq!(map.get(usize::MAX), None);
        assert_eq!(map.find(map_type::MAP_LIST).map(|m| m.offset), Some(0x80));
        assert_eq!(map.find(map_type::CALL_SITE_ID), None);
        let kinds: Vec<u16> = map.iter().map(|m| m.kind).collect();
        assert_eq!(kinds, [map_type::HEADER, map_type::METHOD_HANDLE, map_type::MAP_LIST]);
        assert!(MapList::EMPTY.is_empty());
    }

    #[test]
    fn rejects_out_of_bounds_lists_and_items() {
        // Huge declared count: rejected by the bounds check, nothing allocated.
        let mut buf = map_bytes(0, &[]);
        buf[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(MapList::parse(&buf, 0), Err(DexError::BadRange { what: "map_list", offset: 0 }));
        // Truncated item array.
        let mut buf = map_bytes(0, &[(map_type::HEADER, 1, 0)]);
        buf.pop();
        assert!(matches!(MapList::parse(&buf, 0), Err(DexError::BadRange { what: "map_list", .. })));
        // Size word out of the buffer, and an offset near usize::MAX.
        assert!(matches!(MapList::parse(&[0, 0], 0), Err(DexError::Truncated { .. })));
        assert!(MapList::parse(&buf, usize::MAX - 1).is_err());

        let bad = |item: (u16, u32, u32)| {
            let buf = map_bytes(0x10, &[(map_type::MAP_LIST, 1, 0x10), item]);
            MapList::parse(&buf, 0x10).map(|map| map.len())
        };
        let item_err = Err(DexError::BadRange { what: "map_item", offset: 0x10 + 4 + MapItem::SIZE });
        // Offset past the end of the file.
        assert_eq!(bad((map_type::ENCODED_ARRAY, 1, 0x1000)), item_err);
        // Fixed-size table running past the end.
        assert_eq!(bad((map_type::METHOD_HANDLE, 0x1000_0000, 0)), item_err);
        assert_eq!(bad((map_type::CALL_SITE_ID, u32::MAX, u32::MAX)), item_err);
        // Unknown kinds only need an in-bounds offset.
        assert!(bad((0x7777, u32::MAX, 0x10)).is_ok());
    }
}
