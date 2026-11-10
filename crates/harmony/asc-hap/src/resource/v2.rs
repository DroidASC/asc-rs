//! The `RestoolV2 <version>` layout.
//!
//! ```text
//! header   version[128]  fileSize:u32  keyCount:u32  dataOffset:u32
//! keys     keyCount x { "KEYS"  configId:u32  paramCount:u32  { keyType:u32 value:u32 }* }
//! ids      "IDSS"  length:u32  typeCount:u32  idCount:u32
//!          typeCount x { type:u32  length:u32  count:u32
//!                        count x { id:u32  infoOffset:u32  nameLen:u32  name } }
//! data     at dataOffset: "DATA"  length:u32  idCount:u32
//!          per resource, at its infoOffset:
//!              id:u32  length:u32  valueCount:u32  { configId:u32 valueOffset:u32 }*
//! values   at valueOffset: len:u16  bytes
//! ```
//!
//! Every offset is a file offset. Names and values carry no NUL.

use std::collections::HashMap;

use super::reader::Reader;
use super::v1::read_params;
use super::value::ResourceType;
use super::{Entries, Entry, ResourceIndexError, Result, Tables};

const KEY_HEADER_LEN: usize = 12;
const TYPE_HEADER_LEN: usize = 12;
const ITEM_HEADER_LEN: usize = 12;
const CONFIG_ROW_LEN: usize = 8;

/// `header` stands just past the version text.
pub(super) fn read<'a>(bytes: &'a [u8], mut header: Reader<'a>) -> Result<Tables<'a>> {
    header.u32("file size")?;
    let key_count = header.count(KEY_HEADER_LEN, "qualifier set count")?;
    let data_offset = header.u32("data offset")?;
    Reader::at(bytes, data_offset, "data block")?.tag("DATA")?;

    let mut qualifiers = Vec::with_capacity(key_count);
    // Config ids are positions in practice, but the format stores them.
    let mut positions = HashMap::with_capacity(key_count);
    for position in 0..key_count {
        header.tag("KEYS")?;
        positions.insert(header.u32("qualifier set id")?, position);
        qualifiers.push(read_params(&mut header)?);
    }

    let mut ids = header;
    ids.tag("IDSS")?;
    ids.u32("id block length")?;
    let type_count = ids.count(TYPE_HEADER_LEN, "type count")?;
    ids.u32("id count")?;
    let mut entries = Entries::for_index(bytes);
    for _ in 0..type_count {
        let kind = ResourceType::from_code(ids.u32("resource type")?);
        ids.u32("type block length")?;
        for _ in 0..ids.count(ITEM_HEADER_LEN, "resource count")? {
            let id = ids.u32("resource id")?;
            let info = ids.u32("resource info offset")?;
            let name_len = ids.count(1, "resource name length")?;
            let name = ids.take(name_len, "resource name")?;
            read_values(bytes, Item { id, kind, name, info }, &positions, &mut entries)?;
        }
    }
    Ok(Tables { qualifiers, entries: entries.entries })
}

/// A row of a type's name table.
struct Item<'a> {
    id: u32,
    kind: ResourceType,
    name: &'a [u8],
    /// Where the resource's list of values is.
    info: u32,
}

fn read_values<'a>(bytes: &'a [u8], item: Item<'a>, positions: &HashMap<u32, usize>, entries: &mut Entries<'a>) -> Result<()> {
    let Item { id, kind, name, info } = item;
    let mut rows = Reader::at(bytes, info, "resource info")?;
    let found = rows.u32("resource info id")?;
    if found != id {
        return Err(ResourceIndexError::IdMismatch { listed: id, found, offset: rows.pos() - 4 });
    }
    rows.u32("resource info length")?;
    for _ in 0..rows.count(CONFIG_ROW_LEN, "value count")? {
        let config = rows.u32("qualifier set id")?;
        let offset = rows.u32("value offset")?;
        let &qualifiers = positions.get(&config).ok_or(ResourceIndexError::UnknownQualifiers { id, config })?;
        let value = Reader::at(bytes, offset, "value")?.sized16("value")?;
        entries.push(Entry { id, kind, qualifiers, name, value })?;
    }
    Ok(())
}
