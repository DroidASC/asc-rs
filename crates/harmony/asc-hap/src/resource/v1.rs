//! The `Restool <version>` layout.
//!
//! ```text
//! header   version[128]  fileSize:u32  keyCount:u32
//! keys     keyCount x { "KEYS"  idSetOffset:u32  paramCount:u32  { keyType:u32 value:u32 }* }
//! id sets  one per key, at idSetOffset: "IDSS"  idCount:u32  { id:u32 recordOffset:u32 }*
//! records  size:u32  type:u32  id:u32  valueLen:u16 value  nameLen:u16 name
//! ```
//!
//! `size` counts what follows it. Value and name each end with a NUL
//! that their length counts.

use super::qualifier::{Qualifier, Qualifiers};
use super::reader::{widen, Reader};
use super::value::ResourceType;
use super::{Entries, Entry, ResourceIndexError, Result, Tables};

const KEY_HEADER_LEN: usize = 12;
const PARAM_LEN: usize = 8;
const ID_ROW_LEN: usize = 8;

/// `header` stands just past the version text.
pub(super) fn read<'a>(bytes: &'a [u8], mut header: Reader<'a>) -> Result<Tables<'a>> {
    // The declared file size is not needed to read the tables; a file
    // shorter than its tables fails where the missing bytes are wanted.
    header.u32("file size")?;
    let key_count = header.count(KEY_HEADER_LEN, "qualifier set count")?;
    let mut qualifiers = Vec::with_capacity(key_count);
    let mut id_sets = Vec::with_capacity(key_count);
    for _ in 0..key_count {
        header.tag("KEYS")?;
        id_sets.push(header.u32("id set offset")?);
        qualifiers.push(read_params(&mut header)?);
    }

    let mut entries = Entries::for_index(bytes);
    for (set, &offset) in id_sets.iter().enumerate() {
        let mut rows = Reader::at(bytes, offset, "id set")?;
        rows.tag("IDSS")?;
        for _ in 0..rows.count(ID_ROW_LEN, "id count")? {
            let id = rows.u32("resource id")?;
            let record = rows.u32("record offset")?;
            entries.push(read_record(bytes, id, record, set)?)?;
        }
    }
    Ok(Tables { qualifiers, entries: entries.entries })
}

pub(super) fn read_params(reader: &mut Reader<'_>) -> Result<Qualifiers> {
    let count = reader.count(PARAM_LEN, "qualifier count")?;
    let params = (0..count).map(|_| Ok(Qualifier::from_raw(reader.u32("qualifier key")?, reader.u32("qualifier value")?)));
    params.collect::<Result<Vec<_>>>().map(Qualifiers::new)
}

fn read_record(bytes: &[u8], id: u32, offset: u32, qualifiers: usize) -> Result<Entry<'_>> {
    let mut reader = Reader::at(bytes, offset, "record")?;
    let size = widen(reader.u32("record size")?);
    let mut record = reader.sub(size, "record")?;
    let kind = ResourceType::from_code(record.u32("record type")?);
    let found = record.u32("record id")?;
    if found != id {
        return Err(ResourceIndexError::IdMismatch { listed: id, found, offset: record.pos() - 4 });
    }
    let value = record.sized16("record value")?;
    let name = record.sized16("record name")?;
    let name = name.strip_suffix(&[0]).unwrap_or(name);
    Ok(Entry { id, kind, qualifiers, name, value })
}
