use crate::call_site::{CallSite, MethodHandle};
use crate::class_data::ClassData;
use crate::code::CodeItem;
use crate::header::{Header, Section};
use crate::map::{MapItem, MapList};
use crate::{DexError, Result, leb128, map_type, mutf8, u16_at, u32_at};
use std::ops::Range;

/// `proto_id_item`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtoId {
    /// `shorty_idx`: the short-form descriptor, as an index into `string_ids`.
    pub shorty_idx: u32,
    /// `return_type_idx`: the return type, as an index into `type_ids`.
    pub return_type_idx: u32,
    /// `parameters_off`: offset of the parameter `type_list`, `0` for no parameters.
    pub parameters_off: u32,
}

/// `field_id_item`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldId {
    /// `class_idx`: the defining class, as an index into `type_ids`.
    pub class_idx: u16,
    /// `type_idx`: the field type, as an index into `type_ids`.
    pub type_idx: u16,
    /// `name_idx`: the field name, as an index into `string_ids`.
    pub name_idx: u32,
}

/// `method_id_item`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodId {
    /// `class_idx`: the defining class, as an index into `type_ids`.
    pub class_idx: u16,
    /// `proto_idx`: the prototype, as an index into `proto_ids`.
    pub proto_idx: u16,
    /// `name_idx`: the method name, as an index into `string_ids`.
    pub name_idx: u32,
}

/// `class_def_item`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassDef {
    /// `class_idx`: the class, as an index into `type_ids`.
    pub class_idx: u32,
    /// `access_flags`: [`crate::access`] bits.
    pub access_flags: u32,
    /// `superclass_idx`: the superclass, as an index into `type_ids`, or [`crate::NO_INDEX`].
    pub superclass_idx: u32,
    /// `interfaces_off`: offset of the interfaces `type_list`, `0` if none.
    pub interfaces_off: u32,
    /// `source_file_idx`: the source file name, as an index into `string_ids`, or [`crate::NO_INDEX`].
    pub source_file_idx: u32,
    /// `annotations_off`: offset of the `annotations_directory_item`, `0` if none.
    pub annotations_off: u32,
    /// `class_data_off`: offset of the `class_data_item`, `0` if the class has no data.
    pub class_data_off: u32,
    /// `static_values_off`: offset of the `encoded_array_item` of static field initial values, `0` if none.
    pub static_values_off: u32,
}

impl ClassDef {
    /// Size of a `class_def_item` in bytes.
    pub const SIZE: usize = 32;

    /// Parse the `class_def_item` at `off`.
    ///
    /// # Errors
    ///
    /// `Truncated` when the item lies outside `buf`.
    pub fn parse(buf: &[u8], off: usize) -> Result<ClassDef> {
        Ok(ClassDef {
            class_idx: u32_at(buf, off)?,
            access_flags: u32_at(buf, off + 4)?,
            superclass_idx: u32_at(buf, off + 8)?,
            interfaces_off: u32_at(buf, off + 12)?,
            source_file_idx: u32_at(buf, off + 16)?,
            annotations_off: u32_at(buf, off + 20)?,
            class_data_off: u32_at(buf, off + 24)?,
            static_values_off: u32_at(buf, off + 28)?,
        })
    }
}

/// A `string_data_item` view: the declared UTF-16 length and the raw MUTF-8
/// payload (without the terminating NUL).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringItem<'a> {
    /// Offset of the item (the uleb128 length prefix) inside the DEX buffer.
    pub data_off: u32,
    /// `utf16_size`: declared length in UTF-16 code units (not always accurate).
    pub utf16_len: u32,
    /// MUTF-8 payload, without the terminating NUL.
    pub bytes: &'a [u8],
}

/// Lazily parsed DEX file over a borrowed buffer.
#[derive(Debug, Clone)]
pub struct Dex<'a> {
    buf: &'a [u8],
    header: Header,
    name: String,
    /// Offset of the last NUL byte: no `string_data_item` starting after it
    /// can be terminated.
    last_nul: Option<usize>,
}

impl<'a> Dex<'a> {
    /// Parse the header of `buf`. Nothing else is read.
    ///
    /// # Errors
    ///
    /// As [`Header::parse`].
    pub fn parse(buf: &'a [u8]) -> Result<Self> {
        Self::with_name(buf, "")
    }

    /// Parse the header of `buf` and remember a display name for it.
    ///
    /// # Errors
    ///
    /// As [`Header::parse`].
    pub fn with_name(buf: &'a [u8], name: impl Into<String>) -> Result<Self> {
        let header = Header::parse(buf)?;
        // A DEX ends with its map list (or zero padding): this stops at once.
        let last_nul = memchr::memrchr(0, buf);
        Ok(Dex { buf, header, name: name.into(), last_nul })
    }

    /// The whole underlying buffer (for a 041 container, all of it).
    #[inline]
    pub fn buf(&self) -> &'a [u8] {
        self.buf
    }

    /// The parsed `header_item`.
    #[inline]
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Display name given to [`Self::with_name`], empty for [`Self::parse`].
    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Number of `string_ids` entries.
    #[inline]
    pub fn string_count(&self) -> u32 {
        self.header.string_ids.size
    }
    /// Number of `type_ids` entries.
    #[inline]
    pub fn type_count(&self) -> u32 {
        self.header.type_ids.size
    }
    /// Number of `proto_ids` entries.
    #[inline]
    pub fn proto_count(&self) -> u32 {
        self.header.proto_ids.size
    }
    /// Number of `field_ids` entries.
    #[inline]
    pub fn field_count(&self) -> u32 {
        self.header.field_ids.size
    }
    /// Number of `method_ids` entries.
    #[inline]
    pub fn method_count(&self) -> u32 {
        self.header.method_ids.size
    }
    /// Number of `class_defs` entries.
    #[inline]
    pub fn class_def_count(&self) -> u32 {
        self.header.class_defs.size
    }

    #[inline]
    fn check_idx(&self, what: &'static str, index: u32, size: u32) -> Result<()> {
        if index >= size { Err(DexError::IndexOutOfRange { what, index, size }) } else { Ok(()) }
    }

    // ---- strings ---------------------------------------------------------

    /// Offset of the `string_data_item` for string `idx`.
    ///
    /// # Errors
    ///
    /// `IndexOutOfRange` when `idx` is past the table, `Truncated` when the
    /// entry lies outside the buffer.
    #[inline]
    pub fn string_data_off(&self, idx: u32) -> Result<u32> {
        self.check_idx("string", idx, self.header.string_ids.size)?;
        u32_at(self.buf, self.header.string_ids.off as usize + (idx as usize) * 4)
    }

    /// Parse the `string_data_item` located at `data_off`.
    ///
    /// The terminating NUL is searched for within `3 * utf16_len + 1` bytes
    /// first (every UTF-16 code unit is at most three MUTF-8 bytes). Some
    /// tools wrote a code-point or byte count instead, so when that window
    /// holds no NUL the search continues up to the last NUL of the buffer;
    /// an item that starts past it is reported as unterminated at once, so a
    /// NUL-free tail costs nothing however many ids point into it.
    ///
    /// # Errors
    ///
    /// `Truncated` when the length prefix is cut off, `UnterminatedString` when
    /// no NUL ends the payload.
    pub fn string_item_at(&self, data_off: u32) -> Result<StringItem<'a>> {
        let (utf16_len, n) = leb128::read_uleb128(self.buf, data_off as usize)?;
        let start = data_off as usize + n;
        let rest = self.buf.get(start..).ok_or(DexError::Truncated { what: "string_data", offset: start })?;
        let bound = (utf16_len as usize).saturating_mul(3).saturating_add(1).min(rest.len());
        let end = match memchr::memchr(0, &rest[..bound]) {
            Some(end) => end,
            None => {
                let unterminated = DexError::UnterminatedString(data_off as usize);
                let last = self.last_nul.filter(|&l| l >= start + bound).ok_or(unterminated.clone())?;
                bound + memchr::memchr(0, &rest[bound..=last - start]).ok_or(unterminated)?
            }
        };
        Ok(StringItem { data_off, utf16_len, bytes: &rest[..end] })
    }

    /// Raw MUTF-8 view of string `idx`.
    ///
    /// # Errors
    ///
    /// As [`Self::string_data_off`] and [`Self::string_item_at`].
    #[inline]
    pub fn string_item(&self, idx: u32) -> Result<StringItem<'a>> {
        self.string_item_at(self.string_data_off(idx)?)
    }

    /// Raw MUTF-8 bytes of string `idx` (no terminator).
    ///
    /// # Errors
    ///
    /// As [`Self::string_data_off`] and [`Self::string_item_at`].
    #[inline]
    pub fn string_bytes(&self, idx: u32) -> Result<&'a [u8]> {
        Ok(self.string_item(idx)?.bytes)
    }

    /// Decoded string `idx`.
    ///
    /// # Errors
    ///
    /// As [`Self::string_data_off`] and [`Self::string_item_at`].
    #[inline]
    pub fn string(&self, idx: u32) -> Result<String> {
        Ok(mutf8::decode(self.string_bytes(idx)?))
    }

    /// Binary search the sorted string table for `s` (MUTF-8 bytes, compared
    /// by UTF-16 code units like the table is sorted, see
    /// [`mutf8::cmp_utf16`]).
    ///
    /// # Errors
    ///
    /// When a probed string cannot be read (see [`Self::string_bytes`]).
    pub fn find_string_idx(&self, s: &[u8]) -> Result<Option<u32>> {
        binary_search(self.header.string_ids.size, |mid| Ok(mutf8::cmp_utf16(self.string_bytes(mid)?, s)))
    }

    // ---- types -----------------------------------------------------------

    /// `descriptor_idx` of type `idx`.
    ///
    /// # Errors
    ///
    /// `IndexOutOfRange` when `idx` is past the table, `Truncated` when the
    /// entry lies outside the buffer.
    #[inline]
    pub fn type_string_idx(&self, idx: u32) -> Result<u32> {
        self.check_idx("type", idx, self.header.type_ids.size)?;
        u32_at(self.buf, self.header.type_ids.off as usize + (idx as usize) * 4)
    }

    /// Raw descriptor bytes of type `idx`.
    ///
    /// # Errors
    ///
    /// As [`Self::type_string_idx`] and [`Self::string_bytes`].
    #[inline]
    pub fn type_bytes(&self, idx: u32) -> Result<&'a [u8]> {
        self.string_bytes(self.type_string_idx(idx)?)
    }

    /// Decoded descriptor of type `idx`.
    ///
    /// # Errors
    ///
    /// As [`Self::type_string_idx`] and [`Self::string`].
    #[inline]
    pub fn type_descriptor(&self, idx: u32) -> Result<String> {
        self.string(self.type_string_idx(idx)?)
    }

    /// Binary search the sorted type table for an exact descriptor.
    ///
    /// `descriptor` must be MUTF-8 (see [`mutf8::encode`]): string ids are
    /// sorted by UTF-16 code units, which MUTF-8 byte order follows except
    /// for `U+0000` ([`mutf8::cmp_utf16`] handles that), while UTF-8 byte
    /// order diverges once a supplementary character is involved.
    ///
    /// # Errors
    ///
    /// When a probed descriptor cannot be read (see [`Self::type_bytes`]).
    pub fn find_type_idx(&self, descriptor: &[u8]) -> Result<Option<u32>> {
        binary_search(self.header.type_ids.size, |mid| Ok(mutf8::cmp_utf16(self.type_bytes(mid)?, descriptor)))
    }

    /// Type indexes of the classes nested in class type `type_idx` with `$`:
    /// for `LA;`, every descriptor starting with `LA$` (matched by UTF-16
    /// code units like the table is sorted, see [`mutf8::cmp_utf16_prefix`]).
    /// They form one run, and as `$` sorts below `;` the run ends shortly
    /// before `type_idx`; galloping back from there finds an empty run in two
    /// comparisons. Empty for a descriptor that does not end in `;`.
    ///
    /// # Errors
    ///
    /// When `type_idx` or a probed descriptor cannot be read (see
    /// [`Self::type_bytes`]).
    pub fn nested_type_idx_range(&self, type_idx: u32) -> Result<Range<u32>> {
        let Some(name) = self.type_bytes(type_idx)?.strip_suffix(b";") else {
            return Ok(type_idx..type_idx);
        };
        let prefix = [name, b"$"].concat();
        let cmp = |idx: u32| Ok(mutf8::cmp_utf16_prefix(self.type_bytes(idx)?, &prefix));
        let end = partition_point_near_end(type_idx, |idx| Ok(cmp(idx)?.is_le()))?;
        let start = partition_point_near_end(end, |idx| Ok(cmp(idx)?.is_lt()))?;
        Ok(start..end)
    }

    // ---- protos ----------------------------------------------------------

    /// The `proto_id_item` at index `idx`.
    ///
    /// # Errors
    ///
    /// `IndexOutOfRange` when `idx` is past the table, `Truncated` when the
    /// entry lies outside the buffer.
    #[inline]
    pub fn proto_id(&self, idx: u32) -> Result<ProtoId> {
        self.check_idx("proto", idx, self.header.proto_ids.size)?;
        let off = self.header.proto_ids.off as usize + (idx as usize) * 12;
        Ok(ProtoId {
            shorty_idx: u32_at(self.buf, off)?,
            return_type_idx: u32_at(self.buf, off + 4)?,
            parameters_off: u32_at(self.buf, off + 8)?,
        })
    }

    /// Parse a `type_list` at `off` (an offset of 0 yields an empty list).
    ///
    /// # Errors
    ///
    /// `Truncated` when the size word is out of the buffer, `BadRange` when the
    /// entries are.
    pub fn type_list(&self, off: u32) -> Result<Vec<u16>> {
        if off == 0 {
            return Ok(Vec::new());
        }
        let size = u32_at(self.buf, off as usize)? as usize;
        let start = off as usize + 4;
        let bytes = self.buf.get(start..start + size * 2).ok_or(DexError::BadRange { what: "type_list", offset: off as usize })?;
        Ok(bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes([c[0], c[1]])).collect())
    }

    /// Parameter type indexes of proto `idx`.
    ///
    /// # Errors
    ///
    /// As [`Self::proto_id`] and [`Self::type_list`].
    #[inline]
    pub fn proto_params(&self, idx: u32) -> Result<Vec<u16>> {
        self.type_list(self.proto_id(idx)?.parameters_off)
    }

    // ---- fields / methods ------------------------------------------------

    /// The `field_id_item` at index `idx`.
    ///
    /// # Errors
    ///
    /// `IndexOutOfRange` when `idx` is past the table, `Truncated` when the
    /// entry lies outside the buffer.
    #[inline]
    pub fn field_id(&self, idx: u32) -> Result<FieldId> {
        self.check_idx("field", idx, self.header.field_ids.size)?;
        let off = self.header.field_ids.off as usize + (idx as usize) * 8;
        Ok(FieldId { class_idx: u16_at(self.buf, off)?, type_idx: u16_at(self.buf, off + 2)?, name_idx: u32_at(self.buf, off + 4)? })
    }

    /// The `method_id_item` at index `idx`.
    ///
    /// # Errors
    ///
    /// `IndexOutOfRange` when `idx` is past the table, `Truncated` when the
    /// entry lies outside the buffer.
    #[inline]
    pub fn method_id(&self, idx: u32) -> Result<MethodId> {
        self.check_idx("method", idx, self.header.method_ids.size)?;
        let off = self.header.method_ids.off as usize + (idx as usize) * 8;
        Ok(MethodId { class_idx: u16_at(self.buf, off)?, proto_idx: u16_at(self.buf, off + 2)?, name_idx: u32_at(self.buf, off + 4)? })
    }

    /// `Lpkg/Cls;->name` for a method index.
    ///
    /// # Errors
    ///
    /// As [`Self::method_id`], [`Self::type_descriptor`] and [`Self::string`].
    pub fn method_display(&self, idx: u32) -> Result<String> {
        let m = self.method_id(idx)?;
        Ok(format!("{}->{}", self.type_descriptor(m.class_idx as u32)?, self.string(m.name_idx)?))
    }

    /// `Lpkg/Cls;->name` for a field index.
    ///
    /// # Errors
    ///
    /// As [`Self::field_id`], [`Self::type_descriptor`] and [`Self::string`].
    pub fn field_display(&self, idx: u32) -> Result<String> {
        let f = self.field_id(idx)?;
        Ok(format!("{}->{}", self.type_descriptor(f.class_idx as u32)?, self.string(f.name_idx)?))
    }

    // ---- classes ---------------------------------------------------------

    /// File offset of `class_def_item` `i`. Not bounds checked.
    #[inline]
    pub fn class_def_off(&self, i: u32) -> usize {
        self.header.class_defs.off as usize + (i as usize) * ClassDef::SIZE
    }

    /// The `class_def_item` at index `i`.
    ///
    /// # Errors
    ///
    /// `IndexOutOfRange` when `i` is past the table, `Truncated` when the
    /// entry lies outside the buffer.
    #[inline]
    pub fn class_def(&self, i: u32) -> Result<ClassDef> {
        self.check_idx("class_def", i, self.header.class_defs.size)?;
        ClassDef::parse(self.buf, self.class_def_off(i))
    }

    /// Locate the class definition for a descriptor such as `Lcom/poc/Main;`.
    /// Returns the class_def index and the parsed definition.
    ///
    /// # Errors
    ///
    /// As [`Self::find_type_idx`] and [`Self::find_class_def_by_type`].
    pub fn find_class_def(&self, descriptor: &[u8]) -> Result<Option<(u32, ClassDef)>> {
        let Some(type_idx) = self.find_type_idx(descriptor)? else {
            return Ok(None);
        };
        self.find_class_def_by_type(type_idx)
    }

    /// Locate the class definition whose `class_idx` equals `type_idx`.
    ///
    /// # Errors
    ///
    /// `BadRange` when the `class_defs` table does not fit in the buffer.
    pub fn find_class_def_by_type(&self, type_idx: u32) -> Result<Option<(u32, ClassDef)>> {
        let size = self.header.class_defs.size;
        let base = self.header.class_defs.off as usize;
        let end = base + size as usize * ClassDef::SIZE;
        if end > self.buf.len() {
            return Err(DexError::BadRange { what: "class_defs", offset: base });
        }
        for i in 0..size {
            let off = base + i as usize * ClassDef::SIZE;
            if u32_at(self.buf, off)? == type_idx {
                return Ok(Some((i, ClassDef::parse(self.buf, off)?)));
            }
        }
        Ok(None)
    }

    /// The class definitions whose `class_idx` lies in `types`, with their
    /// class_def index, in class_def order. Only the `class_idx` of the other
    /// definitions is read.
    ///
    /// # Errors
    ///
    /// `BadRange` when the `class_defs` table does not fit in the buffer.
    pub fn find_class_defs_by_type_range(&self, types: Range<u32>) -> Result<Vec<(u32, ClassDef)>> {
        let mut found = Vec::new();
        if types.is_empty() {
            return Ok(found);
        }
        let size = self.header.class_defs.size;
        let base = self.header.class_defs.off as usize;
        let end = base + size as usize * ClassDef::SIZE;
        if end > self.buf.len() {
            return Err(DexError::BadRange { what: "class_defs", offset: base });
        }
        for i in 0..size {
            let off = base + i as usize * ClassDef::SIZE;
            if types.contains(&u32_at(self.buf, off)?) {
                found.push((i, ClassDef::parse(self.buf, off)?));
            }
        }
        Ok(found)
    }

    /// Iterate over all class definitions.
    pub fn class_defs(&self) -> impl Iterator<Item = Result<ClassDef>> + '_ {
        (0..self.header.class_defs.size).map(move |i| self.class_def(i))
    }

    /// Parse the `class_data_item` at `off` (0 yields an empty class data).
    ///
    /// # Errors
    ///
    /// As [`ClassData::parse`].
    #[inline]
    pub fn class_data(&self, off: u32) -> Result<ClassData> {
        ClassData::parse(self.buf, off as usize)
    }

    /// Parse the `code_item` at `off`.
    ///
    /// # Errors
    ///
    /// As [`CodeItem::parse`].
    #[inline]
    pub fn code_item(&self, off: u32) -> Result<CodeItem<'a>> {
        CodeItem::parse(self.buf, off as usize)
    }

    // ---- method handles / call sites --------------------------------------

    /// The `(offset, count)` of the map list entry of type `kind`; empty when
    /// the map has no such entry. In bounds when the map list validated.
    fn map_section(&self, kind: u16) -> Result<Section> {
        Ok(self.map()?.find(kind).map(|item| Section { off: item.offset, size: item.size }).unwrap_or_default())
    }

    /// Number of `method_handle_item`s.
    ///
    /// # Errors
    ///
    /// When the map list is invalid (see [`Self::map`]).
    pub fn method_handle_count(&self) -> Result<u32> {
        Ok(self.map_section(map_type::METHOD_HANDLE)?.size)
    }

    /// Method handle `idx` (the operand of `const-method-handle` and of
    /// `VALUE_METHOD_HANDLE` encoded values).
    ///
    /// # Errors
    ///
    /// `IndexOutOfRange` for `idx` or for a field/method index outside its
    /// table, `Malformed` for an unknown handle type, and the errors of
    /// [`Self::map`].
    pub fn method_handle(&self, idx: u32) -> Result<MethodHandle> {
        let section = self.map_section(map_type::METHOD_HANDLE)?;
        self.check_idx("method_handle", idx, section.size)?;
        let handle = MethodHandle::parse(self.buf, section.off as usize + idx as usize * MethodHandle::SIZE)?;
        let (what, size) = if handle.kind.is_field_accessor() { ("field", self.field_count()) } else { ("method", self.method_count()) };
        self.check_idx(what, handle.field_or_method_idx.into(), size)?;
        Ok(handle)
    }

    /// Number of `call_site_id_item`s.
    ///
    /// # Errors
    ///
    /// When the map list is invalid (see [`Self::map`]).
    pub fn call_site_count(&self) -> Result<u32> {
        Ok(self.map_section(map_type::CALL_SITE_ID)?.size)
    }

    /// `call_site_off` of call site `idx`: the offset of its
    /// `encoded_array_item`.
    ///
    /// # Errors
    ///
    /// `IndexOutOfRange` for `idx` and the errors of [`Self::map`].
    pub fn call_site_off(&self, idx: u32) -> Result<u32> {
        let section = self.map_section(map_type::CALL_SITE_ID)?;
        self.check_idx("call_site", idx, section.size)?;
        u32_at(self.buf, section.off as usize + idx as usize * 4)
    }

    /// Call site `idx` (the operand of `invoke-custom` and
    /// `invoke-custom/range`), with the bootstrap method handle, name and
    /// proto indexes checked against their tables.
    ///
    /// # Errors
    ///
    /// `IndexOutOfRange` for `idx` or a leading element, the errors of
    /// [`CallSite::parse`] and of [`Self::map`].
    pub fn call_site(&self, idx: u32) -> Result<CallSite> {
        let site = CallSite::parse(self.buf, self.call_site_off(idx)? as usize)?;
        self.check_idx("method_handle", site.bootstrap, self.method_handle_count()?)?;
        self.check_idx("string", site.method_name, self.string_count())?;
        self.check_idx("proto", site.method_type, self.proto_count())?;
        Ok(site)
    }

    // ---- map list --------------------------------------------------------

    /// The validated map list (see [`MapList::parse`]); empty when `map_off`
    /// is 0.
    ///
    /// # Errors
    ///
    /// When the list or one of its entries does not fit in the file.
    pub fn map(&self) -> Result<MapList<'a>> {
        match self.header.map_off {
            0 => Ok(MapList::EMPTY),
            off => MapList::parse(self.buf, off as usize),
        }
    }

    /// Parse the map list leniently: stops at the first entry out of the
    /// buffer, entries are not validated (see [`Self::map`] for that).
    /// Empty when `map_off` is 0 or invalid.
    pub fn map_list(&self) -> Vec<MapItem> {
        let off = self.header.map_off as usize;
        if off == 0 {
            return Vec::new();
        }
        let Ok(size) = u32_at(self.buf, off) else { return Vec::new() };
        let mut items = Vec::with_capacity(size.min(64) as usize);
        let mut p = off + 4;
        for _ in 0..size {
            let (Ok(kind), Ok(sz), Ok(o)) = (u16_at(self.buf, p), u32_at(self.buf, p + 4), u32_at(self.buf, p + 8)) else {
                break;
            };
            items.push(MapItem { kind, size: sz, offset: o });
            p += 12;
        }
        items
    }

    /// Find one map item by type.
    pub fn map_item(&self, kind: u16) -> Option<MapItem> {
        let off = self.header.map_off as usize;
        if off == 0 {
            return None;
        }
        let size = u32_at(self.buf, off).ok()?;
        let mut p = off + 4;
        for _ in 0..size {
            if u16_at(self.buf, p).ok()? == kind {
                return Some(MapItem { kind, size: u32_at(self.buf, p + 4).ok()?, offset: u32_at(self.buf, p + 8).ok()? });
            }
            p += 12;
        }
        None
    }
}

/// The first index below `end` from which `pred` is false up to `end`,
/// `pred` being true on a prefix of `0..end` and false on the rest. Gallops
/// back from `end` and bisects the bracket found, so it costs a logarithm of
/// the distance from `end` rather than of `end`.
fn partition_point_near_end(end: u32, mut pred: impl FnMut(u32) -> Result<bool>) -> Result<u32> {
    // `pred` is false on `hi..end`.
    let (mut hi, mut step) = (end, 1u32);
    while hi > 0 {
        let probe = hi.saturating_sub(step);
        if pred(probe)? {
            let (mut left, mut right) = (probe + 1, hi);
            while left < right {
                let mid = left + (right - left) / 2;
                if pred(mid)? {
                    left = mid + 1;
                } else {
                    right = mid;
                }
            }
            return Ok(left);
        }
        hi = probe;
        step = step.saturating_mul(2);
    }
    Ok(0)
}

/// Binary search over `size` sorted items; `cmp(mid)` orders item `mid`
/// against the target.
fn binary_search(size: u32, mut cmp: impl FnMut(u32) -> Result<std::cmp::Ordering>) -> Result<Option<u32>> {
    let (mut left, mut right) = (0u32, size);
    while left < right {
        let mid = left + (right - left) / 2;
        match cmp(mid)? {
            std::cmp::Ordering::Equal => return Ok(Some(mid)),
            std::cmp::Ordering::Less => left = mid + 1,
            std::cmp::Ordering::Greater => right = mid,
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoded::EncodedValue;
    use crate::{MethodHandleKind, map_type};
    use asc_fixture::make_dex;

    #[test]
    fn string_items_find_their_terminator() {
        let data = make_dex();
        let dex = Dex::parse(&data).unwrap();
        assert_eq!(dex.string(5).unwrap(), "token");
        assert_eq!(dex.find_type_idx(b"Lexample/Test;").unwrap(), Some(0));
        let off = dex.string_data_off(5).unwrap() as usize;
        assert_eq!(data[off], 5); // uleb128 utf16_len

        // Declared length too short for the payload (a code-point or byte count
        // written by an older tool): the terminator past the window is used.
        let mut short = data.clone();
        short[off] = 1;
        let dex = Dex::parse(&short).unwrap();
        assert_eq!(dex.string(5).unwrap(), "token");

        // No NUL anywhere up to the end of the buffer: rejected.
        let mut broken = data.clone();
        broken[off + 1 + 5..].fill(b'x');
        let dex = Dex::parse(&broken).unwrap();
        assert_eq!(dex.string_item(5), Err(DexError::UnterminatedString(off)));

        // A generous declared length still finds the real terminator.
        let mut long = data;
        long[off] = 0x7f;
        let dex = Dex::parse(&long).unwrap();
        assert_eq!(dex.string(5).unwrap(), "token");
    }

    /// A header-only DEX (id tables declared but empty: only their sizes
    /// matter) followed by `method_handle_item`s, `call_site_id_item`s, the
    /// call sites' encoded arrays and the map list.
    fn call_site_dex(handles: &[(u16, u16)], sites: &[Vec<EncodedValue>]) -> Vec<u8> {
        let mut buf = vec![0u8; crate::HEADER_SIZE];
        buf[..8].copy_from_slice(b"dex\n038\0");
        for (size_off, size) in [(0x38, 5u32), (0x48, 2), (0x50, 2), (0x58, 3)] {
            buf[size_off..size_off + 4].copy_from_slice(&size.to_le_bytes());
        }
        let handles_off = buf.len() as u32;
        for &(kind, idx) in handles {
            buf.extend_from_slice(&[kind.to_le_bytes(), [0; 2], idx.to_le_bytes(), [0; 2]].concat());
        }
        let ids_off = buf.len();
        buf.resize(ids_off + 4 * sites.len(), 0);
        for (i, site) in sites.iter().enumerate() {
            let off = buf.len() as u32;
            buf[ids_off + 4 * i..ids_off + 4 * i + 4].copy_from_slice(&off.to_le_bytes());
            crate::encoded::write_array(&mut buf, site, &crate::encoded::Identity);
        }
        buf.resize(buf.len().next_multiple_of(4), 0);
        let map_off = buf.len() as u32;
        buf[0x34..0x38].copy_from_slice(&map_off.to_le_bytes());
        let items = [
            (map_type::HEADER, 1, 0),
            (map_type::METHOD_HANDLE, handles.len() as u32, handles_off),
            (map_type::CALL_SITE_ID, sites.len() as u32, ids_off as u32),
            (map_type::MAP_LIST, 1, map_off),
        ];
        buf.extend_from_slice(&(items.len() as u32).to_le_bytes());
        for (kind, size, off) in items {
            buf.extend_from_slice(&[&kind.to_le_bytes()[..], &[0; 2], &size.to_le_bytes(), &off.to_le_bytes()].concat());
        }
        buf
    }

    fn site(bootstrap: u32, name: u32, proto: u32) -> Vec<EncodedValue> {
        vec![EncodedValue::MethodHandle(bootstrap), EncodedValue::String(name), EncodedValue::MethodType(proto)]
    }

    #[test]
    fn method_handles_and_call_sites_resolve_through_the_map() {
        let mut extra = site(1, 4, 0);
        extra.push(EncodedValue::MethodHandle(0));
        let data = call_site_dex(&[(0x04, 2), (0x03, 1)], &[site(0, 4, 1), extra]);
        let dex = Dex::parse(&data).unwrap();
        assert_eq!(dex.map().unwrap().len(), 4);
        assert_eq!(dex.method_handle_count(), Ok(2));
        assert_eq!(dex.method_handle(0), Ok(MethodHandle { kind: MethodHandleKind::InvokeStatic, field_or_method_idx: 2 }));
        assert_eq!(dex.method_handle(1), Ok(MethodHandle { kind: MethodHandleKind::InstanceGet, field_or_method_idx: 1 }));
        assert_eq!(dex.method_handle(2), Err(DexError::IndexOutOfRange { what: "method_handle", index: 2, size: 2 }));
        assert_eq!(dex.call_site_count(), Ok(2));
        assert_eq!(dex.call_site(0), Ok(CallSite { bootstrap: 0, method_name: 4, method_type: 1, extra_args: vec![] }));
        assert_eq!(dex.call_site(1).unwrap().extra_args, [EncodedValue::MethodHandle(0)]);
        assert_eq!(dex.call_site(2), Err(DexError::IndexOutOfRange { what: "call_site", index: 2, size: 2 }));
        assert_eq!(dex.call_site_off(u32::MAX), Err(DexError::IndexOutOfRange { what: "call_site", index: u32::MAX, size: 2 }));

        // No map list: no handles, no call sites.
        let mut no_map = data.clone();
        no_map[0x34..0x38].fill(0);
        let dex = Dex::parse(&no_map).unwrap();
        assert_eq!((dex.method_handle_count(), dex.call_site_count()), (Ok(0), Ok(0)));
        assert!(dex.call_site(0).is_err());
    }

    #[test]
    fn call_site_and_handle_indexes_are_checked() {
        let oob = |what, index, size| DexError::IndexOutOfRange { what, index, size };
        // Handle targets: method 3 of 3, field 2 of 2.
        let data = call_site_dex(&[(0x04, 3), (0x00, 2), (0x09, 0)], &[site(3, 0, 0), site(0, 5, 0), site(0, 0, 2)]);
        let dex = Dex::parse(&data).unwrap();
        assert_eq!(dex.method_handle(0), Err(oob("method", 3, 3)));
        assert_eq!(dex.method_handle(1), Err(oob("field", 2, 2)));
        assert!(matches!(dex.method_handle(2), Err(DexError::Malformed { what: "method_handle_item", .. })));
        assert_eq!(dex.call_site(0), Err(oob("method_handle", 3, 3)));
        assert_eq!(dex.call_site(1), Err(oob("string", 5, 5)));
        assert_eq!(dex.call_site(2), Err(oob("proto", 2, 2)));
    }

    #[test]
    fn hostile_map_entries_are_rejected() {
        let data = call_site_dex(&[(0x04, 0)], &[site(0, 0, 0)]);
        let map_off = u32_at(&data, 0x34).unwrap() as usize;
        // Entry 1 is METHOD_HANDLE, entry 2 CALL_SITE_ID.
        let patch = |entry: usize, size: u32, off: u32| {
            let mut data = data.clone();
            let at = map_off + 4 + entry * MapItem::SIZE;
            data[at + 4..at + 8].copy_from_slice(&size.to_le_bytes());
            data[at + 8..at + 12].copy_from_slice(&off.to_le_bytes());
            data
        };
        for data in [patch(1, u32::MAX, 0x70), patch(2, u32::MAX, 0x78), patch(2, 1, u32::MAX), patch(1, 1, data.len() as u32 - 4)] {
            let dex = Dex::parse(&data).unwrap();
            assert!(matches!(dex.map(), Err(DexError::BadRange { what: "map_item", .. })));
            assert!(dex.method_handle(0).is_err());
            assert!(dex.call_site(0).is_err());
            assert!(dex.call_site_count().is_err());
        }
        // Map list count out of range.
        let mut data = data.clone();
        data[map_off..map_off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let dex = Dex::parse(&data).unwrap();
        assert_eq!(dex.map(), Err(DexError::BadRange { what: "map_list", offset: map_off }));
        // A call site offset pointing past the end of the file.
        let data = call_site_dex(&[(0x04, 0)], &[site(0, 0, 0)]);
        let mut bad = data.clone();
        bad[0x78..0x7c].copy_from_slice(&(data.len() as u32).to_le_bytes());
        assert!(matches!(Dex::parse(&bad).unwrap().call_site(0), Err(DexError::Truncated { .. })));
    }

    #[test]
    fn nested_type_ranges_match_a_prefix_scan() {
        let mut builder = asc_fixture::DexBuilder::new();
        let mut names =
            vec!["LA;", "LA$;", "LA#;", "LA%;", "LA0;", "LA\0;", "LAB;", "LB$x;", "L外😀;", "L外😀$内;", "L外😀\u{FFFF};", "[LA;", "I"];
        let many: Vec<String> = (0..40).map(|i| format!("LA${i};")).chain((0..5).map(|i| format!("LA$1$x{i};"))).collect();
        names.extend(many.iter().map(String::as_str));
        for name in &names {
            builder.type_(name);
        }
        let data = builder.resolve().finish();
        let dex = Dex::parse(&data).unwrap();
        let types: Vec<String> = (0..dex.type_count()).map(|i| dex.type_descriptor(i).unwrap()).collect();
        assert!(types.windows(2).all(|w| w[0].encode_utf16().lt(w[1].encode_utf16())), "{types:?}");
        for (idx, name) in types.iter().enumerate() {
            let range = dex.nested_type_idx_range(idx as u32).unwrap();
            let expected: Vec<&str> = match name.strip_suffix(';') {
                Some(stem) => types.iter().map(String::as_str).filter(|t| t.starts_with(&format!("{stem}$"))).collect(),
                None => Vec::new(),
            };
            let found: Vec<&str> = range.map(|i| types[i as usize].as_str()).collect();
            assert_eq!(found, expected, "{name}");
        }
        let a = types.iter().position(|t| t == "LA;").unwrap() as u32;
        assert_eq!(dex.nested_type_idx_range(a).unwrap().len(), 1 + 40 + 5);
    }
}
