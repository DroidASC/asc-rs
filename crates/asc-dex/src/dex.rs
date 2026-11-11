use crate::class_data::ClassData;
use crate::code::CodeItem;
use crate::header::Header;
use crate::{DexError, Result, leb128, mutf8, u16_at, u32_at};
use std::ops::Range;

/// One entry of the map list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapItem {
    pub kind: u16,
    pub size: u32,
    pub offset: u32,
}

/// `proto_id_item`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtoId {
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub parameters_off: u32,
}

/// `field_id_item`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldId {
    pub class_idx: u16,
    pub type_idx: u16,
    pub name_idx: u32,
}

/// `method_id_item`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodId {
    pub class_idx: u16,
    pub proto_idx: u16,
    pub name_idx: u32,
}

/// `class_def_item`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassDef {
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: u32,
    pub interfaces_off: u32,
    pub source_file_idx: u32,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
}

impl ClassDef {
    pub const SIZE: usize = 32;

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
    pub utf16_len: u32,
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
    pub fn parse(buf: &'a [u8]) -> Result<Self> {
        Self::with_name(buf, "")
    }

    /// Parse the header of `buf` and remember a display name for it.
    pub fn with_name(buf: &'a [u8], name: impl Into<String>) -> Result<Self> {
        let header = Header::parse(buf)?;
        // A DEX ends with its map list (or zero padding): this stops at once.
        let last_nul = memchr::memrchr(0, buf);
        Ok(Dex { buf, header, name: name.into(), last_nul })
    }

    #[inline]
    pub fn buf(&self) -> &'a [u8] {
        self.buf
    }

    #[inline]
    pub fn header(&self) -> &Header {
        &self.header
    }

    #[inline]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[inline]
    pub fn string_count(&self) -> u32 {
        self.header.string_ids.size
    }
    #[inline]
    pub fn type_count(&self) -> u32 {
        self.header.type_ids.size
    }
    #[inline]
    pub fn proto_count(&self) -> u32 {
        self.header.proto_ids.size
    }
    #[inline]
    pub fn field_count(&self) -> u32 {
        self.header.field_ids.size
    }
    #[inline]
    pub fn method_count(&self) -> u32 {
        self.header.method_ids.size
    }
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
    #[inline]
    pub fn string_item(&self, idx: u32) -> Result<StringItem<'a>> {
        self.string_item_at(self.string_data_off(idx)?)
    }

    /// Raw MUTF-8 bytes of string `idx` (no terminator).
    #[inline]
    pub fn string_bytes(&self, idx: u32) -> Result<&'a [u8]> {
        Ok(self.string_item(idx)?.bytes)
    }

    /// Decoded string `idx`.
    #[inline]
    pub fn string(&self, idx: u32) -> Result<String> {
        Ok(mutf8::decode(self.string_bytes(idx)?))
    }

    /// Binary search the sorted string table for `s` (MUTF-8 bytes, compared
    /// by UTF-16 code units like the table is sorted, see
    /// [`mutf8::cmp_utf16`]).
    pub fn find_string_idx(&self, s: &[u8]) -> Result<Option<u32>> {
        binary_search(self.header.string_ids.size, |mid| Ok(mutf8::cmp_utf16(self.string_bytes(mid)?, s)))
    }

    // ---- types -----------------------------------------------------------

    /// `descriptor_idx` of type `idx`.
    #[inline]
    pub fn type_string_idx(&self, idx: u32) -> Result<u32> {
        self.check_idx("type", idx, self.header.type_ids.size)?;
        u32_at(self.buf, self.header.type_ids.off as usize + (idx as usize) * 4)
    }

    /// Raw descriptor bytes of type `idx`.
    #[inline]
    pub fn type_bytes(&self, idx: u32) -> Result<&'a [u8]> {
        self.string_bytes(self.type_string_idx(idx)?)
    }

    /// Decoded descriptor of type `idx`.
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
    pub fn find_type_idx(&self, descriptor: &[u8]) -> Result<Option<u32>> {
        binary_search(self.header.type_ids.size, |mid| Ok(mutf8::cmp_utf16(self.type_bytes(mid)?, descriptor)))
    }

    /// Type indexes of the classes nested in class type `type_idx` with `$`:
    /// for `LA;`, every descriptor starting with `LA$` (matched by UTF-16
    /// code units like the table is sorted, see [`mutf8::cmp_utf16_prefix`]).
    /// They form one run, and as `$` sorts below `;` the run ends shortly
    /// before `type_idx`; galloping back from there finds an empty run in two
    /// comparisons. Empty for a descriptor that does not end in `;`.
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
    #[inline]
    pub fn proto_params(&self, idx: u32) -> Result<Vec<u16>> {
        self.type_list(self.proto_id(idx)?.parameters_off)
    }

    // ---- fields / methods ------------------------------------------------

    #[inline]
    pub fn field_id(&self, idx: u32) -> Result<FieldId> {
        self.check_idx("field", idx, self.header.field_ids.size)?;
        let off = self.header.field_ids.off as usize + (idx as usize) * 8;
        Ok(FieldId { class_idx: u16_at(self.buf, off)?, type_idx: u16_at(self.buf, off + 2)?, name_idx: u32_at(self.buf, off + 4)? })
    }

    #[inline]
    pub fn method_id(&self, idx: u32) -> Result<MethodId> {
        self.check_idx("method", idx, self.header.method_ids.size)?;
        let off = self.header.method_ids.off as usize + (idx as usize) * 8;
        Ok(MethodId { class_idx: u16_at(self.buf, off)?, proto_idx: u16_at(self.buf, off + 2)?, name_idx: u32_at(self.buf, off + 4)? })
    }

    /// `Lpkg/Cls;->name` for a method index.
    pub fn method_display(&self, idx: u32) -> Result<String> {
        let m = self.method_id(idx)?;
        Ok(format!("{}->{}", self.type_descriptor(m.class_idx as u32)?, self.string(m.name_idx)?))
    }

    /// `Lpkg/Cls;->name` for a field index.
    pub fn field_display(&self, idx: u32) -> Result<String> {
        let f = self.field_id(idx)?;
        Ok(format!("{}->{}", self.type_descriptor(f.class_idx as u32)?, self.string(f.name_idx)?))
    }

    // ---- classes ---------------------------------------------------------

    #[inline]
    pub fn class_def_off(&self, i: u32) -> usize {
        self.header.class_defs.off as usize + (i as usize) * ClassDef::SIZE
    }

    #[inline]
    pub fn class_def(&self, i: u32) -> Result<ClassDef> {
        self.check_idx("class_def", i, self.header.class_defs.size)?;
        ClassDef::parse(self.buf, self.class_def_off(i))
    }

    /// Locate the class definition for a descriptor such as `Lcom/poc/Main;`.
    /// Returns the class_def index and the parsed definition.
    pub fn find_class_def(&self, descriptor: &[u8]) -> Result<Option<(u32, ClassDef)>> {
        let Some(type_idx) = self.find_type_idx(descriptor)? else {
            return Ok(None);
        };
        self.find_class_def_by_type(type_idx)
    }

    /// Locate the class definition whose `class_idx` equals `type_idx`.
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
    #[inline]
    pub fn class_data(&self, off: u32) -> Result<ClassData> {
        ClassData::parse(self.buf, off as usize)
    }

    /// Parse the `code_item` at `off`.
    #[inline]
    pub fn code_item(&self, off: u32) -> Result<CodeItem<'a>> {
        CodeItem::parse(self.buf, off as usize)
    }

    // ---- map list --------------------------------------------------------

    /// Parse the map list (empty when `map_off` is 0 or invalid).
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
