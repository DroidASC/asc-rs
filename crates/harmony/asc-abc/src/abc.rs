use std::cmp::Ordering;

use crate::class::{Class, ClassEntry, Field, ForeignClass, Method};
use crate::reader::{Reader, entity_pos, read_u32, slice_at};
use crate::{AbcError, Annotation, Code, DebugInfo, Header, INVALID_OFFSET, LiteralArray, ModuleRecord, RegionHeader, Result, StringData};

/// A borrowed ABC (Panda) file. Opening reads the header and checks that the
/// index tables are in bounds; everything else is parsed on demand.
#[derive(Debug, Clone, Copy)]
pub struct Abc<'a> {
    buf: &'a [u8],
    header: Header,
    /// Set by [`Abc::with_sorted_classes`].
    sorted_classes: bool,
}

impl<'a> Abc<'a> {
    /// Open an ABC file: parse the header, then run [`Abc::check_layout`].
    ///
    /// The layout check reads the class index and the region headers (a few
    /// kilobytes), not the file body. Only when it fails is the Adler-32
    /// checksum computed over the whole buffer, to tell an encrypted file
    /// ([`AbcError::Encrypted`]) from a damaged one.
    ///
    /// # Errors
    /// `TooSmall`, `BadMagic`, `Encrypted`, or the layout error.
    pub fn parse(buf: &'a [u8]) -> Result<Abc<'a>> {
        let abc = Self::parse_lenient(buf)?;
        abc.check_layout()?;
        Ok(abc)
    }

    /// Open an ABC file checking nothing but the magic. For inspecting
    /// damaged files: accessors still bounds-check every read.
    ///
    /// # Errors
    /// `TooSmall` or `BadMagic`.
    pub fn parse_lenient(buf: &'a [u8]) -> Result<Abc<'a>> {
        Ok(Abc { buf, header: Header::parse(buf)?, sorted_classes: false })
    }

    /// The whole file buffer.
    #[inline]
    pub fn bytes(&self) -> &'a [u8] {
        self.buf
    }

    /// The parsed file header.
    #[inline]
    pub fn header(&self) -> &Header {
        &self.header
    }

    // ---- integrity -------------------------------------------------------

    /// Check that the class index, the line number program index, the
    /// literal array index and every region's tables lie inside the file and
    /// that every class index entry points into the file body.
    ///
    /// # Errors
    /// [`AbcError::Encrypted`] when the check fails and the stored checksum
    /// does not match either (plain header, scrambled body); otherwise the
    /// structural error itself. The checksum is not looked at when the
    /// layout is sound: many tools rewrite files without updating it.
    pub fn check_layout(&self) -> Result<()> {
        self.probe_layout().map_err(|err| {
            let computed = self.compute_checksum();
            if computed == self.header.checksum { err } else { AbcError::Encrypted { stored: self.header.checksum, computed } }
        })
    }

    fn probe_layout(&self) -> Result<()> {
        for off in self.class_index()?.iter() {
            entity_pos(self.buf, off, "class")?;
        }
        self.line_program_index()?;
        self.literal_array_index()?;
        for region in self.regions()?.iter() {
            let h = region.header();
            if h.start > h.end {
                return Err(AbcError::Malformed { what: "region header", offset: region.header_pos, reason: "start is past end" });
            }
            region.class_table()?;
            region.entity_table()?;
            region.field_table()?;
            region.proto_table()?;
        }
        Ok(())
    }

    /// Adler-32 of the file from offset 12 on, the value the writer stores
    /// in the header. A full pass over the buffer.
    pub fn compute_checksum(&self) -> u32 {
        adler32(self.buf.get(12..).unwrap_or_default())
    }

    // ---- strings ---------------------------------------------------------

    /// The `String` item at `off`.
    ///
    /// # Errors
    /// `BadOffset`, `Truncated`, `Malformed` or `UnterminatedString`.
    pub fn string(&self, off: u32) -> Result<StringData<'a>> {
        Reader::new(self.buf, entity_pos(self.buf, off, "string")?).string()
    }

    // ---- class index -----------------------------------------------------

    fn table(&self, off: u32, count: u32, what: &'static str) -> Result<OffsetTable<'a>> {
        OffsetTable::at(self.buf, off, count, what)
    }

    /// Offsets of all classes, local and foreign. The writer sorts them by
    /// class name.
    ///
    /// # Errors
    /// `Truncated` when the table does not fit in the file.
    pub fn class_index(&self) -> Result<OffsetTable<'a>> {
        self.table(self.header.class_idx_off, self.header.num_classes, "class index")
    }

    /// The class index entry at file offset `off`.
    ///
    /// # Errors
    /// Any parse error of the class header.
    pub fn class_entry(&self, off: u32) -> Result<ClassEntry<'a>> {
        if self.header.is_foreign(off) {
            let name = Reader::new(self.buf, entity_pos(self.buf, off, "foreign class")?).string()?;
            Ok(ClassEntry::Foreign(ForeignClass { off, descriptor: name }))
        } else {
            Class::parse(*self, off).map(ClassEntry::Local)
        }
    }

    /// The class defined at file offset `off`.
    ///
    /// # Errors
    /// `Malformed` when `off` is in the foreign region, or any parse error.
    pub fn class(&self, off: u32) -> Result<Class<'a>> {
        match self.class_entry(off)? {
            ClassEntry::Local(class) => Ok(class),
            ClassEntry::Foreign(_) => Err(AbcError::Malformed { what: "class", offset: off as usize, reason: "declared in another file" }),
        }
    }

    /// Every class index entry in index order.
    ///
    /// # Errors
    /// `Truncated` when the class index does not fit in the file.
    pub fn classes(&self) -> Result<impl Iterator<Item = Result<ClassEntry<'a>>> + 'a + use<'a>> {
        let abc = *self;
        Ok(self.class_index()?.iter().map(move |off| abc.class_entry(off)))
    }

    /// Look a class up by descriptor (`L<record name>;`, MUTF-8).
    ///
    /// Binary search first; when that misses, a linear scan, because the
    /// sort order is a promise of the writer that an obfuscator can break.
    ///
    /// # Errors
    /// `Truncated` when the class index does not fit in the file; entries
    /// that fail to parse are skipped.
    pub fn find_class(&self, descriptor: &[u8]) -> Result<Option<ClassEntry<'a>>> {
        self.find_class_by(|stored| stored.cmp(descriptor))
    }

    /// Look a class up by record name (the descriptor without `L` and `;`).
    ///
    /// # Errors
    /// See [`Abc::find_class`].
    pub fn find_record(&self, name: &[u8]) -> Result<Option<ClassEntry<'a>>> {
        self.find_class_by(|stored| stored.iter().cmp(b"L".iter().chain(name).chain(b";")))
    }

    /// Whether the class index is in the order lookups by name search it in,
    /// as the compiler writes it. Reads every name once.
    pub fn classes_are_sorted(&self) -> bool {
        let Ok(index) = self.class_index() else { return false };
        let name = |i: u32| index.get(i).and_then(|off| self.string(off).ok()).map(|name| name.bytes);
        let mut previous = name(0);
        (1..index.len()).all(|i| {
            let current = name(i);
            let ordered = matches!((previous, current), (Some(a), Some(b)) if a < b);
            previous = current;
            ordered
        })
    }

    /// This file, known to have a sorted class index
    /// ([`Abc::classes_are_sorted`], asked once by whoever keeps the file):
    /// a lookup by name that finds nothing then says so after its binary
    /// search, instead of reading the whole index to be sure.
    #[must_use]
    pub fn with_sorted_classes(mut self, sorted: bool) -> Abc<'a> {
        self.sorted_classes = sorted;
        self
    }

    fn find_class_by(&self, cmp: impl Fn(&[u8]) -> Ordering) -> Result<Option<ClassEntry<'a>>> {
        let index = self.class_index()?;
        let order = |i: u32| index.get(i).and_then(|off| self.string(off).ok()).map(|name| cmp(name.bytes));
        let (mut left, mut right) = (0u32, index.len());
        let mut found = None;
        while left < right {
            let mid = left + (right - left) / 2;
            match order(mid) {
                Some(Ordering::Equal) => {
                    found = Some(mid);
                    break;
                }
                Some(Ordering::Less) => left = mid + 1,
                Some(Ordering::Greater) => right = mid,
                None => break,
            }
        }
        // An index out of order (a damaged or hand-made file) is read through.
        let found =
            found.or_else(|| if self.sorted_classes { None } else { (0..index.len()).find(|&i| order(i) == Some(Ordering::Equal)) });
        found.and_then(|i| index.get(i)).map(|off| self.class_entry(off)).transpose()
    }

    // ---- regions ---------------------------------------------------------

    /// The region index.
    ///
    /// # Errors
    /// `Truncated` when the region headers do not fit in the file.
    pub fn regions(&self) -> Result<Regions<'a>> {
        let off = self.header.index_section_off as usize;
        let len = (self.header.num_indexes as usize)
            .checked_mul(RegionHeader::SIZE)
            .ok_or(AbcError::Truncated { what: "region index", offset: off })?;
        slice_at(self.buf, off, len, "region index").map(|table| Regions { buf: self.buf, table, table_pos: off })
    }

    /// The region whose `[start, end)` contains file offset `off`, which is
    /// how the runtime (`File::GetIndexHeader`) picks the index tables of an
    /// entity.
    ///
    /// # Errors
    /// `NoRegion` when no region covers `off`.
    pub fn region_of(&self, off: u32) -> Result<Region<'a>> {
        self.regions()?.containing(off).ok_or(AbcError::NoRegion { offset: off })
    }

    /// Resolve a 16-bit id used by an entity at `holder_off` (for an
    /// instruction operand: the offset of the *method*, not of its code) to
    /// the file offset of the string, method or literal array it names.
    ///
    /// # Errors
    /// `NoRegion`, `IndexOutOfRange` or `Truncated`.
    pub fn resolve_entity(&self, holder_off: u32, idx: u16) -> Result<u32> {
        self.region_of(holder_off)?.entity_offset(idx)
    }

    // ---- entities by offset ----------------------------------------------

    /// The method at file offset `off` (local or foreign).
    ///
    /// # Errors
    /// Any parse error.
    pub fn method(&self, off: u32) -> Result<Method<'a>> {
        Method::parse(*self, entity_pos(self.buf, off, "method")?)
    }

    /// The field at file offset `off` (local or foreign).
    ///
    /// # Errors
    /// Any parse error.
    pub fn field(&self, off: u32) -> Result<Field<'a>> {
        Field::parse(*self, entity_pos(self.buf, off, "field")?)
    }

    /// The code item at file offset `off`.
    ///
    /// # Errors
    /// Any parse error.
    pub fn code(&self, off: u32) -> Result<Code<'a>> {
        Code::parse(self.buf, off)
    }

    /// The debug info item at file offset `off`.
    ///
    /// # Errors
    /// Any parse error.
    pub fn debug_info(&self, off: u32) -> Result<DebugInfo<'a>> {
        DebugInfo::parse(*self, off)
    }

    /// The annotation at file offset `off`.
    ///
    /// # Errors
    /// Any parse error.
    pub fn annotation(&self, off: u32) -> Result<Annotation<'a>> {
        Annotation::parse(self.buf, off)
    }

    /// The literal array at file offset `off`.
    ///
    /// # Errors
    /// `BadOffset` or `Truncated`.
    pub fn literal_array(&self, off: u32) -> Result<LiteralArray<'a>> {
        LiteralArray::parse(self.buf, off)
    }

    /// The module record at file offset `off` (the value of a record's
    /// `moduleRecordIdx` field).
    ///
    /// # Errors
    /// `BadOffset` or `Truncated`.
    pub fn module_record(&self, off: u32) -> Result<ModuleRecord<'a>> {
        ModuleRecord::parse(self.buf, off)
    }

    /// The module request phase table at file offset `off` (the value of a
    /// record's `moduleRequestPhaseIdx` field): one byte per module request
    /// of the record, in request order. Zero is an ordinary import; the
    /// compiler writes other values for requests that are loaded lazily.
    ///
    /// The table is `u32 count` followed by `count` bytes
    /// (`AbcLiteralArrayProcessor::FillModuleRequestPhase`). It has no
    /// tags, so reading it as a literal array yields garbage.
    ///
    /// # Errors
    /// `BadOffset` or `Truncated`.
    pub fn module_request_phases(&self, off: u32) -> Result<&'a [u8]> {
        let mut r = Reader::new(self.buf, entity_pos(self.buf, off, "module request phases")?);
        let count = r.u32()? as usize;
        r.take(count, "module request phases")
    }

    // ---- header indexes --------------------------------------------------

    /// Offsets of all literal arrays, or `None` for files newer than
    /// 12.0.6.0, whose header has no such index (literal arrays are then
    /// only reachable from fields and instruction operands).
    ///
    /// # Errors
    /// `Truncated` when the table does not fit in the file.
    pub fn literal_array_index(&self) -> Result<Option<OffsetTable<'a>>> {
        if !self.header.has_literal_array_index() {
            return Ok(None);
        }
        self.table(self.header.literalarray_idx_off, self.header.num_literalarrays, "literal array index").map(Some)
    }

    /// Offsets of all line number programs; debug info refers to them by
    /// position in this table.
    ///
    /// # Errors
    /// `Truncated` when the table does not fit in the file.
    pub fn line_program_index(&self) -> Result<OffsetTable<'a>> {
        self.table(self.header.lnp_idx_off, self.header.num_lnps, "line number program index")
    }
}

/// A table of little-endian `u32` file offsets (unaligned).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OffsetTable<'a> {
    bytes: &'a [u8],
}

impl<'a> OffsetTable<'a> {
    /// The table of `count` entries at file offset `off`. An empty table is
    /// valid wherever it claims to be, and writers since 12.0.x store an
    /// absent one (the field and proto tables of dynamic-language files) as
    /// offset and count both `0xFFFF_FFFF`.
    fn at(buf: &'a [u8], off: u32, count: u32, what: &'static str) -> Result<OffsetTable<'a>> {
        if count == 0 || (off, count) == (INVALID_OFFSET, INVALID_OFFSET) {
            return Ok(OffsetTable { bytes: &[] });
        }
        let len = (count as usize).checked_mul(4).ok_or(AbcError::Truncated { what, offset: off as usize })?;
        slice_at(buf, off as usize, len, what).map(|bytes| OffsetTable { bytes })
    }

    /// `bytes` must be a whole number of 4-byte entries; a trailing partial
    /// entry is ignored.
    pub(crate) fn new(bytes: &'a [u8]) -> OffsetTable<'a> {
        OffsetTable { bytes }
    }

    /// Number of entries. Tables are sized by 32-bit header fields.
    #[inline]
    pub fn len(&self) -> u32 {
        u32::try_from(self.bytes.len() / 4).unwrap_or(u32::MAX)
    }

    /// Whether the table has no entries.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Entry `i` (a file offset), or `None` past the end.
    #[inline]
    pub fn get(&self, i: u32) -> Option<u32> {
        read_u32(self.bytes, (i as usize).checked_mul(4)?).ok()
    }

    /// The entries in table order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = u32> + DoubleEndedIterator + 'a + use<'a> {
        self.bytes.as_chunks::<4>().0.iter().map(|c| u32::from_le_bytes(*c))
    }

    /// Index of the first entry equal to `off`.
    pub fn position(&self, off: u32) -> Option<u32> {
        self.iter().position(|entry| entry == off).and_then(|i| u32::try_from(i).ok())
    }
}

/// The region index: an array of [`RegionHeader`]s.
#[derive(Debug, Clone, Copy)]
pub struct Regions<'a> {
    buf: &'a [u8],
    table: &'a [u8],
    table_pos: usize,
}

impl<'a> Regions<'a> {
    /// Number of regions.
    #[inline]
    pub fn len(&self) -> u32 {
        u32::try_from(self.table.len() / RegionHeader::SIZE).unwrap_or(u32::MAX)
    }

    /// Whether the file has no regions.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// Region number `index`.
    pub fn get(&self, index: u32) -> Option<Region<'a>> {
        let rel = (index as usize).checked_mul(RegionHeader::SIZE)?;
        let header = RegionHeader::parse(self.table, rel).ok()?;
        Some(Region { buf: self.buf, index, header, header_pos: self.table_pos + rel })
    }

    /// Every region in index order; entries whose header is truncated are skipped.
    pub fn iter(&self) -> impl Iterator<Item = Region<'a>> + 'a + use<'a> {
        let regions = *self;
        (0..self.len()).filter_map(move |i| regions.get(i))
    }

    /// The first region whose `[start, end)` contains `off`. A linear scan:
    /// files have a handful of regions and their order is not trusted.
    pub fn containing(&self, off: u32) -> Option<Region<'a>> {
        self.iter().find(|region| region.header.contains(off))
    }
}

/// One region and its 16-bit index tables.
#[derive(Debug, Clone, Copy)]
pub struct Region<'a> {
    buf: &'a [u8],
    index: u32,
    header: RegionHeader,
    header_pos: usize,
}

impl<'a> Region<'a> {
    /// Position of this region in the region index.
    #[inline]
    pub fn index(&self) -> u32 {
        self.index
    }

    /// The region's header entry.
    #[inline]
    pub fn header(&self) -> &RegionHeader {
        &self.header
    }

    /// Whether file offset `off` lies in this region.
    #[inline]
    pub fn contains(&self, off: u32) -> bool {
        self.header.contains(off)
    }

    fn table(&self, off: u32, count: u32, what: &'static str) -> Result<OffsetTable<'a>> {
        OffsetTable::at(self.buf, off, count, what)
    }

    /// The table instruction operands index: file offsets of methods,
    /// strings and literal arrays mixed together (`MethodRegionIndex`; the
    /// dynamic language stores all three kinds in it).
    ///
    /// # Errors
    /// `Truncated` when the table does not fit in the file.
    pub fn entity_table(&self) -> Result<OffsetTable<'a>> {
        self.table(self.header.method_idx_off, self.header.method_idx_size, "region method index")
    }

    /// Field types: each entry is a primitive type code or a class offset.
    ///
    /// # Errors
    /// `Truncated` when the table does not fit in the file.
    pub fn class_table(&self) -> Result<OffsetTable<'a>> {
        self.table(self.header.class_idx_off, self.header.class_idx_size, "region class index")
    }

    /// # Errors
    /// `Truncated` when the table does not fit in the file.
    pub fn field_table(&self) -> Result<OffsetTable<'a>> {
        self.table(self.header.field_idx_off, self.header.field_idx_size, "region field index")
    }

    /// # Errors
    /// `Truncated` when the table does not fit in the file.
    pub fn proto_table(&self) -> Result<OffsetTable<'a>> {
        self.table(self.header.proto_idx_off, self.header.proto_idx_size, "region proto index")
    }

    /// File offset of the string, method or literal array a 16-bit
    /// instruction operand names.
    ///
    /// # Errors
    /// `IndexOutOfRange` or `Truncated`.
    pub fn entity_offset(&self, idx: u16) -> Result<u32> {
        let table = self.entity_table()?;
        table.get(u32::from(idx)).ok_or(AbcError::IndexOutOfRange { what: "region method index", index: u32::from(idx), size: table.len() })
    }

    /// The 16-bit id under which instructions of this region name the
    /// entity at file offset `off`, or `None` when the region never refers
    /// to it. Scanning for references starts here: find the id, then search
    /// only this region's methods for it.
    ///
    /// # Errors
    /// `Truncated` when the table does not fit in the file.
    pub fn entity_idx(&self, off: u32) -> Result<Option<u16>> {
        Ok(self.entity_table()?.position(off).and_then(|i| u16::try_from(i).ok()))
    }

    /// Entry `idx` of the class table.
    ///
    /// # Errors
    /// `IndexOutOfRange` or `Truncated`.
    pub fn class_entry(&self, idx: u16) -> Result<u32> {
        let table = self.class_table()?;
        table.get(u32::from(idx)).ok_or(AbcError::IndexOutOfRange { what: "region class index", index: u32::from(idx), size: table.len() })
    }
}

/// Adler-32 (zlib's definition), summed in blocks short enough that the
/// 32-bit accumulators cannot overflow before the modulo.
fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    const BLOCK: usize = 5552;
    let (mut a, mut b) = (1u32, 0u32);
    for block in data.chunks(BLOCK) {
        for &byte in block {
            a += u32::from(byte);
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adler32_matches_reference_values() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
        assert_eq!(adler32(&[0xff; 100_000]), 0x149A_302C);
    }

    #[test]
    fn module_request_phases_are_counted_bytes() {
        let mut buf = crate::MAGIC.to_vec();
        buf.resize(crate::HEADER_SIZE + 1, 0);
        let off = u32::try_from(buf.len()).unwrap();
        // Read as a literal array this would be "5 values": tag 0, tag 1 ...
        buf.extend_from_slice(&[5, 0, 0, 0, 0, 1, 0, 0, 2, 0xee]);
        let abc = Abc::parse_lenient(&buf).unwrap();
        assert_eq!(abc.module_request_phases(off), Ok(&[0u8, 1, 0, 0, 2][..]));

        let cut = u32::try_from(buf.len()).unwrap();
        buf.extend_from_slice(&[9, 0, 0, 0, 1, 2]);
        let abc = Abc::parse_lenient(&buf).unwrap();
        assert!(matches!(abc.module_request_phases(cut), Err(AbcError::Truncated { .. })));
        assert!(matches!(abc.module_request_phases(4), Err(AbcError::BadOffset { .. })));
        assert!(matches!(abc.module_request_phases(u32::MAX), Err(AbcError::BadOffset { .. })));
    }

    #[test]
    fn offset_table_reads_unaligned_entries() {
        let bytes = [1u8, 0, 0, 0, 2, 0, 0, 0, 0xff, 0xff, 0xff, 0xff];
        let table = OffsetTable { bytes: &bytes };
        assert_eq!(table.len(), 3);
        assert_eq!(table.iter().collect::<Vec<_>>(), [1, 2, u32::MAX]);
        assert_eq!((table.get(1), table.get(3), table.get(u32::MAX)), (Some(2), None, None));
        assert_eq!((table.position(u32::MAX), table.position(7)), (Some(2), None));
    }
}
