//! Persisted locator tables: a [`SearchState`] written to bytes that a later
//! process maps and views in place ([`SearchState::from_persisted`]), so it
//! skips the table builds and shares one copy of the tables with every other
//! process mapping the same file.
//!
//! Layout (native endian; the endian marker rejects a file from a machine of
//! the other byte order):
//!
//! ```text
//! 0    magic "ASCLOCS\0"
//! 8    u32 format version, u32 endian marker
//! 16   u32 DEX length, u32 DEX checksum, [u8; 20] DEX signature, u32 table mask
//! 48   [u64; SCALARS] scalar fields of the tables
//! ..   [(u64 byte offset, u64 element count); SLOTS] table directory
//! ..   tables, each 8-byte aligned
//! ```
//!
//! The DEX identity in the header ties the file to the buffer it was built
//! from; every table is bounds-checked against that DEX on load. Lookups stay
//! bounds-checked too, so a damaged file gives wrong answers at worst, never
//! a crash.

use crate::insn_locator::InsnLocator;
use crate::locators::{FieldLocator, MemberLocator, MethodLocator, StringLocator, TypeLocator};
use crate::table::{Backing, Pod, Table};
use crate::SearchState;
use asc_dex::Dex;

/// Version of the persisted layout; part of the cache key of persisted
/// states, so a format change simply misses old files.
pub const FORMAT_VERSION: u32 = 1;

const MAGIC: &[u8; 8] = b"ASCLOCS\0";
const ENDIAN: u32 = 0x0102_0304;
const SCALARS: usize = 16;
const SLOTS: usize = 16;
const SCALARS_OFF: usize = 48;
const DIR_OFF: usize = SCALARS_OFF + SCALARS * 8;
const DATA_OFF: usize = DIR_OFF + SLOTS * 16;

// Table mask bits.
const STRINGS: u32 = 1;
const TYPES: u32 = 1 << 1;
const METHODS: u32 = 1 << 2;
const FIELDS: u32 = 1 << 3;
const INSNS: u32 = 1 << 4;

// Scalar indexes.
const S_STRDATA_START: usize = 0;
const S_STRDATA_END: usize = 1;
const S_METHOD_TABLE_OFF: usize = 2;
const S_METHOD_COUNT: usize = 3;
const S_FIELD_TABLE_OFF: usize = 4;
const S_FIELD_COUNT: usize = 5;
const S_BASE_BUCKET: usize = 6;
const S_CODE_START: usize = 7;
const S_CODE_END: usize = 8;

// Directory slots. A member locator's `by_class` is absent (count
// `u64::MAX`) when its id table is class-sorted.
const T_STRINGS: usize = 0;
const T_TYPES: usize = 1;
const T_METHOD_NAMES: usize = 2;
const T_METHOD_CLASSES: usize = 3;
const T_FIELD_NAMES: usize = 4;
const T_FIELD_CLASSES: usize = 5;
const T_INSN_TABLE: usize = 6;
const T_INSN_BOUNDS: usize = 7;
const T_INSN_SHARED_STARTS: usize = 8;
const T_INSN_SHARED_IDS: usize = 9;
const ABSENT: u64 = u64::MAX;

impl SearchState {
    /// Which tables the state holds, as a bit mask (compare two masks to
    /// tell whether a persisted copy lacks tables built since).
    pub fn table_mask(&self) -> u32 {
        (self.strings.get().is_some() as u32 * STRINGS)
            | (self.types.get().is_some() as u32 * TYPES)
            | (self.methods.get().is_some() as u32 * METHODS)
            | (self.fields.get().is_some() as u32 * FIELDS)
            | (self.insns.get().is_some() as u32 * INSNS)
    }

    /// Adopt the tables of `other` (built from the same buffer) that this
    /// state lacks; tables it already has are kept.
    pub fn fill_from(&self, other: SearchState) {
        let SearchState { strings, types, methods, fields, insns } = other;
        if let Some(t) = strings.into_inner() {
            let _ = self.strings.set(t);
        }
        if let Some(t) = types.into_inner() {
            let _ = self.types.set(t);
        }
        if let Some(t) = methods.into_inner() {
            let _ = self.methods.set(t);
        }
        if let Some(t) = fields.into_inner() {
            let _ = self.fields.set(t);
        }
        if let Some(t) = insns.into_inner() {
            let _ = self.insns.set(t);
        }
    }

    /// Bytes of the tables viewed in persisted bytes rather than held on
    /// the heap ([`SearchState::heap_bytes`] counts the others).
    pub fn mapped_bytes(&self) -> usize {
        let m = |t: &Table<[u32; 2]>| t.mapped_bytes();
        let w = |t: &Table<u32>| t.mapped_bytes();
        self.strings.get().map_or(0, |s| m(&s.offsets))
            + self.types.get().map_or(0, |t| m(&t.by_string))
            + [self.methods.get().map(|l| &l.0), self.fields.get().map(|l| &l.0)]
                .into_iter()
                .flatten()
                .map(|l| m(&l.by_name) + l.by_class.as_ref().map_or(0, m))
                .sum::<usize>()
            + self.insns.get().map_or(0, |i| w(&i.table) + w(&i.method_bounds) + w(&i.shared_starts) + w(&i.shared_ids))
    }

    /// The tables built so far, as bytes for [`SearchState::from_persisted`].
    /// `dex` must be the buffer they were built from.
    pub fn persist(&self, dex: &Dex<'_>) -> Vec<u8> {
        let mut w = Writer { out: vec![0u8; DATA_OFF], scalars: [0; SCALARS], dir: [(0, ABSENT); SLOTS] };
        let h = dex.header();
        w.out[..8].copy_from_slice(MAGIC);
        w.put_u32(8, FORMAT_VERSION);
        w.put_u32(12, ENDIAN);
        w.put_u32(16, dex.buf().len() as u32);
        w.put_u32(20, h.checksum);
        w.out[24..44].copy_from_slice(&h.signature);
        w.put_u32(44, self.table_mask());
        if let Some(s) = self.strings.get() {
            w.scalars[S_STRDATA_START] = s.strdata_start as u64;
            w.scalars[S_STRDATA_END] = s.strdata_end as u64;
            w.table(T_STRINGS, &s.offsets);
        }
        if let Some(t) = self.types.get() {
            w.table(T_TYPES, &t.by_string);
        }
        if let Some(m) = self.methods.get() {
            w.member(&m.0, S_METHOD_TABLE_OFF, S_METHOD_COUNT, T_METHOD_NAMES, T_METHOD_CLASSES);
        }
        if let Some(f) = self.fields.get() {
            w.member(&f.0, S_FIELD_TABLE_OFF, S_FIELD_COUNT, T_FIELD_NAMES, T_FIELD_CLASSES);
        }
        if let Some(i) = self.insns.get() {
            w.scalars[S_BASE_BUCKET] = i.base_bucket as u64;
            w.scalars[S_CODE_START] = i.code_item_start as u64;
            w.scalars[S_CODE_END] = i.code_item_end as u64;
            w.table(T_INSN_TABLE, &i.table);
            w.table(T_INSN_BOUNDS, &i.method_bounds);
            w.table(T_INSN_SHARED_STARTS, &i.shared_starts);
            w.table(T_INSN_SHARED_IDS, &i.shared_ids);
        }
        w.finish()
    }

    /// A state viewing the tables persisted in `backing` (which must start
    /// at an 8-byte aligned address, as a mapped file does), or `None` when
    /// they were not built from `dex` or do not fit it. Tables the file
    /// lacks are built on demand as usual.
    pub fn from_persisted(dex: &Dex<'_>, backing: Backing) -> Option<SearchState> {
        let r = Reader { bytes: (*backing).as_ref(), backing: &backing };
        let h = dex.header();
        let buf_len = dex.buf().len();
        if r.bytes.get(..8)? != MAGIC
            || r.u32(8)? != FORMAT_VERSION
            || r.u32(12)? != ENDIAN
            || r.u32(16)? as usize != buf_len
            || r.u32(20)? != h.checksum
            || r.bytes.get(24..44)? != h.signature
        {
            return None;
        }
        let mask = r.u32(44)?;
        let state = SearchState::new();
        if mask & STRINGS != 0 {
            let (start, end) = (r.scalar(S_STRDATA_START)? as usize, r.scalar(S_STRDATA_END)? as usize);
            let offsets: Table<[u32; 2]> = r.table(T_STRINGS)?;
            if start > end || end > buf_len || offsets.len() != dex.string_count() as usize {
                return None;
            }
            let _ = state.strings.set(StringLocator { offsets, strdata_start: start, strdata_end: end });
        }
        if mask & TYPES != 0 {
            let by_string: Table<[u32; 2]> = r.table(T_TYPES)?;
            if by_string.len() != dex.type_count() as usize {
                return None;
            }
            let _ = state.types.set(TypeLocator { by_string });
        }
        if mask & METHODS != 0 {
            let m = r.member(h.method_ids.off, dex.method_count(), S_METHOD_TABLE_OFF, S_METHOD_COUNT, T_METHOD_NAMES, T_METHOD_CLASSES)?;
            let _ = state.methods.set(MethodLocator(m));
        }
        if mask & FIELDS != 0 {
            let f = r.member(h.field_ids.off, dex.field_count(), S_FIELD_TABLE_OFF, S_FIELD_COUNT, T_FIELD_NAMES, T_FIELD_CLASSES)?;
            let _ = state.fields.set(FieldLocator(f));
        }
        if mask & INSNS != 0 {
            let method_cap = (dex.method_count() as usize).min(buf_len / 8);
            let (code_start, code_end) = (r.scalar(S_CODE_START)? as usize, r.scalar(S_CODE_END)? as usize);
            let base_bucket = u32::try_from(r.scalar(S_BASE_BUCKET)?).ok()?;
            let table: Table<u32> = r.table(T_INSN_TABLE)?;
            let method_bounds: Table<u32> = r.table(T_INSN_BOUNDS)?;
            let shared_starts: Table<u32> = r.table(T_INSN_SHARED_STARTS)?;
            let shared_ids: Table<u32> = r.table(T_INSN_SHARED_IDS)?;
            let covered = if table.is_empty() { 0 } else { code_end.checked_sub(code_start)? / 16 };
            if method_bounds.len() != method_cap
                || code_start > code_end
                || code_end > buf_len.saturating_add(16)
                || table.len() != covered
                || (!table.is_empty() && code_start != (base_bucket as usize) << 4)
                || shared_starts.is_empty()
            {
                return None;
            }
            let _ = state.insns.set(InsnLocator {
                base_bucket,
                table,
                shared_starts,
                shared_ids,
                method_bounds,
                code_item_start: code_start,
                code_item_end: code_end,
            });
        }
        Some(state)
    }
}

struct Writer {
    out: Vec<u8>,
    scalars: [u64; SCALARS],
    dir: [(u64, u64); SLOTS],
}

impl Writer {
    fn put_u32(&mut self, at: usize, v: u32) {
        self.out[at..at + 4].copy_from_slice(&v.to_ne_bytes());
    }

    fn table<T: Pod>(&mut self, slot: usize, t: &Table<T>) {
        let off = self.out.len();
        self.out.extend_from_slice(t.as_bytes());
        // Keep every table 8-byte aligned.
        self.out.resize(self.out.len().next_multiple_of(8), 0);
        self.dir[slot] = (off as u64, t.len() as u64);
    }

    fn member(&mut self, m: &MemberLocator, s_off: usize, s_count: usize, t_names: usize, t_classes: usize) {
        self.scalars[s_off] = m.table_off as u64;
        self.scalars[s_count] = m.count as u64;
        self.table(t_names, &m.by_name);
        if let Some(c) = &m.by_class {
            self.table(t_classes, c);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        for (i, s) in self.scalars.iter().enumerate() {
            self.out[SCALARS_OFF + i * 8..SCALARS_OFF + i * 8 + 8].copy_from_slice(&s.to_ne_bytes());
        }
        for (i, (off, len)) in self.dir.iter().enumerate() {
            let at = DIR_OFF + i * 16;
            self.out[at..at + 8].copy_from_slice(&off.to_ne_bytes());
            self.out[at + 8..at + 16].copy_from_slice(&len.to_ne_bytes());
        }
        self.out
    }
}

struct Reader<'b> {
    bytes: &'b [u8],
    backing: &'b Backing,
}

impl Reader<'_> {
    fn u32(&self, at: usize) -> Option<u32> {
        Some(u32::from_ne_bytes(self.bytes.get(at..at + 4)?.try_into().ok()?))
    }

    fn u64(&self, at: usize) -> Option<u64> {
        Some(u64::from_ne_bytes(self.bytes.get(at..at + 8)?.try_into().ok()?))
    }

    fn scalar(&self, i: usize) -> Option<u64> {
        self.u64(SCALARS_OFF + i * 8)
    }

    /// `(offset, count)` of a slot; `None` when absent.
    fn slot(&self, slot: usize) -> Option<(usize, usize)> {
        let at = DIR_OFF + slot * 16;
        let (off, len) = (self.u64(at)?, self.u64(at + 8)?);
        if len == ABSENT {
            return None;
        }
        Some((usize::try_from(off).ok()?, usize::try_from(len).ok()?))
    }

    fn table<T: Pod>(&self, slot: usize) -> Option<Table<T>> {
        let (off, len) = self.slot(slot)?;
        Table::view(self.backing, off, len)
    }

    fn member(&self, table_off: u32, count: u32, s_off: usize, s_count: usize, t_names: usize, t_classes: usize) -> Option<MemberLocator> {
        if self.scalar(s_off)? != table_off as u64 || self.scalar(s_count)? != count as u64 {
            return None;
        }
        let by_name: Table<[u32; 2]> = self.table(t_names)?;
        let by_class = match self.slot(t_classes) {
            None => None,
            Some(_) => Some(self.table::<[u32; 2]>(t_classes)?),
        };
        if by_name.len() != count as usize || by_class.as_ref().is_some_and(|c| c.len() != count as usize) {
            return None;
        }
        Some(MemberLocator { table_off: table_off as usize, count, by_name, by_class })
    }
}
