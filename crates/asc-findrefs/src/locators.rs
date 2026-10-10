//! Query → constant-pool index locators.
//!
//! Locators hold only offsets and index tables; the DEX buffer they were built
//! from is passed back in at lookup time, so they can be cached and shared
//! between threads without any raw-pointer aliasing.

use crate::query::{CompiledClass, CompiledMember, CompiledName, CompiledQuery, Parts};
use crate::{MemberQuery, Result};
use asc_dex::Dex;
use regex::bytes::Regex;
use std::collections::BTreeSet;

/// Locates string indexes by regex over the raw string-data region.
///
/// R8 keeps `string_data_item`s contiguous and in index order, so a match
/// position maps to a string through a binary search over the data offsets.
pub struct StringLocator {
    /// `(data_off, string_idx)` sorted by offset.
    offsets: Vec<(u32, u32)>,
    strdata_start: usize,
    strdata_end: usize,
}

impl StringLocator {
    pub fn build(dex: &Dex<'_>) -> Result<StringLocator> {
        let buf = dex.buf();
        let count = dex.string_count();
        // Every string_id is 4 bytes: never reserve more than the buffer could hold.
        let mut offsets = Vec::with_capacity((count as usize).min(buf.len() / 4));
        for idx in 0..count {
            offsets.push((dex.string_data_off(idx)?, idx));
        }
        offsets.sort_unstable();
        let (strdata_start, strdata_end) = match (offsets.first(), offsets.last()) {
            (Some(&(first, _)), Some(&(last, _))) => {
                let item = dex.string_item_at(last)?;
                let end = (last as usize + asc_dex::leb128::uleb128_len(buf, last as usize)?) + item.bytes.len() + 1;
                let end = end.min(buf.len());
                ((first as usize).min(end), end)
            }
            _ => (0, 0),
        };
        Ok(StringLocator { offsets, strdata_start, strdata_end })
    }

    pub fn string_count(&self) -> usize {
        self.offsets.len()
    }

    /// Index of the string whose data contains absolute offset `pos`.
    fn idx_at(&self, pos: usize) -> Option<u32> {
        let i = self.offsets.partition_point(|&(off, _)| (off as usize) <= pos);
        if i == 0 {
            None
        } else {
            Some(self.offsets[i - 1].1)
        }
    }

    /// The string-data region of `buf` (empty when `buf` is not the buffer the
    /// locator was built from and the offsets do not fit).
    fn region<'b>(&self, buf: &'b [u8]) -> &'b [u8] {
        let end = self.strdata_end.min(buf.len());
        let start = self.strdata_start.min(end);
        &buf[start..end]
    }

    /// All string indexes whose data matches `re`.
    pub fn locate(&self, buf: &[u8], re: &Regex) -> BTreeSet<u32> {
        let mut out = BTreeSet::new();
        if self.offsets.is_empty() {
            return out;
        }
        let region = self.region(buf);
        for m in re.find_iter(region) {
            if let Some(idx) = self.idx_at(self.strdata_start + m.start()) {
                out.insert(idx);
            }
        }
        out
    }

    /// All string indexes whose data matches `pattern` (a regex compiled on
    /// the spot; an empty pattern matches nothing).
    pub fn locate_pattern(&self, buf: &[u8], pattern: &str) -> Result<BTreeSet<u32>> {
        if pattern.is_empty() {
            return Ok(BTreeSet::new());
        }
        Ok(self.locate(buf, &Regex::new(pattern)?))
    }
}

/// Locates type indexes through their descriptor strings.
///
/// The DEX spec sorts `type_ids` by descriptor string index and forbids
/// duplicates, but the table is not trusted: it is kept as a sorted
/// `(string_idx, type_idx)` vector and every type sharing a string is
/// reported.
pub struct TypeLocator {
    /// `(string_idx, type_idx)` sorted.
    by_string: Vec<(u32, u32)>,
}

impl TypeLocator {
    pub fn build(dex: &Dex<'_>) -> Result<TypeLocator> {
        let count = dex.type_count();
        let mut by_string = Vec::with_capacity((count as usize).min(dex.buf().len() / 4));
        for t in 0..count {
            by_string.push((dex.type_string_idx(t)?, t));
        }
        by_string.sort_unstable();
        Ok(TypeLocator { by_string })
    }

    /// Every type whose descriptor is string `string_idx`.
    pub fn types_for_string(&self, string_idx: u32) -> impl Iterator<Item = u32> + '_ {
        let start = self.by_string.partition_point(|&(s, _)| s < string_idx);
        self.by_string[start..].iter().take_while(move |&&(s, _)| s == string_idx).map(|&(_, t)| t)
    }

    /// Fuzzy (regex) descriptor match.
    pub fn locate(&self, buf: &[u8], strings: &StringLocator, re: &Regex) -> BTreeSet<u32> {
        let mut out = BTreeSet::new();
        for s in strings.locate(buf, re) {
            out.extend(self.types_for_string(s));
        }
        out
    }

    /// Fuzzy descriptor match with a pattern compiled on the spot.
    pub fn locate_pattern(&self, buf: &[u8], strings: &StringLocator, pattern: &str) -> Result<BTreeSet<u32>> {
        if pattern.is_empty() {
            return Ok(BTreeSet::new());
        }
        Ok(self.locate(buf, strings, &Regex::new(pattern)?))
    }
}

/// Shared implementation for method and field id tables (both are
/// `class_idx:u16, x:u16, name_idx:u32`).
///
/// Valid DEX files keep these tables sorted by class first, so class lookups
/// are a binary search straight over the table; the name index is a sorted
/// `(name_idx, id)` vector, which is several times cheaper to build than a
/// hash map of vectors.
pub struct MemberLocator {
    table_off: usize,
    count: u32,
    /// `(name_idx, id)` sorted.
    by_name: Vec<(u32, u32)>,
    /// `(class_idx, id)` sorted; only built when the table is not class-sorted.
    by_class: Option<Vec<(u32, u32)>>,
}

impl MemberLocator {
    fn build(dex: &Dex<'_>, count: u32, table_off: u32) -> Result<MemberLocator> {
        let buf = dex.buf();
        let base = table_off as usize;
        // Every id item is 8 bytes: never reserve more than the buffer could hold.
        let cap = (count as usize).min(buf.len() / 8);
        let mut by_name: Vec<(u32, u32)> = Vec::with_capacity(cap);
        let mut by_class: Vec<(u32, u32)> = Vec::new();
        let mut sorted = true;
        let mut last_class = 0u32;
        for i in 0..count {
            let off = base + i as usize * 8;
            let class_idx = asc_dex::read_u16(buf, off)? as u32;
            let name_idx = asc_dex::read_u32(buf, off + 4)?;
            by_name.push((name_idx, i));
            if class_idx < last_class {
                sorted = false;
            }
            last_class = class_idx;
        }
        by_name.sort_unstable();
        if !sorted {
            by_class.reserve(cap);
            for i in 0..count {
                let off = base + i as usize * 8;
                by_class.push((asc_dex::read_u16(buf, off)? as u32, i));
            }
            by_class.sort_unstable();
        }
        Ok(MemberLocator { table_off: base, count, by_name, by_class: (!sorted).then_some(by_class) })
    }

    /// `name_idx` of member `id`.
    fn name_idx(&self, buf: &[u8], id: u32) -> Result<u32> {
        Ok(asc_dex::read_u32(buf, self.table_off + id as usize * 8 + 4)?)
    }

    fn ids_by_name(&self, name_idx: u32, out: &mut BTreeSet<u32>) {
        let start = self.by_name.partition_point(|&(n, _)| n < name_idx);
        for &(n, id) in &self.by_name[start..] {
            if n != name_idx {
                break;
            }
            out.insert(id);
        }
    }

    fn ids_by_class(&self, buf: &[u8], class_idx: u32, out: &mut BTreeSet<u32>) {
        if let Some(v) = &self.by_class {
            let start = v.partition_point(|&(c, _)| c < class_idx);
            for &(c, id) in &v[start..] {
                if c != class_idx {
                    break;
                }
                out.insert(id);
            }
            return;
        }
        let class_at = |i: u32| asc_dex::read_u16(buf, self.table_off + i as usize * 8).unwrap_or(u16::MAX) as u32;
        let (mut lo, mut hi) = (0u32, self.count);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if class_at(mid) < class_idx {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        let mut i = lo;
        while i < self.count && class_at(i) == class_idx {
            out.insert(i);
            i += 1;
        }
    }

    fn locate(&self, dex: &Dex<'_>, strings: &StringLocator, types: &TypeLocator, query: &CompiledMember) -> Result<BTreeSet<u32>> {
        let buf = dex.buf();
        let mut out = BTreeSet::new();
        let Some(class) = &query.class else {
            // No class constraint: every member whose name matches.
            match &query.name {
                Some(CompiledName::Regex(re)) => {
                    for s in strings.locate(buf, re) {
                        self.ids_by_name(s, &mut out);
                    }
                }
                Some(CompiledName::Exact { name, bytes }) => {
                    // Walk the distinct name strings rather than regex-searching
                    // the string data: equality needs no escaping and the walk
                    // is bounded by the id table.
                    let mut last: Option<(u32, bool)> = None;
                    for &(n, id) in &self.by_name {
                        let matched = match last {
                            Some((l, m)) if l == n => m,
                            _ => exact_name_matches(dex, n, name, bytes),
                        };
                        last = Some((n, matched));
                        if matched {
                            out.insert(id);
                        }
                    }
                }
                _ => {}
            }
            return Ok(out);
        };

        let mut class_members = BTreeSet::new();
        match class {
            CompiledClass::Precise(descriptor) => {
                if let Some(t) = dex.find_type_idx(descriptor)? {
                    self.ids_by_class(buf, t, &mut class_members);
                }
            }
            CompiledClass::Fuzzy(re) => {
                for t in types.locate(buf, strings, re) {
                    self.ids_by_class(buf, t, &mut class_members);
                }
            }
        }
        if class_members.is_empty() {
            return Ok(out);
        }
        match &query.name {
            None => Ok(class_members),
            Some(CompiledName::Substring(name)) => {
                // Substring match on the member name, as the Python version does.
                for id in class_members {
                    if dex.string(self.name_idx(buf, id)?)?.contains(name.as_str()) {
                        out.insert(id);
                    }
                }
                Ok(out)
            }
            Some(CompiledName::Exact { name, bytes }) => {
                for id in class_members {
                    if exact_name_matches(dex, self.name_idx(buf, id)?, name, bytes) {
                        out.insert(id);
                    }
                }
                Ok(out)
            }
            Some(CompiledName::Regex(re)) => {
                let mut named = BTreeSet::new();
                for s in strings.locate(buf, re) {
                    self.ids_by_name(s, &mut named);
                }
                out.extend(named.intersection(&class_members));
                Ok(out)
            }
        }
    }
}

/// Whether string `name_idx` is exactly `name` (`bytes` is its MUTF-8
/// encoding). Equal bytes are the common case; a non-ASCII string is also
/// compared decoded so a non-canonical encoding (e.g. a 4-byte UTF-8
/// sequence instead of a surrogate pair) still matches. An unreadable string
/// never matches, like a regex over the string data would not.
fn exact_name_matches(dex: &Dex<'_>, name_idx: u32, name: &str, bytes: &[u8]) -> bool {
    match dex.string_bytes(name_idx) {
        Ok(raw) => raw == bytes || (!raw.is_ascii() && asc_dex::mutf8::decode(raw) == name),
        Err(_) => false,
    }
}

/// Method id locator.
pub struct MethodLocator(MemberLocator);

impl MethodLocator {
    pub fn build(dex: &Dex<'_>) -> Result<MethodLocator> {
        Ok(MethodLocator(MemberLocator::build(dex, dex.method_count(), dex.header().method_ids.off)?))
    }

    /// Resolve a member query, compiling its patterns on the spot.
    pub fn locate(&self, dex: &Dex<'_>, strings: &StringLocator, types: &TypeLocator, query: &MemberQuery) -> Result<BTreeSet<u32>> {
        let compiled = CompiledQuery::new(&crate::Query::Method(query.clone()))?;
        self.locate_compiled(dex, strings, types, &compiled)
    }

    /// Resolve a pre-compiled method query (an empty set for other kinds).
    pub fn locate_compiled(
        &self,
        dex: &Dex<'_>,
        strings: &StringLocator,
        types: &TypeLocator,
        query: &CompiledQuery,
    ) -> Result<BTreeSet<u32>> {
        match query.parts() {
            Parts::Member(m) if query.kind() == crate::RefKind::Method => self.0.locate(dex, strings, types, m),
            _ => Ok(BTreeSet::new()),
        }
    }
}

/// Field id locator.
pub struct FieldLocator(MemberLocator);

impl FieldLocator {
    pub fn build(dex: &Dex<'_>) -> Result<FieldLocator> {
        Ok(FieldLocator(MemberLocator::build(dex, dex.field_count(), dex.header().field_ids.off)?))
    }

    /// Resolve a member query, compiling its patterns on the spot.
    pub fn locate(&self, dex: &Dex<'_>, strings: &StringLocator, types: &TypeLocator, query: &MemberQuery) -> Result<BTreeSet<u32>> {
        let compiled = CompiledQuery::new(&crate::Query::Field(query.clone()))?;
        self.locate_compiled(dex, strings, types, &compiled)
    }

    /// Resolve a pre-compiled field query (an empty set for other kinds).
    pub fn locate_compiled(
        &self,
        dex: &Dex<'_>,
        strings: &StringLocator,
        types: &TypeLocator,
        query: &CompiledQuery,
    ) -> Result<BTreeSet<u32>> {
        match query.parts() {
            Parts::Member(m) if query.kind() == crate::RefKind::Field => self.0.locate(dex, strings, types, m),
            _ => Ok(BTreeSet::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locators_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<StringLocator>();
        assert_send_sync::<TypeLocator>();
        assert_send_sync::<MethodLocator>();
        assert_send_sync::<FieldLocator>();
    }

    #[test]
    fn type_lookup_handles_duplicates_and_gaps() {
        let mut loc = TypeLocator { by_string: vec![(1, 0), (3, 2), (3, 1), (7, 3)] };
        loc.by_string.sort_unstable();
        assert_eq!(loc.types_for_string(0).count(), 0);
        assert_eq!(loc.types_for_string(1).collect::<Vec<_>>(), vec![0]);
        assert_eq!(loc.types_for_string(2).count(), 0);
        assert_eq!(loc.types_for_string(3).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(loc.types_for_string(7).collect::<Vec<_>>(), vec![3]);
        assert_eq!(loc.types_for_string(8).count(), 0);
    }
}
