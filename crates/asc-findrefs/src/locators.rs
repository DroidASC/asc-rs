//! Query → constant-pool index locators.
//!
//! Locators hold only offsets and index tables; the DEX buffer they were built
//! from is passed back in at lookup time, so they can be cached and shared
//! between threads without any raw-pointer aliasing.

use crate::query::{CompiledClass, CompiledMember, CompiledName, CompiledQuery, CompiledSignature, CompiledType, Parts};
use crate::table::Table;
use crate::{MemberQuery, Result};
use asc_dex::Dex;
use regex::bytes::Regex;
use std::collections::BTreeSet;

/// Locates string indexes by regex over the raw string-data region.
///
/// R8 keeps `string_data_item`s contiguous and in index order, so a match
/// position maps to a string through a binary search over the data offsets.
pub struct StringLocator {
    /// `[data_off, string_idx]` sorted by offset.
    pub(crate) offsets: Table<[u32; 2]>,
    pub(crate) strdata_start: usize,
    pub(crate) strdata_end: usize,
}

impl StringLocator {
    pub fn build(dex: &Dex<'_>) -> Result<StringLocator> {
        let buf = dex.buf();
        let count = dex.string_count();
        // Every string_id is 4 bytes: never reserve more than the buffer could hold.
        let mut offsets = Vec::with_capacity((count as usize).min(buf.len() / 4));
        for idx in 0..count {
            offsets.push([dex.string_data_off(idx)?, idx]);
        }
        offsets.sort_unstable();
        let (strdata_start, strdata_end) = match (offsets.first(), offsets.last()) {
            (Some(&[first, _]), Some(&[last, _])) => {
                let item = dex.string_item_at(last)?;
                let end = (last as usize + asc_dex::leb128::uleb128_len(buf, last as usize)?) + item.bytes.len() + 1;
                let end = end.min(buf.len());
                ((first as usize).min(end), end)
            }
            _ => (0, 0),
        };
        Ok(StringLocator { offsets: offsets.into(), strdata_start, strdata_end })
    }

    pub fn string_count(&self) -> usize {
        self.offsets.len()
    }

    /// Heap bytes held by the table.
    pub fn heap_bytes(&self) -> usize {
        self.offsets.heap_bytes()
    }

    /// The string-data region of `buf` (empty when `buf` is not the buffer the
    /// locator was built from and the offsets do not fit).
    fn region<'b>(&self, buf: &'b [u8]) -> &'b [u8] {
        let end = self.strdata_end.min(buf.len());
        let start = self.strdata_start.min(end);
        &buf[start..end]
    }

    /// All string indexes whose data matches `re`, each string matched on
    /// its own: a match never runs from one string into the next.
    ///
    /// One pass over the whole string-data region; a match that does not lie
    /// inside one string (it crossed a terminator or a length prefix) is
    /// discarded, and every string it touched is matched again on its own,
    /// so a real match it overlapped is not lost. A pattern with look-around
    /// (`^`, `$`, `\b`, ...) is matched string by string from the start, so
    /// `^abc$` means a string that is exactly `abc`.
    pub fn locate(&self, buf: &[u8], re: &Regex) -> BTreeSet<u32> {
        let mut out = BTreeSet::new();
        if self.offsets.is_empty() {
            return out;
        }
        let shape = PatternShape::of(re);
        if shape.looks {
            return self.locate_each(buf, re, shape.extent);
        }
        let region = self.region(buf);
        // Region offset of the string at sorted position `p` (the region end
        // past the last one).
        let start_of = |p: usize| self.offsets.get(p).map_or(region.len(), |&[off, _]| (off as usize).saturating_sub(self.strdata_start));
        let mut at = 0;
        while at <= region.len() {
            let Some(m) = re.find_at(region, at) else { break };
            let abs = self.strdata_start + m.start();
            // Sorted positions of the strings starting at or before the match.
            let p = self.offsets.partition_point(|&[off, _]| (off as usize) <= abs);
            if let Some((from, to)) = p.checked_sub(1).and_then(|q| self.extent(buf, q, shape.extent)) {
                if from <= abs && abs + m.len() <= to {
                    out.insert(self.offsets[p - 1][1]);
                    // The string matched: its rest cannot add anything.
                    at = start_of(p).max(m.end()).max(m.start() + 1);
                    continue;
                }
            }
            // A match across strings: match each string it touched alone.
            let last = abs + m.len().max(1) - 1;
            let q = self.offsets.partition_point(|&[off, _]| (off as usize) <= last);
            for i in p.saturating_sub(1)..q {
                if self.matches_alone(buf, i, re, shape.extent) {
                    out.insert(self.offsets[i][1]);
                }
            }
            at = start_of(q).max(m.end()).max(m.start() + 1);
        }
        out
    }

    /// [`StringLocator::locate`] string by string, each string being its
    /// `extent`. An unreadable string never matches.
    fn locate_each(&self, buf: &[u8], re: &Regex, extent: Extent) -> BTreeSet<u32> {
        (0..self.offsets.len()).filter(|&i| self.matches_alone(buf, i, re, extent)).map(|i| self.offsets[i][1]).collect()
    }

    /// Whether `re` matches the string at sorted position `i` on its own.
    fn matches_alone(&self, buf: &[u8], i: usize, re: &Regex, extent: Extent) -> bool {
        self.extent(buf, i, extent).is_some_and(|(from, to)| re.is_match(&buf[from..to]))
    }

    /// Absolute `[from, to)` of the string at sorted position `i`: its data
    /// after the length prefix, plus the terminator for
    /// [`Extent::WithTerminator`]. `None` when the prefix is unreadable.
    fn extent(&self, buf: &[u8], i: usize, extent: Extent) -> Option<(usize, usize)> {
        let off = self.offsets[i][0] as usize;
        let from = off + asc_dex::leb128::uleb128_len(buf, off).ok()?;
        let data = buf.get(from..)?;
        let to = match memchr::memchr(0, data) {
            Some(n) => from + n + usize::from(extent == Extent::WithTerminator),
            None => buf.len(),
        };
        Some((from, to))
    }

    /// All string indexes whose data contains the literal bytes `finder`
    /// searches for (a plain substring, attributed to the string where the
    /// occurrence starts exactly like a regex match).
    pub fn locate_literal(&self, buf: &[u8], finder: &memchr::memmem::Finder<'_>) -> BTreeSet<u32> {
        if self.offsets.is_empty() || finder.needle().is_empty() {
            return BTreeSet::new();
        }
        let region = self.region(buf);
        let needle = finder.needle();
        // Without a NUL in the needle an occurrence never crosses a string's
        // terminator, so after a hit the rest of that string can be skipped.
        // Both matches and offsets are in physical order, so one cursor also
        // avoids a binary search per matched string.
        let skip_rest = !needle.contains(&0);
        let mut out = Vec::new();
        let mut offset_pos = 0;
        let mut at = 0;
        while at < region.len() {
            let Some(pos) = finder.find(&region[at..]) else { break };
            let start = at + pos;
            let abs = self.strdata_start + start;
            at = start + needle.len();
            while offset_pos + 1 < self.offsets.len() && self.offsets[offset_pos + 1][0] as usize <= abs {
                offset_pos += 1;
            }
            out.push(self.offsets[offset_pos][1]);
            if skip_rest {
                if let Some(&[next, _]) = self.offsets.get(offset_pos + 1) {
                    at = at.max((next as usize).saturating_sub(self.strdata_start));
                }
            }
        }
        // Physical string-data order is unrelated to string index order.
        out.sort_unstable();
        out.dedup();
        out.into_iter().collect()
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

/// What a string is to a pattern.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Extent {
    /// Its data.
    Data,
    /// Its data and its terminating NUL, for a pattern that spells a NUL:
    /// class patterns end a descriptor with `;\x00`.
    WithTerminator,
}

/// The properties of a pattern that decide how strings are matched.
struct PatternShape {
    /// Look-around (anchors, word boundaries) sees the string's edges.
    looks: bool,
    extent: Extent,
}

impl PatternShape {
    /// A pattern the parser rejects is searched over the whole region as
    /// data, as before.
    fn of(re: &Regex) -> PatternShape {
        let pattern = re.as_str();
        let looks =
            regex_syntax::ParserBuilder::new().utf8(false).build().parse(pattern).is_ok_and(|hir| !hir.properties().look_set().is_empty());
        let spells_nul =
            regex_syntax::ast::parse::Parser::new().parse(pattern).is_ok_and(|ast| regex_syntax::ast::visit(&ast, NulFinder).is_err());
        PatternShape { looks, extent: if spells_nul { Extent::WithTerminator } else { Extent::Data } }
    }
}

/// Fails the walk at a literal NUL (`\x00`, `\0`, in a class or a range
/// from it). A NUL only reached through `.` or a negated class does not
/// count: those keep to the string's data.
struct NulFinder;

impl regex_syntax::ast::Visitor for NulFinder {
    type Output = ();
    type Err = ();

    fn finish(self) -> std::result::Result<(), ()> {
        Ok(())
    }

    fn visit_pre(&mut self, ast: &regex_syntax::ast::Ast) -> std::result::Result<(), ()> {
        match ast {
            regex_syntax::ast::Ast::Literal(l) if l.c == '\0' => Err(()),
            _ => Ok(()),
        }
    }

    fn visit_class_set_item_pre(&mut self, item: &regex_syntax::ast::ClassSetItem) -> std::result::Result<(), ()> {
        match item {
            regex_syntax::ast::ClassSetItem::Literal(l) if l.c == '\0' => Err(()),
            regex_syntax::ast::ClassSetItem::Range(r) if r.start.c == '\0' => Err(()),
            _ => Ok(()),
        }
    }
}

/// Locates type indexes through their descriptor strings.
///
/// The DEX spec sorts `type_ids` by descriptor string index and forbids
/// duplicates, but the table is not trusted: it is kept as a sorted
/// `(string_idx, type_idx)` vector and every type sharing a string is
/// reported.
pub struct TypeLocator {
    /// `[string_idx, type_idx]` sorted.
    pub(crate) by_string: Table<[u32; 2]>,
}

impl TypeLocator {
    pub fn build(dex: &Dex<'_>) -> Result<TypeLocator> {
        let count = dex.type_count();
        let mut by_string = Vec::with_capacity((count as usize).min(dex.buf().len() / 4));
        for t in 0..count {
            by_string.push([dex.type_string_idx(t)?, t]);
        }
        by_string.sort_unstable();
        Ok(TypeLocator { by_string: by_string.into() })
    }

    /// Heap bytes held by the table.
    pub fn heap_bytes(&self) -> usize {
        self.by_string.heap_bytes()
    }

    /// Every type whose descriptor is string `string_idx`.
    pub fn types_for_string(&self, string_idx: u32) -> impl Iterator<Item = u32> + '_ {
        let start = self.by_string.partition_point(|&[s, _]| s < string_idx);
        self.by_string[start..].iter().take_while(move |&&[s, _]| s == string_idx).map(|&[_, t]| t)
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
    pub(crate) table_off: usize,
    pub(crate) count: u32,
    /// `[name_idx, id]` sorted.
    pub(crate) by_name: Table<[u32; 2]>,
    /// `[class_idx, id]` sorted; only built when the table is not class-sorted.
    pub(crate) by_class: Option<Table<[u32; 2]>>,
}

impl MemberLocator {
    fn build(dex: &Dex<'_>, count: u32, table_off: u32) -> Result<MemberLocator> {
        let buf = dex.buf();
        let base = table_off as usize;
        // Every id item is 8 bytes: never reserve more than the buffer could hold.
        let cap = (count as usize).min(buf.len() / 8);
        let mut by_name: Vec<[u32; 2]> = Vec::with_capacity(cap);
        let mut by_class: Vec<[u32; 2]> = Vec::new();
        let mut sorted = true;
        let mut last_class = 0u32;
        for i in 0..count {
            let off = base + i as usize * 8;
            let class_idx = asc_dex::read_u16(buf, off)? as u32;
            let name_idx = asc_dex::read_u32(buf, off + 4)?;
            by_name.push([name_idx, i]);
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
                by_class.push([asc_dex::read_u16(buf, off)? as u32, i]);
            }
            by_class.sort_unstable();
        }
        Ok(MemberLocator { table_off: base, count, by_name: by_name.into(), by_class: (!sorted).then(|| by_class.into()) })
    }

    fn heap_bytes(&self) -> usize {
        self.by_name.heap_bytes() + self.by_class.as_ref().map_or(0, Table::heap_bytes)
    }

    /// `name_idx` of member `id`.
    fn name_idx(&self, buf: &[u8], id: u32) -> Result<u32> {
        Ok(asc_dex::read_u32(buf, self.table_off + id as usize * 8 + 4)?)
    }

    fn ids_by_name(&self, name_idx: u32, out: &mut BTreeSet<u32>) {
        let start = self.by_name.partition_point(|&[n, _]| n < name_idx);
        for &[n, id] in &self.by_name[start..] {
            if n != name_idx {
                break;
            }
            out.insert(id);
        }
    }

    fn ids_by_class(&self, buf: &[u8], class_idx: u32, out: &mut BTreeSet<u32>) {
        if let Some(v) = &self.by_class {
            let start = v.partition_point(|&[c, _]| c < class_idx);
            for &[c, id] in &v[start..] {
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
                Some(CompiledName::Exact { bytes, .. }) => {
                    // The string table is sorted and unique: one binary search
                    // gives the only name string, then its members.
                    if let Some(s) = dex.find_string_idx(bytes)? {
                        self.ids_by_name(s, &mut out);
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

/// Whether method `id` takes `params` (and returns `ret`, when given).
/// Errors propagate rather than count as a mismatch: on a DEX prefix
/// ([`FindRefs::cannot_match`](crate::FindRefs::cannot_match)) the parameter
/// lists may lie beyond it.
fn method_has_signature(dex: &Dex<'_>, id: u32, params: &[CompiledType], ret: Option<&CompiledType>) -> Result<bool> {
    let proto = dex.proto_id(dex.method_id(id)?.proto_idx as u32)?;
    if let Some(ret) = ret {
        if !ret.matches(dex.type_bytes(proto.return_type_idx)?) {
            return Ok(false);
        }
    }
    let have = dex.type_list(proto.parameters_off)?;
    if have.len() != params.len() {
        return Ok(false);
    }
    for (&t, want) in have.iter().zip(params) {
        if !want.matches(dex.type_bytes(t as u32)?) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The members of `ids` that `keep` accepts, the first error aborting.
fn retain_ok(ids: BTreeSet<u32>, mut keep: impl FnMut(u32) -> Result<bool>) -> Result<BTreeSet<u32>> {
    let mut out = BTreeSet::new();
    for id in ids {
        if keep(id)? {
            out.insert(id);
        }
    }
    Ok(out)
}

/// Method id locator.
pub struct MethodLocator(pub(crate) MemberLocator);

impl MethodLocator {
    pub fn build(dex: &Dex<'_>) -> Result<MethodLocator> {
        Ok(MethodLocator(MemberLocator::build(dex, dex.method_count(), dex.header().method_ids.off)?))
    }

    /// Heap bytes held by the tables.
    pub fn heap_bytes(&self) -> usize {
        self.0.heap_bytes()
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
            Parts::Member(m) if query.kind() == crate::RefKind::Method => self.locate_member(dex, strings, types, m),
            Parts::MemberSet(set) => {
                let mut out = BTreeSet::new();
                for m in set {
                    out.extend(self.locate_member(dex, strings, types, m)?);
                }
                Ok(out)
            }
            _ => Ok(BTreeSet::new()),
        }
    }

    fn locate_member(&self, dex: &Dex<'_>, strings: &StringLocator, types: &TypeLocator, m: &CompiledMember) -> Result<BTreeSet<u32>> {
        let ids = self.0.locate(dex, strings, types, m)?;
        match &m.signature {
            Some(CompiledSignature::Method { params, ret }) => retain_ok(ids, |id| method_has_signature(dex, id, params, ret.as_ref())),
            _ => Ok(ids),
        }
    }
}

/// Field id locator.
pub struct FieldLocator(pub(crate) MemberLocator);

impl FieldLocator {
    pub fn build(dex: &Dex<'_>) -> Result<FieldLocator> {
        Ok(FieldLocator(MemberLocator::build(dex, dex.field_count(), dex.header().field_ids.off)?))
    }

    /// Heap bytes held by the tables.
    pub fn heap_bytes(&self) -> usize {
        self.0.heap_bytes()
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
            Parts::Member(m) if query.kind() == crate::RefKind::Field => {
                let ids = self.0.locate(dex, strings, types, m)?;
                match &m.signature {
                    Some(CompiledSignature::Field(t)) => {
                        retain_ok(ids, |id| Ok(t.matches(dex.type_bytes(dex.field_id(id)?.type_idx as u32)?)))
                    }
                    _ => Ok(ids),
                }
            }
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
        let mut by_string = vec![[1, 0], [3, 2], [3, 1], [7, 3]];
        by_string.sort_unstable();
        let loc = TypeLocator { by_string: by_string.into() };
        assert_eq!(loc.types_for_string(0).count(), 0);
        assert_eq!(loc.types_for_string(1).collect::<Vec<_>>(), vec![0]);
        assert_eq!(loc.types_for_string(2).count(), 0);
        assert_eq!(loc.types_for_string(3).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(loc.types_for_string(7).collect::<Vec<_>>(), vec![3]);
        assert_eq!(loc.types_for_string(8).count(), 0);
    }

    #[test]
    fn dense_regex_matches_insert_each_string_once() {
        let offsets = vec![[0, 7], [4, 3], [8, 9]];
        let loc = StringLocator { offsets: offsets.into(), strdata_start: 0, strdata_end: 12 };
        let re = Regex::new(".").unwrap();
        // String data begins with one-byte ULEB lengths and ends in NULs.
        // A dense regex also matches those bytes, so this verifies the same
        // physical-region attribution as the production path.
        assert_eq!(loc.locate(b"\x02aa\0\x02bb\0\x02cc\0", &re), [3, 7, 9].into_iter().collect());
    }
}
