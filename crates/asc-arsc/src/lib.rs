//! `resources.arsc` reader.
//!
//! Parsing only indexes the table: package headers, string pool layouts and
//! the location of every `ResTable_type` chunk. Names and values are decoded
//! from the original bytes when a query asks for them, so opening even a
//! very large table (Douyin: tens of MB) costs little more than walking its
//! chunk headers. Every offset and count read from the file is bounds
//! checked; a damaged chunk is skipped with a warning (see
//! [`ResTable::warnings`]) instead of failing the whole table.
//!
//! The format follows AOSP `frameworks/base/libs/androidfw` (`ResourceTypes.h`,
//! `LoadedArsc.cpp`): u32, 16-bit (`FLAG_OFFSET16`) and sparse
//! (`FLAG_SPARSE`) entry tables, compact entries, bags (style, attr, array,
//! plurals), and the library, overlayable and staged-alias chunks.

mod config;
mod format;

pub use config::Config;
pub use format::{bag_key_name, complex_to_float, quote};

use asc_axml::PoolLayout;
use std::borrow::Cow;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::OnceLock;

const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_TABLE_TYPE: u16 = 0x0002;
const RES_TABLE_PACKAGE_TYPE: u16 = 0x0200;
const RES_TABLE_TYPE_TYPE: u16 = 0x0201;
const RES_TABLE_TYPE_SPEC_TYPE: u16 = 0x0202;
const RES_TABLE_LIBRARY_TYPE: u16 = 0x0203;
const RES_TABLE_OVERLAYABLE_TYPE: u16 = 0x0204;
const RES_TABLE_OVERLAYABLE_POLICY_TYPE: u16 = 0x0205;
const RES_TABLE_STAGED_ALIAS_TYPE: u16 = 0x0206;

const NO_ENTRY: u32 = 0xffff_ffff;
const NO_ENTRY16: u16 = 0xffff;
const TYPE_FLAG_SPARSE: u8 = 0x01;
const TYPE_FLAG_OFFSET16: u8 = 0x02;
const ENTRY_FLAG_COMPLEX: u16 = 0x0001;
/// The entry was declared `<public>`.
pub const ENTRY_FLAG_PUBLIC: u16 = 0x0002;
const ENTRY_FLAG_COMPACT: u16 = 0x0008;
/// `ResTable_typeSpec` flag: the resource is public.
pub const SPEC_PUBLIC: u32 = 0x4000_0000;

/// Size of `ResTable_package` up to and including `typeIdOffset`.
const PACKAGE_HEADER_SIZE: usize = 288;
/// Size of one `ResTable_map`.
const MAP_SIZE: usize = 12;
/// Longest reference chain [`ResTable::resolve`] follows.
pub const MAX_RESOLVE_DEPTH: usize = 32;

pub use asc_axml::{
    TYPE_ATTRIBUTE, TYPE_DIMENSION, TYPE_DYNAMIC_ATTRIBUTE, TYPE_DYNAMIC_REFERENCE, TYPE_FLOAT, TYPE_FRACTION, TYPE_INT_BOOLEAN,
    TYPE_INT_COLOR_ARGB4, TYPE_INT_COLOR_ARGB8, TYPE_INT_COLOR_RGB4, TYPE_INT_COLOR_RGB8, TYPE_INT_DEC, TYPE_INT_HEX, TYPE_NULL,
    TYPE_REFERENCE, TYPE_STRING,
};

#[derive(Debug, thiserror::Error)]
pub enum ArscError {
    #[error("not a resource table")]
    NotArsc,
    #[error("malformed resource table: {0}")]
    Malformed(String),
}

pub type Result<T> = std::result::Result<T, ArscError>;

#[inline]
fn u8_at(b: &[u8], o: usize) -> Option<u8> {
    b.get(o).copied()
}
#[inline]
fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o.checked_add(2)?).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
#[inline]
fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o.checked_add(4)?).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// A fixed-size, NUL-padded UTF-16 field such as a package name.
fn utf16_fixed(b: &[u8], off: usize, units: usize) -> String {
    let units: Vec<u16> = (0..units).map_while(|i| u16_at(b, off + i * 2)).take_while(|&u| u != 0).collect();
    String::from_utf16_lossy(&units)
}

/// One chunk header, with `end` clamped to the enclosing chunk.
#[derive(Debug, Clone, Copy)]
struct Chunk {
    start: usize,
    kind: u16,
    header_size: usize,
    end: usize,
}

/// Walk the chunks in `[from, end)`. Stops (with a warning) at the first
/// header that cannot be valid, since nothing after it can be located.
fn walk_chunks(data: &[u8], from: usize, end: usize, warnings: &mut Vec<String>, mut f: impl FnMut(Chunk, &mut Vec<String>)) {
    let mut p = from;
    while p.checked_add(8).is_some_and(|e| e <= end) {
        let (Some(kind), Some(hs), Some(size)) = (u16_at(data, p), u16_at(data, p + 2), u32_at(data, p + 4)) else { break };
        let (hs, size) = (hs as usize, size as usize);
        if size < 8 || hs < 8 || hs > size {
            warnings.push(format!("bad chunk header at {p:#x} (type {kind:#06x}, header {hs}, size {size})"));
            return;
        }
        let chunk_end = p.checked_add(size).map_or(end, |e| e.min(end));
        if chunk_end < p + size {
            warnings.push(format!("chunk {kind:#06x} at {p:#x} truncated ({size} bytes declared)"));
        }
        f(Chunk { start: p, kind, header_size: hs.min(chunk_end - p), end: chunk_end }, warnings);
        p = chunk_end;
    }
}

/// One `ResTable_type` chunk: the values of one type in one configuration.
#[derive(Debug, Clone, Copy)]
struct TypeChunk {
    config: Config,
    flags: u8,
    /// Entries in the offset table (sparse: number of `(index, offset)` pairs).
    entry_count: u32,
    offsets: usize,
    entries: usize,
    end: usize,
}

impl TypeChunk {
    /// Offset of entry `idx` relative to `entries`, if present.
    fn entry_offset(&self, data: &[u8], idx: u16) -> Option<usize> {
        if self.flags & TYPE_FLAG_SPARSE != 0 {
            let (mut lo, mut hi) = (0usize, self.entry_count as usize);
            while lo < hi {
                let mid = (lo + hi) / 2;
                let at = self.offsets + mid * 4;
                let i = u16_at(data, at)?;
                match i.cmp(&idx) {
                    std::cmp::Ordering::Equal => return Some(u16_at(data, at + 2)? as usize * 4),
                    std::cmp::Ordering::Less => lo = mid + 1,
                    std::cmp::Ordering::Greater => hi = mid,
                }
            }
            None
        } else if (idx as u32) >= self.entry_count {
            None
        } else if self.flags & TYPE_FLAG_OFFSET16 != 0 {
            let v = u16_at(data, self.offsets + idx as usize * 2)?;
            (v != NO_ENTRY16).then_some(v as usize * 4)
        } else {
            let v = u32_at(data, self.offsets + idx as usize * 4)?;
            (v != NO_ENTRY).then_some(v as usize)
        }
    }

    /// Indexes of the entries present in this chunk, ascending.
    fn present(&self, data: &[u8], mut f: impl FnMut(u16)) {
        if self.flags & TYPE_FLAG_SPARSE != 0 {
            for i in 0..self.entry_count as usize {
                if let Some(idx) = u16_at(data, self.offsets + i * 4) {
                    f(idx);
                }
            }
        } else {
            for idx in 0..self.entry_count.min(0x1_0000) {
                if self.entry_offset(data, idx as u16).is_some() {
                    f(idx as u16);
                }
            }
        }
    }

    fn read(&self, data: &[u8], idx: u16) -> Option<std::result::Result<RawEntry, &'static str>> {
        let off = self.entry_offset(data, idx)?;
        Some(read_entry(data, self.entries.checked_add(off), self.end))
    }
}

/// A decoded `ResTable_entry` (key index into the package key pool).
#[derive(Debug, Clone, PartialEq)]
struct RawEntry {
    key: u32,
    flags: u16,
    value: EntryValue,
}

fn read_entry(data: &[u8], at: Option<usize>, end: usize) -> std::result::Result<RawEntry, &'static str> {
    let p = at.filter(|p| p.checked_add(8).is_some_and(|e| e <= end)).ok_or("entry outside its chunk")?;
    let size_or_key = u16_at(data, p).ok_or("truncated entry")?;
    let flags = u16_at(data, p + 2).ok_or("truncated entry")?;
    if flags & ENTRY_FLAG_COMPACT != 0 {
        let value = Value { kind: (flags >> 8) as u8, data: u32_at(data, p + 4).ok_or("truncated entry")? };
        return Ok(RawEntry { key: size_or_key as u32, flags, value: EntryValue::Simple(value) });
    }
    let size = size_or_key as usize;
    let key = u32_at(data, p + 4).ok_or("truncated entry")?;
    if flags & ENTRY_FLAG_COMPLEX != 0 {
        if size < 16 || p + 16 > end {
            return Err("bag entry header too small");
        }
        let parent = u32_at(data, p + 8).ok_or("truncated entry")?;
        let count = u32_at(data, p + 12).ok_or("truncated entry")? as usize;
        let maps = p.checked_add(size).filter(|&m| m <= end).ok_or("bag entry exceeds chunk")?;
        let available = (end - maps) / MAP_SIZE;
        if count > available {
            return Err("bag item count exceeds chunk");
        }
        let items = (0..count)
            .map(|i| {
                let m = maps + i * MAP_SIZE;
                // `ResTable_map`: name (u32), then a `Res_value` (size u16, res0 u8, type u8, data u32).
                let name = u32_at(data, m).unwrap_or(0);
                let kind = u8_at(data, m + 7).unwrap_or(0);
                (name, Value { kind, data: u32_at(data, m + 8).unwrap_or(0) })
            })
            .collect();
        return Ok(RawEntry { key, flags, value: EntryValue::Bag { parent, items } });
    }
    let v = p.checked_add(size.max(8)).filter(|v| v.checked_add(8).is_some_and(|e| e <= end)).ok_or("value outside its chunk")?;
    let value = Value { kind: u8_at(data, v + 3).unwrap_or(0), data: u32_at(data, v + 4).unwrap_or(0) };
    Ok(RawEntry { key, flags, value: EntryValue::Simple(value) })
}

/// All chunks of one type id in one package.
#[derive(Debug, Default)]
struct TypeGroup {
    /// `ResTable_typeSpec` flags array (offset, count).
    spec: Option<(usize, u32)>,
    chunks: Vec<TypeChunk>,
}

/// A `ResTable_lib_entry`: a shared library the package references, with
/// the package id it was built against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Library {
    pub package_id: u32,
    pub name: String,
}

/// An `<overlayable>` declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overlayable {
    pub name: String,
    pub actor: String,
    pub policies: Vec<OverlayablePolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayablePolicy {
    pub flags: u32,
    pub ids: Vec<u32>,
}

/// A staged resource id and the id it was finalized to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StagedAlias {
    pub staged: u32,
    pub finalized: u32,
}

/// One `ResTable_package`.
#[derive(Debug)]
pub struct Package {
    pub id: u8,
    pub name: String,
    type_names: PoolLayout,
    keys: PoolLayout,
    type_id_offset: u32,
    /// Indexed by type id (1..=255).
    groups: Vec<TypeGroup>,
    pub libraries: Vec<Library>,
    pub overlayables: Vec<Overlayable>,
    pub staged_aliases: Vec<StagedAlias>,
}

impl Package {
    fn group(&self, type_id: u8) -> Option<&TypeGroup> {
        self.groups.get(type_id as usize).filter(|g| !g.chunks.is_empty() || g.spec.is_some())
    }

    /// `(config, type flags, entry count)` of every value chunk of `type_id`.
    pub fn type_chunks(&self, type_id: u8) -> Vec<(Config, u8, u32)> {
        self.group(type_id).map_or_else(Vec::new, |g| g.chunks.iter().map(|c| (c.config, c.flags, c.entry_count)).collect())
    }

    /// Type ids that have a spec or at least one value chunk.
    pub fn type_ids(&self) -> impl Iterator<Item = u8> + '_ {
        (1..=255u8).filter(|&t| self.group(t).is_some())
    }
}

/// A typed value (`Res_value`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Value {
    pub kind: u8,
    pub data: u32,
}

impl Value {
    pub fn is_reference(&self) -> bool {
        matches!(self.kind, TYPE_REFERENCE | TYPE_DYNAMIC_REFERENCE) && self.data != 0
    }
}

/// The value of a resource in one configuration.
#[derive(Debug, Clone, PartialEq)]
pub enum EntryValue {
    Simple(Value),
    /// A style, attr definition, array or plurals: a parent (0 for none) and
    /// `(key, value)` items. Keys are attr ids, the `ATTR_*`/plurals ids of
    /// [`format::bag_key_name`], or `0x02000000 | index` for arrays.
    Bag {
        parent: u32,
        items: Vec<(u32, Value)>,
    },
}

/// One configuration's value of a resource.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigValue {
    pub config: Config,
    pub flags: u16,
    pub value: EntryValue,
}

/// `package:type/entry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResName {
    pub package: String,
    pub type_name: String,
    pub entry: String,
}

impl ResName {
    /// `type/entry`, without the package.
    pub fn short(&self) -> String {
        format!("{}/{}", self.type_name, self.entry)
    }
}

impl fmt::Display for ResName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}/{}", self.package, self.type_name, self.entry)
    }
}

/// Result of following a resource's reference chain.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolved {
    /// Every id visited, starting with the requested one.
    pub chain: Vec<u32>,
    /// Config of the value that was picked for the last id in `chain`.
    pub config: Config,
    /// The final value. Still a reference when it points outside this table
    /// (typically `@android:...`).
    pub value: EntryValue,
    /// No configuration matched the request at some step, so the first one
    /// defined was used instead.
    pub fallback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    #[error("resource 0x{0:08x} not found")]
    NotFound(u32),
    #[error("reference cycle: {}", .0.iter().map(|id| format!("0x{id:08x}")).collect::<Vec<_>>().join(" -> "))]
    Cycle(Vec<u32>),
    #[error("reference chain longer than {MAX_RESOLVE_DEPTH}")]
    TooDeep,
}

/// A parsed (indexed) resource table.
pub struct ResTable {
    data: Box<dyn AsRef<[u8]> + Send + Sync>,
    strings: PoolLayout,
    packages: Vec<Package>,
    /// Package index + 1 by package id (0 = none).
    by_id: [u8; 256],
    warnings: Vec<String>,
    /// `(hash of "type/name", id)` sorted by hash, built on the first lookup.
    names: OnceLock<Vec<(u64, u32)>>,
}

impl fmt::Debug for ResTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResTable").field("packages", &self.packages).field("warnings", &self.warnings).finish_non_exhaustive()
    }
}

impl ResTable {
    /// Index the table in `data`. Fails only when `data` is not a resource
    /// table at all; damaged parts are skipped and reported in
    /// [`ResTable::warnings`].
    pub fn parse(data: impl AsRef<[u8]> + Send + Sync + 'static) -> Result<ResTable> {
        let data: Box<dyn AsRef<[u8]> + Send + Sync> = Box::new(data);
        let bytes = (*data).as_ref();
        if u16_at(bytes, 0) != Some(RES_TABLE_TYPE) {
            return Err(ArscError::NotArsc);
        }
        let hs = u16_at(bytes, 2).ok_or(ArscError::NotArsc)? as usize;
        let size = u32_at(bytes, 4).ok_or(ArscError::NotArsc)? as usize;
        if hs < 12 || hs > size {
            return Err(ArscError::Malformed(format!("table header size {hs}, chunk size {size}")));
        }
        let mut warnings = Vec::new();
        if size > bytes.len() {
            warnings.push(format!("table declares {size} bytes, file has {}", bytes.len()));
        }
        let end = size.min(bytes.len());
        let mut strings = None;
        let mut packages: Vec<Package> = Vec::new();
        walk_chunks(bytes, hs, end, &mut warnings, |c, warnings| match c.kind {
            RES_STRING_POOL_TYPE if strings.is_none() => match PoolLayout::parse(bytes, c.start, c.end) {
                Ok(p) => strings = Some(p),
                Err(e) => warnings.push(format!("global string pool: {e}")),
            },
            RES_TABLE_PACKAGE_TYPE => {
                // Several chunks may share a package id (framework-res puts
                // flagged resources in extra chunks with their own type and key
                // pools); like AOSP's package groups, lookups consult them all.
                if let Some(pkg) = parse_package(bytes, c, warnings) {
                    packages.push(pkg);
                }
            }
            other => warnings.push(format!("unexpected chunk {other:#06x} at {:#x} in table", c.start)),
        });
        let mut by_id = [0u8; 256];
        for (i, p) in packages.iter().enumerate().take(255) {
            by_id[p.id as usize] = i as u8 + 1;
        }
        let strings = strings.unwrap_or_else(|| {
            warnings.push("no global string pool".into());
            PoolLayout::default()
        });
        Ok(ResTable { data, strings, packages, by_id, warnings, names: OnceLock::new() })
    }

    #[inline]
    fn bytes(&self) -> &[u8] {
        (*self.data).as_ref()
    }

    pub fn packages(&self) -> &[Package] {
        &self.packages
    }

    /// Heap held by the index, roughly (the table bytes it indexes aside).
    pub fn index_bytes(&self) -> usize {
        use std::mem::size_of;
        let package = |p: &Package| {
            size_of::<Package>()
                + p.name.capacity()
                + p.groups.iter().map(|g| size_of::<TypeGroup>() + g.chunks.capacity() * size_of::<TypeChunk>()).sum::<usize>()
                + p.libraries.iter().map(|l| size_of::<Library>() + l.name.capacity()).sum::<usize>()
                + p.overlayables
                    .iter()
                    .map(|o| {
                        size_of::<Overlayable>()
                            + o.name.capacity()
                            + o.actor.capacity()
                            + o.policies.iter().map(|p| p.ids.capacity() * 4).sum::<usize>()
                    })
                    .sum::<usize>()
                + p.staged_aliases.capacity() * size_of::<StagedAlias>()
        };
        self.packages.iter().map(package).sum::<usize>()
            + self.warnings.iter().map(String::capacity).sum::<usize>()
            + self.names.get().map_or(0, |n| n.capacity() * size_of::<(u64, u32)>())
    }

    /// Problems found while indexing (skipped chunks, clamped counts, ...).
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn package_by_id(&self, id: u8) -> Option<&Package> {
        match self.by_id[id as usize] {
            0 => None,
            i => self.packages.get(i as usize - 1),
        }
    }

    /// String `idx` of the global value pool.
    pub fn string(&self, idx: u32) -> Option<Cow<'_, str>> {
        self.strings.get(self.bytes(), idx)
    }

    /// Every package chunk with `id`'s package id that has `id`'s type,
    /// with the entry index.
    fn locate(&self, id: u32) -> impl Iterator<Item = (&Package, &TypeGroup, u16)> {
        let (pkg_id, type_id) = ((id >> 24) as u8, (id >> 16) as u8);
        self.packages.iter().filter(move |p| p.id == pkg_id).filter_map(move |p| Some((p, p.group(type_id)?, id as u16)))
    }

    /// Name of type `type_id` in `pkg`.
    pub fn type_name(&self, pkg: &Package, type_id: u8) -> Option<Cow<'_, str>> {
        let idx = (type_id as u32).checked_sub(1 + pkg.type_id_offset)?;
        pkg.type_names.get(self.bytes(), idx)
    }

    /// Name of `id`'s type (`string`, `style`, ...).
    pub fn type_name_of(&self, id: u32) -> Option<Cow<'_, str>> {
        self.locate(id).find_map(|(p, _, _)| self.type_name(p, (id >> 16) as u8))
    }

    /// `package:type/entry` of `id`; the key comes from the first
    /// configuration that defines the entry.
    pub fn name(&self, id: u32) -> Option<ResName> {
        let data = self.bytes();
        let (pkg, key) = self.locate(id).find_map(|(p, g, idx)| Some((p, g.chunks.iter().find_map(|c| c.read(data, idx)?.ok())?.key)))?;
        Some(ResName {
            package: pkg.name.clone(),
            type_name: self.type_name(pkg, (id >> 16) as u8)?.into_owned(),
            entry: pkg.keys.get(data, key).unwrap_or_default().into_owned(),
        })
    }

    /// Whether any configuration defines `id`.
    pub fn contains(&self, id: u32) -> bool {
        self.locate(id).any(|(_, g, idx)| g.chunks.iter().any(|c| c.entry_offset(self.bytes(), idx).is_some()))
    }

    /// `ResTable_typeSpec` flags of `id` (e.g. [`SPEC_PUBLIC`]).
    pub fn spec_flags(&self, id: u32) -> Option<u32> {
        self.locate(id).find_map(|(_, group, idx)| {
            let (off, count) = group.spec?;
            ((idx as u32) < count).then(|| u32_at(self.bytes(), off + idx as usize * 4)).flatten()
        })
    }

    /// Every defined resource id, ascending.
    pub fn ids(&self) -> Vec<u32> {
        let data = self.bytes();
        let mut out = Vec::new();
        for pkg in &self.packages {
            for t in pkg.type_ids() {
                let group = &pkg.groups[t as usize];
                let mut seen = Vec::new();
                for c in &group.chunks {
                    c.present(data, |i| {
                        if seen.len() <= i as usize {
                            seen.resize(i as usize + 1, false);
                        }
                        seen[i as usize] = true;
                    });
                }
                let base = (pkg.id as u32) << 24 | (t as u32) << 16;
                out.extend(seen.iter().enumerate().filter(|(_, &s)| s).map(|(i, _)| base | i as u32));
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Value of `id` in every configuration that defines it, in table order.
    /// Entries that cannot be decoded are left out.
    pub fn values(&self, id: u32) -> Vec<ConfigValue> {
        let data = self.bytes();
        self.locate(id)
            .flat_map(|(_, group, idx)| group.chunks.iter().map(move |c| (c, idx)))
            .filter_map(|(c, idx)| {
                let raw = c.read(data, idx)?.ok()?;
                Some(ConfigValue { config: c.config, flags: raw.flags, value: raw.value })
            })
            .collect()
    }

    /// The value of `id` AOSP would pick for a device described by `req`:
    /// the best of the matching configurations, or `None` when none matches.
    pub fn best_value(&self, id: u32, req: &Config) -> Option<ConfigValue> {
        let mut best: Option<ConfigValue> = None;
        for v in self.values(id) {
            if v.config.matches(req) && best.as_ref().is_none_or(|b| v.config.is_better_than(&b.config, req)) {
                best = Some(v);
            }
        }
        best
    }

    /// Follow `id` through references until a non-reference value (or one
    /// pointing outside this table). At each step the configuration best
    /// matching `req` is used, falling back to the first one defined.
    pub fn resolve(&self, id: u32, req: &Config) -> std::result::Result<Resolved, ResolveError> {
        let mut chain = Vec::new();
        let mut fallback = false;
        let mut id = id;
        loop {
            if chain.contains(&id) {
                chain.push(id);
                return Err(ResolveError::Cycle(chain));
            }
            if chain.len() >= MAX_RESOLVE_DEPTH {
                return Err(ResolveError::TooDeep);
            }
            chain.push(id);
            let picked = match self.best_value(id, req) {
                Some(v) => v,
                None => {
                    fallback = true;
                    self.values(id).into_iter().next().ok_or(ResolveError::NotFound(id))?
                }
            };
            match picked.value {
                EntryValue::Simple(v) if v.is_reference() && self.contains(v.data) => id = v.data,
                value => return Ok(Resolved { chain, config: picked.config, value, fallback }),
            }
        }
    }

    /// [`ResTable::resolve`] for [`Config::any_device`].
    pub fn resolve_default(&self, id: u32) -> std::result::Result<Resolved, ResolveError> {
        self.resolve(id, &Config::any_device())
    }

    /// Name hashes of every resource. Only hashes are kept (16 bytes a
    /// resource instead of an owned name); a lookup confirms its candidates
    /// by decoding their names.
    fn name_index(&self) -> &[(u64, u32)] {
        self.names.get_or_init(|| {
            let data = self.bytes();
            let mut index = Vec::new();
            for pkg in &self.packages {
                for t in pkg.type_ids() {
                    let Some(type_name) = self.type_name(pkg, t) else { continue };
                    let base = (pkg.id as u32) << 24 | (t as u32) << 16;
                    for c in &pkg.groups[t as usize].chunks {
                        c.present(data, |i| {
                            if let Some(Ok(raw)) = c.read(data, i) {
                                let key = pkg.keys.get(data, raw.key).unwrap_or_default();
                                index.push((name_hash(&type_name, &key), base | i as u32));
                            }
                        });
                    }
                }
            }
            // Stable, so equal names keep table order; then one row per id.
            index.sort_by_key(|&(h, _)| h);
            index.dedup();
            index.shrink_to_fit();
            index
        })
    }

    /// Id of a resource given as `type/name`, `package:type/name`, optionally
    /// prefixed with `@` or `?`. Without a package, packages are tried in
    /// table order.
    pub fn lookup(&self, name: &str) -> Option<u32> {
        let name = name.trim_start_matches(['@', '?']);
        let (package, rest) = match name.split_once(':') {
            Some((p, r)) => (Some(p), r),
            None => (None, name),
        };
        let (type_name, entry) = rest.split_once('/')?;
        let index = self.name_index();
        let h = name_hash(type_name, entry);
        let start = index.partition_point(|&(x, _)| x < h);
        let mut found: Vec<u32> = index[start..]
            .iter()
            .take_while(|&&(x, _)| x == h)
            .map(|&(_, id)| id)
            .filter(|&id| {
                self.name(id).is_some_and(|n| n.type_name == type_name && n.entry == entry && package.is_none_or(|p| p == n.package))
            })
            .collect();
        // Table order: the first package that defines the name wins.
        let order = |id: u32| self.packages.iter().position(|p| p.id == (id >> 24) as u8).unwrap_or(usize::MAX);
        found.sort_by_key(|&id| (order(id), id));
        found.first().copied()
    }

    /// Call `f(id, config, text)` for every string value in the table:
    /// simple string entries of any type and the string items of bags
    /// (arrays, plurals).
    pub fn for_each_string(&self, mut f: impl FnMut(u32, &Config, &str)) {
        let data = self.bytes();
        for pkg in &self.packages {
            for t in pkg.type_ids() {
                let base = (pkg.id as u32) << 24 | (t as u32) << 16;
                for c in &pkg.groups[t as usize].chunks {
                    c.present(data, |i| {
                        let Some(Ok(raw)) = c.read(data, i) else { return };
                        let mut emit = |v: &Value| {
                            if v.kind == TYPE_STRING {
                                if let Some(s) = self.string(v.data) {
                                    f(base | i as u32, &c.config, &s);
                                }
                            }
                        };
                        match &raw.value {
                            EntryValue::Simple(v) => emit(v),
                            EntryValue::Bag { items, .. } => items.iter().for_each(|(_, v)| emit(v)),
                        }
                    });
                }
            }
        }
    }
}

/// Hash of `type/entry` for the name index (stable within a process).
fn name_hash(type_name: &str, entry: &str) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    type_name.hash(&mut h);
    entry.hash(&mut h);
    h.finish()
}

fn parse_package(data: &[u8], c: Chunk, warnings: &mut Vec<String>) -> Option<Package> {
    let p = c.start;
    if c.header_size < PACKAGE_HEADER_SIZE - 4 {
        warnings.push(format!("package header at {p:#x} too small ({} bytes)", c.header_size));
        return None;
    }
    let id = u32_at(data, p + 8)?;
    if id > 0xff {
        warnings.push(format!("package at {p:#x} has invalid id {id:#x}"));
        return None;
    }
    let name = utf16_fixed(data, p + 12, 128);
    let type_strings = u32_at(data, p + 268)? as usize;
    let key_strings = u32_at(data, p + 276)? as usize;
    let type_id_offset = if c.header_size >= PACKAGE_HEADER_SIZE { u32_at(data, p + 284)? } else { 0 };
    let mut pkg = Package {
        id: id as u8,
        name,
        type_names: PoolLayout::default(),
        keys: PoolLayout::default(),
        type_id_offset,
        groups: (0..256).map(|_| TypeGroup::default()).collect(),
        libraries: Vec::new(),
        overlayables: Vec::new(),
        staged_aliases: Vec::new(),
    };
    let mut pools_seen = 0;
    let label = format!("package {} (0x{id:02x})", pkg.name);
    walk_chunks(data, p + c.header_size, c.end, warnings, |ch, warnings| match ch.kind {
        RES_STRING_POOL_TYPE => {
            let rel = ch.start - p;
            // The header names both pools by offset; fall back to their order.
            let is_types = if type_strings != 0 || key_strings != 0 { rel == type_strings } else { pools_seen == 0 };
            let is_keys = if type_strings != 0 || key_strings != 0 { rel == key_strings } else { pools_seen == 1 };
            pools_seen += 1;
            match PoolLayout::parse(data, ch.start, ch.end) {
                Ok(pool) if is_types => pkg.type_names = pool,
                Ok(pool) if is_keys => pkg.keys = pool,
                Ok(_) => warnings.push(format!("{label}: extra string pool at {:#x}", ch.start)),
                Err(e) => warnings.push(format!("{label}: string pool at {:#x}: {e}", ch.start)),
            }
        }
        RES_TABLE_TYPE_SPEC_TYPE => {
            let (Some(t), Some(count)) = (u8_at(data, ch.start + 8), u32_at(data, ch.start + 12)) else { return };
            if t == 0 {
                warnings.push(format!("{label}: type spec with id 0 at {:#x}", ch.start));
                return;
            }
            let flags = ch.start + ch.header_size;
            let fits = ((ch.end - flags) / 4) as u32;
            if count > fits {
                warnings.push(format!("{label}: type spec {t} claims {count} entries, chunk holds {fits}"));
            }
            let group = &mut pkg.groups[t as usize];
            if group.spec.is_some() {
                warnings.push(format!("{label}: duplicate type spec {t}"));
            } else {
                group.spec = Some((flags, count.min(fits)));
            }
        }
        RES_TABLE_TYPE_TYPE => match parse_type(data, ch) {
            Ok((t, chunk)) => pkg.groups[t as usize].chunks.push(chunk),
            Err(e) => warnings.push(format!("{label}: type chunk at {:#x}: {e}", ch.start)),
        },
        RES_TABLE_LIBRARY_TYPE => {
            let count = u32_at(data, ch.start + 8).unwrap_or(0) as usize;
            let base = ch.start + ch.header_size;
            let fits = (ch.end - base) / 260;
            if count > fits {
                warnings.push(format!("{label}: library chunk claims {count} entries, holds {fits}"));
            }
            for i in 0..count.min(fits) {
                let e = base + i * 260;
                pkg.libraries.push(Library { package_id: u32_at(data, e).unwrap_or(0), name: utf16_fixed(data, e + 4, 128) });
            }
        }
        RES_TABLE_OVERLAYABLE_TYPE => {
            let mut o = Overlayable {
                name: utf16_fixed(data, ch.start + 8, 256),
                actor: utf16_fixed(data, ch.start + 520, 256),
                policies: Vec::new(),
            };
            walk_chunks(data, ch.start + ch.header_size, ch.end, warnings, |pc, warnings| {
                if pc.kind != RES_TABLE_OVERLAYABLE_POLICY_TYPE {
                    warnings.push(format!("{label}: unexpected chunk {:#06x} in overlayable", pc.kind));
                    return;
                }
                let flags = u32_at(data, pc.start + 8).unwrap_or(0);
                let count = u32_at(data, pc.start + 12).unwrap_or(0) as usize;
                let base = pc.start + pc.header_size;
                let ids = (0..count.min((pc.end - base) / 4)).filter_map(|i| u32_at(data, base + i * 4)).collect();
                o.policies.push(OverlayablePolicy { flags, ids });
            });
            pkg.overlayables.push(o);
        }
        RES_TABLE_STAGED_ALIAS_TYPE => {
            let count = u32_at(data, ch.start + 8).unwrap_or(0) as usize;
            let base = ch.start + ch.header_size;
            for i in 0..count.min((ch.end - base) / 8) {
                let e = base + i * 8;
                pkg.staged_aliases.push(StagedAlias { staged: u32_at(data, e).unwrap_or(0), finalized: u32_at(data, e + 4).unwrap_or(0) });
            }
        }
        other => warnings.push(format!("{label}: unknown chunk {other:#06x} at {:#x}", ch.start)),
    });
    Some(pkg)
}

fn parse_type(data: &[u8], ch: Chunk) -> std::result::Result<(u8, TypeChunk), &'static str> {
    let s = ch.start;
    if ch.header_size < 20 + 4 {
        return Err("header too small");
    }
    let t = u8_at(data, s + 8).ok_or("truncated")?;
    if t == 0 {
        return Err("type id 0");
    }
    let flags = u8_at(data, s + 9).ok_or("truncated")?;
    let entry_count = u32_at(data, s + 12).ok_or("truncated")?;
    let entries_start = u32_at(data, s + 16).ok_or("truncated")? as usize;
    let config_size = u32_at(data, s + 20).ok_or("truncated")? as usize;
    let config_end = (s + 20).saturating_add(config_size).min(s + ch.header_size);
    let config = Config::parse(&data[s + 20..config_end]);
    let offsets = s + ch.header_size;
    let entries = s.checked_add(entries_start).filter(|&e| e <= ch.end && e >= offsets).ok_or("entries start outside chunk")?;
    let width = if flags & TYPE_FLAG_OFFSET16 != 0 && flags & TYPE_FLAG_SPARSE == 0 { 2 } else { 4 };
    if (entry_count as usize).checked_mul(width).is_none_or(|n| offsets + n > entries) {
        return Err("entry offset table overlaps entry data");
    }
    if flags & TYPE_FLAG_SPARSE == 0 && entry_count > 0x1_0000 {
        return Err("more than 65536 entries");
    }
    Ok((t, TypeChunk { config, flags, entry_count, offsets, entries, end: ch.end }))
}

#[cfg(test)]
mod tests;
