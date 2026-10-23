//! Read-only APK (zip) access.
//!
//! The archive is memory-mapped and only its central directory is walked.
//! Entries are extracted on demand: stored entries are borrowed straight from
//! the mapping, Deflate entries are inflated (optionally with a cancellation
//! flag; the streaming decoder polls it on every input read, the libdeflate
//! path once per entry, so a parallel class search can abandon the remaining
//! DEX files as soon as one worker hits).
//!
//! Several archives can also be read as one program ([`Apk::open`]).

mod program;

pub use program::Version;

use memmap2::Mmap;
use std::borrow::Cow;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

const CD_SIG: &[u8; 4] = b"PK\x01\x02";
const LH_SIG: &[u8; 4] = b"PK\x03\x04";
const EOCD_SIG: &[u8; 4] = b"PK\x05\x06";
const ZIP64_EOCD_SIG: &[u8; 4] = b"PK\x06\x06";
const ZIP64_LOCATOR_SIG: &[u8; 4] = b"PK\x06\x07";
const DEFLATE_CHUNK: usize = 1 << 19;
/// Deflate cannot expand data by more than about 1032:1; a central directory
/// claiming more is corrupt or hostile and must not drive an allocation.
const MAX_DEFLATE_RATIO: u64 = 1032;
/// A declared size is reserved up front only up to the larger of this and
/// [`TYPICAL_RATIO`] times the compressed payload; anything bigger grows on
/// demand, so a lying central directory cannot force a large allocation
/// while real DEX entries still get a single exact one.
const INITIAL_CAPACITY: usize = 64 << 20;
/// Real DEX files inflate well under this ratio.
const TYPICAL_RATIO: usize = 16;

pub const METHOD_STORED: u16 = 0;
pub const METHOD_DEFLATE: u16 = 8;

#[derive(Debug, thiserror::Error)]
pub enum ApkError {
    #[error("io error on {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("end of central directory not found")]
    NoEocd,
    #[error("central directory out of range")]
    BadCentralDirectory,
    #[error("bad local header signature for entry {0}")]
    BadLocalHeader(String),
    #[error("unsupported compression method {0}")]
    UnsupportedMethod(u16),
    #[error("inflate failed for entry {name}: {source}")]
    Inflate { name: String, source: std::io::Error },
    #[error("size mismatch for entry {name}: expected {expected}, got {actual}")]
    SizeMismatch { name: String, expected: usize, actual: usize },
    #[error("entry {0} not found")]
    NotFound(String),
    #[error("entry {name} declares an implausible size (compressed {comp_size}, uncompressed {uncomp_size})")]
    ImplausibleSize { name: String, comp_size: u64, uncomp_size: u64 },
    #[error("entry {name} exceeds the inflate limit: {reason}")]
    LimitExceeded { name: String, reason: String },
    #[error("cancelled")]
    Cancelled,
    #[error("no archive of {} has classes*.dex ({})", path.display(), notes.join("; "))]
    NoCode { path: PathBuf, notes: Vec<String> },
}

pub type Result<T> = std::result::Result<T, ApkError>;

/// One central-directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub method: u16,
    pub comp_size: u64,
    pub uncomp_size: u64,
    pub local_header_off: u64,
    /// CRC-32 of the uncompressed data, as the central directory records it.
    pub crc32: u32,
    /// The archive of a program it belongs to ([`Apk::archive_path`]).
    pub archive: usize,
}

/// Caps on what reading an APK may inflate, against zip bombs. The default
/// only rejects what Deflate cannot produce; [`Limits::guarded`] is for
/// sweeping untrusted APKs in bulk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Most bytes one entry may inflate to.
    pub max_entry_bytes: u64,
    /// Most an entry may expand over its compressed payload.
    pub max_ratio: u64,
    /// Most bytes all root DEX entries together may declare.
    pub max_dex_total_bytes: u64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits { max_entry_bytes: u64::MAX, max_ratio: MAX_DEFLATE_RATIO, max_dex_total_bytes: u64::MAX }
    }
}

impl Limits {
    /// Real DEX files are at most a few hundred MiB and compress 2-5:1.
    pub fn guarded() -> Limits {
        Limits { max_entry_bytes: 1 << 30, max_ratio: 100, max_dex_total_bytes: 4 << 30 }
    }
}

/// A memory-mapped APK, or several archives (APKs, jars, bare DEX files)
/// read as one program: see [`Apk::open`]. Clones share the mappings, so a
/// host can keep one open and hand out copies while [`Apk::version`] holds.
#[derive(Clone)]
pub struct Apk {
    path: PathBuf,
    archives: Arc<[Archive]>,
    limits: Limits,
    /// Archives of a program left out of its code, one line each.
    notes: Arc<[String]>,
    version: Version,
}

/// One archive of an [`Apk`] as a cache key sees it ([`Apk::directories`]).
#[derive(Debug, Clone, Copy)]
pub struct ArchiveId<'a> {
    pub path: &'a Path,
    /// What its entry names start with in a program ([`archive_of`]); empty
    /// for a lone archive.
    pub label: &'a str,
    /// Its central directory, or a bare DEX file's header.
    pub directory: &'a [u8],
}

/// One file of an [`Apk`].
struct Archive {
    path: PathBuf,
    map: Mmap,
    /// Its name in a program of several archives (`services.jar`,
    /// `app/TeleService/TeleService.apk`), which prefixes its entry names;
    /// empty for a lone archive.
    label: String,
    /// A bare DEX file rather than a zip: one stored entry, the whole file.
    bare_dex: bool,
}

/// `n` bytes at `o`, or `None` if they are not all inside `b` (offsets come
/// from the archive, so the addition itself must not be trusted either).
#[inline]
fn bytes_at(b: &[u8], o: usize, n: usize) -> Option<&[u8]> {
    b.get(o..o.checked_add(n)?)
}
#[inline]
fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    bytes_at(b, o, 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
#[inline]
fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    bytes_at(b, o, 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
#[inline]
fn u64_at(b: &[u8], o: usize) -> Option<u64> {
    bytes_at(b, o, 8).map(|s| u64::from_le_bytes(s.try_into().expect("8 bytes")))
}
/// A `u64` archive offset as `usize`, or `None` when it cannot even be
/// represented (32-bit hosts).
#[inline]
fn offset(v: u64) -> Option<usize> {
    usize::try_from(v).ok()
}

/// The archive of a program a DEX of it comes from, by the DEX's name
/// (`app/Tele.apk` for `app/Tele.apk/classes2.dex`, also as a logical DEX
/// `...classes2.dex!classes1.dex`); `None` for a lone archive's.
pub fn archive_of(dex_name: &str) -> Option<&str> {
    let entry = dex_name.split('!').next().unwrap_or(dex_name);
    entry.rsplit_once('/').map(|(archive, _)| archive)
}

/// Whether `name` (inside one archive) is a root-level `*.dex`
/// (`classes.dex`, `classes2.dex`, ...).
fn is_root_dex(name: &[u8]) -> bool {
    name.ends_with(b".dex") && !name.contains(&b'/')
}

/// The one entry of a bare DEX file, by its name inside the archive.
const BARE_DEX_ENTRY: &str = "classes.dex";
/// Size of the DEX header, which carries the file's checksum and SHA-1.
const DEX_HEADER_SIZE: usize = 0x70;

impl Archive {
    fn open(path: PathBuf, label: String) -> Result<Archive> {
        let file = File::open(&path).map_err(|source| ApkError::Io { path: path.clone(), source })?;
        // SAFETY: the mapping is read-only and the file is not expected to be
        // modified while it is mapped (same contract as the Python mmap use).
        let map = unsafe { Mmap::map(&file) }.map_err(|source| ApkError::Io { path: path.clone(), source })?;
        let bare_dex = map.starts_with(b"dex\n");
        Ok(Archive { path, map, label, bare_dex })
    }

    /// `inner` (a name inside this archive) as the program names it:
    /// `label/inner`, so the archive is all before the last `/`.
    fn entry_name(&self, inner: &[u8]) -> String {
        let inner = String::from_utf8_lossy(inner);
        if self.label.is_empty() {
            inner.into_owned()
        } else {
            format!("{}/{inner}", self.label)
        }
    }

    /// The name inside this archive of the program's entry `name`, if it
    /// names one of this archive's entries.
    fn inner_name<'n>(&self, name: &'n str) -> Option<&'n str> {
        if self.label.is_empty() {
            return None;
        }
        name.strip_prefix(self.label.as_str())?.strip_prefix('/')
    }

    /// Locate the central directory as `(offset, size)`, honouring zip64.
    fn central_directory(&self) -> Result<(usize, usize)> {
        let data = &self.map[..];
        let search_start = data.len().saturating_sub(65536 + 22);
        let eocd = memchr::memmem::rfind(&data[search_start..], EOCD_SIG).map(|p| p + search_start).ok_or(ApkError::NoEocd)?;
        let mut cd_size = u32_at(data, eocd + 12).ok_or(ApkError::NoEocd)? as u64;
        let mut cd_off = u32_at(data, eocd + 16).ok_or(ApkError::NoEocd)? as u64;
        if cd_size == 0xFFFF_FFFF || cd_off == 0xFFFF_FFFF {
            // zip64: locator sits right before the EOCD.
            if eocd >= 20 && &data[eocd - 20..eocd - 16] == ZIP64_LOCATOR_SIG {
                let rec = u64_at(data, eocd - 20 + 8).and_then(offset).ok_or(ApkError::NoEocd)?;
                if bytes_at(data, rec, 4) == Some(ZIP64_EOCD_SIG) {
                    cd_size = rec.checked_add(40).and_then(|o| u64_at(data, o)).ok_or(ApkError::NoEocd)?;
                    cd_off = rec.checked_add(48).and_then(|o| u64_at(data, o)).ok_or(ApkError::NoEocd)?;
                }
            }
        }
        let (Some(off), Some(size)) = (offset(cd_off), offset(cd_size)) else {
            return Err(ApkError::BadCentralDirectory);
        };
        if off.checked_add(size).map(|e| e > data.len()).unwrap_or(true) {
            return Err(ApkError::BadCentralDirectory);
        }
        Ok((off, size))
    }

    /// What identifies this version of the archive: its central directory,
    /// or a bare DEX file's header.
    fn directory(&self) -> Result<&[u8]> {
        if self.bare_dex {
            return Ok(&self.map[..self.map.len().min(DEX_HEADER_SIZE)]);
        }
        let (off, size) = self.central_directory()?;
        Ok(&self.map[off..off + size])
    }

    /// Walk the central directory, `keep` filtering by the name inside this
    /// archive; the entries are of archive `index` of the program.
    fn entries_filtered(&self, index: usize, keep: &mut impl FnMut(&[u8]) -> bool) -> Result<Vec<Entry>> {
        if self.bare_dex {
            if !keep(BARE_DEX_ENTRY.as_bytes()) {
                return Ok(Vec::new());
            }
            let len = self.map.len() as u64;
            return Ok(vec![Entry {
                name: self.entry_name(BARE_DEX_ENTRY.as_bytes()),
                method: METHOD_STORED,
                comp_size: len,
                uncomp_size: len,
                local_header_off: 0,
                crc32: 0,
                archive: index,
            }]);
        }
        let data = &self.map[..];
        let (cd_off, cd_size) = self.central_directory()?;
        let cd_end = cd_off + cd_size;
        let mut entries = Vec::new();
        let mut p = cd_off;
        while p + 46 <= cd_end {
            if &data[p..p + 4] != CD_SIG {
                break;
            }
            let name_len = u16_at(data, p + 28).unwrap_or(0) as usize;
            let extra_len = u16_at(data, p + 30).unwrap_or(0) as usize;
            let comment_len = u16_at(data, p + 32).unwrap_or(0) as usize;
            let name_start = p + 46;
            let name_end = name_start + name_len;
            if name_end > cd_end {
                break;
            }
            let name = &data[name_start..name_end];
            if keep(name) {
                let mut comp_size = u32_at(data, p + 20).unwrap_or(0) as u64;
                let mut uncomp_size = u32_at(data, p + 24).unwrap_or(0) as u64;
                let mut local_header_off = u32_at(data, p + 42).unwrap_or(0) as u64;
                if comp_size == 0xFFFF_FFFF || uncomp_size == 0xFFFF_FFFF || local_header_off == 0xFFFF_FFFF {
                    // zip64 extra field (id 0x0001).
                    let mut q = name_end;
                    let extra_end = name_end + extra_len;
                    while q + 4 <= extra_end {
                        let id = u16_at(data, q).unwrap_or(0);
                        let len = u16_at(data, q + 2).unwrap_or(0) as usize;
                        if id == 0x0001 {
                            let mut r = q + 4;
                            if uncomp_size == 0xFFFF_FFFF {
                                uncomp_size = u64_at(data, r).unwrap_or(0);
                                r += 8;
                            }
                            if comp_size == 0xFFFF_FFFF {
                                comp_size = u64_at(data, r).unwrap_or(0);
                                r += 8;
                            }
                            if local_header_off == 0xFFFF_FFFF {
                                local_header_off = u64_at(data, r).unwrap_or(0);
                            }
                            break;
                        }
                        q += 4 + len;
                    }
                }
                entries.push(Entry {
                    name: self.entry_name(name),
                    method: u16_at(data, p + 10).unwrap_or(0),
                    comp_size,
                    uncomp_size,
                    local_header_off,
                    crc32: u32_at(data, p + 16).unwrap_or(0),
                    archive: index,
                });
            }
            p = name_end + extra_len + comment_len;
        }
        Ok(entries)
    }

    /// Root-level DEX entries in central-directory order. Duplicate names
    /// keep the last occurrence, like [`Apk::find_entry`] (and `zipfile`).
    fn dex_entries_in_order(&self, index: usize) -> Result<Vec<Entry>> {
        let mut entries = self.entries_filtered(index, &mut is_root_dex)?;
        // Last occurrence wins: walk from the back keeping first-seen names.
        entries.reverse();
        let mut seen = std::collections::HashSet::with_capacity(entries.len());
        entries.retain(|e| seen.insert(e.name.clone()));
        entries.reverse();
        Ok(entries)
    }
}

impl Apk {
    /// Open `path` read-only: an APK (any zip, e.g. a jar), a bare DEX file,
    /// or a program of several archives read as one:
    ///
    /// - a directory: every `*.apk`, `*.jar`, `*.zip` and `*.dex` below it;
    /// - several paths (files or directories) joined with `,`, when no file
    ///   of that whole name exists.
    ///
    /// A program's entries are named after their archive
    /// (`services.jar/classes2.dex`, `x.dex/classes.dex` for a bare DEX
    /// file; see [`archive_of`]). Archives without root DEX entries, or
    /// that do not open, are left out and named in [`Apk::notes`]; a program
    /// none of whose archives has code is an error. A program that comes
    /// down to one archive is that archive alone.
    pub fn open(path: impl AsRef<Path>) -> Result<Apk> {
        let path = path.as_ref().to_path_buf();
        let sources = program::sources(&path)?;
        let version = Version::of_sources(&sources)?;
        if let [lone] = &sources[..] {
            let archives = Arc::new([Archive::open(lone.path.clone(), String::new())?]);
            return Ok(Apk { path, archives, limits: Limits::default(), notes: Arc::new([]), version });
        }
        let mut archives = Vec::with_capacity(sources.len());
        let mut notes = Vec::new();
        for s in sources {
            let archive = match Archive::open(s.path, s.label) {
                Ok(a) => a,
                Err(e) => {
                    notes.push(format!("skipped: {e}"));
                    continue;
                }
            };
            match archive.dex_entries_in_order(archives.len()) {
                Ok(dex) if dex.is_empty() => notes.push(format!("{}: no classes*.dex (odex/vdex only?): deodex first", archive.label)),
                Ok(_) => archives.push(archive),
                Err(e) => notes.push(format!("{}: skipped: {e}", archive.label)),
            }
        }
        if archives.is_empty() {
            return Err(ApkError::NoCode { path, notes });
        }
        if let [lone] = &mut archives[..] {
            lone.label.clear();
        }
        Ok(Apk { path, archives: archives.into(), limits: Limits::default(), notes: notes.into(), version })
    }

    /// The files `path` (as [`Apk::open`] takes it) names now, with their
    /// sizes and modification times: equal to an open [`Apk::version`]
    /// when opening again would read the same files. Costs a directory walk
    /// and a `stat` per archive, not a mapping.
    pub fn version_of(path: impl AsRef<Path>) -> Result<Version> {
        Version::of_sources(&program::sources(path.as_ref())?)
    }

    /// The files read and their sizes and times when this was opened.
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// `spec` (a path [`Apk::open`] takes) with its relative paths resolved
    /// against `base`: each of several paths joined with `,` on its own.
    pub fn resolve(spec: &Path, base: &Path) -> PathBuf {
        program::resolve(spec, base)
    }

    /// Enforce `limits` on every later read.
    pub fn with_limits(mut self, limits: Limits) -> Apk {
        self.limits = limits;
        self
    }

    /// The path the APK was opened from (a program's directory or list).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The limits every read enforces ([`Apk::with_limits`]).
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// How many archives make up the program: 1 for a lone archive, whose
    /// entry names are the names inside it.
    pub fn archive_count(&self) -> usize {
        self.archives.len()
    }

    /// One line per archive of a program left out of its code.
    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    /// The file `entry` lives in.
    pub fn archive_path(&self, entry: &Entry) -> &Path {
        &self.archive(entry).path
    }

    /// The raw bytes of the file `entry` lives in.
    pub fn archive_data(&self, entry: &Entry) -> &[u8] {
        &self.archive(entry).map
    }

    fn archive(&self, entry: &Entry) -> &Archive {
        self.archives.get(entry.archive).expect("entry of this APK")
    }

    /// What identifies each archive's version, in program order. A cache key
    /// hashes them.
    pub fn directories(&self) -> Result<Vec<ArchiveId<'_>>> {
        self.archives.iter().map(|a| Ok(ArchiveId { path: &a.path, label: &a.label, directory: a.directory()? })).collect()
    }

    /// A short name for the APK: the file stem, or for a program the first
    /// archive's and how many others follow.
    pub fn stem(&self) -> String {
        let first = self.archives[0].path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        match self.archives.len() {
            1 => first,
            n => format!("{first}-and-{}", n - 1),
        }
    }

    /// `(size, modification time)` of the file; for a program, its sizes and
    /// times hashed into one number and the latest time, so rewriting any
    /// archive changes it.
    pub fn stamp(&self) -> Result<(u64, Option<SystemTime>)> {
        let meta = |a: &Archive| std::fs::metadata(&a.path).map_err(|source| ApkError::Io { path: a.path.clone(), source });
        if let [lone] = &self.archives[..] {
            let m = meta(lone)?;
            return Ok((m.len(), m.modified().ok()));
        }
        let mut size = 0u64;
        let mut latest = None;
        for a in self.archives.iter() {
            let m = meta(a)?;
            let since = m.modified().ok().and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok());
            // Only a hash input: the low bits of the nanoseconds are what differ.
            let nanos = since.map_or(0, |d| d.as_nanos() as u64);
            size = size.rotate_left(13) ^ m.len().wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ nanos;
            latest = latest.max(m.modified().ok());
        }
        Ok((size, latest))
    }

    /// Walk the central directories. `keep` filters entries by their name
    /// inside their archive early, so the full name list is never
    /// materialised for large archives.
    pub fn entries_filtered(&self, mut keep: impl FnMut(&[u8]) -> bool) -> Result<Vec<Entry>> {
        let mut entries = Vec::new();
        for (i, a) in self.archives.iter().enumerate() {
            entries.extend(a.entries_filtered(i, &mut keep)?);
        }
        Ok(entries)
    }

    /// Every entry of the archive.
    pub fn entries(&self) -> Result<Vec<Entry>> {
        self.entries_filtered(|_| true)
    }

    /// Root-level DEX entries sorted by compressed size (smallest first, so a
    /// parallel scan finishes the cheap ones early). Duplicate names keep the
    /// last occurrence, like [`Apk::find_entry`] (and `zipfile`).
    pub fn dex_entries(&self) -> Result<Vec<Entry>> {
        let mut entries = self.dex_entries_in_order()?;
        self.check_dex_total(&entries)?;
        entries.sort_by_key(|e| e.comp_size);
        Ok(entries)
    }

    /// The entries of [`Apk::dex_entries`] in central-directory order, archive
    /// by archive.
    pub fn dex_entries_in_order(&self) -> Result<Vec<Entry>> {
        let mut entries = Vec::new();
        for (i, a) in self.archives.iter().enumerate() {
            entries.extend(a.dex_entries_in_order(i)?);
        }
        Ok(entries)
    }

    fn check_dex_total(&self, entries: &[Entry]) -> Result<()> {
        let total = entries.iter().fold(0u64, |t, e| t.saturating_add(e.uncomp_size));
        if total > self.limits.max_dex_total_bytes {
            return Err(ApkError::LimitExceeded {
                name: "classes*.dex".into(),
                reason: format!("DEX entries declare {total} bytes in all, limit {}", self.limits.max_dex_total_bytes),
            });
        }
        Ok(())
    }

    /// Find an entry by exact name. In a program, a name without an
    /// archive's prefix (`AndroidManifest.xml`) is looked up archive by
    /// archive, the first that has it winning.
    pub fn find_entry(&self, name: &str) -> Result<Option<Entry>> {
        let owner = self.archives.iter().enumerate().find_map(|(i, a)| Some((i, a.inner_name(name)?)));
        let candidates: Vec<(usize, &str)> = match owner {
            Some(found) => vec![found],
            None => (0..self.archives.len()).map(|i| (i, name)).collect(),
        };
        for (i, inner) in candidates {
            let mut found = self.archives[i].entries_filtered(i, &mut |n: &[u8]| n == inner.as_bytes())?;
            if let Some(e) = found.pop() {
                return Ok(Some(e));
            }
        }
        Ok(None)
    }

    /// Compressed payload of `entry` inside the mapping.
    pub fn raw_payload(&self, entry: &Entry) -> Result<&[u8]> {
        let archive = self.archive(entry);
        let data = &archive.map[..];
        let bad = || ApkError::BadLocalHeader(entry.name.clone());
        if archive.bare_dex {
            return offset(entry.comp_size).and_then(|n| data.get(..n)).ok_or_else(bad);
        }
        let lh = offset(entry.local_header_off).ok_or_else(bad)?;
        if bytes_at(data, lh, 4) != Some(LH_SIG) {
            return Err(bad());
        }
        // The signature check bounds `lh`, so these small additions cannot overflow.
        let name_len = u16_at(data, lh + 26).ok_or_else(bad)? as usize;
        let extra_len = u16_at(data, lh + 28).ok_or_else(bad)? as usize;
        let start = lh + 30 + name_len + extra_len;
        let end = offset(entry.comp_size).and_then(|n| start.checked_add(n));
        end.and_then(|end| data.get(start..end)).ok_or_else(bad)
    }

    /// Extract `entry`: stored entries are borrowed straight from the mapping,
    /// Deflate entries are inflated into a fresh buffer.
    pub fn read_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        self.read_entry_cancellable(entry, None)
    }

    /// Extract `entry`, polling `cancel` between input chunks. Returns
    /// `Err(ApkError::Cancelled)` when the flag is raised mid-way.
    pub fn read_entry_cancellable(&self, entry: &Entry, cancel: Option<&AtomicBool>) -> Result<Cow<'_, [u8]>> {
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Err(ApkError::Cancelled);
        }
        let payload = self.raw_payload(entry)?;
        let bound = self.check_declared_size(entry)?;
        let out = match entry.method {
            METHOD_STORED => {
                if entry.uncomp_size != 0 && payload.len() as u64 != entry.uncomp_size {
                    return Err(ApkError::SizeMismatch {
                        name: entry.name.clone(),
                        expected: entry.uncomp_size as usize,
                        actual: payload.len(),
                    });
                }
                return Ok(Cow::Borrowed(payload));
            }
            #[cfg(feature = "libdeflate")]
            METHOD_DEFLATE if entry.uncomp_size > 0 => {
                if let Some(c) = cancel {
                    if c.load(Ordering::Relaxed) {
                        return Err(ApkError::Cancelled);
                    }
                }
                let mut out = vec![0u8; entry.uncomp_size as usize];
                let n = libdeflater::Decompressor::new()
                    .deflate_decompress(payload, &mut out)
                    .map_err(|e| ApkError::Inflate { name: entry.name.clone(), source: std::io::Error::other(format!("{e:?}")) })?;
                out.truncate(n);
                out
            }
            METHOD_DEFLATE => {
                let reader = CancelReader { data: payload, pos: 0, cancel };
                let decoder = flate2::read::DeflateDecoder::new(reader);
                let reserve = (entry.uncomp_size as usize).min(INITIAL_CAPACITY.max(payload.len().saturating_mul(TYPICAL_RATIO)));
                let mut out = Vec::with_capacity(reserve);
                // Stop one byte past the bound so an over-long stream is detected
                // instead of inflated without limit (an entry that declares no
                // uncompressed size has no other cap).
                match decoder.take(bound.saturating_add(1)).read_to_end(&mut out) {
                    Ok(_) => {}
                    Err(_) if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) => return Err(ApkError::Cancelled),
                    Err(e) => return Err(ApkError::Inflate { name: entry.name.clone(), source: e }),
                }
                if out.len() as u64 > bound {
                    return Err(self.past_bound(entry, bound));
                }
                out
            }
            m => return Err(ApkError::UnsupportedMethod(m)),
        };
        if let Some(c) = cancel {
            if c.load(Ordering::Relaxed) {
                return Err(ApkError::Cancelled);
            }
        }
        if entry.uncomp_size != 0 && out.len() as u64 != entry.uncomp_size {
            return Err(ApkError::SizeMismatch { name: entry.name.clone(), expected: entry.uncomp_size as usize, actual: out.len() });
        }
        Ok(Cow::Owned(out))
    }

    /// Reject Deflate entries whose declared uncompressed size cannot come out
    /// of their compressed payload, before anything is allocated for them.
    /// Returns the most an inflated entry may legitimately grow to; it also
    /// bounds entries that declare no uncompressed size at all.
    fn check_declared_size(&self, entry: &Entry) -> Result<u64> {
        let bound = entry.comp_size.saturating_mul(MAX_DEFLATE_RATIO).saturating_add(1024);
        if entry.method == METHOD_DEFLATE && entry.uncomp_size > bound {
            return Err(self.implausible(entry));
        }
        let Limits { max_entry_bytes, max_ratio, .. } = self.limits;
        if entry.uncomp_size > max_entry_bytes {
            return Err(self.over_limit(entry, format!("declares {} bytes, limit {max_entry_bytes}", entry.uncomp_size)));
        }
        let ratio_bound = entry.comp_size.saturating_mul(max_ratio).saturating_add(1024);
        if entry.method == METHOD_DEFLATE && entry.uncomp_size > ratio_bound {
            return Err(self.over_limit(
                entry,
                format!("declares {} bytes from {} compressed, ratio limit {max_ratio}", entry.uncomp_size, entry.comp_size),
            ));
        }
        Ok(bound.min(ratio_bound).min(max_entry_bytes))
    }

    /// An entry whose stream ran past `bound` (from [`Apk::check_declared_size`]).
    fn past_bound(&self, entry: &Entry, bound: u64) -> ApkError {
        if bound < entry.comp_size.saturating_mul(MAX_DEFLATE_RATIO).saturating_add(1024) {
            self.over_limit(entry, format!("inflates past {bound} bytes"))
        } else {
            self.implausible(entry)
        }
    }

    fn over_limit(&self, entry: &Entry, reason: String) -> ApkError {
        ApkError::LimitExceeded { name: entry.name.clone(), reason }
    }

    fn implausible(&self, entry: &Entry) -> ApkError {
        ApkError::ImplausibleSize { name: entry.name.clone(), comp_size: entry.comp_size, uncomp_size: entry.uncomp_size }
    }

    /// Convenience: extract a named entry.
    pub fn read(&self, name: &str) -> Result<Vec<u8>> {
        let entry = self.find_entry(name)?.ok_or_else(|| ApkError::NotFound(name.to_string()))?;
        Ok(self.read_entry(&entry)?.into_owned())
    }
}

/// Decision returned by the callback of [`Apk::inflate_until`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixStep {
    /// Keep inflating; stop once at least this many bytes are available
    /// (`0` = undecided, ask again after the next chunk).
    Continue(usize),
    /// A prefix is not useful for this entry; stop now.
    Abort,
}

/// Outcome of [`Apk::inflate_until`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prefix {
    /// The whole entry (the stream ended before or at the requested length).
    Complete(Vec<u8>),
    /// At least the requested number of leading bytes.
    Partial(Vec<u8>),
    /// The callback aborted; holds whatever was inflated so far.
    Aborted(Vec<u8>),
}

impl Apk {
    /// Inflate a Deflate entry incrementally, letting `decide` inspect the
    /// leading bytes after every chunk to say how much of the entry is
    /// actually needed. Stored entries are returned whole.
    pub fn inflate_until(&self, entry: &Entry, mut decide: impl FnMut(&[u8]) -> PrefixStep) -> Result<Prefix> {
        // Small first chunks so a quick "not useful" costs little; then up to CHUNK.
        const FIRST_CHUNK: usize = 1 << 14;
        const CHUNK: usize = 1 << 18;
        let mut chunk = FIRST_CHUNK;
        if entry.method != METHOD_DEFLATE {
            return Ok(Prefix::Complete(self.read_entry(entry)?.into_owned()));
        }
        let compressed = self.raw_payload(entry)?;
        let bound = self.check_declared_size(entry)?;
        let mut d = flate2::Decompress::new(false);
        let mut out: Vec<u8> = Vec::with_capacity((entry.uncomp_size as usize).min(4 * CHUNK));
        let mut target: Option<usize> = None;
        loop {
            if out.len() as u64 > bound {
                return Err(self.past_bound(entry, bound));
            }
            let base = out.len();
            out.resize(base + chunk, 0);
            chunk = (chunk * 2).min(CHUNK);
            let consumed = d.total_in() as usize;
            let status = d
                .decompress(&compressed[consumed.min(compressed.len())..], &mut out[base..], flate2::FlushDecompress::None)
                .map_err(|e| ApkError::Inflate { name: entry.name.clone(), source: std::io::Error::other(e) })?;
            let written = d.total_out() as usize - base;
            out.truncate(base + written);
            if target.is_none() {
                match decide(&out) {
                    PrefixStep::Continue(0) => {}
                    PrefixStep::Continue(limit) => {
                        // An entry that declares no size cannot cap the request.
                        target = Some(if entry.uncomp_size == 0 { limit } else { limit.min(entry.uncomp_size as usize) })
                    }
                    PrefixStep::Abort => return Ok(Prefix::Aborted(out)),
                }
            }
            if status == flate2::Status::StreamEnd {
                return Ok(Prefix::Complete(out));
            }
            if let Some(limit) = target {
                if out.len() >= limit {
                    return Ok(Prefix::Partial(out));
                }
            }
            if written == 0 && d.total_in() as usize == consumed {
                return Err(ApkError::Inflate { name: entry.name.clone(), source: std::io::Error::other("deflate made no progress") });
            }
        }
    }
}

/// Slice reader that serves bounded chunks and honours a cancellation flag.
struct CancelReader<'a> {
    data: &'a [u8],
    pos: usize,
    cancel: Option<&'a AtomicBool>,
}

impl Read for CancelReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(c) = self.cancel {
            if c.load(Ordering::Relaxed) {
                return Err(std::io::Error::other("cancelled"));
            }
        }
        let remaining = &self.data[self.pos..];
        let n = remaining.len().min(buf.len()).min(DEFLATE_CHUNK);
        buf[..n].copy_from_slice(&remaining[..n]);
        self.pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn limits_reject_bombs_before_inflating() {
        // Zeros compress far beyond any real DEX.
        let bomb = vec![0u8; 4 << 20];
        let f = write_temp(&asc_fixture::make_apk(&[("classes.dex", &bomb)], true));
        let apk = Apk::open(f.path()).unwrap();
        let entry = apk.dex_entries().unwrap().remove(0);
        assert_eq!(apk.read_entry(&entry).unwrap().len(), bomb.len());
        let apk = Apk::open(f.path()).unwrap().with_limits(Limits::guarded());
        let err = apk.read_entry(&entry).unwrap_err();
        assert!(matches!(&err, ApkError::LimitExceeded { reason, .. } if reason.contains("ratio limit 100")), "{err}");
        // An entry with no declared size is cut off by the same bound while streaming.
        let mut undeclared = entry.clone();
        undeclared.uncomp_size = 0;
        assert!(matches!(apk.read_entry(&undeclared), Err(ApkError::LimitExceeded { .. })));
        let small = Limits { max_entry_bytes: 1 << 20, ..Limits::default() };
        let apk = Apk::open(f.path()).unwrap().with_limits(small);
        assert!(matches!(apk.read_entry(&entry), Err(ApkError::LimitExceeded { .. })));
        let total = Limits { max_dex_total_bytes: 1 << 20, ..Limits::default() };
        let apk = Apk::open(f.path()).unwrap().with_limits(total);
        assert!(matches!(apk.dex_entries(), Err(ApkError::LimitExceeded { .. })));
    }

    #[test]
    fn enumerates_and_inflates_dex_entries() {
        let dex = asc_fixture::make_dex();
        for deflate in [false, true] {
            let apk_bytes = asc_fixture::make_apk(
                &[("classes.dex", &dex), ("lib/x/classes.dex", &dex), ("classes2.dex", &dex), ("AndroidManifest.xml", b"xml")],
                deflate,
            );
            let f = write_temp(&apk_bytes);
            let apk = Apk::open(f.path()).unwrap();
            let entries = apk.dex_entries().unwrap();
            let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
            assert_eq!(names.len(), 2);
            assert!(names.contains(&"classes.dex") && names.contains(&"classes2.dex"));
            for e in &entries {
                assert_eq!(apk.read_entry(e).unwrap().as_ref(), dex.as_slice());
            }
            assert_eq!(apk.read("AndroidManifest.xml").unwrap(), b"xml");
            let cancel = AtomicBool::new(true);
            let r = apk.read_entry_cancellable(&entries[0], Some(&cancel));
            assert!(matches!(r, Err(ApkError::Cancelled)));
            if deflate {
                // A lying central directory must not drive a huge allocation.
                let mut lying = entries[0].clone();
                lying.uncomp_size = 1 << 40;
                assert!(matches!(apk.read_entry(&lying), Err(ApkError::ImplausibleSize { .. })));
                assert!(matches!(apk.inflate_until(&lying, |_| PrefixStep::Continue(0)), Err(ApkError::ImplausibleSize { .. })));
                let mut truncated = entries[0].clone();
                truncated.comp_size = u64::MAX;
                assert!(matches!(apk.read_entry(&truncated), Err(ApkError::BadLocalHeader(_))));
            }
        }
    }

    /// Deflate stream of `n` zero bytes (compresses about 1000:1).
    fn zeros_deflated(n: usize) -> Vec<u8> {
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
        e.write_all(&vec![0u8; n]).unwrap();
        e.finish().unwrap()
    }

    /// Hand-rolled zip (the `zip` crate refuses duplicate names and always
    /// writes true sizes): `(name, method, payload, comp_size, uncomp_size)`.
    fn raw_zip(entries: &[(&str, u16, &[u8], u32, u32)]) -> Vec<u8> {
        let mut z = Vec::new();
        let mut cd = Vec::new();
        for (name, method, payload, comp_size, uncomp_size) in entries {
            let lh = z.len() as u32;
            z.extend_from_slice(LH_SIG);
            z.extend_from_slice(&[20, 0, 0, 0]);
            z.extend_from_slice(&method.to_le_bytes());
            z.extend_from_slice(&[0; 8]);
            z.extend_from_slice(&comp_size.to_le_bytes());
            z.extend_from_slice(&uncomp_size.to_le_bytes());
            z.extend_from_slice(&(name.len() as u16).to_le_bytes());
            z.extend_from_slice(&0u16.to_le_bytes());
            z.extend_from_slice(name.as_bytes());
            z.extend_from_slice(payload);
            cd.extend_from_slice(CD_SIG);
            cd.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
            cd.extend_from_slice(&method.to_le_bytes());
            cd.extend_from_slice(&[0; 8]);
            cd.extend_from_slice(&comp_size.to_le_bytes());
            cd.extend_from_slice(&uncomp_size.to_le_bytes());
            cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
            cd.extend_from_slice(&[0; 12]);
            cd.extend_from_slice(&lh.to_le_bytes());
            cd.extend_from_slice(name.as_bytes());
        }
        let cd_off = z.len() as u32;
        z.extend_from_slice(&cd);
        z.extend_from_slice(EOCD_SIG);
        z.extend_from_slice(&[0, 0, 0, 0]);
        z.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        z.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        z.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        z.extend_from_slice(&cd_off.to_le_bytes());
        z.extend_from_slice(&[0, 0]);
        z
    }

    #[test]
    fn undeclared_size_is_still_bounded() {
        // 1 MiB of zeros deflates to about 1 KiB; the 1032:1 bound allows it.
        let ok = zeros_deflated(1 << 20);
        let f = write_temp(&raw_zip(&[("classes.dex", METHOD_DEFLATE, &ok, ok.len() as u32, 0)]));
        let apk = Apk::open(f.path()).unwrap();
        let e = apk.dex_entries().unwrap().remove(0);
        assert_eq!(e.uncomp_size, 0);
        assert_eq!(apk.read_entry(&e).unwrap().len(), 1 << 20);
        match apk.inflate_until(&e, |_| PrefixStep::Continue(4096)).unwrap() {
            Prefix::Partial(v) => assert!(v.len() >= 4096),
            Prefix::Complete(v) => assert_eq!(v.len(), 1 << 20),
            Prefix::Aborted(_) => panic!("unexpected abort"),
        }
        // A shorter compressed size lowers the bound and truncates the stream:
        // either way the entry is rejected instead of inflated open-endedly.
        let mut lying = e.clone();
        lying.comp_size = 200;
        assert!(apk.read_entry(&lying).is_err());
        assert!(apk.inflate_until(&lying, |_| PrefixStep::Continue(0)).is_err());
    }

    #[test]
    fn hostile_offsets_do_not_overflow() {
        let dex = asc_fixture::make_dex();
        let f = write_temp(&asc_fixture::make_apk(&[("classes.dex", &dex)], true));
        let apk = Apk::open(f.path()).unwrap();
        let mut e = apk.dex_entries().unwrap().remove(0);
        for off in [u64::MAX, u64::MAX - 3, u64::MAX - 40, u32::MAX as u64] {
            e.local_header_off = off;
            assert!(matches!(apk.read_entry(&e), Err(ApkError::BadLocalHeader(_))));
            assert!(matches!(apk.inflate_until(&e, |_| PrefixStep::Continue(0)), Err(ApkError::BadLocalHeader(_))));
        }
        // zip64 locator pointing at an offset near usize::MAX.
        let mut bytes = asc_fixture::make_apk(&[("classes.dex", &dex)], false);
        let eocd = bytes.len() - 22;
        bytes[eocd + 16..eocd + 20].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let mut locator = Vec::new();
        locator.extend_from_slice(ZIP64_LOCATOR_SIG);
        locator.extend_from_slice(&0u32.to_le_bytes());
        locator.extend_from_slice(&(u64::MAX - 2).to_le_bytes());
        locator.extend_from_slice(&1u32.to_le_bytes());
        let tail = bytes.split_off(eocd);
        bytes.extend_from_slice(&locator);
        bytes.extend_from_slice(&tail);
        let f = write_temp(&bytes);
        let apk = Apk::open(f.path()).unwrap();
        assert!(matches!(apk.dex_entries(), Err(ApkError::NoEocd | ApkError::BadCentralDirectory)));
    }

    #[test]
    fn duplicate_root_dex_names_keep_the_last() {
        let a = asc_fixture::make_dex();
        let mut b = a.clone();
        b.push(0); // different content, same name
        let (la, lb) = (a.len() as u32, b.len() as u32);
        let f = write_temp(&raw_zip(&[
            ("classes.dex", METHOD_STORED, &a, la, la),
            ("classes2.dex", METHOD_STORED, &a, la, la),
            ("classes.dex", METHOD_STORED, &b, lb, lb),
        ]));
        let apk = Apk::open(f.path()).unwrap();
        let entries = apk.dex_entries().unwrap();
        let mut names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        names.sort();
        assert_eq!(names, ["classes.dex", "classes2.dex"]);
        let dup = entries.iter().find(|e| e.name == "classes.dex").unwrap();
        assert_eq!(apk.read_entry(dup).unwrap().as_ref(), b.as_slice());
        assert_eq!(apk.find_entry("classes.dex").unwrap().unwrap(), *dup);
        // Central-directory order, the duplicate at its last position.
        let ordered: Vec<String> = apk.dex_entries_in_order().unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(ordered, ["classes2.dex", "classes.dex"]);
    }

    #[test]
    fn programs_name_entries_after_their_archive() {
        let dex = asc_fixture::make_dex();
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("system");
        std::fs::create_dir_all(root.join("app/Tele")).unwrap();
        let both = [("classes.dex", &dex[..]), ("classes2.dex", &dex[..]), ("AndroidManifest.xml", b"first")];
        std::fs::write(root.join("services.jar"), asc_fixture::make_apk(&both, true)).unwrap();
        let apk = [("classes.dex", &dex[..]), ("AndroidManifest.xml", b"second")];
        std::fs::write(root.join("app/Tele/Tele.apk"), asc_fixture::make_apk(&apk, false)).unwrap();
        std::fs::write(root.join("odexed.jar"), asc_fixture::make_apk(&[("META-INF/MANIFEST.MF", b"m")], false)).unwrap();
        std::fs::write(root.join("bare.dex"), &dex).unwrap();
        std::fs::write(root.join("broken.zip"), b"not a zip").unwrap();

        let program = Apk::open(&root).unwrap();
        assert_eq!(program.archive_count(), 3);
        let names: Vec<String> = program.dex_entries_in_order().unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(
            names,
            ["app/Tele/Tele.apk/classes.dex", "bare.dex/classes.dex", "services.jar/classes.dex", "services.jar/classes2.dex"]
        );
        for e in program.dex_entries().unwrap() {
            assert_eq!(program.read_entry(&e).unwrap().as_ref(), dex.as_slice(), "{}", e.name);
        }
        let notes = program.notes().join("\n");
        assert!(notes.contains("broken.zip") && notes.contains("odexed.jar: no classes*.dex"), "{notes}");
        // Unprefixed names: the first archive that has one; prefixed: that archive's.
        assert_eq!(program.read("AndroidManifest.xml").unwrap(), b"second");
        assert_eq!(program.read("services.jar/AndroidManifest.xml").unwrap(), b"first");
        let bare = program.find_entry("bare.dex/classes.dex").unwrap().unwrap();
        assert_eq!(program.archive_path(&bare), root.join("bare.dex"));
        assert_eq!(archive_of("app/Tele/Tele.apk/classes.dex"), Some("app/Tele/Tele.apk"));
        assert_eq!(archive_of("services.jar/classes5.dex!classes1.dex"), Some("services.jar"));
        assert_eq!(archive_of("classes5.dex!classes1.dex"), None);
        assert_eq!(program.stem(), "Tele-and-2");
        assert!(program.stamp().is_ok() && program.directories().unwrap().len() == 3);

        // A lone bare DEX, and a list that comes down to one archive, read as before.
        let lone = Apk::open(root.join("bare.dex")).unwrap();
        assert_eq!(lone.dex_entries().unwrap()[0].name, "classes.dex");
        let spec = format!("{},{}", root.join("services.jar").display(), root.join("odexed.jar").display());
        let one = Apk::open(&spec).unwrap();
        assert_eq!(one.archive_count(), 1);
        assert_eq!(one.dex_entries_in_order().unwrap()[0].name, "classes.dex");
        assert_eq!(one.notes().len(), 1);
        let spec = format!("{},{}", root.join("odexed.jar").display(), root.join("broken.zip").display());
        assert!(matches!(Apk::open(&spec), Err(ApkError::NoCode { .. })));
    }

    #[test]
    fn inflate_until_streams_prefixes() {
        let dex = asc_fixture::make_dex();
        let apk_bytes = asc_fixture::make_apk(&[("classes.dex", &dex)], true);
        let f = write_temp(&apk_bytes);
        let apk = Apk::open(f.path()).unwrap();
        let entry = apk.dex_entries().unwrap().remove(0);
        match apk.inflate_until(&entry, |_| PrefixStep::Continue(8)).unwrap() {
            Prefix::Complete(v) | Prefix::Partial(v) => assert!(v.starts_with(b"dex\n") && v.len() >= 8),
            Prefix::Aborted(_) => panic!("unexpected abort"),
        }
        assert!(matches!(apk.inflate_until(&entry, |_| PrefixStep::Abort).unwrap(), Prefix::Aborted(_)));
    }
}
