//! Caches for inflated DEX entries.
//!
//! Inflating the largest DEX of an APK is the critical path of every query, and
//! it produces the same bytes every time. Two caches remove that cost for
//! repeated queries without introducing any preprocessing step: they are
//! filled lazily by the first query that needs an entry.
//!
//! * [`DiskCache`] stores inflated entries under a cache directory keyed by the
//!   APK's size, modification time and central directory. Later processes
//!   memory-map them, so the operating system's page cache keeps them hot.
//!   Writes are plain `put`s; eviction is a separate [`DiskCache::evict`] step
//!   so a host can batch it (writing a 30 MiB entry and walking the whole cache
//!   directory after every one of them is what a query must never wait on).
//!   Its capacity follows the free space of its file system by default
//!   ([`auto_disk_bytes_for`]).
//! * [`MemoryCache`] is a byte-bounded LRU of inflated entries for hosts that
//!   stay alive between queries (GUI, servers).

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Identity of an APK for cache purposes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ApkKey(String);

/// Characters a key stem (and a cached entry file name) may contain.
fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'
}
/// Longest stem kept from the APK file name.
const STEM_MAX: usize = 40;
/// Width of the hex hash that ends every key.
const HASH_HEX_LEN: usize = 16;

impl ApkKey {
    /// Derive the key from the file size, mtime and a hash of the central
    /// directory (so a rewritten archive with the same size is not confused
    /// with the old one).
    pub fn for_apk(apk: &asc_apk::Apk) -> asc_apk::Result<ApkKey> {
        let meta = fs::metadata(apk.path()).map_err(|source| asc_apk::ApkError::Io { path: apk.path().to_path_buf(), source })?;
        let mtime = meta.modified().ok().and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok()).map(|d| d.as_nanos()).unwrap_or(0);
        let mut h = fnv64(apk.central_directory_bytes()?);
        h ^= meta.len().wrapping_mul(0x9E37_79B9_7F4A_7C15);
        h ^= (mtime as u64).rotate_left(17);
        let stem = apk.path().file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let stem: String = stem.chars().filter(|c| is_key_char(*c)).take(STEM_MAX).collect();
        Ok(ApkKey(format!("{stem}-{h:0width$x}", width = HASH_HEX_LEN)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// FNV-1a over 8-byte lanes: the central directory of a large APK runs to a
/// few megabytes and is hashed once per process.
fn fnv64(bytes: &[u8]) -> u64 {
    const PRIME: u64 = 0x0100_0000_01b3;
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut chunks = bytes.chunks_exact(8);
    for c in &mut chunks {
        h ^= u64::from_le_bytes(c.try_into().expect("8-byte chunk"));
        h = h.wrapping_mul(PRIME);
    }
    for &b in chunks.remainder() {
        h ^= b as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}

/// Inflated bytes of one entry, either owned or mapped from the disk cache.
pub enum DexData {
    Owned(Vec<u8>),
    Mapped(memmap2::Mmap),
}

impl Deref for DexData {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            DexData::Owned(v) => v,
            DexData::Mapped(m) => m,
        }
    }
}

impl AsRef<[u8]> for DexData {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("cache io error at {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("{path} is not a droidasc cache directory (no {tag} marker); refusing to touch it")]
    NotACacheDir { path: PathBuf, tag: &'static str },
    #[error("{path}: too little free disk space left to cache {bytes} bytes")]
    LowDiskSpace { path: PathBuf, bytes: u64 },
}

fn io_err(path: &Path) -> impl Fn(std::io::Error) -> CacheError + '_ {
    move |source| CacheError::Io { path: path.to_path_buf(), source }
}

/// On-disk cache of inflated entries.
pub struct DiskCache {
    dir: PathBuf,
    cap: DiskCapacity,
}

/// How a [`DiskCache`] is bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskCapacity {
    /// Follow the free space of the cache's file system ([`auto_disk_bytes_for`]).
    Auto,
    /// A fixed number of bytes.
    Fixed(u64),
}

/// Upper bound of the automatic disk budget.
pub const AUTO_DISK_MAX: u64 = 4 << 30;
/// Smallest free space the automatic budget leaves on the file system; the
/// reserve is the larger of this and [`AUTO_DISK_RESERVE_PERCENT`] of it.
pub const AUTO_DISK_RESERVE_MIN: u64 = 1 << 30;
pub const AUTO_DISK_RESERVE_PERCENT: u64 = 5;
/// Share of (free space + the cache's own bytes) the automatic budget takes.
pub const AUTO_DISK_PERCENT: u64 = 20;

/// Free space the automatic budget never writes into on a file system of
/// `total` bytes.
pub fn auto_disk_reserve(total: u64) -> u64 {
    AUTO_DISK_RESERVE_MIN.max(total / 100 * AUTO_DISK_RESERVE_PERCENT)
}

/// The automatic disk budget for a cache holding `used` bytes on a file
/// system with `(free, total)` bytes (`None`: unknown, e.g. on Windows,
/// giving [`AUTO_DISK_MAX`]).
///
/// [`AUTO_DISK_PERCENT`] of what the cache could occupy (its own bytes plus
/// the free space), at most [`AUTO_DISK_MAX`], and never more than leaves
/// [`auto_disk_reserve`] free. When the disk is already below the reserve,
/// that last bound falls under `used`, so eviction gives the shortfall back.
/// (No separate floor: with a reserve of at least 1 GiB, the reserve is
/// always the tighter bound on a disk too small for 20 % to reach 256 MiB.)
pub fn auto_disk_bytes_for(space: Option<(u64, u64)>, used: u64) -> u64 {
    let Some((free, total)) = space else { return AUTO_DISK_MAX };
    let room = used.saturating_add(free);
    let budget = (room / 100 * AUTO_DISK_PERCENT).min(AUTO_DISK_MAX);
    budget.min(room.saturating_sub(auto_disk_reserve(total)))
}

/// `(free, total)` bytes of the file system holding `path` (or its nearest
/// existing ancestor). `None` where it cannot be determined.
pub fn disk_space(path: &Path) -> Option<(u64, u64)> {
    let mut p = path;
    loop {
        if p.exists() {
            return fs_space(p);
        }
        p = p.parent()?;
    }
}

#[cfg(unix)]
fn fs_space(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `c` is a NUL-terminated path and `st` a properly sized out buffer.
    if unsafe { libc::statvfs(c.as_ptr(), st.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: statvfs succeeded, so it filled `st`.
    let st = unsafe { st.assume_init() };
    // The field types differ between platforms.
    #[allow(clippy::useless_conversion, clippy::unnecessary_cast)]
    let (frsize, bavail, blocks) = (st.f_frsize as u64, st.f_bavail as u64, st.f_blocks as u64);
    Some((bavail.saturating_mul(frsize), blocks.saturating_mul(frsize)))
}

#[cfg(not(unix))]
fn fs_space(_path: &Path) -> Option<(u64, u64)> {
    None
}

/// Environment variable fixing the disk budget, in MiB (default: automatic).
pub const CACHE_MAX_ENV: &str = "DROIDASC_CACHE_MAX_MB";

impl DiskCapacity {
    /// [`DiskCapacity::Fixed`] from [`CACHE_MAX_ENV`] when it holds a number,
    /// [`DiskCapacity::Auto`] otherwise.
    pub fn from_env() -> DiskCapacity {
        DiskCapacity::from_mib(std::env::var(CACHE_MAX_ENV).ok().as_deref())
    }

    /// [`DiskCapacity::Fixed`] for a MiB count, [`DiskCapacity::Auto`] for
    /// `None` or anything that is not one.
    pub fn from_mib(value: Option<&str>) -> DiskCapacity {
        match value.and_then(|v| v.trim().parse::<u64>().ok()) {
            Some(mb) => DiskCapacity::Fixed(mb.saturating_mul(1 << 20)),
            None => DiskCapacity::Auto,
        }
    }
}

/// What [`DiskCache::budget`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskBudget {
    pub capacity: DiskCapacity,
    /// Bytes the cache may hold right now.
    pub cap_bytes: u64,
    /// Bytes it holds.
    pub used: u64,
    /// `(free, total)` of its file system, when known.
    pub space: Option<(u64, u64)>,
}

/// Temporary files older than this are leftovers of a killed writer.
const STALE_TMP: Duration = Duration::from_secs(10 * 60);

/// Marker file written into the cache root (see <https://bford.info/cachedir/>).
/// A directory is only used as a cache (written to, evicted, cleared) when it
/// carries this marker, is empty or missing, or holds nothing but the cache's
/// own APK directories (one written before the marker existed). Pointing
/// `--cache-dir` at `$HOME` or a project tree therefore neither reclaims its
/// subdirectories as "least recently used APKs" nor plants a tag that makes
/// backup tools skip it.
pub const CACHEDIR_TAG: &str = "CACHEDIR.TAG";
const CACHEDIR_TAG_CONTENT: &str = "Signature: 8a477f597d28d172789f06886806bc55\n\
# This file is a cache directory tag created by droidasc.\n\
# For information about cache directory tags, see: https://bford.info/cachedir/\n";

/// Whether `name` has the shape [`ApkKey::for_apk`] produces
/// (`<stem>-<hash>`, stem of at most [`STEM_MAX`] [`is_key_char`]s, hash of
/// [`HASH_HEX_LEN`] lowercase hex digits). Only such subdirectories are
/// counted, evicted or cleared.
fn is_cache_dir_name(name: &str) -> bool {
    let Some((stem, hash)) = name.rsplit_once('-') else { return false };
    hash.len() == HASH_HEX_LEN
        && hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        && stem.len() <= STEM_MAX
        && stem.chars().all(is_key_char)
}

impl DiskCache {
    /// Capacity of [`DiskCapacity::Auto`] when the free space is unknown.
    pub const DEFAULT_CAP: u64 = AUTO_DISK_MAX;

    /// The default cache directory: `$DROIDASC_CACHE_DIR`, else
    /// `$XDG_CACHE_HOME/droidasc`, else `~/.cache/droidasc`.
    pub fn default_dir() -> Option<PathBuf> {
        if let Some(d) = std::env::var_os("DROIDASC_CACHE_DIR") {
            return Some(PathBuf::from(d));
        }
        if let Some(d) = std::env::var_os("XDG_CACHE_HOME") {
            return Some(PathBuf::from(d).join("droidasc"));
        }
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache").join("droidasc"))
    }

    /// A cache in `dir` bounded by [`DiskCapacity::from_env`] (automatic
    /// unless [`CACHE_MAX_ENV`] is set).
    pub fn open(dir: impl Into<PathBuf>) -> DiskCache {
        DiskCache { dir: dir.into(), cap: DiskCapacity::from_env() }
    }

    /// Open the default directory, if one can be determined.
    pub fn open_default() -> Option<DiskCache> {
        Self::default_dir().map(Self::open)
    }

    /// A fixed capacity of `cap_bytes`.
    pub fn with_capacity(self, cap_bytes: u64) -> DiskCache {
        self.with_capacity_mode(DiskCapacity::Fixed(cap_bytes))
    }

    pub fn with_capacity_mode(mut self, cap: DiskCapacity) -> DiskCache {
        self.cap = cap;
        self
    }

    pub fn capacity_mode(&self) -> DiskCapacity {
        self.cap
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Bytes the cache may hold when it holds `used`: the fixed capacity, or
    /// the automatic budget for the file system's current free space.
    pub fn capacity_for(&self, used: u64) -> u64 {
        match self.cap {
            DiskCapacity::Fixed(b) => b,
            DiskCapacity::Auto => auto_disk_bytes_for(disk_space(&self.dir), used),
        }
    }

    /// Capacity, usage and free space right now (walks the cache directory).
    pub fn budget(&self) -> DiskBudget {
        let used = self.stats().2;
        let space = disk_space(&self.dir);
        let cap_bytes = match self.cap {
            DiskCapacity::Fixed(b) => b,
            DiskCapacity::Auto => auto_disk_bytes_for(space, used),
        };
        DiskBudget { capacity: self.cap, cap_bytes, used, space }
    }

    fn entry_path(&self, key: &ApkKey, entry_name: &str) -> PathBuf {
        let safe: String = entry_name.chars().map(|c| if is_key_char(c) { c } else { '_' }).collect();
        self.dir.join(key.as_str()).join(safe)
    }

    /// Map a cached entry if present and of the expected size.
    pub fn get(&self, key: &ApkKey, entry_name: &str, expected_len: u64) -> Option<DexData> {
        let path = self.entry_path(key, entry_name);
        let file = fs::File::open(&path).ok()?;
        let len = file.metadata().ok()?.len();
        if expected_len != 0 && len != expected_len {
            return None;
        }
        // Touch the APK directory so LRU eviction sees recent use.
        let _ = touch_dir(path.parent()?);
        // SAFETY: read-only mapping of a file this process wrote atomically; a
        // concurrent overwrite replaces the directory entry, not the mapped inode.
        let map = unsafe { memmap2::MmapOptions::new().populate().map(&file) }.ok()?;
        Some(DexData::Mapped(map))
    }

    /// Store an inflated entry (atomic rename; concurrent writers are
    /// harmless). Does not evict: call [`DiskCache::evict`] after a batch of
    /// puts.
    pub fn put(&self, key: &ApkKey, entry_name: &str, bytes: &[u8]) -> Result<(), CacheError> {
        // Checked before anything is created: the tag must never land in a
        // directory that holds someone else's files.
        if !self.is_cache_dir() {
            return Err(self.not_a_cache_dir());
        }
        // One statvfs per entry: with the automatic budget, never write into
        // the reserve the file system needs (another program may have filled
        // the disk since the last eviction).
        if self.cap == DiskCapacity::Auto {
            if let Some((free, total)) = disk_space(&self.dir) {
                if free.saturating_sub(bytes.len() as u64) < auto_disk_reserve(total) {
                    return Err(CacheError::LowDiskSpace { path: self.dir.clone(), bytes: bytes.len() as u64 });
                }
            }
        }
        let path = self.entry_path(key, entry_name);
        let parent = path.parent().expect("entry path has a parent");
        fs::create_dir_all(parent).map_err(io_err(parent))?;
        // Best effort: an unwritable root (shared cache, full disk) must not
        // stop entries from being written into their own directories.
        let _ = self.ensure_tag();
        let tmp = parent.join(format!(".{}.{}.tmp", path.file_name().unwrap_or_default().to_string_lossy(), std::process::id()));
        {
            let mut f = fs::File::create(&tmp).map_err(io_err(&tmp))?;
            f.write_all(bytes).map_err(io_err(&tmp))?;
            f.sync_data().ok();
        }
        fs::rename(&tmp, &path).map_err(io_err(&path))?;
        Ok(())
    }

    /// `(apk directories, files, bytes)` currently stored.
    pub fn stats(&self) -> (usize, usize, u64) {
        let mut dirs = 0;
        let mut files = 0;
        let mut bytes = 0;
        for (_, _, n, size) in self.apk_dirs() {
            dirs += 1;
            files += n;
            bytes += size;
        }
        (dirs, files, bytes)
    }

    /// Delete every cached APK directory (and nothing else). Returns the
    /// number of bytes freed. Refuses to run on a directory that is not a
    /// cache directory (see [`CACHEDIR_TAG`]).
    pub fn clear(&self) -> Result<u64, CacheError> {
        if !self.dir.exists() {
            return Ok(0);
        }
        if !self.is_cache_dir() {
            return Err(self.not_a_cache_dir());
        }
        let mut bytes = 0;
        for (_, path, _, size) in self.apk_dirs() {
            fs::remove_dir_all(&path).map_err(io_err(&path))?;
            bytes += size;
        }
        Ok(bytes)
    }

    /// `Ok` when the directory may be used as this cache (see
    /// [`CACHEDIR_TAG`]), [`CacheError::NotACacheDir`] otherwise. Hosts call
    /// this up front: [`DiskCache::put`] refuses such a directory too, but its
    /// errors are usually swallowed by a background writer.
    pub fn check_usable(&self) -> Result<(), CacheError> {
        if self.is_cache_dir() {
            Ok(())
        } else {
            Err(self.not_a_cache_dir())
        }
    }

    fn not_a_cache_dir(&self) -> CacheError {
        CacheError::NotACacheDir { path: self.dir.clone(), tag: CACHEDIR_TAG }
    }

    /// Write the [`CACHEDIR_TAG`] marker if it is missing.
    fn ensure_tag(&self) -> Result<(), CacheError> {
        if self.has_tag() {
            return Ok(());
        }
        let tag = self.dir.join(CACHEDIR_TAG);
        // `create_new` so two first writers cannot race; whoever loses is done.
        match fs::OpenOptions::new().write(true).create_new(true).open(&tag) {
            // A truncated tag would still count as one; remove it so the next
            // put retries.
            Ok(mut f) => f.write_all(CACHEDIR_TAG_CONTENT.as_bytes()).map_err(|e| {
                drop(f);
                let _ = fs::remove_file(&tag);
                io_err(&tag)(e)
            }),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(io_err(&tag)(e)),
        }
    }

    fn has_tag(&self) -> bool {
        self.dir.join(CACHEDIR_TAG).is_file()
    }

    /// Whether the directory may be treated as this cache's own: it carries
    /// the tag, does not exist yet, or contains nothing but APK directories
    /// of the cache's naming shape (plus Finder's `.DS_Store`), which is what
    /// a cache written before the tag was introduced looks like. Any other
    /// file, dot-files included, means the directory is someone else's.
    fn is_cache_dir(&self) -> bool {
        if self.has_tag() {
            return true;
        }
        match fs::read_dir(&self.dir) {
            Ok(rd) => rd.flatten().all(|d| {
                let name = d.file_name();
                let name = name.to_string_lossy();
                match d.file_type() {
                    Ok(t) if t.is_dir() => is_cache_dir_name(&name),
                    Ok(t) if t.is_file() => name == ".DS_Store",
                    _ => false,
                }
            }),
            Err(e) => e.kind() == std::io::ErrorKind::NotFound,
        }
    }

    /// `(mtime, path, file count, bytes)` per APK directory (subdirectories
    /// whose name matches [`is_cache_dir_name`]; anything else in the
    /// directory is ignored); also removes temporary files left behind by a
    /// killed writer.
    fn apk_dirs(&self) -> Vec<(SystemTime, PathBuf, usize, u64)> {
        let mut out = Vec::new();
        let Ok(rd) = fs::read_dir(&self.dir) else { return out };
        let now = SystemTime::now();
        for d in rd.flatten() {
            let path = d.path();
            if !is_cache_dir_name(&d.file_name().to_string_lossy()) || !path.is_dir() {
                continue;
            }
            let mtime = d.metadata().and_then(|m| m.modified()).unwrap_or(SystemTime::UNIX_EPOCH);
            let (mut files, mut size) = (0usize, 0u64);
            if let Ok(fd) = fs::read_dir(&path) {
                for f in fd.flatten() {
                    let Ok(m) = f.metadata() else { continue };
                    let name = f.file_name();
                    let is_tmp = name.to_string_lossy().ends_with(".tmp");
                    if is_tmp && m.modified().ok().and_then(|t| now.duration_since(t).ok()).is_some_and(|age| age > STALE_TMP) {
                        let _ = fs::remove_file(f.path());
                        continue;
                    }
                    files += 1;
                    size += m.len();
                }
            }
            out.push((mtime, path, files, size));
        }
        out
    }

    /// Evict least recently used APK directories until under capacity
    /// ([`DiskCache::capacity_for`], re-evaluated against the current free
    /// space). Does nothing in a directory that is not a cache directory (see
    /// [`CACHEDIR_TAG`]).
    pub fn evict(&self) {
        if !self.is_cache_dir() {
            return;
        }
        let mut dirs = self.apk_dirs();
        let mut total: u64 = dirs.iter().map(|d| d.3).sum();
        let cap = self.capacity_for(total);
        if total <= cap {
            return;
        }
        dirs.sort();
        for (_, path, _, size) in dirs {
            if total <= cap {
                break;
            }
            if fs::remove_dir_all(&path).is_ok() {
                total = total.saturating_sub(size);
            }
        }
    }
}

fn touch_dir(dir: &Path) -> std::io::Result<()> {
    let now = SystemTime::now();
    if fs::File::open(dir).and_then(|f| f.set_modified(now)).is_ok() {
        return Ok(());
    }
    // Portable fallback: update the directory mtime by creating and removing a marker.
    let marker = dir.join(".touch");
    fs::File::create(&marker)?;
    fs::remove_file(&marker)
}

struct Slot<T> {
    value: Arc<T>,
    size: usize,
    /// Logical clock of the last access; the smallest is the LRU victim.
    tick: u64,
}

/// Byte-bounded LRU of inflated entries plus any per-entry state the host
/// wants to keep alongside (`T`).
pub struct MemoryCache<T> {
    cap_bytes: usize,
    used: usize,
    clock: u64,
    map: HashMap<ApkKey, HashMap<String, Slot<T>>>,
}

impl<T> MemoryCache<T> {
    pub fn new(cap_bytes: usize) -> Self {
        MemoryCache { cap_bytes, used: 0, clock: 0, map: HashMap::new() }
    }

    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    pub fn get(&mut self, key: &ApkKey, entry_name: &str) -> Option<Arc<T>> {
        let tick = self.tick();
        let slot = self.map.get_mut(key)?.get_mut(entry_name)?;
        slot.tick = tick;
        Some(Arc::clone(&slot.value))
    }

    pub fn insert(&mut self, key: &ApkKey, entry_name: &str, value: Arc<T>, size: usize) {
        let tick = self.tick();
        let per_apk = self.map.entry(key.clone()).or_default();
        if let Some(old) = per_apk.insert(entry_name.to_string(), Slot { value, size, tick }) {
            self.used -= old.size;
        }
        self.used += size;
        self.evict_over_cap();
    }

    /// Re-charge `value` (still the entry cached under `entry_name`) at
    /// `size` bytes, e.g. once per-entry state built after insertion has
    /// grown it, and evict least recently used entries if that exceeds the
    /// capacity. Does nothing when the slot holds something else by now.
    pub fn resize(&mut self, key: &ApkKey, entry_name: &str, value: &Arc<T>, size: usize) {
        let Some(slot) = self.map.get_mut(key).and_then(|m| m.get_mut(entry_name)) else { return };
        if !Arc::ptr_eq(&slot.value, value) {
            return;
        }
        let old = std::mem::replace(&mut slot.size, size);
        self.used = self.used - old + size;
        self.evict_over_cap();
    }

    /// Swap the entry cached under `entry_name` for `new` when it is still
    /// `current`, keeping its size and recency. Returns whether it swapped.
    pub fn replace(&mut self, key: &ApkKey, entry_name: &str, current: &Arc<T>, new: Arc<T>) -> bool {
        match self.map.get_mut(key).and_then(|m| m.get_mut(entry_name)) {
            Some(slot) if Arc::ptr_eq(&slot.value, current) => {
                slot.value = new;
                true
            }
            _ => false,
        }
    }

    /// Size the entry cached under `entry_name` is charged at.
    pub fn charged_bytes(&self, key: &ApkKey, entry_name: &str) -> Option<usize> {
        self.map.get(key)?.get(entry_name).map(|s| s.size)
    }

    /// Evict least recently used entries until under capacity (always
    /// keeping the last one: a single entry larger than the cap stays usable).
    fn evict_over_cap(&mut self) {
        while self.used > self.cap_bytes && self.len() > 1 {
            let Some((k, name)) = self.lru() else { break };
            if let Some(per_apk) = self.map.get_mut(&k) {
                if let Some(old) = per_apk.remove(&name) {
                    self.used -= old.size;
                }
                if per_apk.is_empty() {
                    self.map.remove(&k);
                }
            }
        }
    }

    fn lru(&self) -> Option<(ApkKey, String)> {
        self.map
            .iter()
            .flat_map(|(k, per)| per.iter().map(move |(n, s)| (s.tick, k, n)))
            .min_by_key(|(t, _, _)| *t)
            .map(|(_, k, n)| (k.clone(), n.clone()))
    }

    pub fn used_bytes(&self) -> usize {
        self.used
    }

    /// Every cached value, in no particular order (recency is not touched).
    pub fn values(&self) -> impl Iterator<Item = &Arc<T>> {
        self.map.values().flat_map(|per| per.values().map(|s| &s.value))
    }

    pub fn len(&self) -> usize {
        self.map.values().map(HashMap::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drop every entry cached for `key` and return the bytes released.
    pub fn remove_apk(&mut self, key: &ApkKey) -> usize {
        let freed: usize = self.map.remove(key).map(|per| per.values().map(|s| s.size).sum()).unwrap_or(0);
        self.used -= freed;
        freed
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.used = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_remove_apk_releases_only_that_apk() {
        let (a, b) = (ApkKey("a-0123456789abcdef".into()), ApkKey("b-0123456789abcdef".into()));
        let mut mem = MemoryCache::new(1 << 20);
        mem.insert(&a, "classes.dex", Arc::new(1), 100);
        mem.insert(&a, "classes2.dex", Arc::new(2), 50);
        mem.insert(&b, "classes.dex", Arc::new(3), 7);
        assert_eq!(mem.remove_apk(&a), 150);
        assert_eq!(mem.remove_apk(&a), 0);
        assert_eq!((mem.used_bytes(), mem.len()), (7, 1));
        assert!(mem.get(&b, "classes.dex").is_some());
    }

    #[test]
    fn disk_roundtrip_and_clear() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::open(dir.path()).with_capacity(1 << 20);
        let key = ApkKey("app-0123456789abcdef".into());
        assert!(cache.get(&key, "classes.dex", 3).is_none());
        cache.put(&key, "classes.dex", b"abc").unwrap();
        assert_eq!(&*cache.get(&key, "classes.dex", 3).unwrap(), b"abc");
        assert!(cache.get(&key, "classes.dex", 4).is_none());
        let (dirs, files, bytes) = cache.stats();
        assert_eq!((dirs, files, bytes), (1, 1, 3));
        assert_eq!(cache.clear().unwrap(), 3);
        assert!(cache.get(&key, "classes.dex", 3).is_none());
    }

    #[test]
    fn disk_evicts_least_recently_used_apk() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::open(dir.path()).with_capacity(10);
        let old = ApkKey("old-0000000000000001".into());
        let new = ApkKey("new-0000000000000002".into());
        cache.put(&old, "classes.dex", &[0; 6]).unwrap();
        // Make sure the second directory is strictly newer.
        let later = SystemTime::now() + Duration::from_secs(5);
        cache.put(&new, "classes.dex", &[0; 6]).unwrap();
        fs::File::open(dir.path().join("new-0000000000000002")).unwrap().set_modified(later).unwrap();
        assert_eq!(cache.stats(), (2, 2, 12));
        cache.evict();
        assert_eq!(cache.stats(), (1, 1, 6));
        assert!(cache.get(&new, "classes.dex", 6).is_some());
        assert!(cache.get(&old, "classes.dex", 6).is_none());
    }

    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;

    #[test]
    fn auto_disk_budget_follows_free_space() {
        // Unknown file system (Windows): the old fixed cap.
        assert_eq!(auto_disk_bytes_for(None, 0), AUTO_DISK_MAX);
        // Large disk: capped at 4 GiB.
        assert_eq!(auto_disk_bytes_for(Some((500 * GIB, 1000 * GIB)), 0), AUTO_DISK_MAX);
        // Small disk: 20 % of free + own bytes.
        assert_eq!(auto_disk_bytes_for(Some((10 * GIB, 20 * GIB)), 0), 10 * GIB / 100 * 20);
        assert_eq!(auto_disk_bytes_for(Some((9 * GIB, 20 * GIB)), GIB), 10 * GIB / 100 * 20);
        // Never eats into the reserve (1 GiB here).
        assert_eq!(auto_disk_bytes_for(Some((GIB + 100 * MIB, 16 * GIB)), 0), 100 * MIB);
        assert_eq!(auto_disk_bytes_for(Some((GIB, 16 * GIB)), 0), 0);
    }

    #[test]
    fn auto_disk_budget_shrinks_below_usage_on_a_nearly_full_disk() {
        // 100 GiB disk: 5 GiB reserve. 6 GiB cached, 0.5 GiB free: 20 % of
        // the 6.5 GiB the cache could hold, well below what it holds now.
        assert_eq!(auto_disk_bytes_for(Some((GIB / 2, 100 * GIB)), 6 * GIB), (6 * GIB + GIB / 2) / 100 * 20);
        // 5.5 GiB cached, 0.5 GiB free: the reserve binds (1 GiB < 20 % of
        // 6 GiB), giving back the 4.5 GiB shortfall.
        assert_eq!(auto_disk_bytes_for(Some((GIB / 2, 100 * GIB)), 5 * GIB + GIB / 2), GIB);
        // Nothing left to give: evict everything.
        assert_eq!(auto_disk_bytes_for(Some((GIB / 2, 100 * GIB)), 3 * GIB), 0);
        assert_eq!(auto_disk_reserve(100 * GIB), 5 * GIB);
        assert_eq!(auto_disk_reserve(4 * GIB), GIB);
    }

    #[test]
    fn explicit_disk_capacity_wins() {
        assert_eq!(DiskCapacity::from_mib(Some(" 512 ")), DiskCapacity::Fixed(512 * MIB));
        assert_eq!(DiskCapacity::from_mib(Some("lots")), DiskCapacity::Auto);
        assert_eq!(DiskCapacity::from_mib(None), DiskCapacity::Auto);
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::open(dir.path()).with_capacity_mode(DiskCapacity::Auto).with_capacity(7);
        assert_eq!(cache.capacity_mode(), DiskCapacity::Fixed(7));
        assert_eq!(cache.capacity_for(1 << 40), 7);
        let b = cache.budget();
        assert_eq!((b.capacity, b.cap_bytes, b.used), (DiskCapacity::Fixed(7), 7, 0));
        // The file system of a real directory is known on Unix.
        assert_eq!(b.space.is_some(), cfg!(unix));
        let auto = DiskCache::open(dir.path()).with_capacity_mode(DiskCapacity::Auto);
        assert_eq!(auto.budget().cap_bytes, auto_disk_bytes_for(disk_space(dir.path()), 0));
        // A directory that does not exist yet is measured on its parent.
        assert_eq!(disk_space(&dir.path().join("a/b")).is_some(), cfg!(unix));
    }

    #[test]
    fn eviction_follows_a_lowered_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let keys: Vec<ApkKey> = (0..3).map(|i| ApkKey(format!("app-000000000000000{i}"))).collect();
        let cache = DiskCache::open(dir.path()).with_capacity(100);
        for (i, k) in keys.iter().enumerate() {
            cache.put(k, "classes.dex", &[0; 10]).unwrap();
            let t = SystemTime::now() + Duration::from_secs(10 * i as u64);
            fs::File::open(dir.path().join(k.as_str())).unwrap().set_modified(t).unwrap();
        }
        cache.evict();
        assert_eq!(cache.stats(), (3, 3, 30));
        // Same directory, smaller budget (as when the free space drops): the
        // next eviction pass trims to it, oldest first.
        let cache = cache.with_capacity(15);
        cache.evict();
        assert_eq!(cache.stats(), (1, 1, 10));
        assert!(cache.get(&keys[2], "classes.dex", 10).is_some());
    }

    #[test]
    fn cache_dir_names_are_recognised() {
        assert!(is_cache_dir_name("app-0123456789abcdef"));
        assert!(is_cache_dir_name("-0123456789abcdef")); // empty stem
        assert!(is_cache_dir_name("my.app_v2-0123456789abcdef"));
        assert!(!is_cache_dir_name("Documents"));
        assert!(!is_cache_dir_name("app-0123456789ABCDEF")); // upper-case hex
        assert!(!is_cache_dir_name("app-0123456789abcde")); // 15 digits
        assert!(!is_cache_dir_name("app 1-0123456789abcdef")); // space
        assert!(!is_cache_dir_name(&format!("{}-0123456789abcdef", "a".repeat(41))));
    }

    #[test]
    fn unrelated_directories_survive_evict_and_clear() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::open(dir.path()).with_capacity(4);
        let key = ApkKey("app-0123456789abcdef".into());
        // The first write tags the (empty) directory ...
        cache.put(&key, "classes.dex", &[0; 8]).unwrap();
        assert!(dir.path().join(CACHEDIR_TAG).is_file());
        // ... and whatever lands next to the cache afterwards is left alone.
        let thesis = dir.path().join("my-thesis");
        fs::create_dir(&thesis).unwrap();
        fs::write(thesis.join("chapter1.txt"), vec![0u8; 100]).unwrap();
        fs::write(dir.path().join("notes.txt"), b"keep").unwrap();
        // Only the cache directory is counted, even though the thesis is bigger.
        assert_eq!(cache.stats(), (1, 1, 8));
        cache.evict();
        assert!(thesis.join("chapter1.txt").is_file());
        assert!(cache.get(&key, "classes.dex", 8).is_none());
        cache.put(&key, "classes.dex", &[0; 8]).unwrap();
        assert_eq!(cache.clear().unwrap(), 8);
        assert!(thesis.join("chapter1.txt").is_file());
        assert!(dir.path().join("notes.txt").is_file());
        assert!(dir.path().join(CACHEDIR_TAG).is_file());
        assert!(dir.path().is_dir());
        assert_eq!(cache.stats(), (0, 0, 0));
    }

    #[test]
    fn foreign_directories_are_refused_and_never_tagged() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::open(dir.path()).with_capacity(1);
        // A cache-shaped subdirectory next to unrelated content: not ours.
        let lookalike = dir.path().join("app-0123456789abcdef");
        fs::create_dir(&lookalike).unwrap();
        fs::write(lookalike.join("classes.dex"), [0; 16]).unwrap();
        fs::write(dir.path().join("notes.txt"), b"keep").unwrap();
        cache.evict();
        assert!(lookalike.join("classes.dex").is_file());
        assert!(matches!(cache.clear(), Err(CacheError::NotACacheDir { .. })));
        assert!(lookalike.join("classes.dex").is_file());
        // Writing refuses too, so no tag is planted that would make backup
        // tools skip the user's directory.
        let key = ApkKey("other-fedcba9876543210".into());
        assert!(matches!(cache.put(&key, "classes.dex", &[0; 4]), Err(CacheError::NotACacheDir { .. })));
        assert!(!dir.path().join(CACHEDIR_TAG).exists());
        assert!(!dir.path().join("other-fedcba9876543210").exists());
        // An empty or missing directory is fine.
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(DiskCache::open(empty.path()).clear().unwrap(), 0);
        assert_eq!(DiskCache::open(empty.path().join("missing")).clear().unwrap(), 0);
    }

    #[test]
    fn legacy_cache_directories_are_adopted() {
        // Written by a build that predates the tag: only APK directories.
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::open(dir.path()).with_capacity(1);
        let legacy = dir.path().join("app-0123456789abcdef");
        fs::create_dir(&legacy).unwrap();
        fs::write(legacy.join("classes.dex"), [0; 16]).unwrap();
        assert_eq!(cache.stats(), (1, 1, 16));
        cache.evict();
        assert!(!legacy.exists(), "over capacity: evicted");
        fs::create_dir(&legacy).unwrap();
        fs::write(legacy.join("classes.dex"), [0; 16]).unwrap();
        assert_eq!(cache.clear().unwrap(), 16);
        // A put adopts it for good.
        let key = ApkKey("app-0123456789abcdef".into());
        cache.put(&key, "classes.dex", &[0; 4]).unwrap();
        assert!(dir.path().join(CACHEDIR_TAG).is_file());
    }

    #[test]
    fn a_tag_that_is_not_a_file_is_not_a_tag() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::open(dir.path()).with_capacity(1);
        fs::create_dir(dir.path().join(CACHEDIR_TAG)).unwrap();
        fs::write(dir.path().join("notes.txt"), b"keep").unwrap();
        let key = ApkKey("app-0123456789abcdef".into());
        assert!(matches!(cache.put(&key, "classes.dex", &[0; 4]), Err(CacheError::NotACacheDir { .. })));
        assert!(matches!(cache.clear(), Err(CacheError::NotACacheDir { .. })));
    }

    #[test]
    fn dot_files_make_a_directory_foreign() {
        // A checkout or config directory can hold nothing but dot-files.
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::open(dir.path());
        fs::write(dir.path().join(".gitignore"), b"*\n").unwrap();
        assert!(matches!(cache.check_usable(), Err(CacheError::NotACacheDir { .. })));
        let key = ApkKey("app-0123456789abcdef".into());
        assert!(matches!(cache.put(&key, "classes.dex", &[0; 4]), Err(CacheError::NotACacheDir { .. })));
        assert!(!dir.path().join(CACHEDIR_TAG).exists());
        // Finder metadata next to a legacy cache does not.
        let legacy = tempfile::tempdir().unwrap();
        fs::create_dir(legacy.path().join("app-0123456789abcdef")).unwrap();
        fs::write(legacy.path().join(".DS_Store"), b"").unwrap();
        assert!(DiskCache::open(legacy.path()).check_usable().is_ok());
    }

    #[test]
    fn memory_lru_evicts_by_bytes() {
        let mut m: MemoryCache<Vec<u8>> = MemoryCache::new(10);
        let k = ApkKey("k".into());
        m.insert(&k, "a", Arc::new(vec![0; 4]), 4);
        m.insert(&k, "b", Arc::new(vec![0; 4]), 4);
        assert!(m.get(&k, "a").is_some()); // a is now most recent
        m.insert(&k, "c", Arc::new(vec![0; 4]), 4); // evicts b
        assert!(m.get(&k, "b").is_none());
        assert!(m.get(&k, "a").is_some());
        assert_eq!(m.used_bytes(), 8);
        assert_eq!(m.len(), 2);
        // Re-inserting an entry replaces its accounting.
        m.insert(&k, "a", Arc::new(vec![0; 2]), 2);
        assert_eq!(m.used_bytes(), 6);
        m.clear();
        assert!(m.is_empty());
    }

    #[test]
    fn memory_lru_resize_charges_and_evicts() {
        let mut m: MemoryCache<Vec<u8>> = MemoryCache::new(10);
        let k = ApkKey("k".into());
        let a = Arc::new(vec![0; 4]);
        m.insert(&k, "a", Arc::clone(&a), 4);
        let b = Arc::new(vec![0; 4]);
        m.insert(&k, "b", Arc::clone(&b), 4);
        // Growing b past the cap evicts a (least recently used).
        m.resize(&k, "b", &b, 7);
        assert_eq!(m.used_bytes(), 7);
        assert!(m.get(&k, "a").is_none());
        assert_eq!(m.charged_bytes(&k, "b"), Some(7));
        // A stale handle does not re-charge whatever replaced it.
        let b2 = Arc::new(vec![1; 4]);
        m.insert(&k, "b", Arc::clone(&b2), 4);
        m.resize(&k, "b", &b, 9);
        assert_eq!(m.charged_bytes(&k, "b"), Some(4));
        // The last entry is kept even when it alone exceeds the cap.
        m.resize(&k, "b", &b2, 50);
        assert_eq!((m.len(), m.used_bytes()), (1, 50));
    }

    #[test]
    fn memory_lru_replace_keeps_size_and_recency() {
        let mut m: MemoryCache<Vec<u8>> = MemoryCache::new(10);
        let k = ApkKey("k".into());
        let a = Arc::new(vec![0; 4]);
        m.insert(&k, "a", Arc::clone(&a), 4);
        m.insert(&k, "b", Arc::new(vec![0; 4]), 4);
        assert!(m.get(&k, "a").is_some()); // a most recent
        let a2 = Arc::new(vec![9; 4]);
        assert!(m.replace(&k, "a", &a, Arc::clone(&a2)));
        assert!(!m.replace(&k, "a", &a, Arc::new(vec![])), "stale handle");
        assert!(!m.replace(&k, "missing", &a, Arc::new(vec![])));
        assert_eq!(m.used_bytes(), 8);
        m.insert(&k, "c", Arc::new(vec![0; 4]), 4); // evicts b, not the replaced a
        assert!(Arc::ptr_eq(&m.get(&k, "a").unwrap(), &a2));
        assert!(m.get(&k, "b").is_none());
    }

    #[test]
    fn fnv_lanes_match_scalar() {
        fn scalar(bytes: &[u8]) -> u64 {
            let mut h: u64 = 0xcbf2_9ce4_8422_2325;
            for &b in bytes {
                h ^= b as u64;
                h = h.wrapping_mul(0x0100_0000_01b3);
            }
            h
        }
        // The lane variant is a different function on purpose; it only has to
        // be stable and spread inputs. Check it distinguishes nearby inputs.
        let a = fnv64(b"PK\x01\x02classes.dex");
        let b = fnv64(b"PK\x01\x02classes2.dex");
        assert_ne!(a, b);
        assert_ne!(fnv64(b""), fnv64(b"\0"));
        assert_eq!(fnv64(b"abc"), scalar(b"abc")); // short inputs take the scalar path
    }
}
