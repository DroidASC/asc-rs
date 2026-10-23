//! Caches for inflated DEX entries and what is derived from them.
//!
//! Inflating the largest DEX of an APK is the critical path of every query, and
//! it produces the same bytes every time. Two caches remove that cost for
//! repeated queries without introducing any preprocessing step: they are
//! filled lazily by the first query that needs an entry.
//!
//! * [`DiskCache`] stores data under a cache directory keyed by the APK's
//!   size, modification time and central directory ([`ApkKey`]), in three
//!   tiers ([`Tier`]) that share one budget:
//!   - **L1** inflated DEX entries ([`DiskCache::put`] / [`DiskCache::get`]),
//!     cheap to rebuild and large: evicted first, largest-and-oldest first.
//!     Entries below [`DiskCache::min_dex_bytes`] are not worth writing
//!     (re-inflating them is cheaper than the write).
//!   - **L2** derived indexes ([`DiskCache::put_derived`] /
//!     [`DiskCache::get_derived`]): locator tables and other per-DEX or
//!     per-APK structures, stored so they can be mapped and viewed in place.
//!     Every process mapping one shares its pages instead of building a
//!     private copy. Kept by rebuild cost per byte; evicted last.
//!   - **L3** rendered results ([`DiskCache::put_rendered`] /
//!     [`DiskCache::get_rendered`]): small outputs keyed by the query and the
//!     tool version, plain LRU under a small budget of their own.
//!
//!   Later processes memory-map L1 and L2 files, so the operating system's
//!   page cache keeps them hot. Writes are plain `put`s; eviction is a
//!   separate [`DiskCache::evict`] step so a host can batch it (writing a
//!   30 MiB entry and walking the whole cache directory after every one of
//!   them is what a query must never wait on). The budget follows the free
//!   space of the file system by default ([`auto_disk_bytes_for`]).
//!
//!   Writes are never synced: everything here can be rebuilt, and a sync
//!   per file costs more than the query that wrote it (macOS flushes the
//!   drive's own cache on every one). A temporary file renamed into place
//!   keeps readers from seeing half a file while the system runs; what a
//!   crash can leave is a file whose pages never reached the disk. Every
//!   file carries a CRC-32 of its contents, checked when a file last
//!   written before the current boot is first read ([`predates_boot`]):
//!   a damaged one is deleted and read as a miss. L3 files are small and
//!   always checked.
//! * [`MemoryCache`] is a byte-bounded LRU of inflated entries for hosts that
//!   stay alive between queries (MCP servers, the daemon).
//! * [`ProcessRegistry`] lets resident hosts of one user see each other, so
//!   their memory budgets add up to one machine-wide budget.

mod procs;

pub use procs::{ProcessRegistry, ProcessUsage};

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

impl DexData {
    /// `len` bytes at `offset` of the file at `path`, mapped read-only (any
    /// offset: the mapping starts at the page holding it). For entries an
    /// APK stores uncompressed, so a host keeping them gets file pages the
    /// OS can share and reclaim instead of a heap copy. The file must not
    /// change while mapped, the same contract as mapping the APK itself.
    pub fn map_region(path: &Path, offset: u64, len: usize) -> std::io::Result<DexData> {
        let file = fs::File::open(path)?;
        if file.metadata()?.len() < offset.saturating_add(len as u64) {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "region past the end of the file"));
        }
        // SAFETY: read-only mapping of a range checked to lie inside the file;
        // see the contract above.
        let map = unsafe { memmap2::MmapOptions::new().offset(offset).len(len).map(&file) }?;
        Ok(DexData::Mapped(map))
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

/// On-disk cache of inflated entries, derived indexes and rendered results.
pub struct DiskCache {
    dir: PathBuf,
    cap: DiskCapacity,
    min_dex_bytes: u64,
    min_derived_cost: Duration,
    /// Tiers written and read; the others behave as permanently empty.
    tiers: [bool; 3],
    /// Bytes this handle wrote since its last eviction walk.
    written: std::sync::atomic::AtomicU64,
    /// When the system booted ([`boot_time`]): files written before it are
    /// checked on read.
    boot: Option<SystemTime>,
}

/// The tiers of a [`DiskCache`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Tier {
    /// L1: inflated DEX entries, `<dir>/<apk key>/<entry>`.
    Dex,
    /// L2: derived indexes, `<dir>/derived/<apk key>/<name>~<kind>.v<format>.<version>`.
    Derived,
    /// L3: rendered results, `<dir>/rendered/<apk key>/<hash of the query>`.
    Rendered,
}

impl Tier {
    pub const ALL: [Tier; 3] = [Tier::Dex, Tier::Derived, Tier::Rendered];

    /// Name in [`TIERS_ENV`].
    pub fn name(self) -> &'static str {
        match self {
            Tier::Dex => "dex",
            Tier::Derived => "derived",
            Tier::Rendered => "rendered",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Tier::Dex => "L1 dex",
            Tier::Derived => "L2 derived",
            Tier::Rendered => "L3 rendered",
        }
    }
}

/// Subdirectory of the L2 tier.
const DERIVED_DIR: &str = "derived";
/// Subdirectory of the L3 tier.
const RENDERED_DIR: &str = "rendered";
/// Where each APK key's source path is recorded, to spot dead entries.
const SOURCES_DIR: &str = "sources";
/// Where the MCP server writes replies too long for the client (its own
/// budget and pruning; this cache only recognizes and clears it).
pub const SPILL_DIR: &str = "out";

/// Absolute cap of L3, which also never takes more than
/// 1/[`RENDERED_BUDGET_DIVISOR`] of the total budget.
pub const RENDERED_MAX: u64 = 128 << 20;
pub const RENDERED_BUDGET_DIVISOR: u64 = 8;
/// L2 never takes more than 1/[`DERIVED_BUDGET_DIVISOR`] of the total budget.
pub const DERIVED_BUDGET_DIVISOR: u64 = 2;

/// Inflated DEX entries smaller than this are not written to L1 by default:
/// re-inflating them costs less than writing (and later evicting) them.
pub const DEFAULT_MIN_DEX_BYTES: u64 = 4 << 20;
/// Environment variable overriding [`DEFAULT_MIN_DEX_BYTES`], in MiB.
pub const MIN_DEX_ENV: &str = "DROIDASC_CACHE_MIN_DEX_MB";
/// Derived indexes that took less than this to build are not written to L2
/// by default: mapping and checking a file would save next to nothing.
pub const DEFAULT_MIN_DERIVED_COST: Duration = Duration::from_millis(2);

/// Environment variable naming the tiers to use (`dex,derived,rendered`, the
/// default: all of them), e.g. to measure one tier on its own.
pub const TIERS_ENV: &str = "DROIDASC_CACHE_TIERS";

/// Header of an L2 file; the payload follows at [`DERIVED_HEADER`], so it is
/// as aligned as the mapping (page-aligned) up to that.
const DERIVED_MAGIC: &[u8; 8] = b"ASCL2\0\0\0";
const DERIVED_HEADER: usize = 64;
/// Layout version of the L2 header, part of every L2 file name.
const DERIVED_FORMAT: u32 = 2;
const RENDERED_MAGIC: &[u8; 8] = b"ASCL3\0\0\0";
/// Layout version of L3 files, part of every L3 key.
const RENDERED_FORMAT: u32 = 2;
/// End of an L1 file, after the inflated bytes: this magic, then the
/// CRC-32 of those bytes. Readers map only the bytes before it.
const L1_MAGIC: &[u8; 4] = b"ASC1";
const L1_TRAILER: u64 = 8;

/// A derived index mapped from L2: the payload [`DiskCache::put_derived`]
/// stored, 64-byte aligned.
pub struct Derived {
    map: memmap2::Mmap,
    /// Rebuild cost recorded by the writer.
    pub build_cost: Duration,
}

impl Deref for Derived {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.map[DERIVED_HEADER..]
    }
}

impl AsRef<[u8]> for Derived {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

/// Per-tier usage reported by [`DiskCache::tier_stats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TierStats {
    /// APK keys with data in the tier.
    pub apks: usize,
    pub files: usize,
    pub bytes: u64,
}

/// One evictable unit: an L1 APK directory, or one L2 / L3 file.
struct Item {
    tier: Tier,
    key: String,
    path: PathBuf,
    mtime: SystemTime,
    files: usize,
    bytes: u64,
    /// Rebuild cost (L2 only).
    cost_us: u64,
}

/// How a [`DiskCache`] is bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskCapacity {
    /// Follow the free space of the cache's file system ([`auto_disk_bytes_for`]).
    Auto,
    /// A fixed number of bytes.
    Fixed(u64),
}

/// Upper bound of the automatic disk budget. Large enough for the inflated
/// DEX of a phone's worth of APKs (416 system and store APKs: 8.6 GB).
pub const AUTO_DISK_MAX: u64 = 32 << 30;
/// The automatic disk budget where the free space cannot be read.
pub const AUTO_DISK_UNKNOWN: u64 = 4 << 30;
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
/// giving [`AUTO_DISK_UNKNOWN`]).
///
/// [`AUTO_DISK_PERCENT`] of what the cache could occupy (its own bytes plus
/// the free space), at most [`AUTO_DISK_MAX`], and never more than leaves
/// [`auto_disk_reserve`] free. When the disk is already below the reserve,
/// that last bound falls under `used`, so eviction gives the shortfall back.
/// (No separate floor: with a reserve of at least 1 GiB, the reserve is
/// always the tighter bound on a disk too small for 20 % to reach 256 MiB.)
pub fn auto_disk_bytes_for(space: Option<(u64, u64)>, used: u64) -> u64 {
    let Some((free, total)) = space else { return AUTO_DISK_UNKNOWN };
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
    pub const DEFAULT_CAP: u64 = AUTO_DISK_UNKNOWN;

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
        let min_dex_bytes = match std::env::var(MIN_DEX_ENV).ok().and_then(|v| v.trim().parse::<u64>().ok()) {
            Some(mb) => mb.saturating_mul(1 << 20),
            None => DEFAULT_MIN_DEX_BYTES,
        };
        let tiers = match std::env::var(TIERS_ENV) {
            Ok(v) => Tier::ALL.map(|t| v.split(',').any(|n| n.trim() == t.name())),
            Err(_) => [true; 3],
        };
        DiskCache {
            dir: dir.into(),
            cap: DiskCapacity::from_env(),
            min_dex_bytes,
            min_derived_cost: DEFAULT_MIN_DERIVED_COST,
            tiers,
            written: Default::default(),
            boot: boot_time(),
        }
    }

    /// Use only `tiers`: reads of the others miss and writes to them are
    /// skipped. Entries already stored in them still count and are evicted.
    pub fn with_tiers(mut self, tiers: &[Tier]) -> DiskCache {
        self.tiers = Tier::ALL.map(|t| tiers.contains(&t));
        self
    }

    pub fn uses(&self, tier: Tier) -> bool {
        self.tiers[tier as usize]
    }

    /// Write inflated entries of at least `bytes` to L1 (0: all of them).
    pub fn with_min_dex_bytes(mut self, bytes: u64) -> DiskCache {
        self.min_dex_bytes = bytes;
        self
    }

    /// Smallest inflated entry worth writing to L1 ([`DEFAULT_MIN_DEX_BYTES`]
    /// unless [`MIN_DEX_ENV`] says otherwise). [`DiskCache::put`] itself
    /// writes whatever it is given; hosts ask [`DiskCache::admits_dex`] first.
    pub fn min_dex_bytes(&self) -> u64 {
        self.min_dex_bytes
    }

    pub fn admits_dex(&self, len: u64) -> bool {
        len >= self.min_dex_bytes
    }

    /// Write derived indexes that took at least `cost` to build to L2
    /// (default [`DEFAULT_MIN_DERIVED_COST`]; zero: all of them).
    pub fn with_min_derived_cost(mut self, cost: Duration) -> DiskCache {
        self.min_derived_cost = cost;
        self
    }

    /// Whether an index that took `cost` to build is worth an L2 file.
    /// Like [`DiskCache::admits_dex`], a policy for hosts to apply.
    pub fn admits_derived(&self, cost: Duration) -> bool {
        cost >= self.min_derived_cost
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

    /// Whether a cache file must be checked before use ([`predates_boot`]).
    fn predates_boot(&self, meta: &fs::Metadata) -> bool {
        predates_boot(meta.modified().ok(), self.boot, SystemTime::now())
    }

    /// Delete a damaged file; always a miss.
    fn discard<T>(&self, path: &Path) -> Option<T> {
        // A concurrent writer may have just renamed a sound file over it:
        // deleting that one only costs a rebuild.
        let _ = fs::remove_file(path);
        None
    }

    fn entry_path(&self, key: &ApkKey, entry_name: &str) -> PathBuf {
        self.dir.join(key.as_str()).join(safe_name(entry_name))
    }

    fn derived_path(&self, key: &ApkKey, name: &str, kind: &str, version: u32) -> PathBuf {
        let file = format!("{}~{}.v{DERIVED_FORMAT}.{version}", safe_name(name), safe_name(kind));
        self.dir.join(DERIVED_DIR).join(key.as_str()).join(file)
    }

    fn rendered_path(&self, key: &ApkKey, query: &str) -> PathBuf {
        self.dir.join(RENDERED_DIR).join(key.as_str()).join(format!("{:016x}", fnv64(query.as_bytes())))
    }

    /// Map a cached entry if present and of the expected size (0: any).
    /// A file from before the current boot is checked against its CRC-32
    /// first; a damaged one is deleted.
    pub fn get(&self, key: &ApkKey, entry_name: &str, expected_len: u64) -> Option<DexData> {
        if !self.uses(Tier::Dex) {
            return None;
        }
        let path = self.entry_path(key, entry_name);
        let file = fs::File::open(&path).ok()?;
        let meta = file.metadata().ok()?;
        let len = meta.len().checked_sub(L1_TRAILER).filter(|&l| l > 0)?;
        if expected_len != 0 && len != expected_len {
            return None;
        }
        let mut trailer = [0u8; L1_TRAILER as usize];
        (&file).seek(SeekFrom::Start(len)).ok()?;
        (&file).read_exact(&mut trailer).ok()?;
        // Not `populate`d: pre-faulting every entry of an APK costs more than
        // faulting in the pages a query reads (getclass reads one class).
        let map = map_prefix(&file, len)?;
        if &trailer[..4] != L1_MAGIC {
            return self.discard(&path);
        }
        if self.predates_boot(&meta) {
            if crc32fast::hash(&map) != u32::from_le_bytes(trailer[4..].try_into().expect("4 bytes")) {
                return self.discard(&path);
            }
            let _ = touch_file(&file);
        }
        // Touch the APK directory so LRU eviction sees recent use.
        let _ = touch_dir(path.parent()?);
        Some(DexData::Mapped(map))
    }

    /// Store an inflated entry (atomic rename; concurrent writers are
    /// harmless). Does not evict: call [`DiskCache::evict`] after a batch of
    /// puts.
    pub fn put(&self, key: &ApkKey, entry_name: &str, bytes: &[u8]) -> Result<(), CacheError> {
        if !self.uses(Tier::Dex) {
            return Ok(());
        }
        let mut trailer = [0u8; L1_TRAILER as usize];
        trailer[..4].copy_from_slice(L1_MAGIC);
        trailer[4..].copy_from_slice(&crc32fast::hash(bytes).to_le_bytes());
        self.write_atomic(&self.entry_path(key, entry_name), &[bytes, &trailer])
    }

    /// Map the L2 index `name` (e.g. a logical DEX name) of `kind` at the
    /// producer's format `version`, as [`DiskCache::put_derived`] stored it.
    /// A file of another version, a damaged header or a truncated payload
    /// is a miss.
    pub fn get_derived(&self, key: &ApkKey, name: &str, kind: &str, version: u32) -> Option<Derived> {
        if !self.uses(Tier::Derived) {
            return None;
        }
        let path = self.derived_path(key, name, kind, version);
        let file = fs::File::open(&path).ok()?;
        let meta = file.metadata().ok()?;
        let map = map_file(&file)?;
        let header = map.get(..DERIVED_HEADER)?;
        let u32_at = |o: usize| u32::from_le_bytes(header[o..o + 4].try_into().expect("4 bytes"));
        let u64_at = |o: usize| u64::from_le_bytes(header[o..o + 8].try_into().expect("8 bytes"));
        if &header[..8] != DERIVED_MAGIC
            || u32_at(8) != DERIVED_FORMAT
            || u32_at(12) != version
            || u64_at(24) != (map.len() - DERIVED_HEADER) as u64
        {
            return None;
        }
        if self.predates_boot(&meta) && crc32fast::hash(&map[DERIVED_HEADER..]) != u32_at(32) {
            return self.discard(&path);
        }
        let _ = touch_file(&file);
        Some(Derived { build_cost: Duration::from_micros(u64_at(16)), map })
    }

    /// Store an L2 index (see [`DiskCache::get_derived`]). `build_cost` is
    /// what rebuilding it takes: eviction keeps the indexes that save the
    /// most time per byte.
    pub fn put_derived(
        &self,
        key: &ApkKey,
        name: &str,
        kind: &str,
        version: u32,
        build_cost: Duration,
        payload: &[u8],
    ) -> Result<(), CacheError> {
        if !self.uses(Tier::Derived) {
            return Ok(());
        }
        let mut header = [0u8; DERIVED_HEADER];
        header[..8].copy_from_slice(DERIVED_MAGIC);
        header[8..12].copy_from_slice(&DERIVED_FORMAT.to_le_bytes());
        header[12..16].copy_from_slice(&version.to_le_bytes());
        header[16..24].copy_from_slice(&(build_cost.as_micros() as u64).to_le_bytes());
        header[24..32].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        header[32..36].copy_from_slice(&crc32fast::hash(payload).to_le_bytes());
        self.write_atomic(&self.derived_path(key, name, kind, version), &[&header, payload])
    }

    /// The L3 result stored under `query` (the query, its options and the
    /// producer's version: build it with [`rendered_key`]).
    pub fn get_rendered(&self, key: &ApkKey, query: &str) -> Option<Vec<u8>> {
        if !self.uses(Tier::Rendered) {
            return None;
        }
        let path = self.rendered_path(key, query);
        let mut data = fs::read(&path).ok()?;
        let key_len = u32::from_le_bytes(data.get(8..12)?.try_into().ok()?) as usize;
        let crc = u32::from_le_bytes(data.get(12..16)?.try_into().ok()?);
        let body = 16usize.checked_add(key_len)?;
        if data.get(..8)? != RENDERED_MAGIC || crc32fast::hash(&data[16..]) != crc {
            return self.discard(&path);
        }
        // The full key is stored and compared, so a hash collision is a miss.
        if data.get(16..body)? != query.as_bytes() {
            return None;
        }
        if let Ok(f) = fs::File::open(&path) {
            let _ = touch_file(&f);
        }
        data.drain(..body);
        Some(data)
    }

    /// Store an L3 result (see [`DiskCache::get_rendered`]).
    pub fn put_rendered(&self, key: &ApkKey, query: &str, payload: &[u8]) -> Result<(), CacheError> {
        if !self.uses(Tier::Rendered) {
            return Ok(());
        }
        let mut crc = crc32fast::Hasher::new();
        crc.update(query.as_bytes());
        crc.update(payload);
        let mut header = Vec::with_capacity(16 + query.len());
        header.extend_from_slice(RENDERED_MAGIC);
        header.extend_from_slice(&(query.len() as u32).to_le_bytes());
        header.extend_from_slice(&crc.finalize().to_le_bytes());
        header.extend_from_slice(query.as_bytes());
        self.write_atomic(&self.rendered_path(key, query), &[&header, payload])
    }

    /// Record where the APK of `key` lives, so eviction can tell the entries
    /// of an APK deleted or replaced since (evicted first) from live ones.
    /// Cheap to repeat; hosts call it once per APK.
    pub fn note_source(&self, key: &ApkKey, apk_path: &Path) -> Result<(), CacheError> {
        let path = self.dir.join(SOURCES_DIR).join(key.as_str());
        let Some(stamp) = source_stamp(apk_path) else { return Ok(()) };
        if fs::read_to_string(&path).is_ok_and(|s| s == stamp) {
            return Ok(());
        }
        self.write_atomic(&path, &[stamp.as_bytes()])
    }

    /// Write `parts` to `path` (atomic rename; concurrent writers are
    /// harmless), refusing foreign directories and the free-space reserve.
    /// Not synced: a file a crash damages fails its checksum on read (see
    /// the module documentation).
    fn write_atomic(&self, path: &Path, parts: &[&[u8]]) -> Result<(), CacheError> {
        // Checked before anything is created: the tag must never land in a
        // directory that holds someone else's files.
        if !self.is_cache_dir() {
            return Err(self.not_a_cache_dir());
        }
        let len: u64 = parts.iter().map(|p| p.len() as u64).sum();
        // One statvfs per write: with the automatic budget, never write into
        // the reserve the file system needs (another program may have filled
        // the disk since the last eviction).
        if self.cap == DiskCapacity::Auto {
            if let Some((free, total)) = disk_space(&self.dir) {
                if free.saturating_sub(len) < auto_disk_reserve(total) {
                    return Err(CacheError::LowDiskSpace { path: self.dir.clone(), bytes: len });
                }
            }
        }
        let parent = path.parent().expect("cache path has a parent");
        fs::create_dir_all(parent).map_err(io_err(parent))?;
        // Best effort: an unwritable root (shared cache, full disk) must not
        // stop entries from being written into their own directories.
        let _ = self.ensure_tag();
        let tmp = parent.join(format!(".{}.{}.tmp", path.file_name().unwrap_or_default().to_string_lossy(), std::process::id()));
        {
            let mut f = fs::File::create(&tmp).map_err(io_err(&tmp))?;
            for p in parts {
                f.write_all(p).map_err(io_err(&tmp))?;
            }
        }
        fs::rename(&tmp, path).map_err(io_err(path))?;
        self.written.fetch_add(len, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// `(APKs, files, bytes)` currently stored, over every tier (an APK
    /// with data in several tiers counts once).
    pub fn stats(&self) -> (usize, usize, u64) {
        let items = self.items();
        let keys: HashSet<&str> = items.iter().map(|i| i.key.as_str()).collect();
        (keys.len(), items.iter().map(|i| i.files).sum(), items.iter().map(|i| i.bytes).sum())
    }

    /// Usage of each tier, in [`Tier::ALL`] order.
    pub fn tier_stats(&self) -> [TierStats; 3] {
        let items = self.items();
        Tier::ALL.map(|tier| {
            let of_tier = || items.iter().filter(move |i| i.tier == tier);
            let keys: HashSet<&str> = of_tier().map(|i| i.key.as_str()).collect();
            TierStats { apks: keys.len(), files: of_tier().map(|i| i.files).sum(), bytes: of_tier().map(|i| i.bytes).sum() }
        })
    }

    /// Delete every cached entry of every tier (and nothing else). Returns
    /// the number of bytes freed. Refuses to run on a directory that is not
    /// a cache directory (see [`CACHEDIR_TAG`]).
    pub fn clear(&self) -> Result<u64, CacheError> {
        if !self.dir.exists() {
            return Ok(0);
        }
        if !self.is_cache_dir() {
            return Err(self.not_a_cache_dir());
        }
        let mut bytes = 0;
        for item in self.items() {
            remove_item(&item).map_err(io_err(&item.path))?;
            bytes += item.bytes;
        }
        for sub in [DERIVED_DIR, RENDERED_DIR, SOURCES_DIR, SPILL_DIR] {
            let path = self.dir.join(sub);
            if path.is_dir() {
                fs::remove_dir_all(&path).map_err(io_err(&path))?;
            }
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
                    Ok(t) if t.is_dir() => is_cache_dir_name(&name) || TIER_DIRS.contains(&&*name) || name == SPILL_DIR,
                    Ok(t) if t.is_file() => name == ".DS_Store" || name == EVICT_MARKER,
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
        apk_dirs_in(&self.dir)
    }

    /// Every evictable unit of every tier.
    fn items(&self) -> Vec<Item> {
        let mut out: Vec<Item> = self
            .apk_dirs()
            .into_iter()
            .map(|(mtime, path, files, bytes)| Item {
                tier: Tier::Dex,
                key: path.file_name().unwrap_or_default().to_string_lossy().into_owned(),
                path,
                mtime,
                files,
                bytes,
                cost_us: 0,
            })
            .collect();
        for (tier, sub) in [(Tier::Derived, DERIVED_DIR), (Tier::Rendered, RENDERED_DIR)] {
            for (_, dir, _, _) in apk_dirs_in(&self.dir.join(sub)) {
                let key = dir.file_name().unwrap_or_default().to_string_lossy().into_owned();
                let Ok(rd) = fs::read_dir(&dir) else { continue };
                for f in rd.flatten() {
                    let Ok(m) = f.metadata() else { continue };
                    if !m.is_file() || f.file_name().to_string_lossy().ends_with(".tmp") {
                        continue;
                    }
                    let cost_us = if tier == Tier::Derived { derived_cost_us(&f.path()) } else { 0 };
                    let mtime = m.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                    out.push(Item { tier, key: key.clone(), path: f.path(), mtime, files: 1, bytes: m.len(), cost_us });
                }
            }
        }
        out
    }

    /// APK keys whose recorded source ([`DiskCache::note_source`]) is gone
    /// or has changed since.
    fn dead_keys(&self) -> HashSet<String> {
        let mut out = HashSet::new();
        let Ok(rd) = fs::read_dir(self.dir.join(SOURCES_DIR)) else { return out };
        for f in rd.flatten() {
            let Ok(stamp) = fs::read_to_string(f.path()) else { continue };
            let Some(path) = stamp.lines().nth(2) else { continue };
            if source_stamp(Path::new(path)).as_deref() != Some(stamp.as_str()) {
                out.insert(f.file_name().to_string_lossy().into_owned());
            }
        }
        out
    }
}

/// `(mtime, path, file count, bytes)` per APK directory directly under
/// `root` (subdirectories whose name matches [`is_cache_dir_name`]; anything
/// else is ignored); also removes temporary files left behind by a killed
/// writer.
fn apk_dirs_in(root: &Path) -> Vec<(SystemTime, PathBuf, usize, u64)> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(root) else { return out };
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

impl DiskCache {
    /// Evict until under capacity ([`DiskCache::capacity_for`],
    /// re-evaluated against the current free space). Does nothing in a
    /// directory that is not a cache directory (see [`CACHEDIR_TAG`]).
    ///
    /// L3 is first trimmed to its own budget (the smaller of
    /// [`RENDERED_MAX`] and 1/[`RENDERED_BUDGET_DIVISOR`] of the total) and
    /// L2 to 1/[`DERIVED_BUDGET_DIVISOR`]. Over the total, entries of APKs
    /// that are gone ([`DiskCache::note_source`]) go first, then L1 (the
    /// largest, least recently used APK directories first), then L3 (least
    /// recently used first), then L2 (least rebuild time saved per byte
    /// first, discounted by age).
    pub fn evict(&self) {
        if !self.is_cache_dir() {
            return;
        }
        self.written.store(0, std::sync::atomic::Ordering::Relaxed);
        let _ = fs::File::create(self.dir.join(EVICT_MARKER));
        let items = self.items();
        let mut total: u64 = items.iter().map(|i| i.bytes).sum();
        let cap = self.capacity_for(total);
        let caps = [cap, cap / DERIVED_BUDGET_DIVISOR, (cap / RENDERED_BUDGET_DIVISOR).min(RENDERED_MAX)];
        let mut tier_used = [0u64; 3];
        for i in &items {
            tier_used[i.tier as usize] += i.bytes;
        }
        if total > cap || tier_used[1] > caps[1] || tier_used[2] > caps[2] {
            let order = eviction_order(&items, &self.dead_keys());
            let mut gone = vec![false; items.len()];
            let mut remove = |idx: usize, total: &mut u64, tier_used: &mut [u64; 3]| {
                if !gone[idx] && remove_item(&items[idx]).is_ok() {
                    gone[idx] = true;
                    *total = total.saturating_sub(items[idx].bytes);
                    let t = items[idx].tier as usize;
                    tier_used[t] = tier_used[t].saturating_sub(items[idx].bytes);
                }
            };
            // The per-tier budgets of L3 and L2, each in its own order.
            for tier in [Tier::Rendered, Tier::Derived] {
                for &idx in order.iter().filter(|&&i| items[i].tier == tier) {
                    if tier_used[tier as usize] <= caps[tier as usize] {
                        break;
                    }
                    remove(idx, &mut total, &mut tier_used);
                }
            }
            for &idx in &order {
                if total <= cap {
                    break;
                }
                remove(idx, &mut total, &mut tier_used);
            }
        }
        // Drop the source records of keys with nothing left.
        if let Ok(rd) = fs::read_dir(self.dir.join(SOURCES_DIR)) {
            let live: HashSet<String> = self.items().into_iter().map(|i| i.key).collect();
            for f in rd.flatten() {
                if !live.contains(&*f.file_name().to_string_lossy()) {
                    let _ = fs::remove_file(f.path());
                }
            }
        }
    }
}

impl DiskCache {
    /// [`DiskCache::evict`], skipped when another walk happened less than
    /// [`EVICT_INTERVAL`] ago and this handle has written less than
    /// 1/[`EVICT_WRITE_DIVISOR`] of the budget since its own last walk. For
    /// hosts that evict after every burst of writes: a process per query
    /// would otherwise walk the whole cache thousands of times over a batch.
    pub fn evict_lazily(&self) {
        if !self.recently_evicted() {
            self.evict();
        }
    }

    /// Whether a walk can be skipped: some process walked the cache less
    /// than [`EVICT_INTERVAL`] ago and this handle has written less than
    /// 1/[`EVICT_WRITE_DIVISOR`] of the budget since its own last walk. A
    /// walk reads every file's metadata (and every L2 header), which a
    /// process per query would otherwise repeat thousands of times over a
    /// batch; the overshoot is bounded, and every automatic-budget write
    /// still checks the free-space reserve.
    fn recently_evicted(&self) -> bool {
        let written = self.written.load(std::sync::atomic::Ordering::Relaxed);
        let fresh = fs::metadata(self.dir.join(EVICT_MARKER))
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| SystemTime::now().duration_since(t).ok())
            .is_some_and(|age| age < EVICT_INTERVAL);
        fresh && written < self.capacity_for(0) / EVICT_WRITE_DIVISOR
    }
}

/// Touched by every eviction walk; see [`DiskCache::evict`].
const EVICT_MARKER: &str = ".last-evict";
const EVICT_INTERVAL: Duration = Duration::from_secs(5);
const EVICT_WRITE_DIVISOR: u64 = 16;

/// Indexes of `items` in eviction order: entries of dead APKs first
/// (largest first), then L1 by `age × size` (descending), then L3 by age
/// (descending), then L2 by `rebuild µs / byte / (1 + age in hours)`
/// (ascending). Ages count from the newest item (plus one second), so clock
/// skew between writers cannot invert the order; ties go oldest first.
fn eviction_order(items: &[Item], dead: &HashSet<String>) -> Vec<usize> {
    let newest = items.iter().map(|i| i.mtime).max().unwrap_or(SystemTime::UNIX_EPOCH);
    let age_secs = |i: &Item| newest.duration_since(i.mtime).unwrap_or_default().as_secs_f64() + 1.0;
    let score = |i: &Item| -> (u8, f64) {
        if dead.contains(&i.key) {
            return (0, -(i.bytes as f64));
        }
        match i.tier {
            Tier::Dex => (1, -(age_secs(i) * i.bytes as f64)),
            Tier::Rendered => (2, -age_secs(i)),
            Tier::Derived => (3, i.cost_us as f64 / i.bytes.max(1) as f64 / (1.0 + age_secs(i) / 3600.0)),
        }
    };
    let mut order: Vec<usize> = (0..items.len()).collect();
    order.sort_by(|&a, &b| {
        let (sa, sb) = (score(&items[a]), score(&items[b]));
        sa.0.cmp(&sb.0).then(sa.1.total_cmp(&sb.1)).then(items[a].mtime.cmp(&items[b].mtime))
    });
    order
}

fn remove_item(item: &Item) -> std::io::Result<()> {
    match item.tier {
        Tier::Dex => fs::remove_dir_all(&item.path),
        _ => fs::remove_file(&item.path),
    }
}

/// Subdirectories of the cache root that belong to it besides APK directories.
const TIER_DIRS: [&str; 3] = [DERIVED_DIR, RENDERED_DIR, SOURCES_DIR];

/// `name` with every character a cache file name may not hold replaced.
fn safe_name(name: &str) -> String {
    name.chars().map(|c| if is_key_char(c) { c } else { '_' }).collect()
}

/// The key an L3 result is stored under: the producer (e.g. `findrefs`)
/// and its version, the L3 layout version and the query, so a tool upgrade
/// never serves output of the old one.
pub fn rendered_key(producer: &str, version: &str, query: &str) -> String {
    format!("{producer}\0{version}\0{RENDERED_FORMAT}\0{query}")
}

/// Read-only mapping of a cache file.
fn map_file(file: &fs::File) -> Option<memmap2::Mmap> {
    // SAFETY: read-only mapping of a file renamed into place atomically; a
    // concurrent overwrite replaces the directory entry, not the mapped inode.
    unsafe { memmap2::MmapOptions::new().map(file) }.ok()
}

/// The first `len` bytes of `file`, mapped as [`map_file`] does.
fn map_prefix(file: &fs::File, len: u64) -> Option<memmap2::Mmap> {
    let len = usize::try_from(len).ok()?;
    // SAFETY: as in `map_file`; the caller checked `len` against the file.
    unsafe { memmap2::MmapOptions::new().len(len).map(file) }.ok()
}

/// Whether a file last modified at `mtime` may predate the current boot,
/// and so may hold pages a crash kept from reaching the disk. Unknown
/// times count as old, and so does a time in the future (a clock moved
/// back since): checking a sound file costs one read, trusting a damaged
/// one a wrong answer.
fn predates_boot(mtime: Option<SystemTime>, boot: Option<SystemTime>, now: SystemTime) -> bool {
    match (mtime, boot) {
        (Some(m), Some(b)) => m < b || m > now,
        _ => true,
    }
}

/// When the system booted, read once per process.
fn boot_time() -> Option<SystemTime> {
    static BOOT: OnceLock<Option<SystemTime>> = OnceLock::new();
    *BOOT.get_or_init(read_boot_time)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_boot_time() -> Option<SystemTime> {
    let stat = fs::read_to_string("/proc/stat").ok()?;
    let secs = stat.lines().find_map(|l| l.strip_prefix("btime "))?.trim().parse().ok()?;
    Some(UNIX_EPOCH + Duration::from_secs(secs))
}

#[cfg(target_vendor = "apple")]
fn read_boot_time() -> Option<SystemTime> {
    let mut tv = libc::timeval { tv_sec: 0, tv_usec: 0 };
    let mut len = std::mem::size_of::<libc::timeval>();
    // SAFETY: `kern.boottime` is a `struct timeval`; the kernel writes at most
    // `len` bytes into `tv` and sets `len` to what it wrote.
    let rc = unsafe { libc::sysctlbyname(c"kern.boottime".as_ptr(), (&raw mut tv).cast(), &mut len, std::ptr::null_mut(), 0) };
    if rc != 0 || len != std::mem::size_of::<libc::timeval>() {
        return None;
    }
    Some(UNIX_EPOCH + Duration::from_secs(u64::try_from(tv.tv_sec).ok()?) + Duration::from_micros(u64::try_from(tv.tv_usec).ok()?))
}

#[cfg(not(any(target_os = "linux", target_os = "android", target_vendor = "apple")))]
fn read_boot_time() -> Option<SystemTime> {
    None
}

/// Rebuild cost recorded in an L2 file's header (0 when unreadable).
fn derived_cost_us(path: &Path) -> u64 {
    use std::io::Read;
    let mut header = [0u8; 24];
    match fs::File::open(path).and_then(|mut f| f.read_exact(&mut header)) {
        Ok(()) if &header[..8] == DERIVED_MAGIC => u64::from_le_bytes(header[16..24].try_into().expect("8 bytes")),
        _ => 0,
    }
}

/// `size\nmtime\npath` of an APK, as [`DiskCache::note_source`] records it.
fn source_stamp(apk: &Path) -> Option<String> {
    let abs = fs::canonicalize(apk).ok()?;
    let meta = fs::metadata(&abs).ok()?;
    let mtime = meta.modified().ok()?.duration_since(SystemTime::UNIX_EPOCH).ok()?.as_nanos();
    let path = abs.to_str()?;
    (!path.contains('\n')).then(|| format!("{}\n{mtime}\n{path}", meta.len()))
}

fn touch_file(file: &fs::File) -> std::io::Result<()> {
    file.set_modified(SystemTime::now())
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
    /// Bytes the host holds elsewhere against the same capacity.
    reserved: usize,
    clock: u64,
    map: HashMap<ApkKey, HashMap<String, Slot<T>>>,
}

impl<T> MemoryCache<T> {
    pub fn new(cap_bytes: usize) -> Self {
        MemoryCache { cap_bytes, used: 0, reserved: 0, clock: 0, map: HashMap::new() }
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
        while self.used + self.reserved > self.cap_bytes && self.len() > 1 {
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

    pub fn capacity_bytes(&self) -> usize {
        self.cap_bytes
    }

    /// Bytes counted against the capacity besides the entries
    /// ([`MemoryCache::set_reserved`]).
    pub fn reserved_bytes(&self) -> usize {
        self.reserved
    }

    /// Count `bytes` the host holds elsewhere against the capacity, evicting
    /// least recently used entries to make room.
    pub fn set_reserved(&mut self, bytes: usize) {
        self.reserved = bytes;
        self.evict_over_cap();
    }

    /// Change the capacity, evicting least recently used entries if the
    /// cache now holds more.
    pub fn set_capacity(&mut self, cap_bytes: usize) {
        self.cap_bytes = cap_bytes;
        self.evict_over_cap();
    }

    /// The entry cached under `entry_name`, without touching its recency.
    pub fn peek(&self, key: &ApkKey, entry_name: &str) -> Option<Arc<T>> {
        self.map.get(key)?.get(entry_name).map(|s| Arc::clone(&s.value))
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
    fn regions_of_a_file_map_at_any_offset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("app.apk");
        let bytes: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        fs::write(&path, &bytes).unwrap();
        for (off, len) in [(0, 10), (4097, 3000), (12_345, 7655), (19_999, 1)] {
            let d = DexData::map_region(&path, off as u64, len).unwrap();
            assert!(matches!(d, DexData::Mapped(_)));
            assert_eq!(&*d, &bytes[off..off + len]);
        }
        assert!(DexData::map_region(&path, 19_999, 2).is_err());
        assert!(DexData::map_region(&dir.path().join("missing"), 0, 1).is_err());
    }

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
        assert_eq!((dirs, files, bytes), (1, 1, 3 + L1_TRAILER));
        assert_eq!(cache.clear().unwrap(), 3 + L1_TRAILER);
        assert!(cache.get(&key, "classes.dex", 3).is_none());
    }

    #[test]
    fn disk_evicts_least_recently_used_apk() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::open(dir.path()).with_capacity(20);
        let old = ApkKey("old-0000000000000001".into());
        let new = ApkKey("new-0000000000000002".into());
        cache.put(&old, "classes.dex", &[0; 6]).unwrap();
        // Make sure the second directory is strictly newer.
        let later = SystemTime::now() + Duration::from_secs(5);
        cache.put(&new, "classes.dex", &[0; 6]).unwrap();
        fs::File::open(dir.path().join("new-0000000000000002")).unwrap().set_modified(later).unwrap();
        assert_eq!(cache.stats(), (2, 2, 2 * (6 + L1_TRAILER)));
        cache.evict();
        assert_eq!(cache.stats(), (1, 1, 6 + L1_TRAILER));
        assert!(cache.get(&new, "classes.dex", 6).is_some());
        assert!(cache.get(&old, "classes.dex", 6).is_none());
    }

    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;

    #[test]
    fn auto_disk_budget_follows_free_space() {
        // Unknown file system (Windows): the old fixed cap.
        assert_eq!(auto_disk_bytes_for(None, 0), AUTO_DISK_UNKNOWN);
        // Large disk: capped at 32 GiB.
        assert_eq!(auto_disk_bytes_for(Some((500 * GIB, 1000 * GIB)), 0), AUTO_DISK_MAX);
        // 100 GiB free: 20 GiB, past the old 4 GiB cap.
        assert_eq!(auto_disk_bytes_for(Some((100 * GIB, 500 * GIB)), 0), 100 * GIB / 100 * 20);
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
        // Compare against the space the budget itself measured: other tests write to the
        // same file system concurrently, so a second `disk_space` call may differ.
        let ab = auto.budget();
        assert_eq!(ab.cap_bytes, auto_disk_bytes_for(ab.space, ab.used));
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
        assert_eq!(cache.stats(), (3, 3, 3 * (10 + L1_TRAILER)));
        // Same directory, smaller budget (as when the free space drops): the
        // next eviction pass trims to it, oldest first.
        let cache = cache.with_capacity(25);
        cache.evict();
        assert_eq!(cache.stats(), (1, 1, 10 + L1_TRAILER));
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
        assert_eq!(cache.stats(), (1, 1, 8 + L1_TRAILER));
        cache.evict();
        assert!(thesis.join("chapter1.txt").is_file());
        assert!(cache.get(&key, "classes.dex", 8).is_none());
        cache.put(&key, "classes.dex", &[0; 8]).unwrap();
        assert_eq!(cache.clear().unwrap(), 8 + L1_TRAILER);
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
    fn a_directory_holding_only_spilled_replies_is_still_a_cache() {
        // The MCP server may spill a reply before the first DEX is cached.
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join(SPILL_DIR)).unwrap();
        fs::write(dir.path().join(SPILL_DIR).join("ab.txt"), b"reply").unwrap();
        let cache = DiskCache::open(dir.path());
        assert!(cache.check_usable().is_ok());
        cache.put(&ApkKey("app-0123456789abcdef".into()), "classes.dex", &[0; 4]).unwrap();
        cache.clear().unwrap();
        assert!(!dir.path().join(SPILL_DIR).exists(), "clear removes spilled replies too");
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
    fn memory_lru_capacity_can_shrink_and_peek_keeps_recency() {
        let mut m: MemoryCache<u8> = MemoryCache::new(10);
        let k = ApkKey("k".into());
        m.insert(&k, "a", Arc::new(1), 4);
        m.insert(&k, "b", Arc::new(2), 4);
        assert_eq!(*m.peek(&k, "a").unwrap(), 1); // a stays least recently used
        m.set_capacity(5);
        assert_eq!((m.capacity_bytes(), m.used_bytes()), (5, 4));
        assert!(m.peek(&k, "a").is_none());
        assert!(m.peek(&k, "b").is_some());
    }

    #[test]
    fn memory_lru_reserved_bytes_make_room_under_the_cap() {
        let mut m: MemoryCache<u8> = MemoryCache::new(10);
        let k = ApkKey("k".into());
        m.insert(&k, "a", Arc::new(1), 4);
        m.insert(&k, "b", Arc::new(2), 4);
        m.set_reserved(3);
        assert_eq!((m.used_bytes(), m.reserved_bytes()), (4, 3), "a evicted to fit 3 reserved bytes");
        assert!(m.peek(&k, "a").is_none());
        m.insert(&k, "c", Arc::new(3), 3);
        assert_eq!(m.used_bytes(), 7);
        m.set_reserved(0);
        m.insert(&k, "d", Arc::new(4), 3);
        assert_eq!(m.used_bytes(), 10, "nothing reserved: the whole cap holds entries");
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

    fn set_mtime(path: &Path, secs_from_now: i64) {
        let t = if secs_from_now >= 0 {
            SystemTime::now() + Duration::from_secs(secs_from_now as u64)
        } else {
            SystemTime::now() - Duration::from_secs((-secs_from_now) as u64)
        };
        fs::File::open(path).unwrap().set_modified(t).unwrap();
    }

    #[test]
    fn files_are_checked_when_they_predate_the_boot() {
        let now = SystemTime::now();
        let boot = Some(now - Duration::from_secs(60));
        assert!(predates_boot(Some(now - Duration::from_secs(61)), boot, now));
        assert!(!predates_boot(Some(now - Duration::from_secs(59)), boot, now));
        // A clock moved back, an unknown boot or mtime: checked.
        assert!(predates_boot(Some(now + Duration::from_secs(5)), boot, now));
        assert!(predates_boot(Some(now), None, now));
        assert!(predates_boot(None, boot, now));
    }

    /// A cache whose system booted a minute ago.
    fn booted_cache(dir: &Path) -> DiskCache {
        let mut cache = DiskCache::open(dir).with_capacity(1 << 20);
        cache.boot = Some(SystemTime::now() - Duration::from_secs(60));
        cache
    }

    /// Overwrite `damage` (offset, bytes) and cut the file to `cut`, then
    /// make it look written before the boot of [`booted_cache`].
    fn age(path: &Path, damage: Option<(u64, &[u8])>, cut: Option<u64>) {
        let f = fs::OpenOptions::new().write(true).open(path).unwrap();
        if let Some((at, bytes)) = damage {
            (&f).seek(SeekFrom::Start(at)).unwrap();
            (&f).write_all(bytes).unwrap();
        }
        if let Some(len) = cut {
            f.set_len(len).unwrap();
        }
        f.set_modified(SystemTime::now() - Duration::from_secs(120)).unwrap();
    }

    #[test]
    fn l1_files_from_an_earlier_boot_are_checked() {
        let dir = tempfile::tempdir().unwrap();
        let cache = booted_cache(dir.path());
        let key = ApkKey("app-0123456789abcdef".into());
        let data: Vec<u8> = (0..4096u32).map(|i| i as u8).collect();
        let path = cache.entry_path(&key, "classes.dex");
        let n = data.len() as u64;

        // Sound: served, and marked checked for this boot.
        cache.put(&key, "classes.dex", &data).unwrap();
        age(&path, None, None);
        assert_eq!(&*cache.get(&key, "classes.dex", n).unwrap(), &data[..]);
        assert!(!cache.predates_boot(&fs::metadata(&path).unwrap()));

        // Zeroed pages, a flipped byte: deleted and missed.
        let flipped = [!data[7]];
        for (at, bytes) in [(1024, &[0u8; 1024][..]), (7, &flipped[..])] {
            cache.put(&key, "classes.dex", &data).unwrap();
            age(&path, Some((at, bytes)), None);
            assert!(cache.get(&key, "classes.dex", n).is_none(), "damage at {at}");
            assert!(!path.exists(), "damage at {at}");
        }
        // Cut short (looked up without a declared size, so the length alone
        // cannot tell): the trailer is gone.
        for cut in [n, n - 100] {
            cache.put(&key, "classes.dex", &data).unwrap();
            age(&path, None, Some(cut));
            assert!(cache.get(&key, "classes.dex", 0).is_none(), "cut to {cut}");
            assert!(!path.exists(), "cut to {cut}");
        }

        // Written during this boot: trusted without a check.
        cache.put(&key, "classes.dex", &data).unwrap();
        let f = fs::OpenOptions::new().write(true).open(&path).unwrap();
        (&f).write_all(&[!data[0]]).unwrap();
        f.set_modified(SystemTime::now()).unwrap();
        assert_eq!(cache.get(&key, "classes.dex", n).unwrap()[0], !data[0]);
    }

    #[test]
    fn l2_and_l3_files_carry_checksums() {
        let dir = tempfile::tempdir().unwrap();
        let cache = booted_cache(dir.path());
        let key = ApkKey("app-0123456789abcdef".into());
        let path = cache.derived_path(&key, "classes.dex", "locators", 1);
        let flip = DERIVED_HEADER as u64 + 3;
        cache.put_derived(&key, "classes.dex", "locators", 1, Duration::from_millis(7), b"tables").unwrap();
        age(&path, None, None);
        assert_eq!(&*cache.get_derived(&key, "classes.dex", "locators", 1).unwrap(), b"tables");
        age(&path, Some((flip, b"X")), None);
        assert!(cache.get_derived(&key, "classes.dex", "locators", 1).is_none());
        assert!(!path.exists());

        // L3 is checked on every read.
        cache.put_rendered(&key, "q", b"rows").unwrap();
        assert_eq!(cache.get_rendered(&key, "q").unwrap(), b"rows");
        let path = cache.rendered_path(&key, "q");
        let len = fs::metadata(&path).unwrap().len();
        let f = fs::OpenOptions::new().write(true).open(&path).unwrap();
        (&f).seek(SeekFrom::Start(len - 1)).unwrap();
        (&f).write_all(b"X").unwrap();
        assert!(cache.get_rendered(&key, "q").is_none());
        assert!(!path.exists());
    }

    #[test]
    fn derived_roundtrip_is_versioned_and_aligned() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::open(dir.path()).with_capacity(1 << 20);
        let key = ApkKey("app-0123456789abcdef".into());
        assert!(cache.get_derived(&key, "classes.dex", "locators", 1).is_none());
        cache.put_derived(&key, "classes.dex", "locators", 1, Duration::from_millis(7), b"tables").unwrap();
        let d = cache.get_derived(&key, "classes.dex", "locators", 1).unwrap();
        assert_eq!(&*d, b"tables");
        assert_eq!(d.build_cost, Duration::from_millis(7));
        assert_eq!(d.as_ptr() as usize % 64, 0, "payload as aligned as the mapping");
        // Another producer version, kind or name is another file.
        assert!(cache.get_derived(&key, "classes.dex", "locators", 2).is_none());
        assert!(cache.get_derived(&key, "classes.dex", "callgraph", 1).is_none());
        assert!(cache.get_derived(&key, "classes2.dex", "locators", 1).is_none());
        // A truncated file is a miss.
        let path = cache.derived_path(&key, "classes.dex", "locators", 1);
        let full = fs::read(&path).unwrap();
        fs::write(&path, &full[..full.len() - 1]).unwrap();
        assert!(cache.get_derived(&key, "classes.dex", "locators", 1).is_none());
        fs::write(&path, &full[..10]).unwrap();
        assert!(cache.get_derived(&key, "classes.dex", "locators", 1).is_none());
        let [l1, l2, l3] = cache.tier_stats();
        assert_eq!((l1.files, l2.files, l3.files), (0, 1, 0));
    }

    #[test]
    fn rendered_results_are_keyed_by_the_full_query() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::open(dir.path()).with_capacity(1 << 20);
        let key = ApkKey("app-0123456789abcdef".into());
        let q = rendered_key("findrefs", "1.0", "string\0token");
        assert!(cache.get_rendered(&key, &q).is_none());
        cache.put_rendered(&key, &q, b"rows").unwrap();
        assert_eq!(cache.get_rendered(&key, &q).unwrap(), b"rows");
        assert!(cache.get_rendered(&key, &rendered_key("findrefs", "1.1", "string\0token")).is_none(), "tool upgrade");
        // A file found under another query's hash (a collision) is a miss.
        let other = rendered_key("findrefs", "1.0", "string\0other");
        fs::rename(cache.rendered_path(&key, &q), cache.rendered_path(&key, &other)).unwrap();
        assert!(cache.get_rendered(&key, &other).is_none());
    }

    #[test]
    fn stats_and_clear_cover_every_tier() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::open(dir.path()).with_capacity(1 << 20);
        let (a, b) = (ApkKey("a-0123456789abcdef".into()), ApkKey("b-0123456789abcdef".into()));
        cache.put(&a, "classes.dex", &[0; 10]).unwrap();
        cache.put_derived(&a, "classes.dex", "locators", 1, Duration::ZERO, &[0; 6]).unwrap();
        cache.put_rendered(&b, "q", &[0; 3]).unwrap();
        let (apks, files, bytes) = cache.stats();
        assert_eq!((apks, files), (2, 3));
        assert_eq!(bytes, (10 + L1_TRAILER) + (64 + 6) + (16 + 1 + 3));
        let [l1, l2, l3] = cache.tier_stats();
        assert_eq!((l1.apks, l2.apks, l3.apks), (1, 1, 1));
        // A cache with tier directories but no tag (lost) is still ours.
        fs::remove_file(dir.path().join(CACHEDIR_TAG)).unwrap();
        assert!(cache.check_usable().is_ok());
        assert_eq!(cache.clear().unwrap(), bytes);
        assert_eq!(cache.stats(), (0, 0, 0));
        assert!(!dir.path().join("derived").exists() && !dir.path().join("rendered").exists());
    }

    #[test]
    fn disabled_tiers_miss_and_skip_writes() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::open(dir.path()).with_capacity(1 << 20).with_tiers(&[Tier::Derived]);
        let key = ApkKey("app-0123456789abcdef".into());
        cache.put(&key, "classes.dex", b"abc").unwrap();
        cache.put_rendered(&key, "q", b"rows").unwrap();
        cache.put_derived(&key, "classes.dex", "k", 1, Duration::ZERO, b"t").unwrap();
        assert_eq!(cache.tier_stats().map(|t| t.files), [0, 1, 0]);
        let all = DiskCache::open(dir.path()).with_capacity(1 << 20).with_tiers(&Tier::ALL);
        all.put(&key, "classes.dex", b"abc").unwrap();
        assert!(cache.get(&key, "classes.dex", 3).is_none());
        assert!(cache.uses(Tier::Derived) && !cache.uses(Tier::Dex));
    }

    #[test]
    fn lazy_eviction_skips_a_walk_right_after_another() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::open(dir.path()).with_capacity(1 << 30);
        let key = ApkKey("app-0123456789abcdef".into());
        cache.put(&key, "classes.dex", &[0; 100]).unwrap();
        cache.evict();
        assert!(dir.path().join(EVICT_MARKER).is_file());
        assert!(cache.check_usable().is_ok(), "the marker is the cache's own");
        // Over a lowered budget: a lazy pass right after a walk leaves it ...
        let cache = cache.with_capacity(50);
        cache.evict_lazily();
        assert_eq!(cache.stats().1, 1);
        // ... until enough was written since (1/16 of the budget), or the walk is old.
        cache.put(&key, "classes2.dex", &[0; 100]).unwrap();
        cache.evict_lazily();
        assert_eq!(cache.stats().1, 0);
    }

    #[test]
    fn small_dex_entries_are_not_admitted_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::open(dir.path());
        if std::env::var_os(MIN_DEX_ENV).is_none() {
            assert_eq!(cache.min_dex_bytes(), DEFAULT_MIN_DEX_BYTES);
        }
        let cache = cache.with_min_dex_bytes(100);
        assert!(!cache.admits_dex(99));
        assert!(cache.admits_dex(100));
        assert!(cache.with_min_dex_bytes(0).admits_dex(0));
    }

    #[test]
    fn eviction_trims_tiers_then_goes_l1_l3_l2() {
        let dir = tempfile::tempdir().unwrap();
        // Budget 1000: L2 may hold 500, L3 125.
        let cache = DiskCache::open(dir.path()).with_capacity(1000);
        let k = |i: u32| ApkKey(format!("app-{i:016x}"));
        // L3: four 64-byte results (+ header), the oldest beyond L3's own budget.
        for i in 0..4 {
            let q = format!("q{i}");
            cache.put_rendered(&k(0), &q, &[0; 64]).unwrap();
            set_mtime(&cache.rendered_path(&k(0), &q), -100 + i as i64);
        }
        cache.evict();
        let [_, _, l3] = cache.tier_stats();
        assert_eq!(l3.files, 1, "trimmed to its own budget, newest kept");
        assert!(cache.get_rendered(&k(0), "q3").is_some());
        // L2: a cheap and an expensive index per byte; L1: two APKs.
        cache.put_derived(&k(1), "classes.dex", "cheap", 1, Duration::from_micros(10), &[0; 136]).unwrap();
        cache.put_derived(&k(1), "classes.dex", "dear", 1, Duration::from_secs(1), &[0; 136]).unwrap();
        cache.put(&k(2), "classes.dex", &[0; 300]).unwrap();
        cache.put(&k(3), "classes.dex", &[0; 300]).unwrap();
        set_mtime(&dir.path().join(k(2).as_str()), -50);
        // 78 + 400 + 600 = 1078 > 1000: one L1 directory goes, the older.
        cache.evict();
        assert!(cache.get(&k(2), "classes.dex", 300).is_none());
        assert!(cache.get(&k(3), "classes.dex", 300).is_some());
        assert_eq!(cache.tier_stats().map(|t| t.files), [1, 2, 1]);
        // Budget 450 (L2 225, L3 56): L3 and the cheap L2 index exceed their
        // own budgets, then L1 goes to fit the total.
        let cache = cache.with_capacity(450);
        cache.evict();
        assert_eq!(cache.tier_stats().map(|t| t.files), [0, 1, 0]);
        assert!(cache.get_derived(&k(1), "classes.dex", "dear", 1).is_some());
    }

    #[test]
    fn l1_eviction_weighs_size_with_age() {
        let dir = tempfile::tempdir().unwrap();
        let cache = DiskCache::open(dir.path()).with_capacity(600);
        let (big, small) = (ApkKey("big-0000000000000001".into()), ApkKey("small-0000000000000002".into()));
        // The big entry is newer but costs far more space per second of age.
        cache.put(&small, "classes.dex", &[0; 100]).unwrap();
        cache.put(&big, "classes.dex", &[0; 550]).unwrap();
        set_mtime(&dir.path().join(small.as_str()), -3);
        cache.evict();
        assert!(cache.get(&small, "classes.dex", 100).is_some());
        assert!(cache.get(&big, "classes.dex", 550).is_none());
    }

    #[test]
    fn entries_of_deleted_apks_go_first() {
        let dir = tempfile::tempdir().unwrap();
        let apks = tempfile::tempdir().unwrap();
        let cache = DiskCache::open(dir.path()).with_capacity(1000);
        let (live, dead) = (ApkKey("live-0000000000000001".into()), ApkKey("dead-0000000000000002".into()));
        let (live_apk, dead_apk) = (apks.path().join("live.apk"), apks.path().join("dead.apk"));
        fs::write(&live_apk, b"PK").unwrap();
        fs::write(&dead_apk, b"PK").unwrap();
        cache.note_source(&live, &live_apk).unwrap();
        cache.note_source(&dead, &dead_apk).unwrap();
        cache.put(&live, "classes.dex", &[0; 400]).unwrap();
        // The dead APK's entry is the newest one, and its L2 index the dearest.
        cache.put_derived(&dead, "classes.dex", "locators", 1, Duration::from_secs(9), &[0; 100]).unwrap();
        cache.put(&dead, "classes.dex", &[0; 400]).unwrap();
        set_mtime(&dir.path().join(live.as_str()), -100);
        fs::remove_file(&dead_apk).unwrap();
        // 400 + 164 + 400 = 964: within budget, nothing goes.
        cache.evict();
        assert_eq!(cache.stats().1, 3);
        let cache = cache.with_capacity(500);
        cache.evict();
        assert!(cache.get(&live, "classes.dex", 400).is_some());
        assert!(cache.get(&dead, "classes.dex", 400).is_none());
        assert!(cache.get_derived(&dead, "classes.dex", "locators", 1).is_none());
        assert!(!dir.path().join("sources").join(dead.as_str()).exists(), "source record dropped with its entries");
        assert!(dir.path().join("sources").join(live.as_str()).exists());
    }
}
