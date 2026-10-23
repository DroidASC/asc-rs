//! The Droid ASC engine: stateless, zero-preprocessing queries against an APK.
//!
//! * [`Engine::get_class_dex`] inflates the DEX entries in parallel (smallest
//!   first) and stops as soon as one defines the requested class.
//! * [`Engine::find_refs`] runs a reference search over every DEX entry in
//!   parallel and streams results back as each DEX completes.
//! * [`Engine::get_class`] rebuilds a minimal DEX containing only the target
//!   class and renders it as smali.
//! * [`Engine::list_classes`] lists the classes of every DEX entry in order.
//! * [`Engine::manifest_xml`] decodes the binary `AndroidManifest.xml`.
//!
//! Optionally the engine keeps inflated DEX entries in an on-disk cache
//! (shared across processes) and/or an in-memory LRU together with the locator
//! tables built for them, so repeated queries skip inflation and table builds.
//! The disk cache also keeps the locator tables (L2, mapped by later
//! processes instead of rebuilt) and `find_refs` results (L3); see
//! [`asc_cache`] for the tiers.
//! Disk writes happen on a background thread so a query never waits on them;
//! [`Engine::flush_cache_writes`] waits for them to land and [`Engine::close_cache_writes`]
//! (run on drop) additionally stops queueing new ones.

mod callgraph;
mod classes;
pub mod names;
mod tiers;

use asc_apk::{Apk, Entry, Limits};
use asc_cache::{ApkKey, DexData, DiskCache, MemoryCache, Tier};
use asc_dex::container::{dex041_logical_offsets, logical_dex_buffers, logical_dex_iter};
use asc_dex::Dex;
pub use asc_findrefs::CompiledQuery;
use asc_findrefs::{FindRefs, Hit, Query, RefKind, SearchState};
use asc_rebuild::Rebuilt;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, OnceLock, Weak};
use std::time::{Instant, SystemTime};

pub use asc_apk::Limits as InflateLimits;
pub use asc_cache;
pub use asc_findrefs::{ClassQuery, ClassRelation, MemberQuery};
pub use asc_smali::Options as SmaliOptions;
pub use callgraph::{CallQuery, CallRow, CallTree, Direction};
pub use classes::{dex_classes, ClassListing, DexClasses, EntryClasses};
pub use tiers::auto_memory_share;

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error(transparent)]
    Apk(#[from] asc_apk::ApkError),
    #[error(transparent)]
    Dex(#[from] asc_dex::DexError),
    #[error(transparent)]
    Find(#[from] asc_findrefs::FindError),
    #[error(transparent)]
    Rebuild(#[from] asc_rebuild::RebuildError),
    #[error(transparent)]
    Smali(#[from] asc_smali::SmaliError),
    #[error(transparent)]
    Axml(#[from] asc_axml::AxmlError),
    #[error("class {0} not found in APK")]
    ClassNotFound(String),
    #[error("{0}")]
    Query(String),
    #[error("{dex}: {reason}")]
    BadDex { dex: String, reason: String },
    #[error("worker panicked while processing {0}")]
    WorkerPanic(String),
}

pub type Result<T> = std::result::Result<T, EngineError>;

/// Shared inflated bytes of a DEX (possibly one logical DEX of a container).
pub type DexBytes = Arc<DexData>;

/// A DEX (possibly one logical DEX of a 041 container) that defines a class.
#[derive(Clone)]
pub struct ClassHit {
    pub dex_name: String,
    pub dex: DexBytes,
}

/// Result of a full `getclass`.
#[derive(Clone)]
pub struct ClassSource {
    pub dex_name: String,
    pub source: String,
    /// The minimal single-class DEX, or `None` when the class could not be
    /// rebuilt (see `warning`) and `source` was disassembled from the
    /// original DEX instead.
    pub rebuilt: Option<Rebuilt>,
    /// Why the rebuild was skipped, when it was.
    pub warning: Option<String>,
    /// Microseconds spent locating and inflating the DEX.
    pub scan_us: u128,
}

/// One aggregated reference result: a method and what it references.
///
/// For a class relation query (`Extends` / `Implements`) the row is a class
/// instead: `method_idx` is its type index, `method` its descriptor, `matched`
/// the target descriptor and `relation` is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefResult {
    pub dex_name: String,
    pub method_idx: u32,
    /// `Lcls;->name`
    pub method: String,
    /// Display names of the matched constants (strings, descriptors, members).
    pub matched: Vec<String>,
    /// Set for the rows of a class relation query.
    pub relation: Option<ClassRelation>,
    /// The referencing instructions, in offset order (none for class relations).
    pub sites: Vec<RefSite>,
    /// Smali around the sites, when asked for ([`RefContext`]).
    pub context: Option<String>,
}

/// One instruction behind a [`RefResult`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefSite {
    /// Absolute byte offset of the instruction in the DEX.
    pub offset: u32,
    /// Index into the row's `matched` of the constant it references.
    pub matched: usize,
    /// Code units from the start of the method's code (filled with a context).
    pub pc: Option<u32>,
    /// Source line from the debug info (filled with a context, when known).
    pub line: Option<u32>,
}

/// How much code to return with each `findrefs` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RefContext {
    /// The row alone (the Python output).
    #[default]
    None,
    /// The referencing instructions with this many smali lines around each.
    Lines(usize),
    /// The whole referencing method.
    Method,
}

/// Options of [`Engine::find_refs_opts`].
#[derive(Debug, Clone, Copy)]
pub struct FindOptions {
    /// One row per method (with every matched constant) instead of one per instruction.
    pub aggregate: bool,
    pub context: RefContext,
}

impl Default for FindOptions {
    fn default() -> Self {
        FindOptions { aggregate: true, context: RefContext::None }
    }
}

impl RefResult {
    /// The Python CLI line format: `dex | Lcls;->m | matched=(a; b)`, or
    /// `dex | Lsub; extends Lbase;` for a class relation.
    pub fn line(&self) -> String {
        match self.relation {
            Some(rel) => format!("{} | {} {} {}", self.dex_name, self.method, rel.verb(), self.matched.join("; ")),
            None => format!("{} | {} | matched=({})", self.dex_name, self.method, self.matched.join("; ")),
        }
    }

    /// The row followed by its context lines (just the row without one).
    pub fn text(&self) -> String {
        let mut out = self.line();
        if let Some(c) = &self.context {
            out.push('\n');
            out.push_str(c.trim_end_matches('\n'));
        }
        out
    }
}

/// Results for one DEX, delivered as soon as its search completes.
#[derive(Debug, Clone)]
pub struct RefBatch {
    pub entry_name: String,
    pub results: Vec<RefResult>,
    pub inflate_us: u128,
    pub search_us: u128,
    /// Where the bytes came from: `inflate`, `memory`, `disk` or `stored`.
    pub source: &'static str,
    pub error: Option<String>,
}

impl RefBatch {
    /// Record a failure of one logical DEX of this entry. A container holds
    /// several, so failures accumulate instead of overwriting each other.
    /// Consumers prefix `entry_name`; only a container's logical DEX (whose
    /// name differs) adds its own.
    fn note_error(&mut self, name: &str, e: EngineError) {
        let msg = if name == self.entry_name { e.to_string() } else { format!("{name}: {e}") };
        self.error = Some(match self.error.take() {
            Some(prev) => format!("{prev}; {msg}"),
            None => msg,
        });
    }
}

/// Summary of a whole `find_refs` run.
#[derive(Debug, Clone, Default)]
pub struct RefSummary {
    pub entries: usize,
    pub total_results: usize,
    pub total_us: u128,
}

/// Cache configuration for an [`Engine`].
#[derive(Default)]
pub struct CacheConfig {
    /// In-memory LRU capacity for inflated entries (0 disables it).
    pub memory_bytes: usize,
    /// On-disk cache shared across processes.
    pub disk: Option<DiskCache>,
    /// Treat `memory_bytes` as a starting point and keep resizing the LRU to
    /// this process's share of one budget for every resident host the user
    /// runs ([`auto_memory_share`]), instead of a fixed capacity.
    pub memory_auto: bool,
}

impl CacheConfig {
    /// Disk cache in the default directory, no in-memory cache (CLI default).
    pub fn disk_default() -> CacheConfig {
        CacheConfig { disk: DiskCache::open_default(), ..CacheConfig::default() }
    }

    /// Disk cache plus an in-memory LRU of a fixed capacity.
    pub fn resident(memory_bytes: usize) -> CacheConfig {
        CacheConfig { memory_bytes, disk: DiskCache::open_default(), memory_auto: false }
    }

    /// Disk cache plus an in-memory LRU sized automatically (GUI / server
    /// default): [`auto_memory_bytes`] to start with, then this process's
    /// share once other resident hosts run, so several of them on one
    /// machine do not each claim 2 GiB.
    pub fn resident_auto() -> CacheConfig {
        CacheConfig { memory_auto: true, ..CacheConfig::resident(auto_memory_bytes()) }
    }
}

/// Upper bound of [`auto_memory_bytes`].
pub const AUTO_MEMORY_MAX: usize = 2 << 30;
/// Lower bound of [`auto_memory_bytes`]: below this the LRU would thrash on
/// every query (it always keeps at least one entry anyway).
pub const AUTO_MEMORY_MIN: usize = 64 << 20;

/// In-memory cache budget for this machine: a quarter of the memory
/// currently available, clamped to [`AUTO_MEMORY_MIN`]..=[`AUTO_MEMORY_MAX`];
/// [`AUTO_MEMORY_MAX`] when the available memory cannot be determined.
pub fn auto_memory_bytes() -> usize {
    auto_memory_bytes_for(available_memory())
}

/// [`auto_memory_bytes`] for a given amount of available memory.
pub fn auto_memory_bytes_for(available: Option<u64>) -> usize {
    match available {
        Some(a) => usize::try_from(a / 4).unwrap_or(usize::MAX).clamp(AUTO_MEMORY_MIN, AUTO_MEMORY_MAX),
        None => AUTO_MEMORY_MAX,
    }
}

/// Bytes of memory available to this process: `MemAvailable`, lowered to
/// the headroom left under a cgroup v2 `memory.max` when one applies.
/// `None` where neither can be read (non-Linux systems).
pub fn available_memory() -> Option<u64> {
    let system = std::fs::read_to_string("/proc/meminfo").ok().and_then(|t| meminfo_available(&t));
    let cgroup = cgroup_headroom();
    match (system, cgroup) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// `MemAvailable` from `/proc/meminfo` text, in bytes.
fn meminfo_available(meminfo: &str) -> Option<u64> {
    let line = meminfo.lines().find(|l| l.starts_with("MemAvailable:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    kb.checked_mul(1024)
}

/// `memory.max - memory.current` of this process's cgroup v2, if limited.
fn cgroup_headroom() -> Option<u64> {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel = cgroup.lines().find_map(|l| l.strip_prefix("0::"))?;
    let dir = Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
    let read = |f: &str| std::fs::read_to_string(dir.join(f)).ok();
    cgroup_headroom_from(&read("memory.max")?, &read("memory.current")?)
}

/// Headroom from the text of `memory.max` (`max` when unlimited) and
/// `memory.current`.
fn cgroup_headroom_from(max: &str, current: &str) -> Option<u64> {
    let max: u64 = max.trim().parse().ok()?;
    let current: u64 = current.trim().parse().ok()?;
    Some(max.saturating_sub(current))
}

/// A cache several [`Engine`]s share, so a process serving many APKs keeps
/// one memory budget (the LRU is keyed by APK) and one disk-writer thread.
/// Engines attached with [`Engine::with_shared_cache`] leave queued disk
/// writes alone when dropped; dropping the `SharedCache` flushes them and
/// stops queueing (as dropping a private engine does).
pub struct SharedCache(Option<Arc<EngineCache>>);

impl SharedCache {
    /// Build the cache [`Engine::with_cache`] would; warnings (an unusable
    /// disk cache directory) go to `logger`.
    pub fn new(config: CacheConfig, logger: impl Fn(&str) + Send + Sync + 'static) -> SharedCache {
        let mut holder = Engine::new("").with_logger(logger).with_cache(config);
        SharedCache(holder.cache.take())
    }

    /// Bytes currently held by the shared in-memory cache.
    pub fn memory_bytes(&self) -> usize {
        self.0.as_ref().and_then(|c| c.memory.as_ref()).map(|m| m.lock().unwrap().used_bytes()).unwrap_or(0)
    }

    /// Budget of the shared in-memory cache (0 when it is disabled).
    pub fn memory_capacity(&self) -> usize {
        self.0.as_ref().and_then(|c| c.memory.as_ref()).map(|m| m.lock().unwrap().capacity_bytes()).unwrap_or(0)
    }

    /// Block until every queued disk-cache write has landed.
    pub fn flush_writes(&self) {
        if let Some(c) = &self.0 {
            c.flush(false);
        }
    }
}

impl Drop for SharedCache {
    fn drop(&mut self) {
        if let Some(c) = &self.0 {
            c.flush(true);
        }
    }
}

/// One logical DEX of a cached entry with its lazily built locator tables.
/// The tables are shared with the entry that replaces this one once its
/// bytes are remapped from the disk cache (same bytes, so still valid).
pub struct LogicalDex {
    pub name: String,
    pub data: DexBytes,
    pub state: Arc<SearchState>,
    persisted: Arc<tiers::Persisted>,
}

/// A cached inflated entry.
pub struct CachedEntry {
    pub name: String,
    pub data: DexBytes,
    logical: OnceLock<Vec<LogicalDex>>,
}

impl CachedEntry {
    fn new(name: &str, data: DexBytes) -> CachedEntry {
        CachedEntry { name: name.to_string(), data, logical: OnceLock::new() }
    }

    /// Logical DEX files of this entry (one, unless it is a 041 container).
    pub fn logical(&self) -> &[LogicalDex] {
        self.logical.get_or_init(|| {
            let bufs = logical_dex_buffers(&self.name, &self.data);
            bufs.into_iter()
                .map(|(name, buf)| {
                    let data = match buf {
                        Cow::Borrowed(_) => Arc::clone(&self.data),
                        Cow::Owned(v) => Arc::new(DexData::Owned(v)),
                    };
                    LogicalDex { name, data, state: Arc::new(SearchState::new()), persisted: Arc::default() }
                })
                .collect()
        })
    }

    /// Bytes this entry keeps resident once searched: the inflated entry plus,
    /// for a 041 container, one full-container copy per further logical DEX
    /// (what `logical()` materialises). Computed from the headers alone so
    /// accounting does not itself trigger those copies.
    pub fn resident_bytes(&self) -> usize {
        self.data.len() * dex041_logical_offsets(&self.data).len()
    }

    /// Bytes of the locator tables built (on the heap) or mapped (from L2)
    /// so far for this entry's logical DEX files (0 before the first search).
    pub fn state_bytes(&self) -> usize {
        self.logical.get().map_or(0, |l| l.iter().map(|d| d.state.heap_bytes() + d.state.mapped_bytes()).sum())
    }

    /// What the in-memory cache charges for this entry: its bytes plus the
    /// locator tables built for it.
    pub fn charged_bytes(&self) -> usize {
        self.resident_bytes() + self.state_bytes()
    }

    /// The same entry over `data` (identical bytes from another source, e.g.
    /// the disk cache mapping), keeping the locator tables already built.
    /// A container's normalised logical copies are owned and are kept as is.
    fn with_data(&self, data: DexBytes) -> CachedEntry {
        let logical = OnceLock::new();
        if let Some(old) = self.logical.get() {
            let moved = old
                .iter()
                .map(|l| LogicalDex {
                    name: l.name.clone(),
                    data: if Arc::ptr_eq(&l.data, &self.data) { Arc::clone(&data) } else { Arc::clone(&l.data) },
                    state: Arc::clone(&l.state),
                    persisted: Arc::clone(&l.persisted),
                })
                .collect();
            let _ = logical.set(moved);
        }
        CachedEntry { name: self.name.clone(), data, logical }
    }

    /// The same entry with the locator tables of logical DEX `idx` replaced
    /// by `state` (the same tables viewed from L2).
    fn with_state(&self, idx: usize, state: Arc<SearchState>) -> CachedEntry {
        let logical = OnceLock::new();
        if let Some(old) = self.logical.get() {
            let moved = old
                .iter()
                .enumerate()
                .map(|(i, l)| LogicalDex {
                    name: l.name.clone(),
                    data: Arc::clone(&l.data),
                    state: if i == idx { Arc::clone(&state) } else { Arc::clone(&l.state) },
                    persisted: Arc::clone(&l.persisted),
                })
                .collect();
            let _ = logical.set(moved);
        }
        CachedEntry { name: self.name.clone(), data: Arc::clone(&self.data), logical }
    }

    /// Whether the entry's bytes are mapped from the disk cache.
    pub fn is_mapped(&self) -> bool {
        matches!(*self.data, DexData::Mapped(_))
    }
}

/// A queued disk write for the APK of `key` at `apk`.
struct WriteJob {
    key: ApkKey,
    apk: Arc<Path>,
    kind: Job,
}

enum Job {
    /// An inflated entry for L1: the bytes are shared with the query that
    /// produced them, so queueing costs nothing.
    Dex {
        name: String,
        data: DexBytes,
        /// The in-memory cache entry holding `data`, if any: once the file is
        /// in place its heap bytes are swapped for a mapping of that file.
        remap: Option<Weak<CachedEntry>>,
    },
    /// Locator tables for L2.
    Derived(tiers::DerivedJob),
    /// A query result for L3.
    Rendered { query: String, payload: Vec<u8> },
}

struct Writer {
    tx: mpsc::Sender<WriteJob>,
    handle: std::thread::JoinHandle<()>,
}

type SharedMemory = Arc<Mutex<MemoryCache<CachedEntry>>>;

struct EngineCache {
    memory: Option<SharedMemory>,
    /// Publishes (and, when automatic, adjusts) the memory cache's size.
    budget: Option<tiers::MemoryBudget>,
    disk: Option<Arc<DiskCache>>,
    writer: Mutex<Option<Writer>>,
    /// Set by `flush`: later writes are dropped rather than handed to a new
    /// writer thread the exiting process would kill mid-write.
    closed: AtomicBool,
    /// Entries currently being inflated, so concurrent queries share one
    /// inflate instead of racing (and replacing each other's locator tables).
    inflight: Mutex<HashSet<String>>,
    inflight_done: Condvar,
}

impl EngineCache {
    /// Queue a disk write; falls back to a synchronous write only when the
    /// writer thread cannot be started.
    fn put_async(&self, job: WriteJob) {
        let Some(disk) = &self.disk else { return };
        let mut writer = self.writer.lock().unwrap();
        if self.closed.load(Ordering::Relaxed) {
            return;
        }
        if writer.is_none() {
            let (tx, rx) = mpsc::channel::<WriteJob>();
            let thread_disk = Arc::clone(disk);
            let thread_memory = self.memory.clone();
            let spawned = std::thread::Builder::new().name("droidasc-cache-writer".into()).spawn(move || {
                let mut pending: Option<WriteJob> = None;
                let mut noted = HashSet::new();
                loop {
                    let job = match pending.take() {
                        Some(j) => j,
                        None => match rx.recv() {
                            Ok(j) => j,
                            Err(_) => break,
                        },
                    };
                    run_job(&thread_disk, thread_memory.as_ref(), job, &mut noted);
                    // Walk the cache directory once per burst, not once per entry.
                    match rx.try_recv() {
                        Ok(next) => pending = Some(next),
                        Err(_) => thread_disk.evict_lazily(),
                    }
                }
            });
            match spawned {
                Ok(handle) => *writer = Some(Writer { tx, handle }),
                Err(_) => {
                    run_job(disk, self.memory.as_ref(), job, &mut HashSet::new());
                    disk.evict_lazily();
                    return;
                }
            }
        }
        if let Some(w) = writer.as_ref() {
            if w.tx.send(job).is_err() {
                *writer = None;
            }
        }
    }

    /// Wait for every queued disk write to land. With `close`, writes queued
    /// afterwards are dropped (the next query re-inflates and re-queues them).
    fn flush(&self, close: bool) {
        let taken = {
            let mut writer = self.writer.lock().unwrap();
            // Under the lock, so a concurrent `put_async` either queued its job
            // before the take or sees the flag.
            if close {
                self.closed.store(true, Ordering::Relaxed);
            }
            writer.take()
        };
        if let Some(Writer { tx, handle }) = taken {
            drop(tx);
            let _ = handle.join();
        }
    }

    /// Account for bytes just charged to the memory cache.
    fn charged(&self) {
        if let (Some(budget), Some(memory)) = (&self.budget, &self.memory) {
            budget.maybe_rebalance(memory);
        }
    }

    fn begin_inflate(&self, id: String) -> InflightGuard<'_> {
        let mut set = self.inflight.lock().unwrap();
        while set.contains(&id) {
            set = self.inflight_done.wait(set).unwrap();
        }
        set.insert(id.clone());
        InflightGuard { cache: self, id }
    }
}

/// Run a queued write on the writer thread. The first write for an APK
/// also records where it lives (`noted` remembers which were).
fn run_job(disk: &DiskCache, memory: Option<&SharedMemory>, job: WriteJob, noted: &mut HashSet<ApkKey>) {
    let WriteJob { key, apk, kind } = job;
    if noted.insert(key.clone()) {
        let _ = disk.note_source(&key, &apk);
    }
    match kind {
        Job::Dex { name, data, remap } => {
            if disk.put(&key, &name, &data).is_ok() {
                remap_entry(disk, memory, key, name, data, remap);
            }
        }
        Job::Derived(d) => tiers::write_derived(disk, memory, &key, d),
        Job::Rendered { query, payload } => {
            let _ = disk.put_rendered(&key, &query, &payload);
        }
    }
}

/// Swap a freshly written entry's heap bytes for a mapping of its cache file:
/// the pages become file-backed (reclaimable by the OS and shared with other
/// processes) and the heap copy is freed once the queries still holding the
/// old entry drop it. The mapping is compared byte for byte first, so a file
/// changed underneath (another writer, a cleared cache) is never served.
fn remap_entry(
    disk: &DiskCache,
    memory: Option<&SharedMemory>,
    key: ApkKey,
    name: String,
    data: DexBytes,
    remap: Option<Weak<CachedEntry>>,
) {
    // The job's own handle on the bytes goes first, so the heap copy is freed
    // as soon as the superseded entry is.
    drop(data);
    let (Some(memory), Some(entry)) = (memory, remap.and_then(|w| w.upgrade())) else { return };
    if entry.is_mapped() {
        return;
    }
    let Some(mapped) = disk.get(&key, &name, entry.data.len() as u64) else { return };
    if *mapped != **entry.data {
        return;
    }
    let new = Arc::new(entry.with_data(Arc::new(mapped)));
    memory.lock().unwrap().replace(&key, &name, &entry, new);
}

/// Make freed DEX-sized blocks go straight back to the OS. glibc serves
/// blocks above its mmap threshold with `mmap`, but raises that threshold to
/// the size of every such block freed (up to 32 MiB), after which inflated
/// DEX copies come from the heap arenas and stay resident after an eviction
/// or a remap, fragmented between longer-lived locator tables. Fixing the
/// threshold disables that adjustment. Process-wide; done once, by the first
/// engine that keeps entries in memory.
fn tune_allocator() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            extern "C" {
                fn mallopt(param: std::os::raw::c_int, value: std::os::raw::c_int) -> std::os::raw::c_int;
            }
            const M_MMAP_THRESHOLD: std::os::raw::c_int = -3;
            // SAFETY: mallopt only adjusts glibc allocator parameters.
            unsafe {
                mallopt(M_MMAP_THRESHOLD, 1 << 20);
            }
        });
    }
}

struct InflightGuard<'c> {
    cache: &'c EngineCache,
    id: String,
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.cache.inflight.lock().unwrap().remove(&self.id);
        self.cache.inflight_done.notify_all();
    }
}

/// Cache activity counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub memory_hits: u64,
    pub disk_hits: u64,
    /// Logical DEX files whose locator tables were mapped from L2.
    pub derived_hits: u64,
    pub inflates: u64,
}

type Logger = Arc<dyn Fn(&str) + Send + Sync>;

/// Where an entry's bytes came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Memory,
    Disk,
    Stored,
    Inflate,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Source::Memory => "memory",
            Source::Disk => "disk",
            Source::Stored => "stored",
            Source::Inflate => "inflate",
        }
    }
}

enum Loaded<'a> {
    Borrowed(Cow<'a, [u8]>),
    Cached(Arc<CachedEntry>),
}

impl<'a> Loaded<'a> {
    fn bytes(&self) -> &[u8] {
        match self {
            Loaded::Borrowed(c) => c,
            Loaded::Cached(e) => &e.data,
        }
    }

    /// Logical DEX buffers, moving the inflated bytes instead of copying them
    /// when the entry is a plain (non-container) DEX. A container's logical
    /// DEXes are copied one at a time, as the caller reaches them.
    fn into_logical(self, entry_name: &str) -> Box<dyn Iterator<Item = (String, DexBytes)> + 'a> {
        match self {
            Loaded::Cached(e) => {
                let logical: Vec<_> = e.logical().iter().map(|l| (l.name.clone(), Arc::clone(&l.data))).collect();
                Box::new(logical.into_iter())
            }
            Loaded::Borrowed(c) => {
                let offsets = dex041_logical_offsets(&c);
                if offsets.len() <= 1 {
                    return Box::new(std::iter::once((entry_name.to_string(), Arc::new(DexData::Owned(c.into_owned())))));
                }
                let name = entry_name.to_string();
                Box::new(offsets.into_iter().enumerate().map(move |(i, off)| {
                    let data = asc_dex::container::normalize_dex041_logical(&c, off).into_owned();
                    (format!("{name}!classes{}.dex", i + 1), Arc::new(DexData::Owned(data)))
                }))
            }
        }
    }
}

/// Engine over one APK.
pub struct Engine {
    apk_path: PathBuf,
    threads: usize,
    debug: bool,
    logger: Logger,
    cache: Option<Arc<EngineCache>>,
    /// `cache` belongs to a [`SharedCache`], which closes it instead of us.
    shared_cache: bool,
    stats: Arc<Stats>,
    /// `(size, mtime, key)` of the APK the key was last computed for.
    key_cache: Mutex<Option<(u64, Option<SystemTime>, ApkKey)>>,
    limits: Limits,
}

/// An APK opened for a search whose DEX entries are scheduled by the caller,
/// e.g. across many APKs at once ([`Engine::search_target`]).
pub struct SearchTarget {
    apk: Apk,
    key: Option<ApkKey>,
    /// Root DEX entries, smallest compressed first.
    pub entries: Vec<Entry>,
}

#[derive(Default)]
struct Stats {
    memory_hits: AtomicUsize,
    disk_hits: AtomicUsize,
    derived_hits: AtomicUsize,
    inflates: AtomicUsize,
}

/// Worker threads to use when the caller does not say.
pub fn default_threads() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8)
}

impl Engine {
    pub fn new(apk_path: impl AsRef<Path>) -> Engine {
        Engine {
            apk_path: apk_path.as_ref().to_path_buf(),
            threads: default_threads(),
            debug: false,
            logger: Arc::new(|m| println!("{m}")),
            cache: None,
            shared_cache: false,
            stats: Arc::new(Stats::default()),
            key_cache: Mutex::new(None),
            limits: Limits::default(),
        }
    }

    /// Refuse entries that inflate past `limits` (zip bombs).
    pub fn with_limits(mut self, limits: Limits) -> Engine {
        self.limits = limits;
        self
    }

    pub fn with_threads(mut self, threads: usize) -> Engine {
        self.threads = threads.max(1);
        self
    }

    pub fn with_debug(mut self, debug: bool) -> Engine {
        self.debug = debug;
        self
    }

    /// Route debug output somewhere other than stdout.
    pub fn with_logger(mut self, logger: impl Fn(&str) + Send + Sync + 'static) -> Engine {
        self.logger = Arc::new(logger);
        self
    }

    /// Enable caching of inflated entries. A disk cache whose directory holds
    /// foreign files is dropped with a warning through the logger (set it
    /// first), instead of every write failing silently in the background.
    pub fn with_cache(mut self, mut config: CacheConfig) -> Engine {
        if let Some(Err(e)) = config.disk.as_ref().map(DiskCache::check_usable) {
            (self.logger)(&format!("Warning: {e}; disk cache disabled"));
            config.disk = None;
        }
        if config.memory_bytes > 0 {
            tune_allocator();
        }
        if config.memory_bytes == 0 && config.disk.is_none() {
            self.cache = None;
        } else {
            let cache = EngineCache {
                memory: (config.memory_bytes > 0).then(|| Arc::new(Mutex::new(MemoryCache::new(config.memory_bytes)))),
                budget: (config.memory_bytes > 0).then(|| tiers::MemoryBudget::new(config.memory_auto)),
                disk: config.disk.map(Arc::new),
                writer: Mutex::new(None),
                closed: AtomicBool::new(false),
                inflight: Mutex::new(HashSet::new()),
                inflight_done: Condvar::new(),
            };
            // Registers this process and takes its share right away.
            cache.charged();
            self.cache = Some(Arc::new(cache));
        }
        self
    }

    /// Use `cache` (shared with other engines) instead of a private one.
    pub fn with_shared_cache(mut self, cache: &SharedCache) -> Engine {
        self.cache = cache.0.clone();
        self.shared_cache = true;
        self
    }

    pub fn apk_path(&self) -> &Path {
        &self.apk_path
    }

    pub fn threads(&self) -> usize {
        self.threads
    }

    pub fn cache_stats(&self) -> CacheStats {
        CacheStats {
            memory_hits: self.stats.memory_hits.load(Ordering::Relaxed) as u64,
            disk_hits: self.stats.disk_hits.load(Ordering::Relaxed) as u64,
            derived_hits: self.stats.derived_hits.load(Ordering::Relaxed) as u64,
            inflates: self.stats.inflates.load(Ordering::Relaxed) as u64,
        }
    }

    /// Bytes currently charged to the in-memory cache: entry bytes plus the
    /// locator tables built for them.
    pub fn memory_cache_bytes(&self) -> usize {
        self.cache.as_ref().and_then(|c| c.memory.as_ref()).map(|m| m.lock().unwrap().used_bytes()).unwrap_or(0)
    }

    /// Drop this APK's entries from the in-memory cache (shared or not) and
    /// return the bytes released; queries still holding them keep them alive.
    pub fn release_memory_cache(&self) -> usize {
        let Some(memory) = self.cache.as_ref().and_then(|c| c.memory.as_ref()) else { return 0 };
        let key = self.key_cache.lock().unwrap().as_ref().map(|(_, _, key)| key.clone());
        let Some(key) = key.or_else(|| self.open().ok().and_then(|apk| self.apk_key(&apk))) else { return 0 };
        memory.lock().unwrap().remove_apk(&key)
    }

    /// Entry bytes of the in-memory cache that are mapped from the disk cache
    /// (file-backed pages the OS can reclaim) rather than held on the heap.
    pub fn memory_cache_mapped_bytes(&self) -> usize {
        let Some(m) = self.cache.as_ref().and_then(|c| c.memory.as_ref()) else { return 0 };
        m.lock().unwrap().values().filter(|e| e.is_mapped()).map(|e| e.data.len()).sum()
    }

    /// Bytes of the in-memory cache's locator tables that are viewed in L2
    /// files (file-backed pages shared with other processes) rather than
    /// held on the heap.
    pub fn memory_cache_mapped_table_bytes(&self) -> usize {
        let Some(m) = self.cache.as_ref().and_then(|c| c.memory.as_ref()) else { return 0 };
        let m = m.lock().unwrap();
        m.values().filter_map(|e| e.logical.get()).flatten().map(|l| l.state.mapped_bytes()).sum()
    }

    /// Block until every queued disk-cache write has been renamed into place.
    pub fn flush_cache_writes(&self) {
        if let Some(c) = &self.cache {
            c.flush(false);
        }
    }

    /// [`Engine::flush_cache_writes`] for process exit: also stops queueing,
    /// so a worker still holding the engine cannot start a writer thread that
    /// exiting would kill mid-write. Run on drop.
    pub fn close_cache_writes(&self) {
        if let Some(c) = &self.cache {
            c.flush(true);
        }
    }

    fn log(&self, msg: impl AsRef<str>) {
        if self.debug {
            (self.logger)(msg.as_ref());
        }
    }

    pub fn open(&self) -> Result<Apk> {
        Ok(Apk::open(&self.apk_path)?.with_limits(self.limits))
    }

    /// Open the APK for [`Engine::search_target`].
    pub fn search_target(&self) -> Result<SearchTarget> {
        let apk = self.open()?;
        let entries = apk.dex_entries()?;
        let key = self.apk_key(&apk);
        Ok(SearchTarget { apk, key, entries })
    }

    /// Search one entry of `target` (what [`Engine::find_refs_with`] runs per
    /// entry), through this engine's caches.
    pub fn search_target_entry(
        &self,
        target: &SearchTarget,
        entry: &Entry,
        query: &CompiledQuery,
        aggregate: bool,
        cancel: &AtomicBool,
    ) -> RefBatch {
        search_entry(
            &target.apk,
            target.key.as_ref(),
            entry,
            query,
            FindOptions { aggregate, context: RefContext::None },
            cancel,
            self.cache.as_deref(),
            &self.stats,
        )
    }

    /// Root-level DEX entries, smallest compressed first.
    pub fn dex_entries(&self) -> Result<Vec<Entry>> {
        Ok(self.open()?.dex_entries()?)
    }

    /// Cache key for `apk` when caching is enabled. Hashing the central
    /// directory is done once per APK version; later calls only `stat`.
    pub fn apk_key(&self, apk: &Apk) -> Option<ApkKey> {
        self.cache.as_ref()?;
        let meta = std::fs::metadata(apk.path()).ok()?;
        let ident = (meta.len(), meta.modified().ok());
        let mut cached = self.key_cache.lock().unwrap();
        if let Some((len, mtime, key)) = cached.as_ref() {
            if (*len, *mtime) == ident {
                return Some(key.clone());
            }
        }
        let key = ApkKey::for_apk(apk).ok()?;
        *cached = Some((ident.0, ident.1, key.clone()));
        Some(key)
    }

    /// Inflated bytes of `entry`, through the caches when enabled. Stored
    /// entries are copied only when an in-memory cache wants to keep them.
    pub fn entry_bytes(&self, apk: &Apk, key: Option<&ApkKey>, entry: &Entry) -> Result<DexBytes> {
        Ok(match load_entry(apk, key, entry, self.cache.as_deref(), &self.stats, None)?.0 {
            Loaded::Borrowed(c) => Arc::new(DexData::Owned(c.into_owned())),
            Loaded::Cached(e) => Arc::clone(&e.data),
        })
    }

    /// Find the DEX that defines `descriptor` (`Lcom/poc/Main;`).
    ///
    /// DEX entries are inflated in parallel, smallest first. Entries that are
    /// not cached are first streamed only as far as their id tables and string
    /// data to answer the probe cheaply; only a hit is inflated fully. The call
    /// returns as soon as one worker finds the class; workers still inflating
    /// another entry at that moment finish on their own in the background.
    pub fn get_class_dex(&self, descriptor: &str) -> Result<Option<ClassHit>> {
        let t0 = Instant::now();
        let apk = Arc::new(self.open()?);
        let entries = Arc::new(apk.dex_entries()?);
        let key = Arc::new(self.apk_key(&apk));
        self.log(format!("[APK] scan setup={} us entries={}", t0.elapsed().as_micros(), entries.len()));
        if entries.is_empty() {
            return Ok(None);
        }
        // DEX descriptors are MUTF-8: a supplementary character is a surrogate pair,
        // not the 4-byte UTF-8 sequence `as_bytes` would compare against.
        let target: Arc<Vec<u8>> = Arc::new(asc_dex::mutf8::encode(descriptor));
        let next = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let workers = self.threads.min(entries.len()).max(1);
        let (tx, rx) = mpsc::channel::<std::result::Result<Option<ClassHit>, EngineError>>();
        let debug = self.debug;
        for w in 0..workers {
            let (apk, entries, key, target, next, stop, tx, logger, cache, stats) = (
                Arc::clone(&apk),
                Arc::clone(&entries),
                Arc::clone(&key),
                Arc::clone(&target),
                Arc::clone(&next),
                Arc::clone(&stop),
                tx.clone(),
                Arc::clone(&self.logger),
                self.cache.clone(),
                Arc::clone(&self.stats),
            );
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(entry) = entries.get(i) else { break };
                    let t0 = Instant::now();
                    // Cached bytes answer directly; otherwise probe a prefix so
                    // most entries never get fully inflated.
                    let cached = cache.as_deref().and_then(|c| lookup_cached(c, key.as_ref().as_ref(), entry, &stats));
                    let (loaded, source) = match cached {
                        Some((e, source)) => (Loaded::Cached(e), source),
                        None => {
                            match probe_entry(&apk, entry, &target) {
                                Ok(Some(false)) => {
                                    if debug {
                                        logger(&format!(
                                            "[APK] [T{w:04x}] '{}' prefix-probe={} us hit=false",
                                            entry.name,
                                            t0.elapsed().as_micros()
                                        ));
                                    }
                                    let _ = tx.send(Ok(None));
                                    continue;
                                }
                                Ok(Some(true)) | Ok(None) => {}
                                Err(e) => {
                                    let _ = tx.send(Err(e));
                                    continue;
                                }
                            }
                            match load_entry(&apk, key.as_ref().as_ref(), entry, cache.as_deref(), &stats, Some(&stop)) {
                                Ok(l) => l,
                                Err(EngineError::Apk(asc_apk::ApkError::Cancelled)) => break,
                                Err(e) => {
                                    let _ = tx.send(Err(e));
                                    continue;
                                }
                            }
                        }
                    };
                    let t1 = Instant::now();
                    let mut found = None;
                    // Exactly one message per entry: the caller counts them to
                    // know when every entry has answered.
                    let mut entry_err: Option<EngineError> = None;
                    for (name, data) in loaded.into_logical(&entry.name) {
                        if stop.load(Ordering::Relaxed) {
                            return;
                        }
                        match asc_dex::quick::dex_defines_class(&data, &target) {
                            Ok(true) => {
                                found = Some(ClassHit { dex_name: name, dex: data });
                                break;
                            }
                            Ok(false) => {}
                            Err(e) => {
                                entry_err.get_or_insert(e.into());
                            }
                        }
                    }
                    let is_hit = found.is_some();
                    if debug {
                        logger(&format!(
                            "[APK] [T{w:04x}] '{}' {}={} us lookup={} us hit={}",
                            entry.name,
                            source.as_str(),
                            (t1 - t0).as_micros(),
                            t1.elapsed().as_micros(),
                            is_hit
                        ));
                    }
                    if is_hit {
                        stop.store(true, Ordering::Relaxed);
                        let _ = tx.send(Ok(found));
                        return;
                    }
                    let _ = tx.send(entry_err.map_or(Ok(None), Err));
                }
            });
        }
        drop(tx);
        let mut hit = None;
        let mut last_err = None;
        let mut seen = 0usize;
        for msg in rx {
            match msg {
                Ok(Some(h)) => {
                    hit = Some(h);
                    break;
                }
                Ok(None) => {
                    seen += 1;
                    if seen == entries.len() {
                        break;
                    }
                }
                Err(e) => {
                    seen += 1;
                    last_err = Some(e);
                    if seen == entries.len() {
                        break;
                    }
                }
            }
        }
        stop.store(true, Ordering::Relaxed);
        self.log(format!("[APK] getclass total={} us", t0.elapsed().as_micros()));
        match (hit, last_err) {
            (Some(h), _) => Ok(Some(h)),
            (None, Some(e)) => Err(e),
            (None, None) => Ok(None),
        }
    }

    /// Locate, rebuild and disassemble a class.
    pub fn get_class(&self, descriptor: &str) -> Result<ClassSource> {
        self.get_class_with(descriptor, SmaliOptions::default())
    }

    pub fn get_class_with(&self, descriptor: &str, opts: SmaliOptions) -> Result<ClassSource> {
        self.get_class_method(descriptor, opts, None)
    }

    /// [`Engine::get_class_with`] that renders only the method whose
    /// `name(params)ret` is `method` (no fields) when one is given. A malformed
    /// signature is rejected before the APK is read; a class without such a
    /// method is an error. The rebuilt DEX still holds the whole class.
    pub fn get_class_method(&self, descriptor: &str, opts: SmaliOptions, method: Option<&str>) -> Result<ClassSource> {
        if let Some(m) = method {
            asc_smali::normalize_method_signature(m)?;
        }
        let t0 = Instant::now();
        let hit = self.get_class_dex(descriptor)?.ok_or_else(|| EngineError::ClassNotFound(descriptor.to_string()))?;
        let scan_us = t0.elapsed().as_micros();
        let (rebuilt, source, warning) = match decompile_dex_class_method(&hit.dex, descriptor, opts, method) {
            Ok((r, s)) => (Some(r), s, None),
            // The class is there but cannot be rebuilt faithfully (undefined
            // opcode, invoke-custom, too many members for 16-bit indexes...):
            // still show it, disassembled from the original DEX, and say why
            // there is no DEX to dump.
            Err(EngineError::Rebuild(e)) if e.is_input_limitation() => {
                let dex = Dex::with_name(&hit.dex, &hit.dex_name)?;
                let source = asc_smali::disassemble_class_method(&dex, descriptor, opts, method)?;
                let warning = format!("class not rebuilt ({e}); disassembled from the original DEX instead");
                self.log(format!("[DEBUG] {warning}"));
                (None, source, Some(warning))
            }
            Err(e) => return Err(e),
        };
        if self.debug {
            if let Some(r) = &rebuilt {
                let t = r.timings;
                self.log(format!(
                    "[DEBUG] Hollower Time: {} us\n[DEBUG] Collect Time: {} us\n[DEBUG] Remapper Time: {} us\n[DEBUG] Builder Time: {} us\n[DEBUG] Total Extraction Time: {} us",
                    t.hollow_us,
                    t.collect_us,
                    t.map_us,
                    t.build_us,
                    t.total_us()
                ));
            }
        }
        Ok(ClassSource { dex_name: hit.dex_name, source, rebuilt, warning, scan_us })
    }

    /// Search every DEX entry for references. `sink` receives one batch per
    /// entry in completion order. Returns a summary once all entries finish.
    pub fn find_refs(&self, query: &Query, mut sink: impl FnMut(RefBatch)) -> Result<RefSummary> {
        self.find_refs_with(query, true, &AtomicBool::new(false), &mut sink)
    }

    /// `find_refs` with control over aggregation and cancellation. An invalid
    /// pattern is reported once, up front, instead of once per DEX.
    pub fn find_refs_with(
        &self,
        query: &Query,
        aggregate: bool,
        cancel: &AtomicBool,
        sink: &mut dyn FnMut(RefBatch),
    ) -> Result<RefSummary> {
        self.find_refs_opts(query, FindOptions { aggregate, context: RefContext::None }, cancel, sink)
    }

    /// `find_refs` with every option: aggregation, context, cancellation.
    pub fn find_refs_opts(
        &self,
        query: &Query,
        opts: FindOptions,
        cancel: &AtomicBool,
        sink: &mut dyn FnMut(RefBatch),
    ) -> Result<RefSummary> {
        let t0 = Instant::now();
        let compiled = CompiledQuery::new(query)?;
        let apk = self.open()?;
        let mut entries = apk.dex_entries()?;
        // Every entry has to be searched, so run the largest first: the biggest
        // inflate is the critical path and must not wait behind the small ones.
        entries.reverse();
        let key = self.apk_key(&apk);
        let mut summary = RefSummary { entries: entries.len(), ..Default::default() };
        if entries.is_empty() {
            return Ok(summary);
        }
        // L3: the rows of an earlier run of this query on this APK.
        let disk = self.cache.as_ref().and_then(|c| c.disk.as_ref()).filter(|d| d.uses(Tier::Rendered));
        let rendered = disk.zip(key.as_ref()).map(|(d, k)| (d, k, tiers::findrefs_key(query, opts)));
        if let Some(batches) = rendered.as_ref().and_then(|(d, k, q)| d.get_rendered(k, q)).and_then(|b| tiers::decode_batches(&b)) {
            for batch in batches {
                summary.total_results += batch.results.len();
                sink(batch);
            }
            summary.total_us = t0.elapsed().as_micros();
            self.log(format!("[APK] for_each_findrefs total={} us count={} source=result", summary.total_us, entries.len()));
            return Ok(summary);
        }
        let mut recorder = rendered.as_ref().map(|_| tiers::ResultRecorder::new());
        let next = AtomicUsize::new(0);
        let (tx, rx) = mpsc::channel::<RefBatch>();
        let workers = self.threads.min(entries.len()).max(1);
        let cache = self.cache.as_deref();
        let stats = &self.stats;
        let compiled = &compiled;
        std::thread::scope(|s| {
            for _ in 0..workers {
                let tx = tx.clone();
                let (apk, entries, next, key) = (&apk, &entries, &next, key.as_ref());
                s.spawn(move || loop {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(entry) = entries.get(i) else { break };
                    let batch = search_entry(apk, key, entry, compiled, opts, cancel, cache, stats);
                    if tx.send(batch).is_err() {
                        break;
                    }
                });
            }
            drop(tx);
            for batch in rx {
                if self.debug {
                    self.log(format!(
                        "[APK] '{}' {}={} us process={} us results={}{}",
                        batch.entry_name,
                        batch.source,
                        batch.inflate_us,
                        batch.search_us,
                        batch.results.len(),
                        batch.error.as_ref().map(|e| format!(" error={e}")).unwrap_or_default()
                    ));
                }
                summary.total_results += batch.results.len();
                if let Some(r) = recorder.as_mut() {
                    r.record(&batch);
                }
                sink(batch);
            }
        });
        if let (Some((_, k, q)), Some(payload)) = (rendered, recorder.and_then(tiers::ResultRecorder::finish)) {
            // A cancelled run may be missing entries.
            if !cancel.load(Ordering::Relaxed) {
                let job = WriteJob { key: k.clone(), apk: Arc::from(apk.path()), kind: Job::Rendered { query: q, payload } };
                self.cache.as_ref().expect("rendered implies a cache").put_async(job);
            }
        }
        summary.total_us = t0.elapsed().as_micros();
        self.log(format!("[APK] for_each_findrefs total={} us count={} workers={}", summary.total_us, entries.len(), workers));
        Ok(summary)
    }

    /// Fill the context of rows an earlier [`Engine::find_refs`] returned
    /// (typically one page of them): only their DEX files are loaded, from
    /// the cache when it holds them. Returns the entries that failed to load.
    pub fn fill_context(&self, rows: &mut [RefResult], ctx: RefContext) -> Result<Vec<String>> {
        if ctx == RefContext::None || rows.is_empty() {
            return Ok(Vec::new());
        }
        let wanted: HashSet<String> = rows.iter().map(|r| entry_of(&r.dex_name).to_string()).collect();
        let (views, errors) = self.load_views(Some(&wanted))?;
        let mut errors = errors;
        for v in &views {
            let r = Dex::with_name(&v.data, &v.name).map_err(EngineError::from).and_then(|dex| {
                attach_context(&FindRefs::with_state(&dex, &v.state), rows.iter_mut().filter(|r| r.dex_name == v.name), ctx)
            });
            if let Err(e) = r {
                errors.push(format!("{}: {e}", v.name));
            }
        }
        self.recharge_views(&views);
        Ok(errors)
    }

    /// Load DEX entries (every one, or those named in `only`) in parallel,
    /// as logical DEX files in entry order with their locator tables (the
    /// cached ones when the memory cache holds the entry). Entries that fail
    /// to load are reported as `name: error` strings.
    fn load_views(&self, only: Option<&HashSet<String>>) -> Result<(Vec<DexView>, Vec<String>)> {
        let apk = self.open()?;
        let mut entries = apk.dex_entries()?;
        if let Some(only) = only {
            entries.retain(|e| only.contains(&e.name));
        }
        let key = self.apk_key(&apk);
        let next = AtomicUsize::new(0);
        let workers = self.threads.min(entries.len()).max(1);
        let cache = self.cache.as_deref();
        let l2 = cache.and_then(|c| c.disk.as_deref()).filter(|d| d.uses(Tier::Derived)).zip(key.as_ref());
        let mut slots: Vec<Option<std::result::Result<Vec<DexView>, String>>> = (0..entries.len()).map(|_| None).collect();
        let done = Mutex::new(&mut slots);
        std::thread::scope(|s| {
            for _ in 0..workers {
                s.spawn(|| loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(entry) = entries.get(i) else { break };
                    let r = load_entry(&apk, key.as_ref(), entry, cache, &self.stats, None)
                        .map(|(loaded, _)| match loaded {
                            Loaded::Cached(e) => e
                                .logical()
                                .iter()
                                .enumerate()
                                .map(|(idx, l)| {
                                    if let (Some((disk, k)), Ok(dex)) = (l2, Dex::with_name(&l.data, &l.name)) {
                                        if tiers::load_derived(disk, k, l, &dex) {
                                            self.stats.derived_hits.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                    DexView {
                                        name: l.name.clone(),
                                        data: Arc::clone(&l.data),
                                        state: Arc::clone(&l.state),
                                        entry: Some(Arc::clone(&e)),
                                        idx,
                                        mask: l.state.table_mask(),
                                        loaded: Instant::now(),
                                    }
                                })
                                .collect(),
                            borrowed => borrowed
                                .into_logical(&entry.name)
                                .map(|(name, data)| DexView {
                                    name,
                                    data,
                                    state: Arc::new(SearchState::new()),
                                    entry: None,
                                    idx: 0,
                                    mask: 0,
                                    loaded: Instant::now(),
                                })
                                .collect(),
                        })
                        .map_err(|e| format!("{}: {e}", entry.name));
                    done.lock().unwrap()[i] = Some(r);
                });
            }
        });
        let mut views = Vec::new();
        let mut errors = Vec::new();
        for slot in slots.into_iter().flatten() {
            match slot {
                Ok(mut v) => views.append(&mut v),
                Err(e) => errors.push(e),
            }
        }
        Ok((views, errors))
    }

    /// Charge the memory cache for the tables a pass over `views` built,
    /// and queue the new tables for L2.
    fn recharge_views(&self, views: &[DexView]) {
        let Some(cache) = self.cache.as_deref() else { return };
        let Some(key) = self.key_cache.lock().unwrap().as_ref().map(|k| k.2.clone()) else { return };
        let disk = cache.disk.as_deref().filter(|d| d.uses(Tier::Derived));
        let mut seen = HashSet::new();
        for v in views {
            let Some(e) = &v.entry else { continue };
            if let Some(job) = disk.and_then(|d| tiers::derived_job(d, e, v.idx, v.mask, v.loaded.elapsed())) {
                cache.put_async(WriteJob { key: key.clone(), apk: Arc::from(self.apk_path.as_path()), kind: Job::Derived(job) });
            }
            if seen.insert(Arc::as_ptr(e)) {
                recharge(Some(cache), Some(&key), e);
            }
        }
    }

    /// Decode `AndroidManifest.xml`.
    pub fn manifest_xml(&self) -> Result<String> {
        let apk = self.open()?;
        let data = apk.read("AndroidManifest.xml")?;
        Ok(asc_axml::decode(&data)?)
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // A shared cache outlives this engine; its `SharedCache` owner closes it.
        if !self.shared_cache {
            self.close_cache_writes();
        }
    }
}

/// One logical DEX loaded for a pass over the whole APK.
struct DexView {
    name: String,
    data: DexBytes,
    state: Arc<SearchState>,
    /// The memory cache entry holding it, recharged after the pass.
    entry: Option<Arc<CachedEntry>>,
    /// Its index among the entry's logical DEX files.
    idx: usize,
    /// Its tables (`SearchState::table_mask`) when loaded, and when that was:
    /// tables built during the pass are queued for L2 with the pass's time.
    mask: u32,
    loaded: Instant,
}

/// The APK entry a (logical) DEX name belongs to: `classes2.dex!classes1.dex`
/// is the first logical DEX of the `classes2.dex` container.
fn entry_of(dex_name: &str) -> &str {
    dex_name.split('!').next().unwrap_or(dex_name)
}

/// Memory or disk cache lookup (no inflation).
fn lookup_cached(cache: &EngineCache, key: Option<&ApkKey>, entry: &Entry, stats: &Stats) -> Option<(Arc<CachedEntry>, Source)> {
    let key = key?;
    if let Some(mem) = &cache.memory {
        if let Some(e) = mem.lock().unwrap().get(key, &entry.name) {
            stats.memory_hits.fetch_add(1, Ordering::Relaxed);
            return Some((e, Source::Memory));
        }
    }
    if entry.method == asc_apk::METHOD_DEFLATE {
        if let Some(disk) = &cache.disk {
            if let Some(data) = disk.get(key, &entry.name, entry.uncomp_size) {
                stats.disk_hits.fetch_add(1, Ordering::Relaxed);
                let e = Arc::new(CachedEntry::new(&entry.name, Arc::new(data)));
                if let Some(mem) = &cache.memory {
                    // The declared size may be 0 (undeclared) and omits a
                    // container's logical copies; charge what will be resident.
                    let size = e.resident_bytes();
                    mem.lock().unwrap().insert(key, &entry.name, Arc::clone(&e), size);
                    cache.charged();
                }
                return Some((e, Source::Disk));
            }
        }
    }
    None
}

/// Bytes of `entry`: cache → (stored: borrow) → inflate (+ fill caches).
fn load_entry<'a>(
    apk: &'a Apk,
    key: Option<&ApkKey>,
    entry: &Entry,
    cache: Option<&EngineCache>,
    stats: &Stats,
    cancel: Option<&AtomicBool>,
) -> Result<(Loaded<'a>, Source)> {
    if let (Some(c), Some(k)) = (cache, key) {
        if let Some((e, source)) = lookup_cached(c, Some(k), entry, stats) {
            return Ok((Loaded::Cached(e), source));
        }
        // One inflate per entry at a time; whoever waited re-checks the cache.
        let _guard = c.begin_inflate(format!("{}/{}", k.as_str(), entry.name));
        if let Some((e, source)) = lookup_cached(c, Some(k), entry, stats) {
            return Ok((Loaded::Cached(e), source));
        }
        let bytes = apk.read_entry_cancellable(entry, cancel)?;
        let (data, keep_in_memory, source) = match bytes {
            // Stored entries are already free to read; keep them only for the
            // locator tables that ride along with a cached entry (in memory,
            // or through L2). Mapped from the APK file rather than copied, so
            // they stay file pages the OS can share and reclaim.
            Cow::Borrowed(b) => {
                if c.memory.is_none() && !c.disk.as_ref().is_some_and(|d| d.uses(Tier::Derived)) {
                    return Ok((Loaded::Borrowed(Cow::Borrowed(b)), Source::Stored));
                }
                let offset = b.as_ptr() as usize - apk.data().as_ptr() as usize;
                let data = DexData::map_region(apk.path(), offset as u64, b.len()).unwrap_or_else(|_| DexData::Owned(b.to_vec()));
                (data, c.memory.is_some(), Source::Stored)
            }
            Cow::Owned(v) => {
                stats.inflates.fetch_add(1, Ordering::Relaxed);
                (DexData::Owned(v), c.memory.is_some(), Source::Inflate)
            }
        };
        let e = Arc::new(CachedEntry::new(&entry.name, Arc::new(data)));
        let mut remap = None;
        if keep_in_memory {
            if let Some(mem) = &c.memory {
                // Account for the container copies too, so the LRU cap holds.
                let size = e.resident_bytes();
                mem.lock().unwrap().insert(k, &entry.name, Arc::clone(&e), size);
                c.charged();
                remap = Some(Arc::downgrade(&e));
            }
        }
        // Small entries are cheaper to inflate again than to write.
        if source == Source::Inflate && c.disk.as_ref().is_some_and(|d| d.admits_dex(e.data.len() as u64)) {
            let job = WriteJob {
                key: k.clone(),
                apk: Arc::from(apk.path()),
                kind: Job::Dex { name: entry.name.clone(), data: Arc::clone(&e.data), remap },
            };
            c.put_async(job);
        }
        return Ok((Loaded::Cached(e), source));
    }
    let bytes = apk.read_entry_cancellable(entry, cancel)?;
    let source = if matches!(bytes, Cow::Owned(_)) {
        stats.inflates.fetch_add(1, Ordering::Relaxed);
        Source::Inflate
    } else {
        Source::Stored
    };
    Ok((Loaded::Borrowed(bytes), source))
}

/// Decide from a streamed prefix whether `entry` defines the class.
/// `Ok(Some(x))` is a definitive answer; `Ok(None)` means "inflate it fully".
fn probe_entry(apk: &Apk, entry: &Entry, target: &[u8]) -> Result<Option<bool>> {
    /// Entries below this are cheaper to inflate whole.
    const MIN_GAIN: u64 = 256 * 1024;
    /// Room after the last string offset for the string's own bytes.
    const SLACK: usize = 64 * 1024;
    /// Only worth a streaming (slower) decoder below this share of the entry.
    const WORTH_BELOW: f64 = 0.70;
    if entry.method != asc_apk::METHOD_DEFLATE || entry.uncomp_size <= MIN_GAIN {
        return Ok(None);
    }
    let size = entry.uncomp_size as usize;
    let prefix = apk.inflate_until(entry, |out| {
        if out.len() >= 8 && &out[..8] == asc_dex::container::DEX041_MAGIC {
            return asc_apk::PrefixStep::Abort;
        }
        match asc_dex::quick::probe_needed_len(out) {
            Some(needed) if (needed as f64) < size as f64 * WORTH_BELOW => asc_apk::PrefixStep::Continue(needed + SLACK),
            Some(_) => asc_apk::PrefixStep::Abort,
            None => asc_apk::PrefixStep::Continue(0),
        }
    })?;
    let bytes = match prefix {
        asc_apk::Prefix::Complete(data) | asc_apk::Prefix::Partial(data) => data,
        asc_apk::Prefix::Aborted(_) => return Ok(None),
    };
    // A truncated string read means the answer is not provable from the prefix.
    Ok(asc_dex::quick::dex_defines_class(&bytes, target).ok())
}

#[allow(clippy::too_many_arguments)]
fn search_entry(
    apk: &Apk,
    key: Option<&ApkKey>,
    entry: &Entry,
    query: &CompiledQuery,
    opts: FindOptions,
    cancel: &AtomicBool,
    cache: Option<&EngineCache>,
    stats: &Stats,
) -> RefBatch {
    let t0 = Instant::now();
    let mut batch =
        RefBatch { entry_name: entry.name.clone(), results: Vec::new(), inflate_us: 0, search_us: 0, source: "inflate", error: None };
    let (loaded, source) = match load_entry(apk, key, entry, cache, stats, Some(cancel)) {
        Ok(l) => l,
        Err(e) => {
            batch.error = Some(e.to_string());
            return batch;
        }
    };
    batch.source = source.as_str();
    let t1 = Instant::now();
    batch.inflate_us = (t1 - t0).as_micros();
    match &loaded {
        Loaded::Cached(e) => {
            let l2 = cache.and_then(|c| c.disk.as_deref().filter(|d| d.uses(Tier::Derived)).map(|d| (c, d))).zip(key);
            for (i, l) in e.logical().iter().enumerate() {
                let r = Dex::with_name(&l.data, &l.name).map_err(EngineError::from).and_then(|dex| {
                    if let Some(((_, disk), k)) = l2 {
                        if tiers::load_derived(disk, k, l, &dex) {
                            stats.derived_hits.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    let (mask, t) = (l.state.table_mask(), Instant::now());
                    let rows = rows_compiled(&FindRefs::with_state(&dex, &l.state), query, opts);
                    if let Some(((c, disk), k)) = l2 {
                        if let Some(job) = tiers::derived_job(disk, e, i, mask, t.elapsed()) {
                            c.put_async(WriteJob { key: k.clone(), apk: Arc::from(apk.path()), kind: Job::Derived(job) });
                        }
                    }
                    rows
                });
                match r {
                    Ok(mut rows) => batch.results.append(&mut rows),
                    Err(e) => batch.note_error(&l.name, e),
                }
            }
            recharge(cache, key, e);
        }
        Loaded::Borrowed(_) => {
            for (name, buf) in logical_dex_iter(&entry.name, loaded.bytes()) {
                match find_refs_in_dex_compiled(&name, &buf, query, opts) {
                    Ok(mut r) => batch.results.append(&mut r),
                    Err(e) => batch.note_error(&name, e),
                }
            }
        }
    }
    batch.search_us = t1.elapsed().as_micros();
    batch
}

/// Charge the in-memory cache for the locator tables a search just built for
/// `e`, evicting other entries if that exceeds the capacity.
fn recharge(cache: Option<&EngineCache>, key: Option<&ApkKey>, e: &Arc<CachedEntry>) {
    let (Some(mem), Some(key)) = (cache.and_then(|c| c.memory.as_ref()), key) else { return };
    let size = e.charged_bytes();
    {
        let mut mem = mem.lock().unwrap();
        if !mem.charged_bytes(key, &e.name).is_some_and(|old| old != size) {
            return;
        }
        mem.resize(key, &e.name, e, size);
    }
    if let Some(c) = cache {
        c.charged();
    }
}

fn matched_name(dex: &Dex<'_>, kind: RefKind, idx: u32) -> Result<String> {
    Ok(match kind {
        RefKind::String => dex.string(idx)?,
        RefKind::Type => dex.type_descriptor(idx)?,
        RefKind::Method => dex.method_display(idx)?,
        RefKind::Field => dex.field_display(idx)?,
    })
}

/// Run a reference search over one DEX buffer and return structured results.
pub fn find_refs_in_dex(dex_name: &str, buf: &[u8], query: &Query, aggregate: bool) -> Result<Vec<RefResult>> {
    find_refs_in_dex_opts(dex_name, buf, query, FindOptions { aggregate, context: RefContext::None })
}

/// [`find_refs_in_dex`] with a context.
pub fn find_refs_in_dex_opts(dex_name: &str, buf: &[u8], query: &Query, opts: FindOptions) -> Result<Vec<RefResult>> {
    find_refs_in_dex_compiled(dex_name, buf, &CompiledQuery::new(query)?, opts)
}

fn find_refs_in_dex_compiled(dex_name: &str, buf: &[u8], query: &CompiledQuery, opts: FindOptions) -> Result<Vec<RefResult>> {
    let dex = Dex::with_name(buf, dex_name)?;
    rows_compiled(&FindRefs::new(&dex), query, opts)
}

/// Result rows of `query` over the DEX `fr` searches: class relation rows
/// straight from the class definitions, otherwise the code scan's hits.
fn rows_compiled(fr: &FindRefs<'_, '_, '_>, query: &CompiledQuery, opts: FindOptions) -> Result<Vec<RefResult>> {
    let dex = fr.dex();
    let Some(classes) = fr.class_relation(query)? else {
        let hits = fr.find_ref_compiled(query)?;
        let mut rows = results_from_hits(dex, query.kind(), &hits, opts.aggregate)?;
        if opts.context != RefContext::None {
            attach_context(fr, &mut rows, opts.context)?;
        }
        return Ok(rows);
    };
    let target = match query.query() {
        Query::Extends(t) | Query::Implements(t) => t.as_str(),
        _ => "",
    };
    let dex_name = dex.name().to_string();
    classes
        .into_iter()
        .map(|c| {
            Ok(RefResult {
                dex_name: dex_name.clone(),
                method_idx: c,
                method: dex.type_descriptor(c)?,
                matched: vec![target.to_string()],
                relation: query.relation(),
                sites: Vec::new(),
                context: None,
            })
        })
        .collect()
}

/// Turn raw hits into display results (grouped per method when `aggregate`).
pub fn results_from_hits(dex: &Dex<'_>, kind: RefKind, hits: &[Hit], aggregate: bool) -> Result<Vec<RefResult>> {
    let dex_name = dex.name().to_string();
    if !aggregate {
        let mut out = Vec::new();
        for hit in hits {
            let Some(methods) = &hit.methods else { continue };
            let matched = matched_name(dex, kind, hit.matched_idx)?;
            for &m in methods.ids() {
                out.push(RefResult {
                    dex_name: dex_name.clone(),
                    method_idx: m,
                    method: dex.method_display(m)?,
                    matched: vec![matched.clone()],
                    relation: None,
                    sites: vec![RefSite { offset: hit.offset, matched: 0, pc: None, line: None }],
                    context: None,
                });
            }
        }
        return Ok(out);
    }
    // method -> (matched indexes, (offset, matched index) per hit)
    type Group = (std::collections::BTreeSet<u32>, Vec<(u32, u32)>);
    let mut grouped: BTreeMap<u32, Group> = BTreeMap::new();
    for hit in hits {
        let Some(methods) = &hit.methods else { continue };
        for &m in methods.ids() {
            let g = grouped.entry(m).or_default();
            g.0.insert(hit.matched_idx);
            g.1.push((hit.offset, hit.matched_idx));
        }
    }
    let mut out = Vec::with_capacity(grouped.len());
    for (m, (idxs, offsets)) in grouped {
        let idxs: Vec<u32> = idxs.into_iter().collect();
        let matched = idxs.iter().map(|&i| matched_name(dex, kind, i)).collect::<Result<Vec<_>>>()?;
        let sites = offsets
            .into_iter()
            .map(|(offset, idx)| RefSite { offset, matched: idxs.binary_search(&idx).unwrap_or(0), pc: None, line: None })
            .collect();
        out.push(RefResult {
            dex_name: dex_name.clone(),
            method_idx: m,
            method: dex.method_display(m)?,
            matched,
            relation: None,
            sites,
            context: None,
        });
    }
    Ok(out)
}

/// Fill the sites' `pc` / `line` and the `context` of rows found in `fr`'s DEX.
/// A method that cannot be rendered gets a `# context unavailable` comment.
fn attach_context<'r>(fr: &FindRefs<'_, '_, '_>, rows: impl IntoIterator<Item = &'r mut RefResult>, ctx: RefContext) -> Result<()> {
    let dex = fr.dex();
    let bounds = fr.insn_locator()?.method_bounds();
    for row in rows {
        let start = bounds.get(row.method_idx as usize).copied().unwrap_or(u32::MAX);
        let listing = match asc_smali::disassemble_method(dex, row.method_idx, SmaliOptions::default()) {
            Ok(l) => l,
            Err(e) => {
                row.context = Some(format!("  # context unavailable: {e}\n"));
                continue;
            }
        };
        for site in &mut row.sites {
            if let Some(pc) = site.offset.checked_sub(start).filter(|_| start != u32::MAX).map(|b| b / 2) {
                site.pc = Some(pc);
                site.line = listing.source_line(pc);
            }
        }
        row.context = Some(render_context(&listing, &row.sites, ctx));
    }
    Ok(())
}

/// Most smali lines one row's context shows; beyond it the rest is summarised.
const CONTEXT_MAX_LINES: usize = 150;
/// A whole method longer than [`CONTEXT_MAX_LINES`] shows this many lines
/// around each reference instead.
const METHOD_FALLBACK_LINES: usize = 10;

/// Context block of one row: an `@` line listing the sites, then the smali
/// (`>` marks the referencing instructions; windows are separated by `--`).
fn render_context(listing: &asc_smali::MethodListing, sites: &[RefSite], ctx: RefContext) -> String {
    let mut out = String::from("  @");
    for (i, s) in sites.iter().enumerate() {
        out.push_str(if i == 0 { " " } else { ", " });
        match (s.pc, s.line) {
            (Some(pc), Some(line)) => out.push_str(&format!("pc 0x{pc:x} line {line}")),
            (Some(pc), None) => out.push_str(&format!("pc 0x{pc:x}")),
            _ => out.push_str(&format!("offset 0x{:x}", s.offset)),
        }
    }
    out.push('\n');
    let lines: Vec<&str> = listing.text.lines().collect();
    let mut hits: Vec<usize> = sites.iter().filter_map(|s| s.pc).filter_map(|pc| listing.line_of(pc)).map(|l| l as usize).collect();
    hits.sort_unstable();
    hits.dedup();
    let around = |n: usize| {
        let mut w: Vec<(usize, usize)> = Vec::new();
        for &h in &hits {
            let (a, b) = (h.saturating_sub(n), (h + n + 1).min(lines.len()));
            match w.last_mut() {
                Some(last) if a <= last.1 => last.1 = last.1.max(b),
                _ => w.push((a, b)),
            }
        }
        w
    };
    let windows = match ctx {
        RefContext::None => return out,
        RefContext::Method if lines.len() <= CONTEXT_MAX_LINES => vec![(0, lines.len())],
        RefContext::Method => {
            out.push_str(&format!("  # method has {} lines; showing {METHOD_FALLBACK_LINES} around each reference\n", lines.len()));
            around(METHOD_FALLBACK_LINES)
        }
        RefContext::Lines(n) => around(n),
    };
    let mut shown = 0;
    for (i, &(a, b)) in windows.iter().enumerate() {
        if shown + (b - a) > CONTEXT_MAX_LINES {
            let rest: usize = windows[i..].iter().map(|w| w.1 - w.0).sum::<usize>();
            out.push_str(&format!("  # cut at {CONTEXT_MAX_LINES} lines ({rest} more); read the method with getclass\n"));
            break;
        }
        if i > 0 {
            out.push_str("  --\n");
        }
        for (j, line) in lines[a..b].iter().enumerate() {
            out.push_str(if hits.binary_search(&(a + j)).is_ok() { "  > " } else { "    " });
            out.push_str(line);
            out.push('\n');
        }
        shown += b - a;
    }
    out
}

/// Python `AscHandler.findrefs` equivalent: formatted lines for one DEX.
pub fn find_refs_lines(dex_name: &str, buf: &[u8], query: &Query, aggregate: bool) -> Result<Vec<String>> {
    Ok(find_refs_in_dex(dex_name, buf, query, aggregate)?.iter().map(RefResult::line).collect())
}

/// Rebuild `descriptor` out of `buf` and disassemble it.
pub fn decompile_dex_class(buf: &[u8], descriptor: &str, opts: SmaliOptions) -> Result<(Rebuilt, String)> {
    decompile_dex_class_method(buf, descriptor, opts, None)
}

/// [`decompile_dex_class`] rendering only `method` (`name(params)ret`) when given.
pub fn decompile_dex_class_method(buf: &[u8], descriptor: &str, opts: SmaliOptions, method: Option<&str>) -> Result<(Rebuilt, String)> {
    let dex = Dex::parse(buf)?;
    let rebuilt = asc_rebuild::rebuild_class(&dex, descriptor)?;
    let new_dex = Dex::parse(&rebuilt.bytes)?;
    let source = asc_smali::disassemble_class_method(&new_dex, descriptor, opts, method)?;
    Ok((rebuilt, source))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_budget_is_a_clamped_quarter_of_available_memory() {
        assert_eq!(auto_memory_bytes_for(None), AUTO_MEMORY_MAX);
        assert_eq!(auto_memory_bytes_for(Some(4 << 30)), 1 << 30);
        assert_eq!(auto_memory_bytes_for(Some(8 << 30)), AUTO_MEMORY_MAX);
        assert_eq!(auto_memory_bytes_for(Some(64 << 30)), AUTO_MEMORY_MAX);
        assert_eq!(auto_memory_bytes_for(Some((8 << 30) - 4)), (2 << 30) - 1);
        assert_eq!(auto_memory_bytes_for(Some(100 << 20)), AUTO_MEMORY_MIN);
        assert_eq!(auto_memory_bytes_for(Some(0)), AUTO_MEMORY_MIN);
        assert_eq!(auto_memory_bytes_for(Some(u64::MAX)), AUTO_MEMORY_MAX);
        let auto = auto_memory_bytes();
        assert!((AUTO_MEMORY_MIN..=AUTO_MEMORY_MAX).contains(&auto));
    }

    #[test]
    fn meminfo_and_cgroup_parsing() {
        let meminfo = "MemTotal:       12000000 kB\nMemFree:          500000 kB\nMemAvailable:    8000000 kB\n";
        assert_eq!(meminfo_available(meminfo), Some(8_000_000 * 1024));
        assert_eq!(meminfo_available("MemTotal: 1 kB\n"), None);
        assert_eq!(meminfo_available("MemAvailable: lots kB\n"), None);
        assert_eq!(cgroup_headroom_from("max\n", "123\n"), None);
        assert_eq!(cgroup_headroom_from("1000\n", "300\n"), Some(700));
        assert_eq!(cgroup_headroom_from("1000\n", "3000\n"), Some(0));
    }
}
