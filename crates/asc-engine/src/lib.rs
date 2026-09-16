//! The Droid ASC engine: stateless, zero-preprocessing queries against an APK.
//!
//! * [`Engine::get_class_dex`] inflates the DEX entries in parallel (smallest
//!   first) and stops as soon as one defines the requested class.
//! * [`Engine::find_refs`] runs a reference search over every DEX entry in
//!   parallel and streams results back as each DEX completes.
//! * [`Engine::get_class`] rebuilds a minimal DEX containing only the target
//!   class and renders it as smali.
//! * [`Engine::manifest_xml`] decodes the binary `AndroidManifest.xml`.
//!
//! Optionally the engine keeps inflated DEX entries in an on-disk cache
//! (shared across processes) and/or an in-memory LRU together with the locator
//! tables built for them, so repeated queries skip inflation and table builds.
//! Disk writes happen on a background thread so a query never waits on them;
//! [`Engine::flush_cache_writes`] waits for them to land and [`Engine::close_cache_writes`]
//! (run on drop) additionally stops queueing new ones.

pub mod names;

use asc_apk::{Apk, Entry};
use asc_cache::{ApkKey, DexData, DiskCache, MemoryCache};
use asc_dex::container::{dex041_logical_offsets, logical_dex_buffers};
use asc_dex::Dex;
use asc_findrefs::{CompiledQuery, FindRefs, Hit, Query, RefKind, SearchState};
use asc_rebuild::Rebuilt;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, OnceLock};
use std::time::{Instant, SystemTime};

pub use asc_cache;
pub use asc_findrefs::{ClassQuery, MemberQuery};
pub use asc_smali::Options as SmaliOptions;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefResult {
    pub dex_name: String,
    pub method_idx: u32,
    /// `Lcls;->name`
    pub method: String,
    /// Display names of the matched constants (strings, descriptors, members).
    pub matched: Vec<String>,
}

impl RefResult {
    /// The Python CLI line format: `dex | Lcls;->m | matched=(a; b)`.
    pub fn line(&self) -> String {
        format!("{} | {} | matched=({})", self.dex_name, self.method, self.matched.join("; "))
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
pub struct CacheConfig {
    /// In-memory LRU capacity for inflated entries (0 disables it).
    pub memory_bytes: usize,
    /// On-disk cache shared across processes.
    pub disk: Option<DiskCache>,
}

impl CacheConfig {
    /// Disk cache in the default directory, no in-memory cache (CLI default).
    pub fn disk_default() -> CacheConfig {
        CacheConfig { memory_bytes: 0, disk: DiskCache::open_default() }
    }

    /// Disk cache plus an in-memory LRU (GUI / server default).
    pub fn resident(memory_bytes: usize) -> CacheConfig {
        CacheConfig { memory_bytes, disk: DiskCache::open_default() }
    }
}

/// One logical DEX of a cached entry with its lazily built locator tables.
pub struct LogicalDex {
    pub name: String,
    pub data: DexBytes,
    pub state: SearchState,
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
                    LogicalDex { name, data, state: SearchState::new() }
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
}

/// A queued disk write: the bytes are shared with the query that produced
/// them, so queueing costs nothing.
struct WriteJob {
    key: ApkKey,
    name: String,
    data: DexBytes,
}

struct Writer {
    tx: mpsc::Sender<WriteJob>,
    handle: std::thread::JoinHandle<()>,
}

struct EngineCache {
    memory: Option<Mutex<MemoryCache<CachedEntry>>>,
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
    fn put_async(&self, key: &ApkKey, name: &str, data: &DexBytes) {
        let Some(disk) = &self.disk else { return };
        let job = WriteJob { key: key.clone(), name: name.to_string(), data: Arc::clone(data) };
        let mut writer = self.writer.lock().unwrap();
        if self.closed.load(Ordering::Relaxed) {
            return;
        }
        if writer.is_none() {
            let (tx, rx) = mpsc::channel::<WriteJob>();
            let thread_disk = Arc::clone(disk);
            let spawned = std::thread::Builder::new().name("droidasc-cache-writer".into()).spawn(move || {
                let mut pending: Option<WriteJob> = None;
                loop {
                    let job = match pending.take() {
                        Some(j) => j,
                        None => match rx.recv() {
                            Ok(j) => j,
                            Err(_) => break,
                        },
                    };
                    let _ = thread_disk.put(&job.key, &job.name, &job.data);
                    // Walk the cache directory once per burst, not once per entry.
                    match rx.try_recv() {
                        Ok(next) => pending = Some(next),
                        Err(_) => thread_disk.evict(),
                    }
                }
            });
            match spawned {
                Ok(handle) => *writer = Some(Writer { tx, handle }),
                Err(_) => {
                    let _ = disk.put(&job.key, &job.name, &job.data);
                    disk.evict();
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

    fn begin_inflate(&self, id: String) -> InflightGuard<'_> {
        let mut set = self.inflight.lock().unwrap();
        while set.contains(&id) {
            set = self.inflight_done.wait(set).unwrap();
        }
        set.insert(id.clone());
        InflightGuard { cache: self, id }
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

impl Loaded<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Loaded::Borrowed(c) => c,
            Loaded::Cached(e) => &e.data,
        }
    }

    /// Logical DEX buffers, moving the inflated bytes instead of copying them
    /// when the entry is a plain (non-container) DEX.
    fn into_logical(self, entry_name: &str) -> Vec<(String, DexBytes)> {
        match self {
            Loaded::Cached(e) => e.logical().iter().map(|l| (l.name.clone(), Arc::clone(&l.data))).collect(),
            Loaded::Borrowed(c) => {
                let bufs = logical_dex_buffers(entry_name, &c);
                if matches!(bufs.as_slice(), [(_, Cow::Borrowed(b))] if b.len() == c.len()) {
                    drop(bufs);
                    return vec![(entry_name.to_string(), Arc::new(DexData::Owned(c.into_owned())))];
                }
                bufs.into_iter().map(|(n, b)| (n, Arc::new(DexData::Owned(b.into_owned())))).collect()
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
    stats: Arc<Stats>,
    /// `(size, mtime, key)` of the APK the key was last computed for.
    key_cache: Mutex<Option<(u64, Option<SystemTime>, ApkKey)>>,
}

#[derive(Default)]
struct Stats {
    memory_hits: AtomicUsize,
    disk_hits: AtomicUsize,
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
            stats: Arc::new(Stats::default()),
            key_cache: Mutex::new(None),
        }
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
        if config.memory_bytes == 0 && config.disk.is_none() {
            self.cache = None;
        } else {
            self.cache = Some(Arc::new(EngineCache {
                memory: (config.memory_bytes > 0).then(|| Mutex::new(MemoryCache::new(config.memory_bytes))),
                disk: config.disk.map(Arc::new),
                writer: Mutex::new(None),
                closed: AtomicBool::new(false),
                inflight: Mutex::new(HashSet::new()),
                inflight_done: Condvar::new(),
            }));
        }
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
            inflates: self.stats.inflates.load(Ordering::Relaxed) as u64,
        }
    }

    /// Bytes currently held by the in-memory cache.
    pub fn memory_cache_bytes(&self) -> usize {
        self.cache.as_ref().and_then(|c| c.memory.as_ref()).map(|m| m.lock().unwrap().used_bytes()).unwrap_or(0)
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
        Ok(Apk::open(&self.apk_path)?)
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
        let target: Arc<Vec<u8>> = Arc::new(descriptor.as_bytes().to_vec());
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
        let t0 = Instant::now();
        let hit = self.get_class_dex(descriptor)?.ok_or_else(|| EngineError::ClassNotFound(descriptor.to_string()))?;
        let scan_us = t0.elapsed().as_micros();
        let (rebuilt, source, warning) = match decompile_dex_class(&hit.dex, descriptor, opts) {
            Ok((r, s)) => (Some(r), s, None),
            // The class is there but cannot be rebuilt faithfully (undefined
            // opcode, invoke-custom, too many members for 16-bit indexes...):
            // still show it, disassembled from the original DEX, and say why
            // there is no DEX to dump.
            Err(EngineError::Rebuild(e)) if e.is_input_limitation() => {
                let dex = Dex::with_name(&hit.dex, &hit.dex_name)?;
                let source = asc_smali::disassemble_class(&dex, descriptor, opts)?;
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
                    let batch = search_entry(apk, key, entry, compiled, aggregate, cancel, cache, stats);
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
                sink(batch);
            }
        });
        summary.total_us = t0.elapsed().as_micros();
        self.log(format!("[APK] for_each_findrefs total={} us count={} workers={}", summary.total_us, entries.len(), workers));
        Ok(summary)
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
        self.close_cache_writes();
    }
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
            // Stored entries are already free to read; keep them in memory only
            // for the locator tables that ride along with the cached entry.
            Cow::Borrowed(b) => {
                if c.memory.is_none() {
                    return Ok((Loaded::Borrowed(Cow::Borrowed(b)), Source::Stored));
                }
                (b.to_vec(), true, Source::Stored)
            }
            Cow::Owned(v) => {
                stats.inflates.fetch_add(1, Ordering::Relaxed);
                (v, c.memory.is_some(), Source::Inflate)
            }
        };
        let e = Arc::new(CachedEntry::new(&entry.name, Arc::new(DexData::Owned(data))));
        if source == Source::Inflate {
            c.put_async(k, &entry.name, &e.data);
        }
        if keep_in_memory {
            if let Some(mem) = &c.memory {
                // Account for the container copies too, so the LRU cap holds.
                let size = e.resident_bytes();
                mem.lock().unwrap().insert(k, &entry.name, Arc::clone(&e), size);
            }
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
    aggregate: bool,
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
            for l in e.logical() {
                let r = Dex::with_name(&l.data, &l.name).map_err(EngineError::from).and_then(|dex| {
                    FindRefs::with_state(&dex, &l.state)
                        .find_ref_compiled(query)
                        .map_err(EngineError::from)
                        .and_then(|hits| results_from_hits(&dex, query.kind(), &hits, aggregate))
                });
                match r {
                    Ok(mut rows) => batch.results.append(&mut rows),
                    Err(e) => batch.note_error(&l.name, e),
                }
            }
        }
        Loaded::Borrowed(_) => {
            for (name, buf) in logical_dex_buffers(&entry.name, loaded.bytes()) {
                match find_refs_in_dex_compiled(&name, &buf, query, aggregate) {
                    Ok(mut r) => batch.results.append(&mut r),
                    Err(e) => batch.note_error(&name, e),
                }
            }
        }
    }
    batch.search_us = t1.elapsed().as_micros();
    batch
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
    find_refs_in_dex_compiled(dex_name, buf, &CompiledQuery::new(query)?, aggregate)
}

fn find_refs_in_dex_compiled(dex_name: &str, buf: &[u8], query: &CompiledQuery, aggregate: bool) -> Result<Vec<RefResult>> {
    let dex = Dex::with_name(buf, dex_name)?;
    let fr = FindRefs::new(&dex);
    let hits = fr.find_ref_compiled(query)?;
    results_from_hits(&dex, query.kind(), &hits, aggregate)
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
                });
            }
        }
        return Ok(out);
    }
    let mut grouped: BTreeMap<u32, std::collections::BTreeSet<u32>> = BTreeMap::new();
    for hit in hits {
        let Some(methods) = &hit.methods else { continue };
        for &m in methods.ids() {
            grouped.entry(m).or_default().insert(hit.matched_idx);
        }
    }
    let mut out = Vec::with_capacity(grouped.len());
    for (m, idxs) in grouped {
        let matched = idxs.into_iter().map(|i| matched_name(dex, kind, i)).collect::<Result<Vec<_>>>()?;
        out.push(RefResult { dex_name: dex_name.clone(), method_idx: m, method: dex.method_display(m)?, matched });
    }
    Ok(out)
}

/// Python `AscHandler.findrefs` equivalent: formatted lines for one DEX.
pub fn find_refs_lines(dex_name: &str, buf: &[u8], query: &Query, aggregate: bool) -> Result<Vec<String>> {
    Ok(find_refs_in_dex(dex_name, buf, query, aggregate)?.iter().map(RefResult::line).collect())
}

/// Rebuild `descriptor` out of `buf` and disassemble it.
pub fn decompile_dex_class(buf: &[u8], descriptor: &str, opts: SmaliOptions) -> Result<(Rebuilt, String)> {
    let dex = Dex::parse(buf)?;
    let rebuilt = asc_rebuild::rebuild_class(&dex, descriptor)?;
    let new_dex = Dex::parse(&rebuilt.bytes)?;
    let source = asc_smali::disassemble_class(&new_dex, descriptor, opts)?;
    Ok((rebuilt, source))
}
