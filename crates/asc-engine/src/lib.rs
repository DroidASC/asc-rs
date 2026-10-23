//! The asc-rs engine: stateless, zero-preprocessing queries against an APK.
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

mod budget;
mod callgraph;
mod classes;
mod compact;
mod compose;
pub mod condition;
pub mod config;
mod defs;
mod hierarchy;
pub mod hints;
mod manifest;
pub mod names;
mod prebuild;
mod resident;
mod resources;
mod rules;
mod skip;
mod sweep;
pub mod text;
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
use std::time::{Duration, Instant, SystemTime};

pub use asc_apk::archive_of;
pub use asc_apk::Limits as InflateLimits;
pub use asc_arsc;
pub use asc_cache;
pub use asc_findrefs::{ClassQuery, ClassRelation, MemberQuery};
pub use asc_smali::Options as SmaliOptions;
pub use budget::{available_memory, total_memory, Device, MemoryPolicy};
pub use callgraph::{CallQuery, CallRoots, CallRow, CallTree, Direction};
pub use classes::{dex_classes, ClassListing, DexClasses, EntryClasses};
pub use compact::TextRows;
pub use compose::{MatchingMethods, DEFAULT_FAN_OUT};
pub use hierarchy::{HierarchyQuery, HierarchyRow, HierarchyTree, Lineage};
pub use manifest::{protection_level_name, Application, Component, DataSpec, IntentFilter, ManifestSummary, Permission};
pub use prebuild::PrebuildReport;
pub use resources::{parse_id, ResourceField, ResourceRow};
pub use rules::compile_rules;
pub use sweep::{Claim, DexDedup};
pub use tiers::{auto_threads, auto_threads_for, Busy};

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
    #[error(transparent)]
    Arsc(#[from] asc_arsc::ArscError),
    /// `hint` (empty, or starting with `:` / `;`) says why and what to try.
    #[error("class {class} not found in APK{hint}")]
    ClassNotFound { class: String, hint: String },
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
    /// In a program, the DEX files of other archives that define the class
    /// too (the hit is the first archive's, in program order).
    pub also_defined_in: Vec<String>,
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
    /// See [`ClassHit::also_defined_in`].
    pub also_defined_in: Vec<String>,
}

/// One aggregated reference result: a method and what it references.
///
/// For a class relation query (`Extends` / `Implements`) the row is a class
/// instead: `method_idx` is its type index, `method` and `signature` its
/// descriptor, `matched` the target descriptor and `relation` is set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefResult {
    pub dex_name: String,
    pub method_idx: u32,
    /// `Lcls;->name`
    pub method: String,
    /// `Lcls;->name(params)ret`
    pub signature: String,
    /// The matched constants (strings, descriptors, members).
    pub matched: Vec<Matched>,
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

/// A constant a [`RefResult`] matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Matched {
    /// The value of a string constant.
    String(String),
    /// A type descriptor, `Lcls;->name(params)ret` or `Lcls;->name:type`.
    Symbol(String),
}

impl Matched {
    /// The string value or the symbol, unquoted.
    pub fn as_str(&self) -> &str {
        match self {
            Matched::String(s) | Matched::Symbol(s) => s,
        }
    }
}

/// Strings are quoted and escaped (one line, readable as JSON); symbols are
/// written as they are, since descriptors never hold `, ` or a newline.
impl std::fmt::Display for Matched {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Matched::String(s) => f.write_str(&text::quoted(s)),
            Matched::Symbol(s) => f.write_str(s),
        }
    }
}

impl RefResult {
    /// `dex | Lcls;->m(params)ret | "a", Lx;->f:I`, or `dex | Lsub; | extends
    /// Lbase;` for a class relation: three `|` columns, one line.
    pub fn line(&self) -> String {
        let matched = self.matched.iter().map(Matched::to_string).collect::<Vec<_>>().join(", ");
        match self.relation {
            Some(rel) => format!("{} | {} | {} {matched}", self.dex_name, self.signature, rel.verb()),
            None => format!("{} | {} | {matched}", self.dex_name, self.signature),
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
    /// The rows as text instead, for [`Engine::find_refs_text`] (`results`
    /// is then empty).
    pub text: Option<TextRows>,
    pub inflate_us: u128,
    pub search_us: u128,
    /// Where the bytes came from: `inflate`, `memory`, `disk` or `stored`.
    pub source: &'static str,
    pub error: Option<String>,
}

impl RefBatch {
    /// The number of rows, in `results` or `text`.
    pub fn row_count(&self) -> usize {
        self.results.len() + self.text.as_ref().map_or(0, TextRows::len)
    }

    /// Record a failure of one logical DEX of this entry. A container holds
    /// several, so failures accumulate instead of overwriting each other.
    /// Consumers prefix `entry_name`; only a container's logical DEX (whose
    /// name differs) adds its own.
    fn note_error(&mut self, name: &str, e: &str) {
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
    /// What the search left out on purpose, e.g. a supertype method a
    /// dispatch set did not follow; one line each, for `#` lines or hints.
    pub notes: Vec<String>,
}

/// Cache configuration for an [`Engine`].
pub struct CacheConfig {
    /// In-memory LRU capacity for inflated entries (0 disables it).
    pub memory_bytes: usize,
    /// On-disk cache shared across processes.
    pub disk: Option<DiskCache>,
    /// Treat `memory_bytes` as a starting point and keep resizing the LRU to
    /// this process's share of one budget for every resident host the user
    /// runs ([`MemoryPolicy::share`]), instead of a fixed capacity.
    pub memory_auto: Option<MemoryPolicy>,
    /// Heap queued disk writes may hold before new ones are deferred
    /// ([`WriteJob::defer`]); a memory cache's budget lowers it further.
    pub write_queue_bytes: usize,
    /// Disk writer threads (`None`: [`CacheConfig::auto_writers`]).
    pub writers: Option<usize>,
}

impl CacheConfig {
    /// Default of [`CacheConfig::write_queue_bytes`]. A cold multi-APK sweep
    /// inflates far faster than the writers persist, and each queued job
    /// keeps its DEX bytes or tables alive until written; without a bound the
    /// heap grows with the backlog (tens of GB over a phone's APKs).
    pub const WRITE_QUEUE: usize = 512 << 20;
    /// Most automatic writer threads: writing is I/O, but a deferred L1
    /// write inflates its entry again first.
    pub const MAX_AUTO_WRITERS: usize = 4;

    /// Disk cache in the default directory, no in-memory cache (CLI default).
    pub fn disk_default() -> CacheConfig {
        CacheConfig { disk: DiskCache::open_default(), ..CacheConfig::default() }
    }

    /// Disk cache plus an in-memory LRU of a fixed capacity.
    pub fn resident(memory_bytes: usize) -> CacheConfig {
        CacheConfig { memory_bytes, disk: DiskCache::open_default(), ..CacheConfig::default() }
    }

    /// One writer per 8 CPUs, 1..=[`CacheConfig::MAX_AUTO_WRITERS`].
    pub fn auto_writers(cpus: usize) -> usize {
        (cpus / 8).clamp(1, CacheConfig::MAX_AUTO_WRITERS)
    }
}

impl Default for CacheConfig {
    fn default() -> CacheConfig {
        CacheConfig { memory_bytes: 0, disk: None, memory_auto: None, write_queue_bytes: CacheConfig::WRITE_QUEUE, writers: None }
    }
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

    /// Bytes counted against the memory budget besides the cache's entries
    /// ([`SharedCache::set_reserved`]).
    pub fn memory_reserved(&self) -> usize {
        self.0.as_ref().and_then(|c| c.memory.as_ref()).map(|m| m.lock().unwrap().reserved_bytes()).unwrap_or(0)
    }

    /// Count `bytes` the host holds outside the cache (the class graphs and
    /// resource tables of its engines, [`Engine::resident_bytes`]) against
    /// the memory budget: the cache evicts entries to make room for them.
    pub fn set_reserved(&self, bytes: usize) {
        if let Some(m) = self.0.as_ref().and_then(|c| c.memory.as_ref()) {
            m.lock().unwrap().set_reserved(bytes);
        }
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

/// The memory cache charges file-backed bytes (mapped from the disk cache
/// or the APK) at this fraction of their size, heap bytes in full.
///
/// File pages are not what runs a machine out of memory: the kernel drops
/// clean ones under pressure (they are re-read from the file) and every
/// process mapping the same L1 / L2 file or APK shares one copy, so charging
/// them in full made each of N processes evict as if it held its own copy,
/// and summed to N times the real footprint in the process registry
/// (`MemAvailable`, which the budget starts from, already counts reclaimable
/// page cache). They still cost something (address space, page cache churn,
/// the re-reads), so they are not free either: the LRU still bounds them, at
/// up to this many times the budget.
pub const MAPPED_CHARGE_DIVISOR: usize = 8;

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

    /// What the in-memory cache charges for this entry: heap bytes in full
    /// (the inflated entry when not mapped, a container's logical copies,
    /// tables built on the heap) and file-backed bytes (the entry mapped from
    /// L1 or the APK, tables mapped from L2) at 1/[`MAPPED_CHARGE_DIVISOR`].
    pub fn charged_bytes(&self) -> usize {
        let copies = dex041_logical_offsets(&self.data).len();
        let len = self.data.len();
        let own =
            if self.is_mapped() { (len / MAPPED_CHARGE_DIVISOR) * copies.min(1) + len * copies.saturating_sub(1) } else { len * copies };
        let tables = self
            .logical
            .get()
            .map_or(0, |l| l.iter().map(|d| d.state.heap_bytes() + d.state.mapped_bytes() / MAPPED_CHARGE_DIVISOR).sum::<usize>());
        own + tables
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

/// How often a call waiting on its workers checks for cancellation.
const CANCEL_POLL: Duration = Duration::from_millis(20);

/// The flag of a call nobody cancels.
pub(crate) static NOT_CANCELLED: AtomicBool = AtomicBool::new(false);

/// What a cancelled call returns.
pub(crate) fn cancelled() -> EngineError {
    asc_apk::ApkError::Cancelled.into()
}

impl WriteJob {
    /// Heap the job keeps alive until written. L3 payloads are small and
    /// not counted.
    fn held_bytes(&self) -> usize {
        match &self.kind {
            Job::Dex { data, .. } => data.len(),
            Job::Derived(d) => d.held_bytes(),
            Job::Graph { graph, .. } => graph.heap_bytes(),
            Job::Rendered { .. } | Job::Reinflate { .. } => 0,
        }
    }

    /// The job without the bytes it holds, for a full queue. An L1 entry is
    /// inflated again from the APK when its turn comes, so a cold sweep still
    /// leaves L1 complete; L2 tables and the class graph cannot be rebuilt
    /// by a writer and are released (`None`) for a later query to queue again.
    fn defer(self) -> Option<WriteJob> {
        let WriteJob { key, apk, kind } = self;
        let kind = match kind {
            Job::Dex { entry, limits, remap, .. } => Job::Reinflate { entry, limits, remap },
            Job::Derived(d) => {
                d.abandon();
                return None;
            }
            Job::Graph { .. } => return None,
            kind @ (Job::Rendered { .. } | Job::Reinflate { .. }) => kind,
        };
        Some(WriteJob { key, apk, kind })
    }

    /// Dropped unwritten: an L1 entry is simply written by a later query;
    /// L2 tables must be released for one to queue them again.
    fn abandon(self) {
        if let Job::Derived(d) = self.kind {
            d.abandon();
        }
    }
}

enum Job {
    /// An inflated entry for L1: the bytes are shared with the query that
    /// produced them, so queueing costs nothing.
    Dex {
        entry: Entry,
        /// The APK's read limits, should the write be deferred.
        limits: Limits,
        data: DexBytes,
        /// The in-memory cache entry holding `data`, if any: once the file is
        /// in place its heap bytes are swapped for a mapping of that file.
        remap: Option<Weak<CachedEntry>>,
    },
    /// An L1 write deferred by a full queue: the writer inflates `entry`
    /// again (if the APK is unchanged and the file still missing).
    Reinflate { entry: Entry, limits: Limits, remap: Option<Weak<CachedEntry>> },
    /// Locator tables for L2.
    Derived(tiers::DerivedJob),
    /// A query result for L3.
    Rendered { query: String, payload: Vec<u8> },
    /// The class graph for L2, serialised by the writer; `cost` is what
    /// building it took.
    Graph { graph: Arc<hierarchy::ClassGraph>, cost: Duration },
}

struct Writer {
    /// Each job with its [`WriteJob::held_bytes`] when queued.
    tx: mpsc::Sender<(WriteJob, usize)>,
    handles: Vec<std::thread::JoinHandle<()>>,
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
    /// L2 writes queued and not yet written: their tables stay on the heap
    /// until written and mapped, so a prebuild waits while this is high.
    derived_pending: Arc<AtomicUsize>,
    /// Heap held by queued writes, bounded by [`EngineCache::queue_cap`].
    pending_bytes: Arc<AtomicUsize>,
    /// [`CacheConfig::write_queue_bytes`].
    queue_cap: usize,
    /// [`CacheConfig::writers`].
    writers: Option<usize>,
}

impl EngineCache {
    /// Heap the queued writes may hold: [`CacheConfig::write_queue_bytes`], or the
    /// memory cache's budget when smaller. The budget is this process's share
    /// of the user's (`--memory-mb`, or split over the registered processes):
    /// sixteen servers sweeping at once would otherwise each queue 512 MiB
    /// whatever their caches may hold.
    fn queue_cap(&self) -> usize {
        let budget = self.memory.as_ref().map_or(usize::MAX, |m| m.lock().unwrap().capacity_bytes());
        self.queue_cap.min(budget)
    }

    /// Queue a disk write; falls back to a synchronous write only when no
    /// writer thread can be started. A write that would take the queued heap
    /// past [`EngineCache::queue_cap`] is queued without its bytes instead
    /// ([`WriteJob::defer`]): the query never waits for the disk, the heap
    /// stays bounded, and L1 still ends up complete.
    fn put_async(&self, job: WriteJob) {
        let Some(disk) = &self.disk else { return };
        // Before the writer lock: never hold it while waiting for the memory cache's.
        let cap = self.queue_cap();
        let mut writer = self.writer.lock().unwrap();
        if self.closed.load(Ordering::Relaxed) {
            return;
        }
        let pending = self.pending_bytes.load(Ordering::Relaxed);
        let job = if pending > 0 && pending + job.held_bytes() > cap {
            match job.defer() {
                Some(job) => job,
                None => return,
            }
        } else {
            job
        };
        let held = job.held_bytes();
        if writer.is_none() {
            match self.spawn_writers(disk) {
                Some(w) => *writer = Some(w),
                None => {
                    run_job(disk, self.memory.as_ref(), job, &mut WriterState::default());
                    disk.evict_lazily();
                    return;
                }
            }
        }
        if let Some(w) = writer.as_ref() {
            let derived = matches!(job.kind, Job::Derived(_));
            if derived {
                self.derived_pending.fetch_add(1, Ordering::Relaxed);
            }
            self.pending_bytes.fetch_add(held, Ordering::Relaxed);
            if let Err(mpsc::SendError((job, _))) = w.tx.send((job, held)) {
                if derived {
                    self.derived_pending.fetch_sub(1, Ordering::Relaxed);
                }
                self.pending_bytes.fetch_sub(held, Ordering::Relaxed);
                job.abandon();
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
        if let Some(Writer { tx, handles }) = taken {
            drop(tx);
            for handle in handles {
                let _ = handle.join();
            }
        }
    }

    /// Start the writer threads, sharing one queue; `None` when not even one
    /// can be started.
    fn spawn_writers(&self, disk: &Arc<DiskCache>) -> Option<Writer> {
        let (tx, rx) = mpsc::channel::<(WriteJob, usize)>();
        let rx = Arc::new(Mutex::new(rx));
        let count = self.writers.unwrap_or_else(|| CacheConfig::auto_writers(tiers::cpus())).max(1);
        let handles: Vec<_> = (0..count)
            .map_while(|_| {
                let (rx, disk, memory) = (Arc::clone(&rx), Arc::clone(disk), self.memory.clone());
                let (derived_pending, pending_bytes) = (Arc::clone(&self.derived_pending), Arc::clone(&self.pending_bytes));
                std::thread::Builder::new()
                    .name("droidasc-cache-writer".into())
                    .spawn(move || {
                        // Writes (and re-inflating deferred entries) must not take CPU from queries.
                        prebuild::lower_priority();
                        let mut state = WriterState::default();
                        loop {
                            // Only the receive holds the lock, so the writers run their jobs in parallel.
                            let Ok((job, held)) = rx.lock().expect("writer queue mutex poisoned").recv() else { break };
                            let derived = matches!(job.kind, Job::Derived(_));
                            run_job(&disk, memory.as_ref(), job, &mut state);
                            pending_bytes.fetch_sub(held, Ordering::Relaxed);
                            if derived {
                                derived_pending.fetch_sub(1, Ordering::Relaxed);
                            }
                            // Throttled by bytes written, so a long burst still keeps
                            // the directory within budget without a walk per entry.
                            disk.evict_lazily();
                        }
                    })
                    .ok()
            })
            .collect();
        (!handles.is_empty()).then_some(Writer { tx, handles })
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

/// What one writer thread keeps between jobs.
#[derive(Default)]
struct WriterState {
    /// APKs whose location the cache already recorded.
    noted: HashSet<ApkKey>,
    /// The archive deferred L1 writes last inflated from: a sweep defers
    /// runs of entries of the same APK.
    opened: Option<(Arc<Path>, ApkKey, Apk)>,
}

impl WriterState {
    /// `path` opened with `limits`, if it is still the archive `key` names.
    fn apk(&mut self, path: &Arc<Path>, key: &ApkKey, limits: Limits) -> Option<&Apk> {
        if !matches!(&self.opened, Some((p, k, _)) if p == path && k == key) {
            self.opened = None;
            let apk = Apk::open(path).ok()?.with_limits(limits);
            // Rewritten since the job was queued: its entries are not the ones to store.
            if ApkKey::for_apk(&apk).ok()? != *key {
                return None;
            }
            self.opened = Some((Arc::clone(path), key.clone(), apk));
        }
        self.opened.as_ref().map(|(_, _, apk)| apk)
    }
}

/// Run a queued write on a writer thread. The first write for an APK also
/// records where it lives.
fn run_job(disk: &DiskCache, memory: Option<&SharedMemory>, job: WriteJob, state: &mut WriterState) {
    let WriteJob { key, apk, kind } = job;
    if state.noted.insert(key.clone()) {
        let _ = disk.note_source(&key, &apk);
    }
    match kind {
        Job::Dex { entry, data, remap, .. } => {
            if disk.put(&key, &entry.name, &data).is_ok() {
                remap_entry(disk, memory, key, entry.name, data, remap);
            }
        }
        Job::Reinflate { entry, limits, remap } => {
            // Written meanwhile, by a later query of the entry or another process.
            if disk.get(&key, &entry.name, entry.uncomp_size).is_some() {
                return;
            }
            let Some(archive) = state.apk(&apk, &key, limits) else { return };
            let Ok(Cow::Owned(bytes)) = archive.read_entry(&entry) else { return };
            let data: DexBytes = Arc::new(DexData::Owned(bytes));
            if disk.put(&key, &entry.name, &data).is_ok() {
                remap_entry(disk, memory, key, entry.name, data, remap);
            }
        }
        Job::Derived(d) => tiers::write_derived(disk, memory, &key, d),
        Job::Rendered { query, payload } => {
            let _ = disk.put_rendered(&key, &query, &payload);
        }
        Job::Graph { graph, cost } => {
            let _ = disk.put_derived(&key, hierarchy::GRAPH_NAME, hierarchy::GRAPH_KIND, hierarchy::GRAPH_FORMAT, cost, graph.bytes());
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
    // Now file-backed: charged less.
    let size = new.charged_bytes();
    let mut memory = memory.lock().unwrap();
    if memory.replace(&key, &name, &entry, Arc::clone(&new)) {
        memory.resize(&key, &name, &new, size);
    }
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
    /// Derived indexes mapped from L2: the locator tables of a logical DEX,
    /// and the class graph.
    pub derived_hits: u64,
    pub inflates: u64,
    /// Deflate entries a search left out: a streamed prefix showed it could
    /// not match them, so they were never inflated whole.
    pub skipped: u64,
}

type Logger = Arc<dyn Fn(&str) + Send + Sync>;

/// Where an entry's bytes came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Memory,
    Disk,
    Stored,
    Inflate,
    /// Not loaded: a prefix showed the search cannot match it.
    Skipped,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Source::Memory => "memory",
            Source::Disk => "disk",
            Source::Stored => "stored",
            Source::Inflate => "inflate",
            Source::Skipped => "skipped",
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
    threads: Threads,
    debug: bool,
    logger: Logger,
    cache: Option<Arc<EngineCache>>,
    /// `cache` belongs to a [`SharedCache`], which closes it instead of us.
    shared_cache: bool,
    stats: Arc<Stats>,
    /// `(size, mtime, key)` of the APK the key was last computed for.
    key_cache: Mutex<Option<(u64, Option<SystemTime>, ApkKey)>>,
    /// The APK last opened, handed out again while its files are unchanged
    /// (a program of many jars costs a mapping and a directory parse each).
    opened: Mutex<Option<Apk>>,
    limits: Limits,
    /// Parsed `resources.arsc` for the APK version it was read from.
    resources: Mutex<Option<resources::CachedTable>>,
    /// Background table builds ([`Engine::prebuild`]) and the searches they
    /// give way to.
    prebuild: prebuild::Prebuild,
    /// The class hierarchy, for the APK version it was built from.
    class_graph: Mutex<Option<hierarchy::CachedGraph>>,
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
    skipped: AtomicUsize,
}

/// Worker threads of a search.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Threads {
    /// [`auto_threads`], read again by every search.
    #[default]
    Auto,
    Fixed(usize),
}

/// How often a worker [`Threads::wait_turn`] holds back looks again.
const TURN_POLL: Duration = Duration::from_millis(10);

impl Threads {
    /// The thread count for a search starting now (at least 1).
    pub fn count(self) -> usize {
        match self {
            Threads::Auto => auto_threads(),
            Threads::Fixed(n) => n.max(1),
        }
    }

    /// The most workers [`Threads::wait_turn`] ever lets run at once.
    pub fn most(self) -> usize {
        match self {
            Threads::Auto => tiers::cpus(),
            Threads::Fixed(n) => n.max(1),
        }
    }

    /// For a long search that starts [`Threads::most`] workers: hold worker
    /// `k` back (between units of work) while [`auto_threads`] allows fewer
    /// than `k + 1`, or until `stop()`. The count shrinks as other processes
    /// start scans and grows back as they finish, which a count read once at
    /// the start cannot follow: every process of a burst would see the others
    /// idle and take every CPU.
    pub fn wait_turn(self, k: usize, stop: impl Fn() -> bool) {
        if self == Threads::Auto {
            while k >= auto_threads() && !stop() {
                std::thread::sleep(TURN_POLL);
            }
        }
    }
}

impl From<usize> for Threads {
    fn from(n: usize) -> Threads {
        Threads::Fixed(n)
    }
}

/// `None` (no `--threads`) is [`Threads::Auto`].
impl From<Option<usize>> for Threads {
    fn from(n: Option<usize>) -> Threads {
        n.map_or(Threads::Auto, Threads::Fixed)
    }
}

impl Engine {
    /// An engine over `apk_path`: an APK, a jar, a bare DEX file, or a
    /// program of several read as one (a directory, or paths joined with
    /// `,`; see [`Apk::open`]).
    pub fn new(apk_path: impl AsRef<Path>) -> Engine {
        Engine {
            apk_path: apk_path.as_ref().to_path_buf(),
            threads: Threads::Auto,
            debug: false,
            logger: Arc::new(|m| println!("{m}")),
            cache: None,
            shared_cache: false,
            stats: Arc::new(Stats::default()),
            key_cache: Mutex::new(None),
            opened: Mutex::new(None),
            limits: Limits::default(),
            resources: Mutex::new(None),
            prebuild: prebuild::Prebuild::default(),
            class_graph: Mutex::new(None),
        }
    }

    /// Refuse entries that inflate past `limits` (zip bombs).
    pub fn with_limits(mut self, limits: Limits) -> Engine {
        self.limits = limits;
        self
    }

    pub fn with_threads(mut self, threads: impl Into<Threads>) -> Engine {
        self.threads = threads.into();
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
                derived_pending: Arc::new(AtomicUsize::new(0)),
                pending_bytes: Arc::new(AtomicUsize::new(0)),
                queue_cap: config.write_queue_bytes,
                writers: config.writers,
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

    /// The thread count for a search starting now.
    pub fn threads(&self) -> usize {
        self.threads.count()
    }

    pub fn cache_stats(&self) -> CacheStats {
        CacheStats {
            memory_hits: self.stats.memory_hits.load(Ordering::Relaxed) as u64,
            disk_hits: self.stats.disk_hits.load(Ordering::Relaxed) as u64,
            derived_hits: self.stats.derived_hits.load(Ordering::Relaxed) as u64,
            inflates: self.stats.inflates.load(Ordering::Relaxed) as u64,
            skipped: self.stats.skipped.load(Ordering::Relaxed) as u64,
        }
    }

    /// Heap this engine holds outside the memory cache, roughly: the class
    /// graph and the parsed resource table it keeps for later calls. A host
    /// keeping many engines counts it against its memory budget
    /// ([`SharedCache::set_reserved`]).
    pub fn resident_bytes(&self) -> usize {
        let graph = self.class_graph.lock().unwrap().as_ref().map_or(0, |(_, g)| g.heap_bytes());
        let table = self.resources.lock().unwrap().as_ref().map_or(0, resources::CachedTable::heap_bytes);
        graph + table
    }

    /// Bytes currently charged to the in-memory cache: entry bytes plus the
    /// locator tables built for them.
    pub fn memory_cache_bytes(&self) -> usize {
        self.cache.as_ref().and_then(|c| c.memory.as_ref()).map(|m| m.lock().unwrap().used_bytes()).unwrap_or(0)
    }

    /// Drop this APK's entries from the in-memory cache (shared or not), and
    /// its parsed resource table, and return the DEX bytes released; queries
    /// still holding them keep them alive.
    pub fn release_memory_cache(&self) -> usize {
        self.release_resources();
        self.class_graph.lock().unwrap().take();
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

    /// Open the APK, or reuse the one opened last while [`Apk::version_of`]
    /// finds the same files, sizes and times.
    pub fn open(&self) -> Result<Apk> {
        let version = Apk::version_of(&self.apk_path)?;
        let mut opened = self.opened.lock().unwrap();
        if let Some(apk) = opened.as_ref().filter(|a| *a.version() == version) {
            return Ok(apk.clone().with_limits(self.limits));
        }
        let apk = Apk::open(&self.apk_path)?.with_limits(self.limits);
        *opened = Some(apk.clone());
        Ok(apk)
    }

    /// `apk_path` (what [`Engine::new`] takes) with relative paths resolved
    /// against `base`, each path of a program on its own.
    pub fn resolve_path(apk_path: &Path, base: &Path) -> PathBuf {
        Apk::resolve(apk_path, base)
    }

    /// Whether `apk_path` opens: a readable file, or a program with code.
    pub fn can_open(apk_path: &Path) -> bool {
        Apk::open(apk_path).is_ok()
    }

    /// One line per archive of a program left out of its code (no root DEX,
    /// e.g. a jar deodexed into `oat/`, or not a zip); none for one file.
    pub fn program_notes(&self) -> Vec<String> {
        if self.apk_path.is_file() {
            return Vec::new();
        }
        self.open().map(|apk| apk.notes().to_vec()).unwrap_or_default()
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
            Shape::Results,
            None,
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
        let ident = apk.stamp().ok()?;
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
    /// data to answer the probe cheaply; only a hit is inflated fully.
    ///
    /// A class several DEX files define resolves as a class loader would:
    /// the first archive of a program, then `classes.dex`, `classes2.dex`,
    /// ... ([`load_ranks`]). Once a DEX defines it, DEX files after it are no
    /// longer read; workers still inflating one at that moment finish on
    /// their own in the background. A program reads every archive, to name
    /// the others that define the class too ([`ClassHit::also_defined_in`]).
    pub fn get_class_dex(&self, descriptor: &str) -> Result<Option<ClassHit>> {
        self.get_class_dex_cancellable(descriptor, &NOT_CANCELLED)
    }

    /// [`Engine::get_class_dex`] that stops, with `ApkError::Cancelled`, once
    /// `cancel` is raised.
    pub fn get_class_dex_cancellable(&self, descriptor: &str, cancel: &AtomicBool) -> Result<Option<ClassHit>> {
        if cancel.load(Ordering::Relaxed) {
            return Err(cancelled());
        }
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
        // Rank of the best DEX defining the class so far: later ones need not be read.
        let best = Arc::new(AtomicUsize::new(usize::MAX));
        let ranks: Arc<Vec<usize>> = Arc::new(load_ranks(&entries));
        let exhaustive = apk.archive_count() > 1;
        let workers = self.threads().min(entries.len()).max(1);
        let (tx, rx) = mpsc::channel::<(usize, std::result::Result<Option<ClassHit>, EngineError>)>();
        let debug = self.debug;
        for w in 0..workers {
            let (apk, entries, key, target, next, stop, tx, logger, cache, stats, best, ranks) = (
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
                Arc::clone(&best),
                Arc::clone(&ranks),
            );
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(entry) = entries.get(i) else { break };
                    let rank = ranks[i];
                    // A DEX the class loader would read after the best hit cannot win.
                    if !exhaustive && rank > best.load(Ordering::Relaxed) {
                        let _ = tx.send((i, Ok(None)));
                        continue;
                    }
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
                                    let _ = tx.send((i, Ok(None)));
                                    continue;
                                }
                                Ok(Some(true)) | Ok(None) => {}
                                Err(e) => {
                                    let _ = tx.send((i, Err(e)));
                                    continue;
                                }
                            }
                            match load_entry(&apk, key.as_ref().as_ref(), entry, cache.as_deref(), &stats, Some(&stop)) {
                                Ok(l) => l,
                                Err(EngineError::Apk(asc_apk::ApkError::Cancelled)) => break,
                                Err(e) => {
                                    let _ = tx.send((i, Err(e)));
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
                                found = Some(ClassHit { dex_name: name, dex: data, also_defined_in: Vec::new() });
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
                    if let Some(hit) = found {
                        best.fetch_min(rank, Ordering::Relaxed);
                        let _ = tx.send((i, Ok(Some(hit))));
                        continue;
                    }
                    let _ = tx.send((i, entry_err.map_or(Ok(None), Err)));
                }
            });
        }
        drop(tx);
        let mut hits: Vec<(usize, ClassHit)> = Vec::new();
        let mut last_err = None;
        let mut answered = vec![false; entries.len()];
        let mut seen = 0usize;
        loop {
            let (i, msg) = match rx.recv_timeout(CANCEL_POLL) {
                Ok(msg) => msg,
                Err(mpsc::RecvTimeoutError::Timeout) if cancel.load(Ordering::Relaxed) => {
                    stop.store(true, Ordering::Relaxed);
                    return Err(cancelled());
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            };
            seen += 1;
            answered[i] = true;
            match msg {
                Ok(Some(h)) => hits.push((ranks[i], h)),
                Ok(None) => {}
                Err(e) => last_err = Some(e),
            }
            if seen == entries.len() {
                break;
            }
            // The best hit wins once every DEX the class loader reads before it has answered.
            let best = hits.iter().map(|(rank, _)| *rank).min();
            if let Some(best) = best.filter(|_| !exhaustive) {
                if ranks.iter().zip(&answered).all(|(&rank, &done)| done || rank >= best) {
                    break;
                }
            }
        }
        stop.store(true, Ordering::Relaxed);
        self.log(format!("[APK] getclass total={} us", t0.elapsed().as_micros()));
        hits.sort_by_key(|(rank, _)| *rank);
        let mut hits = hits.into_iter().map(|(_, h)| h);
        match (hits.next(), last_err) {
            (Some(mut h), _) => {
                let archive = archive_of(&h.dex_name).map(str::to_string);
                h.also_defined_in = hits.map(|o| o.dex_name).filter(|n| archive_of(n).map(str::to_string) != archive).collect();
                Ok(Some(h))
            }
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
        self.get_class_method_cancellable(descriptor, opts, method, &NOT_CANCELLED)
    }

    /// [`Engine::get_class_method`] that stops looking for the class, with
    /// `ApkError::Cancelled`, once `cancel` is raised.
    pub fn get_class_method_cancellable(
        &self,
        descriptor: &str,
        opts: SmaliOptions,
        method: Option<&str>,
        cancel: &AtomicBool,
    ) -> Result<ClassSource> {
        if let Some(m) = method {
            asc_smali::normalize_method_signature(m)?;
        }
        let t0 = Instant::now();
        let hit = self
            .get_class_dex_cancellable(descriptor, cancel)?
            .ok_or_else(|| EngineError::ClassNotFound { class: descriptor.to_string(), hint: self.class_not_found_hint(descriptor) })?;
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
        Ok(ClassSource { dex_name: hit.dex_name, source, rebuilt, warning, scan_us, also_defined_in: hit.also_defined_in })
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
        self.find_refs_shaped(query, opts, Shape::Results, cancel, sink)
    }

    /// The rows of [`Engine::find_refs`] (one per method, no context) as
    /// text: each batch holds them in [`RefBatch::text`], exactly the
    /// [`RefResult::line`]s `find_refs` would give, with no structured rows.
    /// A broad query renders and replays much faster this way.
    pub fn find_refs_text(&self, query: &Query, cancel: &AtomicBool, sink: &mut dyn FnMut(RefBatch)) -> Result<RefSummary> {
        self.find_refs_shaped(query, FindOptions::default(), Shape::Text, cancel, sink)
    }

    fn find_refs_shaped(
        &self,
        query: &Query,
        opts: FindOptions,
        shape: Shape,
        cancel: &AtomicBool,
        sink: &mut dyn FnMut(RefBatch),
    ) -> Result<RefSummary> {
        let t0 = Instant::now();
        compose::check_patterns(query)?;
        if let Some(engine) = self.transient(compose::needs_program(query))? {
            return engine.find_refs_shaped(query, opts, shape, cancel, sink);
        }
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
        let rendered = disk.zip(key.as_ref()).map(|(d, k)| (d, k, tiers::findrefs_key(query, opts, shape)));
        if let Some(recorded) = rendered.as_ref().and_then(|(d, k, q)| d.get_rendered_view(k, q)).and_then(tiers::decode_batches) {
            for batch in recorded.batches {
                summary.total_results += batch.row_count();
                sink(batch);
            }
            summary.notes = recorded.notes;
            summary.total_us = t0.elapsed().as_micros();
            self.log(format!("[APK] for_each_findrefs total={} us count={} source=result", summary.total_us, entries.len()));
            return Ok(summary);
        }
        // `method:{RULE}`: the methods RULE matches first, then the calls of
        // them. L3 keys on the query as given, so a replay skips this too.
        let resolved = self.resolve(std::slice::from_ref(query), cancel)?;
        summary.notes = resolved.notes.into_iter().next().unwrap_or_default();
        let _query = self.prebuild.query();
        let compiled = CompiledQuery::new(resolved.queries.as_ref().map_or(query, |r| &r[0]))?;
        let mut recorder = rendered.as_ref().map(|(d, _, _)| tiers::ResultRecorder::new(tiers::result_limit(d, shape)));
        let next = AtomicUsize::new(0);
        let (tx, rx) = mpsc::channel::<RefBatch>();
        let workers = self.threads().min(entries.len()).max(1);
        let cache = self.cache.as_deref();
        let stats = &self.stats;
        let probe = skip::Probe::new(vec![&compiled]);
        let (compiled, probe) = (&compiled, &probe);
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
                    let batch = search_entry(apk, key, entry, compiled, opts, shape, Some(probe), cancel, cache, stats);
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
                        batch.row_count(),
                        batch.error.as_ref().map(|e| format!(" error={e}")).unwrap_or_default()
                    ));
                }
                summary.total_results += batch.row_count();
                if let Some(r) = recorder.as_mut() {
                    r.record(&batch);
                }
                sink(batch);
            }
        });
        if let (Some((_, k, q)), Some(payload)) = (rendered, recorder.and_then(|r| r.finish(&summary.notes))) {
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
        let _query = self.prebuild.query();
        let wanted: HashSet<String> = rows.iter().map(|r| entry_of(&r.dex_name).to_string()).collect();
        let (views, errors) = self.load_views(Some(&wanted), &NOT_CANCELLED)?;
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
    /// Stops with `ApkError::Cancelled` once `cancel` is raised.
    fn load_views(&self, only: Option<&HashSet<String>>, cancel: &AtomicBool) -> Result<(Vec<DexView>, Vec<String>)> {
        let apk = self.open()?;
        let mut entries = apk.dex_entries()?;
        if let Some(only) = only {
            entries.retain(|e| only.contains(&e.name));
        }
        let key = self.apk_key(&apk);
        let next = AtomicUsize::new(0);
        let workers = self.threads().min(entries.len()).max(1);
        let cache = self.cache.as_deref();
        let l2 = cache.and_then(|c| c.disk.as_deref()).filter(|d| d.uses(Tier::Derived)).zip(key.as_ref());
        let mut slots: Vec<Option<std::result::Result<Vec<DexView>, String>>> = (0..entries.len()).map(|_| None).collect();
        let done = Mutex::new(&mut slots);
        std::thread::scope(|s| {
            for _ in 0..workers {
                s.spawn(|| loop {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(entry) = entries.get(i) else { break };
                    let r = load_entry(&apk, key.as_ref(), entry, cache, &self.stats, Some(cancel))
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
        if cancel.load(Ordering::Relaxed) {
            return Err(cancelled());
        }
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
        self.prebuild.cancel();
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
/// Each entry's place in the order a class loader reads DEX files: archive
/// by archive in program order, then `classes.dex`, `classes2.dex`, ... by
/// number, other names last.
fn load_ranks(entries: &[Entry]) -> Vec<usize> {
    let key = |e: &Entry| {
        let inner = e.name.rsplit('/').next().unwrap_or(&e.name);
        let number = match inner.strip_prefix("classes").and_then(|rest| rest.strip_suffix(".dex")) {
            Some("") => 1,
            Some(n) if !n.starts_with('0') => n.parse().unwrap_or(u64::MAX),
            _ => u64::MAX,
        };
        (e.archive, number, inner.to_string())
    };
    let mut order: Vec<usize> = (0..entries.len()).collect();
    order.sort_by_cached_key(|&i| key(&entries[i]));
    let mut ranks = vec![0; entries.len()];
    for (rank, i) in order.into_iter().enumerate() {
        ranks[i] = rank;
    }
    ranks
}

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
                    let size = e.charged_bytes();
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
                let offset = b.as_ptr() as usize - apk.archive_data(entry).as_ptr() as usize;
                let data =
                    DexData::map_region(apk.archive_path(entry), offset as u64, b.len()).unwrap_or_else(|_| DexData::Owned(b.to_vec()));
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
                let size = e.charged_bytes();
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
                kind: Job::Dex { entry: entry.clone(), limits: apk.limits(), data: Arc::clone(&e.data), remap },
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
    shape: Shape,
    probe: Option<&skip::Probe<'_>>,
    cancel: &AtomicBool,
    cache: Option<&EngineCache>,
    stats: &Stats,
) -> RefBatch {
    let run = |fr: &FindRefs<'_, '_, '_>| {
        Ok(vec![match shape {
            Shape::Results => Rows::Results(rows_compiled(fr, query, opts)?),
            Shape::Text => Rows::Text(compact::text_rows(fr, query)?),
        }])
    };
    search_entry_with(apk, key, entry, 1, &run, probe, cancel, cache, stats).pop().expect("one batch per query")
}

/// Rows of `n` queries over one logical DEX, one per query.
pub(crate) type RunRows<'q> = dyn Fn(&FindRefs<'_, '_, '_>) -> Result<Vec<Rows>> + Sync + 'q;

/// The rows of one query over one logical DEX, in the form asked for.
pub(crate) enum Rows {
    Results(Vec<RefResult>),
    Text(TextRows),
}

/// The form [`Engine::find_refs_opts`] (`Results`) and
/// [`Engine::find_refs_text`] (`Text`) return rows in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shape {
    Results,
    Text,
}

/// Load one entry (through the caches) and run `run` over each of its
/// logical DEX files: one batch per query, all sharing the load. With a
/// `probe`, an entry no cache keeps may first be shown not to match from a
/// prefix, and then is not loaded at all.
#[allow(clippy::too_many_arguments)]
pub(crate) fn search_entry_with(
    apk: &Apk,
    key: Option<&ApkKey>,
    entry: &Entry,
    n: usize,
    run: &RunRows<'_>,
    probe: Option<&skip::Probe<'_>>,
    cancel: &AtomicBool,
    cache: Option<&EngineCache>,
    stats: &Stats,
) -> Vec<RefBatch> {
    let t0 = Instant::now();
    let empty = RefBatch {
        entry_name: entry.name.clone(),
        results: Vec::new(),
        text: None,
        inflate_us: 0,
        search_us: 0,
        source: "inflate",
        error: None,
    };
    let mut batches = vec![empty; n];
    if probe.is_some_and(|p| p.skips(apk, entry, cache, stats)) {
        let inflate_us = t0.elapsed().as_micros();
        for b in &mut batches {
            (b.source, b.inflate_us) = (Source::Skipped.as_str(), inflate_us);
        }
        return batches;
    }
    let (loaded, source) = match load_entry(apk, key, entry, cache, stats, Some(cancel)) {
        Ok(l) => l,
        Err(e) => {
            let msg = e.to_string();
            for b in &mut batches {
                b.error = Some(msg.clone());
            }
            return batches;
        }
    };
    let t1 = Instant::now();
    let mut add = |name: &str, r: Result<Vec<Rows>>| match r {
        Ok(rows) => {
            for (b, rows) in batches.iter_mut().zip(rows) {
                match rows {
                    Rows::Results(mut rows) => b.results.append(&mut rows),
                    Rows::Text(t) => match &mut b.text {
                        Some(text) => text.append(&t),
                        None => b.text = Some(t),
                    },
                }
            }
        }
        Err(e) => {
            let msg = e.to_string();
            for b in batches.iter_mut() {
                b.note_error(name, &msg);
            }
        }
    };
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
                    let rows = run(&FindRefs::with_state(&dex, &l.state));
                    if let Some(((c, disk), k)) = l2 {
                        if let Some(job) = tiers::derived_job(disk, e, i, mask, t.elapsed()) {
                            c.put_async(WriteJob { key: k.clone(), apk: Arc::from(apk.path()), kind: Job::Derived(job) });
                        }
                    }
                    rows
                });
                add(&l.name, r);
            }
            recharge(cache, key, e);
        }
        Loaded::Borrowed(_) => {
            for (name, buf) in logical_dex_iter(&entry.name, loaded.bytes()) {
                let r = Dex::with_name(&buf, &name).map_err(EngineError::from).and_then(|dex| run(&FindRefs::new(&dex)));
                add(&name, r);
            }
        }
    }
    let (inflate_us, search_us) = ((t1 - t0).as_micros(), t1.elapsed().as_micros());
    for b in &mut batches {
        (b.source, b.inflate_us, b.search_us) = (source.as_str(), inflate_us, search_us);
    }
    batches
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

/// The constant a hit matched, with the note of a call-site constraint
/// (`Lc;->m(I)V [arg0=1]`) when it has one.
fn hit_matched(dex: &Dex<'_>, kind: RefKind, idx: u32, note: Option<&str>) -> Result<Matched> {
    let m = matched_name(dex, kind, idx)?;
    Ok(match note {
        Some(note) => Matched::Symbol(format!("{} {note}", m.as_str())),
        None => m,
    })
}

fn matched_name(dex: &Dex<'_>, kind: RefKind, idx: u32) -> Result<Matched> {
    Ok(match kind {
        RefKind::String => Matched::String(dex.string(idx)?),
        RefKind::Type => Matched::Symbol(dex.type_descriptor(idx)?),
        RefKind::Method => Matched::Symbol(asc_smali::method_signature(dex, idx)?),
        RefKind::Field => Matched::Symbol(asc_smali::field_signature(dex, idx)?),
    })
}

impl RefResult {
    /// The row of method `m` of `dex`, with no context yet.
    fn method_row(dex: &Dex<'_>, m: u32, matched: Vec<Matched>, sites: Vec<RefSite>) -> Result<RefResult> {
        Ok(RefResult {
            dex_name: dex.name().to_string(),
            method_idx: m,
            method: dex.method_display(m)?,
            signature: asc_smali::method_signature(dex, m)?,
            matched,
            relation: None,
            sites,
            context: None,
        })
    }
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
    if let Some(c) = query.compound() {
        return rules::compound_rows(fr, c, opts);
    }
    if let Some(d) = query.defined() {
        let mut rows = defined_rows(dex, d)?;
        if opts.context != RefContext::None {
            attach_context(fr, &mut rows, opts.context)?;
        }
        return Ok(rows);
    }
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
            let class = dex.type_descriptor(c)?;
            Ok(RefResult {
                dex_name: dex_name.clone(),
                method_idx: c,
                method: class.clone(),
                signature: class,
                matched: vec![Matched::Symbol(target.to_string())],
                relation: query.relation(),
                sites: Vec::new(),
                context: None,
            })
        })
        .collect()
}

/// Rows of a method-definition predicate: one per matching method, with no
/// call site (the `matched` column names the predicate).
pub(crate) fn defined_rows(dex: &Dex<'_>, d: &asc_findrefs::Defined) -> Result<Vec<RefResult>> {
    let label = d.label();
    defs::defined_methods(dex, d)?
        .into_iter()
        .map(|m| RefResult::method_row(dex, m, vec![Matched::Symbol(label.clone())], Vec::new()))
        .collect()
}

/// Turn raw hits into display results (grouped per method when `aggregate`).
pub fn results_from_hits(dex: &Dex<'_>, kind: RefKind, hits: &[Hit], aggregate: bool) -> Result<Vec<RefResult>> {
    if !aggregate {
        let mut out = Vec::new();
        for hit in hits {
            let Some(methods) = &hit.methods else { continue };
            let matched = hit_matched(dex, kind, hit.matched_idx, hit.note.as_deref())?;
            for &m in methods.ids() {
                let site = RefSite { offset: hit.offset, matched: 0, pc: None, line: None };
                out.push(RefResult::method_row(dex, m, vec![matched.clone()], vec![site])?);
            }
        }
        return Ok(out);
    }
    // method -> (matched (index, note)s, (offset, matched (index, note)) per hit)
    type Key<'h> = (u32, Option<&'h str>);
    type Group<'h> = (std::collections::BTreeSet<Key<'h>>, Vec<(u32, Key<'h>)>);
    let mut grouped: BTreeMap<u32, Group<'_>> = BTreeMap::new();
    for hit in hits {
        let Some(methods) = &hit.methods else { continue };
        let key = (hit.matched_idx, hit.note.as_deref());
        for &m in methods.ids() {
            let g = grouped.entry(m).or_default();
            g.0.insert(key);
            g.1.push((hit.offset, key));
        }
    }
    let mut out = Vec::with_capacity(grouped.len());
    for (m, (idxs, offsets)) in grouped {
        let idxs: Vec<Key<'_>> = idxs.into_iter().collect();
        let matched = idxs.iter().map(|&(i, note)| hit_matched(dex, kind, i, note)).collect::<Result<Vec<_>>>()?;
        let sites = offsets
            .into_iter()
            .map(|(offset, idx)| RefSite { offset, matched: idxs.binary_search(&idx).unwrap_or(0), pc: None, line: None })
            .collect();
        out.push(RefResult::method_row(dex, m, matched, sites)?);
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

    /// An APK of `n` deflated copies of the fixture DEX, an L1-only cache
    /// (admitting entries of any size), and the entry names.
    fn multi_dex_apk(dir: &Path, n: usize) -> (PathBuf, DiskCache, Vec<String>) {
        let dex = asc_fixture::make_dex();
        let names: Vec<String> = (1..=n).map(|i| if i == 1 { "classes.dex".into() } else { format!("classes{i}.dex") }).collect();
        let entries: Vec<(&str, &[u8])> = names.iter().map(|name| (name.as_str(), dex.as_slice())).collect();
        let apk = dir.join("multi.apk");
        std::fs::write(&apk, asc_fixture::make_apk(&entries, true)).unwrap();
        (apk, l1_cache(&dir.join("cache")), names)
    }

    fn l1_cache(dir: &Path) -> DiskCache {
        DiskCache::open(dir).with_capacity(1 << 30).with_min_dex_bytes(0).with_tiers(&[Tier::Dex])
    }

    #[test]
    fn a_full_write_queue_defers_l1_writes_instead_of_dropping_them() {
        let dir = tempfile::tempdir().unwrap();
        let (apk, disk, names) = multi_dex_apk(dir.path(), 8);
        let mut engine = Engine::new(&apk).with_threads(4).with_cache(CacheConfig { disk: Some(disk), ..CacheConfig::default() });
        // Room for one entry's bytes: every other write is queued without them.
        Arc::get_mut(engine.cache.as_mut().unwrap()).unwrap().queue_cap = 1;
        engine.find_refs(&Query::String("token".into()), |batch| assert!(batch.error.is_none())).unwrap();
        engine.flush_cache_writes();
        let cache = engine.cache.as_deref().unwrap();
        assert_eq!(cache.pending_bytes.load(Ordering::Relaxed), 0);
        let key = engine.apk_key(&Apk::open(&apk).unwrap()).unwrap();
        let len = asc_fixture::make_dex().len() as u64;
        for name in &names {
            assert!(cache.disk.as_ref().unwrap().get(&key, name, len).is_some(), "{name} missing from L1");
        }
    }

    #[test]
    fn the_write_queue_stays_within_the_memory_budget() {
        let dir = tempfile::tempdir().unwrap();
        let disk = || Some(DiskCache::open(dir.path().join("cache")));
        let cap = |engine: &Engine| engine.cache.as_deref().unwrap().queue_cap();
        assert_eq!(cap(&Engine::new("x.apk").with_cache(CacheConfig { disk: disk(), ..CacheConfig::default() })), CacheConfig::WRITE_QUEUE);
        let small = Engine::new("x.apk").with_cache(CacheConfig { memory_bytes: 64 << 20, disk: disk(), ..CacheConfig::default() });
        assert_eq!(cap(&small), 64 << 20);
        let large = Engine::new("x.apk").with_cache(CacheConfig { memory_bytes: 4 << 30, disk: disk(), ..CacheConfig::default() });
        assert_eq!(cap(&large), CacheConfig::WRITE_QUEUE);
        let set = Engine::new("x.apk").with_cache(CacheConfig {
            memory_bytes: 4 << 30,
            disk: disk(),
            write_queue_bytes: 1 << 20,
            ..CacheConfig::default()
        });
        assert_eq!(cap(&set), 1 << 20);
        assert_eq!((CacheConfig::auto_writers(4), CacheConfig::auto_writers(16), CacheConfig::auto_writers(64)), (1, 2, 4));
    }

    #[test]
    fn a_deferred_write_inflates_its_entry_again_unless_the_apk_changed() {
        let dir = tempfile::tempdir().unwrap();
        let (apk_path, disk, names) = multi_dex_apk(dir.path(), 2);
        let apk = Apk::open(&apk_path).unwrap();
        let key = ApkKey::for_apk(&apk).unwrap();
        let entries = apk.dex_entries().unwrap();
        let limits = apk.limits();
        let job = |entry: &Entry| WriteJob {
            key: key.clone(),
            apk: Arc::from(apk_path.as_path()),
            kind: Job::Dex { entry: entry.clone(), limits, data: Arc::new(DexData::Owned(vec![0; 64])), remap: None },
        };
        // Deferring lets go of the bytes; the writer inflates the entry itself.
        let deferred = job(&entries[0]).defer().unwrap();
        assert!(matches!(deferred.kind, Job::Reinflate { .. }));
        assert_eq!(deferred.held_bytes(), 0);
        run_job(&disk, None, deferred, &mut WriterState::default());
        let written = disk.get(&key, &entries[0].name, entries[0].uncomp_size).expect("inflated again and written");
        assert_eq!(&*written, &*apk.read_entry(&entries[0]).unwrap());
        // Replaced since the job was queued: nothing is written for the old key.
        drop(apk);
        let replacement = dir.path().join("replacement.apk");
        std::fs::write(&replacement, asc_fixture::make_apk(&[(names[0].as_str(), &asc_fixture::make_dex()[..])], false)).unwrap();
        std::fs::rename(&replacement, &apk_path).unwrap();
        let other = l1_cache(&dir.path().join("other"));
        run_job(&other, None, job(&entries[1]).defer().unwrap(), &mut WriterState::default());
        assert!(other.get(&key, &entries[1].name, entries[1].uncomp_size).is_none());
    }
}
