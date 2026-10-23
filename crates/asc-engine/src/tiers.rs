//! The engine's use of the disk cache tiers beyond inflated DEX entries, and
//! the memory budget shared by the resident hosts of one user.
//!
//! * L2 (`asc_cache::Tier::Derived`): the locator tables of each logical DEX
//!   ([`LOCATORS_KIND`]). A search first adopts the tables a previous
//!   process persisted (mapped, so every process shares one copy of their
//!   pages), and queues the tables it had to build for writing once they took
//!   long enough to build (`DiskCache::admits_derived`). Once written, the copy in the memory cache is
//!   swapped for a view of the file, like inflated bytes are remapped to L1.
//! * L3 (`asc_cache::Tier::Rendered`): the result rows of a `find_refs`
//!   query, replayed by a later run of the same query on the same APK with
//!   the same build of the tool.
//!
//! Other derived indexes (call graph edges, resource tables, manifest
//! summaries) go to L2 the same way: serialise them into bytes that can be
//! viewed in place, store them with `DiskCache::put_derived(key, name, kind,
//! version, build_cost, bytes)` from the cache writer, and map them back with
//! `DiskCache::get_derived(key, name, kind, version)`. Pick a `kind` of their
//! own and bump `version` whenever the layout changes; per-APK indexes use a
//! fixed `name` such as `apk`.

use crate::{
    auto_memory_bytes_for, available_memory, CachedEntry, DexBytes, FindOptions, LogicalDex, Matched, RefBatch, RefResult, RefSite,
    SharedMemory, AUTO_MEMORY_MAX, AUTO_MEMORY_MIN,
};
use asc_cache::{ApkKey, DiskCache, ProcessRegistry, ProcessUsage};
use asc_dex::Dex;
use asc_findrefs::{ClassRelation, Query, SearchState};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// L2 kind of the persisted locator tables.
pub(crate) const LOCATORS_KIND: &str = "locators";
/// `find_refs` results larger than this (encoded) are not kept in L3.
pub(crate) const L3_MAX_RESULT: usize = 4 << 20;
/// Layout version of the encoded `find_refs` results.
const RESULT_FORMAT: u32 = 3;
/// Ends the encoded results (where an entry name's length would be), so a
/// truncated file is told from a complete one.
const RESULT_END: u32 = u32::MAX;

/// L2 bookkeeping of one logical DEX, shared by the entries that replace
/// each other in the memory cache.
#[derive(Default)]
pub(crate) struct Persisted {
    /// L2 has been consulted for this DEX.
    tried: AtomicBool,
    /// Tables on disk or queued for writing (`SearchState::table_mask` bits).
    queued: AtomicU32,
    /// Time spent building the tables so far.
    cost_us: AtomicU64,
}

/// Adopt the locator tables persisted for `l` (once per logical DEX).
pub(crate) fn load_derived(disk: &DiskCache, key: &ApkKey, l: &LogicalDex, dex: &Dex<'_>) -> bool {
    if l.persisted.tried.swap(true, Ordering::Relaxed) {
        return false;
    }
    let Some(d) = disk.get_derived(key, &l.name, LOCATORS_KIND, asc_findrefs::PERSIST_FORMAT_VERSION) else { return false };
    let cost = d.build_cost.as_micros() as u64;
    let Some(state) = SearchState::from_persisted(dex, Arc::new(d)) else { return false };
    l.persisted.queued.fetch_or(state.table_mask(), Ordering::Relaxed);
    l.persisted.cost_us.fetch_add(cost, Ordering::Relaxed);
    l.state.fill_from(state);
    true
}

/// Tables of a logical DEX to persist.
pub(crate) struct DerivedJob {
    /// Memory cache entry and logical index the tables belong to.
    entry: String,
    logical: usize,
    name: String,
    data: DexBytes,
    state: Arc<SearchState>,
    persisted: Arc<Persisted>,
    /// The `queued` bits this job claimed.
    claimed: u32,
}

impl DerivedJob {
    /// Heap the job keeps alive until written: the tables it persists.
    pub(crate) fn held_bytes(&self) -> usize {
        self.state.heap_bytes()
    }

    /// Not written after all: a later search may queue these tables again.
    pub(crate) fn abandon(self) {
        self.persisted.queued.fetch_and(!self.claimed, Ordering::Relaxed);
    }
}

/// A write of the tables of `entry.logical()[idx]`, when a search that
/// started with `mask_before` built tables worth persisting (`spent` is
/// what it took).
pub(crate) fn derived_job(disk: &DiskCache, entry: &CachedEntry, idx: usize, mask_before: u32, spent: Duration) -> Option<DerivedJob> {
    let l = entry.logical().get(idx)?;
    let mask = l.state.table_mask();
    let p = &l.persisted;
    if mask == mask_before && mask & !p.queued.load(Ordering::Relaxed) == 0 {
        return None;
    }
    let cost = if mask != mask_before {
        p.cost_us.fetch_add(spent.as_micros() as u64, Ordering::Relaxed) + spent.as_micros() as u64
    } else {
        p.cost_us.load(Ordering::Relaxed)
    };
    if !disk.admits_derived(Duration::from_micros(cost)) {
        return None;
    }
    let claimed = mask & !p.queued.fetch_or(mask, Ordering::Relaxed);
    if claimed == 0 {
        return None;
    }
    Some(DerivedJob {
        entry: entry.name.clone(),
        logical: idx,
        name: l.name.clone(),
        data: Arc::clone(&l.data),
        state: Arc::clone(&l.state),
        persisted: Arc::clone(&l.persisted),
        claimed,
    })
}

/// Write a [`DerivedJob`] (on the cache writer thread), then swap the heap
/// tables of the memory cache's entry for views of the file.
pub(crate) fn write_derived(disk: &DiskCache, memory: Option<&SharedMemory>, key: &ApkKey, job: DerivedJob) {
    let Ok(dex) = Dex::with_name(&job.data, &job.name) else { return };
    let mask = job.state.table_mask();
    let bytes = job.state.persist(&dex);
    let cost = Duration::from_micros(job.persisted.cost_us.load(Ordering::Relaxed));
    let version = asc_findrefs::PERSIST_FORMAT_VERSION;
    if disk.put_derived(key, &job.name, LOCATORS_KIND, version, cost, &bytes).is_err() {
        return;
    }
    drop(bytes);
    let Some(memory) = memory else { return };
    let Some(mapped) =
        disk.get_derived(key, &job.name, LOCATORS_KIND, version).and_then(|d| SearchState::from_persisted(&dex, Arc::new(d)))
    else {
        return;
    };
    // Tables built after the snapshot would be lost by the swap: keep the
    // heap state then (the next write maps them all).
    if mapped.table_mask() != mask || job.state.table_mask() != mask {
        return;
    }
    let mut mem = memory.lock().unwrap();
    let Some(current) = mem.peek(key, &job.entry) else { return };
    let still_ours = current.logical.get().and_then(|l| l.get(job.logical)).is_some_and(|l| Arc::ptr_eq(&l.state, &job.state));
    if still_ours {
        let new = Arc::new(current.with_state(job.logical, Arc::new(mapped)));
        let size = new.charged_bytes();
        if mem.replace(key, &job.entry, &current, Arc::clone(&new)) {
            mem.resize(key, &job.entry, &new, size);
        }
    }
}

/// Fingerprint of this build of the tool: the crate version plus the size
/// and modification time of the running executable, so a rebuilt binary
/// never replays results of the old one.
fn tool_version() -> &'static str {
    static VERSION: OnceLock<String> = OnceLock::new();
    VERSION.get_or_init(|| {
        let exe = std::env::current_exe().ok().and_then(|p| std::fs::metadata(p).ok());
        let stamp = exe.map(|m| {
            let mtime = m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_nanos());
            format!("{}.{mtime}", m.len())
        });
        format!("{}+{}", env!("CARGO_PKG_VERSION"), stamp.unwrap_or_default())
    })
}

/// The L3 key of a `find_refs` query.
pub(crate) fn findrefs_key(query: &Query, opts: FindOptions) -> String {
    asc_cache::rendered_key("findrefs", tool_version(), &format!("{query:?}\0{opts:?}"))
}

/// Encodes the batches of a `find_refs` run for L3 as they stream past.
/// Runs with an error (an entry that could not be searched may succeed next
/// time) or results beyond [`L3_MAX_RESULT`] are not kept.
pub(crate) struct ResultRecorder {
    out: Vec<u8>,
    keep: bool,
}

impl ResultRecorder {
    pub(crate) fn new() -> ResultRecorder {
        let mut out = Vec::new();
        out.extend_from_slice(&RESULT_FORMAT.to_le_bytes());
        ResultRecorder { out, keep: true }
    }

    pub(crate) fn record(&mut self, b: &RefBatch) {
        if !self.keep {
            return;
        }
        if b.error.is_some() {
            self.keep = false;
            self.out = Vec::new();
            return;
        }
        put_str(&mut self.out, &b.entry_name);
        put_u32(&mut self.out, b.results.len() as u32);
        for r in &b.results {
            put_str(&mut self.out, &r.dex_name);
            put_u32(&mut self.out, r.method_idx);
            put_str(&mut self.out, &r.method);
            put_str(&mut self.out, &r.signature);
            put_u32(&mut self.out, r.matched.len() as u32);
            for m in &r.matched {
                self.out.push(match m {
                    Matched::String(_) => 0,
                    Matched::Symbol(_) => 1,
                });
                put_str(&mut self.out, m.as_str());
            }
            self.out.push(match r.relation {
                None => 0,
                Some(ClassRelation::Extends) => 1,
                Some(ClassRelation::Implements) => 2,
            });
            put_u32(&mut self.out, r.sites.len() as u32);
            for site in &r.sites {
                put_u32(&mut self.out, site.offset);
                put_u32(&mut self.out, site.matched as u32);
                put_opt(&mut self.out, site.pc);
                put_opt(&mut self.out, site.line);
            }
            match &r.context {
                None => self.out.push(0),
                Some(c) => {
                    self.out.push(1);
                    put_str(&mut self.out, c);
                }
            }
        }
        if self.out.len() > L3_MAX_RESULT {
            self.keep = false;
            self.out = Vec::new();
        }
    }

    pub(crate) fn finish(mut self) -> Option<Vec<u8>> {
        put_u32(&mut self.out, RESULT_END);
        self.keep.then_some(self.out)
    }
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_opt(out: &mut Vec<u8>, v: Option<u32>) {
    match v {
        None => out.push(0),
        Some(v) => {
            out.push(1);
            put_u32(out, v);
        }
    }
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_u32(out, s.len() as u32);
    out.extend_from_slice(s.as_bytes());
}

/// Batches recorded by [`ResultRecorder`]; `None` for anything malformed.
pub(crate) fn decode_batches(bytes: &[u8]) -> Option<Vec<RefBatch>> {
    let mut r = Cursor { bytes, at: 0 };
    if r.u32()? != RESULT_FORMAT {
        return None;
    }
    let mut out = Vec::new();
    loop {
        let len = r.u32()?;
        if len == RESULT_END {
            return (r.at == bytes.len()).then_some(out);
        }
        let entry_name = String::from_utf8(r.take(len as usize)?.to_vec()).ok()?;
        let n = r.u32()? as usize;
        let mut results = Vec::with_capacity(n.min(bytes.len()));
        for _ in 0..n {
            let dex_name = r.str()?;
            let method_idx = r.u32()?;
            let method = r.str()?;
            let signature = r.str()?;
            let m = r.u32()? as usize;
            let matched = (0..m)
                .map(|_| match r.u8()? {
                    0 => Some(Matched::String(r.str()?)),
                    1 => Some(Matched::Symbol(r.str()?)),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()?;
            let relation = match r.u8()? {
                0 => None,
                1 => Some(ClassRelation::Extends),
                2 => Some(ClassRelation::Implements),
                _ => return None,
            };
            let sites = (0..r.u32()?)
                .map(|_| Some(RefSite { offset: r.u32()?, matched: r.u32()? as usize, pc: r.opt()?, line: r.opt()? }))
                .collect::<Option<Vec<_>>>()?;
            let context = match r.u8()? {
                0 => None,
                1 => Some(r.str()?),
                _ => return None,
            };
            results.push(RefResult { dex_name, method_idx, method, signature, matched, relation, sites, context });
        }
        out.push(RefBatch { entry_name, results, inflate_us: 0, search_us: 0, source: "result", error: None });
    }
}

struct Cursor<'b> {
    bytes: &'b [u8],
    at: usize,
}

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let s = self.bytes.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(s)
    }

    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }

    /// `Some(None)` / `Some(Some(v))` for a present field, `None` when malformed.
    fn opt(&mut self) -> Option<Option<u32>> {
        match self.u8()? {
            0 => Some(None),
            1 => Some(Some(self.u32()?)),
            _ => None,
        }
    }

    fn str(&mut self) -> Option<String> {
        let n = self.u32()? as usize;
        String::from_utf8(self.take(n)?.to_vec()).ok()
    }
}

/// How often a memory cache re-reads the registry and resizes itself.
const REBALANCE_EVERY: Duration = Duration::from_secs(1);

/// The process's registration: one per process, however many caches it has.
struct Registration {
    caches: usize,
    registry: Option<ProcessRegistry>,
    /// Bytes held by all of this process's memory caches.
    held: u64,
    /// Requests in progress ([`Busy`]).
    requests: usize,
}

impl Registration {
    fn publish(&self) {
        if let Some(registry) = &self.registry {
            let _ = registry.update(self.held, self.requests > 0);
        }
    }
}

static REGISTRATION: Mutex<Registration> = Mutex::new(Registration { caches: 0, registry: None, held: 0, requests: 0 });

/// Marks this process busy in the user's process registry while a request
/// (an MCP tool call, a daemon command) runs, so the others split the CPUs
/// with it from its first moment ([`auto_threads`]) and take them back as soon
/// as it ends. Nested and concurrent requests count once.
#[must_use = "the process is busy only while the guard lives"]
pub struct Busy(());

impl Busy {
    pub fn enter() -> Busy {
        let mut reg = REGISTRATION.lock().unwrap();
        reg.requests += 1;
        if reg.requests == 1 {
            reg.publish();
        }
        Busy(())
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        let mut reg = REGISTRATION.lock().unwrap();
        reg.requests -= 1;
        if reg.requests == 0 {
            reg.publish();
        }
    }
}

/// The memory budget of one memory cache: published to the user's process
/// registry and, when automatic, resized to this process's share of one
/// budget for all registered processes ([`auto_memory_share`]).
pub(crate) struct MemoryBudget {
    auto: bool,
    last: Mutex<Option<Instant>>,
    published: AtomicU64,
}

impl MemoryBudget {
    pub(crate) fn new(auto: bool) -> MemoryBudget {
        let mut reg = REGISTRATION.lock().unwrap();
        reg.caches += 1;
        if reg.registry.is_none() {
            reg.registry = ProcessRegistry::default_dir().and_then(ProcessRegistry::open);
        }
        MemoryBudget { auto, last: Mutex::new(None), published: AtomicU64::new(0) }
    }

    /// Publish what `memory` holds and, when automatic, resize it to this
    /// process's share. At most once per [`REBALANCE_EVERY`].
    pub(crate) fn maybe_rebalance(&self, memory: &SharedMemory) {
        {
            let mut last = self.last.lock().unwrap();
            if last.is_some_and(|t| t.elapsed() < REBALANCE_EVERY) {
                return;
            }
            *last = Some(Instant::now());
        }
        let used = {
            let m = memory.lock().unwrap();
            (m.used_bytes() + m.reserved_bytes()) as u64
        };
        let previous = self.published.swap(used, Ordering::Relaxed);
        let (held, others) = {
            let mut reg = REGISTRATION.lock().unwrap();
            reg.held = (reg.held + used).saturating_sub(previous);
            reg.publish();
            let Some(registry) = &reg.registry else { return };
            (reg.held, registry.others())
        };
        if self.auto {
            let cap = auto_memory_share(available_memory(), held, &others);
            memory.lock().unwrap().set_capacity(cap);
        }
    }
}

impl Drop for MemoryBudget {
    fn drop(&mut self) {
        let mut reg = REGISTRATION.lock().unwrap();
        reg.held = reg.held.saturating_sub(self.published.load(Ordering::Relaxed));
        reg.caches -= 1;
        if reg.caches == 0 {
            // Unregisters (removes this process's entry).
            reg.registry = None;
        } else {
            reg.publish();
        }
    }
}

/// This process's share of one memory budget for every registered process
/// of the user: a quarter of what they could hold together (the available
/// memory plus what their caches hold already), split evenly, clamped to
/// [`AUTO_MEMORY_MIN`]..=[`AUTO_MEMORY_MAX`]. Alone, the same as
/// [`crate::auto_memory_bytes`] (with its own cache counted back in).
pub fn auto_memory_share(available: Option<u64>, held_here: u64, others: &[ProcessUsage]) -> usize {
    let Some(available) = available else { return auto_memory_bytes_for(None) };
    let held: u64 = held_here + others.iter().map(|o| o.bytes).sum::<u64>();
    let share = available.saturating_add(held) / 4 / (others.len() as u64 + 1);
    usize::try_from(share).unwrap_or(usize::MAX).clamp(AUTO_MEMORY_MIN, AUTO_MEMORY_MAX)
}

/// Busy for [`auto_threads`], for an entry that does not say ([`Busy`]
/// came later): one updated this recently. Memory caches republish at most
/// every [`REBALANCE_EVERY`] while they load entries, and not at all when
/// idle (an MCP server waiting for an agent's next call).
const BUSY_WINDOW: Duration = Duration::from_secs(5);

/// How often [`auto_threads`] re-reads the registry: a burst of scans
/// started together by several agents lasts about a second. A read checks
/// every entry's process: about 1 ms for 31 servers on macOS, which callers
/// wait for (letting them go on with the last count made 16 servers' cold
/// sweep 10 % slower).
const THREADS_EVERY: Duration = Duration::from_millis(100);

/// Worker threads of a search whose caller fixed none: this machine's CPUs
/// split between this process and the user's other busy registered ones
/// ([`auto_threads_for`]). Re-read at most once per [`THREADS_EVERY`], so
/// a sweep follows the others starting and finishing their scans
/// ([`crate::Threads::wait_turn`]).
pub fn auto_threads() -> usize {
    static LAST: Mutex<Option<(Instant, usize)>> = Mutex::new(None);
    let mut last = LAST.lock().unwrap();
    if let Some((at, threads)) = *last {
        if at.elapsed() < THREADS_EVERY {
            return threads;
        }
    }
    let others = match &REGISTRATION.lock().unwrap().registry {
        Some(registry) => registry.others(),
        // One-shot commands keep no memory cache and do not register; they
        // still give way to the resident hosts.
        None => ProcessRegistry::default_dir().map(|d| ProcessRegistry::others_in(&d)).unwrap_or_default(),
    };
    let busy = others.iter().filter(|o| o.busy.unwrap_or(o.idle < BUSY_WINDOW)).count();
    let cpus = cpus();
    let threads = auto_threads_for(cpus, busy);
    *last = Some((Instant::now(), threads));
    threads
}

/// This machine's CPUs.
pub(crate) fn cpus() -> usize {
    std::thread::available_parallelism().map_or(8, |n| n.get())
}

/// Workers the busy processes may start together, per CPU. An exact split
/// (1) leaves CPUs idle while the processes holding the largest APKs finish
/// alone: 8 servers scanning 312 APKs on 16 CPUs took 223 ms with 2 workers
/// each, 180 ms with 8 and 176 ms with 16, for 13 % more memory at 8.
const OVERSUBSCRIBE: usize = 4;

/// [`OVERSUBSCRIBE`] x `cpus` workers split evenly between this process and
/// `busy_others`, at most `cpus` and at least 2 (where there are 2): a scan
/// on one thread gives up its overlap of inflating one entry while searching
/// another. Up to 4 busy processes each keep every CPU.
pub fn auto_threads_for(cpus: usize, busy_others: usize) -> usize {
    (cpus * OVERSUBSCRIBE / (busy_others + 1)).clamp(cpus.min(2), cpus)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_splits_one_budget_between_processes() {
        const GIB: u64 = 1 << 30;
        let other = |bytes| ProcessUsage { pid: 1, bytes, idle: Duration::ZERO, busy: None };
        // Alone: a quarter of what is available plus what we hold.
        assert_eq!(auto_memory_share(Some(4 * GIB), 0, &[]), GIB as usize);
        assert_eq!(auto_memory_share(Some(3 * GIB), GIB, &[]), GIB as usize);
        assert_eq!(auto_memory_share(Some(64 * GIB), 0, &[]), AUTO_MEMORY_MAX);
        // Eight processes on 8 GiB available, 1 GiB held among them.
        let others = vec![other(GIB / 8); 7];
        assert_eq!(auto_memory_share(Some(8 * GIB), GIB / 8, &others), (9 * GIB / 4 / 8) as usize);
        // Never below the floor, unknown memory keeps the old default.
        assert_eq!(auto_memory_share(Some(GIB), 0, &vec![other(0); 63]), AUTO_MEMORY_MIN);
        assert_eq!(auto_memory_share(None, 0, &others), AUTO_MEMORY_MAX);
    }

    #[test]
    fn threads_split_between_busy_processes() {
        assert_eq!(auto_threads_for(32, 0), 32);
        assert_eq!(auto_threads_for(32, 3), 32, "4 busy processes keep every CPU");
        assert_eq!(auto_threads_for(32, 7), 16);
        assert_eq!(auto_threads_for(32, 15), 8);
        assert_eq!(auto_threads_for(32, 255), 2, "never below 2");
        assert_eq!(auto_threads_for(1, 3), 1, "nor above the CPUs");
        assert!(auto_threads() >= 1);
    }

    #[test]
    fn workers_wait_for_their_turn() {
        use crate::Threads;
        Threads::Auto.wait_turn(0, || panic!("the first worker always runs"));
        Threads::Fixed(1).wait_turn(5, || panic!("fixed counts never hold a worker back"));
        let asked = std::sync::atomic::AtomicUsize::new(0);
        // Past every CPU a worker waits until the search tells it to stop.
        Threads::Auto.wait_turn(Threads::Auto.most(), || asked.fetch_add(1, Ordering::Relaxed) >= 2);
        assert_eq!(asked.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn results_roundtrip_and_errors_are_not_kept() {
        let row = |rel| RefResult {
            dex_name: "classes.dex".into(),
            method_idx: 7,
            method: "La;->b".into(),
            signature: "La;->b()V".into(),
            matched: vec![Matched::String("x\ny".into()), Matched::Symbol("La;->c:I".into())],
            relation: rel,
            sites: vec![RefSite { offset: 9, matched: 1, pc: Some(3), line: None }],
            context: rel.map(|_| "    const-string v0, \"x\"".to_string()),
        };
        let batch = |name: &str, results, error: Option<String>| RefBatch {
            entry_name: name.into(),
            results,
            inflate_us: 5,
            search_us: 6,
            source: "inflate",
            error,
        };
        let mut rec = ResultRecorder::new();
        rec.record(&batch("classes.dex", vec![row(None), row(Some(ClassRelation::Implements))], None));
        rec.record(&batch("classes2.dex", vec![], None));
        let bytes = rec.finish().unwrap();
        let back = decode_batches(&bytes).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].results, vec![row(None), row(Some(ClassRelation::Implements))]);
        assert_eq!((back[1].entry_name.as_str(), back[1].source), ("classes2.dex", "result"));
        assert!(decode_batches(&bytes[..bytes.len() - 1]).is_none());
        // Cut at a batch boundary: the end marker is missing.
        let mut one = ResultRecorder::new();
        one.record(&batch("classes2.dex", vec![], None));
        let one = one.finish().unwrap();
        assert!(decode_batches(&one[..one.len() - 4]).is_none());
        assert_eq!(decode_batches(&one).unwrap().len(), 1);
        assert!(decode_batches(b"").is_none());
        let mut failed = ResultRecorder::new();
        failed.record(&batch("classes.dex", vec![], Some("bad".into())));
        assert!(failed.finish().is_none());
    }
}
