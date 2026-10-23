//! Building the locator tables of an opened APK ahead of its first query
//! ([`Engine::prebuild`]), on background threads that give way to queries.
//!
//! * Only entries already held by the caches are prepared (the memory cache
//!   after a warm open, L1, or stored entries, which only need mapping): a
//!   prebuild never inflates, so on a budget too small for the APK it does
//!   nothing rather than thrash the LRU.
//! * Tables persisted in L2 are mapped instead of built; tables built here
//!   are queued for L2 like a query's.
//! * Queries come first: the workers run at the lowest CPU priority and
//!   stop between tables while a search of this engine is running. A query
//!   needing a table a worker is half way through waits for that build
//!   (`SearchState` builds each table once) instead of starting over.
//! * [`Engine::cancel_prebuild`] stops it between tables and waits for the
//!   workers; it is permanent for the engine (an APK closed for good).

use crate::{lookup_cached, recharge, tiers, Engine, Job, Loaded, Result, WriteJob};
use asc_cache::Tier;
use asc_dex::Dex;
use asc_findrefs::FindRefs;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// How a paused worker polls for the searches it gave way to.
const YIELD_POLL: Duration = Duration::from_millis(1);
/// L2 writes a prebuild lets queue up before it waits for the writer.
const MAX_PENDING_WRITES: usize = 2;

/// The tables a prebuild prepares, in order (every search needs the
/// instruction table; strings and types back most member queries too). The
/// call graph is left to the first walk: it is large and rarely needed.
const TABLES: [fn(&FindRefs<'_, '_, '_>) -> asc_findrefs::Result<()>; 5] = [
    |f| f.insn_locator().map(drop),
    |f| f.string_locator().map(drop),
    |f| f.type_locator().map(drop),
    |f| f.method_locator().map(drop),
    |f| f.field_locator().map(drop),
];

/// Background build state of one engine.
#[derive(Default)]
pub(crate) struct Prebuild {
    cancel: AtomicBool,
    running: Mutex<bool>,
    done: Condvar,
    /// Searches of this engine in progress: workers wait while any runs.
    queries: AtomicUsize,
}

/// Held by a search for its duration ([`Prebuild::query`]).
pub(crate) struct QueryGuard<'p>(&'p Prebuild);

impl Drop for QueryGuard<'_> {
    fn drop(&mut self) {
        self.0.queries.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Prebuild {
    /// Mark a search as running until the guard drops.
    pub(crate) fn query(&self) -> QueryGuard<'_> {
        self.queries.fetch_add(1, Ordering::Relaxed);
        QueryGuard(self)
    }

    pub(crate) fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// Wait while a search runs; `false` once cancelled.
    fn give_way(&self) -> bool {
        while self.queries.load(Ordering::Relaxed) > 0 && !self.cancelled() {
            std::thread::sleep(YIELD_POLL);
        }
        !self.cancelled()
    }
}

/// What [`Engine::prebuild`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrebuildReport {
    /// Logical DEX files prepared.
    pub dex: usize,
    /// Of those, the ones whose tables came from L2.
    pub from_disk: usize,
    /// Root entries skipped because no cache held them.
    pub skipped: usize,
    /// Stopped by [`Engine::cancel_prebuild`] (or already running).
    pub cancelled: bool,
    pub elapsed_us: u128,
}

impl Engine {
    /// Build (or map from L2) the locator tables of every DEX entry the
    /// caches hold, so the first query of each kind skips its table builds.
    /// Blocks until done; meant for a background thread after a warm open.
    /// Does nothing without a memory cache (the tables would be dropped).
    pub fn prebuild(&self) -> Result<PrebuildReport> {
        let t0 = Instant::now();
        let mut report = PrebuildReport::default();
        let Some(cache) = self.cache.as_deref().filter(|c| c.memory.is_some()) else { return Ok(report) };
        {
            let mut running = self.prebuild.running.lock().unwrap();
            if *running || self.prebuild.cancelled() {
                report.cancelled = true;
                return Ok(report);
            }
            *running = true;
        }
        let _done = Finished(&self.prebuild);
        let apk = self.open()?;
        let mut entries = apk.dex_entries()?;
        // Largest first, as a search runs them.
        entries.reverse();
        let key = self.apk_key(&apk);
        let l2 = cache.disk.as_deref().filter(|d| d.uses(Tier::Derived)).zip(key.as_ref());
        let next = AtomicUsize::new(0);
        let tally = Mutex::new(&mut report);
        std::thread::scope(|s| {
            for _ in 0..self.threads().min(entries.len()) {
                s.spawn(|| {
                    lower_priority();
                    while self.prebuild.give_way() {
                        let Some(entry) = entries.get(next.fetch_add(1, Ordering::Relaxed)) else { break };
                        let cached = match lookup_cached(cache, key.as_ref(), entry, &self.stats) {
                            Some((e, _)) => Some(e),
                            // Stored entries are only mapped: as cheap as a lookup.
                            None if entry.method == asc_apk::METHOD_STORED => {
                                match crate::load_entry(&apk, key.as_ref(), entry, Some(cache), &self.stats, Some(&self.prebuild.cancel)) {
                                    Ok((Loaded::Cached(e), _)) => Some(e),
                                    _ => None,
                                }
                            }
                            None => None,
                        };
                        let Some(e) = cached else {
                            tally.lock().unwrap().skipped += 1;
                            continue;
                        };
                        for (i, l) in e.logical().iter().enumerate() {
                            let Ok(dex) = Dex::with_name(&l.data, &l.name) else { continue };
                            let mapped = l2.is_some_and(|(disk, k)| tiers::load_derived(disk, k, l, &dex));
                            let (mask, t) = (l.state.table_mask(), Instant::now());
                            let fr = FindRefs::with_state(&dex, &l.state);
                            for build in TABLES {
                                // A damaged DEX fails its query later with the same error.
                                if !self.prebuild.give_way() || build(&fr).is_err() {
                                    break;
                                }
                            }
                            if let Some((disk, k)) = l2 {
                                if let Some(job) = tiers::derived_job(disk, &e, i, mask, t.elapsed()) {
                                    cache.put_async(WriteJob { key: k.clone(), apk: Arc::from(apk.path()), kind: Job::Derived(job) });
                                    // Built tables stay on the heap until the writer maps them:
                                    // building far ahead of it only adds up heap.
                                    while cache.derived_pending.load(Ordering::Relaxed) > MAX_PENDING_WRITES && !self.prebuild.cancelled() {
                                        std::thread::sleep(YIELD_POLL);
                                    }
                                }
                            }
                            let mut tally = tally.lock().unwrap();
                            tally.dex += 1;
                            tally.from_disk += mapped as usize;
                        }
                        recharge(Some(cache), key.as_ref(), &e);
                    }
                });
            }
        });
        report.cancelled = self.prebuild.cancelled();
        report.elapsed_us = t0.elapsed().as_micros();
        self.log(format!(
            "[APK] prebuild dex={} from_disk={} skipped={} cancelled={} total={} us",
            report.dex, report.from_disk, report.skipped, report.cancelled, report.elapsed_us
        ));
        Ok(report)
    }

    /// Stop a running [`Engine::prebuild`] (and any later one) and wait for
    /// its workers to finish the table they are on.
    pub fn cancel_prebuild(&self) {
        self.prebuild.cancel();
        let mut running = self.prebuild.running.lock().unwrap();
        while *running {
            running = self.prebuild.done.wait(running).unwrap();
        }
    }
}

/// Clears `running` when a prebuild ends, however it ends.
struct Finished<'p>(&'p Prebuild);

impl Drop for Finished<'_> {
    fn drop(&mut self) {
        *self.0.running.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = false;
        self.0.done.notify_all();
    }
}

/// Run the calling thread at the lowest CPU priority (nice 19), so the
/// prebuild only uses cycles queries leave idle.
fn lower_priority() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        extern "C" {
            fn gettid() -> std::os::raw::c_int;
            fn setpriority(which: std::os::raw::c_int, who: std::os::raw::c_uint, prio: std::os::raw::c_int) -> std::os::raw::c_int;
        }
        const PRIO_PROCESS: std::os::raw::c_int = 0;
        // SAFETY: plain syscalls on the calling thread's own id; Linux applies
        // the nice value to that thread only.
        unsafe {
            setpriority(PRIO_PROCESS, gettid() as std::os::raw::c_uint, 19);
        }
    }
}
