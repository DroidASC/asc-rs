//! Background data access: class index, class extraction, reference search.
//!
//! Every job runs on its own thread and reports back through [`Event`]s. The
//! UI never blocks: it drains the channel once per frame. Search events carry
//! the generation number of the search that produced them, so results from a
//! cancelled or superseded search can be told apart from the current one;
//! class events carry a request id for the same reason. A panicking worker
//! is caught and reported as an error event so nothing stays at "loading".

use asc_dex::container::logical_dex_buffers;
use asc_dex::Dex;
use asc_engine::{Engine, RefResult};
use asc_findrefs::Query;
use std::collections::{BTreeMap, HashSet};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// A class known to the index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassEntry {
    pub descriptor: String,
    pub dex_name: String,
}

/// Package tree node.
#[derive(Debug, Default)]
pub struct PackageNode {
    pub children: BTreeMap<String, PackageNode>,
    pub classes: Vec<ClassEntry>,
    /// Classes in this package and every sub-package, fixed at build time.
    pub count: usize,
}

impl PackageNode {
    fn insert(&mut self, parts: &[&str], entry: ClassEntry) {
        self.count += 1;
        match parts.split_first() {
            Some((head, rest)) if !rest.is_empty() => self.children.entry((*head).to_string()).or_default().insert(rest, entry),
            _ => self.classes.push(entry),
        }
    }
}

/// Immutable class index built once per APK.
#[derive(Debug, Default)]
pub struct ClassIndex {
    pub root: PackageNode,
    pub all: Vec<ClassEntry>,
    /// Lower-cased descriptors, parallel to `all`, so filtering never
    /// re-allocates per class.
    lower: Vec<String>,
    known: HashSet<String>,
    pub dex_count: usize,
}

impl ClassIndex {
    pub fn build(mut all: Vec<ClassEntry>, dex_count: usize) -> ClassIndex {
        all.sort_by(|a, b| a.descriptor.cmp(&b.descriptor));
        all.dedup_by(|a, b| a.descriptor == b.descriptor);
        let mut root = PackageNode::default();
        for entry in &all {
            let parts: Vec<&str> = asc_engine::names::class_inner(&entry.descriptor).split('/').collect();
            root.insert(&parts, entry.clone());
        }
        let lower = all.iter().map(|c| c.descriptor.to_lowercase()).collect();
        let known = all.iter().map(|c| c.descriptor.clone()).collect();
        ClassIndex { root, all, lower, known, dex_count }
    }

    /// Whether `descriptor` (Dalvik form) is defined in the APK.
    pub fn contains(&self, descriptor: &str) -> bool {
        self.known.contains(descriptor)
    }

    /// Case-insensitive substring filter over descriptors; returns indexes
    /// into `all`. Dots are accepted as package separators.
    pub fn filter(&self, keyword: &str, limit: usize) -> Vec<usize> {
        let kw = keyword.to_lowercase().replace('.', "/");
        if kw.is_empty() {
            return Vec::new();
        }
        self.lower.iter().enumerate().filter(|(_, d)| d.contains(&kw)).map(|(i, _)| i).take(limit).collect()
    }
}

/// Outcome of enumerating the classes of an APK.
pub struct LoadedIndex {
    pub index: ClassIndex,
    /// `entry: error` for every DEX entry (or logical DEX) that could not be
    /// read or parsed; the index still holds the classes of the others.
    pub failed: Vec<String>,
}

/// Messages from background jobs to the UI.
pub enum Event {
    LoadProgress {
        done: usize,
        total: usize,
    },
    Loaded {
        result: Result<LoadedIndex, String>,
        elapsed_ms: u128,
    },
    /// `req` is the id handed to [`Store::open_class`]; a reply whose id no
    /// longer matches the tab's is stale and must be ignored.
    ClassOpened {
        descriptor: String,
        req: u64,
        result: Result<OpenedClass, String>,
    },
    Manifest(Result<String, String>),
    SearchProgress {
        gen: u64,
        done: usize,
        total: usize,
        hits: usize,
    },
    SearchResults {
        gen: u64,
        rows: Vec<RefResult>,
    },
    /// One DEX entry of search `gen` could not be searched.
    SearchError {
        gen: u64,
        message: String,
    },
    SearchDone {
        gen: u64,
        result: Result<usize, String>,
    },
}

/// A class extracted and disassembled by [`Store::open_class`].
pub struct OpenedClass {
    pub dex_name: String,
    pub source: String,
    pub scan_ms: u128,
    /// Set when the class could not be rebuilt and was disassembled in place.
    pub warning: Option<String>,
}

/// Handle shared by the UI and its workers.
pub struct Store {
    pub engine: Arc<Engine>,
    pub tx: Sender<Event>,
    pub ctx: egui::Context,
}

/// Human-readable payload of a caught panic.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

impl Store {
    fn send(&self, ev: Event) {
        let _ = self.tx.send(ev);
        self.ctx.request_repaint();
    }

    /// Run `body` on a new thread; if it panics, `on_panic` turns the panic
    /// message into the event that unblocks the UI.
    ///
    /// This only helps in builds that unwind: the workspace release profile
    /// sets `panic = "abort"`, so there a panicking worker takes the process
    /// down. The engine is written not to panic on hostile input; this is a
    /// debug-build safety net, not a guarantee.
    fn spawn(self: &Arc<Self>, body: impl FnOnce(&Store) + Send + 'static, on_panic: impl FnOnce(String) -> Event + Send + 'static) {
        let me = Arc::clone(self);
        std::thread::spawn(move || {
            if let Err(payload) = catch_unwind(AssertUnwindSafe(|| body(&me))) {
                me.send(on_panic(format!("worker panicked: {}", panic_message(&*payload))));
            }
        });
    }

    /// Enumerate every class in the APK on a worker pool.
    pub fn load_index(self: &Arc<Self>) {
        let started = Instant::now();
        self.spawn(
            move |me| {
                let result = me.enumerate_classes();
                me.send(Event::Loaded { result, elapsed_ms: started.elapsed().as_millis() });
            },
            move |e| Event::Loaded { result: Err(e), elapsed_ms: started.elapsed().as_millis() },
        );
    }

    fn enumerate_classes(&self) -> Result<LoadedIndex, String> {
        let apk = self.engine.open().map_err(|e| e.to_string())?;
        let entries = apk.dex_entries().map_err(|e| e.to_string())?;
        let key = self.engine.apk_key(&apk);
        let total = entries.len();
        let next = AtomicUsize::new(0);
        let done = AtomicUsize::new(0);
        let all: Mutex<Vec<ClassEntry>> = Mutex::new(Vec::new());
        let failed: Mutex<Vec<String>> = Mutex::new(Vec::new());
        std::thread::scope(|s| {
            for _ in 0..self.engine.threads().min(total.max(1)) {
                let (apk, entries, next, done, all, failed, key) = (&apk, &entries, &next, &done, &all, &failed, key.as_ref());
                s.spawn(move || loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(entry) = entries.get(i) else { break };
                    match self.engine.entry_bytes(apk, key, entry) {
                        Ok(data) => {
                            let mut local = Vec::new();
                            let mut bad = Vec::new();
                            for (name, buf) in logical_dex_buffers(&entry.name, &data) {
                                match Dex::with_name(&buf, &name) {
                                    Ok(dex) => {
                                        for def in dex.class_defs().flatten() {
                                            if let Ok(desc) = dex.type_descriptor(def.class_idx) {
                                                local.push(ClassEntry { descriptor: desc, dex_name: name.clone() });
                                            }
                                        }
                                    }
                                    Err(e) => bad.push(format!("{name}: {e}")),
                                }
                            }
                            all.lock().unwrap().extend(local);
                            failed.lock().unwrap().extend(bad);
                        }
                        Err(e) => failed.lock().unwrap().push(format!("{}: {e}", entry.name)),
                    }
                    let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                    self.send(Event::LoadProgress { done: d, total });
                });
            }
        });
        let all = all.into_inner().unwrap();
        let mut failed = failed.into_inner().unwrap();
        failed.sort();
        if all.is_empty() && !failed.is_empty() {
            return Err(failed.join("\n"));
        }
        Ok(LoadedIndex { index: ClassIndex::build(all, total), failed })
    }

    /// Extract and disassemble one class; the reply carries `req` back.
    pub fn open_class(self: &Arc<Self>, descriptor: String, req: u64) {
        let d = descriptor.clone();
        self.spawn(
            move |me| {
                let result = me
                    .engine
                    .get_class(&descriptor)
                    .map(|s| OpenedClass { dex_name: s.dex_name, source: s.source, scan_ms: s.scan_us / 1000, warning: s.warning })
                    .map_err(|e| e.to_string());
                me.send(Event::ClassOpened { descriptor, req, result });
            },
            move |e| Event::ClassOpened { descriptor: d, req, result: Err(e) },
        );
    }

    pub fn open_manifest(self: &Arc<Self>) {
        self.spawn(
            |me| {
                let result = me.engine.manifest_xml().map_err(|e| e.to_string());
                me.send(Event::Manifest(result));
            },
            |e| Event::Manifest(Err(e)),
        );
    }

    /// Run a reference search; results stream back per DEX, tagged with `gen`.
    pub fn search(self: &Arc<Self>, query: Query, gen: u64, cancel: Arc<AtomicBool>) {
        self.spawn(
            move |me| {
                let total = me.engine.dex_entries().map(|e| e.len()).unwrap_or(0);
                let mut done = 0usize;
                let mut hits = 0usize;
                let mut sink = |batch: asc_engine::RefBatch| {
                    done += 1;
                    hits += batch.results.len();
                    if let Some(e) = batch.error {
                        me.send(Event::SearchError { gen, message: format!("{}: {e}", batch.entry_name) });
                    }
                    if !batch.results.is_empty() {
                        me.send(Event::SearchResults { gen, rows: batch.results });
                    }
                    me.send(Event::SearchProgress { gen, done, total, hits });
                };
                let result = me.engine.find_refs_with(&query, true, &cancel, &mut sink).map(|s| s.total_results).map_err(|e| e.to_string());
                me.send(Event::SearchDone { gen, result });
            },
            move |e| Event::SearchDone { gen, result: Err(e) },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(d: &str, dex: &str) -> ClassEntry {
        ClassEntry { descriptor: d.into(), dex_name: dex.into() }
    }

    fn sample() -> ClassIndex {
        ClassIndex::build(
            vec![
                entry("Lcom/x/app/Main;", "classes.dex"),
                entry("Lcom/x/app/Util;", "classes2.dex"),
                entry("Lcom/x/lib/Api;", "classes.dex"),
                entry("LMain;", "classes.dex"),
                entry("Lcom/x/app/Main;", "classes2.dex"),
                entry("Lb/A;", "classes.dex"),
            ],
            2,
        )
    }

    #[test]
    fn build_sorts_and_dedupes() {
        let ix = sample();
        let names: Vec<&str> = ix.all.iter().map(|c| c.descriptor.as_str()).collect();
        assert_eq!(names, ["LMain;", "Lb/A;", "Lcom/x/app/Main;", "Lcom/x/app/Util;", "Lcom/x/lib/Api;"]);
        assert_eq!(ix.dex_count, 2);
        assert!(ix.contains("Lcom/x/lib/Api;"));
        assert!(!ix.contains("Lcom/x/lib/Nope;"));
    }

    #[test]
    fn package_tree_has_counts_and_default_package() {
        let ix = sample();
        assert_eq!(ix.root.count, 5);
        assert_eq!(ix.root.classes, vec![entry("LMain;", "classes.dex")]);
        let com = &ix.root.children["com"];
        assert_eq!(com.count, 3);
        assert!(com.classes.is_empty());
        let x = &com.children["x"];
        assert_eq!(x.children.keys().collect::<Vec<_>>(), ["app", "lib"]);
        assert_eq!(x.children["app"].count, 2);
        assert_eq!(
            x.children["app"].classes.iter().map(|c| c.descriptor.as_str()).collect::<Vec<_>>(),
            ["Lcom/x/app/Main;", "Lcom/x/app/Util;"]
        );
        assert_eq!(x.children["lib"].count, 1);
        assert_eq!(ix.root.children["b"].count, 1);
    }

    #[test]
    fn filter_accepts_dots_and_limits() {
        let ix = sample();
        let hit = |kw: &str, n: usize| ix.filter(kw, n).into_iter().map(|i| ix.all[i].descriptor.clone()).collect::<Vec<_>>();
        assert_eq!(hit("com.x.app", 10), ["Lcom/x/app/Main;", "Lcom/x/app/Util;"]);
        assert_eq!(hit("MAIN", 10), ["LMain;", "Lcom/x/app/Main;"]);
        assert_eq!(hit("main", 1), ["LMain;"]);
        assert!(hit("", 10).is_empty());
        assert!(hit("zzz", 10).is_empty());
    }

    #[test]
    fn panic_payloads_are_readable() {
        let err = catch_unwind(|| panic!("boom {}", 1)).unwrap_err();
        assert_eq!(panic_message(&*err), "boom 1");
        let err = catch_unwind(|| panic!("literal")).unwrap_err();
        assert_eq!(panic_message(&*err), "literal");
    }
}
