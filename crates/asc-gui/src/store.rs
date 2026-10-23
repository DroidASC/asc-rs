//! Background data access: class index, class extraction, reference search.
//!
//! Every job runs on its own thread and reports back through [`Event`]s. The
//! UI never blocks: it drains the channel once per frame. Search events carry
//! the generation number of the search that produced them, so results from a
//! cancelled or superseded search can be told apart from the current one;
//! class events carry a request id for the same reason. A panicking worker
//! is caught and reported as an error event so nothing stays at "loading".

use asc_engine::{Engine, RefResult};
use asc_findrefs::Query;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Instant;

/// A class known to the index, borrowed from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassEntry<'a> {
    pub descriptor: &'a str,
    pub dex_name: &'a str,
}

/// Package tree node; its name, children and classes are ranges into the
/// index's flat tables.
#[derive(Debug, Clone, Copy)]
struct Node {
    parent: u32,
    /// Byte range of the name in [`ClassIndex::text`].
    name: (u32, u32),
    /// Range of [`ClassIndex::children`].
    children: (u32, u32),
    /// Range of [`ClassIndex::members`].
    classes: (u32, u32),
    /// Classes in this package and every sub-package.
    count: u32,
}

/// Immutable class index built once per APK.
///
/// Descriptors are sorted, deduplicated and stored once, back to back, in
/// `text`; a class is its position in that order. The package tree is a
/// flat node table whose children and classes are ranges into two index
/// arrays, so it costs a few bytes per class rather than another copy.
#[derive(Debug, Default)]
pub struct ClassIndex {
    text: String,
    /// `ends[i]` is the end of descriptor `i` in `text`; it starts at
    /// `ends[i - 1]` (0 for the first).
    ends: Vec<u32>,
    /// Index into `dex_names` of the DEX that defines each class.
    dex: Vec<u16>,
    dex_names: Vec<String>,
    /// Classes whose descriptor is not ASCII, ascending: the only ones the
    /// filter lower-cases with full Unicode rules.
    non_ascii: Vec<u32>,
    /// Node 0 is the default package; a node's parent precedes it.
    nodes: Vec<Node>,
    /// Child node ids, grouped by parent and sorted by name.
    children: Vec<u32>,
    /// Class indexes grouped by package, in descriptor order.
    members: Vec<u32>,
    pub dex_count: usize,
}

/// A package of a [`ClassIndex`].
#[derive(Clone, Copy)]
pub struct Package<'a> {
    ix: &'a ClassIndex,
    node: &'a Node,
}

impl<'a> Package<'a> {
    /// Last component of the package name (empty for the default package).
    pub fn name(&self) -> &'a str {
        name_of(&self.ix.text, self.node)
    }

    /// Classes in this package and every sub-package.
    pub fn count(&self) -> usize {
        self.node.count as usize
    }

    /// Sub-packages, by name.
    pub fn children(&self) -> impl ExactSizeIterator<Item = Package<'a>> + 'a {
        let ix = self.ix;
        ix.children[self.node.children.0 as usize..self.node.children.1 as usize]
            .iter()
            .map(move |&id| Package { ix, node: &ix.nodes[id as usize] })
    }

    /// Classes directly in this package, in descriptor order.
    pub fn classes(&self) -> impl ExactSizeIterator<Item = ClassEntry<'a>> + 'a {
        let ix = self.ix;
        ix.members[self.node.classes.0 as usize..self.node.classes.1 as usize].iter().map(move |&i| ix.get(i as usize))
    }
}

fn name_of<'t>(text: &'t str, node: &Node) -> &'t str {
    &text[node.name.0 as usize..node.name.1 as usize]
}

/// Stable sort by descriptor: equal chunks are sorted on scoped threads,
/// then one more stable sort merges the sorted runs it finds. Equal
/// descriptors keep their input order either way.
fn sort_classes(items: &mut [(String, u16)]) {
    let by_descriptor = |a: &(String, u16), b: &(String, u16)| a.0.cmp(&b.0);
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get()).min(16);
    if threads > 1 && items.len() >= 1 << 15 {
        std::thread::scope(|s| {
            for part in items.chunks_mut(items.len().div_ceil(threads)) {
                s.spawn(move || part.sort_by(by_descriptor));
            }
        });
    }
    items.sort_by(by_descriptor);
}

/// First position at or after `from` where `hay` holds `needle` ignoring
/// ASCII case; `needle` is lower-case ASCII and not empty.
///
/// Candidates for the first byte are found eight bytes at a time: OR-ing a
/// byte with 0x20 gives a lower-case letter exactly when it is that letter
/// in either case, so a letter needs one compare per byte like any other.
fn find_ascii_ci(hay: &[u8], needle: &[u8], mut from: usize) -> Option<usize> {
    const ONES: u64 = u64::from_ne_bytes([0x01; 8]);
    const HIGH: u64 = u64::from_ne_bytes([0x80; 8]);
    let first = needle[0];
    let fold = if first.is_ascii_lowercase() { 0x20 } else { 0 };
    let (pat, fold_word) = (u64::from_ne_bytes([first; 8]), u64::from_ne_bytes([fold; 8]));
    let last = hay.len().checked_sub(needle.len())?;
    while from <= last {
        let candidate = if from + 8 <= hay.len() {
            let x = (u64::from_le_bytes(hay[from..from + 8].try_into().unwrap()) | fold_word) ^ pat;
            let zero = x.wrapping_sub(ONES) & !x & HIGH;
            if zero == 0 {
                from += 8;
                continue;
            }
            from + (zero.trailing_zeros() / 8) as usize
        } else if hay[from] | fold == first {
            from
        } else {
            from += 1;
            continue;
        };
        if candidate > last {
            return None;
        }
        if hay[candidate + 1..candidate + needle.len()].eq_ignore_ascii_case(&needle[1..]) {
            return Some(candidate);
        }
        from = candidate + 1;
    }
    None
}

impl ClassIndex {
    /// Build from `(dex name, descriptors)` groups in DEX order. A class
    /// defined more than once is labelled with the first DEX that has it.
    pub fn build(dexes: impl IntoIterator<Item = (String, Vec<String>)>, dex_count: usize) -> ClassIndex {
        let mut dex_names: Vec<String> = Vec::new();
        let mut dex_ids: HashMap<String, u16> = HashMap::new();
        let mut items: Vec<(String, u16)> = Vec::new();
        for (name, descriptors) in dexes {
            let id = match dex_ids.get(&name) {
                Some(&id) => id,
                // The label is only shown on hover: past 65535 names the
                // last slot stands for all the rest.
                None if dex_names.len() == u16::MAX as usize => {
                    dex_names.push("(one of many DEX files)".to_string());
                    u16::MAX
                }
                None if dex_names.len() > u16::MAX as usize => u16::MAX,
                None => {
                    let id = dex_names.len() as u16;
                    dex_names.push(name.clone());
                    dex_ids.insert(name, id);
                    id
                }
            };
            items.extend(descriptors.into_iter().map(|d| (d, id)));
        }
        drop(dex_ids);
        sort_classes(&mut items);
        items.dedup_by(|a, b| a.0 == b.0);

        let bytes: usize = items.iter().map(|(d, _)| d.len()).sum();
        assert!(bytes <= u32::MAX as usize, "class descriptors exceed 4 GiB");
        let mut text = String::with_capacity(bytes);
        let mut ends = Vec::with_capacity(items.len());
        let mut dex = Vec::with_capacity(items.len());
        let mut non_ascii = Vec::new();
        for (i, (d, id)) in items.into_iter().enumerate() {
            if !d.is_ascii() {
                non_ascii.push(i as u32);
            }
            text.push_str(&d);
            ends.push(text.len() as u32);
            dex.push(id);
        }
        let mut ix = ClassIndex { text, ends, dex, dex_names, non_ascii, dex_count, ..ClassIndex::default() };
        ix.build_tree();
        ix
    }

    /// Fill `nodes`, `children` and `members` from the sorted descriptors.
    fn build_tree(&mut self) {
        let root = Node { parent: 0, name: (0, 0), children: (0, 0), classes: (0, 0), count: 0 };
        let mut nodes = vec![root];
        let mut node_of = Vec::with_capacity(self.len());
        {
            let text = self.text.as_str();
            let base = text.as_ptr() as usize;
            // `path[d]` is the package at depth `d` of the previous class.
            // Descriptors are sorted, so a package is nearly always found
            // there; the map is only consulted for new packages (or, with
            // malformed descriptors, for re-entered ones).
            let mut path: Vec<u32> = vec![0];
            let mut lookup: HashMap<(u32, &str), u32> = HashMap::new();
            for i in 0..self.len() {
                let inner = asc_engine::names::class_inner(self.descriptor(i));
                let mut parent = 0u32;
                let mut segments = inner.split('/').peekable();
                let mut depth = 1;
                while let Some(seg) = segments.next() {
                    if segments.peek().is_none() {
                        break; // the class name itself
                    }
                    let id = match path.get(depth) {
                        Some(&id) if nodes[id as usize].parent == parent && name_of(text, &nodes[id as usize]) == seg => id,
                        _ => {
                            path.truncate(depth);
                            let id = *lookup.entry((parent, seg)).or_insert_with(|| {
                                let start = (seg.as_ptr() as usize - base) as u32;
                                nodes.push(Node { parent, name: (start, start + seg.len() as u32), ..root });
                                (nodes.len() - 1) as u32
                            });
                            path.push(id);
                            id
                        }
                    };
                    parent = id;
                    depth += 1;
                }
                node_of.push(parent);
            }
        }

        // Classes: a counting sort by package keeps descriptor order.
        for &n in &node_of {
            nodes[n as usize].count += 1;
        }
        let mut at = 0u32;
        for node in &mut nodes {
            node.classes = (at, at);
            at += node.count;
        }
        let mut members = vec![0u32; node_of.len()];
        for (i, &n) in node_of.iter().enumerate() {
            let slot = &mut nodes[n as usize].classes.1;
            members[*slot as usize] = i as u32;
            *slot += 1;
        }
        drop(node_of);
        for id in (1..nodes.len()).rev() {
            let (parent, count) = (nodes[id].parent as usize, nodes[id].count);
            nodes[parent].count += count;
        }

        // Children: node ids sorted by (parent, name), one range per parent.
        let text = self.text.as_str();
        let mut children: Vec<u32> = (1..nodes.len() as u32).collect();
        children.sort_unstable_by(|&a, &b| {
            let (a, b) = (&nodes[a as usize], &nodes[b as usize]);
            a.parent.cmp(&b.parent).then_with(|| name_of(text, a).cmp(name_of(text, b)))
        });
        let mut start = 0;
        while start < children.len() {
            let parent = nodes[children[start] as usize].parent;
            let end = start + children[start..].iter().take_while(|&&c| nodes[c as usize].parent == parent).count();
            nodes[parent as usize].children = (start as u32, end as u32);
            start = end;
        }
        self.nodes = nodes;
        self.children = children;
        self.members = members;
    }

    /// Number of classes.
    pub fn len(&self) -> usize {
        self.ends.len()
    }

    /// Descriptor of class `i`.
    pub fn descriptor(&self, i: usize) -> &str {
        let start = if i == 0 { 0 } else { self.ends[i - 1] as usize };
        &self.text[start..self.ends[i] as usize]
    }

    /// Class `i` with its DEX label.
    pub fn get(&self, i: usize) -> ClassEntry<'_> {
        ClassEntry { descriptor: self.descriptor(i), dex_name: &self.dex_names[self.dex[i] as usize] }
    }

    /// The default package, root of the package tree.
    pub fn root(&self) -> Package<'_> {
        Package { ix: self, node: &self.nodes[0] }
    }

    /// Whether `descriptor` (Dalvik form) is defined in the APK.
    pub fn contains(&self, descriptor: &str) -> bool {
        let (mut lo, mut hi) = (0, self.len());
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            match self.descriptor(mid).cmp(descriptor) {
                Ordering::Less => lo = mid + 1,
                Ordering::Greater => hi = mid,
                Ordering::Equal => return true,
            }
        }
        false
    }

    /// Case-insensitive substring filter over descriptors; returns at most
    /// `limit` class indexes, in order. Dots are accepted as package
    /// separators. Same result as `to_lowercase().contains(..)` on every
    /// descriptor: an ASCII descriptor lower-cases to its ASCII lower case,
    /// so only the non-ASCII ones are actually lower-cased.
    pub fn filter(&self, keyword: &str, limit: usize) -> Vec<usize> {
        let kw = keyword.to_lowercase().replace('.', "/");
        let mut out = Vec::new();
        if kw.is_empty() || limit == 0 {
            return out;
        }
        let unicode = |i: usize| self.descriptor(i).to_lowercase().contains(&kw);
        let mut odd = self.non_ascii.iter().map(|&i| i as usize).peekable();
        if !kw.is_ascii() {
            // An ASCII descriptor cannot contain a non-ASCII keyword.
            out.extend(odd.filter(|&i| unicode(i)).take(limit));
            return out;
        }
        // Search all of `text` at once and map each hit to its class; the
        // non-ASCII classes are merged in, in order, wherever they fall.
        let (text, kw) = (self.text.as_bytes(), kw.as_bytes());
        let (mut pos, mut class) = (0, 0);
        while let Some(at) = find_ascii_ci(text, kw, pos) {
            class += self.ends[class..].partition_point(|&e| e as usize <= at);
            let end = self.ends[class] as usize;
            if at + kw.len() > end {
                pos = at + 1; // runs into the next descriptor
                continue;
            }
            while let Some(i) = odd.next_if(|&i| i < class) {
                if unicode(i) && push_full(&mut out, i, limit) {
                    return out;
                }
            }
            if (odd.next_if_eq(&class).is_none() || unicode(class)) && push_full(&mut out, class, limit) {
                return out;
            }
            (pos, class) = (end, class + 1);
        }
        for i in odd {
            if unicode(i) && push_full(&mut out, i, limit) {
                break;
            }
        }
        out
    }
}

/// Push `i`; whether `out` now holds `limit` items.
fn push_full(out: &mut Vec<usize>, i: usize, limit: usize) -> bool {
    out.push(i);
    out.len() >= limit
}

/// Outcome of enumerating the classes of an APK.
pub struct LoadedIndex {
    pub index: ClassIndex,
    /// `entry: error` for every DEX entry (or logical DEX) that could not be
    /// read or parsed; the index still holds the classes of the others.
    pub failed: Vec<String>,
}

/// Turn the result of [`Engine::scan_classes`] into the class index, keeping
/// the classes of every DEX that could be read.
fn index_scanned(scanned: Vec<asc_engine::EntryClasses>) -> Result<LoadedIndex, String> {
    let total = scanned.len();
    let mut dexes = Vec::new();
    let mut failed = Vec::new();
    for entry in scanned {
        match entry.result {
            // Unreadable `class_def`s are skipped silently, as before.
            Ok(list) => {
                for dex in list {
                    match dex.error {
                        Some(e) => failed.push(format!("{}: {e}", dex.dex_name)),
                        None => dexes.push((dex.dex_name, dex.descriptors)),
                    }
                }
            }
            Err(e) => failed.push(format!("{}: {e}", entry.entry_name)),
        }
    }
    failed.sort();
    if dexes.iter().all(|(_, d)| d.is_empty()) && !failed.is_empty() {
        return Err(failed.join("\n"));
    }
    Ok(LoadedIndex { index: ClassIndex::build(dexes, total), failed })
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
        let scanned =
            self.engine.scan_classes(None, |done, total| self.send(Event::LoadProgress { done, total })).map_err(|e| e.to_string())?;
        index_scanned(scanned)
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

    fn entry<'a>(d: &'a str, dex: &'a str) -> ClassEntry<'a> {
        ClassEntry { descriptor: d, dex_name: dex }
    }

    /// One `(dex, [descriptor])` group per class, in the given order.
    fn build(classes: &[(&str, &str)], dex_count: usize) -> ClassIndex {
        ClassIndex::build(classes.iter().map(|&(d, dex)| (dex.to_string(), vec![d.to_string()])), dex_count)
    }

    fn sample() -> ClassIndex {
        build(
            &[
                ("Lcom/x/app/Main;", "classes.dex"),
                ("Lcom/x/app/Util;", "classes2.dex"),
                ("Lcom/x/lib/Api;", "classes.dex"),
                ("LMain;", "classes.dex"),
                ("Lcom/x/app/Main;", "classes2.dex"),
                ("Lb/A;", "classes.dex"),
            ],
            2,
        )
    }

    fn names(ix: &ClassIndex) -> Vec<&str> {
        (0..ix.len()).map(|i| ix.descriptor(i)).collect()
    }

    fn child<'a>(p: Package<'a>, name: &str) -> Package<'a> {
        p.children().find(|c| c.name() == name).unwrap()
    }

    #[test]
    fn build_sorts_and_dedupes() {
        let ix = sample();
        assert_eq!(names(&ix), ["LMain;", "Lb/A;", "Lcom/x/app/Main;", "Lcom/x/app/Util;", "Lcom/x/lib/Api;"]);
        assert_eq!(ix.dex_count, 2);
        assert!(ix.contains("Lcom/x/lib/Api;"));
        assert!(!ix.contains("Lcom/x/lib/Nope;"));
    }

    #[test]
    fn duplicates_keep_the_first_dex() {
        let ix = sample();
        assert_eq!(ix.get(2), entry("Lcom/x/app/Main;", "classes.dex"));
        assert_eq!(ix.get(3), entry("Lcom/x/app/Util;", "classes2.dex"));
        // Interned: two distinct DEX names however often they repeat.
        assert_eq!(ix.dex_names, ["classes.dex", "classes2.dex"]);
        let ix = build(&[("LA;", "b.dex"), ("LA;", "a.dex"), ("LA;", "b.dex")], 2);
        assert_eq!(ix.len(), 1);
        assert_eq!(ix.get(0).dex_name, "b.dex");
    }

    #[test]
    fn contains_searches_every_position() {
        let ix = sample();
        for d in names(&ix) {
            assert!(ix.contains(d), "{d}");
            assert!(!ix.contains(&format!("{d}x")));
            assert!(!ix.contains(&d[..d.len() - 1]));
        }
        assert!(!ix.contains(""));
        assert!(!ClassIndex::default().contains("LA;"));
    }

    #[test]
    fn package_tree_has_counts_and_default_package() {
        let ix = sample();
        let root = ix.root();
        assert_eq!(root.count(), 5);
        assert_eq!(root.classes().collect::<Vec<_>>(), [entry("LMain;", "classes.dex")]);
        let com = child(root, "com");
        assert_eq!(com.count(), 3);
        assert_eq!(com.classes().len(), 0);
        let x = child(com, "x");
        assert_eq!(x.children().map(|c| c.name()).collect::<Vec<_>>(), ["app", "lib"]);
        assert_eq!(child(x, "app").count(), 2);
        assert_eq!(child(x, "app").classes().map(|c| c.descriptor).collect::<Vec<_>>(), ["Lcom/x/app/Main;", "Lcom/x/app/Util;"]);
        assert_eq!(child(x, "lib").count(), 1);
        assert_eq!(child(root, "b").count(), 1);
    }

    #[test]
    fn package_children_sort_by_name_not_by_descriptor() {
        // `-` and `$` sort before `/`, so in descriptor order `a-b/` and
        // `a$/` come before `a/`; as names `a` is first, as in a BTreeMap.
        let ix = build(&[("La/X;", "d"), ("La-b/Y;", "d"), ("La$/Z;", "d"), ("La/c/W;", "d"), ("La/B;", "d")], 1);
        let root = ix.root();
        assert_eq!(root.children().map(|c| (c.name(), c.count())).collect::<Vec<_>>(), [("a", 3), ("a$", 1), ("a-b", 1)]);
        let a = child(root, "a");
        assert_eq!(a.classes().map(|c| c.descriptor).collect::<Vec<_>>(), ["La/B;", "La/X;"]);
        assert_eq!(child(a, "c").classes().map(|c| c.descriptor).collect::<Vec<_>>(), ["La/c/W;"]);
    }

    #[test]
    fn filter_accepts_dots_and_limits() {
        let ix = sample();
        let hit = |kw: &str, n: usize| ix.filter(kw, n).into_iter().map(|i| ix.descriptor(i)).collect::<Vec<_>>();
        assert_eq!(hit("com.x.app", 10), ["Lcom/x/app/Main;", "Lcom/x/app/Util;"]);
        assert_eq!(hit("MAIN", 10), ["LMain;", "Lcom/x/app/Main;"]);
        assert_eq!(hit("main", 1), ["LMain;"]);
        assert!(hit("main", 0).is_empty());
        assert!(hit("", 10).is_empty());
        assert!(hit("zzz", 10).is_empty());
    }

    #[test]
    fn filter_lowercases_non_ascii_names() {
        let ix = build(&[("Lé/Ünï;", "d"), ("Lx/KELVIN\u{212A};", "d"), ("Lx/Plain;", "d"), ("Lx/ΣΑΣ;", "d"), ("Lx/İ;", "d")], 1);
        let hit = |kw: &str| ix.filter(kw, 10).into_iter().map(|i| ix.descriptor(i)).collect::<Vec<_>>();
        assert_eq!(hit("ünï"), ["Lé/Ünï;"]);
        assert_eq!(hit("ÜNÏ"), ["Lé/Ünï;"]);
        assert_eq!(hit("é.ü"), ["Lé/Ünï;"]);
        // The Kelvin sign lower-cases to an ASCII `k`.
        assert_eq!(hit("NK"), ["Lx/KELVIN\u{212A};"]);
        assert_eq!(hit("\u{212A}"), ["Lx/KELVIN\u{212A};"]);
        assert_eq!(hit("σας"), ["Lx/ΣΑΣ;"]);
        assert_eq!(hit("i\u{307}"), ["Lx/İ;"]);
        assert_eq!(hit("x/"), ["Lx/KELVIN\u{212A};", "Lx/Plain;", "Lx/İ;", "Lx/ΣΑΣ;"]);
    }

    #[test]
    fn ascii_search_finds_every_position() {
        let hay = b"xxAbCxxxxxxxabcx-Q";
        let find = |n: &[u8], from| find_ascii_ci(hay, n, from);
        assert_eq!(find(b"abc", 0), Some(2));
        assert_eq!(find(b"abc", 3), Some(12));
        assert_eq!(find(b"abc", 13), None);
        assert_eq!(find(b"-q", 0), Some(16));
        assert_eq!(find(b"q", 17), Some(17));
        assert_eq!(find(b"x-qz", 0), None);
        assert_eq!(find(b"a", 0), Some(2));
        assert_eq!(find(b"xxabcxxxxxxxabcx-qq", 0), None);
        // `@` | 0x20 is a backquote, not a letter.
        assert_eq!(find_ascii_ci(b"@@@@@@@@`", b"`", 0), Some(8));
    }

    #[test]
    fn dex_labels_past_u16_share_the_last_slot() {
        let ix = ClassIndex::build((0..70_000).map(|i| (format!("d{i}"), vec![format!("LC{i};")])), 1);
        assert_eq!(ix.dex_names.len(), 65_536);
        let label = |i: u32| ix.get((0..ix.len()).find(|&k| ix.descriptor(k) == format!("LC{i};")).unwrap()).dex_name;
        assert_eq!(label(65_534), "d65534");
        assert_eq!(label(65_535), "(one of many DEX files)");
        assert_eq!(label(69_999), "(one of many DEX files)");
    }

    /// The previous implementation (one `String` per class, a `BTreeMap`
    /// tree and a lower-cased copy), kept to check the compact one against.
    mod reference {
        use std::collections::BTreeMap;

        #[derive(Default)]
        pub struct Node {
            pub children: BTreeMap<String, Node>,
            pub classes: Vec<(String, String)>,
            pub count: usize,
        }

        pub fn build(mut all: Vec<(String, String)>) -> (Vec<(String, String)>, Node) {
            all.sort_by(|a, b| a.0.cmp(&b.0));
            all.dedup_by(|a, b| a.0 == b.0);
            let mut root = Node::default();
            for e in &all {
                let parts: Vec<&str> = asc_engine::names::class_inner(&e.0).split('/').collect();
                let mut node = &mut root;
                node.count += 1;
                for p in &parts[..parts.len() - 1] {
                    node = node.children.entry(p.to_string()).or_default();
                    node.count += 1;
                }
                node.classes.push(e.clone());
            }
            (all, root)
        }

        pub fn filter(all: &[(String, String)], keyword: &str, limit: usize) -> Vec<usize> {
            let kw = keyword.to_lowercase().replace('.', "/");
            if kw.is_empty() {
                return Vec::new();
            }
            (0..all.len()).filter(|&i| all[i].0.to_lowercase().contains(&kw)).take(limit).collect()
        }
    }

    fn same_tree(p: Package<'_>, r: &reference::Node) {
        assert_eq!(p.count(), r.count);
        let classes: Vec<_> = p.classes().map(|c| (c.descriptor.to_string(), c.dex_name.to_string())).collect();
        assert_eq!(classes, r.classes);
        assert_eq!(p.children().map(|c| c.name()).collect::<Vec<_>>(), r.children.keys().collect::<Vec<_>>());
        for (c, rc) in p.children().zip(r.children.values()) {
            same_tree(c, rc);
        }
    }

    #[test]
    fn matches_the_reference_on_awkward_names() {
        // Small xorshift so the cases are varied but reproducible.
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move |n: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % n as u64) as usize
        };
        let parts = ["a", "A", "b", "a-b", "a$", "", "ü", "Ü", "\u{212A}", "x.y", "com", "Com", "z9"];
        let mut input = Vec::new();
        for _ in 0..3000 {
            let depth = next(4);
            let d = (0..=depth).map(|_| parts[next(parts.len())]).collect::<Vec<_>>().join("/");
            // Mostly well-formed, some without `L` or `;`.
            let d = match next(10) {
                0 => d,
                1 => format!("L{d}"),
                2 => format!("{d};"),
                _ => format!("L{d};"),
            };
            input.push((d, format!("classes{}.dex", next(4))));
        }
        let ix = ClassIndex::build(input.iter().map(|(d, dex)| (dex.clone(), vec![d.clone()])), 4);
        let (all, tree) = reference::build(input);
        assert_eq!(names(&ix), all.iter().map(|e| e.0.as_str()).collect::<Vec<_>>());
        assert!((0..ix.len()).all(|i| ix.get(i).dex_name == all[i].1));
        same_tree(ix.root(), &tree);
        for kw in ["a", "A", "a/", "a.b", "-", "$", "ü", "Ü", "k", "K", "\u{212A}", "/;", ";l", "a;la", "L", "zz", "com/c", "", "."] {
            for limit in [0, 1, 7, usize::MAX] {
                assert_eq!(ix.filter(kw, limit), reference::filter(&all, kw, limit), "{kw:?} {limit}");
            }
        }
        for (d, _) in &all {
            assert!(ix.contains(d));
            assert!(!ix.contains(&format!("{d}~")));
        }
    }

    #[test]
    fn panic_payloads_are_readable() {
        let err = catch_unwind(|| panic!("boom {}", 1)).unwrap_err();
        assert_eq!(panic_message(&*err), "boom 1");
        let err = catch_unwind(|| panic!("literal")).unwrap_err();
        assert_eq!(panic_message(&*err), "literal");
    }

    /// `RssAnon` of this process in KiB.
    fn rss_anon_kib() -> u64 {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let line = status.lines().find_map(|l| l.strip_prefix("RssAnon:")).unwrap_or("0");
        line.trim().trim_end_matches("kB").trim().parse().unwrap_or(0)
    }

    /// Index build time and memory on a real APK:
    /// `ASC_BENCH_APK=app.apk cargo test --release -p asc-gui bench_index -- --ignored --nocapture`.
    #[test]
    #[ignore = "needs ASC_BENCH_APK"]
    fn bench_index() {
        let apk = std::env::var("ASC_BENCH_APK").expect("set ASC_BENCH_APK to an APK path");
        let engine = Engine::new(std::path::Path::new(&apk));
        let started = Instant::now();
        let scanned = engine.scan_classes(None, |_, _| {}).unwrap();
        println!("scan_classes: {} ms", started.elapsed().as_millis());
        let rss = rss_anon_kib();
        let started = Instant::now();
        let ix = index_scanned(scanned).unwrap().index;
        let build = started.elapsed();
        println!(
            "index: {} classes, built in {} ms, RssAnon {:+} MiB",
            ix.len(),
            build.as_millis(),
            (rss_anon_kib() as i64 - rss as i64) / 1024
        );
        for kw in ["a", "com.ss", "Activity", "zzzzqq"] {
            let started = Instant::now();
            let n = ix.filter(kw, usize::MAX).len();
            println!("filter {kw:?}: {n} hits in {} ms", started.elapsed().as_millis());
        }
        drop(ix);
    }
}
