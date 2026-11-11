//! HarmonyOS (HAP / ABC) query engine for asc-rs: the sibling of the DEX
//! engine, over ArkCompiler bytecode.
//!
//! [`Engine::open`] takes a `.hap` / `.hsp`, an `.app`, a bare `.abc`, a
//! directory or a comma-separated list of those, and reads them as one
//! program. Nothing is indexed: every query parses what it needs straight
//! from the mapped files.
//!
//! - [`Engine::list_classes`]: the records (modules) of the program;
//! - [`Engine::get_class`]: disassembly of a record or one of its functions;
//! - [`Engine::find_refs`]: where a string, property, global, import,
//!   function or number is used, and call sites by resolved callee;
//! - [`Engine::call_graph`]: callers / callees of a function, across
//!   records, with what cannot be resolved kept as leaves;
//! - [`Engine::hierarchy`]: subclasses / supertypes of a class, from the
//!   parent each class definition names;
//! - [`Engine::module_requests`]: the modules the program imports;
//! - [`Engine::manifest`]: `module.json` and its siblings, joined to the code;
//! - [`Engine::resources`]: `resources.index` of each package, and
//!   [`Engine::package_files`]: the text files resources name.
//!
//! App-store packages ship an encrypted `modules.abc`. Such an entry does
//! not fail the open: it is reported in [`Engine::notes`] and left out of
//! the queries, and a decrypted bare `.abc` of the same name next to the
//! package stands in for it.

mod callgraph;
mod disasm;
mod error;
mod hierarchy;
mod hints;
mod manifest;
mod measure;
mod ops;
mod path;
mod program;
mod records;
mod refs;
mod resources;
mod scopes;
pub mod text;
mod track;

use asc_cache::LockExt;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub use asc_abc::RecordKind;
pub use asc_cache::Threads;
pub use asc_hap;
pub use callgraph::{
    CallEdge, CallNode, CallQuery, CallRoots, CallRow, CallTree, Direction, EdgeKind, FormCount, GraphSize, LeafKind, Reached, RequestForm,
};
pub use error::{EngineError, Result};
pub use hierarchy::{ClassDefinition, ClassNode, ClassRow, DefinedMethod, HierarchyQuery, HierarchyTree, Lineage, ParentKind};
pub use manifest::{CodeLink, Document, DocumentText, EntryCode, Manifest, ManifestLine, PackageManifest, PackageRecords};
pub use measure::{CallResolution, CalleeRoot, ResolutionOptions, ResolvedCapture};
pub use ops::Access;
pub use program::{EntryInfo, EntryStatus, Format, Stamp, StandIn};
pub use records::{ListOptions, NameFilter, RecordListing};
pub use refs::{
    FunctionSet, ListedFunction, NumberQuery, Pattern, Query, RefBatch, RefContext, RefRow, RefSite, RefSummary, RequestListing,
};
pub use resources::{ChainEnd, PackageFile, ResolvedResource, ResourceField, ResourceRow, ResourceTables};
pub use scopes::{ScopeStats, Unresolved};

use program::Program;

/// Bytes a hash table takes on the heap, roughly: its buckets and one
/// control byte each (what the keys and values own besides is the caller's).
fn table_bytes<K, V>(map: &HashMap<K, V>) -> usize {
    map.capacity() * (std::mem::size_of::<(K, V)>() + 1)
}

/// What an [`Engine`] holds in memory, in bytes ([`Engine::memory_use`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemoryUse {
    /// On the heap for as long as the program is open: Deflate inner
    /// packages of an `.app` and Deflate entries, inflated when it opened.
    pub inflated: usize,
    /// On the heap until [`Engine::release_analyses`]: what call graph walks
    /// and `call:` searches computed (importers, scope analyses, call edges,
    /// the callee paths of call sites). An estimate from
    /// the capacities of the tables, without the allocator's overhead.
    pub analyses: usize,
    /// On the heap for as long as the program is open, once a listing
    /// asked: where each module is in `ets/sourceMaps.map` of a debug
    /// build (the file itself is read in place, or counts as `inflated`).
    pub source_maps: usize,
    /// The code and documents read in place from the mapped files (the
    /// rest of a package, its libraries and resources, is never touched):
    /// pages the system reads on demand and may drop again. Entries read in
    /// place from an inflated inner package count here too, on top of
    /// `inflated`.
    pub mapped: usize,
}

impl MemoryUse {
    /// The bytes on the heap: what closing the engine gives back for sure.
    pub fn heap(&self) -> usize {
        self.inflated + self.analyses + self.source_maps
    }
}

/// What [`Engine::get_class`] disassembles.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct ClassQuery<'q> {
    /// The record: its canonical name (`&entry/src/main/ets/pages/Index&`)
    /// or a path suffix of it (`pages/Index`, `pages/Index.ets`).
    pub record: &'q str,
    /// One function instead of the whole record: its raw name
    /// (`#~@0>#build`), its restored name (`Index.build`) or a dotted suffix
    /// of that (`build`).
    pub function: Option<&'q str>,
    /// Look in this ABC entry only (its name, or a suffix of it starting at
    /// a `/`), for a record several entries define.
    pub entry: Option<&'q str>,
}

impl<'q> ClassQuery<'q> {
    /// The whole of `record`, in any entry.
    pub fn new(record: &'q str) -> ClassQuery<'q> {
        ClassQuery { record, function: None, entry: None }
    }

    /// One function of the record instead of all of it.
    #[must_use]
    pub fn function(self, function: Option<&'q str>) -> Self {
        ClassQuery { function, ..self }
    }

    /// The record in this ABC entry only.
    #[must_use]
    pub fn entry(self, entry: Option<&'q str>) -> Self {
        ClassQuery { entry, ..self }
    }
}

/// How [`Engine::get_class_as`] writes a listing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ListingStyle {
    /// Write `; line N` where the line of the debug info changes, instead
    /// of only the first line of a function in its header. With source
    /// maps in the package each says its source line too.
    pub lines: bool,
}

impl ListingStyle {
    /// Write `; line N` wherever the line changes (see [`ListingStyle::lines`](#structfield.lines)).
    #[must_use]
    pub fn lines(self, lines: bool) -> Self {
        ListingStyle { lines }
    }
}

/// Disassembly of a record or function.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClassSource {
    /// The ABC entry that defines the record.
    pub entry: String,
    /// Canonical record name.
    pub record: String,
    /// Raw name of the function, when one was asked for.
    pub function: Option<String>,
    /// The disassembly listing.
    pub text: String,
}

/// A HarmonyOS program opened for queries.
pub struct Engine {
    program: Program,
    threads: Threads,
    /// What call graph walks and `call:` searches computed so far; replaced
    /// by an empty one to release it ([`Engine::release_analyses`]).
    graph: Mutex<Arc<callgraph::GraphCache>>,
    /// The class definitions hierarchy walks worked out so far; released
    /// with `graph`.
    classes: Mutex<Arc<hierarchy::ClassCache>>,
}

impl Drop for Engine {
    /// The analyses go on several threads, as [`Engine::release_analyses`] frees them.
    fn drop(&mut self) {
        // Only freed: a poisoned cache is as good as any for that.
        let graph = std::mem::take(self.graph.get_mut().unwrap_or_else(std::sync::PoisonError::into_inner));
        callgraph::GraphCache::discard(graph, self.threads());
    }
}

impl Engine {
    /// Open `path`: a `.hap` / `.hsp`, an `.app` or another zip that holds
    /// packages (also inside further zips), a bare `.abc`, the directory a
    /// package was unpacked into (`module.json` with `ets/*.abc` next to
    /// it), a directory of those (every such file and directory below it),
    /// or several paths joined with `,`.
    ///
    /// # Errors
    /// A path that does not exist, a lone file that is neither a zip nor an
    /// ABC file, or a program without any ABC entry
    /// ([`EngineError::NoCode`]). An encrypted or damaged entry is not an
    /// error: see [`Engine::entries`] and [`Engine::notes`].
    pub fn open(path: impl AsRef<Path>) -> Result<Engine> {
        Ok(Engine { program: Program::open(path.as_ref())?, threads: Threads::Auto, graph: Mutex::default(), classes: Mutex::default() })
    }

    /// Search with `threads` worker threads: a fixed count (at least one),
    /// or [`Threads::Auto`] (the default), the CPUs this process gets next to
    /// the user's other busy asc processes, as the DEX engine counts them
    /// ([`asc_cache::auto_threads`]).
    #[must_use]
    pub fn with_threads(mut self, threads: impl Into<Threads>) -> Engine {
        self.threads = threads.into();
        self
    }

    /// The worker threads of a search starting now.
    pub fn threads(&self) -> usize {
        self.threads.count()
    }

    /// The path the program was opened from.
    pub fn path(&self) -> &Path {
        self.program.path()
    }

    /// The files the program was read from, as they were when it opened.
    pub fn stamp(&self) -> &Stamp {
        self.program.stamp()
    }

    /// Whether opening [`Engine::path`] again would read the same files: no
    /// file of the program changed in size or modification time, appeared or
    /// went away since. A host that keeps the engine open asks before every
    /// answer and opens the program again when this is `false` (also when
    /// the path cannot be listed any more). The same test as the DEX side's
    /// `Apk::version_of`.
    pub fn is_current(&self) -> bool {
        Stamp::of(self.path()).is_ok_and(|now| now == *self.stamp())
    }

    /// What the engine holds in memory right now. Cheap: nothing is walked
    /// but the entries of the program.
    pub fn memory_use(&self) -> MemoryUse {
        let program = self.program.memory();
        MemoryUse {
            inflated: program.inflated,
            analyses: self.graph_cache().heap_bytes() + self.class_cache().heap_bytes(),
            source_maps: program.source_maps,
            mapped: program.mapped,
        }
    }

    /// What the engine counts for in the memory budget of a resident host,
    /// next to the class graphs and resource tables of DEX engines (the DEX
    /// engine's `resident_bytes`): what it holds on the heap in full, and the
    /// code it reads in place from its mapped files at
    /// 1/[`MAPPED_CHARGE_DIVISOR`](asc_cache::MAPPED_CHARGE_DIVISOR), as the
    /// memory cache charges a DEX entry it maps.
    pub fn resident_bytes(&self) -> usize {
        let held = self.memory_use();
        held.heap() + held.mapped / asc_cache::MAPPED_CHARGE_DIVISOR
    }

    /// For the program a host used last, which stays open whatever its size:
    /// when it alone is over `share` (the bytes open programs may hold), give
    /// back what its call graph walks computed ([`Engine::release_analyses`]).
    /// The next walk computes what it needs again. (The class graph of a DEX
    /// engine cannot be had in part, so there is no such step there.)
    pub fn shed_analyses(&self, share: usize) {
        if share > 0 && self.resident_bytes() > share {
            self.release_analyses();
        }
    }

    /// Forget what call graph walks and `call:` searches computed and return
    /// the bytes it took ([`MemoryUse::analyses`]). Answers do not change:
    /// the next query computes what it needs again. A query running now
    /// keeps what it started with until it is done.
    pub fn release_analyses(&self) -> usize {
        let released = std::mem::take(&mut *self.graph.lock_or_default());
        let classes = std::mem::take(&mut *self.classes.lock_or_default());
        let bytes = released.heap_bytes() + classes.heap_bytes();
        callgraph::GraphCache::discard(released, self.threads());
        bytes
    }

    /// The class definitions a hierarchy walk starting now reads and fills.
    fn class_cache(&self) -> Arc<hierarchy::ClassCache> {
        Arc::clone(&self.classes.lock_or_default())
    }

    /// The call graph cache a walk or search starting now reads and fills.
    fn graph_cache(&self) -> Arc<callgraph::GraphCache> {
        Arc::clone(&self.graph.lock_or_default())
    }

    /// Every ABC entry of the program, in program order, readable or not.
    pub fn entries(&self) -> impl Iterator<Item = &EntryInfo> {
        self.program.infos()
    }

    /// What the program leaves out, one line each: encrypted entries
    /// nothing stands in for, packages without code, files that did not open.
    pub fn notes(&self) -> &[String] {
        self.program.notes()
    }

    /// The parsed ABC file of entry `name`, for callers that need more than
    /// the queries here; `None` when there is no such entry or it is not
    /// readable.
    pub fn abc(&self, name: &str) -> Option<asc_abc::Abc<'_>> {
        let index = self.program.infos().position(|info| info.name == name)?;
        self.program.abc(index)
    }

    /// The records of the program, entry by entry in program order, each
    /// entry's records in class index order (sorted by name by the compiler).
    ///
    /// # Errors
    /// [`EngineError::Abc`] for the first record that cannot be read.
    pub fn list_classes(&self, options: &ListOptions) -> Result<Vec<RecordListing>> {
        records::list(&self.program, options)
    }

    /// Disassemble a record, or one function of it.
    ///
    /// # Errors
    /// [`EngineError::NotFound`] / [`EngineError::Ambiguous`] (with the
    /// candidates) when the record or function name does not pick exactly
    /// one; [`EngineError::Disassembly`] when the record is malformed.
    pub fn get_class(&self, query: &ClassQuery<'_>) -> Result<ClassSource> {
        self.get_class_as(query, ListingStyle::default())
    }

    /// As [`Engine::get_class`], written the way `style` says.
    ///
    /// # Errors
    /// As [`Engine::get_class`].
    pub fn get_class_as(&self, query: &ClassQuery<'_>, style: ListingStyle) -> Result<ClassSource> {
        let located = records::resolve_record(&self.program, query.record, query.entry)?;
        let record = String::from_utf8_lossy(located.class.name()).into_owned();
        // The source of a debug build, when its package packs source maps.
        let map = self.program.module_map(located.entry, &record);
        let listing = disasm::Listing { map: map.as_ref(), lines: style.lines };
        let (function, text) = match query.function {
            None => (None, disasm::record_from(&located.abc, &located.class, listing)?),
            Some(name) => {
                let method = records::resolve_function(&located, name)?;
                let raw = method.name().map(|name| name.to_str().into_owned()).unwrap_or_default();
                (Some(raw), disasm::function_from(&located.abc, &located.class, &method, listing)?)
            }
        };
        Ok(ClassSource { entry: located.entry.to_owned(), record, function, text })
    }

    /// Search every readable entry. `sink` receives one batch per entry, in
    /// program order; each entry is scanned on [`Engine::threads`] threads.
    ///
    /// # Errors
    /// [`EngineError::Cancelled`] once `cancel` is raised (checked between
    /// units of work; batches already delivered stay delivered).
    pub fn find_refs(&self, query: &Query, cancel: &AtomicBool, sink: &mut dyn FnMut(RefBatch)) -> Result<RefSummary> {
        self.find_refs_in(query, None, cancel, sink)
    }

    /// As [`Engine::find_refs`], in the ABC entries `entry` names only
    /// (`None`: all): an entry by its name or a suffix of it that starts at
    /// a `/` (`ets/widgets.abc`), or every entry of a package by the
    /// package's name (`entry.hap`, `shop.app/entry.hap`). A resource id is
    /// unique within one package only: this is how a search for one stays in
    /// its package.
    ///
    /// # Errors
    /// As [`Engine::find_refs`]; [`EngineError::NoEntry`] when `entry` names
    /// no entry of the program.
    pub fn find_refs_in(
        &self,
        query: &Query,
        entry: Option<&str>,
        cancel: &AtomicBool,
        sink: &mut dyn FnMut(RefBatch),
    ) -> Result<RefSummary> {
        let started = Instant::now();
        let selected = records::selected_entries(&self.program, entry)?;
        let mut summary = RefSummary { notes: self.notes().to_vec(), ..RefSummary::default() };
        // One cache for the whole search, whatever is released meanwhile.
        let cache = self.graph_cache();
        // The function sets of its `call:{...}` conditions come first, from the whole program.
        let prepared = refs::Prepared::new(self, query, cancel)?;
        let graph = prepared.graph();
        let scope = refs::Scope { cache: &cache, graph: graph.as_ref(), workers: self.threads(), cancel };
        for (index, abc) in self.program.readable().filter(|(index, _)| selected.contains(index)) {
            let name = self.program.info(index).map_or("", |info| info.name.as_str());
            let entry = refs::Entry { name, index: u32::try_from(index).unwrap_or(u32::MAX), abc };
            let batch = refs::search_entry(&entry, query, &scope)?;
            summary.entries += 1;
            summary.total_results += batch.rows.len();
            sink(batch);
        }
        summary.total_us = started.elapsed().as_micros();
        Ok(summary)
    }

    /// Fill the [`RefRow::context`] of `rows`, which a search found in the
    /// ABC entry `entry` (in the order it gave them): the listing of each
    /// row's function around its sites. A whole function
    /// ([`RefContext::Method`]) is listed with the first of consecutive rows
    /// in it; the others say so. Rows in record fields, and rows of an entry
    /// the program does not have, are left as they are.
    pub fn fill_context(&self, entry: &str, rows: &mut [RefRow], context: RefContext) {
        if let Some(abc) = self.abc(entry) {
            refs::fill_context(&abc, rows, context);
        }
    }

    /// The distinct module requests of the program (`@ohos:net.http`,
    /// `@normalized:N&&&entry/src/main/ets/pages/Index&` …), entry by entry
    /// in program order, sorted by request, with the number of records that
    /// ask for each and the names they import from it. `pattern` keeps the
    /// requests it matches. Only the module records are read, no code.
    ///
    /// # Errors
    /// [`EngineError::Abc`] for an entry whose class index cannot be read.
    pub fn module_requests(&self, pattern: Option<&Pattern>) -> Result<Vec<RequestListing>> {
        self.module_requests_in(pattern, None)
    }

    /// As [`Engine::module_requests`], of the ABC entries `entry` names only
    /// (as [`Engine::find_refs_in`] takes it).
    ///
    /// # Errors
    /// As [`Engine::module_requests`]; [`EngineError::NoEntry`] when `entry`
    /// names no entry of the program.
    pub fn module_requests_in(&self, pattern: Option<&Pattern>, entry: Option<&str>) -> Result<Vec<RequestListing>> {
        let selected = records::selected_entries(&self.program, entry)?;
        let mut requests = refs::module_requests(&self.program, pattern)?;
        if entry.is_some() {
            let names: Vec<&str> = selected.iter().filter_map(|&index| Some(self.program.info(index)?.name.as_str())).collect();
            requests.retain(|request| names.contains(&request.entry.as_str()));
        }
        Ok(requests)
    }

    /// The ABC entries `entry` names (as [`Engine::find_refs_in`] takes
    /// it; `None`: all), readable or not, in program order.
    ///
    /// # Errors
    /// [`EngineError::NoEntry`] when `entry` names no entry of the program.
    pub fn entries_in(&self, entry: Option<&str>) -> Result<Vec<&EntryInfo>> {
        let selected = records::selected_entries(&self.program, entry)?;
        Ok(selected.into_iter().filter_map(|index| self.program.info(index)).collect())
    }

    /// The encrypted package entries that are read from a decrypted file
    /// found next to the package, in program order. Such a program answers
    /// as if it were not encrypted, so these are no part of
    /// [`Engine::notes`]; `manifest-summary` names the file on the `abc`
    /// line of each entry.
    pub fn stand_ins(&self) -> &[StandIn] {
        self.program.stand_ins()
    }

    /// One line that says the program reads decrypted files in place of
    /// encrypted entries, for a front end to show; `None` when it reads
    /// none. One stand-in is named; several are counted.
    pub fn stand_in_note(&self) -> Option<String> {
        match self.stand_ins() {
            [] => None,
            [one] => Some(format!("{} is encrypted in its package; served from the decrypted {}", one.entry, one.file)),
            many => Some(format!(
                "{} encrypted abc entries are served from the decrypted files next to them (manifest-summary names each: its `abc` lines)",
                many.len()
            )),
        }
    }

    /// Whether the program has more than one ABC entry, i.e. whether rows
    /// need their entry column to be told apart.
    pub fn has_several_entries(&self) -> bool {
        self.program.len() > 1
    }
}
