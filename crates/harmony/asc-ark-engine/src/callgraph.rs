//! Callers / callees of a function across the records of a program.
//!
//! An ArkTS call names no callee, so the graph is made of what can be
//! proved about each call site ([`edges`]): edges to functions of the
//! program — local, through imports and exports ([`modules`]), by name
//! inside a class and up its parent classes ([`crate::hierarchy`]) — and
//! leaves for everything else: external (system APIs, globals), unlinked
//! (an import of the program that led to no function) or unresolved
//! ([`LeafKind`]). An edge that is not proved says so by its kind
//! ([`EdgeKind`]). A leaf keeps the callee path `findrefs call:` prints, so
//! "which functions reach `import:@ohos:net.http`" is a callers query whose
//! root is a pattern over leaves.
//!
//! Nothing is indexed up front. The edges of a record are computed when a
//! walk first needs them and kept in memory for the life of the [`Engine`]:
//!
//! - callees of a function need the edges of its record, and the captured
//!   variables and module-level bindings of the records it imports from;
//! - callers of a function need the edges of the records that can name it:
//!   its own record and the records whose requests lead to it, directly or
//!   through `export … from` chains ([`modules::Importers::importers_of`]).
//!   That set comes from the module records alone. An edge into another
//!   record is made through an import of the calling record, with two
//!   exceptions a method of a class has to pay for:
//!   - a method is inherited: `this.m()`, `super.m()`, `D.m()` and
//!     `new D().m()` lead to the method of an ancestor of `D`, whose record
//!     the caller need not import. So the callers of a method are also
//!     looked for in the records of the subclasses of its class and in the
//!     records that import those. Subclasses are found level by level, each
//!     level among the records that import the class above (a class names
//!     its parent through an import): the class definitions of those
//!     records are worked out ([`crate::hierarchy`]), nothing else. At most
//!     [`CallQuery::max_subclasses`] subclasses of one class are followed,
//!     the nearest first: the rows of the methods of a class with more say
//!     how many were left out ([`CallRow::subclasses_skipped`]);
//!   - an object is exported: `api.m()`, where another record exports
//!     `api = new C()`, leads to the method of `C`, which the caller need
//!     not import either. So the callers of an instance method are also
//!     looked for in the records that import a record with such a binding
//!     of the class or of a subclass of it, or with a function or a static
//!     property that hands out objects of one ([`made`]).
//! - callers of a leaf pattern need the edges of every record.

mod edges;
mod made;
pub(crate) mod modules;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use asc_abc::{Abc, ClassEntry};

pub(crate) use edges::FnRef;
use edges::{Edge, RecordEdges, Target};
pub use edges::{EdgeKind, LeafKind};
use made::RecordObjects;
pub(crate) use modules::RecordId;
pub use modules::{FormCount, RequestForm};
use modules::{Importers, Layout, Packages};

use crate::hierarchy::{self, ClassRef};
use crate::refs::method::name_matches;
use crate::refs::CallPaths;
use crate::refs::{self, Query};
use crate::refs::{chunks, run_units, Regions, RECORD_CHUNK};
use crate::scopes::{ExportedDefinitions, ScopeTables, Scopes};
use crate::track::Tracker;
use crate::{records, Engine, EngineError, Pattern, Result};

/// Which way to walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Functions with a call site (or definition) that leads to the target.
    Callers,
    /// What the target's call sites lead to.
    Callees,
}

impl Direction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Direction::Callers => "callers",
            Direction::Callees => "callees",
        }
    }

    const fn arrow(self) -> &'static str {
        match self {
            Direction::Callers => "<-",
            Direction::Callees => "->",
        }
    }
}

/// Where a call graph starts.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum CallRoots {
    /// The functions a name picks.
    Function {
        /// The record: its canonical name or a path suffix of it, as for
        /// `getclass`. Without one, every record is searched.
        record: Option<String>,
        /// The raw name (`#~@0>#build`), the restored name (`Index.build`)
        /// or a dotted suffix of that (`build`).
        function: String,
        /// Look in this ABC entry only.
        entry: Option<String>,
    },
    /// Callers only: every leaf whose callee path matches, e.g.
    /// `^import:@ohos:net\.http`. The paths are the ones `findrefs call:`
    /// prints.
    Leaf(Pattern),
    /// Every function a rule matches: those whose code matches its
    /// conditions, a `method:` condition naming the functions themselves.
    Matching(Query),
}

impl CallRoots {
    /// A function root from its spelling: `FUNCTION` or `RECORD->FUNCTION`,
    /// the form the location column of result rows has.
    pub fn function(spec: &str) -> CallRoots {
        let (record, function) = match spec.split_once("->") {
            Some((record, function)) => (Some(record.to_owned()), function),
            None => (None, spec),
        };
        CallRoots::Function { record, function: function.to_owned(), entry: None }
    }
}

/// A call graph query.
#[derive(Debug, Clone)]
pub struct CallQuery {
    pub roots: CallRoots,
    pub direction: Direction,
    /// Levels to expand (1 = direct callers / callees).
    pub depth: usize,
    /// Stop discovering nodes beyond this many (roots included).
    pub max_nodes: usize,
    /// Follow and show [`EdgeKind::Defines`] edges.
    pub defines: bool,
    /// Callees: also list the unresolved call sites as leaves, not only
    /// count them.
    pub unresolved: bool,
    /// Callers only: keep just the branches that end at a function this
    /// rule matches (the paths from such a function to a root), and stop
    /// there.
    pub from: Option<Query>,
    /// Leave out every function one of these rules matches, with
    /// everything reached only through it.
    pub unless: Vec<Query>,
    /// Callers of a method: the subclasses of its class that are looked
    /// through for call sites that reach it by inheritance (`this.m()` in a
    /// subclass, `super.m()`, a call on an object of a subclass). The
    /// nearest are taken first; a class with more gets
    /// [`CallRow::subclasses_skipped`].
    pub max_subclasses: usize,
}

impl CallQuery {
    /// 2 levels, at most 500 nodes, definitions shown, unresolved call
    /// sites counted, 512 subclasses followed per class.
    pub fn new(roots: CallRoots, direction: Direction) -> CallQuery {
        CallQuery {
            roots,
            direction,
            depth: 2,
            max_nodes: 500,
            defines: true,
            unresolved: false,
            from: None,
            unless: Vec::new(),
            max_subclasses: DEFAULT_MAX_SUBCLASSES,
        }
    }
}

/// Subclasses of one class a callers walk looks through, unless
/// [`CallQuery::max_subclasses`] says otherwise: more than any class of the
/// programs measured has (387), so that only a class with a pathological
/// number of them is cut short.
const DEFAULT_MAX_SUBCLASSES: usize = 512;

/// What a row of the tree is.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CallNode {
    Function {
        /// The ABC entry that holds it.
        entry: String,
        /// Canonical record name.
        record: String,
        /// Raw function name: `record->function` can be given back as a root.
        function: String,
        /// Readable name, e.g. `Index.build`.
        restored: String,
    },
    /// A callee that is not a function of the program.
    Leaf {
        /// The callee path, as `findrefs call:` prints it.
        path: String,
        /// Where the path starts: outside the program, at an import of it,
        /// or where tracking stopped.
        kind: LeafKind,
    },
}

/// One line of the tree, in depth-first order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallRow {
    /// 0 for a root.
    pub depth: usize,
    /// Index of the parent row (`None` for a root).
    pub parent: Option<usize>,
    pub node: CallNode,
    /// How the parent row and this one are linked; `None` for a root. When
    /// several call sites link them, the strongest kind, in the order
    /// [`EdgeKind`] lists them (a proved call before a by-name one before a
    /// definition).
    pub kind: Option<EdgeKind>,
    /// Call sites (or definitions) that link the parent row and this one.
    pub sites: usize,
    /// Shown again: what is below this node is listed at another row of it.
    pub repeated: bool,
    /// For a function whose edges were computed: its call sites that are
    /// unresolved leaves.
    pub unresolved: Option<usize>,
    /// [`CallQuery::from`] matches it.
    pub from: bool,
    /// Callers walk, for a method whose callers were looked for: this many
    /// subclasses of its class, at least (their own subclasses are not
    /// counted), were not followed, [`CallQuery::max_subclasses`] being
    /// reached. The call sites that reach the method through them were not
    /// looked for: the ones in their subclasses, and the ones on their
    /// objects in the records that import them. (Their own code is in a
    /// record that imports a class that was followed, and was read.)
    pub subclasses_skipped: usize,
}

/// Result of [`Engine::call_graph`].
#[derive(Debug, Clone)]
pub struct CallTree {
    pub direction: Direction,
    pub depth: usize,
    pub rows: Vec<CallRow>,
    /// Distinct functions among the rows.
    pub functions: usize,
    /// Distinct leaves among the rows.
    pub leaves: usize,
    /// More nodes exist than `max_nodes` allowed.
    pub truncated: bool,
    /// Records whose edges the walk looked at.
    pub records_scanned: usize,
    /// Functions left out because a rule of [`CallQuery::unless`] matches them.
    pub pruned: usize,
    /// With [`CallQuery::from`]: what it kept of the walk.
    pub reached: Option<Reached>,
    /// What the program leaves out (encrypted entries).
    pub notes: Vec<String>,
}

impl CallTree {
    /// One line per row: indentation and the depth number, an arrow
    /// (`<-` caller, `->` callee), `RECORD->FUNCTION | restored name` or a
    /// leaf's callee path, and flags: `[new]`, `[super]`, `[instance]`,
    /// `[this-class]`, `[inherited]`, `[reassigned]`, `[defines]` for the
    /// kind of link ([`EdgeKind`]), `[external]` / `[unlinked]` /
    /// `[unresolved]` for a leaf ([`LeafKind`]),
    /// `x3` for several call sites, `unresolved=N` for the call sites of a
    /// function that lead nowhere, `[ENTRY]` when `with_entry`, `[from]`
    /// for a function [`CallQuery::from`] matches, `[N+ subclasses
    /// skipped]` ([`CallRow::subclasses_skipped`]), and `(repeated)`.
    pub fn lines(&self, with_entry: bool) -> Vec<String> {
        self.rows
            .iter()
            .map(|row| {
                let mut line = "  ".repeat(row.depth);
                line.push_str(&row.depth.to_string());
                if row.depth > 0 {
                    line.push(' ');
                    line.push_str(self.direction.arrow());
                }
                line.push(' ');
                match &row.node {
                    CallNode::Function { record, function, restored, .. } => {
                        line.push_str(&format!("{record}->{function} | {restored}"));
                    }
                    CallNode::Leaf { path, kind } => {
                        line.push_str(path);
                        line.push_str(&format!(" [{}]", kind.label()));
                    }
                }
                if let Some(label) = row.kind.and_then(EdgeKind::label) {
                    line.push_str(&format!(" [{label}]"));
                }
                if row.sites > 1 {
                    line.push_str(&format!(" x{}", row.sites));
                }
                if let Some(unresolved) = row.unresolved.filter(|&count| count > 0) {
                    line.push_str(&format!(" unresolved={unresolved}"));
                }
                if let (true, CallNode::Function { entry, .. }) = (with_entry, &row.node) {
                    line.push_str(&format!(" [{entry}]"));
                }
                if row.from {
                    line.push_str(" [from]");
                }
                if row.subclasses_skipped > 0 {
                    line.push_str(&format!(" [{}+ subclasses skipped]", row.subclasses_skipped));
                }
                if row.repeated {
                    line.push_str(" (repeated)");
                }
                line
            })
            .collect()
    }

    /// Footer comment summarising the walk.
    pub fn footer(&self) -> String {
        let mut footer = format!(
            "# {} rows, {} distinct functions, {} leaves ({}, depth {}); {} records scanned",
            self.rows.len(),
            self.functions,
            self.leaves,
            self.direction.as_str(),
            self.depth,
            self.records_scanned
        );
        if let Some(reached) = self.reached {
            footer.push_str(&format!("; {} from functions reached", reached.from));
        }
        if self.pruned > 0 {
            footer.push_str(&format!("; {} functions left out by unless", self.pruned));
        }
        if self.truncated {
            footer.push_str("; truncated (raise max_nodes or lower depth)");
        }
        let skipped: Vec<&CallRow> = self.rows.iter().filter(|row| row.subclasses_skipped > 0).collect();
        if !skipped.is_empty() {
            let subclasses: usize = skipped.iter().map(|row| row.subclasses_skipped).sum();
            footer.push_str(&format!(
                "\n# subclasses skipped: {} rows are methods of a class with too many subclasses to look through; callers that reach \
                 them by inheritance through the {subclasses}+ left out (this.m() / super.m() in their subclasses, a call on an \
                 object of one in a record that imports it) were not looked for: `hierarchy CLASS --method NAME` lists the subclasses",
                skipped.len()
            ));
        }
        if let Some(Reached { from: 0, walked }) = self.reached {
            footer.push_str(&format!(
                "\n# from: none of the {walked} callers walked matches (depth {}); a path ends where a callback is called by the \
                 system or through a value ([unresolved] call sites): raise depth, or walk the callees of the function",
                self.depth
            ));
        }
        for note in &self.notes {
            footer.push_str(&format!("\n# {note}"));
        }
        footer
    }
}

/// What [`CallQuery::from`] kept of a walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reached {
    /// The distinct functions the rule matches among those walked: where
    /// the paths of the tree start.
    pub from: usize,
    /// The distinct functions walked, before the rows on no such path were dropped.
    pub walked: usize,
}

/// One edge of the graph, for [`Engine::call_edges`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallEdge {
    pub from: CallNode,
    /// Offset of the instruction in the code of `from`.
    pub pc: u32,
    pub kind: EdgeKind,
    pub to: CallNode,
    /// For an edge through an import: the callee path of the call site.
    pub via: Option<String>,
}

/// What [`Engine::call_edges`] built.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GraphSize {
    pub records: usize,
    pub functions: usize,
    pub edges: usize,
    /// Bytes the edges take in memory, roughly.
    pub edge_bytes: usize,
}

/// What is known about one record, each part computed on first use.
#[derive(Default)]
pub(crate) struct Slot {
    scopes: OnceLock<Scopes>,
    /// What the module-level bindings of the record hold: asked by the
    /// hierarchy for every record it reads, by the call graph for a record
    /// with a binding that is written more than once.
    exported: OnceLock<ExportedDefinitions>,
    edges: OnceLock<RecordEdges>,
    /// The objects its functions and static properties hand out: asked by
    /// the call sites on what a function of the record returned.
    objects: OnceLock<RecordObjects>,
    /// Left by the first `call:` search that went through the whole record.
    call_paths: OnceLock<CallPaths>,
}

/// What the call graph and `call:` searches keep for an [`Engine`] until
/// [`Engine::release_analyses`] starts over with an empty one. A query holds
/// the cache it started with, so one released under it stays whole for that
/// query.
#[derive(Default)]
pub(crate) struct GraphCache {
    importers: OnceLock<Importers>,
    packages: Packages,
    slots: Mutex<HashMap<RecordId, Arc<Slot>>>,
    /// Heap bytes of what was computed so far, roughly: added once per part,
    /// by the thread whose result is kept.
    bytes: AtomicUsize,
}

impl GraphCache {
    /// Bytes the analyses computed so far take on the heap, roughly.
    pub(crate) fn heap_bytes(&self) -> usize {
        self.bytes.load(Ordering::Relaxed) + self.packages.heap_bytes()
    }

    /// Where the documents of the packages say records are.
    pub(crate) fn packages(&self) -> &Packages {
        &self.packages
    }

    /// What the module-level bindings of the record whose slot is `slot`
    /// hold: `build` runs when no query asked yet, and what it returns is kept.
    pub(crate) fn exported<'s>(&self, slot: &'s Slot, build: impl FnOnce() -> ExportedDefinitions) -> &'s ExportedDefinitions {
        slot.exported.get_or_init(|| {
            let exported = build();
            self.charge(exported.heap_bytes());
            exported
        })
    }

    fn charge(&self, bytes: usize) {
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// The slot of record `id`, made on first use.
    pub(crate) fn slot(&self, id: RecordId) -> Arc<Slot> {
        let mut slots = self.slots.lock().expect("call graph cache mutex poisoned");
        Arc::clone(slots.entry(id).or_insert_with(|| {
            self.charge(SLOT_BYTES);
            Arc::default()
        }))
    }

    /// The scopes of the record whose slot is `slot`: `build` runs when no
    /// query worked them out yet (other threads asking meanwhile wait for
    /// it), and what it returns is kept.
    pub(crate) fn scopes<'s>(&self, slot: &'s Slot, build: impl FnOnce() -> Scopes) -> &'s Scopes {
        slot.scopes.get_or_init(|| {
            let scopes = build();
            self.charge(scopes.heap_bytes());
            scopes
        })
    }

    /// Free `cache` on up to `threads` threads, unless a query still holds
    /// it (it is then freed when that query is done). The analyses of a
    /// large program are hundreds of thousands of small allocations: freed
    /// one after the other they take as long as a query.
    pub(crate) fn discard(cache: Arc<GraphCache>, threads: usize) {
        let Some(cache) = Arc::into_inner(cache) else { return };
        let slots = cache.slots.into_inner().unwrap_or_else(std::sync::PoisonError::into_inner);
        if threads < 2 || slots.len() < 2 * DISCARD_CHUNK {
            return;
        }
        let mut slots: Vec<Arc<Slot>> = slots.into_values().collect();
        let chunk = slots.len().div_ceil(threads).max(DISCARD_CHUNK);
        std::thread::scope(|scope| {
            while !slots.is_empty() {
                let part = slots.split_off(slots.len().saturating_sub(chunk));
                scope.spawn(move || drop(part));
            }
        });
    }

    /// Keep `paths`, the callee paths of the record whose slot is `slot`,
    /// unless another search left them first.
    pub(crate) fn keep_call_paths(&self, slot: &Slot, paths: CallPaths) {
        slot.call_paths.get_or_init(|| {
            self.charge(paths.heap_bytes());
            paths
        });
    }
}

impl Slot {
    /// The scopes of the record, when a query worked them out already.
    pub(crate) fn built_scopes(&self) -> Option<&Scopes> {
        self.scopes.get()
    }

    /// The callee paths of the record, when a `call:` search left them.
    pub(crate) fn call_paths(&self) -> Option<&CallPaths> {
        self.call_paths.get()
    }
}

/// Records freed per thread at least, for [`GraphCache::discard`] to use another thread.
const DISCARD_CHUNK: usize = 64;

/// What a record's entry in [`GraphCache::slots`] takes before anything is computed.
const SLOT_BYTES: usize = std::mem::size_of::<(RecordId, Arc<Slot>)>() + std::mem::size_of::<Slot>() + 2 * std::mem::size_of::<usize>();

/// One query's view of the program and the cache.
pub(crate) struct Session<'e> {
    engine: &'e Engine,
    /// The entries by index; `None` for the unreadable ones.
    abcs: Vec<Option<Abc<'e>>>,
    regions: Vec<Option<Regions<'e>>>,
    tables: ScopeTables,
    cache: Arc<GraphCache>,
    /// The class hierarchy, for the walks and call sites that go up or down
    /// a parent link: made when the first one does.
    classes: OnceLock<hierarchy::Session<'e>>,
}

/// A node of a walk.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Node {
    Function(FnRef),
    Leaf { path: String, kind: LeafKind },
}

/// A link from a node to one next to it.
#[derive(Debug, Clone)]
struct Neighbor {
    node: Node,
    kind: EdgeKind,
    sites: usize,
}

/// Whether a walk for `query` takes `edge`.
fn follows(edge: &Edge, query: &CallQuery) -> bool {
    match (edge.kind, edge.target) {
        (EdgeKind::Defines, _) => query.defines,
        // Upward, an unresolved leaf is only ever a root the query asked for.
        (_, Target::Leaf { kind: LeafKind::Unresolved, .. }) => query.unresolved || query.direction == Direction::Callers,
        _ => true,
    }
}

/// A row still to be written: a node and how its parent row leads to it.
struct Pending {
    node: Node,
    depth: usize,
    parent: Option<usize>,
    kind: Option<EdgeKind>,
    sites: usize,
}

/// The neighbors of a node, in first-seen order.
#[derive(Debug, Default)]
struct Neighbors(Vec<Neighbor>);

impl Neighbors {
    fn add(&mut self, node: Node, kind: EdgeKind) {
        match self.0.iter_mut().find(|known| known.node == node) {
            Some(known) => {
                known.sites += 1;
                known.kind = known.kind.min(kind);
            }
            None => self.0.push(Neighbor { node, kind, sites: 1 }),
        }
    }
}

impl<'e> Session<'e> {
    pub(crate) fn new(engine: &'e Engine) -> Session<'e> {
        let program = &engine.program;
        let abcs: Vec<Option<Abc<'e>>> = (0..program.len()).map(|index| program.abc(index)).collect();
        let regions = abcs.iter().map(|abc| abc.as_ref().map(Regions::of)).collect();
        Session { engine, abcs, regions, tables: ScopeTables::new(), cache: engine.graph_cache(), classes: OnceLock::new() }
    }

    fn layout(&self) -> Layout<'_, 'e> {
        Layout { abcs: &self.abcs, program: &self.engine.program, packages: self.cache.packages() }
    }

    /// The class hierarchy of the program, over the same cache.
    fn classes(&self) -> &hierarchy::Session<'e> {
        self.classes.get_or_init(|| hierarchy::Session::with_graph(self.engine, Arc::clone(&self.cache)))
    }

    /// Who imports each record: read from every module record the first
    /// time a walk goes upward.
    fn importers(&self, cancel: &AtomicBool) -> Result<&Importers> {
        let cache = &*self.cache;
        if let Some(importers) = cache.importers.get() {
            return Ok(importers);
        }
        // Two walks may both build it; the first to finish is kept.
        let built = Importers::build(self.layout(), self.engine.threads, cancel)?;
        Ok(cache.importers.get_or_init(|| {
            cache.charge(built.heap_bytes());
            built
        }))
    }

    fn abc(&self, entry: u32) -> Option<Abc<'e>> {
        self.abcs.get(entry as usize).copied().flatten()
    }

    /// The readable entries of the program, by index.
    pub(crate) fn readable(&self) -> impl Iterator<Item = (u32, Abc<'e>)> + '_ {
        self.abcs.iter().enumerate().filter_map(|(index, abc)| Some((u32::try_from(index).ok()?, (*abc)?)))
    }

    pub(crate) fn entry_name(&self, entry: u32) -> &'e str {
        self.engine.program.info(entry as usize).map_or("", |info| info.name.as_str())
    }

    pub(crate) fn threads(&self) -> usize {
        self.engine.threads
    }

    pub(crate) fn cache(&self) -> &GraphCache {
        &self.cache
    }

    /// The call sites of the function at method offset `method` of record
    /// `id` (whose slot is `slot`) that lead to a function of `wanted`, in
    /// code order: the offset of the instruction, the kind of the link and
    /// the callee. A definition is not a call.
    pub(crate) fn calls_into(
        &self,
        slot: &Slot,
        id: RecordId,
        method: u32,
        wanted: &HashSet<FnRef>,
        out: &mut Vec<(u32, EdgeKind, FnRef)>,
    ) {
        let Some(edges) = self.edges(slot, id) else { return };
        for edge in edges.of(method) {
            if let (Target::Function(callee), false) = (edge.target, edge.kind == EdgeKind::Defines) {
                if wanted.contains(&callee) {
                    out.push((edge.pc, edge.kind, callee));
                }
            }
        }
    }

    /// `RECORD->FUNCTION` of `function`, as the rows of a tree print it, and its restored name.
    pub(crate) fn location(&self, function: FnRef) -> (String, String) {
        match self.describe(&Node::Function(function)) {
            CallNode::Function { record, function, restored, .. } => (format!("{record}->{function}"), restored),
            CallNode::Leaf { path, .. } => (path, String::new()),
        }
    }

    fn regions(&self, entry: u32) -> Option<&Regions<'e>> {
        self.regions.get(entry as usize)?.as_ref()
    }

    pub(crate) fn slot(&self, id: RecordId) -> Arc<Slot> {
        self.cache.slot(id)
    }

    /// The scopes of record `id`, whose slot is `slot`.
    fn scopes<'s>(&self, slot: &'s Slot, id: RecordId) -> Option<&'s Scopes> {
        if let Some(scopes) = slot.scopes.get() {
            return Some(scopes);
        }
        let (abc, regions) = self.abc(id.entry).zip(self.regions(id.entry))?;
        let class = abc.class(id.class).ok()?;
        Some(self.cache.scopes(slot, || Scopes::build(abc, regions, &class, &self.tables, &mut Tracker::default())))
    }

    /// What the module-level bindings of record `id` hold; `slot` is its
    /// slot and `scopes` its scopes.
    fn exported<'s>(&self, slot: &'s Slot, id: RecordId, scopes: &Scopes) -> Option<&'s ExportedDefinitions> {
        if let Some(exported) = slot.exported.get() {
            return Some(exported);
        }
        let (abc, regions) = self.abc(id.entry).zip(self.regions(id.entry))?;
        let class = abc.class(id.class).ok()?;
        Some(self.cache.exported(slot, || ExportedDefinitions::build(abc, regions, &class, scopes, &self.tables)))
    }

    /// The edges of record `id`, whose slot is `slot`.
    fn edges<'s>(&self, slot: &'s Slot, id: RecordId) -> Option<&'s RecordEdges> {
        if let Some(edges) = slot.edges.get() {
            return Some(edges);
        }
        let scopes = self.scopes(slot, id)?;
        Some(slot.edges.get_or_init(|| {
            let edges = self.build_edges(id, slot, scopes);
            self.cache.charge(edges.heap_bytes());
            edges
        }))
    }

    /// The objects record `id`, whose slot is `slot`, hands out.
    fn objects<'s>(&self, slot: &'s Slot, id: RecordId) -> Option<&'s RecordObjects> {
        if let Some(objects) = slot.objects.get() {
            return Some(objects);
        }
        let scopes = self.scopes(slot, id)?;
        Some(slot.objects.get_or_init(|| {
            let objects = self.build_objects(id, slot, scopes);
            self.cache.charge(objects.heap_bytes());
            objects
        }))
    }

    /// The record that holds the function at `function`.
    fn record_of(&self, function: FnRef) -> Option<RecordId> {
        let method = self.abc(function.entry)?.method(function.method).ok()?;
        Some(RecordId { entry: function.entry, class: method.class_off().ok()? })
    }

    /// Every record of the program, in program order.
    fn all_records(&self) -> Vec<RecordId> {
        let mut out = Vec::new();
        for (entry, abc) in self.abcs.iter().enumerate() {
            let Some(abc) = abc else { continue };
            let entry = u32::try_from(entry).unwrap_or(u32::MAX);
            // An entry whose class index does not read has no records.
            for class in abc.classes().into_iter().flatten() {
                if let Ok(ClassEntry::Local(class)) = class {
                    out.push(RecordId { entry, class: class.offset() });
                }
            }
        }
        out
    }

    /// Compute the edges of `records` on the engine's threads.
    fn load(&self, records: &[RecordId], cancel: &AtomicBool) -> Result<Vec<Arc<Slot>>> {
        let units: Vec<Range<usize>> = chunks(records.len(), 4).collect();
        let loaded = run_units(units.len(), self.engine.threads, cancel, |unit| {
            records[units[unit].clone()]
                .iter()
                .map(|&id| {
                    let slot = self.slot(id);
                    // A record that does not read has no edges.
                    let _ = self.edges(&slot, id);
                    slot
                })
                .collect::<Vec<_>>()
        })?;
        Ok(loaded.into_iter().flatten().collect())
    }

    fn node_of(&self, edges: &RecordEdges, target: Target) -> Node {
        match target {
            Target::Function(function) => Node::Function(function),
            Target::Leaf { text, kind } => Node::Leaf { path: edges.text(text).to_owned(), kind },
        }
    }

    fn describe(&self, node: &Node) -> CallNode {
        match node {
            Node::Leaf { path, kind } => CallNode::Leaf { path: path.clone(), kind: *kind },
            Node::Function(function) => {
                let entry = self.engine.program.info(function.entry as usize).map_or("", |info| info.name.as_str()).to_owned();
                let method = self.abc(function.entry).and_then(|abc| abc.method(function.method).ok());
                let raw = method.and_then(|method| method.name().ok()).map_or_else(|| "?".to_owned(), |name| name.to_str().into_owned());
                let class = self.record_of(*function).and_then(|id| self.abc(id.entry)?.class(id.class).ok());
                let record = class.map_or_else(|| "?".to_owned(), |class| String::from_utf8_lossy(class.name()).into_owned());
                let restored = class.map_or_else(|| raw.clone(), |class| class.restore_function_name(&raw));
                CallNode::Function { entry, record, function: raw, restored }
            }
        }
    }

    /// The functions `roots` names.
    fn function_roots(&self, record: Option<&str>, function: &str, entry: Option<&str>, cancel: &AtomicBool) -> Result<Vec<FnRef>> {
        let program = &self.engine.program;
        if let Some(record) = record {
            let located = records::resolve_record(program, record, entry)?;
            let method = records::resolve_function(&located, function)?;
            let entry = program.infos().position(|info| info.name == located.entry).and_then(|index| u32::try_from(index).ok());
            return Ok(entry.map(|entry| FnRef { entry, method: method.offset() }).into_iter().collect());
        }
        let wanted = Pattern::exact(function);
        let mut found = Vec::new();
        for (index, abc) in self.abcs.iter().enumerate() {
            let (Some(abc), Some(info)) = (abc, program.info(index)) else { continue };
            // As `getclass --entry`: the name, or a suffix of it that starts at a `/`.
            let is_entry = |wanted: &str| info.name == wanted || info.name.strip_suffix(wanted).is_some_and(|rest| rest.ends_with('/'));
            if entry.is_some_and(|wanted| !is_entry(wanted)) {
                continue;
            }
            let entry_index = u32::try_from(index).unwrap_or(u32::MAX);
            let classes: Vec<u32> =
                abc.class_index().map_err(|source| EngineError::Abc { entry: info.name.clone(), source })?.iter().collect();
            let units: Vec<Range<usize>> = chunks(classes.len(), RECORD_CHUNK).collect();
            let matched = run_units(units.len(), self.engine.threads, cancel, |unit| {
                let mut out = Vec::new();
                for &off in &classes[units[unit].clone()] {
                    let Ok(ClassEntry::Local(class)) = abc.class_entry(off) else { continue };
                    let Ok(methods) = class.methods() else { continue };
                    for method in methods.map_while(|method| method.ok()) {
                        let Ok(raw) = method.name() else { continue };
                        let raw = raw.to_str();
                        if method.code_off().is_some() && name_matches(&wanted, &raw, || class.restore_function_name(&raw)) {
                            out.push(FnRef { entry: entry_index, method: method.offset() });
                        }
                    }
                }
                out
            })?;
            found.extend(matched.into_iter().flatten());
        }
        if found.is_empty() {
            return Err(EngineError::NotFound { what: "function", name: function.to_owned(), notes: program.notes().to_vec() });
        }
        Ok(found)
    }

    /// The callees of each function of `frontier`.
    fn callees(
        &self,
        frontier: &[Node],
        query: &CallQuery,
        cancel: &AtomicBool,
        scanned: &mut HashSet<RecordId>,
    ) -> Result<HashMap<Node, Neighbors>> {
        let functions: Vec<FnRef> =
            frontier.iter().filter_map(|node| if let Node::Function(function) = node { Some(*function) } else { None }).collect();
        let homes: Vec<Option<RecordId>> = functions.iter().map(|&function| self.record_of(function)).collect();
        let mut records: Vec<RecordId> = homes.iter().flatten().copied().collect();
        records.sort_unstable();
        records.dedup();
        let slots = self.load(&records, cancel)?;
        scanned.extend(records.iter().copied());
        let mut out = HashMap::new();
        for (&function, home) in functions.iter().zip(homes) {
            let slot = home.and_then(|home| records.binary_search(&home).ok()).map(|index| &slots[index]);
            let Some(edges) = slot.and_then(|slot| slot.edges.get()) else { continue };
            let mut neighbors = Neighbors::default();
            for edge in edges.of(function.method).iter().filter(|edge| follows(edge, query)) {
                neighbors.add(self.node_of(edges, edge.target), edge.kind);
            }
            out.insert(Node::Function(function), neighbors);
        }
        Ok(out)
    }

    /// The callers of each node of `frontier`. The methods whose class has
    /// more subclasses than the walk looks through are added to `skipped`,
    /// with the number left out.
    fn callers(
        &self,
        frontier: &[Node],
        query: &CallQuery,
        cancel: &AtomicBool,
        scanned: &mut HashSet<RecordId>,
        skipped: &mut HashMap<Node, usize>,
    ) -> Result<HashMap<Node, Neighbors>> {
        let (records, slots) = if frontier.iter().any(|node| matches!(node, Node::Leaf { .. })) {
            // Every record is looked at: no subclass is left out.
            let records = self.all_records();
            let slots = self.load(&records, cancel)?;
            (records, slots)
        } else {
            self.records_that_reach(frontier, query.max_subclasses, cancel, skipped)?
        };
        scanned.extend(records.iter().copied());
        // Looked up per edge: by reference, without building a node for each.
        let wanted_functions: HashSet<FnRef> =
            frontier.iter().filter_map(|node| if let Node::Function(function) = node { Some(*function) } else { None }).collect();
        let wanted_leaves: HashSet<(&str, LeafKind)> = frontier
            .iter()
            .filter_map(|node| if let Node::Leaf { path, kind } = node { Some((path.as_str(), *kind)) } else { None })
            .collect();
        let mut out: HashMap<Node, Neighbors> = HashMap::new();
        for (id, slot) in records.iter().zip(&slots) {
            let Some(edges) = slot.edges.get() else { continue };
            for (method, of_function) in edges.functions() {
                let caller = FnRef { entry: id.entry, method };
                for edge in of_function.iter().filter(|edge| follows(edge, query)) {
                    let is_wanted = match edge.target {
                        Target::Function(function) => wanted_functions.contains(&function),
                        Target::Leaf { text, kind } => !wanted_leaves.is_empty() && wanted_leaves.contains(&(edges.text(text), kind)),
                    };
                    if is_wanted {
                        out.entry(self.node_of(edges, edge.target)).or_default().add(Node::Function(caller), edge.kind);
                    }
                }
            }
        }
        Ok(out)
    }

    /// The records whose code can have an edge to a function of `frontier`,
    /// in order, with their edges computed: see the module documentation.
    /// At most `max_subclasses` subclasses of each class are followed; the
    /// methods of a class with more are added to `skipped`.
    fn records_that_reach(
        &self,
        frontier: &[Node],
        max_subclasses: usize,
        cancel: &AtomicBool,
        skipped: &mut HashMap<Node, usize>,
    ) -> Result<(Vec<RecordId>, Vec<Arc<Slot>>)> {
        let importers = self.importers(cancel)?;
        // The records of `homes` and the records that import them.
        let with_importers = |homes: HashSet<RecordId>| -> HashSet<RecordId> {
            let mut records: HashSet<RecordId> = homes.iter().flat_map(|&home| importers.importers_of(home)).collect();
            records.extend(homes);
            records
        };
        // The classes with a method in the frontier, and whether one of those methods is an instance method.
        let mut family: HashSet<ClassRef> = HashSet::new();
        let mut instance_methods = false;
        let mut homes: HashSet<RecordId> = HashSet::new();
        let mut methods: Vec<(&Node, ClassRef)> = Vec::new();
        for node in frontier {
            let Node::Function(function) = node else { continue };
            let Some(home) = self.record_of(*function) else { continue };
            homes.insert(home);
            let slot = self.slot(home);
            let membership = self.scopes(&slot, home).and_then(|scopes| scopes.membership(function.method));
            // A constructor is only reached by name: `new`, or `super(...)` of a direct subclass.
            if let Some(membership) = membership.filter(|membership| membership.class != function.method) {
                instance_methods |= !membership.is_static;
                let class = ClassRef { entry: function.entry, ctor: membership.class };
                family.insert(class);
                methods.push((node, class));
            }
        }
        let mut records = with_importers(homes);
        // Their subclasses, level by level: a class names its parent through an import, so the
        // subclasses of a level are in the records that import the records of that level.
        // Each class of a method counts the subclasses followed for it: a subclass is of the
        // first of them that reaches it.
        let mut root_of: HashMap<ClassRef, ClassRef> = family.iter().map(|&class| (class, class)).collect();
        let mut followed: HashMap<ClassRef, usize> = HashMap::new();
        let mut left_out: HashMap<ClassRef, usize> = HashMap::new();
        let mut level: HashSet<ClassRef> = family.clone();
        while !level.is_empty() {
            let candidates = with_importers(level.iter().filter_map(|class| self.classes().record_of(*class)).collect());
            let mut candidates: Vec<RecordId> = candidates.into_iter().collect();
            candidates.sort_unstable();
            let subclasses = self.classes().subclasses_among(&level, &candidates, cancel)?;
            records.extend(candidates);
            level.clear();
            for (class, parent) in subclasses {
                let Some(&root) = root_of.get(&parent) else { continue };
                if family.contains(&class) {
                    continue;
                }
                let count = followed.entry(root).or_default();
                if *count >= max_subclasses {
                    *left_out.entry(root).or_default() += 1;
                    continue;
                }
                *count += 1;
                family.insert(class);
                root_of.insert(class, root);
                level.insert(class);
            }
        }
        for (node, class) in methods {
            if let Some(&count) = left_out.get(&class) {
                skipped.insert(node.clone(), count);
            }
        }
        let mut records: Vec<RecordId> = records.into_iter().collect();
        records.sort_unstable();
        let mut slots = self.load(&records, cancel)?;
        if instance_methods {
            // The records that export an object of one of the classes, or hand one out: whoever
            // imports them can call its methods. A record that hands out an object of a class makes
            // it: only the ones with a `new` of one of the classes are asked what they return.
            let constructors: HashSet<FnRef> = family.iter().map(|class| FnRef { entry: class.entry, method: class.ctor }).collect();
            let mut readers: HashSet<RecordId> = HashSet::new();
            for (&id, slot) in records.iter().zip(&slots) {
                let makes_one = || slot.edges.get().is_some_and(|edges| edges.calls_any_of(&constructors));
                if self.holds_instance_of(id, slot, &family) || (makes_one() && self.hands_out(id, slot, &family)) {
                    readers.extend(importers.importers_of(id));
                }
            }
            let mut more: Vec<RecordId> = readers.into_iter().filter(|id| records.binary_search(id).is_err()).collect();
            if !more.is_empty() {
                more.sort_unstable();
                slots.extend(self.load(&more, cancel)?);
                records.extend(more);
            }
        }
        Ok((records, slots))
    }

    /// The leaves whose path `pattern` matches, in program order.
    fn leaf_roots(&self, pattern: &Pattern, cancel: &AtomicBool, scanned: &mut HashSet<RecordId>) -> Result<Vec<Node>> {
        let records = self.all_records();
        let slots = self.load(&records, cancel)?;
        scanned.extend(records.iter().copied());
        let mut seen = HashSet::new();
        let mut roots = Vec::new();
        for slot in &slots {
            let Some(edges) = slot.edges.get() else { continue };
            // A record names each path once: the pattern is tried once per name.
            let matched: Vec<bool> = edges.texts().map(|text| pattern.is_match(text)).collect();
            if !matched.contains(&true) {
                continue;
            }
            for (_, of_function) in edges.functions() {
                for edge in of_function {
                    let Target::Leaf { text, kind } = edge.target else { continue };
                    if matched.get(text as usize) == Some(&true) && seen.insert((edges.text(text), kind)) {
                        roots.push(Node::Leaf { path: edges.text(text).to_owned(), kind });
                    }
                }
            }
        }
        Ok(roots)
    }

    /// The call sites of `function` that are unresolved leaves, when its
    /// record is one of `scanned`, those the walk looked at. (Not: when its
    /// edges are known. What earlier queries left in the cache must not
    /// show in the rows.)
    fn unresolved_of(&self, function: FnRef, scanned: &HashSet<RecordId>) -> Option<usize> {
        let record = self.record_of(function).filter(|record| scanned.contains(record))?;
        let slot = self.slot(record);
        let edges = slot.edges.get()?;
        let is_unresolved = |edge: &&Edge| matches!(edge.target, Target::Leaf { kind: LeafKind::Unresolved, .. });
        Some(edges.of(function.method).iter().filter(is_unresolved).count())
    }

    fn walk(&self, query: &CallQuery, cancel: &AtomicBool) -> Result<CallTree> {
        let mut scanned = HashSet::new();
        let roots: Vec<Node> = match (&query.roots, query.direction) {
            (CallRoots::Function { record, function, entry }, _) => {
                self.function_roots(record.as_deref(), function, entry.as_deref(), cancel)?.into_iter().map(Node::Function).collect()
            }
            (CallRoots::Leaf(pattern), Direction::Callers) => self.leaf_roots(pattern, cancel, &mut scanned)?,
            (CallRoots::Leaf(_), Direction::Callees) => {
                return Err(EngineError::Query("a leaf has no callees: a callee path is a root for callers only".to_owned()));
            }
            (CallRoots::Matching(rule), _) => {
                let mut matched: Vec<FnRef> = refs::matching(rule, self, cancel)?.into_iter().collect();
                if matched.is_empty() {
                    return Err(EngineError::Query("no function matches the root rule".to_owned()));
                }
                // In program order, whatever order the set gives them in.
                matched.sort_unstable();
                matched.into_iter().map(Node::Function).collect()
            }
        };
        if query.from.is_some() && query.direction == Direction::Callees {
            return Err(EngineError::Query("`from` keeps paths of a callers walk: walk the callers of the target instead".to_owned()));
        }
        let from = query.from.as_ref().map(|rule| refs::matching(rule, self, cancel)).transpose()?;
        let mut unless: HashSet<FnRef> = HashSet::new();
        for rule in &query.unless {
            unless.extend(refs::matching(rule, self, cancel)?);
        }
        let is_function_of = |set: &HashSet<FnRef>, node: &Node| matches!(node, Node::Function(function) if set.contains(function));
        let is_from = |node: &Node| from.as_ref().is_some_and(|from| is_function_of(from, node));
        let mut pruned: HashSet<Node> = roots.iter().filter(|root| is_function_of(&unless, root)).cloned().collect();
        let roots: Vec<Node> = roots.into_iter().filter(|root| !pruned.contains(root)).collect();
        // Level by level: the neighbors of every node first met at that level.
        let mut level_of: HashMap<Node, usize> = HashMap::new();
        let mut truncated = false;
        let mut frontier = Vec::new();
        for root in &roots {
            if level_of.len() >= query.max_nodes {
                truncated = true;
                break;
            }
            if !level_of.contains_key(root) {
                level_of.insert(root.clone(), 0);
                // A `from` function ends its paths.
                if !is_from(root) {
                    frontier.push(root.clone());
                }
            }
        }
        let mut neighbors: HashMap<Node, Neighbors> = HashMap::new();
        let mut skipped: HashMap<Node, usize> = HashMap::new();
        for level in 0..query.depth {
            if frontier.is_empty() {
                break;
            }
            let found = match query.direction {
                Direction::Callees => self.callees(&frontier, query, cancel, &mut scanned)?,
                Direction::Callers => self.callers(&frontier, query, cancel, &mut scanned, &mut skipped)?,
            };
            let mut next = Vec::new();
            for node in &frontier {
                for neighbor in found.get(node).into_iter().flat_map(|neighbors| &neighbors.0) {
                    if level_of.contains_key(&neighbor.node) {
                        continue;
                    }
                    if is_function_of(&unless, &neighbor.node) {
                        pruned.insert(neighbor.node.clone());
                        continue;
                    }
                    if level_of.len() >= query.max_nodes {
                        truncated = true;
                        continue;
                    }
                    level_of.insert(neighbor.node.clone(), level + 1);
                    if !is_from(&neighbor.node) {
                        next.push(neighbor.node.clone());
                    }
                }
            }
            neighbors.extend(found);
            frontier = next;
        }
        let reached = from.as_ref().map(|_| {
            let walked = level_of.keys().filter(|node| matches!(node, Node::Function(_))).count();
            let starts: Vec<Node> = level_of.keys().filter(|node| is_from(node)).cloned().collect();
            let keep = on_paths_to(&neighbors, &level_of, &starts);
            level_of.retain(|node, _| keep.contains(node));
            Reached { from: starts.len(), walked }
        });

        // Depth first: a node is expanded where it is first met at its own level.
        let mut rows: Vec<CallRow> = Vec::new();
        let mut expanded: HashSet<Node> = HashSet::new();
        let root = |root: &Node| Pending { node: root.clone(), depth: 0, parent: None, kind: None, sites: 0 };
        let mut stack: Vec<Pending> = roots.iter().rev().filter(|root| level_of.contains_key(*root)).map(root).collect();
        // A root listed twice is one row.
        let mut root_seen = HashSet::new();
        stack.retain(|pending| root_seen.insert(pending.node.clone()));
        while let Some(Pending { node, depth, parent, kind, sites }) = stack.pop() {
            let expand = level_of.get(&node) == Some(&depth) && !expanded.contains(&node);
            let unresolved = if let Node::Function(function) = &node { self.unresolved_of(*function, &scanned) } else { None };
            let has_more =
                neighbors.get(&node).is_some_and(|neighbors| neighbors.0.iter().any(|neighbor| level_of.contains_key(&neighbor.node)));
            let from = is_from(&node);
            let subclasses_skipped = skipped.get(&node).copied().unwrap_or(0);
            let node_row = self.describe(&node);
            rows.push(CallRow {
                depth,
                parent,
                node: node_row,
                kind,
                sites,
                repeated: !expand && has_more,
                unresolved,
                from,
                subclasses_skipped,
            });
            if !expand {
                continue;
            }
            expanded.insert(node.clone());
            let index = rows.len() - 1;
            let below = neighbors.get(&node).map(|neighbors| neighbors.0.as_slice()).unwrap_or_default();
            for neighbor in below.iter().rev().filter(|neighbor| level_of.contains_key(&neighbor.node)) {
                let (parent, kind) = (Some(index), Some(neighbor.kind));
                stack.push(Pending { node: neighbor.node.clone(), depth: depth + 1, parent, kind, sites: neighbor.sites });
            }
        }
        let functions = level_of.keys().filter(|node| matches!(node, Node::Function(_))).count();
        Ok(CallTree {
            direction: query.direction,
            depth: query.depth,
            rows,
            functions,
            leaves: level_of.len() - functions,
            truncated,
            records_scanned: scanned.len(),
            pruned: pruned.len(),
            reached,
            notes: self.engine.notes().to_vec(),
        })
    }
}

/// The nodes of a walk from which one of `starts` is reached through the
/// links of `neighbors`, `starts` among them: what `from` keeps.
fn on_paths_to(neighbors: &HashMap<Node, Neighbors>, level_of: &HashMap<Node, usize>, starts: &[Node]) -> HashSet<Node> {
    let mut above: HashMap<&Node, Vec<&Node>> = HashMap::new();
    for (node, below) in neighbors {
        for neighbor in below.0.iter().filter(|neighbor| level_of.contains_key(&neighbor.node)) {
            above.entry(&neighbor.node).or_default().push(node);
        }
    }
    let mut keep: HashSet<Node> = starts.iter().cloned().collect();
    let mut pending: Vec<&Node> = starts.iter().collect();
    while let Some(node) = pending.pop() {
        for parent in above.get(node).into_iter().flatten() {
            if keep.insert((*parent).clone()) {
                pending.push(parent);
            }
        }
    }
    keep
}

impl Engine {
    /// Callers or callees of functions, to a bounded depth: see
    /// [`CallQuery`] and the rows of [`CallTree`].
    ///
    /// The edges of the records the walk touches are computed on
    /// [`Engine::threads`] threads and kept: a later walk reuses them.
    ///
    /// # Errors
    /// [`EngineError::NotFound`] / [`EngineError::Ambiguous`] when the root
    /// names no function or, with a record, not exactly one;
    /// [`EngineError::Query`] for callees of a leaf pattern;
    /// [`EngineError::Cancelled`].
    pub fn call_graph(&self, query: &CallQuery, cancel: &AtomicBool) -> Result<CallTree> {
        Session::new(self).walk(query, cancel)
    }

    /// Every edge of the program, record by record in program order, each
    /// function's in code order: the whole graph, built on
    /// [`Engine::threads`] threads and kept like the edges a walk computes.
    /// For checks and measurements; a walk does not need it.
    ///
    /// # Errors
    /// [`EngineError::Cancelled`].
    pub fn call_edges(&self, cancel: &AtomicBool, sink: &mut dyn FnMut(CallEdge)) -> Result<GraphSize> {
        let session = Session::new(self);
        let records = session.all_records();
        let slots = session.load(&records, cancel)?;
        let mut size = GraphSize { records: records.len(), ..GraphSize::default() };
        for (id, slot) in records.iter().zip(&slots) {
            let Some(edges) = slot.edges.get() else { continue };
            size.edges += edges.len();
            size.edge_bytes += edges.heap_bytes();
            for (method, of_function) in edges.functions() {
                size.functions += 1;
                let from = session.describe(&Node::Function(FnRef { entry: id.entry, method }));
                for edge in of_function {
                    sink(CallEdge {
                        from: from.clone(),
                        pc: edge.pc,
                        kind: edge.kind,
                        to: session.describe(&session.node_of(edges, edge.target)),
                        via: edge.via.map(|text| edges.text(text).to_owned()),
                    });
                }
            }
        }
        Ok(size)
    }

    /// As [`Engine::call_edges`] without listing them: builds the whole
    /// graph and says how large it is.
    ///
    /// # Errors
    /// [`EngineError::Cancelled`].
    pub fn build_call_graph(&self, cancel: &AtomicBool) -> Result<GraphSize> {
        let session = Session::new(self);
        let records = session.all_records();
        let slots = session.load(&records, cancel)?;
        let mut size = GraphSize { records: records.len(), ..GraphSize::default() };
        for edges in slots.iter().filter_map(|slot| slot.edges.get()) {
            size.edges += edges.len();
            size.edge_bytes += edges.heap_bytes();
            size.functions += edges.functions().count();
        }
        Ok(size)
    }

    /// How the module requests of the program are spelled and how many of
    /// each form name a record of the program (the others are system
    /// modules, native libraries, or packages that are not in it).
    ///
    /// # Errors
    /// [`EngineError::Cancelled`].
    pub fn request_forms(&self, cancel: &AtomicBool) -> Result<BTreeMap<RequestForm, FormCount>> {
        Ok(Session::new(self).importers(cancel)?.forms().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn function(record: &str, function: &str, restored: &str) -> CallNode {
        CallNode::Function { entry: "ets/modules.abc".into(), record: record.into(), function: function.into(), restored: restored.into() }
    }

    #[test]
    fn roots_are_spelled_like_locations() {
        let CallRoots::Function { record, function, entry } = CallRoots::function("&entry/src/main/ets/pages/Index&->#~@0>#build") else {
            panic!("a function root")
        };
        assert_eq!((record.as_deref(), function.as_str(), entry), (Some("&entry/src/main/ets/pages/Index&"), "#~@0>#build", None));
        let CallRoots::Function { record, function, .. } = CallRoots::function("Index.build") else { panic!("a function root") };
        assert_eq!((record, function.as_str()), (None, "Index.build"));
    }

    #[test]
    fn rows_print_like_the_dex_tree() {
        let row = |depth, parent, node, kind, sites, repeated, unresolved| CallRow {
            depth,
            parent,
            node,
            kind,
            sites,
            repeated,
            unresolved,
            from: false,
            subclasses_skipped: 0,
        };
        let index = "&entry/src/main/ets/pages/Index&";
        let tree = CallTree {
            direction: Direction::Callees,
            depth: 2,
            rows: vec![
                row(0, None, function(index, "#~@0>#load", "Index.load"), None, 0, false, Some(2)),
                row(1, Some(0), function(index, "#~@0>@1*#", "Index.load.<anonymous>"), Some(EdgeKind::Defines), 1, false, None),
                row(1, Some(0), function(index, "#~@0>#parse", "Index.parse"), Some(EdgeKind::ThisClass), 3, true, Some(0)),
                row(
                    1,
                    Some(0),
                    CallNode::Leaf { path: "import:@ohos:net.http#default.createHttp".into(), kind: LeafKind::External },
                    Some(EdgeKind::Call),
                    1,
                    false,
                    None,
                ),
                row(
                    2,
                    Some(1),
                    CallNode::Leaf { path: "this.cfg.get".into(), kind: LeafKind::Unresolved },
                    Some(EdgeKind::New),
                    1,
                    false,
                    None,
                ),
                row(
                    2,
                    Some(1),
                    CallNode::Leaf { path: "import:lib#Store.open().read".into(), kind: LeafKind::Unlinked },
                    Some(EdgeKind::Call),
                    2,
                    false,
                    None,
                ),
            ],
            functions: 3,
            leaves: 3,
            truncated: true,
            records_scanned: 1,
            pruned: 0,
            reached: None,
            notes: vec!["x is encrypted".into()],
        };
        assert_eq!(
            tree.lines(false),
            [
                "0 &entry/src/main/ets/pages/Index&->#~@0>#load | Index.load unresolved=2",
                "  1 -> &entry/src/main/ets/pages/Index&->#~@0>@1*# | Index.load.<anonymous> [defines]",
                "  1 -> &entry/src/main/ets/pages/Index&->#~@0>#parse | Index.parse [this-class] x3 (repeated)",
                "  1 -> import:@ohos:net.http#default.createHttp [external]",
                "    2 -> this.cfg.get [unresolved] [new]",
                "    2 -> import:lib#Store.open().read [unlinked] x2",
            ]
        );
        assert!(tree.lines(true)[0].ends_with(" unresolved=2 [ets/modules.abc]"));
        assert_eq!(
            tree.footer(),
            "# 6 rows, 3 distinct functions, 3 leaves (callees, depth 2); 1 records scanned; truncated (raise max_nodes or lower depth)\n# x is encrypted"
        );
    }

    #[test]
    fn several_sites_keep_the_strongest_kind() {
        let mut neighbors = Neighbors::default();
        let target = Node::Function(FnRef { entry: 0, method: 8 });
        neighbors.add(target.clone(), EdgeKind::Defines);
        neighbors.add(target.clone(), EdgeKind::ThisClass);
        neighbors.add(Node::Leaf { path: "?".into(), kind: LeafKind::Unresolved }, EdgeKind::Call);
        neighbors.add(target, EdgeKind::Defines);
        assert_eq!(neighbors.0.iter().map(|n| (n.kind, n.sites)).collect::<Vec<_>>(), [(EdgeKind::ThisClass, 3), (EdgeKind::Call, 1)]);
    }
}
