//! Class hierarchy of a program: the parent of every class definition, and
//! walks over those links in both directions.
//!
//! An ArkTS class is created at run time by `defineclasswithbuffer` (or
//! `callruntime.definesendableclass`): a constructor method, a literal
//! array with the methods, and a register that holds the parent class. No
//! table names the parent, so it is what the register can be proved to
//! hold, by the rules of [`crate::track`] with captured variables resolved
//! ([`crate::scopes`]):
//!
//! - `hole`: the class has no `extends` clause;
//! - a class (or function) the same record defines, directly, through a
//!   captured variable or through a module-level binding with one writer;
//! - an imported binding whose request names a record of the program and
//!   whose export chain ends at a local export with one writer, the value
//!   written being a class or function of that record
//!   ([`crate::callgraph`]'s resolution of imports);
//! - the same through a binding that is written more than once, when one
//!   write stores a class or function and every other write stores a value
//!   computed at run time: what a class decorator compiles to
//!   (`C = decorator(C) || C`). The link is marked *reassigned*: the
//!   binding holds the class or what the decorator returned for it (the
//!   rule is [`crate::scopes::ExportedDefinitions`], which the call graph
//!   follows too);
//! - anything else is a leaf that keeps the value's path as `findrefs call:`
//!   prints paths: *external* when the path starts at an import whose
//!   request names no record of the program (`import:@ohos:app.ability.UIAbility#default`)
//!   or at a global (`global:Error`), *unresolved* otherwise (`arg0`,
//!   `lex(1,2)`, `expr`, `?`, an import of a program record whose export
//!   does not lead to one definition). Nothing is guessed.
//!
//! A class is identified by its constructor: `RECORD->#~@0=#Name`, printed
//! with the class name restored from it. The methods a class defines are
//! the ones its literal array lists and the methods and accessors the
//! instructions after the definition add by name ([`crate::scopes`]);
//! fields and methods with computed names are not seen.
//!
//! The classes of a record are worked out when a walk first needs them and
//! kept for the life of the [`Engine`] (until [`Engine::release_analyses`]):
//! supertypes need the records along the chain, subclasses every record.

use asc_cache::LockExt;
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use asc_abc::{Abc, ClassEntry, ModuleRecord};
use asc_arkisa::Prefix;

use crate::callgraph::modules::{Binding, Layout};
use crate::callgraph::{GraphCache, RecordId};
use crate::path::{Link, MAX_PATH_LINKS, Names, NoLexicals, Origin, Path, PathBuilder};
use crate::refs::{Regions, chunks, pc_of, run_units};
use crate::scopes::{Exported, ExportedDefinitions, Reader, ScopeTables, Scopes, export_group};
use crate::track::{Event, Tracker, Watch};
use crate::{Engine, EngineError, Pattern, Result, records, table_bytes};

/// Module-level bindings followed from one to the next before a parent is
/// left unresolved.
const MAX_HOPS: usize = 8;
/// Records analysed per unit of parallel work.
const RECORDS_PER_UNIT: usize = 4;
/// What a restored constructor name ends with: `Index.constructor`.
const CONSTRUCTOR_SUFFIX: &str = ".constructor";

/// Which way to walk the hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lineage {
    /// Classes that extend the target, transitively.
    Subclasses,
    /// The target's parent class, its parent, and so on.
    Supers,
}

impl Lineage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Lineage::Subclasses => "subclasses",
            Lineage::Supers => "supers",
        }
    }

    /// The word before a row reached from its parent row.
    const fn word(self) -> &'static str {
        match self {
            Lineage::Subclasses => "subclass",
            Lineage::Supers => "extends",
        }
    }
}

/// A hierarchy query.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HierarchyQuery {
    /// Where the walk starts:
    ///
    /// - `CLASS`: every class of the program with that name — its restored
    ///   name (`EntryAbility`), a dotted suffix of it (`Inner` for
    ///   `Outer.Inner`) or the raw name of its constructor
    ///   (`#~@0=#EntryAbility`);
    /// - `RECORD->CLASS`, as rows print classes: the record by its
    ///   canonical name or a path suffix of it, as for `getclass` (a
    ///   function of the record that is no class is taken too: a parent
    ///   may be one);
    /// - `import:REGEX` / `global:REGEX`: every parent path that is no
    ///   class of the program and that the regex — the whole text, with an
    ///   optional `^` ahead — matches (`import:@ohos:app\.ability\.UIAbility`,
    ///   `^global:Error$`); the paths are what rows print. Subclasses only.
    ///
    /// A plain `CLASS` that names no class of the program starts at the
    /// parent paths that contain it as text, when the walk is downward.
    pub class: String,
    /// Look for the class in this ABC entry only.
    pub entry: Option<String>,
    pub direction: Lineage,
    /// Levels to walk (1 = direct subclasses / the parent).
    pub depth: usize,
    /// Stop discovering classes beyond this many (the roots included).
    pub max_nodes: usize,
    /// Mark the classes whose literal lists a method of this name.
    pub method: Option<String>,
}

impl HierarchyQuery {
    /// The query with [`entry`](#structfield.entry) set.
    #[must_use]
    pub fn entry(self, entry: Option<String>) -> Self {
        HierarchyQuery { entry, ..self }
    }

    /// The query with [`depth`](#structfield.depth) set.
    #[must_use]
    pub fn depth(self, depth: usize) -> Self {
        HierarchyQuery { depth, ..self }
    }

    /// The query with [`max_nodes`](#structfield.max_nodes) set.
    #[must_use]
    pub fn max_nodes(self, max_nodes: usize) -> Self {
        HierarchyQuery { max_nodes, ..self }
    }

    /// The query with [`method`](#structfield.method) set.
    #[must_use]
    pub fn method(self, method: Option<String>) -> Self {
        HierarchyQuery { method, ..self }
    }
}

impl HierarchyQuery {
    /// A walk from `class`: 16 levels, at most 2000 classes, no method marked.
    pub fn new(class: impl Into<String>, direction: Lineage) -> HierarchyQuery {
        HierarchyQuery { class: class.into(), entry: None, direction, depth: 16, max_nodes: 2000, method: None }
    }
}

/// What a row of the tree is.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClassNode {
    /// A class of the program (or a function used as one).
    Class {
        /// The ABC entry that holds it.
        entry: String,
        /// Canonical record name.
        record: String,
        /// Raw name of its constructor: `record->function` can be given
        /// back as the class of a query, and to `getclass` / `callgraph`.
        function: String,
        /// Readable name, e.g. `EntryAbility`.
        name: String,
    },
    /// A parent that is not a class of the program.
    Leaf {
        /// The parent's path, as `findrefs call:` prints paths.
        path: String,
        /// It starts at an import outside the program or at a global, as
        /// opposed to somewhere tracking stopped.
        external: bool,
    },
}

/// A method a class defines under the name a query asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DefinedMethod {
    /// Raw function name, in the record of the class.
    pub function: String,
    /// Readable name, e.g. `EntryAbility.onCreate`.
    pub restored: String,
    pub is_static: bool,
}

impl DefinedMethod {
    /// Raw `function`, `restored` as it reads, static or not.
    pub fn new(function: impl Into<String>, restored: impl Into<String>, is_static: bool) -> DefinedMethod {
        DefinedMethod { function: function.into(), restored: restored.into(), is_static }
    }
}

/// One line of the tree, in depth-first order.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClassRow {
    /// 0 for a root.
    pub depth: usize,
    /// Index of the parent row (`None` for a root).
    pub parent: Option<usize>,
    pub node: ClassNode,
    /// Shown again: what is below this node is listed at another row of it.
    pub repeated: bool,
    /// The class is a `callruntime.definesendableclass` one.
    pub sendable: bool,
    /// The node is a function of the program no class definition makes: a
    /// parent that is a plain function.
    pub plain_function: bool,
    /// A supers walk ends here: the class has no `extends` clause.
    pub no_parent: bool,
    /// The link to the parent row goes through a binding that is assigned
    /// the class and then a value computed at run time (a class decorator):
    /// the subclass extends the class or what replaced it.
    pub reassigned: bool,
    /// The methods (and accessors) of the queried name the class defines.
    pub defines: Vec<DefinedMethod>,
    /// A method was asked for and the layout of the class literal was not
    /// understood: whether the class defines it is not known.
    pub members_unknown: bool,
}

impl ClassRow {
    /// A row of `node` at `depth` under row `parent`, with no flag set and
    /// no method defined. For front ends that lay out trees of their own
    /// (and their tests).
    pub fn new(depth: usize, parent: Option<usize>, node: ClassNode) -> ClassRow {
        ClassRow {
            depth,
            parent,
            node,
            repeated: false,
            sendable: false,
            plain_function: false,
            no_parent: false,
            reassigned: false,
            defines: Vec::new(),
            members_unknown: false,
        }
    }
}

/// Result of [`Engine::hierarchy`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HierarchyTree {
    pub direction: Lineage,
    pub depth: usize,
    pub rows: Vec<ClassRow>,
    /// Distinct classes among the rows.
    pub classes: usize,
    /// Distinct leaves among the rows.
    pub leaves: usize,
    /// More nodes exist than `max_nodes` allowed.
    pub truncated: bool,
    /// The queried method, as given.
    pub method: Option<String>,
    /// A plain class name matched no class and the roots are the parent
    /// paths that contain it.
    pub roots_by_text: bool,
    /// Records whose class definitions the walk looked at.
    pub records_scanned: usize,
    /// What the program leaves out (encrypted entries).
    pub notes: Vec<String>,
}

impl HierarchyTree {
    /// One line per row: indentation and the depth number, `subclass` (or
    /// `extends` going up), then `RECORD->CONSTRUCTOR | Name` or a leaf's
    /// path, and flags: `[external]` / `[unresolved]` for a leaf,
    /// `[sendable]`, `[function]` for a parent that is a plain function,
    /// `[no superclass]` where a supers walk ends at a class without
    /// `extends`, `[reassigned]` for a link through a binding a decorator
    /// reassigns, `[defines FUNCTION]` / `[defines static FUNCTION]` and
    /// `[members unknown]` for a queried method, `[ENTRY]` when
    /// `with_entry`, and `(repeated)`.
    pub fn lines(&self, with_entry: bool) -> Vec<String> {
        self.rows
            .iter()
            .map(|row| {
                let mut line = "  ".repeat(row.depth);
                line.push_str(&row.depth.to_string());
                if row.depth > 0 {
                    line.push(' ');
                    line.push_str(self.direction.word());
                }
                line.push(' ');
                match &row.node {
                    ClassNode::Class { record, function, name, .. } => line.push_str(&format!("{record}->{function} | {name}")),
                    ClassNode::Leaf { path, external } => {
                        line.push_str(path);
                        line.push_str(if *external { " [external]" } else { " [unresolved]" });
                    }
                }
                if row.sendable {
                    line.push_str(" [sendable]");
                }
                if row.plain_function {
                    line.push_str(" [function]");
                }
                if row.no_parent {
                    line.push_str(" [no superclass]");
                }
                if row.reassigned {
                    line.push_str(" [reassigned]");
                }
                for defined in &row.defines {
                    line.push_str(&format!(" [defines {}{}]", if defined.is_static { "static " } else { "" }, defined.function));
                }
                if row.members_unknown {
                    line.push_str(" [members unknown]");
                }
                if let (true, ClassNode::Class { entry, .. }) = (with_entry, &row.node) {
                    line.push_str(&format!(" [{entry}]"));
                }
                if row.repeated {
                    line.push_str(" (repeated)");
                }
                line
            })
            .collect()
    }

    /// `RECORD->FUNCTION | Class.method` of every definition of the queried
    /// method below (or above) the roots, one per line, prefixed `override`
    /// (`inherited` going up): what `getclass` and `callgraph` take.
    pub fn definition_lines(&self) -> Vec<String> {
        let word = match self.direction {
            Lineage::Subclasses => "override",
            Lineage::Supers => "inherited",
        };
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for row in self.rows.iter().filter(|row| row.depth > 0 && !row.defines.is_empty()) {
            let ClassNode::Class { record, .. } = &row.node else { continue };
            if !seen.insert(&row.node) {
                continue;
            }
            for defined in &row.defines {
                out.push(format!(
                    "{word} {record}->{} | {}{}",
                    defined.function,
                    defined.restored,
                    if defined.is_static { " [static]" } else { "" }
                ));
            }
        }
        out
    }

    /// The tree as both front ends print it: the rows, then the definition
    /// lines, and the footer. Rows name their ABC entry only when the
    /// classes of the tree come from several; `several_entries`: the
    /// program has more than one, and the footer then names the one entry
    /// of a tree that has one.
    pub fn text(&self, several_entries: bool) -> (Vec<String>, String) {
        let mut entries = self.rows.iter().filter_map(|row| match &row.node {
            ClassNode::Class { entry, .. } => Some(entry.as_str()),
            ClassNode::Leaf { .. } => None,
        });
        let first = entries.next();
        let with_entry = entries.any(|entry| Some(entry) != first);
        let mut lines = self.lines(with_entry);
        lines.extend(self.definition_lines());
        let mut footer = self.footer();
        if let (Some(entry), true, false) = (first, several_entries, with_entry) {
            let at = footer.find('\n').unwrap_or(footer.len());
            footer.insert_str(at, &format!("; all in {entry}"));
        }
        (lines, footer)
    }

    /// Footer comment summarising the walk.
    pub fn footer(&self) -> String {
        let mut footer = format!(
            "# {} rows, {} distinct classes, {} leaves ({}, depth {}); {} records scanned",
            self.rows.len(),
            self.classes,
            self.leaves,
            self.direction.as_str(),
            self.depth,
            self.records_scanned
        );
        if let Some(method) = &self.method {
            let below = match self.direction {
                Lineage::Subclasses => "subclasses",
                Lineage::Supers => "supertypes",
            };
            footer.push_str(&format!("; {} {below} define {method}", self.definition_lines().len()));
        }
        if self.truncated {
            footer.push_str("; truncated (raise max_nodes or lower depth)");
        }
        if self.roots_by_text {
            footer.push_str("\n# no class of the program has that name: the roots are the parent paths that contain it");
        }
        for note in &self.notes {
            footer.push_str(&format!("\n# {note}"));
        }
        footer
    }
}

/// How the parent of a class definition was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum ParentKind {
    /// No `extends` clause.
    None,
    /// A class (or function) the same record defines.
    SameRecord,
    /// A class (or function) of another record, through an import.
    OtherRecord,
    /// An import outside the program or a global.
    External,
    /// Tracking stopped: the path says where.
    Unresolved,
}

impl ParentKind {
    pub const ALL: [ParentKind; 5] =
        [ParentKind::None, ParentKind::SameRecord, ParentKind::OtherRecord, ParentKind::External, ParentKind::Unresolved];

    pub const fn label(self) -> &'static str {
        match self {
            ParentKind::None => "none",
            ParentKind::SameRecord => "same record",
            ParentKind::OtherRecord => "other record",
            ParentKind::External => "external",
            ParentKind::Unresolved => "unresolved",
        }
    }
}

/// One class definition site, for [`Engine::class_definitions`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ClassDefinition {
    /// The class: always [`ClassNode::Class`].
    pub class: ClassNode,
    /// Raw name of the function that holds the instruction.
    pub definer: String,
    /// Offset of the instruction in the code of `definer`.
    pub pc: u32,
    pub sendable: bool,
    pub kind: ParentKind,
    /// The parent; `None` for [`ParentKind::None`].
    pub parent: Option<ClassNode>,
    /// The parent was read from a binding that is reassigned (see
    /// [`ClassRow::reassigned`]).
    pub reassigned: bool,
    /// Methods the class literal lists (instance, static); `None` when its
    /// layout was not understood.
    pub methods: Option<(usize, usize)>,
}

/// A class of a program: the ABC entry and the offset of its constructor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct ClassRef {
    pub entry: u32,
    pub ctor: u32,
}

/// The parent of a class definition, as far as its own record tells.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Parent {
    /// `hole`: no `extends` clause.
    None,
    /// A class constructor or function of the record.
    Local(Exported),
    /// An exported binding of another record of the program. `text`: the
    /// parent's path, for when the binding does not lead to a definition.
    Import {
        binding: Binding,
        text: u32,
    },
    Leaf {
        text: u32,
        external: bool,
    },
}

/// A method of a class literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MemberDef {
    /// File offset of its name.
    name: u32,
    method: u32,
    is_static: bool,
}

/// One class definition site.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ClassDef {
    ctor: u32,
    /// Method offset of the function that holds the instruction.
    definer: u32,
    pc: u32,
    sendable: bool,
    parent: Parent,
    /// `None` when the layout of the class literal was not understood.
    members: Option<Vec<MemberDef>>,
}

/// The class definitions of one record.
#[derive(Debug, Default)]
pub(crate) struct RecordClasses {
    /// In function then code order.
    defs: Vec<ClassDef>,
    /// Per constructor: its first definition in `defs`.
    by_ctor: HashMap<u32, u32>,
    texts: Vec<String>,
}

impl RecordClasses {
    fn text(&self, id: u32) -> &str {
        self.texts.get(id as usize).map_or("?", String::as_str)
    }

    /// Every definition of the class whose constructor is `ctor`.
    fn of(&self, ctor: u32) -> impl Iterator<Item = &ClassDef> {
        let first = self.by_ctor.get(&ctor).map_or(self.defs.len(), |&index| index as usize);
        self.defs[first..].iter().filter(move |def| def.ctor == ctor)
    }

    /// Bytes this takes on the heap, roughly.
    fn heap_bytes(&self) -> usize {
        use std::mem::size_of;
        let members = |def: &ClassDef| def.members.as_ref().map_or(0, |members| members.capacity() * size_of::<MemberDef>());
        let bound = |def: &ClassDef| match &def.parent {
            Parent::Import { binding, .. } => binding.exports.capacity() * size_of::<u32>(),
            Parent::None | Parent::Local(_) | Parent::Leaf { .. } => 0,
        };
        self.defs.capacity() * size_of::<ClassDef>()
            + self.defs.iter().map(|def| members(def) + bound(def)).sum::<usize>()
            + table_bytes(&self.by_ctor)
            + self.texts.capacity() * size_of::<String>()
            + self.texts.iter().map(String::capacity).sum::<usize>()
    }
}

/// What the hierarchy keeps for an [`Engine`] until
/// [`Engine::release_analyses`] starts over with an empty one. A walk holds
/// the cache it started with.
#[derive(Default)]
pub(crate) struct ClassCache {
    records: Mutex<HashMap<RecordId, Arc<RecordClasses>>>,
    /// Heap bytes of what was computed so far, roughly.
    bytes: AtomicUsize,
}

impl ClassCache {
    /// Bytes the class definitions worked out so far take on the heap, roughly.
    pub(crate) fn heap_bytes(&self) -> usize {
        self.bytes.load(Ordering::Relaxed)
    }
}

/// What a record's entry in [`ClassCache::records`] takes besides its contents.
const ENTRY_BYTES: usize =
    std::mem::size_of::<(RecordId, Arc<RecordClasses>)>() + std::mem::size_of::<RecordClasses>() + 2 * std::mem::size_of::<usize>();

/// A node of a walk.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Node {
    Class(ClassRef),
    Leaf { path: String, external: bool },
}

/// One query's view of the program and the caches.
pub(crate) struct Session<'e> {
    engine: &'e Engine,
    /// The entries by index; `None` for the unreadable ones.
    abcs: Vec<Option<Abc<'e>>>,
    regions: Vec<Option<Regions<'e>>>,
    tables: ScopeTables,
    /// Where the scopes of a record are shared with the call graph.
    graph: Arc<GraphCache>,
    cache: Arc<ClassCache>,
}

/// The record a parent is resolved in.
struct Home<'s, 'a> {
    id: RecordId,
    abc: Abc<'a>,
    module: Option<ModuleRecord<'a>>,
    scopes: &'s Scopes,
}

impl Home<'_, '_> {
    /// The local export entries that share the local name of entry `index`.
    fn export_group(&self, index: u32) -> Option<Vec<u32>> {
        export_group(&self.abc, self.module.as_ref()?, index)
    }
}

/// Interns the leaf texts of one record.
#[derive(Default)]
struct Texts {
    ids: HashMap<String, u32>,
    list: Vec<String>,
}

impl Texts {
    fn id(&mut self, text: &str) -> u32 {
        if let Some(&id) = self.ids.get(text) {
            return id;
        }
        let id = u32::try_from(self.list.len()).unwrap_or(u32::MAX);
        self.list.push(text.to_owned());
        self.ids.insert(text.to_owned(), id);
        id
    }
}

/// The class name a restored constructor name stands for: `Index` for
/// `Index.constructor`.
fn class_name(restored: &str) -> &str {
    restored.strip_suffix(CONSTRUCTOR_SUFFIX).filter(|name| !name.is_empty()).unwrap_or(restored)
}

/// Whether a class spelling is a regex over parent paths: it starts, after
/// an optional `^`, with the kind of a path outside the program.
fn is_parent_path(spec: &str) -> bool {
    let spec = spec.strip_prefix('^').unwrap_or(spec);
    spec.starts_with("import:") || spec.starts_with("global:")
}

/// Whether `wanted` names the class whose constructor is `raw`: the raw
/// name, the class name or a dotted suffix of it.
fn names_class(wanted: &str, raw: &str, name: &str) -> bool {
    wanted == raw || wanted == name || name.strip_suffix(wanted).is_some_and(|rest| rest.ends_with('.'))
}

impl<'e> Session<'e> {
    fn new(engine: &'e Engine) -> Session<'e> {
        Session::with_graph(engine, engine.graph_cache())
    }

    /// A view for a query that holds `graph` already: the scopes of a
    /// record are then shared with it whatever is released meanwhile.
    pub(crate) fn with_graph(engine: &'e Engine, graph: Arc<GraphCache>) -> Session<'e> {
        let program = &engine.program;
        let abcs: Vec<Option<Abc<'e>>> = (0..program.len()).map(|index| program.abc(index)).collect();
        let regions = abcs.iter().map(|abc| abc.as_ref().map(Regions::of)).collect();
        Session { engine, abcs, regions, tables: ScopeTables::new(), graph, cache: engine.class_cache() }
    }

    fn layout(&self) -> Layout<'_, 'e> {
        Layout { abcs: &self.abcs, program: &self.engine.program, packages: self.graph.packages() }
    }

    /// The class or function the binding of local export `index` of record
    /// `id` holds, when that is known.
    fn exported(&self, id: RecordId, index: u32) -> Option<Exported> {
        let abc = self.abc(id.entry)?;
        let regions = self.regions.get(id.entry as usize)?.as_ref()?;
        let class = abc.class(id.class).ok()?;
        let slot = self.graph.slot(id);
        let scopes = self.graph.scopes(&slot, || Scopes::build(abc, regions, &class, &self.tables, &mut Tracker::default()));
        self.graph.exported(&slot, || ExportedDefinitions::build(abc, regions, &class, scopes, &self.tables)).get(index)
    }

    fn abc(&self, entry: u32) -> Option<Abc<'e>> {
        self.abcs.get(entry as usize).copied().flatten()
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

    /// The class definitions of record `id`, worked out on first use.
    fn record(&self, id: RecordId) -> Arc<RecordClasses> {
        let known = self.cache.records.lock_or_default().get(&id).cloned();
        if let Some(known) = known {
            return known;
        }
        // Two walks may both analyse it; the first to finish is kept.
        let built = Arc::new(self.analyse(id));
        let mut records = self.cache.records.lock_or_default();
        Arc::clone(records.entry(id).or_insert_with(|| {
            self.cache.bytes.fetch_add(ENTRY_BYTES + built.heap_bytes(), Ordering::Relaxed);
            built
        }))
    }

    /// The class definitions of `records`, worked out on the engine's threads.
    fn load(&self, records: &[RecordId], cancel: &AtomicBool) -> Result<Vec<Arc<RecordClasses>>> {
        let units: Vec<Range<usize>> = chunks(records.len(), RECORDS_PER_UNIT).collect();
        let loaded = run_units(units.len(), self.engine.threads(), cancel, |unit| {
            records[units[unit].clone()].iter().map(|&id| self.record(id)).collect::<Vec<_>>()
        })?;
        Ok(loaded.into_iter().flatten().collect())
    }

    /// Work out the class definitions of record `id`. A record that does
    /// not read has none.
    fn analyse(&self, id: RecordId) -> RecordClasses {
        let mut out = RecordClasses::default();
        let Some((abc, regions)) = self.abc(id.entry).zip(self.regions.get(id.entry as usize).and_then(Option::as_ref)) else {
            return out;
        };
        let Ok(class) = abc.class(id.class) else { return out };
        let slot = self.graph.slot(id);
        let scopes = self.graph.scopes(&slot, || Scopes::build(abc, regions, &class, &self.tables, &mut Tracker::default()));
        let home = Home { id, abc, module: class.module_record().ok().flatten(), scopes };
        let names = Names { abc: &abc, module: home.module.as_ref() };
        let mut texts = Texts::default();
        let mut tracker = Tracker::default();
        let (mut path, mut text) = (Path::default(), String::new());
        // A malformed member list ends the record's functions.
        let methods: Vec<_> = class.methods().into_iter().flatten().map_while(|method| method.ok()).collect();
        let exported = self.graph.exported(&slot, || ExportedDefinitions::build(abc, regions, &class, scopes, &self.tables));
        for method in &methods {
            let Some(function) = regions.function(abc, method) else { continue };
            let offset = method.offset();
            let reader = Reader::new(scopes, offset);
            let entity = |entity_id: u32| function.entity(entity_id);
            // Code that does not decode has no class definitions to show.
            let _ = tracker.run_events(self.tables.effects(), &function.code, Watch::Classes, |frame, insn, event| {
                let Event::Class { parent } = event else { return };
                let Some(ctor) = insn.method_id().and_then(|method_id| function.entity(method_id)) else { return };
                match &reader {
                    Some(reader) => PathBuilder { frame, function: offset, entity: &entity, lexicals: reader }.build(parent, &mut path),
                    None => PathBuilder { frame, function: offset, entity: &entity, lexicals: &NoLexicals }.build(parent, &mut path),
                }
                text.clear();
                names.write(&mut text, &path);
                let parent = self.parent(&home, exported, &path, &mut |external| Parent::Leaf { text: texts.id(&text), external });
                let members = scopes.class(ctor).map(|info| {
                    let instance =
                        info.instance.iter().map(|member| MemberDef { name: member.name, method: member.method, is_static: false });
                    let statics = info.statics.iter().map(|member| MemberDef { name: member.name, method: member.method, is_static: true });
                    instance.chain(statics).collect::<Vec<_>>()
                });
                let sendable = insn.opcode.prefix == Some(Prefix::CallRuntime);
                out.defs.push(ClassDef { ctor, definer: offset, pc: pc_of(insn), sendable, parent, members });
            });
        }
        for (index, def) in out.defs.iter().enumerate() {
            out.by_ctor.entry(def.ctor).or_insert(u32::try_from(index).unwrap_or(u32::MAX));
        }
        out.defs.shrink_to_fit();
        out.texts = texts.list;
        out
    }

    /// What `path`, the value of a parent register in record `home`, is.
    /// `leaf` makes the leaf that keeps the path (`true`: external).
    /// `exports`: the definitions the bindings of `home` hold.
    fn parent(&self, home: &Home<'_, 'e>, exports: &ExportedDefinitions, path: &Path, leaf: &mut dyn FnMut(bool) -> Parent) -> Parent {
        let mut current = path.clone();
        for _ in 0..MAX_HOPS {
            if current.cut {
                break;
            }
            match (current.origin, &current.links[..]) {
                (Origin::Constant("hole"), []) => return Parent::None,
                (Origin::Definition(Some(method)), []) => return Parent::Local(Exported { method, reassigned: false }),
                (Origin::ModuleLocal(index), links) => {
                    if let (Some(exported), []) = (exports.get(index), links) {
                        return Parent::Local(exported);
                    }
                    let Some(written) = home.export_group(index).and_then(|group| home.scopes.module_binding(&group).ok()) else { break };
                    if written.path.cut || written.path.links.len() + links.len() > MAX_PATH_LINKS {
                        break;
                    }
                    let mut next = written.path.clone();
                    next.links.extend_from_slice(links);
                    current = next;
                }
                (Origin::Import(index), links) => {
                    let Some(import) = home.module.as_ref().and_then(|module| module.regular_imports.get(index as usize)) else { break };
                    let Some(target) = self.layout().request(home.id, import.module_request_idx) else {
                        return leaf(current.is_known());
                    };
                    let name = home.abc.string(import.import_name_off).ok().map(|name| name.bytes);
                    return self.imported(target, name.filter(|_| links.is_empty()), leaf);
                }
                (Origin::Namespace(index), links) => {
                    let target = u16::try_from(index).ok().and_then(|index| self.layout().request(home.id, index));
                    let Some(target) = target else { return leaf(current.is_known()) };
                    let name = match links {
                        [Link::Property(Some(name))] => home.abc.string(*name).ok().map(|name| name.bytes),
                        _ => None,
                    };
                    return self.imported(target, name, leaf);
                }
                (Origin::Global(_) | Origin::GlobalObject, _) => return leaf(current.is_known()),
                _ => break,
            }
        }
        leaf(false)
    }

    /// The binding record `target` exports as `name`; unresolved without a
    /// name (the parent is a member of the import, not the import) or when
    /// the export chain does not end in the program.
    fn imported(&self, target: RecordId, name: Option<&[u8]>, leaf: &mut dyn FnMut(bool) -> Parent) -> Parent {
        match name.and_then(|name| self.layout().export(target, name)) {
            Some(binding) => match leaf(false) {
                Parent::Leaf { text, .. } => Parent::Import { binding, text },
                other => other,
            },
            None => leaf(false),
        }
    }

    /// The node `parent` of a class of `home` (whose definitions are
    /// `classes`) is; `None` for a class without parent.
    /// The flag says whether the link goes through a reassigned binding.
    fn parent_node(&self, home: RecordId, classes: &RecordClasses, parent: &Parent) -> Option<(Node, bool)> {
        match parent {
            Parent::None => None,
            Parent::Local(local) => Some((Node::Class(ClassRef { entry: home.entry, ctor: local.method }), local.reassigned)),
            Parent::Leaf { text, external } => Some((Node::Leaf { path: classes.text(*text).to_owned(), external: *external }, false)),
            Parent::Import { binding, text } => {
                // The entries of a binding share one variable: any of them names it.
                let exported = binding.exports.first().and_then(|&index| self.exported(binding.record, index));
                Some(match exported {
                    Some(exported) => (Node::Class(ClassRef { entry: binding.record.entry, ctor: exported.method }), exported.reassigned),
                    None => (Node::Leaf { path: classes.text(*text).to_owned(), external: false }, false),
                })
            }
        }
    }

    /// The one parent class (or function) of `class`, with whether the
    /// link goes through a reassigned binding: `None` for a class without
    /// parent, with a parent outside the program or one that was not
    /// resolved, and for a constructor two definitions give different
    /// parents.
    pub(crate) fn superclass(&self, class: ClassRef) -> Option<(ClassRef, bool)> {
        match &self.parents(class)[..] {
            [(Node::Class(parent), reassigned)] => Some((*parent, *reassigned)),
            _ => None,
        }
    }

    /// The classes `records` define with one of `parents` as their parent,
    /// each with that parent, in the order of `records`; the definitions of
    /// those records are worked out, and their parents resolved, on the
    /// engine's threads.
    ///
    /// # Errors
    /// [`EngineError::Cancelled`].
    pub(crate) fn subclasses_among(
        &self,
        parents: &HashSet<ClassRef>,
        records: &[RecordId],
        cancel: &AtomicBool,
    ) -> Result<Vec<(ClassRef, ClassRef)>> {
        let units: Vec<Range<usize>> = chunks(records.len(), RECORDS_PER_UNIT).collect();
        let found = run_units(units.len(), self.engine.threads(), cancel, |unit| {
            let mut found = Vec::new();
            for &id in &records[units[unit].clone()] {
                let classes = self.record(id);
                for def in &classes.defs {
                    if let Some((Node::Class(parent), _)) = self.parent_node(id, &classes, &def.parent)
                        && parents.contains(&parent)
                    {
                        found.push((ClassRef { entry: id.entry, ctor: def.ctor }, parent));
                    }
                }
            }
            found
        })?;
        Ok(found.into_iter().flatten().collect())
    }

    /// The record that holds the constructor of `class`.
    pub(crate) fn record_of(&self, class: ClassRef) -> Option<RecordId> {
        let method = self.abc(class.entry)?.method(class.ctor).ok()?;
        Some(RecordId { entry: class.entry, class: method.class_off().ok()? })
    }

    /// The parents of `class`: one per definition of it, without repeats,
    /// each with whether the link goes through a reassigned binding.
    fn parents(&self, class: ClassRef) -> Vec<(Node, bool)> {
        let Some(home) = self.record_of(class) else { return Vec::new() };
        let classes = self.record(home);
        let mut out: Vec<(Node, bool)> = Vec::new();
        for def in classes.of(class.ctor) {
            if let Some((node, reassigned)) = self.parent_node(home, &classes, &def.parent)
                && !out.iter().any(|(known, _)| *known == node)
            {
                out.push((node, reassigned));
            }
        }
        out
    }

    fn entry_name(&self, entry: u32) -> &'e str {
        self.engine.program.info(entry as usize).map_or("", |info| info.name.as_str())
    }

    /// `(record, raw constructor name, class name)` of `class`.
    fn names_of(&self, class: ClassRef) -> (String, String, String) {
        let method = self.abc(class.entry).and_then(|abc| abc.method(class.ctor).ok());
        let raw = method.and_then(|method| method.name().ok()).map_or_else(|| "?".to_owned(), |name| name.to_str().into_owned());
        let record = self.record_of(class).and_then(|id| self.abc(id.entry)?.class(id.class).ok());
        let name = record.map_or_else(|| raw.clone(), |record| class_name(&record.restore_function_name(&raw)).to_owned());
        let record = record.map_or_else(|| "?".to_owned(), |record| String::from_utf8_lossy(record.name()).into_owned());
        (record, raw, name)
    }

    fn describe(&self, node: &Node) -> ClassNode {
        match node {
            Node::Leaf { path, external } => ClassNode::Leaf { path: path.clone(), external: *external },
            Node::Class(class) => {
                let (record, function, name) = self.names_of(*class);
                ClassNode::Class { entry: self.entry_name(class.entry).to_owned(), record, function, name }
            }
        }
    }

    /// The methods called `wanted` the literal of `def` lists; `None` when
    /// its layout was not understood.
    fn defined(&self, class: ClassRef, def: &ClassDef, wanted: &str) -> Option<Vec<DefinedMethod>> {
        let abc = self.abc(class.entry)?;
        let record = self.record_of(class).and_then(|id| abc.class(id.class).ok());
        let members = def.members.as_ref()?;
        let named = members.iter().filter(|member| abc.string(member.name).is_ok_and(|name| name.bytes == wanted.as_bytes()));
        Some(
            named
                .map(|member| {
                    let raw = abc.method(member.method).ok().and_then(|method| method.name().ok());
                    let function = raw.map_or_else(|| "?".to_owned(), |name| name.to_str().into_owned());
                    let restored = record.map_or_else(|| function.clone(), |record| record.restore_function_name(&function));
                    DefinedMethod { function, restored, is_static: member.is_static }
                })
                .collect(),
        )
    }

    /// Whether record `id` has a function `name` could name as a class: by
    /// its raw name, or with the restored name of a constructor.
    fn has_function_named(&self, id: RecordId, name: &str) -> bool {
        let Some(record) = self.abc(id.entry).and_then(|abc| abc.class(id.class).ok()) else { return false };
        // The last part of a class name is the text after the last `#` of its constructor's raw name.
        let last = name.rsplit('.').next().unwrap_or(name);
        record.methods().into_iter().flatten().map_while(|method| method.ok()).any(|method| {
            method.name().is_ok_and(|raw| {
                let raw = raw.to_str();
                raw == name || (raw.ends_with(last) && names_class(name, &raw, class_name(&record.restore_function_name(&raw))))
            })
        })
    }

    /// The classes of the program `name` names, in `record` when one is
    /// given; the records read for it are added to `scanned`.
    fn class_roots(
        &self,
        record: Option<&str>,
        name: &str,
        entry: Option<&str>,
        cancel: &AtomicBool,
        scanned: &mut HashSet<RecordId>,
    ) -> Result<Vec<ClassRef>> {
        let program = &self.engine.program;
        let mut located = None;
        let records: Vec<RecordId> = match record {
            Some(record) => {
                let found = records::resolve_record(program, record, entry)?;
                located = Some(found);
                let entry = program.infos().position(|info| info.name == found.entry).and_then(|index| u32::try_from(index).ok());
                entry.map(|entry| RecordId { entry, class: found.class.offset() }).into_iter().collect()
            }
            None => {
                // As `getclass --entry`: the name, or a suffix of it that starts at a `/`.
                let is_entry = |id: &RecordId| {
                    let name = self.entry_name(id.entry);
                    entry.is_none_or(|wanted| name == wanted || name.strip_suffix(wanted).is_some_and(|rest| rest.ends_with('/')))
                };
                let all: Vec<RecordId> = self.all_records().into_iter().filter(is_entry).collect();
                // Only the records with a function of that name are analysed: read from the method names alone.
                let units: Vec<Range<usize>> = chunks(all.len(), crate::refs::RECORD_CHUNK).collect();
                let named = run_units(units.len(), self.engine.threads(), cancel, |unit| {
                    all[units[unit].clone()].iter().copied().filter(|id| self.has_function_named(*id, name)).collect::<Vec<_>>()
                })?;
                named.into_iter().flatten().collect()
            }
        };
        scanned.extend(records.iter().copied());
        let loaded = self.load(&records, cancel)?;
        let mut found = Vec::new();
        for (id, classes) in records.iter().zip(&loaded) {
            let Some(record) = self.abc(id.entry).and_then(|abc| abc.class(id.class).ok()) else { continue };
            let mut seen = HashSet::new();
            for def in classes.defs.iter().filter(|def| seen.insert(def.ctor)) {
                let class = ClassRef { entry: id.entry, ctor: def.ctor };
                let Some(raw) = self.abc(id.entry).and_then(|abc| abc.method(def.ctor).ok()).and_then(|method| method.name().ok()) else {
                    continue;
                };
                let raw = raw.to_str();
                // The raw name decides alone when it is what was asked for: no name is restored then.
                if name == raw || names_class(name, &raw, class_name(&record.restore_function_name(&raw))) {
                    found.push(class);
                }
            }
        }
        // A function of the record that is no class, as the row of a parent that is one prints it.
        if let (true, Some(located), Some(id)) = (found.is_empty(), located, records.first()) {
            found.extend(records::resolve_function(&located, name).ok().map(|method| ClassRef { entry: id.entry, ctor: method.offset() }));
        }
        Ok(found)
    }

    fn walk(&self, query: &HierarchyQuery, cancel: &AtomicBool) -> Result<HierarchyTree> {
        let spec = query.class.trim();
        let entry = query.entry.as_deref();
        let down = query.direction == Lineage::Subclasses;
        let not_found = |what: &'static str| EngineError::NotFound { what, name: spec.to_owned(), notes: self.engine.notes().to_vec() };
        let is_path = is_parent_path(spec);
        if is_path && !down {
            return Err(EngineError::Query(
                "a parent path outside the program has no supertypes here: it is a root for subclasses only".to_owned(),
            ));
        }
        if is_path && entry.is_some() {
            return Err(EngineError::Query("an entry picks a class of the program: it does not go with a parent path".to_owned()));
        }
        let mut scanned: HashSet<RecordId> = HashSet::new();
        let class_roots = if is_path {
            Vec::new()
        } else {
            let (record, name) = match spec.split_once("->") {
                Some((record, name)) => (Some(record), name),
                None => (None, spec),
            };
            let found = self.class_roots(record, name, entry, cancel, &mut scanned)?;
            if found.is_empty() && (record.is_some() || !down) {
                return Err(not_found("class"));
            }
            found
        };

        // Downward, every record: any of them may define a subclass.
        let mut children: HashMap<Node, Vec<(Node, bool)>> = HashMap::new();
        if down {
            let records = self.all_records();
            let loaded = self.load(&records, cancel)?;
            scanned.extend(records.iter().copied());
            for (id, classes) in records.iter().zip(&loaded) {
                for def in &classes.defs {
                    let Some((parent, reassigned)) = self.parent_node(*id, classes, &def.parent) else { continue };
                    let class = Node::Class(ClassRef { entry: id.entry, ctor: def.ctor });
                    let below = children.entry(parent).or_default();
                    if !below.iter().any(|(known, _)| *known == class) {
                        below.push((class, reassigned));
                    }
                }
            }
        }
        let mut roots_by_text = false;
        let roots: Vec<Node> = if !class_roots.is_empty() {
            class_roots.into_iter().map(Node::Class).collect()
        } else {
            let pattern = if is_path {
                Pattern::regex(spec)?
            } else {
                roots_by_text = true;
                Pattern::contains(spec)
            };
            let mut leaves: Vec<&Node> =
                children.keys().filter(|node| matches!(node, Node::Leaf { path, .. } if pattern.is_match(path))).collect();
            if leaves.is_empty() {
                return Err(not_found(if is_path { "parent path" } else { "class" }));
            }
            // External before unresolved, then by path: the table has no order of its own.
            leaves.sort_by(|a, b| match (a, b) {
                (Node::Leaf { path: a, external: a_external }, Node::Leaf { path: b, external: b_external }) => {
                    b_external.cmp(a_external).then_with(|| a.cmp(b))
                }
                _ => std::cmp::Ordering::Equal,
            });
            leaves.into_iter().cloned().collect()
        };

        let neighbors = |node: &Node| -> Vec<(Node, bool)> {
            match (node, down) {
                (_, true) => children.get(node).cloned().unwrap_or_default(),
                (Node::Class(class), false) => self.parents(*class),
                (Node::Leaf { .. }, false) => Vec::new(),
            }
        };
        // Level by level: the neighbors of every node first met at that level.
        let mut level_of: HashMap<Node, usize> = HashMap::new();
        let mut below: HashMap<Node, Vec<(Node, bool)>> = HashMap::new();
        let mut truncated = false;
        let mut frontier = Vec::new();
        for root in &roots {
            if level_of.len() >= query.max_nodes {
                truncated = true;
                break;
            }
            if !level_of.contains_key(root) {
                level_of.insert(root.clone(), 0);
                frontier.push(root.clone());
            }
        }
        for level in 0..query.depth {
            if frontier.is_empty() {
                break;
            }
            if cancel.load(Ordering::Relaxed) {
                return Err(EngineError::Cancelled);
            }
            let mut next = Vec::new();
            for node in &frontier {
                let found = neighbors(node);
                for (neighbor, _) in &found {
                    if level_of.contains_key(neighbor) {
                        continue;
                    }
                    if level_of.len() >= query.max_nodes {
                        truncated = true;
                        continue;
                    }
                    level_of.insert(neighbor.clone(), level + 1);
                    next.push(neighbor.clone());
                }
                below.insert(node.clone(), found);
            }
            frontier = next;
        }

        // Depth first: a node is expanded where it is first met at its own level.
        let mut rows: Vec<ClassRow> = Vec::new();
        let mut expanded: HashSet<Node> = HashSet::new();
        let mut stack: Vec<(Node, usize, Option<usize>, bool)> =
            roots.iter().rev().filter(|root| level_of.contains_key(*root)).map(|root| (root.clone(), 0, None, false)).collect();
        // A root listed twice is one row.
        let mut root_seen = HashSet::new();
        stack.retain(|(node, ..)| root_seen.insert(node.clone()));
        while let Some((node, depth, parent, reassigned)) = stack.pop() {
            let expand = level_of.get(&node) == Some(&depth) && !expanded.contains(&node);
            let shown: Vec<&(Node, bool)> =
                below.get(&node).into_iter().flatten().filter(|(neighbor, _)| level_of.contains_key(neighbor)).collect();
            let mut row = ClassRow {
                depth,
                parent,
                node: self.describe(&node),
                repeated: !expand && !shown.is_empty(),
                sendable: false,
                plain_function: false,
                no_parent: false,
                reassigned,
                defines: Vec::new(),
                members_unknown: false,
            };
            if let Node::Class(class) = &node {
                self.flag(&mut row, *class, query, &mut scanned);
            }
            rows.push(row);
            if !expand {
                continue;
            }
            expanded.insert(node.clone());
            let index = rows.len() - 1;
            for (neighbor, reassigned) in shown.into_iter().rev() {
                stack.push((neighbor.clone(), depth + 1, Some(index), *reassigned));
            }
        }
        let classes = level_of.keys().filter(|node| matches!(node, Node::Class(_))).count();
        Ok(HierarchyTree {
            direction: query.direction,
            depth: query.depth,
            rows,
            classes,
            leaves: level_of.len() - classes,
            truncated,
            method: query.method.clone(),
            roots_by_text,
            records_scanned: scanned.len(),
            notes: self.engine.notes().to_vec(),
        })
    }

    /// What the row of `class` says of it besides its name.
    fn flag(&self, row: &mut ClassRow, class: ClassRef, query: &HierarchyQuery, scanned: &mut HashSet<RecordId>) {
        let Some(home) = self.record_of(class) else { return };
        scanned.insert(home);
        let classes = self.record(home);
        let mut defs = classes.of(class.ctor).peekable();
        if defs.peek().is_none() {
            row.plain_function = true;
            return;
        }
        for def in defs {
            row.sendable |= def.sendable;
            row.no_parent |= query.direction == Lineage::Supers && def.parent == Parent::None;
            let Some(wanted) = &query.method else { continue };
            match self.defined(class, def, wanted) {
                Some(defined) => {
                    for method in defined {
                        if !row.defines.contains(&method) {
                            row.defines.push(method);
                        }
                    }
                }
                None => row.members_unknown = true,
            }
        }
    }
}

impl Engine {
    /// Subclasses or supertypes of classes, to a bounded depth: see
    /// [`HierarchyQuery`] and the rows of [`HierarchyTree`].
    ///
    /// The class definitions of the records the walk touches are worked out
    /// on [`Engine::threads`] threads and kept: a later walk reuses them.
    ///
    /// # Errors
    /// [`EngineError::NotFound`] when the class names nothing (or, with a
    /// record, the record does not exist); [`EngineError::Ambiguous`] for a
    /// record name several records answer to; [`EngineError::Query`] for
    /// the supertypes of a parent path; [`EngineError::Pattern`];
    /// [`EngineError::Cancelled`].
    pub fn hierarchy(&self, query: &HierarchyQuery, cancel: &AtomicBool) -> Result<HierarchyTree> {
        Session::new(self).walk(query, cancel)
    }

    /// Every class definition of the program with its parent, record by
    /// record in program order, each record's in function then code order.
    /// For checks and measurements; a walk does not need it. Returns the
    /// number of records read.
    ///
    /// # Errors
    /// [`EngineError::Cancelled`].
    pub fn class_definitions(&self, cancel: &AtomicBool, sink: &mut dyn FnMut(ClassDefinition)) -> Result<usize> {
        let session = Session::new(self);
        let records = session.all_records();
        let loaded = session.load(&records, cancel)?;
        for (id, classes) in records.iter().zip(&loaded) {
            let Some(abc) = session.abc(id.entry) else { continue };
            for def in &classes.defs {
                let (parent, reassigned) = session.parent_node(*id, classes, &def.parent).unzip();
                let kind = match &parent {
                    None => ParentKind::None,
                    Some(Node::Class(class)) if session.record_of(*class) == Some(*id) => ParentKind::SameRecord,
                    Some(Node::Class(_)) => ParentKind::OtherRecord,
                    Some(Node::Leaf { external: true, .. }) => ParentKind::External,
                    Some(Node::Leaf { external: false, .. }) => ParentKind::Unresolved,
                };
                let definer = abc.method(def.definer).ok().and_then(|method| method.name().ok());
                sink(ClassDefinition {
                    class: session.describe(&Node::Class(ClassRef { entry: id.entry, ctor: def.ctor })),
                    definer: definer.map_or_else(|| "?".to_owned(), |name| name.to_str().into_owned()),
                    pc: def.pc,
                    sendable: def.sendable,
                    kind,
                    parent: parent.as_ref().map(|node| session.describe(node)),
                    reassigned: reassigned.unwrap_or(false),
                    methods: def.members.as_ref().map(|members| {
                        let statics = members.iter().filter(|member| member.is_static).count();
                        (members.len() - statics, statics)
                    }),
                });
            }
        }
        Ok(records.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(record: &str, function: &str, name: &str) -> ClassNode {
        ClassNode::Class { entry: "ets/modules.abc".into(), record: record.into(), function: function.into(), name: name.into() }
    }

    fn row(depth: usize, parent: Option<usize>, node: ClassNode) -> ClassRow {
        ClassRow {
            depth,
            parent,
            node,
            repeated: false,
            sendable: false,
            plain_function: false,
            no_parent: false,
            reassigned: false,
            defines: Vec::new(),
            members_unknown: false,
        }
    }

    #[test]
    fn class_names_come_from_constructors() {
        assert_eq!(class_name("Index.constructor"), "Index");
        assert_eq!(class_name("Outer.make.Inner.constructor"), "Outer.make.Inner");
        assert_eq!(class_name("Index"), "Index");
        assert_eq!(class_name(".constructor"), ".constructor");
        assert!(names_class("Inner", "#~@0>@1~@2=#Inner", "Outer.make.Inner"));
        assert!(names_class("Outer.make.Inner", "#~@0>@1~@2=#Inner", "Outer.make.Inner"));
        assert!(names_class("#~@0>@1~@2=#Inner", "#~@0>@1~@2=#Inner", "Outer.make.Inner"));
        assert!(!names_class("ner", "#~@0>@1~@2=#Inner", "Outer.make.Inner"));
        assert!(!names_class("Outer", "#~@0>@1~@2=#Inner", "Outer.make.Inner"));
        assert!(is_parent_path("import:@ohos:net") && is_parent_path("^global:Error$") && is_parent_path("global:"));
        assert!(!is_parent_path("Importer") && !is_parent_path("pages/import:x") && !is_parent_path("^^import:x"));
    }

    #[test]
    fn rows_print_like_the_dex_tree() {
        let ability = "&entry/src/main/ets/entryability/EntryAbility&";
        let base = "&entry/src/main/ets/base/Base&";
        let on_create = DefinedMethod { function: "#~@0>#onCreate".into(), restored: "EntryAbility.onCreate".into(), is_static: false };
        let make = DefinedMethod { function: "#~@0<#make".into(), restored: "Base.make".into(), is_static: true };
        let tree = HierarchyTree {
            direction: Lineage::Subclasses,
            depth: 16,
            rows: vec![
                row(0, None, ClassNode::Leaf { path: "import:@ohos:app.ability.UIAbility#default".into(), external: true }),
                ClassRow { defines: vec![on_create], ..row(1, Some(0), class(ability, "#~@0=#EntryAbility", "EntryAbility")) },
                ClassRow { sendable: true, defines: vec![make], ..row(1, Some(0), class(base, "#~@0=#Base", "Base")) },
                ClassRow { members_unknown: true, reassigned: true, ..row(2, Some(2), class(base, "#~@1=#Odd", "Odd")) },
                ClassRow { repeated: true, ..row(2, Some(2), class(ability, "#~@0=#EntryAbility", "EntryAbility")) },
            ],
            classes: 3,
            leaves: 1,
            truncated: true,
            method: Some("onCreate".into()),
            roots_by_text: true,
            records_scanned: 2,
            notes: vec!["x is encrypted".into()],
        };
        assert_eq!(
            tree.lines(false),
            [
                "0 import:@ohos:app.ability.UIAbility#default [external]",
                "  1 subclass &entry/src/main/ets/entryability/EntryAbility&->#~@0=#EntryAbility | EntryAbility [defines #~@0>#onCreate]",
                "  1 subclass &entry/src/main/ets/base/Base&->#~@0=#Base | Base [sendable] [defines static #~@0<#make]",
                "    2 subclass &entry/src/main/ets/base/Base&->#~@1=#Odd | Odd [reassigned] [members unknown]",
                "    2 subclass &entry/src/main/ets/entryability/EntryAbility&->#~@0=#EntryAbility | EntryAbility (repeated)",
            ]
        );
        assert!(tree.lines(true)[1].ends_with(" [defines #~@0>#onCreate] [ets/modules.abc]"));
        assert!(!tree.lines(true)[0].contains("modules.abc"));
        assert_eq!(
            tree.definition_lines(),
            [
                "override &entry/src/main/ets/entryability/EntryAbility&->#~@0>#onCreate | EntryAbility.onCreate",
                "override &entry/src/main/ets/base/Base&->#~@0<#make | Base.make [static]",
            ]
        );
        assert_eq!(
            tree.footer(),
            "# 5 rows, 3 distinct classes, 1 leaves (subclasses, depth 16); 2 records scanned; 2 subclasses define onCreate; \
             truncated (raise max_nodes or lower depth)\n\
             # no class of the program has that name: the roots are the parent paths that contain it\n# x is encrypted"
        );

        let up = HierarchyTree {
            direction: Lineage::Supers,
            rows: vec![
                row(0, None, class(ability, "#~@0=#EntryAbility", "EntryAbility")),
                ClassRow { no_parent: true, ..row(1, Some(0), class(base, "#~@0=#Base", "Base")) },
                ClassRow { plain_function: true, ..row(1, Some(0), class(base, "#*#Old", "Old")) },
                row(1, Some(0), ClassNode::Leaf { path: "arg0".into(), external: false }),
            ],
            method: None,
            truncated: false,
            roots_by_text: false,
            notes: Vec::new(),
            ..tree
        };
        assert_eq!(
            up.lines(false)[1..],
            [
                "  1 extends &entry/src/main/ets/base/Base&->#~@0=#Base | Base [no superclass]",
                "  1 extends &entry/src/main/ets/base/Base&->#*#Old | Old [function]",
                "  1 extends arg0 [unresolved]",
            ]
        );
        assert_eq!(up.footer(), "# 4 rows, 3 distinct classes, 1 leaves (supers, depth 16); 2 records scanned");
        // One entry in a program of several is named once, in the footer.
        let (lines, footer) = up.text(true);
        assert!(lines.iter().all(|line| !line.contains("modules.abc")), "{lines:?}");
        assert_eq!(footer, "# 4 rows, 3 distinct classes, 1 leaves (supers, depth 16); 2 records scanned; all in ets/modules.abc");
        assert!(!up.text(false).1.contains("all in"));
        let mut mixed = up.clone();
        if let ClassNode::Class { entry, .. } = &mut mixed.rows[1].node {
            *entry = "ets/widgets.abc".into();
        }
        let (lines, footer) = mixed.text(true);
        assert!(lines[0].ends_with(" [ets/modules.abc]") && lines[1].ends_with(" [ets/widgets.abc]") && !footer.contains("all in"));
    }
}
