//! Reference search over a single DEX without any global preprocessing.
//!
//! The pipeline mirrors the Python `findrefs` package:
//!
//! 1. A *locator* turns the user's query into a set of constant-pool indexes
//!    (string, type, method or field ids). String matching runs a regex over
//!    the raw string-data region; member lookups use small per-DEX maps.
//! 2. The *code scanner* sweeps the raw code-item region once for opcodes that
//!    carry an index of that kind and keeps the positions whose operand is in
//!    the located set.
//! 3. The *instruction locator* maps each surviving byte offset back to the
//!    method that owns it through a dense 16-byte bucket table, and confirms
//!    the offset really sits on an instruction boundary.
//!
//! String queries are a regex, or a plain substring found with SIMD `memmem`
//! ([`Query::StringLiteral`]). `Extends` / `Implements` queries skip the
//! pipeline: they compare `class_def_item`s with the target's type index
//! ([`FindRefs::class_relation`]).
//!
//! Queries can be pre-compiled once per search ([`CompiledQuery`]) and run
//! against many DEX files with [`FindRefs::find_ref_compiled`].

#![forbid(unsafe_code)]

mod callgraph;
mod calls;
mod classdefs;
mod insn_locator;
mod locators;
mod persist;
mod query;
mod scanner;
mod table;

pub use callgraph::CallGraph;
pub use calls::{CallConstraint, Certainty, ResultWant, Slot, Want};
pub use insn_locator::{InsnLocator, MethodRef};
pub use locators::{FieldLocator, MethodLocator, StringLocator, TypeLocator};
pub use persist::FORMAT_VERSION as PERSIST_FORMAT_VERSION;
pub use query::{CompiledQuery, Compound};
pub use scanner::{CodeScanner, IdxSet, RefKind};
pub use table::Backing;

use asc_dex::Dex;
use query::Parts;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Mutex, OnceLock, PoisonError};

/// Errors from reference search.
#[derive(Debug, thiserror::Error)]
pub enum FindError {
    #[error(transparent)]
    Dex(#[from] asc_dex::DexError),
    #[error("invalid pattern: {0}")]
    Pattern(#[from] regex::Error),
    #[error("invalid query: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, FindError>;

/// Class part of a member query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassQuery {
    /// Exact Dalvik descriptor when `precise`, otherwise a fuzzy pattern.
    pub pattern: String,
    pub precise: bool,
}

/// Method or field query: at least one of `class` / `name` must be set.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MemberQuery {
    pub class: Option<ClassQuery>,
    /// Fuzzy member name (regex when `class` is absent or fuzzy, substring
    /// when the class is precise), or the exact name when `exact_name` is set.
    pub name: Option<String>,
    /// Match `name` exactly (whatever the class constraint) instead of as a
    /// regex / substring; used for "references to this member" lookups.
    pub exact_name: bool,
    /// Only the members of this signature: one overload of a method, or a
    /// field of one type. Checked against the id tables, before any code is
    /// scanned.
    pub signature: Option<MemberSignature>,
}

/// The signature constraint of a [`MemberQuery`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberSignature {
    /// A method's parameters, and its return type when one is given.
    Method { params: Vec<TypeMatch>, ret: Option<TypeMatch> },
    /// A field's type.
    Field(TypeMatch),
}

/// One type of a [`MemberSignature`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeMatch {
    /// Exactly this descriptor: `I`, `Ljava/lang/String;`, `[B`.
    Descriptor(String),
    /// A class of this simple name in any package, `dims` levels of array
    /// deep (`String[]` written without its package).
    Simple { name: String, dims: usize },
}

impl TypeMatch {
    /// Whether the descriptor `descriptor` is of this type.
    pub fn matches(&self, descriptor: &str) -> bool {
        query::CompiledType::new(self).matches(&asc_dex::mutf8::encode(descriptor))
    }
}

impl std::fmt::Display for TypeMatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TypeMatch::Descriptor(d) => f.write_str(d),
            TypeMatch::Simple { name, dims } => write!(f, "{name}{}", "[]".repeat(*dims)),
        }
    }
}

impl std::fmt::Display for MemberSignature {
    /// `(I, String)V`, `(I)` or `:I`, the way the query reads.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemberSignature::Method { params, ret } => {
                f.write_str("(")?;
                for (i, p) in params.iter().enumerate() {
                    // Descriptors run together, as Dalvik writes them; a simple
                    // name needs a separator to stay readable.
                    let simple = |t: &TypeMatch| matches!(t, TypeMatch::Simple { .. });
                    if i > 0 && (simple(p) || simple(&params[i - 1])) {
                        f.write_str(", ")?;
                    }
                    write!(f, "{p}")?;
                }
                f.write_str(")")?;
                ret.as_ref().map_or(Ok(()), |r| write!(f, "{r}"))
            }
            MemberSignature::Field(t) => write!(f, ":{t}"),
        }
    }
}

/// A reference search request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Query {
    /// Strings matching a regex.
    String(String),
    /// Strings containing a plain substring (no regex syntax).
    StringLiteral(String),
    Type(String),
    Method(MemberQuery),
    /// References to any of these methods: a set read from a file, or the
    /// methods a [`Query::Nested`] condition resolved to.
    MethodSet(Vec<MemberQuery>),
    /// References to the methods whose own code matches the inner query
    /// (`method:{RULE}`). The inner query has to see every DEX, so whoever
    /// holds them all (the engine) resolves this into a [`Query::MethodSet`]
    /// first; compiling it as it is fails.
    Nested(Box<Query>),
    /// The calls that may dispatch to a method of `target` (a `MethodSet` or
    /// `Nested`): those naming it, and those naming the same method on a
    /// supertype of its class or on a subclass inheriting it
    /// (`method:{RULE}` and `method:@FILE` by default). The engine resolves
    /// it over the class hierarchy into `target` plus those methods, `via`
    /// mapping each added one (`Lcls;->name(params)ret`, or `Lcls;->name`
    /// for every overload) to the classes of `target` it stands for; a hit on
    /// one carries the note `(dispatch LIST)`.
    Virtual {
        target: Box<Query>,
        via: BTreeMap<String, String>,
        /// Most classes of the program that may define a supertype's method
        /// for the calls naming it to be followed (`None`: no limit). A
        /// method every lambda or callback implements says nothing about
        /// which one runs.
        fan_out: Option<usize>,
    },
    Field(MemberQuery),
    /// The calls of a method query (`Method`, `MethodSet` or `Nested`) that
    /// every constraint keeps (`method:X[arg1="id", ret=unused]`); see
    /// [`CallConstraint`]. Its hits carry a note of the values judged.
    Call {
        target: Box<Query>,
        constraints: Vec<CallConstraint>,
    },
    /// Classes whose superclass is exactly this descriptor (`Lcom/poc/Base;`).
    /// Answered from `class_def_item`s, not by a code scan.
    Extends(String),
    /// Classes that directly implement exactly this interface descriptor.
    Implements(String),
    /// Methods matched by how they are declared, not by what their code
    /// references (`flag:`, `annotation:`, `override:`, `in:{...}`). Answered
    /// from the class definitions; the rows have no call site.
    Defined(Defined),
    /// Methods whose code matches every query of `all` and none of `none`
    /// (string / type / method / field queries; at least one in `all`).
    /// A row lists the constants each `all` query matched, in that order.
    All {
        all: Vec<Query>,
        none: Vec<Query>,
    },
}

impl Query {
    /// The index table the query targets; class relations report
    /// [`RefKind::Type`] (their results are classes).
    pub fn kind(&self) -> RefKind {
        match self {
            Query::String(_) | Query::StringLiteral(_) => RefKind::String,
            Query::Type(_) | Query::Extends(_) | Query::Implements(_) => RefKind::Type,
            Query::Method(_) | Query::MethodSet(_) | Query::Nested(_) | Query::Virtual { .. } | Query::Call { .. } | Query::Defined(_) => {
                RefKind::Method
            }
            Query::Field(_) => RefKind::Field,
            // Rows of a compound query list constants of several kinds.
            Query::All { all, .. } => all.first().map_or(RefKind::String, Query::kind),
        }
    }

    /// The class relation of an `Extends` / `Implements` query.
    pub fn relation(&self) -> Option<ClassRelation> {
        match self {
            Query::Extends(_) => Some(ClassRelation::Extends),
            Query::Implements(_) => Some(ClassRelation::Implements),
            _ => None,
        }
    }
}

/// A method-definition predicate ([`Query::Defined`]).
///
/// `Flags` and `Annotation` are matched against each method's own
/// declaration. `Override` and `In` need the class hierarchy (which spans
/// every DEX), so the engine resolves them into `Members` — a set of
/// declaring classes, optionally with a name and proto — before a search;
/// compiling them unresolved fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Defined {
    /// Carries all of these access flags (`flag:public,static`).
    Flags(u32),
    /// Annotated with this annotation type descriptor (`annotation:Lx/Y;`).
    Annotation(String),
    /// Declared in one of `classes` (exact descriptors), and, when set, with
    /// this `name` and `proto` (`(params)ret`). `override:` and `in:{...}`
    /// resolve to this.
    Members { classes: Vec<String>, name: Option<String>, proto: Option<String> },
    /// `override:TARGET`: methods overriding or implementing it. The engine
    /// resolves it into `Members` over the class hierarchy.
    Override(MemberQuery),
    /// `in:{CLASS-RULE}`: methods declared in a matching class. The engine
    /// resolves it into `Members`.
    In(Box<Query>),
}

impl Defined {
    /// A short label for the matched column of a definitional row.
    pub fn label(&self) -> String {
        match self {
            Defined::Flags(_) => "flag".into(),
            Defined::Annotation(a) => format!("@{a}"),
            Defined::Members { name: Some(n), .. } => format!("override {n}"),
            Defined::Members { .. } => "in".into(),
            Defined::Override(m) => format!("override {}", m.name.as_deref().unwrap_or("")),
            Defined::In(_) => "in".into(),
        }
    }
}

/// How a class relates to the target of an `Extends` / `Implements` query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClassRelation {
    /// The class's `superclass_idx` is the target.
    Extends,
    /// The target is in the class's `interfaces` list.
    Implements,
}

impl ClassRelation {
    /// The verb of the Python output line (`Lsub; extends Lbase;`).
    pub fn verb(self) -> &'static str {
        match self {
            ClassRelation::Extends => "extends",
            ClassRelation::Implements => "implements",
        }
    }
}

/// One instruction that references a located index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// Absolute byte offset of the instruction in the DEX.
    pub offset: u32,
    /// The constant-pool index the instruction references.
    pub matched_idx: u32,
    /// Owning method(s); `None` when the offset failed instruction verification.
    pub methods: Option<MethodRef>,
    /// What the constraints of a [`Query::Call`] judged at this call site
    /// (`[arg1="id", ret=unused]`, `?` first when one is undetermined),
    /// and for a [`Query::Virtual`] alias, the methods it may dispatch to
    /// (`(dispatch Lcls;)`).
    pub note: Option<String>,
}

/// Lazily-built locator tables for one DEX buffer.
///
/// The tables hold offsets into the buffer they were built from (no
/// references or pointers), so a `SearchState` must only ever be used
/// together with that same buffer or lookups will silently return nonsense.
/// The engine caches one per inflated DEX so repeated queries skip the builds.
///
/// Each table is built once: a second caller asking for a table under
/// construction waits for it rather than building its own copy (a query
/// arriving while a background prebuild is half way through a table gets
/// that table sooner than by starting over).
#[derive(Default)]
pub struct SearchState {
    strings: OnceLock<StringLocator>,
    types: OnceLock<TypeLocator>,
    methods: OnceLock<MethodLocator>,
    fields: OnceLock<FieldLocator>,
    insns: OnceLock<InsnLocator>,
    calls: OnceLock<CallGraph>,
    /// One lock per table, held while that table is built.
    building: [Mutex<()>; 6],
}

/// `cell`'s value, built by `build` under `lock` the first time.
fn built<'c, T>(cell: &'c OnceLock<T>, lock: &Mutex<()>, build: impl FnOnce() -> Result<T>) -> Result<&'c T> {
    if let Some(v) = cell.get() {
        return Ok(v);
    }
    let _building = lock.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(v) = cell.get() {
        return Ok(v);
    }
    let v = build()?;
    Ok(cell.get_or_init(|| v))
}

impl SearchState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the instruction table has been built (a proxy for "warm").
    pub fn is_warm(&self) -> bool {
        self.insns.get().is_some()
    }

    /// Heap bytes of the tables built so far (0 for a fresh state). Grows as
    /// queries of new kinds build their locators.
    pub fn heap_bytes(&self) -> usize {
        self.strings.get().map_or(0, StringLocator::heap_bytes)
            + self.types.get().map_or(0, TypeLocator::heap_bytes)
            + self.methods.get().map_or(0, MethodLocator::heap_bytes)
            + self.fields.get().map_or(0, FieldLocator::heap_bytes)
            + self.insns.get().map_or(0, InsnLocator::heap_bytes)
            + self.calls.get().map_or(0, CallGraph::heap_bytes)
    }

    /// The call graph, if a query has built it.
    pub fn call_graph(&self) -> Option<&CallGraph> {
        self.calls.get()
    }

    /// Install a call graph loaded from elsewhere (e.g. an on-disk cache of
    /// [`CallGraph::to_bytes`]); `false` if one is already built. It must
    /// describe the same buffer this state is used with.
    pub fn set_call_graph(&self, graph: CallGraph) -> bool {
        self.calls.set(graph).is_ok()
    }
}

enum StateRef<'s> {
    Owned(Box<SearchState>),
    Shared(&'s SearchState),
}

/// Reference search over one DEX.
pub struct FindRefs<'d, 'a, 's> {
    dex: &'d Dex<'a>,
    state: StateRef<'s>,
}

impl<'d, 'a, 's> FindRefs<'d, 'a, 's> {
    /// Search with private, throw-away locator tables.
    pub fn new(dex: &'d Dex<'a>) -> Self {
        FindRefs { dex, state: StateRef::Owned(Box::default()) }
    }

    /// Search reusing tables built earlier for the *same* buffer.
    pub fn with_state(dex: &'d Dex<'a>, state: &'s SearchState) -> Self {
        FindRefs { dex, state: StateRef::Shared(state) }
    }

    fn state(&self) -> &SearchState {
        match &self.state {
            StateRef::Owned(s) => s,
            StateRef::Shared(s) => s,
        }
    }

    pub fn dex(&self) -> &'d Dex<'a> {
        self.dex
    }

    pub fn string_locator(&self) -> Result<&StringLocator> {
        let st = self.state();
        built(&st.strings, &st.building[0], || StringLocator::build(self.dex))
    }

    pub fn type_locator(&self) -> Result<&TypeLocator> {
        let st = self.state();
        built(&st.types, &st.building[1], || TypeLocator::build(self.dex))
    }

    pub fn method_locator(&self) -> Result<&MethodLocator> {
        let st = self.state();
        built(&st.methods, &st.building[2], || MethodLocator::build(self.dex))
    }

    pub fn field_locator(&self) -> Result<&FieldLocator> {
        let st = self.state();
        built(&st.fields, &st.building[3], || FieldLocator::build(self.dex))
    }

    pub fn insn_locator(&self) -> Result<&InsnLocator> {
        let st = self.state();
        built(&st.insns, &st.building[4], || Ok(InsnLocator::build(self.dex)?))
    }

    /// The DEX's call graph, built on first use (the instruction table too).
    pub fn call_graph(&self) -> Result<&CallGraph> {
        let st = self.state();
        built(&st.calls, &st.building[5], || Ok(CallGraph::build(self.dex.buf(), self.insn_locator()?)))
    }

    /// Resolve the query to constant-pool indexes (compiling its patterns).
    pub fn locate(&self, query: &Query) -> Result<BTreeSet<u32>> {
        self.locate_compiled(&CompiledQuery::new(query)?)
    }

    /// Resolve a pre-compiled query to constant-pool indexes.
    pub fn locate_compiled(&self, query: &CompiledQuery) -> Result<BTreeSet<u32>> {
        let buf = self.dex.buf();
        match (query.kind(), query.parts()) {
            (_, Parts::Pattern(None)) | (_, Parts::Literal(None)) => Ok(BTreeSet::new()),
            (RefKind::String, Parts::Pattern(Some(re))) => Ok(self.string_locator()?.locate(buf, re)),
            (RefKind::String, Parts::Literal(Some(f))) => Ok(self.string_locator()?.locate_literal(buf, f)),
            (_, Parts::Relation(..)) => Ok(self.class_relation(query)?.unwrap_or_default().into_iter().collect()),
            (RefKind::Type, Parts::Pattern(Some(re))) => Ok(self.type_locator()?.locate(buf, self.string_locator()?, re)),
            (_, Parts::Call(c)) => self.locate_compiled(&c.target),
            (_, Parts::Virtual(target, _)) => self.locate_compiled(target),
            (RefKind::Method, Parts::Member(_) | Parts::MemberSet(_)) => {
                self.method_locator()?.locate_compiled(self.dex, self.string_locator()?, self.type_locator()?, query)
            }
            (RefKind::Field, Parts::Member(_)) => {
                self.field_locator()?.locate_compiled(self.dex, self.string_locator()?, self.type_locator()?, query)
            }
            // `CompiledQuery::new` always pairs the kind with the matching parts.
            _ => Ok(BTreeSet::new()),
        }
    }

    /// Whether `query` certainly has no hit in this DEX, judged from the id
    /// tables and the string data alone: no code is read, so this also works
    /// on a DEX prefix that holds those (an error then means the prefix was
    /// not enough, and the caller has to search the whole DEX).
    ///
    /// `true` exactly when [`FindRefs::find_ref_compiled`] (or, for a class
    /// relation, [`FindRefs::class_relation`]; for a compound query, its rows)
    /// could only come out empty.
    pub fn cannot_match(&self, query: &CompiledQuery) -> Result<bool> {
        if let Some(c) = query.compound() {
            // Rows need a hit of every `all` part in one method.
            for part in &c.all {
                if self.cannot_match(part)? {
                    return Ok(true);
                }
            }
            return Ok(false);
        }
        match query.parts() {
            Parts::Call(c) => self.cannot_match(&c.target),
            Parts::Virtual(target, _) => self.cannot_match(target),
            // A class nobody references cannot be extended or implemented.
            Parts::Relation(_, descriptor) => Ok(self.dex.find_type_idx(descriptor)?.is_none()),
            // A definition predicate reads no code, so locating it yields
            // nothing: rule it out only from the type table (flags could be
            // on any method, so they never skip).
            Parts::Defined(Defined::Flags(_)) => Ok(false),
            Parts::Defined(Defined::Annotation(a)) => Ok(self.dex.find_type_idx(&asc_dex::mutf8::encode(a))?.is_none()),
            Parts::Defined(Defined::Members { classes, .. }) => {
                for c in classes {
                    if self.dex.find_type_idx(&asc_dex::mutf8::encode(c))?.is_some() {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            // Unresolved predicates never reach a search.
            Parts::Defined(Defined::Override(_) | Defined::In(_)) => Ok(false),
            // Nor can its members be: one binary search, before the member
            // tables are built (most DEX files do not reference the class).
            Parts::Member(query::CompiledMember { class: Some(query::CompiledClass::Precise(descriptor)), .. })
                if self.dex.find_type_idx(descriptor)?.is_none() =>
            {
                Ok(true)
            }
            _ => Ok(self.locate_compiled(query)?.is_empty()),
        }
    }

    /// Full search: locate indexes, scan code, resolve owning methods.
    pub fn find_ref(&self, query: &Query) -> Result<Vec<Hit>> {
        self.find_ref_compiled(&CompiledQuery::new(query)?)
    }

    /// Full search with a query compiled once (typically shared by every DEX
    /// of an APK).
    ///
    /// Class relations (`Extends` / `Implements`) reference no code and give
    /// no hits here; [`FindRefs::class_relation`] answers them. Compound
    /// queries give none either: run their parts with [`FindRefs::find_many`].
    pub fn find_ref_compiled(&self, query: &CompiledQuery) -> Result<Vec<Hit>> {
        if query.relation().is_some() || query.compound().is_some() || query.defined().is_some() {
            return Ok(Vec::new());
        }
        let idxs = self.locate_compiled(query)?;
        if idxs.is_empty() {
            return Ok(Vec::new());
        }
        let hits = self.scan_idxs(query.kind(), &idxs)?;
        self.refine(query, hits)
    }

    /// The hits of `query`'s located indexes that it keeps, with their notes:
    /// a [`Query::Virtual`] labels the calls it reached by dispatch, a
    /// [`Query::Call`] judges the values of its target's calls.
    fn refine(&self, query: &CompiledQuery, hits: Vec<Hit>) -> Result<Vec<Hit>> {
        match query.parts() {
            Parts::Call(c) => {
                let hits = self.refine(&c.target, hits)?;
                self.constrain(c, hits)
            }
            Parts::Virtual(_, via) => self.label_dispatch(via, hits),
            _ => Ok(hits),
        }
    }

    /// `hits` with a `(dispatch LIST)` note on each call [`Query::Virtual`]
    /// added for dispatch.
    fn label_dispatch(&self, via: &BTreeMap<String, String>, mut hits: Vec<Hit>) -> Result<Vec<Hit>> {
        if via.is_empty() {
            return Ok(hits);
        }
        let mut labels: HashMap<u32, Option<&str>> = HashMap::new();
        for hit in &mut hits {
            let label = match labels.get(&hit.matched_idx) {
                Some(&l) => l,
                None => {
                    let m = self.dex.method_id(hit.matched_idx)?;
                    let name = self.dex.method_display(hit.matched_idx)?;
                    let proto = self.dex.proto_id(u32::from(m.proto_idx))?;
                    let mut sig = format!("{name}(");
                    for p in self.dex.type_list(proto.parameters_off)? {
                        sig.push_str(&self.dex.type_descriptor(u32::from(p))?);
                    }
                    sig.push(')');
                    sig.push_str(&self.dex.type_descriptor(proto.return_type_idx)?);
                    let l = via.get(&sig).or_else(|| via.get(&name)).map(String::as_str);
                    labels.insert(hit.matched_idx, l);
                    l
                }
            };
            if let Some(label) = label {
                hit.note = Some(format!("(dispatch {label})"));
            }
        }
        Ok(hits)
    }

    /// Hits of several queries with one code scan per index kind: the
    /// located sets of the queries of a kind are merged, scanned once, and
    /// each hit is handed to every query whose set holds its index. Gives,
    /// per query, what [`FindRefs::find_ref_compiled`] would (class relations
    /// and compound queries: nothing).
    pub fn find_many(&self, queries: &[&CompiledQuery]) -> Result<Vec<Vec<Hit>>> {
        let mut out: Vec<Vec<Hit>> = (0..queries.len()).map(|_| Vec::new()).collect();
        let mut located: Vec<Option<BTreeSet<u32>>> = Vec::with_capacity(queries.len());
        for q in queries {
            let skip = q.relation().is_some() || q.compound().is_some();
            located.push(if skip { None } else { Some(self.locate_compiled(q)?).filter(|s| !s.is_empty()) });
        }
        for kind in [RefKind::String, RefKind::Type, RefKind::Method, RefKind::Field] {
            let mine: Vec<usize> = (0..queries.len()).filter(|&i| queries[i].kind() == kind && located[i].is_some()).collect();
            let union: BTreeSet<u32> = match mine.as_slice() {
                [] => continue,
                [only] => located[*only].clone().unwrap_or_default(),
                _ => mine.iter().flat_map(|&i| located[i].iter().flatten().copied()).collect(),
            };
            for hit in self.scan_idxs(kind, &union)? {
                for &i in &mine {
                    if located[i].as_ref().is_some_and(|s| s.contains(&hit.matched_idx)) {
                        out[i].push(hit.clone());
                    }
                }
            }
        }
        for (q, hits) in queries.iter().zip(out.iter_mut()) {
            *hits = self.refine(q, std::mem::take(hits))?;
        }
        Ok(out)
    }

    /// Answer an `Extends` / `Implements` query: the `class_idx` of every
    /// class definition that extends / implements the target, in
    /// `class_defs` order. `None` for any other query.
    pub fn class_relation(&self, query: &CompiledQuery) -> Result<Option<Vec<u32>>> {
        match query.parts() {
            Parts::Relation(rel, descriptor) => Ok(Some(classdefs::related_classes(self.dex, *rel, descriptor)?)),
            _ => Ok(None),
        }
    }

    /// Scan for already-located indexes of `kind`.
    pub fn scan_idxs(&self, kind: RefKind, idxs: &BTreeSet<u32>) -> Result<Vec<Hit>> {
        let buf = self.dex.buf();
        let insn = self.insn_locator()?;
        let scanner = CodeScanner::new(insn);
        // Every id table has at least 4-byte entries, so an index at or above
        // `buf.len() / 4` cannot name anything in this DEX; dropping such
        // targets also bounds the dense bitset for callers passing arbitrary
        // indexes (`u32::MAX` would otherwise allocate 512 MiB).
        let max_idx = (buf.len() / 4) as u32;
        let set = IdxSet::from_iter(idxs.iter().copied().filter(|&i| i < max_idx));
        // CodeScanner's public raw API retains unverified byte-pattern
        // candidates. FindRefs asks its internal instruction-aware variant to
        // omit odd offsets before allocating candidate storage; no DEX opcode
        // can start there.
        let matches = scanner.scan_instruction_candidates(buf, kind, &set);
        let offsets: Vec<u32> = matches.iter().map(|m| m.0).collect();
        let methods = insn.locate(buf, &offsets);
        Ok(matches
            .into_iter()
            .zip(methods)
            .map(|((offset, matched_idx), methods)| Hit { offset, matched_idx, methods, note: None })
            .collect())
    }
}
