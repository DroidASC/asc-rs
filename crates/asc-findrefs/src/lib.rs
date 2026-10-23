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

mod classdefs;
mod insn_locator;
mod locators;
mod query;
mod scanner;

pub use insn_locator::{InsnLocator, MethodRef};
pub use locators::{FieldLocator, MethodLocator, StringLocator, TypeLocator};
pub use query::CompiledQuery;
pub use scanner::{CodeScanner, IdxSet, RefKind};

use asc_dex::Dex;
use query::Parts;
use std::collections::BTreeSet;
use std::sync::OnceLock;

/// Errors from reference search.
#[derive(Debug, thiserror::Error)]
pub enum FindError {
    #[error(transparent)]
    Dex(#[from] asc_dex::DexError),
    #[error("invalid pattern: {0}")]
    Pattern(#[from] regex::Error),
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
    Field(MemberQuery),
    /// Classes whose superclass is exactly this descriptor (`Lcom/poc/Base;`).
    /// Answered from `class_def_item`s, not by a code scan.
    Extends(String),
    /// Classes that directly implement exactly this interface descriptor.
    Implements(String),
}

impl Query {
    /// The index table the query targets; class relations report
    /// [`RefKind::Type`] (their results are classes).
    pub fn kind(&self) -> RefKind {
        match self {
            Query::String(_) | Query::StringLiteral(_) => RefKind::String,
            Query::Type(_) | Query::Extends(_) | Query::Implements(_) => RefKind::Type,
            Query::Method(_) => RefKind::Method,
            Query::Field(_) => RefKind::Field,
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
}

/// Lazily-built locator tables for one DEX buffer.
///
/// The tables hold offsets into the buffer they were built from (no
/// references or pointers), so a `SearchState` must only ever be used
/// together with that same buffer or lookups will silently return nonsense.
/// The engine caches one per inflated DEX so repeated queries skip the builds.
#[derive(Default)]
pub struct SearchState {
    strings: OnceLock<StringLocator>,
    types: OnceLock<TypeLocator>,
    methods: OnceLock<MethodLocator>,
    fields: OnceLock<FieldLocator>,
    insns: OnceLock<InsnLocator>,
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
        if let Some(l) = st.strings.get() {
            return Ok(l);
        }
        let l = StringLocator::build(self.dex)?;
        Ok(st.strings.get_or_init(|| l))
    }

    pub fn type_locator(&self) -> Result<&TypeLocator> {
        let st = self.state();
        if let Some(l) = st.types.get() {
            return Ok(l);
        }
        let l = TypeLocator::build(self.dex)?;
        Ok(st.types.get_or_init(|| l))
    }

    pub fn method_locator(&self) -> Result<&MethodLocator> {
        let st = self.state();
        if let Some(l) = st.methods.get() {
            return Ok(l);
        }
        let l = MethodLocator::build(self.dex)?;
        Ok(st.methods.get_or_init(|| l))
    }

    pub fn field_locator(&self) -> Result<&FieldLocator> {
        let st = self.state();
        if let Some(l) = st.fields.get() {
            return Ok(l);
        }
        let l = FieldLocator::build(self.dex)?;
        Ok(st.fields.get_or_init(|| l))
    }

    pub fn insn_locator(&self) -> Result<&InsnLocator> {
        let st = self.state();
        if let Some(l) = st.insns.get() {
            return Ok(l);
        }
        let l = InsnLocator::build(self.dex)?;
        Ok(st.insns.get_or_init(|| l))
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
            (RefKind::Method, Parts::Member(_)) => {
                self.method_locator()?.locate_compiled(self.dex, self.string_locator()?, self.type_locator()?, query)
            }
            (RefKind::Field, Parts::Member(_)) => {
                self.field_locator()?.locate_compiled(self.dex, self.string_locator()?, self.type_locator()?, query)
            }
            // `CompiledQuery::new` always pairs the kind with the matching parts.
            _ => Ok(BTreeSet::new()),
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
    /// no hits here; [`FindRefs::class_relation`] answers them.
    pub fn find_ref_compiled(&self, query: &CompiledQuery) -> Result<Vec<Hit>> {
        if query.relation().is_some() {
            return Ok(Vec::new());
        }
        let idxs = self.locate_compiled(query)?;
        if idxs.is_empty() {
            return Ok(Vec::new());
        }
        self.scan_idxs(query.kind(), &idxs)
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
        let matches = scanner.scan(buf, kind, &set);
        let offsets: Vec<u32> = matches.iter().map(|m| m.0).collect();
        let methods = insn.locate(buf, &offsets);
        Ok(matches.into_iter().zip(methods).map(|((offset, matched_idx), methods)| Hit { offset, matched_idx, methods }).collect())
    }
}
