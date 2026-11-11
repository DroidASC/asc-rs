//! Reading captured variables: per function, over scopes that are built
//! when a scan first needs them.

use std::cell::{OnceCell, RefCell};
use std::sync::Arc;

use asc_abc::{Abc, Class};

use super::{FnId, ScopeTables, Scopes, Unresolved, Written};
use crate::callgraph::{GraphCache, RecordId, Slot};
use crate::path::{Lexicals, Origin, Path, Stored};
use crate::refs::Regions;
use crate::track::Tracker;

/// The [`Scopes`] of the record a scan is in, built when first asked for:
/// most queries touch few records, and a record without closures needs none.
pub(crate) struct RecordScopes<'s, 'a> {
    abc: Abc<'a>,
    regions: &'s Regions<'a>,
    tables: &'s ScopeTables,
    class: Option<Class<'a>>,
    /// Scratch space of the pass; the scan has its own tracker running.
    tracker: RefCell<Tracker>,
    kept: Kept<'s>,
}

/// Where the scopes of the current record are kept.
enum Kept<'s> {
    /// Here, until the scan moves on to the next record.
    Scan(OnceCell<Box<Scopes>>),
    /// In the engine's cache, for every later query: built at most once per
    /// record whichever query needs them first.
    Engine {
        cache: &'s GraphCache,
        /// Index of the ABC entry in the program.
        entry: u32,
        /// The cache's slot of the current record, once asked for.
        slot: OnceCell<Arc<Slot>>,
    },
}

impl<'s, 'a> RecordScopes<'s, 'a> {
    /// Scopes that live as long as the scan is in their record.
    pub(crate) fn new(abc: Abc<'a>, regions: &'s Regions<'a>, tables: &'s ScopeTables) -> RecordScopes<'s, 'a> {
        RecordScopes { abc, regions, tables, class: None, tracker: RefCell::default(), kept: Kept::Scan(OnceCell::new()) }
    }

    /// Scopes read from, and left in, `cache`; `abc` is entry `entry` of
    /// the program the cache belongs to.
    pub(crate) fn shared(
        abc: Abc<'a>,
        regions: &'s Regions<'a>,
        tables: &'s ScopeTables,
        cache: &'s GraphCache,
        entry: u32,
    ) -> RecordScopes<'s, 'a> {
        let kept = Kept::Engine { cache, entry, slot: OnceCell::new() };
        RecordScopes { abc, regions, tables, class: None, tracker: RefCell::default(), kept }
    }

    /// Move on to `class`.
    pub(crate) fn enter(&mut self, class: &Class<'a>) {
        self.class = Some(*class);
        match &mut self.kept {
            Kept::Scan(built) => *built = OnceCell::new(),
            Kept::Engine { slot, .. } => *slot = OnceCell::new(),
        }
    }

    /// The scopes of the current record. Before any record was entered, and
    /// while the pass itself runs, there are none.
    pub(crate) fn get(&self) -> Option<&Scopes> {
        if let Some(built) = self.built() {
            return Some(built);
        }
        let class = self.class.as_ref()?;
        let mut tracker = self.tracker.try_borrow_mut().ok()?;
        let mut build = || Scopes::build(self.abc, self.regions, class, self.tables, &mut tracker);
        Some(match &self.kept {
            Kept::Scan(built) => built.get_or_init(|| Box::new(build())),
            Kept::Engine { cache, entry, slot } => {
                let slot = slot.get_or_init(|| cache.slot(RecordId { entry: *entry, class: class.offset() }));
                cache.scopes(slot, build)
            }
        })
    }

    /// The scopes of the current record, when they are at hand already.
    fn built(&self) -> Option<&Scopes> {
        match &self.kept {
            Kept::Scan(built) => built.get().map(|built| &**built),
            Kept::Engine { slot, .. } => slot.get()?.built_scopes(),
        }
    }

    /// Whether the scopes of the current record were built.
    pub(crate) fn is_built(&self) -> bool {
        self.built().is_some()
    }

    /// The captured variables as the function at method offset `method` reads them.
    pub(crate) fn of_function(&self, method: u32) -> FunctionLexicals<'_, 's, 'a> {
        FunctionLexicals { record: self, method }
    }

    /// [`Scopes::reduce`], which only builds the scopes for a path that
    /// starts at a definition and goes on.
    pub(crate) fn reduce(&self, path: &mut Path) {
        if matches!(path.origin, Origin::Definition(Some(_)))
            && !path.links.is_empty()
            && let Some(scopes) = self.get()
        {
            scopes.reduce(&self.abc, path);
        }
    }
}

/// [`Lexicals`] of one function over lazily built scopes.
pub(crate) struct FunctionLexicals<'r, 's, 'a> {
    record: &'r RecordScopes<'s, 'a>,
    method: u32,
}

impl FunctionLexicals<'_, '_, '_> {
    /// As [`Lexicals::stored`], with the reason when there is no value.
    pub(crate) fn lexical(&self, pc: u32, level: u32, slot: u32) -> Result<Stored<'_>, Unresolved> {
        let scopes = self.record.get().ok_or(Unresolved::NoIdentity)?;
        Reader::new(scopes, self.method).ok_or(Unresolved::NoIdentity)?.lexical(pc, level, slot)
    }

    /// The variable's value with the store that writes it.
    pub(crate) fn written(&self, pc: u32, level: u32, slot: u32) -> Result<&Written, Unresolved> {
        let scopes = self.record.get().ok_or(Unresolved::NoIdentity)?;
        Reader::new(scopes, self.method).ok_or(Unresolved::NoIdentity)?.written(pc, level, slot).map(|(written, _)| written)
    }
}

impl Lexicals for FunctionLexicals<'_, '_, '_> {
    fn stored(&self, pc: u32, level: u32, slot: u32) -> Option<Stored<'_>> {
        self.lexical(pc, level, slot).ok()
    }
}

/// The captured variables as one function reads them.
pub(crate) struct Reader<'s> {
    scopes: &'s Scopes,
    function: FnId,
    /// Name the environment instead of the value: for the values stores write.
    identity_only: bool,
}

impl<'s> Reader<'s> {
    /// For the function at method offset `method`; `None` when the record
    /// has no such function.
    pub(crate) fn new(scopes: &'s Scopes, method: u32) -> Option<Reader<'s>> {
        Some(Reader { scopes, function: scopes.function_id(method)?, identity_only: false })
    }

    /// For the values function `function` stores: a captured variable it
    /// reads is named by its environment, not replaced by its value, which
    /// is not settled while the stores are still being collected.
    pub(super) fn of_writer(scopes: &'s Scopes, function: FnId) -> Reader<'s> {
        Reader { scopes, function, identity_only: true }
    }

    /// As [`Lexicals::stored`], with the reason when there is no value.
    pub(crate) fn lexical(&self, pc: u32, level: u32, slot: u32) -> Result<Stored<'s>, Unresolved> {
        self.written(pc, level, slot).map(|(written, own_frame)| Stored { path: &written.path, own_frame })
    }

    /// The variable's value with the store that writes it, and whether the
    /// environment was made by the reading invocation itself.
    pub(crate) fn written(&self, pc: u32, level: u32, slot: u32) -> Result<(&'s Written, bool), Unresolved> {
        let (env, own_frame) = self.scopes.locate(self.function, pc, level)?;
        match self.scopes.slots.get(&(env, slot)) {
            Some(Ok(written)) => Ok((written, own_frame)),
            Some(Err(why)) => Err(*why),
            None if self.scopes.is_tainted((env, slot)) => Err(Unresolved::Tainted),
            None => Err(Unresolved::NoWriter),
        }
    }
}

impl Lexicals for Reader<'_> {
    fn stored(&self, pc: u32, level: u32, slot: u32) -> Option<Stored<'_>> {
        if self.identity_only {
            return None;
        }
        self.lexical(pc, level, slot).ok()
    }

    fn slot(&self, pc: u32, level: u32, slot: u32) -> Option<Origin> {
        if !self.identity_only {
            return None;
        }
        let (env, _) = self.scopes.locate(self.function, pc, level).ok()?;
        Some(Origin::Slot { env, slot })
    }
}
