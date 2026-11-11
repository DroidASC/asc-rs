//! Reference search (`findrefs`).
//!
//! Locate first, then scan, like the DEX engine. An ABC file has no string
//! table: instructions name strings, methods and literal arrays by a 16-bit
//! id into the index table of the method's region, and that table mixes the
//! three without saying which is which. So a search by name:
//!
//! 1. reads every entry of every region's table and tests it; the ids that
//!    match form one bitset per region ([`IdSet`]). For strings, an entry
//!    that is really a method or a literal array yields a few garbage bytes
//!    and, if those happen to match, an id no string operand ever uses;
//! 2. walks every method's code comparing id operands against the bitset of
//!    its region: nothing is decoded per instruction.
//!
//! Queries without a name to locate (numbers, imports, calls) skip step 1.
//!
//! Each kind of query is a [`Condition`], prepared once per ABC entry (the
//! first step), that hands out one [`Worker`] per thread (the second). A
//! worker sees every record, then every function of it, and reports
//! [`Hit`]s. A lone query
//! turns each hit into a row; [`Query::All`] keeps the functions every
//! condition hits and none of its [`Query::Not`] parts does, and prints one
//! row per function. A rule also stands for the functions it matches
//! ([`matching`]): the endpoints of a call graph walk and the set of a
//! `call:{RULE}` condition ([`callto`]), which is worked out before the
//! search that uses it ([`Sets`]).
//!
//! Both steps run on `threads` scoped threads over fixed-size chunks; rows
//! come back in file order whatever the thread count.

mod call;
mod callto;
mod context;
mod import;
pub(crate) mod method;
mod names;
mod number;
mod query;
mod rule;

use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use asc_abc::{Abc, Class, ClassEntry, Code, Fields, Method, OffsetTable};
use asc_arkisa::{DecodeError, Instruction};

pub(crate) use call::CallPaths;
pub(crate) use context::fill as fill_context;
pub use context::RefContext;
pub(crate) use import::module_requests;
pub use import::RequestListing;
pub use query::{FunctionSet, ListedFunction, NumberQuery, Pattern, Query};

use crate::callgraph::{FnRef, GraphCache, Session};
use crate::{disasm, EngineError, Result};

/// Region table entries tested per unit of work in step 1.
const ID_CHUNK: usize = 8192;
/// Records scanned per unit of work in step 2.
pub(crate) const RECORD_CHUNK: usize = 16;
/// Literal arrays nest (an array of arrays of strings); deeper than this is
/// a cycle or hostile.
pub(crate) const MAX_LITERAL_DEPTH: usize = 8;
/// Hits of one condition a conjunction row spells out before it counts the rest.
const SHOWN_PER_CONDITION: usize = 2;

/// Where a reference is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefSite {
    /// An instruction of a function.
    Code {
        /// The raw (mangled) function name, the one a query can look up.
        function: String,
        /// The readable name, e.g. `Index.build`.
        restored: String,
        /// Byte offset of the instruction in the function's code.
        pc: u32,
    },
    /// A field of the record itself (`scopeNames`, `jsonFileContent`, the
    /// default value of an element of an annotation interface).
    Field { name: String },
    /// An annotation a function carries: no instruction of its code.
    Annotation {
        /// The raw (mangled) function name.
        function: String,
        /// The readable name.
        restored: String,
    },
}

/// One reference: an instruction or record field naming a matched string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefRow {
    /// Canonical name of the record.
    pub record: String,
    pub site: RefSite,
    /// The matched strings, decoded.
    pub matched: Vec<String>,
    /// The instruction as disassembly, or for strings inside a literal
    /// array, the mnemonic and the matched items.
    pub text: String,
    /// Code offsets of the matched instructions, in order: the one of the
    /// row, or for a row of [`Query::All`] every one its conditions hit.
    pub sites: Vec<u32>,
    /// The code around the sites, when asked for ([`RefContext`]).
    pub context: Option<String>,
    /// File offset of the function, for the context.
    pub(crate) method: Option<u32>,
}

impl RefRow {
    /// The row followed by its context lines (just the row without one).
    pub fn text(&self, entry: &str) -> String {
        let mut out = self.line(entry);
        if let Some(context) = &self.context {
            out.push('\n');
            out.push_str(context.trim_end_matches('\n'));
        }
        out
    }

    /// `entry | record->function+0xPC | restored name | text`: the location
    /// column uses canonical names, which a query can be given back (`->`
    /// as in the DEX rows; a `.` would run into versioned record names such
    /// as `&@ohos/crypto-js/index&2.0.0`). A field reference is
    /// `entry | record field NAME | - | text`, one in an annotation of a
    /// function `entry | record->function | restored name | text`: the
    /// function without an offset.
    pub fn line(&self, entry: &str) -> String {
        match &self.site {
            RefSite::Code { function, restored, pc } => {
                format!("{entry} | {}->{function}+{pc:#x} | {restored} | {}", self.record, self.text)
            }
            RefSite::Field { name } => format!("{entry} | {} field {name} | - | {}", self.record, self.text),
            RefSite::Annotation { function, restored } => format!("{entry} | {}->{function} | {restored} | {}", self.record, self.text),
        }
    }
}

/// The rows of one ABC entry, delivered when its search completes.
#[derive(Debug, Clone)]
pub struct RefBatch {
    pub entry_name: String,
    /// In file order: records as the class index lists them, then functions,
    /// then instructions.
    pub rows: Vec<RefRow>,
    pub search_us: u128,
    /// Records or functions that could not be read: the first reason and
    /// how many there were. The rows of everything else are still there.
    pub error: Option<String>,
}

/// Summary of a whole [`crate::Engine::find_refs`] run.
#[derive(Debug, Clone, Default)]
pub struct RefSummary {
    /// Entries searched.
    pub entries: usize,
    pub total_results: usize,
    pub total_us: u128,
    /// What the search left out, one line each (encrypted entries).
    pub notes: Vec<String>,
}

/// Run `work` on every unit `0..units` with up to `workers` scoped threads;
/// the results come back in unit order. A unit that starts after `cancel`
/// is raised is not run, and the call reports the cancellation.
pub(crate) fn run_units<T: Send>(units: usize, workers: usize, cancel: &AtomicBool, work: impl Fn(usize) -> T + Sync) -> Result<Vec<T>> {
    let next = AtomicUsize::new(0);
    let drain = || {
        let mut done = Vec::new();
        while !cancel.load(Ordering::Relaxed) {
            let unit = next.fetch_add(1, Ordering::Relaxed);
            if unit >= units {
                break;
            }
            done.push((unit, work(unit)));
        }
        done
    };
    let workers = workers.min(units).max(1);
    let mut done = if workers == 1 {
        drain()
    } else {
        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..workers).map(|_| scope.spawn(drain)).collect();
            // A panicking worker is a bug in `work`; let it surface as one.
            handles.into_iter().flat_map(|handle| handle.join().unwrap_or_else(|panic| std::panic::resume_unwind(panic))).collect()
        })
    };
    if done.len() != units {
        return Err(EngineError::Cancelled);
    }
    done.sort_unstable_by_key(|&(unit, _)| unit);
    Ok(done.into_iter().map(|(_, result)| result).collect())
}

pub(crate) fn chunks(total: usize, size: usize) -> impl Iterator<Item = Range<usize>> {
    (0..total).step_by(size).map(move |start| start..(start + size).min(total))
}

/// What a search of one ABC entry runs on.
pub(crate) struct Env<'q, 'a> {
    /// Name of the entry, for errors.
    pub entry: &'q str,
    /// Its index in the program.
    pub entry_index: u32,
    /// The analyses the engine keeps between queries.
    pub cache: &'q GraphCache,
    /// The query is one condition: its workers see every function of
    /// every record. (In a conjunction, only the functions the conditions
    /// before it hit.)
    pub is_lone: bool,
    /// The call graph and the function sets of the `call:{...}` conditions
    /// of the query, when it has any.
    pub graph: Option<&'q Graph<'q, 'a>>,
    pub abc: Abc<'a>,
    pub regions: &'q Regions<'a>,
    pub workers: usize,
    pub cancel: &'q AtomicBool,
}

/// One region of the file: the method offsets it covers and its entity table.
struct RegionTable<'a> {
    start: u32,
    end: u32,
    table: OffsetTable<'a>,
}

/// The regions of a file whose header and table read.
pub(crate) struct Regions<'a>(Vec<RegionTable<'a>>);

impl<'a> Regions<'a> {
    pub(crate) fn of(abc: &Abc<'a>) -> Regions<'a> {
        let mut regions = Vec::new();
        // A region whose header or table does not read has no methods to scan either.
        for region in abc.regions().into_iter().flat_map(|regions| regions.iter()) {
            if let Ok(table) = region.entity_table() {
                let header = region.header();
                regions.push(RegionTable { start: header.start, end: header.end, table });
            }
        }
        Regions(regions)
    }

    /// `method` with its code and the entity table of its region; `None`
    /// when it has no code, the code does not read or no region covers it.
    pub(crate) fn function<'s>(&self, abc: Abc<'a>, method: &'s Method<'a>) -> Option<Function<'s, 'a>> {
        let code = method.code().ok()??;
        let region = self.of_method(method)?;
        Some(Function { abc, method, code, region, table: self.0[region].table })
    }

    /// The region `method` lies in. The region number in its access flags
    /// is a hint; the offset decides.
    fn of_method(&self, method: &Method<'a>) -> Option<usize> {
        let covers = |region: &RegionTable<'a>| region.start <= method.offset() && method.offset() < region.end;
        let hint = method.region_hint() as usize;
        if self.0.get(hint).is_some_and(covers) {
            return Some(hint);
        }
        self.0.iter().position(covers)
    }
}

/// Entity ids of every region: one bit per table entry.
#[derive(Default)]
pub(crate) struct IdSet(Vec<Vec<u64>>);

impl IdSet {
    /// Step 1: the ids whose table entry (a file offset) `is_match` accepts.
    pub(crate) fn locate(env: &Env<'_, '_>, is_match: impl Fn(u32) -> bool + Sync) -> Result<IdSet> {
        let regions = &env.regions.0;
        let units: Vec<(usize, Range<usize>)> = regions
            .iter()
            .enumerate()
            .flat_map(|(index, region)| chunks(region.table.len() as usize, ID_CHUNK).map(move |ids| (index, ids)))
            .collect();
        let found = run_units(units.len(), env.workers, env.cancel, |unit| {
            let (region, ids) = &units[unit];
            let table = regions[*region].table;
            let accepted = |id: &usize| u32::try_from(*id).ok().and_then(|id| table.get(id)).is_some_and(&is_match);
            ids.clone().filter(accepted).collect::<Vec<usize>>()
        })?;
        let mut sets: Vec<Vec<u64>> = regions.iter().map(|region| vec![0; (region.table.len() as usize).div_ceil(64)]).collect();
        for ((region, _), ids) in units.iter().zip(found) {
            for id in ids {
                sets[*region][id / 64] |= 1 << (id % 64);
            }
        }
        Ok(IdSet(sets))
    }

    #[inline]
    pub(crate) fn contains(&self, region: usize, id: u32) -> bool {
        self.0.get(region).and_then(|set| set.get(id as usize / 64)).is_some_and(|word| word >> (id % 64) & 1 != 0)
    }
}

/// A record being scanned.
pub(crate) struct Record<'s, 'a> {
    pub abc: Abc<'a>,
    pub class: &'s Class<'a>,
    /// Its fields, from the first.
    pub fields: &'s Fields<'a>,
}

/// A function being scanned.
pub(crate) struct Function<'s, 'a> {
    pub abc: Abc<'a>,
    pub method: &'s Method<'a>,
    pub code: Code<'a>,
    /// Index of the method's region in [`Regions`], for [`IdSet::contains`].
    pub region: usize,
    /// The entity table of that region.
    pub table: OffsetTable<'a>,
}

impl<'a> Function<'_, 'a> {
    /// `insn` as disassembly.
    pub(crate) fn text(&self, insn: &Instruction<'_>) -> String {
        disasm::instruction(&self.abc, self.method, insn)
    }

    /// `insn` as disassembly, without the items of its literal array.
    pub(crate) fn text_without_literals(&self, insn: &Instruction<'_>) -> String {
        disasm::instruction_without_literals(&self.abc, self.method, insn)
    }

    /// File offset of the entity a 16-bit id operand names.
    pub(crate) fn entity(&self, id: u32) -> Option<u32> {
        self.table.get(id)
    }
}

/// A match inside a function.
pub(crate) struct Hit {
    /// Offset of the instruction in the function's code.
    pub pc: u32,
    pub matched: Vec<String>,
    pub text: String,
}

/// A match in the record itself.
pub(crate) struct RecordHit {
    /// The record field the match hangs off.
    pub field: String,
    pub matched: Vec<String>,
    pub text: String,
}

/// A match in an annotation of a function.
pub(crate) struct AnnotationHit {
    pub matched: Vec<String>,
    pub text: String,
}

/// A query prepared for one ABC entry: what step 1 found, shared by the
/// worker threads.
pub(crate) trait Condition<'a>: Sync {
    fn worker<'s>(&'s self) -> Box<dyn Worker<'a> + 's>;

    /// Whether step 1 showed that nothing in the entry can match.
    fn is_impossible(&self) -> bool {
        false
    }

    /// Whether a function scan is much dearer than a walk over the code;
    /// a conjunction tests such a condition last.
    fn is_costly(&self) -> bool {
        false
    }
}

/// The scan of one thread for one condition.
pub(crate) trait Worker<'a> {
    /// Called for each record before its functions: reports the matches in
    /// the record itself and returns whether its functions can match.
    fn record(&mut self, record: &Record<'_, 'a>, hits: &mut Vec<RecordHit>) -> bool;

    /// Reports the matches in `function`, in code order.
    ///
    /// # Errors
    /// Code that does not decode: the hits before the bad instruction stay.
    fn function(&mut self, function: &Function<'_, 'a>, hits: &mut Vec<Hit>) -> std::result::Result<(), DecodeError>;

    /// Reports the matches in the annotations `function` carries, in file
    /// order. Asked of a lone query only: a conjunction is about the code.
    fn annotations(&mut self, _function: &Function<'_, 'a>, _hits: &mut Vec<AnnotationHit>) {}
}

/// The functions of the sets a query names, by the address of each
/// [`FunctionSet`] in it: a query is borrowed for as long as it is answered.
#[derive(Default)]
pub(crate) struct Sets(HashMap<usize, HashSet<FnRef>>);

impl Sets {
    fn key(set: &FunctionSet) -> usize {
        std::ptr::from_ref(set) as usize
    }

    fn of(&self, set: &FunctionSet) -> Option<&HashSet<FnRef>> {
        self.0.get(&Sets::key(set))
    }

    /// Work out the set of every `call:{...}` in `query`, innermost first.
    fn resolve(&mut self, query: &Query, session: &Session<'_>, cancel: &AtomicBool) -> Result<()> {
        match query {
            Query::All(parts) => parts.iter().try_for_each(|part| self.resolve(part, session, cancel)),
            Query::Not(part) => self.resolve(part, session, cancel),
            Query::CallTo(set) => {
                let functions = match set {
                    FunctionSet::Matching(rule) => {
                        self.resolve(rule, session, cancel)?;
                        functions_matching(rule, session, self, cancel)?
                    }
                    FunctionSet::Listed(listed) => method::listed_functions(session, listed, cancel)?,
                };
                self.0.insert(Sets::key(set), functions);
                Ok(())
            }
            Query::StringRegex(_)
            | Query::StringLiteral(_)
            | Query::Prop { .. }
            | Query::Global { .. }
            | Query::Import { .. }
            | Query::Method { .. }
            | Query::Number(_)
            | Query::Call(_) => Ok(()),
        }
    }
}

/// What a query with `call:{...}` conditions is answered from.
pub(crate) struct Graph<'q, 'a> {
    pub session: &'q Session<'a>,
    pub sets: &'q Sets,
}

/// The call graph session and the sets of `query`, when it needs them.
pub(crate) struct Prepared<'e> {
    session: Option<Session<'e>>,
    sets: Sets,
}

impl<'e> Prepared<'e> {
    /// # Errors
    /// What the searches for the sets of `query` fail with.
    pub(crate) fn new(engine: &'e crate::Engine, query: &Query, cancel: &AtomicBool) -> Result<Prepared<'e>> {
        let mut sets = Sets::default();
        let session = if query.needs_graph() {
            let session = Session::new(engine);
            sets.resolve(query, &session, cancel)?;
            Some(session)
        } else {
            None
        };
        Ok(Prepared { session, sets })
    }

    pub(crate) fn graph(&self) -> Option<Graph<'_, 'e>> {
        self.session.as_ref().map(|session| Graph { session, sets: &self.sets })
    }
}

/// The functions `rule` matches, in the whole program: those whose code
/// matches its conditions, a `method:` condition naming the functions
/// themselves.
///
/// # Errors
/// [`EngineError::Query`] for a rule that is no set of functions,
/// [`EngineError::Cancelled`].
pub(crate) fn matching(rule: &Query, session: &Session<'_>, cancel: &AtomicBool) -> Result<HashSet<FnRef>> {
    let mut sets = Sets::default();
    sets.resolve(rule, session, cancel)?;
    functions_matching(rule, session, &sets, cancel)
}

fn functions_matching(rule: &Query, session: &Session<'_>, sets: &Sets, cancel: &AtomicBool) -> Result<HashSet<FnRef>> {
    let graph = Graph { session, sets };
    let mut functions = HashSet::new();
    for (index, abc) in session.readable() {
        let entry = Entry { name: session.entry_name(index), index, abc };
        let scope = Scope { cache: session.cache(), graph: Some(&graph), workers: session.threads(), cancel };
        let found = scan_entry(&entry, rule, &scope, Wanted::Functions)?;
        functions.extend(found.functions.into_iter().map(|method| FnRef { entry: index, method }));
    }
    Ok(functions)
}

fn condition<'q, 'a: 'q>(query: &'q Query, env: &Env<'q, 'a>) -> Result<Box<dyn Condition<'a> + 'q>> {
    use names::{Matcher, Names, Scope};
    Ok(match query {
        Query::StringRegex(regex) => Box::new(Names::prepare(env, Matcher::Regex(regex), Scope::Text)?),
        Query::StringLiteral(needle) => Box::new(Names::prepare(env, Matcher::contains(needle), Scope::Text)?),
        Query::Prop { name, access } => Box::new(Names::prepare(env, Matcher::of(name), Scope::Property(*access))?),
        Query::Global { name, access } => Box::new(Names::prepare(env, Matcher::of(name), Scope::Global(*access))?),
        Query::Import { request, name, declarations_only } => Box::new(import::Imports::new(request, name.as_deref(), *declarations_only)),
        Query::Method { record, name } => Box::new(method::Methods::prepare(env, record.as_deref(), name)?),
        Query::Number(number) => Box::new(number::Numbers::prepare(env, number)),
        Query::Call(pattern) => Box::new(call::Calls::prepare(env, pattern)?),
        Query::CallTo(set) => {
            let graph = env.graph.ok_or_else(|| EngineError::Query("a call:{...} condition was not prepared".into()))?;
            let functions = graph.sets.of(set).ok_or_else(|| EngineError::Query("a call:{...} condition was not prepared".into()))?;
            Box::new(callto::CallsTo::new(graph.session, functions, env.entry_index))
        }
        Query::All(_) | Query::Not(_) => {
            return Err(EngineError::Query("a conjunction inside a conjunction is not supported: list its conditions".into()))
        }
    })
}

/// A query taken apart: the conditions on the code of a function, and the
/// `method:` conditions of a conjunction, which are about its name.
#[derive(Default)]
struct Parts<'q> {
    all: Vec<&'q Query>,
    none: Vec<&'q Query>,
    named: Vec<&'q Query>,
    not_named: Vec<&'q Query>,
    /// One condition on its own: every hit is a row.
    is_lone: bool,
}

impl<'q> Parts<'q> {
    fn of(query: &'q Query, wanted: Wanted) -> Result<Parts<'q>> {
        let mut parts = Parts::default();
        match query {
            Query::All(list) => {
                for part in list {
                    match part {
                        Query::Not(excluded) if matches!(**excluded, Query::Method { .. }) => parts.not_named.push(excluded),
                        Query::Not(excluded) => parts.none.push(excluded),
                        Query::Method { .. } => parts.named.push(part),
                        code => parts.all.push(code),
                    }
                }
            }
            Query::Not(_) => return Err(EngineError::Query("a rule needs a condition without `!` (`!` only removes functions)".into())),
            // As a set, the functions of that name; as a search, where they are defined.
            Query::Method { .. } if wanted == Wanted::Functions => parts.named.push(query),
            lone => {
                parts.all.push(lone);
                parts.is_lone = wanted == Wanted::Rows;
            }
        }
        Ok(parts)
    }
}

/// What a scan gives back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wanted {
    Rows,
    /// The functions that match, not rows.
    Functions,
}

/// Unreadable records and functions: the first reason and the count.
#[derive(Default)]
struct Errors {
    first: Option<String>,
    count: usize,
}

impl Errors {
    fn note(&mut self, what: impl FnOnce() -> String) {
        self.count += 1;
        if self.first.is_none() {
            self.first = Some(what());
        }
    }

    fn merge(&mut self, other: Errors) {
        self.count += other.count;
        self.first = self.first.take().or(other.first);
    }

    fn into_message(self) -> Option<String> {
        let first = self.first?;
        Some(match self.count {
            1 => first,
            n => format!("{first} (and {} more)", n - 1),
        })
    }
}

/// The names a row of a function carries.
struct FunctionNames {
    record: String,
    raw: String,
    restored: String,
}

/// Step 2 state of one thread over one ABC entry.
struct Scanner<'s, 'a> {
    abc: Abc<'a>,
    regions: &'s Regions<'a>,
    plan: &'s Plan<'s>,
    /// One per condition a function has to match, in query order.
    workers: Vec<Box<dyn Worker<'a> + 's>>,
    /// One per condition a function must not match.
    excluders: Vec<Box<dyn Worker<'a> + 's>>,
    /// Whether the functions of the record being scanned can match each excluder.
    excluder_live: Vec<bool>,
    /// The hits of the function being scanned, per condition.
    hits: Vec<Vec<Hit>>,
    /// Reused for the hits of an excluder.
    excluded: Vec<Hit>,
    /// The hits in the annotations of the function being scanned.
    annotated: Vec<AnnotationHit>,
    rows: Vec<RefRow>,
    /// Method offsets of the functions that match, for [`Wanted::Functions`].
    functions: Vec<u32>,
    errors: Errors,
}

/// What every thread of a scan shares.
struct Plan<'s> {
    wanted: Wanted,
    is_lone: bool,
    /// The kind of each condition a function has to match, for the rows of a conjunction.
    kinds: Vec<&'static str>,
    /// Indexes of those conditions in the order they are tested.
    order: Vec<usize>,
    /// The functions the `method:` conditions of a conjunction leave, by
    /// method offset; `None` without such a condition.
    named: Option<&'s HashSet<u32>>,
    /// The functions its `!method:` conditions take away.
    not_named: &'s HashSet<u32>,
}

impl<'a> Scanner<'_, 'a> {
    fn scan_record(&mut self, class: &Class<'a>) {
        let record = || String::from_utf8_lossy(class.name()).into_owned();
        let fields = match class.fields() {
            Ok(fields) => fields,
            Err(err) => return self.errors.note(|| format!("{}: {err}", record())),
        };
        let mut record_hits = Vec::new();
        let mut live = true;
        for worker in &mut self.workers {
            live &= worker.record(&Record { abc: self.abc, class, fields: &fields }, &mut record_hits);
        }
        // A conjunction is about functions: what matches in the record itself is not a row of it.
        if self.plan.is_lone {
            self.rows.extend(record_hits.drain(..).map(|hit| RefRow {
                record: record(),
                site: RefSite::Field { name: hit.field },
                matched: hit.matched,
                text: hit.text,
                sites: Vec::new(),
                context: None,
                method: None,
            }));
        }
        if !live {
            return;
        }
        for (worker, live) in self.excluders.iter_mut().zip(&mut self.excluder_live) {
            record_hits.clear();
            *live = worker.record(&Record { abc: self.abc, class, fields: &fields }, &mut record_hits);
        }
        let methods = match fields.into_methods() {
            Ok(methods) => methods,
            Err(err) => return self.errors.note(|| format!("{}: {err}", record())),
        };
        for method in methods {
            match method {
                Ok(method) => self.scan_method(class, &method),
                Err(err) => self.errors.note(|| format!("{}: {err}", record())),
            }
        }
    }

    fn scan_method(&mut self, class: &Class<'a>, method: &Method<'a>) {
        let plan = self.plan;
        let offset = method.offset();
        if plan.named.is_some_and(|named| !named.contains(&offset)) || plan.not_named.contains(&offset) {
            return;
        }
        let record = || String::from_utf8_lossy(class.name()).into_owned();
        let code = match method.code() {
            Ok(Some(code)) => code,
            Ok(None) => return,
            Err(err) => return self.errors.note(|| format!("{}: {err}", record())),
        };
        let Some(region) = self.regions.of_method(method) else {
            return self.errors.note(|| format!("{}: no region covers method {:#x}", record(), method.offset()));
        };
        let function = Function { abc: self.abc, method, code, region, table: self.regions.0[region].table };
        let mut failed = None;
        self.annotated.clear();
        if plan.is_lone {
            if let Some(worker) = self.workers.first_mut() {
                worker.annotations(&function, &mut self.annotated);
            }
        }
        self.hits.iter_mut().for_each(Vec::clear);
        for &index in &plan.order {
            let hits = &mut self.hits[index];
            if let Err(err) = self.workers[index].function(&function, hits) {
                failed.get_or_insert(err);
            }
            // The conjunction is decided as soon as one condition has no hit.
            if hits.is_empty() {
                break;
            }
        }
        let mut matches = !self.hits.iter().any(Vec::is_empty);
        if matches {
            for (worker, _) in self.excluders.iter_mut().zip(&self.excluder_live).filter(|(_, live)| **live) {
                self.excluded.clear();
                if let Err(err) = worker.function(&function, &mut self.excluded) {
                    failed.get_or_insert(err);
                }
                if !self.excluded.is_empty() {
                    matches = false;
                    break;
                }
            }
        }
        let raw_name = || method.name().map(|name| name.to_str().into_owned()).unwrap_or_default();
        if let Some(err) = failed {
            self.errors.note(|| format!("{}->{}: {err}", record(), raw_name()));
        }
        if !matches && self.annotated.is_empty() {
            return;
        }
        if plan.wanted == Wanted::Functions {
            return self.functions.push(offset);
        }
        // Decoded only for a function with a row: most have none.
        let raw = raw_name();
        let names = FunctionNames { record: record(), restored: class.restore_function_name(&raw), raw };
        let site = |pc| RefSite::Code { function: names.raw.clone(), restored: names.restored.clone(), pc };
        if plan.is_lone {
            // What stands on the function comes before what is in it. Without a match in the
            // code there is no code hit to drain.
            self.rows.extend(self.annotated.drain(..).map(|hit| RefRow {
                record: names.record.clone(),
                site: RefSite::Annotation { function: names.raw.clone(), restored: names.restored.clone() },
                matched: hit.matched,
                text: hit.text,
                sites: Vec::new(),
                context: None,
                method: None,
            }));
            for hit in self.hits[0].drain(..) {
                self.rows.push(RefRow {
                    record: names.record.clone(),
                    site: site(hit.pc),
                    matched: hit.matched,
                    text: hit.text,
                    sites: vec![hit.pc],
                    context: None,
                    method: Some(offset),
                });
            }
        } else {
            let mut sites: Vec<u32> = self.hits.iter().flatten().map(|hit| hit.pc).collect();
            sites.sort_unstable();
            sites.dedup();
            // A conjunction of names alone has no instruction to show.
            let pc = self.hits.first().and_then(|hits| hits.first()).map_or(0, |hit| hit.pc);
            let text = if self.hits.is_empty() { "method".to_owned() } else { conjunction_text(&plan.kinds, &self.hits) };
            let matched = self.hits.iter_mut().flatten().flat_map(|hit| std::mem::take(&mut hit.matched)).collect();
            self.rows.push(RefRow {
                record: names.record.clone(),
                site: site(pc),
                matched,
                text,
                sites,
                context: None,
                method: Some(offset),
            });
        }
    }
}

/// What each condition of a conjunction matched in one function, in query
/// order: `string +0x12 lda.str "https://…" && call +0x20 callthis1 … (+3 more)`.
fn conjunction_text(kinds: &[&'static str], hits: &[Vec<Hit>]) -> String {
    let mut out = String::new();
    for (kind, hits) in kinds.iter().zip(hits) {
        if !out.is_empty() {
            out.push_str(" && ");
        }
        out.push_str(kind);
        for (index, hit) in hits.iter().take(SHOWN_PER_CONDITION).enumerate() {
            out.push_str(if index == 0 { " " } else { ", " });
            out.push_str(&format!("+{:#x} {}", hit.pc, hit.text));
        }
        if hits.len() > SHOWN_PER_CONDITION {
            out.push_str(&format!(" (+{} more)", hits.len() - SHOWN_PER_CONDITION));
        }
    }
    out
}

/// Code sizes are 32-bit (`uleb` in the code header).
pub(crate) fn pc_of(insn: &Instruction<'_>) -> u32 {
    u32::try_from(insn.pc).unwrap_or(u32::MAX)
}

/// An ABC entry of a program, as a search is told about it.
pub(crate) struct Entry<'q, 'a> {
    pub name: &'q str,
    /// Its index in the program.
    pub index: u32,
    pub abc: Abc<'a>,
}

/// What a scan of one ABC entry runs with.
pub(crate) struct Scope<'q, 'a> {
    /// What the search works out that later queries can use (the captured
    /// variables of the records a `call:` condition looks into) is read
    /// from and left here.
    pub cache: &'q GraphCache,
    pub graph: Option<&'q Graph<'q, 'a>>,
    pub workers: usize,
    pub cancel: &'q AtomicBool,
}

/// What a scan of one ABC entry found.
struct Scanned {
    batch: RefBatch,
    functions: Vec<u32>,
}

/// Search one ABC entry for the rows of `query`.
pub(crate) fn search_entry<'a>(entry: &Entry<'_, 'a>, query: &Query, scope: &Scope<'_, 'a>) -> Result<RefBatch> {
    Ok(scan_entry(entry, query, scope, Wanted::Rows)?.batch)
}

/// The functions the `method:` conditions `named` leave in the entry of
/// `env`: those every one of them names.
fn named_by_all(env: &Env<'_, '_>, named: &[&Query]) -> Result<Option<HashSet<u32>>> {
    let mut left: Option<HashSet<u32>> = None;
    for query in named {
        let Query::Method { record, name } = query else { continue };
        let found = method::named_functions(env, record.as_deref(), name)?;
        left = Some(match left {
            Some(left) => left.intersection(&found).copied().collect(),
            None => found,
        });
    }
    Ok(left)
}

fn scan_entry<'a>(entry: &Entry<'_, 'a>, query: &Query, scope: &Scope<'_, 'a>, wanted: Wanted) -> Result<Scanned> {
    let started = Instant::now();
    let (entry_name, abc) = (entry.name, entry.abc);
    let (workers, cancel) = (scope.workers, scope.cancel);
    let mut scanned = Scanned {
        batch: RefBatch { entry_name: entry_name.to_owned(), rows: Vec::new(), search_us: 0, error: None },
        functions: Vec::new(),
    };
    let regions = Regions::of(&abc);
    let parts = Parts::of(query, wanted)?;
    // The workers of one condition alone see every function: nothing was tested ahead of them.
    let sees_all = parts.all.len() == 1 && parts.none.is_empty() && parts.named.is_empty() && parts.not_named.is_empty();
    let env = Env {
        entry: entry_name,
        entry_index: entry.index,
        cache: scope.cache,
        is_lone: sees_all,
        graph: scope.graph,
        abc,
        regions: &regions,
        workers,
        cancel,
    };
    let done = |mut scanned: Scanned| {
        scanned.batch.search_us = started.elapsed().as_micros();
        Ok(scanned)
    };
    let named = named_by_all(&env, &parts.named)?;
    if named.as_ref().is_some_and(HashSet::is_empty) {
        return done(scanned);
    }
    let mut not_named = HashSet::new();
    for excluded in &parts.not_named {
        let Query::Method { record, name } = excluded else { continue };
        not_named.extend(method::named_functions(&env, record.as_deref(), name)?);
    }
    let mut conditions = Vec::with_capacity(parts.all.len());
    for part in &parts.all {
        let condition = condition(part, &env)?;
        // Nothing matches one condition: nothing matches the query.
        if condition.is_impossible() {
            return done(scanned);
        }
        conditions.push(condition);
    }
    if conditions.is_empty() && named.is_none() {
        return done(scanned);
    }
    // A condition nothing matches takes no function away.
    let mut excluders = Vec::with_capacity(parts.none.len());
    for part in &parts.none {
        let excluder = condition(part, &env)?;
        if !excluder.is_impossible() {
            excluders.push(excluder);
        }
    }
    excluders.sort_by_key(|excluder| excluder.is_costly());
    // Cheap conditions first, each group in query order.
    let mut order: Vec<usize> = (0..conditions.len()).collect();
    order.sort_by_key(|&index| conditions[index].is_costly());
    let plan = Plan {
        wanted,
        is_lone: parts.is_lone,
        kinds: parts.all.iter().map(|part| part.kind()).collect(),
        order,
        named: named.as_ref(),
        not_named: &not_named,
    };

    let classes: Vec<u32> = abc.class_index().map_err(|source| EngineError::Abc { entry: entry_name.to_owned(), source })?.iter().collect();
    let units: Vec<Range<usize>> = chunks(classes.len(), RECORD_CHUNK).collect();
    let found = run_units(units.len(), workers, cancel, |unit| {
        let mut scanner = Scanner {
            abc,
            regions: &regions,
            plan: &plan,
            workers: conditions.iter().map(|condition| condition.worker()).collect(),
            excluders: excluders.iter().map(|excluder| excluder.worker()).collect(),
            excluder_live: vec![true; excluders.len()],
            hits: conditions.iter().map(|_| Vec::new()).collect(),
            excluded: Vec::new(),
            annotated: Vec::new(),
            rows: Vec::new(),
            functions: Vec::new(),
            errors: Errors::default(),
        };
        for &off in &classes[units[unit].clone()] {
            match abc.class_entry(off) {
                Ok(ClassEntry::Local(class)) => scanner.scan_record(&class),
                Ok(ClassEntry::Foreign(_)) => {}
                Err(err) => scanner.errors.note(|| format!("class at {off:#x}: {err}")),
            }
        }
        (scanner.rows, scanner.functions, scanner.errors)
    })?;
    let mut errors = Errors::default();
    for (rows, functions, unit_errors) in found {
        scanned.batch.rows.extend(rows);
        scanned.functions.extend(functions);
        errors.merge(unit_errors);
    }
    scanned.batch.error = errors.into_message();
    done(scanned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_run_in_order_on_any_thread_count() {
        let cancel = AtomicBool::new(false);
        for workers in [1, 3, 64] {
            assert_eq!(run_units(10, workers, &cancel, |unit| unit * 2).unwrap(), (0..10).map(|unit| unit * 2).collect::<Vec<_>>());
        }
        assert!(run_units(0, 4, &cancel, |unit| unit).unwrap().is_empty());
        cancel.store(true, Ordering::Relaxed);
        assert!(matches!(run_units(10, 4, &cancel, |unit| unit), Err(EngineError::Cancelled)));
        assert_eq!(chunks(5, 2).collect::<Vec<_>>(), [0..2, 2..4, 4..5]);
    }

    #[test]
    fn rows_print_canonical_locations() {
        let mut row = RefRow {
            record: "&entry/src/main/ets/pages/Index&".into(),
            site: RefSite::Code { function: "#~@0>#build".into(), restored: "Index.build".into(), pc: 0x12 },
            matched: vec!["hello".into()],
            text: "lda.str \"hello\"".into(),
            sites: vec![0x12],
            context: None,
            method: None,
        };
        assert_eq!(
            row.line("ets/modules.abc"),
            "ets/modules.abc | &entry/src/main/ets/pages/Index&->#~@0>#build+0x12 | Index.build | lda.str \"hello\""
        );
        row.site = RefSite::Field { name: "scopeNames".into() };
        assert_eq!(row.line("a.abc"), "a.abc | &entry/src/main/ets/pages/Index& field scopeNames | - | lda.str \"hello\"");
        row.site = RefSite::Annotation { function: "#~@0>#build".into(), restored: "Index.build".into() };
        row.text = "annotation @&entry/src/main/ets/Marks&.Route path=\"hello\"".into();
        assert_eq!(
            row.line("a.abc"),
            "a.abc | &entry/src/main/ets/pages/Index&->#~@0>#build | Index.build | annotation @&entry/src/main/ets/Marks&.Route path=\"hello\""
        );
    }

    #[test]
    fn conjunction_rows_list_each_condition() {
        let hit = |pc, text: &str| Hit { pc, matched: Vec::new(), text: text.to_owned() };
        let hits = [vec![hit(0x12, "lda.str \"a\"")], vec![hit(1, "x"), hit(2, "y"), hit(3, "z"), hit(4, "w")]];
        assert_eq!(conjunction_text(&["string", "call"], &hits), "string +0x12 lda.str \"a\" && call +0x1 x, +0x2 y (+2 more)");
    }
}
