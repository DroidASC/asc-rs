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
//! condition hits and prints one row per function.
//!
//! Both steps run on `threads` scoped threads over fixed-size chunks; rows
//! come back in file order whatever the thread count.

mod call;
mod import;
pub(crate) mod method;
mod names;
mod number;
mod query;

use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use asc_abc::{Abc, Class, ClassEntry, Code, Fields, Method, OffsetTable};
use asc_arkisa::{DecodeError, Instruction};

pub(crate) use call::CallPaths;
pub(crate) use import::module_requests;
pub use import::RequestListing;
pub use query::{NumberQuery, Pattern, Query};

use crate::callgraph::GraphCache;
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
    /// A field of the record itself (`scopeNames`, `jsonFileContent`).
    Field { name: String },
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
}

impl RefRow {
    /// `entry | record->function+0xPC | restored name | text`: the location
    /// column uses canonical names, which a query can be given back (`->`
    /// as in the DEX rows; a `.` would run into versioned record names such
    /// as `&@ohos/crypto-js/index&2.0.0`). A field reference is
    /// `entry | record field NAME | - | text`.
    pub fn line(&self, entry: &str) -> String {
        match &self.site {
            RefSite::Code { function, restored, pc } => {
                format!("{entry} | {}->{function}+{pc:#x} | {restored} | {}", self.record, self.text)
            }
            RefSite::Field { name } => format!("{entry} | {} field {name} | - | {}", self.record, self.text),
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
        Query::All(_) => return Err(EngineError::Query("a conjunction inside a conjunction is not supported: list its conditions".into())),
    })
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
    /// One per condition, in query order.
    workers: Vec<Box<dyn Worker<'a> + 's>>,
    /// The kind of each condition, for the rows of a conjunction; empty for a lone query.
    kinds: &'s [&'static str],
    /// Condition indexes in the order a conjunction tests them.
    order: &'s [usize],
    /// The hits of the function being scanned, per condition.
    hits: Vec<Vec<Hit>>,
    rows: Vec<RefRow>,
    errors: Errors,
}

impl<'a> Scanner<'_, 'a> {
    fn is_conjunction(&self) -> bool {
        !self.kinds.is_empty()
    }

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
        if !self.is_conjunction() {
            self.rows.extend(record_hits.into_iter().map(|hit| RefRow {
                record: record(),
                site: RefSite::Field { name: hit.field },
                matched: hit.matched,
                text: hit.text,
            }));
        }
        if !live {
            return;
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
        self.hits.iter_mut().for_each(Vec::clear);
        for &index in self.order {
            let hits = &mut self.hits[index];
            if let Err(err) = self.workers[index].function(&function, hits) {
                failed.get_or_insert(err);
            }
            // The conjunction is decided as soon as one condition has no hit.
            if hits.is_empty() {
                break;
            }
        }
        let raw_name = || method.name().map(|name| name.to_str().into_owned()).unwrap_or_default();
        if let Some(err) = failed {
            self.errors.note(|| format!("{}->{}: {err}", record(), raw_name()));
        }
        if self.hits.iter().any(Vec::is_empty) {
            return;
        }
        // Decoded only for a function with a row: most have none.
        let raw = raw_name();
        let names = FunctionNames { record: record(), restored: class.restore_function_name(&raw), raw };
        let site = |pc| RefSite::Code { function: names.raw.clone(), restored: names.restored.clone(), pc };
        if self.is_conjunction() {
            let pc = self.hits[0][0].pc;
            let text = conjunction_text(self.kinds, &self.hits);
            let matched = self.hits.iter_mut().flatten().flat_map(|hit| std::mem::take(&mut hit.matched)).collect();
            self.rows.push(RefRow { record: names.record.clone(), site: site(pc), matched, text });
        } else {
            for hit in self.hits[0].drain(..) {
                self.rows.push(RefRow { record: names.record.clone(), site: site(hit.pc), matched: hit.matched, text: hit.text });
            }
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

/// Search one ABC entry. What the search works out that later queries can
/// use (the captured variables of the records a `call:` condition looks
/// into) is read from and left in `cache`.
pub(crate) fn search_entry(
    entry: &Entry<'_, '_>,
    query: &Query,
    cache: &GraphCache,
    workers: usize,
    cancel: &AtomicBool,
) -> Result<RefBatch> {
    let started = Instant::now();
    let (entry_name, abc) = (entry.name, entry.abc);
    let mut batch = RefBatch { entry_name: entry_name.to_owned(), rows: Vec::new(), search_us: 0, error: None };
    let regions = Regions::of(&abc);
    let (parts, kinds): (&[Query], Vec<&'static str>) = match query {
        Query::All(parts) => (parts, parts.iter().map(Query::kind).collect()),
        lone => (std::slice::from_ref(lone), Vec::new()),
    };
    let is_lone = !matches!(query, Query::All(_));
    let env = Env { entry: entry_name, entry_index: entry.index, cache, is_lone, abc, regions: &regions, workers, cancel };
    let mut conditions = Vec::with_capacity(parts.len());
    for part in parts {
        let condition = condition(part, &env)?;
        // Nothing matches one condition: nothing matches the query.
        if condition.is_impossible() {
            conditions.clear();
            break;
        }
        conditions.push(condition);
    }
    if conditions.is_empty() {
        batch.search_us = started.elapsed().as_micros();
        return Ok(batch);
    }
    // Cheap conditions first, each group in query order.
    let mut order: Vec<usize> = (0..conditions.len()).collect();
    order.sort_by_key(|&index| conditions[index].is_costly());

    let classes: Vec<u32> = abc.class_index().map_err(|source| EngineError::Abc { entry: entry_name.to_owned(), source })?.iter().collect();
    let units: Vec<Range<usize>> = chunks(classes.len(), RECORD_CHUNK).collect();
    let scanned = run_units(units.len(), workers, cancel, |unit| {
        let mut scanner = Scanner {
            abc,
            regions: &regions,
            workers: conditions.iter().map(|condition| condition.worker()).collect(),
            kinds: &kinds,
            order: &order,
            hits: conditions.iter().map(|_| Vec::new()).collect(),
            rows: Vec::new(),
            errors: Errors::default(),
        };
        for &off in &classes[units[unit].clone()] {
            match abc.class_entry(off) {
                Ok(ClassEntry::Local(class)) => scanner.scan_record(&class),
                Ok(ClassEntry::Foreign(_)) => {}
                Err(err) => scanner.errors.note(|| format!("class at {off:#x}: {err}")),
            }
        }
        (scanner.rows, scanner.errors)
    })?;
    let mut errors = Errors::default();
    for (rows, unit_errors) in scanned {
        batch.rows.extend(rows);
        errors.merge(unit_errors);
    }
    batch.error = errors.into_message();
    batch.search_us = started.elapsed().as_micros();
    Ok(batch)
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
        };
        assert_eq!(
            row.line("ets/modules.abc"),
            "ets/modules.abc | &entry/src/main/ets/pages/Index&->#~@0>#build+0x12 | Index.build | lda.str \"hello\""
        );
        row.site = RefSite::Field { name: "scopeNames".into() };
        assert_eq!(row.line("a.abc"), "a.abc | &entry/src/main/ets/pages/Index& field scopeNames | - | lda.str \"hello\"");
    }

    #[test]
    fn conjunction_rows_list_each_condition() {
        let hit = |pc, text: &str| Hit { pc, matched: Vec::new(), text: text.to_owned() };
        let hits = [vec![hit(0x12, "lda.str \"a\"")], vec![hit(1, "x"), hit(2, "y"), hit(3, "z"), hit(4, "w")]];
        assert_eq!(conjunction_text(&["string", "call"], &hits), "string +0x12 lda.str \"a\" && call +0x1 x, +0x2 y (+2 more)");
    }
}
