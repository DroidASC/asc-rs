//! `call:`: call sites by resolved callee.
//!
//! A call instruction has no callee operand, so [`crate::track`] follows
//! each function's values and every call site is described by the path of
//! its callee:
//!
//! | path | the callee is |
//! |---|---|
//! | `import:@ohos:net.http#default.createHttp` | a member of regular import `default` of that module request (`#*`: its namespace) |
//! | `global:console.log` | a member of a global binding; `globalThis` is the global object |
//! | `this.load`, `super.aboutToAppear`, `super` | a member of `this` / of the parent class, the parent constructor |
//! | `local:#*#helper` | a function or class this function defines (raw name) |
//! | `module:Index` | a module-level binding of this record (a local export) |
//! | `lex(1,3).send` | a member of a captured variable (level, slot) that did not resolve; `slex` in a sendable environment |
//! | `arg0.then` | a member of the first declared parameter |
//! | `expr`, `?` | computed in the block by something else; set in another block |
//! | `this@#~@0>#load.cfg`, `arg0@#*#outer` | a member of the `this` / a parameter of an enclosing function (raw name), read through a captured variable |
//!
//! A path goes on through what it names: `base.name` is a property,
//! `base[3]` and `base[]` elements with a constant and with a computed key,
//! `base()` what calling `base` returned (`new base()` for a constructor),
//! so `import:@ohos:net.http#default.createHttp().request` is the `request`
//! method of the object `createHttp()` returned. `func` is the running
//! function and `new.target` its `new.target`.
//!
//! A captured variable (`ldlexvar`) is replaced by what was stored in it
//! when exactly one store of the record can write it and the stored value
//! is known ([`crate::scopes`]): the call then prints as if the value had
//! been used directly, `import:…`, `local:…`. Only what is relative to a
//! frame keeps a mark: the `this` and the parameters of the function that
//! captured them are `this@FUNCTION` and `argN@FUNCTION`, unless the
//! environment belongs to the running invocation itself. A variable that
//! does not resolve stays `lex(level,slot)`.
//!
//! A path that starts at a class of the record and names a method of its
//! class literal is that method: `C.create()` is `local:#~@0<#create` and
//! `new C().load()` is `local:#~@0>#load`. Members the literal does not
//! list (inherited, fields, accessors) stay `local:#~@0=#C.name`.
//!
//! The first five rows are resolved; the others say where tracking stopped.
//! The query is matched against the path, so a path can be pasted back (as a
//! regex, escape its dots and parentheses).
//!
//! Tracking every function is what a search costs, so the first search
//! that sees all of a record (one `call:` condition alone) leaves the
//! callee path of each of its call sites in the engine's cache
//! ([`CallPaths`]). Later searches test those and only track the functions
//! with a call site that matches, to print it with its arguments.

use std::hash::{BuildHasher, RandomState};
use std::sync::Arc;

use asc_abc::{Abc, ModuleRecord};
use asc_arkisa::DecodeError;

use super::{Condition, Env, Function, Hit, Pattern, Record, RecordHit, Regions, Worker, pc_of};
use crate::Result;
use crate::callgraph::{GraphCache, RecordId, Slot};
use crate::path::{Names, Path, PathBuilder};
use crate::scopes::{RecordScopes, ScopeTables};
use crate::track::{CallSite, Tracker};

/// Arguments of a call that are printed.
const MAX_ARGUMENTS: usize = 8;

/// The callee path of every call site of one record, as a search spells
/// them, for the functions whose code was tracked to its end.
#[derive(Debug, Default)]
pub(crate) struct CallPaths {
    /// The distinct paths, one after the other.
    text: String,
    /// Where each path ends in `text`, by path id.
    ends: Vec<u32>,
    /// Method offset, first call site and number of call sites of each
    /// function, by method offset.
    functions: Vec<(u32, u32, u32)>,
    /// The path id of each call site, function by function in code order.
    sites: Vec<u32>,
}

impl CallPaths {
    /// Bytes this takes on the heap, roughly.
    pub(crate) fn heap_bytes(&self) -> usize {
        use std::mem::size_of;
        self.text.capacity()
            + self.ends.capacity() * size_of::<u32>()
            + self.functions.capacity() * size_of::<(u32, u32, u32)>()
            + self.sites.capacity() * size_of::<u32>()
    }

    /// The path whose id is `id`.
    fn path(&self, id: u32) -> &str {
        let start = id.checked_sub(1).map_or(0, |before| self.ends[before as usize]);
        self.text.get(start as usize..self.ends[id as usize] as usize).unwrap_or_default()
    }

    /// The distinct paths, by id.
    fn paths(&self) -> impl Iterator<Item = &str> {
        (0..self.ends.len()).map(|id| self.path(id as u32))
    }

    /// The path ids of the call sites of the function at method offset
    /// `method`; `None` for a function that was not tracked to its end.
    fn sites_of(&self, method: u32) -> Option<&[u32]> {
        let at = self.functions.binary_search_by_key(&method, |&(method, _, _)| method).ok()?;
        let (_, start, len) = self.functions[at];
        self.sites.get(start as usize..(start + len) as usize)
    }
}

/// [`CallPaths`] of the record a scan is in, while it is collected.
#[derive(Default)]
struct Collected {
    paths: CallPaths,
    /// Open-addressed set of the paths: 0 for a free place, else a path id
    /// plus one. Its length is a power of two, at least twice the paths.
    places: Vec<u32>,
    /// Keyed per scan: the paths are spelled by the file.
    hasher: RandomState,
    /// The record is too large for 32-bit positions.
    overflowed: bool,
}

impl Collected {
    /// A call site of the function being scanned, whose callee is `path`.
    fn site(&mut self, path: &str) {
        if (self.paths.ends.len() + 1) * 2 > self.places.len() {
            self.grow();
        }
        let mask = self.places.len() - 1;
        // Truncated: only the low bits pick the place.
        let mut place = self.hasher.hash_one(path) as usize & mask;
        let id = loop {
            match self.places[place] {
                0 => {
                    let id = self.paths.ends.len();
                    self.paths.text.push_str(path);
                    let (Ok(end), Ok(marked)) = (u32::try_from(self.paths.text.len()), u32::try_from(id + 1)) else {
                        self.overflowed = true;
                        return;
                    };
                    self.paths.ends.push(end);
                    self.places[place] = marked;
                    break marked - 1;
                }
                marked if self.paths.path(marked - 1) == path => break marked - 1,
                _ => place = (place + 1) & mask,
            }
        };
        self.paths.sites.push(id);
    }

    /// Twice the places, every path put again.
    fn grow(&mut self) {
        let len = (self.places.len() * 2).max(16);
        self.places.clear();
        self.places.resize(len, 0);
        for id in 0..self.paths.ends.len() {
            let mut place = self.hasher.hash_one(self.paths.path(id as u32)) as usize & (len - 1);
            while self.places[place] != 0 {
                place = (place + 1) & (len - 1);
            }
            self.places[place] = id as u32 + 1;
        }
    }

    /// The function at method offset `method` was tracked to its end: its
    /// call sites are the ones from `first` on. Otherwise they are dropped.
    fn function(&mut self, method: u32, first: usize, is_whole: bool) {
        let sites = &mut self.paths.sites;
        match (u32::try_from(first), u32::try_from(sites.len() - first)) {
            (Ok(first), Ok(count)) if is_whole => self.paths.functions.push((method, first, count)),
            (Ok(_), Ok(_)) => sites.truncate(first),
            _ => self.overflowed = true,
        }
    }

    /// `None` for a record too large for 32-bit positions.
    fn finish(self) -> Option<CallPaths> {
        let mut paths = self.paths;
        if self.overflowed {
            return None;
        }
        paths.functions.sort_unstable_by_key(|&(method, _, _)| method);
        paths.text.shrink_to_fit();
        paths.ends.shrink_to_fit();
        paths.functions.shrink_to_fit();
        paths.sites.shrink_to_fit();
        Some(paths)
    }
}

/// What a scan knows of the call sites of the record it is in.
enum Known {
    /// Not asked for: no function of the record was scanned yet.
    Unasked,
    /// Nothing, and this scan does not see every function.
    Nothing,
    /// An earlier search left them in the slot; [`CallsWorker::matched`]
    /// says which of its paths the pattern matches.
    Kept(Arc<Slot>),
    /// This scan collects them, to leave them in the slot.
    Collecting(Arc<Slot>, Collected),
}

/// A prepared `call:` search of one ABC entry.
pub(crate) struct Calls<'q, 'a> {
    abc: Abc<'a>,
    regions: &'q Regions<'a>,
    pattern: &'q Pattern,
    tables: ScopeTables,
    /// Where the captured variables and the callee paths of each record
    /// are kept between queries.
    cache: &'q GraphCache,
    /// Index of the entry in the program.
    entry: u32,
    /// The workers see every function: they can leave [`CallPaths`].
    sees_all: bool,
}

impl<'q, 'a> Calls<'q, 'a> {
    pub(crate) fn prepare(env: &Env<'q, 'a>, pattern: &'q Pattern) -> Result<Calls<'q, 'a>> {
        Ok(Calls {
            abc: env.abc,
            regions: env.regions,
            pattern,
            tables: ScopeTables::new(),
            cache: env.cache,
            entry: env.entry_index,
            sees_all: env.is_lone,
        })
    }
}

impl<'a> Condition<'a> for Calls<'_, 'a> {
    fn worker<'s>(&'s self) -> Box<dyn Worker<'a> + 's> {
        Box::new(CallsWorker {
            calls: self,
            tracker: Tracker::default(),
            module: None,
            scopes: RecordScopes::shared(self.abc, self.regions, &self.tables, self.cache, self.entry),
            record: 0,
            known: Known::Unasked,
            matched: Vec::new(),
            path: Path::default(),
            text: String::new(),
        })
    }

    fn is_costly(&self) -> bool {
        true
    }
}

struct CallsWorker<'s, 'q, 'a> {
    calls: &'s Calls<'q, 'a>,
    tracker: Tracker,
    /// The module record of the record being scanned.
    module: Option<ModuleRecord<'a>>,
    /// The captured variables of the record being scanned, worked out when
    /// the first call site needs one and no earlier query did.
    scopes: RecordScopes<'s, 'a>,
    /// Class offset of the record being scanned.
    record: u32,
    known: Known,
    /// With [`Known::Kept`]: whether the pattern matches each path, by id.
    matched: Vec<bool>,
    /// Reused for the values of each call site.
    path: Path,
    /// Reused for the callee path of each call site.
    text: String,
}

impl CallsWorker<'_, '_, '_> {
    /// Find out what is known of the record's call sites, before its first
    /// function is scanned.
    fn ask(&mut self) {
        let calls = self.calls;
        let slot = calls.cache.slot(RecordId { entry: calls.entry, class: self.record });
        self.known = match slot.call_paths() {
            Some(paths) => {
                self.matched.clear();
                self.matched.extend(paths.paths().map(|path| calls.pattern.is_match(path)));
                Known::Kept(slot)
            }
            None if calls.sees_all => Known::Collecting(slot, Collected::default()),
            None => Known::Nothing,
        };
    }

    /// Done with the record: leave what was collected in the cache.
    fn leave(&mut self) {
        if let Known::Collecting(slot, collected) = std::mem::replace(&mut self.known, Known::Unasked) {
            if let Some(paths) = collected.finish() {
                self.calls.cache.keep_call_paths(&slot, paths);
            }
        }
    }
}

impl Drop for CallsWorker<'_, '_, '_> {
    /// The scan ends inside its last record.
    fn drop(&mut self) {
        // A scan that is unwinding may have stopped inside a function.
        if !std::thread::panicking() {
            self.leave();
        }
    }
}

/// `callee(arg, arg)`, with `new ` in front of a constructor call.
fn write_call(out: &mut String, callee: &str, site: &CallSite<'_>, mut argument: impl FnMut(&mut String, usize)) {
    if site.construct {
        out.push_str("new ");
    }
    out.push_str(callee);
    out.push('(');
    for index in 0..site.args.len().min(MAX_ARGUMENTS) {
        if index > 0 {
            out.push_str(", ");
        }
        argument(out, index);
    }
    let more = site.args.len() > MAX_ARGUMENTS || site.spread;
    if more {
        out.push_str(if site.args.is_empty() { "…" } else { ", …" });
    }
    out.push(')');
}

impl<'a> Worker<'a> for CallsWorker<'_, '_, 'a> {
    fn record(&mut self, record: &Record<'_, 'a>, _: &mut Vec<RecordHit>) -> bool {
        // Without a readable module record the imports print as `import:?`.
        self.module = record.class.module_record().ok().flatten();
        self.scopes.enter(record.class);
        self.leave();
        self.record = record.class.offset();
        true
    }

    fn function(&mut self, function: &Function<'_, 'a>, hits: &mut Vec<Hit>) -> std::result::Result<(), DecodeError> {
        if matches!(self.known, Known::Unasked) {
            self.ask();
        }
        let method = function.method.offset();
        let mut collected = match &mut self.known {
            Known::Kept(slot) => {
                // No call site of the function matches: nothing to track.
                let sites = slot.call_paths().and_then(|paths| paths.sites_of(method));
                if sites.is_some_and(|sites| !sites.iter().any(|&id| self.matched.get(id as usize) == Some(&true))) {
                    return Ok(());
                }
                None
            }
            Known::Collecting(_, collected) => Some(collected),
            Known::Unasked | Known::Nothing => None,
        };
        let first_site = collected.as_ref().map_or(0, |collected| collected.paths.sites.len());
        let calls = self.calls;
        let names = Names { abc: &calls.abc, module: self.module.as_ref() };
        let (path, callee) = (&mut self.path, &mut self.text);
        let scopes = &self.scopes;
        let lexicals = scopes.of_function(method);
        let entity = |id: u32| function.entity(id);
        let tracked = self.tracker.run(calls.tables.effects(), &function.code, |frame, insn, site| {
            let builder = PathBuilder { frame, function: method, entity: &entity, lexicals: &lexicals };
            let mut describe = |out: &mut String, value| {
                builder.build(value, path);
                scopes.reduce(path);
                names.write(out, path);
            };
            callee.clear();
            describe(callee, site.callee);
            if let Some(collected) = &mut collected {
                collected.site(callee);
            }
            if !calls.pattern.is_match(callee) {
                return;
            }
            let mut text = function.text(insn);
            text.push_str(" ; ");
            write_call(&mut text, callee, site, |out, index| describe(out, site.args[index]));
            hits.push(Hit { pc: pc_of(insn), matched: vec![callee.clone()], text });
        });
        if let Some(collected) = collected {
            // Code that does not decode is tracked again by every search, which reports it.
            collected.function(method, first_site, tracked.is_ok());
        }
        tracked
    }
}
