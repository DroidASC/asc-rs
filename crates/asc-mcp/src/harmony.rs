//! HarmonyOS programs (`.hap` / `.hsp` / `.app` / `.abc`) behind the tools of
//! the DEX side: `listclass`, `getclass`, `getmanifest`, `manifest_summary`,
//! `resources`, `callgraph`, `hierarchy` and `findrefs` (string, prop,
//! global, import, method, number, call, and several of them in one
//! function).
//!
//! This is a thin dispatch ahead of the layer both formats will share. A
//! tool call that names a HarmonyOS program never reaches the DEX tools:
//! [`run`] answers it from the program's [`Session`], or fails with one line
//! that names what does work. A session holds the engine and nothing else:
//! the engine opens in milliseconds, indexes nothing and keeps nothing on
//! disk, so the disk caches of the DEX side take no part. What it holds in
//! memory ([`resident_bytes`]) counts against the memory budget next to the
//! DEX engines, and at most [`MAX_OPEN`] programs stay open; the ids of the
//! others open them again. A program whose files changed is opened again
//! before it answers.

mod callgraph;
mod hierarchy;
mod resources;

pub use callgraph::{function_roots, leaf_roots, no_callers_hint, no_leaf_hint, CallerFilter, TreeText};
pub use hierarchy::no_class_hint;

use crate::res::{self, Filter};
use crate::{
    bool_arg, choice_arg, page_args, page_footer, prepend_notes, str_arg, usize_arg, Call, ToolError, ToolResult, FINDREFS_LIMIT,
    LISTCLASS_LIMIT,
};
use asc_ark_engine::{
    text, Access, ClassQuery, ClassSource, Document, Engine, EngineError, EntryStatus, ListOptions, Manifest, ManifestLine, NameFilter,
    Pattern, Query, RefRow, RefSite,
};
use asc_engine::{names, Threads, MAPPED_CHARGE_DIVISOR};
use serde_json::{json, Value};
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// HarmonyOS programs kept open, whatever they hold: each maps its files.
/// What they hold on the heap is bounded by the memory budget besides.
const MAX_OPEN: usize = 8;
/// ABC entries the description of a program lists by name.
const MAX_ENTRIES_LISTED: usize = 12;
/// Bytes of function names a "no such function" error lists.
const MAX_FUNCTIONS_LISTED: usize = 2 << 10;

/// What an open HarmonyOS program counts for in the memory budget of a
/// resident host, next to the class graphs and resource tables of DEX
/// engines (`asc_engine::Engine::resident_bytes`): what it holds on the heap
/// in full, and the code it reads in place from its mapped files at
/// 1/[`MAPPED_CHARGE_DIVISOR`], as the memory cache charges a DEX entry it
/// maps.
pub fn resident_bytes(engine: &Engine) -> usize {
    let held = engine.memory_use();
    held.heap() + held.mapped / MAPPED_CHARGE_DIVISOR
}

/// For the program a host used last, which stays open whatever its size:
/// when it alone is over `share` (the bytes open programs may hold,
/// `SharedCache::resident_share`), it gives back what its call graph walks
/// computed. The next walk computes what it needs again. (The class graph of
/// a DEX engine cannot be had in part, so there is no such step there.)
pub fn shed_analyses(engine: &Engine, share: usize) {
    if share > 0 && resident_bytes(engine) > share {
        engine.release_analyses();
    }
}

/// Why a HarmonyOS program is no target of a call over many APKs (the
/// section that reports it names the path).
pub(crate) fn not_swept() -> ToolError {
    ToolError("a HarmonyOS program: `apks` / `dir` take Android programs only; pass it alone as `apk`".into())
}

/// What only a HarmonyOS program has is refused on a DEX program, not
/// ignored: `arg` asked for there is an error (`why`: what to add to it).
pub(crate) fn refuse_on_dex(args: &Value, arg: &str, why: &str) -> Result<(), ToolError> {
    if asks_for(args, arg) {
        return Err(ToolError(format!("`{arg}` applies to HarmonyOS programs only{why}")));
    }
    Ok(())
}

/// The tools that work on a HarmonyOS program, as the program's
/// introduction and error messages list them:
/// `listclass, getclass, getmanifest, manifest_summary, resources, callgraph, hierarchy, findrefs kind=string|literal|…`.
fn supported() -> String {
    let tools: Vec<&str> = CARRIED.iter().map(|carried| carried.tool).collect();
    format!("{} kind={}", tools.join(", "), RefKind::names("|"))
}

fn unsupported(what: &str) -> ToolError {
    ToolError(format!("{what} is not supported for HarmonyOS programs yet (supported: {})", supported()))
}

/// As [`unsupported`], for a `findrefs` kind or argument.
fn unsupported_search(what: &str) -> ToolError {
    ToolError(format!("findrefs {what} is not supported for HarmonyOS programs yet (supported kinds: {})", RefKind::names(", ")))
}

fn dex_only(arg: &str) -> ToolError {
    ToolError(format!("`{arg}` is DEX-only"))
}

/// The manifest tools, for the program's introduction.
const MANIFEST_USAGE: &str = "# manifest_summary: module.json, each ability / extension with record=NAME (what getclass takes) and its \
     onXxx callbacks, a `$type:name` reference followed by what it stands for (`label=$string:x(\"value\")`, \
     `pages=$profile:main_pages(PATH)`); kind=\"page\" / kind=\"route\": the page list and the route table, each with its record \
     (`route NAME buildFunction=F source=FILE record=NAME`); kind=\"abc\": the code entries; file=pack.info|pkgContextInfo.json \
     for the other documents (also getmanifest)\n";
/// What keeps `findrefs` and `listclass` to part of a program, for the program's introduction.
const ENTRY_USAGE: &str = "entry=NAME (also listclass): only that abc entry or package (entry.hap), as rows name it: a resource id is \
     unique within one package only";

/// `entries: a, b, ... (N more)`: the ABC entries of the program, for the
/// error of an `entry` that names none of them.
pub fn entries_hint(engine: &Engine) -> String {
    let names: Vec<&str> = engine.entries().map(|entry| entry.name.as_str()).collect();
    let mut hint = format!("entries: {}", names.iter().take(MAX_ENTRIES_LISTED).copied().collect::<Vec<_>>().join(", "));
    if names.len() > MAX_ENTRIES_LISTED {
        hint.push_str(&format!(", ... {} more", names.len() - MAX_ENTRIES_LISTED));
    }
    hint.push_str("; a package names all of its entries");
    hint
}

/// An engine error of a call that `entry` keeps to part of the program.
fn entry_error(engine: &Engine, error: EngineError) -> ToolError {
    match &error {
        EngineError::NoEntry(_) => ToolError(format!("{error} ({})", entries_hint(engine))),
        _ => error.into(),
    }
}

/// A HarmonyOS program of the session.
pub struct Session {
    pub id: String,
    pub path: PathBuf,
    pub engine: Engine,
    /// Tick of its last use: the least recently used program closes first.
    used: AtomicU64,
    /// Whether a reply has said what the program is.
    introduced: AtomicBool,
}

impl Session {
    /// Mark the program as used at `tick` of the server's sessions.
    pub(crate) fn touch(&self, tick: u64) {
        self.used.store(tick, Ordering::Relaxed);
    }

    /// The tick of its last use.
    pub(crate) fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    /// What the first reply about the program says ahead of its answer: that
    /// it is a HarmonyOS program, the tools that apply, its ABC entries and
    /// what the tools take on such a program.
    fn introduction(&self) -> (String, Value) {
        let entries: Vec<_> = self.engine.entries().collect();
        let mut text = format!(
            "# {}: HarmonyOS program, {} abc entr{} (tools: {}; `class` is a record, `method` a function)\n",
            self.id,
            entries.len(),
            if entries.len() == 1 { "y" } else { "ies" },
            supported()
        );
        let status = |status: &EntryStatus| match status {
            EntryStatus::Readable => Cow::Borrowed("readable"),
            EntryStatus::Encrypted => Cow::Borrowed("encrypted"),
            EntryStatus::Unreadable(reason) => Cow::Owned(format!("unreadable: {reason}")),
        };
        let version = |entry: &asc_ark_engine::EntryInfo| entry.version.map(|v| v.to_string());
        let stand_ins = self.engine.stand_ins();
        for entry in entries.iter().take(MAX_ENTRIES_LISTED) {
            let version = version(entry).unwrap_or_else(|| "?".into());
            text.push_str(&format!("# abc | {} | {version} | {} bytes | {}", entry.name, entry.size, status(&entry.status)));
            if let Some(stand_in) = stand_ins.iter().find(|stand_in| stand_in.entry == entry.name) {
                text.push_str(&format!(" (encrypted in the package; served from the decrypted {})", stand_in.file));
            }
            text.push('\n');
        }
        if entries.len() > MAX_ENTRIES_LISTED {
            text.push_str(&format!("# abc | ... {} more (see `program`)\n", entries.len() - MAX_ENTRIES_LISTED));
        }
        // Said here, once per program, instead of in the tool schemas every turn pays for.
        text.push_str(&format!("# findrefs `value` by kind: {}; {ENTRY_USAGE}\n", RefKind::usages()));
        text.push_str(MANIFEST_USAGE);
        text.push_str(resources::USAGE);
        text.push_str(callgraph::USAGE);
        text.push_str(hierarchy::USAGE);
        let entries: Vec<Value> = entries
            .iter()
            .map(|entry| json!({"name": entry.name, "version": version(entry), "size": entry.size, "status": status(&entry.status)}))
            .collect();
        (text, json!({"format": "harmony", "entries": entries, "tools": supported()}))
    }

    /// A tool's reply with what is said of the program ahead of it: on the
    /// first reply what it is and its notes; on every reply the notes of a
    /// program that has entries no query reads (an empty answer must not
    /// read as "nothing there"). That encrypted entries are read from
    /// decrypted files is said once, in one line: nothing is left out.
    fn framed(&self, text: String, mut structured: Value) -> (String, Value) {
        let mut head = String::new();
        let first = !self.introduced.swap(true, Ordering::Relaxed);
        if first {
            let (introduction, program) = self.introduction();
            head.push_str(&introduction);
            structured["program"] = program;
        }
        let notes = self.engine.notes();
        let left_out = self.engine.entries().any(|entry| entry.status != EntryStatus::Readable);
        let stand_in = self.engine.stand_in_note().filter(|_| first);
        if !notes.is_empty() && (first || left_out) {
            head.extend(notes.iter().map(|note| format!("# warning: {note}\n")));
        }
        if let Some(note) = &stand_in {
            head.push_str(&format!("# note: {note}\n"));
        }
        let said: Vec<String> = notes.iter().filter(|_| first || left_out).cloned().chain(stand_in).collect();
        if !said.is_empty() {
            prepend_notes(&mut structured, said);
        }
        (head + &text, structured)
    }
}

/// The HarmonyOS programs of a server: open ones, and the paths of those
/// closed to stay within [`MAX_OPEN`], by apk_id.
#[derive(Default)]
pub(crate) struct Sessions {
    open: Vec<Arc<Session>>,
    closed: HashMap<String, PathBuf>,
}

impl Sessions {
    pub(crate) fn by_id(&self, id: &str) -> Option<&Arc<Session>> {
        self.open.iter().find(|session| session.id == id)
    }

    pub(crate) fn by_path(&self, path: &Path) -> Option<&Arc<Session>> {
        self.open.iter().find(|session| session.path == path)
    }

    /// The path of the closed program `id`, which the caller opens again.
    pub(crate) fn take_closed(&mut self, id: &str) -> Option<PathBuf> {
        self.closed.remove(id)
    }

    /// The open programs.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Arc<Session>> {
        self.open.iter()
    }

    /// Close `session`; its id opens the program again. A call still
    /// answering from it keeps it alive until it is done.
    pub(crate) fn close(&mut self, session: &Arc<Session>) {
        self.open.retain(|open| !Arc::ptr_eq(open, session));
        self.keep_closed(session.id.clone(), session.path.clone());
    }

    /// Remember that `id` names the program at `path`, which is not open.
    pub(crate) fn keep_closed(&mut self, id: String, path: PathBuf) {
        self.closed.insert(id, path);
    }

    /// Open `path` as the program `id`, closing the least recently used
    /// programs beyond [`MAX_OPEN`]. `reopened`: the id was handed out
    /// before, so the program needs no introduction.
    pub(crate) fn open(&mut self, id: String, path: PathBuf, threads: Threads, reopened: bool) -> Result<Arc<Session>, ToolError> {
        let mut engine = Engine::open(&path)?;
        if let Threads::Fixed(threads) = threads {
            engine = engine.with_threads(threads);
        }
        while self.open.len() >= MAX_OPEN {
            let oldest = self.open.iter().min_by_key(|session| session.used()).cloned().expect("MAX_OPEN is not zero");
            self.close(&oldest);
        }
        let session = Arc::new(Session { id, path, engine, used: AtomicU64::new(0), introduced: AtomicBool::new(reopened) });
        self.open.push(Arc::clone(&session));
        Ok(session)
    }

    #[cfg(test)]
    pub(crate) fn open_ids(&self) -> Vec<&str> {
        self.open.iter().map(|session| session.id.as_str()).collect()
    }
}

/// A tool as it answers on a HarmonyOS program.
struct Carried {
    tool: &'static str,
    run: fn(&Session, &Value, &Call) -> ToolResult,
    /// Arguments that only mean something on DEX code.
    dex_only: &'static [&'static str],
}

/// The tools that carry over, `findrefs` last (see [`supported`]). Any other
/// tool is [`unsupported`].
const CARRIED: &[Carried] = &[
    Carried { tool: "listclass", run: listclass, dex_only: &[] },
    Carried { tool: "getclass", run: getclass, dex_only: &["debug_info"] },
    Carried { tool: "getmanifest", run: getmanifest, dex_only: &[] },
    Carried { tool: "manifest_summary", run: manifest_summary, dex_only: &[] },
    Carried { tool: "resources", run: resources::resources, dex_only: &[] },
    Carried { tool: "callgraph", run: callgraph::callgraph, dex_only: &["virtual"] },
    Carried { tool: "hierarchy", run: hierarchy::hierarchy, dex_only: &[] },
    Carried { tool: "findrefs", run: findrefs, dex_only: &["collapse_sdks", "sdk_prefixes"] },
];

/// Whether `args` asks for `key`: given, and not as `null` or `false`.
fn asks_for(args: &Value, key: &str) -> bool {
    !matches!(args.get(key), None | Some(Value::Null | Value::Bool(false))) && args[key] != "false"
}

/// Answer `tool` on the program of `session`.
pub(crate) fn run(session: &Session, tool: &str, args: &Value, call: &Call) -> ToolResult {
    let carried = CARRIED.iter().find(|carried| carried.tool == tool).ok_or_else(|| unsupported(tool))?;
    if let Some(arg) = carried.dex_only.iter().find(|arg| asks_for(args, arg)) {
        return Err(dex_only(arg));
    }
    let (text, structured) = (carried.run)(session, args, call)?;
    Ok(session.framed(text, structured))
}

/// One record per line; a program of several ABC entries also names the entry.
fn listclass(session: &Session, args: &Value, _: &Call) -> ToolResult {
    let (offset, limit) = page_args(args, LISTCLASS_LIMIT)?;
    let prefix = str_arg(args, "prefix")?;
    let options = ListOptions {
        filter: prefix.map(|p| NameFilter::Prefix(p.to_owned())),
        all: bool_arg(args, "all")?.unwrap_or(false),
        entry: str_arg(args, "entry")?.map(str::to_owned),
    };
    let engine = &session.engine;
    let records = engine.list_classes(&options).map_err(|e| entry_error(engine, e))?;
    let total = records.len();
    let page: Vec<_> = records.iter().skip(offset).take(limit).collect();
    let with_entry = engine.has_several_entries();
    let mut text: String = page.iter().map(|record| record.line(with_entry) + "\n").collect();
    let next = (offset + page.len() < total).then_some(offset + page.len());
    text.push_str(&page_footer("records", offset, page.len(), total, next));
    // A prefix spelled as on the DEX side (`com.a`) finds nothing: show what names look like.
    let hint = match prefix {
        Some(prefix) if total == 0 => {
            let every = engine.list_classes(&ListOptions { filter: None, ..options.clone() })?;
            every
                .first()
                .map(|first| format!("no record name starts with {prefix:?}; the program has {} records, e.g. {}", every.len(), first.name))
        }
        _ => None,
    };
    if let Some(hint) = &hint {
        text.push_str(&format!("# hint: {hint}\n"));
    }
    let classes: Vec<Value> = page
        .iter()
        .map(|record| json!({"class": record.name, "entry": record.entry, "functions": record.functions, "source": record.source_file}))
        .collect();
    let structured = json!({
        "apk_id": session.id,
        "total": total,
        "offset": offset,
        "returned": page.len(),
        "next_offset": next,
        "classes": classes,
        "hints": hint.into_iter().collect::<Vec<_>>(),
    });
    Ok((text, structured))
}

/// What `getclass` is asked for: a record, or one function of it.
struct Target<'a> {
    record: &'a str,
    function: Option<&'a str>,
}

impl<'a> Target<'a> {
    /// `class` with `method`, or the location column of a findrefs row
    /// pasted as the class: `RECORD->FUNCTION` or `RECORD->FUNCTION+0xPC`.
    fn parse(class: &'a str, method: Option<&'a str>) -> Target<'a> {
        if method.is_some() {
            return Target { record: class, function: method };
        }
        match class.split_once("->") {
            Some((record, function)) => Target { record, function: Some(function) },
            None => Target { record: class, function: None },
        }
    }
}

/// `function` without the `+0xPC` a findrefs row appends to it.
fn without_pc(function: &str) -> &str {
    match function.rsplit_once("+0x") {
        Some((name, pc)) if !name.is_empty() && !pc.is_empty() && pc.bytes().all(|b| b.is_ascii_hexdigit()) => name,
        _ => function,
    }
}

/// Whether two of the `entry | record` candidates of an ambiguous record are
/// one record in different entries: more of its path cannot tell those apart.
fn several_entries_define(candidates: &[String]) -> bool {
    let records: Vec<&str> = candidates.iter().filter_map(|candidate| candidate.split_once(" | ")).map(|(_, record)| record).collect();
    records.iter().enumerate().any(|(i, record)| records[..i].contains(record))
}

/// `#~@0>#build (Index.build), ...`: the functions of the record disassembled as `source`.
fn function_list(source: &str) -> String {
    let mut headers = source.lines().filter_map(|line| line.strip_prefix(".function "));
    let mut out = String::new();
    while let Some(header) = headers.next() {
        if out.len() + header.len() > MAX_FUNCTIONS_LISTED {
            out.push_str(&format!("... {} more", 1 + headers.count()));
            break;
        }
        match header.split_once("  ; ") {
            Some((raw, restored)) => out.push_str(&format!("{raw} ({restored}), ")),
            None => out.push_str(&format!("{header}, ")),
        }
    }
    out.trim_end_matches(", ").to_owned()
}

/// A record's disassembly, or one function's.
fn getclass(session: &Session, args: &Value, _: &Call) -> ToolResult {
    let class = str_arg(args, "class")?.ok_or_else(|| ToolError("getclass needs `class` (a record, as listclass prints them)".into()))?;
    let target = Target::parse(class, str_arg(args, "method")?);
    let entry = str_arg(args, "entry")?;
    let engine = &session.engine;
    let get = |function: Option<&str>| engine.get_class(&ClassQuery { record: target.record, function, entry });
    let source = match get(target.function) {
        // The function as a findrefs row names it, with the instruction's offset.
        Err(EngineError::NotFound { what: "function", .. }) if target.function.is_some_and(|f| without_pc(f) != f) => {
            get(target.function.map(without_pc))
        }
        other => other,
    };
    let mut source = source.map_err(|e| match &e {
        EngineError::Ambiguous { candidates, .. } if several_entries_define(candidates) => {
            ToolError(format!("{e}\n(name the entry, the first column, with `entry`)"))
        }
        EngineError::NotFound { what: "function", .. } => match get(None) {
            Ok(whole) => ToolError(format!("{e}; its functions: {}", function_list(&whole.text))),
            Err(_) => ToolError(e.to_string()),
        },
        _ => ToolError(e.to_string()),
    })?;
    // As on the DEX side: resource ids are named unless the caller declines.
    if bool_arg(args, "resource_names")?.unwrap_or(true) {
        engine.annotate_resource_ids(&mut source);
    }
    let ClassSource { entry, record, function, text } = source;
    let mut structured = json!({"apk_id": session.id, "class": record, "entry": entry, "source": text});
    if let Some(function) = function {
        structured["methods"] = json!([function]);
    }
    Ok((text, structured))
}

/// The arguments of one condition object, beyond its kind.
struct Spec<'a> {
    value: Cow<'a, str>,
    literal: bool,
    exact: bool,
    access: Option<Access>,
    /// `decl`: import declarations only.
    declarations_only: bool,
}

impl Spec<'_> {
    /// A name pattern, as the CLI reads one: a regex, or with `literal` /
    /// `exact` plain text.
    fn pattern(&self, text: &str) -> Result<Pattern, EngineError> {
        match (self.literal, self.exact) {
            (_, true) => Ok(Pattern::exact(text)),
            (true, false) => Ok(Pattern::contains(text)),
            (false, false) => Pattern::regex(text),
        }
    }
}

/// One kind of reference `findrefs` searches a HarmonyOS program for. A kind
/// the engine learns is one more row of [`RefKind::ALL`].
struct RefKind {
    /// As `kind` and `KIND:VALUE` conditions spell it.
    name: &'static str,
    /// Other spellings models use; case and a trailing `s` do not matter.
    aliases: &'static [&'static str],
    /// The query a condition object asks for.
    query: fn(&Spec<'_>) -> Result<Query, EngineError>,
    /// What `value` is, for the program's introduction.
    usage: &'static str,
}

impl RefKind {
    const ALL: &'static [RefKind] = &[
        RefKind {
            name: "string",
            aliases: &["str", "text"],
            query: |spec| if spec.literal { Ok(Query::string_literal(&*spec.value)) } else { Query::string_regex(&spec.value) },
            usage: "regex (literal=true: text)",
        },
        RefKind { name: "literal", aliases: &[], query: |spec| Ok(Query::string_literal(&*spec.value)), usage: "text" },
        RefKind {
            name: "prop",
            aliases: &["property", "propertie"],
            query: |spec| Ok(Query::Prop { name: spec.pattern(&spec.value)?, access: spec.access }),
            usage: "property name regex (exact / literal), access=read|write|define|call",
        },
        RefKind {
            name: "global",
            aliases: &[],
            query: |spec| Query::global(spec.pattern(&spec.value)?, spec.access),
            usage: "global name regex (exact / literal), access=read|write",
        },
        RefKind {
            name: "import",
            aliases: &[],
            query: |spec| match Query::import(&spec.value, spec.literal)? {
                Query::Import { request, name, .. } => Ok(Query::Import { request, name, declarations_only: spec.declarations_only }),
                other => Ok(other),
            },
            usage: "REQUEST[#NAME], REQUEST a regex over the module request (@ohos:net.http), decl=true for the declarations \
                    only, requests=true for the distinct requests",
        },
        RefKind {
            name: "method",
            aliases: &["function", "func"],
            query: |spec| {
                Query::method(without_pc(&spec.value), |name| if spec.exact { Ok(Pattern::exact(name)) } else { Pattern::regex(name) })
            },
            usage: "[RECORD->]FUNCTION, where it is defined (or `class` + `name`; exact)",
        },
        RefKind {
            name: "number",
            aliases: &["num", "int", "const"],
            query: |spec| Ok(Query::Number(spec.value.parse()?)),
            usage: "1919810, 0x1d4b42, 1.5 or A..B",
        },
        RefKind {
            name: "call",
            aliases: &[],
            query: |spec| Ok(Query::Call(if spec.literal { Pattern::contains(&*spec.value) } else { Pattern::regex(&spec.value)? })),
            usage: "regex over the resolved callee (import:@ohos:net.http#default.createHttp, global:console.log, this.x)",
        },
    ];

    /// The kinds, joined with `separator`.
    fn names(separator: &str) -> String {
        RefKind::ALL.iter().map(|kind| kind.name).collect::<Vec<_>>().join(separator)
    }

    /// `kind: what value is` of every kind, for the program's introduction.
    fn usages() -> String {
        let kinds: Vec<String> = RefKind::ALL.iter().map(|kind| format!("{}: {}", kind.name, kind.usage)).collect();
        format!("{}; all=[conditions]: functions matching every one", kinds.join("; "))
    }

    fn find(kind: &str) -> Result<&'static RefKind, ToolError> {
        let spelled = kind.trim().to_ascii_lowercase();
        let find = |k: &str| RefKind::ALL.iter().find(|kind| kind.name == k || kind.aliases.contains(&k));
        find(&spelled)
            .or_else(|| spelled.strip_suffix('s').and_then(find))
            .ok_or_else(|| unsupported_search(&format!("kind={}", kind.trim())))
    }
}

/// `access` of a condition object.
fn access_arg(args: &Value, kind: &RefKind) -> Result<Option<Access>, ToolError> {
    if str_arg(args, "access")?.is_none() {
        return Ok(None);
    }
    if !matches!(kind.name, "prop" | "global") {
        return Err(ToolError("`access` is only valid for kind=prop and kind=global on HarmonyOS programs".into()));
    }
    const CHOICES: &[(&str, &[&str])] = &[("read", &["get", "load"]), ("write", &["set", "store"]), ("define", &[]), ("call", &[])];
    Ok(Some(match choice_arg(args, "access", "read", CHOICES)? {
        "read" => Access::Read,
        "write" => Access::Write,
        "define" => Access::Define,
        _ => Access::Call,
    }))
}

/// What a findrefs call asks for.
#[derive(Debug)]
enum Search {
    Refs(Query),
    /// `kind=import` with `requests`: the distinct module requests.
    Requests(Pattern),
}

/// Where the next condition of a rule starts after a `&`: at `KIND:` or
/// `!KIND:`. Any other `&` is text: record names and module requests are
/// full of them (`&entry/src/main/ets/pages/Index&`).
fn starts_condition(rest: &str) -> bool {
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('!').unwrap_or(rest);
    let word: &str = rest.split(|c: char| !c.is_ascii_alphabetic()).next().unwrap_or_default();
    !word.is_empty() && rest[word.len()..].starts_with(':')
}

/// The conditions of a rule: its parts between the `&` that join conditions.
fn rule_parts(rule: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    for (at, _) in rule.match_indices('&') {
        let escaped = rule[..at].ends_with('\\');
        if !escaped && starts_condition(&rule[at + 1..]) {
            parts.push(rule[start..at].trim());
            start = at + 1;
        }
    }
    parts.push(rule[start..].trim());
    parts
}

impl Search {
    /// The query a condition object spells: `{kind, value, ...}`.
    fn of_object(args: &Value) -> Result<Search, ToolError> {
        let kind =
            str_arg(args, "kind")?.ok_or_else(|| ToolError(format!("findrefs needs `kind` ({}) and `value`", RefKind::names(", "))))?;
        // Looked up before the value is asked for: a DEX kind names its target otherwise.
        let known = RefKind::find(kind)?;
        if asks_for(args, "fuzzy_class") {
            return Err(dex_only("fuzzy_class"));
        }
        let access = access_arg(args, known)?;
        let flag = |arg: &str| -> Result<bool, ToolError> {
            let asked = bool_arg(args, arg)?.unwrap_or(false);
            if asked && known.name != "import" {
                return Err(ToolError(format!("`{arg}` is only valid for kind=import")));
            }
            Ok(asked)
        };
        let (declarations_only, requests) = (flag("decl")?, flag("requests")?);
        // A function is also named as on the DEX side: `name`, in `class`.
        let name = if known.name == "method" { str_arg(args, "name")? } else { None };
        let value = str_arg(args, "value")?.or(name).ok_or_else(|| ToolError(format!("a {} query needs `value`", known.name)))?;
        let value = match str_arg(args, "class")? {
            Some(record) if known.name == "method" => Cow::Owned(format!("{record}->{value}")),
            _ => Cow::Borrowed(value),
        };
        let spec = Spec {
            value,
            literal: bool_arg(args, "literal")?.unwrap_or(false),
            exact: bool_arg(args, "exact")?.unwrap_or(false),
            access,
            declarations_only,
        };
        match (known.query)(&spec)? {
            Query::Import { .. } if requests && declarations_only => Err(ToolError("give `decl` or `requests`, not both".into())),
            Query::Import { request, name: None, .. } if requests => Ok(Search::Requests(request)),
            Query::Import { .. } if requests => Err(ToolError("`requests` lists module requests: leave out the #NAME".into())),
            query => Ok(Search::Refs(query)),
        }
    }

    /// One `KIND:VALUE` condition, read as the CLI's `findrefs all` reads
    /// it: a string search by the DEX side's syntax (one syntax for both),
    /// any other kind by [`Query::condition`].
    fn of_condition(spec: &str) -> Result<Query, ToolError> {
        if spec.starts_with('!') {
            return Err(unsupported_search("with excluded conditions (`!`)"));
        }
        let Some((kind, value)) = spec.split_once(':') else {
            // Not `KIND:VALUE` at all: the DEX side says what is.
            return Err(names::parse_rule(spec).map_or_else(|e| ToolError(e.to_string()), |_| unsupported_search(spec)));
        };
        let known = RefKind::find(kind)?;
        match known.name {
            "string" | "literal" => match names::parse_condition(&format!("{}:{value}", known.name))? {
                asc_findrefs::Query::String(pattern) => Ok(Query::string_regex(&pattern)?),
                asc_findrefs::Query::StringLiteral(text) => Ok(Query::string_literal(text)),
                _ => Err(unsupported_search(spec)),
            },
            name => Ok(Query::condition(&format!("{name}:{value}"))?),
        }
    }

    /// The conditions a rule string joins with `&`.
    fn of_rule(rule: &str) -> Result<Vec<Query>, ToolError> {
        rule_parts(rule).into_iter().map(Search::of_condition).collect()
    }

    /// What `args` ask for: `kind` + `value`, a `rule`, or `all` (objects
    /// or `KIND:VALUE` strings). One condition is that query itself, as on
    /// the DEX side; several are the functions matching every one.
    fn of_call(args: &Value) -> Result<Search, ToolError> {
        if asks_for(args, "rules") {
            return Err(unsupported_search("rules"));
        }
        if args.get("none").and_then(Value::as_array).is_some_and(|none| !none.is_empty()) {
            return Err(unsupported_search("with excluded conditions (`none`)"));
        }
        let mut queries = match (str_arg(args, "rule")?, args.get("all")) {
            (Some(rule), _) => Search::of_rule(rule)?,
            (None, None | Some(Value::Null)) => return Search::of_object(args),
            (None, Some(Value::Array(_))) if asks_for(args, "kind") => {
                return Err(ToolError("give `kind` (one query) or `all` (several conditions), not both".into()));
            }
            (None, Some(Value::Array(all))) => {
                let mut queries = Vec::new();
                for condition in all {
                    match condition {
                        Value::String(rule) => queries.extend(Search::of_rule(rule)?),
                        Value::Object(_) => match Search::of_object(condition)? {
                            Search::Refs(query) => queries.push(query),
                            Search::Requests(_) => return Err(ToolError("`requests` is a listing, not a condition of `all`".into())),
                        },
                        _ => return Err(ToolError("`all` must be a list of condition objects (or KIND:VALUE strings)".into())),
                    }
                }
                queries
            }
            (None, Some(_)) => return Err(ToolError("`all` must be a list of condition objects (or KIND:VALUE strings)".into())),
        };
        match queries.len() {
            0 => Err(ToolError("`all` needs at least one condition".into())),
            1 => Ok(Search::Refs(queries.remove(0))),
            _ => Ok(Search::Refs(Query::All(queries))),
        }
    }
}

/// What to try when `query` matched nothing: a regex that reads like plain
/// text, and where else the engine finds the name. The engine words its
/// hints for the CLI (`findrefs prop`, `--access`); here they name arguments.
fn no_results_hints(engine: &Engine, query: &Query, cancel: &AtomicBool) -> Vec<String> {
    let as_regex = matches!(query, Query::StringRegex(regex) if regex::escape(regex.as_str()) != regex.as_str());
    let own = as_regex.then(|| "`value` is a regex; literal=true searches it as plain text".to_owned());
    let found = engine.no_results_hints(query, cancel).into_iter().map(|hint| hint.replace("findrefs ", "kind=").replace("--", ""));
    own.into_iter().chain(found).collect()
}

/// A findrefs row as JSON: where the reference is and what it names. A
/// matched string is cut as the row's text cuts it.
fn row_json(entry: &str, row: &RefRow) -> Value {
    let matched: Vec<Cow<'_, str>> = row.matched.iter().map(|matched| text::cut(matched, text::ROW_STRING_BYTES)).collect();
    let mut v = json!({"entry": entry, "record": row.record, "matched": matched, "text": row.text});
    if let RefSite::Code { function, restored, pc } = &row.site {
        v["function"] = json!(function);
        v["name"] = json!(restored);
        v["pc"] = json!(pc);
    } else if let RefSite::Field { name } = &row.site {
        v["field"] = json!(name);
    }
    v
}

/// One row per reference, entry by entry in program order.
fn findrefs(session: &Session, args: &Value, call: &Call) -> ToolResult {
    if asks_for(args, "context") {
        return Err(unsupported_search("context"));
    }
    let query = match Search::of_call(args)? {
        Search::Refs(query) => query,
        Search::Requests(pattern) => return module_requests(session, args, &pattern),
    };
    let (offset, limit) = page_args(args, FINDREFS_LIMIT)?;
    let entry = str_arg(args, "entry")?;
    let engine = &session.engine;
    // Entries left out whole (encrypted, damaged) are named in the program's notes.
    let unreadable = engine.entries_in(entry).map_err(|e| entry_error(engine, e))?;
    let unreadable = unreadable.into_iter().filter(|entry| entry.status != EntryStatus::Readable).count();
    let mut rows = Vec::new();
    let mut errors = Vec::new();
    let mut total = 0;
    let summary = engine.find_refs_in(&query, entry, &call.cancel, &mut |batch| {
        // Only the page is rendered.
        let skip = offset.saturating_sub(total);
        total += batch.rows.len();
        let room = limit - rows.len();
        rows.extend(batch.rows.iter().skip(skip).take(room).map(|row| (row.line(&batch.entry_name), row_json(&batch.entry_name, row))));
        if let Some(error) = batch.error {
            errors.push(format!("{}: {error}", batch.entry_name));
        }
    })?;
    let mut text: String = rows.iter().map(|(line, _)| format!("{line}\n")).collect();
    let next = (offset + rows.len() < total).then_some(offset + rows.len());
    text.push_str(&page_footer("results", offset, rows.len(), total, next));
    for error in &errors {
        text.push_str(&format!("# Warning: {error}\n"));
    }
    let mut hints = if total == 0 && errors.is_empty() { no_results_hints(engine, &query, &call.cancel) } else { Vec::new() };
    if let (Some(entry), true) = (entry, total == 0 && errors.is_empty()) {
        hints.push(format!("entry={entry} kept the search to {} of the {} abc entries", summary.entries, engine.entries().count()));
    }
    for hint in &hints {
        text.push_str(&format!("# hint: {hint}\n"));
    }
    let unsearched = unreadable + errors.len();
    let structured = json!({
        "apk_id": session.id,
        "total": total,
        "hints": hints,
        "offset": offset,
        "returned": rows.len(),
        "next_offset": next,
        "results": rows.into_iter().map(|(_, row)| row).collect::<Vec<_>>(),
        "errors": errors,
        "unsearched_entries": unsearched,
    });
    Ok((text, structured))
}

/// `kind=import` with `requests`: one line per distinct module request.
fn module_requests(session: &Session, args: &Value, pattern: &Pattern) -> ToolResult {
    let (offset, limit) = page_args(args, FINDREFS_LIMIT)?;
    let engine = &session.engine;
    let requests = engine.module_requests_in(Some(pattern), str_arg(args, "entry")?).map_err(|e| entry_error(engine, e))?;
    let total = requests.len();
    let with_entry = engine.has_several_entries();
    let page: Vec<_> = requests.iter().skip(offset).take(limit).collect();
    let mut text: String = page.iter().map(|request| request.line(with_entry) + "\n").collect();
    let next = (offset + page.len() < total).then_some(offset + page.len());
    text.push_str(&page_footer("requests", offset, page.len(), total, next));
    let results: Vec<Value> = page.iter().map(|request| json!({"entry": request.entry, "request": request.request})).collect();
    let structured = json!({
        "apk_id": session.id,
        "total": total,
        "offset": offset,
        "returned": page.len(),
        "next_offset": next,
        "results": results,
    });
    Ok((text, structured))
}

/// `file`: the manifest document it names.
fn document_arg(args: &Value) -> Result<Option<Document>, ToolError> {
    str_arg(args, "file")?.map(|name| name.parse::<Document>().map_err(|e| ToolError(format!("`file`: {e}")))).transpose()
}

/// The manifests of the program, which must have `document` (any, when `None`).
fn manifest_of(session: &Session, document: Option<Document>) -> Result<Manifest, ToolError> {
    let engine = &session.engine;
    let manifest = engine.manifest()?;
    match document {
        Some(document) if !manifest.has(document) => {
            Err(EngineError::NoManifest { path: engine.path().to_path_buf(), document: Some(document.file_name()), bare: false }.into())
        }
        _ => Ok(manifest),
    }
}

/// `module.json` (or the document `file` names) of each package, re-indented.
fn getmanifest(session: &Session, args: &Value, _: &Call) -> ToolResult {
    if asks_for(args, "resolve") {
        return Err(ToolError(
            "`resolve` is DEX-only: module.json is printed as it is; manifest_summary puts what a $type:name reference stands for \
             behind it"
                .into(),
        ));
    }
    let document = document_arg(args)?.unwrap_or(Document::Module);
    let manifest = manifest_of(session, Some(document))?;
    let several = manifest.has_several_packages();
    let documents = manifest.documents(document);
    let mut text = String::new();
    for found in &documents {
        if several {
            text.push_str(&format!("# {}\n", found.heading()));
        }
        text.push_str(found.text.trim_end());
        text.push('\n');
    }
    let listed: Vec<Value> =
        documents.iter().map(|found| json!({"package": found.package, "text": found.text, "also_in": found.also_in})).collect();
    Ok((text, json!({"apk_id": session.id, "file": document.file_name(), "documents": listed})))
}

/// The lines of a summary another application can reach: the `bundle` and
/// `module` lines, exported abilities and extensions with the lines under
/// them, defined permissions and data proxies.
fn reachable(lines: &[ManifestLine]) -> Vec<&ManifestLine> {
    // Whether the `module`, `ability` or `extension` line last seen is kept: the lines under it go with it.
    let mut owner_kept = false;
    lines
        .iter()
        .filter(|line| match line.text.split(' ').next().unwrap_or_default() {
            "bundle" | "define-permission" | "proxy-data" | "note" => true,
            "module" => {
                owner_kept = true;
                true
            }
            "ability" | "extension" => {
                owner_kept = line.text.contains(" exported=true ");
                owner_kept
            }
            "callbacks" | "skill" | "uri" | "deeplink" | "metadata" => owner_kept,
            _ => false,
        })
        .collect()
}

/// The manifest's facts, one per line, each `srcEntry` joined to its record.
/// The arguments of the DEX tool carry over: `filter` (exported by default,
/// unless `kind` / `name` / `file` narrow the summary), `kind`, `name`, `offset`.
fn manifest_summary(session: &Session, args: &Value, _: &Call) -> ToolResult {
    let document = document_arg(args)?;
    let kinds = res::kinds_arg(args)?;
    let name = res::name_arg(args)?;
    let narrowed = !kinds.is_empty() || name.is_some() || document.is_some();
    let filter = res::filter_arg(args, if narrowed { Filter::All } else { Filter::Exported })?;
    let offset = usize_arg(args, "offset")?.unwrap_or(0);
    let manifest = manifest_of(session, document)?;
    let several = manifest.has_several_packages();
    let lines = manifest.summary_lines(document);
    let kept: Vec<&ManifestLine> = match filter {
        Filter::All => lines.iter().collect(),
        Filter::Exported => reachable(&lines),
    };
    let records: Vec<String> = kept
        .into_iter()
        .filter(|line| kinds.is_empty() || kinds.iter().any(|kind| line.text.split(' ').next() == Some(kind.as_str())))
        .filter(|line| name.as_ref().is_none_or(|name| name.is_match(&line.text)))
        .map(|line| line.line(several))
        .collect();
    let mut text = String::new();
    if filter == Filter::Exported && str_arg(args, "filter")?.is_none() {
        text.push_str(
            "# filter=exported (the default without kind / name / file): exported abilities and extensions with their record; \
             filter=\"all\" for every line (permissions, pages, routes, pack.info), kind / name to narrow (kind=\"route\"), \
             file=\"pkgContextInfo.json\" for the package table\n",
        );
    }
    for record in records.iter().skip(offset) {
        text.push_str(record);
        text.push('\n');
    }
    let shown = records.len().saturating_sub(offset);
    if offset > 0 || narrowed {
        text.push_str(&format!("# records {offset}..{} of {}\n", offset + shown, records.len()));
    }
    let mut structured = manifest.json();
    if filter == Filter::Exported {
        for package in structured["packages"].as_array_mut().into_iter().flatten() {
            if let Some(components) = package["components"].as_array_mut() {
                components.retain(|component| component["exported"] == true);
            }
            // The lines left these out too; a route table has hundreds of entries.
            if let Some(package) = package.as_object_mut() {
                package.remove("pages");
                package.remove("routes");
            }
        }
    }
    structured["apk_id"] = json!(session.id);
    structured["records_total"] = json!(records.len());
    Ok((text, structured))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_come_apart_at_the_arrow() {
        let t = Target::parse("&a/b&->#~@0>#build+0x12", None);
        assert_eq!((t.record, t.function), ("&a/b&", Some("#~@0>#build+0x12")));
        let t = Target::parse("pages/Index", Some("Index.build"));
        assert_eq!((t.record, t.function), ("pages/Index", Some("Index.build")));
        assert_eq!(Target::parse("pages/Index", None).function, None);
        assert_eq!(without_pc("#~@0>#build+0x12"), "#~@0>#build");
        assert_eq!(without_pc("#~@0>#build"), "#~@0>#build");
        assert_eq!(without_pc("a+0xzz"), "a+0xzz");
    }

    /// The search `args` ask for, as its debug text (a `Query` does not compare).
    fn asked(args: Value) -> Result<String, String> {
        Search::of_call(&args).map(|search| format!("{search:?}")).map_err(|e| e.0)
    }

    #[test]
    fn conditions_come_from_every_spelling() {
        let regex = asked(json!({"kind": "string", "value": "https?://"}));
        assert_eq!(regex, Ok("Refs(StringRegex(Regex(\"https?://\")))".to_owned()));
        assert_eq!(asked(json!({"rule": "string:https?://"})), regex);
        assert_eq!(asked(json!({"all": ["string:https?://"]})), regex);
        assert_eq!(asked(json!({"all": [{"kind": "string", "value": "https?://"}]})), regex);
        assert_eq!(asked(json!({"kind": "Strings", "value": "https?://"})), regex);
        assert_eq!(asked(json!({"rule": "literal:a?b"})), Ok("Refs(StringLiteral(\"a?b\"))".to_owned()));
        assert_eq!(asked(json!({"kind": "text", "value": "a?b", "literal": true})), asked(json!({"rule": "literal:a?b"})));

        // An object and the condition string of the same query are one query.
        let same: [(Value, &str); 9] = [
            (json!({"kind": "prop", "value": "request", "exact": true}), "prop:=request"),
            (json!({"kind": "property", "value": "^req"}), "prop:^req"),
            (json!({"kind": "global", "value": "console", "exact": true}), "global:=console"),
            (json!({"kind": "import", "value": "@ohos:net\\.http#default"}), "import:@ohos:net\\.http#default"),
            (json!({"kind": "method", "value": "&a/b&->#~@0>#build+0x1b", "exact": true}), "method:&a/b&->=#~@0>#build"),
            (json!({"kind": "method", "name": "build", "class": "pages/Index"}), "method:pages/Index->build"),
            (json!({"kind": "function", "value": "build"}), "methods:build"),
            (json!({"kind": "number", "value": "0x10..0x1f"}), "number:16..31"),
            (json!({"kind": "call", "value": "^global:console\\."}), "call:^global:console\\."),
        ];
        for (object, rule) in same {
            let by_object = asked(object.clone());
            assert!(by_object.is_ok(), "{object}: {by_object:?}");
            assert_eq!(by_object, asked(json!({"rule": rule})), "{object}");
            assert_eq!(by_object, asked(json!({"all": [object]})), "{rule}");
        }
        let with = |extra: Value, expected: &str| {
            let found = asked(extra.clone()).unwrap();
            assert!(found.contains(expected), "{extra}: {found}");
        };
        with(json!({"kind": "prop", "value": "x", "access": "Write"}), "access: Some(Write)");
        with(json!({"kind": "prop", "value": "x", "access": "call"}), "access: Some(Call)");
        with(json!({"kind": "prop", "value": "a.b", "literal": true}), "Contains(\"a.b\")");
        with(json!({"kind": "global", "value": "x", "access": "read"}), "access: Some(Read)");
        with(json!({"kind": "import", "value": "@ohos:net.http", "literal": true, "decl": true}), "declarations_only: true");
        with(json!({"kind": "import", "value": "@ohos:net.http", "literal": true}), "Contains(\"@ohos:net.http\")");
        with(json!({"kind": "import", "value": "net", "requests": true}), "Requests(Regex(");
        with(json!({"kind": "call", "value": "a.b(", "literal": true}), "Call(Contains(\"a.b(\"))");
    }

    #[test]
    fn several_conditions_are_one_conjunction() {
        let both = asked(json!({"rule": "prop:=request & string:https?://"})).unwrap();
        assert!(both.starts_with("Refs(All([Prop {") && both.ends_with("StringRegex(Regex(\"https?://\"))]))"), "{both}");
        assert_eq!(asked(json!({"rule": "prop:=request&string:https?://"})).unwrap(), both);
        assert_eq!(asked(json!({"all": ["prop:=request", "string:https?://"]})).unwrap(), both);
        assert_eq!(asked(json!({"all": ["prop:=request & string:https?://"]})).unwrap(), both);
        let objects = json!({"all": [{"kind": "prop", "value": "request", "exact": true}, {"kind": "string", "value": "https?://"}]});
        assert_eq!(asked(objects).unwrap(), both);

        // Only `&` ahead of a KIND: joins: record names and module requests keep theirs.
        assert_eq!(
            rule_parts("method:&a/b&->f & call:import:@normalized:N&&&a/b&#x"),
            ["method:&a/b&->f", "call:import:@normalized:N&&&a/b&#x"]
        );
        assert_eq!(rule_parts("string:a&b"), ["string:a&b"]);
        assert_eq!(rule_parts(r"string:a\&literal:b"), [r"string:a\&literal:b"]);
        assert_eq!(rule_parts("string:a & !literal:b"), ["string:a", "!literal:b"]);
    }

    #[test]
    fn what_cannot_be_asked_says_why() {
        let kinds = "string, literal, prop, global, import, method, number, call";
        let not_yet = |what: &str| Err(format!("findrefs {what} is not supported for HarmonyOS programs yet (supported kinds: {kinds})"));
        assert_eq!(asked(json!({"kind": "field", "class": "La;", "name": "b"})), not_yet("kind=field"));
        assert_eq!(asked(json!({"rule": "type:La;"})), not_yet("kind=type"));
        assert_eq!(asked(json!({"rule": "string:a & type:La;"})), not_yet("kind=type"));
        assert_eq!(asked(json!({"rule": "string:a & !string:b"})), not_yet("with excluded conditions (`!`)"));
        assert_eq!(asked(json!({"kind": "string", "value": "a", "none": ["string:b"]})), not_yet("with excluded conditions (`none`)"));
        assert_eq!(asked(json!({"rules": [{"kind": "string", "value": "a"}]})), not_yet("rules"));
        assert_eq!(asked(json!({"kind": "string"})), Err("a string query needs `value`".to_owned()));
        assert_eq!(asked(json!({})), Err(format!("findrefs needs `kind` ({kinds}) and `value`")));
        assert_eq!(asked(json!({"rule": "nonsense"})).map_err(|e| e.contains("nonsense")), Err(true));
        assert_eq!(asked(json!({"rule": "prop:"})), Err("prop: needs a value".to_owned()));
        assert_eq!(asked(json!({"all": []})), Err("`all` needs at least one condition".to_owned()));
        assert_eq!(
            asked(json!({"kind": "string", "value": "a", "all": ["string:b"]})),
            Err("give `kind` (one query) or `all` (several conditions), not both".to_owned())
        );
        let only = "`access` is only valid for kind=prop and kind=global on HarmonyOS programs";
        assert_eq!(asked(json!({"kind": "string", "value": "a", "access": "read"})), Err(only.to_owned()));
        assert_eq!(
            asked(json!({"kind": "prop", "value": "a", "access": "delete"})).map_err(|e| e.contains("read, write, define, call")),
            Err(true)
        );
        assert_eq!(
            asked(json!({"kind": "global", "value": "a", "access": "call"})),
            Err("a global is read or written, not call: use `prop` or `call` for members".to_owned())
        );
        assert_eq!(
            asked(json!({"kind": "prop", "value": "a", "requests": true})),
            Err("`requests` is only valid for kind=import".to_owned())
        );
        assert_eq!(asked(json!({"kind": "prop", "value": "a", "decl": true})), Err("`decl` is only valid for kind=import".to_owned()));
        assert_eq!(
            asked(json!({"kind": "import", "value": "net#default", "requests": true})),
            Err("`requests` lists module requests: leave out the #NAME".to_owned())
        );
        assert_eq!(
            asked(json!({"kind": "import", "value": "net", "requests": true, "decl": true})),
            Err("give `decl` or `requests`, not both".to_owned())
        );
        assert_eq!(
            asked(json!({"kind": "method", "name": "b", "class": "a", "fuzzy_class": true})),
            Err("`fuzzy_class` is DEX-only".to_owned())
        );
        assert_eq!(asked(json!({"kind": "number", "value": "abc"})).map_err(|e| e.contains("is not a number")), Err(true));
        assert_eq!(
            supported(),
            "listclass, getclass, getmanifest, manifest_summary, resources, callgraph, hierarchy, findrefs \
             kind=string|literal|prop|global|import|method|number|call"
        );
    }

    #[test]
    fn the_exported_filter_keeps_whole_component_blocks() {
        let line = |text: &str| ManifestLine { package: "entry.hap".into(), text: text.into() };
        let lines: Vec<ManifestLine> = [
            "bundle com.x versionCode=1",
            "module entry type=entry record=&entry/src/main/ets/Stage&",
            "callbacks entry record=&entry/src/main/ets/Stage& functions=Stage.onCreate",
            "module-metadata name=a value=b",
            "request-permission ohos.permission.INTERNET reason=- when=- abilities=-",
            "define-permission com.x.P grantMode=-",
            "ability Main exported=true (explicit) permissions=- skills=1 srcEntry=./ets/Main.ets record=&entry/src/main/ets/Main&",
            "callbacks Main record=&entry/src/main/ets/Main& functions=Main.onCreate",
            "skill Main skill=1 actions=- entities=- uris=1 permissions=-",
            "deeplink Main x://open",
            "extension Inner type=form exported=false (default) permissions=- skills=0 srcEntry=./ets/Inner.ets record=- (no record a or b)",
            "metadata Inner name=ohos.extension.form resource=$profile:form_config",
            "pack-app com.x bundleType=- versionCode=1 versionName=1",
            "package-table packages=3 native=1 with-records=1 records=2 unlocated=0 file=pkgContextInfo.json",
            "note module.json: something",
        ]
        .map(line)
        .into();
        let kept: Vec<&str> = reachable(&lines).into_iter().map(|line| line.text.split(' ').next().unwrap()).collect();
        assert_eq!(kept, ["bundle", "module", "callbacks", "define-permission", "ability", "callbacks", "skill", "deeplink", "note"]);
    }

    #[test]
    fn function_lists_stay_short() {
        let source = ".record r\n.function #~@0>#build  ; Index.build\n; x\n  0000  lda v0\n\n.function func_main_0\n";
        assert_eq!(function_list(source), "#~@0>#build (Index.build), func_main_0");
        let many: String = (0..400).map(|i| format!(".function f{i:0>20}\n")).collect();
        let listed = function_list(&many);
        assert!(listed.len() <= MAX_FUNCTIONS_LISTED + 32 && listed.ends_with(" more"), "{listed}");
    }
}
