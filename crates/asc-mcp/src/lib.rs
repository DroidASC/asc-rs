//! MCP server over stdio: one resident process that keeps APKs open.
//!
//! The CLI pays process start, APK open and DEX inflation on every command.
//! An agent session asks dozens of questions about the same APK, so this
//! server keeps one [`Engine`] per opened APK, all sharing one in-memory LRU
//! (and the on-disk cache), and answers each tool call from the inflated DEX
//! and locator tables already resident.
//!
//! Transport: JSON-RPC 2.0, one message per line on stdin/stdout (the MCP
//! stdio transport). `initialize`, `ping` and `tools/list` are answered as
//! they are read; tool calls run concurrently, so a slow query never holds up
//! a `ping` or a quick lookup, and replies may come back out of order (each
//! carries its request `id`). The APK a call opens gets its `apk_id` before
//! the next message is read, and `close_apk` waits for the calls already running.
//! A panic inside a tool call becomes an `isError` result. Supported methods:
//! `initialize`, `notifications/initialized` (and any other notification,
//! ignored), `notifications/cancelled`, `ping`, `tools/list` and `tools/call`.
//! Tool failures are reported as results with `isError: true`; the server
//! keeps running. `notifications/cancelled` stops the named call: work not
//! yet started is skipped and, as the protocol asks, the call gets no reply.
//!
//! Tool results carry the CLI's text (same line formats as `droidasc`) as
//! `content`, and the same data as `structuredContent`.
//!
//! `findrefs`, `listclass` and `open_apk` also take many APKs at once
//! (`apks` or `dir`, see [`multi`]): the reply has one section per APK, cut
//! to a byte budget, with a `cursor` to page through the rest.

pub mod class_text;
mod lenient;
pub mod multi;
pub mod output;
mod res;
mod rules;

use asc_engine::{
    hints, names, CacheConfig, CallQuery, Claim, CompiledQuery, DexDedup, Direction, Engine, InflateLimits, Matched, RefBatch, RefContext,
    RefResult, SharedCache, SmaliOptions, Threads,
};
use asc_findrefs::Query;
use class_text::ClassText;
use multi::{Report, Reports, Section};
use output::{SpillDir, Structured, FITTED, FULL};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::io::{self, BufRead, Write};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Instant;

/// Protocol version answered when the client does not name one.
pub const DEFAULT_PROTOCOL_VERSION: &str = "2025-06-18";

const FINDREFS_LIMIT: usize = 500;
const LISTCLASS_LIMIT: usize = 1000;
const CALLGRAPH_DEPTH: usize = 2;
const CALLGRAPH_MAX_NODES: usize = 200;
/// Rows shown per APK in a multi-APK reply.
const PER_APK: usize = 10;
/// Package segments `group: "package"` merges hits by.
const PACKAGE_DEPTH: usize = 3;

/// Server settings.
pub struct Options {
    pub threads: Threads,
    pub debug: bool,
    /// Shared by every opened APK.
    pub cache: CacheConfig,
    /// Caps on inflating entries (zip bombs); every APK of a session is untrusted.
    pub limits: InflateLimits,
    /// Package prefixes folded by `collapse_sdks` (`com.foo` or `Lcom/foo/`).
    pub sdk_prefixes: Vec<String>,
    /// Where replies over their budget are written (`spill`); `None` pages them.
    pub spill_dir: Option<PathBuf>,
    /// Disk budget of `spill_dir`.
    pub spill_bytes: u64,
    pub structured: Structured,
}

impl Options {
    /// Guarded inflate limits, the built-in SDK prefixes, replies spilled
    /// under the cache directory (see [`SpillDir::default_dir`]) and the
    /// full structured results.
    pub fn new(threads: impl Into<Threads>, debug: bool, cache: CacheConfig) -> Options {
        let spill_dir = SpillDir::default_dir(cache.disk.as_ref().map(|d| d.dir()));
        Options {
            threads: threads.into(),
            debug,
            cache,
            limits: InflateLimits::guarded(),
            sdk_prefixes: multi::DEFAULT_SDK_PREFIXES.iter().map(|p| p.to_string()).collect(),
            spill_dir: Some(spill_dir),
            spill_bytes: output::SPILL_BUDGET,
            structured: Structured::Full,
        }
    }
}

/// Serve MCP requests from `input` until it closes, writing responses to `output`.
pub fn serve(input: impl BufRead, output: impl Write + Send, opts: Options) -> io::Result<()> {
    let server = Server::new(opts);
    let output = Mutex::new(output);
    // The first failed write, reported once input ends.
    let write_error = Mutex::new(None);
    let send = |reply: Option<Value>| {
        let Some(reply) = reply else { return };
        let mut line = reply.to_string();
        line.push('\n');
        let mut out = output.lock().unwrap_or_else(PoisonError::into_inner);
        if let Err(e) = out.write_all(line.as_bytes()).and_then(|()| out.flush()) {
            lock(&write_error).get_or_insert(e);
        }
    };
    // Cancel flags of the calls running, by request id (as JSON text).
    let inflight: Mutex<HashMap<String, Arc<AtomicBool>>> = Mutex::new(HashMap::new());
    thread::scope(|scope| -> io::Result<()> {
        let mut running = Vec::new();
        for line in input.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            running.retain(|h: &thread::ScopedJoinHandle<()>| !h.is_finished());
            match classify(&line) {
                Message::Cancel(id) => {
                    if let Some(flag) = lock(&inflight).get(&id) {
                        flag.store(true, Ordering::Relaxed);
                    }
                }
                Message::Other => send(server.handle_line(&line)),
                Message::Call { name, .. } if name == "close_apk" => {
                    for h in running.drain(..) {
                        let _ = h.join();
                    }
                    send(server.handle_line(&line));
                }
                Message::Call { id, .. } => {
                    // Open the APK a call names (open_apk, or any tool given a
                    // new `apk` path) before reading on, so apk_ids follow request
                    // order and later calls can use them; a failure is reported by
                    // the call itself.
                    let _ = server.register(&line);
                    let cancel = Arc::new(AtomicBool::new(false));
                    lock(&inflight).insert(id.clone(), Arc::clone(&cancel));
                    let (server, send, inflight) = (&server, &send, &inflight);
                    running.push(scope.spawn(move || {
                        let reply = server.handle_call(&line, &Call { cancel: Arc::clone(&cancel) });
                        lock(inflight).remove(&id);
                        if !cancel.load(Ordering::Relaxed) {
                            send(reply);
                        }
                    }));
                }
            }
        }
        Ok(())
    })?;
    match write_error.into_inner().unwrap_or_else(PoisonError::into_inner) {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// How the reader thread routes a message.
enum Message {
    /// A `tools/call` request: its id (as JSON text) and tool name.
    Call { id: String, name: String },
    /// `notifications/cancelled` for the request with this id.
    Cancel(String),
    /// Anything else, answered inline.
    Other,
}

fn classify(line: &str) -> Message {
    let Ok(msg) = serde_json::from_str::<Value>(line) else { return Message::Other };
    let method = msg.get("method").and_then(Value::as_str);
    let params = msg.get("params");
    match (method, msg.get("id")) {
        (Some("tools/call"), Some(id)) => match params.and_then(|p| p.get("name")).and_then(Value::as_str) {
            Some(name) => Message::Call { id: id.to_string(), name: name.to_string() },
            None => Message::Other,
        },
        (Some("notifications/cancelled"), None) => match params.and_then(|p| p.get("requestId")) {
            Some(id) => Message::Cancel(id.to_string()),
            None => Message::Other,
        },
        _ => Message::Other,
    }
}

/// Lock `m` even if a panicking tool call poisoned it; the guarded state is
/// only ever left consistent.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Per-call state handed to every tool.
pub struct Call {
    /// Raised by `notifications/cancelled`; long tools poll it.
    pub cancel: Arc<AtomicBool>,
}

impl Call {
    fn check(&self) -> Result<(), ToolError> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err(ToolError("cancelled".into()));
        }
        Ok(())
    }
}

type ToolFn = fn(&Server, &Value, &Call) -> ToolResult;

/// One MCP tool: its handler and its `tools/list` entry.
struct Tool {
    name: &'static str,
    run: ToolFn,
    /// `{"description", "inputSchema"}`.
    definition: fn() -> Value,
}

/// Every tool, in `tools/list` order.
const TOOLS: &[Tool] = &[
    Tool { name: "open_apk", run: Server::open_apk, definition: defs::open_apk },
    Tool { name: "close_apk", run: Server::close_apk, definition: defs::close_apk },
    Tool { name: "getclass", run: Server::getclass, definition: defs::getclass },
    Tool { name: "findrefs", run: Server::findrefs, definition: defs::findrefs },
    Tool { name: "callgraph", run: Server::callgraph, definition: defs::callgraph },
    Tool { name: "hierarchy", run: Server::hierarchy, definition: rules::defs::hierarchy },
    Tool { name: "listclass", run: Server::listclass, definition: defs::listclass },
    Tool { name: "getmanifest", run: Server::getmanifest, definition: defs::getmanifest },
    Tool { name: "manifest_summary", run: Server::manifest_summary, definition: res::defs::manifest_summary },
    Tool { name: "resources", run: Server::resources, definition: res::defs::resources },
];

/// An APK of the session.
pub struct OpenApk {
    pub id: String,
    pub path: PathBuf,
    pub engine: Engine,
}

struct Sessions {
    apks: Vec<Arc<OpenApk>>,
    next_id: usize,
}

/// Session state: the opened APKs and the cache they share. Tool calls take
/// `&self` and may run concurrently.
pub struct Server {
    threads: Threads,
    debug: bool,
    limits: InflateLimits,
    /// Descriptor prefixes (`Lcom/foo/`) of `collapse_sdks`.
    sdk_prefixes: Vec<String>,
    // Declared before `cache` so engines drop first; dropping the shared
    // cache then lands their queued disk writes.
    sessions: Mutex<Sessions>,
    /// Multi-APK reports, for `cursor`.
    reports: Mutex<Reports>,
    spill: Option<SpillDir>,
    structured: Structured,
    cache: SharedCache,
}

/// A tool failure, reported to the client as `isError: true`.
pub struct ToolError(pub String);

impl<E: std::fmt::Display> From<E> for ToolError {
    fn from(e: E) -> ToolError {
        ToolError(e.to_string())
    }
}

/// A tool's text (`content`) and data (`structuredContent`).
pub type ToolResult = Result<(String, Value), ToolError>;

/// Counts over the APKs of a sweep.
/// One APK of a findrefs sweep: its entries and their dedup claims, or the
/// batches L3 already holds (`claims` empty).
struct SweepTarget {
    target: asc_engine::SearchTarget,
    claims: Vec<Claim>,
    cached: Mutex<Option<Vec<RefBatch>>>,
}

#[derive(Default)]
pub struct SweepStats {
    pub with_hits: usize,
    pub hits: usize,
    pub errors: usize,
    /// APKs were dropped from memory as they finished.
    pub released: bool,
}

impl Server {
    pub fn new(opts: Options) -> Server {
        Server {
            threads: opts.threads,
            debug: opts.debug,
            limits: opts.limits,
            sdk_prefixes: opts.sdk_prefixes.iter().map(|p| multi::normalize_prefix(p)).collect(),
            sessions: Mutex::new(Sessions { apks: Vec::new(), next_id: 1 }),
            reports: Mutex::new(Reports::default()),
            spill: opts.spill_dir.map(|d| SpillDir::new(d, opts.spill_bytes)),
            structured: opts.structured,
            cache: SharedCache::new(opts.cache, |m| eprintln!("{m}")),
        }
    }

    /// Handle one JSON-RPC message; `None` for notifications.
    pub fn handle_line(&self, line: &str) -> Option<Value> {
        self.handle_call(line, &Call { cancel: Arc::new(AtomicBool::new(false)) })
    }

    /// [`Server::handle_line`] for a message whose tool call `call` can cancel.
    pub fn handle_call(&self, line: &str, call: &Call) -> Option<Value> {
        let msg: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => return Some(error_reply(Value::Null, -32700, &format!("parse error: {e}"))),
        };
        let Some(obj) = msg.as_object() else {
            return Some(error_reply(Value::Null, -32600, "invalid request: expected a JSON object"));
        };
        let id = obj.get("id").cloned();
        let method = obj.get("method").and_then(Value::as_str);
        let params = obj.get("params").cloned().unwrap_or(Value::Null);
        let (Some(id), Some(method)) = (id, method) else {
            // A notification (or a response to us, which we never ask for).
            return None;
        };
        Some(match self.request(method, &params, call) {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err((code, msg)) => error_reply(id, code, &msg),
        })
    }

    /// Open (register) the APK a `tools/call` line names, without running it.
    fn register(&self, line: &str) -> Result<(), ToolError> {
        let msg: Value = serde_json::from_str(line)?;
        let args = msg.get("params").and_then(|p| p.get("arguments")).cloned().unwrap_or(Value::Null);
        self.resolve(&args).map(drop)
    }

    fn request(&self, method: &str, params: &Value, call: &Call) -> Result<Value, (i64, String)> {
        match method {
            "initialize" => {
                let version = params.get("protocolVersion").and_then(Value::as_str).unwrap_or(DEFAULT_PROTOCOL_VERSION);
                Ok(json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "droidasc", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": "Droid ASC: Android APK code search and smali. Pass `apk` (a path) to any tool, or \
                        open_apk once and use its apk_id. Usual flow: findrefs with context=\"method\" (finds the code \
                        and shows it, often no getclass needed) -> getclass with method=\"name\" for more of a class \
                        (a large class comes as an outline first) -> callgraph / hierarchy to follow calls. \
                        manifest_summary gives the attack surface (kind=\"provider\" etc. to narrow); resources reads \
                        resources.arsc and res/xml. Many APKs: give apks (paths) or dir (+ glob) instead of apk; the \
                        reply has a section per APK (per_apk rows each) and a cursor for its next page. Replies stay \
                        within max_bytes (16 KB): beyond it the full output is written to a file whose path the reply \
                        gives (read the lines you need), or with spill=\"never\" paged (page=N). A `more` / `next` hint \
                        is the complete arguments of the next call. Booleans default to false unless described otherwise.",
                }))
            }
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": tool_definitions()})),
            "tools/call" => {
                let name = params.get("name").and_then(Value::as_str).ok_or((-32602, "tools/call needs `name`".to_string()))?;
                let empty = Value::Object(Map::new());
                let args = params.get("arguments").unwrap_or(&empty);
                if !args.is_object() {
                    return Err((-32602, "`arguments` must be an object".into()));
                }
                let Some(tool) = TOOLS.iter().find(|t| t.name == name) else {
                    return Err((-32602, format!("unknown tool: {name}")));
                };
                let normalized = lenient::normalize(name, args);
                let args = normalized.as_ref().unwrap_or(args);
                // A `more` / `next` hint passed back as the cursor is a call.
                let followed = follow_up(args);
                let args = followed.as_ref().unwrap_or(args);
                // A bug in the engine must not take the whole session down.
                let result = guarded(name, || {
                    let (text, structured) = match str_arg(args, "cursor")? {
                        Some(cursor) => self.more(name, cursor)?,
                        None => (tool.run)(self, args, call)?,
                    };
                    output::fit(name, args, text, structured, self.spill.as_ref())
                });
                Ok(match result {
                    Ok(f) => {
                        let mut content = vec![json!({"type": "text", "text": f.text})];
                        content.extend(f.link);
                        json!({
                            "content": content,
                            "structuredContent": self.structured.apply(f.structured),
                            "isError": false,
                        })
                    }
                    Err(ToolError(msg)) => json!({
                        "content": [{"type": "text", "text": format!("Error: {msg}")}],
                        "isError": true,
                    }),
                })
            }
            _ => Err((-32601, format!("method not found: {method}"))),
        }
    }

    // ---- APK sessions ------------------------------------------------------

    fn index_of(sessions: &Sessions, args: &Value) -> Result<Option<usize>, ToolError> {
        if let Some(id) = str_arg(args, "apk_id")? {
            return match sessions.apks.iter().position(|a| a.id == id) {
                Some(i) => Ok(Some(i)),
                None => Err(ToolError(format!("no open APK with apk_id {id:?}"))),
            };
        }
        match str_arg(args, "apk")? {
            Some(path) => {
                let path = canonical(path)?;
                Ok(sessions.apks.iter().position(|a| a.path == path))
            }
            None => Err(ToolError("pass `apk_id` (from open_apk) or `apk` (a path)".into())),
        }
    }

    /// The APK `args` names, opening it when given by a path not yet open.
    fn resolve(&self, args: &Value) -> Result<Arc<OpenApk>, ToolError> {
        // Held while opening, so two calls naming a new path get one session.
        let mut sessions = lock(&self.sessions);
        if let Some(i) = Self::index_of(&sessions, args)? {
            return Ok(Arc::clone(&sessions.apks[i]));
        }
        // `index_of` only returns `Ok(None)` for an `apk` path.
        let path = canonical(str_arg(args, "apk")?.unwrap_or_default())?;
        self.open_locked(&mut sessions, path)
    }

    /// The session for `path`, opening it if needed.
    pub fn open_path(&self, path: &Path) -> Result<Arc<OpenApk>, ToolError> {
        let path = canonical(&path.to_string_lossy())?;
        let mut sessions = lock(&self.sessions);
        if let Some(apk) = sessions.apks.iter().find(|a| a.path == path) {
            return Ok(Arc::clone(apk));
        }
        self.open_locked(&mut sessions, path)
    }

    fn open_locked(&self, sessions: &mut Sessions, path: PathBuf) -> Result<Arc<OpenApk>, ToolError> {
        let engine = Engine::new(&path)
            .with_threads(self.threads)
            .with_debug(self.debug)
            .with_logger(|m| eprintln!("{m}"))
            .with_limits(self.limits)
            .with_shared_cache(&self.cache);
        // Fail now on a file that is not a readable APK, not on the first query.
        engine.dex_entries()?;
        let id = format!("apk{}", sessions.next_id);
        sessions.next_id += 1;
        let apk = Arc::new(OpenApk { id, path, engine });
        sessions.apks.push(Arc::clone(&apk));
        Ok(apk)
    }

    fn open_apk(&self, args: &Value, call: &Call) -> ToolResult {
        if let Some(paths) = multi::targets(args)? {
            return self.open_apks(args, call, &paths);
        }
        let t = Instant::now();
        let apk = self.resolve(args)?;
        let warm = bool_arg(args, "warm")?.unwrap_or(true);
        let dex_entries = apk.engine.dex_entries()?.len();
        let mut classes = Value::Null;
        let mut prebuild = false;
        if warm {
            classes = json!(warm_classes(&apk)?);
            // The locator tables too, in the background, so the first query
            // of each kind skips its builds (queries take priority).
            if bool_arg(args, "prebuild")?.unwrap_or(true) {
                let apk = Arc::clone(&apk);
                prebuild = thread::Builder::new()
                    .name("droidasc-prebuild".into())
                    .spawn(move || {
                        let _ = apk.engine.prebuild();
                    })
                    .is_ok();
            }
        }
        let open_ms = t.elapsed().as_secs_f64() * 1e3;
        let mut text = format!("apk_id: {}\npath: {}\ndex entries: {dex_entries}", apk.id, apk.path.display());
        if let Some(n) = classes.as_u64() {
            text.push_str(&format!("\nclasses: {n}"));
        }
        let structured = json!({
            "apk_id": apk.id,
            "path": apk.path.display().to_string(),
            "dex_entries": dex_entries,
            "classes": classes,
            "prebuild": prebuild,
            "open_ms": open_ms,
            "memory_cache_bytes": self.cache.memory_bytes(),
        });
        Ok((text, structured))
    }

    /// `open_apk` over many APKs: register them (an inventory with apk_ids),
    /// inflating nothing unless `warm` is set.
    fn open_apks(&self, args: &Value, call: &Call, paths: &[PathBuf]) -> ToolResult {
        let t = Instant::now();
        let warm = bool_arg(args, "warm")?.unwrap_or(false);
        let (sections, _, stats) = self.sweep(
            paths,
            call,
            Some(false),
            |apk| {
                let entries = apk.engine.dex_entries().map_err(|e| e.to_string())?;
                let bytes: u64 = entries.iter().map(|e| e.uncomp_size).sum();
                Ok(((), vec![(bytes, (entries.len(), bytes))]))
            },
            |apk, (), &(dex, bytes)| {
                let classes = if warm { warm_classes(apk).map(Some).map_err(|e| e.0) } else { Ok(None) };
                (dex, bytes, classes)
            },
            |apk, r| {
                let (dex, bytes, classes) = r.into_iter().next().expect("one unit");
                let classes = match classes {
                    Err(e) => return (0, Some(Section::error(&apk.id, &apk.path, &e))),
                    Ok(n) => n,
                };
                let mut line = format!("{} | {dex} dex | {:.1} MiB | {}", apk.id, bytes as f64 / 1048576.0, apk.path.display());
                if let Some(n) = classes {
                    line.push_str(&format!(" | {n} classes"));
                }
                let json = json!({"apk_id": apk.id, "path": apk.path.display().to_string(), "dex_entries": dex,
                    "dex_bytes": bytes, "classes": classes});
                (1, Some(Section { lines: vec![line], json }))
            },
        );
        let header = format!("# opened {} APKs ({} errors), {:.0} ms", stats.with_hits, stats.errors, t.elapsed().as_secs_f64() * 1e3);
        let summary = json!({"apks_total": paths.len(), "opened": stats.with_hits, "errors": stats.errors});
        self.report(Report { tool: "open_apk", header, summary, sections, empty: Vec::new(), max_bytes: max_bytes(args)? })
    }

    fn close_apk(&self, args: &Value, _: &Call) -> ToolResult {
        let apk = {
            let mut sessions = lock(&self.sessions);
            let Some(i) = Self::index_of(&sessions, args)? else { return Err(ToolError("that APK is not open".into())) };
            sessions.apks.remove(i)
        };
        apk.engine.cancel_prebuild();
        let released = apk.engine.release_memory_cache();
        Ok((
            format!("closed {} (released {} MiB of cached DEX)", apk.id, released >> 20),
            json!({"apk_id": apk.id, "closed": true, "released_bytes": released}),
        ))
    }

    // ---- many APKs -----------------------------------------------------------

    /// Run a multi-APK tool: open every path (one that fails becomes an error
    /// section), plan each APK into units and run them all on one queue
    /// ([`multi::fan_out`]), then turn each APK's results into
    /// `(hits, section)`; no section counts the APK as empty. With `release`
    /// (`None`: when the APKs' DEX would not fit the memory budget anyway, so
    /// a sweep does not evict what other calls still use), an APK's cached DEX
    /// leaves memory as soon as its last unit finishes.
    pub fn sweep<C, U, R>(
        &self,
        paths: &[PathBuf],
        call: &Call,
        release: Option<bool>,
        plan: impl Fn(&OpenApk) -> multi::Plan<C, U> + Sync,
        run: impl Fn(&OpenApk, &C, &U) -> R + Sync,
        section: impl Fn(&OpenApk, Vec<R>) -> (usize, Option<Section>),
    ) -> (Vec<Section>, Vec<String>, SweepStats)
    where
        C: Send + Sync,
        U: Send + Sync,
        R: Send,
    {
        let opened: Vec<Result<Arc<OpenApk>, String>> = paths.iter().map(|p| self.open_path(p).map_err(|e| e.0)).collect();
        let apks: Vec<Arc<OpenApk>> = opened.iter().filter_map(|o| o.as_ref().ok().cloned()).collect();
        let release = release.unwrap_or_else(|| {
            let dex_bytes: u64 = apks.iter().filter_map(|a| a.engine.dex_entries().ok()).flatten().map(|e| e.uncomp_size).sum();
            dex_bytes > self.cache.memory_capacity() as u64
        });
        let done = |apk: &OpenApk| {
            if release {
                apk.engine.release_memory_cache();
            }
        };
        let mut outcomes = multi::fan_out(self.threads.count(), &apks, &call.cancel, &plan, &run, done).into_iter();
        let mut stats = SweepStats { released: release, ..SweepStats::default() };
        let (mut sections, mut empty) = (Vec::new(), Vec::new());
        for (path, o) in paths.iter().zip(&opened) {
            let apk = match o {
                Ok(apk) => apk,
                Err(e) => {
                    stats.errors += 1;
                    sections.push(Section::error("-", path, e));
                    continue;
                }
            };
            match outcomes.next().expect("one outcome per opened APK") {
                Err(e) => {
                    stats.errors += 1;
                    sections.push(Section::error(&apk.id, &apk.path, &e));
                }
                Ok(results) => {
                    let (hits, s) = section(apk, results);
                    stats.hits += hits;
                    match s {
                        Some(s) => {
                            if s.json.get("error").is_some() {
                                stats.errors += 1;
                            } else {
                                stats.with_hits += usize::from(hits > 0);
                            }
                            sections.push(s);
                        }
                        None => empty.push(apk.id.clone()),
                    }
                }
            }
        }
        (sections, empty, stats)
    }

    /// Keep `report` for its cursor and return its first page.
    pub fn report(&self, report: Report) -> ToolResult {
        let report = Arc::new(report);
        let id = lock(&self.reports).keep(Arc::clone(&report));
        Ok(with_full_report(&report, report.page(0, Some(id))))
    }

    /// The page of a kept report a `cursor` points at.
    fn more(&self, tool: &str, cursor: &str) -> ToolResult {
        let (id, from) = multi::parse_cursor(cursor).ok_or_else(|| {
            ToolError(format!(
                "bad cursor {cursor:?}: pass the `cursor` a reply returned (like \"3:2\"), or the JSON arguments of a \
                 `more` / `next` hint as the call's arguments"
            ))
        })?;
        let report = lock(&self.reports).get(id).ok_or_else(|| ToolError(format!("cursor {cursor:?} has expired; run the query again")))?;
        if report.tool != tool {
            return Err(ToolError(format!("cursor {cursor:?} belongs to {}", report.tool)));
        }
        Ok(with_full_report(&report, report.page(from, Some(id))))
    }

    /// SDK prefixes to fold away, if `collapse_sdks` (default `default`) is on.
    fn sdk_filter(&self, args: &Value, default: bool) -> Result<Option<Vec<String>>, ToolError> {
        if !bool_arg(args, "collapse_sdks")?.unwrap_or(default) {
            return Ok(None);
        }
        Ok(Some(match args.get("sdk_prefixes") {
            None | Some(Value::Null) => self.sdk_prefixes.clone(),
            Some(Value::Array(list)) => list
                .iter()
                .map(|p| p.as_str().map(multi::normalize_prefix))
                .collect::<Option<_>>()
                .ok_or_else(|| ToolError("`sdk_prefixes` must be a list of strings".into()))?,
            Some(_) => return Err(ToolError("`sdk_prefixes` must be a list of strings".into())),
        }))
    }

    // ---- queries -----------------------------------------------------------

    /// A class's smali, or the methods `method` names. A class over the output
    /// budget comes as an outline (unless `full`), the whole class handed on
    /// for a spill file.
    fn getclass(&self, args: &Value, _: &Call) -> ToolResult {
        let apk = self.resolve(args)?;
        let class = str_arg(args, "class")?.ok_or_else(|| ToolError("getclass needs `class`".into()))?;
        // Off by default: obfuscated APKs carry meaningless `.line`s, and agents
        // turned them off in 259 of 292 getclass calls of the Grok replay.
        let debug_info = bool_arg(args, "debug_info")?.unwrap_or(false);
        let descriptor = names::format_class_name(class)?;
        let opts = SmaliOptions { line_numbers: debug_info, param_names: debug_info };
        let mut src = apk.engine.get_class_method(&descriptor, opts, None)?;
        if bool_arg(args, "resource_names")?.unwrap_or(true) {
            src.source = apk.engine.annotate_resource_ids(&src.source);
        }
        let mut text = String::new();
        if let Some(w) = &src.warning {
            // A smali comment, so the text still assembles.
            text.push_str(&format!("# Warning: {w}\n"));
        }
        let parsed = ClassText::parse(&src.source);
        let budget = output::budget(args)?;
        let mut structured = json!({
            "apk_id": apk.id,
            "class": descriptor,
            "dex_name": src.dex_name,
            "warning": src.warning,
            "rebuilt": src.rebuilt.is_some(),
        });
        match str_arg(args, "method")? {
            Some(m) => {
                let picked = parsed.select(m);
                if picked.is_empty() {
                    return Err(ToolError(format!("{descriptor} has no method {m:?}; its methods: {}", parsed.signatures(4 << 10))));
                }
                structured["methods"] = json!(picked.iter().map(|b| b.signature).collect::<Vec<_>>());
                text.push_str(&parsed.with_methods(&picked));
            }
            None if text.len() + src.source.len() > budget && !bool_arg(args, "full")?.unwrap_or(false) => {
                structured["outline"] = json!(true);
                structured[FULL] = json!(format!("{text}{}", src.source));
                text.push_str(&parsed.outline(src.source.len(), budget));
            }
            None => text.push_str(&src.source),
        }
        structured["source"] = json!(text);
        Ok((text, structured))
    }

    fn findrefs(&self, args: &Value, call: &Call) -> ToolResult {
        if args.get("rules").is_some() {
            return self.findrefs_rules(args, call);
        }
        let query = parse_query(args)?;
        if let Some(paths) = multi::targets(args)? {
            return self.findrefs_many(args, call, &paths, &query);
        }
        let apk = self.resolve(args)?;
        let sdks = self.sdk_filter(args, false)?;
        let (offset, limit) = page_args(args, FINDREFS_LIMIT)?;
        let context = context_arg(args)?;
        let mut batches = Vec::new();
        apk.engine.find_refs_with(&query, true, &call.cancel, &mut |b| batches.push(b))?;
        call.check()?;
        let entries = batches.len();
        let mut found = Found::new(batches, sdks.as_deref());
        let total = found.rows.len();
        let mut page: Vec<RefResult> = found.rows.iter().skip(offset).take(limit).cloned().collect();
        // Only the page is rendered, from the DEX files the search just loaded.
        found.errors.extend(apk.engine.fill_context(&mut page, context)?);
        let mut text = String::new();
        for r in &page {
            text.push_str(&r.text());
            text.push('\n');
        }
        let next = (offset + page.len() < total).then_some(offset + page.len());
        text.push_str(&page_footer("results", offset, page.len(), total, next));
        if found.sdk_hits > 0 {
            text.push_str(&format!("# {} more in SDK packages (collapse_sdks=false shows them): {}\n", found.sdk_hits, found.sdk_list()));
        }
        for e in &found.errors {
            text.push_str(&format!("# Warning: {e}\n"));
        }
        let hints = if total == 0 && found.sdk_hits == 0 { apk.engine.no_results_hints(&query, entries) } else { Vec::new() };
        for h in &hints {
            text.push_str(&format!("# hint: {h}\n"));
        }
        let structured = json!({
            "apk_id": apk.id,
            "total": total,
            "hints": hints,
            "offset": offset,
            "returned": page.len(),
            "next_offset": next,
            "results": page.iter().map(|r| ref_json(r, context)).collect::<Vec<_>>(),
            "sdk_hits": found.sdk_hits,
            "errors": found.errors,
        });
        Ok((text, structured))
    }

    fn callgraph(&self, args: &Value, _call: &Call) -> ToolResult {
        let apk = self.resolve(args)?;
        let class = str_arg(args, "class")?.ok_or_else(|| ToolError("callgraph needs `class`".into()))?;
        let method = str_arg(args, "method")?.ok_or_else(|| ToolError("callgraph needs `method`".into()))?;
        let direction = match choice_arg(args, "direction", "callers", CALL_DIRECTIONS)? {
            "callers" => Direction::Callers,
            _ => Direction::Callees,
        };
        let q = CallQuery {
            class: names::format_class_name(class)?,
            method: method.to_string(),
            direction,
            depth: usize_arg(args, "depth")?.unwrap_or(CALLGRAPH_DEPTH),
            max_nodes: usize_arg(args, "max_nodes")?.unwrap_or(CALLGRAPH_MAX_NODES),
            virtual_calls: bool_arg(args, "virtual")?.unwrap_or(false),
        };
        let tree = apk.engine.call_graph(&q)?;
        let mut text = String::new();
        for line in tree.lines() {
            text.push_str(&line);
            text.push('\n');
        }
        text.push_str(&tree.footer());
        text.push('\n');
        for e in &tree.errors {
            text.push_str(&format!("# Warning: {e}\n"));
        }
        let rows: Vec<Value> = tree
            .rows
            .iter()
            .map(|r| json!({"depth": r.depth, "parent": r.parent, "method": r.method, "dex": r.dex, "repeated": r.repeated, "via": r.via}))
            .collect();
        let structured = json!({
            "apk_id": apk.id,
            "direction": direction.as_str(),
            "depth": tree.depth,
            "methods": tree.methods,
            "truncated": tree.truncated,
            "rows": rows,
            "errors": tree.errors,
        });
        Ok((text, structured))
    }

    /// `findrefs` over many APKs: every DEX of every APK on one queue,
    /// largest first.
    fn findrefs_many(&self, args: &Value, call: &Call, paths: &[PathBuf], query: &Query) -> ToolResult {
        let t = Instant::now();
        let compiled = CompiledQuery::new(query)?;
        let sdks = self.sdk_filter(args, true)?;
        let view = View {
            per_apk: usize_arg(args, "per_apk")?.unwrap_or(PER_APK),
            group: match choice_arg(args, "group", "none", GROUPS)? {
                "package" => Some(usize_arg(args, "package_depth")?.unwrap_or(PACKAGE_DEPTH).max(1)),
                _ => None,
            },
            collapsed: sdks.is_some(),
            query: query_args(args, FINDREFS_QUERY_KEYS),
        };
        let release = bool_arg(args, "release")?;
        // Identical DEX in several APKs is searched once.
        let dedup = DexDedup::new();
        let cached = AtomicUsize::new(0);
        let dex_entries = AtomicUsize::new(0);
        let (sections, empty, stats) = self.sweep(
            paths,
            call,
            release,
            |apk| {
                let target = apk.engine.search_target().map_err(|e| e.to_string())?;
                dex_entries.fetch_add(target.entries.len(), Ordering::Relaxed);
                // L3: this query already ran on this APK version.
                if let Some(batches) = apk.engine.cached_refs(&target, query, true) {
                    cached.fetch_add(1, Ordering::Relaxed);
                    return Ok((SweepTarget { target, claims: Vec::new(), cached: Mutex::new(Some(batches)) }, vec![(0, None)]));
                }
                let claims: Vec<Claim> = target.entries.iter().map(|e| dedup.claim(e)).collect();
                // A follower waits for its leader: run it after the real work.
                let units = (claims.iter().zip(&target.entries).enumerate())
                    .map(|(i, (c, e))| (if DexDedup::follows(c) { 1 } else { e.uncomp_size.max(e.comp_size) }, Some(i)))
                    .collect();
                Ok((SweepTarget { target, claims, cached: Mutex::new(None) }, units))
            },
            |apk, t, unit| match *unit {
                None => lock(&t.cached).take().unwrap_or_default(),
                Some(i) => {
                    let (entry, claim) = (&t.target.entries[i], &t.claims[i]);
                    vec![apk.engine.search_target_entry_dedup(&t.target, entry, &compiled, true, &call.cancel, claim)]
                }
            },
            |apk, batches| {
                let batches: Vec<RefBatch> = batches.into_iter().flatten().collect();
                if batches.iter().all(|b| b.source != "result") {
                    apk.engine.store_refs(query, true, &batches);
                }
                let found = Found::new(batches, sdks.as_deref());
                (found.rows.len() + found.sdk_hits, found.section(apk, &view))
            },
        );
        call.check()?;
        let ms = t.elapsed().as_secs_f64() * 1e3;
        let mut header = format!(
            "# findrefs {} over {} APKs: {} with hits, {} hits, {} errors, {ms:.0} ms",
            rules::describe(args),
            paths.len(),
            stats.with_hits,
            stats.hits,
            stats.errors
        );
        let hints: Vec<String> = if stats.hits == 0 {
            std::iter::once(hints::searched_hint(paths.len(), dex_entries.load(Ordering::Relaxed)))
                .chain(hints::query_hint(query))
                .collect()
        } else {
            Vec::new()
        };
        for h in &hints {
            header.push_str(&format!("\n# hint: {h}"));
        }
        let summary = json!({
            "hints": hints,
            "apks_total": paths.len(),
            "apks_with_hits": stats.with_hits,
            "total": stats.hits,
            "errors": stats.errors,
            "elapsed_ms": ms,
            "released": stats.released,
            "memory_cache_bytes": self.cache.memory_bytes(),
            "apks_from_result_cache": cached.load(Ordering::Relaxed),
            "dex_shared": dedup.shared(),
        });
        self.report(Report { tool: "findrefs", header, summary, sections, empty, max_bytes: max_bytes(args)? })
    }

    fn listclass(&self, args: &Value, call: &Call) -> ToolResult {
        if let Some(paths) = multi::targets(args)? {
            return self.listclass_many(args, call, &paths);
        }
        let apk = self.resolve(args)?;
        let (offset, limit) = page_args(args, LISTCLASS_LIMIT)?;
        let classes = apk.engine.list_classes(str_arg(args, "prefix")?)?;
        let total = classes.len();
        let page: Vec<_> = classes.iter().skip(offset).take(limit).collect();
        let mut text = String::new();
        for c in &page {
            text.push_str(&c.descriptor);
            text.push('\n');
        }
        let next = (offset + page.len() < total).then_some(offset + page.len());
        text.push_str(&page_footer("classes", offset, page.len(), total, next));
        let structured = json!({
            "apk_id": apk.id,
            "total": total,
            "offset": offset,
            "returned": page.len(),
            "next_offset": next,
            "classes": page.iter().map(|c| json!({"class": c.descriptor, "dex": c.dex_name})).collect::<Vec<_>>(),
        });
        Ok((text, structured))
    }

    /// `listclass` over many APKs: which of them define classes under `prefix`.
    fn listclass_many(&self, args: &Value, call: &Call, paths: &[PathBuf]) -> ToolResult {
        let t = Instant::now();
        let prefix = str_arg(args, "prefix")?;
        let per_apk = usize_arg(args, "per_apk")?.unwrap_or(PER_APK);
        let release = bool_arg(args, "release")?;
        let (sections, empty, stats) = self.sweep(
            paths,
            call,
            release,
            |apk| {
                let bytes = std::fs::metadata(&apk.path).map(|m| m.len()).unwrap_or(0);
                Ok(((), vec![(bytes, ())]))
            },
            |apk, (), ()| apk.engine.list_classes(prefix).map_err(|e| e.to_string()),
            |apk, r| {
                let classes = match r.into_iter().next().expect("one unit") {
                    Ok(c) => c,
                    Err(e) => return (0, Some(Section::error(&apk.id, &apk.path, &e))),
                };
                if classes.is_empty() {
                    return (0, None);
                }
                let id = &apk.id;
                let mut lines = vec![format!("{id} | {} classes | {}", classes.len(), apk.path.display())];
                lines.extend(classes.iter().take(per_apk).map(|c| format!("{id} | {}", c.descriptor)));
                let next = (classes.len() > per_apk).then(|| {
                    let mut next = query_args(args, &["prefix"]);
                    next.insert("apk_id".into(), json!(id));
                    next.insert("offset".into(), json!(per_apk));
                    Value::Object(next)
                });
                if let Some(next) = &next {
                    lines.push(format!("{id} | more | {} more: listclass {next}", classes.len() - per_apk));
                }
                let json = json!({
                    "next": next,
                    "apk_id": id,
                    "path": apk.path.display().to_string(),
                    "total": classes.len(),
                    "classes": classes.iter().take(per_apk).map(|c| &c.descriptor).collect::<Vec<_>>(),
                });
                (classes.len(), Some(Section { lines, json }))
            },
        );
        call.check()?;
        let header = format!(
            "# listclass {} over {} APKs: {} with classes, {} classes, {} errors, {:.0} ms",
            prefix.unwrap_or("(all)"),
            paths.len(),
            stats.with_hits,
            stats.hits,
            stats.errors,
            t.elapsed().as_secs_f64() * 1e3
        );
        let summary = json!({"apks_total": paths.len(), "apks_with_hits": stats.with_hits, "total": stats.hits, "errors": stats.errors});
        self.report(Report { tool: "listclass", header, summary, sections, empty, max_bytes: max_bytes(args)? })
    }

    fn getmanifest(&self, args: &Value, _: &Call) -> ToolResult {
        let apk = self.resolve(args)?;
        let xml =
            if bool_arg(args, "resolve")?.unwrap_or(false) { apk.engine.manifest_xml_resolved()? } else { apk.engine.manifest_xml()? };
        let structured = json!({"apk_id": apk.id, "xml": xml});
        Ok((xml, structured))
    }
}

/// A page of `report`, handing over the whole report (for a spill file)
/// when the page does not show all of it.
fn with_full_report(report: &Report, (text, mut structured): (String, Value)) -> (String, Value) {
    let partial = !structured["cursor"].is_null() || structured["shown"][0].as_u64().is_some_and(|from| from > 0);
    if partial {
        structured[FULL] = json!(report.full_text());
    }
    // The report pages itself (by cursor).
    structured[FITTED] = json!(true);
    (text, structured)
}

/// The arguments a call means when its `cursor` is not a report cursor but
/// a hint passed back: a JSON object of arguments, or `tool {json}` as a
/// `more` line prints it. Arguments given next to it fill in what it lacks.
fn follow_up(args: &Value) -> Option<Value> {
    let mut hint = match args.get("cursor")? {
        Value::Object(o) => o.clone(),
        Value::String(s) if multi::parse_cursor(s).is_none() => {
            let s = s.trim();
            let brace = s.find('{')?;
            if !s[..brace].trim().chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return None;
            }
            match serde_json::from_str::<Value>(&s[brace..]).ok()? {
                Value::Object(o) => o,
                _ => return None,
            }
        }
        _ => return None,
    };
    hint.remove("cursor");
    for (k, v) in args.as_object()? {
        if k != "cursor" && !hint.contains_key(k) {
            hint.insert(k.clone(), v.clone());
        }
    }
    Some(Value::Object(hint))
}

/// Inflate every DEX into the shared cache (as a side effect of listing its
/// classes) and return the class count.
fn warm_classes(apk: &OpenApk) -> Result<usize, ToolError> {
    let mut n = 0;
    for entry in apk.engine.scan_classes(None, |_, _| {})? {
        for dex in entry.result.into_iter().flatten() {
            n += dex.descriptors.len();
        }
    }
    Ok(n)
}

/// How a multi-APK findrefs shows one APK.
struct View {
    per_apk: usize,
    /// Merge hits by this many package segments.
    group: Option<usize>,
    /// SDK hits were folded away.
    collapsed: bool,
    /// The query part of the call's arguments, repeated in `more` hints.
    query: Map<String, Value>,
}

/// One APK's findrefs results: rows in DEX order, minus folded SDK hits.
struct Found {
    rows: Vec<RefResult>,
    sdk_hits: usize,
    /// Folded hits per SDK prefix.
    sdks: BTreeMap<String, usize>,
    errors: Vec<String>,
    /// Every DEX entry failed.
    failed: bool,
}

impl Found {
    fn new(mut batches: Vec<RefBatch>, sdks: Option<&[String]>) -> Found {
        // Entries finish in any order; page over a stable one.
        batches.sort_by_cached_key(|b| dex_order(&b.entry_name));
        let errors = batches.iter().filter_map(|b| b.error.as_ref().map(|e| format!("{}: {e}", b.entry_name))).collect();
        let failed = !batches.is_empty() && batches.iter().all(|b| b.error.is_some() && b.results.is_empty());
        let mut found = Found { rows: Vec::new(), sdk_hits: 0, sdks: BTreeMap::new(), errors, failed };
        for r in batches.into_iter().flat_map(|b| b.results) {
            match sdks.and_then(|s| multi::sdk_of(s, multi::result_class(&r.method))) {
                Some(sdk) => {
                    found.sdk_hits += 1;
                    *found.sdks.entry(sdk.to_string()).or_default() += 1;
                }
                None => found.rows.push(r),
            }
        }
        found
    }

    /// `Landroidx/ 23, Lkotlin/ 4`, most hits first.
    fn sdk_list(&self) -> String {
        let mut v: Vec<_> = self.sdks.iter().collect();
        v.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        v.iter().map(|(p, n)| format!("{p} {n}")).collect::<Vec<_>>().join(", ")
    }

    /// The APK's section: a summary line, then rows (or package groups), each
    /// starting with the apk_id so the reply greps per APK.
    fn section(&self, apk: &OpenApk, view: &View) -> Option<Section> {
        if self.rows.is_empty() && self.sdk_hits == 0 && self.errors.is_empty() {
            return None;
        }
        let id = &apk.id;
        if self.failed {
            return Some(Section::error(id, &apk.path, &self.errors.join("; ")));
        }
        let mut head = format!("{id} | {} hits", self.rows.len());
        if self.sdk_hits > 0 {
            head.push_str(&format!(" (+{} in SDKs)", self.sdk_hits));
        }
        let mut lines = vec![format!("{head} | {}", apk.path.display())];
        let mut bytes = lines[0].len();
        let fits = |bytes: usize, line: &str| bytes + line.len() < multi::MAX_APK_BYTES;
        let mut json = json!({
            "apk_id": id,
            "path": apk.path.display().to_string(),
            "total": self.rows.len(),
            "sdk_hits": self.sdk_hits,
            "sdks": self.sdks,
            "errors": self.errors,
        });
        match view.group {
            None => {
                let mut shown = Vec::new();
                for r in self.rows.iter().take(view.per_apk) {
                    let line = format!("{id} | {}", r.line());
                    if !fits(bytes, &line) {
                        break;
                    }
                    bytes += line.len() + 1;
                    lines.push(line);
                    shown.push(result_json(r));
                }
                let n = shown.len();
                if n < self.rows.len() {
                    let mut next = view.query.clone();
                    next.insert("apk_id".into(), json!(id));
                    next.insert("offset".into(), json!(n));
                    next.insert("collapse_sdks".into(), json!(view.collapsed));
                    lines.push(format!("{id} | more | {} more: findrefs {}", self.rows.len() - n, Value::Object(next.clone())));
                    json["next"] = Value::Object(next);
                }
                json["results"] = Value::Array(shown);
                json["next_offset"] = json!((n < self.rows.len()).then_some(n));
            }
            Some(depth) => {
                // package → (hits, first hit)
                let mut groups: BTreeMap<&str, (usize, &str)> = BTreeMap::new();
                for r in &self.rows {
                    let g = groups.entry(multi::package_of(multi::result_class(&r.method), depth)).or_insert((0, &r.method));
                    g.0 += 1;
                }
                let mut groups: Vec<_> = groups.into_iter().collect();
                groups.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then(a.0.cmp(b.0)));
                let mut shown = Vec::new();
                for (pkg, (n, example)) in groups.iter().take(view.per_apk) {
                    let line = format!("{id} | {pkg} | {n} hits | e.g. {example}");
                    if !fits(bytes, &line) {
                        break;
                    }
                    bytes += line.len() + 1;
                    lines.push(line);
                    shown.push(json!({"package": pkg, "hits": n, "example": example}));
                }
                if shown.len() < groups.len() {
                    let mut next = view.query.clone();
                    next.insert("apks".into(), json!([apk.path.display().to_string()]));
                    next.insert("group".into(), json!("package"));
                    next.insert("package_depth".into(), json!(depth));
                    next.insert("per_apk".into(), json!(groups.len()));
                    next.insert("collapse_sdks".into(), json!(view.collapsed));
                    lines.push(format!(
                        "{id} | more | {} more packages: findrefs {}",
                        groups.len() - shown.len(),
                        Value::Object(next.clone())
                    ));
                    json["next"] = Value::Object(next);
                }
                json["packages"] = Value::Array(shown);
            }
        }
        if self.sdk_hits > 0 {
            lines.push(format!("{id} | sdk | {}", self.sdk_list()));
        }
        for e in &self.errors {
            lines.push(format!("{id} | warning | {e}"));
        }
        Some(Section { lines, json })
    }
}

fn result_json(r: &RefResult) -> Value {
    ref_json(r, RefContext::None)
}

/// The findrefs query `args` describe.
///
/// Lenient where intent is clear: the kind is read by [`names::parse_kind`]
/// (`methods`, `Strings`, `literal`), a member target may come whole in
/// `value` or `name` (`Landroid/webkit/WebView;->loadUrl`, `WebView.loadUrl`),
/// a type / class relation may name its class in `class`, and a single
/// query given beside `all` joins its conditions.
fn parse_query(args: &Value) -> Result<Query, ToolError> {
    if let Some(q) = rules::compound(args)? {
        return Ok(q);
    }
    let kind = str_arg(args, "kind")?
        .ok_or_else(|| ToolError("findrefs needs `kind` (string, type, method, field, extends or impl), or `all` / `rules`".into()))?;
    let kind = names::parse_kind(kind)?;
    Ok(match kind {
        "string" | "literal" | "type" | "extends" | "impl" => {
            let value = match str_arg(args, "value")? {
                Some(v) => v,
                // `{kind: "type", class: "Lc;"}`
                None if kind != "string" && kind != "literal" => {
                    str_arg(args, "class")?.ok_or_else(|| ToolError(format!("a {kind} query needs `value` (the class)")))?
                }
                None => return Err(ToolError(format!("a {kind} query needs `value`"))),
            };
            match kind {
                "literal" => Query::StringLiteral(value.to_string()),
                "string" if bool_arg(args, "literal")?.unwrap_or(false) => Query::StringLiteral(value.to_string()),
                "string" => Query::String(value.to_string()),
                "type" => Query::Type(value.to_string()),
                "extends" => Query::Extends(names::format_class_name(value.trim())?),
                _ => Query::Implements(names::format_class_name(value.trim())?),
            }
        }
        _ => {
            // The target may come whole in `value` (as for the other kinds).
            let name = match str_arg(args, "name")? {
                Some(n) => Some(n),
                None => str_arg(args, "value")?,
            };
            let m = names::member_query(
                kind,
                str_arg(args, "class")?,
                bool_arg(args, "fuzzy_class")?.unwrap_or(false),
                name,
                bool_arg(args, "exact")?.unwrap_or(false),
            )?;
            if kind == "method" {
                Query::Method(m)
            } else {
                Query::Field(m)
            }
        }
    })
}

/// `direction` of callgraph, with the spellings models also use.
const CALL_DIRECTIONS: &[(&str, &[&str])] =
    &[("callers", &["caller", "up", "incoming", "in"]), ("callees", &["callee", "down", "outgoing", "out"])];
/// `group` of a multi-APK findrefs.
const GROUPS: &[(&str, &[&str])] = &[("none", &["no", "off", "false"]), ("package", &["pkg", "packages"])];

/// The findrefs arguments that define the query (not the APKs, paging or view).
const FINDREFS_QUERY_KEYS: &[&str] = &["kind", "value", "literal", "name", "class", "fuzzy_class", "exact", "all", "none", "sdk_prefixes"];

/// The `keys` present in `args`, for the arguments of a follow-up call.
fn query_args(args: &Value, keys: &[&str]) -> Map<String, Value> {
    keys.iter().filter_map(|&k| Some((k.to_string(), args.get(k)?.clone()))).collect()
}

/// `string "http://"`, `method Ljava/lang/Runtime;->exec`, ... for a report header.
fn describe_query(args: &Value) -> String {
    let s = |k: &str| args.get(k).and_then(Value::as_str);
    let kind = s("kind").unwrap_or("?");
    match (s("value"), s("class"), s("name")) {
        (Some(v), _, _) => format!("{kind} {v:?}"),
        (None, Some(c), Some(n)) => format!("{kind} {c}->{n}"),
        (None, Some(c), None) => format!("{kind} {c}"),
        (None, None, Some(n)) => format!("{kind} {n}"),
        _ => kind.to_string(),
    }
}

fn max_bytes(args: &Value) -> Result<usize, ToolError> {
    output::budget(args)
}

/// Run a tool, turning a panic into a tool error.
fn guarded<T>(name: &str, tool: impl FnOnce() -> Result<T, ToolError>) -> Result<T, ToolError> {
    panic::catch_unwind(AssertUnwindSafe(tool))
        .unwrap_or_else(|p| Err(ToolError(format!("internal error in {name}: {}", panic_message(&*p)))))
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    payload.downcast_ref::<&str>().copied().or_else(|| payload.downcast_ref::<String>().map(String::as_str)).unwrap_or("panic")
}

fn error_reply(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn canonical(path: &str) -> Result<PathBuf, ToolError> {
    if path.is_empty() {
        return Err(ToolError("`apk` is empty".into()));
    }
    Path::new(path).canonicalize().map_err(|e| ToolError(format!("cannot open {path}: {e}")))
}

pub fn str_arg<'a>(args: &'a Value, key: &str) -> Result<Option<&'a str>, ToolError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(ToolError(format!("`{key}` must be a string"))),
    }
}

/// A boolean argument; `"true"` / `"false"` are taken too, as models write them.
pub fn bool_arg(args: &Value, key: &str) -> Result<Option<bool>, ToolError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(Value::String(s)) if s == "true" => Ok(Some(true)),
        Some(Value::String(s)) if s == "false" => Ok(Some(false)),
        Some(_) => Err(ToolError(format!("`{key}` must be a boolean"))),
    }
}

/// An enumerated string argument, `default` when absent. `choices` pairs
/// each value with the other spellings models use for it; case and a
/// trailing `s` do not matter. Unknown values fail with the valid ones.
pub fn choice_arg(args: &Value, key: &str, default: &'static str, choices: &[(&'static str, &[&str])]) -> Result<&'static str, ToolError> {
    let Some(v) = str_arg(args, key)? else { return Ok(default) };
    let v = v.trim().to_ascii_lowercase();
    let find = |v: &str| choices.iter().find(|(c, aliases)| *c == v || aliases.contains(&v)).map(|(c, _)| *c);
    find(&v).or_else(|| v.strip_suffix('s').and_then(find)).ok_or_else(|| {
        let valid: Vec<&str> = choices.iter().map(|(c, _)| *c).collect();
        ToolError(format!("unknown {key} {v:?}: use {}", valid.join(", ")))
    })
}

/// A non-negative integer argument, also given as a string of digits.
pub fn usize_arg(args: &Value, key: &str) -> Result<Option<usize>, ToolError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => as_usize(v).map(Some).ok_or_else(|| ToolError(format!("`{key}` must be a non-negative integer"))),
    }
}

fn as_usize(v: &Value) -> Option<usize> {
    match v {
        Value::Number(n) => n.as_u64().and_then(|n| usize::try_from(n).ok()),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Smali lines around each hit for `context: true`.
const CONTEXT_LINES: usize = 3;

/// `context`: a number of smali lines around each referencing instruction,
/// or `"method"` for the whole method (`true`: [`CONTEXT_LINES`]).
fn context_arg(args: &Value) -> Result<RefContext, ToolError> {
    match args.get("context") {
        None | Some(Value::Null) => Ok(RefContext::None),
        Some(Value::String(s)) if s == "method" => Ok(RefContext::Method),
        // `context: true` asks for some code around each hit.
        Some(Value::Bool(true)) => Ok(RefContext::Lines(CONTEXT_LINES)),
        Some(Value::Bool(false)) => Ok(RefContext::None),
        Some(v) => {
            as_usize(v).map(RefContext::Lines).ok_or_else(|| ToolError("`context` must be a non-negative integer or \"method\"".into()))
        }
    }
}

/// A findrefs row as JSON; with a context, also where the references are
/// (`pc` in code units, source `line`) and the smali around them.
fn ref_json(r: &RefResult, context: RefContext) -> Value {
    let matched: Vec<&str> = r.matched.iter().map(Matched::as_str).collect();
    let mut v = json!({"dex": r.dex_name, "method": r.method, "signature": r.signature, "matched": matched});
    if context != RefContext::None {
        v["sites"] = r.sites.iter().map(|s| json!({"pc": s.pc, "line": s.line, "matched": matched.get(s.matched)})).collect();
        v["context"] = json!(r.context);
    }
    v
}

fn page_args(args: &Value, default_limit: usize) -> Result<(usize, usize), ToolError> {
    let offset = usize_arg(args, "offset")?.unwrap_or(0);
    let limit = usize_arg(args, "limit")?.unwrap_or(default_limit);
    if limit == 0 {
        return Err(ToolError("`limit` must be at least 1".into()));
    }
    Ok((offset, limit))
}

/// `# N results` / `# 500 of 4054 results; next offset=500` (a comment line
/// that no CLI result line can be mistaken for).
fn page_footer(what: &str, offset: usize, returned: usize, total: usize, next: Option<usize>) -> String {
    match next {
        None if offset == 0 => format!("# {total} {what}\n"),
        None => format!("# {what} {}..{} of {total}\n", offset, offset + returned),
        Some(n) => format!("# {what} {}..{} of {total}; call again with offset={n} for more\n", offset, offset + returned),
    }
}

/// Sort key putting `classes.dex, classes2.dex, ..., classes10.dex` in order.
fn dex_order(name: &str) -> (String, u64, String) {
    let stem = name.split('!').next().unwrap_or(name);
    let digits: String = stem.chars().filter(char::is_ascii_digit).collect();
    let letters: String = stem.chars().filter(|c| !c.is_ascii_digit()).collect();
    (letters, digits.parse().unwrap_or(if digits.is_empty() { 1 } else { u64::MAX }), name.to_string())
}

fn tool_definitions() -> Value {
    Value::Array(
        TOOLS
            .iter()
            .map(|t| {
                let mut d = (t.definition)();
                d["name"] = json!(t.name);
                // Every reply is fitted to its budget (see `output`).
                if let Some(p) = d["inputSchema"]["properties"].as_object_mut() {
                    p.extend(defs::output_props().as_object().into_iter().flatten().map(|(k, v)| (k.clone(), v.clone())));
                }
                if d.get("annotations").is_none() {
                    d["annotations"] = defs::read_only();
                }
                d
            })
            .collect(),
    )
}

/// `tools/list` entries. Tools that sweep many APKs add [`defs::many`] to
/// their properties; their `outputSchema` describes the one-APK reply (a
/// multi-APK reply is a summary with `apks` sections, as the server
/// instructions say). Parameters say what they are and their default in a
/// few words, those every tool shares only where the instructions do not:
/// the list is what an agent reads before its first call.
pub mod defs {
    use serde_json::{json, Map, Value};

    /// What every tool but close_apk is: it reads the APK and answers;
    /// caches are not part of what the tool changes.
    pub fn read_only() -> Value {
        json!({"readOnlyHint": true, "openWorldHint": false})
    }

    /// `structuredContent` of the main path, as `(field, type)`; `?` after
    /// the type admits null. Spill and page fields (`file`, `page`, ...) come
    /// on top when the reply is over its budget, so no field is required.
    pub fn shape(fields: &[(&str, &str)]) -> Value {
        let props: Map<String, Value> = fields
            .iter()
            .map(|(name, ty)| {
                let ty = match ty.strip_suffix('?') {
                    Some(t) => json!([t, "null"]),
                    None => json!(ty),
                };
                (name.to_string(), json!({"type": ty}))
            })
            .collect();
        json!({"type": "object", "properties": props})
    }

    pub fn apk_props() -> Value {
        json!({
            "apk_id": {"type": "string"},
            "apk": {"type": "string", "description": "APK path instead of apk_id (opened on first use)."},
        })
    }

    /// Budget and spill properties every tool takes (explained in the server
    /// instructions too).
    pub fn output_props() -> Value {
        json!({
            "max_bytes": {"type": "integer"},
            "spill": {"type": "string", "description": "auto, always or never."},
            "page": {"type": "integer"},
        })
    }

    /// The selection and paging properties of a multi-APK call.
    pub fn many() -> Value {
        json!({
            "apks": {"type": "array", "items": {"type": "string"}},
            "dir": {"type": "string"},
            "glob": {"type": "string", "description": "Default *.apk."},
            "recursive": {"type": "boolean", "description": "Default true."},
            "per_apk": {"type": "integer", "description": "Default 10."},
            "cursor": {"type": "string"},
            "release": {"type": "boolean", "description": "Free each APK when done; default: if they overflow the cache."},
        })
    }

    pub fn page_props(limit: usize) -> Value {
        json!({
            "offset": {"type": "integer"},
            "limit": {"type": "integer", "description": format!("Default {limit}.")},
        })
    }

    /// `base` plus every property of `extra`.
    pub fn merge(mut base: Value, extra: &[Value]) -> Value {
        if let Some(p) = base.as_object_mut() {
            for e in extra.iter().filter_map(Value::as_object) {
                p.extend(e.clone());
            }
        }
        base
    }

    pub fn open_apk() -> Value {
        json!({
            "description": "Open an APK (inflating its DEX unless warm=false) and return its apk_id. With apks / dir: \
                register each (apk_id, DEX size, path).",
            "inputSchema": {"type": "object", "properties": merge(json!({
                "apk": {"type": "string"},
                "warm": {"type": "boolean", "description": "Default true (false with apks / dir)."},
                "prebuild": {"type": "boolean", "description": "Build search tables in the background, default true."},
            }), &[many()])},
            "outputSchema": shape(&[("apk_id", "string"), ("path", "string"), ("dex_entries", "integer"), ("classes", "integer?")]),
        })
    }

    pub fn close_apk() -> Value {
        json!({
            "description": "Forget an opened APK.",
            "inputSchema": {"type": "object", "properties": apk_props()},
            "annotations": {"readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false},
            "outputSchema": shape(&[("apk_id", "string"), ("closed", "boolean"), ("released_bytes", "integer")]),
        })
    }

    pub fn getclass() -> Value {
        json!({
            "description": "A class as smali. Over the budget: an outline (fields, method signatures and sizes) unless \
                full=true; then ask for methods.",
            "inputSchema": {"type": "object", "properties": merge(apk_props(), &[json!({
                "class": {"type": "string", "description": "Lcom/a/B; or com.a.B"},
                "method": {"type": "string", "description": "Only these methods: a name (every overload) or name(params)ret."},
                "full": {"type": "boolean", "description": "Whole class even over budget, default false."},
                "debug_info": {"type": "boolean", "description": ".line / .param, default false."},
                "resource_names": {"type": "boolean", "description": "`# @type/name` after resource ids, default true."},
            })]), "required": ["class"]},
            "outputSchema": shape(&[
                ("apk_id", "string"), ("class", "string"), ("dex_name", "string"), ("source", "string"), ("warning", "string?"),
                ("rebuilt", "boolean"),
            ]),
        })
    }

    pub fn findrefs() -> Value {
        json!({
            "description": "Methods referencing a string / type / method / field, one per line: `dex | Lcls;->m(I)V | \
                \"str\", Lx;->f:I`; or classes extending / implementing a type. context=N or \"method\" adds the code. \
                `all` / `none`: several conditions in one method; `rules`: several queries in one pass. With apks / dir: \
                a section per APK, SDK hits folded.",
            "inputSchema": {"type": "object", "properties": merge(apk_props(), &[json!({
                "kind": {"type": "string", "description": "string, literal, type, method, field, extends or impl (also \
                    plurals and synonyms: implements, class, call...)."},
                "value": {"type": "string", "description": "string: regex (literal=true: text); type, extends, impl: a type; method / field: a whole target also works, e.g. Landroid/webkit/WebView;->loadUrl, android.webkit.WebView.loadUrl(String)."},
                "literal": {"type": "boolean"},
                "name": {"type": "string", "description": "Member name, regex (exact=true: equal); name(params)ret or name:T: that overload / type."},
                "class": {"type": "string", "description": "Declaring class; without package: any package."},
                "fuzzy_class": {"type": "boolean", "description": "class is a regex, default false."},
                "exact": {"type": "boolean"},
                "context": {"type": ["integer", "string", "boolean"], "description": "Lines of smali around each hit, or \"method\"."},
                "collapse_sdks": {"type": "boolean", "description": "Fold androidx, kotlin, gms... hits into counts; default true with apks / dir."},
                "sdk_prefixes": {"type": "array", "items": {"type": "string"}, "description": "Instead of the built-in SDK list."},
                "group": {"type": "string", "description": "none (default) or package: rows per package."},
                "package_depth": {"type": "integer", "description": "Default 3."},
            }), crate::rules::defs::findrefs_props(), page_props(super::FINDREFS_LIMIT), many()])},
            "outputSchema": shape(&[
                ("apk_id", "string"), ("total", "integer"), ("returned", "integer"), ("next_offset", "integer?"),
                ("results", "array"), ("hints", "array"), ("rules", "array"),
            ]),
        })
    }

    pub fn callgraph() -> Value {
        json!({
            "description": "Callers (default) or callees of a method across every DEX, as an indented tree (`2 <- \
                Lx;->m()V`). `[no body]`: not in the APK. Static calls only unless virtual=true.",
            "inputSchema": {"type": "object", "properties": merge(apk_props(), &[json!({
                "class": {"type": "string"},
                "method": {"type": "string", "description": "A name (every overload) or name(params)ret."},
                "direction": {"type": "string", "description": "callers (default) or callees."},
                "depth": {"type": "integer", "description": format!("Default {}.", super::CALLGRAPH_DEPTH)},
                "max_nodes": {"type": "integer", "description": format!("Default {}.", super::CALLGRAPH_MAX_NODES)},
                "virtual": {"type": "boolean", "description": "Also virtual / interface calls, default false."},
            })]), "required": ["class", "method"]},
            "outputSchema": shape(&[
                ("apk_id", "string"), ("direction", "string"), ("depth", "integer"), ("methods", "integer"), ("truncated", "boolean"),
                ("rows", "array"),
            ]),
        })
    }

    pub fn listclass() -> Value {
        json!({
            "description": "Classes the APK defines, optionally under a prefix. With apks / dir: count and first classes per APK.",
            "inputSchema": {"type": "object", "properties": merge(apk_props(), &[json!({
                "prefix": {"type": "string", "description": "com.a or Lcom/a"},
            }), page_props(super::LISTCLASS_LIMIT), many()])},
            "outputSchema": shape(&[("apk_id", "string"), ("total", "integer"), ("next_offset", "integer?"), ("classes", "array")]),
        })
    }

    pub fn getmanifest() -> Value {
        json!({
            "description": "AndroidManifest.xml as XML (records: manifest_summary).",
            "inputSchema": {"type": "object", "properties": merge(apk_props(), &[json!({
                "resolve": {"type": "boolean", "description": "Resource references by name, default false."},
            })])},
            "outputSchema": shape(&[("apk_id", "string"), ("xml", "string")]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_panicking_tool_becomes_a_tool_error() {
        let err = guarded::<()>("findrefs", || panic!("boom {}", 42)).err().unwrap();
        assert_eq!(err.0, "internal error in findrefs: boom 42");
        let err = guarded::<()>("getclass", || std::panic::panic_any(7u8)).err().unwrap();
        assert_eq!(err.0, "internal error in getclass: panic");
    }

    #[test]
    fn dex_names_sort_numerically() {
        let mut v = vec!["classes10.dex", "classes2.dex", "classes.dex", "classes2.dex!classes2.dex", "classes2.dex!classes1.dex"];
        v.sort_by_key(|n| dex_order(n));
        assert_eq!(v, ["classes.dex", "classes2.dex", "classes2.dex!classes1.dex", "classes2.dex!classes2.dex", "classes10.dex"]);
    }

    #[test]
    fn footer_describes_the_page() {
        assert_eq!(page_footer("results", 0, 3, 3, None), "# 3 results\n");
        assert_eq!(page_footer("results", 0, 2, 5, Some(2)), "# results 0..2 of 5; call again with offset=2 for more\n");
        assert_eq!(page_footer("classes", 4, 1, 5, None), "# classes 4..5 of 5\n");
    }

    #[test]
    fn messages_are_routed() {
        let call = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"findrefs"}}"#;
        assert!(matches!(classify(call), Message::Call { id, name } if id == "7" && name == "findrefs"));
        let cancel = r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"a"}}"#;
        assert!(matches!(classify(cancel), Message::Cancel(id) if id == "\"a\""));
        assert!(matches!(classify(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#), Message::Other));
    }
}
