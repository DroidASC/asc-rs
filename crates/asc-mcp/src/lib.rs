//! MCP server over stdio: one resident process that keeps APKs open.
//!
//! The CLI pays process start, APK open and DEX inflation on every command.
//! An agent session asks dozens of questions about the same APK, so this
//! server keeps one [`Engine`] per opened APK, all sharing one in-memory LRU
//! (and the on-disk cache), and answers each tool call from the inflated DEX
//! and locator tables already resident.
//!
//! Transport: JSON-RPC 2.0, one message per line on stdin/stdout (the MCP
//! stdio transport). Requests are handled in order. Supported methods:
//! `initialize`, `notifications/initialized` (and any other notification,
//! ignored), `ping`, `tools/list` and `tools/call`. Tool failures are
//! reported as results with `isError: true`; the server keeps running.
//!
//! Tool results carry the CLI's text (same line formats as `droidasc`) as
//! `content`, and the same data as `structuredContent`.

use asc_engine::{names, CacheConfig, Engine, SharedCache, SmaliOptions};
use asc_findrefs::Query;
use serde_json::{json, Map, Value};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Protocol version answered when the client does not name one.
pub const DEFAULT_PROTOCOL_VERSION: &str = "2025-06-18";

const FINDREFS_LIMIT: usize = 500;
const LISTCLASS_LIMIT: usize = 1000;

/// Server settings.
pub struct Options {
    pub threads: usize,
    pub debug: bool,
    /// Shared by every opened APK.
    pub cache: CacheConfig,
}

/// Serve MCP requests from `input` until it closes, writing responses to `output`.
pub fn serve(input: impl BufRead, mut output: impl Write, opts: Options) -> io::Result<()> {
    let mut server = Server::new(opts);
    for line in input.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(reply) = server.handle_line(&line) {
            serde_json::to_writer(&mut output, &reply)?;
            output.write_all(b"\n")?;
            output.flush()?;
        }
    }
    Ok(())
}

struct OpenApk {
    id: String,
    path: PathBuf,
    engine: Engine,
}

/// Session state: the opened APKs and the cache they share.
pub struct Server {
    threads: usize,
    debug: bool,
    // Declared before `cache` so engines drop first; dropping the shared
    // cache then lands their queued disk writes.
    apks: Vec<OpenApk>,
    cache: SharedCache,
    next_id: usize,
}

/// A tool failure, reported to the client as `isError: true`.
struct ToolError(String);

impl<E: std::fmt::Display> From<E> for ToolError {
    fn from(e: E) -> ToolError {
        ToolError(e.to_string())
    }
}

type ToolResult = Result<(String, Value), ToolError>;

impl Server {
    pub fn new(opts: Options) -> Server {
        Server {
            threads: opts.threads,
            debug: opts.debug,
            apks: Vec::new(),
            cache: SharedCache::new(opts.cache, |m| eprintln!("{m}")),
            next_id: 1,
        }
    }

    /// Handle one JSON-RPC message; `None` for notifications.
    pub fn handle_line(&mut self, line: &str) -> Option<Value> {
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
        Some(match self.request(method, &params) {
            Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Err((code, msg)) => error_reply(id, code, &msg),
        })
    }

    fn request(&mut self, method: &str, params: &Value) -> Result<Value, (i64, String)> {
        match method {
            "initialize" => {
                let version = params.get("protocolVersion").and_then(Value::as_str).unwrap_or(DEFAULT_PROTOCOL_VERSION);
                Ok(json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "droidasc", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": "Droid ASC: query an APK without preprocessing. open_apk once (it inflates every DEX \
                        so later calls are fast), then findrefs to locate strings / types / methods / fields and getclass \
                        to read the smali of a class. Every tool also accepts `apk` (a path) instead of `apk_id`.",
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
                let result = match name {
                    "open_apk" => self.open_apk(args),
                    "close_apk" => self.close_apk(args),
                    "getclass" => self.getclass(args),
                    "findrefs" => self.findrefs(args),
                    "listclass" => self.listclass(args),
                    "getmanifest" => self.getmanifest(args),
                    _ => return Err((-32602, format!("unknown tool: {name}"))),
                };
                Ok(match result {
                    Ok((text, structured)) => json!({
                        "content": [{"type": "text", "text": text}],
                        "structuredContent": structured,
                        "isError": false,
                    }),
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

    fn index_of(&self, args: &Value) -> Result<Option<usize>, ToolError> {
        if let Some(id) = str_arg(args, "apk_id")? {
            return match self.apks.iter().position(|a| a.id == id) {
                Some(i) => Ok(Some(i)),
                None => Err(ToolError(format!("no open APK with apk_id {id:?}"))),
            };
        }
        match str_arg(args, "apk")? {
            Some(path) => {
                let path = canonical(path)?;
                Ok(self.apks.iter().position(|a| a.path == path))
            }
            None => Err(ToolError("pass `apk_id` (from open_apk) or `apk` (a path)".into())),
        }
    }

    /// The APK `args` names, opening it when given by a path not yet open.
    fn resolve(&mut self, args: &Value) -> Result<usize, ToolError> {
        if let Some(i) = self.index_of(args)? {
            return Ok(i);
        }
        // `index_of` only returns `Ok(None)` for an `apk` path.
        let path = canonical(str_arg(args, "apk")?.unwrap_or_default())?;
        let engine = Engine::new(&path)
            .with_threads(self.threads)
            .with_debug(self.debug)
            .with_logger(|m| eprintln!("{m}"))
            .with_shared_cache(&self.cache);
        // Fail now on a file that is not a readable APK, not on the first query.
        engine.dex_entries()?;
        let id = format!("apk{}", self.next_id);
        self.next_id += 1;
        self.apks.push(OpenApk { id, path, engine });
        Ok(self.apks.len() - 1)
    }

    fn open_apk(&mut self, args: &Value) -> ToolResult {
        let t = Instant::now();
        let i = self.resolve(args)?;
        let warm = bool_arg(args, "warm")?.unwrap_or(true);
        let apk = &self.apks[i];
        let dex_entries = apk.engine.dex_entries()?.len();
        let mut classes = Value::Null;
        if warm {
            // Inflates every DEX into the shared cache as a side effect.
            let mut n = 0;
            for entry in apk.engine.scan_classes(None, |_, _| {})? {
                for dex in entry.result.into_iter().flatten() {
                    n += dex.descriptors.len();
                }
            }
            classes = json!(n);
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
            "open_ms": open_ms,
            "memory_cache_bytes": self.cache.memory_bytes(),
        });
        Ok((text, structured))
    }

    fn close_apk(&mut self, args: &Value) -> ToolResult {
        let Some(i) = self.index_of(args)? else { return Err(ToolError("that APK is not open".into())) };
        let apk = self.apks.remove(i);
        Ok((format!("closed {}", apk.id), json!({"apk_id": apk.id, "closed": true})))
    }

    // ---- queries -----------------------------------------------------------

    fn getclass(&mut self, args: &Value) -> ToolResult {
        let i = self.resolve(args)?;
        let class = str_arg(args, "class")?.ok_or_else(|| ToolError("getclass needs `class`".into()))?;
        let debug_info = bool_arg(args, "debug_info")?.unwrap_or(true);
        let descriptor = names::format_class_name(class)?;
        let opts = SmaliOptions { line_numbers: debug_info, param_names: debug_info };
        let src = self.apks[i].engine.get_class_with(&descriptor, opts)?;
        let mut text = String::new();
        if let Some(w) = &src.warning {
            // A smali comment, so the text still assembles.
            text.push_str(&format!("# Warning: {w}\n"));
        }
        text.push_str(&src.source);
        let structured = json!({
            "apk_id": self.apks[i].id,
            "class": descriptor,
            "dex_name": src.dex_name,
            "warning": src.warning,
            "rebuilt": src.rebuilt.is_some(),
            "source": src.source,
        });
        Ok((text, structured))
    }

    fn findrefs(&mut self, args: &Value) -> ToolResult {
        let i = self.resolve(args)?;
        let kind = str_arg(args, "kind")?.ok_or_else(|| ToolError("findrefs needs `kind` (string, type, method or field)".into()))?;
        let query = match kind {
            "string" | "type" => {
                let value = str_arg(args, "value")?.ok_or_else(|| ToolError(format!("a {kind} query needs `value`")))?;
                if kind == "string" {
                    Query::String(value.to_string())
                } else {
                    Query::Type(value.to_string())
                }
            }
            "method" | "field" => {
                let m = names::member_query(
                    kind,
                    str_arg(args, "class")?,
                    bool_arg(args, "fuzzy_class")?.unwrap_or(false),
                    str_arg(args, "name")?,
                    bool_arg(args, "exact")?.unwrap_or(false),
                )?;
                if kind == "method" {
                    Query::Method(m)
                } else {
                    Query::Field(m)
                }
            }
            _ => return Err(ToolError(format!("unknown kind {kind:?}: use string, type, method or field"))),
        };
        let (offset, limit) = page_args(args, FINDREFS_LIMIT)?;
        let mut batches = Vec::new();
        self.apks[i].engine.find_refs(&query, |b| batches.push(b))?;
        // Entries finish in any order; page over a stable one.
        batches.sort_by_cached_key(|b| dex_order(&b.entry_name));
        let errors: Vec<String> = batches.iter().filter_map(|b| b.error.as_ref().map(|e| format!("{}: {e}", b.entry_name))).collect();
        let total: usize = batches.iter().map(|b| b.results.len()).sum();
        let page: Vec<_> = batches.iter().flat_map(|b| &b.results).skip(offset).take(limit).collect();
        let mut text = String::new();
        for r in &page {
            text.push_str(&r.line());
            text.push('\n');
        }
        let next = (offset + page.len() < total).then_some(offset + page.len());
        text.push_str(&page_footer("results", offset, page.len(), total, next));
        for e in &errors {
            text.push_str(&format!("# Warning: {e}\n"));
        }
        let results: Vec<Value> = page.iter().map(|r| json!({"dex": r.dex_name, "method": r.method, "matched": r.matched})).collect();
        let structured = json!({
            "apk_id": self.apks[i].id,
            "total": total,
            "offset": offset,
            "returned": page.len(),
            "next_offset": next,
            "results": results,
            "errors": errors,
        });
        Ok((text, structured))
    }

    fn listclass(&mut self, args: &Value) -> ToolResult {
        let i = self.resolve(args)?;
        let (offset, limit) = page_args(args, LISTCLASS_LIMIT)?;
        let classes = self.apks[i].engine.list_classes(str_arg(args, "prefix")?)?;
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
            "apk_id": self.apks[i].id,
            "total": total,
            "offset": offset,
            "returned": page.len(),
            "next_offset": next,
            "classes": page.iter().map(|c| json!({"class": c.descriptor, "dex": c.dex_name})).collect::<Vec<_>>(),
        });
        Ok((text, structured))
    }

    fn getmanifest(&mut self, args: &Value) -> ToolResult {
        let i = self.resolve(args)?;
        let xml = self.apks[i].engine.manifest_xml()?;
        let structured = json!({"apk_id": self.apks[i].id, "xml": xml});
        Ok((xml, structured))
    }
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

fn str_arg<'a>(args: &'a Value, key: &str) -> Result<Option<&'a str>, ToolError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(ToolError(format!("`{key}` must be a string"))),
    }
}

fn bool_arg(args: &Value, key: &str) -> Result<Option<bool>, ToolError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(b)) => Ok(Some(*b)),
        Some(_) => Err(ToolError(format!("`{key}` must be a boolean"))),
    }
}

fn usize_arg(args: &Value, key: &str) -> Result<Option<usize>, ToolError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v.as_u64().map(|n| Some(n as usize)).ok_or_else(|| ToolError(format!("`{key}` must be a non-negative integer"))),
    }
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

fn apk_props() -> Value {
    json!({
        "apk_id": {"type": "string", "description": "Id returned by open_apk."},
        "apk": {"type": "string", "description": "APK path; opened implicitly if not open yet (alternative to apk_id)."},
    })
}

fn with_props(extra: Value) -> Value {
    let mut props = apk_props();
    if let (Some(p), Some(e)) = (props.as_object_mut(), extra.as_object()) {
        p.extend(e.clone());
    }
    props
}

fn page_props() -> Value {
    json!({
        "offset": {"type": "integer", "minimum": 0, "description": "Skip this many results (default 0)."},
        "limit": {"type": "integer", "minimum": 1, "description": "Return at most this many results."},
    })
}

fn tool_definitions() -> Value {
    let mut findrefs_props = with_props(json!({
        "kind": {"type": "string", "enum": ["string", "type", "method", "field"]},
        "value": {"type": "string", "description": "string: regex over string constants; type: fuzzy type descriptor / name."},
        "name": {"type": "string", "description": "method / field: name (regex or substring; exact with `exact`)."},
        "class": {"type": "string", "description": "method / field: declaring class (Lcom/poc/Main; or com.poc.Main)."},
        "fuzzy_class": {"type": "boolean", "description": "Treat `class` as a fuzzy pattern."},
        "exact": {"type": "boolean", "description": "Match `name` exactly."},
    }));
    let mut listclass_props = with_props(json!({
        "prefix": {"type": "string", "description": "Package / class prefix (com.poc or Lcom/poc)."},
    }));
    for props in [&mut findrefs_props, &mut listclass_props] {
        if let (Some(p), Some(e)) = (props.as_object_mut(), page_props().as_object()) {
            p.extend(e.clone());
        }
    }
    json!([
        {
            "name": "open_apk",
            "description": "Open an APK for this session and return its apk_id. With warm (default true) every DEX is \
                inflated now, so later calls answer from memory. Opening the same path again returns the same apk_id.",
            "inputSchema": {"type": "object", "properties": {
                "apk": {"type": "string", "description": "APK path."},
                "warm": {"type": "boolean", "description": "Inflate every DEX now (default true)."},
            }, "required": ["apk"]},
        },
        {
            "name": "close_apk",
            "description": "Forget an opened APK.",
            "inputSchema": {"type": "object", "properties": apk_props()},
        },
        {
            "name": "getclass",
            "description": "Disassemble one class to smali (rebuilt into a minimal DEX first).",
            "inputSchema": {"type": "object", "properties": with_props(json!({
                "class": {"type": "string", "description": "Lcom/poc/Main; or com.poc.Main."},
                "debug_info": {"type": "boolean", "description": "Emit .line / .param directives (default true)."},
            })), "required": ["class"]},
        },
        {
            "name": "findrefs",
            "description": "Find code references to a string, type, method or field across every DEX. One line per \
                referencing method: `dex | Lcls;->method | matched=(...)`. Paged; the last line says how many there are.",
            "inputSchema": {"type": "object", "properties": findrefs_props, "required": ["kind"]},
        },
        {
            "name": "listclass",
            "description": "List the classes the APK defines, in DEX order. Paged.",
            "inputSchema": {"type": "object", "properties": listclass_props},
        },
        {
            "name": "getmanifest",
            "description": "Decode AndroidManifest.xml.",
            "inputSchema": {"type": "object", "properties": apk_props()},
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
