//! Fitting a tool's reply into an agent's context.
//!
//! Every reply is held to an output budget (`max_bytes`, default
//! [`MAX_BYTES`]): clients cut long tool results (Grok Build at about 20 KB)
//! and every byte returned is re-read on each later turn. What does not fit
//! goes, by `spill`:
//!
//! * `auto` (default): to a file (`out/<sha256>.txt` in the cache directory),
//!   the reply carrying its head, the absolute path, its size and, for smali,
//!   an index of where each method is. For clients whose agent can read files.
//! * `always`: every reply to a file, inline only its head.
//! * `never`: pages of whole records (lines, or a line and the indented lines
//!   under it) with the complete arguments of the call for the next one.
//!
//! A tool can also hand over more than it shows inline (a class outline
//! standing for the whole class, the first page of a multi-APK report) by
//! putting the whole text under [`FULL`] in its structured result.

use crate::{choice_arg, usize_arg, ToolError};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

/// Default output budget of one reply (text bytes, about 4k tokens).
pub const MAX_BYTES: usize = 16 << 10;
/// Smallest budget a call may ask for.
const MIN_BYTES: usize = 256;
/// Inline head of a reply whose full text went to a file.
const HEAD_BYTES: usize = 2 << 10;
/// Default disk budget of the spill directory.
pub const SPILL_BUDGET: u64 = 64 << 20;
/// Structured-result key under which a tool passes the full text behind
/// what it shows inline; removed before the reply is sent.
pub(crate) const FULL: &str = "__full";
/// Structured-result key marking text a tool already paged to the budget
/// itself (a multi-APK report page, with its cursor): sent as it is, the
/// full text only spilled next to it.
pub(crate) const FITTED: &str = "__fitted";

/// Where text that does not fit the budget goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Spill {
    Auto,
    Always,
    Never,
}

impl Spill {
    fn from_args(args: &Value) -> Result<Spill, ToolError> {
        const CHOICES: &[(&str, &[&str])] =
            &[("auto", &["default"]), ("always", &["yes", "true", "file"]), ("never", &["no", "false", "off"])];
        Ok(match choice_arg(args, "spill", "auto", CHOICES)? {
            "always" => Spill::Always,
            "never" => Spill::Never,
            _ => Spill::Auto,
        })
    }
}

/// The budget a call asks for.
pub fn budget(args: &Value) -> Result<usize, ToolError> {
    Ok(usize_arg(args, "max_bytes")?.unwrap_or(MAX_BYTES).max(MIN_BYTES))
}

/// A directory of spilled replies, kept under a byte budget (oldest first out).
pub struct SpillDir {
    dir: PathBuf,
    budget: u64,
    /// Serializes write + prune, so a prune never removes a file another
    /// call has just written and is about to name.
    lock: Mutex<()>,
}

impl SpillDir {
    pub fn new(dir: PathBuf, budget: u64) -> SpillDir {
        SpillDir { dir, budget, lock: Mutex::new(()) }
    }

    /// `out/` in the disk cache directory, else `$XDG_RUNTIME_DIR/droidasc/out`,
    /// else a per-user directory under the system temporary directory.
    pub fn default_dir(cache_dir: Option<&Path>) -> PathBuf {
        if let Some(d) = cache_dir {
            return d.join(asc_engine::asc_cache::SPILL_DIR);
        }
        if let Some(run) = std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
            return PathBuf::from(run).join("droidasc").join("out");
        }
        let user = std::env::var("USER").unwrap_or_else(|_| "user".into());
        std::env::temp_dir().join(format!("droidasc-{user}")).join("out")
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Write `text` (or find it already written: files are named by content)
    /// and return its path.
    pub fn write(&self, text: &str) -> io::Result<PathBuf> {
        let _guard = self.lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        create_private_dir(&self.dir)?;
        let digest = Sha256::digest(text.as_bytes());
        let name: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
        let path = self.dir.join(format!("{name}.txt"));
        if path.is_file() {
            // Reused: mark it recently used so the prune keeps it.
            fs::File::options().append(true).open(&path)?.set_modified(SystemTime::now())?;
        } else {
            let tmp = self.dir.join(format!("{name}.{}.tmp", std::process::id()));
            let mut f = private_file(&tmp)?;
            f.write_all(text.as_bytes())?;
            drop(f);
            fs::rename(&tmp, &path)?;
        }
        self.prune(&path);
        Ok(path)
    }

    /// Remove the least recently used files until the directory fits its
    /// budget; `keep` (just written) always stays.
    fn prune(&self, keep: &Path) {
        let Ok(rd) = fs::read_dir(&self.dir) else { return };
        let mut files: Vec<(SystemTime, PathBuf, u64)> = rd
            .flatten()
            .filter_map(|e| {
                let m = e.metadata().ok()?;
                m.is_file().then(|| (m.modified().unwrap_or(SystemTime::UNIX_EPOCH), e.path(), m.len()))
            })
            .collect();
        let mut total: u64 = files.iter().map(|f| f.2).sum();
        files.sort();
        for (_, path, len) in files {
            if total <= self.budget {
                break;
            }
            if path != keep && fs::remove_file(&path).is_ok() {
                total -= len;
            }
        }
    }
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if !dir.is_dir() {
        fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    }
    // Replies can quote an APK's strings and code: this user only.
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)
}

#[cfg(unix)]
fn private_file(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::File::options().write(true).create(true).truncate(true).mode(0o600).open(path)
}

#[cfg(not(unix))]
fn private_file(path: &Path) -> io::Result<fs::File> {
    fs::File::create(path)
}

/// A reply fitted to its budget, and the file it points at, if any.
pub struct Fitted {
    pub text: String,
    pub structured: Value,
    /// An MCP `resource_link` content item for the spilled file.
    pub link: Option<Value>,
}

/// The call a reply answers, as far as fitting it goes.
struct Request<'a> {
    tool: &'a str,
    args: &'a Value,
    budget: usize,
    mode: Spill,
    /// `page` can page through the output (not a report, which has a cursor).
    pageable: bool,
}

impl Request<'_> {
    /// The call's arguments with `extra` set (and no `cursor`): the call
    /// for another page of the same output.
    fn with(&self, extra: &[(&str, Value)]) -> Value {
        let mut args: Map<String, Value> = self.args.as_object().cloned().unwrap_or_default();
        args.remove("cursor");
        for (k, v) in extra {
            args.insert((*k).into(), v.clone());
        }
        Value::Object(args)
    }
}

/// Fit a tool's `text` to the budget `args` ask for (see the module docs).
pub fn fit(tool: &str, args: &Value, text: String, mut structured: Value, spill: Option<&SpillDir>) -> Result<Fitted, ToolError> {
    let req = Request { tool, args, budget: budget(args)?, mode: Spill::from_args(args)?, pageable: true };
    let full = structured.as_object_mut().and_then(|o| o.remove(FULL)).and_then(|v| match v {
        Value::String(s) => Some(s),
        _ => None,
    });
    let fitted = structured.as_object_mut().and_then(|o| o.remove(FITTED)).is_some();
    if fitted {
        return Ok(match (req.mode, full, spill) {
            (Spill::Auto | Spill::Always, Some(full), Some(dir)) => match dir.write(&full) {
                Ok(path) => {
                    let req = Request { mode: Spill::Auto, budget: usize::MAX, pageable: false, ..req };
                    spilled(&req, &text, &full, &path, structured)
                }
                Err(_) => Fitted { text, structured, link: None },
            },
            _ => Fitted { text, structured, link: None },
        });
    }
    if let Some(part) = usize_arg(args, "page")? {
        return paged(&req, full.as_deref().unwrap_or(&text), part, structured);
    }
    let over = text.len() > req.budget;
    let to_file = match req.mode {
        Spill::Never => false,
        Spill::Always => true,
        Spill::Auto => over || full.is_some(),
    };
    let mut warning = None;
    if to_file {
        if let Some(dir) = spill {
            let content = full.as_deref().unwrap_or(&text);
            match dir.write(content) {
                Ok(path) => return Ok(spilled(&req, &text, content, &path, structured)),
                Err(e) => warning = Some(format!("# Warning: cannot write the full output to {}: {e}\n", dir.dir().display())),
            }
        }
    }
    if over {
        let mut f = paged(&req, full.as_deref().unwrap_or(&text), 0, structured)?;
        if let Some(w) = warning {
            f.text.push_str(&w);
        }
        return Ok(f);
    }
    Ok(Fitted { text, structured, link: None })
}

/// The reply for a file holding `content`: `text` itself when it fits (and
/// spill is not `always`), else its head; then the path, the call that pages
/// through it instead and, for a class, where each method is.
fn spilled(req: &Request<'_>, text: &str, content: &str, path: &Path, mut structured: Value) -> Fitted {
    let budget = req.budget;
    let fits = text.len() <= budget && req.mode != Spill::Always;
    let mut out = if fits { text.to_string() } else { head(text, HEAD_BYTES.min(budget)) };
    let lines = content.lines().count();
    let index = if req.tool == "getclass" { method_index(content) } else { Vec::new() };
    out.push_str(&format!(
        "# full output ({lines} lines, {} bytes) in {}; read the lines you need from it (grep / read with an offset)",
        content.len(),
        path.display()
    ));
    if req.pageable {
        out.push_str(&format!(", or page through it here: {} {}", req.tool, req.with(&[("spill", json!("never")), ("page", json!(0))])));
    }
    out.push('\n');
    if !index.is_empty() {
        out.push_str(&format!("# methods in that file ({}), by line:\n", index.len()));
        for (i, (sig, a, b)) in index.iter().enumerate() {
            let line = format!("#   {a}-{b} {sig}\n");
            if out.len() + line.len() > budget {
                out.push_str(&format!("#   ... {} more, see `index`\n", index.len() - i));
                break;
            }
            out.push_str(&line);
        }
    }
    let uri = format!("file://{}", path.display());
    if let Some(o) = structured.as_object_mut() {
        o.insert("file".into(), json!(path.display().to_string()));
        o.insert("lines".into(), json!(lines));
        o.insert("bytes".into(), json!(content.len()));
        o.insert("truncated".into(), json!(!fits));
        if !index.is_empty() {
            let index: Vec<Value> = index.iter().map(|(sig, a, b)| json!({"method": sig, "lines": [a, b]})).collect();
            o.insert("index".into(), Value::Array(index));
        }
    }
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let link = json!({"type": "resource_link", "uri": uri, "name": name, "mimeType": "text/plain", "size": content.len(),
        "description": "The full output of this tool call."});
    Fitted { text: out, structured, link: Some(link) }
}

/// Part `part` of `text`: whole records up to the budget (less room for the
/// footer), and the arguments of the call for the next part.
fn paged(req: &Request<'_>, text: &str, part: usize, mut structured: Value) -> Result<Fitted, ToolError> {
    let footer = req.args.to_string().len() + req.tool.len() + 96;
    let pages = pages(text, req.budget.saturating_sub(footer).max(MIN_BYTES / 2));
    let Some(page) = pages.get(part) else {
        return Err(ToolError(format!("there is no page {part}: this output has {} (0..{})", pages.len(), pages.len())));
    };
    let mut out = page.to_string();
    if !out.ends_with('\n') {
        // A line longer than a page, continued on the next one.
        out.push_str(" [continues]\n");
    }
    let next = (part + 1 < pages.len()).then(|| req.with(&[("page", json!(part + 1))]));
    match &next {
        Some(n) => out.push_str(&format!(
            "# page {part} of 0..{} (output budget {} bytes); next page: {} {n}\n",
            pages.len(),
            req.budget,
            req.tool
        )),
        None if part > 0 => out.push_str(&format!("# page {part}, the last of 0..{}\n", pages.len())),
        None => {}
    }
    if let Some(o) = structured.as_object_mut() {
        o.insert("page".into(), json!(part));
        o.insert("pages".into(), json!(pages.len()));
        o.insert("next".into(), json!(next));
    }
    Ok(Fitted { text: out, structured, link: None })
}

/// `text` split into pages of whole records, each within `budget` (a record
/// longer than that is split at lines, a line at a character boundary).
fn pages(text: &str, budget: usize) -> Vec<&str> {
    let mut pages = Vec::new();
    let mut start = 0;
    let mut end = 0;
    for r in records(text) {
        let r_end = offset_of(text, r) + r.len();
        if r_end - start <= budget {
            end = r_end;
            continue;
        }
        if end > start {
            pages.push(&text[start..end]);
            start = end;
        }
        if r_end - start <= budget {
            end = r_end;
            continue;
        }
        // One record over the budget: split it.
        for chunk in split_long(&text[start..r_end], budget) {
            pages.push(chunk);
        }
        start = r_end;
        end = r_end;
    }
    if end > start {
        pages.push(&text[start..end]);
    }
    if pages.is_empty() {
        pages.push(text);
    }
    pages
}

fn offset_of(text: &str, part: &str) -> usize {
    part.as_ptr() as usize - text.as_ptr() as usize
}

/// Records of `text`, each with its trailing newline: a line that starts in
/// column 0, with the indented and blank lines after it (a findrefs row and
/// its context, a smali method body).
fn records(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut pos = 0;
    for line in text.split_inclusive('\n') {
        let continues = line.starts_with([' ', '\t']) || line.trim().is_empty();
        if pos > start && !continues {
            out.push(&text[start..pos]);
            start = pos;
        }
        pos += line.len();
    }
    if pos > start {
        out.push(&text[start..pos]);
    }
    out
}

/// `text` (over `budget`) in chunks of whole lines, a longer line in pieces.
fn split_long(text: &str, budget: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut end = 0;
    for line in text.split_inclusive('\n') {
        let l_end = end + line.len();
        if l_end - start > budget && end > start {
            out.push(&text[start..end]);
            start = end;
        }
        if l_end - start > budget {
            let mut s = start;
            while l_end - s > budget {
                let mut cut = s + budget;
                while !text.is_char_boundary(cut) {
                    cut -= 1;
                }
                out.push(&text[s..cut]);
                s = cut;
            }
            start = s;
        }
        end = l_end;
    }
    if end > start {
        out.push(&text[start..end]);
    }
    out
}

/// Whole lines of `text` up to `max` bytes (at least part of the first).
fn head(text: &str, max: usize) -> String {
    let mut out = String::new();
    for line in text.split_inclusive('\n') {
        if out.len() + line.len() > max {
            if out.is_empty() {
                let mut cut = max;
                while !line.is_char_boundary(cut) {
                    cut -= 1;
                }
                out.push_str(&line[..cut]);
                out.push('\n');
            }
            break;
        }
        out.push_str(line);
    }
    out
}

/// `(signature, first line, last line)` of every `.method` in smali `text`,
/// 1-based.
pub fn method_index(text: &str) -> Vec<(String, usize, usize)> {
    let mut out = Vec::new();
    let mut open: Option<(String, usize)> = None;
    for (i, line) in text.lines().enumerate() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix(".method ") {
            let sig = rest.split_whitespace().last().unwrap_or(rest).to_string();
            open = Some((sig, i + 1));
        } else if t.starts_with(".end method") {
            if let Some((sig, a)) = open.take() {
                out.push((sig, a, i + 1));
            }
        }
    }
    out
}

/// How much of the structured result to send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Structured {
    /// Everything the tool produced.
    Full,
    /// Without values longer than [`COMPACT_VALUE_BYTES`] when serialized:
    /// clients such as Grok Build show the model the text *and* the JSON,
    /// so the bulk (rows, smali) would be sent twice.
    Compact,
}

/// Longest top-level value [`Structured::Compact`] keeps.
const COMPACT_VALUE_BYTES: usize = 256;

impl Structured {
    pub fn apply(self, mut v: Value) -> Value {
        if self == Structured::Full {
            return v;
        }
        let Some(o) = v.as_object_mut() else { return v };
        let bulky: Vec<String> = o
            .iter()
            .filter(|(k, val)| *k != "next" && serde_json::to_string(val).map_or(0, |s| s.len()) > COMPACT_VALUE_BYTES)
            .map(|(k, _)| k.clone())
            .collect();
        for k in &bulky {
            o.remove(k);
        }
        if !bulky.is_empty() {
            o.insert("omitted".into(), json!(bulky));
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_keep_indented_lines_with_their_head() {
        let text = "a | x\n  @ pc 0x1\n  >  insn\nb | y\n\n.end method\n";
        assert_eq!(records(text), ["a | x\n  @ pc 0x1\n  >  insn\n", "b | y\n\n", ".end method\n"]);
    }

    #[test]
    fn pages_split_on_records_and_long_lines() {
        let text = "aaaa\nbbbb\ncccc\n";
        assert_eq!(pages(text, 10), ["aaaa\nbbbb\n", "cccc\n"]);
        let long = "x".repeat(25) + "\n";
        let p = pages(&long, 10);
        assert_eq!(p.concat(), long);
        assert!(p.iter().all(|s| s.len() <= 10), "{p:?}");
        // Multi-byte characters are never cut.
        let wide = "é".repeat(20);
        assert_eq!(pages(&wide, 7).concat(), wide);
    }

    #[test]
    fn method_index_names_line_ranges() {
        let smali = ".class LA;\n\n.method public a()V\n    return-void\n.end method\n\n.method static b(I)I\n    return p0\n.end method\n";
        assert_eq!(method_index(smali), [("a()V".to_string(), 3, 5), ("b(I)I".to_string(), 7, 9)]);
    }

    #[test]
    fn compact_drops_bulky_values() {
        let v = json!({"total": 3, "source": "x".repeat(600), "next": {"a": "y".repeat(600)}});
        let c = Structured::Compact.apply(v.clone());
        assert_eq!(c["total"], 3);
        assert!(c.get("source").is_none());
        assert!(c["next"].is_object());
        assert_eq!(c["omitted"], json!(["source"]));
        assert_eq!(Structured::Full.apply(v.clone()), v);
    }

    #[test]
    fn spill_files_are_named_by_content_and_pruned() {
        let dir = tempfile::tempdir().unwrap();
        let spill = SpillDir::new(dir.path().join("out"), 40);
        let a = spill.write(&"a".repeat(30)).unwrap();
        assert_eq!(spill.write(&"a".repeat(30)).unwrap(), a, "same content, same file");
        let b = spill.write(&"b".repeat(30)).unwrap();
        // Over the 40-byte budget: the older file goes, the new one stays.
        assert!(!a.exists() && b.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&b).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(fs::metadata(dir.path().join("out")).unwrap().permissions().mode() & 0o777, 0o700);
        }
    }
}
