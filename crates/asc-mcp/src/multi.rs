//! Tool calls over many APKs at once: target selection, one work queue for
//! every APK's units, and a paged report that fits an agent's context.
//!
//! A multi-APK tool names its targets with `apks` (paths) or `dir` (plus
//! `glob`), plans each APK into weighted units (findrefs: one per DEX entry,
//! weighted by inflated size), and runs all units of all APKs on one pool,
//! heaviest first, so the largest DEX of the whole set starts at once instead
//! of waiting behind a run of small APKs. Each APK becomes a [`Section`] of
//! pre-rendered lines; [`Report::page`] emits whole sections up to a byte
//! budget and returns a cursor for the rest.

use crate::{lock, OpenApk, ToolError};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// Default output budget of one multi-APK reply (text bytes, about 8k tokens).
pub const MAX_BYTES: usize = 32 << 10;
/// Default budget of one APK's section.
pub const MAX_APK_BYTES: usize = 4 << 10;
/// Most apk_ids of empty APKs a page lists by name.
const MAX_EMPTY_LISTED: usize = 32;
/// Directory levels `dir` descends.
const MAX_DEPTH: usize = 8;

/// The APK paths `args` selects with `apks` or `dir` / `glob`, sorted; `None`
/// when neither is given (a single-APK call).
pub fn targets(args: &Value) -> Result<Option<Vec<PathBuf>>, ToolError> {
    let mut paths = match (args.get("apks"), args.get("dir")) {
        (None | Some(Value::Null), None | Some(Value::Null)) => return Ok(None),
        (Some(_), Some(d)) if !d.is_null() => return Err(ToolError("pass `apks` or `dir`, not both".into())),
        (Some(list), _) => {
            let list = list.as_array().ok_or_else(|| ToolError("`apks` must be a list of paths".into()))?;
            let mut paths = Vec::with_capacity(list.len());
            for p in list {
                let p = p.as_str().ok_or_else(|| ToolError("`apks` must be a list of paths".into()))?;
                paths.push(PathBuf::from(p));
            }
            paths
        }
        (_, Some(dir)) => {
            let dir = dir.as_str().ok_or_else(|| ToolError("`dir` must be a string".into()))?;
            let glob = crate::str_arg(args, "glob")?.unwrap_or("*.apk");
            let recursive = crate::bool_arg(args, "recursive")?.unwrap_or(true);
            let mut paths = Vec::new();
            walk(Path::new(dir), glob, if recursive { MAX_DEPTH } else { 0 }, &mut paths)
                .map_err(|e| ToolError(format!("cannot list {dir}: {e}")))?;
            paths
        }
    };
    paths.sort();
    paths.dedup();
    if paths.is_empty() {
        return Err(ToolError("no APKs selected".into()));
    }
    Ok(Some(paths))
}

fn walk(dir: &Path, glob: &str, depth: usize, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        // Not followed through symlinks, so a link loop cannot recurse.
        let ty = entry.file_type()?;
        let path = entry.path();
        if ty.is_dir() {
            if depth > 0 {
                // An unreadable subdirectory is skipped, not fatal.
                let _ = walk(&path, glob, depth - 1, out);
            }
        } else if entry.file_name().to_str().is_some_and(|n| glob_match(glob.as_bytes(), n.as_bytes())) {
            out.push(path);
        }
    }
    Ok(())
}

/// Shell-style match of a file name: `*` any run, `?` one byte.
pub fn glob_match(pat: &[u8], name: &[u8]) -> bool {
    let (mut p, mut n) = (0, 0);
    // Where the last `*` was and the name position it is matching up to.
    let mut star = None;
    while n < name.len() {
        if p < pat.len() && (pat[p] == b'?' || pat[p] == name[n]) {
            p += 1;
            n += 1;
        } else if p < pat.len() && pat[p] == b'*' {
            star = Some((p, n));
            p += 1;
        } else if let Some((sp, sn)) = star {
            p = sp + 1;
            n = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    pat[p..].iter().all(|&c| c == b'*')
}

/// What one APK of a fan-out produced: its units' results in plan order, or
/// why it could not be planned (or was cancelled).
pub type Outcome<R> = Result<Vec<R>, String>;

/// An APK's plan: the context its units share, and the weighted units.
pub type Plan<C, U> = Result<(C, Vec<(u64, U)>), String>;

/// Run `run` over every unit of every APK. `plan` opens an APK and splits it
/// into `(weight, unit)`s sharing a context `C`; all units of all APKs share
/// one queue of `threads` workers, heaviest first. As soon as an APK's last
/// unit finishes, its context is dropped (with whatever it maps) and `done`
/// runs (to release what the APK caches). Units not started when `cancel` is
/// raised are skipped and the APK reports an error.
pub fn fan_out<C, U, R>(
    threads: usize,
    apks: &[Arc<OpenApk>],
    cancel: &AtomicBool,
    plan: impl Fn(&OpenApk) -> Plan<C, U> + Sync,
    run: impl Fn(&OpenApk, &C, &U) -> R + Sync,
    done: impl Fn(&OpenApk) + Sync,
) -> Vec<Outcome<R>>
where
    C: Send + Sync,
    U: Send + Sync,
    R: Send,
{
    let workers = threads.max(1);
    let next = AtomicUsize::new(0);
    let plans: Vec<Mutex<Option<Plan<C, U>>>> = apks.iter().map(|_| Mutex::new(None)).collect();
    std::thread::scope(|s| {
        for _ in 0..workers.min(apks.len()) {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(apk) = apks.get(i) else { break };
                let p = if cancel.load(Ordering::Relaxed) { Err("cancelled".to_string()) } else { plan(apk) };
                *lock(&plans[i]) = Some(p);
            });
        }
    });

    let mut contexts: Vec<Mutex<Option<Arc<C>>>> = Vec::with_capacity(apks.len());
    let mut units: Vec<Vec<U>> = Vec::with_capacity(apks.len());
    let mut failed: Vec<Option<String>> = Vec::with_capacity(apks.len());
    let mut jobs: Vec<(u64, usize, usize)> = Vec::new();
    for (a, p) in plans.into_iter().enumerate() {
        match p.into_inner().unwrap_or_else(|e| e.into_inner()).expect("planned") {
            Ok((ctx, us)) => {
                jobs.extend(us.iter().enumerate().map(|(j, (w, _))| (*w, a, j)));
                failed.push(None);
                contexts.push(Mutex::new(Some(Arc::new(ctx))));
                units.push(us.into_iter().map(|(_, u)| u).collect());
            }
            Err(e) => {
                failed.push(Some(e));
                contexts.push(Mutex::new(None));
                units.push(Vec::new());
            }
        }
    }
    let slots: Vec<Mutex<Vec<Option<R>>>> = units.iter().map(|u| Mutex::new(u.iter().map(|_| None).collect())).collect();
    let left: Vec<AtomicUsize> = units.iter().map(|u| AtomicUsize::new(u.len())).collect();
    for (a, u) in units.iter().enumerate() {
        if u.is_empty() {
            lock(&contexts[a]).take();
            done(&apks[a]);
        }
    }
    // Heaviest APK first, its units together and heaviest first: the biggest
    // work starts at once, and each APK finishes (and lets go of its mapping
    // and cache) soon after it starts instead of at the end of the sweep.
    let mut apk_weight = vec![0u64; apks.len()];
    for &(w, a, _) in &jobs {
        apk_weight[a] = apk_weight[a].saturating_add(w);
    }
    jobs.sort_by(|x, y| apk_weight[y.1].cmp(&apk_weight[x.1]).then(x.1.cmp(&y.1)).then(y.0.cmp(&x.0)).then(x.2.cmp(&y.2)));
    let next = AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..workers.min(jobs.len()) {
            s.spawn(|| loop {
                let k = next.fetch_add(1, Ordering::Relaxed);
                let Some(&(_, a, j)) = jobs.get(k) else { break };
                if !cancel.load(Ordering::Relaxed) {
                    let ctx = lock(&contexts[a]).clone().expect("a context lives until its last unit");
                    let r = run(&apks[a], &ctx, &units[a][j]);
                    lock(&slots[a])[j] = Some(r);
                }
                if left[a].fetch_sub(1, Ordering::AcqRel) == 1 {
                    // Every other unit dropped its reference before counting down.
                    lock(&contexts[a]).take();
                    done(&apks[a]);
                }
            });
        }
    });
    failed
        .into_iter()
        .zip(slots)
        .map(|(f, slot)| {
            if let Some(e) = f {
                return Err(e);
            }
            let rs: Option<Vec<R>> = slot.into_inner().unwrap_or_else(|e| e.into_inner()).into_iter().collect();
            rs.ok_or_else(|| "cancelled".to_string())
        })
        .collect()
}

/// One APK's part of a report.
pub struct Section {
    /// Lines without their trailing newline; the first one names the APK.
    pub lines: Vec<String>,
    pub json: Value,
}

impl Section {
    fn bytes(&self) -> usize {
        self.lines.iter().map(|l| l.len() + 1).sum()
    }

    /// The APK's error as a one-line section.
    pub fn error(apk: &str, path: &Path, err: &str) -> Section {
        Section {
            lines: vec![format!("{apk} | error | {} | {err}", path.display())],
            json: json!({"apk_id": apk, "path": path.display().to_string(), "error": err}),
        }
    }
}

/// A multi-APK result, kept by the server so a cursor can page through it.
pub struct Report {
    pub tool: &'static str,
    /// First line of every page: what was asked and the totals.
    pub header: String,
    pub summary: Value,
    /// APKs with something to show (hits or an error), in path order.
    pub sections: Vec<Section>,
    /// apk_ids of the APKs that had nothing to show.
    pub empty: Vec<String>,
    pub max_bytes: usize,
}

impl Report {
    /// The page starting at section `from`: whole sections up to the byte
    /// budget (at least one), and the section index to continue from.
    pub fn page(&self, from: usize, cursor_id: Option<usize>) -> (String, Value) {
        let from = from.min(self.sections.len());
        let mut text = format!("{}\n", self.header);
        let mut end = from;
        for s in &self.sections[end..] {
            if end > from && text.len() + s.bytes() > self.max_bytes {
                break;
            }
            for l in &s.lines {
                text.push_str(l);
                text.push('\n');
            }
            end += 1;
        }
        let more = end < self.sections.len();
        let cursor = match (more, cursor_id) {
            (true, Some(id)) => Some(format!("{id}:{end}")),
            _ => None,
        };
        if from == 0 && !self.empty.is_empty() {
            // A long id list is noise next to the hits; the data has it all.
            if self.empty.len() <= MAX_EMPTY_LISTED {
                text.push_str(&format!("# nothing in {} APKs: {}\n", self.empty.len(), self.empty.join(" ")));
            } else {
                text.push_str(&format!("# nothing in the other {} APKs\n", self.empty.len()));
            }
        }
        match &cursor {
            Some(c) => text.push_str(&format!(
                "# APKs {}..{} of {} shown (output budget {} bytes); call {} with cursor=\"{c}\" for the rest\n",
                from,
                end,
                self.sections.len(),
                self.max_bytes,
                self.tool
            )),
            None if from > 0 => text.push_str(&format!("# APKs {from}..{end} of {} shown\n", self.sections.len())),
            None if more => text.push_str(&format!(
                "# APKs {from}..{end} of {} shown; the report is gone, call {} again\n",
                self.sections.len(),
                self.tool
            )),
            None => {}
        }
        let mut summary = self.summary.clone();
        if let Some(o) = summary.as_object_mut() {
            o.insert("apks".into(), Value::Array(self.sections[from..end].iter().map(|s| s.json.clone()).collect()));
            o.insert("shown".into(), json!([from, end]));
            o.insert("cursor".into(), json!(cursor));
            if from == 0 {
                o.insert("empty".into(), json!(self.empty));
            }
        }
        (text, summary)
    }
}

/// Reports kept for cursors, newest last.
#[derive(Default)]
pub struct Reports {
    next_id: usize,
    kept: Vec<(usize, Arc<Report>)>,
}

/// Reports a session keeps for paging; older ones are dropped.
const KEPT_REPORTS: usize = 16;

impl Reports {
    pub fn keep(&mut self, report: Arc<Report>) -> usize {
        self.next_id += 1;
        let id = self.next_id;
        if self.kept.len() == KEPT_REPORTS {
            self.kept.remove(0);
        }
        self.kept.push((id, report));
        id
    }

    pub fn get(&self, id: usize) -> Option<Arc<Report>> {
        self.kept.iter().find(|(i, _)| *i == id).map(|(_, r)| Arc::clone(r))
    }
}

/// Parse a cursor `"<report>:<section>"`.
pub fn parse_cursor(c: &str) -> Option<(usize, usize)> {
    let (a, b) = c.split_once(':')?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

/// Package prefixes of common third-party SDKs, as descriptor prefixes.
pub const DEFAULT_SDK_PREFIXES: &[&str] = &[
    "Landroid/support/",
    "Landroidx/",
    "Lkotlin/",
    "Lkotlinx/",
    "Lcom/google/android/gms/",
    "Lcom/google/android/material/",
    "Lcom/google/firebase/",
    "Lcom/google/common/",
    "Lcom/google/protobuf/",
    "Lcom/google/gson/",
    "Lcom/google/crypto/tink/",
    "Lcom/google/errorprone/",
    "Lcom/google/thirdparty/",
    "Ldagger/",
    "Ljavax/inject/",
    "Lokhttp3/",
    "Lokio/",
    "Lretrofit2/",
    "Lcom/squareup/",
    "Lcom/bumptech/glide/",
    "Lcom/facebook/",
    "Lio/reactivex/",
    "Lio/grpc/",
    "Lorg/apache/",
    "Lorg/json/",
    "Lorg/intellij/",
    "Lorg/jetbrains/",
    "Lorg/chromium/",
    "Lcom/fasterxml/",
    "Lcom/tencent/",
    "Lcom/alibaba/",
    "Lcom/alipay/",
    "Lcom/huawei/hms/",
    "Lcom/bytedance/sdk/",
    "Lcom/umeng/",
];

/// Descriptor-form package prefixes (`Lcom/foo/`) from `com.foo` / `Lcom/foo/` spellings.
pub fn normalize_prefix(p: &str) -> String {
    let mut d = p.trim().replace('.', "/");
    if !d.starts_with('L') {
        d.insert(0, 'L');
    }
    if !d.ends_with('/') {
        d.push('/');
    }
    d
}

/// The class descriptor of a result's `Lcls;->member` (or a bare `Lcls;`).
pub fn result_class(method: &str) -> &str {
    method.split("->").next().unwrap_or(method)
}

/// The first `depth` package segments of a class descriptor, as `Lcom/foo/`;
/// the default package is `L`.
pub fn package_of(class: &str, depth: usize) -> &str {
    let body = class.strip_prefix('L').unwrap_or(class);
    let mut end = 0;
    for (i, _) in body.match_indices('/').take(depth) {
        end = i + 1;
    }
    &class[..1 + end.min(body.len())]
}

/// The SDK prefix `class` falls under, if any.
pub fn sdk_of<'a>(prefixes: &'a [String], class: &str) -> Option<&'a str> {
    prefixes.iter().map(String::as_str).filter(|p| class.starts_with(p)).max_by_key(|p| p.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globs_match_file_names() {
        let m = |p: &str, n: &str| glob_match(p.as_bytes(), n.as_bytes());
        assert!(m("*.apk", "Chrome.apk"));
        assert!(!m("*.apk", "Chrome.apk.idsig"));
        assert!(m("Go*gle*.apk", "GoogleCamera.apk"));
        assert!(m("a?c", "abc") && !m("a?c", "ac"));
        assert!(m("*", "") && m("**x*", "aax"));
    }

    #[test]
    fn packages_and_sdks() {
        assert_eq!(package_of("Lcom/foo/bar/Baz;", 2), "Lcom/foo/");
        assert_eq!(package_of("Lcom/foo/bar/Baz;", 9), "Lcom/foo/bar/");
        assert_eq!(package_of("LTop;", 3), "L");
        assert_eq!(result_class("Lcom/a/B;->m"), "Lcom/a/B;");
        assert_eq!(normalize_prefix("com.google.android.gms"), "Lcom/google/android/gms/");
        let sdks: Vec<String> = ["Lcom/google/", "Lcom/google/android/gms/"].map(String::from).to_vec();
        assert_eq!(sdk_of(&sdks, "Lcom/google/android/gms/X;"), Some("Lcom/google/android/gms/"));
        assert_eq!(sdk_of(&sdks, "Lcom/poc/X;"), None);
    }

    #[test]
    fn pages_split_on_whole_sections() {
        let section = |i: usize| Section { lines: vec![format!("apk{i} | x"), "y".repeat(40)], json: json!(i) };
        let report = Report {
            tool: "findrefs",
            header: "# head".into(),
            summary: json!({}),
            sections: (0..5).map(section).collect(),
            empty: vec!["apk9".into()],
            max_bytes: 120,
        };
        let (text, v) = report.page(0, Some(3));
        assert!(text.starts_with("# head\napk0 | x\n"), "{text}");
        assert!(text.contains("# nothing in 1 APKs: apk9\n"));
        assert_eq!(v["cursor"], "3:2");
        let (text, v) = report.page(4, Some(3));
        assert_eq!(v["cursor"], Value::Null);
        assert!(text.ends_with("# APKs 4..5 of 5 shown\n"), "{text}");
        // A section larger than the budget is still shown on its own page.
        let big = Report { max_bytes: 1, ..report };
        assert_eq!(big.page(0, Some(1)).1["shown"], json!([0, 1]));
    }
}
