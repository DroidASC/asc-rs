//! `manifest_summary` and `resources`: the APK's manifest attack surface and
//! its resource table, for one APK or (`apks` / `dir`) many.

use crate::multi::{self, Report, Section};
use crate::{bool_arg, max_bytes, str_arg, usize_arg, Call, OpenApk, Server, ToolError, ToolResult};
use asc_engine::{ManifestSummary, ResourceField, ResourceRow};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Instant;

/// Records per APK in a multi-APK manifest summary.
const SUMMARY_PER_APK: usize = 40;
/// Rows of a single-APK resource search.
const RESOURCES_LIMIT: usize = 200;

/// Which records of a summary to show.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Filter {
    All,
    /// Exported components, deep links, non-signature permissions,
    /// cleartext domains and warnings: what an outside app can reach.
    Exported,
}

fn filter_arg(args: &Value, default: Filter) -> Result<Filter, ToolError> {
    match str_arg(args, "filter")? {
        None => Ok(default),
        Some("all") => Ok(Filter::All),
        Some("exported") => Ok(Filter::Exported),
        Some(f) => Err(ToolError(format!("unknown filter {f:?}: use all or exported"))),
    }
}

/// `summary.lines()`, or only the externally reachable part.
fn summary_lines(s: &ManifestSummary, filter: Filter) -> Vec<String> {
    let lines = s.lines();
    if filter == Filter::All {
        return lines;
    }
    let kinds = ["activity ", "activity-alias ", "service ", "receiver ", "provider "];
    lines
        .into_iter()
        .filter(|l| {
            (kinds.iter().any(|k| l.starts_with(k)) && l.contains(" exported=true "))
                || l.starts_with("deeplink ")
                || l.starts_with("warning ")
                || (l.starts_with("permission ") && !l.contains("protectionLevel=signature"))
                || (l.starts_with("nsc ") && l.contains("cleartextTrafficPermitted=true"))
        })
        .collect()
}

/// `exported: 3 activity, 1 provider` counts, and the flags an auditor checks first.
fn summary_head(s: &ManifestSummary) -> String {
    let mut counts: Vec<(&str, usize)> = Vec::new();
    for c in s.components.iter().filter(|c| c.exported) {
        match counts.iter_mut().find(|(k, _)| *k == c.kind) {
            Some((_, n)) => *n += 1,
            None => counts.push((&c.kind, 1)),
        }
    }
    let exported =
        if counts.is_empty() { "none".to_string() } else { counts.iter().map(|(k, n)| format!("{n} {k}")).collect::<Vec<_>>().join(", ") };
    let a = &s.application;
    let mut flags = Vec::new();
    if a.debuggable {
        flags.push("debuggable");
    }
    if a.allow_backup {
        flags.push("allowBackup");
    }
    if a.cleartext_effective.0 {
        flags.push("cleartext");
    }
    if a.test_only {
        flags.push("testOnly");
    }
    let opt = |v: Option<i64>| v.map_or("-".to_string(), |v| v.to_string());
    format!(
        "{} | minSdk={} targetSdk={} | exported: {exported} | flags: {}",
        s.package,
        opt(s.min_sdk),
        opt(s.target_sdk),
        if flags.is_empty() { "-".to_string() } else { flags.join(",") }
    )
}

/// The summary JSON, with only exported components under [`Filter::Exported`].
fn summary_json(s: &ManifestSummary, filter: Filter) -> Value {
    let mut v = s.json();
    if filter == Filter::Exported {
        if let Some(list) = v["components"].as_array_mut() {
            list.retain(|c| c["exported"] == true);
        }
    }
    v
}

fn rows_json(rows: &[ResourceRow]) -> Value {
    Value::Array(rows.iter().map(ResourceRow::json).collect())
}

fn field_arg(args: &Value) -> Result<ResourceField, ToolError> {
    match str_arg(args, "in")?.unwrap_or("any") {
        "name" => Ok(ResourceField::Name),
        "value" => Ok(ResourceField::Value),
        "any" => Ok(ResourceField::Any),
        f => Err(ToolError(format!("unknown `in` {f:?}: use name, value or any"))),
    }
}

/// What one APK's `resources` call answers: matching rows and their total.
fn resource_rows(apk: &OpenApk, args: &Value, limit: usize) -> Result<(Vec<ResourceRow>, usize, Vec<String>), ToolError> {
    let engine = &apk.engine;
    if let Some(pattern) = str_arg(args, "search")? {
        let (rows, total) = engine.search_resources(pattern, bool_arg(args, "literal")?.unwrap_or(false), field_arg(args)?, limit)?;
        return Ok((rows, total, Vec::new()));
    }
    let Some(query) = str_arg(args, "query")? else {
        return Err(ToolError("resources needs `query` (an id or type/name), `search` or `xml`".into()));
    };
    if bool_arg(args, "resolve")?.unwrap_or(false) {
        let (chain, row) = engine.resolve_resource(query, None)?;
        return Ok((vec![row], 1, chain));
    }
    let rows = engine.resource(query)?;
    let total = rows.len();
    Ok((rows.into_iter().take(limit).collect(), total, Vec::new()))
}

impl Server {
    pub(crate) fn manifest_summary(&self, args: &Value, call: &Call) -> ToolResult {
        if let Some(paths) = multi::targets(args)? {
            return self.manifest_summary_many(args, call, &paths);
        }
        let apk = self.resolve(args)?;
        let filter = filter_arg(args, Filter::All)?;
        let s = apk.engine.manifest_summary()?;
        let mut text = String::new();
        if filter == Filter::Exported {
            text.push_str(&summary_head(&s));
            text.push('\n');
        }
        for l in summary_lines(&s, filter) {
            text.push_str(&l);
            text.push('\n');
        }
        let mut structured = summary_json(&s, filter);
        structured["apk_id"] = json!(apk.id);
        Ok((text, structured))
    }

    /// The exposure survey of many APKs: per APK a head line (package, SDKs,
    /// exported component counts, risky flags) and its reachable records.
    fn manifest_summary_many(&self, args: &Value, call: &Call, paths: &[PathBuf]) -> ToolResult {
        let t = Instant::now();
        let filter = filter_arg(args, Filter::Exported)?;
        let per_apk = usize_arg(args, "per_apk")?.unwrap_or(SUMMARY_PER_APK);
        let (sections, empty, stats) = self.sweep(
            paths,
            call,
            // Manifests never touch the DEX cache.
            Some(false),
            |apk| {
                let bytes = std::fs::metadata(&apk.path).map(|m| m.len()).unwrap_or(0);
                Ok(((), vec![(bytes, ())]))
            },
            |apk, (), ()| apk.engine.manifest_summary().map_err(|e| e.to_string()),
            |apk, r| {
                let s = match r.into_iter().next().expect("one unit") {
                    Ok(s) => s,
                    Err(e) => return (0, Some(Section::error(&apk.id, &apk.path, &e))),
                };
                let id = &apk.id;
                let exported = s.components.iter().filter(|c| c.exported).count();
                let mut lines = vec![format!("{id} | {} | {}", summary_head(&s), apk.path.display())];
                let mut bytes = lines[0].len();
                let records = summary_lines(&s, filter);
                let mut shown = 0;
                for l in records.iter().take(per_apk) {
                    let line = format!("{id} | {l}");
                    if bytes + line.len() >= multi::MAX_APK_BYTES {
                        break;
                    }
                    bytes += line.len() + 1;
                    lines.push(line);
                    shown += 1;
                }
                if shown < records.len() {
                    lines.push(format!("{id} | more | {} more: manifest_summary apk_id={id}", records.len() - shown));
                }
                let mut json = summary_json(&s, filter);
                json["apk_id"] = json!(id);
                json["path"] = json!(apk.path.display().to_string());
                (exported, Some(Section { lines, json }))
            },
        );
        call.check()?;
        let ms = t.elapsed().as_secs_f64() * 1e3;
        let header = format!(
            "# manifest_summary over {} APKs: {} with exported components, {} exported, {} errors, {ms:.0} ms",
            paths.len(),
            stats.with_hits,
            stats.hits,
            stats.errors
        );
        let summary = json!({
            "apks_total": paths.len(),
            "apks_with_exported": stats.with_hits,
            "exported_total": stats.hits,
            "errors": stats.errors,
            "elapsed_ms": ms,
        });
        self.report(Report { tool: "manifest_summary", header, summary, sections, empty, max_bytes: max_bytes(args)? })
    }

    pub(crate) fn resources(&self, args: &Value, call: &Call) -> ToolResult {
        if let Some(paths) = multi::targets(args)? {
            return self.resources_many(args, call, &paths);
        }
        let apk = self.resolve(args)?;
        if let Some(path) = str_arg(args, "xml")? {
            let xml = apk.engine.xml(path)?;
            return Ok((xml.clone(), json!({"apk_id": apk.id, "path": path, "xml": xml})));
        }
        let limit = usize_arg(args, "limit")?.unwrap_or(RESOURCES_LIMIT).max(1);
        let (rows, total, chain) = resource_rows(&apk, args, limit)?;
        let mut text = String::new();
        if !chain.is_empty() {
            text.push_str(&format!("chain {}\n", chain.join(" -> ")));
        }
        for r in &rows {
            text.push_str(&r.line());
            text.push('\n');
        }
        if total > rows.len() {
            text.push_str(&format!("# {} of {total} rows; raise `limit` for more\n", rows.len()));
        } else {
            text.push_str(&format!("# {total} rows\n"));
        }
        let structured = json!({"apk_id": apk.id, "total": total, "rows": rows_json(&rows), "chain": chain});
        Ok((text, structured))
    }

    /// A resource lookup or search over many APKs: one section per APK with
    /// matches.
    fn resources_many(&self, args: &Value, call: &Call, paths: &[PathBuf]) -> ToolResult {
        let t = Instant::now();
        if str_arg(args, "xml")?.is_some() {
            return Err(ToolError("`xml` reads one APK; pass apk_id or apk".into()));
        }
        // Fail on bad arguments once, not once per APK.
        field_arg(args)?;
        if str_arg(args, "search")?.is_none() && str_arg(args, "query")?.is_none() {
            return Err(ToolError("resources needs `query` (an id or type/name) or `search`".into()));
        }
        let per_apk = usize_arg(args, "per_apk")?.unwrap_or(crate::PER_APK);
        let (sections, empty, stats) = self.sweep(
            paths,
            call,
            Some(false),
            |apk| {
                let bytes = std::fs::metadata(&apk.path).map(|m| m.len()).unwrap_or(0);
                Ok(((), vec![(bytes, ())]))
            },
            |apk, (), ()| resource_rows(apk, args, per_apk).map_err(|e| e.0),
            |apk, r| {
                let (rows, total, chain) = match r.into_iter().next().expect("one unit") {
                    Ok(r) => r,
                    // A name the APK does not define is no match, not an error.
                    Err(e) if e.starts_with("no resource") => return (0, None),
                    Err(e) => return (0, Some(Section::error(&apk.id, &apk.path, &e))),
                };
                if total == 0 {
                    return (0, None);
                }
                let id = &apk.id;
                let mut lines = vec![format!("{id} | {total} rows | {}", apk.path.display())];
                if !chain.is_empty() {
                    lines.push(format!("{id} | chain {}", chain.join(" -> ")));
                }
                lines.extend(rows.iter().map(|r| format!("{id} | {}", r.line())));
                if total > rows.len() {
                    lines.push(format!("{id} | more | {} more: resources apk_id={id} limit={total}", total - rows.len()));
                }
                let json =
                    json!({"apk_id": id, "path": apk.path.display().to_string(), "total": total, "rows": rows_json(&rows), "chain": chain});
                (total, Some(Section { lines, json }))
            },
        );
        call.check()?;
        let ms = t.elapsed().as_secs_f64() * 1e3;
        let what = str_arg(args, "search")?.map(|s| format!("search {s:?}")).or(str_arg(args, "query")?.map(|q| format!("query {q}")));
        let header = format!(
            "# resources {} over {} APKs: {} with rows, {} rows, {} errors, {ms:.0} ms",
            what.unwrap_or_default(),
            paths.len(),
            stats.with_hits,
            stats.hits,
            stats.errors
        );
        let summary = json!({"apks_total": paths.len(), "apks_with_hits": stats.with_hits, "total": stats.hits, "errors": stats.errors, "elapsed_ms": ms});
        self.report(Report { tool: "resources", header, summary, sections, empty, max_bytes: max_bytes(args)? })
    }
}

/// `tools/list` entries of this module's tools.
pub mod defs {
    use crate::defs::{apk_props, many, merge};
    use serde_json::{json, Value};

    pub fn manifest_summary() -> Value {
        json!({
            "description": "The manifest's attack surface, one record per line: `package`, `application` (debuggable, \
                allowBackup, effective cleartext policy, network security config), `uses-permission`, `permission` \
                (protectionLevel), one line per component (`activity <class> exported=true (intent-filter)`: exported or \
                not and why, permission, provider authorities / grantUriPermissions / read / write permissions), \
                `intent-filter`, `deeplink <class> scheme://host/path*`, `provider-path` (FileProvider paths) and `nsc` \
                (network security config). Resource references are resolved; a boolean that differs between \
                configurations lists every variant. Class names are fully qualified, ready for getclass. With apks / \
                dir: per APK a head line (package, SDKs, exported counts, risky flags) and its exported records.",
            "inputSchema": {"type": "object", "properties": merge(apk_props(), &[json!({
                "filter": {"type": "string", "enum": ["all", "exported"], "description": "all records, or only what other \
                    apps can reach: exported components, deep links, non-signature permissions, cleartext domains \
                    (default all for one APK, exported for many)."},
            }), many()])},
        })
    }

    pub fn resources() -> Value {
        json!({
            "description": "Query resources.arsc. One row per resource and configuration: `0x7f0d0001 string/app_name \
                [zh-rCN] \"value\"` (no brackets for the default configuration; bags as {parent=@style/X key=value ...}). \
                `query` lists every configuration's value of one resource (with `resolve`: follows the reference chain); \
                `search` matches names and / or string values; `xml` decodes a binary XML file of the APK \
                (res/xml/..., layouts) with references shown by name. With apks / dir: `query` or `search` in each APK.",
            "inputSchema": {"type": "object", "properties": merge(apk_props(), &[json!({
                "query": {"type": "string", "description": "A resource id (0x7f0d0001) or name (string/app_name, @pkg:type/name)."},
                "resolve": {"type": "boolean", "description": "With query: follow references to the final value."},
                "search": {"type": "string", "description": "Regex over resource names and string values."},
                "literal": {"type": "boolean", "description": "Match `search` as plain text."},
                "in": {"type": "string", "enum": ["name", "value", "any"], "description": "What `search` matches (default any)."},
                "limit": {"type": "integer", "minimum": 1, "description": "Most rows to return (default 200)."},
                "xml": {"type": "string", "description": "Path of a binary XML file inside the APK to decode."},
            }), many()])},
        })
    }
}
