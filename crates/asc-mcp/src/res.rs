//! `manifest_summary` and `resources`: the APK's manifest attack surface and
//! its resource table, for one APK or (`apks` / `dir`) many.

use crate::multi::{self, Report, Section};
use crate::{bool_arg, choice_arg, max_bytes, str_arg, usize_arg, Call, OpenApk, Server, ToolError, ToolResult};
use asc_engine::{ManifestSummary, ResourceField, ResourceRow};
use regex::Regex;
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
    if str_arg(args, "filter")?.is_none() {
        return Ok(default);
    }
    const CHOICES: &[(&str, &[&str])] = &[("all", &["any", "none", "everything"]), ("exported", &["export", "public", "reachable"])];
    Ok(match choice_arg(args, "filter", "exported", CHOICES)? {
        "all" => Filter::All,
        _ => Filter::Exported,
    })
}

/// `kind`: record kinds (the first word of a record: `provider`,
/// `uses-permission`, `deeplink`, ...), as a string (comma separated) or a list.
fn kinds_arg(args: &Value) -> Result<Vec<String>, ToolError> {
    let bad = || ToolError("`kind` must be a record kind (provider, activity, ...) or a list of them".into());
    match args.get("kind") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(s)) => Ok(s.split(',').map(str::trim).filter(|k| !k.is_empty()).map(String::from).collect()),
        Some(Value::Array(list)) => list.iter().map(|k| k.as_str().map(String::from).ok_or_else(bad)).collect(),
        Some(_) => Err(bad()),
    }
}

/// `name`: a case-insensitive regex over the record (plain text when it is
/// not a valid regex).
fn name_arg(args: &Value) -> Result<Option<Regex>, ToolError> {
    let Some(pattern) = str_arg(args, "name")? else { return Ok(None) };
    let re = Regex::new(&format!("(?i){pattern}")).or_else(|_| Regex::new(&format!("(?i){}", regex::escape(pattern))))?;
    Ok(Some(re))
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
    const CHOICES: &[(&str, &[&str])] = &[("name", &["key"]), ("value", &[]), ("any", &["both", "all"])];
    Ok(match choice_arg(args, "in", "any", CHOICES)? {
        "name" => ResourceField::Name,
        "value" => ResourceField::Value,
        _ => ResourceField::Any,
    })
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
        let kinds = kinds_arg(args)?;
        let name = name_arg(args)?;
        // Narrowing by kind or name looks for something specific: do not hide
        // what is not exported.
        let narrowed = !kinds.is_empty() || name.is_some();
        let filter = filter_arg(args, if narrowed { Filter::All } else { Filter::Exported })?;
        let offset = usize_arg(args, "offset")?.unwrap_or(0);
        let s = apk.engine.manifest_summary()?;
        let records: Vec<String> = summary_lines(&s, filter)
            .into_iter()
            .filter(|l| kinds.is_empty() || kinds.iter().any(|k| l.split(' ').next() == Some(k.as_str())))
            .filter(|l| name.as_ref().is_none_or(|n| n.is_match(l)))
            .collect();
        let mut text = String::new();
        if filter == Filter::Exported {
            text.push_str(&summary_head(&s));
            text.push('\n');
            if str_arg(args, "filter")?.is_none() {
                text.push_str(
                    "# filter=exported (the default without kind / name): what other apps can reach; filter=\"all\" \
                     for every record, kind / name to narrow\n",
                );
            }
        }
        for l in records.iter().skip(offset) {
            text.push_str(l);
            text.push('\n');
        }
        let shown = records.len().saturating_sub(offset);
        if offset > 0 || narrowed {
            text.push_str(&format!("# records {offset}..{} of {}\n", offset + shown, records.len()));
        }
        let mut structured = summary_json(&s, filter);
        structured["apk_id"] = json!(apk.id);
        structured["records_total"] = json!(records.len());
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
            // A sweep reads each table once: let it go rather than keep hundreds resident.
            |apk, (), ()| {
                let s = apk.engine.manifest_summary().map_err(|e| e.to_string());
                apk.engine.release_resources();
                s
            },
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
                let mut next = None;
                if shown < records.len() {
                    let mut n = serde_json::Map::new();
                    n.insert("apk_id".into(), json!(id));
                    // One APK defaults to `all`: name the sweep's filter.
                    n.insert("filter".into(), json!(if filter == Filter::All { "all" } else { "exported" }));
                    let n = Value::Object(n);
                    lines.push(format!("{id} | more | {} more: manifest_summary {n}", records.len() - shown));
                    next = Some(n);
                }
                let mut json = summary_json(&s, filter);
                json["next"] = json!(next);
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
            |apk, (), ()| {
                let r = resource_rows(apk, args, per_apk).map_err(|e| e.0);
                apk.engine.release_resources();
                r
            },
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
                let next = (total > rows.len()).then(|| {
                    let mut n = crate::query_args(args, &["query", "search", "literal", "in", "resolve"]);
                    n.insert("apk_id".into(), json!(id));
                    n.insert("limit".into(), json!(total));
                    Value::Object(n)
                });
                if let Some(n) = &next {
                    lines.push(format!("{id} | more | {} more: resources {n}", total - rows.len()));
                }
                let json = json!({"apk_id": id, "path": apk.path.display().to_string(), "total": total, "rows": rows_json(&rows), "chain": chain, "next": next});
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
    use crate::defs::{apk_props, many, merge, shape_many};
    use serde_json::{json, Value};

    pub fn manifest_summary() -> Value {
        json!({
            "description": "The manifest's attack surface, one record per line: package, application flags, \
                (uses-)permission, each component (`provider <class> exported=true (intent-filter) authorities=...`), \
                intent-filter, deeplink, provider-path, nsc. Default filter=exported unless kind / name narrow it. \
                With apks / dir: a head line and exported records per APK.",
            "inputSchema": {"type": "object", "properties": merge(apk_props(), &[json!({
                "filter": {"type": "string", "description": "exported or all."},
                "kind": {"type": ["string", "array"], "description": "Record kinds: provider, activity, service, receiver, \
                    permission, deeplink, ..."},
                "name": {"type": "string", "description": "Regex over the record (case-insensitive)."},
                "offset": {"type": "integer"},
            }), many()])},
            "outputSchema": shape_many(&[
                ("apk_id", "string"), ("package", "string?"), ("application", "object"), ("uses_permissions", "array"),
                ("components", "array"), ("warnings", "array"), ("records_total", "integer"),
            ]),
        })
    }

    pub fn resources() -> Value {
        json!({
            "description": "resources.arsc rows `0x7f0d0001 | string/app_name [zh-rCN] | \"value\"`: `query` one \
                resource (every configuration; resolve=true follows references), `search` names / values, or `xml` \
                decodes a binary XML file (res/xml/..., layouts).",
            "inputSchema": {"type": "object", "properties": merge(apk_props(), &[json!({
                "query": {"type": "string", "description": "0x7f0d0001 or string/app_name"},
                "resolve": {"type": "boolean"},
                "search": {"type": "string", "description": "Regex (literal=true: text)."},
                "literal": {"type": "boolean"},
                "in": {"type": "string", "description": "search in name, value or any (default)."},
                "limit": {"type": "integer", "description": format!("Default {}.", super::RESOURCES_LIMIT)},
                "xml": {"type": "string", "description": "Path inside the APK, e.g. res/xml/file_paths.xml"},
            }), many()])},
            "outputSchema": shape_many(&[("apk_id", "string"), ("total", "integer"), ("rows", "array"), ("chain", "array"), ("xml", "string")]),
        })
    }
}
