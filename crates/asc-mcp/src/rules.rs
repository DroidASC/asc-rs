//! Compound conditions (`all` / `none`), rule sets (`rules`) for findrefs,
//! and the `hierarchy` tool.

use crate::multi::{self, Report, Section};
use crate::{
    bool_arg, context_arg, describe_query, max_bytes, parse_query, ref_json, result_json, str_arg, usize_arg, Call, Found, OpenApk, Server,
    ToolError, ToolResult, PER_APK,
};
use asc_engine::{compile_rules, names, FindOptions, HierarchyQuery, Lineage, RefBatch, RefResult};
use asc_findrefs::Query;
use serde_json::{json, Map, Value};
use std::path::PathBuf;
use std::time::Instant;

/// Rows per rule of a single-APK rule set.
const RULE_LIMIT: usize = 100;
const HIERARCHY_DEPTH: usize = 16;
const HIERARCHY_MAX_NODES: usize = 500;

/// The condition objects under `key` (`all` / `none`), parsed.
fn conditions(args: &Value, key: &str) -> Result<Vec<Query>, ToolError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(list)) => list
            .iter()
            .map(|c| if c.is_object() { parse_query(c) } else { Err(ToolError(format!("`{key}` must be a list of condition objects"))) })
            .collect(),
        Some(_) => Err(ToolError(format!("`{key}` must be a list of condition objects"))),
    }
}

/// `all` / `none` as a compound query, if either is given.
pub(crate) fn compound(args: &Value) -> Result<Option<Query>, ToolError> {
    if args.get("all").is_none() && args.get("none").is_none() {
        return Ok(None);
    }
    if args.get("kind").is_some() {
        return Err(ToolError("give either `kind` or `all` / `none`, not both".into()));
    }
    let all = conditions(args, "all")?;
    if all.is_empty() {
        return Err(ToolError("`all` needs at least one condition (`none` only removes methods)".into()));
    }
    Ok(Some(Query::All { all, none: conditions(args, "none")? }))
}

/// `all(string "a", method Lb;->c) none(...)` for a compound, else the plain description.
pub(crate) fn describe(args: &Value) -> String {
    let list = |key: &str| {
        args.get(key).and_then(Value::as_array).map(|l| l.iter().map(describe).collect::<Vec<_>>().join(", ")).unwrap_or_default()
    };
    if args.get("all").is_none() && args.get("none").is_none() {
        return describe_query(args);
    }
    let mut s = format!("all({})", list("all"));
    if args.get("none").is_some() {
        s.push_str(&format!(" none({})", list("none")));
    }
    s
}

/// The rule objects of `rules`, parsed, with their names `r1`, `r2`, ...
fn parse_rules(args: &Value) -> Result<(Vec<Value>, Vec<Query>), ToolError> {
    let Some(Value::Array(list)) = args.get("rules") else {
        return Err(ToolError("`rules` must be a list of findrefs condition objects".into()));
    };
    if list.is_empty() {
        return Err(ToolError("`rules` is empty".into()));
    }
    if args.get("kind").is_some() || args.get("all").is_some() {
        return Err(ToolError("give either `rules` or one query (`kind` / `all`), not both".into()));
    }
    let mut queries = Vec::with_capacity(list.len());
    for (i, r) in list.iter().enumerate() {
        if !r.is_object() {
            return Err(ToolError(format!("rule {} is not an object", i + 1)));
        }
        let q = match compound(r)? {
            Some(q) => q,
            None => parse_query(r).map_err(|e| ToolError(format!("rule r{}: {}", i + 1, e.0)))?,
        };
        queries.push(q);
    }
    Ok((list.clone(), queries))
}

/// The arguments of a single-APK findrefs that continues `rule` at `offset`.
fn follow_up(rule: &Value, args: &Value, apk_id: &str, offset: usize, collapsed: bool) -> Value {
    let mut next: Map<String, Value> = rule.as_object().cloned().unwrap_or_default();
    if let Some(p) = args.get("sdk_prefixes") {
        next.insert("sdk_prefixes".into(), p.clone());
    }
    next.insert("apk_id".into(), json!(apk_id));
    next.insert("offset".into(), json!(offset));
    next.insert("collapse_sdks".into(), json!(collapsed));
    Value::Object(next)
}

/// Batches of every unit (one `Vec` per unit, one batch per rule) regrouped per rule.
fn per_rule(units: Vec<Vec<RefBatch>>, n: usize) -> Vec<Vec<RefBatch>> {
    let mut out: Vec<Vec<RefBatch>> = (0..n).map(|_| Vec::new()).collect();
    for unit in units {
        for (i, b) in unit.into_iter().enumerate() {
            out[i].push(b);
        }
    }
    out
}

impl Server {
    /// findrefs with `rules`: every rule answered by one pass over each DEX,
    /// output grouped by rule (`r1 | ...`).
    pub(crate) fn findrefs_rules(&self, args: &Value, call: &Call) -> ToolResult {
        let (rules, queries) = parse_rules(args)?;
        if let Some(paths) = multi::targets(args)? {
            return self.findrefs_rules_many(args, call, &paths, &rules, &queries);
        }
        let apk = self.resolve(args)?;
        let sdks = self.sdk_filter(args, false)?;
        let limit = usize_arg(args, "limit")?.unwrap_or(RULE_LIMIT).max(1);
        let context = context_arg(args)?;
        let mut batches: Vec<Vec<RefBatch>> = (0..queries.len()).map(|_| Vec::new()).collect();
        apk.engine.find_refs_rules(&queries, FindOptions::default(), &call.cancel, &mut |i, b| batches[i].push(b))?;
        call.check()?;
        let mut text = String::new();
        let mut out = Vec::new();
        let mut errors = Vec::new();
        for (i, b) in batches.into_iter().enumerate() {
            let name = format!("r{}", i + 1);
            let mut found = Found::new(b, sdks.as_deref());
            let total = found.rows.len();
            let mut page: Vec<RefResult> = found.rows.iter().take(limit).cloned().collect();
            found.errors.extend(apk.engine.fill_context(&mut page, context)?);
            text.push_str(&format!("# {name} {}: {total} results", describe(&rules[i])));
            if found.sdk_hits > 0 {
                text.push_str(&format!(" (+{} in SDKs: {})", found.sdk_hits, found.sdk_list()));
            }
            text.push('\n');
            for r in &page {
                for (j, line) in r.text().lines().enumerate() {
                    // Context lines keep their indentation after the prefix.
                    text.push_str(&if j == 0 { format!("{name} | {line}\n") } else { format!("{name} |{line}\n") });
                }
            }
            let next = (page.len() < total).then(|| follow_up(&rules[i], args, &apk.id, page.len(), sdks.is_some()));
            if let Some(n) = &next {
                text.push_str(&format!("{name} | more | {} more: findrefs {n}\n", total - page.len()));
            }
            errors.extend(std::mem::take(&mut found.errors));
            out.push(json!({
                "rule": name,
                "query": rules[i],
                "total": total,
                "returned": page.len(),
                "results": page.iter().map(|r| ref_json(r, context)).collect::<Vec<_>>(),
                "sdk_hits": found.sdk_hits,
                "next": next,
            }));
        }
        errors.sort();
        errors.dedup();
        for e in &errors {
            text.push_str(&format!("# Warning: {e}\n"));
        }
        Ok((text, json!({"apk_id": apk.id, "rules": out, "errors": errors})))
    }

    /// Rules over many APKs: one queue of DEX entries, each searched once for
    /// every rule; per APK one section with the rows grouped by rule.
    fn findrefs_rules_many(&self, args: &Value, call: &Call, paths: &[PathBuf], rules: &[Value], queries: &[Query]) -> ToolResult {
        let t = Instant::now();
        let compiled = compile_rules(queries)?;
        let sdks = self.sdk_filter(args, true)?;
        let per_apk = usize_arg(args, "per_apk")?.unwrap_or(PER_APK);
        let n = queries.len();
        let names: Vec<String> = (1..=n).map(|i| format!("r{i}")).collect();
        let mut rule_hits = vec![(0usize, 0usize); n]; // (hits, APKs with hits)
        let tally = std::sync::Mutex::new(&mut rule_hits);
        let (sections, empty, stats) = self.sweep(
            paths,
            call,
            bool_arg(args, "release")?,
            |apk| {
                let target = apk.engine.search_target().map_err(|e| e.to_string())?;
                let units = target.entries.iter().enumerate().map(|(i, e)| (e.uncomp_size.max(e.comp_size), i)).collect();
                Ok((target, units))
            },
            |apk, target, &i| apk.engine.search_target_entry_rules(target, &target.entries[i], &compiled, true, &call.cancel),
            |apk, units| {
                let found: Vec<Found> = per_rule(units, n).into_iter().map(|b| Found::new(b, sdks.as_deref())).collect();
                {
                    let mut tally = tally.lock().unwrap();
                    for (i, f) in found.iter().enumerate() {
                        // Counted like a single-rule sweep: SDK hits too.
                        tally[i].0 += f.rows.len() + f.sdk_hits;
                        tally[i].1 += usize::from(f.rows.len() + f.sdk_hits > 0);
                    }
                }
                rules_section(apk, &found, &names, rules, args, per_apk, sdks.is_some())
            },
        );
        call.check()?;
        let ms = t.elapsed().as_secs_f64() * 1e3;
        let mut header = format!(
            "# findrefs {n} rules over {} APKs: {} with hits, {} hits, {} errors, {ms:.0} ms",
            paths.len(),
            stats.with_hits,
            stats.hits,
            stats.errors
        );
        for (i, (hits, apks)) in rule_hits.iter().enumerate() {
            header.push_str(&format!("\n# {} {}: {hits} hits in {apks} APKs", names[i], describe(&rules[i])));
        }
        let summary = json!({
            "apks_total": paths.len(),
            "apks_with_hits": stats.with_hits,
            "total": stats.hits,
            "errors": stats.errors,
            "elapsed_ms": ms,
            "released": stats.released,
            "rules": rules.iter().zip(&names).zip(&rule_hits).map(|((q, r), (hits, apks))| {
                json!({"rule": r, "query": q, "total": hits, "apks_with_hits": apks})
            }).collect::<Vec<_>>(),
        });
        self.report(Report { tool: "findrefs", header, summary, sections, empty, max_bytes: max_bytes(args)? })
    }

    pub(crate) fn hierarchy(&self, args: &Value, _: &Call) -> ToolResult {
        let apk = self.resolve(args)?;
        let class = str_arg(args, "class")?.ok_or_else(|| ToolError("hierarchy needs `class`".into()))?;
        let direction = match str_arg(args, "direction")?.unwrap_or("subclasses") {
            "subclasses" => Lineage::Subclasses,
            "supers" => Lineage::Supers,
            d => return Err(ToolError(format!("unknown direction {d:?}: use subclasses or supers"))),
        };
        let q = HierarchyQuery {
            class: names::format_class_name(class)?,
            direction,
            depth: usize_arg(args, "depth")?.unwrap_or(HIERARCHY_DEPTH),
            max_nodes: usize_arg(args, "max_nodes")?.unwrap_or(HIERARCHY_MAX_NODES),
            method: str_arg(args, "method")?.map(String::from),
        };
        let tree = apk.engine.hierarchy(&q)?;
        let mut text = String::new();
        for line in tree.lines().into_iter().chain(tree.definition_lines()) {
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
            .map(|r| {
                json!({
                    "depth": r.depth,
                    "parent": r.parent,
                    "class": r.class,
                    "relation": r.relation.map(|r| r.verb()),
                    "dex": r.dex,
                    "repeated": r.repeated,
                    "defines": r.defines,
                })
            })
            .collect();
        let structured = json!({
            "apk_id": apk.id,
            "direction": direction.as_str(),
            "depth": tree.depth,
            "classes": tree.classes,
            "truncated": tree.truncated,
            "rows": rows,
            "definitions": tree.definition_lines(),
            "errors": tree.errors,
        });
        Ok((text, structured))
    }
}

/// One APK's section of a rule set: a head line with per-rule counts, then
/// each rule's first `per_apk` rows (`apkN | r2 | dex | ...`).
fn rules_section(
    apk: &OpenApk,
    found: &[Found],
    names: &[String],
    rules: &[Value],
    args: &Value,
    per_apk: usize,
    collapsed: bool,
) -> (usize, Option<Section>) {
    let id = &apk.id;
    let hits: usize = found.iter().map(|f| f.rows.len()).sum();
    let sdk_hits: usize = found.iter().map(|f| f.sdk_hits).sum();
    let mut errors: Vec<String> = found.iter().flat_map(|f| f.errors.iter().cloned()).collect();
    errors.sort();
    errors.dedup();
    if hits == 0 && sdk_hits == 0 && errors.is_empty() {
        return (0, None);
    }
    if found.iter().all(|f| f.failed) {
        return (0, Some(Section::error(id, &apk.path, &errors.join("; "))));
    }
    let counts: Vec<String> =
        found.iter().zip(names).filter(|(f, _)| !f.rows.is_empty()).map(|(f, r)| format!("{r} {}", f.rows.len())).collect();
    let mut head = format!("{id} | {hits} hits ({})", counts.join(", "));
    if sdk_hits > 0 {
        head.push_str(&format!(" (+{sdk_hits} in SDKs)"));
    }
    let mut lines = vec![format!("{head} | {}", apk.path.display())];
    let mut bytes = lines[0].len();
    let mut per_rule_json = Vec::new();
    for ((f, name), rule) in found.iter().zip(names).zip(rules) {
        if f.rows.is_empty() {
            continue;
        }
        let mut shown = Vec::new();
        for r in f.rows.iter().take(per_apk) {
            let line = format!("{id} | {name} | {}", r.line());
            if bytes + line.len() >= multi::MAX_APK_BYTES {
                break;
            }
            bytes += line.len() + 1;
            lines.push(line);
            shown.push(result_json(r));
        }
        let next = (shown.len() < f.rows.len()).then(|| follow_up(rule, args, id, shown.len(), collapsed));
        if let Some(n) = &next {
            lines.push(format!("{id} | {name} | more | {} more: findrefs {n}", f.rows.len() - shown.len()));
        }
        per_rule_json.push(json!({"rule": name, "total": f.rows.len(), "sdk_hits": f.sdk_hits, "results": shown, "next": next}));
    }
    let sdks: Vec<String> =
        found.iter().zip(names).filter(|(f, _)| f.sdk_hits > 0).map(|(f, r)| format!("{r}: {}", f.sdk_list())).collect();
    if !sdks.is_empty() {
        lines.push(format!("{id} | sdk | {}", sdks.join("; ")));
    }
    for e in &errors {
        lines.push(format!("{id} | warning | {e}"));
    }
    let json = json!({
        "apk_id": id,
        "path": apk.path.display().to_string(),
        "total": hits,
        "sdk_hits": sdk_hits,
        "rules": per_rule_json,
        "errors": errors,
    });
    (hits + sdk_hits, Some(Section { lines, json }))
}

pub mod defs {
    use crate::defs::{apk_props, merge};
    use serde_json::{json, Value};

    pub fn hierarchy() -> Value {
        json!({
            "description": "Class hierarchy across every DEX: the transitive subclasses / implementers (default) or \
                supertypes of a class, as an indented tree (`depth subclass Lx; classes2.dex`, `[not in APK]` for \
                framework types, `(repeated)` for a class reached twice). With `method`, marks the classes defining it \
                (`[defines m(..)V]`) and lists each as `override Lsub;->m(..)V dex` (or `inherited` going up).",
            "inputSchema": {"type": "object", "properties": merge(apk_props(), &[json!({
                "class": {"type": "string", "description": "Lcom/poc/Base; or com.poc.Base."},
                "direction": {"type": "string", "enum": ["subclasses", "supers"], "description": "Default subclasses."},
                "depth": {"type": "integer", "minimum": 1, "description": "Levels to walk (default 16)."},
                "max_nodes": {"type": "integer", "minimum": 1, "description": "Stop after this many classes (default 500)."},
                "method": {"type": "string", "description": "Method name (every overload) or exact name(params)ret to find \
                    overrides of."},
            })]), "required": ["class"]},
        })
    }

    /// findrefs properties for compound conditions and rule sets.
    pub fn findrefs_props() -> Value {
        let condition = json!({"type": "object", "description": "A findrefs condition: kind + value / name / class / \
            literal / exact / fuzzy_class, as for a single query (not extends / impl)."});
        json!({
            "all": {"type": "array", "items": condition, "description": "Instead of kind: methods whose code matches \
                every condition (e.g. a string and a method call); `matched` lists what each matched, in order."},
            "none": {"type": "array", "items": condition, "description": "With all: drop methods matching any of these."},
            "rules": {"type": "array", "items": {"type": "object", "description": "A single query (kind ...) or a \
                compound (all / none)."}, "description": "Instead of one query: several, answered by one pass over each \
                DEX; output grouped by rule (`r1 | ...`, many APKs: `apkN | r1 | ...`), limit / per_apk per rule."},
        })
    }
}
