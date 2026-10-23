//! Compound conditions (`all` / `none`), rule sets (`rules`) for findrefs,
//! and the `hierarchy` tool.

use crate::multi::{self, Report, Section};
use crate::{
    bool_arg, choice_arg, context_arg, describe_query, max_bytes, parse_query, ref_json, result_json, str_arg, usize_arg, Call, Found,
    OpenApk, Server, ToolError, ToolResult, PER_APK,
};
use asc_engine::{
    compile_rules, hints, names, Claim, CompiledQuery, DexDedup, FindOptions, HierarchyQuery, Lineage, RefBatch, RefResult, SearchTarget,
};
use asc_findrefs::Query;
use serde_json::{json, Map, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// Rows per rule of a single-APK rule set.
const RULE_LIMIT: usize = 100;
const HIERARCHY_DEPTH: usize = 16;
const HIERARCHY_MAX_NODES: usize = 500;

/// One condition: an object as for one query, or a `KIND:VALUE` string as
/// the CLI takes them (`"method:android.webkit.WebView->loadUrl"`).
fn condition(c: &Value, key: &str) -> Result<Query, ToolError> {
    match c {
        Value::Object(_) => parse_query(c),
        Value::String(s) => Ok(names::parse_condition(s)?),
        _ => Err(ToolError(format!("`{key}` must be a list of condition objects (or KIND:VALUE strings)"))),
    }
}

/// The conditions under `key` (`all` / `none`), parsed.
fn conditions(args: &Value, key: &str) -> Result<Vec<Query>, ToolError> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(list)) => list.iter().map(|c| condition(c, key)).collect(),
        Some(_) => Err(ToolError(format!("`{key}` must be a list of condition objects (or KIND:VALUE strings)"))),
    }
}

/// `all` / `none` as a compound query, if either is given. A complete
/// single query beside them (`kind` …) is one more `all` condition.
pub(crate) fn compound(args: &Value) -> Result<Option<Query>, ToolError> {
    if args.get("all").is_none() && args.get("none").is_none() {
        return Ok(None);
    }
    let mut all = conditions(args, "all")?;
    if args.get("kind").is_some() {
        let mut single = args.as_object().cloned().unwrap_or_default();
        single.remove("all");
        single.remove("none");
        match parse_query(&Value::Object(single)) {
            Ok(q) => all.insert(0, q),
            Err(e) => {
                return Err(ToolError(format!(
                    "`kind` beside `all` / `none` must be a complete query to join them ({}), or be left out",
                    e.0
                )))
            }
        }
    }
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
    // String rules become objects, so follow-up hints carry them like any other.
    let list: Vec<Value> = list
        .iter()
        .enumerate()
        .map(|(i, r)| match r {
            // Kept as written, so follow-up calls carry it the same way.
            Value::String(s) => Ok(json!({ "rule": s })),
            Value::Object(_) => Ok(r.clone()),
            _ => Err(ToolError(format!("rule {} is not an object (or a KIND:VALUE string)", i + 1))),
        })
        .collect::<Result<_, _>>()?;
    let mut queries = Vec::with_capacity(list.len());
    for (i, r) in list.iter().enumerate() {
        let q = match compound(r)? {
            Some(q) => q,
            None => parse_query(r).map_err(|e| ToolError(format!("rule r{}: {}", i + 1, e.0)))?,
        };
        queries.push(q);
    }
    Ok((list, queries))
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

/// Batches of every unit, tagged with their rule, regrouped per rule.
fn per_rule(units: Vec<Vec<(usize, RefBatch)>>, n: usize) -> Vec<Vec<RefBatch>> {
    let mut out: Vec<Vec<RefBatch>> = (0..n).map(|_| Vec::new()).collect();
    for (i, b) in units.into_iter().flatten() {
        out[i].push(b);
    }
    out
}

/// One APK of a rule sweep: the rules L3 answered, and the claims of its
/// entries for the rules still to search.
struct RulesTarget {
    target: SearchTarget,
    /// Rules to search, as indexes into the rule set.
    missing: Vec<usize>,
    claims: Vec<Claim>,
    /// Rows replayed from L3, tagged with their rule.
    cached: Mutex<Vec<(usize, RefBatch)>>,
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
        let summary = apk.engine.find_refs_rules(&queries, FindOptions::default(), &call.cancel, &mut |i, b| batches[i].push(b))?;
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
            let hint = (total == 0 && found.sdk_hits == 0).then(|| hints::query_hint(&queries[i])).flatten();
            if let Some(h) = &hint {
                text.push_str(&format!("# {name} hint: {h}\n"));
            }
            errors.extend(std::mem::take(&mut found.errors));
            out.push(json!({
                "rule": name,
                "query": rules[i],
                "total": total,
                "hint": hint,
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
        for n in &summary.notes {
            text.push_str(&format!("# {n}\n"));
        }
        Ok((text, json!({"apk_id": apk.id, "rules": out, "errors": errors, "notes": summary.notes})))
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
        let tally = Mutex::new(&mut rule_hits);
        // Identical DEX in several APKs is searched once (per set of rules).
        let dedup = DexDedup::new();
        let cached_rules = AtomicUsize::new(0);
        let dex_entries = AtomicUsize::new(0);
        let (sections, empty, stats) = self.sweep(
            paths,
            call,
            bool_arg(args, "release")?,
            |apk| {
                let target = apk.engine.search_target().map_err(|e| e.to_string())?;
                dex_entries.fetch_add(target.entries.len(), Ordering::Relaxed);
                // L3: each rule may have run on this APK version already, alone or in a set.
                let mut cached = Vec::new();
                let mut missing = Vec::new();
                for (i, q) in queries.iter().enumerate() {
                    match apk.engine.cached_refs(&target, q, true) {
                        Some(batches) => cached.extend(batches.into_iter().map(|b| (i, b))),
                        None => missing.push(i),
                    }
                }
                cached_rules.fetch_add(n - missing.len(), Ordering::Relaxed);
                let claims: Vec<Claim> =
                    if missing.is_empty() { Vec::new() } else { target.entries.iter().map(|e| dedup.claim_rules(e, &missing)).collect() };
                // The replayed rows, then the entries; a follower waits for its leader, so it runs last.
                let units = std::iter::once((0, None))
                    .chain(
                        (claims.iter().zip(&target.entries).enumerate())
                            .map(|(i, (c, e))| (if DexDedup::follows(c) { 1 } else { e.uncomp_size.max(e.comp_size) }, Some(i))),
                    )
                    .collect();
                Ok((RulesTarget { target, missing, claims, cached: Mutex::new(cached) }, units))
            },
            |apk, t, unit| match *unit {
                None => std::mem::take(&mut *crate::lock(&t.cached)),
                Some(i) => {
                    let searched: Vec<&CompiledQuery> = t.missing.iter().map(|&r| &compiled[r]).collect();
                    let (entry, claim) = (&t.target.entries[i], &t.claims[i]);
                    let batches = apk.engine.search_target_entry_rules_dedup(&t.target, entry, &searched, true, &call.cancel, claim);
                    t.missing.iter().copied().zip(batches).collect()
                }
            },
            |apk, units| {
                let per_rule = per_rule(units, n);
                for (q, batches) in queries.iter().zip(&per_rule) {
                    // Searched now, not replayed: keep it for the next run of the rule, alone or in a set.
                    if !batches.is_empty() && batches.iter().all(|b| b.source != "result") {
                        apk.engine.store_refs(q, true, batches);
                    }
                }
                let found: Vec<Found> = per_rule.into_iter().map(|b| Found::new(b, sdks.as_deref())).collect();
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
        if rule_hits.iter().any(|&(hits, _)| hits == 0) {
            header.push_str(&format!("\n# hint: {}", hints::searched_hint(paths.len(), dex_entries.load(Ordering::Relaxed))));
        }
        let rule_hints: Vec<Option<String>> =
            rule_hits.iter().zip(queries).map(|(&(hits, _), q)| (hits == 0).then(|| hints::query_hint(q)).flatten()).collect();
        for (i, (hits, apks)) in rule_hits.iter().enumerate() {
            header.push_str(&format!("\n# {} {}: {hits} hits in {apks} APKs", names[i], describe(&rules[i])));
            if let Some(h) = &rule_hints[i] {
                header.push_str(&format!("\n# {} hint: {h}", names[i]));
            }
        }
        let summary = json!({
            "apks_total": paths.len(),
            "apks_with_hits": stats.with_hits,
            "total": stats.hits,
            "errors": stats.errors,
            "elapsed_ms": ms,
            "released": stats.released,
            "memory_cache_bytes": self.cache.memory_bytes(),
            "rules_from_result_cache": cached_rules.load(Ordering::Relaxed),
            "dex_shared": dedup.shared(),
            "rules": rules.iter().zip(&names).zip(&rule_hits).zip(&rule_hints).map(|(((q, r), (hits, apks)), hint)| {
                json!({"rule": r, "query": q, "total": hits, "apks_with_hits": apks, "hint": hint})
            }).collect::<Vec<_>>(),
        });
        self.report(Report { tool: "findrefs", header, summary, sections, empty, max_bytes: max_bytes(args)? })
    }

    pub(crate) fn hierarchy(&self, args: &Value, call: &Call) -> ToolResult {
        let apk = self.resolve(args)?;
        let class = str_arg(args, "class")?.ok_or_else(|| ToolError("hierarchy needs `class`".into()))?;
        const CHOICES: &[(&str, &[&str])] = &[
            ("subclasses", &["subclass", "children", "descendants", "implementers", "down"]),
            ("supers", &["super", "superclasses", "supertypes", "parents", "ancestors", "up"]),
        ];
        let direction = match choice_arg(args, "direction", "subclasses", CHOICES)? {
            "subclasses" => Lineage::Subclasses,
            _ => Lineage::Supers,
        };
        let q = HierarchyQuery {
            class: names::format_class_name(class)?,
            direction,
            depth: usize_arg(args, "depth")?.unwrap_or(HIERARCHY_DEPTH),
            max_nodes: usize_arg(args, "max_nodes")?.unwrap_or(HIERARCHY_MAX_NODES),
            method: str_arg(args, "method")?.map(String::from),
        };
        let tree = apk.engine.hierarchy_cancellable(&q, &call.cancel)?;
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
    use crate::defs::{apk_props, merge, shape};
    use serde_json::{json, Value};

    pub fn hierarchy() -> Value {
        json!({
            "description": "Subclasses / implementers (default) or supertypes of a class, as an indented tree; with \
                `method`, which of them override it.",
            "inputSchema": {"type": "object", "properties": merge(apk_props(), &[json!({
                "class": {"type": "string"},
                "direction": {"type": "string", "description": "subclasses (default) or supers."},
                "depth": {"type": "integer", "description": format!("Default {}.", super::HIERARCHY_DEPTH)},
                "max_nodes": {"type": "integer", "description": format!("Default {}.", super::HIERARCHY_MAX_NODES)},
                "method": {"type": "string", "description": "A name or name(params)ret."},
            })]), "required": ["class"]},
            "outputSchema": shape(&[
                ("apk_id", "string"), ("direction", "string"), ("depth", "integer"), ("classes", "integer"), ("truncated", "boolean"),
                ("rows", "array"),
            ]),
        })
    }

    /// findrefs properties for compound conditions and rule sets.
    pub fn findrefs_props() -> Value {
        let condition = json!({"type": "object", "description": "{kind, value / name / class, ...} as for one query."});
        json!({
            "all": {"type": "array", "items": condition, "description": "Instead of kind: methods matching every condition."},
            "none": {"type": "array", "items": condition, "description": "With all: minus methods matching any."},
            "rule": {"type": "string", "description": "Instead of kind: a rule as the CLI writes it, `KIND:VALUE` \
                joined by `&`, `!` before a part to exclude; method:{RULE} = calls of the methods whose code matches \
                RULE, method:@FILE = calls of the methods FILE lists."},
            "rules": {"type": "array", "items": condition, "description": "Several queries (or all / none, or rule \
                strings) in one pass, output grouped `r1 | ...`."},
        })
    }
}
