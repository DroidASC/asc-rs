//! `callgraph` on a HarmonyOS program: the arguments of the DEX tool that
//! carry over. Trees are shown as the `asc` command shows them
//! ([`TreeText`]).

use super::Session;
use crate::{CALL_DIRECTIONS, CALLGRAPH_DEPTH, CALLGRAPH_MAX_NODES, Call, ToolError, ToolResult, bool_arg, choice_arg, str_arg, usize_arg};
use asc_ark_engine::{CallNode, CallQuery, CallRoots, CallRow, Direction, EngineError, LeafKind, Query};
use asc_frontend::harmony::{TreeText, function_roots, no_callers_hint, no_leaf_hint, rule_roots};
use serde_json::{Value, json};

/// What the tool takes on a HarmonyOS program, for the program's introduction.
pub(super) const USAGE: &str = "# callgraph: class=RECORD + method=FUNCTION (or class=RECORD->FUNCTION as rows print it, or method alone), \
     direction, depth, max_nodes; or to=RULE: \"call:REGEX\" for the callers of every callee path matching (the paths of kind=call, e.g. \
     call:^import:@ohos:net\\.http), any other rule for the functions it matches (to=\"string:^https?://\"); from=RULE keeps only \
     the paths from the functions matching (`[from]`; alone: their callees), unless=RULE (or a list) leaves out the functions \
     matching and what only they reach; in these rules method:NAME is the function of that name (=NAME exact); defines=false \
     leaves out `[defines]` (a closure is created, not called); unresolved=true lists the unresolved call sites of callees; `entry`. \
     Rows: `[super]` proved; `[this-class]` / `[inherited]` / `[instance]` matched by name, `[reassigned]` through a decorated class: not guaranteed; \
     leaves are no function of the program: `[external]` starts outside it (system API, global), `[unlinked]` at an import of it that \
     led to no function, `[unresolved]` at a value tracking lost; `[N+ subclasses skipped]`: callers through that many subclasses \
     were not looked for\n";

/// A row as JSON.
fn row_json(row: &CallRow) -> Value {
    let mut value = json!({"depth": row.depth, "parent": row.parent, "repeated": row.repeated});
    if row.from {
        value["from"] = json!(true);
    }
    match &row.node {
        CallNode::Function { entry, record, function, restored } => {
            value["method"] = json!(format!("{record}->{function}"));
            value["name"] = json!(restored);
            value["entry"] = json!(entry);
        }
        CallNode::Leaf { path, kind } => {
            value["callee"] = json!(path);
            value["external"] = json!(*kind == LeafKind::External);
            if *kind == LeafKind::Unlinked {
                value["unlinked"] = json!(true);
            }
        }
    }
    if row.subclasses_skipped > 0 {
        value["subclasses_skipped"] = json!(row.subclasses_skipped);
    }
    if let Some(kind) = row.kind {
        value["kind"] = json!(kind.label().unwrap_or("call"));
        value["sites"] = json!(row.sites);
    }
    if let Some(unresolved) = row.unresolved {
        value["unresolved"] = json!(unresolved);
    }
    value
}

/// The rule under `key`, read as the CLI reads one.
fn rule_arg(args: &Value, key: &str) -> Result<Option<Query>, ToolError> {
    str_arg(args, key)?.map(|rule| Query::rule(rule, None).map_err(|e| ToolError(format!("`{key}`: {e}")))).transpose()
}

/// `unless`: a rule or a list of rules.
fn unless_arg(args: &Value) -> Result<Vec<Query>, ToolError> {
    let rule = |rule: &str| Query::rule(rule, None).map_err(|e| ToolError(format!("`unless`: {e}")));
    match args.get("unless") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(one)) => Ok(vec![rule(one)?]),
        Some(Value::Array(list)) => list
            .iter()
            .map(|item| rule(item.as_str().ok_or_else(|| ToolError("`unless` must be a rule or a list of rules".into()))?))
            .collect(),
        Some(_) => Err(ToolError("`unless` must be a rule or a list of rules".into())),
    }
}

/// Callers or callees of functions, or the callers of callee paths.
pub(super) fn callgraph(session: &Session, args: &Value, call: &Call) -> ToolResult {
    let mut direction = match choice_arg(args, "direction", "callers", CALL_DIRECTIONS)? {
        "callers" => Direction::Callers,
        _ => Direction::Callees,
    };
    let entry = str_arg(args, "entry")?;
    let to = str_arg(args, "to")?;
    let mut from = rule_arg(args, "from")?;
    let roots = match (str_arg(args, "class")?, str_arg(args, "method")?, rule_arg(args, "to")?) {
        // As on the DEX side: `from` alone walks the callees of the functions it matches.
        (None, None, None) => {
            direction = Direction::Callees;
            CallRoots::Matching(from.take().ok_or_else(|| {
                ToolError(
                    "callgraph needs `class` + `method` (or `class`: RECORD->FUNCTION as rows print it), or `to`: a rule (call:REGEX \
                     for callee paths), or `from`: a rule"
                        .into(),
                )
            })?)
        }
        (Some(_), _, Some(_)) | (_, Some(_), Some(_)) => {
            return Err(ToolError("give the target as `class` + `method` or as `to`, not both".into()));
        }
        (None, None, Some(_)) if entry.is_some() => {
            return Err(ToolError("`entry` picks the root function: it does not go with `to`".into()));
        }
        (None, None, Some(to)) => {
            // The callers of a callee path are the only walk from one.
            if matches!(to, Query::Call(_)) {
                direction = Direction::Callers;
            }
            rule_roots(to)
        }
        (Some(record), Some(function), None) => function_roots(Some(record), function, entry),
        (Some(spec), None, None) | (None, Some(spec), None) => function_roots(None, spec, entry),
    };
    if from.is_some() && direction == Direction::Callees {
        return Err(ToolError("`from` keeps caller paths: it goes with direction=callers (the default) or `to`".into()));
    }
    let query = CallQuery {
        depth: usize_arg(args, "depth")?.unwrap_or(CALLGRAPH_DEPTH),
        max_nodes: usize_arg(args, "max_nodes")?.unwrap_or(CALLGRAPH_MAX_NODES),
        defines: bool_arg(args, "defines")?.unwrap_or(true),
        unresolved: bool_arg(args, "unresolved")?.unwrap_or(false),
        from,
        unless: unless_arg(args)?,
        ..CallQuery::new(roots, direction)
    };
    let engine = &session.engine;
    let mut tree = engine.call_graph(&query, &call.cancel).map_err(|e| match &e {
        EngineError::Ambiguous { candidates, .. } if super::several_entries_define(candidates) => {
            ToolError(format!("{e}\n(name the entry, the first column, with `entry`)"))
        }
        EngineError::NotFound { what: "function", .. } => {
            ToolError(format!("{e} (findrefs kind=method lists the functions a name defines)"))
        }
        _ => ToolError(e.to_string()),
    })?;
    // The reply is framed with them.
    tree.notes.clear();
    let shown = TreeText::of(&tree, engine.has_several_entries());
    let mut text: String = shown.lines.iter().map(|line| format!("{line}\n")).collect();
    text.push_str(&shown.footer);
    text.push('\n');
    let hints: Vec<String> = match (to, &query.roots) {
        // Without rows though no `from` dropped them: no callee path matched.
        (Some(to), CallRoots::Leaf(_)) if tree.rows.is_empty() && tree.reached.is_none() => vec![no_leaf_hint(to, "findrefs kind=call")],
        _ => no_callers_hint(&tree, "findrefs kind=prop value=NAME exact=true access=call").into_iter().collect(),
    };
    for hint in &hints {
        text.push_str(&format!("# hint: {hint}\n"));
    }
    let rows: Vec<Value> = tree.rows.iter().map(row_json).collect();
    let structured = json!({
        "apk_id": session.id,
        "direction": direction.as_str(),
        "depth": tree.depth,
        "methods": tree.functions,
        "leaves": tree.leaves,
        "truncated": tree.truncated,
        "records_scanned": tree.records_scanned,
        "pruned": tree.pruned,
        "reached": tree.reached.map(|reached| reached.from),
        "rows": rows,
        "hints": hints,
    });
    Ok((text, structured))
}

#[cfg(test)]
mod tests {
    use super::*;
    use asc_ark_engine::EdgeKind;

    fn function(name: &str) -> CallNode {
        CallNode::Function {
            entry: "a.abc".into(),
            record: "&a/b&".into(),
            function: format!("#~@0>#{name}"),
            restored: format!("B.{name}"),
        }
    }

    fn row(depth: usize, parent: Option<usize>, node: CallNode) -> CallRow {
        let kind = parent.map(|_| EdgeKind::Call);
        CallRow { depth, parent, node, kind, sites: 1, repeated: false, unresolved: None, from: false, subclasses_skipped: 0 }
    }

    #[test]
    fn rules_are_read_as_the_cli_reads_them() {
        assert_eq!(
            rule_arg(&json!({"to": "call:("}), "to").map(|_| ()).map_err(|e| e.0.split(':').next().map(str::to_owned)),
            Err(Some("`to`".to_owned()))
        );
        let unless = |args: Value| unless_arg(&args).map(|rules| rules.len()).map_err(|e| e.0);
        assert_eq!(unless(json!({"unless": ["method:=a", "string:b"]})), Ok(2));
        assert_eq!(unless(json!({"unless": "method:=a"})), Ok(1));
        assert_eq!(unless(json!({})), Ok(0));
        assert_eq!(unless(json!({"unless": [1]})), Err("`unless` must be a rule or a list of rules".to_owned()));
    }

    #[test]
    fn rows_say_what_they_are() {
        let mut from = row(1, Some(0), function("onCreate"));
        from.from = true;
        assert_eq!(row_json(&from)["from"], json!(true));
        assert_eq!(row_json(&row(0, None, function("send"))).get("from"), None);
        let leaf = |path: &str, kind| row(1, Some(0), CallNode::Leaf { path: path.into(), kind });
        let mut root = row(0, None, function("send"));
        root.subclasses_skipped = 3;
        let rows: Vec<Value> = [
            root,
            leaf("import:@ohos:net.http#default.createHttp", LeafKind::External),
            leaf("import:lib#Store.open().read", LeafKind::Unlinked),
            leaf("arg0.then", LeafKind::Unresolved),
        ]
        .iter()
        .map(row_json)
        .collect();
        assert_eq!((rows[0]["subclasses_skipped"].clone(), rows[1].get("subclasses_skipped")), (json!(3), None));
        assert_eq!((rows[1]["external"].clone(), rows[1].get("unlinked")), (json!(true), None));
        assert_eq!((rows[2]["external"].clone(), rows[2]["unlinked"].clone()), (json!(false), json!(true)));
        assert_eq!((rows[3]["external"].clone(), rows[3].get("unlinked")), (json!(false), None));
    }
}
