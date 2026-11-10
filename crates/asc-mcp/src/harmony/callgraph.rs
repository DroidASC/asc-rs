//! `callgraph` on a HarmonyOS program: the arguments of the DEX tool that
//! carry over, and how a tree of the engine is shown. The `asc`
//! command shows its trees through [`TreeText`] too, so that both front ends
//! print the same rows.

use super::{without_pc, Session};
use crate::{bool_arg, choice_arg, str_arg, usize_arg, Call, ToolError, ToolResult, CALLGRAPH_DEPTH, CALLGRAPH_MAX_NODES, CALL_DIRECTIONS};
use asc_ark_engine::{CallNode, CallQuery, CallRoots, CallRow, CallTree, Direction, EngineError, Query};
use serde_json::{json, Value};

/// What the tool takes on a HarmonyOS program, for the program's introduction.
pub(super) const USAGE: &str =
    "# callgraph: class=RECORD + method=FUNCTION (or class=RECORD->FUNCTION as rows print it, or method alone), \
     direction, depth, max_nodes; or to=RULE: \"call:REGEX\" for the callers of every callee path matching (the paths of kind=call, e.g. \
     call:^import:@ohos:net\\.http), any other rule for the functions it matches (to=\"string:^https?://\"); from=RULE keeps only \
     the paths from the functions matching (`[from]`; alone: their callees), unless=RULE (or a list) leaves out the functions \
     matching and what only they reach; in these rules method:NAME is the function of that name (=NAME exact); defines=false \
     leaves out `[defines]` (a closure is created, not called); unresolved=true lists the unresolved call sites of callees; `entry`. \
     Rows: `[super]` proved; `[this-class]` / `[inherited]` / `[instance]` matched by name, `[reassigned]` through a decorated class: not guaranteed; `[external]` / `[unresolved]` are leaves, no function of the program\n";

/// The roots `to` names: the callee paths a lone `call:PATTERN` matches,
/// else the functions the rule matches.
pub fn rule_roots(rule: Query) -> CallRoots {
    match rule {
        Query::Call(pattern) => CallRoots::Leaf(pattern),
        other => CallRoots::Matching(other),
    }
}

/// The root a function spelling names: `function` in `record`, or one text
/// as result rows print it (`RECORD->FUNCTION`, `RECORD->FUNCTION+0xPC`), or
/// a function name alone (every function of that name).
pub fn function_roots(record: Option<&str>, function: &str, entry: Option<&str>) -> CallRoots {
    let (record, function) = match (record, function.split_once("->")) {
        (None, Some((record, function))) => (Some(record), function),
        _ => (record, function),
    };
    CallRoots::Function { record: record.map(str::to_owned), function: without_pc(function).to_owned(), entry: entry.map(str::to_owned) }
}

/// The hint of a walk whose `to` pattern matched no callee path (`search`:
/// how the front end spells the search that lists them).
pub fn no_leaf_hint(rule: &str, search: &str) -> String {
    format!(
        "no call site has a callee path matching {rule}: the paths are what {search} prints \
         (import:REQUEST#NAME.member, global:NAME.member, this.member); `{search} .` lists them all"
    )
}

/// The hint of a callers walk from functions that found no caller, or
/// `None` (`search`: how the front end spells a search for call sites by
/// member name).
pub fn no_callers_hint(tree: &CallTree, search: &str) -> Option<String> {
    let only_roots = !tree.rows.is_empty() && tree.rows.iter().all(|row| row.depth == 0 && matches!(row.node, CallNode::Function { .. }));
    (tree.direction == Direction::Callers && tree.depth > 0 && only_roots).then(|| {
        format!(
            "no caller was resolved: a function the system calls (a lifecycle or event callback) or one reached only through a \
             value (a property, an argument) has none; {search} lists call sites by member name"
        )
    })
}

/// A tree as both front ends print it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeText {
    /// One line per row.
    pub lines: Vec<String>,
    /// `#` lines after the rows: what the walk covered, what was left out.
    pub footer: String,
}

impl TreeText {
    /// The rows of `tree`. Rows name their ABC entry only when the
    /// functions of the tree come from several; `several_entries`: the
    /// program has more than one, and the footer then names the one entry
    /// of a tree that has one.
    pub fn of(tree: &CallTree, several_entries: bool) -> TreeText {
        let mut entries = tree.rows.iter().filter_map(|row| match &row.node {
            CallNode::Function { entry, .. } => Some(entry.as_str()),
            CallNode::Leaf { .. } => None,
        });
        let first = entries.next();
        let with_entry = entries.any(|entry| Some(entry) != first);
        let lines = tree.lines(with_entry);
        let mut footer = tree.footer();
        if let (Some(entry), true, false) = (first, several_entries, with_entry) {
            let at = footer.find('\n').unwrap_or(footer.len());
            footer.insert_str(at, &format!("; all in {entry}"));
        }
        TreeText { lines, footer }
    }
}

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
        CallNode::Leaf { path, external } => {
            value["callee"] = json!(path);
            value["external"] = json!(external);
        }
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
            return Err(ToolError("`entry` picks the root function: it does not go with `to`".into()))
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

    fn function(entry: &str, name: &str) -> CallNode {
        CallNode::Function { entry: entry.into(), record: "&a/b&".into(), function: format!("#~@0>#{name}"), restored: format!("B.{name}") }
    }

    fn row(depth: usize, parent: Option<usize>, node: CallNode) -> CallRow {
        CallRow { depth, parent, node, kind: parent.map(|_| EdgeKind::Call), sites: 1, repeated: false, unresolved: None, from: false }
    }

    fn tree(rows: Vec<CallRow>) -> CallTree {
        let functions = rows.iter().filter(|row| matches!(row.node, CallNode::Function { .. })).count();
        let leaves = rows.len() - functions;
        CallTree {
            direction: Direction::Callers,
            depth: 3,
            rows,
            functions,
            leaves,
            truncated: false,
            records_scanned: 1,
            pruned: 0,
            reached: None,
            notes: Vec::new(),
        }
    }

    #[test]
    fn roots_come_from_every_spelling() {
        let root = |record, function| match function_roots(record, function, Some("ets/modules.abc")) {
            CallRoots::Function { record, function, entry } => (record, function, entry),
            other => panic!("{other:?}"),
        };
        let entry = Some("ets/modules.abc".to_owned());
        assert_eq!(root(None, "&a/b&->#~@0>#build+0x1f"), (Some("&a/b&".to_owned()), "#~@0>#build".to_owned(), entry.clone()));
        assert_eq!(root(Some("pages/Index"), "Index.build"), (Some("pages/Index".to_owned()), "Index.build".to_owned(), entry.clone()));
        assert_eq!(root(None, "Index.build"), (None, "Index.build".to_owned(), entry));
        let roots = |rule: &str| rule_roots(Query::rule(rule, None).unwrap());
        assert!(matches!(roots("call:^import:@ohos:net\\.http"), CallRoots::Leaf(_)));
        assert!(matches!(roots("string:token"), CallRoots::Matching(Query::StringRegex(_))));
        assert!(matches!(roots("call:x & string:token"), CallRoots::Matching(Query::All(_))));
        assert!(matches!(roots("call:{string:token}"), CallRoots::Matching(Query::CallTo(_))));
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
    fn a_tree_of_one_entry_names_it_once() {
        let one = tree(vec![row(0, None, function("a.abc", "x")), row(1, Some(0), function("a.abc", "y"))]);
        let text = TreeText::of(&one, true);
        assert_eq!(text.lines, ["0 &a/b&->#~@0>#x | B.x", "  1 <- &a/b&->#~@0>#y | B.y"]);
        assert_eq!(text.footer, "# 2 rows, 2 distinct functions, 0 leaves (callers, depth 3); 1 records scanned; all in a.abc");
        assert!(!TreeText::of(&one, false).footer.contains("all in"));
        let two = tree(vec![row(0, None, function("a.abc", "x")), row(1, Some(0), function("b.abc", "y"))]);
        let text = TreeText::of(&two, true);
        assert_eq!(text.lines, ["0 &a/b&->#~@0>#x | B.x [a.abc]", "  1 <- &a/b&->#~@0>#y | B.y [b.abc]"]);
        assert!(!text.footer.contains("all in"), "{}", text.footer);
    }

    #[test]
    fn from_rows_and_what_was_left_out_are_said() {
        let mut walked = tree(vec![row(0, None, function("a.abc", "send")), row(1, Some(0), function("a.abc", "onCreate"))]);
        walked.rows[1].from = true;
        walked.pruned = 2;
        walked.reached = Some(asc_ark_engine::Reached { from: 1, walked: 6 });
        let text = TreeText::of(&walked, true);
        assert_eq!(text.lines, ["0 &a/b&->#~@0>#send | B.send", "  1 <- &a/b&->#~@0>#onCreate | B.onCreate [from]"]);
        assert_eq!(
            text.footer,
            "# 2 rows, 2 distinct functions, 0 leaves (callers, depth 3); 1 records scanned; 1 from functions reached; \
             2 functions left out by unless; all in a.abc"
        );
        assert_eq!(row_json(&walked.rows[1])["from"], json!(true));
        assert_eq!(row_json(&walked.rows[0]).get("from"), None);
        let mut nowhere = tree(Vec::new());
        nowhere.reached = Some(asc_ark_engine::Reached { from: 0, walked: 6 });
        let footer = TreeText::of(&nowhere, false).footer;
        assert!(
            footer.contains("; 0 from functions reached\n# from: none of the 6 callers walked matches (depth 3); a path ends"),
            "{footer}"
        );
    }
}
