//! `callgraph` on a HarmonyOS program: the arguments of the DEX tool that
//! carry over, and how a tree of the engine is shown. The `asc`
//! command shows its trees through [`TreeText`] too, so that both front ends
//! print the same rows.

use super::{asks_for, without_pc, Session};
use crate::{bool_arg, choice_arg, str_arg, usize_arg, Call, ToolError, ToolResult, CALLGRAPH_DEPTH, CALLGRAPH_MAX_NODES, CALL_DIRECTIONS};
use asc_ark_engine::{CallNode, CallQuery, CallRoots, CallRow, CallTree, Direction, EngineError, Pattern, Query};
use serde_json::{json, Value};
use std::collections::HashSet;

/// What the tool takes on a HarmonyOS program, for the program's introduction.
pub(super) const USAGE: &str =
    "# callgraph: class=RECORD + method=FUNCTION (or class=RECORD->FUNCTION as rows print it, or method alone), \
     direction, depth, max_nodes; or to=\"call:REGEX\" for the callers of every callee path matching (the paths of kind=call, e.g. \
     call:^import:@ohos:net\\.http); from=\"method:NAME\" keeps only the paths from the callers matching (`[from]`); defines=false \
     leaves out `[defines]` (a closure is created, not called); unresolved=true lists the unresolved call sites of callees; `entry`. \
     Rows: `[super]` proved; `[this-class]` / `[inherited]` / `[instance]` matched by name, `[reassigned]` through a decorated class: not guaranteed; `[external]` / `[unresolved]` are leaves, no function of the program\n";

/// The arguments of the tool on a HarmonyOS program, for its errors.
const TAKES: &str = "class + method or to=call:REGEX, from=method:NAME, direction, depth, max_nodes, defines, unresolved, entry";

/// `to` on a HarmonyOS program, as errors spell it out (`arg`: how the front
/// end names the argument).
pub fn to_usage(arg: &str) -> String {
    format!(
        "{arg} takes call:PATTERN on a HarmonyOS program: a regex over callee paths as findrefs call prints them, \
         e.g. call:^import:@ohos:net\\.http"
    )
}

/// The roots `call:PATTERN` names: every callee path the regex matches.
///
/// # Errors
/// What `rule` should be, starting with the name of the argument, `arg`.
pub fn leaf_roots(rule: &str, arg: &str) -> Result<CallRoots, String> {
    match (rule.starts_with("call:"), Query::condition(rule)) {
        (true, Ok(Query::Call(pattern))) => Ok(CallRoots::Leaf(pattern)),
        (true, Err(e)) => Err(format!("{arg}: {e}")),
        _ => Err(to_usage(arg)),
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

/// `from` of a callers walk: the functions whose paths to the roots are kept.
#[derive(Debug, Clone)]
pub struct CallerFilter {
    /// Part of the record name.
    record: Option<String>,
    name: Pattern,
}

impl CallerFilter {
    /// `method:[RECORD->]NAME`, as the `method:` condition of findrefs:
    /// `NAME` a regex over the raw and the restored function name, `=NAME`
    /// the exact name (or a dotted suffix of the restored one).
    ///
    /// # Errors
    /// What `rule` should be, starting with the name of the argument, `arg`.
    pub fn parse(rule: &str, arg: &str) -> Result<CallerFilter, String> {
        match (rule.starts_with("method:"), Query::condition(rule)) {
            (true, Ok(Query::Method { record, name })) => Ok(CallerFilter { record, name }),
            (true, Err(e)) => Err(format!("{arg}: {e}")),
            _ => Err(format!(
                "{arg} takes method:[RECORD->]NAME on a HarmonyOS program: NAME a regex over function names, =NAME the exact \
                 name, e.g. method:=EntryAbility.onNewWant"
            )),
        }
    }

    fn matches(&self, node: &CallNode) -> bool {
        let CallNode::Function { record, function, restored, .. } = node else { return false };
        if self.record.as_ref().is_some_and(|wanted| !record.contains(wanted.as_str())) {
            return false;
        }
        match &self.name {
            Pattern::Exact(wanted) => {
                function == wanted || restored == wanted || restored.strip_suffix(wanted.as_str()).is_some_and(|rest| rest.ends_with('.'))
            }
            name => name.is_match(function) || name.is_match(restored),
        }
    }
}

/// A tree as both front ends print it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeText {
    /// One line per row shown.
    pub lines: Vec<String>,
    /// The rows shown, as indexes into the rows of the tree.
    pub shown: Vec<usize>,
    /// `#` lines after the rows: what the walk covered, what was left out.
    pub footer: String,
}

impl TreeText {
    /// The rows of `tree`, all of them or, with `from`, those on a path from
    /// a caller it names down to a root (that caller marked `[from]`).
    ///
    /// A walk expands each function once, where it is nearest to a root, so
    /// every such caller within the depth has a row, and a shortest path.
    ///
    /// Rows name their ABC entry only when the functions of the tree come
    /// from several; `several_entries`: the program has more than one, and
    /// the footer then names the one entry of a tree that has one.
    pub fn of(tree: &CallTree, several_entries: bool, from: Option<&CallerFilter>) -> TreeText {
        let mut entries = tree.rows.iter().filter_map(|row| match &row.node {
            CallNode::Function { entry, .. } => Some(entry.as_str()),
            CallNode::Leaf { .. } => None,
        });
        let first = entries.next();
        let with_entry = entries.any(|entry| Some(entry) != first);
        let mut lines = tree.lines(with_entry);
        let mut footer = tree.footer();
        if let (Some(entry), true, false) = (first, several_entries, with_entry) {
            let at = footer.find('\n').unwrap_or(footer.len());
            footer.insert_str(at, &format!("; all in {entry}"));
        }
        let Some(from) = from else {
            return TreeText { shown: (0..lines.len()).collect(), lines, footer };
        };
        let mut keep = vec![false; tree.rows.len()];
        let mut paths = 0;
        let mut callers = HashSet::new();
        for (index, row) in tree.rows.iter().enumerate() {
            if row.depth == 0 || !from.matches(&row.node) {
                continue;
            }
            paths += 1;
            callers.insert(&row.node);
            lines[index].push_str(" [from]");
            let mut at = Some(index);
            while let Some(row) = at.filter(|&row| !keep[row]) {
                keep[row] = true;
                at = tree.rows[row].parent;
            }
        }
        let shown: Vec<usize> = (0..tree.rows.len()).filter(|&index| keep[index]).collect();
        footer.push_str(&match paths {
            0 => format!(
                "\n# from: none of the {} callers walked matches (depth {}); a path ends where a callback is called by the system \
                 or through a value ([unresolved] call sites): raise depth, or walk the callees of the function",
                tree.functions, tree.depth
            ),
            _ => format!(
                "\n# from: {} of {} rows shown: {paths} path{} from {} matching function{}",
                shown.len(),
                tree.rows.len(),
                if paths == 1 { "" } else { "s" },
                callers.len(),
                if callers.len() == 1 { "" } else { "s" }
            ),
        });
        let lines = lines.into_iter().zip(&keep).filter_map(|(line, keep)| keep.then_some(line)).collect();
        TreeText { lines, shown, footer }
    }
}

/// A row as JSON; `parent`: its parent among the rows shown.
fn row_json(row: &CallRow, parent: Option<usize>) -> Value {
    let mut value = json!({"depth": row.depth, "parent": parent, "repeated": row.repeated});
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

/// Callers or callees of a function, or the callers of callee paths.
pub(super) fn callgraph(session: &Session, args: &Value, call: &Call) -> ToolResult {
    if asks_for(args, "unless") {
        return Err(ToolError(format!("callgraph `unless` is not supported for HarmonyOS programs yet (callgraph takes: {TAKES})")));
    }
    let mut direction = match choice_arg(args, "direction", "callers", CALL_DIRECTIONS)? {
        "callers" => Direction::Callers,
        _ => Direction::Callees,
    };
    let entry = str_arg(args, "entry")?;
    let to = str_arg(args, "to")?;
    let roots = match (str_arg(args, "class")?, str_arg(args, "method")?, to) {
        (None, None, None) => {
            return Err(ToolError(
                "callgraph needs `class` + `method` (or `class`: RECORD->FUNCTION as rows print it), or `to`: call:REGEX".into(),
            ))
        }
        (Some(_), _, Some(_)) | (_, Some(_), Some(_)) => {
            return Err(ToolError("give the target as `class` + `method` or as `to`, not both".into()));
        }
        (None, None, Some(_)) if entry.is_some() => {
            return Err(ToolError("`entry` picks the root function: it does not go with `to`".into()))
        }
        (None, None, Some(to)) => {
            // The callers of a callee path are the only walk from one.
            direction = Direction::Callers;
            leaf_roots(to, "`to`").map_err(ToolError)?
        }
        (Some(record), Some(function), None) => function_roots(Some(record), function, entry),
        (Some(spec), None, None) | (None, Some(spec), None) => function_roots(None, spec, entry),
    };
    let from = str_arg(args, "from")?.map(|rule| CallerFilter::parse(rule, "`from`").map_err(ToolError)).transpose()?;
    if from.is_some() && direction == Direction::Callees {
        return Err(ToolError("`from` keeps caller paths: it goes with direction=callers (the default) or `to`".into()));
    }
    let query = CallQuery {
        depth: usize_arg(args, "depth")?.unwrap_or(CALLGRAPH_DEPTH),
        max_nodes: usize_arg(args, "max_nodes")?.unwrap_or(CALLGRAPH_MAX_NODES),
        defines: bool_arg(args, "defines")?.unwrap_or(true),
        unresolved: bool_arg(args, "unresolved")?.unwrap_or(false),
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
    let shown = TreeText::of(&tree, engine.has_several_entries(), from.as_ref());
    let mut text: String = shown.lines.iter().map(|line| format!("{line}\n")).collect();
    text.push_str(&shown.footer);
    text.push('\n');
    let hints: Vec<String> = match to {
        Some(to) if tree.rows.is_empty() => vec![no_leaf_hint(to, "findrefs kind=call")],
        _ => no_callers_hint(&tree, "findrefs kind=prop value=NAME exact=true access=call").into_iter().collect(),
    };
    for hint in &hints {
        text.push_str(&format!("# hint: {hint}\n"));
    }
    let position = |index: usize| shown.shown.binary_search(&index).ok();
    let rows: Vec<Value> =
        shown.shown.iter().map(|&index| row_json(&tree.rows[index], tree.rows[index].parent.and_then(position))).collect();
    let structured = json!({
        "apk_id": session.id,
        "direction": direction.as_str(),
        "depth": tree.depth,
        "methods": tree.functions,
        "leaves": tree.leaves,
        "truncated": tree.truncated,
        "records_scanned": tree.records_scanned,
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
        CallRow { depth, parent, node, kind: parent.map(|_| EdgeKind::Call), sites: 1, repeated: false, unresolved: None }
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
        assert!(matches!(leaf_roots("call:^import:@ohos:net\\.http", "--to"), Ok(CallRoots::Leaf(_))));
        assert_eq!(leaf_roots("call:(", "--to").unwrap_err().split(':').next(), Some("--to"));
        assert!(leaf_roots("string:token", "--to").unwrap_err().starts_with("--to takes call:PATTERN on a HarmonyOS program"));
        assert!(CallerFilter::parse("call:x", "`from`").unwrap_err().starts_with("`from` takes method:[RECORD->]NAME"));
        assert!(CallerFilter::parse("method:(", "`from`").unwrap_err().starts_with("`from`: invalid pattern"));
    }

    #[test]
    fn a_tree_of_one_entry_names_it_once() {
        let one = tree(vec![row(0, None, function("a.abc", "x")), row(1, Some(0), function("a.abc", "y"))]);
        let text = TreeText::of(&one, true, None);
        assert_eq!(text.lines, ["0 &a/b&->#~@0>#x | B.x", "  1 <- &a/b&->#~@0>#y | B.y"]);
        assert_eq!(text.footer, "# 2 rows, 2 distinct functions, 0 leaves (callers, depth 3); 1 records scanned; all in a.abc");
        assert!(!TreeText::of(&one, false, None).footer.contains("all in"));
        let two = tree(vec![row(0, None, function("a.abc", "x")), row(1, Some(0), function("b.abc", "y"))]);
        let text = TreeText::of(&two, true, None);
        assert_eq!(text.lines, ["0 &a/b&->#~@0>#x | B.x [a.abc]", "  1 <- &a/b&->#~@0>#y | B.y [b.abc]"]);
        assert!(!text.footer.contains("all in"), "{}", text.footer);
    }

    #[test]
    fn from_keeps_the_paths_of_matching_callers() {
        let leaf = CallNode::Leaf { path: "import:@ohos:net.http#default.createHttp".into(), external: true };
        let walked = tree(vec![
            row(0, None, leaf),
            row(1, Some(0), function("a.abc", "send")),
            row(2, Some(1), function("a.abc", "onCreate")),
            row(3, Some(2), function("a.abc", "boot")),
            row(2, Some(1), function("a.abc", "other")),
            row(1, Some(0), function("a.abc", "poll")),
            row(2, Some(5), function("a.abc", "onNewWant")),
        ]);
        let from = CallerFilter::parse("method:^B\\.on", "from").unwrap();
        let text = TreeText::of(&walked, false, Some(&from));
        assert_eq!(text.shown, [0, 1, 2, 5, 6]);
        assert_eq!(
            text.lines,
            [
                "0 import:@ohos:net.http#default.createHttp [external]",
                "  1 <- &a/b&->#~@0>#send | B.send",
                "    2 <- &a/b&->#~@0>#onCreate | B.onCreate [from]",
                "  1 <- &a/b&->#~@0>#poll | B.poll",
                "    2 <- &a/b&->#~@0>#onNewWant | B.onNewWant [from]",
            ]
        );
        assert!(text.footer.ends_with("\n# from: 5 of 7 rows shown: 2 paths from 2 matching functions"), "{}", text.footer);

        // An exact name is the raw name, the restored one or a dotted suffix of it; the record is a part of its name.
        for (rule, shown) in [
            ("method:=onNewWant", 3),
            ("method:=B.onNewWant", 3),
            ("method:=#~@0>#onNewWant", 3),
            ("method:a/b->=#~@0>#onNewWant", 3),
            ("method:x/y->=onNewWant", 0),
            ("method:=NewWant", 0),
        ] {
            let from = CallerFilter::parse(rule, "from").unwrap();
            assert_eq!(TreeText::of(&walked, false, Some(&from)).shown.len(), shown, "{rule}");
        }
        let none = TreeText::of(&walked, false, Some(&CallerFilter::parse("method:=nowhere", "from").unwrap()));
        assert!(none.lines.is_empty() && none.footer.contains("\n# from: none of the 6 callers walked matches (depth 3)"), "{none:?}");
    }
}
