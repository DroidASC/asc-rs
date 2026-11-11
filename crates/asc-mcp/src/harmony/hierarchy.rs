//! `hierarchy` on a HarmonyOS program: the arguments of the DEX tool carry
//! over, and the tree is printed as the `asc` command prints it.

use super::Session;
use crate::rules::{HIERARCHY_DEPTH, HIERARCHY_DIRECTIONS, HIERARCHY_MAX_NODES};
use crate::{Call, ToolError, ToolResult, choice_arg, str_arg, usize_arg};
use asc_ark_engine::{ClassNode, ClassRow, EngineError, HierarchyQuery, HierarchyTree, Lineage};
use asc_frontend::harmony::no_class_hint;
use serde_json::{Value, json};
use std::sync::atomic::AtomicBool;

/// What the tool takes on a HarmonyOS program, for the program's introduction.
pub(super) const USAGE: &str = "# hierarchy: class=NAME (EntryAbility) or RECORD->CLASS as rows print it, or \"import:REGEX\" / \"global:REGEX\" for the \
     subclasses of a parent outside the program (import:@ohos:app\\.ability\\.UIAbility, ^global:ViewPU$); direction, depth, max_nodes, \
     `entry`; method=NAME marks `[defines FUNCTION]` from the class's members. Rows: `[external]` / `[unresolved]` are parents that are \
     no class of the program (the path is where tracking stopped), `[reassigned]` a parent read from a binding a decorator reassigns\n";

/// A row as JSON.
fn row_json(row: &ClassRow) -> Value {
    let mut value = json!({"depth": row.depth, "parent": row.parent, "repeated": row.repeated});
    match &row.node {
        ClassNode::Class { entry, record, function, name } => {
            value["class"] = json!(format!("{record}->{function}"));
            value["name"] = json!(name);
            value["entry"] = json!(entry);
        }
        ClassNode::Leaf { path, external } => {
            value["path"] = json!(path);
            value["external"] = json!(external);
        }
    }
    for (flag, set) in
        [("sendable", row.sendable), ("function", row.plain_function), ("no_superclass", row.no_parent), ("reassigned", row.reassigned)]
    {
        if set {
            value[flag] = json!(true);
        }
    }
    if !row.defines.is_empty() {
        let defines: Vec<Value> = row
            .defines
            .iter()
            .map(|defined| json!({"function": defined.function, "name": defined.restored, "static": defined.is_static}))
            .collect();
        value["defines"] = json!(defines);
    }
    if row.members_unknown {
        value["members_unknown"] = json!(true);
    }
    value
}

/// The tree of `query`. A `class` that came apart at its `->` on the way
/// here (`class`: the record, `method`: the class) is put together again
/// when that names a class definition.
fn walk(session: &Session, mut query: HierarchyQuery, cancel: &AtomicBool) -> Result<HierarchyTree, EngineError> {
    let engine = &session.engine;
    if let Some(member) = query.method.clone().filter(|_| !query.class.contains("->")) {
        let whole = HierarchyQuery { class: format!("{}->{member}", query.class), method: None, ..query.clone() };
        // `class` + `method` of a method the class has also reads as a function of a record: that is not it.
        match engine.hierarchy(&whole, cancel) {
            Ok(tree) if tree.rows.iter().all(|row| row.depth > 0 || !row.plain_function) => return Ok(tree),
            _ => {}
        }
    }
    query.class = query.class.trim().to_owned();
    engine.hierarchy(&query, cancel)
}

/// Subclasses or supertypes of a class, or the subclasses of a parent path.
pub(super) fn hierarchy(session: &Session, args: &Value, call: &Call) -> ToolResult {
    let class = str_arg(args, "class")?
        .ok_or_else(|| ToolError("hierarchy needs `class`: a class name, RECORD->CLASS as rows print it, or import:REGEX".into()))?;
    let direction = match choice_arg(args, "direction", "subclasses", HIERARCHY_DIRECTIONS)? {
        "subclasses" => Lineage::Subclasses,
        _ => Lineage::Supers,
    };
    let query = HierarchyQuery {
        class: class.to_owned(),
        entry: str_arg(args, "entry")?.map(str::to_owned),
        direction,
        depth: usize_arg(args, "depth")?.unwrap_or(HIERARCHY_DEPTH),
        max_nodes: usize_arg(args, "max_nodes")?.unwrap_or(HIERARCHY_MAX_NODES),
        method: str_arg(args, "method")?.map(str::to_owned),
    };
    let engine = &session.engine;
    let mut tree = walk(session, query, &call.cancel).map_err(|e| match &e {
        EngineError::Ambiguous { candidates, .. } if super::several_entries_define(candidates) => {
            ToolError(format!("{e}\n(name the entry, the first column, with `entry`)"))
        }
        EngineError::NotFound { what: "class" | "parent path", .. } => {
            ToolError(format!("{e} ({})", no_class_hint("findrefs kind=method")))
        }
        _ => ToolError(e.to_string()),
    })?;
    // The reply is framed with them.
    tree.notes.clear();
    let (lines, footer) = tree.text(engine.has_several_entries());
    let mut text: String = lines.iter().map(|line| format!("{line}\n")).collect();
    text.push_str(&footer);
    text.push('\n');
    let structured = json!({
        "apk_id": session.id,
        "direction": direction.as_str(),
        "depth": tree.depth,
        "classes": tree.classes,
        "leaves": tree.leaves,
        "truncated": tree.truncated,
        "records_scanned": tree.records_scanned,
        "rows": tree.rows.iter().map(row_json).collect::<Vec<_>>(),
        "definitions": tree.definition_lines(),
    });
    Ok((text, structured))
}

#[cfg(test)]
mod tests {
    use super::*;
    use asc_ark_engine::DefinedMethod;

    #[test]
    fn rows_carry_only_the_flags_that_are_set() {
        let class =
            ClassNode::Class { entry: "ets/modules.abc".into(), record: "&a/b&".into(), function: "#~@0=#B".into(), name: "B".into() };
        let plain = ClassRow {
            depth: 1,
            parent: Some(0),
            node: class.clone(),
            repeated: false,
            sendable: false,
            plain_function: false,
            no_parent: false,
            reassigned: false,
            defines: Vec::new(),
            members_unknown: false,
        };
        assert_eq!(
            row_json(&plain),
            json!({"depth": 1, "parent": 0, "repeated": false, "class": "&a/b&->#~@0=#B", "name": "B", "entry": "ets/modules.abc"})
        );
        let defined = DefinedMethod { function: "#~@0>#run".into(), restored: "B.run".into(), is_static: false };
        let flagged = ClassRow { sendable: true, reassigned: true, defines: vec![defined], ..plain.clone() };
        let value = row_json(&flagged);
        assert_eq!((&value["sendable"], &value["reassigned"]), (&json!(true), &json!(true)));
        assert_eq!(value["defines"], json!([{"function": "#~@0>#run", "name": "B.run", "static": false}]));
        let leaf = ClassRow { node: ClassNode::Leaf { path: "global:Error".into(), external: true }, depth: 0, parent: None, ..plain };
        assert_eq!(row_json(&leaf), json!({"depth": 0, "parent": null, "repeated": false, "path": "global:Error", "external": true}));
        assert!(no_class_hint("findrefs method NAME").contains("RECORD->CLASS"));
    }
}
