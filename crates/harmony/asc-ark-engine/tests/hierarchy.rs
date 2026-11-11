//! The class hierarchy on a synthetic program (`asc_fixture`'s
//! `class_hierarchy_program`): parents in a register, a captured variable,
//! through imports (a re-export, a namespace, a reassigned binding, a plain
//! function), outside the program, missing and untracked; both directions
//! with depth and size limits, overriding methods, two ABC entries, the
//! memory accounting.

use std::path::Path;
use std::sync::atomic::AtomicBool;

use asc_ark_engine::{ClassDefinition, ClassNode, Engine, EngineError, HierarchyQuery, Lineage, ParentKind};
use asc_fixture::abc::{AbcBuilder, CLASSES_APP, CLASSES_BASE, CLASSES_INDEX, class_hierarchy_program};

fn open(dir: &Path, builder: &AbcBuilder) -> Engine {
    let path = dir.join("modules.abc");
    std::fs::write(&path, builder.build().bytes).unwrap();
    Engine::open(&path).unwrap()
}

fn short(line: &str) -> String {
    let mut line = line.to_owned();
    for (record, name) in [(CLASSES_APP, "App"), (CLASSES_BASE, "Base"), (CLASSES_INDEX, "Index")] {
        line = line.replace(&format!("{record}->"), &format!("{name}->"));
    }
    line.replace("@normalized:N&&&entry/src/main/ets/", "N:")
}

fn query(class: &str, direction: Lineage) -> HierarchyQuery {
    HierarchyQuery::new(class, direction)
}

/// The rows, definition lines and footer of a walk, record names shortened.
fn lines(engine: &Engine, query: &HierarchyQuery) -> Vec<String> {
    let tree = engine.hierarchy(query, &AtomicBool::new(false)).unwrap();
    let (lines, footer) = tree.text(engine.has_several_entries());
    lines.iter().map(|line| short(line)).chain([footer]).collect()
}

fn error(engine: &Engine, query: &HierarchyQuery) -> String {
    engine.hierarchy(query, &AtomicBool::new(false)).unwrap_err().to_string()
}

fn definitions(engine: &Engine) -> Vec<ClassDefinition> {
    let mut out = Vec::new();
    assert_eq!(engine.class_definitions(&AtomicBool::new(false), &mut |definition| out.push(definition)).unwrap(), 3);
    out
}

fn location(node: &ClassNode) -> String {
    match node {
        ClassNode::Class { record, function, name, .. } => short(&format!("{record}->{function} | {name}")),
        ClassNode::Leaf { path, .. } => short(path),
    }
}

#[test]
fn every_definition_has_its_parent() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &class_hierarchy_program());
    let found: Vec<String> = definitions(&engine)
        .iter()
        .map(|definition| {
            let parent = definition.parent.as_ref().map(location).unwrap_or_default();
            let flags =
                format!("{}{}", if definition.sendable { " sendable" } else { "" }, if definition.reassigned { " reassigned" } else { "" });
            format!("{} in {} <- {}{flags}: {parent}", location(&definition.class), definition.definer, definition.kind.label())
        })
        .collect();
    assert_eq!(
        found,
        [
            // Records in class index order.
            "Base->#~@0=#Base | Base in func_main_0 <- none: ",
            "Base->#~@1=#Watched | Watched in func_main_0 <- none: ",
            "App->#~@0=#EntryAbility | EntryAbility in func_main_0 <- external: import:@ohos:app.ability.UIAbility#default",
            "App->#~@1=#Local | Local in func_main_0 <- none: ",
            "App->#~@2=#Child | Child in func_main_0 <- same record: App->#~@1=#Local | Local",
            "App->#~@3=#GrandChild | GrandChild in func_main_0 <- same record: App->#~@2=#Child | Child",
            // `export { Base } from` in the index leads to the definition.
            "App->#~@4=#Derived | Derived in func_main_0 <- other record: Base->#~@0=#Base | Base",
            // The binding is assigned the class, then what a decorator returned for it.
            "App->#~@5=#Card | Card in func_main_0 <- other record reassigned: Base->#~@1=#Watched | Watched",
            "App->#~@6=#AppError | AppError in func_main_0 <- external: global:Error",
            // A request that names no record of the program.
            "App->#~@8=#Lost | Lost in func_main_0 <- external: import:N:missing/Gone&#Gone",
            "App->#~@a=#Spaced | Spaced in func_main_0 <- other record: Base->#~@0=#Base | Base",
            "App->#~@b=#Legacy | Legacy in func_main_0 <- other record: Base->#*#legacy | legacy",
            "App->#~@c=#Shared | Shared in func_main_0 <- none sendable: ",
            // The record is there, the name is not exported: not external, and not guessed.
            "App->#~@f=#Odd | Odd in func_main_0 <- unresolved: import:N:base/Base&#nothing",
            // Two classes are stored into the binding.
            "App->#~@10=#Twice | Twice in func_main_0 <- unresolved: import:N:base/Base&#Either",
            "App->#*@d~@7=#Mixed | mix.Mixed in #*#mix <- unresolved: arg0",
            // A captured variable with one writer.
            "App->#*@e~@9=#Inner | make.Inner in #*#make <- same record: App->#~@1=#Local | Local",
        ]
    );
    let all = definitions(&engine);
    let count = |kind| all.iter().filter(|definition| definition.kind == kind).count();
    assert_eq!(ParentKind::ALL.map(count), [4, 3, 4, 3, 3]);
    let methods: Vec<_> = all.iter().filter(|definition| definition.methods != Some((0, 0))).map(|definition| definition.methods).collect();
    assert_eq!(methods, [Some((1, 1)), Some((1, 0)), Some((1, 0)), Some((1, 0)), Some((1, 0))]);
}

#[test]
fn subclasses_of_classes_and_of_parent_paths() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &class_hierarchy_program());
    let down = |class: &str| query(class, Lineage::Subclasses);
    assert_eq!(
        lines(&engine, &down("Local")),
        [
            "0 App->#~@1=#Local | Local",
            "  1 subclass App->#~@2=#Child | Child",
            "    2 subclass App->#~@3=#GrandChild | GrandChild",
            "  1 subclass App->#*@e~@9=#Inner | make.Inner",
            "# 4 rows, 4 distinct classes, 0 leaves (subclasses, depth 16); 3 records scanned",
        ]
    );
    // The class as rows print it, by its record, by a dotted suffix of its name.
    let local = lines(&engine, &down("Local"));
    assert_eq!(lines(&engine, &down(&format!("{CLASSES_APP}->#~@1=#Local"))), local);
    assert_eq!(lines(&engine, &down("pages/App->Local")), local);
    assert_eq!(lines(&engine, &down("#~@1=#Local")), local);
    assert_eq!(lines(&engine, &down("Inner"))[0], "0 App->#*@e~@9=#Inner | make.Inner");
    assert_eq!(lines(&engine, &down("make.Inner"))[0], "0 App->#*@e~@9=#Inner | make.Inner");

    // Across records: through the re-export, the namespace, and the reassigned binding.
    assert_eq!(
        lines(&engine, &HierarchyQuery { method: Some("run".into()), ..down("Base") }),
        [
            "0 Base->#~@0=#Base | Base [defines #~@0>#run]",
            "  1 subclass App->#~@4=#Derived | Derived [defines #~@4>#run]",
            "  1 subclass App->#~@a=#Spaced | Spaced",
            "override App->#~@4>#run | Derived.run",
            "# 3 rows, 3 distinct classes, 0 leaves (subclasses, depth 16); 3 records scanned; 1 subclasses define run",
        ]
    );
    assert_eq!(
        lines(&engine, &HierarchyQuery { method: Some("make".into()), ..down("Base") })[0],
        "0 Base->#~@0=#Base | Base [defines static #~@0<#make]"
    );
    assert_eq!(
        lines(&engine, &down("Watched"))[..2],
        ["0 Base->#~@1=#Watched | Watched", "  1 subclass App->#~@5=#Card | Card [reassigned]"]
    );
    // A function that is extended is a root too.
    assert_eq!(
        lines(&engine, &down(&format!("{CLASSES_BASE}->#*#legacy")))[..2],
        ["0 Base->#*#legacy | legacy [function]", "  1 subclass App->#~@b=#Legacy | Legacy"]
    );

    // A parent outside the program: by a regex over its path, or by a name no class has.
    let ability = [
        "0 import:@ohos:app.ability.UIAbility#default [external]".to_owned(),
        "  1 subclass App->#~@0=#EntryAbility | EntryAbility [defines #~@0>#onCreate]".to_owned(),
        "override App->#~@0>#onCreate | EntryAbility.onCreate".to_owned(),
    ];
    let by_path = lines(&engine, &HierarchyQuery { method: Some("onCreate".into()), ..down("import:@ohos:app\\.ability\\.UIAbility") });
    assert_eq!(by_path[..3], ability);
    assert_eq!(
        by_path[3],
        "# 2 rows, 1 distinct classes, 1 leaves (subclasses, depth 16); 3 records scanned; 1 subclasses define onCreate"
    );
    let by_name = lines(&engine, &HierarchyQuery { method: Some("onCreate".into()), ..down("UIAbility") });
    assert_eq!(by_name[..3], ability);
    assert!(
        by_name[3].ends_with("\n# no class of the program has that name: the roots are the parent paths that contain it"),
        "{by_name:?}"
    );
    assert_eq!(lines(&engine, &down("^global:Error$"))[..2], ["0 global:Error [external]", "  1 subclass App->#~@6=#AppError | AppError"]);
    // Every import that is a parent and did not lead to a class: external ones first, each kind by path.
    assert_eq!(
        lines(&engine, &down("import:"))[..8],
        [
            "0 import:N:missing/Gone&#Gone [external]",
            "  1 subclass App->#~@8=#Lost | Lost",
            "0 import:@ohos:app.ability.UIAbility#default [external]",
            "  1 subclass App->#~@0=#EntryAbility | EntryAbility",
            "0 import:N:base/Base&#Either [unresolved]",
            "  1 subclass App->#~@10=#Twice | Twice",
            "0 import:N:base/Base&#nothing [unresolved]",
            "  1 subclass App->#~@f=#Odd | Odd",
        ]
    );
}

#[test]
fn supertypes_end_where_tracking_does() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &class_hierarchy_program());
    let up = |class: &str| query(class, Lineage::Supers);
    assert_eq!(
        lines(&engine, &HierarchyQuery { method: Some("run".into()), ..up("GrandChild") }),
        [
            "0 App->#~@3=#GrandChild | GrandChild",
            "  1 extends App->#~@2=#Child | Child [defines #~@2>#run]",
            "    2 extends App->#~@1=#Local | Local [no superclass] [defines #~@1>#run]",
            "inherited App->#~@2>#run | Child.run",
            "inherited App->#~@1>#run | Local.run",
            // Only the records along the chain are read.
            "# 3 rows, 3 distinct classes, 0 leaves (supers, depth 16); 1 records scanned; 2 supertypes define run",
        ]
    );
    assert_eq!(
        lines(&engine, &up("Card")),
        [
            "0 App->#~@5=#Card | Card",
            "  1 extends Base->#~@1=#Watched | Watched [no superclass] [reassigned]",
            "# 2 rows, 2 distinct classes, 0 leaves (supers, depth 16); 2 records scanned",
        ]
    );
    assert_eq!(lines(&engine, &up("EntryAbility"))[1], "  1 extends import:@ohos:app.ability.UIAbility#default [external]");
    assert_eq!(lines(&engine, &up("Mixed"))[1], "  1 extends arg0 [unresolved]");
    assert_eq!(lines(&engine, &up("Legacy"))[1], "  1 extends Base->#*#legacy | legacy [function]");
    assert_eq!(lines(&engine, &up("Shared"))[0], "0 App->#~@c=#Shared | Shared [sendable] [no superclass]");
    assert_eq!(lines(&engine, &up("Inner"))[1], "  1 extends App->#~@1=#Local | Local [no superclass]");
}

#[test]
fn walks_are_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &class_hierarchy_program());
    let shallow = lines(&engine, &HierarchyQuery { depth: 1, ..query("Local", Lineage::Subclasses) });
    assert_eq!(shallow.len(), 4, "{shallow:?}");
    assert!(!shallow.iter().any(|line| line.contains("GrandChild")) && shallow[3].contains("(subclasses, depth 1)"));
    let small = lines(&engine, &HierarchyQuery { max_nodes: 2, ..query("Local", Lineage::Subclasses) });
    assert_eq!(small.len(), 3, "{small:?}");
    assert!(small[2].ends_with("; truncated (raise max_nodes or lower depth)"), "{small:?}");
    let none = lines(&engine, &HierarchyQuery { depth: 0, ..query("GrandChild", Lineage::Supers) });
    assert_eq!(
        none,
        ["0 App->#~@3=#GrandChild | GrandChild", "# 1 rows, 1 distinct classes, 0 leaves (supers, depth 0); 1 records scanned"]
    );
}

#[test]
fn what_names_nothing_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &class_hierarchy_program());
    assert_eq!(error(&engine, &query("Nowhere", Lineage::Subclasses)), "class Nowhere not found");
    assert_eq!(error(&engine, &query("UIAbility", Lineage::Supers)), "class UIAbility not found");
    assert_eq!(error(&engine, &query("pages/App->Nowhere", Lineage::Subclasses)), "class pages/App->Nowhere not found");
    assert_eq!(error(&engine, &query("pages/Gone->Local", Lineage::Subclasses)), "record pages/Gone not found");
    assert_eq!(error(&engine, &query("import:@ohos:net", Lineage::Subclasses)), "parent path import:@ohos:net not found");
    assert_eq!(
        error(&engine, &query("import:@ohos:app", Lineage::Supers)),
        "a parent path outside the program has no supertypes here: it is a root for subclasses only"
    );
    assert!(error(&engine, &query("import:(", Lineage::Subclasses)).starts_with("invalid pattern"));
    let other_entry = HierarchyQuery { entry: Some("other.abc".into()), ..query("pages/App->Local", Lineage::Subclasses) };
    assert_eq!(error(&engine, &other_entry), "no entry named other.abc");
    let cancelled = engine.hierarchy(&query("Local", Lineage::Subclasses), &AtomicBool::new(true));
    assert!(matches!(cancelled, Err(EngineError::Cancelled)), "{cancelled:?}");
}

#[test]
fn two_entries_are_told_apart() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = class_hierarchy_program().build().bytes;
    std::fs::write(dir.path().join("a.abc"), &bytes).unwrap();
    std::fs::write(dir.path().join("b.abc"), &bytes).unwrap();
    let engine = Engine::open(dir.path()).unwrap();
    // A name alone is every class of that name; rows then say which entry each is in.
    let both = lines(&engine, &query("Child", Lineage::Subclasses));
    assert_eq!(
        both[..4],
        [
            "0 App->#~@2=#Child | Child [a.abc]",
            "  1 subclass App->#~@3=#GrandChild | GrandChild [a.abc]",
            "0 App->#~@2=#Child | Child [b.abc]",
            "  1 subclass App->#~@3=#GrandChild | GrandChild [b.abc]",
        ]
    );
    let one = lines(&engine, &HierarchyQuery { entry: Some("b.abc".into()), ..query("Child", Lineage::Subclasses) });
    assert_eq!(one[..2], ["0 App->#~@2=#Child | Child", "  1 subclass App->#~@3=#GrandChild | GrandChild"]);
    assert!(one[2].ends_with("; all in b.abc"), "{one:?}");
    // An import resolves in the entry of the importing record first.
    let derived = lines(&engine, &HierarchyQuery { entry: Some("b.abc".into()), ..query("Derived", Lineage::Supers) });
    assert!(derived[1].starts_with("  1 extends Base->#~@0=#Base | Base") && derived[2].ends_with("; all in b.abc"), "{derived:?}");
    let ambiguous = error(&engine, &query("pages/App->Child", Lineage::Subclasses));
    assert!(ambiguous.starts_with("record pages/App is ambiguous"), "{ambiguous}");
}

#[test]
fn what_a_walk_keeps_is_counted_and_released() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &class_hierarchy_program());
    assert_eq!(engine.memory_use().analyses, 0);
    let first = lines(&engine, &query("Local", Lineage::Subclasses));
    let held = engine.memory_use().analyses;
    assert!(held > 0);
    // A second walk computes nothing new.
    assert_eq!(lines(&engine, &query("Local", Lineage::Subclasses)), first);
    assert_eq!(engine.memory_use().analyses, held);
    assert_eq!(engine.release_analyses(), held);
    assert_eq!(engine.memory_use().analyses, 0);
    assert_eq!(lines(&engine, &query("Local", Lineage::Subclasses)), first);
    assert_eq!(engine.memory_use().analyses, held);
}
