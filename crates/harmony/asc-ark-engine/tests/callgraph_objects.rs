//! The call graph where a class literal does not say it all: calls on what
//! a function returned or a static property holds, the members a class gets
//! after its definition, `super` in arrow functions, and the bound on the
//! subclasses a callers walk looks through.

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::AtomicBool;

use asc_ark_engine::{CallEdge, CallNode, CallQuery, CallRoots, Direction, EdgeKind, Engine, LeafKind};
use asc_fixture::abc::{
    AbcBuilder, HANDED_APP, HANDED_KIND, HANDED_STORE, LATE_PANEL, LATE_SUB, LINEAGE_APP, LINEAGE_BASE, LINEAGE_LEAF, LINEAGE_MIDDLE,
    LINEAGE_SERVICE, PATCHED_APP, PATCHED_CACHE, PATCHED_VAULT, class_calls_program, handed_objects_program, late_members_program,
    patched_objects_program,
};

/// `builder`'s program as `modules.abc` in `dir`, opened. A cold engine on
/// the same program keeps the file as it is: the engines before it map it,
/// and Windows refuses to rewrite a mapped file.
fn open(dir: &Path, builder: &AbcBuilder) -> Engine {
    let path = dir.join("modules.abc");
    let bytes = builder.build().bytes;
    if std::fs::read(&path).ok().as_deref() != Some(bytes.as_slice()) {
        std::fs::write(&path, bytes).unwrap();
    }
    Engine::open(&path).unwrap()
}

/// The rows of `query`, record names shortened to their last path segment.
fn lines(engine: &Engine, query: &CallQuery) -> Vec<String> {
    let tree = engine.call_graph(query, &AtomicBool::new(false)).unwrap();
    let names = [
        (HANDED_APP, "App"),
        (HANDED_KIND, "Kind"),
        (HANDED_STORE, "Store"),
        (LATE_PANEL, "Panel"),
        (LATE_SUB, "Sub"),
        (LINEAGE_APP, "App"),
        (LINEAGE_BASE, "Base"),
        (LINEAGE_MIDDLE, "Middle"),
        (LINEAGE_LEAF, "Leaf"),
        (LINEAGE_SERVICE, "Service"),
        (PATCHED_APP, "Patched"),
        (PATCHED_VAULT, "Vault"),
        (PATCHED_CACHE, "Cache"),
    ];
    let short = |mut line: String| {
        for (record, name) in names {
            line = line.replace(&format!("{record}->"), &format!("{name}->"));
        }
        line.replace("@normalized:N&&&entry/src/main/ets/", "N:")
    };
    tree.lines(false).into_iter().map(short).collect()
}

fn callees(engine: &Engine, root: &str) -> Vec<String> {
    lines(engine, &CallQuery::new(CallRoots::function(root), Direction::Callees).depth(1).unresolved(true))
}

/// The callers of `root` on an engine that has loaded nothing: the records
/// the walk picks have to be enough.
fn cold_callers(builder: &AbcBuilder, root: &str) -> Vec<String> {
    let dir = tempfile::tempdir().unwrap();
    lines(&open(dir.path(), builder), &CallQuery::new(CallRoots::function(root), Direction::Callers).depth(1))
}

fn edges(engine: &Engine) -> Vec<CallEdge> {
    let mut out = Vec::new();
    engine.call_edges(&AtomicBool::new(false), &mut |edge| out.push(edge)).unwrap();
    out
}

/// Every edge between functions is seen from both ends, the callers side on
/// an engine that has loaded nothing.
fn both_directions_agree(builder: &AbcBuilder) {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), builder);
    let level_one = |engine: &Engine, node: &CallNode, direction| -> HashSet<CallNode> {
        let CallNode::Function { record, function, .. } = node else { return HashSet::new() };
        let roots = CallRoots::Function { record: Some(record.clone()), function: function.clone(), entry: None };
        let query = CallQuery::new(roots, direction).depth(1).max_nodes(usize::MAX);
        engine
            .call_graph(&query, &AtomicBool::new(false))
            .unwrap()
            .rows
            .into_iter()
            .filter(|row| row.depth == 1)
            .map(|row| row.node)
            .collect()
    };
    for edge in edges(&engine).iter().filter(|edge| matches!(edge.to, CallNode::Function { .. })) {
        assert!(level_one(&open(dir.path(), builder), &edge.to, Direction::Callers).contains(&edge.from), "{edge:?}");
        assert!(level_one(&engine, &edge.from, Direction::Callees).contains(&edge.to), "{edge:?}");
    }
}

#[test]
fn calls_on_what_a_function_returned_reach_the_class_it_makes() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &handed_objects_program());
    assert_eq!(
        callees(&engine, "pages/App->run"),
        [
            "0 App->#*#run | run",
            "  1 -> Store->#~@0<#getInstance | Store.getInstance x2",
            // `Store.getInstance().load()`, `Store.create().load()`, `Store.instance.load()`, `make().load()`.
            "  1 -> Store->#~@0>#load | Store.load [instance] x4",
            "  1 -> Store->#~@0<#shared | Store.shared",
            // `Store.shared()` returns `new this()`; `Store.ready` is written by the static initializer.
            "  1 -> Store->#~@0>#save | Store.save [instance] x2",
            "  1 -> Store->#~@0<#create | Store.create",
            "  1 -> Store->#~@1<#open | Hub.open x2",
            // `Hub.open()` returns `new Kind()`, a class of a record this one does not import: its
            // parent's method, and its own.
            "  1 -> Kind->#~@0>#base | KindBase.base [instance]",
            "  1 -> Kind->#~@1>#own | Kind.own [instance]",
            "  1 -> Store->#*#make | make",
            "  1 -> Store->#~@0<#pick | Store.pick",
            // One `return` hands back a parameter.
            "  1 -> import:N:store/Store&#Store.pick().load [unlinked]",
            "  1 -> Store->#~@0<#cached | Store.cached",
            // `Store.cache` is written from a parameter.
            "  1 -> import:N:store/Store&#Store.cached().load [unlinked]",
            "  1 -> Store->#~@1<#loose | Hub.loose",
            // `Hub.spare = new Store()`, but a store of the record writes a `spare` of an object nobody knows.
            "  1 -> import:N:store/Store&#Hub.loose().load [unlinked]",
            // The class is known, and has no such method.
            "  1 -> import:N:store/Store&#Store.getInstance().absent [unlinked]",
        ]
    );
    // In the record of the class: the class read from a captured variable, and `this` of a static method.
    assert_eq!(
        callees(&engine, "store/Store->probe"),
        [
            "0 Store->#*#probe | probe",
            "  1 -> Store->#~@0<#getInstance | Store.getInstance",
            "  1 -> Store->#~@0>#load | Store.load [instance]"
        ]
    );
    assert_eq!(
        callees(&engine, "store/Store->Store.relay"),
        [
            "0 Store->#~@0<#relay | Store.relay",
            "  1 -> Store->#~@0<#getInstance | Store.getInstance [this-class]",
            "  1 -> Store->#~@0>#save | Store.save [instance]"
        ]
    );
    let all = edges(&engine);
    let instance: Vec<&CallEdge> = all.iter().filter(|edge| edge.kind == EdgeKind::Instance).collect();
    assert_eq!(instance.len(), 10);
    // What goes through an import says how the call site spells it.
    let via: HashSet<String> = instance
        .iter()
        .filter_map(|edge| edge.via.as_deref())
        .map(|via| via.replace("@normalized:N&&&entry/src/main/ets/", "N:"))
        .collect();
    assert!(via.contains("import:N:store/Store&#Store.getInstance().load") && via.contains("import:N:store/Store&#Store.ready.save"));
    assert!(via.contains("import:N:store/Store&#make().load") && via.contains("import:N:store/Store&#Hub.open().base"), "{via:?}");
    let leaf = |kind| all.iter().filter(|edge| matches!(&edge.to, CallNode::Leaf { kind: leaf, .. } if *leaf == kind)).count();
    // (The unresolved one is `new this()` in `Store.shared`.)
    assert_eq!((leaf(LeafKind::External), leaf(LeafKind::Unlinked), leaf(LeafKind::Unresolved)), (0, 4, 1));
}

#[test]
fn callers_of_a_method_come_through_the_records_that_hand_out_its_objects() {
    let program = handed_objects_program();
    assert_eq!(
        cold_callers(&program, "store/Store->Store.load"),
        ["0 Store->#~@0>#load | Store.load", "  1 <- App->#*#run | run [instance] x4", "  1 <- Store->#*#probe | probe [instance]"]
    );
    assert_eq!(
        cold_callers(&program, "store/Store->Store.save"),
        [
            "0 Store->#~@0>#save | Store.save",
            "  1 <- App->#*#run | run [instance] x2",
            "  1 <- Store->#~@0<#relay | Store.relay [instance]"
        ]
    );
    // `pages/App` imports the record of `Hub`, not the one of `Kind` and `KindBase`.
    assert_eq!(
        cold_callers(&program, "kind/Kind->KindBase.base"),
        ["0 Kind->#~@0>#base | KindBase.base", "  1 <- App->#*#run | run [instance]"]
    );
    assert_eq!(cold_callers(&program, "kind/Kind->Kind.own"), ["0 Kind->#~@1>#own | Kind.own", "  1 <- App->#*#run | run [instance]"]);
    both_directions_agree(&program);
}

#[test]
fn a_hot_patch_stub_does_not_hide_what_a_function_returns() {
    let program = patched_objects_program();
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &program);
    assert_eq!(
        callees(&engine, "pages/Patched->run"),
        [
            "0 Patched->#*#run | run",
            // Four functions of the record open with the stub: its `return` is not one of theirs.
            "  1 -> Vault->#~@0<#getInstance | Vault.getInstance",
            "  1 -> Vault->#~@0>#load | Vault.load [instance]",
            "  1 -> Vault->#~@0<#fresh | Vault.fresh",
            "  1 -> Vault->#~@0>#save | Vault.save [instance]",
            // A store on the way to the call: no stub, and a `return` of something nobody knows.
            "  1 -> Vault->#~@0<#broken | Vault.broken",
            "  1 -> import:N:patched/Vault&#Vault.broken().load [unlinked]",
            // The same instructions in two functions of a record are an early return written twice.
            "  1 -> Cache->#~@0<#getInstance | Cache.getInstance",
            "  1 -> import:N:patched/Cache&#Cache.getInstance().get [unlinked]",
        ]
    );
    assert_eq!(
        cold_callers(&program, "patched/Vault->Vault.load"),
        ["0 Vault->#~@0>#load | Vault.load", "  1 <- Patched->#*#run | run [instance]"]
    );
    assert_eq!(
        cold_callers(&program, "patched/Vault->Vault.save"),
        ["0 Vault->#~@0>#save | Vault.save", "  1 <- Patched->#*#run | run [instance]"]
    );
    assert_eq!(cold_callers(&program, "patched/Cache->Cache.get"), ["0 Cache->#~@0>#get | Cache.get"]);
    both_directions_agree(&program);
}

#[test]
fn members_defined_after_the_class_are_members() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &late_members_program());
    // `paint` is defined after the class; `size` is an accessor: calling it is not calling the getter.
    assert_eq!(
        callees(&engine, "Panel.first"),
        [
            "0 Panel->#~@1>#first | Panel.first unresolved=1",
            "  1 -> Panel->#~@1>#paint | Panel.paint [this-class]",
            "  1 -> this.size [unresolved]"
        ]
    );
    // A method the literal does not list is a method of its class: `this` and `super` in it.
    assert_eq!(
        callees(&engine, "Panel.paint"),
        [
            "0 Panel->#~@1>#paint | Panel.paint",
            "  1 -> Panel->#~@1>#first | Panel.first [this-class] unresolved=1",
            "  1 -> Panel->#~@0>#tick | Frame.tick [inherited]",
            "  1 -> Panel->#~@0>#paint | Frame.paint [super]",
            "  1 -> Panel->#~@1>@2*# | Panel.paint.<anonymous> x2",
        ]
    );
    assert_eq!(callees(&engine, "Panel.size"), ["0 Panel->#~@1>#size | Panel.size", "  1 -> Panel->#~@0>#tick | Frame.tick [super]"]);
    // The static side: a method, and the static initializer.
    assert_eq!(callees(&engine, "Panel.of"), ["0 Panel->#~@1<#of | Panel.of", "  1 -> Panel->#~@1<#of | Panel.of [this-class] (repeated)"]);
    assert_eq!(
        callees(&engine, "Panel.static_initializer"),
        ["0 Panel->#~@1>#static_initializer | Panel.static_initializer", "  1 -> Panel->#~@1<#of | Panel.of [this-class]"]
    );
    // From a subclass in another record: the method of `Panel`, not the one `Frame` lists under
    // the same name; the accessor ends the lookup; the static method by its name.
    assert_eq!(
        callees(&engine, "Sub.go"),
        [
            "0 Sub->#~@0>#go | Sub.go unresolved=1",
            "  1 -> Panel->#~@1>#paint | Panel.paint [inherited]",
            "  1 -> this.size [unresolved]",
            "  1 -> Panel->#~@1<#of | Panel.of",
        ]
    );
    let program = late_members_program();
    assert_eq!(
        cold_callers(&program, "Panel.paint"),
        [
            "0 Panel->#~@1>#paint | Panel.paint",
            "  1 <- Sub->#~@0>#go | Sub.go [inherited] unresolved=1",
            "  1 <- Panel->func_main_0 | func_main_0 [defines]",
            "  1 <- Panel->#~@1>#first | Panel.first [this-class] unresolved=1",
        ]
    );
    assert_eq!(
        cold_callers(&program, "Frame.paint"),
        ["0 Panel->#~@0>#paint | Frame.paint", "  1 <- Panel->#~@1>#paint | Panel.paint [super]"]
    );
    both_directions_agree(&program);
}

#[test]
fn an_arrow_function_has_the_super_of_the_method_around_it() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &late_members_program());
    assert_eq!(
        callees(&engine, "#~@1>@2*#"),
        [
            "0 Panel->#~@1>@2*# | Panel.paint.<anonymous>",
            "  1 -> Panel->#~@0>#draw | Frame.draw [super]",
            "  1 -> Panel->#~@1>@2*@3*# | Panel.paint.later.<anonymous> [defines]",
        ]
    );
    // Through two arrow functions.
    assert_eq!(
        callees(&engine, "#~@1>@2*@3*#"),
        ["0 Panel->#~@1>@2*@3*# | Panel.paint.later.<anonymous>", "  1 -> Panel->#~@0>#tick | Frame.tick [super]"]
    );
    // No method around it: a plain function, and a method of an object that is no class.
    assert_eq!(callees(&engine, "loose"), ["0 Panel->#*#loose | loose unresolved=1", "  1 -> super.draw [unresolved]"]);
    assert_eq!(callees(&engine, "lit"), ["0 Panel->#*#lit | lit unresolved=1", "  1 -> super.draw [unresolved]"]);
    let program = late_members_program();
    assert_eq!(
        cold_callers(&program, "Frame.draw"),
        ["0 Panel->#~@0>#draw | Frame.draw", "  1 <- Panel->#~@1>@2*# | Panel.paint.<anonymous> [super]"]
    );
    assert_eq!(
        cold_callers(&program, "Frame.tick"),
        [
            "0 Panel->#~@0>#tick | Frame.tick",
            "  1 <- Panel->#~@1>#paint | Panel.paint [inherited]",
            "  1 <- Panel->#~@1>@2*@3*# | Panel.paint.later.<anonymous> [super]",
            "  1 <- Panel->#~@1>#size | Panel.size [super]",
        ]
    );
}

#[test]
fn a_callers_walk_looks_through_a_bounded_number_of_subclasses() {
    // `Base` <- `Middle` <- `Leaf`; `Base.run` is reached from `Middle` and `Leaf` by inheritance and
    // on an object of `Middle` another record exports.
    let program = class_calls_program();
    let callers = |max_subclasses: usize| {
        let dir = tempfile::tempdir().unwrap();
        let engine = open(dir.path(), &program);
        let query = CallQuery::new(CallRoots::function("base/Base->Base.run"), Direction::Callers).depth(1).max_subclasses(max_subclasses);
        (lines(&engine, &query), engine.call_graph(&query, &AtomicBool::new(false)).unwrap())
    };
    let (all, tree) = callers(CallQuery::new(CallRoots::function("x"), Direction::Callers).max_subclasses);
    assert_eq!(
        all,
        [
            "0 Base->#~@0>#run | Base.run",
            "  1 <- App->#*#run | run [instance] x2",
            "  1 <- Middle->#~@0>#relay | Middle.relay [inherited]",
            "  1 <- Leaf->#~@0>#go | Leaf.go [super] x2 unresolved=1",
        ]
    );
    assert!(tree.rows.iter().all(|row| row.subclasses_skipped == 0) && !tree.footer().contains("skipped"), "{}", tree.footer());
    // One subclass: `Middle` is followed and `Leaf` is not, and the row says so. The code of
    // `Leaf` itself is read all the same, its record being one that imports `Middle`: what is
    // not looked for is beyond it.
    let (one, tree) = callers(1);
    assert_eq!(one[0], "0 Base->#~@0>#run | Base.run [1+ subclasses skipped]");
    assert_eq!(one[1..], all[1..]);
    assert_eq!(tree.rows[0].subclasses_skipped, 1);
    // None: what the records that import the record of the class itself say (`pages/App` is one
    // of them). The code of `Leaf`, which imports `Middle` only, is not reached.
    let (none, tree) = callers(0);
    assert_eq!(none[0], "0 Base->#~@0>#run | Base.run [1+ subclasses skipped]");
    assert_eq!(none[1..], all[1..3]);
    assert_eq!(
        tree.footer(),
        "# 3 rows, 3 distinct functions, 0 leaves (callers, depth 1); 4 records scanned\n\
         # subclasses skipped: 1 rows are methods of a class with too many subclasses to look through; callers that reach them by \
         inheritance through the 1+ left out (this.m() / super.m() in their subclasses, a call on an object of one in a record that \
         imports it) were not looked for: `hierarchy CLASS --method NAME` lists the subclasses"
    );
}
