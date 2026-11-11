//! The call graph on a synthetic program of four records: local calls,
//! calls through imports (regular, namespace, renamed and star re-exports,
//! a class and its methods), external and unresolved leaves, definitions,
//! both directions with depth and size limits, two ABC entries, damage.

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::AtomicBool;

use asc_abc::FunctionKind;
use asc_ark_engine::{CallEdge, CallNode, CallQuery, CallRoots, Direction, EdgeKind, Engine, EngineError, Pattern, RequestForm};
use asc_fixture::abc::{AbcBuilder, AbcCode, AbcFunction, AbcLiteral, AbcModule, AbcRecord, Asm, Op};

const APP: &str = "&entry/src/main/ets/pages/App&";
const UTIL: &str = "&entry/src/main/ets/util/Util&";
const INDEX: &str = "&entry/src/main/ets/lib/Index&";
const BOX: &str = "&entry/src/main/ets/lib/Box&";
const OTHER: &str = "&feature/src/main/ets/Other&";

fn request(record: &str) -> String {
    format!("@normalized:N&&{record}")
}

fn function(name: &str, num_vregs: u32, declared_args: u32, asm: Asm) -> AbcFunction {
    AbcFunction::new(name, AbcCode::new(num_vregs, 3 + declared_args, asm)).kind(FunctionKind::FUNCTION)
}

/// Call regular import `index`.
fn call_import(asm: &mut Asm, index: u8) {
    asm.op("ldexternalmodulevar", [index.into()]).op("callarg0", [0.into()]);
}

/// Call member `name` of regular import `index`.
fn call_import_member(asm: &mut Asm, index: u8, name: &str) {
    asm.op("ldexternalmodulevar", [index.into()]).op("ldobjbyname", [0.into(), Op::str(name)]).op("callarg0", [0.into()]);
}

fn app_record() -> AbcRecord {
    let module = AbcModule::new()
        .import("helper", "helper", &request(UTIL))
        .import("Box", "Box", &request(INDEX))
        .import("star", "star", &request(INDEX))
        .import("http", "default", "@ohos:net.http")
        .import("gone", "gone", &request("&entry/src/main/ets/missing/Gone&"))
        .import("aliased", "aliased", &request(INDEX))
        .namespace_import("util", &request(UTIL));

    let mut main = Asm::new();
    main.op("definefunc", [0.into(), Op::method("#*#run"), 1.into()]).op("sta", [0.into()]);
    main.op("lda", [0.into()]).op("callarg0", [0.into()]).op("returnundefined", []);

    // `run(p)`: two locals, so p is register 5.
    let mut run = Asm::new();
    call_import(&mut run, 0);
    call_import_member(&mut run, 1, "make");
    run.op("ldexternalmodulevar", [1.into()]).op("sta", [0.into()]).op("mov", [1.into(), 0.into()]);
    run.op("newobjrange", [0.into(), 1.into(), 1.into()]).op("ldobjbyname", [0.into(), Op::str("get")]).op("callarg0", [0.into()]);
    call_import(&mut run, 2);
    call_import(&mut run, 5);
    call_import_member(&mut run, 3, "createHttp");
    call_import(&mut run, 4);
    run.op("getmodulenamespace", [0.into()]).op("ldobjbyname", [0.into(), Op::str("helper")]).op("callarg0", [0.into()]);
    run.op("lda", [5.into()]).op("ldobjbyname", [0.into(), Op::str("then")]).op("callarg0", [0.into()]);
    run.op("definefunc", [0.into(), Op::method("#*@0*#cb"), 0.into()]).op("sta", [0.into()]);
    call_import_member(&mut run, 1, "nothing");
    run.op("returnundefined", []);

    let mut cb = Asm::new();
    call_import(&mut cb, 0);
    cb.op("returnundefined", []);

    AbcRecord::ets_module(APP, "entry", &["run"], module)
        .function(function("func_main_0", 1, 0, main))
        .function(function("#*#run", 2, 1, run))
        .function(function("#*@0*#cb", 0, 0, cb))
}

fn util_record() -> AbcRecord {
    let module = AbcModule::new().export("helper", "helper").export("star", "star");
    let mut main = Asm::new();
    main.op("definefunc", [0.into(), Op::method("#*#helper"), 0.into()]).op("stmodulevar", [0.into()]);
    main.op("definefunc", [0.into(), Op::method("#*#star"), 0.into()]).op("stmodulevar", [1.into()]);
    main.op("returnundefined", []);
    let mut helper = Asm::new();
    helper.op("ldlocalmodulevar", [1.into()]).op("callarg0", [0.into()]);
    helper.op("tryldglobalbyname", [0.into(), Op::str("console")]).op("ldobjbyname", [0.into(), Op::str("log")]).op("callarg0", [0.into()]);
    helper.op("returnundefined", []);
    let mut star = Asm::new();
    star.op("returnundefined", []);
    AbcRecord::ets_module(UTIL, "entry", &[], module)
        .function(function("func_main_0", 0, 0, main))
        .function(function("#*#helper", 0, 0, helper))
        .function(function("#*#star", 0, 0, star))
}

/// Only re-exports: `export { Box } from`, `export { helper as aliased }
/// from`, `export * from`.
fn index_record() -> AbcRecord {
    let module = AbcModule::new()
        .indirect_export("Box", "Box", &request(BOX))
        .indirect_export("aliased", "helper", &request(UTIL))
        .star_export(&request(UTIL));
    let mut main = Asm::new();
    main.op("returnundefined", []);
    AbcRecord::ets_module(INDEX, "entry", &[], module).function(function("func_main_0", 0, 0, main))
}

fn box_record(builder: &mut AbcBuilder) -> AbcRecord {
    let literal = builder.literal_array([
        AbcLiteral::str("get"),
        AbcLiteral::method(BOX, "#~@0>#get"),
        AbcLiteral::MethodAffiliate(0),
        AbcLiteral::str("size"),
        AbcLiteral::method(BOX, "#~@0>#size"),
        AbcLiteral::MethodAffiliate(0),
        AbcLiteral::str("make"),
        AbcLiteral::method(BOX, "#~@0<#make"),
        AbcLiteral::MethodAffiliate(0),
        AbcLiteral::Integer(2),
    ]);
    let mut main = Asm::new();
    main.op("ldhole", []).op("sta", [0.into()]);
    main.op("defineclasswithbuffer", [0.into(), Op::method("#~@0=#Box"), literal.into(), 0.into(), 0.into()]).op("sta", [1.into()]);
    main.op("lda", [1.into()]).op("stmodulevar", [0.into()]).op("returnundefined", []);
    let mut leaf = Asm::new();
    leaf.op("returnundefined", []);
    // An instance method: `this.size()` is a method of the class, `this.other()` is not.
    let mut get = Asm::new();
    get.op("ldthisbyname", [0.into(), Op::str("size")]).op("callarg0", [0.into()]);
    get.op("ldthisbyname", [0.into(), Op::str("other")]).op("callarg0", [0.into()]);
    get.op("returnundefined", []);
    // A static method: `this` is the class, which has no `get`.
    let mut make = Asm::new();
    make.op("ldthisbyname", [0.into(), Op::str("get")]).op("callarg0", [0.into()]);
    make.op("returnundefined", []);
    AbcRecord::ets_module(BOX, "entry", &["Box"], AbcModule::new().export("Box", "Box"))
        .function(function("func_main_0", 2, 0, main))
        .function(function("#~@0=#Box", 0, 0, leaf.clone()))
        .function(function("#~@0>#get", 0, 0, get))
        .function(function("#~@0>#size", 0, 0, leaf))
        .function(function("#~@0<#make", 0, 0, make))
}

fn program() -> AbcBuilder {
    let mut builder = AbcBuilder::new();
    let boxed = box_record(&mut builder);
    builder.record(app_record()).record(util_record()).record(index_record()).record(boxed);
    builder
}

fn open(dir: &Path, builder: &AbcBuilder) -> Engine {
    let path = dir.join("modules.abc");
    std::fs::write(&path, builder.build().bytes).unwrap();
    Engine::open(&path).unwrap()
}

fn query(roots: CallRoots, direction: Direction, depth: usize) -> CallQuery {
    CallQuery { depth, ..CallQuery::new(roots, direction) }
}

/// The tree with the record names shortened to their last path segment.
fn lines(engine: &Engine, query: &CallQuery) -> Vec<String> {
    let tree = engine.call_graph(query, &AtomicBool::new(false)).unwrap();
    tree.lines(false).into_iter().map(|line| short(&line)).collect()
}

fn short(line: &str) -> String {
    let mut line = line.to_owned();
    for (record, name) in [(APP, "App"), (UTIL, "Util"), (INDEX, "Index"), (BOX, "Box"), (OTHER, "Other")] {
        line = line.replace(&format!("{record}->"), &format!("{name}->"));
    }
    line.replace("@normalized:N&&&entry/src/main/ets/", "N:")
}

#[test]
fn callees_follow_imports_exports_and_classes() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &program());
    let run = CallRoots::function(&format!("{APP}->#*#run"));
    assert_eq!(
        lines(&engine, &query(run.clone(), Direction::Callees, 1)),
        [
            "0 App->#*#run | run unresolved=1",
            // The import, the renamed re-export of it and the namespace member: three call sites.
            "  1 -> Util->#*#helper | helper x3",
            // `Box` comes through `export { Box } from`; its literal names the methods.
            "  1 -> Box->#~@0<#make | Box.make",
            "  1 -> Box->#~@0=#Box | Box.constructor [new]",
            "  1 -> Box->#~@0>#get | Box.get",
            // Through `export * from`.
            "  1 -> Util->#*#star | star",
            "  1 -> import:@ohos:net.http#default.createHttp [external]",
            // A request that names no record of the program.
            "  1 -> import:N:missing/Gone&#gone [external]",
            "  1 -> App->#*@0*#cb | run.cb [defines]",
            // The record resolves, the member is not a method of the class.
            "  1 -> import:N:lib/Index&#Box.nothing [unlinked]",
        ]
    );
    // Unresolved call sites are counted on the row, and listed on request.
    let listed = lines(&engine, &CallQuery { unresolved: true, ..query(run.clone(), Direction::Callees, 1) });
    assert_eq!(listed.len(), 11);
    assert_eq!(listed[8], "  1 -> arg0.then [unresolved]");
    // Without definitions, the closure is not reached.
    let plain = lines(&engine, &CallQuery { defines: false, ..query(run.clone(), Direction::Callees, 1) });
    assert!(plain.len() == 9 && !plain.iter().any(|line| line.contains("cb")), "{plain:?}");

    assert_eq!(
        lines(&engine, &query(run, Direction::Callees, 2))[..9],
        [
            "0 App->#*#run | run unresolved=1",
            "  1 -> Util->#*#helper | helper x3",
            // A module-level binding of the record, with its one `stmodulevar`.
            "    2 -> Util->#*#star | star",
            "    2 -> global:console.log [external]",
            "  1 -> Box->#~@0<#make | Box.make unresolved=1",
            "  1 -> Box->#~@0=#Box | Box.constructor [new]",
            "  1 -> Box->#~@0>#get | Box.get unresolved=1",
            // By name in the class of the calling method.
            "    2 -> Box->#~@0>#size | Box.size [this-class]",
            // Listed under `helper` too; it has nothing below it to repeat.
            "  1 -> Util->#*#star | star",
        ]
    );
    let tree = engine.call_graph(&query(CallRoots::function("func_main_0"), Direction::Callees, 1), &AtomicBool::new(false)).unwrap();
    // Without a record, every function of that name is a root.
    assert_eq!(tree.rows.iter().filter(|row| row.depth == 0).count(), 4);
    assert_eq!((tree.functions, tree.leaves, tree.truncated, tree.records_scanned), (8, 0, false, 4));
    assert!(
        tree.footer().starts_with("# 8 rows, 8 distinct functions, 0 leaves (callees, depth 1); 4 records scanned"),
        "{}",
        tree.footer()
    );
}

#[test]
fn callers_come_from_the_records_that_can_import() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &program());
    assert_eq!(
        lines(&engine, &query(CallRoots::function("star"), Direction::Callers, 2)),
        [
            "0 Util->#*#star | star",
            "  1 <- App->#*#run | run unresolved=1",
            // Defined and called there: the call is the stronger link.
            "    2 <- App->func_main_0 | func_main_0 x2",
            "  1 <- Util->func_main_0 | func_main_0 [defines]",
            "  1 <- Util->#*#helper | helper",
            "    2 <- App->#*#run | run x3 unresolved=1 (repeated)",
            "    2 <- App->#*@0*#cb | run.cb",
            "    2 <- Util->func_main_0 | func_main_0 [defines]",
        ]
    );
    // A method reached by name only.
    assert_eq!(
        lines(&engine, &query(CallRoots::function("Box.size"), Direction::Callers, 3)),
        [
            "0 Box->#~@0>#size | Box.size",
            "  1 <- Box->#~@0>#get | Box.get [this-class] unresolved=1",
            "    2 <- App->#*#run | run unresolved=1",
            "      3 <- App->func_main_0 | func_main_0 x2",
        ]
    );
    // System APIs are leaves; a pattern over leaves is a root for callers.
    let http = CallRoots::Leaf(Pattern::regex("^import:@ohos:net\\.http").unwrap());
    assert_eq!(
        lines(&engine, &query(http.clone(), Direction::Callers, 2)),
        [
            "0 import:@ohos:net.http#default.createHttp [external]",
            "  1 <- App->#*#run | run unresolved=1",
            "    2 <- App->func_main_0 | func_main_0 x2",
        ]
    );
    // Unresolved leaves can be asked for the same way.
    let then = CallRoots::Leaf(Pattern::exact("arg0.then"));
    assert_eq!(lines(&engine, &query(then, Direction::Callers, 1)), ["0 arg0.then [unresolved]", "  1 <- App->#*#run | run unresolved=1"]);
    let failed = engine.call_graph(&query(http, Direction::Callees, 1), &AtomicBool::new(false));
    assert!(matches!(failed, Err(EngineError::Query(_))), "{failed:?}");

    // The limits.
    let helper = CallRoots::function(&format!("{UTIL}->helper"));
    assert_eq!(lines(&engine, &query(helper.clone(), Direction::Callers, 0)), ["0 Util->#*#helper | helper"]);
    let capped = engine.call_graph(&CallQuery { max_nodes: 2, ..query(helper, Direction::Callers, 3) }, &AtomicBool::new(false)).unwrap();
    assert!(capped.truncated && capped.rows.len() == 2 && capped.footer().contains("truncated"), "{capped:?}");

    // Roots that name nothing, or too much inside one record.
    let missing = engine.call_graph(&query(CallRoots::function("nowhere"), Direction::Callers, 1), &AtomicBool::new(false));
    assert!(matches!(missing, Err(EngineError::NotFound { what: "function", .. })), "{missing:?}");
    let no_record = engine.call_graph(&query(CallRoots::function("pages/Nope->run"), Direction::Callers, 1), &AtomicBool::new(false));
    assert!(matches!(no_record, Err(EngineError::NotFound { what: "record", .. })), "{no_record:?}");
    // The record by a path suffix, the function by its restored name.
    assert_eq!(lines(&engine, &query(CallRoots::function("lib/Box->Box.make"), Direction::Callers, 1)).len(), 2);
}

fn edges(engine: &Engine) -> Vec<CallEdge> {
    let mut out = Vec::new();
    engine.call_edges(&AtomicBool::new(false), &mut |edge| out.push(edge)).unwrap();
    out
}

fn name(node: &CallNode) -> String {
    match node {
        CallNode::Function { record, function, .. } => short(&format!("{record}->{function}")),
        CallNode::Leaf { path, .. } => short(path),
    }
}

#[test]
fn every_call_site_is_an_edge_and_both_directions_agree() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &program());
    let all = edges(&engine);
    // 18 call sites and 5 definitions (the class is one; its methods are not).
    let count = |kind| all.iter().filter(|edge| edge.kind == kind).count();
    assert_eq!(
        (all.len(), count(EdgeKind::Call), count(EdgeKind::New), count(EdgeKind::ThisClass), count(EdgeKind::Defines)),
        (23, 16, 1, 1, 5)
    );
    let through_imports: Vec<String> = all
        .iter()
        .filter_map(|edge| Some(format!("{} => {} via {}", name(&edge.from), name(&edge.to), short(edge.via.as_ref()?))))
        .collect();
    assert_eq!(
        through_imports,
        [
            "App->#*#run => Util->#*#helper via import:N:util/Util&#helper",
            "App->#*#run => Box->#~@0<#make via import:N:lib/Index&#Box.make",
            "App->#*#run => Box->#~@0=#Box via import:N:lib/Index&#Box",
            "App->#*#run => Box->#~@0>#get via new import:N:lib/Index&#Box().get",
            "App->#*#run => Util->#*#star via import:N:lib/Index&#star",
            "App->#*#run => Util->#*#helper via import:N:lib/Index&#aliased",
            "App->#*#run => Util->#*#helper via import:N:util/Util&#*.helper",
            "App->#*@0*#cb => Util->#*#helper via import:N:util/Util&#helper",
        ]
    );
    // Both walks see every edge between functions: a cold engine for the callers side, so that
    // only the records that walk picks are loaded.
    let level_one = |engine: &Engine, node: &CallNode, direction| -> HashSet<CallNode> {
        let CallNode::Function { record, function, .. } = node else { return HashSet::new() };
        let roots = CallRoots::Function { record: Some(record.clone()), function: function.clone(), entry: None };
        let tree = engine.call_graph(&CallQuery { max_nodes: usize::MAX, ..query(roots, direction, 1) }, &AtomicBool::new(false)).unwrap();
        tree.rows.into_iter().filter(|row| row.depth == 1).map(|row| row.node).collect()
    };
    for edge in all.iter().filter(|edge| matches!(edge.to, CallNode::Function { .. })) {
        let cold = open(dir.path(), &program());
        assert!(level_one(&cold, &edge.to, Direction::Callers).contains(&edge.from), "{edge:?}");
        assert!(level_one(&engine, &edge.from, Direction::Callees).contains(&edge.to), "{edge:?}");
    }
    let forms = engine.request_forms(&AtomicBool::new(false)).unwrap();
    let form = |form| forms.get(&form).map(|count| (count.requests, count.resolved));
    assert_eq!((form(RequestForm::Normalized), form(RequestForm::System), form(RequestForm::Bundle)), (Some((5, 4)), Some((1, 0)), None));
    let size = engine.build_call_graph(&AtomicBool::new(false)).unwrap();
    assert_eq!((size.records, size.functions, size.edges), (4, 12, 23));
}

#[test]
fn imports_resolve_across_entries() {
    // A second ABC file whose record imports from the first.
    let module = AbcModule::new().import("helper", "helper", &request(UTIL)).import("Box", "Box", &request(INDEX));
    let mut main = Asm::new();
    call_import(&mut main, 0);
    call_import_member(&mut main, 1, "make");
    main.op("returnundefined", []);
    let mut second = AbcBuilder::new();
    second.record(AbcRecord::ets_module(OTHER, "feature", &[], module).function(function("func_main_0", 0, 0, main)));

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.abc"), program().build().bytes).unwrap();
    std::fs::write(dir.path().join("b.abc"), second.build().bytes).unwrap();
    let engine = Engine::open(dir.path()).unwrap();
    let tree = engine
        .call_graph(&query(CallRoots::function(&format!("{OTHER}->func_main_0")), Direction::Callees, 1), &AtomicBool::new(false))
        .unwrap();
    let rows: Vec<String> = tree.lines(true).iter().map(|line| short(line)).collect();
    assert_eq!(
        rows,
        [
            "0 Other->func_main_0 | func_main_0 [b.abc]",
            "  1 -> Util->#*#helper | helper [a.abc]",
            "  1 -> Box->#~@0<#make | Box.make [a.abc]",
        ]
    );
    let callers = engine.call_graph(&query(CallRoots::function("Box.make"), Direction::Callers, 1), &AtomicBool::new(false)).unwrap();
    let rows: Vec<String> = callers.lines(true).iter().map(|line| short(line)).collect();
    assert_eq!(
        rows,
        [
            "0 Box->#~@0<#make | Box.make unresolved=1 [a.abc]",
            "  1 <- App->#*#run | run unresolved=1 [a.abc]",
            "  1 <- Other->func_main_0 | func_main_0 [b.abc]",
        ]
    );
}

#[test]
fn unreadable_code_hides_the_exports_of_its_record() {
    // `Util` with one more function, whose code does not decode: it could hold a second
    // `stmodulevar`, so what the record exports is no longer known.
    let mut broken = Asm::new();
    broken.op("ldnull", []).raw(&[0xff, 0x00]);
    let mut builder = AbcBuilder::new();
    let boxed = box_record(&mut builder);
    let util = util_record().function(function("#*#broken", 0, 0, broken));
    builder.record(app_record()).record(util).record(index_record()).record(boxed);
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &builder);
    let rows = lines(&engine, &query(CallRoots::function(&format!("{APP}->#*#run")), Direction::Callees, 1));
    assert!(rows.contains(&"  1 -> import:N:util/Util&#helper [unlinked]".to_owned()), "{rows:?}");
    assert!(rows.contains(&"  1 -> import:N:lib/Index&#star [unlinked]".to_owned()), "{rows:?}");
    // The other record is not affected.
    assert!(rows.contains(&"  1 -> Box->#~@0<#make | Box.make".to_owned()), "{rows:?}");
    assert!(!rows.iter().any(|row| row.contains("Util->")), "{rows:?}");
}

#[test]
fn damaged_files_do_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    let good = program().build().bytes;
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for round in 0..200 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let mut bytes = good.clone();
        let at = asc_abc::HEADER_SIZE + (state as usize) % (bytes.len() - asc_abc::HEADER_SIZE);
        bytes[at] ^= 1 << (round % 8);
        let path = dir.path().join("damaged.abc");
        std::fs::write(&path, &bytes).unwrap();
        // A file that no longer opens is fine; one that opens must answer.
        let Ok(engine) = Engine::open(&path) else { continue };
        let cancel = AtomicBool::new(false);
        let _ = engine.call_edges(&cancel, &mut |_| {});
        for direction in [Direction::Callers, Direction::Callees] {
            let _ = engine.call_graph(&query(CallRoots::function("run"), direction, 3), &cancel);
            let _ = engine.call_graph(&query(CallRoots::function("func_main_0"), direction, 3), &cancel);
        }
        let _ = engine.call_graph(&query(CallRoots::Leaf(Pattern::regex(".").unwrap()), Direction::Callers, 2), &cancel);
        let _ = engine.request_forms(&cancel);
    }
    // A cancelled walk says so.
    let engine = open(dir.path(), &program());
    let cancelled = engine.call_graph(&query(CallRoots::function("star"), Direction::Callers, 1), &AtomicBool::new(true));
    assert!(matches!(cancelled, Err(EngineError::Cancelled)), "{cancelled:?}");
}

/// The tree of `query` on the class program, record names shortened.
fn class_lines(engine: &Engine, query: &CallQuery) -> Vec<String> {
    use asc_fixture::abc::{LINEAGE_APP, LINEAGE_BASE, LINEAGE_LEAF, LINEAGE_MIDDLE, LINEAGE_SERVICE};
    let tree = engine.call_graph(query, &AtomicBool::new(false)).unwrap();
    let names =
        [(LINEAGE_APP, "App"), (LINEAGE_BASE, "Base"), (LINEAGE_MIDDLE, "Middle"), (LINEAGE_LEAF, "Leaf"), (LINEAGE_SERVICE, "Service")];
    tree.lines(false)
        .into_iter()
        .map(|mut line| {
            for (record, name) in names {
                line = line.replace(&format!("{record}->"), &format!("{name}->"));
            }
            line.replace("@normalized:N&&&entry/src/main/ets/", "N:")
        })
        .collect()
}

#[test]
fn calls_go_up_the_parent_classes() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &asc_fixture::abc::class_calls_program());
    let callees =
        |root: &str| class_lines(&engine, &CallQuery { unresolved: true, ..query(CallRoots::function(root), Direction::Callees, 1) });
    // `this.run()` is found two classes up, `this.stop()` one up; `super.run()` is the same
    // function as `this.run()` here, and the proved call is the one the row shows.
    assert_eq!(
        callees("leaf/Leaf->Leaf.go"),
        [
            "0 Leaf->#~@0>#go | Leaf.go unresolved=1",
            "  1 -> Base->#~@0>#run | Base.run [super] x2",
            "  1 -> Middle->#~@0>#stop | Middle.stop [inherited]",
            // No class of the chain lists it.
            "  1 -> this.none [unresolved]",
            "  1 -> Leaf->#~@0>#go | Leaf.go [this-class] unresolved=1 (repeated)",
        ]
    );
    assert_eq!(
        callees("mid/Middle->Middle.relay"),
        ["0 Middle->#~@0>#relay | Middle.relay", "  1 -> Base->#~@0>#run | Base.run [inherited]"]
    );
    // `super.stop()` skips the method of the class itself; a static method looks at the static side.
    assert_eq!(callees("mid/Middle->Middle.stop"), ["0 Middle->#~@0>#stop | Middle.stop", "  1 -> Base->#~@0>#stop | Base.stop [super]"]);
    assert_eq!(
        callees("mid/Middle->Middle.build"),
        ["0 Middle->#~@0<#build | Middle.build", "  1 -> Base->#~@0<#make | Base.make [super] x2"]
    );
    // `super(...)` is the parent's constructor.
    assert_eq!(
        callees("leaf/Leaf->Leaf.constructor"),
        ["0 Leaf->#~@0=#Leaf | Leaf.constructor", "  1 -> Middle->#~@0=#Middle | Middle.constructor [super]"]
    );
    assert_eq!(
        callees("mid/Middle->Middle.constructor"),
        ["0 Middle->#~@0=#Middle | Middle.constructor", "  1 -> Base->#~@0=#Base | Base.constructor [super]"]
    );
    // A parent outside the program: the call sites stay as they were.
    assert_eq!(callees("leaf/Leaf->Ext.constructor"), ["0 Leaf->#~@1=#Ext | Ext.constructor unresolved=1", "  1 -> super [unresolved]"]);
    assert_eq!(
        callees("leaf/Leaf->Ext.onCreate"),
        ["0 Leaf->#~@1>#onCreate | Ext.onCreate unresolved=2", "  1 -> this.missing [unresolved]", "  1 -> super.onCreate [unresolved]"]
    );
    // A parent read from a reassigned binding marks whatever goes through it.
    assert_eq!(
        callees("svc/Service->Card.constructor"),
        ["0 Service->#~@1=#Card | Card.constructor", "  1 -> Base->#~@1=#Tagged | Tagged.constructor [reassigned]"]
    );
    assert_eq!(callees("svc/Service->Card.show"), ["0 Service->#~@1>#show | Card.show", "  1 -> Base->#~@1>#go | Tagged.go [reassigned]"]);
}

#[test]
fn exported_objects_and_decorated_classes_are_followed() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &asc_fixture::abc::class_calls_program());
    assert_eq!(
        class_lines(&engine, &query(CallRoots::function("pages/App->run"), Direction::Callees, 1)),
        [
            "0 App->#*#run | run",
            // `api = new Middle()` in another record, which imports `Middle`: the method of the class …
            "  1 -> Middle->#~@0>#stop | Middle.stop [instance]",
            // … or of its parent; `new Middle().run()` leads there too, as an inherited method.
            "  1 -> Base->#~@0>#run | Base.run [instance] x2",
            // `tag = new Tagged()`, and `Tagged` is reassigned by a decorator.
            "  1 -> Base->#~@1>#go | Tagged.go [reassigned]",
            // An object of a class of the exporting record.
            "  1 -> Service->#~@0>#ping | Local.ping [instance]",
            // `one = Middle.build()`: what a call returned is not known.
            "  1 -> import:N:svc/Service&#one.run [unlinked]",
            // No class of the chain lists it.
            "  1 -> import:N:svc/Service&#api.absent [unlinked]",
            "  1 -> Base->#~@1=#Tagged | Tagged.constructor [reassigned]",
            "  1 -> Base->#~@1<#create | Tagged.create [reassigned]",
            // `Middle.make()`: a static method of the parent.
            "  1 -> Base->#~@0<#make | Base.make [inherited]",
            "  1 -> Middle->#~@0=#Middle | Middle.constructor [new]",
        ]
    );
    let all = edges(&engine);
    let count = |kind| all.iter().filter(|edge| edge.kind == kind).count();
    assert_eq!(
        EdgeKind::ALL.map(count),
        // Call, New, Super, Instance, ThisClass, Inherited, Reassigned, Defines.
        [9, 3, 5, 5, 1, 6, 6, 9]
    );
    // What goes through an import says how the call site spells it.
    let via: Vec<String> = all
        .iter()
        .filter(|edge| matches!(edge.kind, EdgeKind::Instance | EdgeKind::Reassigned) && edge.via.is_some())
        .map(|edge| edge.via.as_deref().unwrap_or_default().replace("@normalized:N&&&entry/src/main/ets/", "N:"))
        .collect();
    assert_eq!(
        via,
        [
            "import:N:svc/Service&#api.stop",
            "import:N:svc/Service&#api.run",
            "import:N:svc/Service&#tag.go",
            "import:N:svc/Service&#local.ping",
            "import:N:base/Base&#Tagged",
            "import:N:base/Base&#Tagged.create",
            "import:N:base/Base&#Tagged",
            // A binding of the record itself, which holds an object of an imported class.
            "module:api.relay",
        ]
    );
    // The object of a class of the record, read back in the record: nothing is imported.
    assert_eq!(
        class_lines(&engine, &query(CallRoots::function("svc/Service->probe"), Direction::Callees, 1)),
        [
            "0 Service->#*#probe | probe",
            "  1 -> Service->#~@0>#ping | Local.ping [instance]",
            "  1 -> Middle->#~@0>#relay | Middle.relay [instance]"
        ]
    );
}

#[test]
fn callers_of_a_method_come_through_subclasses_and_exported_objects() {
    let dir = tempfile::tempdir().unwrap();
    // Each walk on an engine that has loaded nothing: the records it picks have to be enough.
    let callers = |root: &str| {
        let cold = open(dir.path(), &asc_fixture::abc::class_calls_program());
        class_lines(&cold, &query(CallRoots::function(root), Direction::Callers, 1))
    };
    // `pages/App` and `leaf/Leaf` do not import the record of `Base`.
    assert_eq!(
        callers("base/Base->Base.run"),
        [
            "0 Base->#~@0>#run | Base.run",
            "  1 <- App->#*#run | run [instance] x2",
            "  1 <- Middle->#~@0>#relay | Middle.relay [inherited]",
            "  1 <- Leaf->#~@0>#go | Leaf.go [super] x2 unresolved=1",
        ]
    );
    assert_eq!(
        callers("base/Base->Base.make"),
        ["0 Base->#~@0<#make | Base.make", "  1 <- App->#*#run | run [inherited]", "  1 <- Middle->#~@0<#build | Middle.build [super] x2"]
    );
    assert_eq!(
        callers("mid/Middle->Middle.stop"),
        [
            "0 Middle->#~@0>#stop | Middle.stop",
            "  1 <- App->#*#run | run [instance]",
            "  1 <- Leaf->#~@0>#go | Leaf.go [inherited] unresolved=1"
        ]
    );
    assert_eq!(
        callers("svc/Service->Local.ping"),
        ["0 Service->#~@0>#ping | Local.ping", "  1 <- App->#*#run | run [instance]", "  1 <- Service->#*#probe | probe [instance]"]
    );
    assert_eq!(
        callers("base/Base->Tagged.go"),
        ["0 Base->#~@1>#go | Tagged.go", "  1 <- App->#*#run | run [reassigned]", "  1 <- Service->#~@1>#show | Card.show [reassigned]"]
    );
    assert_eq!(
        callers("base/Base->Tagged.constructor"),
        [
            "0 Base->#~@1=#Tagged | Tagged.constructor",
            "  1 <- App->#*#run | run [reassigned]",
            "  1 <- Base->func_main_0 | func_main_0 [defines]",
            "  1 <- Service->func_main_0 | func_main_0 [reassigned]",
            "  1 <- Service->#~@1=#Card | Card.constructor [reassigned]",
        ]
    );
    // Every edge of the program is seen from both ends.
    let engine = open(dir.path(), &asc_fixture::abc::class_calls_program());
    let level_one = |engine: &Engine, node: &CallNode, direction| -> HashSet<CallNode> {
        let CallNode::Function { record, function, .. } = node else { return HashSet::new() };
        let roots = CallRoots::Function { record: Some(record.clone()), function: function.clone(), entry: None };
        let tree = engine.call_graph(&CallQuery { max_nodes: usize::MAX, ..query(roots, direction, 1) }, &AtomicBool::new(false)).unwrap();
        tree.rows.into_iter().filter(|row| row.depth == 1).map(|row| row.node).collect()
    };
    for edge in edges(&engine).iter().filter(|edge| matches!(edge.to, CallNode::Function { .. })) {
        let cold = open(dir.path(), &asc_fixture::abc::class_calls_program());
        assert!(level_one(&cold, &edge.to, Direction::Callers).contains(&edge.from), "{edge:?}");
        assert!(level_one(&engine, &edge.from, Direction::Callees).contains(&edge.to), "{edge:?}");
    }
}

#[test]
fn a_lookup_stops_where_the_classes_do_not_decide() {
    const RECORD: &str = "&entry/src/main/ets/Odd&";
    let literal = |builder: &mut AbcBuilder, methods: &[(&str, &str)]| {
        let mut items = Vec::new();
        for (name, method) in methods {
            items.extend([AbcLiteral::str(name), AbcLiteral::method(RECORD, method), AbcLiteral::MethodAffiliate(0)]);
        }
        items.push(AbcLiteral::Integer(i32::try_from(methods.len()).unwrap()));
        builder.literal_array(items)
    };
    let mut builder = AbcBuilder::new();
    // `Top` lists `twice` two times (a redefinition) and `once` one time; `Low extends Top`;
    // `Free` extends a parameter.
    let top = literal(&mut builder, &[("twice", "#~@0>#twice"), ("twice", "#~@0>#twice^1"), ("once", "#~@0>#once")]);
    let low = literal(&mut builder, &[("use", "#~@1>#use")]);
    let free = literal(&mut builder, &[("use", "#~@2>#use")]);
    let mut main = Asm::new();
    main.op("ldhole", []).op("sta", [0.into()]);
    main.op("defineclasswithbuffer", [0.into(), Op::method("#~@0=#Top"), top.into(), 0.into(), 0.into()]).op("sta", [0.into()]);
    main.op("defineclasswithbuffer", [0.into(), Op::method("#~@1=#Low"), low.into(), 0.into(), 0.into()]);
    main.op("definefunc", [0.into(), Op::method("#*#mix"), 1.into()]).op("returnundefined", []);
    // `mix(base)`: no locals, so `base` is register 3.
    let mut mix = Asm::new();
    mix.op("defineclasswithbuffer", [0.into(), Op::method("#*@3~@2=#Free"), free.into(), 0.into(), 3.into()]).op("return", []);
    let mut uses = Asm::new();
    for name in ["twice", "once"] {
        uses.op("ldthisbyname", [0.into(), Op::str(name)]).op("callarg0", [0.into()]);
        uses.op("ldsuperbyname", [0.into(), Op::str(name)]).op("callarg0", [0.into()]);
    }
    uses.op("returnundefined", []);
    let mut leaf = Asm::new();
    leaf.op("returnundefined", []);
    // `super(...args)`: the constructor passes its own function object (register 1: one local),
    // then something else.
    let mut spread = Asm::new();
    spread.op("lda", [1.into()]).op("supercallspread", [0.into(), 0.into()]);
    spread.op("ldundefined", []).op("supercallspread", [0.into(), 0.into()]).op("returnundefined", []);
    let mut record = AbcRecord::ets_module(RECORD, "entry", &["Top", "Low", "Free", "mix"], AbcModule::new())
        .function(function("func_main_0", 1, 0, main))
        .function(function("#*#mix", 0, 1, mix))
        .function(function("#~@1=#Low", 1, 0, spread))
        .function(function("#~@1>#use", 0, 0, uses.clone()))
        .function(function("#~@2>#use", 0, 0, uses));
    for name in ["#~@0=#Top", "#~@0>#twice", "#~@0>#twice^1", "#~@0>#once", "#*@3~@2=#Free"] {
        record = record.function(function(name, 0, 0, leaf.clone()));
    }
    builder.record(record);
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &builder);
    let callees = |root: &str| {
        let query = CallQuery { unresolved: true, ..query(CallRoots::function(root), Direction::Callees, 1) };
        let tree = engine.call_graph(&query, &AtomicBool::new(false)).unwrap();
        tree.lines(false).into_iter().skip(1).map(|line| line.replace(&format!("{RECORD}->"), "")).collect::<Vec<_>>()
    };
    assert_eq!(
        callees("Low.use"),
        [
            // Listed twice by the parent: which one runs is not decided, and the lookup does not go on.
            "  1 -> this.twice [unresolved]",
            "  1 -> super.twice [unresolved]",
            "  1 -> #~@0>#once | Top.once [super] x2",
        ]
    );
    // `super(...)` is the parent's constructor when the function it is called for is the running one.
    assert_eq!(callees("Low.constructor"), ["  1 -> #~@0=#Top | Top.constructor [super]", "  1 -> super [unresolved]"]);
    // A parent that is not known.
    assert_eq!(
        callees("#~@2>#use"),
        [
            "  1 -> this.twice [unresolved]",
            "  1 -> super.twice [unresolved]",
            "  1 -> this.once [unresolved]",
            "  1 -> super.once [unresolved]",
        ]
    );
}

#[test]
fn a_binding_written_twice_is_followed_only_as_a_decorated_class() {
    use asc_fixture::abc::{CLASSES_BASE, class_hierarchy_program};
    // A second ABC file that imports the bindings of the hierarchy program: `Watched` is a class
    // reassigned by a decorator, `Either` is assigned two classes.
    let module = AbcModule::new().import("Watched", "Watched", &request(CLASSES_BASE)).import("Either", "Either", &request(CLASSES_BASE));
    let mut main = Asm::new();
    for index in 0..2u8 {
        main.op("ldexternalmodulevar", [index.into()]).op("sta", [0.into()]).op("newobjrange", [0.into(), 1.into(), 0.into()]);
    }
    main.op("returnundefined", []);
    let mut second = AbcBuilder::new();
    second.record(AbcRecord::ets_module(OTHER, "feature", &[], module).function(function("func_main_0", 1, 0, main)));
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.abc"), class_hierarchy_program().build().bytes).unwrap();
    std::fs::write(dir.path().join("b.abc"), second.build().bytes).unwrap();
    let engine = Engine::open(dir.path()).unwrap();
    let root = CallRoots::function(&format!("{OTHER}->func_main_0"));
    let tree = engine.call_graph(&query(root, Direction::Callees, 1), &AtomicBool::new(false)).unwrap();
    let rows: Vec<String> = tree.lines(true).iter().map(|line| line.replace(&format!("{CLASSES_BASE}->"), "Base->")).collect();
    assert_eq!(
        rows[1..],
        [
            "  1 -> Base->#~@1=#Watched | Watched.constructor [reassigned] [a.abc]",
            // Assigned two classes: neither is taken.
            "  1 -> import:@normalized:N&&&entry/src/main/ets/base/Base&#Either [unlinked] [new]",
        ]
    );
    let callers =
        engine.call_graph(&query(CallRoots::function("Watched.constructor"), Direction::Callers, 1), &AtomicBool::new(false)).unwrap();
    assert!(
        callers.lines(false).contains(&format!("  1 <- {OTHER}->func_main_0 | func_main_0 [reassigned]")),
        "{:?}",
        callers.lines(false)
    );
}

/// The two packages of the fixture in a directory: `entry.hap` and `lib.hsp`.
fn packaged(dir: &Path, library_module_json: &str) -> Engine {
    use asc_fixture::abc::{PACKAGED_ENTRY_MODULE_JSON, PACKAGED_ENTRY_PKG_CONTEXT, packaged_entry_program, packaged_library_program};
    use asc_fixture::hap::{Compression, Hap};
    let entry = Hap::new().modules_abc(&packaged_entry_program().build().bytes).module_json(PACKAGED_ENTRY_MODULE_JSON).entry(
        "pkgContextInfo.json",
        PACKAGED_ENTRY_PKG_CONTEXT.as_bytes(),
        Compression::Deflated,
    );
    let library = Hap::new().modules_abc(&packaged_library_program().build().bytes).module_json(library_module_json);
    std::fs::write(dir.join("entry.hap"), entry.build()).unwrap();
    std::fs::write(dir.join("lib.hsp"), library.build()).unwrap();
    Engine::open(dir).unwrap()
}

#[test]
fn requests_are_led_by_their_module_and_by_the_package_table() {
    use asc_fixture::abc::{PACKAGED_INDEX, PACKAGED_KIT, PACKAGED_LIBRARY_MODULE_JSON, PACKAGED_OWN, PACKAGED_TOOL};
    let callees = |engine: &Engine| {
        let root = CallRoots::Function { record: Some(PACKAGED_INDEX.into()), function: "func_main_0".into(), entry: None };
        let tree = engine.call_graph(&query(root, Direction::Callees, 1), &AtomicBool::new(false)).unwrap();
        tree.lines(true).into_iter().skip(1).collect::<Vec<_>>()
    };
    let dir = tempfile::tempdir().unwrap();
    let engine = packaged(dir.path(), PACKAGED_LIBRARY_MODULE_JSON);
    assert_eq!(
        callees(&engine),
        [
            // Both packages have the record: the request names module `lib`.
            format!("  1 -> {PACKAGED_TOOL}->#*#tool | tool [lib.hsp/ets/modules.abc]"),
            // A package name: its entry file, in the module the table of the requesting package gives …
            format!("  1 -> {PACKAGED_KIT}->#*#kit | kit [lib.hsp/ets/modules.abc]"),
            // … or in the package itself.
            format!("  1 -> {PACKAGED_OWN}->#*#own | own [entry.hap/ets/modules.abc]"),
            // A package the table does not list.
            "  1 -> import:absent#gone [external]".to_owned(),
            // A module the program does not have: the record of the requesting package.
            format!("  1 -> {PACKAGED_TOOL}->#*#spare | spare [entry.hap/ets/modules.abc]"),
        ]
    );
    let forms = engine.request_forms(&AtomicBool::new(false)).unwrap();
    let form = |form| forms.get(&form).map(|count| (count.requests, count.resolved));
    assert_eq!(
        (form(RequestForm::Normalized), form(RequestForm::Plain), form(RequestForm::System)),
        (Some((2, 2)), Some((2, 1)), Some((1, 1)))
    );
    // The callers of each copy are the ones whose request leads to it.
    let callers = |entry: &str, function: &str| {
        let roots = CallRoots::Function { record: Some(PACKAGED_TOOL.into()), function: function.into(), entry: Some(entry.into()) };
        let tree =
            packaged(dir.path(), PACKAGED_LIBRARY_MODULE_JSON).call_graph(&query(roots, Direction::Callers, 1), &AtomicBool::new(false));
        tree.unwrap().rows.iter().filter(|row| row.depth == 1 && row.kind == Some(EdgeKind::Call)).count()
    };
    assert_eq!((callers("lib.hsp/ets/modules.abc", "tool"), callers("entry.hap/ets/modules.abc", "tool")), (1, 0));
    assert_eq!((callers("lib.hsp/ets/modules.abc", "spare"), callers("entry.hap/ets/modules.abc", "spare")), (0, 1));

    // Without a package of that module name, the requesting package comes first, as before; a
    // package name whose module is not there is looked up the same way, and is not found.
    let other = tempfile::tempdir().unwrap();
    let renamed = PACKAGED_LIBRARY_MODULE_JSON.replace("\"lib\"", "\"renamed\"");
    let rows = callees(&packaged(other.path(), &renamed));
    assert_eq!(rows[0], format!("  1 -> {PACKAGED_TOOL}->#*#tool | tool [entry.hap/ets/modules.abc]"));
    assert_eq!(rows[1], format!("  1 -> {PACKAGED_KIT}->#*#kit | kit [lib.hsp/ets/modules.abc]"));
}

fn rule(spec: &str) -> asc_ark_engine::Query {
    asc_ark_engine::Query::rule(spec, None).unwrap()
}

#[test]
fn rules_are_roots_ends_and_fences_of_a_walk() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &program());
    let star = CallRoots::function(&format!("{UTIL}->star"));
    let tree = |query: &CallQuery| engine.call_graph(query, &AtomicBool::new(false)).unwrap();
    let whole = lines(&engine, &query(star.clone(), Direction::Callers, 3));

    // `unless` leaves a function out, with what only it reaches.
    let fenced = CallQuery { unless: vec![rule("method:=helper")], ..query(star.clone(), Direction::Callers, 3) };
    let rows = lines(&engine, &fenced);
    assert!(rows.len() < whole.len() && !rows.iter().any(|row| row.contains("helper") || row.contains("cb")), "{rows:?}");
    assert_eq!(rows[..2], ["0 Util->#*#star | star", "  1 <- App->#*#run | run unresolved=1"]);
    assert_eq!(tree(&fenced).pruned, 1);
    assert!(tree(&fenced).footer().contains("; 1 functions left out by unless"));
    // By what its code does: the functions that log are `helper` (and `Other`'s, which nothing here reaches).
    let by_code = CallQuery { unless: vec![rule("global:=console & prop:=log")], ..query(star.clone(), Direction::Callers, 3) };
    assert_eq!(lines(&engine, &by_code), rows);
    // Several rules add up; a root can be left out too.
    let both = CallQuery { unless: vec![rule("method:=helper"), rule("method:=run")], ..query(star.clone(), Direction::Callers, 3) };
    assert_eq!(lines(&engine, &both), ["0 Util->#*#star | star", "  1 <- Util->func_main_0 | func_main_0 [defines]"]);
    assert_eq!(tree(&both).pruned, 2);
    let no_root = tree(&CallQuery { unless: vec![rule("method:=star")], ..query(star.clone(), Direction::Callers, 3) });
    assert!(no_root.rows.is_empty() && no_root.pruned == 1, "{no_root:?}");

    // `from` keeps the paths that start at a matching function, and ends them there.
    let from = CallQuery { from: Some(rule("method:=cb")), ..query(star.clone(), Direction::Callers, 3) };
    assert_eq!(
        lines(&engine, &from),
        ["0 Util->#*#star | star", "  1 <- Util->#*#helper | helper", "    2 <- App->#*@0*#cb | run.cb [from]"]
    );
    let kept = tree(&from);
    assert_eq!((kept.reached.map(|reached| reached.from), kept.functions), (Some(1), 3));
    assert!(kept.rows[2].from && !kept.rows[1].from);
    assert!(kept.footer().contains("; 1 from functions reached"), "{}", kept.footer());
    // By code: `run` is the function with the unresolved `p.then()`; nothing above it is walked.
    let by_code = CallQuery { from: Some(rule("prop:=then")), ..query(star.clone(), Direction::Callers, 3) };
    let rows = lines(&engine, &by_code);
    assert_eq!(rows[1], "  1 <- App->#*#run | run unresolved=1 [from]");
    assert!(!rows.iter().any(|row| row.contains("App->func_main_0")), "{rows:?}");
    // None reached: no rows, and the footer says how far the walk went.
    let nowhere = tree(&CallQuery { from: Some(rule("method:=make")), ..query(star.clone(), Direction::Callers, 3) });
    assert!(nowhere.rows.is_empty());
    assert!(
        nowhere.footer().contains("; 0 from functions reached\n# from: none of the 6 callers walked matches (depth 3)"),
        "{}",
        nowhere.footer()
    );
    // `from` and `unless` together; `from` is for callers only.
    let fenced_from =
        CallQuery { from: Some(rule("method:=run")), unless: vec![rule("method:=helper")], ..query(star.clone(), Direction::Callers, 3) };
    assert_eq!(lines(&engine, &fenced_from), ["0 Util->#*#star | star", "  1 <- App->#*#run | run unresolved=1 [from]"]);
    let down =
        engine.call_graph(&CallQuery { from: Some(rule("method:=run")), ..query(star, Direction::Callees, 1) }, &AtomicBool::new(false));
    assert!(matches!(down, Err(EngineError::Query(_))), "{down:?}");

    // A rule as the roots: the functions it matches, in program order.
    let roots = CallRoots::Matching(rule("prop:=then"));
    assert_eq!(
        lines(&engine, &query(roots.clone(), Direction::Callers, 1)),
        ["0 App->#*#run | run unresolved=1", "  1 <- App->func_main_0 | func_main_0 x2"]
    );
    assert_eq!(
        lines(&engine, &query(roots, Direction::Callees, 1))[..2],
        ["0 App->#*#run | run unresolved=1", "  1 -> Util->#*#helper | helper x3"]
    );
    let named = lines(&engine, &query(CallRoots::Matching(rule("method:^Box\\.(get|size)$")), Direction::Callers, 0));
    assert_eq!(named, ["0 Box->#~@0>#get | Box.get", "0 Box->#~@0>#size | Box.size"]);
    let none =
        engine.call_graph(&query(CallRoots::Matching(rule("prop:=nothing-like-this")), Direction::Callers, 1), &AtomicBool::new(false));
    assert!(matches!(none, Err(EngineError::Query(message)) if message == "no function matches the root rule"));
}

#[test]
fn calls_into_a_set_of_functions_are_rows() {
    use asc_ark_engine::{FunctionSet, Query};
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &program());
    let find = |query: &Query| -> Vec<String> {
        let mut out = Vec::new();
        engine
            .find_refs(query, &AtomicBool::new(false), &mut |batch| {
                out.extend(batch.rows.iter().map(|row| short(&row.line("")).trim_start_matches(" | ").to_owned()));
            })
            .unwrap();
        out
    };
    // One level of a callers walk, with the instruction of each call: a definition is not a call.
    assert_eq!(
        find(&rule("call:{method:=star}")),
        [
            "App->#*#run+0x1e | run | callarg0 ; -> Util->#*#star (star)",
            "Util->#*#helper+0x2 | helper | callarg0 ; -> Util->#*#star (star)"
        ]
    );
    // By name in the class of the caller: the link says so.
    let size = find(&rule("call:{method:=Box.size}"));
    assert_eq!(size, ["Box->#~@0>#get+0x4 | Box.get | callarg0 ; -> Box->#~@0>#size (Box.size) [this-class]"]);
    let made = find(&rule("call:{method:=Box.constructor}"));
    assert!(made.len() == 1 && made[0].ends_with(" ; -> Box->#~@0=#Box (Box.constructor) [new]"), "{made:?}");
    // The set is a rule: by code, with exclusions, and nested one level up.
    assert_eq!(find(&rule("call:{global:=console & prop:=log & !method:^func_main}")).len(), find(&rule("call:{method:=helper}")).len());
    let two_up = find(&rule("call:{call:{method:=star}}"));
    assert!(two_up.iter().any(|row| row.starts_with("App->func_main_0+")) && two_up.iter().any(|row| row.contains("cb+")), "{two_up:?}");
    assert!(
        two_up.iter().all(|row| row.contains(" ; -> App->#*#run (run)") || row.contains(" ; -> Util->#*#helper (helper)")),
        "{two_up:?}"
    );
    // A condition like any other: in a conjunction, and excluded.
    let callers = find(&rule("call:{method:=helper} & !method:=cb"));
    assert_eq!(callers.len(), 1, "{callers:?}");
    assert!(callers[0].starts_with("App->#*#run+0x2 | run | call +0x2 callarg0 ; -> Util->#*#helper (helper), +0x"), "{callers:?}");
    assert!(callers[0].ends_with(" (+1 more)"), "{callers:?}");
    assert_eq!(find(&rule("prop:=then & !call:{method:=star}")), Vec::<String>::new());
    assert_eq!(find(&rule("prop:=get & !call:{method:=star}")).len(), 1);
    // An empty set matches nothing, and takes nothing away.
    assert!(find(&rule("call:{method:=nowhere}")).is_empty());
    assert_eq!(find(&rule("prop:=then & !call:{method:=nowhere}")).len(), 1);

    // The functions of a list: rows as findrefs and callgraph print them, or names.
    let listed = |text: &str| Query::CallTo(FunctionSet::listed(text));
    let star = find(&rule("call:{method:=star}"));
    assert_eq!(find(&listed(&format!("x.abc | {UTIL}->#*#star+0x0 | star | returnundefined\n"))), star);
    assert_eq!(find(&listed(&format!("# a tree\n0 {UTIL}->#*#star | star\n  1 <- {APP}->#*#run | run\n"))).len(), star.len() + 1);
    assert_eq!(find(&listed("star\n")), star);
    assert_eq!(find(&listed("util/Util->star\n")), star);
    assert!(find(&listed("pages/App->star\n")).is_empty());
    let list = dir.path().join("functions.txt");
    std::fs::write(&list, "star\n").unwrap();
    assert_eq!(find(&Query::rule("call:{@functions.txt}", Some(dir.path())).unwrap()), star);
    assert_eq!(find(&Query::rule(&format!("call:{{@{}}}", list.display()), None).unwrap()), star);
    // As the roots of a walk: the callers of the callers.
    let roots = CallRoots::Matching(rule("call:{method:=star}"));
    // (No count of unresolved call sites at depth 0: a row says what its walk looked at, not what earlier queries left.)
    assert_eq!(lines(&engine, &query(roots, Direction::Callers, 0)), ["0 App->#*#run | run", "0 Util->#*#helper | helper"]);
}
