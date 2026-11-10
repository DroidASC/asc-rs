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
            "  1 -> import:N:lib/Index&#Box.nothing [external]",
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
    assert!(rows.contains(&"  1 -> import:N:util/Util&#helper [external]".to_owned()), "{rows:?}");
    assert!(rows.contains(&"  1 -> import:N:lib/Index&#star [external]".to_owned()), "{rows:?}");
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
