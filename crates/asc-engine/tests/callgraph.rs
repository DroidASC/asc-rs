//! Call graph walks and findrefs context over a two-DEX APK.

use asc_dex::debug_info::{DebugInfo, DebugOp};
use asc_engine::{CacheConfig, CallQuery, Direction, Engine, FindOptions, RefContext};
use asc_findrefs::Query;
use asc_fixture::{dbg_special, make_apk, ClassSpec, CodeSpec, DexBuilder, MethodSpec};
use std::io::Write;
use std::sync::atomic::AtomicBool;

const ENTRY: &str = "La/Entry;";
const OTHER: &str = "La/Other;";
const LIB: &str = "Lb/Lib;";
const EXT: &str = "Lext/Api;";

fn le16(v: u32) -> [u8; 2] {
    (v as u16).to_le_bytes()
}

/// `invoke-static {}` / `invoke-static {v0}` of method `m`.
fn invoke(m: u32, args: u8) -> Vec<u8> {
    let mut v = vec![0x71, args << 4];
    v.extend_from_slice(&le16(m));
    v.extend_from_slice(&[0, 0]);
    v
}

fn body(parts: &[Vec<u8>]) -> CodeSpec {
    let mut insns: Vec<u8> = parts.concat();
    insns.extend_from_slice(&[0x0e, 0x00]); // return-void
    CodeSpec { registers: 1, outs: 1, insns, ..Default::default() }
}

fn static_method(idx: u32, code: CodeSpec) -> MethodSpec {
    MethodSpec { idx, access: 0x1 | 0x8, code: Some(code) }
}

/// classes.dex: `Entry.start()V` loads "secret" and calls `Lib.helper(I)V`;
/// `Other.other()V` calls `Lib.helper(I)V` too.
fn app_dex() -> Vec<u8> {
    let mut d = DexBuilder::new();
    d.string("secret").string("Entry.java").type_("Ljava/lang/Object;");
    d.method(ENTRY, "start", "V", &[]).method(OTHER, "other", "V", &[]).method(LIB, "helper", "V", &["I"]);
    let mut ids = d.resolve();
    let helper = ids.method(LIB, "helper", "V", &["I"]);
    let mut start = vec![0x1a, 0x00];
    start.extend_from_slice(&le16(ids.string("secret")));
    let mut start_code = body(&[start, vec![0x12, 0x10], invoke(helper, 1)]);
    // .line 7 at pc 0, .line 9 at pc 2 (the const/4 before the call).
    start_code.debug =
        Some(DebugInfo { line_start: 7, parameter_names: vec![], ops: vec![dbg_special(0, 0), dbg_special(2, 2), DebugOp::EndSequence] });
    let start_idx = ids.method(ENTRY, "start", "V", &[]);
    let other_idx = ids.method(OTHER, "other", "V", &[]);
    ids.add_class(ClassSpec {
        descriptor: ENTRY.into(),
        access: 0x1,
        superclass: Some("Ljava/lang/Object;".into()),
        source_file: Some("Entry.java".into()),
        direct_methods: vec![static_method(start_idx, start_code)],
        ..Default::default()
    });
    ids.add_class(ClassSpec {
        descriptor: OTHER.into(),
        access: 0x1,
        superclass: Some("Ljava/lang/Object;".into()),
        direct_methods: vec![static_method(other_idx, body(&[vec![0x12, 0x10], invoke(helper, 1)]))],
        ..Default::default()
    });
    ids.finish()
}

/// classes2.dex: `Lib.helper(I)V` calls `Lib.sink()V` and `Ext.call()V` (no
/// body anywhere); `Lib.sink()V` calls back into `Entry.start()V`.
fn lib_dex() -> Vec<u8> {
    let mut d = DexBuilder::new();
    d.type_("Ljava/lang/Object;");
    d.method(LIB, "helper", "V", &["I"]).method(LIB, "sink", "V", &[]).method(EXT, "call", "V", &[]).method(ENTRY, "start", "V", &[]);
    let mut ids = d.resolve();
    let (sink, ext, start) = (ids.method(LIB, "sink", "V", &[]), ids.method(EXT, "call", "V", &[]), ids.method(ENTRY, "start", "V", &[]));
    let helper = ids.method(LIB, "helper", "V", &["I"]);
    // helper: invoke sink twice (one edge), then ext.
    let helper_code = CodeSpec {
        registers: 1,
        ins: 1,
        outs: 1,
        insns: [invoke(sink, 0), invoke(sink, 0), invoke(ext, 0), vec![0x0e, 0]].concat(),
        ..Default::default()
    };
    ids.add_class(ClassSpec {
        descriptor: LIB.into(),
        access: 0x1,
        superclass: Some("Ljava/lang/Object;".into()),
        direct_methods: vec![static_method(helper, helper_code), static_method(sink, body(&[invoke(start, 0)]))],
        ..Default::default()
    });
    ids.finish()
}

fn temp_apk() -> tempfile::NamedTempFile {
    let bytes = make_apk(&[("classes.dex", &app_dex()), ("classes2.dex", &lib_dex())], true);
    let mut f = tempfile::Builder::new().suffix(".apk").tempfile().unwrap();
    f.write_all(&bytes).unwrap();
    f.flush().unwrap();
    f
}

fn query(class: &str, method: &str, direction: Direction, depth: usize) -> CallQuery {
    CallQuery { class: class.into(), method: method.into(), direction, depth, max_nodes: 100, virtual_calls: false }
}

#[test]
fn callers_and_callees_cross_dex_files() {
    let apk = temp_apk();
    for engine in [
        Engine::new(apk.path()).with_threads(2),
        Engine::new(apk.path()).with_threads(2).with_cache(CacheConfig { memory_bytes: 64 << 20, ..Default::default() }),
    ] {
        for _ in 0..2 {
            let t = engine.call_graph(&query(LIB, "helper", Direction::Callers, 3)).unwrap();
            assert_eq!(
                t.lines(),
                [
                    "0 Lb/Lib;->helper(I)V",
                    "  1 <- La/Entry;->start()V",
                    "    2 <- Lb/Lib;->sink()V",
                    "      3 <- Lb/Lib;->helper(I)V (repeated)",
                    "  1 <- La/Other;->other()V",
                ]
            );
            assert_eq!((t.methods, t.truncated), (4, false));
            assert_eq!(t.rows[1].dex, ["classes.dex"]);
            assert_eq!(t.rows[2].parent, Some(1));

            let t = engine.call_graph(&query(ENTRY, "start()V", Direction::Callees, 2)).unwrap();
            assert_eq!(
                t.lines(),
                [
                    "0 La/Entry;->start()V",
                    "  1 -> Lb/Lib;->helper(I)V",
                    "    2 -> Lb/Lib;->sink()V",
                    "    2 -> Lext/Api;->call()V [no body]",
                ]
            );
            assert_eq!(t.rows[1].dex, ["classes2.dex"]);
            // Depth 1 still tells which callees have no body in the APK.
            let t = engine.call_graph(&query(LIB, "helper", Direction::Callees, 1)).unwrap();
            assert_eq!(t.lines(), ["0 Lb/Lib;->helper(I)V", "  1 -> Lb/Lib;->sink()V", "  1 -> Lext/Api;->call()V [no body]"]);
        }
        if engine.memory_cache_bytes() > 0 {
            // The graphs ride along with the cached entries.
            assert!(engine.memory_cache_bytes() > app_dex().len() + lib_dex().len());
        }
    }
}

#[test]
fn call_graph_limits_and_errors() {
    let apk = temp_apk();
    let engine = Engine::new(apk.path()).with_threads(1);
    let mut q = query(LIB, "helper", Direction::Callers, 5);
    q.max_nodes = 2;
    let t = engine.call_graph(&q).unwrap();
    assert!(t.truncated && t.methods == 2, "{:?}", t.lines());
    assert!(t.footer().contains("truncated"));
    let err = engine.call_graph(&query(LIB, "nothing", Direction::Callers, 1)).unwrap_err().to_string();
    assert!(err.contains("no method Lb/Lib;->nothing"), "{err}");
    assert!(engine.call_graph(&query(LIB, "helper(I", Direction::Callers, 1)).is_err());
    // Exact signature that does not exist.
    assert!(engine.call_graph(&query(LIB, "helper()V", Direction::Callers, 1)).is_err());
}

#[test]
fn findrefs_context_marks_the_referencing_instructions() {
    let apk = temp_apk();
    let engine = Engine::new(apk.path()).with_threads(2).with_cache(CacheConfig { memory_bytes: 64 << 20, ..Default::default() });
    let run = |q: &Query, context| {
        let mut rows = Vec::new();
        engine
            .find_refs_opts(q, FindOptions { aggregate: true, context }, &AtomicBool::new(false), &mut |b| rows.extend(b.results))
            .unwrap();
        rows.sort_by_key(|r| r.line());
        rows
    };
    let q = Query::String("secret".into());
    let plain = run(&q, RefContext::None);
    assert_eq!(plain.len(), 1);
    assert!(plain[0].context.is_none() && plain[0].sites.len() == 1 && plain[0].sites[0].pc.is_none());

    let rows = run(&q, RefContext::Lines(1));
    assert_eq!(rows[0].line(), plain[0].line());
    assert_eq!((rows[0].sites[0].pc, rows[0].sites[0].line), (Some(0), Some(7)));
    assert_eq!(
        rows[0].text(),
        "classes.dex | La/Entry;->start | matched=(secret)\n  @ pc 0x0 line 7\n        .line 7\n  >     const-string v0, \"secret\"\n        .line 9"
    );
    let rows = run(&q, RefContext::Method);
    let ctx = rows[0].context.as_deref().unwrap();
    assert!(ctx.contains("    .method public static start()V\n") && ctx.ends_with("    .end method\n"), "{ctx}");

    // Two call sites of helper in two methods; context added after the fact
    // (a page of rows) matches the one computed during the search.
    let q = Query::Method(asc_engine::MemberQuery { class: None, name: Some("helper".into()), exact_name: true });
    let inline = run(&q, RefContext::Lines(0));
    let mut later = run(&q, RefContext::None);
    assert_eq!(later.len(), 2);
    assert!(engine.fill_context(&mut later, RefContext::Lines(0)).unwrap().is_empty());
    assert_eq!(later, inline);
    assert!(inline.iter().all(|r| r.context.as_deref().unwrap().contains("  >     invoke-static {v0}, Lb/Lib;->helper(I)V\n")));
    // Without any cache too.
    let cold = Engine::new(apk.path()).with_threads(1);
    let mut rows = Vec::new();
    cold.find_refs(&q, |b| rows.extend(b.results)).unwrap();
    rows.sort_by_key(|r| r.line());
    cold.fill_context(&mut rows, RefContext::Lines(0)).unwrap();
    assert_eq!(rows, inline);
}
