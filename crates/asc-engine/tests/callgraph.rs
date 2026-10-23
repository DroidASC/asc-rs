//! Call graph walks and findrefs context over a two-DEX APK.

use asc_dex::debug_info::{DebugInfo, DebugOp};
use asc_engine::{names, CacheConfig, CallQuery, CallRoots, Direction, Engine, FindOptions, RefContext};
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
    CallQuery { depth, max_nodes: 100, ..CallQuery::method(class, method, direction) }
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
        "classes.dex | La/Entry;->start()V | \"secret\"\n  @ pc 0x0 line 7\n        .line 7\n  >     const-string v0, \"secret\"\n        .line 9"
    );
    let rows = run(&q, RefContext::Method);
    let ctx = rows[0].context.as_deref().unwrap();
    assert!(ctx.contains("    .method public static start()V\n") && ctx.ends_with("    .end method\n"), "{ctx}");

    // Two call sites of helper in two methods; context added after the fact
    // (a page of rows) matches the one computed during the search.
    let q = Query::Method(asc_engine::MemberQuery { class: None, name: Some("helper".into()), exact_name: true, signature: None });
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

/// `dex | method | matched` of every row, sorted.
fn find_lines(engine: &Engine, q: &Query) -> Vec<String> {
    let mut rows = Vec::new();
    engine.find_refs(q, |b| rows.extend(b.results.iter().map(|r| r.line()))).unwrap();
    rows.sort();
    rows
}

#[test]
fn nested_conditions_and_method_sets_resolve_across_dex_files() {
    let apk = temp_apk();
    let dir = tempfile::tempdir().unwrap();
    let cached = || {
        let disk = asc_engine::asc_cache::DiskCache::open(dir.path().join("cache")).with_capacity(1 << 30).with_min_dex_bytes(0);
        Engine::new(apk.path()).with_threads(2).with_cache(CacheConfig { memory_bytes: 64 << 20, disk: Some(disk), ..Default::default() })
    };
    for engine in [Engine::new(apk.path()).with_threads(2), cached()] {
        // Entry.start (classes.dex) loads "secret"; Lib.sink (classes2.dex) calls it.
        let q = names::parse_rule("method:{literal:secret}").unwrap();
        for _ in 0..2 {
            assert_eq!(find_lines(&engine, &q), ["classes2.dex | Lb/Lib;->sink()V | La/Entry;->start()V"]);
        }
        // Callers of what calls sink (helper): Entry.start and Other.other; then narrowed.
        let q = names::parse_rule("method:{method:Lb/Lib;->sink}").unwrap();
        assert_eq!(
            find_lines(&engine, &q),
            ["classes.dex | La/Entry;->start()V | Lb/Lib;->helper(I)V", "classes.dex | La/Other;->other()V | Lb/Lib;->helper(I)V"]
        );
        let q = names::parse_rule("method:{method:Lb/Lib;->sink} & !string:secret").unwrap();
        assert_eq!(find_lines(&engine, &q), ["classes.dex | La/Other;->other()V | Lb/Lib;->helper(I)V"]);
        // Two levels of nesting, and an inner rule nobody matches.
        let q = names::parse_rule("method:{method:{literal:secret}}").unwrap();
        assert_eq!(find_lines(&engine, &q), ["classes2.dex | Lb/Lib;->helper(I)V | Lb/Lib;->sink()V"]);
        assert!(find_lines(&engine, &names::parse_rule("method:{literal:absent}").unwrap()).is_empty());
        let q = names::parse_rule("method:{extends:Ljava/lang/Object;}").unwrap();
        let e = engine.find_refs(&q, |_| {}).unwrap_err().to_string();
        assert!(e.contains("name classes, not code"), "{e}");

        // A method set from a file: what findrefs printed before.
        std::fs::write(dir.path().join("set.txt"), "classes2.dex | Lb/Lib;->sink()V | x\nLb/Lib;->helper(I)V\n").unwrap();
        let q = asc_engine::condition::parse_rule_in("method:@set.txt", Some(dir.path())).unwrap();
        assert_eq!(
            find_lines(&engine, &q),
            [
                "classes.dex | La/Entry;->start()V | Lb/Lib;->helper(I)V",
                "classes.dex | La/Other;->other()V | Lb/Lib;->helper(I)V",
                "classes2.dex | Lb/Lib;->helper(I)V | Lb/Lib;->sink()V",
            ]
        );
        // Rule sets resolve every nested rule of every rule.
        let rules = [names::parse_rule("method:{literal:secret}").unwrap(), names::parse_rule("string:secret").unwrap()];
        let mut per_rule = [0; 2];
        engine
            .find_refs_rules(&rules, FindOptions::default(), &AtomicBool::new(false), &mut |i, b| per_rule[i] += b.results.len())
            .unwrap();
        assert_eq!(per_rule, [1, 1]);
        engine.flush_cache_writes();
    }
    // A replay from L3 skips the inner rule too.
    let engine = cached();
    let mut sources = Vec::new();
    engine.find_refs(&names::parse_rule("method:{literal:secret}").unwrap(), |b| sources.push(b.source)).unwrap();
    assert!(!sources.is_empty() && sources.iter().all(|s| *s == "result"), "{sources:?}");
    assert_eq!(engine.cache_stats().inflates, 0);
    // L3 keys on the set read from the file, not on its path.
    std::fs::write(dir.path().join("set.txt"), "Lb/Lib;->sink()V\n").unwrap();
    let q = asc_engine::condition::parse_rule_in("method:@set.txt", Some(dir.path())).unwrap();
    assert_eq!(find_lines(&cached(), &q), ["classes2.dex | Lb/Lib;->helper(I)V | Lb/Lib;->sink()V"]);
}

#[test]
fn conditions_pick_roots_paths_and_pruned_methods() {
    let apk = temp_apk();
    let engine = Engine::new(apk.path()).with_threads(2);
    let rule = |s: &str| names::parse_rule(s).unwrap();
    let to = |s: &str| CallQuery { depth: 3, ..CallQuery::new(CallRoots::Matching(rule(s)), Direction::Callers) };
    // Every method calling Ext.call (just helper), and its callers.
    let t = engine.call_graph(&to("method:Lext/Api;->call")).unwrap();
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
    // Only the paths from a method loading "secret" (Entry.start), which ends them.
    let t = engine.call_graph(&CallQuery { from: Some(rule("literal:secret")), ..to("method:Lext/Api;->call") }).unwrap();
    assert_eq!(t.lines(), ["0 Lb/Lib;->helper(I)V", "  1 <- La/Entry;->start()V [from]"]);
    assert_eq!((t.reached, t.methods), (Some(1), 2));
    assert!(t.footer().contains("1 from methods reached"), "{}", t.footer());
    // From methods out of reach: nothing left.
    let t = engine.call_graph(&CallQuery { from: Some(rule("method:Lext/Api;->absent")), ..to("method:Lext/Api;->call") });
    assert!(t.unwrap().rows.is_empty());
    // Unless: Entry.start is left out, and sink with it (only reached through it).
    let t = engine.call_graph(&CallQuery { unless: vec![rule("literal:secret")], ..to("method:Lext/Api;->call") }).unwrap();
    assert_eq!(t.lines(), ["0 Lb/Lib;->helper(I)V", "  1 <- La/Other;->other()V"]);
    assert_eq!(t.pruned, 1);
    assert!(t.footer().contains("1 methods left out by unless"), "{}", t.footer());
    // A root matching unless is left out too.
    let t = engine.call_graph(&CallQuery { unless: vec![rule("method:Lext/Api;->call")], ..to("method:Lext/Api;->call") }).unwrap();
    assert!(t.rows.is_empty() && t.pruned == 1);
    // Callees of every method matching a rule.
    let t = engine.call_graph(&CallQuery { depth: 1, ..CallQuery::new(CallRoots::Matching(rule("literal:secret")), Direction::Callees) });
    assert_eq!(t.unwrap().lines(), ["0 La/Entry;->start()V", "  1 -> Lb/Lib;->helper(I)V"]);
    for (q, want) in [
        (CallQuery { from: Some(rule("literal:secret")), ..CallQuery::method(LIB, "helper", Direction::Callees) }, "callers walk"),
        (to("literal:absent"), "no method's code matches"),
        (to("extends:Ljava/lang/Object;"), "name classes, not code"),
    ] {
        let e = engine.call_graph(&q).unwrap_err().to_string();
        assert!(e.contains(want), "{e}");
    }
}
