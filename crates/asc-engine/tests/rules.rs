//! Compound queries, rule sets, the class hierarchy and virtual dispatch
//! over a two-DEX APK.

use asc_engine::{names, CacheConfig, CallQuery, Direction, Engine, FindOptions, HierarchyQuery, Lineage};
use asc_findrefs::Query;
use asc_fixture::{make_apk, ClassSpec, CodeSpec, DexBuilder, MethodSpec};
use std::io::Write;
use std::sync::atomic::AtomicBool;

const OBJ: &str = "Ljava/lang/Object;";
const BASE: &str = "La/Base;";
const SUB: &str = "La/Sub;";
const LEAF: &str = "La/Leaf;";
const CALLER: &str = "La/Caller;";
const API: &str = "Lb/Api;";
const IMPL: &str = "Lb/Impl;";

fn le16(v: u32) -> [u8; 2] {
    (v as u16).to_le_bytes()
}

/// `invoke-virtual {v0}` of method `m`.
fn invoke(m: u32) -> Vec<u8> {
    let mut v = vec![0x6e, 0x10];
    v.extend_from_slice(&le16(m));
    v.extend_from_slice(&[0, 0]);
    v
}

fn const_string(s: u32) -> Vec<u8> {
    let mut v = vec![0x1a, 0x00];
    v.extend_from_slice(&le16(s));
    v
}

fn body(parts: &[Vec<u8>]) -> CodeSpec {
    let mut insns: Vec<u8> = parts.concat();
    insns.extend_from_slice(&[0x0e, 0x00]); // return-void
    CodeSpec { registers: 1, ins: 1, outs: 1, insns, ..Default::default() }
}

fn method(idx: u32, access: u32, code: CodeSpec) -> MethodSpec {
    MethodSpec { idx, access, code: Some(code) }
}

fn class(descriptor: &str, superclass: &str, interfaces: &[&str]) -> ClassSpec {
    ClassSpec {
        descriptor: descriptor.into(),
        access: 0x1,
        superclass: Some(superclass.into()),
        interfaces: interfaces.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

/// classes.dex: `Base implements Api` with `run()V`, `Sub extends Base`
/// overriding it, `Leaf extends Sub`; `Caller.go()` loads "token" and calls
/// `Base.run()`, `Caller.only()` only loads "token", `Caller.call()` only
/// calls `Base.run()`.
fn app_dex() -> Vec<u8> {
    let mut d = DexBuilder::new();
    d.string("token").type_(OBJ).type_(API).type_(LEAF);
    for c in [BASE, SUB] {
        d.method(c, "run", "V", &[]);
    }
    for m in ["go", "only", "call"] {
        d.method(CALLER, m, "V", &[]);
    }
    let mut ids = d.resolve();
    let base_run = ids.method(BASE, "run", "V", &[]);
    let token = ids.string("token");
    let mut base = class(BASE, OBJ, &[API]);
    base.virtual_methods = vec![method(base_run, 0x1, body(&[]))];
    let mut sub = class(SUB, BASE, &[]);
    sub.virtual_methods = vec![method(ids.method(SUB, "run", "V", &[]), 0x1, body(&[]))];
    let mut caller = class(CALLER, OBJ, &[]);
    caller.direct_methods = vec![
        method(ids.method(CALLER, "call", "V", &[]), 0x9, body(&[invoke(base_run)])),
        method(ids.method(CALLER, "go", "V", &[]), 0x9, body(&[const_string(token), invoke(base_run)])),
        method(ids.method(CALLER, "only", "V", &[]), 0x9, body(&[const_string(token)])),
    ];
    for c in [base, sub, class(LEAF, SUB, &[]), caller] {
        ids.add_class(c);
    }
    ids.finish()
}

/// classes2.dex: the interface `Api` and `Impl implements Api` with `run()V`.
fn lib_dex() -> Vec<u8> {
    let mut d = DexBuilder::new();
    d.type_(OBJ).method(API, "run", "V", &[]).method(IMPL, "run", "V", &[]);
    let mut ids = d.resolve();
    let mut api = class(API, OBJ, &[]);
    api.access = 0x601; // public interface abstract
    api.virtual_methods = vec![MethodSpec { idx: ids.method(API, "run", "V", &[]), access: 0x401, code: None }];
    let mut imp = class(IMPL, OBJ, &[API]);
    imp.virtual_methods = vec![method(ids.method(IMPL, "run", "V", &[]), 0x1, body(&[]))];
    ids.add_class(api);
    ids.add_class(imp);
    ids.finish()
}

fn temp_apk() -> tempfile::NamedTempFile {
    let bytes = make_apk(&[("classes.dex", &app_dex()), ("classes2.dex", &lib_dex())], true);
    let mut f = tempfile::Builder::new().suffix(".apk").tempfile().unwrap();
    f.write_all(&bytes).unwrap();
    f.flush().unwrap();
    f
}

fn engines(apk: &std::path::Path) -> [Engine; 2] {
    [
        Engine::new(apk).with_threads(2),
        Engine::new(apk).with_threads(2).with_cache(CacheConfig { memory_bytes: 64 << 20, ..Default::default() }),
    ]
}

fn lines(engine: &Engine, q: &Query) -> Vec<String> {
    let mut out = Vec::new();
    engine.find_refs(q, |b| out.extend(b.results.iter().map(|r| r.line()))).unwrap();
    out.sort();
    out
}

fn cond(spec: &str) -> Query {
    names::parse_condition(spec).unwrap()
}

#[test]
fn compound_queries_intersect_per_method() {
    let apk = temp_apk();
    for engine in engines(apk.path()) {
        let both = Query::All { all: vec![cond("string:tok"), cond("method:La/Base;->run")], none: vec![] };
        assert_eq!(lines(&engine, &both), ["classes.dex | La/Caller;->go()V | \"token\", La/Base;->run()V"]);
        // The order of the parts is the order of `matched`.
        let swapped = Query::All { all: vec![cond("method:La/Base;->=run"), cond("literal:token")], none: vec![] };
        assert_eq!(lines(&engine, &swapped), ["classes.dex | La/Caller;->go()V | La/Base;->run()V, \"token\""]);
        let without = Query::All { all: vec![cond("string:token")], none: vec![cond("method:~Base->run")] };
        assert_eq!(lines(&engine, &without), ["classes.dex | La/Caller;->only()V | \"token\""]);
        let nothing = Query::All { all: vec![cond("string:token"), cond("type:Lnowhere;")], none: vec![] };
        assert!(lines(&engine, &nothing).is_empty());
    }
}

#[test]
fn compound_queries_reject_what_cannot_combine() {
    let apk = temp_apk();
    let engine = Engine::new(apk.path());
    for (q, msg) in [
        (Query::All { all: vec![], none: vec![cond("string:x")] }, "at least one"),
        (Query::All { all: vec![cond("extends:a.Base")], none: vec![] }, "cannot be combined"),
        (Query::All { all: vec![Query::All { all: vec![cond("string:x")], none: vec![] }], none: vec![] }, "do not nest"),
    ] {
        let err = engine.find_refs(&q, |_| {}).unwrap_err().to_string();
        assert!(err.contains(msg), "{err}");
    }
    assert!(names::parse_condition("bogus").is_err());
    assert!(names::parse_condition("method:").is_err());
}

#[test]
fn a_rule_set_answers_like_one_query_per_rule() {
    let apk = temp_apk();
    let rules = vec![
        cond("string:token"),
        cond("method:run"),
        cond("type:La/Base;"),
        cond("extends:a.Sub"),
        cond("impl:b.Api"),
        Query::All { all: vec![cond("string:token"), cond("method:La/Base;->run")], none: vec![] },
        cond("string:absent"),
    ];
    for engine in engines(apk.path()) {
        let mut got: Vec<Vec<String>> = vec![Vec::new(); rules.len()];
        let summary = engine
            .find_refs_rules(&rules, FindOptions::default(), &AtomicBool::new(false), &mut |i, b| {
                assert!(b.error.is_none(), "{:?}", b.error);
                got[i].extend(b.results.iter().map(|r| r.line()));
            })
            .unwrap();
        for (i, rule) in rules.iter().enumerate() {
            got[i].sort();
            assert_eq!(got[i], lines(&engine, rule), "rule {i}");
        }
        assert_eq!(got[1].len(), 2, "{:?}", got[1]);
        assert_eq!(got[3], ["classes.dex | La/Leaf; | extends La/Sub;"]);
        assert_eq!(summary.total_results, got.iter().map(Vec::len).sum::<usize>());
    }
}

#[test]
fn a_rule_set_shares_rendered_results_with_single_queries() {
    let apk = temp_apk();
    let cache = tempfile::tempdir().unwrap();
    let engine = || {
        let disk = asc_engine::asc_cache::DiskCache::open(cache.path()).with_capacity(1 << 30).with_min_dex_bytes(0);
        Engine::new(apk.path()).with_threads(2).with_cache(CacheConfig { memory_bytes: 64 << 20, disk: Some(disk), ..Default::default() })
    };
    let (alone, set) = (cond("string:token"), vec![cond("string:token"), cond("method:run")]);
    let e = engine();
    let first = lines(&e, &alone);
    e.flush_cache_writes();
    // The set replays the rule a single query left in L3 and searches the other.
    let e = engine();
    let mut sources: Vec<Vec<&str>> = vec![Vec::new(); set.len()];
    let mut got: Vec<Vec<String>> = vec![Vec::new(); set.len()];
    e.find_refs_rules(&set, FindOptions::default(), &AtomicBool::new(false), &mut |i, b| {
        sources[i].push(b.source);
        got[i].extend(b.results.iter().map(|r| r.line()));
    })
    .unwrap();
    assert!(sources[0].iter().all(|s| *s == "result"), "{sources:?}");
    assert!(sources[1].iter().all(|s| *s != "result"), "{sources:?}");
    got[0].sort();
    assert_eq!(got[0], first);
    e.flush_cache_writes();
    // And a single query replays what the set searched.
    let e = engine();
    let mut replayed = Vec::new();
    e.find_refs(&set[1], |b| {
        assert_eq!(b.source, "result");
        replayed.extend(b.results.iter().map(|r| r.line()));
    })
    .unwrap();
    replayed.sort();
    got[1].sort();
    assert_eq!(replayed, got[1]);
    assert_eq!(replayed.len(), 2, "{replayed:?}");
}

fn hq(class: &str, direction: Lineage, method: Option<&str>) -> HierarchyQuery {
    HierarchyQuery { class: class.into(), direction, depth: 16, max_nodes: 100, method: method.map(String::from) }
}

#[test]
fn hierarchy_walks_subclasses_and_supertypes_across_dex_files() {
    let apk = temp_apk();
    for engine in engines(apk.path()) {
        let t = engine.hierarchy(&hq(API, Lineage::Subclasses, Some("run"))).unwrap();
        assert_eq!(
            t.lines(),
            [
                "0 Lb/Api; classes2.dex [defines run()V]",
                "  1 implementer La/Base; classes.dex [defines run()V]",
                "    2 subclass La/Sub; classes.dex [defines run()V]",
                "      3 subclass La/Leaf; classes.dex",
                "  1 implementer Lb/Impl; classes2.dex [defines run()V]",
            ]
        );
        assert_eq!(
            t.definition_lines(),
            ["override La/Base;->run()V classes.dex", "override La/Sub;->run()V classes.dex", "override Lb/Impl;->run()V classes2.dex"]
        );
        assert_eq!((t.classes, t.truncated), (5, false));
        assert!(t.footer().ends_with("; 3 define run"), "{}", t.footer());

        let t = engine.hierarchy(&hq(LEAF, Lineage::Supers, Some("run()V"))).unwrap();
        assert_eq!(
            t.lines(),
            [
                "0 La/Leaf; classes.dex",
                "  1 extends La/Sub; classes.dex [defines run()V]",
                "    2 extends La/Base; classes.dex [defines run()V]",
                "      3 implements Lb/Api; classes2.dex [defines run()V]",
                // Object's shallowest depth is 3 (Base extends it); under Api it is a leaf.
                "        4 extends Ljava/lang/Object; [not in APK]",
                "      3 extends Ljava/lang/Object; [not in APK]",
            ]
        );
        assert_eq!(t.definition_lines()[0], "inherited La/Sub;->run()V classes.dex");

        let t = engine.hierarchy(&HierarchyQuery { depth: 1, ..hq(BASE, Lineage::Subclasses, None) }).unwrap();
        assert_eq!(t.lines(), ["0 La/Base; classes.dex", "  1 subclass La/Sub; classes.dex"]);
        assert!(t.truncated, "Leaf is one level further down");
        assert!(engine.hierarchy(&hq("La/Missing;", Lineage::Subclasses, None)).is_err());
    }
}

#[test]
fn virtual_dispatch_links_calls_through_supertypes_and_overrides() {
    let apk = temp_apk();
    for engine in engines(apk.path()) {
        let q = |class: &str, method: &str, direction, virtual_calls| CallQuery {
            class: class.into(),
            method: method.into(),
            direction,
            depth: 1,
            max_nodes: 100,
            virtual_calls,
        };
        let t = engine.call_graph(&q(SUB, "run", Direction::Callers, false)).unwrap();
        assert_eq!(t.lines(), ["0 La/Sub;->run()V"]);
        let t = engine.call_graph(&q(SUB, "run", Direction::Callers, true)).unwrap();
        assert_eq!(
            t.lines(),
            ["0 La/Sub;->run()V", "  1 <- La/Caller;->call()V (via La/Base;)", "  1 <- La/Caller;->go()V (via La/Base;)"]
        );
        assert_eq!(t.rows[1].via.as_deref(), Some(BASE));

        let t = engine.call_graph(&q(CALLER, "go", Direction::Callees, true)).unwrap();
        assert_eq!(t.lines(), ["0 La/Caller;->go()V", "  1 -> La/Base;->run()V", "  1 -> La/Sub;->run()V (override of La/Base;)"]);
        // Leaf inherits run without defining it: no override row.
        let t = engine.call_graph(&q(CALLER, "go", Direction::Callees, false)).unwrap();
        assert_eq!(t.lines(), ["0 La/Caller;->go()V", "  1 -> La/Base;->run()V"]);
    }
}
