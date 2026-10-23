//! Virtual dispatch through a method set, and the four composition
//! primitives together on a two-jar program: a call through an interface
//! finds the implementation its body matches, across archives.
//!
//! app.jar: `Lp/I;` declares `leak(String)V`; `Lp/Caller;->call(Lp/I;)V`
//! passes the string "android_id" to `Lp/I;->leak` (an interface call).
//! lib.jar: `Lp/Impl;` implements `Lp/I;`, and its `leak` body loads
//! "android_id".

use asc_engine::{names, CacheConfig, CallQuery, CallRoots, Direction, Engine};
use asc_findrefs::Query;
use asc_fixture::{make_apk, ClassSpec, CodeSpec, DexBuilder, MethodSpec};
use std::sync::atomic::AtomicBool;

const IFACE: &str = "Lp/I;";
const IMPL: &str = "Lp/Impl;";
const CALLER: &str = "Lp/Caller;";
const OBJ: &str = "Ljava/lang/Object;";
const STR: &str = "Ljava/lang/String;";

fn le16(v: u32) -> [u8; 2] {
    (v as u16).to_le_bytes()
}

/// app.jar: the interface and the caller that invokes it.
fn app_dex() -> Vec<u8> {
    let mut d = DexBuilder::new();
    d.string("android_id").type_(OBJ).type_(STR).type_(IFACE);
    d.method(IFACE, "leak", "V", &[STR]).method(CALLER, "call", "V", &[IFACE]);
    let mut ids = d.resolve();
    let leak = ids.method(IFACE, "leak", "V", &[STR]);
    // call(Lp/I;)V: registers=2, ins=1 -> v1 = p0 (the I), v0 local.
    let mut call = vec![0x1a, 0x00]; // const-string v0, "android_id"
    call.extend_from_slice(&le16(ids.string("android_id")));
    call.extend_from_slice(&[0x72, 0x20]); // invoke-interface {v1, v0}, leak
    call.extend_from_slice(&le16(leak));
    call.extend_from_slice(&[0x01, 0x00]); // regs C=v1 (receiver), D=v0 (arg0)
    call.extend_from_slice(&[0x0e, 0x00]); // return-void
    let call_code = CodeSpec { registers: 2, ins: 1, outs: 2, insns: call, ..Default::default() };
    ids.add_class(ClassSpec {
        descriptor: IFACE.into(),
        access: 0x1 | 0x200 | 0x400,
        superclass: Some(OBJ.into()),
        virtual_methods: vec![MethodSpec { idx: leak, access: 0x1 | 0x400, code: None }],
        ..Default::default()
    });
    let call_idx = ids.method(CALLER, "call", "V", &[IFACE]);
    ids.add_class(ClassSpec {
        descriptor: CALLER.into(),
        access: 0x1,
        superclass: Some(OBJ.into()),
        direct_methods: vec![MethodSpec { idx: call_idx, access: 0x1 | 0x8, code: Some(call_code) }],
        ..Default::default()
    });
    ids.finish()
}

/// lib.jar: the implementation whose body loads "android_id".
fn lib_dex() -> Vec<u8> {
    let mut d = DexBuilder::new();
    d.string("android_id").type_(OBJ).type_(STR).type_(IFACE);
    d.method(IMPL, "leak", "V", &[STR]);
    let mut ids = d.resolve();
    let leak = ids.method(IMPL, "leak", "V", &[STR]);
    // leak(String)V: registers=3, ins=2 -> v1=this, v2=param, v0 local.
    let mut body = vec![0x1a, 0x00]; // const-string v0, "android_id"
    body.extend_from_slice(&le16(ids.string("android_id")));
    body.extend_from_slice(&[0x0e, 0x00]); // return-void
    let code = CodeSpec { registers: 3, ins: 2, insns: body, ..Default::default() };
    ids.add_class(ClassSpec {
        descriptor: IMPL.into(),
        access: 0x1,
        superclass: Some(OBJ.into()),
        interfaces: vec![IFACE.into()],
        virtual_methods: vec![MethodSpec { idx: leak, access: 0x1, code: Some(code) }],
        ..Default::default()
    });
    ids.finish()
}

const MANY: &str = "Lp/Many;";
const MANY_CALLER: &str = "Lp/ManyCaller;";
/// An empty interface every `Lp/Mi;` also implements: no call can name
/// `run` on it.
const TAG: &str = "Lp/Tag;";
/// One more implementer of `Lp/Many;->run()V` than the default fan-out.
const IMPLEMENTERS: usize = asc_engine::DEFAULT_FAN_OUT + 1;

/// many.jar: `Lp/Many;` declares `run()V` and has [`IMPLEMENTERS`]
/// implementations `Lp/M0;`, `Lp/M1;`, ... (each also implementing [`TAG`]); only `Lp/M0;->run` loads
/// "serial". `Lp/ManyCaller;->go(Lp/Many;)V` calls `Lp/Many;->run`.
fn many_dex() -> Vec<u8> {
    let impls: Vec<String> = (0..IMPLEMENTERS).map(|i| format!("Lp/M{i};")).collect();
    let mut d = DexBuilder::new();
    d.string("serial").type_(OBJ).type_(MANY).type_(TAG);
    d.method(MANY, "run", "V", &[]).method(MANY_CALLER, "go", "V", &[MANY]);
    for c in &impls {
        d.type_(c).method(c, "run", "V", &[]);
    }
    let mut ids = d.resolve();
    let run = ids.method(MANY, "run", "V", &[]);
    ids.add_class(ClassSpec { descriptor: TAG.into(), access: 0x1 | 0x200 | 0x400, superclass: Some(OBJ.into()), ..Default::default() });
    ids.add_class(ClassSpec {
        descriptor: MANY.into(),
        access: 0x1 | 0x200 | 0x400,
        superclass: Some(OBJ.into()),
        virtual_methods: vec![MethodSpec { idx: run, access: 0x1 | 0x400, code: None }],
        ..Default::default()
    });
    for (i, c) in impls.iter().enumerate() {
        let mut body = Vec::new();
        if i == 0 {
            body.extend_from_slice(&[0x1a, 0x00]); // const-string v0, "serial"
            body.extend_from_slice(&le16(ids.string("serial")));
        }
        body.extend_from_slice(&[0x0e, 0x00]); // return-void
        let code = CodeSpec { registers: 2, ins: 1, insns: body, ..Default::default() };
        let idx = ids.method(c, "run", "V", &[]);
        ids.add_class(ClassSpec {
            descriptor: c.clone(),
            access: 0x1,
            superclass: Some(OBJ.into()),
            interfaces: vec![MANY.into(), TAG.into()],
            virtual_methods: vec![MethodSpec { idx, access: 0x1, code: Some(code) }],
            ..Default::default()
        });
    }
    // go(Lp/Many;)V: registers=1, ins=1 -> v0 = p0.
    let mut go = vec![0x72, 0x10]; // invoke-interface {v0}, Lp/Many;->run
    go.extend_from_slice(&le16(run));
    go.extend_from_slice(&[0x00, 0x00, 0x0e, 0x00]); // regs C=v0; return-void
    let go_idx = ids.method(MANY_CALLER, "go", "V", &[MANY]);
    ids.add_class(ClassSpec {
        descriptor: MANY_CALLER.into(),
        access: 0x1,
        superclass: Some(OBJ.into()),
        direct_methods: vec![MethodSpec {
            idx: go_idx,
            access: 0x1 | 0x8,
            code: Some(CodeSpec { registers: 1, ins: 1, outs: 1, insns: go, ..Default::default() }),
        }],
        ..Default::default()
    });
    ids.finish()
}

/// A directory of the jars, read as one program.
fn program() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("app.jar"), make_apk(&[("classes.dex", &app_dex())], true)).unwrap();
    std::fs::write(dir.path().join("lib.jar"), make_apk(&[("classes.dex", &lib_dex())], true)).unwrap();
    std::fs::write(dir.path().join("many.jar"), make_apk(&[("classes.dex", &many_dex())], true)).unwrap();
    dir
}

fn rows(engine: &Engine, q: &Query) -> Vec<String> {
    rows_and_notes(engine, q).0
}

fn rows_and_notes(engine: &Engine, q: &Query) -> (Vec<String>, Vec<String>) {
    let mut out = Vec::new();
    let summary = engine.find_refs(q, |b| out.extend(b.results.iter().map(|r| r.line()))).unwrap();
    out.sort();
    (out, summary.notes)
}

#[test]
fn dispatch_nesting_constraints_and_defs_compose_across_jars() {
    let dir = program();
    let cache_dir = tempfile::tempdir().unwrap();
    let cached = || {
        let disk = asc_engine::asc_cache::DiskCache::open(cache_dir.path().join("c")).with_capacity(1 << 30).with_min_dex_bytes(0);
        Engine::new(dir.path()).with_threads(2).with_cache(CacheConfig { memory_bytes: 64 << 20, disk: Some(disk), ..Default::default() })
    };
    for engine in [Engine::new(dir.path()).with_threads(2), cached()] {
        // Nested, default dispatch: the interface call in app.jar resolves to
        // the implementation whose body loads "android_id", in lib.jar.
        let r = rows(&engine, &names::parse_rule("method:{literal:android_id}").unwrap());
        assert_eq!(r, ["app.jar/classes.dex | Lp/Caller;->call(Lp/I;)V | Lp/I;->leak(Ljava/lang/String;)V (dispatch Lp/Impl;)"]);

        // `=`: only the methods themselves are named, and nobody calls
        // Lp/Impl;->leak directly, so nothing matches.
        assert!(rows(&engine, &names::parse_rule("method:={literal:android_id}").unwrap()).is_empty());

        // A call-site constraint reads the string passed to the dispatched
        // interface call, and the dispatch label follows it.
        let r = rows(&engine, &names::parse_rule(r#"method:{literal:android_id}[arg0="android_id"]"#).unwrap());
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(r[0].contains(r#"[arg0="android_id"]"#) && r[0].contains("(dispatch Lp/Impl;)"), "{}", r[0]);
        assert!(rows(&engine, &names::parse_rule(r#"method:{literal:android_id}[arg0="other"]"#).unwrap()).is_empty());

        // Definition predicate: override: names both the interface method and
        // the implementation, across jars, with no call site.
        let r = rows(&engine, &names::parse_rule("override:p.I->leak").unwrap());
        assert_eq!(
            r,
            [
                "app.jar/classes.dex | Lp/I;->leak(Ljava/lang/String;)V | override leak",
                "lib.jar/classes.dex | Lp/Impl;->leak(Ljava/lang/String;)V | override leak",
            ]
        );

        // Callgraph --to a nested rule, following dispatch, crosses to the
        // caller in the other jar; --unless on the caller prunes it.
        let to = |unless: Vec<Query>| CallQuery {
            depth: 3,
            virtual_calls: true,
            unless,
            ..CallQuery::new(CallRoots::Matching(names::parse_rule("method:{literal:android_id}").unwrap()), Direction::Callers)
        };
        let t = engine.call_graph(&to(Vec::new())).unwrap();
        assert!(t.lines().iter().any(|l| l.contains("Lp/Caller;->call")), "{:?}", t.lines());
        let t = engine.call_graph(&to(vec![names::parse_rule("method:Lp/I;->leak").unwrap()])).unwrap();
        assert!(!t.lines().iter().any(|l| l.contains("Lp/Caller;->call")), "pruned: {:?}", t.lines());
        // An interface with a couple of implementers is followed: no note.
        assert!(rows_and_notes(&engine, &names::parse_rule("method:{literal:android_id}").unwrap()).1.is_empty());
    }
    let _ = AtomicBool::new(false);
}

#[test]
fn a_supertype_with_many_implementers_is_noted_not_followed() {
    let dir = program();
    let cache_dir = tempfile::tempdir().unwrap();
    let cached = || {
        let disk = asc_engine::asc_cache::DiskCache::open(cache_dir.path().join("c")).with_capacity(1 << 30).with_min_dex_bytes(0);
        Engine::new(dir.path()).with_threads(2).with_cache(CacheConfig { memory_bytes: 64 << 20, disk: Some(disk), ..Default::default() })
    };
    let want_note = format!(
        "dispatch not followed via Lp/Many;->run()V ({} implementers): name it explicitly, or write method:*{{...}}, to include",
        IMPLEMENTERS + 1
    );
    let call_row = "many.jar/classes.dex | Lp/ManyCaller;->go(Lp/Many;)V | Lp/Many;->run()V";
    for engine in [Engine::new(dir.path()).with_threads(2), cached()] {
        // Lp/Many;->run is declared by Lp/Many; and every implementer: over the
        // fan-out, so its call is left out and noted. Lp/Tag; declares no
        // run(), so no call can name it there: neither followed nor noted.
        let (r, notes) = rows_and_notes(&engine, &names::parse_rule("method:{literal:serial}").unwrap());
        assert!(r.is_empty(), "{r:?}");
        assert_eq!(notes, std::slice::from_ref(&want_note));
        // `*` follows it anyway, labelled.
        let (r, notes) = rows_and_notes(&engine, &names::parse_rule("method:*{literal:serial}").unwrap());
        assert_eq!(r, [format!("{call_row} (dispatch Lp/M0;)")]);
        assert!(notes.is_empty(), "{notes:?}");
        // Naming the supertype method finds the call too.
        assert_eq!(rows(&engine, &names::parse_rule("method:Lp/Many;->run").unwrap()), [call_row]);
        // A rule set and a callgraph carry the note as well.
        let mut n = 0;
        let summary = engine
            .find_refs_rules(
                &[names::parse_rule("method:{literal:serial}").unwrap()],
                Default::default(),
                &AtomicBool::new(false),
                &mut |_, b| n += b.results.len(),
            )
            .unwrap();
        assert_eq!((n, summary.notes), (0, vec![want_note.clone()]));
        let rule = names::parse_rule("method:{method:{literal:serial}}").unwrap();
        let t = engine.call_graph(&CallQuery { depth: 1, ..CallQuery::new(CallRoots::Matching(rule), Direction::Callers) });
        // Nothing calls run() through Lp/M0; directly: no root left, an error.
        assert!(t.is_err());
        engine.flush_cache_writes();
    }
    // An L3 replay keeps the note.
    let engine = cached();
    let (r, notes) = rows_and_notes(&engine, &names::parse_rule("method:{literal:serial}").unwrap());
    assert!(r.is_empty() && notes == [want_note], "{r:?} {notes:?}");
    assert_eq!(engine.cache_stats().inflates, 0);
}
