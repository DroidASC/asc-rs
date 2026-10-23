//! Call-site constraints (`method:X[argN=...]`, `[ret=...]`) over real code.

use asc_engine::{names, CacheConfig, CallQuery, CallRoots, Direction, Engine};
use asc_fixture::{make_apk, ClassSpec, CodeSpec, DexBuilder, MethodSpec};
use std::io::Write;

const CALLER: &str = "La/Caller;";
const SECURE: &str = "Lsys/Secure;";
const LOG: &str = "Lsys/Log;";
const BUILD: &str = "Lsys/Build;";
const RES: &str = "Lsys/Res;";
const STR: &str = "Ljava/lang/String;";

fn u16le(v: u32) -> [u8; 2] {
    u16::try_from(v).unwrap().to_le_bytes()
}

/// A 21c instruction (`const-string`, `const-class`, `new-instance`, `sget-object`).
fn op21c(op: u8, a: u8, idx: u32) -> Vec<u8> {
    let mut v = vec![op, a];
    v.extend_from_slice(&u16le(idx));
    v
}

/// `invoke-{kind} {regs}` (35c) of method `m`.
fn invoke(op: u8, m: u32, regs: &[u8]) -> Vec<u8> {
    let r = |i: usize| regs.get(i).copied().unwrap_or(0);
    let count = u8::try_from(regs.len()).unwrap();
    let mut v = vec![op, (count << 4) | r(4)];
    v.extend_from_slice(&u16le(m));
    v.extend_from_slice(&[(r(1) << 4) | r(0), (r(3) << 4) | r(2)]);
    v
}

const STATIC: u8 = 0x71;
const VIRTUAL: u8 = 0x6e;
const RETURN_VOID: [u8; 2] = [0x0e, 0x00];

fn method(idx: u32, registers: u16, ins: u16, parts: &[Vec<u8>]) -> MethodSpec {
    let insns = [parts.concat(), RETURN_VOID.to_vec()].concat();
    MethodSpec { idx, access: 0x1 | 0x8, code: Some(CodeSpec { registers, ins, outs: 4, insns, ..Default::default() }) }
}

/// One class of callers, each calling the sys API with different values.
fn dex() -> Vec<u8> {
    let mut d = DexBuilder::new();
    d.string("android_id").string("other").string("k").type_("Ljava/lang/Object;");
    d.field(BUILD, "SERIAL", STR);
    d.method(SECURE, "getString", STR, &[RES, STR])
        .method(SECURE, "putLong", "V", &[RES, "J", STR])
        .method(SECURE, "query", "V", &[STR])
        .method(LOG, "d", "V", &[STR])
        .method(LOG, "i", "V", &["I"])
        .method(LOG, "c", "V", &["Ljava/lang/Class;"]);
    let callers =
        [("direct", vec![]), ("param", vec![STR]), ("branchy", vec!["I"]), ("unknown", vec![]), ("wide", vec![]), ("misc", vec![])];
    for (name, params) in &callers {
        d.method(CALLER, name, "V", params);
    }
    let mut ids = d.resolve();
    let get = ids.method(SECURE, "getString", STR, &[RES, STR]);
    let put = ids.method(SECURE, "putLong", "V", &[RES, "J", STR]);
    let query = ids.method(SECURE, "query", "V", &[STR]);
    let (log_d, log_i, log_c) =
        (ids.method(LOG, "d", "V", &[STR]), ids.method(LOG, "i", "V", &["I"]), ids.method(LOG, "c", "V", &["Ljava/lang/Class;"]));
    let s = |v: &str| ids.string(v);
    let caller = |name: &str, params: &[&str]| ids.method(CALLER, name, "V", params);
    let methods = vec![
        // const/4 v1, 0; const-string v0, "android_id"; getString(v1, v0);
        // move-result-object v0; Log.d(v0)
        method(
            caller("direct", &[]),
            2,
            0,
            &[
                vec![0x12, 0x01],
                op21c(0x1a, 0, s("android_id")),
                invoke(STATIC, get, &[1, 0]),
                vec![0x0c, 0x00],
                invoke(STATIC, log_d, &[0]),
            ],
        ),
        // getString(null, p0), result dropped
        method(caller("param", &[STR]), 3, 1, &[vec![0x12, 0x01], invoke(STATIC, get, &[1, 2])]),
        // v0 = "other"; if (p0 != 0) v0 = "android_id"; getString(null, v0)
        method(
            caller("branchy", &["I"]),
            3,
            1,
            &[
                vec![0x12, 0x01],
                op21c(0x1a, 0, s("other")),
                vec![0x38, 0x02, 0x04, 0x00], // if-eqz v2, +4 (past the next const-string)
                op21c(0x1a, 0, s("android_id")),
                invoke(STATIC, get, &[1, 0]),
            ],
        ),
        // v0 = v0[v1] (computed): getString(null, v0)
        method(caller("unknown", &[]), 2, 0, &[vec![0x12, 0x01], vec![0x46, 0x00, 0x00, 0x01], invoke(STATIC, get, &[1, 0])]),
        // putLong(null, 42L, "k"): the wide arg1 takes v1 and v2
        method(
            caller("wide", &[]),
            4,
            0,
            &[vec![0x12, 0x00], vec![0x16, 0x01, 42, 0], op21c(0x1a, 3, s("k")), invoke(STATIC, put, &[0, 1, 2, 3])],
        ),
        // new Secure().query(Build.SERIAL); Log.i(1000); Log.c(Secure.class)
        method(
            caller("misc", &[]),
            2,
            0,
            &[
                op21c(0x22, 0, u32::from(ids.type_(SECURE))),
                op21c(0x62, 1, ids.field(BUILD, "SERIAL", STR)),
                invoke(VIRTUAL, query, &[0, 1]),
                vec![0x13, 0x00, 0xe8, 0x03], // const/16 v0, 1000
                invoke(STATIC, log_i, &[0]),
                op21c(0x1c, 0, u32::from(ids.type_(SECURE))),
                invoke(STATIC, log_c, &[0]),
            ],
        ),
    ];
    ids.add_class(ClassSpec {
        descriptor: CALLER.into(),
        access: 0x1,
        superclass: Some("Ljava/lang/Object;".into()),
        direct_methods: methods,
        ..Default::default()
    });
    ids.finish()
}

fn temp_apk() -> tempfile::NamedTempFile {
    let mut f = tempfile::Builder::new().suffix(".apk").tempfile().unwrap();
    f.write_all(&make_apk(&[("classes.dex", &dex())], true)).unwrap();
    f.flush().unwrap();
    f
}

/// `caller name | matched` of every row of `rule`, sorted.
fn rows(engine: &Engine, rule: &str) -> Vec<String> {
    let q = names::parse_rule(rule).unwrap();
    let mut out = Vec::new();
    engine
        .find_refs(&q, |b| {
            assert!(b.error.is_none(), "{:?}", b.error);
            out.extend(b.results.iter().map(|r| {
                let name = r.method.rsplit("->").next().unwrap().to_string();
                let matched: Vec<String> =
                    r.matched.iter().map(|m| m.as_str().split_once(' ').map_or("", |(_, n)| n).to_string()).collect();
                format!("{name} {}", matched.join(","))
            }))
        })
        .unwrap();
    out.sort();
    out
}

#[test]
fn argument_values_keep_display_and_mark_sites() {
    let apk = temp_apk();
    let cached = CacheConfig { memory_bytes: 64 << 20, ..Default::default() };
    for engine in [Engine::new(apk.path()).with_threads(2), Engine::new(apk.path()).with_threads(2).with_cache(cached)] {
        let get = "method:sys.Secure->getString";
        // `*` keeps every call and shows the candidates.
        assert_eq!(
            rows(&engine, &format!("{get}[arg1=*]")),
            ["branchy [arg1=\"android_id\"|\"other\"]", "direct [arg1=\"android_id\"]", "param [arg1=param0]", "unknown [arg1=?]",]
        );
        // `=` keeps what may match and what cannot be decided (`?`); `==` only the former.
        assert_eq!(
            rows(&engine, &format!("{get}[arg1=\"android_id\"]")),
            ["branchy [arg1=\"android_id\"|\"other\"]", "direct [arg1=\"android_id\"]", "unknown ?[arg1=?]"]
        );
        assert_eq!(
            rows(&engine, &format!("{get}[arg1==\"android_id\"]")),
            ["branchy [arg1=\"android_id\"|\"other\"]", "direct [arg1=\"android_id\"]"]
        );
        assert_eq!(rows(&engine, &format!("{get}[arg1==~^and.*_id$]")), rows(&engine, &format!("{get}[arg1==\"android_id\"]")));
        assert_eq!(rows(&engine, &format!("{get}[arg1==param]")), ["param [arg1=param0]"]);
        assert_eq!(rows(&engine, &format!("{get}[arg1==param0, arg0==null]")), ["param [arg1=param0, arg0=0]"]);
        assert!(rows(&engine, &format!("{get}[arg1==param2]")).is_empty());
        // The result: read in `direct` (logged), dropped in the others.
        assert_eq!(rows(&engine, &format!("{get}[ret==used]")), ["direct [ret=used]"]);
        assert_eq!(
            rows(&engine, &format!("{get}[ret=unused][arg1=\"other\"]")),
            ["branchy [ret=unused, arg1=\"android_id\"|\"other\"]", "unknown ?[ret=unused, arg1=?]"]
        );
        // Origins: a call's result, a field read, a new instance, a class, numbers.
        assert_eq!(rows(&engine, "method:sys.Log->d[arg0==ret:sys.Secure->getString]"), ["direct [arg0=ret:Lsys/Secure;->getString]"]);
        assert_eq!(rows(&engine, "method:sys.Secure->query[arg0==field:sys.Build->SERIAL]"), ["misc [arg0=field:Lsys/Build;->SERIAL]"]);
        assert_eq!(rows(&engine, "method:sys.Secure->query[this==new:sys.Secure]"), ["misc [this=new:Lsys/Secure;]"]);
        assert_eq!(rows(&engine, "method:sys.Log->c[arg0==class:sys.Secure]"), ["misc [arg0=class:Lsys/Secure;]"]);
        assert_eq!(rows(&engine, "method:sys.Log->i[arg0==0x3e8]"), ["misc [arg0=1000]"]);
        assert!(rows(&engine, "method:sys.Log->i[arg0==true]").is_empty());
        // A wide argument takes two registers: arg2 is the string after the long.
        assert_eq!(rows(&engine, "method:sys.Secure->putLong[arg1==42, arg2==\"k\"]"), ["wide [arg1=42, arg2=\"k\"]"]);
        // A static call has no receiver; a missing argument matches nothing.
        assert!(rows(&engine, &format!("{get}[this=*]")).is_empty());
        assert!(rows(&engine, &format!("{get}[arg7=*]")).is_empty());
    }
}

#[test]
fn constraints_compose_with_rules_nesting_and_call_graphs() {
    let apk = temp_apk();
    let engine = Engine::new(apk.path()).with_threads(2);
    // Inside compounds, `!` parts and nested bodies.
    assert_eq!(
        rows(&engine, "method:sys.Secure->getString[arg1==\"android_id\"] & !method:sys.Log->d"),
        ["branchy [arg1=\"android_id\"|\"other\"]"]
    );
    let q = names::parse_rule("method:{method:sys.Secure->getString[arg1==param]}").unwrap();
    assert!(matches!(q, asc_findrefs::Query::Virtual { target, .. } if matches!(*target, asc_findrefs::Query::Nested(_))));
    // Callgraph roots by a constrained call.
    let rule = names::parse_rule("method:sys.Secure->getString[arg1==\"android_id\"]").unwrap();
    let t = engine.call_graph(&CallQuery { depth: 1, ..CallQuery::new(CallRoots::Matching(rule), Direction::Callers) }).unwrap();
    let mut roots: Vec<String> = t.lines().into_iter().filter(|l| l.starts_with("0 ")).collect();
    roots.sort();
    assert_eq!(roots, ["0 La/Caller;->branchy(I)V", "0 La/Caller;->direct()V"]);
    // Rule sets keep each rule's constraints apart.
    let rules = [names::parse_rule("method:sys.Log->i[arg0==1000]").unwrap(), names::parse_rule("method:sys.Log->i[arg0==1]").unwrap()];
    let mut per_rule = [0; 2];
    engine
        .find_refs_rules(&rules, asc_engine::FindOptions::default(), &std::sync::atomic::AtomicBool::new(false), &mut |i, b| {
            per_rule[i] += b.results.len()
        })
        .unwrap();
    assert_eq!(per_rule, [1, 0]);
}

#[test]
fn result_cache_keys_on_the_constraints() {
    let apk = temp_apk();
    let dir = tempfile::tempdir().unwrap();
    let cached = || {
        let disk = asc_engine::asc_cache::DiskCache::open(dir.path().join("cache")).with_capacity(1 << 30).with_min_dex_bytes(0);
        Engine::new(apk.path()).with_threads(2).with_cache(CacheConfig { memory_bytes: 64 << 20, disk: Some(disk), ..Default::default() })
    };
    let (hit, miss) = ("method:sys.Log->i[arg0==1000]", "method:sys.Log->i[arg0==1]");
    let engine = cached();
    assert_eq!(rows(&engine, hit).len(), 1);
    assert!(rows(&engine, miss).is_empty());
    engine.flush_cache_writes();
    // Replayed from L3, each under its own key.
    let engine = cached();
    for (rule, want) in [(hit, 1), (miss, 0)] {
        let mut sources = Vec::new();
        let mut n = 0;
        engine
            .find_refs(&names::parse_rule(rule).unwrap(), |b| {
                sources.push(b.source);
                n += b.results.len();
            })
            .unwrap();
        assert_eq!(n, want, "{rule}");
        assert!(sources.iter().all(|s| *s == "result"), "{rule}: {sources:?}");
    }
}
