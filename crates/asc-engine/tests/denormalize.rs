//! Names written as decompiled Java / Kotlin source spells them, looked up
//! as the DEX names they stand for by `getclass`, `findrefs`, `callgraph`
//! and `hierarchy`:
//! - nested classes with dots (`Outer.Inner` → `Outer$Inner`)
//! - anonymous classes (`Anonymous1` → `$1`)
//! - reserved-word / digit escapes (`Cdo`, `Cif`, `C_`, `C1a` → `do`, `if`, `_`, `1a`)
//! - Kotlin backticks and hex escapes (`` `in` ``, `_dex_61_2D_62_` → `in`, `a-b`)
//! - collision suffixes (`a$2`, `m$2` → `a`, `m`)
//! - constructors by class name, and inner classes by their
//!   `dalvik.annotation.InnerClass` name (`Outer.RealInner` → `Outer$a`)
//!
//! A name the DEX has as written always wins: the readings are a fallback.

use asc_dex::encoded::{AnnotationItem, EncodedAnnotation, EncodedValue};
use asc_engine::{CallQuery, Direction, Engine, EngineError, HierarchyQuery, Lineage, names};
use asc_findrefs::Query;
use asc_fixture::{ClassSpec, CodeSpec, DexBuilder, MethodSpec, make_apk};
use std::io::Write;

fn temp_apk_from_dex(dex: &[u8]) -> tempfile::NamedTempFile {
    let bytes = make_apk(&[("classes.dex", dex)], true);
    let mut f = tempfile::Builder::new().suffix(".apk").tempfile().unwrap();
    f.write_all(&bytes).unwrap();
    f.flush().unwrap();
    f
}

fn le16(v: u32) -> [u8; 2] {
    (v as u16).to_le_bytes()
}

/// A DEX with a class for each kind of source spelling.
fn make_normalized_dex() -> Vec<u8> {
    const OBJ: &str = "Ljava/lang/Object;";
    const STR: &str = "Ljava/lang/String;";
    const CB: &str = "Lcom/app/Callback;";
    const OUTER: &str = "Lcom/app/Outer;";
    const INNER: &str = "Lcom/app/Outer$Inner;";
    const DEEP: &str = "Lcom/app/Outer$Inner$Deep;";
    const ANON: &str = "Lcom/app/Outer$1;";
    const OBF_INNER: &str = "Lcom/app/Outer$a;";
    const KW_CLS: &str = "Lcom/Cpkg/do/if;";
    const EXT_SW: &str = "Lcom/other/switch;";
    const KT_CLS: &str = "Lcom/kt/in/When;";
    const COLL: &str = "Lcom/app/Collision;";
    const ANN_INNER: &str = "Ldalvik/annotation/InnerClass;";

    let mut d = DexBuilder::new();
    d.type_(OBJ)
        .type_(STR)
        .type_(CB)
        .type_(OUTER)
        .type_(INNER)
        .type_(DEEP)
        .type_(ANON)
        .type_(OBF_INNER)
        .type_(KW_CLS)
        .type_(EXT_SW)
        .type_(KT_CLS)
        .type_(COLL)
        .type_(ANN_INNER)
        .string("name")
        .string("accessFlags")
        .string("RealInner")
        .string("When.kt")
        .field(KW_CLS, "for", "I")
        .field(KW_CLS, "_", "I")
        .field(COLL, "a", "I")
        .field(COLL, "a", STR)
        .method(OBJ, "<init>", "V", &[])
        .method(CB, "onEvent", "V", &["I"])
        .method(OUTER, "<init>", "V", &["I"])
        .method(OUTER, "entry", "V", &[INNER])
        .method(INNER, "innerWork", "I", &[])
        .method(DEEP, "deepWork", "I", &[])
        .method(ANON, "<init>", "V", &[])
        .method(ANON, "onEvent", "V", &["I"])
        .method(OBF_INNER, "secret", "I", &[])
        .method(KW_CLS, "while", "I", &["I"])
        .method(KW_CLS, "1a", "V", &[])
        .method(EXT_SW, "case", "I", &[])
        .method(KT_CLS, "fun", "I", &[])
        .method(KT_CLS, "a-b", "I", &[])
        .method(COLL, "m", OBJ, &["I"])
        .method(COLL, "m", STR, &["I"])
        .method(COLL, "caller", "V", &[]);

    let mut ids = d.resolve();

    let m_obj_init = ids.method(OBJ, "<init>", "V", &[]);
    let m_inner_work = ids.method(INNER, "innerWork", "I", &[]);
    let m_ext_case = ids.method(EXT_SW, "case", "I", &[]);
    let f_kw_for = ids.field(KW_CLS, "for", "I");
    let f_kw_under = ids.field(KW_CLS, "_", "I");
    let f_coll_a_int = ids.field(COLL, "a", "I");
    let f_coll_a_str = ids.field(COLL, "a", STR);
    let ret_const_1 = CodeSpec { registers: 1, insns: vec![0x12, 0x10, 0x0f, 0x00], ..Default::default() };

    ids.add_class(ClassSpec {
        descriptor: CB.into(),
        access: 0x0601, // public abstract interface
        superclass: Some(OBJ.into()),
        virtual_methods: vec![MethodSpec { idx: ids.method(CB, "onEvent", "V", &["I"]), access: 0x0401, code: None }],
        ..Default::default()
    });

    // Outer: `<init>(I)V`, and `entry(LInner;)V` calling `Inner.innerWork()`.
    let mut entry_insns = vec![0x6e, 0x10]; // invoke-virtual {v1}, Inner->innerWork()I
    entry_insns.extend_from_slice(&le16(m_inner_work));
    entry_insns.extend_from_slice(&[0x01, 0x00, 0x0e, 0x00]); // return-void
    let mut init_insns = vec![0x70, 0x10]; // invoke-direct {v0}, Object-><init>()V
    init_insns.extend_from_slice(&le16(m_obj_init));
    init_insns.extend_from_slice(&[0x00, 0x00, 0x0e, 0x00]);
    ids.add_class(ClassSpec {
        descriptor: OUTER.into(),
        access: 0x1,
        superclass: Some(OBJ.into()),
        direct_methods: vec![MethodSpec {
            idx: ids.method(OUTER, "<init>", "V", &["I"]),
            access: 0x10001, // public constructor
            code: Some(CodeSpec { registers: 2, ins: 2, outs: 1, insns: init_insns.clone(), ..Default::default() }),
        }],
        virtual_methods: vec![MethodSpec {
            idx: ids.method(OUTER, "entry", "V", &[INNER]),
            access: 0x1,
            code: Some(CodeSpec { registers: 2, ins: 2, outs: 1, insns: entry_insns, ..Default::default() }),
        }],
        ..Default::default()
    });

    ids.add_class(ClassSpec {
        descriptor: INNER.into(),
        access: 0x1,
        superclass: Some(OBJ.into()),
        virtual_methods: vec![MethodSpec { idx: m_inner_work, access: 0x1, code: Some(ret_const_1.clone()) }],
        ..Default::default()
    });
    ids.add_class(ClassSpec {
        descriptor: DEEP.into(),
        access: 0x1,
        superclass: Some(INNER.into()),
        virtual_methods: vec![MethodSpec { idx: ids.method(DEEP, "deepWork", "I", &[]), access: 0x1, code: Some(ret_const_1.clone()) }],
        ..Default::default()
    });

    // Anonymous Outer$1 implementing Callback.
    ids.add_class(ClassSpec {
        descriptor: ANON.into(),
        access: 0x1,
        superclass: Some(OBJ.into()),
        interfaces: vec![CB.into()],
        direct_methods: vec![MethodSpec {
            idx: ids.method(ANON, "<init>", "V", &[]),
            access: 0x10001,
            code: Some(CodeSpec { registers: 1, ins: 1, outs: 1, insns: init_insns, ..Default::default() }),
        }],
        virtual_methods: vec![MethodSpec {
            idx: ids.method(ANON, "onEvent", "V", &["I"]),
            access: 0x1,
            code: Some(CodeSpec { registers: 2, ins: 2, insns: vec![0x0e, 0x00], ..Default::default() }),
        }],
        ..Default::default()
    });

    // Obfuscated Outer$a, whose InnerClass annotation names it `RealInner`.
    let inner_class = AnnotationItem {
        visibility: 0, // VISIBILITY_BUILD
        annotation: EncodedAnnotation {
            type_idx: ids.type_(ANN_INNER) as u32,
            elements: vec![
                (ids.string("accessFlags"), EncodedValue::Primitive { kind: 0x04, raw: vec![1] }),
                (ids.string("name"), EncodedValue::String(ids.string("RealInner"))),
            ],
        },
    };
    ids.add_class(ClassSpec {
        descriptor: OBF_INNER.into(),
        access: 0x1,
        superclass: Some(OBJ.into()),
        class_annotations: vec![inner_class],
        virtual_methods: vec![MethodSpec { idx: ids.method(OBF_INNER, "secret", "I", &[]), access: 0x1, code: Some(ret_const_1.clone()) }],
        ..Default::default()
    });

    // Lcom/Cpkg/do/if; reading `for:I`, `_:I` and calling `Lcom/other/switch;->case()I`.
    let mut kw_insns = vec![0x60, 0x00]; // sget v0, for:I
    kw_insns.extend_from_slice(&le16(f_kw_for));
    kw_insns.extend_from_slice(&[0x60, 0x01]); // sget v1, _:I
    kw_insns.extend_from_slice(&le16(f_kw_under));
    kw_insns.extend_from_slice(&[0x71, 0x00]); // invoke-static {}, switch->case()I
    kw_insns.extend_from_slice(&le16(m_ext_case));
    kw_insns.extend_from_slice(&[0x00, 0x00, 0x0a, 0x00, 0x0f, 0x00]); // move-result v0; return v0
    ids.add_class(ClassSpec {
        descriptor: KW_CLS.into(),
        access: 0x1,
        superclass: Some(OBJ.into()),
        static_fields: vec![(f_kw_for, 0x9), (f_kw_under, 0x9)],
        direct_methods: vec![
            MethodSpec {
                idx: ids.method(KW_CLS, "while", "I", &["I"]),
                access: 0x9,
                code: Some(CodeSpec { registers: 3, ins: 1, outs: 0, insns: kw_insns, ..Default::default() }),
            },
            MethodSpec {
                idx: ids.method(KW_CLS, "1a", "V", &[]),
                access: 0x9,
                code: Some(CodeSpec { registers: 1, insns: vec![0x0e, 0x00], ..Default::default() }),
            },
        ],
        ..Default::default()
    });

    // Kotlin-style Lcom/kt/in/When; with `fun()I` and `a-b()I`.
    ids.add_class(ClassSpec {
        descriptor: KT_CLS.into(),
        access: 0x1,
        superclass: Some(OBJ.into()),
        source_file: Some("When.kt".into()),
        direct_methods: vec![
            MethodSpec { idx: ids.method(KT_CLS, "fun", "I", &[]), access: 0x9, code: Some(ret_const_1.clone()) },
            MethodSpec { idx: ids.method(KT_CLS, "a-b", "I", &[]), access: 0x9, code: Some(ret_const_1) },
        ],
        ..Default::default()
    });

    // Collision: `a:I`, `a:String`, `m(I)Object` (bridge), `m(I)String`.
    let mut caller_insns = vec![0x60, 0x00]; // sget v0, a:I
    caller_insns.extend_from_slice(&le16(f_coll_a_int));
    caller_insns.extend_from_slice(&[0x62, 0x01]); // sget-object v1, a:String
    caller_insns.extend_from_slice(&le16(f_coll_a_str));
    caller_insns.extend_from_slice(&[0x71, 0x10]); // invoke-static {v0}, m(I)String
    caller_insns.extend_from_slice(&le16(ids.method(COLL, "m", STR, &["I"])));
    caller_insns.extend_from_slice(&[0x00, 0x00, 0x0e, 0x00]);
    let ret_null = CodeSpec { registers: 2, ins: 1, insns: vec![0x12, 0x00, 0x11, 0x00], ..Default::default() };
    ids.add_class(ClassSpec {
        descriptor: COLL.into(),
        access: 0x1,
        superclass: Some(OBJ.into()),
        static_fields: vec![(f_coll_a_int, 0x9), (f_coll_a_str, 0x9)],
        direct_methods: vec![
            MethodSpec { idx: ids.method(COLL, "m", OBJ, &["I"]), access: 0x1049, code: Some(ret_null.clone()) },
            MethodSpec { idx: ids.method(COLL, "m", STR, &["I"]), access: 0x9, code: Some(ret_null) },
            MethodSpec {
                idx: ids.method(COLL, "caller", "V", &[]),
                access: 0x9,
                code: Some(CodeSpec { registers: 2, outs: 1, insns: caller_insns, ..Default::default() }),
            },
        ],
        ..Default::default()
    });

    ids.finish()
}

fn rows(engine: &Engine, q: &Query) -> (Vec<String>, Vec<String>) {
    let mut out = Vec::new();
    let summary = engine.find_refs(q, |b| out.extend(b.results.iter().map(|r| r.line()))).unwrap();
    out.sort();
    (out, summary.notes)
}

#[test]
fn getclass_reads_classes_as_source_spells_them() {
    let apk = temp_apk_from_dex(&make_normalized_dex());
    let engine = Engine::new(apk.path()).with_threads(2);
    for (written, real, member) in [
        ("com.app.Outer.Inner", "Lcom/app/Outer$Inner;", "innerWork()I"),
        ("com.app.Outer.Inner.Deep", "Lcom/app/Outer$Inner$Deep;", "deepWork()I"),
        ("com.app.Outer.Anonymous1", "Lcom/app/Outer$1;", "onEvent(I)V"),
        ("com.app.Outer$Anonymous1", "Lcom/app/Outer$1;", "onEvent(I)V"),
        ("com.Cpkg.Cdo.Cif", "Lcom/Cpkg/do/if;", "while(I)I"),
        ("com.kt.`in`.When", "Lcom/kt/in/When;", "fun()I"),
        // Named by its InnerClass annotation.
        ("com.app.Outer.RealInner", "Lcom/app/Outer$a;", "secret()I"),
    ] {
        let src = engine.get_class(&names::format_class_name(written).unwrap()).unwrap();
        assert_eq!(src.descriptor, real, "{written}");
        assert!(src.source.contains(member), "{written}:\n{}", src.source);
    }
    // As written: the descriptor is the one asked for.
    assert_eq!(engine.get_class("Lcom/app/Outer;").unwrap().descriptor, "Lcom/app/Outer;");
    assert!(matches!(engine.get_class("Lcom/app/Outer/Nothing;"), Err(EngineError::ClassNotFound { .. })));
}

#[test]
fn findrefs_callgraph_and_hierarchy_fall_back_when_the_name_misses() {
    let apk = temp_apk_from_dex(&make_normalized_dex());
    let engine = Engine::new(apk.path()).with_threads(2);

    let q = names::member_query("method", None, false, Some("com.app.Outer.Inner->innerWork"), true).unwrap();
    let (found, notes) = rows(&engine, &Query::Method(q));
    assert_eq!(found, ["classes.dex | Lcom/app/Outer;->entry(Lcom/app/Outer$Inner;)V | Lcom/app/Outer$Inner;->innerWork()I"]);
    assert!(notes.iter().any(|n| n.contains("Java/Kotlin")), "{notes:?}");

    let q = names::member_query("method", None, false, Some("com.other.Cswitch->Ccase"), true).unwrap();
    assert_eq!(rows(&engine, &Query::Method(q)).0, ["classes.dex | Lcom/Cpkg/do/if;->while(I)I | Lcom/other/switch;->case()I"]);

    let q = names::member_query("field", Some("com.Cpkg.Cdo.Cif"), false, Some("Cfor"), true).unwrap();
    assert_eq!(rows(&engine, &Query::Field(q)).0, ["classes.dex | Lcom/Cpkg/do/if;->while(I)I | Lcom/Cpkg/do/if;->for:I [read]"]);
    let q = names::member_query("field", Some("com.app.Collision"), false, Some("a$2"), true).unwrap();
    assert_eq!(
        rows(&engine, &Query::Field(q)).0,
        [
            "classes.dex | Lcom/app/Collision;->caller()V | Lcom/app/Collision;->a:I [read], Lcom/app/Collision;->a:Ljava/lang/String; [read]"
        ]
    );

    assert_eq!(
        rows(&engine, &Query::Extends(names::format_class_name("com.app.Outer.Inner").unwrap())).0,
        ["classes.dex | Lcom/app/Outer$Inner$Deep; | extends Lcom/app/Outer$Inner;"]
    );

    // A query that matches as written gets no note.
    let q = names::member_query("method", None, false, Some("Lcom/app/Outer$Inner;->innerWork"), true).unwrap();
    let (found, notes) = rows(&engine, &Query::Method(q));
    assert_eq!(found.len(), 1);
    assert!(notes.is_empty(), "{notes:?}");
    // Neither as written nor read as source: no rows.
    let q = names::member_query("method", None, false, Some("com.app.Outer.Inner->nothing"), true).unwrap();
    assert_eq!(rows(&engine, &Query::Method(q)), (Vec::new(), Vec::new()));

    let cg = engine
        .call_graph(&CallQuery::method(names::format_class_name("com.app.Outer.Inner").unwrap(), "innerWork", Direction::Callers))
        .unwrap();
    assert_eq!(cg.lines(), ["0 Lcom/app/Outer$Inner;->innerWork()I", "  1 <- Lcom/app/Outer;->entry(Lcom/app/Outer$Inner;)V"]);
    assert!(cg.notes.iter().any(|n| n.contains("Lcom/app/Outer$Inner;->innerWork")), "{:?}", cg.notes);
    let ctor = engine.call_graph(&CallQuery::method("Lcom/app/Outer;", "Outer", Direction::Callers)).unwrap();
    assert_eq!(ctor.rows[0].method, "Lcom/app/Outer;-><init>(I)V");

    let h = engine
        .hierarchy(
            &HierarchyQuery::new(names::format_class_name("com.app.Outer.Inner").unwrap(), Lineage::Subclasses)
                .depth(4)
                .method(Some("deepWork".into())),
        )
        .unwrap();
    assert!(h.lines().iter().any(|l| l.contains("Lcom/app/Outer$Inner$Deep;") && l.contains("[defines deepWork()I]")), "{:?}", h.lines());
    let h = engine.hierarchy(&HierarchyQuery::new("Lcom/Cpkg/do/if;", Lineage::Supers).method(Some("Cwhile".into()))).unwrap();
    assert!(h.lines()[0].contains("[defines while(I)I]"), "{:?}", h.lines());
}

#[test]
fn a_name_the_dex_has_as_written_wins() {
    // Both `Lcom/app/Outer/Inner;` and `Lcom/app/Outer$Inner;`; on Dual both
    // `Cdo` and `do`, `m$2` and `m`, `a$2` and `a`.
    const OBJ: &str = "Ljava/lang/Object;";
    const SLASH: &str = "Lcom/app/Outer/Inner;";
    const DOLLAR: &str = "Lcom/app/Outer$Inner;";
    const DUAL: &str = "Lcom/app/Dual;";

    let mut d = DexBuilder::new();
    d.type_(OBJ)
        .type_(SLASH)
        .type_(DOLLAR)
        .type_(DUAL)
        .field(DUAL, "a", "I")
        .field(DUAL, "a$2", "I")
        .method(SLASH, "fromSlash", "I", &[])
        .method(DOLLAR, "fromDollar", "I", &[])
        .method(DUAL, "Cdo", "I", &[])
        .method(DUAL, "do", "I", &[])
        .method(DUAL, "m", "I", &[])
        .method(DUAL, "m$2", "I", &[])
        .method(DUAL, "useExact", "V", &[]);
    let mut ids = d.resolve();
    let ret_val = |v: u8| CodeSpec { registers: 1, insns: vec![0x12, (v & 0x0f) << 4, 0x0f, 0x00], ..Default::default() };
    ids.add_class(ClassSpec {
        descriptor: SLASH.into(),
        access: 0x1,
        superclass: Some(OBJ.into()),
        direct_methods: vec![MethodSpec { idx: ids.method(SLASH, "fromSlash", "I", &[]), access: 0x9, code: Some(ret_val(1)) }],
        ..Default::default()
    });
    ids.add_class(ClassSpec {
        descriptor: DOLLAR.into(),
        access: 0x1,
        superclass: Some(OBJ.into()),
        direct_methods: vec![MethodSpec { idx: ids.method(DOLLAR, "fromDollar", "I", &[]), access: 0x9, code: Some(ret_val(2)) }],
        ..Default::default()
    });
    let mut use_insns = vec![0x60, 0x00]; // sget v0, a$2:I
    use_insns.extend_from_slice(&le16(ids.field(DUAL, "a$2", "I")));
    use_insns.extend_from_slice(&[0x60, 0x00]); // sget v0, a:I
    use_insns.extend_from_slice(&le16(ids.field(DUAL, "a", "I")));
    use_insns.extend_from_slice(&[0x71, 0x00]); // invoke-static {}, Cdo()I
    use_insns.extend_from_slice(&le16(ids.method(DUAL, "Cdo", "I", &[])));
    use_insns.extend_from_slice(&[0x00, 0x00, 0x71, 0x00]); // invoke-static {}, do()I
    use_insns.extend_from_slice(&le16(ids.method(DUAL, "do", "I", &[])));
    use_insns.extend_from_slice(&[0x00, 0x00, 0x0e, 0x00]);
    ids.add_class(ClassSpec {
        descriptor: DUAL.into(),
        access: 0x1,
        superclass: Some(OBJ.into()),
        static_fields: vec![(ids.field(DUAL, "a", "I"), 0x9), (ids.field(DUAL, "a$2", "I"), 0x9)],
        direct_methods: vec![
            MethodSpec { idx: ids.method(DUAL, "Cdo", "I", &[]), access: 0x9, code: Some(ret_val(4)) },
            MethodSpec { idx: ids.method(DUAL, "do", "I", &[]), access: 0x9, code: Some(ret_val(5)) },
            MethodSpec { idx: ids.method(DUAL, "m", "I", &[]), access: 0x9, code: Some(ret_val(6)) },
            MethodSpec { idx: ids.method(DUAL, "m$2", "I", &[]), access: 0x9, code: Some(ret_val(7)) },
            MethodSpec {
                idx: ids.method(DUAL, "useExact", "V", &[]),
                access: 0x9,
                code: Some(CodeSpec { registers: 1, outs: 0, insns: use_insns, ..Default::default() }),
            },
        ],
        ..Default::default()
    });

    let apk = temp_apk_from_dex(&ids.finish());
    let engine = Engine::new(apk.path()).with_threads(2);

    let cls = engine.get_class(&names::format_class_name("com.app.Outer.Inner").unwrap()).unwrap();
    assert_eq!(cls.descriptor, SLASH);
    assert!(cls.source.contains("fromSlash()") && !cls.source.contains("fromDollar()"), "{}", cls.source);

    let q = names::member_query("method", Some(DUAL), false, Some("Cdo"), true).unwrap();
    let (found, notes) = rows(&engine, &Query::Method(q));
    assert_eq!(found, ["classes.dex | Lcom/app/Dual;->useExact()V | Lcom/app/Dual;->Cdo()I"]);
    assert!(notes.is_empty(), "{notes:?}");
    let q = names::member_query("field", Some(DUAL), false, Some("a$2"), true).unwrap();
    assert_eq!(rows(&engine, &Query::Field(q)).0, ["classes.dex | Lcom/app/Dual;->useExact()V | Lcom/app/Dual;->a$2:I [read]"]);

    let cg = engine.call_graph(&CallQuery::method(DUAL, "m$2", Direction::Callers)).unwrap();
    assert_eq!(cg.rows[0].method, "Lcom/app/Dual;->m$2()I");
    assert!(cg.notes.is_empty(), "{:?}", cg.notes);
}

#[test]
fn a_name_made_up_by_the_fallback_matches_whole_members_only() {
    // `a$2` reads as `a`; a substring match on the class would also hit `abc`.
    const OBJ: &str = "Ljava/lang/Object;";
    const COLL: &str = "Lcom/app/Collision;";
    let mut d = DexBuilder::new();
    d.type_(OBJ).type_(COLL).field(COLL, "a", "I").field(COLL, "abc", "I").method(COLL, "use", "V", &[]);
    let mut ids = d.resolve();
    let mut code = vec![0x60, 0x00];
    code.extend_from_slice(&le16(ids.field(COLL, "a", "I")));
    code.extend_from_slice(&[0x60, 0x00]);
    code.extend_from_slice(&le16(ids.field(COLL, "abc", "I")));
    code.extend_from_slice(&[0x0e, 0x00]);
    ids.add_class(ClassSpec {
        descriptor: COLL.into(),
        access: 0x1,
        superclass: Some(OBJ.into()),
        static_fields: vec![(ids.field(COLL, "a", "I"), 0x9), (ids.field(COLL, "abc", "I"), 0x9)],
        direct_methods: vec![MethodSpec {
            idx: ids.method(COLL, "use", "V", &[]),
            access: 0x9,
            code: Some(CodeSpec { registers: 1, outs: 0, insns: code, ..Default::default() }),
        }],
        ..Default::default()
    });
    let apk = temp_apk_from_dex(&ids.finish());
    let engine = Engine::new(apk.path()).with_threads(2);
    // `exact = false` is what the CLI and MCP send by default.
    let q = names::member_query("field", Some(COLL), false, Some("a$2"), false).unwrap();
    assert_eq!(rows(&engine, &Query::Field(q)).0, ["classes.dex | Lcom/app/Collision;->use()V | Lcom/app/Collision;->a:I [read]"]);
}

#[test]
fn java_style_signatures_without_return_type() {
    let apk = temp_apk_from_dex(&make_normalized_dex());
    let engine = Engine::new(apk.path()).with_threads(2);

    // No return type and a nested class written with a dot.
    let cg = engine.call_graph(&CallQuery::method("Lcom/app/Outer;", "entry(com.app.Outer.Inner)", Direction::Callers)).unwrap();
    assert_eq!(cg.rows[0].method, "Lcom/app/Outer;->entry(Lcom/app/Outer$Inner;)V", "{:?}", cg.lines());
    let cg = engine.call_graph(&CallQuery::method("Lcom/app/Outer;", "Outer(int)", Direction::Callers)).unwrap();
    assert_eq!(cg.rows[0].method, "Lcom/app/Outer;-><init>(I)V", "{:?}", cg.lines());
    // Unbalanced is still an error.
    assert!(engine.call_graph(&CallQuery::method("Lcom/app/Outer;", "entry(I", Direction::Callers)).is_err());

    let h =
        engine.hierarchy(&HierarchyQuery::new("Lcom/app/Outer$1;", Lineage::Supers).depth(3).method(Some("onEvent(int)".into()))).unwrap();
    assert!(h.lines().first().is_some_and(|l| l.contains("[defines onEvent(I)V]")), "{:?}", h.lines());

    let q = names::member_query("method", None, false, Some("com.app.Outer->entry(com.app.Outer.Inner)"), true).unwrap();
    assert_eq!(rows(&engine, &Query::Method(q)).0.len(), 0, "nothing calls entry");
    let q = names::member_query("method", None, false, Some("com.app.Outer.Inner->innerWork()"), true).unwrap();
    assert_eq!(rows(&engine, &Query::Method(q)).0.len(), 1);
}

#[test]
fn compound_rules_read_each_part_as_source() {
    let apk = temp_apk_from_dex(&make_normalized_dex());
    let engine = Engine::new(apk.path()).with_threads(2);
    let rule = names::parse_rule("method:com.other.Cswitch->Ccase & field:com.Cpkg.Cdo.Cif->Cfor").unwrap();
    assert_eq!(
        rows(&engine, &rule).0,
        ["classes.dex | Lcom/Cpkg/do/if;->while(I)I | Lcom/other/switch;->case()I, Lcom/Cpkg/do/if;->for:I [read]"]
    );
    // One part as written, one read as source: the part as written still counts.
    let rule = names::parse_rule("method:Lcom/other/switch;->case & field:com.Cpkg.Cdo.Cif->Cfor").unwrap();
    assert_eq!(
        rows(&engine, &rule).0,
        ["classes.dex | Lcom/Cpkg/do/if;->while(I)I | Lcom/other/switch;->case()I, Lcom/Cpkg/do/if;->for:I [read]"]
    );
}

#[test]
fn single_dex_search_falls_back_too() {
    let dex = make_normalized_dex();
    let q = Query::Method(names::member_query("method", None, false, Some("com.app.Outer.Inner->innerWork"), true).unwrap());
    let found: Vec<String> = asc_engine::find_refs_in_dex("classes.dex", &dex, &q, true).unwrap().iter().map(|r| r.line()).collect();
    assert_eq!(found, ["classes.dex | Lcom/app/Outer;->entry(Lcom/app/Outer$Inner;)V | Lcom/app/Outer$Inner;->innerWork()I"]);
}
