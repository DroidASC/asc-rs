//! Comprehensive tests for `dexdec` <-> `asc-rs` naming normalization:
//! 1. Header Symbol Map (`// [dex-map]`) emission when and only when symbols are renamed.
//! 2. Fallback de-normalization across `getclass`, `findrefs`, `callgraph`, and `hierarchy`
//!    covering all 6 normalization categories:
//!    - Nested class dot separators (`Outer.Inner` -> `Outer$Inner`)
//!    - Anonymous class placeholders (`Anonymous1` -> `$1`)
//!    - Java reserved / numeric prefixes (`Cdo`, `Cif`, `C_`, `C1a` -> `do`, `if`, `_`, `1a`)
//!    - Kotlin backtick & hex escapes (`` `in` ``, `_dex_61_2D_62_` -> `in`, `a-b`)
//!    - Same-name field & bridge-method collision suffixes (`a$2`, `m$2` -> `a`, `m`)
//!    - Constructor source names (`ClassName`, `constructor` -> `<init>`) and
//!      `dalvik.annotation.InnerClass` renamed inner classes (`Outer.RealInner` -> `Outer$a`)
//! 3. Strict original-first precedence: when the exact queried name exists in the DEX,
//!    fallback de-normalization is never triggered.

use asc_dex::encoded::{AnnotationItem, EncodedAnnotation, EncodedValue};
use asc_engine::{names, CallQuery, DecompileOptions, Direction, Engine, HierarchyQuery, Lineage, SourceLang};
use asc_findrefs::Query;
use asc_fixture::{make_apk, ClassSpec, CodeSpec, DexBuilder, MethodSpec};
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

/// Build a synthetic DEX exercising all 6 normalization categories.
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
        // Fields
        .field(KW_CLS, "for", "I")
        .field(KW_CLS, "_", "I")
        .field(COLL, "a", "I")
        .field(COLL, "a", STR)
        // Methods
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
    let m_outer_init = ids.method(OUTER, "<init>", "V", &["I"]);
    let m_outer_entry = ids.method(OUTER, "entry", "V", &[INNER]);
    let m_inner_work = ids.method(INNER, "innerWork", "I", &[]);
    let m_deep_work = ids.method(DEEP, "deepWork", "I", &[]);
    let m_anon_init = ids.method(ANON, "<init>", "V", &[]);
    let m_anon_event = ids.method(ANON, "onEvent", "V", &["I"]);
    let m_obf_secret = ids.method(OBF_INNER, "secret", "I", &[]);
    let m_kw_while = ids.method(KW_CLS, "while", "I", &["I"]);
    let m_kw_1a = ids.method(KW_CLS, "1a", "V", &[]);
    let m_ext_case = ids.method(EXT_SW, "case", "I", &[]);
    let m_kt_fun = ids.method(KT_CLS, "fun", "I", &[]);
    let m_kt_ab = ids.method(KT_CLS, "a-b", "I", &[]);
    let m_coll_m_obj = ids.method(COLL, "m", OBJ, &["I"]);
    let m_coll_m_str = ids.method(COLL, "m", STR, &["I"]);
    let m_coll_caller = ids.method(COLL, "caller", "V", &[]);

    let f_kw_for = ids.field(KW_CLS, "for", "I");
    let f_kw_under = ids.field(KW_CLS, "_", "I");
    let f_coll_a_int = ids.field(COLL, "a", "I");
    let f_coll_a_str = ids.field(COLL, "a", STR);

    // 1. Interface Callback
    ids.add_class(ClassSpec {
        descriptor: CB.into(),
        access: 0x0601, // public abstract interface
        superclass: Some(OBJ.into()),
        virtual_methods: vec![MethodSpec { idx: ids.method(CB, "onEvent", "V", &["I"]), access: 0x0401, code: None }],
        ..Default::default()
    });

    // 2. Outer class: `<init>(I)V` and `entry(LInner;)V` calling `Inner.innerWork()`
    let mut entry_insns = Vec::new();
    entry_insns.extend_from_slice(&[0x6e, 0x10]); // invoke-virtual {v1}, Inner->innerWork()I
    entry_insns.extend_from_slice(&le16(m_inner_work));
    entry_insns.extend_from_slice(&[0x01, 0x00]);
    entry_insns.extend_from_slice(&[0x0e, 0x00]); // return-void

    let mut init_insns = Vec::new();
    init_insns.extend_from_slice(&[0x70, 0x10]); // invoke-direct {v0}, Object;-><init>()V
    init_insns.extend_from_slice(&le16(m_obj_init));
    init_insns.extend_from_slice(&[0x00, 0x00]);
    init_insns.extend_from_slice(&[0x0e, 0x00]);

    ids.add_class(ClassSpec {
        descriptor: OUTER.into(),
        access: 0x1,
        superclass: Some(OBJ.into()),
        direct_methods: vec![MethodSpec {
            idx: m_outer_init,
            access: 0x10001, // public constructor
            code: Some(CodeSpec { registers: 2, ins: 2, outs: 1, insns: init_insns.clone(), ..Default::default() }),
        }],
        virtual_methods: vec![MethodSpec {
            idx: m_outer_entry,
            access: 0x1,
            code: Some(CodeSpec { registers: 2, ins: 2, outs: 1, insns: entry_insns, ..Default::default() }),
        }],
        ..Default::default()
    });

    // 3. Outer$Inner and Outer$Inner$Deep
    let ret_const_1 = CodeSpec { registers: 1, insns: vec![0x12, 0x10, 0x0f, 0x00], ..Default::default() };
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
        virtual_methods: vec![MethodSpec { idx: m_deep_work, access: 0x1, code: Some(ret_const_1.clone()) }],
        ..Default::default()
    });

    // 4. Anonymous class Outer$1 implementing Callback
    ids.add_class(ClassSpec {
        descriptor: ANON.into(),
        access: 0x1,
        superclass: Some(OBJ.into()),
        interfaces: vec![CB.into()],
        direct_methods: vec![MethodSpec {
            idx: m_anon_init,
            access: 0x10001,
            code: Some(CodeSpec { registers: 1, ins: 1, outs: 1, insns: init_insns, ..Default::default() }),
        }],
        virtual_methods: vec![MethodSpec {
            idx: m_anon_event,
            access: 0x1,
            code: Some(CodeSpec { registers: 2, ins: 2, insns: vec![0x0e, 0x00], ..Default::default() }),
        }],
        ..Default::default()
    });

    // 5. Obfuscated inner class Outer$a with InnerClass annotation `name = "RealInner"`
    let ann_inner_item = AnnotationItem {
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
        class_annotations: vec![ann_inner_item],
        virtual_methods: vec![MethodSpec { idx: m_obf_secret, access: 0x1, code: Some(ret_const_1.clone()) }],
        ..Default::default()
    });

    // 6. Keyword class Lcom/Cpkg/do/if; reading `for:I`, `_:I` and calling `Lcom/other/switch;->case()I`
    let mut kw_insns = Vec::new();
    kw_insns.extend_from_slice(&[0x60, 0x00]); // sget v0, for:I
    kw_insns.extend_from_slice(&le16(f_kw_for));
    kw_insns.extend_from_slice(&[0x60, 0x01]); // sget v1, _:I
    kw_insns.extend_from_slice(&le16(f_kw_under));
    kw_insns.extend_from_slice(&[0x71, 0x00]); // invoke-static {}, switch->case()I
    kw_insns.extend_from_slice(&le16(m_ext_case));
    kw_insns.extend_from_slice(&[0x00, 0x00]);
    kw_insns.extend_from_slice(&[0x0a, 0x00]); // move-result v0
    kw_insns.extend_from_slice(&[0x0f, 0x00]); // return v0

    ids.add_class(ClassSpec {
        descriptor: KW_CLS.into(),
        access: 0x1,
        superclass: Some(OBJ.into()),
        static_fields: vec![(f_kw_for, 0x9), (f_kw_under, 0x9)],
        direct_methods: vec![
            MethodSpec {
                idx: m_kw_while,
                access: 0x9,
                code: Some(CodeSpec { registers: 3, ins: 1, outs: 0, insns: kw_insns, ..Default::default() }),
            },
            MethodSpec { idx: m_kw_1a, access: 0x9, code: Some(CodeSpec { registers: 1, insns: vec![0x0e, 0x00], ..Default::default() }) },
        ],
        ..Default::default()
    });

    // 7. Kotlin class Lcom/kt/in/When; (source_file = "When.kt") with `fun()I` and `a-b()I`
    ids.add_class(ClassSpec {
        descriptor: KT_CLS.into(),
        access: 0x1,
        superclass: Some(OBJ.into()),
        source_file: Some("When.kt".into()),
        direct_methods: vec![
            MethodSpec { idx: m_kt_fun, access: 0x9, code: Some(ret_const_1.clone()) },
            MethodSpec { idx: m_kt_ab, access: 0x9, code: Some(ret_const_1) },
        ],
        ..Default::default()
    });

    // 8. Collision class with `a:I`, `a:Ljava/lang/String;`, `m(I)Object`, `m(I)String`
    let mut caller_insns = Vec::new();
    caller_insns.extend_from_slice(&[0x60, 0x00]); // sget v0, a:I
    caller_insns.extend_from_slice(&le16(f_coll_a_int));
    caller_insns.extend_from_slice(&[0x62, 0x01]); // sget-object v1, a:String
    caller_insns.extend_from_slice(&le16(f_coll_a_str));
    caller_insns.extend_from_slice(&[0x71, 0x10]); // invoke-static {v0}, m(I)String
    caller_insns.extend_from_slice(&le16(m_coll_m_str));
    caller_insns.extend_from_slice(&[0x00, 0x00]);
    caller_insns.extend_from_slice(&[0x0e, 0x00]);

    let ret_null = CodeSpec {
        registers: 2,
        ins: 1,
        insns: vec![0x12, 0x00, 0x11, 0x00], // const/4 v0, 0; return-object v0
        ..Default::default()
    };
    ids.add_class(ClassSpec {
        descriptor: COLL.into(),
        access: 0x1,
        superclass: Some(OBJ.into()),
        static_fields: vec![(f_coll_a_int, 0x9), (f_coll_a_str, 0x9)],
        direct_methods: vec![
            MethodSpec {
                idx: m_coll_m_obj,
                access: 0x1049, // public static bridge synthetic
                code: Some(ret_null.clone()),
            },
            MethodSpec { idx: m_coll_m_str, access: 0x9, code: Some(ret_null) },
            MethodSpec {
                idx: m_coll_caller,
                access: 0x9,
                code: Some(CodeSpec { registers: 2, outs: 1, insns: caller_insns, ..Default::default() }),
            },
        ],
        ..Default::default()
    });

    ids.finish()
}

#[test]
fn header_symbol_map_is_emitted_only_when_symbols_are_renamed() {
    let apk = temp_apk_from_dex(&make_normalized_dex());
    let engine = Engine::new(apk.path()).with_threads(2);
    let java_opts = DecompileOptions { lang: SourceLang::Java, ..Default::default() };

    // 1. Anonymous class `Lcom/app/Outer$1;` -> `Anonymous1` gets a `[dex-map]` header.
    let anon = engine.decompile_class("Lcom/app/Outer$1;", java_opts).unwrap();
    assert!(anon.source.starts_with("// [dex-map]\n"), "{}", anon.source);
    assert!(anon.source.contains("//   class  Outer.Anonymous1 => Lcom/app/Outer$1;"), "{}", anon.source);

    // 2. Keyword class `Lcom/Cpkg/do/if;` -> `Cdo`, `Cif`, `Cfor`, `C_`, `Cwhile`, `C1a`, and external ref `Cswitch.Ccase`.
    let kw = engine.decompile_class("Lcom/Cpkg/do/if;", java_opts).unwrap();
    assert!(kw.source.starts_with("// [dex-map]\n"), "{}", kw.source);
    for expected in [
        "//   class  com.Cpkg.Cdo.Cif => Lcom/Cpkg/do/if;",
        "//   field  Cif.C_ => Lcom/Cpkg/do/if;->_:I",
        "//   field  Cif.Cfor => Lcom/Cpkg/do/if;->for:I",
        "//   method Cif.C1a => Lcom/Cpkg/do/if;->1a()V",
        "//   method Cif.Cwhile => Lcom/Cpkg/do/if;->while(I)I",
        "//   ref    Cswitch.Ccase => Lcom/other/switch;->case()I",
    ] {
        assert!(kw.source.contains(expected), "missing {expected:?} in:\n{}", kw.source);
    }

    // 3. Collision class `Lcom/app/Collision;` -> `a$2` and `m$2`.
    let coll = engine.decompile_class("Lcom/app/Collision;", java_opts).unwrap();
    assert!(coll.source.starts_with("// [dex-map]\n"), "{}", coll.source);
    assert!(coll.source.contains("//   field  Collision.a$2 => Lcom/app/Collision;->a:Ljava/lang/String;"), "{}", coll.source);
    assert!(coll.source.contains("//   method Collision.m$2 => Lcom/app/Collision;->m(I)Ljava/lang/String;"), "{}", coll.source);

    // 4. Plain class without any renamed identifiers (`Lcom/app/Outer$Inner;`) has NO `[dex-map]` header.
    let plain = engine.decompile_class("Lcom/app/Outer$Inner;", java_opts).unwrap();
    assert!(!plain.source.contains("// [dex-map]"), "{}", plain.source);
}

#[test]
fn getclass_fallback_resolves_all_six_normalization_categories() {
    let apk = temp_apk_from_dex(&make_normalized_dex());
    let engine = Engine::new(apk.path()).with_threads(2);
    let java_opts = DecompileOptions { lang: SourceLang::Java, ..Default::default() };

    // Category 1: Nested class dot separators (`Outer.Inner` and `Outer.Inner.Deep`).
    let inner = engine.decompile_class(&names::format_class_name("com.app.Outer.Inner").unwrap(), java_opts).unwrap();
    assert!(inner.source.contains("innerWork()"), "{}", inner.source);
    let deep = engine.decompile_class(&names::format_class_name("com.app.Outer.Inner.Deep").unwrap(), java_opts).unwrap();
    assert!(deep.source.contains("deepWork()"), "{}", deep.source);

    // Category 2: Anonymous class `Outer.Anonymous1` and `Outer$Anonymous1`.
    for q in ["com.app.Outer.Anonymous1", "com.app.Outer$Anonymous1"] {
        let anon = engine.decompile_class(&names::format_class_name(q).unwrap(), java_opts).unwrap();
        assert!(anon.source.contains("onEvent("), "{q}:\n{}", anon.source);
    }

    // Category 3: Java reserved keyword / numeric prefixes (`com.Cpkg.Cdo.Cif`, methods `Cwhile`, `C1a`).
    let kw_desc = names::format_class_name("com.Cpkg.Cdo.Cif").unwrap();
    let kw_m1 = engine.decompile_class_method(&kw_desc, java_opts, Some("Cwhile")).unwrap();
    assert_eq!(kw_m1.methods, ["while(I)I"]);
    let kw_m2 = engine.decompile_class_method(&kw_desc, java_opts, Some("C1a")).unwrap();
    assert_eq!(kw_m2.methods, ["1a()V"]);

    // Category 4: Kotlin backtick-escaped package & method names (``com.kt.`in`.When``, `` `fun` ``, `_dex_61_2D_62_`).
    let kt_desc = names::format_class_name("com.kt.`in`.When").unwrap();
    let kt_opts = DecompileOptions { lang: SourceLang::Auto, ..Default::default() };
    let kt_m1 = engine.decompile_class_method(&kt_desc, kt_opts, Some("`fun`")).unwrap();
    assert_eq!(kt_m1.lang, SourceLang::Kotlin);
    assert_eq!(kt_m1.methods, ["fun()I"]);
    let kt_m2 = engine.decompile_class_method(&kt_desc, kt_opts, Some("_dex_61_2D_62_")).unwrap();
    assert_eq!(kt_m2.methods, ["a-b()I"]);

    // Category 5: Collision suffix `m$2` on `Lcom/app/Collision;`.
    let coll_m = engine.decompile_class_method("Lcom/app/Collision;", java_opts, Some("m$2")).unwrap();
    assert_eq!(coll_m.methods.len(), 2);

    // Category 6a: Constructor queried by source class name (`Outer`, `Anonymous1`, `constructor`).
    let ctor1 = engine.decompile_class_method("Lcom/app/Outer;", java_opts, Some("Outer")).unwrap();
    assert_eq!(ctor1.methods, ["<init>(I)V"]);
    let ctor2 = engine.decompile_class_method("Lcom/app/Outer;", java_opts, Some("Outer(int)")).unwrap();
    assert_eq!(ctor2.methods, ["<init>(I)V"]);
    let ctor3 = engine.decompile_class_method("Lcom/app/Outer$1;", java_opts, Some("Anonymous1")).unwrap();
    assert_eq!(ctor3.methods, ["<init>()V"]);

    // Category 6b: `InnerClass` annotation renamed inner class (`com.app.Outer.RealInner` -> `Lcom/app/Outer$a;`).
    let obf = engine.decompile_class(&names::format_class_name("com.app.Outer.RealInner").unwrap(), java_opts).unwrap();
    assert!(obf.source.contains("secret()"), "{}", obf.source);
}

#[test]
fn findrefs_callgraph_and_hierarchy_fallback_when_original_misses() {
    let apk = temp_apk_from_dex(&make_normalized_dex());
    let engine = Engine::new(apk.path()).with_threads(2);
    let collect_lines = |q: &Query| -> Vec<String> {
        let mut out = Vec::new();
        engine.find_refs(q, |b| out.extend(b.results.iter().map(|r| r.line()))).unwrap();
        out.sort();
        out
    };

    // 1. findrefs method with normalized class & method names:
    //    `com.app.Outer.Inner->innerWork` -> hits `Lcom/app/Outer;->entry`
    let q_nested = names::member_query("method", None, false, Some("com.app.Outer.Inner->innerWork"), true).unwrap();
    assert_eq!(
        collect_lines(&Query::Method(q_nested)),
        ["classes.dex | Lcom/app/Outer;->entry(Lcom/app/Outer$Inner;)V | Lcom/app/Outer$Inner;->innerWork()I"]
    );

    // 2. findrefs method with Java reserved keyword prefix: `com.other.Cswitch->Ccase`
    let q_kw = names::member_query("method", None, false, Some("com.other.Cswitch->Ccase"), true).unwrap();
    assert_eq!(collect_lines(&Query::Method(q_kw)), ["classes.dex | Lcom/Cpkg/do/if;->while(I)I | Lcom/other/switch;->case()I"]);

    // 3. findrefs field with keyword prefix (`Cfor`, `C_`) and collision suffix (`a$2`):
    let q_f_kw = names::member_query("field", Some("com.Cpkg.Cdo.Cif"), false, Some("Cfor"), true).unwrap();
    assert_eq!(collect_lines(&Query::Field(q_f_kw)), ["classes.dex | Lcom/Cpkg/do/if;->while(I)I | Lcom/Cpkg/do/if;->for:I [read]"]);
    let q_f_coll = names::member_query("field", Some("com.app.Collision"), false, Some("a$2"), true).unwrap();
    assert_eq!(
        collect_lines(&Query::Field(q_f_coll)),
        ["classes.dex | Lcom/app/Collision;->caller()V | Lcom/app/Collision;->a:I [read], Lcom/app/Collision;->a:Ljava/lang/String; [read]"]
    );

    // 4. findrefs extends with `com.app.Outer.Inner` -> hits `Lcom/app/Outer$Inner$Deep;`
    assert_eq!(
        collect_lines(&Query::Extends(names::format_class_name("com.app.Outer.Inner").unwrap())),
        ["classes.dex | Lcom/app/Outer$Inner$Deep; | extends Lcom/app/Outer$Inner;"]
    );

    // 5. callgraph with normalized class and method (`com.app.Outer.Inner` `innerWork`):
    let cg = engine
        .call_graph(&CallQuery::method(names::format_class_name("com.app.Outer.Inner").unwrap(), "innerWork", Direction::Callers))
        .unwrap();
    assert_eq!(cg.lines(), ["0 Lcom/app/Outer$Inner;->innerWork()I", "  1 <- Lcom/app/Outer;->entry(Lcom/app/Outer$Inner;)V",]);

    // 6. hierarchy with normalized class (`com.app.Outer.Inner`) and method (`deepWork`):
    let h = engine
        .hierarchy(&HierarchyQuery {
            class: names::format_class_name("com.app.Outer.Inner").unwrap(),
            direction: Lineage::Subclasses,
            depth: 4,
            max_nodes: 100,
            method: Some("deepWork".into()),
        })
        .unwrap();
    assert!(h.lines().iter().any(|l| l.contains("Lcom/app/Outer$Inner$Deep;") && l.contains("[defines deepWork()I]")), "{:?}", h.lines());
}

#[test]
fn original_input_always_takes_precedence_over_denormalization() {
    // Build a DEX that defines BOTH:
    // - `Lcom/app/Outer/Inner;` (with method `fromSlash()I`) AND `Lcom/app/Outer$Inner;` (with method `fromDollar()I`)
    // - On `Lcom/app/Dual;`: BOTH `Cdo()I` (returns 10) AND `do()I` (returns 20),
    //   BOTH `m$2()I` AND `m()I`, and BOTH a normal method `Dual()I` AND constructor `<init>()V`.
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
        .method(DUAL, "<init>", "V", &[])
        .method(DUAL, "Dual", "I", &[])
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

    // `useExact` only references `Cdo`, `m$2`, and `a$2` (NOT `do`, `m`, or `a`).
    let mut use_insns = Vec::new();
    use_insns.extend_from_slice(&[0x60, 0x00]); // sget v0, a$2:I
    use_insns.extend_from_slice(&le16(ids.field(DUAL, "a$2", "I")));
    use_insns.extend_from_slice(&[0x60, 0x00]); // sget v0, a:I
    use_insns.extend_from_slice(&le16(ids.field(DUAL, "a", "I")));
    use_insns.extend_from_slice(&[0x71, 0x00]); // invoke-static {}, Cdo()I
    use_insns.extend_from_slice(&le16(ids.method(DUAL, "Cdo", "I", &[])));
    use_insns.extend_from_slice(&[0x00, 0x00]);
    use_insns.extend_from_slice(&[0x71, 0x00]); // invoke-static {}, do()I
    use_insns.extend_from_slice(&le16(ids.method(DUAL, "do", "I", &[])));
    use_insns.extend_from_slice(&[0x00, 0x00]);
    use_insns.extend_from_slice(&[0x0e, 0x00]);

    ids.add_class(ClassSpec {
        descriptor: DUAL.into(),
        access: 0x1,
        superclass: Some(OBJ.into()),
        static_fields: vec![(ids.field(DUAL, "a", "I"), 0x9), (ids.field(DUAL, "a$2", "I"), 0x9)],
        direct_methods: vec![
            MethodSpec {
                idx: ids.method(DUAL, "<init>", "V", &[]),
                access: 0x10001,
                code: Some(CodeSpec { registers: 1, ins: 1, insns: vec![0x0e, 0x00], ..Default::default() }),
            },
            MethodSpec { idx: ids.method(DUAL, "Dual", "I", &[]), access: 0x9, code: Some(ret_val(3)) },
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
    let java_opts = DecompileOptions { lang: SourceLang::Java, ..Default::default() };

    // 1. `com.app.Outer.Inner` resolves to the exact `Lcom/app/Outer/Inner;` (`fromSlash`), NOT `Lcom/app/Outer$Inner;`!
    let cls = engine.decompile_class(&names::format_class_name("com.app.Outer.Inner").unwrap(), java_opts).unwrap();
    assert!(cls.source.contains("fromSlash()") && !cls.source.contains("fromDollar()"), "{}", cls.source);

    // 2. Method `Cdo` on `Dual` selects only `Cdo()I` (returns 4), NOT `do()I` (returns 5)!
    let m_cdo = engine.decompile_class_method(DUAL, java_opts, Some("Cdo")).unwrap();
    assert_eq!(m_cdo.methods, ["Cdo()I"]);
    assert!(m_cdo.source.contains("return 4;"), "{}", m_cdo.source);

    // 3. Method `m$2` on `Dual` selects only `m$2()I` (returns 7), NOT `m()I` (returns 6)!
    let m_2 = engine.decompile_class_method(DUAL, java_opts, Some("m$2")).unwrap();
    assert_eq!(m_2.methods, ["m$2()I"]);
    assert!(m_2.source.contains("return 7;"), "{}", m_2.source);

    // 4. Method `Dual` on `Dual` selects the literal `Dual()I` method (returns 3), NOT `<init>()V`!
    let m_dual = engine.decompile_class_method(DUAL, java_opts, Some("Dual")).unwrap();
    assert_eq!(m_dual.methods, ["Dual()I"]);
    assert!(m_dual.source.contains("return 3;"), "{}", m_dual.source);

    // 5. `findrefs` for exact `Cdo` matches ONLY `Dual->Cdo()I` (not `Dual->do()I`),
    //    and exact `a$2` matches ONLY `Dual->a$2:I` (not `Dual->a:I`).
    let mut m_hits = Vec::new();
    let q_cdo = names::member_query("method", Some(DUAL), false, Some("Cdo"), true).unwrap();
    engine.find_refs(&Query::Method(q_cdo), |b| m_hits.extend(b.results.iter().map(|r| r.line()))).unwrap();
    assert_eq!(m_hits, ["classes.dex | Lcom/app/Dual;->useExact()V | Lcom/app/Dual;->Cdo()I"]);

    let mut f_hits = Vec::new();
    let q_a2 = names::member_query("field", Some(DUAL), false, Some("a$2"), true).unwrap();
    engine.find_refs(&Query::Field(q_a2), |b| f_hits.extend(b.results.iter().map(|r| r.line()))).unwrap();
    assert_eq!(f_hits, ["classes.dex | Lcom/app/Dual;->useExact()V | Lcom/app/Dual;->a$2:I [read]"]);
}

#[test]
fn collision_suffixes_follow_dexdec_argtype_order() {
    // `dexdec` numbers same-named members in ArgType order: primitives by
    // variant (Z < I), then objects by internal name ("com/app/Foo" <
    // "com/app/Foo$Bar", shorter prefix first). ASCII order of the raw
    // descriptors disagrees ('I' < 'Z', 'L' < 'Z').
    const OBJ: &str = "Ljava/lang/Object;";
    const COLL: &str = "Lcom/app/Kinds;";
    const FOO: &str = "Lcom/app/Foo;";
    const BARS: &str = "Lcom/app/Foo$Bar;";

    let mut d = DexBuilder::new();
    d.type_(OBJ)
        .type_(COLL)
        .type_(FOO)
        .type_(BARS)
        .field(COLL, "a", "Z")
        .field(COLL, "a", "I")
        .field(COLL, "a", FOO)
        .field(COLL, "a", BARS)
        .method(COLL, "m", "Z", &[])
        .method(COLL, "m", OBJ, &[]);
    let mut ids = d.resolve();
    let ret = CodeSpec { registers: 1, insns: vec![0x12, 0x00, 0x0f, 0x00], ..Default::default() };
    ids.add_class(ClassSpec {
        descriptor: COLL.into(),
        access: 0x1,
        superclass: Some(OBJ.into()),
        static_fields: vec![
            (ids.field(COLL, "a", "Z"), 0x9),
            (ids.field(COLL, "a", "I"), 0x9),
            (ids.field(COLL, "a", FOO), 0x9),
            (ids.field(COLL, "a", BARS), 0x9),
        ],
        direct_methods: vec![
            MethodSpec { idx: ids.method(COLL, "m", "Z", &[]), access: 0x9, code: Some(ret.clone()) },
            MethodSpec { idx: ids.method(COLL, "m", OBJ, &[]), access: 0x9, code: Some(ret) },
        ],
        ..Default::default()
    });

    let apk = temp_apk_from_dex(&ids.finish());
    let engine = Engine::new(apk.path()).with_threads(2);
    let src = engine.decompile_class(COLL, DecompileOptions { lang: SourceLang::Java, ..Default::default() }).unwrap().source;

    // Z is field #1 (keeps its name); I #2, Foo #3, Foo$Bar #4 — ArgType
    // order, which disagrees with the descriptors' ASCII order ('I' < 'Z').
    assert!(src.contains("//   field  Kinds.a$2 => Lcom/app/Kinds;->a:I"), "{src}");
    assert!(src.contains("//   field  Kinds.a$3 => Lcom/app/Kinds;->a:Lcom/app/Foo;"), "{src}");
    assert!(src.contains("//   field  Kinds.a$4 => Lcom/app/Kinds;->a:Lcom/app/Foo$Bar;"), "{src}");
    // Methods: Z first (keeps its name), then Object.
    assert!(src.contains("//   method Kinds.m$2 => Lcom/app/Kinds;->m()Ljava/lang/Object;"), "{src}");

    // The de-normalized names select the member `dexdec` gave them to, by the
    // same order (a field query does not need `exact`).
    let mut a2 = Vec::new();
    let q = names::member_query("field", Some(COLL), false, Some("a$2"), false).unwrap();
    engine.find_refs(&Query::Field(q), |b| a2.extend(b.results.iter().map(|r| r.line()))).unwrap();
    assert!(a2.is_empty() || a2.iter().all(|l| l.contains("Kinds;->a:")), "{a2:?}");
}

#[test]
fn non_exact_fallback_names_match_whole_members_only() {
    // `a$2` de-normalizes to `a`; a substring match on `Lcom/app/Collision;`
    // would also hit `abc`, so the fallback must match the name whole.
    const OBJ: &str = "Ljava/lang/Object;";
    const COLL: &str = "Lcom/app/Collision;";

    let mut d = DexBuilder::new();
    d.type_(OBJ).type_(COLL).field(COLL, "a", "I").field(COLL, "abc", "I").method(COLL, "use", "V", &[]);
    let mut ids = d.resolve();
    let mut code = Vec::new();
    code.extend_from_slice(&[0x60, 0x00]);
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
    let mut rows = Vec::new();
    // `exact = false` is what the CLI and MCP send by default.
    let q = names::member_query("field", Some(COLL), false, Some("a$2"), false).unwrap();
    engine.find_refs(&Query::Field(q), |b| rows.extend(b.results.iter().map(|r| r.line()))).unwrap();
    assert_eq!(rows, ["classes.dex | Lcom/app/Collision;->use()V | Lcom/app/Collision;->a:I [read]"], "{rows:?}");
}

#[test]
fn callgraph_and_hierarchy_accept_java_style_method_signatures() {
    let apk = temp_apk_from_dex(&make_normalized_dex());
    let engine = Engine::new(apk.path()).with_threads(2);
    let outer = names::format_class_name("com.app.Outer").unwrap();

    // `entry(com.app.Outer.Inner)` has no return type and a normalized nested
    // parameter: it must not fail before the fallback runs.
    let cg = engine.call_graph(&CallQuery::method(outer.clone(), "entry(com.app.Outer.Inner)", Direction::Callers)).unwrap();
    assert!(cg.rows.iter().any(|r| r.method == "Lcom/app/Outer;->entry(Lcom/app/Outer$Inner;)V"), "{:?}", cg.lines());

    // The hierarchy marker accepts a return-less signature too.
    let h = engine
        .hierarchy(&HierarchyQuery {
            class: "Lcom/app/Outer$1;".into(),
            direction: Lineage::Supers,
            depth: 3,
            max_nodes: 50,
            method: Some("onEvent(int)".into()),
        })
        .unwrap();
    assert!(h.lines().first().is_some_and(|l| l.contains("[defines onEvent(I)V]")), "{:?}", h.lines());
}

#[test]
fn compound_rules_signature_parameter_types_and_outer_closure_header_map() {
    let apk = temp_apk_from_dex(&make_normalized_dex());
    let engine = Engine::new(apk.path()).with_threads(2);
    let java_opts = DecompileOptions { lang: SourceLang::Java, ..Default::default() };

    // 1. Outer class closure decompilation emits `[dex-map]` entries for its nested
    //    anonymous (`Outer$1` -> `Outer.Anonymous1`) and InnerClass-renamed (`Outer$a` -> `Outer.RealInner`) classes.
    let outer = engine.decompile_class("Lcom/app/Outer;", java_opts).unwrap();
    assert!(outer.source.starts_with("// [dex-map]\n"), "{}", outer.source);
    assert!(outer.source.contains("//   class  Outer.Anonymous1 => Lcom/app/Outer$1;"), "{}", outer.source);
    assert!(outer.source.contains("//   class  Outer.RealInner => Lcom/app/Outer$a;"), "{}", outer.source);

    // 2. Method-only decompilation on `Lcom/Cpkg/do/if;` with `--method Cwhile`
    //    includes `Cwhile` in `[dex-map]` and omits unselected `C1a`.
    let single_m = engine.decompile_class_method("Lcom/Cpkg/do/if;", java_opts, Some("Cwhile")).unwrap();
    assert!(single_m.source.contains("//   method Cif.Cwhile => Lcom/Cpkg/do/if;->while(I)I"), "{}", single_m.source);
    assert!(!single_m.source.contains("C1a"), "unselected method should not appear in method-only output:\n{}", single_m.source);

    // 3. Signature with normalized nested parameter type `entry(com.app.Outer.Inner)`
    //    resolves parameter `Lcom/app/Outer/Inner;` -> `Lcom/app/Outer$Inner;`.
    let entry_m = engine.decompile_class_method("Lcom/app/Outer;", java_opts, Some("entry(com.app.Outer.Inner)")).unwrap();
    assert_eq!(entry_m.methods, ["entry(Lcom/app/Outer$Inner;)V"]);

    let mut sig_hits = Vec::new();
    let q_sig = names::member_query("method", None, false, Some("com.app.Outer->entry(com.app.Outer.Inner)"), true).unwrap();
    assert!(names::denormalize_query(&Query::Method(q_sig)).is_some());

    // 4. Compound `Query::All` combining normalized method + normalized field queries falls back cleanly.
    let rule = names::parse_rule("method:com.other.Cswitch->Ccase & field:com.Cpkg.Cdo.Cif->Cfor").unwrap();
    engine.find_refs(&rule, |b| sig_hits.extend(b.results.iter().map(|r| r.line()))).unwrap();
    assert_eq!(sig_hits, ["classes.dex | Lcom/Cpkg/do/if;->while(I)I | Lcom/other/switch;->case()I, Lcom/Cpkg/do/if;->for:I [read]"]);
}
