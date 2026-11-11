//! The reference searches other than `string:` on a synthetic program built
//! for them: every kind, every access class, ids of two regions, wide and
//! prefixed opcodes, the tracker's block rules, malformed code.

use std::path::Path;
use std::sync::atomic::AtomicBool;

use asc_abc::FunctionKind;
use asc_ark_engine::{Access, Engine, EngineError, Pattern, Query, RefRow, RefSite};
use asc_fixture::abc::{AbcBuilder, AbcCode, AbcFunction, AbcLiteral, AbcModule, AbcRecord, Asm, Catch, Op};

const NET: &str = "&entry/src/main/ets/pages/Net&";
const UTIL: &str = "&entry/src/main/ets/util/Util&";
const LIB: &str = "&@ohos/lib/index&1.2.0";
const URL: &str = "https://example.com/api";
/// `0x9e3779b9` as the signed 32-bit integer `ldai` holds.
const GOLDEN: i32 = -1_640_531_527;

fn function(name: &str, num_vregs: u32, declared_args: u32, asm: Asm) -> AbcFunction {
    AbcFunction::new(name, AbcCode::new(num_vregs, 3 + declared_args, asm)).kind(FunctionKind::FUNCTION)
}

/// `acc = <object in reg>.name`, kept in `out`.
fn member(asm: &mut Asm, object: u8, name: &str, out: u8) {
    asm.op("lda", [object.into()]).op("ldobjbyname", [0.into(), Op::str(name)]).op("sta", [out.into()]);
}

fn net_record(builder: &mut AbcBuilder) -> AbcRecord {
    let class = builder.literal_array([
        AbcLiteral::str("load"),
        AbcLiteral::method(NET, "#~@0>#load"),
        AbcLiteral::MethodAffiliate(1),
        AbcLiteral::str("size"),
        AbcLiteral::Getter(asc_fixture::abc::MethodRef::new(NET, "#~@0>#size")),
        AbcLiteral::MethodAffiliate(0),
        AbcLiteral::Integer(2),
    ]);
    let inner = builder.literal_array([AbcLiteral::Integer(7), AbcLiteral::Integer(GOLDEN)]);
    let numbers = builder.literal_array([
        AbcLiteral::Integer(1_919_810),
        AbcLiteral::Double(1.5),
        AbcLiteral::Float(2.5),
        AbcLiteral::str("7"),
        AbcLiteral::LiteralArray(inner),
    ]);
    let options =
        builder.literal_array([AbcLiteral::str("retries"), AbcLiteral::Integer(7), AbcLiteral::str("ratio"), AbcLiteral::Double(0.5)]);
    let module = AbcModule::new()
        .import("http", "default", "@ohos:net.http")
        .import("req", "request", "@ohos:net.http")
        .import("helper", "helper", "@normalized:N&&&entry/src/main/ets/util/Util&")
        .namespace_import("log", "@ohos:hilog")
        .export("Net", "default")
        .indirect_export("fetch", "request", "@ohos:net.http")
        .star_export("@normalized:N&&&@ohos/lib/index&1.2.0");
    let mut module = module;
    module.request("@ohos:side.effect");

    let mut main = Asm::new();
    main.op("ldhole", []).op("sta", [0.into()]);
    main.op("defineclasswithbuffer", [0.into(), Op::method("#~@0=#Net"), class.into(), 0.into(), 0.into()]).op("sta", [1.into()]);
    main.op("definefunc", [1.into(), Op::method("#*#local"), 0.into()]).op("sta", [2.into()]);
    main.op("lda", [2.into()]).op("callarg0", [3.into()]);
    main.op("lda", [1.into()]).op("stmodulevar", [0.into()]).op("returnundefined", []);

    let mut constructor = Asm::new();
    // super(...args), then two own fields.
    constructor.op("supercallthisrange", [0.into(), 0.into(), 0.into()]);
    constructor.op("ldai", [7.into()]).op("definefieldbyname", [0.into(), Op::str("retries"), 2.into()]);
    constructor.op("lda.str", [Op::str(URL)]).op("stthisbyname", [2.into(), Op::str("url")]);
    constructor.op("ldthis", []).op("return", []);

    // The method the tracker tests read: `load(a)`, registers v0..v11, `a` in a3 = v15.
    let mut load = Asm::new();
    load.op("ldexternalmodulevar", [0.into()]).op("sta", [0.into()]);
    member(&mut load, 0, "createHttp", 1);
    load.op("lda", [1.into()]).op("callthis0", [0.into(), 0.into()]).op("sta", [2.into()]);
    member(&mut load, 2, "request", 3);
    load.op("lda.str", [Op::str(URL)]).op("sta", [4.into()]);
    load.op("ldthisbyname", [2.into(), Op::str("cfg")]).op("sta", [5.into()]);
    load.op("lda", [3.into()]).op("callthis2", [4.into(), 2.into(), 4.into(), 5.into()]);
    // console.log(GOLDEN)
    load.op("tryldglobalbyname", [6.into(), Op::str("console")]).op("sta", [6.into()]);
    member(&mut load, 6, "log", 7);
    load.op("ldai", [GOLDEN.into()]).op("sta", [8.into()]);
    load.op("lda", [7.into()]).op("callthis1", [8.into(), 6.into(), 8.into()]);
    // The prologue ends here: a branch. v9 is written after it, v0 was not.
    load.op("lda", [15.into()]).op("jeqz", [Op::label("join")]);
    load.op("ldexternalmodulevar", [1.into()]).op("sta", [9.into()]);
    load.op("lda", [9.into()]).op("callarg1", [10.into(), 4.into()]);
    load.op("lda", [9.into()]);
    load.label("join");
    // The accumulator and v9 do not flow into a jump target …
    load.op("callarg0", [12.into()]);
    load.op("lda", [9.into()]).op("callarg0", [14.into()]);
    // … v0, written only in the prologue, does.
    member(&mut load, 0, "destroy", 10);
    load.op("lda", [10.into()]).op("callthis0", [16.into(), 0.into()]);
    load.op("callthis0withname", [18.into(), Op::str("close"), 2.into()]);
    load.op("returnundefined", []);

    let mut size = Asm::new();
    size.op("createarraywithbuffer", [0.into(), numbers.into()]).op("sta", [0.into()]);
    size.op("createobjectwithbuffer", [1.into(), options.into()]).op("sta", [1.into()]);
    size.op("fldai", [1.5.into()]).op("stobjbyname", [2.into(), Op::str("ratio"), 1.into()]);
    size.op("ldai", [1_919_810.into()]).op("stownbyname", [4.into(), Op::str("magic"), 1.into()]);
    size.op("lda", [1.into()]).op("ldobjbyname", [6.into(), Op::str("ratio")]).op("return", []);

    // Everything else a call can be, one per line.
    let mut local = Asm::new();
    local.op("getmodulenamespace", [2.into()]).op("sta", [0.into()]);
    member(&mut local, 0, "info", 1);
    local.op("lda", [1.into()]).op("callthis1", [0.into(), 0.into(), 4.into()]);
    local.op("tryldglobalbyname", [2.into(), Op::str("Map")]).op("sta", [2.into()]);
    local.op("newobjrange", [3.into(), 1.into(), 2.into()]);
    local.op("ldlexvar", [0.into(), 2.into()]).op("callarg0", [5.into()]);
    local.op("wide.ldexternalmodulevar", [2.into()]).op("sta", [3.into()]);
    local.op("lda", [3.into()]).op("wide.callrange", [2.into(), 4.into()]);
    local.op("ldlocalmodulevar", [0.into()]).op("sta", [3.into()]);
    local.op("lda", [3.into()]).op("ldobjbyname", [7.into(), Op::str("instance")]).op("wide.callthisrange", [1.into(), 3.into()]);
    local.op("ldglobal", []).op("ldobjbyname", [9.into(), Op::str("setTimeout")]).op("callarg1", [11.into(), 4.into()]);
    local.op("lda", [4.into()]).op("ldobjbyindex", [13.into(), 3.into()]).op("callarg0", [15.into()]);
    local.op("lda.str", [Op::str("key")]).op("ldobjbyvalue", [17.into(), 4.into()]).op("callarg0", [19.into()]);
    local.op("lda", [5.into()]).op("ldobjbyvalue", [21.into(), 4.into()]).op("callarg0", [23.into()]);
    local.op("ldsuperbyname", [25.into(), Op::str("aboutToAppear")]).op("callthis0", [27.into(), 6.into()]);
    local.op("add2", [29.into(), 0.into()]).op("callarg0", [30.into()]);
    local.op("ldglobalvar", [32.into(), Op::str("legacy")]).op("stglobalvar", [33.into(), Op::str("legacy")]);
    local.op("trystglobalbyname", [34.into(), Op::str("counter")]);
    local.op("definepropertybyname", [35.into(), Op::str("retries"), 0.into()]);
    local.op("stsuperbyname", [37.into(), Op::str("url"), 0.into()]);
    local.op("apply", [39.into(), 0.into(), 1.into()]);
    local.op("returnundefined", []);

    // A handler is a block leader too.
    let mut guarded = Asm::new();
    guarded.op("ldexternalmodulevar", [0.into()]).op("sta", [0.into()]);
    guarded.label("try").op("ldexternalmodulevar", [1.into()]).op("sta", [1.into()]);
    guarded.op("lda", [1.into()]).op("callarg0", [0.into()]);
    guarded.label("try_end").op("returnundefined", []);
    guarded.label("handler").op("sta", [2.into()]);
    guarded.op("lda", [1.into()]).op("callarg0", [2.into()]);
    guarded.op("lda", [0.into()]).op("callarg0", [4.into()]);
    guarded.label("handler_end").op("returnundefined", []);
    guarded.catch(Catch::all(("try", "try_end"), ("handler", "handler_end")));

    // Decodes for two instructions, then an undefined opcode.
    let mut broken = Asm::new();
    broken.op("tryldglobalbyname", [0.into(), Op::str("console")]).op("ldobjbyname", [1.into(), Op::str("log")]).raw(&[0xff, 0x00]);

    AbcRecord::ets_module(NET, "entry", &["Net"], module)
        .function(function("func_main_0", 4, 0, main))
        .function(function("#~@0=#Net", 1, 0, constructor))
        .function(function("#~@0>#load", 12, 1, load))
        .function(function("#~@0>#size", 2, 0, size))
        .function(function("#*#local", 7, 0, local))
        .function(function("#*#guarded", 3, 0, guarded))
        .function(function("#*#broken", 1, 0, broken))
}

/// A second record (and, in the split build, a second region) that uses the
/// same names with other ids.
fn util_record() -> AbcRecord {
    let module = AbcModule::new().import("http", "default", "@ohos:net.http").export("helper", "helper");
    let mut main = Asm::new();
    main.op("definefunc", [0.into(), Op::method("#*#helper"), 1.into()]).op("stmodulevar", [0.into()]);
    main.op("definefunc", [1.into(), Op::method_in(NET, "#*#local"), 0.into()]).op("returnundefined", []);
    let mut helper = Asm::new();
    helper.op("lda.str", [Op::str("padding so that ids differ")]);
    helper.op("ldexternalmodulevar", [0.into()]).op("ldobjbyname", [0.into(), Op::str("request")]).op("callarg1", [2.into(), 3.into()]);
    helper.op("tryldglobalbyname", [4.into(), Op::str("console")]).op("ldobjbyname", [5.into(), Op::str("log")]).op("callarg0", [7.into()]);
    helper.op("ldai", [GOLDEN.into()]).op("return", []);
    AbcRecord::ets_module(UTIL, "entry", &[], module).function(function("func_main_0", 1, 0, main)).function(function(
        "#*#helper",
        0,
        1,
        helper,
    ))
}

fn program() -> AbcBuilder {
    let mut builder = AbcBuilder::new();
    let net = net_record(&mut builder);
    builder.record(net).record(util_record()).record(AbcRecord::ets_module(LIB, "lib", &[], AbcModule::new()));
    builder
}

fn open(dir: &Path, bytes: &[u8]) -> Engine {
    let path = dir.join("modules.abc");
    std::fs::write(&path, bytes).unwrap();
    Engine::open(&path).unwrap()
}

fn rows(engine: &Engine, query: &Query) -> (Vec<RefRow>, Option<String>) {
    let mut rows = Vec::new();
    let mut error = None;
    engine
        .find_refs(query, &AtomicBool::new(false), &mut |batch| {
            rows.extend(batch.rows);
            error = batch.error;
        })
        .unwrap();
    (rows, error)
}

/// `function | text`, with the record only when it is not [`NET`].
fn short(row: &RefRow) -> String {
    let record = if row.record == NET { String::new() } else { format!("{} ", row.record) };
    match &row.site {
        RefSite::Code { function, .. } => format!("{record}{function} | {}", row.text),
        RefSite::Field { name } => format!("{record}field {name} | {}", row.text),
        RefSite::Annotation { function, .. } => format!("{record}{function} | {}", row.text),
    }
}

fn find(engine: &Engine, query: &Query) -> Vec<String> {
    rows(engine, query).0.iter().map(short).collect()
}

fn condition(spec: &str) -> Query {
    Query::condition(spec).unwrap()
}

#[test]
fn properties_carry_their_access() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &program().build().bytes);
    let (found, error) = rows(&engine, &condition("prop:."));
    assert_eq!(
        found.iter().map(short).collect::<Vec<_>>(),
        [
            "#~@0=#Net | definefieldbyname \"retries\", a1 [define]",
            "#~@0=#Net | stthisbyname \"url\" [write]",
            // A load whose value a call in the same block calls is a call …
            "#~@0>#load | ldobjbyname \"createHttp\" [call]",
            "#~@0>#load | ldobjbyname \"request\" [call]",
            // … one that is passed on is a read.
            "#~@0>#load | ldthisbyname \"cfg\" [read]",
            "#~@0>#load | ldobjbyname \"log\" [call]",
            "#~@0>#load | ldobjbyname \"destroy\" [call]",
            "#~@0>#load | callthis0withname \"close\", v2 [call]",
            "#~@0>#size | stobjbyname \"ratio\", v1 [write]",
            "#~@0>#size | stownbyname \"magic\", v1 [define]",
            "#~@0>#size | ldobjbyname \"ratio\" [read]",
            "#*#local | ldobjbyname \"info\" [call]",
            "#*#local | ldobjbyname \"instance\" [call]",
            "#*#local | ldobjbyname \"setTimeout\" [call]",
            "#*#local | ldsuperbyname \"aboutToAppear\" [call]",
            "#*#local | definepropertybyname \"retries\", v0 [define]",
            "#*#local | stsuperbyname \"url\", v0 [write]",
            // Code that does not decode to its end has no blocks to track: its loads stay reads.
            "#*#broken | ldobjbyname \"log\" [read]",
            "&entry/src/main/ets/util/Util& #*#helper | ldobjbyname \"request\" [call]",
            "&entry/src/main/ets/util/Util& #*#helper | ldobjbyname \"log\" [call]",
        ]
    );
    assert_eq!(error.as_deref(), Some("&entry/src/main/ets/pages/Net&->#*#broken: undefined opcode 0xff at offset 0x8"));
    assert_eq!(found[2].matched, ["createHttp"]);
    assert!(matches!(&found[2].site, RefSite::Code { restored, pc: 0x6, .. } if restored == "Net.load"), "{:?}", found[2].site);

    // Each filter keeps its own rows, and together they are all of them.
    let with = |access| find(&engine, &Query::Prop { name: Pattern::regex(".").unwrap(), access: Some(access) });
    let label = |access: Access| format!(" [{access}]");
    for access in Access::ALL {
        let kept = with(access);
        assert!(!kept.is_empty() && kept.iter().all(|row| row.ends_with(&label(access))), "{access}: {kept:?}");
    }
    assert_eq!(Access::ALL.map(|access| with(access).len()), [3, 3, 3, 11]);

    // The three ways to name it.
    let named = |name: Pattern| find(&engine, &Query::Prop { name, access: None }).len();
    assert_eq!((named(Pattern::exact("request")), named(Pattern::exact("reques")), named(Pattern::contains("reques"))), (2, 0, 2));
    assert_eq!(named(Pattern::regex("^(url|ratio)$").unwrap()), 4);
    assert_eq!(find(&engine, &condition("prop:=retries")).len(), 2);
    // A global or a plain string is not a property.
    assert!(find(&engine, &condition("prop:=console")).is_empty() && find(&engine, &condition("prop:^https")).is_empty());
}

#[test]
fn globals_are_read_or_written() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &program().build().bytes);
    assert_eq!(
        find(&engine, &condition("global:.")),
        [
            "#~@0>#load | tryldglobalbyname \"console\" [read]",
            "#*#local | tryldglobalbyname \"Map\" [read]",
            "#*#local | ldglobalvar \"legacy\" [read]",
            "#*#local | stglobalvar \"legacy\" [write]",
            "#*#local | trystglobalbyname \"counter\" [write]",
            "#*#broken | tryldglobalbyname \"console\" [read]",
            "&entry/src/main/ets/util/Util& #*#helper | tryldglobalbyname \"console\" [read]",
        ]
    );
    let written = Query::global(Pattern::regex(".").unwrap(), Some(Access::Write)).unwrap();
    assert_eq!(find(&engine, &written), ["#*#local | stglobalvar \"legacy\" [write]", "#*#local | trystglobalbyname \"counter\" [write]"]);
    assert_eq!(find(&engine, &Query::global(Pattern::exact("legacy"), Some(Access::Read)).unwrap()).len(), 1);
    assert!(find(&engine, &condition("global:=log")).is_empty());
    assert!(matches!(Query::global(Pattern::exact("x"), Some(Access::Define)), Err(EngineError::Query(_))));
}

#[test]
fn imports_are_declarations_and_loads() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &program().build().bytes);
    let http = [
        "field moduleRecordIdx | regular import 0: import { default as http } from \"@ohos:net.http\"",
        "field moduleRecordIdx | regular import 1: import { request as req } from \"@ohos:net.http\"",
        "field moduleRecordIdx | indirect export 0: export { request as fetch } from \"@ohos:net.http\"",
        "#~@0>#load | ldexternalmodulevar 0  ; import { default as http } from \"@ohos:net.http\"",
        "#~@0>#load | ldexternalmodulevar 1  ; import { request as req } from \"@ohos:net.http\"",
        "#*#guarded | ldexternalmodulevar 0  ; import { default as http } from \"@ohos:net.http\"",
        "#*#guarded | ldexternalmodulevar 1  ; import { request as req } from \"@ohos:net.http\"",
        "&entry/src/main/ets/util/Util& field moduleRecordIdx | regular import 0: import { default as http } from \"@ohos:net.http\"",
        "&entry/src/main/ets/util/Util& #*#helper | ldexternalmodulevar 0  ; import { default as http } from \"@ohos:net.http\"",
    ];
    assert_eq!(find(&engine, &condition("import:@ohos:net\\.http")), http);
    assert_eq!(find(&engine, &Query::import("@ohos:net.http", true).unwrap()), http);
    // One binding of the module: `request` is regular import 1 and the indirect export.
    assert_eq!(find(&engine, &condition("import:@ohos:net\\.http#request")), [http[1], http[2], http[4], http[6]]);
    let (found, _) = rows(&engine, &condition("import:net#default"));
    assert_eq!(found.iter().map(short).collect::<Vec<_>>(), [http[0], http[3], http[5], http[7], http[8]]);
    assert!(found.iter().all(|row| row.matched == ["@ohos:net.http#default"]));

    // `*` is the namespace: the namespace import, `export *`, and `getmodulenamespace` of the request.
    assert_eq!(
        find(&engine, &condition("import:.#*")),
        [
            "field moduleRecordIdx | namespace import 0: import * as log from \"@ohos:hilog\"",
            "field moduleRecordIdx | star export 0: export * from \"@normalized:N&&&@ohos/lib/index&1.2.0\"",
            "#*#local | getmodulenamespace 2  ; import * as log from \"@ohos:hilog\"",
        ]
    );
    // The wide form, and a request nothing is bound from.
    assert_eq!(
        find(&engine, &condition("import:util/Util")),
        [
            "field moduleRecordIdx | regular import 2: import { helper } from \"@normalized:N&&&entry/src/main/ets/util/Util&\"",
            "#*#local | wide.ldexternalmodulevar 2  ; import { helper } from \"@normalized:N&&&entry/src/main/ets/util/Util&\"",
        ]
    );
    assert_eq!(find(&engine, &condition("import:side")), ["field moduleRecordIdx | request 4: import \"@ohos:side.effect\""]);
    assert!(find(&engine, &condition("import:side#default")).is_empty() && find(&engine, &condition("import:@ohos:nothing")).is_empty());

    // Declarations only: no code row.
    let Query::Import { request, name, .. } = condition("import:@ohos:") else { panic!("an import query") };
    let declarations = find(&engine, &Query::Import { request, name, declarations_only: true });
    assert_eq!(declarations.len(), 6, "{declarations:?}");
    assert!(declarations.iter().all(|row| row.contains("field moduleRecordIdx | ")));

    // The distinct requests, without reading code.
    let requests =
        |pattern: Option<&Pattern>| engine.module_requests(pattern).unwrap().iter().map(|request| request.line(false)).collect::<Vec<_>>();
    assert_eq!(
        requests(None),
        [
            "@normalized:N&&&@ohos/lib/index&1.2.0 | 1 record | *",
            "@normalized:N&&&entry/src/main/ets/util/Util& | 1 record | helper",
            "@ohos:hilog | 1 record | *",
            "@ohos:net.http | 2 records | default, request",
            "@ohos:side.effect | 1 record | -",
        ]
    );
    assert_eq!(requests(Some(&Pattern::regex("^@ohos:net").unwrap())), ["@ohos:net.http | 2 records | default, request"]);
}

#[test]
fn methods_are_found_where_they_become_functions() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &program().build().bytes);
    let class = "func_main_0 | defineclasswithbuffer #~@0=#Net, [ … (+7 more) ], 0, v0  ; Net.constructor";
    assert_eq!(
        find(&engine, &condition("method:.")),
        [
            &format!("{class} ; literal@0x636 [1]=method #~@0>#load (Net.load), [4]=getter #~@0>#size (Net.size)"),
            "func_main_0 | definefunc #*#local, 0  ; local",
            "&entry/src/main/ets/util/Util& func_main_0 | definefunc #*#helper, 1  ; helper",
            // Named by the id of another region's table in the split build.
            "&entry/src/main/ets/util/Util& func_main_0 | definefunc #*#local, 0  ; local",
        ]
    );
    // By raw name, restored name, or a dotted suffix of it; a literal item alone is a row too.
    let load = ["func_main_0 | defineclasswithbuffer literal@0x636 [1]=method #~@0>#load (Net.load)"];
    for name in ["method:=#~@0>#load", "method:=Net.load", "method:=load", "method:^Net\\.load$", "method:>#load"] {
        assert_eq!(find(&engine, &condition(name)), load, "{name}");
    }
    assert_eq!(
        find(&engine, &condition("method:=Net.size")),
        ["func_main_0 | defineclasswithbuffer literal@0x636 [4]=getter #~@0>#size (Net.size)"]
    );
    assert_eq!(find(&engine, &condition("method:=Net.constructor")), [class]);
    assert!(find(&engine, &condition("method:=Net")).is_empty(), "a class is named by its constructor");
    assert!(find(&engine, &condition("method:=oad")).is_empty());
    let (found, _) = rows(&engine, &condition("method:=local"));
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].matched, ["#*#local"]);

    // The record that defines the function, as a result row spells it or by a path suffix.
    let helper = ["&entry/src/main/ets/util/Util& func_main_0 | definefunc #*#helper, 1  ; helper"];
    assert_eq!(find(&engine, &condition(&format!("method:{UTIL}->=#*#helper"))), helper);
    assert_eq!(find(&engine, &condition("method:util/Util->helper")), helper);
    assert_eq!(find(&engine, &condition("method:util/Util.ets->.")), helper);
    assert!(find(&engine, &condition("method:pages/Net->=helper")).is_empty());
    // A function nothing defines by id (the constructor is named by the class instruction only).
    assert!(find(&engine, &condition("method:=func_main_0")).is_empty());
}

#[test]
fn numbers_are_constants_not_bookkeeping() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &program().build().bytes);
    let magic = ["#~@0>#size | createarraywithbuffer literal@0x667 [0]=1919810 (0x1d4b42)", "#~@0>#size | ldai 0x1d4b42 (1919810)"];
    assert_eq!(find(&engine, &condition("number:0x1d4b42")), magic);
    assert_eq!(find(&engine, &condition("number:1919810")), magic);
    assert_eq!(find(&engine, &condition("number:1919000..1920000")), magic);

    // A negative integer, by its value and by its unsigned 32-bit spelling; one of them nested in an array.
    let golden = [
        "#~@0>#load | ldai -1640531527 (u32 0x9e3779b9)",
        "#~@0>#size | createarraywithbuffer literal@0x667 [4][1]=-1640531527 (0x9e3779b9)",
        "&entry/src/main/ets/util/Util& #*#helper | ldai -1640531527 (u32 0x9e3779b9)",
    ];
    for spelling in ["number:-1640531527", "number:0x9e3779b9", "number:2654435769", "number:-0x61c88647", "number:-0x80000000..-1"] {
        assert_eq!(find(&engine, &condition(spelling)), golden, "{spelling}");
    }

    // Floats: `fldai`, DOUBLE and FLOAT items. The integer 7 is found as 7.0 too.
    assert_eq!(
        find(&engine, &condition("number:1.5")),
        ["#~@0>#size | createarraywithbuffer literal@0x667 [1]=1.5", "#~@0>#size | fldai 1.5"]
    );
    assert_eq!(find(&engine, &condition("number:2.5")), ["#~@0>#size | createarraywithbuffer literal@0x667 [2]=2.5"]);
    assert_eq!(find(&engine, &condition("number:0.25..0.75")), ["#~@0>#size | createobjectwithbuffer literal@0x688 [3]=0.5"]);
    let seven = [
        "#~@0=#Net | ldai 7",
        "#~@0>#size | createarraywithbuffer literal@0x667 [4][0]=7",
        "#~@0>#size | createobjectwithbuffer literal@0x688 [1]=7",
    ];
    assert_eq!(find(&engine, &condition("number:7")), seven);
    assert_eq!(find(&engine, &condition("number:7.0")), seven);

    // Not constants: inline-cache slots (12, 18, 39 …), registers (15), the method count 2 of
    // the class literal, the string "7".
    for bookkeeping in ["number:12", "number:18", "number:39", "number:15", "number:2", "number:3"] {
        assert_eq!(find(&engine, &condition(bookkeeping)), [] as [&str; 0], "{bookkeeping}");
    }
    // Ruled out without a scan: the bytes are nowhere in the file.
    assert!(find(&engine, &condition("number:0x7654321")).is_empty());
    assert!(matches!(Query::condition("number:twelve"), Err(EngineError::Query(_))));
}

#[test]
fn calls_resolve_inside_a_block_and_say_where_they_stop() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &program().build().bytes);
    let (found, error) = rows(&engine, &condition("call:."));
    assert_eq!(
        found.iter().map(short).collect::<Vec<_>>(),
        [
            "func_main_0 | callarg0 ; local:#*#local()",
            "#~@0=#Net | supercallthisrange 0, v0 ; super()",
            "#~@0>#load | callthis0 v0 ; import:@ohos:net.http#default.createHttp()",
            // Arguments with a known source are spelled out.
            // … and so is where a called object came from: what `createHttp()` returned.
            "#~@0>#load | callthis2 v2, v4, v5 ; import:@ohos:net.http#default.createHttp().request(\"https://example.com/api\", this.cfg)",
            "#~@0>#load | callthis1 v6, v8 ; global:console.log(-1640531527)",
            // After the branch: a new value, tracked to the end of its block.
            "#~@0>#load | callarg1 v4 ; import:@ohos:net.http#request(\"https://example.com/api\")",
            // At the jump target neither the accumulator nor v9 (written after the prologue) is known …
            "#~@0>#load | callarg0 ; ?()",
            "#~@0>#load | callarg0 ; ?()",
            // … but v0 and v2, written only in the prologue, are.
            "#~@0>#load | callthis0 v0 ; import:@ohos:net.http#default.destroy()",
            "#~@0>#load | callthis0withname \"close\", v2 ; import:@ohos:net.http#default.createHttp().close()",
            "#*#local | callthis1 v0, v4 ; import:@ohos:hilog#*.info(?)",
            "#*#local | newobjrange 1, v2 ; new global:Map()",
            "#*#local | callarg0 ; lex(0,2)()",
            "#*#local | wide.callrange 2, v4  ; v4..v5 ; import:@normalized:N&&&entry/src/main/ets/util/Util&#helper(?, ?)",
            // `this` is the first register of the range, the argument the second.
            "#*#local | wide.callthisrange 1, v3  ; v3..v4 ; module:Net.instance(?)",
            "#*#local | callarg1 v4 ; globalThis.setTimeout(?)",
            "#*#local | callarg0 ; ?[3]()",
            "#*#local | callarg0 ; ?.key()",
            "#*#local | callarg0 ; ?[]()",
            "#*#local | callthis0 v6 ; super.aboutToAppear()",
            "#*#local | callarg0 ; expr()",
            "#*#local | apply v0, v1 ; global:legacy(…)",
            // Inside the try range the value of this block is known; in the handler only
            // what the prologue set.
            "#*#guarded | callarg0 ; import:@ohos:net.http#request()",
            "#*#guarded | callarg0 ; ?()",
            "#*#guarded | callarg0 ; import:@ohos:net.http#default()",
            "&entry/src/main/ets/util/Util& #*#helper | callarg1 a3 ; import:@ohos:net.http#default.request(arg0)",
            "&entry/src/main/ets/util/Util& #*#helper | callarg0 ; global:console.log()",
        ]
    );
    // The function that does not decode has no call rows and is reported.
    assert_eq!(error.as_deref(), Some("&entry/src/main/ets/pages/Net&->#*#broken: undefined opcode 0xff at offset 0x8"));
    assert_eq!(found[2].matched, ["import:@ohos:net.http#default.createHttp"]);

    // The path is what a query matches, so a path can be pasted back.
    let count = |spec: &str| find(&engine, &condition(spec)).len();
    assert_eq!(count("call:^import:@ohos:net\\.http#default\\."), 5);
    assert_eq!(count("call:^import:@ohos:net\\.http.*\\.request$"), 2);
    assert_eq!(count("call:createHttp\\(\\)\\.request$"), 1);
    assert_eq!(count("call:^global:console\\."), 2);
    assert_eq!(count("call:^local:"), 1);
    assert_eq!(count("call:^\\?"), 6);
    assert_eq!(count("call:\\.request$"), 2);
    let pasted = Query::Call(Pattern::exact("import:@ohos:net.http#default.createHttp"));
    assert_eq!(find(&engine, &Query::Call(Pattern::contains("net.http#default.createHttp"))).len(), 3);
    assert_eq!(find(&engine, &pasted), ["#~@0>#load | callthis0 v0 ; import:@ohos:net.http#default.createHttp()"]);
    assert_eq!(find(&engine, &Query::Call(Pattern::exact("super"))), ["#~@0=#Net | supercallthisrange 0, v0 ; super()"]);
    assert!(find(&engine, &condition("call:nothing-like-this")).is_empty());
}

#[test]
fn a_conjunction_is_one_row_per_function() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &program().build().bytes);
    let all = |specs: &[&str]| Query::All(specs.iter().map(|spec| condition(spec)).collect());
    // The location is the first hit of the first condition; each condition lists what it matched.
    let (found, _) = rows(&engine, &all(&["string:^https://", "call:createHttp$"]));
    let [row] = &found[..] else { panic!("one function expected: {found:?}") };
    assert!(matches!(&row.site, RefSite::Code { function, pc: 0x1b, .. } if function == "#~@0>#load"), "{:?}", row.site);
    assert_eq!(
        row.text,
        "string +0x1b lda.str \"https://example.com/api\" && call +0xe callthis0 v0 ; import:@ohos:net.http#default.createHttp()"
    );
    assert_eq!(row.matched, [URL, "import:@ohos:net.http#default.createHttp"]);
    // The order of the conditions is the order of the columns, whichever is tested first.
    let swapped = find(&engine, &all(&["call:createHttp$", "string:^https://"]));
    assert_eq!(
        swapped,
        [
            "#~@0>#load | call +0xe callthis0 v0 ; import:@ohos:net.http#default.createHttp() && string +0x1b lda.str \"https://example.com/api\""
        ]
    );

    // More hits than a row spells out are counted.
    let many = find(&engine, &all(&["import:@ohos:net", "prop:.", "global:=console"]));
    assert_eq!(many.len(), 2, "{many:?}");
    assert!(many[0].starts_with("#~@0>#load | import +0x0 ldexternalmodulevar 0 "), "{many:?}");
    assert!(
        many[0].contains(" && prop +0x6 ldobjbyname \"createHttp\" [call], +0x15 ldobjbyname \"request\" [call] (+4 more) && global +0x"),
        "{many:?}"
    );
    assert!(many[1].starts_with("&entry/src/main/ets/util/Util& #*#helper | import +0x"), "{many:?}");

    // Every condition must hit in the same function; a hit in the record itself is not one.
    assert!(find(&engine, &all(&["string:^https://", "global:=Map"])).is_empty());
    assert!(find(&engine, &all(&["string:^Net$", "call:."])).is_empty());
    assert!(find(&engine, &all(&["number:7", "prop:=nothing"])).is_empty());
    assert_eq!(find(&engine, &all(&["number:7", "prop:=retries"])).len(), 1);
    assert!(find(&engine, &Query::All(Vec::new())).is_empty());
    let nested = engine.find_refs(&Query::All(vec![all(&["number:7"]), condition("prop:.")]), &AtomicBool::new(false), &mut |_| {});
    assert!(matches!(nested, Err(EngineError::Query(_))));
}

/// Every kind, in a form with rows in both records.
const QUERIES: [&str; 12] = [
    "prop:.",
    "prop:=request",
    "global:.",
    "import:.",
    "import:@ohos:net\\.http#default",
    "method:.",
    "method:=local",
    "number:-0x80000000..0xffffffff",
    "number:0x9e3779b9",
    "call:.",
    "call:^import:",
    "string:.",
];

#[test]
fn ids_resolve_in_the_region_of_each_method() {
    let dir = tempfile::tempdir().unwrap();
    let single = open(dir.path(), &program().build().bytes);
    let split_dir = tempfile::tempdir().unwrap();
    // `Util` in a second region: "request", "console", "log" and `#*#local` have other ids there.
    let split = open(split_dir.path(), &program().split_region_before(UTIL).build().bytes);
    assert_eq!(split.abc("modules.abc").unwrap().regions().unwrap().len(), 2);
    // Literal array offsets move with the layout; everything else must be the same.
    let rows_of = |engine: &Engine, spec: &str| {
        let found = find(engine, &condition(spec));
        found
            .into_iter()
            .map(|row| {
                row.split("literal@").map(|part| part.trim_start_matches(|c: char| c.is_ascii_hexdigit() || c == 'x')).collect::<String>()
            })
            .collect::<Vec<_>>()
    };
    for spec in QUERIES {
        let expected = rows_of(&single, spec);
        assert!(
            expected.iter().any(|row| row.starts_with(UTIL)) && expected.iter().any(|row| !row.starts_with(UTIL)),
            "{spec}: {expected:?}"
        );
        assert_eq!(rows_of(&split, spec), expected, "{spec}");
    }
    let conjunction = Query::All(vec![condition("import:@ohos:net"), condition("call:\\.request$"), condition("prop:=log")]);
    assert_eq!(find(&split, &conjunction), find(&single, &conjunction));
    assert_eq!(find(&split, &conjunction).len(), 2);

    // Rows do not depend on the thread count.
    let threaded = open(split_dir.path(), &program().split_region_before(UTIL).build().bytes).with_threads(5);
    let one = open(split_dir.path(), &program().split_region_before(UTIL).build().bytes).with_threads(1);
    for spec in QUERIES {
        assert_eq!(rows(&threaded, &condition(spec)).0, rows(&one, &condition(spec)).0, "{spec}");
    }
}

#[test]
fn damaged_code_never_panics() {
    let original = program().build().bytes;
    let dir = tempfile::tempdir().unwrap();
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut searched = 0;
    for round in 0..150 {
        let mut bytes = original.clone();
        // A few bytes anywhere past the header: code, literal arrays, module records, index tables.
        for _ in 0..1 + round % 6 {
            let at = asc_abc::HEADER_SIZE + (next() as usize) % (bytes.len() - asc_abc::HEADER_SIZE);
            bytes[at] = next() as u8;
        }
        let path = dir.path().join("modules.abc");
        std::fs::write(&path, &bytes).unwrap();
        // A file damaged beyond opening is not this test's subject.
        let Ok(engine) = Engine::open(&path) else { continue };
        for spec in QUERIES {
            // Rows or an error, never a panic.
            let _ = engine.find_refs(&condition(spec), &AtomicBool::new(false), &mut |_| {});
        }
        let _ = engine.module_requests(None);
        let _ =
            engine.find_refs(&Query::All(QUERIES[..4].iter().map(|spec| condition(spec)).collect()), &AtomicBool::new(false), &mut |_| {});
        searched += 1;
    }
    assert!(searched > 50, "only {searched} damaged files opened");
}

/// A `call:` search leaves the callee paths of the records it went through
/// in the engine, and later searches answer from them: the same rows and
/// the same report of what did not decode as an engine that has none, also
/// on damaged files.
#[test]
fn call_searches_answer_alike_from_kept_paths() {
    let original = program().build().bytes;
    let dir = tempfile::tempdir().unwrap();
    let all = |specs: &[&str]| Query::All(specs.iter().map(|spec| condition(spec)).collect());
    let queries = [
        condition("call:."),
        condition("call:^import:"),
        condition("call:^import:@ohos:net\\.http#default\\.createHttp$"),
        condition("call:^\\?"),
        condition("call:nothing-like-this"),
        all(&["string:^https://", "call:createHttp$"]),
        all(&["call:.", "prop:."]),
        all(&["call:^global:", "call:^import:"]),
    ];
    let answers = |engine: &Engine| -> Vec<(Vec<RefRow>, Option<String>)> { queries.iter().map(|query| rows(engine, query)).collect() };
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let (mut searched, mut reported) = (0, 0);
    for round in 0..120 {
        let mut bytes = original.clone();
        // The first round is the program as built; the others damage a few bytes of it.
        for _ in 0..round.min(1) * (1 + round % 4) {
            let at = asc_abc::HEADER_SIZE + (next() as usize) % (bytes.len() - asc_abc::HEADER_SIZE);
            bytes[at] = next() as u8;
        }
        let path = dir.path().join("modules.abc");
        std::fs::write(&path, &bytes).unwrap();
        let Ok(engine) = Engine::open(&path) else { continue };
        let engine = engine.with_threads(1 + round % 3);
        // Nothing kept: each query on an engine that was just emptied.
        let fresh: Vec<_> = queries
            .iter()
            .map(|query| {
                engine.release_analyses();
                rows(&engine, query)
            })
            .collect();
        // A conjunction keeps no paths; the first lone search does, for every later query.
        engine.release_analyses();
        assert_eq!(rows(&engine, &queries[5]), fresh[5], "round {round}");
        let before = engine.memory_use().analyses;
        assert_eq!(rows(&engine, &queries[1]), fresh[1], "round {round}");
        // (A damaged file may have no function left to track.)
        assert!(engine.memory_use().analyses > before || round > 0);
        assert_eq!(answers(&engine), fresh, "round {round}");
        let kept = engine.memory_use().analyses;
        assert_eq!(answers(&engine), fresh, "round {round}");
        assert_eq!(engine.memory_use().analyses, kept, "round {round}: a repeated search computes nothing new");
        assert_eq!(engine.release_analyses(), kept);
        searched += 1;
        reported += usize::from(fresh[0].1.is_some());
    }
    assert!(searched > 50, "only {searched} damaged files opened");
    assert!(reported > 5, "only {reported} files with code that does not decode");
}

#[test]
fn hints_point_at_the_kind_that_has_it() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &program().build().bytes);
    let cancel = AtomicBool::new(false);
    let hints = |query: &Query| {
        assert!(find(&engine, query).is_empty(), "a hint is for a query without results");
        engine.no_results_hints(query, &cancel)
    };
    assert_eq!(
        hints(&Query::string_literal("@ohos:net.http")),
        ["1 module request matches (e.g. @ohos:net.http): imports are not string operands, try `findrefs import`"]
    );
    assert_eq!(hints(&condition("prop:=console")), ["=console is a global name, used 3 times: try `findrefs global`"]);
    assert_eq!(hints(&condition("prop:=local")), ["=local names a function, defined 2 times: try `findrefs method`"]);
    assert_eq!(
        hints(&Query::Prop { name: Pattern::exact("cfg"), access: Some(Access::Write) }),
        ["the property is accessed once in other ways: drop --access"]
    );
    assert_eq!(hints(&condition("global:=createHttp")), ["=createHttp is a property name, used once: try `findrefs prop`"]);
    assert_eq!(
        hints(&condition("method:=createHttp")),
        ["no function is defined under that name, but it is a property name, used once: try `findrefs prop` (--access call for its calls)"]
    );
    assert_eq!(hints(&condition("method:#*#local^1")), ["a raw function name holds regex metacharacters (`*`, `^`): pass it with --exact"]);
    assert_eq!(hints(&condition("import:@ohos:nothing")).len(), 1);
    assert_eq!(hints(&condition("call:nothing-like-this")).len(), 1);
    assert!(hints(&condition("number:0x7654321")).is_empty() && hints(&Query::string_literal("nowhere at all")).is_empty());
}

/// The rows of `query` over the program at `path`, in `entry` only when given.
fn lines_in(engine: &Engine, query: &Query, entry: Option<&str>) -> Vec<String> {
    let mut lines = Vec::new();
    engine
        .find_refs_in(query, entry, &AtomicBool::new(false), &mut |batch| {
            lines.extend(batch.rows.iter().map(|row| row.line(&batch.entry_name)));
        })
        .unwrap();
    lines
}

#[test]
fn long_strings_are_cut_and_show_where_they_match() {
    use asc_fixture::hap::{LONG_FILLER_BYTES, LONG_MARKER, LONG_PAGE, routed_program};
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &routed_program().build().bytes);
    let limit = asc_ark_engine::text::ROW_STRING_BYTES;
    assert!(LONG_FILLER_BYTES > limit);
    let mut matched = Vec::new();
    let mut lines = Vec::new();
    engine
        .find_refs(&Query::string_literal("example.com/far"), &AtomicBool::new(false), &mut |batch| {
            for row in &batch.rows {
                matched.extend(row.matched.iter().map(String::len));
                lines.push(row.line(&batch.entry_name));
            }
        })
        .unwrap();
    // The record's field, the operand and the item of the literal array, each on one bounded line.
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert!(lines.iter().all(|line| line.len() < limit + 600), "{:?}", lines.iter().map(String::len).collect::<Vec<_>>());
    // The search ran on the whole strings, which the rows still carry.
    assert!(matched.iter().all(|&len| len > LONG_FILLER_BYTES), "{matched:?}");
    let at = LONG_FILLER_BYTES + "https://".len();
    let tail = |kind: &str, filler: &str| format!("match at byte {at}: …\"{}{LONG_MARKER}/{kind}", filler.repeat(88));
    assert!(
        lines[0].starts_with(&format!("modules.abc | {LONG_PAGE} field jsonFileContent | - | \"{{\\\"text\\\":\\\"ccc")),
        "{}",
        lines[0]
    );
    let field_at = at + "{\"text\":\"".len();
    assert!(
        lines[0].ends_with(&format!(
            "c\"… (+{} bytes) match at byte {field_at}: …\"{}{LONG_MARKER}/field\\\"}}\"",
            LONG_FILLER_BYTES + "{\"text\":\"".len() + LONG_MARKER.len() + "/field\"}".len() - limit,
            "c".repeat(88)
        )),
        "{}",
        &lines[0][lines[0].len() - 300..]
    );
    assert!(lines[1].starts_with(&format!("modules.abc | {LONG_PAGE}->#*#long+0x0 | long | lda.str \"aaa")), "{}", &lines[1][..120]);
    assert!(
        lines[1].ends_with(&format!(
            "a\"… (+{} bytes) ; {}\"",
            LONG_FILLER_BYTES + LONG_MARKER.len() + "/operand".len() - limit,
            tail("operand", "a")
        )),
        "{}",
        &lines[1][lines[1].len() - 300..]
    );
    assert!(lines[2].contains(" | createarraywithbuffer literal@0x") && lines[2].contains(" [1]=\"bbb"), "{}", &lines[2][..160]);
    assert!(lines[2].ends_with(&format!(
        "b\"… (+{} bytes) {}\"",
        LONG_FILLER_BYTES + LONG_MARKER.len() + "/item".len() - limit,
        tail("item", "b")
    )));
    // A regex is located the same way; a match in the part shown needs no excerpt.
    let by_regex = lines_in(&engine, &Query::string_regex("https://example\\.com/far/op").unwrap(), None);
    assert!(
        by_regex[0].ends_with(&format!("match at byte {LONG_FILLER_BYTES}: …\"{}{LONG_MARKER}/operand\"", "a".repeat(96))),
        "{by_regex:?}"
    );
    let at_start = lines_in(&engine, &Query::string_regex("^aaaa").unwrap(), None);
    assert!(at_start.len() == 1 && at_start[0].ends_with(" bytes)") && !at_start[0].contains("match at byte"), "{at_start:?}");
    // A conjunction row is made of the same texts.
    let both = lines_in(&engine, &condition_pair("string:far/operand", "string:far/item"), None);
    assert!(both.len() == 1 && both[0].len() < 2 * limit + 1200 && both[0].matches("match at byte").count() == 2, "{both:?}");
}

fn condition_pair(first: &str, second: &str) -> Query {
    Query::All(vec![condition(first), condition(second)])
}

#[test]
fn a_search_can_be_kept_to_an_entry_or_a_package() {
    use asc_ark_engine::ListOptions;
    use asc_fixture::hap::{Hap, make_hap};
    let dir = tempfile::tempdir().unwrap();
    let abc = asc_fixture::abc::make_abc();
    std::fs::write(dir.path().join("a.hap"), make_hap(&abc)).unwrap();
    std::fs::write(dir.path().join("b.hsp"), Hap::new().modules_abc(&abc).abc("widgets", &abc).module_json("{}").build()).unwrap();
    std::fs::write(dir.path().join("c.abc"), &abc).unwrap();
    let engine = Engine::open(dir.path()).unwrap();
    let query = Query::string_literal("Hello World");
    let entries = |entry: Option<&str>| -> Vec<String> {
        lines_in(&engine, &query, entry).iter().map(|line| line.split(" | ").next().unwrap().to_owned()).collect()
    };
    assert_eq!(entries(None), ["a.hap/ets/modules.abc", "b.hsp/ets/modules.abc", "b.hsp/ets/widgets.abc", "c.abc"]);
    // A package names all of its entries; an entry is named whole or by a suffix that starts at a `/`.
    assert_eq!(entries(Some("b.hsp")), ["b.hsp/ets/modules.abc", "b.hsp/ets/widgets.abc"]);
    assert_eq!(entries(Some("a.hap")), ["a.hap/ets/modules.abc"]);
    assert_eq!(entries(Some("b.hsp/ets/widgets.abc")), ["b.hsp/ets/widgets.abc"]);
    assert_eq!(entries(Some("ets/widgets.abc")), ["b.hsp/ets/widgets.abc"]);
    assert_eq!(entries(Some("ets/modules.abc")), ["a.hap/ets/modules.abc", "b.hsp/ets/modules.abc"]);
    assert_eq!(entries(Some("c.abc")), ["c.abc"]);
    let none = engine.find_refs_in(&query, Some("b"), &AtomicBool::new(false), &mut |_| panic!("no entry is searched"));
    assert!(matches!(none, Err(EngineError::NoEntry(name)) if name == "b"));

    let listed = |entry: &str| {
        let options = ListOptions { entry: Some(entry.to_owned()), ..ListOptions::default() };
        let mut entries: Vec<String> = engine.list_classes(&options).unwrap().into_iter().map(|record| record.entry).collect();
        entries.dedup();
        entries
    };
    assert_eq!(listed("b.hsp"), ["b.hsp/ets/modules.abc", "b.hsp/ets/widgets.abc"]);
    assert_eq!(listed("c.abc"), ["c.abc"]);
    assert!(matches!(
        engine.list_classes(&ListOptions { entry: Some("nope".into()), ..ListOptions::default() }),
        Err(EngineError::NoEntry(_))
    ));
    assert_eq!(
        engine.module_requests_in(None, Some("a.hap")).unwrap().iter().filter(|request| request.entry != "a.hap/ets/modules.abc").count(),
        0
    );
    assert_eq!(engine.entries_in(Some("b.hsp")).unwrap().len(), 2);

    // A lone package, whose entries carry no prefix, is named by its file name.
    let lone = Engine::open(dir.path().join("b.hsp")).unwrap();
    assert_eq!(lines_in(&lone, &query, Some("b.hsp")).len(), 2);
    assert_eq!(lines_in(&lone, &query, Some("ets/widgets.abc")).len(), 1);
}

#[test]
fn excluded_conditions_take_functions_away() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &program().build().bytes);
    let rule = |spec: &str| Query::rule(spec, None).unwrap();
    let functions = |spec: &str| -> Vec<String> {
        let found = find(&engine, &rule(spec));
        found.into_iter().map(|row| row.split(" | ").next().unwrap().to_owned()).collect()
    };
    // The functions that log, and those among them that do not ask for `request`.
    let logs = functions("global:=console & prop:=log");
    assert_eq!(logs, ["#~@0>#load", "#*#broken", &format!("{UTIL} #*#helper")]);
    assert_eq!(functions("global:=console & prop:=log & !prop:=request"), ["#*#broken"]);
    assert_eq!(functions("global:=console & !prop:=request & prop:=log"), ["#*#broken"]);
    // A condition nothing matches takes nothing away; one everything matches leaves nothing.
    assert_eq!(functions("global:=console & prop:=log & !prop:=nothing & !string:nothing-like-this"), logs);
    assert!(functions("global:=console & !global:.").is_empty());
    // One condition and exclusions: one row per function, as for several conditions.
    let rows = find(&engine, &rule("prop:=request & !global:=console"));
    assert!(rows.is_empty(), "{rows:?}");
    let rows = find(&engine, &rule("number:7 & !prop:=nothing"));
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(rows.iter().all(|row| row.contains(" | number +0x")), "{rows:?}");
    // The same compound from its parts.
    let built = Query::compound(vec![condition("global:=console"), condition("prop:=log")], vec![condition("prop:=request")]).unwrap();
    assert_eq!(find(&engine, &built), find(&engine, &rule("global:=console & prop:=log & !prop:=request")));
    assert!(matches!(Query::compound(Vec::new(), vec![condition("prop:.")]), Err(EngineError::Query(_))));
    assert!(matches!(Query::compound(vec![condition("prop:.")], Vec::new()), Ok(Query::Prop { .. })));
    // An exclusion on its own is no search.
    let alone = engine.find_refs(&Query::Not(Box::new(condition("prop:."))), &AtomicBool::new(false), &mut |_| {});
    assert!(matches!(alone, Err(EngineError::Query(_))));
}

#[test]
fn among_conditions_a_method_names_the_function_itself() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &program().build().bytes);
    let rule = |spec: &str| Query::rule(spec, None).unwrap();
    // Alone it is where the function is defined: a row in the function that makes it.
    assert_eq!(find(&engine, &rule("method:=Net.load")).len(), 1);
    assert!(find(&engine, &rule("method:=Net.load"))[0].starts_with("func_main_0 | defineclasswithbuffer "));
    // With other conditions it is the function of that name.
    assert_eq!(
        find(&engine, &rule("method:=Net.load & string:^https://")),
        ["#~@0>#load | string +0x1b lda.str \"https://example.com/api\""]
    );
    assert!(find(&engine, &rule("method:=Net.size & string:^https://")).is_empty());
    assert_eq!(find(&engine, &rule(&format!("method:{UTIL}->. & global:=console"))).len(), 1);
    // Excluded, it takes the function away.
    let logs = find(&engine, &rule("global:=console & prop:=log & !method:=helper"));
    assert_eq!(logs.len(), 2, "{logs:?}");
    assert!(logs.iter().all(|row| !row.contains("helper")), "{logs:?}");
    // Names alone: the functions, with nothing to show of their code.
    let (named, _) = rows(&engine, &rule("method:^Net\\. & !method:=size"));
    assert_eq!(named.iter().map(short).collect::<Vec<_>>(), ["#~@0=#Net | method", "#~@0>#load | method"]);
    assert!(named.iter().all(|row| row.sites.is_empty() && matches!(row.site, RefSite::Code { pc: 0, .. })));
    assert!(find(&engine, &rule("method:=Net.load & method:=Net.size")).is_empty());
    // Rows do not depend on the thread count.
    let one = open(dir.path(), &program().build().bytes).with_threads(1);
    for spec in ["global:=console & prop:=log & !prop:=request", "method:^Net\\. & !method:=size", "method:. & prop:. & !number:7"] {
        assert_eq!(find(&one, &rule(spec)), find(&engine, &rule(spec)), "{spec}");
    }
}

#[test]
fn context_is_the_listing_around_each_site() {
    use asc_ark_engine::RefContext;
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &program().build().bytes);
    let with = |query: &Query, context: RefContext| -> Vec<String> {
        let mut out = Vec::new();
        engine
            .find_refs(query, &AtomicBool::new(false), &mut |mut batch| {
                engine.fill_context(&batch.entry_name, &mut batch.rows, context);
                out.extend(batch.rows.iter().map(|row| row.text(&batch.entry_name)));
            })
            .unwrap();
        out
    };
    let url = condition("string:^https://example\\.com/api$");
    let found = with(&url, RefContext::Lines(1));
    let row = found.iter().find(|row| row.contains("->#~@0>#load+0x1b ")).unwrap_or_else(|| panic!("{found:?}"));
    let lines: Vec<&str> = row.lines().collect();
    assert_eq!(lines.len(), 5, "{row}");
    assert!(lines[0].ends_with(" | lda.str \"https://example.com/api\""), "{row}");
    assert_eq!(lines[1], "  @ pc 0x1b");
    assert!(lines[2].starts_with("      00") && lines[4].starts_with("      00"), "{row}");
    assert_eq!(lines[3], "  >   001b  lda.str \"https://example.com/api\"");
    // No context: the row alone; zero lines: the sites alone.
    assert!(with(&url, RefContext::None).iter().any(|plain| plain == lines[0]));
    assert!(with(&url, RefContext::Lines(0)).iter().any(|sites| sites.lines().count() == 3 && sites.starts_with(lines[0])));

    // The whole function is the listing getclass prints, and is listed once for consecutive rows in it.
    let listing = engine.get_class(&asc_ark_engine::ClassQuery { record: NET, function: Some("#~@0>#load"), entry: None }).unwrap().text;
    let whole = with(&condition("prop:."), RefContext::Method);
    let in_load: Vec<&String> = whole.iter().filter(|row| row.contains("->#~@0>#load+")).collect();
    assert!(in_load.len() >= 2, "{whole:?}");
    let plain: String = in_load[0].lines().skip(2).map(|line| format!("{}\n", &line[4..])).collect();
    assert_eq!(plain, listing);
    assert_eq!(in_load[0].lines().filter(|line| line.starts_with("  > ")).count(), 1);
    assert_eq!(in_load[1].lines().skip(1).collect::<Vec<_>>().len(), 2, "{}", in_load[1]);
    assert!(in_load[1].ends_with("\n  # the function is listed with the row above"), "{}", in_load[1]);

    // A conjunction marks every site of its conditions; labels and try ranges are lines like any other.
    let both = Query::All(vec![condition("string:^https://"), condition("call:createHttp$")]);
    let [row] = &with(&both, RefContext::Lines(0))[..] else { panic!("one row") };
    assert_eq!(row.lines().nth(1), Some("  @ pc 0xe, pc 0x1b"));
    assert_eq!(row.lines().filter(|line| line.starts_with("  > ")).count(), 2);
    assert!(row.contains("\n  --\n"), "{row}");
    let guarded = with(&Query::All(vec![condition("method:=guarded"), condition("call:.")]), RefContext::Method);
    assert!(
        guarded[0].contains("\n      .try 0 [0004, 000c) catchall -> L_000d\n")
            && guarded[0].contains("\n    L_000d:")
            && guarded[0].contains("  ; handler of try 0"),
        "{}",
        guarded[0]
    );
    // A reference in a record field has no code around it.
    let fields = with(&condition("string:."), RefContext::Lines(2));
    let field_rows: Vec<&String> = fields.iter().filter(|row| row.contains(" field ")).collect();
    assert!(!field_rows.is_empty() && field_rows.iter().all(|row| row.lines().count() == 1), "{field_rows:?}");
}
