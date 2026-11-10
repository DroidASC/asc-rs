//! A small program shaped like ArkTS compiler output, for tests that need
//! "an ABC file" rather than a particular structure.

use asc_abc::FunctionKind;

use super::{AbcAnnotation, AbcBuilder, AbcCode, AbcDebugInfo, AbcFunction, AbcLiteral, AbcModule, AbcRecord, Asm, Catch, Op};

/// Record of the sample's ability.
pub const ENTRY_ABILITY: &str = "&entry/src/main/ets/entryability/EntryAbility&";
/// Record of the sample's page.
pub const INDEX_PAGE: &str = "&entry/src/main/ets/pages/Index&";
/// The string `Index.build` passes to `http.createHttp`.
pub const SAMPLE_API_URL: &str = "https://example.com/api/login?token=";
/// The integer `Index.build` loads with `ldai`: `0x1d4b42`.
pub const SAMPLE_MAGIC: i32 = 1_919_810;

fn function(name: &str, kind: u8, code: AbcCode, slots: u32) -> AbcFunction {
    AbcFunction::new(name, code).kind(kind).annotation(AbcAnnotation::slot_number(slots))
}

fn entry_ability(builder: &mut AbcBuilder) -> AbcRecord {
    let class = builder.literal_array([
        AbcLiteral::str("onCreate"),
        AbcLiteral::method(ENTRY_ABILITY, "#~@0>#onCreate"),
        AbcLiteral::MethodAffiliate(2),
        AbcLiteral::Integer(1),
    ]);
    let module = AbcModule::new()
        .import("UIAbility", "default", "@ohos:app.ability.UIAbility")
        .import("hilog", "default", "@ohos:hilog")
        .export("EntryAbility", "default");

    let mut main = Asm::new();
    main.op("ldexternalmodulevar", [0.into()]).op("sta", [0.into()]);
    main.op("defineclasswithbuffer", [0.into(), Op::method("#~@0=#EntryAbility"), class.into(), 0.into(), 0.into()]);
    main.op("sta", [1.into()]).op("lda", [1.into()]).op("stmodulevar", [0.into()]).op("returnundefined", []);

    let mut constructor = Asm::new();
    constructor.op("ldthis", []).op("return", []);

    // hilog.info(1, "testTag", "Ability onCreate")
    let mut on_create = Asm::new();
    on_create.op("ldexternalmodulevar", [1.into()]).op("sta", [0.into()]);
    on_create.op("lda", [0.into()]).op("ldobjbyname", [0.into(), Op::str("info")]).op("sta", [1.into()]);
    on_create.op("ldai", [1.into()]).op("sta", [2.into()]);
    on_create.op("lda.str", [Op::str("testTag")]).op("sta", [3.into()]);
    on_create.op("lda.str", [Op::str("Ability onCreate")]).op("sta", [4.into()]);
    on_create.op("lda", [1.into()]).op("callthis3", [2.into(), 0.into(), 2.into(), 3.into(), 4.into()]);
    on_create.op("returnundefined", []);
    let on_create_lines = AbcDebugInfo::rows("entry/src/main/ets/entryability/EntryAbility.ets", 6, &[(0, 6), (4, 7), (37, 8)]);

    AbcRecord::ets_module(ENTRY_ABILITY, "entry", &["EntryAbility"], module)
        .function(function("func_main_0", FunctionKind::FUNCTION, AbcCode::new(2, 3, main), 1))
        .function(function("#~@0=#EntryAbility", FunctionKind::FUNCTION, AbcCode::new(0, 3, constructor), 0))
        .function(
            function("#~@0>#onCreate", FunctionKind::NONE, AbcCode::new(5, 5, on_create), 4)
                .debug(on_create_lines.param("want").param("launchParam")),
        )
}

fn index_page(builder: &mut AbcBuilder) -> AbcRecord {
    let class = builder.literal_array([
        AbcLiteral::str("build"),
        AbcLiteral::method(INDEX_PAGE, "#~@0>#build"),
        AbcLiteral::MethodAffiliate(0),
        AbcLiteral::str("aboutToAppear"),
        AbcLiteral::method(INDEX_PAGE, "#~@0>#aboutToAppear"),
        AbcLiteral::MethodAffiliate(0),
        AbcLiteral::Integer(2),
    ]);
    let methods = builder.literal_array([AbcLiteral::str("GET"), AbcLiteral::str("POST"), AbcLiteral::Integer(2), AbcLiteral::Bool(true)]);
    let module = AbcModule::new().import("http", "default", "@ohos:net.http").export("Index", "default");

    let mut main = Asm::new();
    main.op("ldhole", []).op("sta", [0.into()]);
    main.op("defineclasswithbuffer", [0.into(), Op::method("#~@0=#Index"), class.into(), 0.into(), 0.into()]).op("sta", [1.into()]);
    main.op("definefunc", [1.into(), Op::method("#*#helper"), 1.into()]).op("sta", [2.into()]);
    main.op("lda", [1.into()]).op("stmodulevar", [0.into()]).op("returnundefined", []);

    let mut constructor = Asm::new();
    constructor.op("ldthis", []).op("return", []);

    // try { http.createHttp(URL) } catch (e) { console.error("request failed") }
    let mut build = Asm::new();
    build.label("try");
    build.op("ldexternalmodulevar", [0.into()]).op("sta", [0.into()]);
    build.op("lda", [0.into()]).op("ldobjbyname", [0.into(), Op::str("createHttp")]).op("sta", [1.into()]);
    build.op("lda.str", [Op::str(SAMPLE_API_URL)]).op("sta", [2.into()]);
    build.op("lda", [1.into()]).op("callthis1", [2.into(), 0.into(), 2.into()]).op("sta", [3.into()]);
    build.label("try_end").op("jmp", [Op::label("done")]);
    build.label("handler").op("sta", [4.into()]);
    build.op("tryldglobalbyname", [4.into(), Op::str("console")]).op("sta", [0.into()]);
    build.op("lda", [0.into()]).op("ldobjbyname", [5.into(), Op::str("error")]).op("sta", [1.into()]);
    build.op("lda.str", [Op::str("request failed")]).op("sta", [2.into()]);
    build.op("lda", [1.into()]).op("callthis1", [7.into(), 0.into(), 2.into()]);
    build.label("handler_end").label("done");
    build.op("ldai", [SAMPLE_MAGIC.into()]).op("sta", [5.into()]);
    build.op("createarraywithbuffer", [9.into(), methods.into()]);
    build.op("lda", [5.into()]).op("jeqz", [Op::label("skip")]).op("lda.str", [Op::str("nonzero")]);
    build.label("skip").op("returnundefined", []);
    build.catch(Catch::all(("try", "try_end"), ("handler", "handler_end")));
    let build_lines =
        AbcDebugInfo::rows("entry/src/main/ets/pages/Index.ets", 12, &[(0, 12), (12, 13), (25, 14), (27, 16), (54, 18), (72, 19)]);

    // this.ratio = 1.5; this.message = "Hello World"  (`this` is the third argument: v1 + 2)
    let mut about_to_appear = Asm::new();
    about_to_appear.op("fldai", [1.5.into()]).op("stobjbyname", [0.into(), Op::str("ratio"), 3.into()]);
    about_to_appear.op("lda.str", [Op::str("Hello World")]).op("stobjbyname", [2.into(), Op::str("message"), 3.into()]);
    about_to_appear.op("returnundefined", []);

    let mut helper = Asm::new();
    helper.op("lda.str", [Op::str("testTag")]).op("return", []);

    AbcRecord::ets_module(INDEX_PAGE, "entry", &["Index"], module)
        .function(function("func_main_0", FunctionKind::FUNCTION, AbcCode::new(3, 3, main), 2))
        .function(function("#~@0=#Index", FunctionKind::FUNCTION, AbcCode::new(0, 3, constructor), 0))
        .function(function("#~@0>#build", FunctionKind::NONE, AbcCode::new(6, 3, build), 11).debug(build_lines))
        .function(function("#~@0>#aboutToAppear", FunctionKind::NONE, AbcCode::new(1, 3, about_to_appear), 4))
        .function(function("#*#helper", FunctionKind::FUNCTION, AbcCode::new(0, 4, helper), 0))
}

/// The sample program as a builder, so that callers can change the version
/// or the region split before building it. Version 12.0.6.0, one region.
///
/// Records, in file order:
///
/// - `_ESSlotNumberAnnotation`: annotation interface; every function below
///   carries a `SlotNumber` annotation.
/// - [`ENTRY_ABILITY`]: package `entry`, scope names `["EntryAbility"]`,
///   imports `UIAbility` = `default` of `@ohos:app.ability.UIAbility`
///   (regular import 0) and `hilog` = `default` of `@ohos:hilog` (1),
///   exports `EntryAbility` as `default`. Functions:
///   - `func_main_0`: `ldexternalmodulevar 0`, `defineclasswithbuffer`
///     naming `#~@0=#EntryAbility` and the class literal
///     `["onCreate", method #~@0>#onCreate, affiliate 2, 1]`;
///   - `#~@0=#EntryAbility`: the constructor;
///   - `#~@0>#onCreate`: `hilog.info(1, "testTag", "Ability onCreate")` as
///     `ldexternalmodulevar 1`, `ldobjbyname "info"`, `ldai 1`, two
///     `lda.str`, `callthis3`. Debug info: parameters `want` and
///     `launchParam`, file `entry/src/main/ets/entryability/EntryAbility.ets`,
///     rows (pc 0, line 6), (4, 7), (37, 8).
/// - [`INDEX_PAGE`]: package `entry`, scope names `["Index"]`, imports
///   `http` = `default` of `@ohos:net.http` (regular import 0), exports
///   `Index` as `default`. Functions:
///   - `func_main_0`: `defineclasswithbuffer` naming `#~@0=#Index` and the
///     class literal `["build", method, affiliate 0, "aboutToAppear",
///     method, affiliate 0, 2]`, then `definefunc #*#helper`;
///   - `#~@0=#Index`: the constructor;
///   - `#~@0>#build`: a try block around `http.createHttp(`[`SAMPLE_API_URL`]`)`
///     (`ldexternalmodulevar 0`, `ldobjbyname "createHttp"`, `lda.str`,
///     `callthis1`), `jmp` over the catch-all handler
///     (`tryldglobalbyname "console"`, `ldobjbyname "error"`,
///     `lda.str "request failed"`, `callthis1`), then `ldai`
///     [`SAMPLE_MAGIC`], `createarraywithbuffer` of
///     `["GET", "POST", 2, true]`, `jeqz` over `lda.str "nonzero"`.
///     Debug info: file `entry/src/main/ets/pages/Index.ets`, rows
///     (0, 12), (12, 13), (25, 14), (27, 16), (54, 18), (72, 19);
///   - `#~@0>#aboutToAppear`: `fldai 1.5`, `stobjbyname "ratio"`,
///     `lda.str "Hello World"`, `stobjbyname "message"`;
///   - `#*#helper`: `lda.str "testTag"`, `return`.
pub fn sample_program() -> AbcBuilder {
    let mut builder = AbcBuilder::new();
    builder.record(AbcRecord::annotation_interface("_ESSlotNumberAnnotation"));
    let ability = entry_ability(&mut builder);
    let page = index_page(&mut builder);
    builder.record(ability).record(page);
    builder
}

/// [`sample_program`] as bytes.
pub fn make_abc() -> Vec<u8> {
    sample_program().build().bytes
}

/// [`sample_program`] with [`INDEX_PAGE`] in a second region, so that
/// `"testTag"` (used by `onCreate` and by `#*#helper`) has a different id
/// on each side: 3 in region 0 (5 entities), 13 in region 1 (14 entities).
/// In the one-region file it is 3 for both (18 entities).
pub fn make_multi_region_abc() -> Vec<u8> {
    sample_program().split_region_before(INDEX_PAGE).build().bytes
}
