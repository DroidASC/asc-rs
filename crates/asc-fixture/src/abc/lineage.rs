//! A program of five records whose calls go through class inheritance,
//! exported objects and a decorated class, for call graph tests:
//!
//! - [`LINEAGE_BASE`] `base/Base`: exports class `Base` (`run()`, `stop()`,
//!   static `make()`) and class `Tagged` (`go()`, static `create()`), which
//!   is assigned and then reassigned with the result of a decorator call
//!   (`Tagged = Sealed(Tagged)`);
//! - [`LINEAGE_MIDDLE`] `mid/Middle`: exports class `Middle extends Base`.
//!   Its constructor calls `super()`; `stop()` calls `super.stop()`;
//!   `relay()` calls `this.run()`, which only `Base` lists; the static
//!   `build()` calls `this.make()` and `super.make()`;
//! - [`LINEAGE_LEAF`] `leaf/Leaf`: imports `Middle` and nothing of
//!   `base/Base`. Class `Leaf extends Middle`: its constructor calls
//!   `super()`; `go()` calls `this.run()` (two classes up), `this.stop()`
//!   (one up), `super.run()`, `this.none()` (nowhere) and `this.go()` (its
//!   own). Class `Ext` extends a system class: `super()`, `this.missing()`
//!   and `super.onCreate()` lead nowhere in the program;
//! - [`LINEAGE_SERVICE`] `svc/Service`: exports the objects
//!   `api = new Middle()`, `tag = new Tagged()` and `local = new Local()`
//!   (`Local` is a class of the record, with `ping()`), the call result
//!   `one = Middle.build()`, and class `Card extends Tagged`, whose
//!   constructor calls `super()` and whose `show()` calls `this.go()`. Its
//!   function `probe()` calls `local.ping()` and `api.relay()` on the
//!   bindings of the record itself;
//! - [`LINEAGE_APP`] `pages/App`: imports the four bindings of
//!   `svc/Service`, `Tagged` and `Middle`, but not `Base`. `run()` calls
//!   `api.stop()`, `api.run()`, `tag.go()`, `local.ping()`, `one.run()`,
//!   `api.absent()`, `new Tagged()`, `Tagged.create()`, `Middle.make()` and
//!   `new Middle().run()`.

use super::{AbcBuilder, AbcCode, AbcFunction, AbcLiteral, AbcModule, AbcRecord, Asm, LiteralArrayId, Op};
use asc_abc::FunctionKind;

pub const LINEAGE_BASE: &str = "&entry/src/main/ets/base/Base&";
pub const LINEAGE_MIDDLE: &str = "&entry/src/main/ets/mid/Middle&";
pub const LINEAGE_LEAF: &str = "&entry/src/main/ets/leaf/Leaf&";
pub const LINEAGE_SERVICE: &str = "&entry/src/main/ets/svc/Service&";
pub const LINEAGE_APP: &str = "&entry/src/main/ets/pages/App&";

fn request(record: &str) -> String {
    format!("@normalized:N&&{record}")
}

fn function(name: &str, num_vregs: u32, asm: Asm) -> AbcFunction {
    AbcFunction::new(name, AbcCode::new(num_vregs, 3, asm)).kind(FunctionKind::FUNCTION)
}

fn leaf() -> Asm {
    let mut asm = Asm::new();
    asm.op("returnundefined", []);
    asm
}

/// A class literal: `(name, raw method name)` of the instance methods, then
/// of the static ones.
fn class_literal(builder: &mut AbcBuilder, record: &str, instance: &[(&str, &str)], statics: &[(&str, &str)]) -> LiteralArrayId {
    let mut items = Vec::new();
    for (name, method) in instance.iter().chain(statics) {
        items.extend([AbcLiteral::str(name), AbcLiteral::method(record, method), AbcLiteral::MethodAffiliate(0)]);
    }
    items.push(AbcLiteral::Integer(i32::try_from(instance.len()).expect("a handful of methods")));
    builder.literal_array(items)
}

/// Define the class whose constructor is `ctor`, its parent in `parent`.
fn define(asm: &mut Asm, ctor: &str, literal: LiteralArrayId, parent: u8) {
    asm.op("defineclasswithbuffer", [0.into(), Op::method(ctor), literal.into(), 0.into(), parent.into()]);
}

/// `this.name()`.
fn call_this(asm: &mut Asm, name: &str) {
    asm.op("ldthisbyname", [0.into(), Op::str(name)]).op("callarg0", [0.into()]);
}

/// `super.name()`.
fn call_super(asm: &mut Asm, name: &str) {
    asm.op("ldsuperbyname", [0.into(), Op::str(name)]).op("callarg0", [0.into()]);
}

/// A constructor that only calls `super()`.
fn super_constructor() -> Asm {
    let mut asm = Asm::new();
    asm.op("supercallthisrange", [0.into(), 0.into(), 0.into()]).op("returnundefined", []);
    asm
}

/// Call member `name` of regular import `index`.
fn call_import_member(asm: &mut Asm, index: u8, name: &str) {
    asm.op("ldexternalmodulevar", [index.into()]).op("ldobjbyname", [0.into(), Op::str(name)]).op("callarg0", [0.into()]);
}

/// `new` regular import `index`, without arguments: the object is left in
/// the accumulator.
fn new_import(asm: &mut Asm, index: u8) {
    asm.op("ldexternalmodulevar", [index.into()]).op("sta", [0.into()]).op("newobjrange", [0.into(), 1.into(), 0.into()]);
}

fn base_record(builder: &mut AbcBuilder) -> AbcRecord {
    let base = class_literal(builder, LINEAGE_BASE, &[("run", "#~@0>#run"), ("stop", "#~@0>#stop")], &[("make", "#~@0<#make")]);
    let tagged = class_literal(builder, LINEAGE_BASE, &[("go", "#~@1>#go")], &[("create", "#~@1<#create")]);
    let mut main = Asm::new();
    main.op("ldhole", []).op("sta", [0.into()]);
    define(&mut main, "#~@0=#Base", base, 0);
    main.op("stmodulevar", [0.into()]);
    main.op("ldhole", []).op("sta", [0.into()]);
    define(&mut main, "#~@1=#Tagged", tagged, 0);
    main.op("sta", [1.into()]).op("stmodulevar", [1.into()]);
    // `Tagged = Sealed(Tagged)`: what a class decorator compiles to.
    main.op("tryldglobalbyname", [0.into(), Op::str("Sealed")]).op("callarg1", [0.into(), 1.into()]).op("stmodulevar", [1.into()]);
    main.op("returnundefined", []);
    let mut record = AbcRecord::ets_module(
        LINEAGE_BASE,
        "entry",
        &["Base", "Tagged"],
        AbcModule::new().export("Base", "Base").export("Tagged", "Tagged"),
    )
    .function(function("func_main_0", 2, main));
    for name in ["#~@0=#Base", "#~@0>#run", "#~@0>#stop", "#~@0<#make", "#~@1=#Tagged", "#~@1>#go", "#~@1<#create"] {
        record = record.function(function(name, 0, leaf()));
    }
    record
}

fn middle_record(builder: &mut AbcBuilder) -> AbcRecord {
    let module = AbcModule::new().import("Base", "Base", &request(LINEAGE_BASE)).export("Middle", "Middle");
    let literal = class_literal(builder, LINEAGE_MIDDLE, &[("stop", "#~@0>#stop"), ("relay", "#~@0>#relay")], &[("build", "#~@0<#build")]);
    let mut main = Asm::new();
    main.op("ldexternalmodulevar", [0.into()]).op("sta", [0.into()]);
    define(&mut main, "#~@0=#Middle", literal, 0);
    main.op("stmodulevar", [0.into()]).op("returnundefined", []);
    let mut stop = Asm::new();
    call_super(&mut stop, "stop");
    stop.op("returnundefined", []);
    let mut relay = Asm::new();
    call_this(&mut relay, "run");
    relay.op("returnundefined", []);
    let mut build = Asm::new();
    call_this(&mut build, "make");
    call_super(&mut build, "make");
    build.op("returnundefined", []);
    AbcRecord::ets_module(LINEAGE_MIDDLE, "entry", &["Middle"], module)
        .function(function("func_main_0", 1, main))
        .function(function("#~@0=#Middle", 1, super_constructor()))
        .function(function("#~@0>#stop", 0, stop))
        .function(function("#~@0>#relay", 0, relay))
        .function(function("#~@0<#build", 0, build))
}

fn leaf_record(builder: &mut AbcBuilder) -> AbcRecord {
    let module = AbcModule::new()
        .import("Middle", "Middle", &request(LINEAGE_MIDDLE))
        .import("UIAbility", "default", "@ohos:app.ability.UIAbility")
        .export("Leaf", "Leaf");
    let leaf_literal = class_literal(builder, LINEAGE_LEAF, &[("go", "#~@0>#go")], &[]);
    let ext_literal = class_literal(builder, LINEAGE_LEAF, &[("onCreate", "#~@1>#onCreate")], &[]);
    let mut main = Asm::new();
    main.op("ldexternalmodulevar", [0.into()]).op("sta", [0.into()]);
    define(&mut main, "#~@0=#Leaf", leaf_literal, 0);
    main.op("stmodulevar", [0.into()]);
    main.op("ldexternalmodulevar", [1.into()]).op("sta", [0.into()]);
    define(&mut main, "#~@1=#Ext", ext_literal, 0);
    main.op("returnundefined", []);
    let mut go = Asm::new();
    call_this(&mut go, "run");
    call_this(&mut go, "stop");
    call_super(&mut go, "run");
    call_this(&mut go, "none");
    call_this(&mut go, "go");
    go.op("returnundefined", []);
    let mut on_create = Asm::new();
    call_this(&mut on_create, "missing");
    call_super(&mut on_create, "onCreate");
    on_create.op("returnundefined", []);
    AbcRecord::ets_module(LINEAGE_LEAF, "entry", &["Leaf", "Ext"], module)
        .function(function("func_main_0", 1, main))
        .function(function("#~@0=#Leaf", 1, super_constructor()))
        .function(function("#~@0>#go", 0, go))
        .function(function("#~@1=#Ext", 1, super_constructor()))
        .function(function("#~@1>#onCreate", 0, on_create))
}

fn service_record(builder: &mut AbcBuilder) -> AbcRecord {
    let module = AbcModule::new()
        .import("Middle", "Middle", &request(LINEAGE_MIDDLE))
        .import("Tagged", "Tagged", &request(LINEAGE_BASE))
        .export("api", "api")
        .export("tag", "tag")
        .export("one", "one")
        .export("local", "local")
        .export("Card", "Card");
    let local = class_literal(builder, LINEAGE_SERVICE, &[("ping", "#~@0>#ping")], &[]);
    let card = class_literal(builder, LINEAGE_SERVICE, &[("show", "#~@1>#show")], &[]);
    let mut main = Asm::new();
    new_import(&mut main, 0);
    main.op("stmodulevar", [0.into()]);
    new_import(&mut main, 1);
    main.op("stmodulevar", [1.into()]);
    main.op("ldexternalmodulevar", [0.into()]).op("ldobjbyname", [0.into(), Op::str("build")]).op("callarg0", [0.into()]);
    main.op("stmodulevar", [2.into()]);
    main.op("ldhole", []).op("sta", [0.into()]);
    define(&mut main, "#~@0=#Local", local, 0);
    main.op("sta", [0.into()]).op("newobjrange", [0.into(), 1.into(), 0.into()]).op("stmodulevar", [3.into()]);
    main.op("ldexternalmodulevar", [1.into()]).op("sta", [0.into()]);
    define(&mut main, "#~@1=#Card", card, 0);
    main.op("stmodulevar", [4.into()]);
    main.op("definefunc", [0.into(), Op::method("#*#probe"), 0.into()]).op("returnundefined", []);
    let mut show = Asm::new();
    call_this(&mut show, "go");
    show.op("returnundefined", []);
    let mut probe = Asm::new();
    for (binding, name) in [(3u8, "ping"), (0, "relay")] {
        probe.op("ldlocalmodulevar", [binding.into()]).op("ldobjbyname", [0.into(), Op::str(name)]).op("callarg0", [0.into()]);
    }
    probe.op("returnundefined", []);
    AbcRecord::ets_module(LINEAGE_SERVICE, "entry", &["Local", "Card", "probe"], module)
        .function(function("func_main_0", 1, main))
        .function(function("#~@0=#Local", 0, leaf()))
        .function(function("#~@0>#ping", 0, leaf()))
        .function(function("#~@1=#Card", 1, super_constructor()))
        .function(function("#~@1>#show", 0, show))
        .function(function("#*#probe", 0, probe))
}

fn app_record() -> AbcRecord {
    let service = request(LINEAGE_SERVICE);
    let module = AbcModule::new()
        .import("api", "api", &service)
        .import("tag", "tag", &service)
        .import("one", "one", &service)
        .import("local", "local", &service)
        .import("Tagged", "Tagged", &request(LINEAGE_BASE))
        .import("Middle", "Middle", &request(LINEAGE_MIDDLE));
    let mut main = Asm::new();
    main.op("definefunc", [0.into(), Op::method("#*#run"), 0.into()]).op("sta", [0.into()]);
    main.op("lda", [0.into()]).op("callarg0", [0.into()]).op("returnundefined", []);
    let mut run = Asm::new();
    call_import_member(&mut run, 0, "stop");
    call_import_member(&mut run, 0, "run");
    call_import_member(&mut run, 1, "go");
    call_import_member(&mut run, 3, "ping");
    call_import_member(&mut run, 2, "run");
    call_import_member(&mut run, 0, "absent");
    new_import(&mut run, 4);
    call_import_member(&mut run, 4, "create");
    call_import_member(&mut run, 5, "make");
    new_import(&mut run, 5);
    run.op("ldobjbyname", [0.into(), Op::str("run")]).op("callarg0", [0.into()]);
    run.op("returnundefined", []);
    AbcRecord::ets_module(LINEAGE_APP, "entry", &["run"], module)
        .function(function("func_main_0", 1, main))
        .function(function("#*#run", 1, run))
}

/// The program: [`LINEAGE_BASE`], [`LINEAGE_MIDDLE`], [`LINEAGE_LEAF`],
/// [`LINEAGE_SERVICE`] and [`LINEAGE_APP`] in one ABC file.
pub fn class_calls_program() -> AbcBuilder {
    let mut builder = AbcBuilder::new();
    let base = base_record(&mut builder);
    let middle = middle_record(&mut builder);
    let leaf = leaf_record(&mut builder);
    let service = service_record(&mut builder);
    builder.record(app_record()).record(base).record(middle).record(leaf).record(service);
    builder
}
