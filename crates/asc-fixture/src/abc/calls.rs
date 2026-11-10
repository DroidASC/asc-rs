//! A program of four records that call each other, for call graph tests:
//!
//! - [`CALLS_APP`] `pages/App`: `func_main_0` defines and calls `run`;
//!   `run(p)` calls `helper` three ways (the import, its renamed re-export
//!   `aliased`, the namespace member `util.helper`), `Box.make()`,
//!   `new Box().get()`, `star` (through `export * from`),
//!   `http.createHttp()` (`@ohos:net.http`), `gone()` (a request that names
//!   no record), `p.then()` (an argument: unresolved), `Box.nothing()` (no
//!   such method), and defines the closure `cb`, which calls `helper`;
//! - [`CALLS_UTIL`] `util/Util`: exports `helper` (calls `star` and
//!   `console.log`) and `star`;
//! - [`CALLS_INDEX`] `lib/Index`: only re-exports (`Box` from `lib/Box`,
//!   `helper as aliased` and `*` from `util/Util`);
//! - [`CALLS_BOX`] `lib/Box`: class `Box` with `get()` (calls `this.size()`
//!   and `this.other()`), `size()` and the static `make()` (calls
//!   `this.get()`, which the class object does not have).

use super::{AbcBuilder, AbcCode, AbcFunction, AbcLiteral, AbcModule, AbcRecord, Asm, Op};
use asc_abc::FunctionKind;

pub const CALLS_APP: &str = "&entry/src/main/ets/pages/App&";
pub const CALLS_UTIL: &str = "&entry/src/main/ets/util/Util&";
pub const CALLS_INDEX: &str = "&entry/src/main/ets/lib/Index&";
pub const CALLS_BOX: &str = "&entry/src/main/ets/lib/Box&";

fn request(record: &str) -> String {
    format!("@normalized:N&&{record}")
}

fn function(name: &str, num_vregs: u32, declared_args: u32, asm: Asm) -> AbcFunction {
    AbcFunction::new(name, AbcCode::new(num_vregs, 3 + declared_args, asm)).kind(FunctionKind::FUNCTION)
}

/// Call regular import `index`.
fn call_import(asm: &mut Asm, index: u8) {
    asm.op("ldexternalmodulevar", [index.into()]).op("callarg0", [0.into()]);
}

/// Call member `name` of regular import `index`.
fn call_import_member(asm: &mut Asm, index: u8, name: &str) {
    asm.op("ldexternalmodulevar", [index.into()]).op("ldobjbyname", [0.into(), Op::str(name)]).op("callarg0", [0.into()]);
}

fn app_record() -> AbcRecord {
    let module = AbcModule::new()
        .import("helper", "helper", &request(CALLS_UTIL))
        .import("Box", "Box", &request(CALLS_INDEX))
        .import("star", "star", &request(CALLS_INDEX))
        .import("http", "default", "@ohos:net.http")
        .import("gone", "gone", &request("&entry/src/main/ets/missing/Gone&"))
        .import("aliased", "aliased", &request(CALLS_INDEX))
        .namespace_import("util", &request(CALLS_UTIL));

    let mut main = Asm::new();
    main.op("definefunc", [0.into(), Op::method("#*#run"), 1.into()]).op("sta", [0.into()]);
    main.op("lda", [0.into()]).op("callarg0", [0.into()]).op("returnundefined", []);

    // `run(p)`: two locals, so p is register 5.
    let mut run = Asm::new();
    call_import(&mut run, 0);
    call_import_member(&mut run, 1, "make");
    run.op("ldexternalmodulevar", [1.into()]).op("sta", [0.into()]).op("mov", [1.into(), 0.into()]);
    run.op("newobjrange", [0.into(), 1.into(), 1.into()]).op("ldobjbyname", [0.into(), Op::str("get")]).op("callarg0", [0.into()]);
    call_import(&mut run, 2);
    call_import(&mut run, 5);
    call_import_member(&mut run, 3, "createHttp");
    call_import(&mut run, 4);
    run.op("getmodulenamespace", [0.into()]).op("ldobjbyname", [0.into(), Op::str("helper")]).op("callarg0", [0.into()]);
    run.op("lda", [5.into()]).op("ldobjbyname", [0.into(), Op::str("then")]).op("callarg0", [0.into()]);
    run.op("definefunc", [0.into(), Op::method("#*@0*#cb"), 0.into()]).op("sta", [0.into()]);
    call_import_member(&mut run, 1, "nothing");
    run.op("returnundefined", []);

    let mut cb = Asm::new();
    call_import(&mut cb, 0);
    cb.op("returnundefined", []);

    AbcRecord::ets_module(CALLS_APP, "entry", &["run"], module)
        .function(function("func_main_0", 1, 0, main))
        .function(function("#*#run", 2, 1, run))
        .function(function("#*@0*#cb", 0, 0, cb))
}

fn util_record() -> AbcRecord {
    let module = AbcModule::new().export("helper", "helper").export("star", "star");
    let mut main = Asm::new();
    main.op("definefunc", [0.into(), Op::method("#*#helper"), 0.into()]).op("stmodulevar", [0.into()]);
    main.op("definefunc", [0.into(), Op::method("#*#star"), 0.into()]).op("stmodulevar", [1.into()]);
    main.op("returnundefined", []);
    let mut helper = Asm::new();
    helper.op("ldlocalmodulevar", [1.into()]).op("callarg0", [0.into()]);
    helper.op("tryldglobalbyname", [0.into(), Op::str("console")]).op("ldobjbyname", [0.into(), Op::str("log")]).op("callarg0", [0.into()]);
    helper.op("returnundefined", []);
    let mut star = Asm::new();
    star.op("returnundefined", []);
    AbcRecord::ets_module(CALLS_UTIL, "entry", &[], module)
        .function(function("func_main_0", 0, 0, main))
        .function(function("#*#helper", 0, 0, helper))
        .function(function("#*#star", 0, 0, star))
}

/// Only re-exports: `export { Box } from`, `export { helper as aliased }
/// from`, `export * from`.
fn index_record() -> AbcRecord {
    let module = AbcModule::new()
        .indirect_export("Box", "Box", &request(CALLS_BOX))
        .indirect_export("aliased", "helper", &request(CALLS_UTIL))
        .star_export(&request(CALLS_UTIL));
    let mut main = Asm::new();
    main.op("returnundefined", []);
    AbcRecord::ets_module(CALLS_INDEX, "entry", &[], module).function(function("func_main_0", 0, 0, main))
}

fn box_record(builder: &mut AbcBuilder) -> AbcRecord {
    let literal = builder.literal_array([
        AbcLiteral::str("get"),
        AbcLiteral::method(CALLS_BOX, "#~@0>#get"),
        AbcLiteral::MethodAffiliate(0),
        AbcLiteral::str("size"),
        AbcLiteral::method(CALLS_BOX, "#~@0>#size"),
        AbcLiteral::MethodAffiliate(0),
        AbcLiteral::str("make"),
        AbcLiteral::method(CALLS_BOX, "#~@0<#make"),
        AbcLiteral::MethodAffiliate(0),
        AbcLiteral::Integer(2),
    ]);
    let mut main = Asm::new();
    main.op("ldhole", []).op("sta", [0.into()]);
    main.op("defineclasswithbuffer", [0.into(), Op::method("#~@0=#Box"), literal.into(), 0.into(), 0.into()]).op("sta", [1.into()]);
    main.op("lda", [1.into()]).op("stmodulevar", [0.into()]).op("returnundefined", []);
    let mut leaf = Asm::new();
    leaf.op("returnundefined", []);
    // An instance method: `this.size()` is a method of the class, `this.other()` is not.
    let mut get = Asm::new();
    get.op("ldthisbyname", [0.into(), Op::str("size")]).op("callarg0", [0.into()]);
    get.op("ldthisbyname", [0.into(), Op::str("other")]).op("callarg0", [0.into()]);
    get.op("returnundefined", []);
    // A static method: `this` is the class, which has no `get`.
    let mut make = Asm::new();
    make.op("ldthisbyname", [0.into(), Op::str("get")]).op("callarg0", [0.into()]);
    make.op("returnundefined", []);
    AbcRecord::ets_module(CALLS_BOX, "entry", &["Box"], AbcModule::new().export("Box", "Box"))
        .function(function("func_main_0", 2, 0, main))
        .function(function("#~@0=#Box", 0, 0, leaf.clone()))
        .function(function("#~@0>#get", 0, 0, get))
        .function(function("#~@0>#size", 0, 0, leaf))
        .function(function("#~@0<#make", 0, 0, make))
}

/// The program: [`CALLS_APP`], [`CALLS_UTIL`], [`CALLS_INDEX`] and
/// [`CALLS_BOX`] in one ABC file.
pub fn call_graph_program() -> AbcBuilder {
    let mut builder = AbcBuilder::new();
    let boxed = box_record(&mut builder);
    builder.record(app_record()).record(util_record()).record(index_record()).record(boxed);
    builder
}
