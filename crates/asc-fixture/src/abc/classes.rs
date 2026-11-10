//! A program of three records with class definitions, for hierarchy tests:
//!
//! - [`CLASSES_BASE`] `base/Base`: exports class `Base` (`run()`, static
//!   `make()`), class `Watched` (assigned, then reassigned with the result
//!   of a decorator call: `Watched = ObservedV2(Watched)`), the plain
//!   function `legacy`, and `Either` (assigned `Base`, then `Watched`);
//! - [`CLASSES_INDEX`] `base/Index`: re-exports `Base` from `base/Base`;
//! - [`CLASSES_APP`] `pages/App`: the classes of the table below, defined
//!   in `func_main_0` unless noted.
//!
//! | class | parent |
//! |---|---|
//! | `EntryAbility` (`onCreate()`) | `@ohos:app.ability.UIAbility#default` |
//! | `Local` (`run()`) | none |
//! | `Child` (`run()`) | `Local`, in a register |
//! | `GrandChild` | `Child` |
//! | `Derived` (`run()`) | `Base`, imported through `base/Index` |
//! | `Card` | `Watched`: a reassigned binding |
//! | `AppError` | the global `Error` |
//! | `Lost` | `Gone` of a record the program does not have |
//! | `Spaced` | `base.Base`, a member of the namespace of `base/Base` |
//! | `Legacy` | the function `legacy` |
//! | `Shared` | none; a sendable class |
//! | `Odd` | `nothing`, which `base/Base` does not export |
//! | `Twice` | `Either` |
//! | `Mixed`, in `mix(base)` | the parameter `base` |
//! | `Inner`, in `make()` | `Local`, a captured variable |

use super::{AbcBuilder, AbcCode, AbcFunction, AbcLiteral, AbcModule, AbcRecord, Asm, LiteralArrayId, Op};
use asc_abc::FunctionKind;

pub const CLASSES_APP: &str = "&entry/src/main/ets/pages/App&";
pub const CLASSES_BASE: &str = "&entry/src/main/ets/base/Base&";
pub const CLASSES_INDEX: &str = "&entry/src/main/ets/base/Index&";

fn request(record: &str) -> String {
    format!("@normalized:N&&{record}")
}

fn function(name: &str, num_vregs: u32, declared_args: u32, asm: Asm) -> AbcFunction {
    AbcFunction::new(name, AbcCode::new(num_vregs, 3 + declared_args, asm)).kind(FunctionKind::FUNCTION)
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

fn base_record(builder: &mut AbcBuilder) -> AbcRecord {
    let module = AbcModule::new().export("Base", "Base").export("Watched", "Watched").export("legacy", "legacy").export("Either", "Either");
    let base = class_literal(builder, CLASSES_BASE, &[("run", "#~@0>#run")], &[("make", "#~@0<#make")]);
    let watched = class_literal(builder, CLASSES_BASE, &[], &[]);
    let mut main = Asm::new();
    main.op("ldhole", []).op("sta", [0.into()]);
    define(&mut main, "#~@0=#Base", base, 0);
    main.op("sta", [1.into()]).op("stmodulevar", [0.into()]).op("stmodulevar", [3.into()]);
    main.op("ldhole", []).op("sta", [0.into()]);
    define(&mut main, "#~@1=#Watched", watched, 0);
    main.op("sta", [2.into()]).op("stmodulevar", [1.into()]).op("stmodulevar", [3.into()]);
    // `Watched = ObservedV2(Watched)`: what a class decorator compiles to.
    main.op("tryldglobalbyname", [0.into(), Op::str("ObservedV2")]).op("callarg1", [0.into(), 2.into()]).op("stmodulevar", [1.into()]);
    main.op("definefunc", [0.into(), Op::method("#*#legacy"), 0.into()]).op("stmodulevar", [2.into()]);
    main.op("returnundefined", []);
    AbcRecord::ets_module(CLASSES_BASE, "entry", &["Base", "Watched"], module)
        .function(function("func_main_0", 3, 0, main))
        .function(function("#~@0=#Base", 0, 0, leaf()))
        .function(function("#~@0>#run", 0, 0, leaf()))
        .function(function("#~@0<#make", 0, 0, leaf()))
        .function(function("#~@1=#Watched", 0, 0, leaf()))
        .function(function("#*#legacy", 0, 0, leaf()))
}

/// Only `export { Base } from`.
fn index_record() -> AbcRecord {
    let module = AbcModule::new().indirect_export("Base", "Base", &request(CLASSES_BASE));
    AbcRecord::ets_module(CLASSES_INDEX, "entry", &[], module).function(function("func_main_0", 0, 0, leaf()))
}

/// The scope names of [`CLASSES_APP`]: `@N` in its function names.
const APP_SCOPES: [&str; 17] = [
    "EntryAbility",
    "Local",
    "Child",
    "GrandChild",
    "Derived",
    "Card",
    "AppError",
    "Mixed",
    "Lost",
    "Inner",
    "Spaced",
    "Legacy",
    "Shared",
    "mix",
    "make",
    "Odd",
    "Twice",
];

fn app_record(builder: &mut AbcBuilder) -> AbcRecord {
    // Requests in the order they are first named: 0 the system module, 1 the index, 2 the base, 3 the missing record.
    let module = AbcModule::new()
        .import("UIAbility", "default", "@ohos:app.ability.UIAbility")
        .import("Base", "Base", &request(CLASSES_INDEX))
        .import("Watched", "Watched", &request(CLASSES_BASE))
        .import("legacy", "legacy", &request(CLASSES_BASE))
        .import("Gone", "Gone", &request("&entry/src/main/ets/missing/Gone&"))
        .import("nothing", "nothing", &request(CLASSES_BASE))
        .import("Either", "Either", &request(CLASSES_BASE))
        .namespace_import("base", &request(CLASSES_BASE));
    let empty = class_literal(builder, CLASSES_APP, &[], &[]);
    let ability = class_literal(builder, CLASSES_APP, &[("onCreate", "#~@0>#onCreate")], &[]);
    let local = class_literal(builder, CLASSES_APP, &[("run", "#~@1>#run")], &[]);
    let child = class_literal(builder, CLASSES_APP, &[("run", "#~@2>#run")], &[]);
    let derived = class_literal(builder, CLASSES_APP, &[("run", "#~@4>#run")], &[]);

    let mut main = Asm::new();
    main.op("newlexenv", [1.into()]);
    let import = |main: &mut Asm, index: u8, ctor: &str, literal| {
        main.op("ldexternalmodulevar", [index.into()]).op("sta", [0.into()]);
        define(main, ctor, literal, 0);
    };
    import(&mut main, 0, "#~@0=#EntryAbility", ability);
    main.op("ldhole", []).op("sta", [0.into()]);
    define(&mut main, "#~@1=#Local", local, 0);
    main.op("sta", [1.into()]).op("stlexvar", [0.into(), 0.into()]);
    define(&mut main, "#~@2=#Child", child, 1);
    main.op("sta", [2.into()]);
    define(&mut main, "#~@3=#GrandChild", empty, 2);
    import(&mut main, 1, "#~@4=#Derived", derived);
    import(&mut main, 2, "#~@5=#Card", empty);
    main.op("tryldglobalbyname", [0.into(), Op::str("Error")]).op("sta", [0.into()]);
    define(&mut main, "#~@6=#AppError", empty, 0);
    import(&mut main, 4, "#~@8=#Lost", empty);
    main.op("getmodulenamespace", [2.into()]).op("ldobjbyname", [0.into(), Op::str("Base")]).op("sta", [0.into()]);
    define(&mut main, "#~@a=#Spaced", empty, 0);
    import(&mut main, 3, "#~@b=#Legacy", empty);
    main.op("ldhole", []).op("sta", [0.into()]);
    main.op("callruntime.definesendableclass", [0.into(), Op::method("#~@c=#Shared"), empty.into(), 0.into(), 0.into()]);
    import(&mut main, 5, "#~@f=#Odd", empty);
    import(&mut main, 6, "#~@10=#Twice", empty);
    main.op("definefunc", [0.into(), Op::method("#*#mix"), 1.into()]);
    main.op("definefunc", [0.into(), Op::method("#*#make"), 0.into()]);
    main.op("returnundefined", []);

    // `mix(base)`: one local, so `base` is register 4.
    let mut mix = Asm::new();
    define(&mut mix, "#*@d~@7=#Mixed", empty, 4);
    mix.op("return", []);
    let mut make = Asm::new();
    make.op("ldlexvar", [0.into(), 0.into()]).op("sta", [0.into()]);
    define(&mut make, "#*@e~@9=#Inner", empty, 0);
    make.op("return", []);

    let mut record = AbcRecord::ets_module(CLASSES_APP, "entry", &APP_SCOPES, module)
        .function(function("func_main_0", 3, 0, main))
        .function(function("#*#mix", 1, 1, mix))
        .function(function("#*#make", 1, 0, make));
    let constructors = [
        "#~@0=#EntryAbility",
        "#~@1=#Local",
        "#~@2=#Child",
        "#~@3=#GrandChild",
        "#~@4=#Derived",
        "#~@5=#Card",
        "#~@6=#AppError",
        "#*@d~@7=#Mixed",
        "#~@8=#Lost",
        "#*@e~@9=#Inner",
        "#~@a=#Spaced",
        "#~@b=#Legacy",
        "#~@c=#Shared",
        "#~@f=#Odd",
        "#~@10=#Twice",
    ];
    for name in constructors.into_iter().chain(["#~@0>#onCreate", "#~@1>#run", "#~@2>#run", "#~@4>#run"]) {
        record = record.function(function(name, 0, 0, leaf()));
    }
    record
}

/// The program: [`CLASSES_APP`], [`CLASSES_BASE`] and [`CLASSES_INDEX`] in
/// one ABC file.
pub fn class_hierarchy_program() -> AbcBuilder {
    let mut builder = AbcBuilder::new();
    let base = base_record(&mut builder);
    let app = app_record(&mut builder);
    builder.record(app).record(base).record(index_record());
    builder
}
