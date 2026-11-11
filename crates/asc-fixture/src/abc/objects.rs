//! Two programs for the call graph rules that need more than a class
//! literal, their code shaped as the official compiler emits it.
//!
//! [`handed_objects_program`]: calls on what a function returned or a static
//! property holds.
//!
//! - [`HANDED_KIND`] `kind/Kind`: exports class `Kind` (`own()`), which
//!   extends `KindBase` (`base()`) of the same record;
//! - [`HANDED_STORE`] `store/Store`: imports `Kind`. Exports
//!   - class `Store` (`load()`, `save()`), kept in a captured variable, with
//!     the static methods `getInstance()` (the lazy singleton:
//!     `if (!Store.instance) Store.instance = new Store(); return
//!     Store.instance`), `shared()` (the same on `this`, with `new this()`
//!     and the property `own`), `create()` (`return new Store()`), `pick(a)`
//!     (`a` or a new `Store`), `cached()` (`return Store.cache`, which
//!     `setCache(v)` writes from its parameter) and `relay()`
//!     (`this.getInstance().save()`); its static initializer writes
//!     `instance = undefined` and `ready = new Store()`;
//!   - class `Hub`, with the static methods `open()` (`return new Kind()`)
//!     and `loose()` (`return Hub.spare`; `Hub.spare = new Store()` at
//!     module level, and `poke(o)` writes a property `spare` of its
//!     parameter);
//!   - the functions `make()` (`return new Store()`), `probe()`
//!     (`Store.getInstance().load()`) and `poke(o)`;
//! - [`HANDED_APP`] `pages/App`: imports `Store`, `Hub` and `make`, nothing
//!   of `kind/Kind`. `run()` calls, in this order,
//!   `Store.getInstance().load()`, `Store.shared().save()`,
//!   `Store.create().load()`, `Store.ready.save()`, `Store.instance.load()`,
//!   `Hub.open().base()`, `Hub.open().own()`, `make().load()`,
//!   `Store.pick().load()`, `Store.cached().load()`, `Hub.loose().load()`
//!   and `Store.getInstance().absent()`.
//!
//! [`late_members_program`]: members a class gets after its definition, and
//! `super` in arrow functions.
//!
//! - [`LATE_PANEL`] `late/Panel`: exports class `Frame` (`draw()`, `tick()`,
//!   `paint()`) and class `Panel extends Frame`. The literal of `Panel`
//!   lists `first()` only; after the definition come the accessor `size`,
//!   the method `paint()` (on the prototype), the static method `of()` and
//!   the static initializer. `first()` calls `this.paint()` and
//!   `this.size()`; `paint()` calls `this.first()`, `this.tick()` and
//!   `super.paint()`, and makes an arrow function that calls `super.draw()`
//!   and makes another one that calls `super.tick()`; the getter of `size`
//!   calls `super.tick()`; `of()` calls `this.of()`; the static initializer
//!   calls `this.of()`. The plain function `loose()` and the method `lit()`
//!   of an object have a `super.draw()` no class answers;
//! - [`LATE_SUB`] `late/Sub`: imports `Panel`. Class `Sub extends Panel`:
//!   `go()` calls `this.paint()`, `this.size()` and `Panel.of()`.

use super::{AbcBuilder, AbcCode, AbcFunction, AbcLiteral, AbcModule, AbcRecord, Asm, LiteralArrayId, Op};
use asc_abc::FunctionKind;

pub const HANDED_KIND: &str = "&entry/src/main/ets/kind/Kind&";
pub const HANDED_STORE: &str = "&entry/src/main/ets/store/Store&";
pub const HANDED_APP: &str = "&entry/src/main/ets/pages/App&";
pub const LATE_PANEL: &str = "&entry/src/main/ets/late/Panel&";
pub const LATE_SUB: &str = "&entry/src/main/ets/late/Sub&";

fn request(record: &str) -> String {
    format!("@normalized:N&&{record}")
}

/// A function with `num_vregs` locals and `declared_args` parameters: the
/// registers after the locals are the function, `new.target`, `this` and
/// the parameters.
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

/// `new` the value in the accumulator, without arguments, through register `scratch`.
fn construct(asm: &mut Asm, scratch: u8) {
    asm.op("sta", [scratch.into()]).op("newobjrange", [0.into(), 1.into(), scratch.into()]);
}

/// The accumulator's method `name`, called on it without arguments through
/// register `scratch`: `value.name()`.
fn call_method(asm: &mut Asm, scratch: u8, name: &str) {
    asm.op("sta", [scratch.into()]).op("ldobjbyname", [0.into(), Op::str(name)]).op("callthis0", [0.into(), scratch.into()]);
}

/// `this.name()` / `super.name()`.
fn call_own(asm: &mut Asm, load: &str, name: &str) {
    asm.op(load, [0.into(), Op::str(name)]).op("callarg0", [0.into()]);
}

fn kind_record(builder: &mut AbcBuilder) -> AbcRecord {
    let base = class_literal(builder, HANDED_KIND, &[("base", "#~@0>#base")], &[]);
    let kind = class_literal(builder, HANDED_KIND, &[("own", "#~@1>#own")], &[]);
    let mut main = Asm::new();
    main.op("ldhole", []).op("sta", [0.into()]);
    define(&mut main, "#~@0=#KindBase", base, 0);
    main.op("sta", [0.into()]);
    define(&mut main, "#~@1=#Kind", kind, 0);
    main.op("stmodulevar", [0.into()]).op("returnundefined", []);
    let mut record = AbcRecord::ets_module(HANDED_KIND, "entry", &["KindBase", "Kind"], AbcModule::new().export("Kind", "Kind"))
        .function(function("func_main_0", 1, 0, main));
    for name in ["#~@0=#KindBase", "#~@0>#base", "#~@1=#Kind", "#~@1>#own"] {
        record = record.function(function(name, 0, 0, leaf()));
    }
    record
}

/// `if (!HOLDER.name) HOLDER.name = new MAKER(); return HOLDER.name`, the
/// holder and the class loaded by `holder` and `maker` (into the accumulator).
fn lazy(name: &str, holder: &dyn Fn(&mut Asm), maker: &dyn Fn(&mut Asm)) -> Asm {
    let mut asm = Asm::new();
    holder(&mut asm);
    asm.op("ldobjbyname", [0.into(), Op::str(name)]).op("jnez", [Op::label("made")]);
    holder(&mut asm);
    asm.op("sta", [0.into()]);
    maker(&mut asm);
    construct(&mut asm, 1);
    asm.op("stobjbyname", [0.into(), Op::str(name), 0.into()]);
    asm.label("made");
    holder(&mut asm);
    asm.op("ldobjbyname", [0.into(), Op::str(name)]).op("return", []);
    asm
}

fn store_record(builder: &mut AbcBuilder) -> AbcRecord {
    let module = AbcModule::new()
        .import("Kind", "Kind", &request(HANDED_KIND))
        .export("Store", "Store")
        .export("Hub", "Hub")
        .export("make", "make")
        .export("probe", "probe")
        .export("poke", "poke");
    let statics = [
        ("getInstance", "#~@0<#getInstance"),
        ("shared", "#~@0<#shared"),
        ("create", "#~@0<#create"),
        ("pick", "#~@0<#pick"),
        ("cached", "#~@0<#cached"),
        ("setCache", "#~@0<#setCache"),
        ("relay", "#~@0<#relay"),
    ];
    let store = class_literal(builder, HANDED_STORE, &[("load", "#~@0>#load"), ("save", "#~@0>#save")], &statics);
    let hub = class_literal(builder, HANDED_STORE, &[], &[("open", "#~@1<#open"), ("loose", "#~@1<#loose")]);
    // The class `Store`, as its own code reads it.
    let store_class = |asm: &mut Asm| {
        asm.op("ldlexvar", [0.into(), 0.into()]);
    };

    let mut main = Asm::new();
    main.op("newlexenv", [1.into()]);
    main.op("ldhole", []).op("sta", [0.into()]);
    define(&mut main, "#~@0=#Store", store, 0);
    main.op("sta", [1.into()]).op("stlexvar", [0.into(), 0.into()]);
    // The static initializer runs with the class as `this`.
    main.op("lda", [1.into()]).op("definemethod", [0.into(), Op::method("#~@0>#static_initializer"), 0.into()]);
    main.op("callthis0", [0.into(), 1.into()]);
    main.op("lda", [1.into()]).op("stmodulevar", [0.into()]);
    main.op("ldhole", []).op("sta", [0.into()]);
    define(&mut main, "#~@1=#Hub", hub, 0);
    main.op("sta", [2.into()]).op("stmodulevar", [1.into()]);
    // `Hub.spare = new Store()`.
    main.op("lda", [1.into()]);
    construct(&mut main, 3);
    main.op("stobjbyname", [0.into(), Op::str("spare"), 2.into()]);
    for (index, name) in ["#*#make", "#*#probe", "#*#poke"].into_iter().enumerate() {
        let declared = u8::from(name == "#*#poke");
        main.op("definefunc", [0.into(), Op::method(name), declared.into()]);
        main.op("stmodulevar", [u8::try_from(index + 2).expect("a handful of exports").into()]);
    }
    main.op("returnundefined", []);

    // Two locals: `this` is register 4, the first parameter register 5.
    let this = |asm: &mut Asm| {
        asm.op("lda", [4.into()]);
    };
    let mut initializer = Asm::new();
    initializer.op("ldundefined", []).op("definepropertybyname", [0.into(), Op::str("instance"), 4.into()]);
    store_class(&mut initializer);
    construct(&mut initializer, 0);
    initializer.op("definepropertybyname", [0.into(), Op::str("ready"), 4.into()]).op("returnundefined", []);
    let mut create = Asm::new();
    store_class(&mut create);
    construct(&mut create, 0);
    create.op("return", []);
    let mut pick = Asm::new();
    pick.op("lda", [5.into()]).op("jnez", [Op::label("given")]);
    store_class(&mut pick);
    construct(&mut pick, 0);
    pick.op("return", []).label("given").op("lda", [5.into()]).op("return", []);
    let mut cached = Asm::new();
    store_class(&mut cached);
    cached.op("ldobjbyname", [0.into(), Op::str("cache")]).op("return", []);
    let mut set_cache = Asm::new();
    store_class(&mut set_cache);
    set_cache.op("sta", [0.into()]).op("lda", [5.into()]).op("stobjbyname", [0.into(), Op::str("cache"), 0.into()]);
    set_cache.op("returnundefined", []);
    let mut relay = Asm::new();
    this(&mut relay);
    call_method(&mut relay, 0, "getInstance");
    call_method(&mut relay, 0, "save");
    relay.op("returnundefined", []);

    let hub_class = |asm: &mut Asm| {
        asm.op("ldlocalmodulevar", [1.into()]);
    };
    let mut open = Asm::new();
    open.op("ldexternalmodulevar", [0.into()]);
    construct(&mut open, 0);
    open.op("return", []);
    let mut loose = Asm::new();
    hub_class(&mut loose);
    loose.op("ldobjbyname", [0.into(), Op::str("spare")]).op("return", []);

    let mut probe = Asm::new();
    store_class(&mut probe);
    call_method(&mut probe, 0, "getInstance");
    call_method(&mut probe, 0, "load");
    probe.op("returnundefined", []);
    // `poke(o)`: `o.spare = new Store()`, on an object nobody knows.
    let mut poke = Asm::new();
    store_class(&mut poke);
    construct(&mut poke, 0);
    poke.op("stobjbyname", [0.into(), Op::str("spare"), 5.into()]).op("returnundefined", []);

    let mut record = AbcRecord::ets_module(HANDED_STORE, "entry", &["Store", "Hub"], module)
        .function(function("func_main_0", 4, 0, main))
        .function(function("#~@0>#static_initializer", 2, 0, initializer))
        .function(function("#~@0<#getInstance", 2, 0, lazy("instance", &store_class, &store_class)))
        .function(function("#~@0<#shared", 2, 0, lazy("own", &this, &this)))
        .function(function("#~@0<#create", 2, 0, create.clone()))
        .function(function("#~@0<#pick", 2, 1, pick))
        .function(function("#~@0<#cached", 2, 0, cached))
        .function(function("#~@0<#setCache", 2, 1, set_cache))
        .function(function("#~@0<#relay", 2, 0, relay))
        .function(function("#~@1<#open", 2, 0, open))
        .function(function("#~@1<#loose", 2, 0, loose))
        .function(function("#*#make", 2, 0, create))
        .function(function("#*#probe", 2, 0, probe))
        .function(function("#*#poke", 2, 1, poke));
    for name in ["#~@0=#Store", "#~@0>#load", "#~@0>#save", "#~@1=#Hub"] {
        record = record.function(function(name, 0, 0, leaf()));
    }
    record
}

fn handed_app_record() -> AbcRecord {
    let store = request(HANDED_STORE);
    let module = AbcModule::new().import("Store", "Store", &store).import("Hub", "Hub", &store).import("make", "make", &store);
    let mut main = Asm::new();
    main.op("definefunc", [0.into(), Op::method("#*#run"), 0.into()]).op("callarg0", [0.into()]).op("returnundefined", []);
    let mut run = Asm::new();
    // `IMPORT.getter().name()`.
    let through = |run: &mut Asm, import: u8, getter: &str, name: &str| {
        run.op("ldexternalmodulevar", [import.into()]);
        call_method(run, 0, getter);
        call_method(run, 0, name);
    };
    // `IMPORT.property.name()`.
    let held = |run: &mut Asm, import: u8, property: &str, name: &str| {
        run.op("ldexternalmodulevar", [import.into()]).op("ldobjbyname", [0.into(), Op::str(property)]);
        call_method(run, 0, name);
    };
    through(&mut run, 0, "getInstance", "load");
    through(&mut run, 0, "shared", "save");
    through(&mut run, 0, "create", "load");
    held(&mut run, 0, "ready", "save");
    held(&mut run, 0, "instance", "load");
    through(&mut run, 1, "open", "base");
    through(&mut run, 1, "open", "own");
    run.op("ldexternalmodulevar", [2.into()]).op("callarg0", [0.into()]);
    call_method(&mut run, 0, "load");
    through(&mut run, 0, "pick", "load");
    through(&mut run, 0, "cached", "load");
    through(&mut run, 1, "loose", "load");
    through(&mut run, 0, "getInstance", "absent");
    run.op("returnundefined", []);
    AbcRecord::ets_module(HANDED_APP, "entry", &[], module)
        .function(function("func_main_0", 0, 0, main))
        .function(function("#*#run", 1, 0, run))
}

/// The program: [`HANDED_APP`], [`HANDED_STORE`] and [`HANDED_KIND`] in one
/// ABC file.
pub fn handed_objects_program() -> AbcBuilder {
    let mut builder = AbcBuilder::new();
    let kind = kind_record(&mut builder);
    let store = store_record(&mut builder);
    builder.record(handed_app_record()).record(store).record(kind);
    builder
}

fn panel_record(builder: &mut AbcBuilder) -> AbcRecord {
    let module = AbcModule::new().export("Frame", "Frame").export("Panel", "Panel");
    let frame = class_literal(builder, LATE_PANEL, &[("draw", "#~@0>#draw"), ("tick", "#~@0>#tick"), ("paint", "#~@0>#paint")], &[]);
    let panel = class_literal(builder, LATE_PANEL, &[("first", "#~@1>#first")], &[]);

    let mut main = Asm::new();
    main.op("ldhole", []).op("sta", [0.into()]);
    define(&mut main, "#~@0=#Frame", frame, 0);
    main.op("sta", [0.into()]).op("stmodulevar", [0.into()]);
    define(&mut main, "#~@1=#Panel", panel, 0);
    main.op("sta", [1.into()]).op("ldobjbyname", [0.into(), Op::str("prototype")]).op("sta", [2.into()]);
    // `get size()`.
    main.op("lda.str", [Op::str("size")]).op("sta", [3.into()]).op("ldundefined", []).op("sta", [4.into()]);
    main.op("lda", [2.into()]).op("definemethod", [0.into(), Op::method("#~@1>#size"), 0.into()]).op("sta", [5.into()]);
    main.op("ldfalse", []).op("definegettersetterbyvalue", [2.into(), 3.into(), 5.into(), 4.into()]);
    // `paint()` and `static of()`: the methods of the class body after the accessor.
    main.op("lda", [2.into()]).op("definemethod", [0.into(), Op::method("#~@1>#paint"), 0.into()]);
    main.op("stownbyname", [0.into(), Op::str("paint"), 2.into()]);
    main.op("lda", [1.into()]).op("definemethod", [0.into(), Op::method("#~@1<#of"), 0.into()]);
    main.op("stownbyname", [0.into(), Op::str("of"), 1.into()]);
    main.op("lda", [1.into()]).op("definemethod", [0.into(), Op::method("#~@1>#static_initializer"), 0.into()]);
    main.op("callthis0", [0.into(), 1.into()]);
    main.op("lda", [1.into()]).op("stmodulevar", [1.into()]);
    main.op("definefunc", [0.into(), Op::method("#*#loose"), 0.into()]);
    // `{ lit() { … } }`, defined like a method: its home object is no class.
    main.op("createemptyobject", []).op("sta", [6.into()]);
    main.op("lda", [6.into()]).op("definemethod", [0.into(), Op::method("#*#lit"), 0.into()]);
    main.op("stownbyname", [0.into(), Op::str("lit"), 6.into()]);
    main.op("returnundefined", []);

    let mut first = Asm::new();
    call_own(&mut first, "ldthisbyname", "paint");
    call_own(&mut first, "ldthisbyname", "size");
    first.op("returnundefined", []);
    // One local: `this` is register 3.
    let mut paint = Asm::new();
    paint.op("newlexenv", [1.into()]).op("lda", [3.into()]).op("stlexvar", [0.into(), 0.into()]);
    call_own(&mut paint, "ldthisbyname", "first");
    call_own(&mut paint, "ldthisbyname", "tick");
    call_own(&mut paint, "ldsuperbyname", "paint");
    paint.op("definefunc", [0.into(), Op::method("#~@1>@2*#"), 0.into()]).op("callarg0", [0.into()]).op("returnundefined", []);
    // `() => { super.draw(); return () => super.tick(); }`, `this` read from the captured variable.
    let super_call = |asm: &mut Asm, name: &str| {
        asm.op("ldlexvar", [0.into(), 0.into()]).op("sta", [0.into()]);
        asm.op("ldsuperbyname", [0.into(), Op::str(name)]).op("callthis0", [0.into(), 0.into()]);
    };
    let mut arrow = Asm::new();
    super_call(&mut arrow, "draw");
    arrow.op("definefunc", [0.into(), Op::method("#~@1>@2*@3*#"), 0.into()]).op("return", []);
    let mut inner = Asm::new();
    super_call(&mut inner, "tick");
    inner.op("return", []);
    let mut size = Asm::new();
    call_own(&mut size, "ldsuperbyname", "tick");
    size.op("return", []);
    let mut of = Asm::new();
    call_own(&mut of, "ldthisbyname", "of");
    of.op("returnundefined", []);
    let mut stray = Asm::new();
    call_own(&mut stray, "ldsuperbyname", "draw");
    stray.op("returnundefined", []);

    let mut record = AbcRecord::ets_module(LATE_PANEL, "entry", &["Frame", "Panel", "paint", "later"], module)
        .function(function("func_main_0", 7, 0, main))
        .function(function("#~@1>#first", 0, 0, first))
        .function(function("#~@1>#paint", 1, 0, paint))
        .function(function("#~@1>@2*#", 1, 0, arrow))
        .function(function("#~@1>@2*@3*#", 1, 0, inner))
        .function(function("#~@1>#size", 0, 0, size))
        .function(function("#~@1<#of", 0, 0, of.clone()))
        .function(function("#~@1>#static_initializer", 0, 0, of))
        .function(function("#*#loose", 0, 0, stray.clone()))
        .function(function("#*#lit", 0, 0, stray));
    for name in ["#~@0=#Frame", "#~@0>#draw", "#~@0>#tick", "#~@0>#paint", "#~@1=#Panel"] {
        record = record.function(function(name, 0, 0, leaf()));
    }
    record
}

fn sub_record(builder: &mut AbcBuilder) -> AbcRecord {
    let module = AbcModule::new().import("Panel", "Panel", &request(LATE_PANEL)).export("Sub", "Sub");
    let sub = class_literal(builder, LATE_SUB, &[("go", "#~@0>#go")], &[]);
    let mut main = Asm::new();
    main.op("ldexternalmodulevar", [0.into()]).op("sta", [0.into()]);
    define(&mut main, "#~@0=#Sub", sub, 0);
    main.op("stmodulevar", [0.into()]).op("returnundefined", []);
    let mut go = Asm::new();
    call_own(&mut go, "ldthisbyname", "paint");
    call_own(&mut go, "ldthisbyname", "size");
    go.op("ldexternalmodulevar", [0.into()]).op("ldobjbyname", [0.into(), Op::str("of")]).op("callarg0", [0.into()]);
    go.op("returnundefined", []);
    AbcRecord::ets_module(LATE_SUB, "entry", &["Sub"], module)
        .function(function("func_main_0", 1, 0, main))
        .function(function("#~@0=#Sub", 0, 0, leaf()))
        .function(function("#~@0>#go", 0, 0, go))
}

/// The program: [`LATE_SUB`] and [`LATE_PANEL`] in one ABC file.
pub fn late_members_program() -> AbcBuilder {
    let mut builder = AbcBuilder::new();
    let panel = panel_record(&mut builder);
    let sub = sub_record(&mut builder);
    builder.record(sub).record(panel);
    builder
}
