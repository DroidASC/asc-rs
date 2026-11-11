//! Two programs of what the compiler writes since API 20 and 24.
//!
//! [`annotations_program`] declares annotations (`@interface`) and puts
//! them on functions:
//!
//! - [`MARKS_APP`] `pages/Pay`: class `Pay`. Its constructor carries the
//!   annotation of the class, `@Route({ path: '/pay', tags: ['pay',
//!   'checkout'], level: 2 })`; `open()` carries `@Route` without values and
//!   `@Marked({ note: 'opens /pay' })`, and loads the string `/pay` itself;
//! - [`MARKS_ROUTE`]: the annotation interface `Route` of that module, with
//!   the defaults `path = '/'`, `tags = ['page', 'default']`,
//!   `grid = [['deep', 'page']]`, `level = 1`, `on = true`;
//! - [`MARKS_LIB`] `@ohos/lib/index`, version 1.2.0, and [`MARKS_LIB_MARKED`],
//!   its annotation interface `Marked` with `note = 'none'`;
//! - the compiler's `_ESSlotNumberAnnotation`, on every function.
//!
//! [`callable_names_program`] is one record, [`NAMED_APP`], with the same
//! function compiled both ways: `named(p)` as `--enable-callable-name`
//! does, each method call a load followed by a call that names the method
//! again, and `plain(p)` without. Each reads `p.cut` once, calls `p.cut`
//! twice (once with the callee kept in a register), `this.fold()` once.
//! `named` also has what no compiler writes: a call by name without a load,
//! and one whose accumulator holds another property.

use super::{AbcAnnotation, AbcBuilder, AbcCode, AbcField, AbcFieldValue, AbcFunction, AbcLiteral, AbcModule, AbcRecord, AbcType, Asm, Op};
use asc_abc::FunctionKind;

pub const MARKS_APP: &str = "&entry/src/main/ets/pages/Pay&";
pub const MARKS_ROUTE: &str = "&entry/src/main/ets/pages/Pay&.Route";
pub const MARKS_LIB: &str = "&@ohos/lib/index&1.2.0";
pub const MARKS_LIB_MARKED: &str = "&@ohos/lib/index&1.2.0.Marked";
pub const NAMED_APP: &str = "&entry/src/main/ets/pages/Named&";

const SLOT_NUMBER: &str = "_ESSlotNumberAnnotation";
const STRING: &str = "panda.String";
const STRINGS: &str = "[Lpanda.String;";
const STRING_GRID: &str = "[[Lpanda.String;";
/// Type tag of an element that is an array, as the compiler writes it.
const STRING_ARRAY_TAG: u8 = b'#';

fn function(name: &str, num_vregs: u32, declared_args: u32, asm: Asm) -> AbcFunction {
    AbcFunction::new(name, AbcCode::new(num_vregs, 3 + declared_args, asm))
        .kind(FunctionKind::FUNCTION)
        .annotation(AbcAnnotation::slot_number(0))
}

fn returns() -> Asm {
    let mut asm = Asm::new();
    asm.op("returnundefined", []);
    asm
}

/// See the [module documentation](self).
pub fn annotations_program() -> AbcBuilder {
    let mut builder = AbcBuilder::new();
    builder.foreign_class(STRING).foreign_class(STRINGS).foreign_class(STRING_GRID);
    let tags = builder.literal_array([AbcLiteral::str("pay"), AbcLiteral::str("checkout")]);
    let default_tags = builder.literal_array([AbcLiteral::str("page"), AbcLiteral::str("default")]);
    let row = builder.literal_array([AbcLiteral::str("deep"), AbcLiteral::str("page")]);
    let default_grid = builder.literal_array([AbcLiteral::LiteralArray(row)]);

    let mut open = Asm::new();
    open.op("lda.str", [Op::str("/pay")]).op("sta", [0.into()]).op("returnundefined", []);
    let class = AbcAnnotation::new(MARKS_ROUTE).string("path", "/pay").array("tags", STRING_ARRAY_TAG, tags).element("level", 2);
    let app = AbcRecord::ets_module(MARKS_APP, "entry", &["Pay"], AbcModule::new())
        .function(function("func_main_0", 0, 0, returns()))
        .function(function("#~@0=#Pay", 0, 0, returns()).annotation(class))
        .function(
            function("#~@0>#open", 1, 0, open)
                .annotation(AbcAnnotation::new(MARKS_ROUTE))
                .annotation(AbcAnnotation::new(MARKS_LIB_MARKED).string("note", "opens /pay")),
        );
    let route = AbcRecord::annotation_interface(MARKS_ROUTE)
        .field(AbcField::new("path", AbcType::Record(STRING.to_owned()), AbcFieldValue::String("/".to_owned())))
        .field(AbcField::new("tags", AbcType::Record(STRINGS.to_owned()), AbcFieldValue::Array(default_tags)))
        .field(AbcField::new("grid", AbcType::Record(STRING_GRID.to_owned()), AbcFieldValue::Array(default_grid)))
        .field(AbcField::new("level", AbcType::F64, AbcFieldValue::Wide(1f64.to_bits())))
        .field(AbcField::new("on", AbcType::U1, AbcFieldValue::Int(1)));
    let lib = AbcRecord::ets_module(MARKS_LIB, "@ohos/lib", &[], AbcModule::new()).function(function("func_main_0", 0, 0, returns()));
    let marked = AbcRecord::annotation_interface(MARKS_LIB_MARKED).field(AbcField::new(
        "note",
        AbcType::Record(STRING.to_owned()),
        AbcFieldValue::String("none".to_owned()),
    ));
    builder.record(AbcRecord::annotation_interface(SLOT_NUMBER)).record(app).record(route).record(lib).record(marked);
    builder
}

/// See the [module documentation](self).
pub fn callable_names_program() -> AbcBuilder {
    // Eight locals: `this` is register 10, `p` register 11.
    const THIS: u8 = 10;
    const P: u8 = 11;
    let load = |asm: &mut Asm, object: u8, name: &str| {
        asm.op("lda", [object.into()]).op("ldobjbyname", [0.into(), Op::str(name)]);
    };

    let mut named = Asm::new();
    // const f = p.cut
    load(&mut named, P, "cut");
    named.op("sta", [0.into()]);
    // p.cut(v1, v2)
    load(&mut named, P, "cut");
    named.op("callthis2withname", [2.into(), Op::str("cut"), P.into(), 1.into(), 2.into()]).op("sta", [3.into()]);
    // p.cut(v6), the callee kept in v4 while the arguments are set up
    load(&mut named, P, "cut");
    named.op("sta", [4.into()]).op("lda", [P.into()]).op("sta", [5.into()]).op("lda", [4.into()]);
    named.op("callthisrangewithname", [4.into(), 1.into(), Op::str("cut"), 5.into()]);
    // this.fold()
    load(&mut named, THIS, "fold");
    named.op("callthis0withname", [6.into(), Op::str("fold"), THIS.into()]);
    // Not from a compiler: no load in front, and a load of another property.
    named.op("callthis0withname", [8.into(), Op::str("close"), P.into()]);
    load(&mut named, P, "cut");
    named.op("callthis0withname", [10.into(), Op::str("fold"), P.into()]);
    named.op("returnundefined", []);

    let mut plain = Asm::new();
    load(&mut plain, P, "cut");
    plain.op("sta", [0.into()]);
    load(&mut plain, P, "cut");
    plain.op("callthis2", [2.into(), P.into(), 1.into(), 2.into()]).op("sta", [3.into()]);
    load(&mut plain, P, "cut");
    plain.op("sta", [4.into()]).op("lda", [P.into()]).op("sta", [5.into()]).op("lda", [4.into()]);
    plain.op("callthisrange", [4.into(), 1.into(), 5.into()]);
    load(&mut plain, THIS, "fold");
    plain.op("callthis0", [6.into(), THIS.into()]);
    plain.op("returnundefined", []);

    let mut builder = AbcBuilder::new();
    builder.record(
        AbcRecord::ets_module(NAMED_APP, "entry", &[], AbcModule::new())
            .function(function("func_main_0", 0, 0, returns()))
            .function(function("#*#named", 8, 1, named))
            .function(function("#*#plain", 8, 1, plain)),
    );
    builder.record(AbcRecord::annotation_interface(SLOT_NUMBER));
    builder
}
