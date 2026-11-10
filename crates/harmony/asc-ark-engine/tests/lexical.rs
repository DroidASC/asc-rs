//! Captured variables in `call:` paths, on synthetic programs: what resolves
//! (one writer, across nested functions, nested and per-iteration
//! environments, through two variables, the wide forms, classes) and what
//! must not (two writers, cycles, environments that cannot be identified,
//! stores that might write the variable).

use std::path::Path;
use std::sync::atomic::AtomicBool;

use asc_abc::FunctionKind;
use asc_ark_engine::{CalleeRoot, Engine, Query, RefSite, ResolutionOptions, Unresolved};
use asc_fixture::abc::{AbcBuilder, AbcCode, AbcFunction, AbcLiteral, AbcModule, AbcRecord, Asm, Catch, Op};

const LEX: &str = "&entry/src/main/ets/pages/Lex&";
const HTTP: &str = "@ohos:net.http";

fn function(name: &str, num_vregs: u32, declared_args: u32, asm: Asm) -> AbcFunction {
    AbcFunction::new(name, AbcCode::new(num_vregs, 3 + declared_args, asm)).kind(FunctionKind::FUNCTION)
}

/// `acc = <the function>`, kept in captured variable `(0, slot)`.
fn define_into(asm: &mut Asm, name: &str, slot: u8) {
    asm.op("definefunc", [0.into(), Op::method(name), 0.into()]).op("stlexvar", [0.into(), slot.into()]);
}

/// Call what captured variable `(level, slot)` holds.
fn call_captured(asm: &mut Asm, level: u8, slot: u8) {
    asm.op("ldlexvar", [level.into(), slot.into()]).op("callarg0", [0.into()]);
}

/// Call member `name` of what captured variable `(level, slot)` holds.
fn call_member(asm: &mut Asm, level: u8, slot: u8, name: &str) {
    asm.op("ldlexvar", [level.into(), slot.into()]).op("ldobjbyname", [0.into(), Op::str(name)]).op("callarg0", [0.into()]);
}

fn leaf() -> Asm {
    let mut asm = Asm::new();
    asm.op("returnundefined", []);
    asm
}

fn open(dir: &Path, builder: &AbcBuilder) -> Engine {
    let path = dir.join("modules.abc");
    std::fs::write(&path, builder.build().bytes).unwrap();
    Engine::open(&path).unwrap()
}

/// The callee path of every call site of `function`, in code order.
fn callees(engine: &Engine, function: &str) -> Vec<String> {
    let mut out = Vec::new();
    engine
        .find_refs(&Query::condition("call:.").unwrap(), &AtomicBool::new(false), &mut |batch| {
            assert_eq!(batch.error, None);
            for mut row in batch.rows {
                if matches!(&row.site, RefSite::Code { function: raw, .. } if raw == function) {
                    out.push(row.matched.swap_remove(0));
                }
            }
        })
        .unwrap();
    out
}

/// One record: `func_main_0` makes an environment, `outer` (a closure of
/// it) another two, `inner` (a closure of `outer`) reads all three.
fn nested() -> AbcBuilder {
    let module = AbcModule::new().import("http", "default", HTTP);
    let mut main = Asm::new();
    // E0: 0 = helper, 1 = a then b, 2 = the import, 3 = never written.
    main.op("newlexenv", [4.into()]);
    define_into(&mut main, "#*#helper", 0);
    main.op("ldexternalmodulevar", [0.into()]).op("stlexvar", [0.into(), 2.into()]);
    define_into(&mut main, "#*#a", 1);
    define_into(&mut main, "#*#b", 1);
    main.op("definefunc", [0.into(), Op::method("#*#outer"), 1.into()]).op("callarg0", [0.into()]);
    call_captured(&mut main, 0, 0);
    main.op("returnundefined", []);

    // `outer(p)`: no locals, so a2 (`this`) is register 2 and p register 3.
    let mut outer = Asm::new();
    // E1: 0 = p, 1 = this.
    outer.op("newlexenv", [2.into()]);
    outer.op("lda", [3.into()]).op("stlexvar", [0.into(), 0.into()]);
    outer.op("lda", [2.into()]).op("stlexvar", [0.into(), 1.into()]);
    call_member(&mut outer, 0, 1, "own");
    call_captured(&mut outer, 1, 0);
    call_captured(&mut outer, 1, 1);
    call_member(&mut outer, 1, 2, "createHttp");
    call_captured(&mut outer, 1, 3);
    call_captured(&mut outer, 5, 0);
    // E2, inside E1: 0 = E0's import, copied.
    outer.op("newlexenv", [1.into()]);
    outer.op("ldlexvar", [2.into(), 2.into()]).op("stlexvar", [0.into(), 0.into()]);
    outer.op("definefunc", [0.into(), Op::method("#*@0*#inner"), 0.into()]).op("callarg0", [0.into()]);
    call_member(&mut outer, 1, 1, "inside");
    outer.op("poplexenv", []);
    call_member(&mut outer, 0, 1, "after");
    outer.op("returnundefined", []);

    let mut inner = Asm::new();
    call_member(&mut inner, 0, 0, "request");
    call_member(&mut inner, 1, 1, "method");
    call_member(&mut inner, 1, 0, "then");
    call_captured(&mut inner, 2, 0);
    inner.op("wide.ldlexvar", [2.into(), 0.into()]).op("callarg0", [0.into()]);
    call_captured(&mut inner, 2, 1);
    inner.op("returnundefined", []);

    let record = AbcRecord::ets_module(LEX, "entry", &["outer"], module)
        .function(function("func_main_0", 0, 0, main))
        .function(function("#*#helper", 0, 0, leaf()))
        .function(function("#*#a", 0, 0, leaf()))
        .function(function("#*#b", 0, 0, leaf()))
        .function(function("#*#outer", 0, 1, outer))
        .function(function("#*@0*#inner", 0, 0, inner));
    let mut builder = AbcBuilder::new();
    builder.record(record);
    builder
}

#[test]
fn one_writer_resolves_across_functions_and_environments() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &nested());
    assert_eq!(callees(&engine, "func_main_0"), ["local:#*#outer", "local:#*#helper"]);
    assert_eq!(
        callees(&engine, "#*#outer"),
        [
            // Its own environment: its own `this`.
            "this.own",
            // One level out, the environment of `func_main_0`.
            "local:#*#helper",
            // Two stores write the variable: not resolved.
            "lex(1,1)",
            "import:@ohos:net.http#default.createHttp",
            // Nothing stores into it; past the environments of the record.
            "lex(1,3)",
            "lex(5,0)",
            "local:#*@0*#inner",
            // Inside the second environment the first is one level out …
            "this.inside",
            // … and current again once the second is popped.
            "this.after",
        ]
    );
    assert_eq!(
        callees(&engine, "#*@0*#inner"),
        [
            // Written from another captured variable, which holds the import.
            "import:@ohos:net.http#default.request",
            // What belongs to the frame of `outer` says so.
            "this@#*#outer.method",
            "arg0@#*#outer.then",
            "local:#*#helper",
            "local:#*#helper",
            "lex(2,1)",
        ]
    );
    // A resolved path is a path: the query matches it like any other.
    let found = |spec: &str| {
        let mut count = 0;
        engine.find_refs(&Query::condition(spec).unwrap(), &AtomicBool::new(false), &mut |batch| count += batch.rows.len()).unwrap();
        count
    };
    assert_eq!((found("call:^import:@ohos:net\\.http#default\\."), found("call:^lex\\("), found("call:^this@")), (2, 4, 1));

    let stats = engine.call_resolution(&ResolutionOptions { records: None, samples: true }, &AtomicBool::new(false)).unwrap();
    assert_eq!((stats.call_sites, stats.captured, stats.captured_resolved), (17, 15, 11));
    let why = |reason| stats.captured_unresolved.get(&reason).copied().unwrap_or(0);
    assert_eq!((why(Unresolved::MultipleWriters), why(Unresolved::NoWriter), why(Unresolved::Outside)), (2, 1, 1));
    assert_eq!((stats.before.get(&CalleeRoot::Lexical), stats.after.get(&CalleeRoot::Lexical)), (Some(&15), Some(&4)));
    assert_eq!((stats.after.get(&CalleeRoot::CapturedThis), stats.after.get(&CalleeRoot::CapturedArgument)), (Some(&1), Some(&1)));
    assert_eq!((stats.scopes.sites, stats.scopes.environments, stats.scopes.resolved_slots, stats.scopes.multi_writer_slots), (3, 3, 5, 1));
    // Every resolved one names its one store.
    let sample = stats.samples.iter().find(|sample| sample.callee == "this@#*#outer.method").unwrap();
    assert_eq!((sample.function.as_str(), sample.level, sample.slot, sample.writer.as_str()), ("#*@0*#inner", 1, 1, "#*#outer"));
    assert_eq!(stats.samples.len(), 11);
}

/// A loop that makes an environment per iteration, a variable written from
/// itself, two variables written from each other, the wide instructions.
fn shapes() -> AbcBuilder {
    let module = AbcModule::new().import("http", "default", HTTP);
    let mut main = Asm::new();
    for name in ["#*#looping", "#*#cycle", "#*#wide", "#*#guarded"] {
        main.op("definefunc", [0.into(), Op::method(name), 1.into()]).op("callarg0", [0.into()]);
    }
    main.op("returnundefined", []);

    // `looping(n)`: the environment is replaced at the end of every round,
    // its one variable copied over; the handler pops it and rethrows.
    let mut looping = Asm::new();
    looping.op("newlexenv", [2.into()]);
    looping.label("try").op("ldexternalmodulevar", [0.into()]).op("stlexvar", [0.into(), 0.into()]);
    looping.op("lda", [3.into()]).op("stlexvar", [0.into(), 1.into()]);
    looping.label("head");
    call_member(&mut looping, 0, 0, "tick");
    looping.op("definefunc", [0.into(), Op::method("#*@0*#body"), 0.into()]).op("callarg0", [0.into()]);
    looping.op("lda", [3.into()]).op("jeqz", [Op::label("try_end")]);
    looping.op("ldlexvar", [0.into(), 0.into()]).op("sta", [0.into()]);
    looping.op("ldlexvar", [0.into(), 1.into()]).op("sta", [1.into()]);
    looping.op("poplexenv", []).op("newlexenv", [2.into()]);
    looping.op("lda", [0.into()]).op("stlexvar", [0.into(), 0.into()]);
    // The counter is written anew each round: a second writer.
    looping.op("inc", [0.into()]).op("stlexvar", [0.into(), 1.into()]);
    looping.op("jmp", [Op::label("head")]);
    looping.label("try_end").op("poplexenv", []).op("returnundefined", []);
    looping.label("handler").op("sta", [0.into()]).op("poplexenv", []).op("lda", [0.into()]).op("throw", []);
    looping.label("handler_end");
    looping.catch(Catch::all(("try", "try_end"), ("handler", "handler_end")));

    let mut body = Asm::new();
    call_member(&mut body, 0, 0, "request");
    call_captured(&mut body, 0, 1);
    body.op("returnundefined", []);

    let mut cycle = Asm::new();
    cycle.op("newlexenv", [3.into()]);
    cycle.op("ldlexvar", [0.into(), 1.into()]).op("stlexvar", [0.into(), 0.into()]);
    cycle.op("ldlexvar", [0.into(), 0.into()]).op("stlexvar", [0.into(), 1.into()]);
    // Written from itself and nothing else: it has no writer.
    cycle.op("ldlexvar", [0.into(), 2.into()]).op("stlexvar", [0.into(), 2.into()]);
    call_captured(&mut cycle, 0, 0);
    call_captured(&mut cycle, 0, 2);
    cycle.op("returnundefined", []);

    let mut wide = Asm::new();
    wide.op("wide.newlexenv", [300.into()]);
    wide.op("definefunc", [0.into(), Op::method("#*#cycle"), 0.into()]).op("wide.stlexvar", [0.into(), 290.into()]);
    wide.op("wide.ldlexvar", [0.into(), 290.into()]).op("callarg0", [0.into()]);
    wide.op("returnundefined", []);

    // A user `try` around code that pops an environment and then returns:
    // the instructions between cannot raise, so the handler has one stack.
    let mut guarded = Asm::new();
    guarded.op("newlexenv", [1.into()]);
    guarded.op("lda", [2.into()]).op("stlexvar", [0.into(), 0.into()]);
    guarded.label("try");
    call_member(&mut guarded, 0, 0, "run");
    guarded.op("lda", [3.into()]).op("jeqz", [Op::label("try_end")]);
    guarded.op("poplexenv", []).op("ldundefined", []).op("returnundefined", []);
    guarded.label("try_end").op("poplexenv", []).op("returnundefined", []);
    guarded.label("handler");
    call_member(&mut guarded, 0, 0, "failed");
    guarded.op("poplexenv", []).op("returnundefined", []);
    guarded.label("handler_end");
    guarded.catch(Catch::all(("try", "try_end"), ("handler", "handler_end")));

    let record = AbcRecord::ets_module(LEX, "entry", &["looping"], module)
        .function(function("func_main_0", 0, 0, main))
        .function(function("#*#looping", 3, 1, looping))
        .function(function("#*@0*#body", 0, 0, body))
        .function(function("#*#cycle", 0, 0, cycle))
        .function(function("#*#wide", 0, 0, wide))
        .function(function("#*#guarded", 0, 1, guarded));
    let mut builder = AbcBuilder::new();
    builder.record(record);
    builder
}

#[test]
fn loops_copies_cycles_and_wide_forms() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &shapes());
    // The two `newlexenv` of the loop are one environment; the copy of a variable into the next
    // round's environment is not a second writer.
    assert_eq!(callees(&engine, "#*#looping"), ["import:@ohos:net.http#default.tick", "local:#*@0*#body"]);
    // The closure made inside the loop sees that environment; its counter has two writers.
    assert_eq!(callees(&engine, "#*@0*#body"), ["import:@ohos:net.http#default.request", "lex(0,1)"]);
    assert_eq!(callees(&engine, "#*#cycle"), ["lex(0,0)", "lex(0,2)"]);
    assert_eq!(callees(&engine, "#*#wide"), ["local:#*#cycle"]);
    assert_eq!(callees(&engine, "#*#guarded"), ["this.run", "this.failed"]);

    let stats = engine.call_resolution(&ResolutionOptions::default(), &AtomicBool::new(false)).unwrap();
    let why = |reason| stats.captured_unresolved.get(&reason).copied().unwrap_or(0);
    assert_eq!((why(Unresolved::Chain), why(Unresolved::NoWriter), why(Unresolved::MultipleWriters)), (1, 1, 1));
    // Five sites, two of them merged; every function's environments were followed.
    assert_eq!((stats.scopes.sites, stats.scopes.environments, stats.scopes.unidentified_functions), (5, 4, 0));
}

/// Functions whose environments cannot be followed, and what their stores
/// do to the variables around them; `with_broken` adds a function whose
/// code does not decode.
fn unidentified_record(name: &str, with_broken: bool) -> AbcRecord {
    let mut main = Asm::new();
    main.op("newlexenv", [3.into()]);
    define_into(&mut main, "#*#helper", 0);
    define_into(&mut main, "#*#helper", 1);
    define_into(&mut main, "#*#helper", 2);
    for closure in ["#*#uneven", "#*#sound", "#*#broken"].into_iter().take(if with_broken { 3 } else { 2 }) {
        main.op("definefunc", [0.into(), Op::method(closure), 1.into()]).op("callarg0", [0.into()]);
    }
    call_captured(&mut main, 0, 0);
    call_captured(&mut main, 0, 1);
    call_captured(&mut main, 0, 2);
    main.op("returnundefined", []);

    // `uneven(flag)`: one branch makes an environment, the other does not.
    let mut uneven = Asm::new();
    uneven.op("lda", [3.into()]).op("jeqz", [Op::label("join")]);
    uneven.op("newlexenv", [1.into()]);
    uneven.label("join");
    call_captured(&mut uneven, 0, 0);
    // Whatever this writes, it is slot 1 of some environment around here.
    uneven.op("ldnull", []).op("stlexvar", [0.into(), 1.into()]);
    uneven.op("definefunc", [0.into(), Op::method("#*@0*#child"), 0.into()]).op("callarg0", [0.into()]);
    uneven.op("returnundefined", []);

    // A closure of it: its chain is unknown, the environment it makes itself is not.
    let mut child = Asm::new();
    child.op("newlexenv", [1.into()]);
    child.op("definefunc", [0.into(), Op::method("#*#helper"), 0.into()]).op("stlexvar", [0.into(), 0.into()]);
    call_captured(&mut child, 0, 0);
    call_captured(&mut child, 1, 0);
    child.op("returnundefined", []);

    // Its environments are fine, so it still reads slot 0 and 2 of the outer one.
    let mut sound = Asm::new();
    call_captured(&mut sound, 0, 0);
    call_captured(&mut sound, 0, 1);
    call_captured(&mut sound, 0, 2);
    sound.op("returnundefined", []);

    // Code that does not decode could store anywhere around it.
    let mut broken = Asm::new();
    broken.op("ldnull", []).raw(&[0xff, 0x00]);

    let record = AbcRecord::ets_module(name, "entry", &["uneven"], AbcModule::new())
        .function(function("func_main_0", 0, 0, main))
        .function(function("#*#helper", 0, 0, leaf()))
        .function(function("#*#uneven", 0, 1, uneven))
        .function(function("#*@0*#child", 0, 0, child))
        .function(function("#*#sound", 0, 0, sound));
    if with_broken {
        record.function(function("#*#broken", 0, 0, broken))
    } else {
        record
    }
}

const TIDY: &str = "&entry/src/main/ets/pages/Tidy&";

fn unidentified() -> AbcBuilder {
    let mut builder = AbcBuilder::new();
    builder.record(unidentified_record(LEX, true)).record(unidentified_record(TIDY, false));
    builder
}

#[test]
fn unidentified_environments_stay_unresolved_and_taint() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &unidentified());
    let of_record = |record: &str, function: &str| {
        let mut out = Vec::new();
        engine
            .find_refs(&Query::condition("call:.").unwrap(), &AtomicBool::new(false), &mut |batch| {
                for mut row in batch.rows {
                    if row.record == record && matches!(&row.site, RefSite::Code { function: raw, .. } if raw == function) {
                        out.push(row.matched.swap_remove(0));
                    }
                }
            })
            .unwrap();
        out
    };
    let tidy = TIDY;
    // Slot 1 may have been written by `uneven`, whose store has no identified target.
    assert_eq!(of_record(tidy, "func_main_0")[2..], ["local:#*#helper".to_owned(), "lex(0,1)".to_owned(), "local:#*#helper".to_owned()]);
    assert_eq!(of_record(tidy, "#*#sound"), ["local:#*#helper", "lex(0,1)", "local:#*#helper"]);
    // Where the stacks disagree nothing is read …
    assert_eq!(of_record(tidy, "#*#uneven"), ["lex(0,0)", "local:#*@0*#child"]);
    // … and a closure made there knows its own environment only.
    assert_eq!(of_record(tidy, "#*@0*#child"), ["local:#*#helper", "lex(1,0)"]);
    // An undecodable function taints every slot around it.
    assert_eq!(of_record(LEX, "#*#sound"), ["lex(0,0)", "lex(0,1)", "lex(0,2)"]);
    assert_eq!(of_record(LEX, "#*@0*#child"), ["local:#*#helper", "lex(1,0)"]);

    let stats = engine.call_resolution(&ResolutionOptions { records: Some("Tidy"), samples: false }, &AtomicBool::new(false)).unwrap();
    let why = |reason| stats.captured_unresolved.get(&reason).copied().unwrap_or(0);
    assert_eq!((stats.records, why(Unresolved::NoIdentity), why(Unresolved::Tainted)), (1, 2, 2));
    // `uneven` is not followed; its closure and `helper` (made there too) have unknown chains.
    assert_eq!((stats.scopes.unidentified_functions, stats.scopes.unknown_chains, stats.scopes.unidentified_stores), (1, 2, 1));
}

/// A class kept in a captured variable and in a register: its static
/// methods, its constructor and the methods of its instances.
fn classes() -> AbcBuilder {
    let mut builder = AbcBuilder::new();
    let literal = builder.literal_array([
        AbcLiteral::str("get"),
        AbcLiteral::method(LEX, "#~@0>#get"),
        AbcLiteral::MethodAffiliate(0),
        AbcLiteral::str("size"),
        AbcLiteral::Getter(asc_fixture::abc::MethodRef::new(LEX, "#~@0>#size")),
        AbcLiteral::MethodAffiliate(0),
        AbcLiteral::str("make"),
        AbcLiteral::method(LEX, "#~@0<#make"),
        AbcLiteral::MethodAffiliate(0),
        AbcLiteral::Integer(2),
    ]);
    let mut main = Asm::new();
    main.op("newlexenv", [1.into()]);
    main.op("ldhole", []).op("sta", [0.into()]);
    main.op("defineclasswithbuffer", [0.into(), Op::method("#~@0=#Box"), literal.into(), 0.into(), 0.into()]).op("sta", [1.into()]);
    main.op("stlexvar", [0.into(), 0.into()]);
    main.op("lda", [1.into()]).op("ldobjbyname", [0.into(), Op::str("make")]).op("callthis0", [0.into(), 1.into()]);
    main.op("mov", [2.into(), 1.into()]).op("newobjrange", [0.into(), 1.into(), 2.into()]).op("sta", [3.into()]);
    main.op("lda", [3.into()]).op("ldobjbyname", [0.into(), Op::str("get")]).op("callthis0", [0.into(), 3.into()]);
    // Not methods of the literal: a getter, an instance method asked of the class, an unknown name.
    main.op("lda", [3.into()]).op("ldobjbyname", [0.into(), Op::str("size")]).op("callthis0", [0.into(), 3.into()]);
    main.op("lda", [1.into()]).op("ldobjbyname", [0.into(), Op::str("get")]).op("callthis0", [0.into(), 1.into()]);
    main.op("lda", [3.into()]).op("ldobjbyname", [0.into(), Op::str("other")]).op("callthis0", [0.into(), 3.into()]);
    main.op("returnundefined", []);

    // A method reaches its class through the environment the class was defined in.
    let mut get = Asm::new();
    call_member(&mut get, 0, 0, "make");
    get.op("ldlexvar", [0.into(), 0.into()]).op("sta", [0.into()]).op("mov", [1.into(), 0.into()]);
    get.op("newobjrange", [0.into(), 1.into(), 1.into()]).op("ldobjbyname", [0.into(), Op::str("get")]).op("callarg0", [0.into()]);
    get.op("returnundefined", []);

    let record = AbcRecord::ets_module(LEX, "entry", &["Box"], AbcModule::new())
        .function(function("func_main_0", 4, 0, main))
        .function(function("#~@0=#Box", 0, 0, leaf()))
        .function(function("#~@0>#get", 2, 0, get))
        .function(function("#~@0>#size", 0, 0, leaf()))
        .function(function("#~@0<#make", 0, 0, leaf()));
    builder.record(record);
    builder
}

#[test]
fn class_literals_name_the_methods() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &classes());
    assert_eq!(
        callees(&engine, "func_main_0"),
        [
            "local:#~@0<#make",
            "local:#~@0=#Box",
            "local:#~@0>#get",
            "new local:#~@0=#Box().size",
            "local:#~@0=#Box.get",
            "new local:#~@0=#Box().other",
        ]
    );
    assert_eq!(callees(&engine, "#~@0>#get"), ["local:#~@0<#make", "local:#~@0=#Box", "local:#~@0>#get"]);
}

#[test]
fn damaged_files_do_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    for builder in [nested(), shapes(), unidentified(), classes()] {
        let good = builder.build().bytes;
        // Flip one byte at a time across the code and data of the file.
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for round in 0..120 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let mut bytes = good.clone();
            let at = asc_abc::HEADER_SIZE + (state as usize) % (bytes.len() - asc_abc::HEADER_SIZE);
            bytes[at] ^= 1 << (round % 8);
            let path = dir.path().join("damaged.abc");
            std::fs::write(&path, &bytes).unwrap();
            // A file that no longer opens is fine; one that opens must answer.
            let Ok(engine) = Engine::open(&path) else { continue };
            let _ = engine.find_refs(&Query::condition("call:.").unwrap(), &AtomicBool::new(false), &mut |_| {});
            let _ = engine.call_resolution(&ResolutionOptions { records: None, samples: true }, &AtomicBool::new(false));
        }
    }
}
