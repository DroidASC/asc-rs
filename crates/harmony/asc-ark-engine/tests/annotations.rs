//! What the compiler writes since API 20 and 24, on the synthetic programs
//! made for it: annotations of the program (`findrefs string`, `listclass`,
//! record lookup) and calls that name their method (`findrefs prop`).

use std::path::Path;
use std::sync::atomic::AtomicBool;

use asc_ark_engine::{Access, ClassQuery, Engine, ListOptions, Pattern, Query, RefContext};
use asc_fixture::abc::{MARKS_APP, MARKS_LIB, MARKS_LIB_MARKED, MARKS_ROUTE, NAMED_APP, annotations_program, callable_names_program};

fn open(dir: &Path, bytes: &[u8]) -> Engine {
    let path = dir.join("modules.abc");
    std::fs::write(&path, bytes).unwrap();
    Engine::open(&path).unwrap()
}

/// The rows of `query`, each with its context, without the entry column.
fn find_with(engine: &Engine, query: &Query, context: RefContext) -> Vec<String> {
    let mut out = Vec::new();
    engine
        .find_refs(query, &AtomicBool::new(false), &mut |mut batch| {
            assert_eq!(batch.error, None);
            engine.fill_context(&batch.entry_name, &mut batch.rows, context);
            out.extend(batch.rows.iter().map(|row| row.text("").trim_start_matches(" | ").to_owned()));
        })
        .unwrap();
    out
}

fn find(engine: &Engine, spec: &str) -> Vec<String> {
    find_with(engine, &Query::rule(spec, None).unwrap(), RefContext::None)
}

/// The rows without the record of the program under test.
fn short(rows: Vec<String>, record: &str) -> Vec<String> {
    rows.into_iter().map(|row| row.replacen(record, "", 1)).collect()
}

#[test]
fn strings_of_annotations_are_found_where_they_stand() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &annotations_program().build().bytes);
    // On a function, before what its code has; in an interface, at the field. Each says it is an
    // annotation, and an array where in it the string is.
    assert_eq!(
        find(&engine, "string:."),
        [
            format!("{MARKS_LIB_MARKED} field note | - | annotation default \"none\""),
            format!("{MARKS_APP} field scopeNames | - | literal@0x442 [0]=\"Pay\""),
            format!(
                "{MARKS_APP}->#~@0=#Pay | Pay.constructor | annotation @{MARKS_ROUTE} path=\"/pay\", tags[0]=\"pay\", tags[1]=\"checkout\""
            ),
            format!("{MARKS_APP}->#~@0>#open | Pay.open | annotation @{MARKS_LIB_MARKED} note=\"opens /pay\""),
            format!("{MARKS_APP}->#~@0>#open+0x0 | Pay.open | lda.str \"/pay\""),
            format!("{MARKS_ROUTE} field path | - | annotation default \"/\""),
            format!("{MARKS_ROUTE} field tags | - | annotation default [0]=\"page\", [1]=\"default\""),
            format!("{MARKS_ROUTE} field grid | - | annotation default [0][0]=\"deep\", [0][1]=\"page\""),
        ]
    );
    // Only what matches is spelled out; an annotation without a match is no row (`@Route` on `open`).
    assert_eq!(
        find(&engine, "string:^(pay|page)$"),
        [
            format!("{MARKS_APP}->#~@0=#Pay | Pay.constructor | annotation @{MARKS_ROUTE} tags[0]=\"pay\""),
            format!("{MARKS_ROUTE} field tags | - | annotation default [0]=\"page\""),
            format!("{MARKS_ROUTE} field grid | - | annotation default [0][1]=\"page\""),
        ]
    );
    let literal = find_with(&engine, &Query::string_literal("opens /"), RefContext::None);
    assert_eq!(literal, [format!("{MARKS_APP}->#~@0>#open | Pay.open | annotation @{MARKS_LIB_MARKED} note=\"opens /pay\"")]);
    // The compiler's own annotations and the names of elements are not strings of the program.
    assert!(find(&engine, "string:SlotNumber|^note$|^path$").is_empty());

    let mut matched = Vec::new();
    engine
        .find_refs(&Query::rule("string:pay", None).unwrap(), &AtomicBool::new(false), &mut |batch| {
            matched.extend(batch.rows.into_iter().map(|row| (row.matched, row.sites)));
        })
        .unwrap();
    let texts = |list: &[&str]| list.iter().map(|text| (*text).to_owned()).collect::<Vec<_>>();
    assert_eq!(matched, [(texts(&["/pay", "pay"]), vec![]), (texts(&["opens /pay"]), vec![]), (texts(&["/pay"]), vec![0])]);
}

#[test]
fn annotation_rows_have_no_code_to_show_and_stay_out_of_conjunctions() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &annotations_program().build().bytes);
    let rows = find_with(&engine, &Query::rule("string:/pay", None).unwrap(), RefContext::Lines(1));
    // The row of the instruction brings its code, the rows of the annotations stand alone.
    assert_eq!(rows.iter().map(|row| row.lines().count()).collect::<Vec<_>>(), [1, 1, 5]);
    assert!(rows[2].contains("\n  @ pc 0x0\n") && rows[2].contains("\n  >   0000  lda.str \"/pay\"\n"), "{}", rows[2]);
    // The listing of the function is where the whole annotation is read.
    let listing = engine.get_class(&ClassQuery { record: "pages/Pay", function: Some("Pay.open"), entry: None }).unwrap().text;
    assert!(listing.contains(&format!("; @{MARKS_ROUTE}\n; @{MARKS_LIB_MARKED}(note=\"opens /pay\")\n")), "{listing}");

    // A conjunction is about the code of a function: `open` loads the string, the constructor only carries it.
    assert_eq!(
        short(find(&engine, "string:^/pay$ & string:/"), MARKS_APP),
        ["->#~@0>#open+0x0 | Pay.open | string +0x0 lda.str \"/pay\" && string +0x0 lda.str \"/pay\""]
    );
    assert!(find(&engine, "string:^checkout$ & string:^pay$").is_empty());
    // An exclusion likewise: what `open` carries does not take it away.
    assert_eq!(find(&engine, "string:^/pay$ & !string:opens").len(), 1);
}

#[test]
fn annotation_interfaces_are_records_named_after_their_module() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &annotations_program().build().bytes);
    let lines = |all: bool| -> Vec<String> {
        let options = ListOptions { all, ..ListOptions::default() };
        engine.list_classes(&options).unwrap().iter().map(|record| record.line(false)).collect()
    };
    let listed = [
        format!("{MARKS_LIB} | functions=1"),
        format!("{MARKS_LIB_MARKED} | functions=0 kind=annotation"),
        format!("{MARKS_APP} | functions=3"),
        format!("{MARKS_ROUTE} | functions=0 kind=annotation"),
    ];
    // Declared by the program: listed without --all, which adds the compiler's own and the types.
    assert_eq!(lines(false), listed);
    let all = lines(true);
    assert_eq!(all.len(), listed.len() + 4, "{all:?}");
    assert!(all.contains(&"_ESSlotNumberAnnotation | functions=0 kind=service".to_owned()), "{all:?}");
    assert!(all.contains(&"panda.String | functions=0 foreign".to_owned()), "{all:?}");

    // A path names the module again, and the interface by what follows it.
    let resolve = |record: &str| engine.get_class(&ClassQuery { record, function: None, entry: None }).map(|source| source.record);
    for (query, record) in [
        ("pages/Pay", MARKS_APP),
        ("pages/Pay.ets", MARKS_APP),
        ("pages/Pay.Route", MARKS_ROUTE),
        ("Pay.Route", MARKS_ROUTE),
        ("index", MARKS_LIB),
        ("@ohos/lib/index.Marked", MARKS_LIB_MARKED),
        ("index.Marked", MARKS_LIB_MARKED),
        (MARKS_LIB_MARKED, MARKS_LIB_MARKED),
        (MARKS_LIB, MARKS_LIB),
    ] {
        assert_eq!(resolve(query).unwrap(), record, "{query}");
    }
    assert!(resolve("Route").is_err() && resolve("pages/Pay.Marked").is_err());
    let text = engine.get_class(&ClassQuery { record: "index.Marked", function: None, entry: None }).unwrap().text;
    assert_eq!(
        text,
        format!(
            ".record {MARKS_LIB_MARKED}\n; annotation interface, package @ohos/lib, 1 field, 0 functions\n.field Lpanda.String; note = \"none\"\n"
        )
    );
}

#[test]
fn a_call_that_names_its_method_is_one_row() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &callable_names_program().build().bytes);
    let found = short(find(&engine, "prop:."), NAMED_APP);
    assert_eq!(
        found,
        [
            "->#*#named+0x2 | named | ldobjbyname \"cut\" [read]",
            // The load in front of each of these is the same call: no row.
            "->#*#named+0xe | named | callthis2withname \"cut\", a3, v1, v2 [call]",
            "->#*#named+0x25 | named | callthisrangewithname 1, \"cut\", v5  ; v5..v6 [call]",
            "->#*#named+0x31 | named | callthis0withname \"fold\", a2 [call]",
            // Without a load in front; and a load of another property stays a read.
            "->#*#named+0x36 | named | callthis0withname \"close\", a3 [call]",
            "->#*#named+0x3d | named | ldobjbyname \"cut\" [read]",
            "->#*#named+0x41 | named | callthis0withname \"fold\", a3 [call]",
            "->#*#plain+0x2 | plain | ldobjbyname \"cut\" [read]",
            "->#*#plain+0xa | plain | ldobjbyname \"cut\" [call]",
            "->#*#plain+0x17 | plain | ldobjbyname \"cut\" [call]",
            "->#*#plain+0x29 | plain | ldobjbyname \"fold\" [call]",
        ]
    );

    // Compiled either way, the same source has the same rows of each access.
    let count = |name: &str, access: Option<Access>, function: &str| {
        let query = Query::Prop { name: Pattern::Exact(name.to_owned()), access };
        let rows = find_with(&engine, &query, RefContext::None);
        if let Some(access) = access {
            assert!(rows.iter().all(|row| row.ends_with(&format!(" [{access}]"))), "{rows:?}");
        }
        rows.iter().filter(|row| row.contains(&format!("->#*#{function}+"))).count()
    };
    for (name, access, plain, named) in [
        ("cut", None, 3, 4),
        ("cut", Some(Access::Read), 1, 2),
        ("cut", Some(Access::Call), 2, 2),
        ("cut", Some(Access::Write), 0, 0),
        ("fold", None, 1, 2),
        ("fold", Some(Access::Read), 0, 0),
        ("fold", Some(Access::Call), 1, 2),
    ] {
        // `named` has one read of `cut` and one call of `fold` more: the two lines no compiler writes.
        assert_eq!((count(name, access, "plain"), count(name, access, "named")), (plain, named), "{name} {access:?}");
    }

    // The row of a call is where `findrefs call` has the call site.
    let calls = short(find(&engine, "call:cut"), NAMED_APP);
    let sites = |rows: &[String]| -> Vec<String> { rows.iter().map(|row| row.split(" | ").next().unwrap().to_owned()).collect() };
    let named_calls: Vec<String> = found.iter().filter(|row| row.contains("withname") && row.contains("\"cut\"")).cloned().collect();
    assert_eq!((named_calls.len(), &sites(&calls)[..2]), (2, &sites(&named_calls)[..]));
}

#[test]
fn conjunctions_and_context_follow_the_call_instruction() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), &callable_names_program().build().bytes);
    // One site per call, the first two shown.
    assert_eq!(
        short(find(&engine, "prop:=fold & prop:=close"), NAMED_APP),
        ["->#*#named+0x31 | named | prop +0x31 callthis0withname \"fold\", a2 [call], +0x41 callthis0withname \"fold\", a3 [call] && \
          prop +0x36 callthis0withname \"close\", a3 [call]"]
    );
    // The loads are no reads to exclude a function by.
    let query = Query::All(vec![
        Query::rule("prop:=fold", None).unwrap(),
        Query::Not(Box::new(Query::Prop { name: Pattern::Exact("fold".to_owned()), access: Some(Access::Read) })),
    ]);
    assert_eq!(find_with(&engine, &query, RefContext::None).len(), 2);

    let query = Query::Prop { name: Pattern::Exact("cut".to_owned()), access: Some(Access::Call) };
    let rows = find_with(&engine, &query, RefContext::Lines(1));
    assert_eq!(
        rows[0],
        format!(
            "{NAMED_APP}->#*#named+0xe | named | callthis2withname \"cut\", a3, v1, v2 [call]\n  @ pc 0xe\n      000a  ldobjbyname \"cut\"\n  \
             >   000e  callthis2withname \"cut\", a3, v1, v2\n      0015  sta v3"
        )
    );
    // One instruction is marked per row, whatever the form of the call.
    assert!(rows.iter().all(|row| row.lines().filter(|line| line.starts_with("  > ")).count() == 1), "{rows:?}");
}

/// The file `asc-pasm/tests/compiled.rs` describes: one source with
/// annotations, compiled on its own by the official compiler.
const COMPILED: &[u8] = include_bytes!("../../asc-pasm/tests/es2abc/annotations.api24.abc");

#[test]
fn a_compiled_file_has_its_annotations_found() {
    let dir = tempfile::tempdir().unwrap();
    let engine = open(dir.path(), COMPILED);
    // In a file that is not merged the names say nothing: the records do.
    let listed: Vec<String> = engine.list_classes(&ListOptions::default()).unwrap().iter().map(|record| record.line(false)).collect();
    assert_eq!(listed, ["Bare | functions=0 kind=annotation", "Marked | functions=0 kind=annotation", "_GLOBAL | functions=4"]);
    assert_eq!(
        find(&engine, "string:^(a|plain|class|only)$"),
        [
            "Marked field name | - | annotation default \"plain\"",
            "Marked field tags | - | annotation default [0]=\"a\"",
            "_GLOBAL->#~@0<#make | Tagged.make | annotation @Marked tags[0]=\"only\"",
            "_GLOBAL->#~@0=#Tagged | Tagged.constructor | annotation @Marked name=\"class\"",
        ]
    );
}

/// Run `command`; what it printed when it failed.
fn run(command: &mut std::process::Command) {
    let out = command.output().unwrap_or_else(|err| panic!("{:?}: {err}", command.get_program()));
    assert!(
        out.status.success(),
        "{:?}: {}{}",
        command.get_program(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Compile `sources` (`(file, record, package)`) into one merged file for
/// bytecode of API 24 with `flags`.
fn compile(compiler: &std::ffi::OsStr, dir: &Path, name: &str, sources: &[(&Path, &str, &str)], flags: &[&str]) -> Vec<u8> {
    // One line per source: path;record;module kind;source file;package;shared.
    let list: String = sources
        .iter()
        .map(|(file, record, package)| format!("{};{record};esm;{package}/source.ts;{package};false\n", file.display()))
        .collect();
    let (list_path, abc_path) = (dir.join(format!("{name}.txt")), dir.join(format!("{name}.abc")));
    std::fs::write(&list_path, list).unwrap();
    let mut command = std::process::Command::new(compiler);
    command.args(["--target-api-version", "24", "--module", "--extension", "ts", "--merge-abc"]).args(flags);
    run(command.arg("--output").arg(&abc_path).arg(format!("@{}", list_path.display())));
    std::fs::read(&abc_path).unwrap()
}

/// The same source as `--enable-callable-name` compiles it and without:
/// `$ASC_ES2ABC` is the official compiler. Without it the test does nothing.
#[test]
fn the_official_compiler_names_calls_and_one_call_is_one_row() {
    const SOURCE: &str = "class Paper {\n  cut(a: number, b: number): number { return a + b; }\n  fold(): void {}\n}\n\
        export function use(p: Paper, q: any): number {\n  const f = p.cut;\n  q.fold();\n  q.cut(1, 2, 3, 4, 5);\n  \
        return p.cut(1, 2) + this.cut(3, 4);\n}\n";
    let Some(compiler) = std::env::var_os("ASC_ES2ABC") else { return };
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("paper.ts");
    std::fs::write(&source, SOURCE).unwrap();
    let sources = [(source.as_path(), "&entry/src/main/ets/paper&", "entry")];
    let rows = |name: &str, flags: &[&str]| {
        let work = dir.path().join(name);
        std::fs::create_dir(&work).unwrap();
        let engine = open(&work, &compile(&compiler, dir.path(), name, &sources, flags));
        let per_access = |name: &str| {
            let with = |access| find_with(&engine, &Query::Prop { name: Pattern::Exact(name.to_owned()), access }, RefContext::None);
            let all = with(None);
            let labels: Vec<String> = all.iter().map(|row| row.rsplit(" [").next().unwrap().to_owned()).collect();
            for access in Access::ALL {
                assert_eq!(with(Some(access)).len(), labels.iter().filter(|label| **label == format!("{access}]")).count(), "{all:?}");
            }
            (labels, all)
        };
        (per_access("cut"), per_access("fold"), find(&engine, "call:\\.(cut|fold)$").len())
    };
    let ((plain_cut, _), (plain_fold, _), plain_calls) = rows("plain", &[]);
    let ((named_cut, named_rows), (named_fold, _), named_calls) = rows("named", &["--enable-callable-name"]);
    // `const f = p.cut` and three calls; one call of `fold`: the same rows either way.
    assert_eq!(plain_cut, ["read]", "call]", "call]", "call]"]);
    assert_eq!((&named_cut, &named_fold), (&plain_cut, &plain_fold), "{named_rows:?}");
    assert_eq!((plain_fold.len(), plain_calls, named_calls), (1, 4, 4));
    // What this build is about: the calls name their method.
    assert_eq!(
        named_rows.iter().filter(|row| row.contains("withname \"cut\"") || row.contains("withname 5, \"cut\"")).count(),
        3,
        "{named_rows:?}"
    );
}

/// Annotation interfaces as the official compiler names them in a merged
/// file, after module names with and without a version. `$ASC_ES2ABC` is
/// the compiler; without it the test does nothing.
#[test]
fn the_official_compiler_names_annotation_interfaces_after_their_module() {
    let Some(compiler) = std::env::var_os("ASC_ES2ABC") else { return };
    let dir = tempfile::tempdir().unwrap();
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../asc-pasm/tests/es2abc/annotations.ts");
    // The compiler takes a source once: one copy per module.
    let modules = [
        ("&entry/src/main/ets/marks&", "entry"),
        ("&@scope/lib/src/marks&1.2.3", "@scope/lib"),
        ("com.other.app&lib/marks&1.0.0-rc.1", "lib"),
    ];
    let copies: Vec<_> = (0..modules.len()).map(|index| dir.path().join(format!("marks{index}.ts"))).collect();
    for copy in &copies {
        std::fs::copy(&source, copy).unwrap();
    }
    let sources: Vec<(&Path, &str, &str)> =
        copies.iter().zip(modules).map(|(copy, (record, package))| (copy.as_path(), record, package)).collect();
    let work = dir.path().join("work");
    std::fs::create_dir(&work).unwrap();
    let engine = open(&work, &compile(&compiler, dir.path(), "marks", &sources, &["--enable-annotations"]));

    let listed: Vec<String> = engine.list_classes(&ListOptions::default()).unwrap().iter().map(|record| record.line(false)).collect();
    let mut expected = Vec::new();
    for (record, _) in modules {
        expected.push(format!("{record} | functions=4"));
        expected.push(format!("{record}.Bare | functions=0 kind=annotation"));
        expected.push(format!("{record}.Marked | functions=0 kind=annotation"));
    }
    expected.sort();
    assert_eq!(listed, expected);

    let resolve = |record: &str| engine.get_class(&ClassQuery { record, function: None, entry: None }).map(|source| source.record);
    assert_eq!(resolve("src/marks").unwrap(), "&@scope/lib/src/marks&1.2.3");
    assert_eq!(resolve("src/marks.Marked").unwrap(), "&@scope/lib/src/marks&1.2.3.Marked");
    assert_eq!(resolve("lib/marks.Bare").unwrap(), "com.other.app&lib/marks&1.0.0-rc.1.Bare");
    assert_eq!(resolve("ets/marks.ts").unwrap(), "&entry/src/main/ets/marks&");
    // The class of each module is annotated with the interface of that module.
    let rows = find(&engine, "string:^class$");
    assert_eq!(rows.len(), 3, "{rows:?}");
    for (record, _) in modules {
        let row = format!("{record}->#~@0=#Tagged | Tagged.constructor | annotation @{record}.Marked name=\"class\"");
        assert!(rows.contains(&row), "{row}\n{rows:?}");
    }
    assert_eq!(find(&engine, "string:^plain$").len(), 3);
}
