use super::*;
use std::time::Instant;

fn parse(text: &str) -> ProguardMapping {
    NameMappings::from_proguard(text).unwrap()
}

fn entries(map: &std::collections::BTreeMap<String, String>) -> Vec<(&str, &str)> {
    map.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
}

#[test]
fn classic_proguard_lines() {
    let p = parse(
        "com.example.Outer -> a.a:\n\
         \x20   int count -> a\n\
         \x20   com.example.Outer$Inner[][] grid -> b\n\
         \x20   java.lang.String name -> name\n\
         \x20   void <init>(int) -> <init>\n\
         \x20   com.example.Outer$Inner find(java.lang.String,long[],com.example.Outer) -> a\n\
         \x20   void find(int) -> a\n\
         \x20   void reset() -> b\n\
         com.example.Outer$Inner -> a.b:\n\
         \x20   com.example.Outer this$0 -> a\n",
    );
    assert_eq!(p.warnings, []);
    let m = &p.mappings;
    assert_eq!(entries(m.classes()), [("La/a;", "Lcom/example/Outer;"), ("La/b;", "Lcom/example/Outer$Inner;")]);
    // Types are translated to the DEX's names, also for classes declared
    // further down; unmapped classes and primitives stay as they are.
    assert_eq!(entries(m.fields()), [("La/a;->a:I", "count"), ("La/a;->b:[[La/b;", "grid"), ("La/b;->a:La/a;", "this$0")]);
    assert_eq!(
        entries(m.methods()),
        [("La/a;->a(I)V", "find"), ("La/a;->a(Ljava/lang/String;[JLa/a;)La/b;", "find"), ("La/a;->b()V", "reset")]
    );
}

#[test]
fn identity_entries_are_omitted() {
    let p = parse("com.Keep -> com.Keep:\n    int x -> x\n    void run() -> run\n    void go() -> a\n");
    assert_eq!(p.warnings, []);
    assert!(p.mappings.classes().is_empty());
    assert!(p.mappings.fields().is_empty());
    // A renamed member of a kept class is keyed by the kept descriptor.
    assert_eq!(entries(p.mappings.methods()), [("Lcom/Keep;->a()V", "go")]);
}

#[test]
fn only_the_outermost_inline_frame_names_the_method() {
    let p = parse(
        "com.a.Caller -> x.y:\n\
         \x20   1:3:void outer(int):10:12 -> a\n\
         \x20   4:4:int com.b.Other.helper(int):50:50 -> a\n\
         \x20   4:4:void sameClassInlined():30 -> a\n\
         \x20   4:4:void outer(int):13 -> a\n\
         \x20   5:6:void outer(int):14:15 -> a\n\
         \x20   1:1:int com.b.Other.only():7:7 -> b\n\
         \x20   1:1:void driver():20 -> b\n\
         com.b.Other -> x.z:\n\
         \x20   1:2:int helper(int):50:51 -> a\n",
    );
    assert_eq!(p.warnings, []);
    assert_eq!(entries(p.mappings.methods()), [("Lx/y;->a(I)V", "outer"), ("Lx/y;->b()V", "driver"), ("Lx/z;->a(I)I", "helper")]);
}

#[test]
fn methods_from_other_classes_rename_nothing() {
    // R8 moved `Util.check` into `x.y` (outermost frame qualified with
    // another class); qualified with the class's own name is just verbose.
    let p = parse(
        "com.a.Main -> x.y:\n\
         \x20   1:2:void com.a.Util.check(com.a.Main):5:6 -> a\n\
         \x20   1:1:void com.a.Main.own():3:3 -> b\n\
         \x20   int com.a.Main.counter -> c\n\
         \x20   int com.a.Util.moved -> d\n",
    );
    assert_eq!(p.warnings, []);
    assert_eq!(entries(p.mappings.methods()), [("Lx/y;->b()V", "own")]);
    assert_eq!(entries(p.mappings.fields()), [("Lx/y;->c:I", "counter")]);
}

#[test]
fn overloads_with_equal_ranges_stay_apart() {
    // Each overload starts a new stack: its first frame has a line range,
    // where call-site frames have one line: `put(long)` is inlined into
    // `put()`.
    let p = parse("A -> a:\n    1:1:void put(int):10:10 -> a\n    1:1:void put(long):20:20 -> a\n    1:1:void put():30 -> a\n");
    assert_eq!(p.warnings, []);
    assert_eq!(entries(p.mappings.methods()), [("La;->a()V", "put"), ("La;->a(I)V", "put")]);
}

#[test]
fn residual_signatures_win_and_cover_later_ranges() {
    let p = parse(
        "com.a.Cart -> z.d:\n\
         \x20   java.util.List items -> a\n\
         \x20     # {\"id\":\"com.android.tools.r8.residualsignature\",\"signature\":\"Ljava/util/ArrayList;\"}\n\
         \x20   1:3:long cost(com.a.Item[],int):83:85 -> b\n\
         \x20     # {\"id\":\"com.android.tools.r8.residualsignature\",\"signature\":\"([Lz/e;)J\"}\n\
         \x20   4:4:int com.a.Item.price():9:9 -> b\n\
         \x20   4:4:long cost(com.a.Item[],int):86 -> b\n\
         \x20   5:9:long cost(com.a.Item[],int):87:89 -> b\n\
         \x20   1:1:long cost(com.a.Item[]):90:90 -> c\n\
         com.a.Item -> z.e:\n",
    );
    assert_eq!(p.warnings, []);
    assert_eq!(entries(p.mappings.fields()), [("Lz/d;->a:Ljava/util/ArrayList;", "items")]);
    // The overload after it has no residual signature of its own.
    assert_eq!(entries(p.mappings.methods()), [("Lz/d;->b([Lz/e;)J", "cost"), ("Lz/d;->c([Lz/e;)J", "cost")]);
}

#[test]
fn comments_and_metadata_are_ignored() {
    let p = parse(
        "# compiler: R8\n\
         # {\"id\":\"com.android.tools.r8.mapping\",\"version\":\"2.2\"}\n\
         # pg_map_id: 1234\n\
         com.a.B -> a:\n\
         # {\"id\":\"sourceFile\",\"fileName\":\"B.java\"}\n\
         # {\"id\":\"com.android.tools.r8.synthesized\"}\n\
         \x20   1:1:void lambda$x$0():5:5 -> a\n\
         \x20     # {\"id\":\"com.android.tools.r8.synthesized\"}\n\
         \x20     # {\"id\":\"com.android.tools.r8.outlineCallsite\",\"positions\":{\"1\":2}}\n\
         \x20     # {\"id\":\"com.android.tools.r8.residualsignature\",\n\
         \x20     # {\"id\":\"something.new\",\"signature\":\"(J)V\"}\n\
         \x20     # not json at all\n\
         \n\
         \x20   int f -> b\n",
    );
    assert_eq!(p.warnings, []);
    assert_eq!(entries(p.mappings.classes()), [("La;", "Lcom/a/B;")]);
    assert_eq!(entries(p.mappings.methods()), [("La;->a()V", "lambda$x$0")]);
    assert_eq!(entries(p.mappings.fields()), [("La;->b:I", "f")]);
}

#[test]
fn crlf_trailing_whitespace_and_bom_are_tolerated() {
    let unix = parse("com.a.B -> a:\n    int f -> b\n    1:2:void g(int):3:4 -> c\n");
    let windows = parse("\u{feff}com.a.B -> a:  \r\n    int f -> b \t\r\n    1:2:void g(int):3:4 -> c\r\n");
    assert_eq!(unix, windows);
    assert_eq!(unix.mappings.methods().len(), 1);
}

#[test]
fn removed_classes_are_skipped() {
    let p = parse("com.a.Gone -> R8$$REMOVED$$CLASS$$0:\n    int f -> a\ncom.a.B -> b:\n    com.a.Gone g -> a\n");
    assert_eq!(p.warnings, []);
    assert_eq!(entries(p.mappings.classes()), [("Lb;", "Lcom/a/B;")]);
    assert_eq!(entries(p.mappings.fields()), [("Lb;->a:Lcom/a/Gone;", "g")]);
}

#[test]
fn conflicts_keep_the_first_entry_and_warn() {
    let p = parse(
        "com.a.One -> a:\n\
         \x20   int x -> a\n\
         \x20   int y -> a\n\
         \x20   int x -> a\n\
         com.a.Two -> a:\n\
         com.a.One -> b:\n",
    );
    let m = &p.mappings;
    assert_eq!(entries(m.classes()), [("La;", "Lcom/a/One;"), ("Lb;", "Lcom/a/One;")]);
    assert_eq!(entries(m.fields()), [("La;->a:I", "x")]);
    let warnings: Vec<String> = p.warnings.iter().map(ToString::to_string).collect();
    assert_eq!(
        warnings,
        [
            "mapping file line 5: La; mapped again to Lcom/a/Two;; keeping Lcom/a/One;",
            "mapping file line 6: original class com.a.One mapped again from b; keeping a",
            "mapping file line 3: La;->a:I mapped again to y; keeping x",
        ]
    );
}

#[test]
fn unusable_names_are_warnings() {
    let p = parse("com.a.B -> a:\n    int f -> b\ncom.a.C -> a..b:\n    int g -> c\n");
    assert_eq!(p.warnings, [ProguardWarning { line: 3, kind: MappingError::Class("La//b;".into()).into() }]);
    assert_eq!(p.mappings.fields().len(), 1);
}

#[test]
fn syntax_errors_carry_line_numbers() {
    let cases = [
        ("# header\nint f -> a\n", 2),
        ("    int f -> a\n", 1),
        ("com.a.B -> a:\n    int f a\n", 2),
        ("com.a.B -> a:\n    1:2:int f -> a\n", 2),
        ("com.a.B -> a:\n    void g(int:3 -> a\n", 2),
        ("com.a.B -> a:\n    void g(int):x -> a\n", 2),
        ("com.a.B -> a\n", 1),
    ];
    for (text, want) in cases {
        match NameMappings::from_proguard(text) {
            Err(ProguardError::Syntax { line, .. }) => assert_eq!(line, want, "{text:?}"),
            other => panic!("{text:?}: {other:?}"),
        }
    }
}

#[test]
fn reader_and_file_give_the_same_result() {
    let text = "com.a.B -> a:\n    int f -> b\n";
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mapping.txt");
    std::fs::write(&path, text).unwrap();
    assert_eq!(NameMappings::from_proguard_reader(text.as_bytes()).unwrap(), parse(text));
    assert_eq!(NameMappings::from_proguard_file(&path).unwrap(), parse(text));
    let missing = NameMappings::from_proguard_file(dir.path().join("none.txt")).unwrap_err();
    assert!(matches!(missing, ProguardError::File { .. }), "{missing}");
}

/// A mapping file shaped like a large app's: classes in nested packages,
/// each with fields, overloads and R8 inline stacks.
fn synthetic(classes: usize) -> String {
    use std::fmt::Write;
    let mut out = String::from("# compiler: R8\n# {\"id\":\"com.android.tools.r8.mapping\",\"version\":\"2.2\"}\n");
    for c in 0..classes {
        let next = (c + 1) % classes;
        let next_class = format!("com.example.p{}.Class{next}", next % 97);
        writeln!(out, "com.example.p{}.Class{c} -> o{}.c{c}:", c % 97, c % 13).unwrap();
        writeln!(out, "# {{\"id\":\"sourceFile\",\"fileName\":\"Class{c}.java\"}}").unwrap();
        for f in 0..4 {
            writeln!(out, "    {next_class}[] field{f} -> f{f}").unwrap();
        }
        for m in 0..4 {
            writeln!(out, "    1:4:void method{m}(int,{next_class}):10:13 -> m{m}").unwrap();
            writeln!(out, "    5:5:int {next_class}.helper():40:40 -> m{m}").unwrap();
            writeln!(out, "    5:5:void method{m}(int,{next_class}):14 -> m{m}").unwrap();
            writeln!(out, "    6:9:void method{m}(int,{next_class}):15:18 -> m{m}").unwrap();
        }
        writeln!(out, "    1:1:long method0(long[]):30:30 -> m0").unwrap();
        writeln!(out, "      # {{\"id\":\"com.android.tools.r8.residualsignature\",\"signature\":\"([J)J\"}}").unwrap();
    }
    out
}

#[test]
fn synthetic_files_parse_completely() {
    let p = parse(&synthetic(800));
    assert_eq!(p.warnings, []);
    assert_eq!((p.mappings.classes().len(), p.mappings.fields().len(), p.mappings.methods().len()), (800, 3_200, 4_000));
    assert_eq!(p.mappings.method("Lo1/c1;->m2(ILo2/c2;)V"), Some("method2"));
    assert_eq!(p.mappings.method("Lo1/c1;->m0([J)J"), Some("method0"));
    assert_eq!(p.mappings.field("Lo6/c799;->f3:[Lo0/c0;"), Some("field3"));
}

/// About 200k lines (12 MB). Some 0.1 s optimised, over a second in a
/// debug build, hence opt-in.
#[test]
#[ignore = "timing: cargo test --release -p asc-engine -- --ignored large_files"]
fn large_files_parse_in_linear_time() {
    let text = synthetic(8_500);
    let lines = text.lines().count();
    assert!(lines > 200_000, "{lines}");
    let start = Instant::now();
    let p = parse(&text);
    let elapsed = start.elapsed();
    assert_eq!(p.warnings, []);
    assert_eq!((p.mappings.classes().len(), p.mappings.fields().len(), p.mappings.methods().len()), (8_500, 34_000, 42_500));
    eprintln!("parsed {lines} lines ({} bytes) in {elapsed:?}", text.len());
}
