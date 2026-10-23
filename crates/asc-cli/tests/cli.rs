//! End-to-end tests of the `droidasc` binary against a synthetic APK.

use asc_fixture::{make_apk, make_class_only_dex, make_dex, make_dex041_container, make_static_field_dex};
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output};

/// `bytes` as an `.apk` file that lives as long as the returned handle.
fn temp_apk_from(bytes: &[u8]) -> tempfile::NamedTempFile {
    let mut f = tempfile::Builder::new().suffix(".apk").tempfile().unwrap();
    f.write_all(bytes).unwrap();
    f.flush().unwrap();
    f
}

fn temp_apk() -> tempfile::NamedTempFile {
    let dex = make_dex();
    temp_apk_from(&make_apk(&[("classes.dex", &dex), ("classes2.dex", &dex)], true))
}

/// Run the binary with `args`; `--no-cache` keeps the user's cache untouched.
fn droidasc(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_droidasc")).arg("--no-cache").args(args).output().expect("run droidasc")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr)
}

fn path(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn getclass_prints_smali() {
    let apk = temp_apk();
    for name in ["Lexample/Test;", "example.Test", "example/Test"] {
        let out = droidasc(&["getclass", path(apk.path()), name]);
        assert!(out.status.success(), "{}", stderr(&out));
        let text = stdout(&out);
        assert!(text.contains(".class public Lexample/Test;"), "{text}");
        assert!(text.contains("const-string v0, \"token\""), "{text}");
    }
    let out = droidasc(&["getclass", path(apk.path()), "Lnope/Missing;"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).starts_with("Error:"), "{}", stderr(&out));
}

#[test]
fn getclass_debug_keeps_stdout_clean() {
    let apk = temp_apk();
    let dir = tempfile::tempdir().unwrap();
    let dex = dir.path().join("Test.dex");
    // Both entries define the class; one worker makes the winner deterministic.
    let out = droidasc(&["getclass", path(apk.path()), "example.Test", "--debug", "--threads", "1", "--dump-dex", path(&dex)]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(!text.contains("[DEBUG]") && !text.contains("[APK]"), "{text}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("[DEBUG] Hit DEX: classes.dex"));
    assert!(std::fs::read(&dex).unwrap().starts_with(b"dex\n"));
}

#[test]
fn findrefs_prints_one_line_per_method() {
    let apk = temp_apk();
    let out = droidasc(&["findrefs", path(apk.path()), "string", "token"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    let mut lines: Vec<&str> = text.lines().collect();
    lines.sort_unstable();
    assert_eq!(
        lines,
        [
            "classes.dex | Lexample/Test;->first()V | \"token\"",
            "classes.dex | Lexample/Test;->second()V | \"token\"",
            "classes2.dex | Lexample/Test;->first()V | \"token\"",
            "classes2.dex | Lexample/Test;->second()V | \"token\"",
        ]
    );
    let out = droidasc(&["findrefs", path(apk.path()), "type", "example.Test"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).lines().all(|l| l.contains(" | Lexample/Test;->") && l.split(" | ").count() == 3));
}

#[test]
fn findrefs_all_rules_and_hierarchy() {
    let apk = temp_apk();
    let a = path(apk.path());
    let sorted = |o: &Output| {
        let mut l: Vec<String> = stdout(o).lines().map(String::from).collect();
        l.sort();
        l
    };
    let out = droidasc(&["findrefs", a, "all", "string:tok", "literal:token", "--threads", "1"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        sorted(&out),
        [
            "classes.dex | Lexample/Test;->first()V | \"token\", \"token\"",
            "classes.dex | Lexample/Test;->second()V | \"token\", \"token\"",
            "classes2.dex | Lexample/Test;->first()V | \"token\", \"token\"",
            "classes2.dex | Lexample/Test;->second()V | \"token\", \"token\"",
        ]
    );
    let out = droidasc(&["findrefs", a, "all", "string:token", "--none", "string:oke"]);
    assert!(out.status.success() && stdout(&out).is_empty(), "{}", stderr(&out));
    let out = droidasc(&["findrefs", a, "all", "nonsense"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("KIND:VALUE"), "{}", stderr(&out));

    let rules = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(rules.path(), "# comment\nextends:java.lang.Object\n").unwrap();
    let out = droidasc(&["findrefs", a, "rules", "string:token", "string:nothing & literal:token", "--file", path(rules.path())]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.starts_with("# r1 string:token\n# r2 string:nothing & literal:token\n# r3 extends:java.lang.Object\n"), "{text}");
    assert!(text.ends_with("# r1 4 results\n# r2 0 results\n# r3 2 results\n"), "{text}");
    assert_eq!(text.lines().filter(|l| l.starts_with("r1 | ")).count(), 4);
    assert!(text.contains("r3 | classes2.dex | Lexample/Test; | extends Ljava/lang/Object;\n"), "{text}");

    let out = droidasc(&["hierarchy", a, "java.lang.Object", "--method", "second"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        stdout(&out),
        "0 Ljava/lang/Object; [not in APK]\n  1 subclass Lexample/Test; classes.dex [defines second()V]\n\
         override Lexample/Test;->second()V classes.dex\n# 2 rows, 2 distinct classes (subclasses, depth 16); 1 define second\n"
    );
    let out = droidasc(&["callgraph", a, "example.Test", "first", "--virtual"]);
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn global_flags_are_accepted_anywhere() {
    let apk = temp_apk();
    let a = droidasc(&["--threads", "2", "--debug", "findrefs", path(apk.path()), "string", "token"]);
    let b = droidasc(&["findrefs", path(apk.path()), "string", "token", "--threads", "2", "--debug"]);
    let c = droidasc(&["findrefs", "--thread", "1", path(apk.path()), "string", "token"]);
    for o in [&a, &b, &c] {
        assert!(o.status.success(), "{}", stderr(o));
        assert_eq!(stdout(o).lines().count(), 4);
        assert!(!stdout(o).contains("[DEBUG]"));
    }
    assert!(String::from_utf8_lossy(&a.stderr).contains("[DEBUG]"));
    assert!(String::from_utf8_lossy(&b.stderr).contains("[DEBUG]"));
}

#[test]
fn member_query_needs_a_class_or_a_name() {
    let apk = temp_apk();
    let out = droidasc(&["findrefs", path(apk.path()), "method"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("method query needs a class or a method name"), "{}", stderr(&out));
    let out = droidasc(&["findrefs", path(apk.path()), "method", "first", "--class", "example.Test"]);
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn exact_flag_matches_whole_member_names() {
    let dex = asc_fixture::make_static_field_dex();
    let apk = temp_apk_from(&make_apk(&[("classes.dex", &dex)], false));
    let run = |args: &[&str]| {
        let mut all = vec!["findrefs", path(apk.path()), "field"];
        all.extend_from_slice(args);
        let out = droidasc(&all);
        assert!(out.status.success(), "{}", stderr(&out));
        stdout(&out)
    };
    let hit = "classes.dex | Lexample/Statics;->getSecond()I | Lexample/Statics;->SECOND:I\n";
    assert_eq!(run(&["SECON"]), hit);
    assert_eq!(run(&["SECOND", "--exact"]), hit);
    assert_eq!(run(&["SECOND", "--exact", "--class", "example.Statics"]), hit);
    assert_eq!(run(&["SECOND", "--exact", "--class", "Statics", "--fuzzy-class"]), hit);
    for args in [&["SECON", "--exact"][..], &["SECON", "--exact", "--class", "example.Statics"], &["SEC.ND", "--exact"]] {
        assert_eq!(run(args), "", "{args:?}");
    }
}

#[test]
fn output_flag_writes_the_file() {
    let apk = temp_apk();
    let dir = tempfile::tempdir().unwrap();
    let refs = dir.path().join("refs.txt");
    let out = droidasc(&["findrefs", path(apk.path()), "string", "token", "-o", path(&refs)]);
    assert!(out.status.success(), "{}", stderr(&out));
    let file = std::fs::read_to_string(&refs).unwrap();
    assert_eq!(file.lines().count(), 4);
    assert_eq!(file, stdout(&out));
    let smali = dir.path().join("Test.smali");
    let out = droidasc(&["getclass", path(apk.path()), "example.Test", "-o", path(&smali)]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(std::fs::read_to_string(&smali).unwrap(), stdout(&out));
}

#[test]
fn unreadable_output_path_is_an_error() {
    let apk = temp_apk();
    let dir = tempfile::tempdir().unwrap();
    let out = droidasc(&["findrefs", path(apk.path()), "string", "token", "-o", path(dir.path())]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("cannot write"), "{}", stderr(&out));
}

#[test]
fn foreign_cache_dir_is_reported_and_left_alone() {
    let f = temp_apk();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("notes.txt"), b"keep").unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_droidasc"))
        .env("DROIDASC_DAEMON", "off")
        // A fixed budget, so the test does not depend on the free space of the temp dir.
        .env("DROIDASC_CACHE_MAX_MB", "1024")
        .args(["--cache-dir", path(dir.path()), "findrefs", path(f.path()), "string", "token"])
        .output()
        .expect("run droidasc");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(String::from_utf8_lossy(&out.stderr).contains("disk cache disabled"), "{}", stderr(&out));
    let names: Vec<_> = std::fs::read_dir(dir.path()).unwrap().map(|d| d.unwrap().file_name()).collect();
    assert_eq!(names, ["notes.txt"]);
}

#[test]
fn broken_dex_entry_gives_partial_exit_status() {
    let dex = make_dex();
    let bytes = make_apk(&[("classes.dex", &dex), ("classes2.dex", b"this is not a dex file")], true);
    let f = temp_apk_from(&bytes);
    let out = droidasc(&["findrefs", path(f.path()), "string", "token"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert_eq!(stdout(&out).lines().count(), 2, "{}", stdout(&out));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Warning: classes2.dex"), "{}", stderr(&out));
}

#[test]
fn help_explains_thread_default() {
    let out = droidasc(&["--help"]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains("busy mcp / daemon processes"), "{text}");
    assert!(text.contains("exit status"), "{text}");
}

#[test]
fn usage_errors_exit_1_not_2() {
    // 2 is reserved for "findrefs finished with unsearchable entries".
    for args in [&[][..], &["findrefs"][..], &["findrefs", "x.apk", "string"][..], &["--bogus"][..]] {
        let out = droidasc(args);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {}", stderr(&out));
    }
    assert!(droidasc(&["--version"]).status.success());
}

#[test]
fn class_that_cannot_be_rebuilt_is_still_disassembled() {
    let dex = asc_fixture::make_rich_dex();
    let bytes = make_apk(&[("classes.dex", &dex)], true);
    let f = temp_apk_from(&bytes);
    let out = droidasc(&["getclass", path(f.path()), "Lexample/Broken;"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains(".class"), "{}", stdout(&out));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Warning: class not rebuilt"), "{}", stderr(&out));
    // Without a rebuilt DEX there is nothing to dump.
    let dir = tempfile::tempdir().unwrap();
    let out = droidasc(&["getclass", path(f.path()), "Lexample/Broken;", "--dump-dex", path(&dir.path().join("b.dex"))]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("not rebuilt"), "{}", stderr(&out));
}

// ---- upstream parity: extends / impl, disassemble, --method -------------

fn rich_apk() -> tempfile::NamedTempFile {
    let dex = asc_fixture::make_rich_dex();
    temp_apk_from(&make_apk(&[("classes.dex", &dex), ("classes2.dex", &make_dex())], true))
}

fn sorted_lines(o: &Output) -> Vec<String> {
    let mut v: Vec<String> = stdout(o).lines().map(str::to_string).collect();
    v.sort_unstable();
    v
}

#[test]
fn findrefs_context_and_callgraph() {
    let apk = temp_apk();
    let out = droidasc(&["findrefs", path(apk.path()), "string", "token", "--context", "0", "--threads", "1"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    // first / second share one code item: both rows show the same instruction.
    assert!(
        text.contains("classes.dex | Lexample/Test;->first()V | \"token\"\n  @ pc 0x0\n  >     const-string v0, \"token\"\n"),
        "{text}"
    );
    assert_eq!(text.matches("  >     const-string").count(), 4, "{text}");
    let out = droidasc(&["findrefs", path(apk.path()), "--context-method", "string", "token"]);
    assert!(stdout(&out).contains("    .method public static second()V\n"), "{}", stdout(&out));
    let out = droidasc(&["findrefs", path(apk.path()), "string", "token", "--context", "1", "--context-method"]);
    assert_eq!(out.status.code(), Some(1));

    let apk = rich_apk();
    let out = droidasc(&["callgraph", path(apk.path()), "example.Rich", "<init>", "--callees"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        stdout(&out),
        "0 Lexample/Rich;-><init>()V\n  1 -> Ljava/lang/Object;-><init>()V [no body]\n# 2 rows, 2 distinct methods (callees, depth 2)\n"
    );
    let out = droidasc(&["callgraph", path(apk.path()), "example.Rich", "nope"]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn findrefs_extends_and_impl_print_class_rows() {
    let apk = rich_apk();
    for target in ["java.lang.Object", "Ljava/lang/Object;", "java/lang/Object"] {
        let out = droidasc(&["findrefs", path(apk.path()), "extends", target]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(
            sorted_lines(&out),
            [
                "classes.dex | Lexample/Broken; | extends Ljava/lang/Object;",
                "classes.dex | Lexample/Custom; | extends Ljava/lang/Object;",
                "classes.dex | Lexample/Iface; | extends Ljava/lang/Object;",
                "classes.dex | Lexample/Rich; | extends Ljava/lang/Object;",
                "classes2.dex | Lexample/Test; | extends Ljava/lang/Object;",
            ]
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("impls.txt");
    let out = droidasc(&["findrefs", path(apk.path()), "impl", "example.Iface", "-o", path(&file)]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "classes.dex | Lexample/Rich; | implements Lexample/Iface;\n");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), stdout(&out));
    // Direct relations only; unknown targets give no rows and no error.
    for args in [["extends", "example.Iface"], ["impl", "java.lang.Object"], ["extends", "no.such.Clazz"]] {
        let out = droidasc(&["findrefs", path(apk.path()), args[0], args[1]]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert!(out.stdout.is_empty(), "{args:?}: {}", stdout(&out));
    }
    let out = droidasc(&["findrefs", path(apk.path()), "extends", ""]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("Class name cannot be empty"), "{}", stderr(&out));
}

#[test]
fn findrefs_string_literal_ignores_regex_syntax() {
    let apk = temp_apk();
    let regex = droidasc(&["findrefs", path(apk.path()), "string", "t.k"]);
    assert_eq!(sorted_lines(&regex).len(), 4, "{}", stderr(&regex));
    let literal = droidasc(&["findrefs", path(apk.path()), "string", "--literal", "t.k"]);
    assert!(literal.status.success() && literal.stdout.is_empty(), "{}", stderr(&literal));
    // An invalid regex is a fine literal.
    let out = droidasc(&["findrefs", path(apk.path()), "string", "oke(", "--literal"]);
    assert!(out.status.success() && out.stdout.is_empty(), "{}", stderr(&out));
    assert_eq!(droidasc(&["findrefs", path(apk.path()), "string", "oke("]).status.code(), Some(1));
    let out = droidasc(&["findrefs", path(apk.path()), "string", "--literal", "oke"]);
    assert_eq!(sorted_lines(&out), sorted_lines(&droidasc(&["findrefs", path(apk.path()), "string", "oke"])));
    assert_eq!(sorted_lines(&out).len(), 4);
}

#[test]
fn disassemble_defaults_to_no_debug_directives_and_writes_only_the_file() {
    let apk = rich_apk();
    let a = droidasc(&["disassemble", path(apk.path()), "example.Rich"]);
    assert!(a.status.success(), "{}", stderr(&a));
    let text = stdout(&a);
    assert!(text.contains(".method public static compute(II)I") && !text.contains(".line"), "{text}");
    let b = droidasc(&["disassemble", path(apk.path()), "example.Rich", "--debuginfo"]);
    assert!(stdout(&b).contains(".line"), "{}", stdout(&b));
    // `--debuginfo` output is what getclass prints by default.
    assert_eq!(stdout(&b), stdout(&droidasc(&["getclass", path(apk.path()), "example.Rich"])));
    assert_eq!(text, stdout(&droidasc(&["getclass", path(apk.path()), "example.Rich", "--no-debug-info"])));
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("Rich.smali");
    let out = droidasc(&["disassemble", path(apk.path()), "Lexample/Rich;", "-o", path(&file)]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(out.stdout.is_empty(), "{}", stdout(&out));
    assert_eq!(std::fs::read_to_string(&file).unwrap(), text);
}

#[test]
fn method_flag_takes_a_name_or_a_signature() {
    let apk = rich_apk();
    for cmd in ["getclass", "disassemble"] {
        let out = droidasc(&[cmd, path(apk.path()), "example.Rich", "--method", "run()V"]);
        assert!(out.status.success(), "{}", stderr(&out));
        let text = stdout(&out);
        assert_eq!(text.matches(".method ").count(), 1, "{text}");
        assert!(text.contains(".method public run()V") && !text.contains(".field"), "{text}");
        // A bare name or a Java-style signature picks the same method.
        for m in ["run", "run()", "Lexample/Rich;->run()V"] {
            let out = droidasc(&[cmd, path(apk.path()), "example.Rich", "--method", m]);
            assert!(out.status.success(), "{m}: {}", stderr(&out));
            let picked = stdout(&out);
            assert_eq!(picked.matches(".method ").count(), 1, "{m}: {picked}");
            assert!(picked.contains(".method public run()V") && !picked.contains(".field"), "{m}: {picked}");
        }
        // A method the class lacks: the error lists the ones it has.
        let out = droidasc(&[cmd, path(apk.path()), "example.Rich", "--method", "run(I)V"]);
        assert_eq!(out.status.code(), Some(1));
        let err = stderr(&out);
        assert!(err.contains("Lexample/Rich; has no method \"run(I)V\"; its methods: ") && err.contains("run()V"), "{err}");
    }
    // The dumped DEX still holds the whole class.
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("a.dex"), dir.path().join("b.dex"));
    assert!(droidasc(&["getclass", path(apk.path()), "example.Rich", "--dump-dex", path(&a)]).status.success());
    assert!(droidasc(&["getclass", path(apk.path()), "example.Rich", "--method", "run()V", "--dump-dex", path(&b)]).status.success());
    assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
}

#[test]
fn rasc_aliases_and_version_flags() {
    let apk = temp_apk();
    let a = droidasc(&["classes", path(apk.path()), "--thread", "1"]);
    assert!(a.status.success(), "{}", stderr(&a));
    assert_eq!(stdout(&a), stdout(&droidasc(&["listclass", path(apk.path())])));
    // No AndroidManifest.xml in the fixture: both names reach the same error.
    let m = droidasc(&["manifest", path(apk.path())]);
    let g = droidasc(&["getmanifest", path(apk.path())]);
    assert_eq!(m.status.code(), Some(1));
    assert_eq!(stderr(&m), stderr(&g));
    assert!(stderr(&m).starts_with("Error:"), "{}", stderr(&m));
    for flag in ["-v", "-V", "--version"] {
        let out = droidasc(&[flag]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert!(stdout(&out).starts_with("droidasc "), "{}", stdout(&out));
    }
}

// ---- listclass (ported from the Python `test_listclass.py`) -------------

#[test]
fn listclass_filters_a_normalized_prefix() {
    let dex = make_class_only_dex(&["Lcom/xxx/First;", "Lcom/xxx/internal/Second;", "Lorg/example/Other;"], 0, false);
    for deflate in [false, true] {
        let apk = temp_apk_from(&make_apk(&[("classes.dex", &dex)], deflate));
        for prefix in ["com.xxx", "com/xxx", "Lcom/xxx"] {
            let out = droidasc(&["listclass", path(apk.path()), "--prefix", prefix]);
            assert!(out.status.success(), "{}", stderr(&out));
            assert_eq!(stdout(&out), "Lcom/xxx/First;\nLcom/xxx/internal/Second;\n", "{prefix} deflate={deflate}");
        }
        let out = droidasc(&["listclass", path(apk.path()), "--prefix", "net"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), "");
    }
}

#[test]
fn listclass_keeps_dex_order_and_writes_only_the_file_with_output() {
    let (a, b) = (make_dex(), make_static_field_dex());
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("classes.txt");
    for deflate in [false, true] {
        let apk = temp_apk_from(&make_apk(&[("classes.dex", &a), ("classes2.dex", &b), ("classes3.dex", &a)], deflate));
        let out = droidasc(&["listclass", path(apk.path()), "--threads", "2", "-o", path(&file)]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), "");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "Lexample/Test;\nLexample/Statics;\nLexample/Test;\n");
    }
}

#[test]
fn listclass_lists_a_large_deflated_dex() {
    let mut dex = make_dex();
    let mut x = 0x2545_f491_4f6c_dd1du64;
    dex.extend((0..1 << 20).map(|_| {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x as u8
    }));
    let len = dex.len() as u32;
    dex[0x20..0x24].copy_from_slice(&len.to_le_bytes());
    let apk = temp_apk_from(&make_apk(&[("classes.dex", &dex)], true));
    let out = droidasc(&["listclass", path(apk.path())]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "Lexample/Test;\n");
}

#[test]
fn listclass_lists_every_logical_dex_of_a_041_container() {
    let container = make_dex041_container();
    for deflate in [false, true] {
        let apk = temp_apk_from(&make_apk(&[("classes.dex", &container)], deflate));
        let out = droidasc(&["listclass", path(apk.path()), "--threads", "1"]);
        assert!(out.status.success(), "{}", stderr(&out));
        assert_eq!(stdout(&out), "Lalpha/First;\nLshared/Duplicate;\nLbeta/Second;\nLshared/Duplicate;\n");
    }
}

#[test]
fn listclass_bad_class_type_index_is_a_clean_error() {
    let mut dex = make_dex();
    let off = u32::from_le_bytes(dex[0x64..0x68].try_into().unwrap()) as usize;
    dex[off..off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    let apk = temp_apk_from(&make_apk(&[("classes.dex", &dex)], false));
    let out = droidasc(&["listclass", path(apk.path())]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.starts_with("Error: classes.dex: class_def 0: type index 4294967295 out of range"), "{err}");
}

#[test]
fn listclass_rejects_an_empty_prefix_and_accepts_zero_threads() {
    let apk = temp_apk_from(&make_apk(&[("classes.dex", &make_dex())], false));
    let out = droidasc(&["listclass", path(apk.path()), "--prefix", " "]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Error: Class prefix cannot be empty"), "{}", stderr(&out));
    // Like every other subcommand, `--threads 0` means one worker.
    let out = droidasc(&["listclass", path(apk.path()), "--threads", "0"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out), "Lexample/Test;\n");
}

#[test]
fn mcp_serves_line_delimited_json_rpc_until_stdin_closes() {
    use std::process::Stdio;
    let apk = temp_apk();
    let mut child = Command::new(env!("CARGO_BIN_EXE_droidasc"))
        .args(["--no-cache", "--threads", "2", "mcp", "--memory-mb", "64"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let requests = [
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}),
        serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "findrefs", "arguments": {"apk": path(apk.path()), "kind": "string", "value": "token"}}}),
    ];
    let mut stdin = child.stdin.take().unwrap();
    for r in &requests {
        writeln!(stdin, "{r}").unwrap();
    }
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let replies: Vec<serde_json::Value> = stdout(&out).lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(replies.len(), 2, "{}", stdout(&out));
    assert_eq!(replies[0]["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(replies[1]["result"]["structuredContent"]["total"], 4);
    let text = replies[1]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("classes.dex | Lexample/Test;->first()V | \"token\"\n"), "{text}");
}

#[test]
fn cache_stats_reports_the_disk_budget() {
    let f = temp_apk();
    let dir = tempfile::tempdir().unwrap();
    let run = |env: Option<&str>, args: &[&str]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_droidasc"));
        cmd.env("DROIDASC_DAEMON", "off");
        match env {
            Some(v) => cmd.env("DROIDASC_CACHE_MAX_MB", v),
            None => cmd.env_remove("DROIDASC_CACHE_MAX_MB"),
        };
        cmd.args(["--cache-dir", path(dir.path())]).args(args).output().expect("run droidasc")
    };
    // Fill with a fixed budget (the automatic one refuses writes when the temp dir is
    // nearly full), then report with the automatic one.
    let out = run(Some("1024"), &["findrefs", path(f.path()), "string", "token"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = run(None, &["cache", "stats"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("\n1 APKs, "), "{text}");
    assert!(text.contains(" (auto), used "), "{text}");
    assert!(text.contains("  L1 dex ") && text.contains("  L2 derived ") && text.contains("  L3 rendered "), "{text}");
    if cfg!(unix) {
        assert!(text.contains("file system: ") && text.contains(" free of "), "{text}");
    }
    // An explicit budget wins over the automatic one; the flag over the environment.
    assert!(stdout(&run(None, &["--cache-max-mb", "3", "cache", "stats"])).contains("budget: 3.0 MiB (explicit)"));
    assert!(stdout(&run(Some("5"), &["cache", "stats"])).contains("budget: 5.0 MiB (explicit)"));
    assert!(stdout(&run(Some("5"), &["--cache-max-mb", "7", "cache", "stats"])).contains("budget: 7.0 MiB (explicit)"));
}

#[test]
fn zero_disk_budget_evicts_after_the_query() {
    let f = temp_apk();
    let dir = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_droidasc"))
            .env("DROIDASC_DAEMON", "off")
            .args(["--cache-dir", path(dir.path())])
            .args(args)
            .output()
            .expect("run droidasc")
    };
    let out = run(&["--cache-max-mb", "0", "findrefs", path(f.path()), "string", "token"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&run(&["cache", "stats"])).contains("0 APKs, 0 files"));
}

#[test]
fn memory_budget_is_a_global_flag() {
    // Before the subcommand as well as after it; one-shot commands accept and ignore it.
    let apk = temp_apk();
    let out = droidasc(&["--memory-mb", "64", "findrefs", path(apk.path()), "string", "token"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let out = droidasc(&["listclass", path(apk.path()), "--memory-mb", "64"]);
    assert!(out.status.success(), "{}", stderr(&out));
}

fn audit_apk() -> tempfile::NamedTempFile {
    let (manifest, arsc) = asc_fixture::res::audit_manifest(30);
    let files = asc_fixture::res::audit_res_files();
    let mut entries: Vec<(&str, &[u8])> = vec![("AndroidManifest.xml", &manifest), ("resources.arsc", &arsc)];
    entries.extend(files.iter().map(|(p, b)| (*p, b.as_slice())));
    temp_apk_from(&make_apk(&entries, true))
}

#[test]
fn manifest_summary_resources_and_xml() {
    let apk = audit_apk();
    let p = path(apk.path());
    let out = droidasc(&["manifest-summary", p]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.lines().any(|l| l == "receiver com.demo.Boot exported=true (explicit)"), "{text}");
    let out = droidasc(&["manifest-summary", p, "--json"]);
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["package"], "com.demo");

    let out = droidasc(&["resources", p, "bool/exported_flag"]);
    assert_eq!(stdout(&out), "0x7f020000 | bool/exported_flag | false\n0x7f020000 | bool/exported_flag [v31] | true\n");
    let out = droidasc(&["resources", p, "0x7f010000", "--resolve"]);
    assert_eq!(stdout(&out), "chain @string/app_name\n0x7f010000 | string/app_name | \"Demo\"\n");
    let out = droidasc(&["resources", p, "--search", "XML/", "--in", "name", "--limit", "1"]);
    assert_eq!(stdout(&out), "", "the regex is case-sensitive");
    let out = droidasc(&["resources", p, "--search", "xml/", "--in", "name", "--limit", "1", "--spill-mb", "0"]);
    let text = stdout(&out);
    assert_eq!(text.lines().count(), 2, "{text}");
    assert_eq!(text.lines().last(), Some("# records 1-1 of 2 shown; rerun with --offset 1"), "{text}");
    let out = droidasc(&["resources", p]);
    assert_eq!(stdout(&out).lines().count(), 5);
    let out = droidasc(&["resources", p, "--in", "bogus", "--search", "x"]);
    assert_eq!(out.status.code(), Some(1));

    let out = droidasc(&["xml", p, "res/xml/network_security_config.xml"]);
    assert!(stdout(&out).contains("<base-config cleartextTrafficPermitted=\"false\"/>"), "{}", stdout(&out));
    let out = droidasc(&["getmanifest", p, "--resolve"]);
    assert!(stdout(&out).contains("android:networkSecurityConfig=\"@xml/network_security_config\""), "{}", stdout(&out));
    let out = droidasc(&["getmanifest", p]);
    assert!(stdout(&out).contains("android:networkSecurityConfig=\"@7F030000\""), "{}", stdout(&out));
}

#[test]
fn member_targets_and_context_spellings_agree() {
    let apk = rich_apk();
    let p = path(apk.path());
    let want = droidasc(&["findrefs", p, "field", "value", "--class", "example.Rich", "--exact"]);
    assert!(want.status.success() && !stdout(&want).is_empty(), "{}", stderr(&want));
    for target in ["Lexample/Rich;->value:I", "example.Rich.value", "example.Rich#value", "Rich.value"] {
        let out = droidasc(&["findrefs", p, "field", target]);
        assert_eq!(stdout(&out), stdout(&want), "{target}: {}", stderr(&out));
    }
    let a = droidasc(&["findrefs", p, "--context", "method", "field", "Lexample/Rich;->value:I"]);
    let b = droidasc(&["findrefs", p, "--context-method", "field", "Lexample/Rich;->value:I"]);
    assert!(a.status.success() && stdout(&a).contains(".method"), "{}", stderr(&a));
    assert_eq!(stdout(&a), stdout(&b));
    let bad = droidasc(&["findrefs", p, "--context", "lots", "string", "x"]);
    assert!(stderr(&bad).contains("neither a number of lines nor `method`"), "{}", stderr(&bad));
}

#[test]
fn misses_print_hints_on_stderr() {
    let apk = rich_apk();
    let p = path(apk.path());
    let out = droidasc(&["findrefs", p, "string", "HÉLLO"]);
    assert!(out.status.success());
    assert!(stdout(&out).is_empty(), "{}", stdout(&out));
    assert!(stderr(&out).contains("hint: searched 2 DEX entries") && stderr(&out).contains("(?i)"), "{}", stderr(&out));
    let out = droidasc(&["getclass", p, "android.app.Activity"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("framework class"), "{}", stderr(&out));
    let out = droidasc(&["getclass", p, "example.Rch"]);
    assert!(stderr(&out).contains("did you mean Lexample/Rich;"), "{}", stderr(&out));
    let out = droidasc(&["manifest_summary", p]);
    assert!(!stderr(&out).contains("unrecognized subcommand"), "{}", stderr(&out));
}

// ---- output window (--limit / --max-bytes / --offset) and DEX order -------

/// An APK of `n` copies of the token DEX: classes.dex, classes2.dex, ...
fn many_dex_apk(n: usize) -> tempfile::NamedTempFile {
    let dex = make_dex();
    let names: Vec<String> = (1..=n).map(|i| if i == 1 { "classes.dex".to_string() } else { format!("classes{i}.dex") }).collect();
    let entries: Vec<(&str, &[u8])> = names.iter().map(|n| (n.as_str(), dex.as_slice())).collect();
    temp_apk_from(&make_apk(&entries, true))
}

/// `droidasc --no-cache` with cut outputs spilled under `runtime`.
fn droidasc_in(runtime: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_droidasc"))
        .env("XDG_RUNTIME_DIR", runtime)
        .env_remove("DROIDASC_LIMIT")
        .env_remove("DROIDASC_MAX_BYTES")
        .envs(envs.iter().copied())
        .arg("--no-cache")
        .args(args)
        .output()
        .expect("run droidasc")
}

/// The file a cut output's hint names.
fn spilled(hint: &str) -> String {
    let path = hint.split("full output in ").nth(1).and_then(|r| r.split(" (").next()).unwrap_or_else(|| panic!("no file in {hint:?}"));
    std::fs::read_to_string(path).unwrap()
}

#[test]
fn findrefs_rows_follow_dex_order() {
    let apk = many_dex_apk(12);
    let order: Vec<String> = (1..=12).map(|i| if i == 1 { "classes.dex".into() } else { format!("classes{i}.dex") }).collect();
    for _ in 0..3 {
        let out = droidasc(&["findrefs", path(apk.path()), "string", "token", "--threads", "8"]);
        assert!(out.status.success(), "{}", stderr(&out));
        let mut dex: Vec<String> = stdout(&out).lines().map(|l| l.split(" | ").next().unwrap().to_string()).collect();
        assert_eq!(dex.len(), 24, "two hits per DEX");
        dex.dedup();
        assert_eq!(dex, order);
        let out = droidasc(&["findrefs", path(apk.path()), "rules", "string:token", "literal:token", "--threads", "8"]);
        let rows: Vec<String> =
            stdout(&out).lines().filter(|l| !l.starts_with('#')).map(|l| l.split(" | ").take(2).collect::<Vec<_>>().join(" ")).collect();
        let expected: Vec<String> = order.iter().flat_map(|d| [1, 1, 2, 2].map(|r| format!("r{r} {d}"))).collect();
        assert_eq!(rows, expected, "grouped by DEX, then by rule");
    }
}

#[test]
fn limit_cuts_stdout_and_spills_the_whole_output() {
    let apk = many_dex_apk(12);
    let runtime = tempfile::tempdir().unwrap();
    let full = stdout(&droidasc(&["findrefs", path(apk.path()), "string", "token"]));
    let rows: Vec<&str> = full.lines().collect();
    assert_eq!(rows.len(), 24);

    let out = droidasc_in(runtime.path(), &["findrefs", path(apk.path()), "string", "token", "--limit", "3"], &[]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[..3], rows[..3]);
    let hint = lines[3];
    assert!(hint.starts_with("# records 1-3 of 24 shown; full output in "), "{hint}");
    assert!(hint.ends_with(" (grep it, or rerun with --offset 3)"), "{hint}");
    assert_eq!(spilled(hint), full);
    assert!(spilled(hint).starts_with(&rows[0].to_string()));

    // The next page, and past the end.
    let out = droidasc_in(runtime.path(), &["findrefs", path(apk.path()), "string", "token", "--offset", "3", "--limit", "3"], &[]);
    let text = stdout(&out);
    assert_eq!(text.lines().take(3).collect::<Vec<_>>(), rows[3..6]);
    assert!(text.lines().nth(3).unwrap().starts_with("# records 4-6 of 24 shown"), "{text}");
    let out = droidasc_in(runtime.path(), &["findrefs", path(apk.path()), "string", "token", "--offset", "22"], &[]);
    assert_eq!(stdout(&out), format!("{}\n{}\n", rows[22], rows[23]), "the rest fits: no hint");
    let out = droidasc_in(runtime.path(), &["findrefs", path(apk.path()), "string", "token", "--offset", "30"], &[]);
    assert_eq!(stdout(&out), "# no records after --offset 30 (24 in all)\n");

    // Whole records within --max-bytes.
    let budget = rows[0].len() + 1 + rows[1].len() + 1 + 2;
    let out = droidasc_in(runtime.path(), &["findrefs", path(apk.path()), "string", "token", "--max-bytes", &budget.to_string()], &[]);
    let text = stdout(&out);
    assert_eq!(text.lines().take(2).collect::<Vec<_>>(), rows[..2]);
    assert!(text.lines().nth(2).unwrap().starts_with("# records 1-2 of 24 shown"), "{text}");

    // An agent host sets the limit once.
    let out = droidasc_in(runtime.path(), &["findrefs", path(apk.path()), "string", "token"], &[("DROIDASC_LIMIT", "2")]);
    assert!(stdout(&out).lines().nth(2).unwrap().starts_with("# records 1-2 of 24 shown"), "{}", stdout(&out));
    let out = droidasc_in(runtime.path(), &["findrefs", path(apk.path()), "string", "token", "--limit", "5"], &[("DROIDASC_LIMIT", "2")]);
    assert!(stdout(&out).contains("# records 1-5 of 24 shown"), "the flag wins: {}", stdout(&out));

    // No spill directory: the hint pages instead.
    let out = droidasc_in(runtime.path(), &["findrefs", path(apk.path()), "string", "token", "--limit", "3", "--spill-mb", "0"], &[]);
    assert_eq!(stdout(&out).lines().last(), Some("# records 1-3 of 24 shown; rerun with --offset 3"));

    // With -o the file holds everything and the hint names it.
    let dir = tempfile::tempdir().unwrap();
    let o = dir.path().join("refs.txt");
    let out = droidasc_in(runtime.path(), &["findrefs", path(apk.path()), "string", "token", "--limit", "1", "-o", path(&o)], &[]);
    assert_eq!(std::fs::read_to_string(&o).unwrap(), full);
    assert!(stdout(&out).lines().last().unwrap().contains(&format!("full output in {}", o.display())), "{}", stdout(&out));
}

#[test]
fn every_text_command_takes_the_window() {
    let apk = many_dex_apk(2);
    let runtime = tempfile::tempdir().unwrap();
    let p = path(apk.path());
    let whole = stdout(&droidasc(&["getclass", p, "example.Test"]));
    let out = droidasc_in(runtime.path(), &["getclass", p, "example.Test", "--limit", "4"], &[]);
    let text = stdout(&out);
    assert_eq!(text.lines().take(4).collect::<Vec<_>>(), whole.lines().take(4).collect::<Vec<_>>());
    let hint = text.lines().nth(4).unwrap();
    assert!(hint.starts_with(&format!("# records 1-4 of {} shown", whole.lines().count())), "{hint}");
    assert_eq!(spilled(hint), whole);

    // A tree's footer is always shown.
    let tree = stdout(&droidasc(&["callgraph", p, "example.Test", "first", "--callees"]));
    let out = droidasc_in(runtime.path(), &["callgraph", p, "example.Test", "first", "--callees", "--limit", "1", "--spill-mb", "0"], &[]);
    let text = stdout(&out);
    assert_eq!(text.lines().next(), tree.lines().next());
    assert_eq!(text.lines().nth(1), tree.lines().last(), "{text}");

    // Without a window nothing changes, byte for byte.
    for args in [&["listclass", p][..], &["getclass", p, "example.Test"], &["callgraph", p, "example.Test", "first"]] {
        let plain = droidasc(args);
        let huge = droidasc_in(runtime.path(), &[args, &["--limit", "100000"]].concat(), &[]);
        assert_eq!(stdout(&huge), stdout(&plain), "{args:?}");
    }
}

#[test]
fn subcommand_help_leaves_out_the_global_options() {
    let top = stdout(&droidasc(&["--help"]));
    for opt in ["--threads", "--cache-dir", "--cache-max-mb", "--memory-mb", "--no-cache", "--limit", "--max-bytes", "--offset"] {
        assert!(top.contains(opt), "{opt} in droidasc --help:\n{top}");
    }
    for sub in [&["getclass", "--help"][..], &["findrefs", "x.apk", "string", "--help"], &["callgraph", "--help"]] {
        let help = stdout(&droidasc(sub));
        for opt in ["--threads", "--cache-dir", "--cache-max-mb", "--memory-mb", "--no-cache", "--debug"] {
            assert!(!help.contains(opt), "{opt} in {sub:?}:\n{help}");
        }
        assert!(help.contains("--limit"), "{sub:?}:\n{help}");
    }
    // Still accepted after the subcommand.
    let apk = temp_apk();
    let out = droidasc(&["findrefs", path(apk.path()), "string", "token", "--threads", "1", "--cache-dir", "/nonexistent-x"]);
    assert!(out.status.success(), "{}", stderr(&out));
}
