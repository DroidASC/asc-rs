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
fn findrefs_prints_python_format_lines() {
    let apk = temp_apk();
    let out = droidasc(&["findrefs", path(apk.path()), "string", "token"]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    let mut lines: Vec<&str> = text.lines().collect();
    lines.sort_unstable();
    assert_eq!(
        lines,
        [
            "classes.dex | Lexample/Test;->first | matched=(token)",
            "classes.dex | Lexample/Test;->second | matched=(token)",
            "classes2.dex | Lexample/Test;->first | matched=(token)",
            "classes2.dex | Lexample/Test;->second | matched=(token)",
        ]
    );
    let out = droidasc(&["findrefs", path(apk.path()), "type", "example.Test"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).lines().all(|l| l.contains(" | Lexample/Test;->") && l.contains("| matched=(")));
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
    assert!(stderr(&out).contains("method query needs at least one of class or method name"), "{}", stderr(&out));
    let out = droidasc(&["findrefs", path(apk.path()), "method", "first", "--class", "example.Test"]);
    assert!(out.status.success(), "{}", stderr(&out));
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
fn legacy_gui_rewrite_does_not_touch_normal_invocations() {
    let apk = temp_apk();
    // `--gui` inside a real subcommand is rejected by clap, not rewritten into `gui`.
    let out = droidasc(&["findrefs", path(apk.path()), "string", "token", "--gui"]);
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("--gui"), "{}", stderr(&out));
    let out = droidasc(&["findrefs", path(apk.path()), "string", "token"]);
    assert!(out.status.success(), "{}", stderr(&out));
}

#[test]
fn help_shows_computed_thread_default() {
    let out = droidasc(&["--help"]);
    assert!(out.status.success());
    let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(8);
    let text = stdout(&out);
    assert!(text.contains(&format!("[default: {n}]")), "{text}");
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
