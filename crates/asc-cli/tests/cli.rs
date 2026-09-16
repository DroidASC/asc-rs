//! End-to-end tests of the `droidasc` binary against a synthetic APK.

use asc_fixture::{make_apk, make_dex};
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
