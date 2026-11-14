//! `asc decompile` on HarmonyOS programs: JavaScript of a record from
//! asc-decompile's mock backend in its `--abc` mode (an arkdec stand-in), on
//! its own (`ASC_DAEMON=off`) and through the daemon, and the disassembly when
//! no backend answers. The real `asc-arkdec-worker` is built in its own
//! repository (asc-arkdec): the test that needs it skips itself unless
//! `ASC_ARKDEC_WORKER` names it.
#![cfg(unix)]

use asc_fixture::abc::{INDEX_PAGE, make_abc};
use asc_fixture::hap::make_hap;
use asc_fixture::{arkdec_worker, make_apk, make_dex, mock_backend};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

/// Under /tmp: socket paths must stay short whatever `$TMPDIR` is.
fn short_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new().prefix("dch").tempdir_in("/tmp").unwrap()
}

/// A working directory with `entry.hap`, `app.apk` and a config file, a
/// cache, a data directory, a private runtime directory and the `asc` under
/// test alone in a directory; the daemons started in it are stopped on drop.
struct Env {
    work: tempfile::TempDir,
    cache: tempfile::TempDir,
    runtime: tempfile::TempDir,
    data: tempfile::TempDir,
    _bin: tempfile::TempDir,
    exe: PathBuf,
}

impl Env {
    /// `config` is the config file: `{mock}` stands for the mock's path,
    /// `{arkdec}` for a script that runs it as an ABC backend.
    fn new(config: &str) -> Env {
        let bin = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let exe = bin.path().join("asc");
        if std::fs::hard_link(env!("CARGO_BIN_EXE_asc"), &exe).is_err() {
            std::fs::copy(env!("CARGO_BIN_EXE_asc"), &exe).unwrap();
        }
        let env = Env { work: short_tempdir(), cache: short_tempdir(), runtime: short_tempdir(), data: short_tempdir(), _bin: bin, exe };
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(env.runtime.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(env.path("entry.hap"), make_hap(&make_abc())).unwrap();
        std::fs::write(env.path("app.apk"), make_apk(&[("classes.dex", &make_dex())], true)).unwrap();
        let script = env.path("arkdec.sh");
        std::fs::write(&script, format!("#!/bin/sh\nexec '{}' --abc \"$@\"\n", mock_backend().display())).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let config = config.replace("{mock}", mock_backend().to_str().unwrap()).replace("{arkdec}", script.to_str().unwrap());
        std::fs::write(env.path("config.toml"), config).unwrap();
        env
    }

    fn run(&self, daemon: bool, args: &[&str]) -> Output {
        self.run_with(daemon, &[], args)
    }

    /// [`Env::run`] with more environment variables.
    fn run_with(&self, daemon: bool, vars: &[(&str, &str)], args: &[&str]) -> Output {
        let mut cmd = Command::new(&self.exe);
        // Nothing of the user's: no worker on PATH or named by the environment.
        cmd.env("XDG_DATA_HOME", self.data.path())
            .env("PATH", "/usr/bin:/bin")
            .env_remove("ASC_ARKDEC_WORKER")
            .env_remove("ASC_RELEASE_URL")
            .env_remove("ASC_AUTO_INSTALL")
            .env("ASC_MEMORY", "1G")
            .envs(vars.iter().copied())
            .current_dir(self.work.path())
            .env("ASC_CONFIG", self.path("config.toml"))
            .env("ASC_RUNTIME_DIR", self.runtime.path())
            .env_remove("ASC_DAEMON")
            .arg("--cache-dir")
            .arg(self.cache.path())
            .args(args);
        if !daemon {
            cmd.env("ASC_DAEMON", "off");
        }
        cmd.output().expect("run asc")
    }

    fn path(&self, name: &str) -> PathBuf {
        self.work.path().join(name)
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.run(true, &["daemon", "stop"]);
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn both(o: &Output) -> String {
    stdout(o) + &String::from_utf8_lossy(&o.stderr)
}

/// The `pid` the mock writes into its text.
fn pid_of(text: &str) -> u32 {
    let start = text.find("pid=").expect("mock output names its pid") + 4;
    text[start..].split_whitespace().next().unwrap().parse().unwrap()
}

/// `text` with what differs between two backend processes masked: the
/// mock's pid and program id.
fn masked(text: &str) -> String {
    text.lines()
        .map(|line| match line.strip_prefix("// pid=") {
            Some(rest) => format!("// pid=<pid> program=<id> {}", rest.split_once(' ').unwrap().1.split_once(' ').unwrap().1),
            None => line.to_string(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The mock as the default HarmonyOS backend, named `mock`.
const MOCK: &str = "[decompile]\nharmony_default = \"mock\"\n[decompilers.mock]\ncommand = \"{mock}\"\nargs = [\"--abc\"]\n";

/// The text of the mock's unit for the Index page: what follows the header.
fn mock_unit_body(text: &str) -> &str {
    let at = text.find("// pid=").expect("the mock's text");
    &text[at..]
}

#[test]
fn the_body_is_the_unit_text() {
    let env = Env::new(MOCK);
    let out = env.run(false, &["decompile", "entry.hap", "pages/Index"]);
    assert_eq!(out.status.code(), Some(0), "{}", both(&out));
    let text = stdout(&out);
    let (header, body) = text.split_once('\n').unwrap();
    assert_eq!(header, format!("// decompile {INDEX_PAGE} | ets/modules.abc | by mock 1.0 | status ok"));
    // Byte for byte what the backend sent as the unit's text.
    let options = "options={}";
    assert!(body.starts_with("// pid=") && body.contains(&format!(" record={INDEX_PAGE} sha256=")), "{body}");
    assert!(body.ends_with(&format!("{options}\nfunction func_main_0() {{}}\nfunction build() {{ return 1; }}\n")), "{body}");

    // One function, cut out of the unit by its span.
    let out = env.run(false, &["decompile", "entry.hap", "pages/Index", "--method", "Index.build", "--entry", "ets/modules.abc"]);
    assert_eq!(out.status.code(), Some(0), "{}", both(&out));
    assert_eq!(
        stdout(&out),
        format!("// decompile {INDEX_PAGE} | ets/modules.abc | by mock 1.0 | status ok, from cache\nfunction build() {{ return 1; }}\n")
    );

    // --raw and --level are request options: a unit of their own.
    let out = env.run(false, &["decompile", "entry.hap", "pages/Index", "--raw", "--level", "pc-dispatch"]);
    assert_eq!(out.status.code(), Some(0), "{}", both(&out));
    assert!(stdout(&out).contains(r#"options={"level":"pcDispatch","raw":true}"#), "{}", stdout(&out));
    assert!(!stdout(&out).contains("from cache"));

    // -o writes the record's path under the directory.
    let out = env.run(false, &["decompile", "entry.hap", "pages/Index", "-o", "src"]);
    assert_eq!(out.status.code(), Some(0), "{}", both(&out));
    assert!(stdout(&out).ends_with("// wrote src/entry/src/main/ets/pages/Index.js\n"), "{}", stdout(&out));
    let written = std::fs::read_to_string(env.path("src/entry/src/main/ets/pages/Index.js")).unwrap();
    assert_eq!(written, mock_unit_body(&text));
    // ArkTS: a unit of its own, written where the backend's .ets path says.
    let out = env.run(false, &["decompile", "entry.hap", "pages/Index", "--language", "ets", "-o", "src"]);
    assert_eq!(out.status.code(), Some(0), "{}", both(&out));
    assert!(stdout(&out).ends_with("| status ok\n// wrote src/entry/src/main/ets/pages/Index.ets\n"), "{}", stdout(&out));
    let written = std::fs::read_to_string(env.path("src/entry/src/main/ets/pages/Index.ets")).unwrap();
    assert!(written.lines().next().unwrap().ends_with(" language=arkts"), "{written}");
}

#[test]
fn daemon_and_one_shot_outputs_are_identical() {
    let one_shot = Env::new(MOCK);
    let daemon = Env::new(MOCK);
    for args in [
        &["decompile", "entry.hap", "pages/Index"][..],
        &["decompile", "entry.hap", "pages/Index", "--method", "build"][..],
        &["decompile", "entry.hap", "pages/Index", "--language", "arkts"][..],
    ] {
        let alone = one_shot.run(false, args);
        let served = daemon.run(true, args);
        assert_eq!(alone.status.code(), Some(0), "{}", both(&alone));
        assert_eq!(served.status.code(), Some(0), "{}", both(&served));
        assert_eq!(masked(&stdout(&served)), masked(&stdout(&alone)), "{args:?}");
    }
    // A hit differs by the cache marker only.
    let first = stdout(&daemon.run(true, &["decompile", "entry.hap", "pages/Index"]));
    let hit = stdout(&daemon.run(true, &["decompile", "entry.hap", INDEX_PAGE]));
    assert_eq!(hit.replacen(", from cache\n", "\n", 1), first.replacen(", from cache\n", "\n", 1));
    assert!(hit.lines().next().unwrap().ends_with(", from cache"), "{hit}");
}

#[test]
fn the_daemon_restarts_a_killed_arkdec() {
    // The built-in arkdec, its worker named by ASC_ARKDEC_WORKER (the mock as an ABC backend).
    let env = Env::new("");
    let script = env.path("arkdec.sh");
    let vars = [("ASC_ARKDEC_WORKER", script.to_str().unwrap())];
    let start = env.run_with(true, &vars, &["daemon", "start"]);
    assert!(start.status.success(), "{}", both(&start));
    let first = env.run_with(true, &vars, &["decompile", "entry.hap", "pages/Index"]);
    assert_eq!(first.status.code(), Some(0), "{}", both(&first));
    assert!(
        stdout(&first).starts_with(&format!("// decompile {INDEX_PAGE} | ets/modules.abc | by arkdec 1.0 | status ok\n")),
        "{}",
        both(&first)
    );
    let pid = pid_of(&stdout(&first));

    // SAFETY: kill only sends a signal; the pid is the daemon's backend.
    assert_eq!(unsafe { libc::kill(libc::pid_t::try_from(pid).unwrap(), libc::SIGKILL) }, 0);
    let t0 = Instant::now();
    let restarted = loop {
        let out = env.run_with(true, &vars, &["decompile", "entry.hap", "entryability/EntryAbility"]);
        if out.status.code() == Some(0) || t0.elapsed() > Duration::from_secs(10) {
            break out;
        }
    };
    assert_eq!(restarted.status.code(), Some(0), "{}", both(&restarted));
    assert!(stdout(&restarted).lines().next().unwrap().ends_with("| by arkdec 1.0 | status ok"), "{}", stdout(&restarted));
    assert_ne!(pid_of(&stdout(&restarted)), pid, "a new backend process answered");
}

#[test]
fn without_arkdec_the_disassembly_answers_and_says_how_to_get_it() {
    let env = Env::new("");
    let out = env.run(false, &["decompile", "entry.hap", "pages/Index", "--method", "Index.build"]);
    assert_eq!(out.status.code(), Some(2), "{}", both(&out));
    let text = stdout(&out);
    let mut lines = text.lines();
    assert_eq!(
        lines.next().unwrap(),
        format!("# decompile {INDEX_PAGE} | ets/modules.abc | by disassembly (no decompiler gave source) | status failed")
    );
    let attempt = lines.next().unwrap();
    assert!(
        attempt.starts_with("# arkdec failed: asc-arkdec-worker not found (ASC_ARKDEC_WORKER, next to asc, on PATH); build it")
            && attempt.contains("[decompilers.arkdec] command"),
        "{attempt}"
    );
    // The listing is getclass's.
    let getclass = env.run(false, &["getclass", "entry.hap", "pages/Index", "--method", "Index.build"]);
    assert_eq!(text.split_once(&format!("{attempt}\n")).unwrap().1, stdout(&getclass));

    // There is nothing to install; the error says what to do.
    let install = env.run(false, &["install", "arkdec"]);
    assert_eq!(install.status.code(), Some(1));
    assert!(both(&install).contains("asc-arkdec-worker has no release to install; build it"), "{}", both(&install));

    // `asc config` lists arkdec as the HarmonyOS default.
    let config = stdout(&env.run(false, &["config"]));
    assert!(config.lines().any(|line| line.starts_with("arkdec | ") && line.ends_with(" | built-in | harmony default")), "{config}");
    assert!(config.lines().any(|line| line.starts_with("dexdec | ") && line.ends_with(" | built-in | default")), "{config}");
}

#[test]
fn arguments_of_the_other_format_are_refused() {
    let env = Env::new(MOCK);
    let refused = [
        (&["decompile", "app.apk", "example.Test", "--raw"][..], "--raw applies to HarmonyOS programs only"),
        (&["decompile", "app.apk", "example.Test", "--level", "pc-dispatch"][..], "--level applies to HarmonyOS programs only"),
        (&["decompile", "app.apk", "example.Test", "--entry", "x"][..], "--entry applies to HarmonyOS programs only"),
        (&["decompile", "app.apk", "example.Test", "--language", "js"][..], "javascript and arkts are the languages of HarmonyOS records"),
        (&["decompile", "app.apk", "example.Test", "--language", "ets"][..], "javascript and arkts are the languages of HarmonyOS records"),
        (&["decompile", "entry.hap", "pages/Index", "--mapping", "m.txt"][..], "--mapping is DEX-only"),
        (&["decompile", "entry.hap", "pages/Index", "--language", "java"][..], "a HarmonyOS record decompiles to javascript"),
        (&["decompile", "entry.hap", "pages/Index", "--level", "structured"][..], "unknown level \"structured\""),
        (&["decompile", "entry.hap", "pages/Nothing"][..], "pages/Nothing"),
    ];
    for (args, error) in refused {
        let out = env.run(false, args);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {}", both(&out));
        assert!(both(&out).contains(error), "{args:?}: {}", both(&out));
    }
    let js = env.run(false, &["decompile", "entry.hap", "pages/Index", "--language", "javascript"]);
    assert_eq!(js.status.code(), Some(0), "{}", both(&js));
}

/// The real worker over every record of the sample program: the daemon's
/// answer is the one-shot command's, byte for byte, and a second ask is a
/// cache hit.
#[test]
fn the_built_in_arkdec_daemon_equals_one_shot() {
    let Some(worker) = arkdec_worker() else {
        eprintln!("skipped: set ASC_ARKDEC_WORKER to an asc-arkdec-worker to run this test");
        return;
    };
    let worker = worker.to_str().unwrap().to_string();
    let vars = [("ASC_ARKDEC_WORKER", worker.as_str())];
    let one_shot = Env::new("");
    let daemon = Env::new("");
    let listed = stdout(&one_shot.run(false, &["listclass", "entry.hap", "--all"]));
    let records: Vec<&str> = listed.lines().map(|line| line.split_whitespace().next().unwrap()).collect();
    assert!(records.contains(&INDEX_PAGE), "{listed}");
    for record in records {
        let alone = one_shot.run_with(false, &vars, &["decompile", "entry.hap", record]);
        let served = daemon.run_with(true, &vars, &["decompile", "entry.hap", record]);
        assert!(stdout(&alone).lines().next().unwrap().contains("| by arkdec "), "{record}: {}", both(&alone));
        assert_eq!(stdout(&served), stdout(&alone), "{record}");
        assert_eq!(served.status.code(), alone.status.code(), "{record}");
        let hit = daemon.run_with(true, &vars, &["decompile", "entry.hap", record]);
        assert_eq!(stdout(&hit).replacen(", from cache\n", "\n", 1), stdout(&alone), "{record}");
    }
}
