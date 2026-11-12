//! `asc decompile` against asc-decompile's mock backend, configured in a
//! config file: on its own (`ASC_DAEMON=off`) and through the daemon, which
//! keeps the backend running and its results cached. The built-in dexdec runs
//! `asc-dexdec-worker`, which asc finds next to itself, or installs from a
//! release (here a local server). The worker is built in its own repository:
//! the tests that need the real one skip themselves unless
//! `ASC_DEXDEC_WORKER` names it.
#![cfg(unix)]

use asc_fixture::http::HttpServer;
use asc_fixture::{dexdec_worker, make_apk, make_dex, mock_backend};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

/// Under /tmp: socket paths must stay short whatever `$TMPDIR` is.
fn short_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new().prefix("dcm").tempdir_in("/tmp").unwrap()
}

/// A working directory with an APK and a config file, a cache, a data
/// directory, a private runtime directory and the `asc` under test alone in
/// a directory; the daemons started in it are stopped on drop.
struct Env {
    work: tempfile::TempDir,
    cache: tempfile::TempDir,
    runtime: tempfile::TempDir,
    data: tempfile::TempDir,
    bin: tempfile::TempDir,
    exe: PathBuf,
}

impl Env {
    /// `config` is the config file, `{mock}` standing for the mock's path.
    /// No `asc-dexdec-worker` is next to the `asc` under test.
    fn new(config: &str) -> Env {
        let (bin, exe) = lone_asc();
        let env = Env { work: short_tempdir(), cache: short_tempdir(), runtime: short_tempdir(), data: short_tempdir(), bin, exe };
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(env.runtime.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dex = make_dex();
        std::fs::write(env.work.path().join("app.apk"), make_apk(&[("classes.dex", &dex)], true)).unwrap();
        let config = config.replace("{mock}", mock_backend().to_str().unwrap());
        std::fs::write(env.work.path().join("config.toml"), config).unwrap();
        std::fs::write(env.work.path().join("mapping.txt"), "com.example.Renamed -> example.Test:\n").unwrap();
        env
    }

    /// [`Env::new`] with the real `asc-dexdec-worker` next to asc; `None`,
    /// and the test skips, unless `ASC_DEXDEC_WORKER` names one.
    fn with_worker(config: &str) -> Option<Env> {
        let Some(worker) = dexdec_worker() else {
            eprintln!("skipped: set ASC_DEXDEC_WORKER to an asc-dexdec-worker to run this test");
            return None;
        };
        let env = Env::new(config);
        link_or_copy(&worker, &env.bin.path().join("asc-dexdec-worker"));
        Some(env)
    }

    fn run(&self, daemon: bool, args: &[&str]) -> Output {
        self.run_with(daemon, &[], args)
    }

    /// [`Env::run`] with more environment variables.
    fn run_with(&self, daemon: bool, vars: &[(&str, &str)], args: &[&str]) -> Output {
        let mut cmd = Command::new(&self.exe);
        // Nothing of the user's: asc installs into the test's data
        // directory, finds no worker on PATH, and downloads only from where
        // a test says.
        cmd.env("XDG_DATA_HOME", self.data.path())
            .env("PATH", "/usr/bin:/bin")
            .env_remove("ASC_RELEASE_URL")
            .env_remove("ASC_AUTO_INSTALL");
        // A fixed memory budget: the auto one (a share of the free memory,
        // split between running asc processes) can be so small on a busy
        // machine that the daemon retires the worker after each request.
        cmd.env("ASC_MEMORY", "1G");
        cmd.envs(vars.iter().copied());
        cmd.current_dir(self.work.path())
            .env("ASC_CONFIG", self.work.path().join("config.toml"))
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

/// The `pid` the mock writes into its source.
fn pid_of(text: &str) -> u32 {
    let start = text.find("pid=").expect("mock output names its pid") + 4;
    text[start..].split_whitespace().next().unwrap().parse().unwrap()
}

const MOCK: &str = "[decompile]\ndefault = \"mock\"\n[decompilers.mock]\ncommand = \"{mock}\"\n";

#[test]
fn decompile_prints_a_header_and_the_source() {
    let env = Env::new(MOCK);
    let out = env.run(false, &["decompile", "app.apk", "example.Test"]);
    assert_eq!(out.status.code(), Some(0), "{}", both(&out));
    let text = stdout(&out);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines[0], "// decompile Lexample/Test; | by mock 1.0 | status ok");
    assert!(lines[1].starts_with("// pid=") && lines[1].ends_with("program=p1 class=Lexample/Test;"), "{text}");

    // Run again in a new process: the backend's answer comes from the disk cache.
    let again = env.run(false, &["decompile", "app.apk", "Lexample/Test;"]);
    assert!(stdout(&again).starts_with("// decompile Lexample/Test; | by mock 1.0 | status ok, from cache\n"), "{}", both(&again));
    assert_eq!(pid_of(&stdout(&again)), pid_of(&text));

    // -o writes under the directory at a path asc makes from the descriptor.
    let out = env.run(false, &["decompile", "app.apk", "example.Test", "-o", "src", "--mapping", "mapping.txt"]);
    assert_eq!(out.status.code(), Some(0), "{}", both(&out));
    let written = env.path("src/com/example/Renamed.java");
    assert!(stdout(&out).ends_with(&format!("// wrote {}\n", Path::new("src/com/example/Renamed.java").display())), "{}", stdout(&out));
    assert!(std::fs::read_to_string(written).unwrap().contains("mappings=1"));
}

#[test]
fn partial_and_failed_classes_exit_2_and_say_why() {
    let env = Env::new(
        "[decompile]\ndefault = \"broken\"\nfallback = [\"mock\"]\n[decompilers.broken]\ncommand = \"{mock}\"\nargs = [\"--fail-all\"]\n[decompilers.mock]\ncommand = \"{mock}\"\n",
    );
    let out = env.run(false, &["decompile", "app.apk", "Lpartial;"]);
    assert_eq!(out.status.code(), Some(2), "{}", both(&out));
    assert_eq!(
        stdout(&out),
        "// decompile Lpartial; | by mock 1.0 | status partial\n// broken failed: mock fails everything\n\
         // failed methods: 1\n//   f()V: irreducible loop\nclass Partial {}\n"
    );
    // Named alone, the failing backend leaves smali.
    let out = env.run(false, &["decompile", "app.apk", "example.Test", "--decompiler", "broken"]);
    assert_eq!(out.status.code(), Some(2), "{}", both(&out));
    assert!(stdout(&out).starts_with("# decompile Lexample/Test; | by smali (no decompiler gave source) | status failed\n# broken failed: mock fails everything\n.class public Lexample/Test;"), "{}", stdout(&out));
    let out = env.run(false, &["decompile", "app.apk", "example.Test", "--decompiler", "jeb"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(both(&out).contains("Error: unknown decompiler \"jeb\"; configured: broken, dexdec, mock"), "{}", both(&out));
}

#[test]
fn names_not_unified_when_the_backend_takes_no_mappings() {
    let env = Env::new("[decompile]\ndefault = \"plain\"\n[decompilers.plain]\ncommand = \"{mock}\"\nargs = [\"--no-mappings\"]\n");
    let out = env.run(false, &["--set", "decompile.mapping=mapping.txt", "decompile", "app.apk", "example.Test"]);
    assert_eq!(out.status.code(), Some(0), "{}", both(&out));
    assert!(stdout(&out).contains("\n// names not unified: plain takes no mapping file; names are the DEX's own\n"), "{}", stdout(&out));
    assert!(!stdout(&out).contains("mappings="));
}

#[test]
fn config_lists_the_backends() {
    let env = Env::new("[decompile]\nfallback = [\"mock\"]\n[decompilers.mock]\ncommand = \"{mock}\"\nargs = [\"--fail-all\"]\n");
    let out = env.run(false, &["config"]);
    let text = stdout(&out);
    assert!(text.contains("\n# decompilers: name | command | source | role\n"), "{text}");
    assert!(text.lines().any(|line| line.starts_with("dexdec | ") && line.ends_with(" | built-in | default")), "{text}");
    assert!(text.contains(&format!("\nmock | {} --fail-all | file | fallback 1\n", mock_backend().display())), "{text}");
    let bad = Env::new("[decompilers.mock]\nargs = []\n");
    let out = bad.run(false, &["config"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(both(&out).contains("decompilers.mock.command"), "{}", both(&out));
}

#[test]
fn the_daemon_keeps_the_backend_and_restarts_it_after_a_kill() {
    let env = Env::new(MOCK);
    let start = env.run(true, &["daemon", "start"]);
    assert!(start.status.success(), "{}", both(&start));
    let first = env.run(true, &["decompile", "app.apk", "example.Test"]);
    assert_eq!(first.status.code(), Some(0), "{}", both(&first));
    let pid = pid_of(&stdout(&first));
    // The same backend process answers the next class: it stays up in the daemon.
    let other = env.run(true, &["decompile", "app.apk", "Lexample/Other;"]);
    assert_eq!(pid_of(&stdout(&other)), pid, "{}", both(&other));
    let status = stdout(&env.run(true, &["daemon", "status"]));
    assert!(status.contains(", 1 decompiler processes ("), "{status}");
    // A second request for a class is served from the cache.
    let cached = env.run(true, &["decompile", "app.apk", "example.Test"]);
    assert!(stdout(&cached).starts_with("// decompile Lexample/Test; | by mock 1.0 | status ok, from cache\n"), "{}", both(&cached));

    // SAFETY: kill only sends a signal; the pid is the daemon's backend.
    assert_eq!(unsafe { libc::kill(libc::pid_t::try_from(pid).unwrap(), libc::SIGKILL) }, 0);
    let t0 = Instant::now();
    let restarted = loop {
        let out = env.run(true, &["decompile", "app.apk", "Lexample/Third;"]);
        if out.status.code() == Some(0) || t0.elapsed() > Duration::from_secs(10) {
            break out;
        }
    };
    assert_eq!(restarted.status.code(), Some(0), "{}", both(&restarted));
    assert_ne!(pid_of(&stdout(&restarted)), pid, "a new backend process answered");
}

/// The `asc-dexdec-worker` processes the daemon of `env` started (read
/// from `/proc`, so Linux only, as the tests that call it).
#[cfg(target_os = "linux")]
fn workers(env: &Env) -> Vec<u32> {
    let status = stdout(&env.run(true, &["daemon", "status"]));
    let daemon: u32 = status.strip_prefix("pid ").and_then(|s| s.split(',').next()).and_then(|p| p.parse().ok()).expect(&status);
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else { continue };
        let cmdline = std::fs::read(entry.path().join("cmdline")).unwrap_or_default();
        let stat = std::fs::read_to_string(entry.path().join("stat")).unwrap_or_default();
        // `pid (comm) state ppid ...`; comm may hold spaces, so read after the last `)`.
        let ppid = stat.rsplit_once(')').and_then(|(_, rest)| rest.split_whitespace().nth(1)).and_then(|p| p.parse::<u32>().ok());
        let program = cmdline.split(|b| *b == 0).next().unwrap_or_default();
        // Installed copies are named asc-dexdec-worker; the release fixture's
        // script execs `$ASC_DEXDEC_WORKER`, which may be named anything.
        let worker = dexdec_worker().is_some_and(|path| program == path.as_os_str().as_encoded_bytes());
        if ppid == Some(daemon) && (program.ends_with(b"/asc-dexdec-worker") || worker) {
            found.push(pid);
        }
    }
    found
}

#[cfg(target_os = "linux")]
#[test]
fn the_built_in_dexdec_answers_through_the_daemon_and_restarts() {
    let Some(env) = Env::with_worker("") else { return };
    let start = env.run(true, &["daemon", "start"]);
    assert!(start.status.success(), "{}", both(&start));
    let first = env.run(true, &["decompile", "app.apk", "example.Test"]);
    assert_eq!(first.status.code(), Some(0), "{}", both(&first));
    let text = stdout(&first);
    assert!(
        text.starts_with("// decompile Lexample/Test; | by dexdec ") && text.lines().next().unwrap().ends_with(" | status ok"),
        "{text}"
    );
    assert!(text.contains("public class Test {"), "{text}");
    let cached = env.run(true, &["decompile", "app.apk", "example.Test"]);
    assert!(stdout(&cached).lines().next().unwrap().ends_with("status ok, from cache"), "{}", both(&cached));
    assert_eq!(stdout(&cached).lines().skip(1).collect::<Vec<_>>(), text.lines().skip(1).collect::<Vec<_>>());

    let before = workers(&env);
    assert_eq!(before.len(), 1, "one worker in the daemon: {before:?}");
    // SAFETY: kill only sends a signal; the pid is the daemon's worker.
    assert_eq!(unsafe { libc::kill(libc::pid_t::try_from(before[0]).unwrap(), libc::SIGKILL) }, 0);
    // Kotlin is another cache key: the request needs a worker again.
    let t0 = Instant::now();
    let again = loop {
        let out = env.run(true, &["decompile", "app.apk", "example.Test", "--language", "kotlin"]);
        if stdout(&out).contains("| by dexdec ") || t0.elapsed() > Duration::from_secs(20) {
            break out;
        }
    };
    assert_eq!(again.status.code(), Some(0), "{}", both(&again));
    assert!(stdout(&again).contains("class Test"), "{}", stdout(&again));
    let after = workers(&env);
    assert!(after.len() == 1 && after != before, "a new worker took over: {before:?} -> {after:?}");
}

#[test]
fn the_built_in_dexdec_applies_mappings_and_reports_failures() {
    let Some(env) = Env::with_worker("[decompilers.dexdec]\ntimeout = 2\n") else { return };
    // The worker takes the mapping file's names: the class moves to its
    // original package, and the file with it.
    let out = env.run(false, &["decompile", "app.apk", "example.Test", "--mapping", "mapping.txt", "-o", "src"]);
    assert_eq!(out.status.code(), Some(0), "{}", both(&out));
    assert!(!stdout(&out).contains("names not unified"), "{}", stdout(&out));
    assert!(stdout(&out).starts_with("// decompile Lexample/Test; | by dexdec "), "{}", stdout(&out));
    let source = std::fs::read_to_string(env.path("src/com/example/Renamed.java")).unwrap();
    assert!(source.starts_with("package com.example;\n"), "{source}");
    assert!(source.contains("public class Renamed {"), "{source}");
    let out = env.run(false, &["decompile", "app.apk", "example.Test"]);
    assert!(stdout(&out).contains("public class Test {"), "{}", stdout(&out));
    // A rename dexdec must drop (onto a platform class) keeps the DEX's name, file included.
    std::fs::write(env.path("platform.txt"), "java.lang.String -> example.Test:\n").unwrap();
    let out = env.run(false, &["decompile", "app.apk", "example.Test", "--mapping", "platform.txt", "-o", "kept"]);
    assert_eq!(out.status.code(), Some(0), "{}", both(&out));
    let source = std::fs::read_to_string(env.path("kept/example/Test.java")).unwrap();
    assert!(source.contains("public class Test {"), "{source}");
    // A panic in the class: smali instead, and why.
    // A cache of its own each: the injected fault is not part of the key.
    let cache = |name: &str| format!("cache.dir={}", env.path(name).display());
    let fault = [("ASC_DEXDEC_WORKER_FAULT", "panic:Lexample/Test;")];
    let panic_cache = cache("panic-cache");
    let out = env.run_with(false, &fault, &["--set", &panic_cache, "decompile", "app.apk", "example.Test"]);
    assert_eq!(out.status.code(), Some(2), "{}", both(&out));
    assert!(
        stdout(&out).starts_with(
            "# decompile Lexample/Test; | by smali (no decompiler gave source) | status failed\n# dexdec failed: generation panicked"
        ),
        "{}",
        stdout(&out)
    );
    // A class that never finishes: the request times out (`timeout = 2`).
    let stall = [("ASC_DEXDEC_WORKER_FAULT", "stall:Lexample/Test;")];
    let stall_cache = cache("stall-cache");
    let out = env.run_with(false, &stall, &["--set", &stall_cache, "decompile", "app.apk", "example.Test"]);
    assert_eq!(out.status.code(), Some(2), "{}", both(&out));
    assert!(stdout(&out).contains("\n# dexdec failed: request timed out after 2s\n"), "{}", stdout(&out));
}

#[test]
fn a_nested_class_is_served_from_its_outer_class_unit() {
    let Some(env) = Env::with_worker("") else { return };
    let dex = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/nest.dex");
    std::fs::copy(dex, env.path("classes.dex")).unwrap();
    let outer = env.run(false, &["decompile", "classes.dex", "Nest"]);
    assert_eq!(outer.status.code(), Some(0), "{}", both(&outer));
    assert!(stdout(&outer).lines().next().unwrap().ends_with(" | status ok"), "{}", stdout(&outer));
    // The outer class's unit folds the inner one in: no second backend call.
    let inner = env.run(false, &["decompile", "classes.dex", "Nest$Inner", "--method", "touch"]);
    assert_eq!(inner.status.code(), Some(0), "{}", both(&inner));
    let text = stdout(&inner);
    let header = text.lines().next().unwrap();
    assert!(header.starts_with("// decompile LNest$Inner; | in LNest; | by dexdec "), "{text}");
    assert!(header.ends_with(" | status ok, from cache"), "{text}");
    assert!(text.contains("int touch(int i) {"), "{text}");
}

/// An `asc` with no worker next to it: a hard link of the one under test,
/// alone in a directory of the target directory (one file system).
fn lone_asc() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let exe = dir.path().join("asc");
    link_or_copy(Path::new(env!("CARGO_BIN_EXE_asc")), &exe);
    (dir, exe)
}

fn link_or_copy(from: &Path, to: &Path) {
    if std::fs::hard_link(from, to).is_err() {
        std::fs::copy(from, to).unwrap();
    }
}

/// A release of the worker as its Release workflow packages it, served by a
/// local server: `<url>/asc-dexdec-worker-p<protocol>-<target>.tar.gz` and its
/// `.sha256`. The packaged worker is a script that runs `worker`.
fn worker_release(worker: &Path) -> HttpServer {
    use asc_frontend::decompile::dexdec::{PROTOCOL, TARGET};
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    let stage = tempfile::tempdir().unwrap();
    let name = format!("asc-dexdec-worker-p{PROTOCOL}-{TARGET}");
    let dir = stage.path().join(&name);
    std::fs::create_dir(&dir).unwrap();
    let script = dir.join("asc-dexdec-worker");
    std::fs::write(&script, format!("#!/bin/sh\nexec '{}' \"$@\"\n", worker.display())).unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::copy(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../LICENSE"), dir.join("LICENSE")).unwrap();
    let tarball = format!("{name}.tar.gz");
    let status = Command::new("tar").current_dir(stage.path()).args(["czf", &tarball, &name]).status().unwrap();
    assert!(status.success());
    let archive = std::fs::read(stage.path().join(&tarball)).unwrap();
    let digest: String = Sha256::digest(&archive).iter().map(|b| format!("{b:02x}")).collect();
    let server = HttpServer::start();
    server.route(&format!("/{tarball}"), 200, archive);
    server.route(&format!("/{tarball}.sha256"), 200, format!("{digest}  {tarball}\n"));
    server
}

#[test]
fn without_a_worker_dexdec_falls_back_to_smali_and_says_how_to_get_one() {
    let env = Env::new("");
    // A debug build does not download from the real release.
    let out = env.run(false, &["decompile", "app.apk", "example.Test"]);
    assert_eq!(out.status.code(), Some(2), "{}", both(&out));
    let text = stdout(&out);
    assert!(text.starts_with("# decompile Lexample/Test; | by smali (no decompiler gave source) | status failed\n"), "{text}");
    let reason = text.lines().nth(1).unwrap();
    assert!(reason.starts_with("# dexdec failed: asc-dexdec-worker not found (next to asc, in "), "{reason}");
    let why =
        if cfg!(feature = "installer") { "a debug build of asc does not download it" } else { "this asc was built without the installer" };
    assert!(reason.contains(&format!("{why}; run `asc install dexdec`")), "{reason}");
    // Switched off, nothing is asked of the release either.
    let server = worker_release(&mock_backend());
    let base = server.url();
    let off = [("ASC_RELEASE_URL", base.as_str()), ("ASC_AUTO_INSTALL", "off")];
    let out = env.run_with(false, &off, &["decompile", "app.apk", "example.Test"]);
    assert_eq!(out.status.code(), Some(2), "{}", both(&out));
    assert!(stdout(&out).contains("not installed: decompile.auto_install is off; run `asc install dexdec`"), "{}", stdout(&out));
    assert!(server.requests().is_empty(), "{:?}", server.requests());
}

#[cfg(target_os = "linux")]
#[cfg(feature = "installer")]
#[test]
fn a_missing_worker_is_installed_from_the_release_and_used() {
    let Some(worker) = dexdec_worker() else {
        eprintln!("skipped: set ASC_DEXDEC_WORKER to an asc-dexdec-worker to run this test");
        return;
    };
    let env = Env::new("");
    let server = worker_release(&worker);
    let base = server.url();
    let url = [("ASC_RELEASE_URL", base.as_str())];
    // Through the daemon: the command installs it first, where its progress shows.
    let out = env.run_with(true, &url, &["decompile", "app.apk", "example.Test"]);
    assert_eq!(out.status.code(), Some(0), "{}", both(&out));
    assert!(stdout(&out).starts_with("// decompile Lexample/Test; | by dexdec "), "{}", both(&out));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("asc: asc-dexdec-worker not found; installing it from http://"), "{stderr}");
    let installed = env.data.path().join("asc/tools").read_dir().unwrap().next().unwrap().unwrap().path().join("asc-dexdec-worker");
    assert!(stderr.contains(&format!("asc: installed {}", installed.display())), "{stderr}");
    assert_eq!(server.requests().len(), 2, "checksum and archive, once: {:?}", server.requests());
    // Found from now on: nothing more is downloaded.
    let out = env.run_with(false, &url, &["decompile", "app.apk", "example.Test", "--language", "kotlin"]);
    assert_eq!(out.status.code(), Some(0), "{}", both(&out));
    assert_eq!(server.requests().len(), 2);
    // `asc install dexdec` downloads it again and says where it went.
    let out = env.run_with(false, &url, &["install", "dexdec"]);
    assert_eq!(out.status.code(), Some(0), "{}", both(&out));
    let protocol = asc_frontend::decompile::dexdec::PROTOCOL;
    assert_eq!(stdout(&out), format!("installed asc-dexdec-worker (protocol {protocol}) at {}\n", installed.display()));
    assert_eq!(server.requests().len(), 4);
    // The daemon's worker was the file replaced: the next request gets a new one.
    let before = workers(&env);
    assert_eq!(before.len(), 1, "{before:?}");
    let out = env.run_with(true, &url, &["decompile", "app.apk", "example.Test", "--mapping", "mapping.txt"]);
    assert_eq!(out.status.code(), Some(0), "{}", both(&out));
    assert!(stdout(&out).starts_with("// decompile Lexample/Test; | by dexdec "), "{}", both(&out));
    let after = workers(&env);
    assert!(after.len() == 1 && after != before, "a new worker took over: {before:?} -> {after:?}");
}

#[cfg(feature = "installer")]
#[test]
fn a_release_without_a_worker_for_this_protocol_is_not_asked_again() {
    let env = Env::new("");
    let server = HttpServer::start();
    let base = server.url();
    let url = [("ASC_RELEASE_URL", base.as_str())];
    let out = env.run_with(false, &url, &["decompile", "app.apk", "example.Test"]);
    assert_eq!(out.status.code(), Some(2), "{}", both(&out));
    // The reason is cut to fit the header; the start and the advice stay.
    assert!(stdout(&out).contains("\n# dexdec failed: installing asc-dexdec-worker failed: http://"), "{}", stdout(&out));
    assert!(
        stdout(&out).contains(
            "no worker for this asc's protocol version and target is released; build it (from https://github.com/DroidASC/asc-dexdec"
        ),
        "{}",
        stdout(&out)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("does not exist (no asc-dexdec-worker for protocol "), "{}", both(&out));
    let asked = server.requests().len();
    assert_eq!(asked, 1, "the checksum is fetched first: {:?}", server.requests());
    // Another process within the hour does not try again.
    let out = env.run_with(false, &url, &["decompile", "app.apk", "example.Test"]);
    assert!(stdout(&out).contains("(not retried for an hour; `asc install dexdec` tries now)"), "{}", stdout(&out));
    assert_eq!(server.requests().len(), asked);
    // The explicit command does.
    let out = env.run_with(false, &url, &["install", "dexdec"]);
    assert_eq!(out.status.code(), Some(1), "{}", both(&out));
    assert!(both(&out).contains("Error: ") && both(&out).contains("does not exist"), "{}", both(&out));
    assert_eq!(server.requests().len(), asked + 1);
}
