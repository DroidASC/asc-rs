//! The daemon answers one-shot commands exactly as the process itself would.
#![cfg(unix)]

use asc_fixture::{make_apk, make_dex};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

/// A private runtime directory (for the socket), a cache and a working
/// directory; the daemons started in it are stopped on drop.
struct Env {
    exe: PathBuf,
    runtime: tempfile::TempDir,
    cache: tempfile::TempDir,
    work: tempfile::TempDir,
}

/// Under /tmp: socket paths must stay short whatever `$TMPDIR` is.
fn short_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new().prefix("dmn").tempdir_in("/tmp").unwrap()
}

impl Env {
    fn new() -> Env {
        Env::with_exe(PathBuf::from(env!("CARGO_BIN_EXE_droidasc")))
    }

    fn with_exe(exe: PathBuf) -> Env {
        let env = Env { exe, runtime: short_tempdir(), cache: short_tempdir(), work: short_tempdir() };
        // The daemon only uses a runtime directory closed to others.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(env.runtime.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let dex = make_dex();
        std::fs::write(env.work.path().join("app.apk"), make_apk(&[("classes.dex", &dex), ("classes2.dex", &dex)], true)).unwrap();
        let broken = make_apk(&[("classes.dex", &dex), ("classes2.dex", b"this is not a dex file")], true);
        std::fs::write(env.work.path().join("broken.apk"), broken).unwrap();
        std::fs::write(env.work.path().join("rules.txt"), "# comment\nextends:java.lang.Object\n").unwrap();
        env
    }

    /// Run `args` in the working directory, through the daemon or not.
    fn run(&self, daemon: bool, args: &[&str]) -> Output {
        let mut cmd = Command::new(&self.exe);
        cmd.current_dir(self.work.path())
            .env("DROIDASC_RUNTIME_DIR", self.runtime.path())
            .env("DROIDASC_CACHE_MAX_MB", "256")
            .env_remove("DROIDASC_DAEMON")
            .arg("--cache-dir")
            .arg(self.cache.path())
            .args(args);
        if !daemon {
            cmd.env("DROIDASC_DAEMON", "off");
        }
        cmd.output().expect("run droidasc")
    }

    fn start(&self) -> u32 {
        let out = self.run(true, &["daemon", "start"]);
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        pid_of(&String::from_utf8_lossy(&out.stdout))
    }

    fn status(&self) -> String {
        String::from_utf8_lossy(&self.run(true, &["daemon", "status"]).stdout).into_owned()
    }

    /// Requests served, summed over the running daemons.
    fn served(&self) -> usize {
        self.status().lines().filter_map(|l| l.split(", ").nth(2)?.split(' ').next()?.parse::<usize>().ok()).sum()
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = self.run(true, &["daemon", "stop"]);
    }
}

fn pid_of(status: &str) -> u32 {
    status
        .strip_prefix("pid ")
        .and_then(|s| s.split(',').next())
        .and_then(|p| p.parse().ok())
        .unwrap_or_else(|| panic!("no pid in {status:?}"))
}

fn alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
        || Command::new("kill").args(["-0", &pid.to_string()]).stderr(std::process::Stdio::null()).status().is_ok_and(|s| s.success())
}

#[test]
fn daemon_output_is_byte_identical() {
    let env = Env::new();
    env.start();
    let cases: &[&[&str]] = &[
        &["findrefs", "app.apk", "string", "token", "--threads", "1"],
        &["findrefs", "app.apk", "string", "a.b(", "--literal", "--threads", "1"],
        &["findrefs", "app.apk", "type", "example.Test", "--threads", "1"],
        &["findrefs", "app.apk", "method", "first", "--class", "example.Test", "--threads", "1"],
        &["findrefs", "app.apk", "method", "--threads", "1"],
        &["findrefs", "app.apk", "field", "x", "--threads", "1"],
        &["findrefs", "app.apk", "extends", "java.lang.Object", "--threads", "1"],
        &["findrefs", "app.apk", "impl", "java.lang.Runnable", "--threads", "1"],
        &["findrefs", "app.apk", "all", "string:tok", "literal:token", "--threads", "1"],
        &["findrefs", "app.apk", "rules", "string:token", "string:nothing & literal:token", "--file", "rules.txt", "--threads", "1"],
        &["findrefs", "app.apk", "--context", "2", "string", "token", "--threads", "1"],
        &["findrefs", "app.apk", "--context-method", "string", "token", "--threads", "1"],
        &["findrefs", "broken.apk", "string", "token", "--threads", "1"],
        &["getclass", "app.apk", "example.Test", "--threads", "1"],
        &["getclass", "app.apk", "Lnope/Missing;"],
        &["disassemble", "app.apk", "example.Test", "--threads", "1"],
        &["listclass", "app.apk"],
        &["listclass", "app.apk", "--prefix", "example"],
        &["getmanifest", "app.apk"],
        &["manifest-summary", "app.apk"],
        &["resources", "app.apk"],
        &["xml", "app.apk", "res/xml/none.xml"],
        &["callgraph", "app.apk", "example.Test", "first", "--virtual"],
        &["callgraph", "app.apk", "example.Test", "nope"],
        &["hierarchy", "app.apk", "java.lang.Object", "--method", "second"],
        // Cut output (the spill file is named by content, so both name the same one).
        &["findrefs", "app.apk", "string", "token", "--limit", "1"],
        &["findrefs", "app.apk", "string", "token", "--offset", "1", "--max-bytes", "4096"],
        &["findrefs", "app.apk", "rules", "string:token", "extends:java.lang.Object", "--limit", "2"],
        &["getclass", "app.apk", "example.Test", "--limit", "3"],
        &["listclass", "app.apk", "--offset", "9"],
        &["callgraph", "app.apk", "example.Test", "first", "--limit", "1", "--spill-mb", "0"],
        // Declined by the daemon (the error names the path as given).
        &["findrefs", "missing.apk", "string", "token"],
    ];
    let before = env.served();
    for args in cases {
        let local = env.run(false, args);
        let remote = env.run(true, args);
        assert_eq!(String::from_utf8_lossy(&remote.stdout), String::from_utf8_lossy(&local.stdout), "stdout of {args:?}");
        assert_eq!(String::from_utf8_lossy(&remote.stderr), String::from_utf8_lossy(&local.stderr), "stderr of {args:?}");
        assert_eq!(remote.status.code(), local.status.code(), "exit status of {args:?}");
    }
    let served = env.served() - before;
    assert_eq!(served, cases.len() - 1, "every case but the missing APK ran in the daemon:\n{}", env.status());
    // Exit status 2 and 1 came through as well.
    assert_eq!(env.run(true, &["findrefs", "broken.apk", "string", "token"]).status.code(), Some(2));
    assert_eq!(env.run(true, &["getclass", "app.apk", "Lnope/Missing;"]).status.code(), Some(1));
}

#[test]
fn output_files_land_relative_to_the_client() {
    let env = Env::new();
    env.start();
    let w = env.work.path();
    for (daemon, name) in [(false, "local"), (true, "remote")] {
        let o = format!("{name}.txt");
        let dex = format!("{name}.dex");
        assert!(env.run(daemon, &["findrefs", "app.apk", "string", "token", "--threads", "1", "-o", &o]).status.success());
        assert!(env.run(daemon, &["getclass", "app.apk", "example.Test", "--threads", "1", "--dump-dex", &dex]).status.success());
        let out = env.run(daemon, &["findrefs", "app.apk", "string", "token", "-o", "no/such/dir/x.txt"]);
        assert_eq!(out.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&out.stderr).starts_with("Error: cannot write no/such/dir/x.txt:"), "{out:?}");
    }
    assert_eq!(std::fs::read(w.join("remote.txt")).unwrap(), std::fs::read(w.join("local.txt")).unwrap());
    assert_eq!(std::fs::read(w.join("remote.dex")).unwrap(), std::fs::read(w.join("local.dex")).unwrap());
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: &str| std::fs::metadata(w.join(p)).unwrap().permissions().mode();
    assert_eq!(mode("remote.txt"), mode("local.txt"), "the client's umask applies");
}

#[test]
fn first_command_starts_the_daemon_and_off_bypasses_it() {
    let env = Env::new();
    let off = env.run(false, &["listclass", "app.apk"]);
    assert!(env.status().starts_with("no daemon"), "DROIDASC_DAEMON=off starts nothing");
    let first = env.run(true, &["listclass", "app.apk"]);
    assert_eq!(first.stdout, off.stdout);
    let t0 = Instant::now();
    while env.status().starts_with("no daemon") {
        assert!(t0.elapsed() < Duration::from_secs(10), "no daemon came up");
        std::thread::sleep(Duration::from_millis(20));
    }
    let before = env.served();
    assert_eq!(env.run(true, &["listclass", "app.apk"]).stdout, off.stdout);
    assert_eq!(env.served(), before + 1);
    // Not forwarded: --debug and --no-cache.
    env.run(true, &["listclass", "app.apk", "--debug"]);
    env.run(true, &["--no-cache", "listclass", "app.apk"]);
    assert_eq!(env.served(), before + 1);
}

#[test]
fn a_replaced_binary_retires_the_old_daemon() {
    let bin = short_tempdir();
    let exe = bin.path().join("droidasc");
    std::fs::copy(env!("CARGO_BIN_EXE_droidasc"), &exe).unwrap();
    let env = Env::with_exe(exe.clone());
    let old = env.start();
    // A new build at the same path (one more byte changes its identity).
    let mut bytes = std::fs::read(&exe).unwrap();
    bytes.push(0);
    let next = bin.path().join("droidasc.new");
    std::fs::write(&next, bytes).unwrap();
    std::fs::set_permissions(&next, std::fs::metadata(&exe).unwrap().permissions()).unwrap();
    std::fs::rename(&next, &exe).unwrap();
    let new = env.start();
    assert_ne!(new, old);
    let t0 = Instant::now();
    while alive(old) {
        assert!(t0.elapsed() < Duration::from_secs(10), "the old build's daemon {old} is still running");
        std::thread::sleep(Duration::from_millis(20));
    }
    let status = env.status();
    assert_eq!(status.lines().count(), 1, "{status}");
    assert_eq!(pid_of(&status), new);
}

#[test]
fn idle_and_wait_times_come_from_the_environment() {
    let env = Env::new();
    // No wait: the first command runs itself while the daemon starts.
    let mut cmd = Command::new(&env.exe);
    cmd.current_dir(env.work.path())
        .env("DROIDASC_RUNTIME_DIR", env.runtime.path())
        .env("DROIDASC_CACHE_MAX_MB", "256")
        .env("DROIDASC_DAEMON_WAIT_MS", "0")
        .env("DROIDASC_DAEMON_IDLE", "1")
        .env_remove("DROIDASC_DAEMON")
        .arg("--cache-dir")
        .arg(env.cache.path())
        .args(["listclass", "app.apk"]);
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let pid = {
        let t0 = Instant::now();
        loop {
            let status = env.status();
            if status.starts_with("pid ") {
                break pid_of(&status);
            }
            assert!(t0.elapsed() < Duration::from_secs(5), "daemon never came up: {status:?}");
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    // `daemon status` is not a request: the daemon exits a second after it started.
    let t0 = Instant::now();
    while alive(pid) {
        assert!(t0.elapsed() < Duration::from_secs(10), "daemon {pid} still up with DROIDASC_DAEMON_IDLE=1");
        std::thread::sleep(Duration::from_millis(50));
    }
}
