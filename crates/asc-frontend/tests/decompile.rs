//! `Decompilers` against asc-decompile's mock backend and a synthetic APK:
//! the chain of backends, L3, restarts, partial and failed classes, smali,
//! and names.
#![cfg(unix)]

use asc_decompile::Lifecycle;
use asc_engine::asc_cache::DiskCache;
use asc_engine::config::Decompiler;
use asc_engine::{CacheConfig, Engine};
use asc_fixture::{make_apk, make_dex, mock_backend};
use asc_frontend::decompile::{BackendEntry, DecompileError, Decompilers, Language, Naming, Request, Settings, Status};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

/// An APK defining `Lexample/Test;`, a disk cache and a mapping file.
struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let dex = make_dex();
        std::fs::write(dir.path().join("app.apk"), make_apk(&[("classes.dex", &dex)], true)).unwrap();
        std::fs::write(dir.path().join("mapping.txt"), "com.example.Renamed -> example.Test:\n    void first() -> first\n").unwrap();
        Fixture { dir }
    }

    fn cache_dir(&self) -> PathBuf {
        self.dir.path().join("cache")
    }

    fn engine(&self) -> Engine {
        let config = CacheConfig::default().disk(Some(DiskCache::open(self.cache_dir())));
        Engine::new(self.dir.path().join("app.apk")).with_cache(config)
    }

    fn mapping(&self) -> PathBuf {
        self.dir.path().join("mapping.txt")
    }

    /// Backends named after their mock flags (`mock`, `fail-startup`, ...),
    /// `default` first and then `fallback`, results cached in the fixture.
    fn decompilers(&self, default: &str, fallback: &[&str]) -> Decompilers {
        Decompilers::new(settings(default, fallback), Some(DiskCache::open(self.cache_dir())))
    }
}

/// The mock run with `flags` (`name` split on `+`, `mock` for none).
fn entry(name: &str) -> BackendEntry {
    let mut table = Decompiler::new(mock_backend());
    table.args = name.split('+').filter(|flag| *flag != "mock").map(|flag| format!("--{flag}")).collect();
    table.timeout = Duration::from_secs(10);
    table.startup_timeout = Duration::from_secs(10);
    let mut entry = BackendEntry::from_config(name, &table, None);
    entry.spec.lifecycle = Lifecycle::default()
        .backoff_initial(Duration::from_millis(10))
        .backoff_max(Duration::from_millis(40))
        .shutdown_grace(Duration::from_millis(200));
    entry
}

fn settings(default: &str, fallback: &[&str]) -> Settings {
    let mut settings = Settings::built_in();
    settings.default = default.to_string();
    settings.fallback = fallback.iter().map(ToString::to_string).collect();
    for name in std::iter::once(&default).chain(fallback) {
        settings.backends.insert(name.to_string(), entry(name));
    }
    settings
}

fn run(decompilers: &Decompilers, engine: &Engine, request: &Request<'_>) -> Result<asc_frontend::decompile::Decompiled, DecompileError> {
    decompilers.decompile(engine, request, &AtomicBool::new(false))
}

/// The `pid` the mock writes into its source.
fn pid_of(text: &str) -> u32 {
    let start = text.find("pid=").expect("mock output names its pid") + 4;
    text[start..].split_whitespace().next().unwrap().parse().unwrap()
}

#[test]
fn the_default_backend_answers_and_the_second_call_is_cached() {
    let fixture = Fixture::new();
    let decompilers = fixture.decompilers("mock", &[]);
    let engine = fixture.engine();
    let first = run(&decompilers, &engine, &Request::new("example.Test")).unwrap();
    assert_eq!((first.backend.as_deref(), first.version.as_deref(), first.status), (Some("mock"), Some("1.0"), Status::Ok));
    assert!(!first.cached && first.attempts.is_empty() && first.failed_methods.is_empty());
    assert!(first.text.contains("class=Lexample/Test;"), "{}", first.text);
    assert_eq!(first.path, Path::new("example/Test.java"));
    assert_eq!(first.header(), "// decompile Lexample/Test; | by mock 1.0 | status ok\n");

    let second = run(&decompilers, &engine, &Request::new("Lexample/Test;")).unwrap();
    assert!(second.cached, "the second call is served from L3");
    assert_eq!(second.text, first.text);
    assert!(second.header().ends_with("status ok, from cache\n"), "{}", second.header());

    // A host started later (another daemon, a one-shot command) finds it too.
    let later = fixture.decompilers("mock", &[]);
    let third = run(&later, &engine, &Request::new("example.Test")).unwrap();
    assert!(third.cached && third.text == first.text);
}

#[test]
fn a_failing_default_hands_over_to_the_fallbacks_in_order() {
    let fixture = Fixture::new();
    let decompilers = fixture.decompilers("fail-startup", &["fail-all", "mock"]);
    let engine = fixture.engine();
    let answer = run(&decompilers, &engine, &Request::new("example.Test")).unwrap();
    assert_eq!((answer.backend.as_deref(), answer.status), (Some("mock"), Status::Ok));
    let tried: Vec<&str> = answer.attempts.iter().map(|a| a.backend.as_str()).collect();
    assert_eq!(tried, ["fail-startup", "fail-all"]);
    assert!(answer.attempts[0].reason.contains("refusing to start"), "{:?}", answer.attempts[0]);
    assert_eq!(answer.attempts[1].reason, "mock fails everything");
    let header = answer.header();
    assert!(header.contains("// fail-startup failed: ") && header.contains("// fail-all failed: mock fails everything\n"), "{header}");

    // The failure is cached as well (for 10 minutes), and says so.
    let again = run(&decompilers, &engine, &Request::new("example.Test")).unwrap();
    assert!(again.cached);
    assert_eq!(again.attempts[1].reason, "mock fails everything (cached failure)");

    // A backend named explicitly is tried alone.
    let named = run(&decompilers, &engine, &Request::new("example.Test").decompiler(Some("fail-all"))).unwrap();
    assert_eq!((named.status, named.attempts.len()), (Status::Smali, 1));
    let unknown = run(&decompilers, &engine, &Request::new("example.Test").decompiler(Some("jeb"))).unwrap_err();
    assert!(
        unknown.to_string().starts_with("unknown decompiler \"jeb\"; configured: arkdec, dexdec, fail-all, fail-startup, mock"),
        "{unknown}"
    );
}

#[test]
fn every_backend_failing_falls_back_to_smali() {
    let fixture = Fixture::new();
    let decompilers = fixture.decompilers("fail-all", &[]);
    let engine = fixture.engine();
    let answer = run(&decompilers, &engine, &Request::new("example.Test")).unwrap();
    assert_eq!((answer.status, answer.backend.as_deref(), answer.language), (Status::Smali, None, None));
    assert!(answer.text.starts_with(".class public Lexample/Test;"), "{}", answer.text);
    assert_eq!(answer.path, Path::new("example/Test.smali"));
    let rendered = answer.render();
    assert!(rendered.starts_with("# decompile Lexample/Test; | by smali (no decompiler gave source) | status failed\n# fail-all failed: "));
    assert!(answer.is_degraded());

    // --method picks from the smali too, and names what there is otherwise.
    let picked = run(&decompilers, &engine, &Request::new("example.Test").method(Some("first"))).unwrap();
    assert!(picked.text.contains(".method public static first()V") && !picked.text.contains("<init>"), "{}", picked.text);
    let missing = run(&decompilers, &engine, &Request::new("example.Test").method(Some("walk"))).unwrap_err().to_string();
    assert!(missing.contains("has no method \"walk\" in its smali; its methods: "), "{missing}");

    // A class the program does not have is an error once nothing gave source.
    let absent = run(&decompilers, &engine, &Request::new("example.Missing")).unwrap_err();
    assert!(matches!(absent, DecompileError::Engine(_)), "{absent}");
}

#[test]
fn partial_classes_list_their_failed_methods_and_do_not_fall_back() {
    let fixture = Fixture::new();
    let decompilers = fixture.decompilers("mock", &["fail-all"]);
    let engine = fixture.engine();
    let answer = run(&decompilers, &engine, &Request::new("Lpartial;")).unwrap();
    assert_eq!((answer.status, answer.backend.as_deref()), (Status::Partial, Some("mock")));
    assert!(answer.attempts.is_empty());
    assert_eq!(answer.failed_methods.len(), 1);
    assert_eq!(answer.failed_methods[0].signature, "f()V");
    assert_eq!(answer.text, "class Partial {}");
    assert_eq!(
        answer.render(),
        "// decompile Lpartial; | by mock 1.0 | status partial\n// failed methods: 1\n//   f()V: irreducible loop\nclass Partial {}\n"
    );
    assert!(answer.is_degraded());
    let missing = run(&decompilers, &engine, &Request::new("Lpartial;").method(Some("f"))).unwrap_err().to_string();
    assert_eq!(missing, "Lpartial; has no method \"f\" in its decompiled source");
}

#[test]
fn a_killed_backend_is_started_again() {
    let fixture = Fixture::new();
    let decompilers = Decompilers::new(settings("mock", &[]), None);
    let engine = fixture.engine();
    let first = run(&decompilers, &engine, &Request::new("example.Test")).unwrap();
    let pid = pid_of(&first.text);
    let processes = decompilers.processes();
    assert_eq!(processes.len(), 1);
    assert_eq!((processes[0].backend.as_str(), processes[0].info.pid), ("mock", pid));
    // SAFETY: kill only sends a signal; the pid is our own child.
    assert_eq!(unsafe { libc::kill(libc::pid_t::try_from(pid).unwrap(), libc::SIGKILL) }, 0);
    let t0 = Instant::now();
    let second = loop {
        let answer = run(&decompilers, &engine, &Request::new("example.Test")).unwrap();
        if answer.status == Status::Ok || t0.elapsed() > Duration::from_secs(10) {
            break answer;
        }
    };
    assert_eq!(second.status, Status::Ok, "{}", second.render());
    assert_ne!(pid_of(&second.text), pid, "a new process answered");
    assert!(second.text.contains("program=p1"), "the program was opened again on it: {}", second.text);
}

#[test]
fn idle_processes_are_retired_to_fit_the_memory_budget() {
    let fixture = Fixture::new();
    let decompilers = Decompilers::new(settings("mock", &[]), None);
    run(&decompilers, &fixture.engine(), &Request::new("example.Test")).unwrap();
    assert_eq!(decompilers.processes().len(), 1);
    // Room for the one open program and nothing more.
    let cache = asc_engine::SharedCache::new(CacheConfig::default().memory_bytes(2 << 20), |_| {});
    let closing = decompilers.fit_resident(&cache, &[1 << 20]);
    assert!(closing.is_empty(), "the program in use stays");
    assert!(decompilers.processes().is_empty(), "the idle backend process went over the budget");
}

#[test]
fn mappings_go_to_backends_that_take_them_and_are_noted_otherwise() {
    let fixture = Fixture::new();
    let engine = fixture.engine();
    let mapping = fixture.mapping();
    let decompilers = fixture.decompilers("mock", &["no-mappings"]);
    let mapped = run(&decompilers, &engine, &Request::new("example.Test").mapping(Some(&mapping))).unwrap();
    assert_eq!(mapped.naming, Naming::Unified);
    assert!(mapped.text.contains("mappings=1"), "the class mapping was sent: {}", mapped.text);
    assert_eq!(mapped.path, Path::new("com/example/Renamed.java"), "the file follows the new name");
    assert!(!mapped.header().contains("names not unified"));
    let plain = run(&decompilers, &engine, &Request::new("example.Test")).unwrap();
    assert!(!plain.cached && !plain.text.contains("mappings="), "mappings are part of the cache key: {}", plain.text);

    let unmapped =
        run(&decompilers, &engine, &Request::new("example.Test").decompiler(Some("no-mappings")).mapping(Some(&mapping))).unwrap();
    assert_eq!(unmapped.naming, Naming::NotUnified);
    assert!(!unmapped.text.contains("mappings="), "{}", unmapped.text);
    assert!(unmapped.header().contains("// names not unified: no-mappings takes no mapping file; names are the DEX's own\n"));
    assert_eq!(unmapped.path, Path::new("example/Test.java"));

    let bad = run(&decompilers, &engine, &Request::new("example.Test").mapping(Some(Path::new("/nonexistent/mapping.txt")))).unwrap_err();
    assert!(bad.to_string().starts_with("cannot read mapping file /nonexistent/mapping.txt"), "{bad}");
}

#[test]
fn resource_names_go_to_backends_that_take_them() {
    use asc_fixture::res::{Res, Val, arsc};
    let fixture = Fixture::new();
    let table =
        arsc("example", &[Res::new("string", "app_name", Val::Str("App")), Res::new("layout", "main", Val::Str("res/layout/main.xml"))]);
    let apk = fixture.dir.path().join("res.apk");
    std::fs::write(&apk, make_apk(&[("classes.dex", &make_dex()), ("resources.arsc", &table)], true)).unwrap();
    let config = CacheConfig::default().disk(Some(DiskCache::open(fixture.cache_dir())));
    let engine = Engine::new(&apk).with_cache(config);
    let decompilers = fixture.decompilers("resources", &["mock"]);

    let named = run(&decompilers, &engine, &Request::new("example.Test")).unwrap();
    assert!(named.text.contains(" resources=2 0x7f010000=string/app_name"), "the table's names were sent: {}", named.text);
    let again = run(&decompilers, &engine, &Request::new("example.Test")).unwrap();
    assert!(again.cached && again.text == named.text);

    let plain = run(&decompilers, &engine, &Request::new("example.Test").decompiler(Some("mock"))).unwrap();
    assert!(!plain.text.contains("resources="), "a backend that does not declare them gets none: {}", plain.text);

    // No resources.arsc: nothing to send.
    let bare = run(&decompilers, &fixture.engine(), &Request::new("example.Test")).unwrap();
    assert!(!bare.text.contains("resources="), "{}", bare.text);
}

#[test]
fn a_language_the_backend_lacks_is_a_failure_of_that_backend() {
    let fixture = Fixture::new();
    let decompilers = fixture.decompilers("mock", &[]);
    let answer = run(&decompilers, &fixture.engine(), &Request::new("example.Test").language(Language::Kotlin)).unwrap();
    assert_eq!(answer.status, Status::Smali);
    assert_eq!(answer.attempts[0].reason, "no kotlin output");
}
