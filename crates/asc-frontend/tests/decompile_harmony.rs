//! `Decompilers::decompile_harmony` against asc-decompile's mock backend in
//! its `--abc` mode (an arkdec stand-in) and a synthetic HAP: records found
//! as `getclass` finds them, L3 keyed by the ABC file's content and the
//! request options, functions cut out by their span, the disassembly when
//! no backend answers, and a crashed backend started again.
#![cfg(unix)]

use asc_decompile::Lifecycle;
use asc_engine::asc_cache::DiskCache;
use asc_engine::config::Decompiler;
use asc_fixture::abc::{AbcCode, AbcFunction, AbcModule, AbcRecord, Asm, INDEX_PAGE, sample_program};
use asc_fixture::hap::make_hap;
use asc_fixture::mock_backend;
use asc_frontend::decompile::{
    BUILT_IN_ARKDEC, BackendEntry, DecompileError, Decompiled, Decompilers, HarmonyRequest, Language, Level, Request, Settings, Status,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

/// Records the mock answers in its own way (asc-decompile `examples/mock_backend.rs`).
const MAGIC: [&str; 3] = ["&crash&", "&inexact&", "&fail&"];

/// The sample program with the [`MAGIC`] records besides.
fn program() -> Vec<u8> {
    let mut builder = sample_program();
    for name in MAGIC {
        let mut asm = Asm::new();
        asm.op("returnundefined", []);
        builder.record(
            AbcRecord::ets_module(name, "entry", &[], AbcModule::new()).function(AbcFunction::new("func_main_0", AbcCode::new(0, 3, asm))),
        );
    }
    builder.build().bytes
}

/// A HAP of [`program`] and a bare copy of its `modules.abc`, and a disk cache.
struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let abc = program();
        std::fs::write(dir.path().join("entry.hap"), make_hap(&abc)).unwrap();
        std::fs::create_dir(dir.path().join("bare")).unwrap();
        std::fs::write(dir.path().join("bare/modules.abc"), &abc).unwrap();
        Fixture { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn engine(&self, name: &str) -> asc_ark_engine::Engine {
        asc_ark_engine::Engine::open(self.path(name)).unwrap()
    }

    /// `harmony` backends (named after their mock flags, joined with `+`;
    /// `abc` is the mock's `--abc`, `mock` none), the first the default and the others
    /// the fallbacks, results cached in the fixture.
    fn decompilers(&self, harmony: &[&str]) -> Decompilers {
        let mut settings = Settings::built_in();
        settings.harmony_default = harmony[0].to_string();
        settings.harmony_fallback = harmony[1..].iter().map(ToString::to_string).collect();
        for name in harmony.iter().filter(|name| **name != BUILT_IN_ARKDEC) {
            settings.backends.insert(name.to_string(), entry(name));
        }
        Decompilers::new(settings, Some(DiskCache::open(self.path("cache"))))
    }
}

fn entry(name: &str) -> BackendEntry {
    let mut table = Decompiler::new(mock_backend());
    table.args = name.split('+').filter(|flag| *flag != "mock").map(|flag| format!("--{flag}")).collect();
    table.timeout = Duration::from_secs(10);
    let mut entry = BackendEntry::from_config(name, &table, None);
    entry.spec.lifecycle = Lifecycle::default().backoff_initial(Duration::from_millis(10)).backoff_max(Duration::from_millis(40));
    entry
}

fn run(decompilers: &Decompilers, engine: &asc_ark_engine::Engine, request: &HarmonyRequest<'_>) -> Result<Decompiled, DecompileError> {
    decompilers.decompile_harmony(engine, request, &AtomicBool::new(false))
}

/// The `pid` the mock writes into its text.
fn pid_of(text: &str) -> u32 {
    let start = text.find("pid=").expect("mock output names its pid") + 4;
    text[start..].split_whitespace().next().unwrap().parse().unwrap()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn a_record_decompiles_and_the_second_call_is_cached() {
    let fixture = Fixture::new();
    let decompilers = fixture.decompilers(&["abc"]);
    let engine = fixture.engine("entry.hap");
    let first = run(&decompilers, &engine, &HarmonyRequest::new("pages/Index")).unwrap();
    assert_eq!((first.backend.as_deref(), first.status, first.language), (Some("abc"), Status::Ok, Some(Language::JavaScript)));
    assert_eq!((first.class.as_str(), first.entry.as_deref()), (INDEX_PAGE, Some("ets/modules.abc")));
    let sha = sha256_hex(&program());
    assert!(
        first.text.starts_with("// pid=") && first.text.contains(&format!("record={INDEX_PAGE} sha256={sha} options={{}}\n")),
        "{}",
        first.text
    );
    assert_eq!(first.header(), format!("// decompile {INDEX_PAGE} | ets/modules.abc | by abc 1.0 | status ok\n"));
    assert_eq!(first.path, Path::new("entry/src/main/ets/pages/Index.js"));
    let functions: Vec<(&str, Option<&str>)> = first.functions.iter().map(|f| (f.signature.as_str(), f.restored.as_deref())).collect();
    assert_eq!(functions, [("func_main_0", None), ("#~@0>#build", Some("Index.build"))]);
    // The zip entry was written out under its content for the backend.
    assert!(fixture.path(&format!("cache/decompilers/abc/{}/{sha}.abc", &sha[..2])).is_file());

    let second = run(&decompilers, &engine, &HarmonyRequest::new(INDEX_PAGE)).unwrap();
    assert!(second.cached && second.text == first.text, "{}", second.header());
    // The same bytes in a bare file: the same content key, so the same unit.
    let bare = run(&decompilers, &fixture.engine("bare/modules.abc"), &HarmonyRequest::new("pages/Index")).unwrap();
    assert!(bare.cached && bare.text == first.text);
    assert_eq!(bare.entry.as_deref(), Some("modules.abc"));
}

#[test]
fn functions_are_cut_out_by_their_span() {
    let fixture = Fixture::new();
    let decompilers = fixture.decompilers(&["abc"]);
    let engine = fixture.engine("entry.hap");
    for method in ["Index.build", "build", "#~@0>#build"] {
        let answer = run(&decompilers, &engine, &HarmonyRequest::new("pages/Index").method(Some(method))).unwrap();
        assert_eq!(answer.text, "function build() { return 1; }\n", "{method}");
        assert_eq!(answer.method.as_deref(), Some("#~@0>#build"));
    }
    // A findrefs location names the function too.
    let pasted = format!("{INDEX_PAGE}->#~@0>#build+0x12");
    assert_eq!(run(&decompilers, &engine, &HarmonyRequest::new(&pasted)).unwrap().text, "function build() { return 1; }\n");
    // A function the backend gives no span: the whole record, and the header says so.
    let whole = run(&decompilers, &engine, &HarmonyRequest::new("pages/Index").method(Some("aboutToAppear"))).unwrap();
    assert!(whole.text.contains("function func_main_0"));
    assert!(whole.header().contains("// abc reported no text of #~@0>#aboutToAppear; the whole record follows\n"), "{}", whole.header());
}

#[test]
fn raw_and_level_reach_the_backend_and_key_the_cache() {
    let fixture = Fixture::new();
    let decompilers = fixture.decompilers(&["abc"]);
    let engine = fixture.engine("entry.hap");
    let plain = run(&decompilers, &engine, &HarmonyRequest::new("pages/Index")).unwrap();
    let raw = run(&decompilers, &engine, &HarmonyRequest::new("pages/Index").raw(true)).unwrap();
    assert!(!raw.cached && raw.text.contains(r#"options={"raw":true}"#), "{}", raw.text);
    let level = run(&decompilers, &engine, &HarmonyRequest::new("pages/Index").level(Some(Level::PcDispatch))).unwrap();
    assert!(!level.cached && level.text.contains(r#"options={"level":"pcDispatch"}"#), "{}", level.text);
    assert_eq!(level.functions[0].level.as_deref(), Some("pcDispatch"));
    assert!(run(&decompilers, &engine, &HarmonyRequest::new("pages/Index").raw(true)).unwrap().cached);
    assert!(run(&decompilers, &engine, &HarmonyRequest::new("pages/Index")).unwrap().text == plain.text);
}

#[test]
fn partial_and_failed_records_and_a_crash() {
    let fixture = Fixture::new();
    let decompilers = fixture.decompilers(&["abc"]);
    let engine = fixture.engine("entry.hap");
    let partial = run(&decompilers, &engine, &HarmonyRequest::new("&inexact&")).unwrap();
    assert_eq!(partial.status, Status::Partial);
    assert!(
        partial
            .header()
            .contains("// failed methods: 1\n//   #~@0>#build (Index.build): inexact: contains an operation of unknown semantics\n"),
        "{}",
        partial.header()
    );
    let first_pid = pid_of(&partial.text);

    // A backend failing on the whole record: the disassembly, with the reason.
    let failed = run(&decompilers, &engine, &HarmonyRequest::new("&fail&")).unwrap();
    assert_eq!((failed.status, failed.backend.as_deref()), (Status::Disassembly, None));
    assert!(failed.text.contains(".function") && failed.text.contains("func_main_0"), "{}", failed.text);
    assert!(failed.header().starts_with("# decompile &fail& | ets/modules.abc | by disassembly (no decompiler gave source) | status failed\n# abc failed: record not found\n"), "{}", failed.header());
    assert_eq!(failed.path, Path::new("fail.pa"));

    // A crash fails that request; the next one is answered by a new process.
    let crashed = run(&decompilers, &engine, &HarmonyRequest::new("&crash&")).unwrap();
    assert_eq!(crashed.status, Status::Disassembly);
    assert!(crashed.attempts[0].reason.contains("exit"), "{:?}", crashed.attempts);
    let again = run(&decompilers, &engine, &HarmonyRequest::new("entryability/EntryAbility")).unwrap();
    assert_eq!(again.status, Status::Ok);
    assert_ne!(pid_of(&again.text), first_pid, "a new process answers");
}

#[test]
fn without_a_harmony_backend_the_disassembly_answers() {
    let fixture = Fixture::new();
    let engine = fixture.engine("entry.hap");
    // A DEX backend in the chain: it writes no javascript.
    let decompilers = fixture.decompilers(&["mock"]);
    let answer = run(&decompilers, &engine, &HarmonyRequest::new("pages/Index").method(Some("Index.build"))).unwrap();
    assert_eq!(answer.status, Status::Disassembly);
    assert_eq!(answer.attempts[0].reason, "no javascript output");
    let listing = engine.get_class(&asc_ark_engine::ClassQuery::new(INDEX_PAGE).function(Some("#~@0>#build"))).unwrap();
    assert_eq!(answer.text, listing.text, "what getclass shows");

    // The built-in arkdec without a worker says how to get one.
    let decompilers = fixture.decompilers(&[BUILT_IN_ARKDEC]);
    if decompilers.settings().arkdec.locate().is_some() {
        eprintln!("skipped the missing-worker half: an asc-arkdec-worker is found (ASC_ARKDEC_WORKER, next to the test or on PATH)");
        return;
    }
    let answer = run(&decompilers, &engine, &HarmonyRequest::new("pages/Index")).unwrap();
    assert_eq!((answer.status, answer.attempts.len()), (Status::Disassembly, 1));
    let reason = &answer.attempts[0].reason;
    assert!(reason.contains("asc-arkdec-worker not found") && reason.contains("ASC_ARKDEC_WORKER"), "{reason}");
}

#[test]
fn requests_that_cannot_be_asked_say_why() {
    let fixture = Fixture::new();
    let decompilers = fixture.decompilers(&["abc"]);
    let engine = fixture.engine("entry.hap");
    let error = |request: &HarmonyRequest<'_>| run(&decompilers, &engine, request).unwrap_err().to_string();
    assert!(error(&HarmonyRequest::new("pages/Nothing")).contains("pages/Nothing"));
    let missing = error(&HarmonyRequest::new("pages/Index").method(Some("nothing")));
    assert!(missing.contains("its functions: ") && missing.contains("Index.build"), "{missing}");
    assert!(error(&HarmonyRequest::new("pages/Index").language(Language::Java)).contains("decompiles to javascript"));
    assert!(error(&HarmonyRequest::new("pages/Index").decompiler(Some("jeb"))).starts_with("unknown decompiler \"jeb\""));

    // JavaScript is not a DEX class's language.
    let dir = tempfile::tempdir().unwrap();
    let apk = dir.path().join("app.apk");
    std::fs::write(&apk, asc_fixture::make_apk(&[("classes.dex", &asc_fixture::make_dex())], true)).unwrap();
    let dex = asc_engine::Engine::new(&apk);
    let wrong = decompilers.decompile(&dex, &Request::new("example.Test").language(Language::JavaScript), &AtomicBool::new(false));
    assert!(wrong.unwrap_err().to_string().contains("javascript is the language of HarmonyOS records"));
}
