//! Lifecycle tests against `examples/mock_backend.rs`.
//!
//! `cargo test` builds examples before running integration tests; the mock is
//! found where Cargo put it.
#![cfg(unix)]

use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use asc_decompile::protocol::ErrorCode;
use asc_decompile::protocol::methods::{InputKind, ProgramInput, ProgramOpenParams, UnitStatus};
use asc_decompile::{Backend, BackendSpec, CallOptions, CancelToken, DecompileRequest, Error, Lifecycle, Priority, Program};
use serde_json::json;

fn mock_path() -> PathBuf {
    asc_fixture::mock_backend()
}

fn spec(args: &[&str]) -> BackendSpec {
    let mut spec = BackendSpec::new(mock_path());
    spec.args = args.iter().map(Into::into).collect();
    spec.timeout = Duration::from_secs(5);
    spec.startup_timeout = Duration::from_secs(5);
    spec.lifecycle = Lifecycle::default()
        .cancel_grace(Duration::from_millis(300))
        .shutdown_grace(Duration::from_millis(200))
        .backoff_initial(Duration::from_millis(10))
        .backoff_max(Duration::from_millis(40));
    spec
}

fn archive() -> ProgramOpenParams {
    ProgramOpenParams::new(ProgramInput::Archive { files: vec!["/data/app.apk".into()] })
}

fn open(backend: &Backend) -> Program {
    backend.open_program(archive(), &CallOptions::default()).unwrap()
}

fn decompile(program: &Program, class: &str) -> Result<String, Error> {
    decompile_with(program, class, &CallOptions::default())
}

fn decompile_with(program: &Program, class: &str, options: &CallOptions) -> Result<String, Error> {
    let mut result = program.decompile(&DecompileRequest::java([class]), options)?;
    assert_eq!(result.units.len(), 1);
    let unit = result.units.remove(0);
    Ok(unit.text().unwrap_or_default().to_owned())
}

/// `pid` field of the mock's default output.
fn pid_of(text: &str) -> u32 {
    let start = text.find("pid=").expect("mock output names its pid") + 4;
    text[start..].split_whitespace().next().unwrap().parse().unwrap()
}

fn is_alive(pid: u32) -> bool {
    // SAFETY: signal 0 only checks that the process exists.
    unsafe { libc::kill(libc::pid_t::try_from(pid).unwrap(), 0) == 0 }
}

fn log_lines(path: &Path, prefix: &str) -> usize {
    std::fs::read_to_string(path).unwrap_or_default().lines().filter(|line| line.starts_with(prefix)).count()
}

struct TempLog(PathBuf);

impl TempLog {
    fn new(name: &str) -> Self {
        let dir = std::env::current_exe().unwrap().parent().unwrap().join("mock-logs");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{name}-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);
        Self(path)
    }

    fn arg(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for TempLog {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn handshake_reports_capabilities() {
    let mut spec = spec(&["--max-concurrency", "3"]);
    spec.options.insert("deobfuscators".into(), json!(false));
    let backend = Backend::new("mock", spec);
    assert!(backend.last_capabilities().is_none(), "nothing starts before the first request");

    let capabilities = backend.capabilities(&CallOptions::default()).unwrap();
    assert_eq!(capabilities.backend.name, "mock");
    assert_eq!(capabilities.max_concurrency.get(), 3);
    assert!(capabilities.accepts(InputKind::Archive));
    assert_eq!(capabilities.options_hash, r#"{"deobfuscators":false}"#, "options are passed through");
    assert_eq!(backend.running_processes(), 1);
    // stderr is drained on its own thread, so give it a moment.
    let deadline = Instant::now() + Duration::from_secs(2);
    while !backend.stderr().contains("mock: started") {
        assert!(Instant::now() < deadline, "stderr not captured: {:?}", backend.stderr());
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn decompiles_and_reports_unit_status() {
    let backend = Backend::new("mock", spec(&[]));
    let program = open(&backend);
    let text = decompile(&program, "La;").unwrap();
    assert!(text.contains("program=p1 class=La;"), "{text}");

    let request = DecompileRequest::java(["Lpartial;", "Lfail;"]);
    let result = program.decompile(&request, &CallOptions::default()).unwrap();
    assert_eq!(result.units[0].status(), UnitStatus::Partial);
    assert_eq!(result.units[0].methods[0].reason.as_deref(), Some("irreducible loop"));
    assert_eq!(result.units[1].status(), UnitStatus::Failed);
    assert_eq!(result.units[1].text(), None);
}

#[test]
fn forwards_progress() {
    let backend = Backend::new("mock", spec(&[]));
    let program = open(&backend);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let options = CallOptions::default().progress(Some(Arc::new(move |p| sink.lock().unwrap().push(p.progress))));
    decompile_with(&program, "Lprogress;", &options).unwrap();
    assert_eq!(*seen.lock().unwrap(), [0.0, 1.0]);
}

#[test]
fn backend_errors_surface_as_rpc_errors() {
    let backend = Backend::new("mock", spec(&[]));
    let input = ProgramInput::Archive { files: vec!["/data/unsupported".into()] };
    let err = backend.open_program(ProgramOpenParams::new(input), &CallOptions::default()).unwrap_err();
    assert!(matches!(&err, Error::Rpc(e) if e.code == ErrorCode::UNSUPPORTED_INPUT), "{err}");
    assert!(!err.is_backend_failure());
}

#[test]
fn timeout_sends_cancel_and_keeps_the_process() {
    let backend = Backend::new("mock", spec(&[]));
    let program = open(&backend);
    let pid = pid_of(&decompile(&program, "La;").unwrap());

    let options = CallOptions::default().timeout(Some(Duration::from_millis(100)));
    let started = Instant::now();
    let err = decompile_with(&program, "Lslow/5000;", &options).unwrap_err();
    assert!(matches!(err, Error::Timeout(_)), "{err}");
    assert!(started.elapsed() < Duration::from_secs(2), "cancel was honoured, no kill grace: {:?}", started.elapsed());

    assert_eq!(pid_of(&decompile(&program, "La;").unwrap()), pid, "the process survives a honoured cancel");
}

#[test]
fn timeout_kills_a_backend_that_ignores_cancel() {
    let backend = Backend::new("mock", spec(&[]));
    let program = open(&backend);
    let pid = pid_of(&decompile(&program, "La;").unwrap());

    let options = CallOptions::default().timeout(Some(Duration::from_millis(100)));
    let started = Instant::now();
    let err = decompile_with(&program, "Lstubborn/5000;", &options).unwrap_err();
    assert!(matches!(err, Error::Timeout(_)), "{err}");
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(400) && elapsed < Duration::from_secs(3), "timeout + cancel grace: {elapsed:?}");

    let new_pid = pid_of(&decompile(&program, "La;").unwrap());
    assert_ne!(new_pid, pid, "the stubborn process was replaced");
    assert!(!is_alive(pid));
}

#[test]
fn caller_cancellation_aborts_the_request() {
    let backend = Backend::new("mock", spec(&[]));
    let program = open(&backend);
    let token = CancelToken::new();
    let canceller = token.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(100));
        canceller.cancel();
    });
    let options = CallOptions::default().cancel(Some(token));
    let started = Instant::now();
    let err = decompile_with(&program, "Lslow/5000;", &options).unwrap_err();
    assert!(matches!(err, Error::Cancelled), "{err}");
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn crash_fails_in_flight_request_then_restarts_and_reopens() {
    let log = TempLog::new("crash");
    let backend = Backend::new("mock", spec(&["--log", log.arg()]));
    let program = open(&backend);
    let pid = pid_of(&decompile(&program, "La;").unwrap());

    let err = decompile(&program, "Lcrash;").unwrap_err();
    let message = err.to_string();
    assert!(matches!(err, Error::Exited { .. }), "{message}");
    assert!(message.contains("exit status: 3"), "{message}");
    assert!(message.contains("mock: crashing on purpose"), "stderr tail is included: {message}");
    assert!(err.is_backend_failure());

    let text = decompile(&program, "La;").unwrap();
    assert_ne!(pid_of(&text), pid);
    assert_eq!(log_lines(&log.0, "start"), 2);
    assert_eq!(log_lines(&log.0, "open"), 2, "the program was reopened on the new process");
}

#[test]
fn crash_restart_waits_for_backoff() {
    let mut spec = spec(&[]);
    spec.lifecycle.backoff_initial = Duration::from_millis(400);
    spec.lifecycle.backoff_max = Duration::from_millis(400);
    let backend = Backend::new("mock", spec);
    let program = open(&backend);
    decompile(&program, "Lcrash;").unwrap_err();
    let started = Instant::now();
    decompile(&program, "La;").unwrap();
    assert!(started.elapsed() >= Duration::from_millis(300), "restart backed off: {:?}", started.elapsed());
}

#[test]
fn lost_session_is_reopened_transparently() {
    let log = TempLog::new("forget");
    let backend = Backend::new("mock", spec(&["--log", log.arg()]));
    let program = open(&backend);
    decompile(&program, "Lforget;").unwrap();
    let text = decompile(&program, "La;").unwrap();
    assert!(text.contains("program=p2"), "{text}");
    assert_eq!(log_lines(&log.0, "start"), 1, "same process");
}

#[test]
fn garbage_on_stdout_kills_the_process() {
    let backend = Backend::new("mock", spec(&[]));
    let program = open(&backend);
    let pid = pid_of(&decompile(&program, "La;").unwrap());
    let err = decompile(&program, "Lgarbage;").unwrap_err();
    let message = err.to_string();
    assert!(matches!(err, Error::Exited { .. }) && message.contains("protocol error"), "{message}");
    assert!(!is_alive(pid));
    assert_ne!(pid_of(&decompile(&program, "La;").unwrap()), pid);
}

#[test]
fn oversized_message_kills_the_process() {
    let backend = Backend::new("mock", spec(&[]));
    let program = open(&backend);
    let err = decompile(&program, "Lhuge;").unwrap_err();
    let message = err.to_string();
    assert!(message.contains("exceeds 67108864 bytes"), "{message}");
    decompile(&program, "La;").unwrap();
}

#[test]
fn startup_timeout() {
    let mut spec = spec(&["--hang-startup"]);
    spec.startup_timeout = Duration::from_millis(200);
    let backend = Backend::new("mock", spec);
    let started = Instant::now();
    let err = backend.capabilities(&CallOptions::default()).unwrap_err();
    assert!(matches!(&err, Error::Startup { reason, .. } if reason.contains("no initialize response")), "{err}");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(backend.running_processes(), 0);
}

#[test]
fn repeated_startup_failures_disable_the_backend() {
    let log = TempLog::new("disable");
    let backend = Backend::new("mock", spec(&["--fail-startup", "--log", log.arg()]));
    let mut errors = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match backend.capabilities(&CallOptions::default()) {
            Err(Error::Disabled { reason }) => {
                assert!(reason.contains("5 consecutive failed starts"), "{reason}");
                break;
            }
            Err(Error::Unavailable { retry_in, .. }) => thread::sleep(retry_in),
            Err(err) => errors.push(err.to_string()),
            Ok(_) => panic!("the mock never starts"),
        }
        assert!(Instant::now() < deadline, "not disabled: {errors:?}");
    }
    assert_eq!(errors.len(), 5, "{errors:?}");
    assert!(errors[0].contains("mock: refusing to start"), "startup errors carry stderr: {}", errors[0]);
    assert!(backend.disabled_reason().is_some());
}

#[test]
fn unknown_protocol_version_disables_immediately() {
    let backend = Backend::new("mock", spec(&["--protocol-version", "2"]));
    let err = backend.capabilities(&CallOptions::default()).unwrap_err();
    assert!(matches!(err, Error::ProtocolVersion { got: 2 }), "{err}");
    assert!(matches!(backend.capabilities(&CallOptions::default()), Err(Error::Disabled { .. })));
}

#[test]
fn shutdown_is_graceful() {
    let backend = Backend::new("mock", spec(&[]));
    let program = open(&backend);
    let pid = pid_of(&decompile(&program, "La;").unwrap());
    let started = Instant::now();
    drop(backend);
    assert!(started.elapsed() < Duration::from_millis(200), "exits on stdin EOF: {:?}", started.elapsed());
    assert!(!is_alive(pid));
    assert!(matches!(decompile(&program, "La;"), Err(Error::Closed)));
}

#[test]
fn shutdown_escalates_to_sigkill() {
    let backend = Backend::new("mock", spec(&["--ignore-shutdown"]));
    let program = open(&backend);
    let pid = pid_of(&decompile(&program, "La;").unwrap());
    drop(program);
    let started = Instant::now();
    backend.shutdown();
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(400), "waited after stdin close and after SIGTERM: {elapsed:?}");
    assert!(!is_alive(pid));
}

#[test]
fn idle_processes_shut_down() {
    let mut spec = spec(&[]);
    spec.idle = Duration::from_millis(150);
    let backend = Backend::new("mock", spec);
    let program = open(&backend);
    let pid = pid_of(&decompile(&program, "La;").unwrap());
    thread::sleep(Duration::from_millis(600));
    assert_eq!(backend.running_processes(), 0);
    assert!(!is_alive(pid));
    let text = decompile(&program, "La;").unwrap();
    assert_ne!(pid_of(&text), pid, "a new process with the program reopened");
}

/// Runs `classes` concurrently, starting them `stagger` apart, and returns the
/// completion order.
fn race(program: &Program, classes: &[(&str, Priority)], stagger: Duration) -> Vec<String> {
    let done = Mutex::new(Vec::new());
    thread::scope(|scope| {
        for (index, &(class, priority)) in classes.iter().enumerate() {
            let done = &done;
            scope.spawn(move || {
                thread::sleep(stagger * u32::try_from(index).unwrap());
                let options = CallOptions::default().priority(priority);
                decompile_with(program, class, &options).unwrap();
                done.lock().unwrap().push(format!("{index}"));
            });
        }
    });
    done.into_inner().unwrap()
}

#[test]
fn pool_runs_instances_times_max_concurrency() {
    let mut spec = spec(&["--max-concurrency", "2"]);
    spec.instances = NonZeroUsize::new(2).unwrap();
    let backend = Backend::new("mock", spec);
    let program = open(&backend);
    let started = Instant::now();
    race(&program, &[("Lslow/400;", Priority::Batch); 4], Duration::ZERO);
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_millis(750), "4 requests on 2×2 slots run at once: {elapsed:?}");
    assert_eq!(backend.running_processes(), 2);
}

#[test]
fn queue_is_fifo_with_interactive_first() {
    let backend = Backend::new("mock", spec(&[]));
    let program = open(&backend);
    let order = race(
        &program,
        &[
            ("Lslow/300;", Priority::Batch),
            ("Lslow/10;", Priority::Batch),
            ("Lslow/10;", Priority::Batch),
            ("Lslow/10;", Priority::Interactive),
        ],
        Duration::from_millis(50),
    );
    assert_eq!(order, ["0", "3", "1", "2"]);
}

#[test]
fn program_close_releases_sessions() {
    let log = TempLog::new("close");
    let backend = Backend::new("mock", spec(&["--log", log.arg()]));
    let program = open(&backend);
    decompile(&program, "La;").unwrap();
    program.close().unwrap();
    assert_eq!(log_lines(&log.0, "close"), 1);

    let slice = ProgramInput::Slice { files: vec!["/c/s.dex".into()], manifest: Default::default() };
    drop(backend.open_program(ProgramOpenParams::new(slice), &CallOptions::default()).unwrap());
    assert_eq!(log_lines(&log.0, "close"), 2, "dropping a program closes it too");
}
