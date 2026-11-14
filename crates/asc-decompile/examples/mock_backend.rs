//! A scriptable decompiler backend for the lifecycle tests.
//!
//! Startup behaviour comes from flags:
//!
//! * `--max-concurrency N` (default 1), `--protocol-version N` (default 1)
//! * `--fail-startup`: write to stderr and exit 2 before reading anything
//! * `--hang-startup`: never answer `initialize`
//! * `--ignore-shutdown`: ignore SIGTERM and stdin EOF; only SIGKILL ends it
//! * `--log FILE`: append `start <pid>` / `open <pid> <programId>` lines
//! * `--no-mappings`: declare `mappings = false`
//! * `--fail-all`: every class comes back `failed`
//! * `--version V` (default 1.0): the version reported in `initialize`
//! * `--abc`: be an ABC backend like arkdec instead: `inputs ["abc"]`,
//!   `languages ["javascript", "arkts"]`, `requestOptions ["raw", "level"]`, no mappings
//!
//! Per-class behaviour comes from the requested descriptor:
//!
//! * `Lslow/<ms>;`: work for `ms`, honouring cancellation
//! * `Lstubborn/<ms>;`: work for `ms`, ignoring cancellation
//! * `Lcrash;`: exit 3 mid-request
//! * `Lgarbage;`: write a non-JSON line to stdout
//! * `Lhuge;`: write a line over the 64 MiB limit
//! * `Lforget;`: drop every program session, then answer normally
//! * `Lfail;` / `Lpartial;`: a failed / partial unit
//! * `Lprogress;`: send two progress notifications first
//! * anything else: `ok`, with text naming the pid and program id (and the
//!   number of mapped classes, when the program was opened with mappings)
//!
//! With `--abc`, `program/open` takes only `kind: "abc"` with one file
//! (`-33002` / `-32602` otherwise) and answers `-33004` when `sha256` is
//! `"mismatch"`; `decompile/classes` takes `javascript` and `arkts` (whose
//! units have an `.ets` path and say `language=arkts` on their first line).
//! Per record:
//!
//! * `&crash&`: exit 3 mid-request
//! * `&slow/<ms>&`: work for `ms`, honouring cancellation
//! * `&inexact&`: a partial unit whose second function failed, with a diagnostic
//! * `&fail&`: a failed unit
//! * anything else: `ok`. The text's first line names the pid, program id,
//!   record, file sha256 and the request's `options`; then two functions,
//!   each reported in `methods` with its `span`

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{self, BufReader, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use asc_decompile::protocol::methods::{
    CancelledParams, ClassUnit, DecompileClassesParams, DecompileClassesResult, Diagnostic, Empty, Implementation, InitializeResult,
    InputKind, Language, MethodReport, MethodStatus, ProgramCloseParams, ProgramId, ProgramInput, ProgramOpenParams, ProgramOpenResult,
    Progress, ProgressParams, Severity, UnitOutcome,
};
use asc_decompile::protocol::server::{Cancellations, Outgoing};
use asc_decompile::protocol::{ErrorCode, ErrorObject, FrameReader, MAX_MESSAGE_BYTES, Message, Request, RequestId};

#[derive(Default)]
struct Flags {
    max_concurrency: u32,
    protocol_version: u32,
    fail_startup: bool,
    hang_startup: bool,
    ignore_shutdown: bool,
    log: Option<PathBuf>,
    no_mappings: bool,
    fail_all: bool,
    version: String,
    abc: bool,
}

impl Flags {
    fn parse() -> Self {
        let mut flags = Self { max_concurrency: 1, protocol_version: 1, version: "1.0".into(), ..Self::default() };
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--max-concurrency" => flags.max_concurrency = args.next().unwrap().parse().unwrap(),
                "--protocol-version" => flags.protocol_version = args.next().unwrap().parse().unwrap(),
                "--fail-startup" => flags.fail_startup = true,
                "--hang-startup" => flags.hang_startup = true,
                "--ignore-shutdown" => flags.ignore_shutdown = true,
                "--log" => flags.log = Some(args.next().unwrap().into()),
                "--no-mappings" => flags.no_mappings = true,
                "--fail-all" => flags.fail_all = true,
                "--version" => flags.version = args.next().unwrap(),
                "--abc" => flags.abc = true,
                other => panic!("unknown flag {other}"),
            }
        }
        flags
    }
}

type Stdout = Outgoing<io::Stdout>;

struct Mock {
    flags: Flags,
    out: Stdout,
    cancellations: Cancellations,
    programs: Mutex<HashMap<String, ProgramOpenParams>>,
    next_program: Mutex<u32>,
}

impl Mock {
    fn log(&self, line: &str) {
        if let Some(path) = &self.flags.log {
            let mut file = OpenOptions::new().create(true).append(true).open(path).unwrap();
            writeln!(file, "{line}").unwrap();
        }
    }

    fn handle(self: &Arc<Self>, request: Request) {
        match request.method.as_str() {
            "initialize" => {
                if self.flags.hang_startup {
                    return;
                }
                let options = serde_json::to_string(&request.params["options"]).unwrap();
                let result =
                    InitializeResult::new(self.flags.protocol_version, Implementation::new("mock", self.flags.version.as_str()), options)
                        .method_status(true)
                        .max_concurrency(self.flags.max_concurrency.try_into().unwrap());
                let result = if self.flags.abc {
                    result
                        .inputs(vec![InputKind::Abc])
                        .languages(vec![Language::JavaScript, Language::ArkTs])
                        .request_options(vec!["raw".into(), "level".into()])
                } else {
                    result
                        .inputs(vec![InputKind::Archive, InputKind::Slice])
                        .languages(vec![Language::Java])
                        .mappings(!self.flags.no_mappings)
                };
                self.out.respond(request.id, Ok(result)).unwrap();
            }
            "program/open" => {
                let result = request.params::<ProgramOpenParams>().and_then(|params| {
                    if params.input.files().iter().any(|file| file.ends_with("unsupported")) {
                        return Err(ErrorObject::new(ErrorCode::UNSUPPORTED_INPUT, "mock rejects this input"));
                    }
                    if self.flags.abc {
                        check_abc(&params.input)?;
                    }
                    let mut next = self.next_program.lock().unwrap();
                    *next += 1;
                    let id = format!("p{next}");
                    self.log(&format!("open {} {id}", std::process::id()));
                    self.programs.lock().unwrap().insert(id.clone(), params);
                    Ok(ProgramOpenResult::new(ProgramId(id)))
                });
                self.out.respond(request.id, result).unwrap();
            }
            "program/close" => {
                let result = request.params::<ProgramCloseParams>().and_then(|params| {
                    self.log(&format!("close {} {}", std::process::id(), params.program_id.0));
                    match self.programs.lock().unwrap().remove(&params.program_id.0) {
                        Some(_) => Ok(Empty {}),
                        None => Err(ErrorObject::new(ErrorCode::PROGRAM_NOT_FOUND, "no such program")),
                    }
                });
                self.out.respond(request.id, result).unwrap();
            }
            "decompile/classes" => {
                let mock = Arc::clone(self);
                thread::spawn(move || mock.decompile(request));
            }
            "shutdown" => self.out.respond(request.id, Ok(Empty {})).unwrap(),
            other => {
                let error = ErrorObject::new(ErrorCode::METHOD_NOT_FOUND, format!("no {other}"));
                self.out.respond::<Empty>(request.id, Err(error)).unwrap();
            }
        }
    }

    fn decompile(&self, request: Request) {
        let id = request.id.clone();
        let result = request.params::<DecompileClassesParams>().and_then(|params| self.units(&id, &params));
        let result = match result {
            Ok(Some(result)) => Ok(result),
            Ok(None) => return,
            Err(err) => Err(err),
        };
        self.cancellations.finish(&id);
        self.out.respond(id, result).unwrap();
    }

    /// `None` when the scripted behaviour means no answer at all.
    fn units(&self, id: &RequestId, params: &DecompileClassesParams) -> Result<Option<DecompileClassesResult>, ErrorObject> {
        if self.flags.abc {
            return self.records(id, params).map(Some);
        }
        let mapped = match self.programs.lock().unwrap().get(&params.program_id.0) {
            Some(program) => program.mappings.as_ref().map(|mappings| mappings.classes.len()),
            None => return Err(ErrorObject::new(ErrorCode::PROGRAM_NOT_FOUND, format!("no program {}", params.program_id.0))),
        };
        let mapped = mapped.map(|n| format!(" mappings={n}")).unwrap_or_default();
        let mut units = Vec::new();
        for class in &params.classes {
            let ok = |text: String| ClassUnit::new(class.clone(), UnitOutcome::Ok { path: None, text });
            let pid = std::process::id();
            let normal = ok(format!("// pid={pid} program={} class={class}{mapped}", params.program_id.0));
            if self.flags.fail_all {
                units.push(ClassUnit::new(class.clone(), UnitOutcome::Failed { reason: "mock fails everything".into() }));
                continue;
            }
            let unit = match class.as_str() {
                "Lcrash;" => {
                    eprintln!("mock: crashing on purpose");
                    std::process::exit(3);
                }
                "Lgarbage;" => {
                    let mut stdout = io::stdout().lock();
                    stdout.write_all(b"this is not json\n").unwrap();
                    stdout.flush().unwrap();
                    return Ok(None);
                }
                "Lhuge;" => {
                    let mut stdout = io::stdout().lock();
                    let chunk = vec![b'x'; 1 << 20];
                    // The client kills us partway; a broken pipe ends the attempt.
                    for _ in 0..=(MAX_MESSAGE_BYTES >> 20) {
                        if stdout.write_all(&chunk).is_err() {
                            break;
                        }
                    }
                    return Ok(None);
                }
                "Lforget;" => {
                    self.programs.lock().unwrap().clear();
                    normal
                }
                "Lfail;" => ClassUnit::new(class.clone(), UnitOutcome::Failed { reason: "mock failure".into() }),
                "Lpartial;" => {
                    let outcome = UnitOutcome::Partial { path: Some("Partial.java".into()), text: "class Partial {}".into() };
                    let failed = MethodReport::new("f()V", MethodStatus::Failed).reason(Some("irreducible loop".into()));
                    ClassUnit::new(class.clone(), outcome).methods(vec![failed])
                }
                "Lprogress;" => {
                    if let Some(token) = &params.progress_token {
                        for step in 0..2 {
                            let progress = ProgressParams::new(token.clone(), f64::from(step)).total(Some(2.0));
                            self.out.notify::<Progress>(&progress).unwrap();
                        }
                    }
                    normal
                }
                class => {
                    if let Some(work) = parse_work(class, "Lslow/") {
                        if !self.work(id, work, true) {
                            let error = ErrorObject::new(ErrorCode::REQUEST_CANCELLED, "cancelled");
                            return Err(error);
                        }
                    } else if let Some(work) = parse_work(class, "Lstubborn/") {
                        self.work(id, work, false);
                    }
                    normal
                }
            };
            units.push(unit);
        }
        Ok(Some(DecompileClassesResult::new(units)))
    }

    /// The `--abc` answer: one unit per record.
    fn records(&self, id: &RequestId, params: &DecompileClassesParams) -> Result<DecompileClassesResult, ErrorObject> {
        let arkts = match params.language {
            Language::JavaScript => false,
            Language::ArkTs => true,
            _ => return Err(ErrorObject::new(ErrorCode::INVALID_PARAMS, "mock --abc writes javascript or arkts only")),
        };
        let sha256 = match self.programs.lock().unwrap().get(&params.program_id.0).map(|program| &program.input) {
            Some(ProgramInput::Abc { sha256, .. }) => sha256.clone().unwrap_or_else(|| "-".into()),
            _ => return Err(ErrorObject::new(ErrorCode::PROGRAM_NOT_FOUND, format!("no program {}", params.program_id.0))),
        };
        let options = serde_json::to_string(&params.options).unwrap();
        let mut units = Vec::new();
        for record in &params.classes {
            let unit = match record.as_str() {
                "&crash&" => {
                    eprintln!("mock: crashing on purpose");
                    std::process::exit(3);
                }
                "&fail&" => ClassUnit::new(record.clone(), UnitOutcome::Failed { reason: "record not found".into() }),
                record => {
                    if let Some(work) = parse_record_work(record)
                        && !self.work(id, work, true)
                    {
                        return Err(ErrorObject::new(ErrorCode::REQUEST_CANCELLED, "cancelled"));
                    }
                    let pid = std::process::id();
                    let language = if arkts { " language=arkts" } else { "" };
                    let header = format!(
                        "// pid={pid} program={} record={record} sha256={sha256} options={options}{language}\n",
                        params.program_id.0
                    );
                    let main = "function func_main_0() {}\n";
                    let build = "function build() { return 1; }\n";
                    let text = format!("{header}{main}{build}");
                    let span = |start: usize, part: &str| Some([start as u64, (start + part.len()) as u64]);
                    let level = if params.options.get("level").is_some() { "pcDispatch" } else { "structured" };
                    let main_report =
                        MethodReport::new("func_main_0", MethodStatus::Ok).level(Some(level.into())).span(span(header.len(), main));
                    let build_report = MethodReport::new("#~@0>#build", MethodStatus::Ok)
                        .restored(Some("Index.build".into()))
                        .level(Some(level.into()))
                        .span(span(header.len() + main.len(), build));
                    let path = Some(format!("{}.{}", record.trim_matches('&'), if arkts { "ets" } else { "js" }));
                    if record == "&inexact&" {
                        let mut failed = build_report.reason(Some("inexact: contains an operation of unknown semantics".into()));
                        failed.status = MethodStatus::Failed;
                        let diagnostic =
                            Diagnostic::new(Severity::Warning, "opaque operation").method(Some("#~@0>#build".into())).pc(Some(0x12));
                        ClassUnit::new(record, UnitOutcome::Partial { path, text })
                            .methods(vec![main_report, failed])
                            .diagnostics(vec![diagnostic])
                    } else {
                        ClassUnit::new(record, UnitOutcome::Ok { path, text }).methods(vec![main_report, build_report])
                    }
                }
            };
            units.push(unit);
        }
        Ok(DecompileClassesResult::new(units))
    }

    /// Sleeps `work`; `false` if cancelled first.
    fn work(&self, id: &RequestId, work: Duration, cancellable: bool) -> bool {
        let deadline = Instant::now() + work;
        while Instant::now() < deadline {
            if cancellable && self.cancellations.is_cancelled(id) {
                self.cancellations.finish(id);
                return false;
            }
            thread::sleep(Duration::from_millis(5));
        }
        true
    }
}

/// What `program/open` of `--abc` accepts.
fn check_abc(input: &ProgramInput) -> Result<(), ErrorObject> {
    let ProgramInput::Abc { files, sha256, .. } = input else {
        return Err(ErrorObject::new(ErrorCode::UNSUPPORTED_INPUT, "mock --abc takes abc input only"));
    };
    if files.len() != 1 {
        return Err(ErrorObject::new(ErrorCode::INVALID_PARAMS, "abc input names exactly one file"));
    }
    if sha256.as_deref() == Some("mismatch") {
        return Err(ErrorObject::new(ErrorCode::INPUT_MISMATCH, "input changed since asc hashed it"));
    }
    Ok(())
}

fn parse_record_work(record: &str) -> Option<Duration> {
    let millis = record.strip_prefix("&slow/")?.strip_suffix('&')?;
    Some(Duration::from_millis(millis.parse().ok()?))
}

fn parse_work(class: &str, prefix: &str) -> Option<Duration> {
    let millis = class.strip_prefix(prefix)?.strip_suffix(';')?;
    Some(Duration::from_millis(millis.parse().ok()?))
}

fn main() {
    let flags = Flags::parse();
    if flags.fail_startup {
        eprintln!("mock: refusing to start");
        std::process::exit(2);
    }
    #[cfg(unix)]
    if flags.ignore_shutdown {
        // SAFETY: installing SIG_IGN for SIGTERM before any other thread exists.
        unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
    }
    let mock = Arc::new(Mock {
        flags,
        out: Outgoing::new(io::stdout()),
        cancellations: Cancellations::new(),
        programs: Mutex::new(HashMap::new()),
        next_program: Mutex::new(0),
    });
    mock.log(&format!("start {}", std::process::id()));
    eprintln!("mock: started");

    let mut reader = FrameReader::new(BufReader::new(io::stdin()));
    while let Some(message) = reader.read_message().unwrap() {
        match message {
            Message::Request(request) => mock.handle(request),
            Message::Notification(notification) if notification.method == "notifications/cancelled" => {
                let params: CancelledParams = notification.params().unwrap();
                mock.cancellations.cancel(params.request_id);
            }
            Message::Notification(_) | Message::Response(_) => {}
        }
    }
    if mock.flags.ignore_shutdown {
        loop {
            thread::sleep(Duration::from_secs(1));
        }
    }
}
