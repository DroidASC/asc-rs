//! A scriptable decompiler backend for the lifecycle tests.
//!
//! Startup behaviour comes from flags:
//!
//! * `--max-concurrency N` (default 1), `--protocol-version N` (default 1)
//! * `--fail-startup`: write to stderr and exit 2 before reading anything
//! * `--hang-startup`: never answer `initialize`
//! * `--ignore-shutdown`: ignore SIGTERM and stdin EOF; only SIGKILL ends it
//! * `--log FILE`: append `start <pid>` / `open <pid> <programId>` lines
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
//! * anything else: `ok`, with text naming the pid and program id

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{self, BufReader, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use asc_decompile::protocol::methods::{
    CancelledParams, ClassUnit, DecompileClassesParams, DecompileClassesResult, Empty, Implementation, InitializeResult, InputKind,
    Language, MethodReport, MethodStatus, ProgramCloseParams, ProgramId, ProgramOpenParams, ProgramOpenResult, Progress, ProgressParams,
    UnitOutcome,
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
}

impl Flags {
    fn parse() -> Self {
        let mut flags = Self { max_concurrency: 1, protocol_version: 1, ..Self::default() };
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--max-concurrency" => flags.max_concurrency = args.next().unwrap().parse().unwrap(),
                "--protocol-version" => flags.protocol_version = args.next().unwrap().parse().unwrap(),
                "--fail-startup" => flags.fail_startup = true,
                "--hang-startup" => flags.hang_startup = true,
                "--ignore-shutdown" => flags.ignore_shutdown = true,
                "--log" => flags.log = Some(args.next().unwrap().into()),
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
                let result = InitializeResult::new(self.flags.protocol_version, Implementation::new("mock", "1.0"), options)
                    .inputs(vec![InputKind::Archive, InputKind::Slice])
                    .languages(vec![Language::Java])
                    .mappings(true)
                    .method_status(true)
                    .max_concurrency(self.flags.max_concurrency.try_into().unwrap());
                self.out.respond(request.id, Ok(result)).unwrap();
            }
            "program/open" => {
                let result = request.params::<ProgramOpenParams>().and_then(|params| {
                    if params.input.files().iter().any(|file| file.ends_with("unsupported")) {
                        return Err(ErrorObject::new(ErrorCode::UNSUPPORTED_INPUT, "mock rejects this input"));
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
        if !self.programs.lock().unwrap().contains_key(&params.program_id.0) {
            return Err(ErrorObject::new(ErrorCode::PROGRAM_NOT_FOUND, format!("no program {}", params.program_id.0)));
        }
        let mut units = Vec::new();
        for class in &params.classes {
            let ok = |text: String| ClassUnit::new(class.clone(), UnitOutcome::Ok { path: None, text });
            let pid = std::process::id();
            let normal = ok(format!("// pid={pid} program={} class={class}", params.program_id.0));
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
