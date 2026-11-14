//! `asc decompile` and the MCP tool `decompile`: Java or Kotlin source of a
//! class from a decompiler backend, or JavaScript of a HarmonyOS record
//! ([`Decompilers::decompile_harmony`]; docs/decompile-backends.md).
//!
//! [`Decompilers`] owns one process pool per backend ([`asc_decompile::Backend`])
//! and the program sessions open on them. A resident host (the daemon, an
//! `asc mcp` session) keeps one for its lifetime, so processes and sessions
//! outlive a request; a command run on its own makes one and drops it at the
//! end, which shuts its processes down.
//!
//! A request goes down the chain of backends ([`Settings::chain`]): the
//! default and then the fallbacks, or only the one named. A backend that
//! fails on the whole class (`failed`, a crash, a timeout, a start that does
//! not complete) hands over to the next; `partial` is an answer, its failed
//! methods listed. When every backend failed the answer is the class's
//! smali (the disassembly, for a HarmonyOS record). DEX and HarmonyOS
//! programs have a chain each ([`Settings::chain_for`]). Results of a
//! backend are kept in the L3 tier of the disk cache,
//! keyed by everything the output depends on (docs/decompile-backends.md
//! §8); failures for 10 minutes only.
//!
//! Names come only from a mapping file the user gives (§7): it is sent with
//! `program/open` to backends that declare `mappings`; for the others the
//! answer says the names are not unified, and the source is left as is.
//!
//! The built-in backends run `asc-dexdec-worker` and `asc-arkdec-worker`,
//! found (dexdec's also installed when missing) as [`worker`] says, looked
//! up again when the file changes.

mod abc_input;
pub mod dexdec;
mod harmony;
#[cfg(feature = "installer")]
pub mod install;
mod l3;
mod outcome;
mod settings;
mod source;
pub mod worker;

pub use asc_decompile::protocol::methods::{Language, MethodReport};
pub use harmony::{HarmonyRequest, Level};
pub use outcome::{Attempt, Decompiled, Naming, Status};
pub use settings::{BUILT_IN, BUILT_IN_ARKDEC, BackendEntry, Origin, Settings};
pub use source::output_path;
pub use worker::{Tool, Worker, WorkerOrigin, WorkerSettings};

use asc_decompile::protocol::ErrorCode;
use asc_decompile::protocol::methods::{ClassUnit, InitializeResult, InputKind, Mappings, ProgramInput, ProgramOpenParams, UnitOutcome};
use asc_decompile::{Backend, CallOptions, CancelToken, DecompileRequest, Priority, ProcessInfo, Program};
use asc_engine::asc_cache::{ApkKey, DiskCache};
use asc_engine::names::{self, MappingsHash, NameMappings};
use asc_engine::{Engine, EngineError, SharedCache, SmaliOptions};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};

use crate::class_text::ClassText;

/// Program sessions kept open across requests; the least recently used beyond this close.
const MAX_PROGRAMS: usize = 16;
/// How often a request checks the caller's cancel flag.
const CANCEL_POLL: Duration = Duration::from_millis(20);

/// Why a request got no answer at all. A backend failing is not one of
/// these: the next backend, or smali, answers then.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DecompileError {
    /// The request names a backend that is not configured.
    #[error("unknown decompiler {name:?}; configured: {known}")]
    UnknownDecompiler {
        /// The name given.
        name: String,
        /// The configured names.
        known: String,
    },
    /// A language other than `java`, `kotlin`, `javascript` or `arkts`.
    #[error("unknown language {0:?}; use java, kotlin, javascript or arkts")]
    UnknownLanguage(String),
    /// A language or option the program's format does not have: JavaScript
    /// or ArkTS of a DEX class, Java of a HarmonyOS record, a mapping file there.
    #[error("{0}")]
    WrongFormat(String),
    /// The HarmonyOS record or function, or its ABC entry: not found,
    /// ambiguous or unreadable; the text says which.
    #[error("{0}")]
    Harmony(String),
    /// The mapping file could not be read.
    #[error("cannot read mapping file {path}: {message}")]
    Mapping {
        /// The file.
        path: PathBuf,
        /// What went wrong.
        message: String,
    },
    /// The class name, the program or the class (for the smali fallback).
    #[error(transparent)]
    Engine(#[from] EngineError),
    /// The class has no method the request names.
    #[error("{class} has no method {method:?} in its {language}{hint}")]
    NoMethod {
        /// The class descriptor.
        class: String,
        /// The method asked for.
        method: String,
        /// `decompiled source` or `smali`.
        language: &'static str,
        /// The methods it has, when known.
        hint: String,
    },
    /// The caller cancelled the request.
    #[error("cancelled")]
    Cancelled,
}

/// The language `name` (`java`, `kotlin`, `kt`, `javascript`, `js`, `arkts`, `ets`), case aside.
///
/// # Errors
///
/// [`DecompileError::UnknownLanguage`] for anything else.
pub fn parse_language(name: &str) -> Result<Language, DecompileError> {
    match name.trim().to_ascii_lowercase().as_str() {
        "java" => Ok(Language::Java),
        "kotlin" | "kt" => Ok(Language::Kotlin),
        "javascript" | "js" => Ok(Language::JavaScript),
        "arkts" | "ets" => Ok(Language::ArkTs),
        _ => Err(DecompileError::UnknownLanguage(name.to_string())),
    }
}

/// `java`, `kotlin`, `javascript` or `arkts`, as messages, the L3 key and MCP say it.
pub fn language_name(language: Language) -> &'static str {
    match language {
        Language::Kotlin => "kotlin",
        Language::JavaScript => "javascript",
        Language::ArkTs => "arkts",
        _ => "java",
    }
}

/// What a request on a DEX program says when it asks for JavaScript or ArkTS.
const DEX_LANGUAGES: &str = "a DEX class decompiles to java or kotlin; javascript and arkts are the languages of HarmonyOS records";

/// What to decompile.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct Request<'a> {
    /// The class, dotted or as a descriptor.
    pub class: &'a str,
    /// The backend to use alone; `None`: the default, then the fallbacks.
    pub decompiler: Option<&'a str>,
    /// The output language.
    pub language: Language,
    /// Only these methods: a name (every overload) or a signature.
    pub method: Option<&'a str>,
    /// The mapping file, in place of `decompile.mapping`.
    pub mapping: Option<&'a Path>,
    /// Queue lane of the backend requests.
    pub priority: Priority,
}

impl<'a> Request<'a> {
    /// Java source of `class` from the default chain.
    pub fn new(class: &'a str) -> Request<'a> {
        Request { class, decompiler: None, language: Language::Java, method: None, mapping: None, priority: Priority::Interactive }
    }

    /// The request with [`decompiler`](#structfield.decompiler) set.
    #[must_use]
    pub fn decompiler(self, decompiler: Option<&'a str>) -> Request<'a> {
        Request { decompiler, ..self }
    }

    /// The request with [`language`](#structfield.language) set.
    #[must_use]
    pub fn language(self, language: Language) -> Request<'a> {
        Request { language, ..self }
    }

    /// The request with [`method`](#structfield.method) set.
    #[must_use]
    pub fn method(self, method: Option<&'a str>) -> Request<'a> {
        Request { method, ..self }
    }

    /// The request with [`mapping`](#structfield.mapping) set.
    #[must_use]
    pub fn mapping(self, mapping: Option<&'a Path>) -> Request<'a> {
        Request { mapping, ..self }
    }

    /// The request with [`priority`](#structfield.priority) set.
    #[must_use]
    pub fn priority(self, priority: Priority) -> Request<'a> {
        Request { priority, ..self }
    }
}

/// A backend process as [`Decompilers::processes`] lists it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BackendProcess {
    /// The backend's name.
    pub backend: String,
    /// The process.
    pub info: ProcessInfo,
    /// Its resident memory, as the system reports it (0 where it cannot tell).
    pub resident_bytes: usize,
}

/// A program open on a backend: one session per process serving it.
struct OpenProgram {
    backend: String,
    files: Vec<PathBuf>,
    /// Of an ABC input: the content the backend checked the file against.
    sha256: Option<String>,
    mappings: Option<MappingsHash>,
    program: Arc<Program>,
    used: u64,
}

#[derive(Default)]
struct Programs {
    open: Vec<OpenProgram>,
    tick: u64,
}

/// A mapping file as last read, reread when it changes.
struct LoadedMapping {
    path: PathBuf,
    stamp: Option<(u64, SystemTime)>,
    mappings: Arc<NameMappings>,
}

/// The worker a built-in backend's pool runs, and the install attempts.
#[derive(Default)]
struct WorkerState {
    /// The file of the pool running now, as it was when the pool started.
    stamp: Option<(u64, SystemTime)>,
    /// When and why an install by this process last failed.
    failed: Option<(Instant, String)>,
    /// A worker of another protocol version was met; it is not looked at again.
    protocol_checked: bool,
}

/// The backends of a host and what they keep open.
pub struct Decompilers {
    settings: Settings,
    // Programs before backends: their sessions close while the pools still run.
    programs: Mutex<Programs>,
    backends: Mutex<BTreeMap<String, Arc<Backend>>>,
    /// By backend name: the worker of each built-in backend's pool.
    workers: Mutex<BTreeMap<String, WorkerState>>,
    mapping: Mutex<Option<LoadedMapping>>,
    disk: Option<DiskCache>,
    /// Where ABC entries are written for a backend to read.
    abc_files: abc_input::Store,
}

/// What a backend is handed.
enum Input<'a> {
    /// The files of a DEX program, as they are.
    Archive(&'a [PathBuf]),
    /// One ABC file of a HarmonyOS program.
    Abc(abc_input::AbcFile<'a>),
}

/// One request on its way down the chain.
struct Context<'a> {
    /// The class descriptor, or the record name.
    unit: &'a str,
    language: Language,
    /// The L3 key of the program (of the ABC file's content, for a record).
    apk: Option<&'a ApkKey>,
    input: Input<'a>,
    mappings: Option<&'a Arc<NameMappings>>,
    /// Per-request options; a backend must declare each.
    request: Map<String, Value>,
    options: CallOptions,
}

/// The first answer down a chain, or why there is none.
enum Outcome {
    Answered {
        name: String,
        answer: Box<Answer>,
        attempts: Vec<Attempt>,
    },
    /// Every backend failed on the whole unit.
    Failed(Vec<Attempt>),
}

/// What a backend answered for the class.
struct Answer {
    unit: ClassUnit,
    capabilities: Arc<InitializeResult>,
    cached: bool,
    naming: Naming,
}

impl Decompilers {
    /// No backend runs until a request needs it. `disk` holds the L3
    /// results; `None` keeps none.
    pub fn new(settings: Settings, disk: Option<DiskCache>) -> Decompilers {
        Decompilers {
            settings,
            programs: Mutex::new(Programs::default()),
            backends: Mutex::new(BTreeMap::new()),
            workers: Mutex::new(BTreeMap::new()),
            mapping: Mutex::new(None),
            abc_files: abc_input::Store::new(disk.as_ref().map(DiskCache::dir)),
            disk,
        }
    }

    /// [`Decompilers::new`] with L3 in the directory of `disk`.
    pub fn with_disk_of(settings: Settings, disk: Option<&DiskCache>) -> Decompilers {
        Decompilers::new(settings, disk.map(l3::reopen))
    }

    /// The backends and the choice between them.
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    fn lock_backends(&self) -> MutexGuard<'_, BTreeMap<String, Arc<Backend>>> {
        self.backends.lock().expect("decompiler pools mutex poisoned")
    }

    fn lock_programs(&self) -> MutexGuard<'_, Programs> {
        self.programs.lock().expect("decompiler programs mutex poisoned")
    }

    /// The pool of `name`, created on first use; `None` if `name` is not configured.
    ///
    /// A pool of the built-in worker made here runs the worker as
    /// [`Settings`] found it; requests look for it again first.
    pub fn backend(&self, name: &str) -> Option<Arc<Backend>> {
        let entry = self.settings.backends.get(name)?;
        let mut backends = self.lock_backends();
        let backend = backends.entry(name.to_string()).or_insert_with(|| Arc::new(Backend::new(name, entry.spec.clone())));
        Some(Arc::clone(backend))
    }

    /// The pool a request on `name` uses. For the worker that asc finds
    /// (§12), the pool runs the worker found now; one whose file changed
    /// since its pool started (reinstalled, rebuilt, removed) is looked for
    /// again, and installed if it is missing and that is allowed.
    fn pool(&self, name: &str, entry: &BackendEntry, options: &CallOptions) -> Result<Arc<Backend>, String> {
        if !entry.finds_worker {
            return self.backend(name).ok_or_else(|| "not configured".to_string());
        }
        let settings = self.settings.worker(entry.tool);
        let mut workers = self.workers.lock().expect("decompiler worker mutex poisoned");
        let state = workers.entry(name.to_string()).or_default();
        if let Some(backend) =
            self.lock_backends().get(name).filter(|b| state.stamp.is_some() && worker::stamp(&b.spec().command) == state.stamp)
        {
            return Ok(Arc::clone(backend));
        }
        let found = settings.locate();
        let worker = match found {
            Some(worker) => worker,
            None => self.install_worker(settings, state).inspect_err(|_| {
                self.lock_backends().remove(name);
            })?,
        };
        let backend = self.start_worker(name, entry, &worker, state);
        if worker.origin == WorkerOrigin::Managed || state.protocol_checked {
            return Ok(backend);
        }
        // A worker speaking another protocol version (an old copy on PATH, a
        // stale build next to asc) cannot serve asc at all: use asc's own
        // install. Any other failure is the request's to report.
        let Err(asc_decompile::Error::ProtocolVersion { got }) = backend.capabilities(options) else {
            return Ok(backend);
        };
        state.protocol_checked = true;
        let managed = settings.managed().ok_or(()).or_else(|()| self.install_worker(settings, state));
        match managed {
            Ok(managed) => Ok(self.start_worker(name, entry, &managed, state)),
            Err(reason) => Err(format!(
                "{} ({}) speaks decompile protocol {got}, this asc {}; {reason}",
                worker.path.display(),
                worker.origin.name(),
                worker::PROTOCOL
            )),
        }
    }

    /// A pool of `entry` running `worker`, in place of the one before.
    fn start_worker(&self, name: &str, entry: &BackendEntry, worker: &Worker, state: &mut WorkerState) -> Arc<Backend> {
        let mut spec = entry.spec.clone();
        spec.command.clone_from(&worker.path);
        state.stamp = worker::stamp(&worker.path);
        let backend = Arc::new(Backend::new(name, spec));
        // The sessions of the pool replaced, if any, are on its processes:
        // closed, and the pool shuts down when its last request lets go.
        self.lock_programs().open.retain(|open| open.backend != name);
        self.lock_backends().insert(name.to_string(), Arc::clone(&backend));
        backend
    }

    /// Installs the worker of asc's protocol version ([`WorkerSettings::auto_install`]),
    /// once an hour at most in this process too (its data directory may not
    /// be writable); `Err` is the reason the request shows.
    fn install_worker(&self, settings: &WorkerSettings, state: &mut WorkerState) -> Result<Worker, String> {
        if let Some((_, reason)) = state.failed.as_ref().filter(|(at, _)| at.elapsed() < worker::RETRY_AFTER) {
            return Err(reason.clone());
        }
        settings.auto_install().inspect_err(|reason| state.failed = Some((Instant::now(), reason.clone())))
    }

    /// Every backend process now running.
    pub fn processes(&self) -> Vec<BackendProcess> {
        let backends: Vec<(String, Arc<Backend>)> = self.lock_backends().iter().map(|(n, b)| (n.clone(), Arc::clone(b))).collect();
        backends
            .iter()
            .flat_map(|(name, backend)| {
                backend.processes().into_iter().map(|info| BackendProcess {
                    backend: name.clone(),
                    resident_bytes: resident_bytes(info.pid),
                    info,
                })
            })
            .collect()
    }

    /// Shuts the backend process down if it is idle (§10).
    pub fn retire(&self, process: &BackendProcess) -> bool {
        let backend = self.lock_backends().get(&process.backend).cloned();
        backend.is_some_and(|backend| backend.retire(process.info.pid))
    }

    /// Of a host's open programs (`program_bytes`, most recently used
    /// first, as [`SharedCache::fit_resident_bytes`] takes them), those to
    /// close so that they and the backend processes fit the memory budget.
    /// Backend processes come after the programs, busy ones first and then
    /// by idle time: the longest idle close first, and are retired here.
    pub fn fit_resident(&self, cache: &SharedCache, program_bytes: &[usize]) -> Vec<usize> {
        let mut processes = self.processes();
        processes.sort_by_key(|process| process.info.idle_for);
        let sizes: Vec<usize> = program_bytes.iter().copied().chain(processes.iter().map(|p| p.resident_bytes)).collect();
        let closing = cache.fit_resident_bytes(&sizes);
        let (programs, backends): (Vec<usize>, Vec<usize>) = closing.into_iter().partition(|&i| i < program_bytes.len());
        for i in backends {
            self.retire(&processes[i - program_bytes.len()]);
        }
        programs
    }

    /// Shuts every backend down; later requests start them again.
    pub fn close(&self) {
        self.lock_programs().open.clear();
        let backends = std::mem::take(&mut *self.lock_backends());
        std::thread::scope(|scope| {
            for backend in backends.into_values() {
                scope.spawn(move || drop(backend));
            }
        });
    }

    /// The mapping file in effect: `path`, else `decompile.mapping`; read
    /// again when it changed since the last request.
    fn mapping(&self, path: Option<&Path>) -> Result<Option<Arc<NameMappings>>, DecompileError> {
        let Some(path) = path.or(self.settings.mapping.as_deref()) else { return Ok(None) };
        let stamp = std::fs::metadata(path).ok().and_then(|m| Some((m.len(), m.modified().ok()?)));
        let mut loaded = self.mapping.lock().expect("mapping mutex poisoned");
        if let Some(current) = loaded.as_ref().filter(|l| l.path == path && l.stamp.is_some() && l.stamp == stamp) {
            return Ok(Some(Arc::clone(&current.mappings)));
        }
        let parsed = NameMappings::from_proguard_file(path)
            .map_err(|e| DecompileError::Mapping { path: path.to_path_buf(), message: e.to_string() })?;
        let mappings = Arc::new(parsed.mappings);
        *loaded = Some(LoadedMapping { path: path.to_path_buf(), stamp, mappings: Arc::clone(&mappings) });
        Ok(Some(mappings))
    }

    /// Decompiles a class of `engine`'s program. Raising `cancel` aborts it.
    ///
    /// # Errors
    ///
    /// A bad class name, an unknown backend or language, an unreadable
    /// mapping file or program, a method the class does not have, a class
    /// the program does not have (found out when every backend failed), or
    /// cancellation. A failing backend is not an error: see the module docs.
    pub fn decompile(&self, engine: &Engine, request: &Request<'_>, cancel: &AtomicBool) -> Result<Decompiled, DecompileError> {
        let descriptor = names::format_class_name(request.class)?;
        if matches!(request.language, Language::JavaScript | Language::ArkTs) {
            return Err(DecompileError::WrongFormat(DEX_LANGUAGES.into()));
        }
        self.check_decompiler(request.decompiler)?;
        let mappings = self.mapping(request.mapping)?.filter(|m| !m.is_empty());
        let apk = engine.open()?;
        let key = engine.apk_key(&apk);
        // Absolute: a backend runs in a working directory of its own.
        let files: Vec<PathBuf> = apk
            .directories()
            .map_err(EngineError::from)?
            .iter()
            .map(|id| std::path::absolute(id.path).unwrap_or_else(|_| id.path.to_path_buf()))
            .collect();
        let mut context = Context {
            unit: &descriptor,
            language: request.language,
            apk: key.as_ref(),
            input: Input::Archive(&files),
            mappings: mappings.as_ref(),
            request: Map::new(),
            options: CallOptions::default().priority(request.priority),
        };
        let chain = self.settings.chain(request.decompiler);
        match self.run_chain(&chain, &mut context, cancel)? {
            Outcome::Answered { name, answer, attempts } => {
                let text = answer.unit.text().unwrap_or_default();
                self.answer(&name, &answer, text, attempts, request, &context)
            }
            Outcome::Failed(attempts) => self.smali(engine, request, &context, attempts, cancel),
        }
    }

    /// `Err` when the request names a backend that is not configured.
    fn check_decompiler(&self, decompiler: Option<&str>) -> Result<(), DecompileError> {
        match decompiler.filter(|name| !self.settings.backends.contains_key(*name)) {
            Some(name) => Err(DecompileError::UnknownDecompiler { name: name.to_string(), known: self.settings.known() }),
            None => Ok(()),
        }
    }

    /// Asks the backends of `chain` in turn for the unit of `context`, until
    /// one gives source. Raising `cancel` aborts the request in flight.
    fn run_chain(&self, chain: &[&str], context: &mut Context<'_>, cancel: &AtomicBool) -> Result<Outcome, DecompileError> {
        let token = CancelToken::new();
        context.options = context.options.clone().cancel(Some(token.clone()));
        let done = AtomicBool::new(false);
        let context = &*context;
        std::thread::scope(|scope| {
            scope.spawn(|| {
                while !done.load(Ordering::Acquire) {
                    if cancel.load(Ordering::Relaxed) {
                        token.cancel();
                        return;
                    }
                    std::thread::sleep(CANCEL_POLL);
                }
            });
            let result = self.ask_chain(chain, context, cancel);
            done.store(true, Ordering::Release);
            result
        })
    }

    fn ask_chain(&self, chain: &[&str], context: &Context<'_>, cancel: &AtomicBool) -> Result<Outcome, DecompileError> {
        let mut attempts = Vec::new();
        for &name in chain {
            if cancel.load(Ordering::Relaxed) {
                return Err(DecompileError::Cancelled);
            }
            let reason = match self.ask(name, context) {
                Ok(answer) => match answer.unit.outcome {
                    UnitOutcome::Ok { .. } | UnitOutcome::Partial { .. } => {
                        return Ok(Outcome::Answered { name: name.to_string(), answer: Box::new(answer), attempts });
                    }
                    UnitOutcome::Failed { ref reason } if answer.cached => format!("{reason} (cached failure)"),
                    UnitOutcome::Failed { ref reason } => reason.clone(),
                    _ => "the backend answered with an unknown status".to_string(),
                },
                Err(reason) => reason,
            };
            attempts.push(Attempt { backend: name.to_string(), reason });
        }
        if cancel.load(Ordering::Relaxed) {
            return Err(DecompileError::Cancelled);
        }
        Ok(Outcome::Failed(attempts))
    }

    /// The unit from backend `name`: from L3, or from the backend (stored in
    /// L3 then); `Err` with the reason when the backend cannot answer at all.
    fn ask(&self, name: &str, context: &Context<'_>) -> Result<Answer, String> {
        let entry = self.settings.backends.get(name).ok_or_else(|| format!("not configured (known: {})", self.settings.known()))?;
        if !entry.enabled {
            return Err("disabled in the config file".into());
        }
        let backend = self.pool(name, entry, &context.options)?;
        // The version and options hash of the last start are what the cache
        // key needs: a resident host knows them without starting anything.
        let capabilities = match backend.last_capabilities() {
            Some(capabilities) => capabilities,
            None => backend.capabilities(&context.options).map_err(|e| e.to_string())?,
        };
        if !capabilities.supports(context.language) {
            return Err(format!("no {} output", language_name(context.language)));
        }
        let kind = match context.input {
            Input::Archive(_) => InputKind::Archive,
            Input::Abc(_) => InputKind::Abc,
        };
        if !(capabilities.accepts(kind) && entry.allows(kind)) {
            return Err(match kind {
                InputKind::Abc => "takes no ABC input".into(),
                _ => "takes only slices of the program, which asc does not build yet".into(),
            });
        }
        if let Some(option) = context.request.keys().find(|option| !capabilities.honours(option)) {
            return Err(format!("does not take the request option `{option}`"));
        }
        let (mappings, naming) = match context.mappings {
            Some(mappings) if capabilities.mappings => (Some(mappings), Naming::Unified),
            Some(_) => (None, Naming::NotUnified),
            None => (None, Naming::Dex),
        };
        let mappings_hash = mappings.map(|m| m.hash());
        let request = if context.request.is_empty() { String::new() } else { Value::Object(context.request.clone()).to_string() };
        let content = match &context.input {
            Input::Abc(abc) => Some(abc.sha256.as_str()),
            Input::Archive(_) => None,
        };
        let key = |capabilities| l3::UnitKey {
            descriptor: context.unit,
            content,
            input: kind,
            backend: name,
            capabilities,
            mappings: mappings_hash,
            language: context.language,
            nested: true,
            request: &request,
        };
        let cache = self.disk.as_ref().zip(context.apk);
        if let Some(unit) = cache.and_then(|(disk, apk)| l3::get(disk, apk, &key(&capabilities))) {
            return Ok(Answer { unit, capabilities, cached: true, naming });
        }
        let decompile = DecompileRequest::new([context.unit], context.language).nested(true).options(context.request.clone());
        let mut result = match self.decompile_on(name, &backend, context, mappings, &decompile) {
            // The file is not what asc hashed (rewritten meanwhile): write the
            // bytes asc read to a file of asc's own and ask once more.
            Err(asc_decompile::Error::Rpc(error)) if error.code == ErrorCode::INPUT_MISMATCH => match &context.input {
                Input::Abc(abc) => {
                    self.forget_program(name, &abc.sha256);
                    let file = self.abc_files.rewrite(abc).map_err(|e| format!("{}; rewriting the input: {e}", error.message))?;
                    let fresh = Context {
                        unit: context.unit,
                        language: context.language,
                        apk: context.apk,
                        input: Input::Abc(abc.with_file(file)),
                        mappings: context.mappings,
                        request: context.request.clone(),
                        options: context.options.clone(),
                    };
                    self.decompile_on(name, &backend, &fresh, mappings, &decompile)
                }
                Input::Archive(_) => Err(asc_decompile::Error::Rpc(error)),
            },
            result => result,
        }
        .map_err(|e| e.to_string())?;
        // A nested class may come as the unit of the class it is folded into (§6.3).
        let at = result.units.iter().position(|unit| unit.covers(context.unit)).or((!result.units.is_empty()).then_some(0));
        let unit = at.map(|at| result.units.swap_remove(at)).ok_or("the backend answered without the class")?;
        // The capabilities of the process that answered, which a restart may have changed.
        let answered = backend.last_capabilities().unwrap_or_else(|| Arc::clone(&capabilities));
        if let Some((disk, apk)) = cache {
            l3::put(disk, apk, &key(&answered), &unit);
        }
        Ok(Answer { unit, capabilities: answered, cached: false, naming })
    }

    /// `request` on the program of `context` open on `backend`.
    fn decompile_on(
        &self,
        name: &str,
        backend: &Backend,
        context: &Context<'_>,
        mappings: Option<&Arc<NameMappings>>,
        request: &DecompileRequest,
    ) -> Result<asc_decompile::protocol::methods::DecompileClassesResult, asc_decompile::Error> {
        let program = self.program(name, backend, &context.input, mappings, &context.options)?;
        program.decompile(request, &context.options)
    }

    /// Closes the programs of `backend` open on ABC content `sha256`.
    fn forget_program(&self, backend: &str, sha256: &str) {
        self.lock_programs().open.retain(|open| !(open.backend == backend && open.sha256.as_deref() == Some(sha256)));
    }

    /// The program open on `backend` with this input and mappings, opened on a miss.
    fn program(
        &self,
        name: &str,
        backend: &Backend,
        input: &Input<'_>,
        mappings: Option<&Arc<NameMappings>>,
        options: &CallOptions,
    ) -> Result<Arc<Program>, asc_decompile::Error> {
        let hash = mappings.map(|m| m.hash());
        let (files, sha256): (Vec<PathBuf>, Option<&str>) = match input {
            Input::Archive(files) => (files.to_vec(), None),
            Input::Abc(abc) => (vec![abc.file.clone()], Some(abc.sha256.as_str())),
        };
        let found = |p: &OpenProgram| p.backend == name && p.files == files && p.sha256.as_deref() == sha256 && p.mappings == hash;
        {
            let mut programs = self.lock_programs();
            programs.tick += 1;
            let tick = programs.tick;
            if let Some(open) = programs.open.iter_mut().find(|p| found(p)) {
                open.used = tick;
                return Ok(Arc::clone(&open.program));
            }
        }
        let input = match input {
            Input::Archive(files) => ProgramInput::Archive { files: files.to_vec() },
            Input::Abc(abc) => abc.program_input(),
        };
        let params = ProgramOpenParams::new(input).mappings(mappings.map(|m| to_protocol(m)));
        // Opened outside the lock: a slow start must not hold up other backends.
        let program = Arc::new(backend.open_program(params, options)?);
        let mut programs = self.lock_programs();
        programs.tick += 1;
        let used = programs.tick;
        if let Some(open) = programs.open.iter().find(|p| found(p)) {
            // Another request opened it meanwhile; ours closes on drop.
            return Ok(Arc::clone(&open.program));
        }
        if programs.open.len() >= MAX_PROGRAMS
            && let Some(oldest) = programs.open.iter().enumerate().min_by_key(|(_, p)| p.used).map(|(i, _)| i)
        {
            programs.open.swap_remove(oldest);
        }
        let open = OpenProgram {
            backend: name.to_string(),
            files,
            sha256: sha256.map(String::from),
            mappings: hash,
            program: Arc::clone(&program),
            used,
        };
        programs.open.push(open);
        Ok(program)
    }

    fn answer(
        &self,
        name: &str,
        answer: &Answer,
        text: &str,
        attempts: Vec<Attempt>,
        request: &Request<'_>,
        context: &Context<'_>,
    ) -> Result<Decompiled, DecompileError> {
        let status = match answer.unit.outcome {
            UnitOutcome::Partial { .. } => Status::Partial,
            _ => Status::Ok,
        };
        // The class whose source the text is: the outer class, when the
        // requested one is nested and folded into it.
        let unit_class = Some(answer.unit.class.as_str()).filter(|class| *class != context.unit && answer.unit.covers(context.unit));
        let source_class = unit_class.unwrap_or(context.unit);
        let mappings = context.mappings.filter(|_| answer.naming == Naming::Unified);
        let renamed = |class: &str| mappings.and_then(|mappings| mappings.classes().get(class)).cloned();
        // `--method` on a nested class looks in its declaration, when the outer source has one.
        let nested_name = renamed(context.unit).unwrap_or_else(|| context.unit.to_string());
        let scope = unit_class.and_then(|_| source::nested_block(text, &nested_name)).unwrap_or(text);
        let text = match request.method {
            Some(method) => source::pick_methods(scope, method, context.unit).ok_or_else(|| DecompileError::NoMethod {
                class: context.unit.to_string(),
                method: method.to_string(),
                language: "decompiled source",
                hint: String::new(),
            })?,
            None => text.to_string(),
        };
        // The file is named after the class as the source names it: the
        // mapping's name, unless the backend's own path says it kept the
        // DEX's (a rename it had to drop, §6.2). Either way asc builds the
        // path itself (§11).
        let extension = if context.language == Language::Kotlin { "kt" } else { "java" };
        let mapped = renamed(source_class);
        let unit_path = match &answer.unit.outcome {
            UnitOutcome::Ok { path, .. } | UnitOutcome::Partial { path, .. } => path.as_deref(),
            _ => None,
        };
        let kept_dex_name = unit_path.is_some_and(|path| Path::new(path) == source::output_path(source_class, extension));
        let shown = mapped.as_deref().filter(|_| !kept_dex_name).unwrap_or(source_class);
        let path =
            unit_path.and_then(|path| source::backend_path(path, extension)).unwrap_or_else(|| source::output_path(shown, extension));
        Ok(Decompiled {
            class: context.unit.to_string(),
            entry: None,
            folded_into: unit_class.map(String::from),
            backend: Some(name.to_string()),
            version: Some(answer.capabilities.backend.version.clone()),
            status,
            language: Some(context.language),
            text,
            failed_methods: outcome::failed(&answer.unit.methods),
            functions: Vec::new(),
            notes: Vec::new(),
            attempts,
            cached: answer.cached,
            naming: answer.naming,
            method: request.method.map(String::from),
            path,
        })
    }

    /// The class as smali, when no backend gave source.
    fn smali(
        &self,
        engine: &Engine,
        request: &Request<'_>,
        context: &Context<'_>,
        attempts: Vec<Attempt>,
        cancel: &AtomicBool,
    ) -> Result<Decompiled, DecompileError> {
        let source = engine.get_class_method_cancellable(context.unit, SmaliOptions::debug_info(false), None, cancel)?.source;
        let text = match request.method {
            Some(method) => {
                let parsed = ClassText::parse(&source);
                let picked = parsed.select(method);
                if picked.is_empty() {
                    return Err(DecompileError::NoMethod {
                        class: context.unit.to_string(),
                        method: method.to_string(),
                        language: "smali",
                        hint: format!("; its methods: {}", parsed.signatures(4 << 10)),
                    });
                }
                parsed.with_methods(&picked)
            }
            None => source,
        };
        Ok(Decompiled {
            class: context.unit.to_string(),
            entry: None,
            folded_into: None,
            backend: None,
            version: None,
            status: Status::Smali,
            language: None,
            text,
            failed_methods: Vec::new(),
            functions: Vec::new(),
            notes: Vec::new(),
            attempts,
            cached: false,
            naming: if context.mappings.is_some() { Naming::NotUnified } else { Naming::Dex },
            method: request.method.map(String::from),
            path: source::output_path(context.unit, "smali"),
        })
    }
}

impl Drop for Decompilers {
    fn drop(&mut self) {
        self.close();
    }
}

impl std::fmt::Debug for Decompilers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Decompilers").field("settings", &self.settings).finish_non_exhaustive()
    }
}

/// The §6.2 `mappings` object of `mappings`.
fn to_protocol(mappings: &NameMappings) -> Mappings {
    let mut out = Mappings::default();
    out.classes = mappings.classes().clone();
    out.fields = mappings.fields().clone();
    out.methods = mappings.methods().clone();
    out
}

/// The resident memory of process `pid` (`VmRSS`), 0 where the system does not say.
fn resident_bytes(pid: u32) -> usize {
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else { return 0 };
    status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .and_then(|value| value.trim().strip_suffix("kB"))
        .and_then(|kib| kib.trim().parse::<usize>().ok())
        .map_or(0, |kib| kib.saturating_mul(1024))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn languages_parse_by_name() {
        assert_eq!(parse_language("Java").unwrap(), Language::Java);
        assert_eq!(parse_language("kt").unwrap(), Language::Kotlin);
        assert_eq!(parse_language("JS").unwrap(), Language::JavaScript);
        assert_eq!(parse_language("javascript").unwrap(), Language::JavaScript);
        assert_eq!(parse_language("ArkTS").unwrap(), Language::ArkTs);
        assert_eq!(parse_language("ets").unwrap(), Language::ArkTs);
        assert_eq!(language_name(Language::ArkTs), "arkts");
        assert!(parse_language("smali").unwrap_err().to_string().contains("use java, kotlin, javascript or arkts"));
    }

    #[test]
    fn this_process_has_a_resident_size_where_proc_exists() {
        let bytes = resident_bytes(std::process::id());
        assert!(bytes > 0 || !Path::new("/proc/self/status").exists());
        assert_eq!(resident_bytes(u32::MAX), 0);
    }
}
