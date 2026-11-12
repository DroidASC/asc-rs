//! One backend process: spawn, handshake, request correlation, shutdown.
//!
//! Each process owns two threads: a reader that parses stdout and routes
//! responses to the waiting callers, and a drain that copies stderr into a ring
//! buffer. Callers block on a per-request channel. When the reader stops (end
//! of stream or protocol violation), it reaps the process and fails every
//! request still in flight with the exit status and the stderr tail.

use std::collections::HashMap;
use std::io::BufReader;
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use asc_decompile_protocol::methods::{
    Cancelled, CancelledParams, Empty, Implementation, Initialize, InitializeParams, InitializeResult, Initialized, Progress,
    ProgressParams, ProgressToken, Shutdown,
};
use asc_decompile_protocol::{
    ErrorCode, ErrorObject, FrameError, FrameReader, FrameWriter, Message, Method, Notification, NotificationMethod, PROTOCOL_VERSION,
    Request, RequestId, Response,
};
use serde_json::Value;

use crate::error::Error;
use crate::spec::{BackendSpec, CancelToken, Lifecycle, ProgressSink};
use crate::stderr::{self, SharedRing, StderrRing};

/// How often blocking waits look at a [`CancelToken`] or a child's exit.
const POLL: Duration = Duration::from_millis(10);

type Reply = Result<Value, Error>;

/// Per-call limits handed down from the pool.
pub(crate) struct CallControl<'a> {
    pub(crate) timeout: Duration,
    pub(crate) cancel: Option<&'a CancelToken>,
    pub(crate) progress: Option<ProgressSink>,
}

struct Pending {
    reply: Sender<Reply>,
    progress: Option<ProgressSink>,
}

#[derive(Default)]
struct Calls {
    pending: HashMap<RequestId, Pending>,
    /// Set once by the reader thread when the process is gone; later calls fail with it.
    exit: Option<ExitInfo>,
}

#[derive(Clone)]
struct ExitInfo {
    reason: String,
    stderr_tail: String,
}

impl ExitInfo {
    fn to_error(&self) -> Error {
        Error::Exited { reason: self.reason.clone(), stderr_tail: self.stderr_tail.clone() }
    }
}

pub(crate) struct Process {
    /// Unique within the pool; program sessions are keyed by it.
    id: u64,
    pid: u32,
    child: Mutex<Child>,
    /// `None` once stdin is closed.
    stdin: Mutex<Option<FrameWriter<ChildStdin>>>,
    calls: Mutex<Calls>,
    next_request: AtomicI64,
    /// Set when the process must not take new work: killed, shutting down or dead.
    retired: AtomicBool,
    /// Set by an orderly shutdown so the reader thread leaves escalation to it.
    shutting_down: AtomicBool,
    /// Why asc killed the process, reported instead of the bare signal.
    kill_reason: Mutex<Option<String>>,
    stderr: SharedRing,
    stderr_closed: Mutex<Receiver<()>>,
    capabilities: OnceLock<Arc<InitializeResult>>,
    lifecycle: Lifecycle,
}

impl Process {
    /// Spawns the backend and completes the `initialize` handshake.
    pub(crate) fn start(id: u64, spec: &BackendSpec, client: &Implementation) -> Result<Arc<Self>, Error> {
        let command_name = spec.command.display().to_string();
        let spawn_error = |source| Error::Spawn { command: command_name.clone(), source };
        let mut command = Command::new(&spec.command);
        command.args(&spec.args).envs(&spec.env).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        if let Some(cwd) = &spec.cwd {
            std::fs::create_dir_all(cwd).map_err(spawn_error)?;
            command.current_dir(cwd);
        }
        let mut child = command.spawn().map_err(spawn_error)?;
        let stdin = child.stdin.take().expect("stdin is piped");
        let stdout = child.stdout.take().expect("stdout is piped");
        let stderr_pipe = child.stderr.take().expect("stderr is piped");

        let ring: SharedRing = Arc::new(Mutex::new(StderrRing::new(spec.lifecycle.stderr_capacity)));
        let (stderr_done, stderr_closed) = mpsc::channel();
        let drain_ring = Arc::clone(&ring);
        let process = Arc::new(Self {
            id,
            pid: child.id(),
            child: Mutex::new(child),
            stdin: Mutex::new(Some(FrameWriter::new(stdin))),
            calls: Mutex::new(Calls::default()),
            next_request: AtomicI64::new(1),
            retired: AtomicBool::new(false),
            shutting_down: AtomicBool::new(false),
            kill_reason: Mutex::new(None),
            stderr: ring,
            stderr_closed: Mutex::new(stderr_closed),
            capabilities: OnceLock::new(),
            lifecycle: spec.lifecycle.clone(),
        });
        let spawned = thread::Builder::new().name(format!("decompile-stderr-{id}")).spawn(move || {
            stderr::drain(stderr_pipe, &drain_ring);
            // The receiver may be gone already; nobody needs to know then.
            let _ = stderr_done.send(());
        });
        let reader = Arc::clone(&process);
        let spawned =
            spawned.and_then(|_| thread::Builder::new().name(format!("decompile-reader-{id}")).spawn(move || reader.read_loop(stdout)));
        if let Err(source) = spawned {
            process.kill("cannot start helper threads");
            return Err(spawn_error(source));
        }

        match process.handshake(spec, client) {
            Ok(capabilities) => {
                process.capabilities.set(Arc::new(capabilities)).expect("capabilities are set once, after the handshake");
                Ok(process)
            }
            Err(err) => {
                process.kill("startup failed");
                Err(err)
            }
        }
    }

    fn handshake(&self, spec: &BackendSpec, client: &Implementation) -> Result<InitializeResult, Error> {
        let params = InitializeParams::new(PROTOCOL_VERSION, client.clone()).options(spec.options.clone());
        let reply = self.send_request::<Initialize>(self.next_id(), &params, None)?;
        let startup_error = |reason: String| Error::Startup { reason, stderr_tail: self.stderr_tail() };
        let result = match reply.recv_timeout(spec.startup_timeout) {
            Ok(reply) => reply,
            Err(RecvTimeoutError::Timeout) => {
                return Err(startup_error(format!("no initialize response within {:?}", spec.startup_timeout)));
            }
            Err(RecvTimeoutError::Disconnected) => Err(self.exit_error()),
        };
        let result: InitializeResult = match result {
            Ok(value) => serde_json::from_value(value).map_err(|err| startup_error(format!("malformed initialize result: {err}")))?,
            Err(Error::Exited { reason, stderr_tail }) => return Err(Error::Startup { reason: format!("exited: {reason}"), stderr_tail }),
            Err(err) => return Err(startup_error(format!("initialize failed: {err}"))),
        };
        if result.protocol_version != PROTOCOL_VERSION {
            return Err(Error::ProtocolVersion { got: result.protocol_version });
        }
        self.notify::<Initialized>(&Empty {})?;
        Ok(result)
    }

    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    /// The operating system's id of the process.
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    pub(crate) fn capabilities(&self) -> &Arc<InitializeResult> {
        self.capabilities.get().expect("a started process has completed its handshake")
    }

    /// Whether the process may take new requests.
    pub(crate) fn is_usable(&self) -> bool {
        !self.retired.load(Ordering::Acquire)
    }

    pub(crate) fn stderr_ring(&self) -> SharedRing {
        Arc::clone(&self.stderr)
    }

    fn stderr_tail(&self) -> String {
        self.stderr.lock().expect("stderr ring mutex poisoned").error_tail()
    }

    /// A fresh request id; callers that need it inside the params (as a progress
    /// token) take one and pass it to [`call_as`](Self::call_as).
    pub(crate) fn next_id(&self) -> RequestId {
        RequestId::Number(self.next_request.fetch_add(1, Ordering::Relaxed))
    }

    /// Sends a typed request and waits for its result, honouring the timeout and
    /// cancellation protocol of §6.4.
    pub(crate) fn call<M: Method>(&self, params: &M::Params, control: &CallControl<'_>) -> Result<M::Result, Error> {
        self.call_as::<M>(self.next_id(), params, control)
    }

    pub(crate) fn call_as<M: Method>(&self, id: RequestId, params: &M::Params, control: &CallControl<'_>) -> Result<M::Result, Error> {
        let reply = self.send_request::<M>(id.clone(), params, control.progress.clone())?;
        let deadline = Instant::now() + control.timeout;
        let abort = match wait(&reply, deadline, control.cancel) {
            Waited::Reply(reply) => return decode::<M>(reply),
            Waited::Disconnected => return Err(self.exit_error()),
            Waited::TimedOut => Error::Timeout(control.timeout),
            Waited::Cancelled => Error::Cancelled,
        };
        let reason = match abort {
            Error::Timeout(_) => "timed out",
            _ => "cancelled by the client",
        };
        // Best effort: a dead process fails the reply below anyway.
        let _ = self.notify::<Cancelled>(&CancelledParams::new(id.clone()).reason(Some(reason.to_owned())));
        match reply.recv_timeout(self.lifecycle.cancel_grace) {
            // Finishing anyway is allowed; the work is not wasted.
            Ok(Ok(value)) => decode::<M>(Ok(value)),
            Ok(Err(Error::Rpc(err))) if err.code == ErrorCode::REQUEST_CANCELLED => Err(abort),
            Ok(Err(err)) => Err(err),
            Err(RecvTimeoutError::Timeout) => {
                self.forget(&id);
                self.kill(&format!("request {id} {reason} and ignored cancellation for {:?}", self.lifecycle.cancel_grace));
                self.wait_exit(self.lifecycle.shutdown_grace);
                Err(abort)
            }
            Err(RecvTimeoutError::Disconnected) => Err(self.exit_error()),
        }
    }

    /// Registers the call, then writes it. A write failure means the process is
    /// dying; the caller then gets the reader's exit error through the channel.
    fn send_request<M: Method>(&self, id: RequestId, params: &M::Params, progress: Option<ProgressSink>) -> Result<Receiver<Reply>, Error> {
        let request = Request::new::<M>(id.clone(), params).map_err(Error::Encode)?;
        let (sender, receiver) = mpsc::channel();
        {
            let mut calls = self.calls.lock().expect("calls mutex poisoned");
            if let Some(exit) = &calls.exit {
                return Err(exit.to_error());
            }
            calls.pending.insert(id.clone(), Pending { reply: sender, progress });
        }
        if let Err(err) = self.write(&request.into()) {
            match err {
                WriteError::Encode(err) => {
                    self.forget(&id);
                    return Err(err);
                }
                WriteError::Broken(reason) => self.kill(&reason),
            }
        }
        Ok(receiver)
    }

    /// The error of a process whose reader has stopped.
    fn exit_error(&self) -> Error {
        match &self.calls.lock().expect("calls mutex poisoned").exit {
            Some(exit) => exit.to_error(),
            None => Error::Exited { reason: "reader thread stopped".to_owned(), stderr_tail: self.stderr_tail() },
        }
    }

    pub(crate) fn notify<N: NotificationMethod>(&self, params: &N::Params) -> Result<(), Error> {
        let notification = Notification::new::<N>(params).map_err(Error::Encode)?;
        match self.write(&notification.into()) {
            Ok(()) => Ok(()),
            Err(WriteError::Encode(err)) => Err(err),
            Err(WriteError::Broken(reason)) => {
                self.kill(&reason);
                Err(Error::Exited { reason, stderr_tail: self.stderr_tail() })
            }
        }
    }

    fn write(&self, message: &Message) -> Result<(), WriteError> {
        let mut stdin = self.stdin.lock().expect("stdin mutex poisoned");
        let Some(writer) = stdin.as_mut() else {
            return Err(WriteError::Broken("stdin already closed".to_owned()));
        };
        writer.write_message(message).map_err(|err| match err {
            FrameError::Json(err) => WriteError::Encode(Error::Encode(err)),
            FrameError::TooLarge { limit } => {
                WriteError::Encode(Error::Encode(serde::ser::Error::custom(format_args!("request exceeds {limit} bytes"))))
            }
            err => WriteError::Broken(format!("cannot write to stdin: {err}")),
        })
    }

    fn forget(&self, id: &RequestId) {
        self.calls.lock().expect("calls mutex poisoned").pending.remove(id);
    }

    /// Kills the process; the reader thread then reports `reason` to every pending call.
    pub(crate) fn kill(&self, reason: &str) {
        self.retired.store(true, Ordering::Release);
        self.kill_reason.lock().expect("kill reason mutex poisoned").get_or_insert_with(|| reason.to_owned());
        // Fails only when the process is already reaped, which is the goal.
        let _ = self.child.lock().expect("child mutex poisoned").kill();
    }

    /// The orderly shutdown of §5: `shutdown`, close stdin, SIGTERM, SIGKILL, one
    /// grace period apart.
    pub(crate) fn shutdown(&self) {
        self.retired.store(true, Ordering::Release);
        self.shutting_down.store(true, Ordering::Release);
        let grace = self.lifecycle.shutdown_grace;
        if let Ok(reply) = self.send_request::<Shutdown>(self.next_id(), &Empty {}, None) {
            // Any outcome moves on to the next step.
            let _ = reply.recv_timeout(grace);
        }
        self.stdin.lock().expect("stdin mutex poisoned").take();
        if self.wait_exit(grace).is_some() {
            return;
        }
        if self.terminate() && self.wait_exit(grace).is_some() {
            return;
        }
        self.kill("did not exit after shutdown");
        // SIGKILL cannot be ignored; waiting reaps the process so it is really gone on return.
        self.wait_exit(grace);
    }

    /// Sends SIGTERM; `false` where there is no such thing.
    #[cfg(unix)]
    fn terminate(&self) -> bool {
        let Ok(pid) = libc::pid_t::try_from(self.pid) else { return false };
        let mut child = self.child.lock().expect("child mutex poisoned");
        // Holding the child lock keeps the pid from being reaped (and reused) meanwhile.
        if let Ok(Some(_)) = child.try_wait() {
            return true;
        }
        // SAFETY: `kill` has no memory-safety preconditions; `pid` is our unreaped child.
        unsafe { libc::kill(pid, libc::SIGTERM) == 0 }
    }

    #[cfg(not(unix))]
    fn terminate(&self) -> bool {
        false
    }

    /// Polls for the exit status for up to `limit`.
    fn wait_exit(&self, limit: Duration) -> Option<ExitStatus> {
        let deadline = Instant::now() + limit;
        loop {
            if let Ok(Some(status)) = self.child.lock().expect("child mutex poisoned").try_wait() {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(POLL);
        }
    }

    fn read_loop(self: Arc<Self>, stdout: ChildStdout) {
        let mut reader = FrameReader::new(BufReader::new(stdout));
        let violation = loop {
            match reader.read_message() {
                Ok(Some(Message::Response(response))) => self.deliver(response),
                Ok(Some(Message::Notification(notification))) => self.on_notification(&notification),
                Ok(Some(Message::Request(request))) => {
                    let error = ErrorObject::new(ErrorCode::METHOD_NOT_FOUND, format!("asc serves no `{}`", request.method));
                    // A failed write shows up as end of stream next.
                    let _ = self.write(&Response::error(Some(request.id), error).into());
                }
                Ok(None) => break None,
                Err(err) => break Some(format!("protocol error on stdout: {err}")),
            }
        };
        drop(reader);
        self.retired.store(true, Ordering::Release);
        if let Some(violation) = &violation {
            self.kill(violation);
        }
        let status = self.reap();
        // Let the drain catch the last words; a grandchild holding stderr open must not stall us.
        let _ = self.stderr_closed.lock().expect("stderr signal mutex poisoned").recv_timeout(Duration::from_millis(500));
        let kill_reason = self.kill_reason.lock().expect("kill reason mutex poisoned").take();
        let reason = match kill_reason {
            Some(why) => format!("killed ({why}), {status}"),
            None => status,
        };
        let exit = ExitInfo { reason, stderr_tail: self.stderr_tail() };
        let pending = {
            let mut calls = self.calls.lock().expect("calls mutex poisoned");
            calls.exit = Some(exit.clone());
            std::mem::take(&mut calls.pending)
        };
        for (_, call) in pending {
            // The caller may have given up already.
            let _ = call.reply.send(Err(exit.to_error()));
        }
    }

    /// Waits for the exit after stdout closed. A process that closes stdout but
    /// lives on is killed after a grace period, unless an orderly shutdown is
    /// already escalating.
    fn reap(&self) -> String {
        loop {
            if let Some(status) = self.wait_exit(self.lifecycle.shutdown_grace) {
                return status.to_string();
            }
            if !self.shutting_down.load(Ordering::Acquire) {
                self.kill("closed stdout but kept running");
            }
        }
    }

    fn deliver(&self, response: Response) {
        let Some(id) = response.id else { return };
        let call = self.calls.lock().expect("calls mutex poisoned").pending.remove(&id);
        // Unknown ids are late answers to calls that already gave up.
        if let Some(call) = call {
            let _ = call.reply.send(response.outcome.map_err(Error::Rpc));
        }
    }

    fn on_notification(&self, notification: &Notification) {
        if notification.method != <Progress as NotificationMethod>::NAME {
            return;
        }
        let Ok(params) = notification.params::<ProgressParams>() else { return };
        let id = match &params.progress_token {
            ProgressToken::Number(id) => RequestId::Number(*id),
            ProgressToken::String(id) => RequestId::String(id.clone()),
        };
        let sink = self.calls.lock().expect("calls mutex poisoned").pending.get(&id).and_then(|call| call.progress.clone());
        if let Some(sink) = sink {
            sink(&params);
        }
    }
}

enum WriteError {
    /// asc's own fault; the process is fine.
    Encode(Error),
    Broken(String),
}

enum Waited {
    Reply(Reply),
    TimedOut,
    Cancelled,
    /// Only if the reader thread died without answering, i.e. it panicked.
    Disconnected,
}

fn wait(reply: &Receiver<Reply>, deadline: Instant, cancel: Option<&CancelToken>) -> Waited {
    loop {
        if cancel.is_some_and(CancelToken::is_cancelled) {
            return Waited::Cancelled;
        }
        let now = Instant::now();
        if now >= deadline {
            return Waited::TimedOut;
        }
        let slice = if cancel.is_some() { (deadline - now).min(POLL * 5) } else { deadline - now };
        match reply.recv_timeout(slice) {
            Ok(reply) => return Waited::Reply(reply),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Waited::Disconnected,
        }
    }
}

fn decode<M: Method>(reply: Reply) -> Result<M::Result, Error> {
    serde_json::from_value(reply?).map_err(Error::InvalidResult)
}
