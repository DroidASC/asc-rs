//! Program sessions that survive backend restarts.

use std::sync::{Arc, Mutex, Weak};

use asc_decompile_protocol::ErrorCode;
use asc_decompile_protocol::methods::{
    DecompileClasses, DecompileClassesParams, DecompileClassesResult, Language, ProgramClose, ProgramCloseParams, ProgramId, ProgramOpen,
    ProgramOpenParams,
};

use crate::error::Error;
use crate::pool::{Inner, Lease};
use crate::process::{CallControl, Process};
use crate::spec::CallOptions;

/// What to decompile from an open [`Program`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecompileRequest {
    /// Type descriptors, e.g. `Lbin/mt/json/JSONObject;`.
    pub classes: Vec<String>,
    pub language: Language,
    /// Fold inner and anonymous classes into their outer class.
    pub nested: bool,
}

impl DecompileRequest {
    /// Java source of `classes`, nested classes folded in: what `asc decompile` asks for.
    pub fn java(classes: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self { classes: classes.into_iter().map(Into::into).collect(), language: Language::Java, nested: true }
    }
}

/// A program opened on a backend (§6.2).
///
/// Sessions belong to processes, so the program is opened lazily on every process
/// that serves it, and again on the replacement after a crash, idle shutdown or
/// restart; callers never see a stale `programId`. Dropping the program closes its
/// sessions on a best-effort basis; [`close`](Self::close) reports failures.
pub struct Program {
    inner: Arc<Inner>,
    params: ProgramOpenParams,
    sessions: Mutex<Vec<Session>>,
}

struct Session {
    process: Weak<Process>,
    id: ProgramId,
}

impl Program {
    /// Opens `params` on one process right away, so a bad input fails here.
    pub(crate) fn open(inner: Arc<Inner>, params: ProgramOpenParams, options: &CallOptions) -> Result<Self, Error> {
        let lease = inner.acquire(options.priority, options.cancel.as_ref())?;
        let program = Self { inner, params, sessions: Mutex::new(Vec::new()) };
        program.session_on(&lease, options)?;
        Ok(program)
    }

    pub fn params(&self) -> &ProgramOpenParams {
        &self.params
    }

    /// Decompiles classes, queueing for a process and (re)opening the program on it.
    ///
    /// # Errors
    ///
    /// Queueing and transport failures ([`Error::is_backend_failure`]), a JSON-RPC
    /// error from the backend, or [`Error::Cancelled`]. Classes that fail to
    /// decompile are not errors; they come back with `status = failed`.
    pub fn decompile(&self, request: &DecompileRequest, options: &CallOptions) -> Result<DecompileClassesResult, Error> {
        let lease = self.inner.acquire(options.priority, options.cancel.as_ref())?;
        let mut reopened = false;
        loop {
            let program_id = self.session_on(&lease, options)?;
            let id = lease.process.next_id();
            let params = DecompileClassesParams {
                program_id,
                classes: request.classes.clone(),
                language: request.language,
                nested: request.nested,
                progress_token: options.progress.is_some().then(|| id.clone().into()),
            };
            let result = lease.process.call_as::<DecompileClasses>(id, &params, &lease.control(options));
            lease.observe(&result);
            match result {
                // The backend lost the session on its own; open it again once.
                Err(Error::Rpc(err)) if err.code == ErrorCode::PROGRAM_NOT_FOUND && !reopened => {
                    self.forget(&lease.process);
                    reopened = true;
                }
                result => return result,
            }
        }
    }

    /// Closes the program on every process that still has it.
    ///
    /// # Errors
    ///
    /// The first failure; the other sessions are closed regardless.
    pub fn close(mut self) -> Result<(), Error> {
        self.close_sessions()
    }

    fn close_sessions(&mut self) -> Result<(), Error> {
        let sessions = std::mem::take(self.sessions.get_mut().expect("program sessions mutex poisoned"));
        let control = CallControl { timeout: self.inner.spec.timeout, cancel: None, progress: None };
        let mut first_error = None;
        for session in sessions {
            let Some(process) = session.process.upgrade().filter(|process| process.is_usable()) else { continue };
            // `program/close` does not count against `maxConcurrency` (§6.1 counts decompile/classes only).
            if let Err(err) = process.call::<ProgramClose>(&ProgramCloseParams { program_id: session.id }, &control) {
                first_error.get_or_insert(err);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// The session id on the leased process, opening one if it has none.
    fn session_on(&self, lease: &Lease, options: &CallOptions) -> Result<ProgramId, Error> {
        {
            let mut sessions = self.sessions.lock().expect("program sessions mutex poisoned");
            sessions.retain(|session| session.process.upgrade().is_some_and(|process| process.is_usable()));
            if let Some(session) = sessions.iter().find(|session| session.process.as_ptr() == Arc::as_ptr(&lease.process)) {
                return Ok(session.id.clone());
            }
        }
        let opened = lease.call::<ProgramOpen>(&self.params, &CallOptions { progress: None, ..options.clone() })?;
        let session = Session { process: Arc::downgrade(&lease.process), id: opened.program_id.clone() };
        self.sessions.lock().expect("program sessions mutex poisoned").push(session);
        Ok(opened.program_id)
    }

    fn forget(&self, process: &Arc<Process>) {
        self.sessions.lock().expect("program sessions mutex poisoned").retain(|session| session.process.as_ptr() != Arc::as_ptr(process));
    }
}

impl Drop for Program {
    fn drop(&mut self) {
        // Errors were reported by `close` if the caller cared.
        let _ = self.close_sessions();
    }
}

impl std::fmt::Debug for Program {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Program").field("backend", &self.inner.name).field("params", &self.params).finish_non_exhaustive()
    }
}
