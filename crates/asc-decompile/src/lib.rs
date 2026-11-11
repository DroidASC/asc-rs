//! Client side of asc's decompiler backends (`docs/decompile-backends.md` §5, §6, §10).
//!
//! A [`Backend`] owns a pool of backend processes started from a [`BackendSpec`]
//! and talks to them with the protocol in [`asc_decompile_protocol`]. It starts
//! processes on demand, restarts them with backoff after crashes, disables the
//! backend after repeated failed starts, and shuts idle ones down. A [`Program`]
//! is a program session that is transparently re-opened on whichever process
//! serves the next request.
//!
//! # Threading
//!
//! Everything is blocking and runs on std threads: each process has a stdout
//! reader and a stderr drain thread, the pool has an idle reaper, and callers
//! block on their own request. asc has no async runtime, a pool has at most a
//! handful of processes, and a request is a blocking round trip either way, so
//! a runtime would add a dependency without removing any waiting.
//!
//! ```no_run
//! use asc_decompile::{Backend, BackendSpec, CallOptions, DecompileRequest};
//! use asc_decompile::protocol::methods::{ProgramInput, ProgramOpenParams};
//!
//! let mut spec = BackendSpec::new("dexdec");
//! spec.args = vec!["serve".into(), "--stdio".into()];
//! let backend = Backend::new("dexdec", spec);
//! let options = CallOptions::default();
//! let input = ProgramInput::Archive { files: vec!["app.apk".into()] };
//! let program = backend.open_program(ProgramOpenParams::new(input), &options)?;
//! let result = program.decompile(&DecompileRequest::java(["Lcom/example/Main;"]), &options)?;
//! println!("{}", result.units[0].text().unwrap_or("<failed>"));
//! # Ok::<(), asc_decompile::Error>(())
//! ```

mod error;
mod pool;
mod process;
mod program;
mod spec;
mod stderr;

use std::sync::Arc;

pub use asc_decompile_protocol as protocol;
use asc_decompile_protocol::methods::{Implementation, InitializeResult, ProgramOpenParams};

pub use error::Error;
pub use program::{DecompileRequest, Program};
pub use spec::{BackendSpec, CallOptions, CancelToken, Lifecycle, Priority, ProgressSink};

use pool::Inner;

/// One configured backend and its process pool.
///
/// Dropping it runs the shutdown sequence on every process; [`Program`]s that
/// outlive it fail with [`Error::Closed`].
pub struct Backend {
    inner: Arc<Inner>,
}

impl Backend {
    /// Creates the pool; no process starts until the first request.
    pub fn new(name: impl Into<String>, spec: BackendSpec) -> Self {
        let client = Implementation::new("asc", env!("CARGO_PKG_VERSION"));
        Self::with_client(name, spec, client)
    }

    /// Like [`new`](Self::new), with the `client` reported in `initialize`.
    pub fn with_client(name: impl Into<String>, spec: BackendSpec, client: Implementation) -> Self {
        Self { inner: Inner::new(name.into(), spec, client) }
    }

    /// The backend's configured name, as used by `--decompiler`.
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    /// How the backend's processes are started and managed.
    pub fn spec(&self) -> &BackendSpec {
        &self.inner.spec
    }

    /// The backend's capabilities, starting a process if none has run yet.
    ///
    /// asc needs them before choosing the input kind (`archive` or `slice`).
    ///
    /// # Errors
    ///
    /// Startup failures, or [`Error::Disabled`] / [`Error::Unavailable`] while restarting is off.
    pub fn capabilities(&self, options: &CallOptions) -> Result<Arc<InitializeResult>, Error> {
        if let Some(capabilities) = self.inner.capabilities() {
            return Ok(capabilities);
        }
        let lease = self.inner.acquire(options.priority, options.cancel.as_ref())?;
        Ok(Arc::clone(lease.process.capabilities()))
    }

    /// Capabilities reported by the latest successful `initialize`, without starting anything.
    pub fn last_capabilities(&self) -> Option<Arc<InitializeResult>> {
        self.inner.capabilities()
    }

    /// Why the backend is disabled for the rest of the session, if it is.
    pub fn disabled_reason(&self) -> Option<String> {
        self.inner.disabled_reason()
    }

    /// The stderr ring buffer of the most recently started process (`asc decompile --debug`).
    pub fn stderr(&self) -> String {
        self.inner.stderr()
    }

    /// Processes currently able to take requests.
    pub fn running_processes(&self) -> usize {
        self.inner.running_processes()
    }

    /// Opens a program session (§6.2).
    ///
    /// # Errors
    ///
    /// Queueing and startup failures, or the backend's JSON-RPC error, such as
    /// `-33002` for an input kind it does not accept.
    pub fn open_program(&self, params: ProgramOpenParams, options: &CallOptions) -> Result<Program, Error> {
        Program::open(Arc::clone(&self.inner), params, options)
    }

    /// Shuts every process down; the same as dropping the backend.
    pub fn shutdown(self) {}
}

impl Drop for Backend {
    fn drop(&mut self) {
        self.inner.close();
    }
}

impl std::fmt::Debug for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Backend").field("name", &self.inner.name).field("spec", &self.inner.spec).finish_non_exhaustive()
    }
}
