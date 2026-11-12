//! How to run a backend: what asc's `[decompilers.<name>]` table turns into.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::num::{NonZeroU32, NonZeroUsize};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use asc_decompile_protocol::methods::ProgressParams;
use serde_json::{Map, Value};

/// Launch and lifecycle settings of one backend (§4). Defaults follow the document.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BackendSpec {
    /// Executable; looked up on `PATH` when it has no `/`.
    pub command: PathBuf,
    /// Arguments passed to `command`.
    pub args: Vec<OsString>,
    /// Added to the inherited environment.
    pub env: BTreeMap<OsString, OsString>,
    /// Working directory, created when missing; `None` inherits asc's.
    pub cwd: Option<PathBuf>,
    /// Number of processes in the pool.
    pub instances: NonZeroUsize,
    /// Caps the `maxConcurrency` a process declares; `None` takes the declaration as it is.
    pub max_concurrency: Option<NonZeroU32>,
    /// A process idle this long after its last request is shut down.
    pub idle: Duration,
    /// Deadline of one request, queueing excluded.
    pub timeout: Duration,
    /// Deadline of the `initialize` response.
    pub startup_timeout: Duration,
    /// Passed through as `initialize`'s `options`.
    pub options: Map<String, Value>,
    /// Grace periods and restart policy.
    pub lifecycle: Lifecycle,
}

impl BackendSpec {
    /// The spec with [`args`](#structfield.args) set.
    #[must_use]
    pub fn args(self, args: Vec<OsString>) -> Self {
        BackendSpec { args, ..self }
    }

    /// The spec with [`env`](#structfield.env) set.
    #[must_use]
    pub fn env(self, env: BTreeMap<OsString, OsString>) -> Self {
        BackendSpec { env, ..self }
    }

    /// The spec with [`cwd`](#structfield.cwd) set.
    #[must_use]
    pub fn cwd(self, cwd: Option<PathBuf>) -> Self {
        BackendSpec { cwd, ..self }
    }

    /// The spec with [`instances`](#structfield.instances) set.
    #[must_use]
    pub fn instances(self, instances: NonZeroUsize) -> Self {
        BackendSpec { instances, ..self }
    }

    /// The spec with [`max_concurrency`](#structfield.max_concurrency) set.
    #[must_use]
    pub fn max_concurrency(self, max_concurrency: Option<NonZeroU32>) -> Self {
        BackendSpec { max_concurrency, ..self }
    }

    /// The spec with [`idle`](#structfield.idle) set.
    #[must_use]
    pub fn idle(self, idle: Duration) -> Self {
        BackendSpec { idle, ..self }
    }

    /// The spec with [`timeout`](#structfield.timeout) set.
    #[must_use]
    pub fn timeout(self, timeout: Duration) -> Self {
        BackendSpec { timeout, ..self }
    }

    /// The spec with [`startup_timeout`](#structfield.startup_timeout) set.
    #[must_use]
    pub fn startup_timeout(self, startup_timeout: Duration) -> Self {
        BackendSpec { startup_timeout, ..self }
    }

    /// The spec with [`options`](#structfield.options) set.
    #[must_use]
    pub fn options(self, options: Map<String, Value>) -> Self {
        BackendSpec { options, ..self }
    }

    /// The spec with [`lifecycle`](#structfield.lifecycle) set.
    #[must_use]
    pub fn lifecycle(self, lifecycle: Lifecycle) -> Self {
        BackendSpec { lifecycle, ..self }
    }
}

impl BackendSpec {
    /// Runs `command` without arguments: one instance taking as many requests
    /// as it declares, 10 min idle, 60 s request timeout, 30 s startup
    /// timeout, no options.
    pub fn new(command: impl Into<PathBuf>) -> Self {
        Self {
            command: command.into(),
            args: Vec::new(),
            env: BTreeMap::new(),
            cwd: None,
            instances: NonZeroUsize::MIN,
            max_concurrency: None,
            idle: Duration::from_secs(10 * 60),
            timeout: Duration::from_secs(60),
            startup_timeout: Duration::from_secs(30),
            options: Map::new(),
            lifecycle: Lifecycle::default(),
        }
    }
}

/// Grace periods and restart policy fixed by §5–§6.4; only tests have reason to change them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Lifecycle {
    /// After a timeout or cancellation, how long a backend may take to answer
    /// `notifications/cancelled` before it is killed.
    pub cancel_grace: Duration,
    /// Each step of the shutdown sequence: `shutdown` response, exit after stdin
    /// is closed, exit after SIGTERM.
    pub shutdown_grace: Duration,
    /// First restart delay; doubled per consecutive failure.
    pub backoff_initial: Duration,
    /// Upper bound of the restart delay.
    pub backoff_max: Duration,
    /// Consecutive failed startups after which the backend is disabled.
    pub max_startup_failures: u32,
    /// Size of each process's stderr ring buffer.
    pub stderr_capacity: usize,
}

impl Lifecycle {
    /// The lifecycle with [`cancel_grace`](#structfield.cancel_grace) set.
    #[must_use]
    pub fn cancel_grace(self, cancel_grace: Duration) -> Self {
        Lifecycle { cancel_grace, ..self }
    }

    /// The lifecycle with [`shutdown_grace`](#structfield.shutdown_grace) set.
    #[must_use]
    pub fn shutdown_grace(self, shutdown_grace: Duration) -> Self {
        Lifecycle { shutdown_grace, ..self }
    }

    /// The lifecycle with [`backoff_initial`](#structfield.backoff_initial) set.
    #[must_use]
    pub fn backoff_initial(self, backoff_initial: Duration) -> Self {
        Lifecycle { backoff_initial, ..self }
    }

    /// The lifecycle with [`backoff_max`](#structfield.backoff_max) set.
    #[must_use]
    pub fn backoff_max(self, backoff_max: Duration) -> Self {
        Lifecycle { backoff_max, ..self }
    }

    /// The lifecycle with [`max_startup_failures`](#structfield.max_startup_failures) set.
    #[must_use]
    pub fn max_startup_failures(self, max_startup_failures: u32) -> Self {
        Lifecycle { max_startup_failures, ..self }
    }

    /// The lifecycle with [`stderr_capacity`](#structfield.stderr_capacity) set.
    #[must_use]
    pub fn stderr_capacity(self, stderr_capacity: usize) -> Self {
        Lifecycle { stderr_capacity, ..self }
    }
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self {
            cancel_grace: Duration::from_secs(5),
            shutdown_grace: Duration::from_secs(2),
            backoff_initial: Duration::from_secs(1),
            backoff_max: Duration::from_secs(60),
            max_startup_failures: 5,
            stderr_capacity: 64 << 10,
        }
    }
}

impl Lifecycle {
    /// Delay before the next start after `strikes` consecutive failures (`strikes >= 1`).
    pub(crate) fn backoff(&self, strikes: u32) -> Duration {
        let doublings = strikes.saturating_sub(1).min(31);
        self.backoff_initial.saturating_mul(1 << doublings).min(self.backoff_max)
    }
}

/// Queue lane of a request (§10): interactive requests overtake queued batch ones.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Priority {
    /// A user or MCP client is waiting on it.
    #[default]
    Interactive,
    /// Bulk work that can wait.
    Batch,
}

/// Lets another thread abort a queued or running request (Ctrl-C, MCP client disconnect).
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// A token not yet cancelled; clones share its state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cancels every request holding this token or a clone of it; cannot be undone.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Whether [`cancel`](Self::cancel) has been called on this token or a clone.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Receives `notifications/progress` of one request, on the process's reader thread.
pub type ProgressSink = Arc<dyn Fn(&ProgressParams) + Send + Sync>;

/// Per-call settings.
#[derive(Clone, Default)]
#[non_exhaustive]
pub struct CallOptions {
    /// Queue lane while waiting for a process.
    pub priority: Priority,
    /// Aborts the call while queued or running; the call then fails with `Error::Cancelled`.
    pub cancel: Option<CancelToken>,
    /// Receives the backend's progress for the call; asks the backend for progress when set.
    pub progress: Option<ProgressSink>,
    /// Overrides [`BackendSpec::timeout`].
    pub timeout: Option<Duration>,
}

impl CallOptions {
    /// The options with [`priority`](#structfield.priority) set.
    #[must_use]
    pub fn priority(self, priority: Priority) -> Self {
        CallOptions { priority, ..self }
    }

    /// The options with [`cancel`](#structfield.cancel) set.
    #[must_use]
    pub fn cancel(self, cancel: Option<CancelToken>) -> Self {
        CallOptions { cancel, ..self }
    }

    /// The options with [`progress`](#structfield.progress) set.
    #[must_use]
    pub fn progress(self, progress: Option<ProgressSink>) -> Self {
        CallOptions { progress, ..self }
    }

    /// The options with [`timeout`](#structfield.timeout) set.
    #[must_use]
    pub fn timeout(self, timeout: Option<Duration>) -> Self {
        CallOptions { timeout, ..self }
    }
}

impl std::fmt::Debug for CallOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallOptions")
            .field("priority", &self.priority)
            .field("cancel", &self.cancel)
            .field("progress", &self.progress.as_ref().map(|_| "<sink>"))
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_up_to_the_cap() {
        let lifecycle = Lifecycle::default();
        let delays: Vec<u64> = (1..=8).map(|n| lifecycle.backoff(n).as_secs()).collect();
        assert_eq!(delays, [1, 2, 4, 8, 16, 32, 60, 60]);
        assert_eq!(lifecycle.backoff(u32::MAX), Duration::from_secs(60));
    }
}
