//! How to run a backend: what asc's `[decompilers.<name>]` table turns into.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use asc_decompile_protocol::methods::ProgressParams;
use serde_json::{Map, Value};

/// Launch and lifecycle settings of one backend (§4). Defaults follow the document.
#[derive(Debug, Clone)]
pub struct BackendSpec {
    /// Executable; looked up on `PATH` when it has no `/`.
    pub command: PathBuf,
    pub args: Vec<OsString>,
    /// Added to the inherited environment.
    pub env: BTreeMap<OsString, OsString>,
    /// Working directory, created when missing; `None` inherits asc's.
    pub cwd: Option<PathBuf>,
    /// Number of processes in the pool.
    pub instances: NonZeroUsize,
    /// A process idle this long after its last request is shut down.
    pub idle: Duration,
    /// Deadline of one request, queueing excluded.
    pub timeout: Duration,
    /// Deadline of the `initialize` response.
    pub startup_timeout: Duration,
    /// Passed through as `initialize`'s `options`.
    pub options: Map<String, Value>,
    pub lifecycle: Lifecycle,
}

impl BackendSpec {
    pub fn new(command: impl Into<PathBuf>) -> Self {
        Self {
            command: command.into(),
            args: Vec::new(),
            env: BTreeMap::new(),
            cwd: None,
            instances: NonZeroUsize::MIN,
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
pub struct Lifecycle {
    /// After a timeout or cancellation, how long a backend may take to answer
    /// `notifications/cancelled` before it is killed.
    pub cancel_grace: Duration,
    /// Each step of the shutdown sequence: `shutdown` response, exit after stdin
    /// is closed, exit after SIGTERM.
    pub shutdown_grace: Duration,
    /// First restart delay; doubled per consecutive failure.
    pub backoff_initial: Duration,
    pub backoff_max: Duration,
    /// Consecutive failed startups after which the backend is disabled.
    pub max_startup_failures: u32,
    /// Size of each process's stderr ring buffer.
    pub stderr_capacity: usize,
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
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Receives `notifications/progress` of one request, on the process's reader thread.
pub type ProgressSink = Arc<dyn Fn(&ProgressParams) + Send + Sync>;

/// Per-call settings.
#[derive(Clone, Default)]
pub struct CallOptions {
    pub priority: Priority,
    pub cancel: Option<CancelToken>,
    pub progress: Option<ProgressSink>,
    /// Overrides [`BackendSpec::timeout`].
    pub timeout: Option<Duration>,
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
