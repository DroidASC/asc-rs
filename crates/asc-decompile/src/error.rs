use std::io;
use std::time::Duration;

use asc_decompile_protocol::{ErrorObject, PROTOCOL_VERSION};

/// Why a backend call failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The backend process could not be spawned.
    #[error("cannot start `{command}`: {source}")]
    Spawn {
        /// The command line as configured.
        command: String,
        /// The spawn failure.
        source: io::Error,
    },
    /// The process started but did not complete `initialize`.
    #[error("backend failed to start: {reason}{}", tail(stderr_tail))]
    Startup {
        /// What went wrong during the handshake.
        reason: String,
        /// The last lines the process wrote to stderr; empty when it wrote none.
        stderr_tail: String,
    },
    /// The backend answered `initialize` with a protocol version asc does not speak.
    #[error("backend speaks protocol version {got}, asc supports {PROTOCOL_VERSION}")]
    ProtocolVersion {
        /// The version the backend reported.
        got: u32,
    },
    /// The process died (or was killed for breaking the protocol) with the request in flight.
    #[error("backend exited: {reason}{}", tail(stderr_tail))]
    Exited {
        /// The exit status, or why asc killed the process.
        reason: String,
        /// The last lines the process wrote to stderr; empty when it wrote none.
        stderr_tail: String,
    },
    /// The request ran longer than its timeout; the backend was asked to cancel it.
    #[error("request timed out after {0:?}")]
    Timeout(Duration),
    /// The caller cancelled the request.
    #[error("request cancelled")]
    Cancelled,
    /// The backend answered with a JSON-RPC error.
    #[error("backend error: {0}")]
    Rpc(#[from] ErrorObject),
    /// The backend's result does not match the method's result schema.
    #[error("backend returned a malformed result: {0}")]
    InvalidResult(serde_json::Error),
    /// The request parameters cannot be represented as JSON.
    #[error("cannot encode request: {0}")]
    Encode(serde_json::Error),
    /// Restarting is backing off after failed startups.
    #[error("backend unavailable for another {retry_in:?} after failing to start: {last_error}")]
    Unavailable {
        /// How long until the next start attempt is allowed.
        retry_in: Duration,
        /// The error of the last failed start.
        last_error: String,
    },
    /// Disabled for the rest of the session (§5).
    #[error("backend disabled: {reason}")]
    Disabled {
        /// Why the backend was disabled.
        reason: String,
    },
    /// The pool was shut down; no further requests are served.
    #[error("backend pool is shut down")]
    Closed,
    /// The request carries a per-request option the backend did not declare
    /// in `requestOptions`; the request was not sent.
    #[error("backend does not take the request option `{option}`")]
    UnsupportedOption {
        /// The option's name.
        option: String,
    },
}

fn tail(stderr_tail: &str) -> String {
    if stderr_tail.is_empty() { String::new() } else { format!("; stderr: {stderr_tail}") }
}

impl Error {
    /// Whether the backend as a whole failed, as opposed to this request; §9 falls
    /// back to the next backend on these.
    pub fn is_backend_failure(&self) -> bool {
        match self {
            Self::Spawn { .. }
            | Self::Startup { .. }
            | Self::ProtocolVersion { .. }
            | Self::Exited { .. }
            | Self::Timeout(_)
            | Self::InvalidResult(_)
            | Self::Unavailable { .. }
            | Self::Disabled { .. } => true,
            Self::Cancelled | Self::Rpc(_) | Self::Encode(_) | Self::Closed | Self::UnsupportedOption { .. } => false,
        }
    }
}
