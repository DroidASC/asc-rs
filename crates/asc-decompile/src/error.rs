use std::io;
use std::time::Duration;

use asc_decompile_protocol::{ErrorObject, PROTOCOL_VERSION};

/// Why a backend call failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("cannot start `{command}`: {source}")]
    Spawn { command: String, source: io::Error },
    /// The process started but did not complete `initialize`.
    #[error("backend failed to start: {reason}{}", tail(stderr_tail))]
    Startup { reason: String, stderr_tail: String },
    #[error("backend speaks protocol version {got}, asc supports {PROTOCOL_VERSION}")]
    ProtocolVersion { got: u32 },
    /// The process died (or was killed for breaking the protocol) with the request in flight.
    #[error("backend exited: {reason}{}", tail(stderr_tail))]
    Exited { reason: String, stderr_tail: String },
    #[error("request timed out after {0:?}")]
    Timeout(Duration),
    #[error("request cancelled")]
    Cancelled,
    /// The backend answered with a JSON-RPC error.
    #[error("backend error: {0}")]
    Rpc(#[from] ErrorObject),
    #[error("backend returned a malformed result: {0}")]
    InvalidResult(serde_json::Error),
    #[error("cannot encode request: {0}")]
    Encode(serde_json::Error),
    /// Restarting is backing off after failed startups.
    #[error("backend unavailable for another {retry_in:?} after failing to start: {last_error}")]
    Unavailable { retry_in: Duration, last_error: String },
    /// Disabled for the rest of the session (§5).
    #[error("backend disabled: {reason}")]
    Disabled { reason: String },
    #[error("backend pool is shut down")]
    Closed,
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
            Self::Cancelled | Self::Rpc(_) | Self::Encode(_) | Self::Closed => false,
        }
    }
}
