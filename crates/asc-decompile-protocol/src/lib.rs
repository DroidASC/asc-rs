//! The protocol asc speaks with decompiler backends (`docs/decompile-backends.md` §5–§6).
//!
//! A backend is a subprocess that exchanges line-delimited JSON-RPC 2.0 messages
//! over stdin / stdout. The lifecycle follows MCP (`initialize`, then the
//! `notifications/initialized` notification, then requests, then `shutdown`);
//! the methods are asc's own, typed by the [`Method`] and [`NotificationMethod`]
//! marker types in [`methods`].
//!
//! The crate is shared by both ends: the client in `asc-decompile` and any
//! backend written in Rust (`asc-dexdec-worker`). It has no
//! process logic, only:
//!
//! * [`Message`] and its parts, the untyped JSON-RPC envelope;
//! * typed parameters and results for every method;
//! * [`FrameReader`] / [`FrameWriter`], the newline framing with the
//!   [`MAX_MESSAGE_BYTES`] limit;
//! * [`server`], small helpers for the backend side.

mod codec;
mod jsonrpc;
pub mod methods;
pub mod server;

pub use codec::{FrameError, FrameReader, FrameWriter, MAX_MESSAGE_BYTES};
pub use jsonrpc::{ErrorCode, ErrorObject, JSONRPC_VERSION, Message, Notification, Request, RequestId, Response};
pub use methods::{Method, NotificationMethod};

/// The only protocol version this crate implements.
pub const PROTOCOL_VERSION: u32 = 1;
