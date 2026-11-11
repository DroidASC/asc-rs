//! Helpers for the backend end of the protocol.
//!
//! A backend reads requests on one thread and usually answers on others (one per
//! request, up to its `maxConcurrency`). [`Outgoing`] serializes their writes to
//! stdout; [`Cancellations`] carries `notifications/cancelled` from the reader to
//! the workers.

use std::collections::HashSet;
use std::io::Write;
use std::sync::{Arc, Mutex};

use serde::Serialize;

use crate::codec::{FrameError, FrameWriter};
use crate::jsonrpc::{ErrorCode, ErrorObject, Message, Notification, RequestId, Response};
use crate::methods::NotificationMethod;

/// The writing half of a connection, shareable across threads.
#[derive(Debug)]
pub struct Outgoing<W> {
    writer: Arc<Mutex<FrameWriter<W>>>,
}

impl<W> Clone for Outgoing<W> {
    fn clone(&self) -> Self {
        Self { writer: Arc::clone(&self.writer) }
    }
}

impl<W: Write> Outgoing<W> {
    pub fn new(writer: W) -> Self {
        Self::from_writer(FrameWriter::new(writer))
    }

    pub fn from_writer(writer: FrameWriter<W>) -> Self {
        Self { writer: Arc::new(Mutex::new(writer)) }
    }

    /// Writes one message as a whole line.
    ///
    /// # Errors
    ///
    /// See [`FrameWriter::write_message`].
    pub fn send(&self, message: impl Into<Message>) -> Result<(), FrameError> {
        self.writer.lock().expect("outgoing writer mutex poisoned").write_message(&message.into())
    }

    /// Answers request `id`. A result that cannot be encoded, or is over the
    /// message limit, is answered with `-32603 internal error` instead, so the
    /// client is never left waiting.
    ///
    /// # Errors
    ///
    /// I/O errors only; the client is gone then.
    pub fn respond<T: Serialize>(&self, id: RequestId, result: Result<T, ErrorObject>) -> Result<(), FrameError> {
        let internal = |reason: String| Response::error(Some(id.clone()), ErrorObject::new(ErrorCode::INTERNAL_ERROR, reason));
        let response = match result {
            Ok(result) => Response::success(id.clone(), &result).unwrap_or_else(|err| internal(format!("cannot encode result: {err}"))),
            Err(error) => Response::error(Some(id.clone()), error),
        };
        match self.send(response) {
            Err(FrameError::TooLarge { limit }) => self.send(internal(format!("result exceeds the {limit}-byte message limit"))),
            Err(FrameError::Json(err)) => self.send(internal(format!("cannot encode result: {err}"))),
            other => other,
        }
    }

    /// Sends a typed notification.
    ///
    /// # Errors
    ///
    /// Encoding and I/O errors.
    pub fn notify<N: NotificationMethod>(&self, params: &N::Params) -> Result<(), FrameError> {
        self.send(Notification::new::<N>(params)?)
    }
}

/// Requests the client asked to cancel and that are still running.
#[derive(Debug, Clone, Default)]
pub struct Cancellations {
    ids: Arc<Mutex<HashSet<RequestId>>>,
}

impl Cancellations {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a `notifications/cancelled`.
    pub fn cancel(&self, id: RequestId) {
        self.lock().insert(id);
    }

    pub fn is_cancelled(&self, id: &RequestId) -> bool {
        self.lock().contains(id)
    }

    /// Forgets `id` once its response is sent; a cancellation for a finished request is ignored.
    pub fn finish(&self, id: &RequestId) {
        self.lock().remove(id);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashSet<RequestId>> {
        self.ids.lock().expect("cancellations mutex poisoned")
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;
    use crate::codec::FrameReader;

    #[test]
    fn respond_replaces_oversized_results_with_an_error() {
        let outgoing = Outgoing::from_writer(FrameWriter::with_limit(Vec::new(), 128));
        outgoing.respond(1.into(), Ok("x".repeat(200))).unwrap();
        outgoing.respond::<Value>(2.into(), Ok(json!({"ok": true}))).unwrap();
        let bytes = Arc::try_unwrap(outgoing.writer).unwrap().into_inner().unwrap().into_inner();

        let mut reader = FrameReader::new(bytes.as_slice());
        let Some(Message::Response(first)) = reader.read_message().unwrap() else { panic!("expected a response") };
        assert_eq!(first.outcome.unwrap_err().code, ErrorCode::INTERNAL_ERROR);
        let Some(Message::Response(second)) = reader.read_message().unwrap() else { panic!("expected a response") };
        assert_eq!(second.outcome.unwrap(), json!({"ok": true}));
    }

    #[test]
    fn cancellations_track_running_requests() {
        let cancellations = Cancellations::new();
        cancellations.cancel(3.into());
        assert!(cancellations.is_cancelled(&3.into()));
        cancellations.finish(&3.into());
        assert!(!cancellations.is_cancelled(&3.into()));
    }
}
