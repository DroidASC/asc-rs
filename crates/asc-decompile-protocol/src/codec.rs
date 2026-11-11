//! Newline-delimited framing: one compact JSON message per line.

use std::io::{self, BufRead, Write};

use crate::jsonrpc::Message;

/// Largest message either end accepts, newline excluded (§5).
pub const MAX_MESSAGE_BYTES: usize = 64 << 20;

/// A framing failure. None of them leave the stream in a known state: the
/// peer should be treated as broken.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("message exceeds {limit} bytes")]
    TooLarge { limit: usize },
    #[error("stream ended in the middle of a message")]
    Truncated,
    #[error("invalid message: {0}")]
    Json(#[from] serde_json::Error),
}

/// Reads frames from a byte stream, never buffering more than the limit.
#[derive(Debug)]
pub struct FrameReader<R> {
    inner: R,
    limit: usize,
    line: Vec<u8>,
}

impl<R: BufRead> FrameReader<R> {
    pub fn new(inner: R) -> Self {
        Self::with_limit(inner, MAX_MESSAGE_BYTES)
    }

    pub fn with_limit(inner: R, limit: usize) -> Self {
        Self { inner, limit, line: Vec::new() }
    }

    /// Reads the next non-empty line, without its line terminator.
    ///
    /// Returns `None` at a clean end of stream.
    ///
    /// # Errors
    ///
    /// [`FrameError::TooLarge`] as soon as the line outgrows the limit (the rest
    /// of it is left unread), [`FrameError::Truncated`] when the stream ends
    /// inside a line, and I/O errors of the underlying reader.
    pub fn read_frame(&mut self) -> Result<Option<&[u8]>, FrameError> {
        self.line.clear();
        loop {
            let available = match self.inner.fill_buf() {
                Ok(available) => available,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err.into()),
            };
            if available.is_empty() {
                return if self.line.is_empty() { Ok(None) } else { Err(FrameError::Truncated) };
            }
            let (chunk, newline) = match available.iter().position(|&b| b == b'\n') {
                Some(end) => (&available[..end], true),
                None => (available, false),
            };
            if self.line.len() + chunk.len() > self.limit {
                return Err(FrameError::TooLarge { limit: self.limit });
            }
            self.line.extend_from_slice(chunk);
            let consumed = chunk.len() + usize::from(newline);
            self.inner.consume(consumed);
            if !newline {
                continue;
            }
            if self.line.last() == Some(&b'\r') {
                self.line.pop();
            }
            if !self.line.is_empty() {
                return Ok(Some(&self.line));
            }
        }
    }

    /// Reads and parses the next message; `None` at a clean end of stream.
    ///
    /// # Errors
    ///
    /// Everything [`read_frame`](Self::read_frame) reports, plus
    /// [`FrameError::Json`] for a line that is not a JSON-RPC message.
    pub fn read_message(&mut self) -> Result<Option<Message>, FrameError> {
        match self.read_frame()? {
            Some(frame) => Ok(Some(serde_json::from_slice(frame)?)),
            None => Ok(None),
        }
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

/// Writes one message per line and flushes after each.
#[derive(Debug)]
pub struct FrameWriter<W> {
    inner: W,
    limit: usize,
    buf: Vec<u8>,
}

impl<W: Write> FrameWriter<W> {
    pub fn new(inner: W) -> Self {
        Self::with_limit(inner, MAX_MESSAGE_BYTES)
    }

    pub fn with_limit(inner: W, limit: usize) -> Self {
        Self { inner, limit, buf: Vec::new() }
    }

    /// Serializes `message` compactly (JSON escapes every newline inside strings),
    /// appends `\n` and flushes.
    ///
    /// # Errors
    ///
    /// [`FrameError::TooLarge`] without writing anything when the message is over
    /// the limit, [`FrameError::Json`] when it cannot be serialized, and I/O errors.
    pub fn write_message(&mut self, message: &Message) -> Result<(), FrameError> {
        self.buf.clear();
        serde_json::to_writer(&mut self.buf, message)?;
        if self.buf.len() > self.limit {
            return Err(FrameError::TooLarge { limit: self.limit });
        }
        self.buf.push(b'\n');
        self.inner.write_all(&self.buf)?;
        self.inner.flush()?;
        Ok(())
    }

    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor};

    use serde_json::{Value, json};

    use super::*;
    use crate::jsonrpc::{Notification, Request};

    fn reader(bytes: &[u8], limit: usize) -> FrameReader<BufReader<Cursor<Vec<u8>>>> {
        // A tiny buffer exercises lines split across several `fill_buf` calls.
        FrameReader::with_limit(BufReader::with_capacity(4, Cursor::new(bytes.to_vec())), limit)
    }

    #[test]
    fn round_trips_messages() {
        let text = "line one\nline two";
        let messages = [
            Message::Request(Request { id: 1.into(), method: "a".into(), params: json!({"text": text}) }),
            Message::Notification(Notification { method: "b".into(), params: Value::Null }),
        ];
        let mut writer = FrameWriter::new(Vec::new());
        for message in &messages {
            writer.write_message(message).unwrap();
        }
        let bytes = writer.into_inner();
        assert_eq!(bytes.iter().filter(|&&b| b == b'\n').count(), 2, "newlines inside strings are escaped");

        let mut reader = reader(&bytes, MAX_MESSAGE_BYTES);
        for message in &messages {
            assert_eq!(&reader.read_message().unwrap().unwrap(), message);
        }
        assert!(reader.read_message().unwrap().is_none());
    }

    #[test]
    fn skips_blank_lines_and_crlf() {
        let mut reader = reader(b"\n\r\n{\"method\":\"x\"}\r\n\n", 64);
        assert!(matches!(reader.read_message().unwrap(), Some(Message::Notification(_))));
        assert!(reader.read_message().unwrap().is_none());
    }

    #[test]
    fn enforces_limit() {
        let mut exact = reader(b"12345678\n", 8);
        assert_eq!(exact.read_frame().unwrap(), Some(&b"12345678"[..]));

        let mut over = reader(b"123456789\n", 8);
        assert!(matches!(over.read_frame(), Err(FrameError::TooLarge { limit: 8 })));

        let mut endless = reader(&[b'x'; 100], 8);
        assert!(matches!(endless.read_frame(), Err(FrameError::TooLarge { .. })));

        let mut writer = FrameWriter::with_limit(Vec::new(), 8);
        let message = Message::Notification(Notification { method: "too long".into(), params: Value::Null });
        assert!(matches!(writer.write_message(&message), Err(FrameError::TooLarge { limit: 8 })));
        assert!(writer.into_inner().is_empty());
    }

    #[test]
    fn reports_truncation_and_garbage() {
        let mut truncated = reader(b"{\"method\":", 64);
        assert!(matches!(truncated.read_frame(), Err(FrameError::Truncated)));

        let mut garbage = reader(b"not json\n", 64);
        assert!(matches!(garbage.read_message(), Err(FrameError::Json(_))));
    }
}
