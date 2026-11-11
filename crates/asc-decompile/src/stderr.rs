//! Bounded capture of a backend's stderr.

use std::collections::VecDeque;
use std::io::Read;
use std::sync::{Arc, Mutex};

/// Bytes of the stderr tail quoted in error messages.
const TAIL_IN_ERRORS: usize = 4 << 10;

/// The most recent `capacity` bytes written to a stream.
#[derive(Debug)]
pub(crate) struct StderrRing {
    bytes: VecDeque<u8>,
    capacity: usize,
}

impl StderrRing {
    pub(crate) fn new(capacity: usize) -> Self {
        Self { bytes: VecDeque::with_capacity(capacity.min(8 << 10)), capacity }
    }

    pub(crate) fn push(&mut self, chunk: &[u8]) {
        let chunk = &chunk[chunk.len().saturating_sub(self.capacity)..];
        let overflow = (self.bytes.len() + chunk.len()).saturating_sub(self.capacity);
        self.bytes.drain(..overflow);
        self.bytes.extend(chunk);
    }

    /// The last `max` bytes as text, trimmed, starting at a line boundary when one is near.
    pub(crate) fn tail(&self, max: usize) -> String {
        let start = self.bytes.len().saturating_sub(max);
        let bytes: Vec<u8> = self.bytes.range(start..).copied().collect();
        let mut text = String::from_utf8_lossy(&bytes).into_owned();
        if start > 0
            && let Some(newline) = text.find('\n')
        {
            text.drain(..=newline);
        }
        text.trim().to_owned()
    }

    pub(crate) fn error_tail(&self) -> String {
        self.tail(TAIL_IN_ERRORS)
    }

    pub(crate) fn contents(&self) -> String {
        self.tail(self.capacity)
    }
}

pub(crate) type SharedRing = Arc<Mutex<StderrRing>>;

/// Copies `stream` into `ring` until end of stream.
pub(crate) fn drain(mut stream: impl Read, ring: &SharedRing) {
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => return,
            Ok(n) => ring.lock().expect("stderr ring mutex poisoned").push(&chunk[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_only_the_last_bytes() {
        let mut ring = StderrRing::new(8);
        ring.push(b"abc");
        ring.push(b"defgh");
        assert_eq!(ring.contents(), "abcdefgh");
        ring.push(b"ij");
        assert_eq!(ring.contents(), "cdefghij");
        ring.push(b"0123456789xyz");
        assert_eq!(ring.contents(), "56789xyz");
    }

    #[test]
    fn tail_starts_at_a_line() {
        let mut ring = StderrRing::new(64);
        ring.push(b"first line\nsecond line\nthird\n");
        assert_eq!(ring.tail(14), "third");
        assert_eq!(ring.tail(1000), "first line\nsecond line\nthird");
    }
}
