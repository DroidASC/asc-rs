//! `asc-dexdec-worker`, the executable of the built-in backend: the names
//! asc-cli and older callers use. The lookup and the install are
//! [`super::worker`]'s, for every built-in worker.

pub use super::worker::{DEXDEC, PROTOCOL, RETRY_AFTER, TARGET, VERSION, WORKER_FILE, Worker, WorkerOrigin, WorkerSettings};
