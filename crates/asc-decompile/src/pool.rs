//! The process pool of one backend: queueing, start / restart, idle shutdown.
//!
//! All state sits behind one mutex with a condition variable. A request takes a
//! ticket in its priority lane and waits until it is at the head of the queue
//! (interactive lane first, FIFO within a lane) and some process has a free
//! request slot, or an empty slot lets it start one. Starting happens outside
//! the lock, so other tickets keep flowing meanwhile.

use std::collections::VecDeque;
use std::num::NonZeroU32;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, Weak};
use std::thread;
use std::time::{Duration, Instant};

use asc_decompile_protocol::Method;
use asc_decompile_protocol::methods::{Implementation, InitializeResult};

use crate::error::Error;
use crate::process::{CallControl, Process};
use crate::spec::{BackendSpec, CallOptions, CancelToken, Priority};
use crate::stderr::SharedRing;

/// How often a waiter with a [`CancelToken`] checks it.
const CANCEL_POLL: Duration = Duration::from_millis(20);

pub(crate) struct Inner {
    pub(crate) name: String,
    pub(crate) spec: BackendSpec,
    client: Implementation,
    state: Mutex<PoolState>,
    /// Signalled whenever a slot, the queue head or the health changes.
    changed: Condvar,
    /// Wakes the idle reaper early on close.
    reaper: Condvar,
}

enum Slot {
    Empty,
    Starting,
    Ready { process: Arc<Process>, in_flight: u32, last_used: Instant },
}

#[derive(Default)]
struct Queue {
    interactive: VecDeque<u64>,
    batch: VecDeque<u64>,
}

impl Queue {
    fn lane(&mut self, priority: Priority) -> &mut VecDeque<u64> {
        match priority {
            Priority::Interactive => &mut self.interactive,
            Priority::Batch => &mut self.batch,
        }
    }

    fn head(&self) -> Option<u64> {
        self.interactive.front().or(self.batch.front()).copied()
    }

    fn remove(&mut self, priority: Priority, ticket: u64) {
        self.lane(priority).retain(|&queued| queued != ticket);
    }
}

#[derive(Default)]
struct Health {
    /// Consecutive failures (failed starts and crashes); drives the backoff.
    strikes: u32,
    /// Consecutive failed starts; disables the backend at the limit.
    startup_failures: u32,
    not_before: Option<Instant>,
    last_startup_error: Option<String>,
    disabled: Option<String>,
}

struct PoolState {
    slots: Vec<Slot>,
    queue: Queue,
    next_ticket: u64,
    next_process: u64,
    health: Health,
    capabilities: Option<Arc<InitializeResult>>,
    /// stderr of the most recently started process, kept after it exits.
    last_stderr: Option<SharedRing>,
    closed: bool,
}

impl PoolState {
    /// Clears slots whose process died, counting each as a strike.
    fn reap_dead(&mut self, inner: &Inner) {
        for slot in &mut self.slots {
            if let Slot::Ready { process, .. } = slot
                && !process.is_usable()
            {
                *slot = Slot::Empty;
                self.health.strikes += 1;
                self.health.not_before = Some(Instant::now() + inner.spec.lifecycle.backoff(self.health.strikes));
            }
        }
    }

    /// A request slot on a ready process: at most what it declared, and at most `cap`.
    fn take_capacity(&mut self, cap: Option<NonZeroU32>) -> Option<Arc<Process>> {
        self.slots.iter_mut().find_map(|slot| match slot {
            Slot::Ready { process, in_flight, .. }
                if *in_flight < process.capabilities().max_concurrency.min(cap.unwrap_or(NonZeroU32::MAX)).get() =>
            {
                *in_flight += 1;
                Some(Arc::clone(process))
            }
            Slot::Empty | Slot::Starting | Slot::Ready { .. } => None,
        })
    }

    fn has_live_process(&self) -> bool {
        self.slots.iter().any(|slot| matches!(slot, Slot::Ready { .. } | Slot::Starting))
    }
}

/// A running process of a pool, as [`Backend::processes`](crate::Backend::processes) lists it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProcessInfo {
    /// The operating system's process id.
    pub pid: u32,
    /// Requests it is serving now.
    pub in_flight: u32,
    /// How long since its last request ended; `None` while it serves one.
    pub idle_for: Option<Duration>,
}

/// What a queued request does once it is its turn.
enum Step {
    Take(Arc<Process>),
    Start(usize),
    Fail(Error),
}

/// A claim on one request slot of a process, released on drop.
pub(crate) struct Lease {
    inner: Arc<Inner>,
    pub(crate) process: Arc<Process>,
}

impl Lease {
    pub(crate) fn control<'a>(&self, options: &'a CallOptions) -> CallControl<'a> {
        CallControl {
            timeout: options.timeout.unwrap_or(self.inner.spec.timeout),
            cancel: options.cancel.as_ref(),
            progress: options.progress.clone(),
        }
    }

    /// Calls `M` on the leased process; a reply of any kind proves the process healthy.
    pub(crate) fn call<M: Method>(&self, params: &M::Params, options: &CallOptions) -> Result<M::Result, Error> {
        let result = self.process.call::<M>(params, &self.control(options));
        self.observe(&result);
        result
    }

    pub(crate) fn observe<T>(&self, result: &Result<T, Error>) {
        if matches!(result, Ok(_) | Err(Error::Rpc(_) | Error::Cancelled)) {
            self.inner.lock().health.strikes = 0;
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut state = self.inner.lock();
        let slot = state.slots.iter_mut().find_map(|slot| match slot {
            Slot::Ready { process, in_flight, last_used } if process.id() == self.process.id() => Some((in_flight, last_used)),
            Slot::Empty | Slot::Starting | Slot::Ready { .. } => None,
        });
        if let Some((in_flight, last_used)) = slot {
            *in_flight -= 1;
            *last_used = Instant::now();
        }
        drop(state);
        self.inner.changed.notify_all();
    }
}

impl Inner {
    pub(crate) fn new(name: String, spec: BackendSpec, client: Implementation) -> Arc<Self> {
        let slots = (0..spec.instances.get()).map(|_| Slot::Empty).collect();
        let inner = Arc::new(Self {
            name,
            spec,
            client,
            state: Mutex::new(PoolState {
                slots,
                queue: Queue::default(),
                next_ticket: 0,
                next_process: 0,
                health: Health::default(),
                capabilities: None,
                last_stderr: None,
                closed: false,
            }),
            changed: Condvar::new(),
            reaper: Condvar::new(),
        });
        let weak = Arc::downgrade(&inner);
        // Without the reaper processes merely live until the pool closes.
        let _ = thread::Builder::new().name(format!("decompile-idle-{}", inner.name)).spawn(move || reap_idle(&weak));
        inner
    }

    fn lock(&self) -> MutexGuard<'_, PoolState> {
        self.state.lock().expect("decompile pool mutex poisoned")
    }

    /// Waits for a request slot, starting a process when needed.
    pub(crate) fn acquire(self: &Arc<Self>, priority: Priority, cancel: Option<&CancelToken>) -> Result<Lease, Error> {
        let mut state = self.lock();
        let ticket = state.next_ticket;
        state.next_ticket += 1;
        state.queue.lane(priority).push_back(ticket);
        let step = loop {
            state.reap_dead(self);
            if state.closed {
                break Step::Fail(Error::Closed);
            }
            if let Some(reason) = &state.health.disabled {
                break Step::Fail(Error::Disabled { reason: reason.clone() });
            }
            if cancel.is_some_and(CancelToken::is_cancelled) {
                break Step::Fail(Error::Cancelled);
            }
            let mut wait_for = None;
            if state.queue.head() == Some(ticket) {
                if let Some(process) = state.take_capacity(self.spec.max_concurrency) {
                    break Step::Take(process);
                }
                let empty = state.slots.iter().position(|slot| matches!(slot, Slot::Empty));
                if let Some(index) = empty {
                    let now = Instant::now();
                    match state.health.not_before.filter(|&at| at > now) {
                        None => break Step::Start(index),
                        // Failing fast beats parking the caller for up to a minute when nothing can
                        // serve it; the backoff after a crash of a working backend is waited out.
                        Some(at) if state.health.startup_failures > 0 && !state.has_live_process() => {
                            let last_error = state.health.last_startup_error.clone().unwrap_or_default();
                            break Step::Fail(Error::Unavailable { retry_in: at - now, last_error });
                        }
                        Some(at) => wait_for = Some(at - now),
                    }
                }
            }
            if cancel.is_some() {
                wait_for = Some(wait_for.map_or(CANCEL_POLL, |wait| wait.min(CANCEL_POLL)));
            }
            state = match wait_for {
                Some(wait) => self.changed.wait_timeout(state, wait).expect("decompile pool mutex poisoned").0,
                None => self.changed.wait(state).expect("decompile pool mutex poisoned"),
            };
        };
        // Leaving the queue lets the next ticket move while this one starts a process.
        state.queue.remove(priority, ticket);
        let outcome = match step {
            Step::Take(process) => {
                drop(state);
                Ok(process)
            }
            Step::Fail(err) => {
                drop(state);
                Err(err)
            }
            Step::Start(index) => self.start(state, index),
        };
        self.changed.notify_all();
        outcome.map(|process| Lease { inner: Arc::clone(self), process })
    }

    /// Starts a process in slot `index` and claims a request slot on it.
    fn start(&self, mut state: MutexGuard<'_, PoolState>, index: usize) -> Result<Arc<Process>, Error> {
        state.slots[index] = Slot::Starting;
        let id = state.next_process;
        state.next_process += 1;
        drop(state);
        self.changed.notify_all();

        let started = Process::start(id, &self.spec, &self.client);

        let mut state = self.lock();
        let lifecycle = &self.spec.lifecycle;
        let outcome = match started {
            Ok(process) if state.closed => {
                state.slots[index] = Slot::Empty;
                drop(state);
                process.shutdown();
                state = self.lock();
                Err(Error::Closed)
            }
            Ok(process) => {
                state.health.startup_failures = 0;
                state.health.last_startup_error = None;
                state.capabilities = Some(Arc::clone(process.capabilities()));
                state.last_stderr = Some(process.stderr_ring());
                state.slots[index] = Slot::Ready { process: Arc::clone(&process), in_flight: 1, last_used: Instant::now() };
                Ok(process)
            }
            Err(err) => {
                state.slots[index] = Slot::Empty;
                let health = &mut state.health;
                health.strikes += 1;
                health.startup_failures += 1;
                health.not_before = Some(Instant::now() + lifecycle.backoff(health.strikes));
                health.last_startup_error = Some(err.to_string());
                if let Error::ProtocolVersion { .. } = err {
                    health.disabled = Some(err.to_string());
                } else if health.startup_failures >= lifecycle.max_startup_failures {
                    health.disabled = Some(format!("{} consecutive failed starts, last: {err}", health.startup_failures));
                }
                Err(err)
            }
        };
        drop(state);
        self.changed.notify_all();
        outcome
    }

    pub(crate) fn capabilities(&self) -> Option<Arc<InitializeResult>> {
        self.lock().capabilities.clone()
    }

    pub(crate) fn disabled_reason(&self) -> Option<String> {
        self.lock().health.disabled.clone()
    }

    pub(crate) fn stderr(&self) -> String {
        let ring = self.lock().last_stderr.clone();
        ring.map(|ring| ring.lock().expect("stderr ring mutex poisoned").contents()).unwrap_or_default()
    }

    pub(crate) fn running_processes(&self) -> usize {
        self.lock().slots.iter().filter(|slot| matches!(slot, Slot::Ready { process, .. } if process.is_usable())).count()
    }

    pub(crate) fn processes(&self) -> Vec<ProcessInfo> {
        let now = Instant::now();
        let state = self.lock();
        state
            .slots
            .iter()
            .filter_map(|slot| match slot {
                Slot::Ready { process, in_flight, last_used } if process.is_usable() => Some(ProcessInfo {
                    pid: process.pid(),
                    in_flight: *in_flight,
                    idle_for: (*in_flight == 0).then(|| now.saturating_duration_since(*last_used)),
                }),
                Slot::Empty | Slot::Starting | Slot::Ready { .. } => None,
            })
            .collect()
    }

    /// Shuts the process `pid` down if it serves no request; the next request starts another.
    pub(crate) fn retire(&self, pid: u32) -> bool {
        let retired = {
            let mut state = self.lock();
            let slot =
                state.slots.iter_mut().find(|slot| matches!(slot, Slot::Ready { process, in_flight: 0, .. } if process.pid() == pid));
            slot.map(|slot| std::mem::replace(slot, Slot::Empty))
        };
        let Some(Slot::Ready { process, .. }) = retired else { return false };
        self.changed.notify_all();
        process.shutdown();
        true
    }

    /// Shuts every process down in parallel and fails all later requests.
    pub(crate) fn close(&self) {
        let processes: Vec<Arc<Process>> = {
            let mut state = self.lock();
            state.closed = true;
            state
                .slots
                .iter_mut()
                .filter_map(|slot| match std::mem::replace(slot, Slot::Empty) {
                    Slot::Ready { process, .. } => Some(process),
                    // A starting process is shut down by its starter, which sees `closed`.
                    Slot::Starting => {
                        *slot = Slot::Starting;
                        None
                    }
                    Slot::Empty => None,
                })
                .collect()
        };
        self.changed.notify_all();
        self.reaper.notify_all();
        thread::scope(|scope| {
            for process in &processes {
                scope.spawn(|| process.shutdown());
            }
        });
    }
}

/// Background loop shutting down processes idle for longer than `spec.idle`.
fn reap_idle(weak: &Weak<Inner>) {
    while let Some(inner) = weak.upgrade() {
        let idle = inner.spec.idle;
        let now = Instant::now();
        let mut state = inner.lock();
        if state.closed {
            return;
        }
        let mut next_check = idle;
        let mut retired = Vec::new();
        for slot in &mut state.slots {
            let Slot::Ready { process, in_flight: 0, last_used } = slot else { continue };
            let due = *last_used + idle;
            if due <= now {
                retired.push(Arc::clone(process));
                *slot = Slot::Empty;
            } else {
                next_check = next_check.min(due - now);
            }
        }
        drop(state);
        if !retired.is_empty() {
            inner.changed.notify_all();
        }
        for process in retired {
            process.shutdown();
        }
        let state = inner.lock();
        if state.closed {
            return;
        }
        // Drops `inner` after the wait so the pool can be freed between checks.
        let _ = inner.reaper.wait_timeout(state, next_check).expect("decompile pool mutex poisoned");
    }
}
