//! How the workspace treats a poisoned lock.
//!
//! A `Mutex` is poisoned when a thread panics while holding it. Hosts that
//! stay alive (the MCP server, the daemon) contain a panicking request with
//! `catch_unwind`, so whatever that request held stays poisoned for every
//! later one. Each lock takes one of two policies:
//!
//! * **Caches and derived state** (built slots, LRUs, pools of open
//!   engines, accounting that can start over) lock with
//!   [`LockExt::lock_or_reset`] / [`LockExt::lock_or_default`]: after a
//!   panic the state may be half-written, so it is reset (rebuilt on demand)
//!   and the poison cleared. One bad request costs a rebuild, not the host.
//! * **Everything else** locks with `.lock().expect("<what> mutex
//!   poisoned")`: short bookkeeping that cannot panic in practice, and the
//!   collectors of scoped worker threads (the scope re-raises a worker's
//!   panic anyway). Poison there is a bug that should surface.
//!
//! Expensive or untrusted work (parsing a DEX, building a graph) runs
//! outside cache locks, so a panic in it poisons nothing.

use std::sync::{Mutex, MutexGuard};

/// Locking a [`Mutex`] whose state can be thrown away after a panic.
pub trait LockExt<T> {
    /// Lock; if a panic poisoned the lock, `reset` the state first and clear
    /// the poison.
    fn lock_or_reset(&self, reset: impl FnOnce(&mut T)) -> MutexGuard<'_, T>;

    /// [`LockExt::lock_or_reset`] back to `T::default()`.
    fn lock_or_default(&self) -> MutexGuard<'_, T>
    where
        T: Default,
    {
        self.lock_or_reset(|state| *state = T::default())
    }
}

impl<T> LockExt<T> for Mutex<T> {
    fn lock_or_reset(&self, reset: impl FnOnce(&mut T)) -> MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|poisoned| {
            let mut state = poisoned.into_inner();
            reset(&mut state);
            self.clear_poison();
            state
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn poison(m: &Mutex<Vec<u32>>) {
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut v = m.lock().unwrap();
            v.push(2);
            panic!("half-written");
        }));
        assert!(caught.is_err() && m.is_poisoned());
    }

    #[test]
    fn a_poisoned_lock_resets_once_and_is_healthy_again() {
        let m = Mutex::new(vec![1]);
        assert_eq!(*m.lock_or_default(), [1]);
        poison(&m);
        assert!(m.lock_or_default().is_empty());
        assert!(!m.is_poisoned());
        m.lock_or_default().push(3);
        assert_eq!(*m.lock_or_reset(|_| unreachable!("not poisoned")), [3]);
        poison(&m);
        assert_eq!(*m.lock_or_reset(|v| v.retain(|&x| x != 2)), [3]);
    }
}
