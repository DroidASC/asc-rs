//! How many worker threads a search takes when its caller fixed none: the
//! CPUs of this machine split between this process and the user's other
//! busy registered ones ([`crate::ProcessRegistry`]). One policy for the DEX
//! and the HarmonyOS engine, so a laptop running both is not oversubscribed.

use crate::{LockExt, ProcessRegistry};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Busy for [`auto_threads`], for a registry entry that does not say (its
/// process predates the busy flag): one updated this recently. Memory
/// caches republish at most every few seconds while they load entries, and
/// not at all when idle (an MCP server waiting for an agent's next call).
const BUSY_WINDOW: Duration = Duration::from_secs(5);

/// How often [`auto_threads`] re-reads the registry: a burst of scans
/// started together by several agents lasts about a second. A read checks
/// every entry's process: about 1 ms for 31 servers on macOS, which callers
/// wait for (letting them go on with the last count made 16 servers' cold
/// sweep 10 % slower).
const THREADS_EVERY: Duration = Duration::from_millis(100);

/// Workers the busy processes may start together, per CPU. An exact split
/// (1) leaves CPUs idle while the processes holding the largest APKs finish
/// alone: 8 servers scanning 312 APKs on 16 CPUs took 223 ms with 2 workers
/// each, 180 ms with 8 and 176 ms with 16, for 13 % more memory at 8.
const OVERSUBSCRIBE: usize = 4;

/// How often a worker [`Threads::wait_turn`] holds back looks again.
const TURN_POLL: Duration = Duration::from_millis(10);

/// Worker threads of a search whose caller fixed none: this machine's CPUs
/// split between this process and the user's other busy registered ones
/// ([`auto_threads_for`]). Re-read at most once per [`THREADS_EVERY`], so
/// a sweep follows the others starting and finishing their scans
/// ([`Threads::wait_turn`]). A process that does not register itself (a
/// one-shot command) still gives way to the resident hosts.
pub fn auto_threads() -> usize {
    static LAST: Mutex<Option<(Instant, usize)>> = Mutex::new(None);
    let mut last = LAST.lock_or_default();
    if let Some((at, threads)) = *last
        && at.elapsed() < THREADS_EVERY
    {
        return threads;
    }
    let others = ProcessRegistry::default_dir().map(|dir| ProcessRegistry::others_in(&dir)).unwrap_or_default();
    let busy = others.iter().filter(|other| other.busy.unwrap_or(other.idle < BUSY_WINDOW)).count();
    let threads = auto_threads_for(cpus(), busy);
    *last = Some((Instant::now(), threads));
    threads
}

/// This machine's CPUs.
pub fn cpus() -> usize {
    std::thread::available_parallelism().map_or(8, |n| n.get())
}

/// [`OVERSUBSCRIBE`] x `cpus` workers split evenly between this process and
/// `busy_others`, at most `cpus` and at least 2 (where there are 2): a scan
/// on one thread gives up its overlap of inflating one entry while searching
/// another. Up to 4 busy processes each keep every CPU.
pub fn auto_threads_for(cpus: usize, busy_others: usize) -> usize {
    (cpus * OVERSUBSCRIBE / (busy_others + 1)).clamp(cpus.min(2), cpus)
}

/// Worker threads of a search.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Threads {
    /// [`auto_threads`], read again by every search.
    #[default]
    Auto,
    Fixed(usize),
}

impl Threads {
    /// The thread count for a search starting now (at least 1).
    pub fn count(self) -> usize {
        match self {
            Threads::Auto => auto_threads(),
            Threads::Fixed(n) => n.max(1),
        }
    }

    /// The most workers [`Threads::wait_turn`] ever lets run at once.
    pub fn most(self) -> usize {
        match self {
            Threads::Auto => cpus(),
            Threads::Fixed(n) => n.max(1),
        }
    }

    /// For a long search that starts [`Threads::most`] workers: hold worker
    /// `k` back (between units of work) while [`auto_threads`] allows fewer
    /// than `k + 1`, or until `stop()`. The count shrinks as other processes
    /// start scans and grows back as they finish, which a count read once at
    /// the start cannot follow: every process of a burst would see the others
    /// idle and take every CPU.
    pub fn wait_turn(self, k: usize, stop: impl Fn() -> bool) {
        if self == Threads::Auto {
            while k >= auto_threads() && !stop() {
                std::thread::sleep(TURN_POLL);
            }
        }
    }
}

impl From<usize> for Threads {
    fn from(n: usize) -> Threads {
        Threads::Fixed(n)
    }
}

/// `None` (no `--threads`) is [`Threads::Auto`].
impl From<Option<usize>> for Threads {
    fn from(n: Option<usize>) -> Threads {
        n.map_or(Threads::Auto, Threads::Fixed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn threads_split_between_busy_processes() {
        assert_eq!(auto_threads_for(32, 0), 32);
        assert_eq!(auto_threads_for(32, 3), 32, "4 busy processes keep every CPU");
        assert_eq!(auto_threads_for(32, 7), 16);
        assert_eq!(auto_threads_for(32, 15), 8);
        assert_eq!(auto_threads_for(32, 255), 2, "never below 2");
        assert_eq!(auto_threads_for(1, 3), 1, "nor above the CPUs");
        assert!(auto_threads() >= 1);
    }

    #[test]
    fn workers_wait_for_their_turn() {
        Threads::Auto.wait_turn(0, || panic!("the first worker always runs"));
        Threads::Fixed(1).wait_turn(5, || panic!("fixed counts never hold a worker back"));
        let asked = AtomicUsize::new(0);
        // Past every CPU a worker waits until the search tells it to stop.
        Threads::Auto.wait_turn(Threads::Auto.most(), || asked.fetch_add(1, Ordering::Relaxed) >= 2);
        assert_eq!(asked.load(Ordering::Relaxed), 3);
        assert_eq!((Threads::from(Some(3)), Threads::from(None)), (Threads::Fixed(3), Threads::Auto));
    }
}
