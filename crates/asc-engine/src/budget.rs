//! What the machine offers ([`Device`]) and how a resident host's memory
//! cache sizes itself from it ([`MemoryPolicy`]).

use asc_cache::ProcessUsage;
use std::path::Path;

/// The machine's memory and CPUs, as the automatic budgets see them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Device {
    /// Physical memory (lowered to a cgroup v2 `memory.max`), when known.
    pub total_memory: Option<u64>,
    /// Memory available right now ([`available_memory`]), when known.
    pub available_memory: Option<u64>,
    pub cpus: usize,
}

impl Device {
    pub fn probe() -> Device {
        Device { total_memory: total_memory(), available_memory: available_memory(), cpus: crate::tiers::cpus() }
    }
}

/// How a memory cache follows the machine: a share of the memory the
/// user's resident hosts could hold together, split between them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryPolicy {
    /// Share of (available memory + what the caches hold), in percent.
    pub percent: u8,
    /// Most one process takes, in bytes.
    pub ceiling: usize,
    /// Split the share between the user's registered processes.
    pub split: bool,
}

impl MemoryPolicy {
    /// Default share of the available memory.
    pub const PERCENT: u8 = 25;
    /// Least one process takes: below this the LRU would thrash on every
    /// query (it always keeps at least one entry anyway).
    pub const FLOOR: usize = 64 << 20;
    /// Bounds of the automatic ceiling ([`MemoryPolicy::auto_ceiling`]).
    pub const CEILING_MIN: usize = 2 << 30;
    pub const CEILING_MAX: usize = 8 << 30;

    /// The default policy for `device`.
    pub fn for_device(device: &Device) -> MemoryPolicy {
        MemoryPolicy { ceiling: MemoryPolicy::auto_ceiling(device.total_memory), ..MemoryPolicy::default() }
    }

    /// A sixteenth of physical memory, within
    /// [`MemoryPolicy::CEILING_MIN`]..=[`MemoryPolicy::CEILING_MAX`]: 2 GiB
    /// up to 32 GB of memory (where a quarter of the available memory is
    /// the tighter bound anyway), 6 GiB on a 96 GB machine. One server then
    /// keeps a phone's worth of hot DEX on a large machine, while sixteen
    /// still split a quarter of it.
    pub fn auto_ceiling(total_memory: Option<u64>) -> usize {
        total_memory.map_or(MemoryPolicy::CEILING_MIN, |t| {
            usize::try_from(t / 16).unwrap_or(usize::MAX).clamp(MemoryPolicy::CEILING_MIN, MemoryPolicy::CEILING_MAX)
        })
    }

    /// The budget of a process alone with `available` bytes free.
    pub fn alone(&self, available: Option<u64>) -> usize {
        self.share(available, 0, &[])
    }

    /// This process's share: [`MemoryPolicy::percent`] of what the user's
    /// registered processes could hold together (the available memory plus
    /// what their caches hold already), split evenly when
    /// [`MemoryPolicy::split`], within [`MemoryPolicy::FLOOR`]..=ceiling.
    /// The ceiling when the available memory is unknown.
    pub fn share(&self, available: Option<u64>, held_here: u64, others: &[ProcessUsage]) -> usize {
        let Some(available) = available else { return self.ceiling.max(MemoryPolicy::FLOOR) };
        let others = if self.split { others } else { &[] };
        let held: u64 = held_here + others.iter().map(|o| o.bytes).sum::<u64>();
        let share = u128::from(available.saturating_add(held)) * u128::from(self.percent) / 100 / (others.len() as u128 + 1);
        usize::try_from(share).unwrap_or(usize::MAX).clamp(MemoryPolicy::FLOOR, self.ceiling.max(MemoryPolicy::FLOOR))
    }
}

impl Default for MemoryPolicy {
    fn default() -> MemoryPolicy {
        MemoryPolicy { percent: MemoryPolicy::PERCENT, ceiling: MemoryPolicy::CEILING_MIN, split: true }
    }
}

/// Bytes of memory available to this process: on Linux `MemAvailable`,
/// lowered to the headroom left under a cgroup v2 `memory.max`; on Apple
/// systems the free, speculative and inactive pages. `None` elsewhere.
pub fn available_memory() -> Option<u64> {
    let system = system_available();
    match (system, cgroup_limit().map(|(max, current)| max.saturating_sub(current))) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// Physical memory, lowered to a cgroup v2 `memory.max`. `None` where it
/// cannot be read.
pub fn total_memory() -> Option<u64> {
    match (system_total(), cgroup_limit().map(|(max, _)| max)) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

#[cfg(target_os = "linux")]
fn system_available() -> Option<u64> {
    meminfo_field(&std::fs::read_to_string("/proc/meminfo").ok()?, "MemAvailable:")
}

#[cfg(target_os = "linux")]
fn system_total() -> Option<u64> {
    meminfo_field(&std::fs::read_to_string("/proc/meminfo").ok()?, "MemTotal:")
}

#[cfg(target_vendor = "apple")]
fn system_available() -> Option<u64> {
    apple::available()
}

#[cfg(target_vendor = "apple")]
fn system_total() -> Option<u64> {
    apple::total()
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn system_available() -> Option<u64> {
    None
}

#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
fn system_total() -> Option<u64> {
    None
}

/// A `/proc/meminfo` field (`MemAvailable:`, `MemTotal:`), in bytes.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn meminfo_field(meminfo: &str, field: &str) -> Option<u64> {
    let line = meminfo.lines().find(|l| l.starts_with(field))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    kb.checked_mul(1024)
}

/// `(memory.max, memory.current)` of this process's cgroup v2, if limited.
fn cgroup_limit() -> Option<(u64, u64)> {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel = cgroup.lines().find_map(|l| l.strip_prefix("0::"))?;
    let dir = Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
    let read = |f: &str| std::fs::read_to_string(dir.join(f)).ok();
    cgroup_limit_from(&read("memory.max")?, &read("memory.current")?)
}

/// Limit and usage from the text of `memory.max` (`max` when unlimited)
/// and `memory.current`.
fn cgroup_limit_from(max: &str, current: &str) -> Option<(u64, u64)> {
    Some((max.trim().parse().ok()?, current.trim().parse().ok()?))
}

#[cfg(target_vendor = "apple")]
mod apple {
    use std::os::raw::c_uint;

    extern "C" {
        // Declared here: libc marks it deprecated in favour of the mach2 crate.
        fn mach_host_self() -> c_uint;
    }

    pub(super) fn total() -> Option<u64> {
        let mut bytes: u64 = 0;
        let mut len = std::mem::size_of::<u64>();
        // SAFETY: the name is NUL-terminated and `bytes` / `len` describe a u64 out buffer.
        let rc = unsafe { libc::sysctlbyname(c"hw.memsize".as_ptr(), (&mut bytes as *mut u64).cast(), &mut len, std::ptr::null_mut(), 0) };
        (rc == 0 && len == std::mem::size_of::<u64>()).then_some(bytes)
    }

    pub(super) fn available() -> Option<u64> {
        let mut info = std::mem::MaybeUninit::<libc::vm_statistics64>::zeroed();
        let mut count = libc::HOST_VM_INFO64_COUNT;
        // SAFETY: `info` is a vm_statistics64 out buffer of `count` integers,
        // as HOST_VM_INFO64 expects; the host port needs no release.
        let rc = unsafe { libc::host_statistics64(mach_host_self(), libc::HOST_VM_INFO64, info.as_mut_ptr().cast(), &mut count) };
        if rc != 0 {
            return None;
        }
        // SAFETY: host_statistics64 succeeded, so it filled `info`.
        let info = unsafe { info.assume_init() };
        // SAFETY: plain query of a system constant.
        let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).ok()?;
        let pages = u64::from(info.free_count) + u64::from(info.speculative_count) + u64::from(info.inactive_count);
        Some(pages.saturating_mul(page))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const GIB: u64 = 1 << 30;

    #[test]
    fn alone_is_a_clamped_share_of_available_memory() {
        let p = MemoryPolicy::default();
        assert_eq!(p.alone(None), MemoryPolicy::CEILING_MIN);
        assert_eq!(p.alone(Some(4 * GIB)), GIB as usize);
        assert_eq!(p.alone(Some(64 * GIB)), MemoryPolicy::CEILING_MIN);
        assert_eq!(p.alone(Some(100 << 20)), MemoryPolicy::FLOOR);
        assert_eq!(p.alone(Some(u64::MAX)), MemoryPolicy::CEILING_MIN);
        let half = MemoryPolicy { percent: 50, ceiling: 16 << 30, split: true };
        assert_eq!(half.alone(Some(8 * GIB)), (4 * GIB) as usize);
    }

    #[test]
    fn share_splits_between_processes_unless_told_not_to() {
        let other = |bytes| ProcessUsage { pid: 1, bytes, idle: Duration::ZERO, busy: None };
        let p = MemoryPolicy { ceiling: 8 << 30, ..MemoryPolicy::default() };
        assert_eq!(p.share(Some(3 * GIB), GIB, &[]), GIB as usize);
        let others = vec![other(GIB / 8); 7];
        assert_eq!(p.share(Some(8 * GIB), GIB / 8, &others), (9 * GIB / 4 / 8) as usize);
        assert_eq!(p.share(Some(GIB), 0, &vec![other(0); 63]), MemoryPolicy::FLOOR);
        assert_eq!(p.share(None, 0, &others), 8 << 30);
        let alone = MemoryPolicy { split: false, ..p };
        assert_eq!(alone.share(Some(8 * GIB), 0, &others), (2 * GIB) as usize);
    }

    #[test]
    fn the_ceiling_follows_physical_memory() {
        assert_eq!(MemoryPolicy::auto_ceiling(None), 2 << 30);
        assert_eq!(MemoryPolicy::auto_ceiling(Some(12 * GIB)), 2 << 30);
        assert_eq!(MemoryPolicy::auto_ceiling(Some(96 * GIB)), 6 << 30);
        assert_eq!(MemoryPolicy::auto_ceiling(Some(512 * GIB)), 8 << 30);
        let d = Device { total_memory: Some(64 * GIB), available_memory: None, cpus: 8 };
        assert_eq!(MemoryPolicy::for_device(&d).ceiling, 4 << 30);
    }

    #[test]
    fn memory_probes_parse() {
        let meminfo = "MemTotal:       16000000 kB\nMemFree:         1000000 kB\nMemAvailable:    8000000 kB\n";
        assert_eq!(meminfo_field(meminfo, "MemAvailable:"), Some(8_000_000 * 1024));
        assert_eq!(meminfo_field(meminfo, "MemTotal:"), Some(16_000_000 * 1024));
        assert_eq!(meminfo_field("MemFree: 1 kB\n", "MemAvailable:"), None);
        assert_eq!(cgroup_limit_from("1073741824\n", "268435456\n"), Some((1 << 30, 256 << 20)));
        assert_eq!(cgroup_limit_from("max\n", "268435456\n"), None);
        if cfg!(any(target_os = "linux", target_vendor = "apple")) {
            let d = Device::probe();
            assert!(d.total_memory.is_some() && d.available_memory.is_some(), "{d:?}");
        }
    }
}
