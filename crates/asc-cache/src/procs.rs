//! Registry of the resident hosts (MCP servers, GUIs) one user runs, so each
//! can size its memory budget as a share of one machine-wide budget instead
//! of every process claiming a quarter of the free memory for itself, and
//! split the CPUs with the others that are busy.
//!
//! Each process keeps a small file `<dir>/<pid>` holding its start time and
//! the bytes its memory cache holds, rewritten while it works (the file's
//! age tells a busy process from an idle one). Entries of processes that are gone
//! (killed without unregistering, or whose pid was reused) are recognised by
//! the start time and removed by whoever reads them.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Environment variable overriding [`ProcessRegistry::default_dir`].
pub const RUNTIME_DIR_ENV: &str = "DROIDASC_RUNTIME_DIR";

/// Another registered process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessUsage {
    pub pid: u32,
    /// Bytes its memory cache held at its last update.
    pub bytes: u64,
    /// Time since that update.
    pub idle: Duration,
}

/// This process's entry in a registry directory; removed on drop.
pub struct ProcessRegistry {
    dir: PathBuf,
    pid: u32,
    start: u64,
}

impl ProcessRegistry {
    /// `$DROIDASC_RUNTIME_DIR`, else `$XDG_RUNTIME_DIR/droidasc`, else
    /// `<temp dir>/droidasc-<uid>/procs`.
    pub fn default_dir() -> Option<PathBuf> {
        if let Some(d) = std::env::var_os(RUNTIME_DIR_ENV) {
            return Some(PathBuf::from(d));
        }
        if let Some(d) = std::env::var_os("XDG_RUNTIME_DIR") {
            return Some(PathBuf::from(d).join("droidasc"));
        }
        Some(std::env::temp_dir().join(format!("droidasc-{}", uid()?)).join("procs"))
    }

    /// Register this process in `dir` (created private to the user). `None`
    /// where processes cannot be told apart reliably (not Linux or macOS) or the
    /// directory is unusable, e.g. owned by someone else.
    pub fn open(dir: impl Into<PathBuf>) -> Option<ProcessRegistry> {
        let dir = dir.into();
        let pid = std::process::id();
        let start = start_time(pid)?;
        create_private_dir(&dir)?;
        let reg = ProcessRegistry { dir, pid, start };
        reg.update(0).ok()?;
        Some(reg)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Publish the bytes this process's memory cache holds now.
    pub fn update(&self, bytes: u64) -> std::io::Result<()> {
        let path = self.dir.join(self.pid.to_string());
        let tmp = self.dir.join(format!(".{}.tmp", self.pid));
        fs::File::create(&tmp)?.write_all(format!("{} {bytes}\n", self.start).as_bytes())?;
        fs::rename(&tmp, path)
    }

    /// Every other live registered process; entries of dead ones are removed.
    pub fn others(&self) -> Vec<ProcessUsage> {
        Self::others_in(&self.dir)
    }

    /// [`ProcessRegistry::others`] of `dir` for a process that does not
    /// register itself (a one-shot command).
    pub fn others_in(dir: &Path) -> Vec<ProcessUsage> {
        let mut out = Vec::new();
        let Ok(rd) = fs::read_dir(dir) else { return out };
        let me = std::process::id();
        for f in rd.flatten() {
            let Some(pid) = f.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else { continue };
            if pid == me {
                continue;
            }
            let Ok(text) = fs::read_to_string(f.path()) else { continue };
            let mut fields = text.split_whitespace().map(|v| v.parse::<u64>().ok());
            let (Some(Some(start)), Some(Some(bytes))) = (fields.next(), fields.next()) else { continue };
            if start_time(pid) == Some(start) {
                let idle = f.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.elapsed().ok()).unwrap_or_default();
                out.push(ProcessUsage { pid, bytes, idle });
            } else {
                let _ = fs::remove_file(f.path());
            }
        }
        out
    }
}

impl Drop for ProcessRegistry {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.dir.join(self.pid.to_string()));
    }
}

/// Start time of `pid` in clock ticks since boot (field 22 of
/// `/proc/<pid>/stat`): with the pid it identifies a process for good.
#[cfg(target_os = "linux")]
fn start_time(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The command name (field 2) may hold spaces and parentheses; the fields
    // after its closing parenthesis start at field 3.
    stat.rsplit_once(')')?.1.split_whitespace().nth(19)?.parse().ok()
}

/// Start time of `pid` in microseconds since the epoch.
#[cfg(target_os = "macos")]
fn start_time(pid: u32) -> Option<u64> {
    let pid = libc::c_int::try_from(pid).ok()?;
    let size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).ok()?;
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    // SAFETY: `info` is a writable buffer of `size` bytes; proc_pidinfo
    // writes at most that many and returns how many it wrote.
    let written = unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, info.as_mut_ptr().cast(), size) };
    if written != size {
        return None;
    }
    // SAFETY: proc_pidinfo filled the whole struct (checked above), and it
    // is plain integers, valid for any bytes.
    let info = unsafe { info.assume_init() };
    Some(info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn start_time(_pid: u32) -> Option<u64> {
    None
}

#[cfg(unix)]
fn uid() -> Option<u32> {
    // SAFETY: getuid has no preconditions.
    Some(unsafe { libc::getuid() })
}

#[cfg(not(unix))]
fn uid() -> Option<u32> {
    None
}

/// Create `dir` readable by the user only, and refuse one owned by someone
/// else (a world-writable temp dir could hold a planted one).
#[cfg(unix)]
fn create_private_dir(dir: &Path) -> Option<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let _ = fs::DirBuilder::new().recursive(true).mode(0o700).create(dir);
    let meta = fs::symlink_metadata(dir).ok()?;
    (meta.is_dir() && Some(meta.uid()) == uid()).then_some(())
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> Option<()> {
    fs::create_dir_all(dir).ok()
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;

    // pid 1 (init) is not readable by every user elsewhere.
    #[cfg(target_os = "linux")]
    #[test]
    fn processes_see_each_other_and_stale_entries_go() {
        let dir = tempfile::tempdir().unwrap();
        let me = ProcessRegistry::open(dir.path()).unwrap();
        me.update(123).unwrap();
        assert!(me.others().is_empty(), "never lists itself");
        // A live process (pid 1 is init) and a dead one (start time mismatch).
        let init_start = start_time(1).unwrap();
        fs::write(dir.path().join("1"), format!("{init_start} 456\n")).unwrap();
        fs::write(dir.path().join("2"), "1 789\n").unwrap();
        fs::write(dir.path().join("notes"), "x").unwrap();
        // Another registry for the same pid stands in for a second process.
        let others: Vec<_> = me.others().iter().map(|o| (o.pid, o.bytes)).collect();
        assert_eq!(others, vec![(1, 456)]);
        assert_eq!(ProcessRegistry::others_in(dir.path()).len(), 1, "readable without registering");
        assert!(me.others()[0].idle < Duration::from_secs(60), "just written");
        assert!(!dir.path().join("2").exists(), "dead entry removed");
        assert!(dir.path().join(std::process::id().to_string()).exists());
        drop(me);
        assert!(!dir.path().join(std::process::id().to_string()).exists(), "unregistered on drop");
    }

    #[test]
    fn start_time_survives_odd_command_names() {
        assert!(start_time(std::process::id()).is_some());
        assert!(start_time(u32::MAX).is_none());
    }
}
