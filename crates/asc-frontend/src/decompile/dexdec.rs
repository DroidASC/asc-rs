//! `asc-dexdec-worker`, the executable of the built-in backend: where asc
//! looks for it and when it installs it (docs/decompile-backends.md §12).
//!
//! Unless `[decompilers.dexdec]` names a `command`, the worker is the first of
//! 1. `asc-dexdec-worker` next to the running asc,
//! 2. the one asc installed for its protocol version and target
//!    ([`WorkerSettings::install_dir`]),
//! 3. `asc-dexdec-worker` on `PATH`.
//!
//! When there is none, the first request for dexdec installs the latest
//! released worker speaking asc's protocol version (`decompile.auto_install`);
//! a failed install is not tried again for [`RETRY_AFTER`], by this process
//! or another. The worker's own version is not tied to asc's.

use asc_engine::config::{Config, DEFAULT_RELEASE_URL};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

#[cfg(feature = "installer")]
use super::install::{InstallError, InstallMode, Release};

/// The worker's executable name.
pub const WORKER_FILE: &str = if cfg!(windows) { "asc-dexdec-worker.exe" } else { "asc-dexdec-worker" };

/// asc's version, as it introduces itself to the release server.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The backend protocol version asc speaks: the worker asc installs speaks
/// the same, whatever its own version.
pub const PROTOCOL: u32 = asc_decompile::protocol::PROTOCOL_VERSION;

/// The target triple asc was built for, which picks the release asset.
pub const TARGET: &str = env!("ASC_BUILD_TARGET");

/// How long a failed auto-install keeps asc from trying again.
pub const RETRY_AFTER: Duration = Duration::from_secs(60 * 60);

/// The marker of a failed auto-install in the install directory: its time
/// is the attempt's, its text the reason.
const FAILED_MARKER: &str = ".install-failed";

/// Where to build the worker yourself.
const BUILD_HINT: &str = "from https://github.com/DroidASC/asc-dexdec";

/// Where a worker was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WorkerOrigin {
    /// Next to the running asc.
    BesideAsc,
    /// In asc's install directory for its protocol version.
    Managed,
    /// On `PATH`.
    Path,
}

impl WorkerOrigin {
    /// `beside asc`, `installed` or `PATH`, as messages say it.
    pub fn name(self) -> &'static str {
        match self {
            WorkerOrigin::BesideAsc => "beside asc",
            WorkerOrigin::Managed => "installed",
            WorkerOrigin::Path => "PATH",
        }
    }
}

/// A worker executable.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Worker {
    /// The file.
    pub path: PathBuf,
    /// Where it was found.
    pub origin: WorkerOrigin,
}

/// How asc finds the worker and whether it installs it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WorkerSettings {
    /// `decompile.auto_install`: install the worker when none is found.
    pub auto_install: bool,
    /// `decompile.release_url`: where releases are downloaded from.
    pub release_url: String,
    /// asc's data directory (`$XDG_DATA_HOME/asc`, `~/.local/share/asc`);
    /// `None`: there is none, so nothing is installed.
    pub data_dir: Option<PathBuf>,
}

impl Default for WorkerSettings {
    fn default() -> WorkerSettings {
        WorkerSettings { auto_install: true, release_url: DEFAULT_RELEASE_URL.to_string(), data_dir: default_data_dir() }
    }
}

impl WorkerSettings {
    /// The settings `config` makes.
    pub fn from_config(config: &Config) -> WorkerSettings {
        WorkerSettings {
            auto_install: config.decompile_auto_install.value,
            release_url: config.decompile_release_url.value.0.clone(),
            data_dir: default_data_dir(),
        }
    }

    /// `<data dir>/tools/asc-dexdec-worker-p<protocol>-<target>/`: where asc
    /// installs the worker of its protocol version, shared by every asc that
    /// speaks it.
    pub fn install_dir(&self) -> Option<PathBuf> {
        Some(self.data_dir.as_ref()?.join("tools").join(format!("asc-dexdec-worker-p{PROTOCOL}-{TARGET}")))
    }

    /// The installed worker of asc's protocol version, if there is one.
    pub fn managed(&self) -> Option<Worker> {
        let path = self.install_dir()?.join(WORKER_FILE);
        is_executable(&path).then_some(Worker { path, origin: WorkerOrigin::Managed })
    }

    /// The worker asc uses, in the order of the module docs; `None` if there is none.
    pub fn locate(&self) -> Option<Worker> {
        beside_asc().or_else(|| self.managed()).or_else(on_path)
    }

    /// Why a missing worker is not installed on its own, if it is not:
    /// `decompile.auto_install` is off, asc was built without the installer,
    /// it is a debug build with the default release URL (tests and
    /// development builds stay off the network), or there is no data directory.
    pub fn auto_install_blocker(&self) -> Option<String> {
        if !self.auto_install {
            Some("decompile.auto_install is off".into())
        } else if !cfg!(feature = "installer") {
            Some("this asc was built without the installer".into())
        } else if cfg!(debug_assertions) && self.release_url == DEFAULT_RELEASE_URL {
            Some("a debug build of asc does not download it".into())
        } else if self.data_dir.is_none() {
            Some("there is no data directory ($XDG_DATA_HOME, $HOME) to install it in".into())
        } else {
            None
        }
    }

    /// The reason of an auto-install that failed less than [`RETRY_AFTER`] ago.
    pub fn recent_failure(&self) -> Option<String> {
        let marker = self.install_dir()?.join(FAILED_MARKER);
        let age = std::fs::metadata(&marker).and_then(|m| m.modified()).ok()?.elapsed().unwrap_or_default();
        (age < RETRY_AFTER).then(|| std::fs::read_to_string(&marker).unwrap_or_default())
    }

    /// Notes that an auto-install failed with `reason`, for [`recent_failure`](Self::recent_failure).
    pub fn record_failure(&self, reason: &str) {
        if let Some(dir) = self.install_dir() {
            let _ = std::fs::create_dir_all(&dir).and_then(|()| std::fs::write(dir.join(FAILED_MARKER), reason));
        }
    }

    /// The release asset of asc's protocol version and target.
    #[cfg(feature = "installer")]
    pub fn release(&self) -> Release {
        Release::current(&self.release_url)
    }

    /// Installs the latest released worker of asc's protocol version into
    /// [`install_dir`](Self::install_dir).
    ///
    /// # Errors
    ///
    /// As [`Release::install`]; [`InstallError::Io`] also when there is no data directory.
    #[cfg(feature = "installer")]
    pub fn install(&self, mode: InstallMode) -> Result<Worker, InstallError> {
        let dir = self.install_dir().ok_or_else(|| InstallError::Io {
            path: PathBuf::from("$XDG_DATA_HOME"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "no data directory: neither $XDG_DATA_HOME nor $HOME is set"),
        })?;
        let path = self.release().install(&dir, mode)?;
        let _ = std::fs::remove_file(dir.join(FAILED_MARKER));
        Ok(Worker { path, origin: WorkerOrigin::Managed })
    }

    /// Installs the worker, as a request that finds none does: unless
    /// [`auto_install_blocker`](Self::auto_install_blocker) says why not, or
    /// an install failed less than [`RETRY_AFTER`] ago. Progress goes to stderr.
    ///
    /// # Errors
    ///
    /// The reason the request shows: why nothing was installed, with what to do.
    pub fn auto_install(&self) -> Result<Worker, String> {
        if let Some(why) = self.auto_install_blocker() {
            return Err(self.missing_hint(&why));
        }
        if let Some(reason) = self.recent_failure() {
            return Err(format!("{reason} (not retried for an hour; `asc install dexdec` tries now)"));
        }
        let result = self.download();
        if let Err(reason) = &result {
            self.record_failure(reason);
        }
        result
    }

    #[cfg(feature = "installer")]
    fn download(&self) -> Result<Worker, String> {
        eprintln!("asc: {WORKER_FILE} not found; installing it from {}", self.release().archive_url());
        match self.install(InstallMode::IfMissing) {
            Ok(worker) => {
                eprintln!("asc: installed {}", worker.path.display());
                Ok(worker)
            }
            Err(error @ InstallError::NotPublished { .. }) => {
                Err(format!("installing {WORKER_FILE} failed: {error}; {}", WorkerSettings::unpublished_hint()))
            }
            Err(error) => Err(format!("installing {WORKER_FILE} failed: {error}")),
        }
    }

    #[cfg(not(feature = "installer"))]
    fn download(&self) -> Result<Worker, String> {
        Err(self.missing_hint("this asc was built without the installer"))
    }

    /// The reason asc gives when there is no worker and it installs none:
    /// what it looked for, why it did not install it (`why`), and what to do.
    pub fn missing_hint(&self, why: &str) -> String {
        let installed = self.install_dir().map(|dir| format!(", in {}", dir.display())).unwrap_or_default();
        format!(
            "{WORKER_FILE} not found (next to asc{installed}, on PATH) and not installed: {why}; \
             run `asc install dexdec`, or build it ({BUILD_HINT}) and put it next to asc or name it in [decompilers.dexdec] command"
        )
    }

    /// The hint for a release that has no worker for this asc (none speaks
    /// its protocol version yet, or none is built for its target).
    pub fn unpublished_hint() -> String {
        format!("no worker for this asc's protocol version and target is released; build it ({BUILD_HINT}) and put it next to asc")
    }
}

/// `$XDG_DATA_HOME/asc`, else `~/.local/share/asc`.
fn default_data_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_DATA_HOME")
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").filter(|home| !home.is_empty()).map(|home| Path::new(&home).join(".local/share")))?;
    Some(base.join("asc"))
}

/// The worker in the directory of the running asc (as started, then with
/// links resolved).
fn beside_asc() -> Option<Worker> {
    let exe = std::env::current_exe().ok()?;
    let resolved = exe.canonicalize().ok();
    [Some(exe), resolved]
        .into_iter()
        .flatten()
        .filter_map(|exe| Some(exe.parent()?.join(WORKER_FILE)))
        .find(|path| is_executable(path))
        .map(|path| Worker { path, origin: WorkerOrigin::BesideAsc })
}

fn on_path() -> Option<Worker> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(WORKER_FILE))
        .find(|path| is_executable(path))
        .map(|path| Worker { path, origin: WorkerOrigin::Path })
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else { return false };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        metadata.is_file()
    }
}

/// `(size, modification time)` of `path`: a replaced worker has another.
pub(crate) fn stamp(path: &Path) -> Option<(u64, SystemTime)> {
    let metadata = std::fs::metadata(path).ok()?;
    Some((metadata.len(), metadata.modified().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    #[test]
    fn the_install_dir_is_keyed_by_protocol_and_target() {
        let settings = WorkerSettings { data_dir: Some("/d/asc".into()), ..WorkerSettings::default() };
        assert_eq!(settings.install_dir().unwrap(), Path::new(&format!("/d/asc/tools/asc-dexdec-worker-p{PROTOCOL}-{TARGET}")));
        assert_eq!(WorkerSettings { data_dir: None, ..settings }.install_dir(), None);
    }

    #[test]
    fn auto_install_says_why_it_does_not_run() {
        let off = WorkerSettings { auto_install: false, ..WorkerSettings::default() };
        assert_eq!(off.auto_install_blocker().as_deref(), Some("decompile.auto_install is off"));
        let mirror =
            WorkerSettings { release_url: "http://127.0.0.1:1/r".into(), data_dir: Some("/d".into()), ..WorkerSettings::default() };
        assert_eq!(mirror.auto_install_blocker().is_none(), cfg!(feature = "installer"));
        let hint = off.missing_hint("decompile.auto_install is off");
        assert!(hint.contains("asc install dexdec") && hint.contains(BUILD_HINT), "{hint}");
    }

    #[test]
    fn failures_are_remembered_for_a_while() {
        let data = tempfile::tempdir().unwrap();
        let settings = WorkerSettings { data_dir: Some(data.path().into()), ..WorkerSettings::default() };
        assert_eq!(settings.recent_failure(), None);
        settings.record_failure("offline");
        assert_eq!(settings.recent_failure().as_deref(), Some("offline"));
        let marker = settings.install_dir().unwrap().join(FAILED_MARKER);
        let old = SystemTime::now() - RETRY_AFTER - Duration::from_secs(1);
        File::options().write(true).open(&marker).unwrap().set_modified(old).unwrap();
        assert_eq!(settings.recent_failure(), None, "an old failure is tried again");
    }
}
