//! The workers of the built-in backends: where asc looks for each and when
//! it installs one (docs/decompile-backends.md §12).
//!
//! A [`Tool`] is one worker executable: `asc-dexdec-worker` of dexdec,
//! `asc-arkdec-worker` of arkdec. Unless the backend's `[decompilers.<name>]`
//! table names a `command`, the worker is the first of
//! 1. the file its environment variable names ([`Tool::env`]; arkdec's
//!    `ASC_ARKDEC_WORKER`),
//! 2. the worker next to the running asc,
//! 3. the one asc installed for its protocol version and target
//!    ([`WorkerSettings::install_dir`]), for a worker that is released,
//! 4. the worker on `PATH`.
//!
//! When there is none, the first request for dexdec installs the latest
//! released worker speaking asc's protocol version (`decompile.auto_install`);
//! a failed install is not tried again for [`RETRY_AFTER`], by this process
//! or another. The worker's own version is not tied to asc's. arkdec has no
//! release: it runs only where its worker is found, and a request without
//! one falls back to the disassembly.

use asc_engine::config::{Config, DEFAULT_RELEASE_URL};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

#[cfg(feature = "installer")]
use super::install::{InstallError, InstallMode, Release};

/// The dexdec worker's executable name.
pub const WORKER_FILE: &str = if cfg!(windows) { "asc-dexdec-worker.exe" } else { "asc-dexdec-worker" };

/// The arkdec worker's executable name.
pub const ARKDEC_WORKER_FILE: &str = if cfg!(windows) { "asc-arkdec-worker.exe" } else { "asc-arkdec-worker" };

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

/// A worker executable of a built-in backend.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Tool {
    /// The backend it serves: `dexdec`, `arkdec`.
    pub backend: &'static str,
    /// The executable's name.
    pub file: &'static str,
    /// The environment variable that names the worker, looked at first.
    pub env: Option<&'static str>,
    /// Where to build it yourself.
    pub build_hint: &'static str,
    /// Whether releases exist that asc installs it from.
    pub released: bool,
}

/// `asc-dexdec-worker`, of the built-in dexdec.
pub const DEXDEC: Tool =
    Tool { backend: "dexdec", file: WORKER_FILE, env: None, build_hint: "from https://github.com/DroidASC/asc-dexdec", released: true };

/// `asc-arkdec-worker`, of arkdec (HarmonyOS records to JavaScript): not
/// released, so never installed; asc uses it where it finds it.
pub const ARKDEC: Tool = Tool {
    backend: "arkdec",
    file: ARKDEC_WORKER_FILE,
    env: Some("ASC_ARKDEC_WORKER"),
    build_hint: "from asc-arkdec: cargo build --release --bin asc-arkdec-worker",
    released: false,
};

impl Tool {
    /// The tool of built-in backend `backend`; dexdec's for any other name.
    pub fn of_backend(backend: &str) -> &'static Tool {
        if backend == ARKDEC.backend { &ARKDEC } else { &DEXDEC }
    }

    /// The file name without `.exe`, which names its install directory and release assets.
    pub fn stem(&self) -> &'static str {
        self.file.strip_suffix(".exe").unwrap_or(self.file)
    }
}

/// Where a worker was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WorkerOrigin {
    /// Named by the tool's environment variable ([`Tool::env`]).
    Env,
    /// Next to the running asc.
    BesideAsc,
    /// In asc's install directory for its protocol version.
    Managed,
    /// On `PATH`.
    Path,
}

impl WorkerOrigin {
    /// `environment`, `beside asc`, `installed` or `PATH`, as messages say it.
    pub fn name(self) -> &'static str {
        match self {
            WorkerOrigin::Env => "environment",
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

/// How asc finds a worker and whether it installs it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WorkerSettings {
    /// The worker.
    pub tool: &'static Tool,
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
        WorkerSettings { tool: &DEXDEC, auto_install: true, release_url: DEFAULT_RELEASE_URL.to_string(), data_dir: default_data_dir() }
    }
}

impl WorkerSettings {
    /// The settings `config` makes for dexdec's worker.
    pub fn from_config(config: &Config) -> WorkerSettings {
        WorkerSettings::for_tool(&DEXDEC, config)
    }

    /// The settings `config` makes for `tool`.
    pub fn for_tool(tool: &'static Tool, config: &Config) -> WorkerSettings {
        WorkerSettings {
            tool,
            auto_install: config.decompile_auto_install.value,
            release_url: config.decompile_release_url.value.0.clone(),
            data_dir: default_data_dir(),
        }
    }

    /// `<data dir>/tools/<worker>-p<protocol>-<target>/`
    /// (`asc-dexdec-worker-p1-x86_64-unknown-linux-gnu`): where asc
    /// installs the worker of its protocol version, shared by every asc that
    /// speaks it.
    pub fn install_dir(&self) -> Option<PathBuf> {
        Some(self.data_dir.as_ref()?.join("tools").join(format!("{}-p{PROTOCOL}-{TARGET}", self.tool.stem())))
    }

    /// The installed worker of asc's protocol version, if there is one; a
    /// worker without releases has none.
    pub fn managed(&self) -> Option<Worker> {
        let path = self.install_dir().filter(|_| self.tool.released)?.join(self.tool.file);
        is_executable(&path).then_some(Worker { path, origin: WorkerOrigin::Managed })
    }

    /// The worker asc uses, in the order of the module docs; `None` if there is none.
    pub fn locate(&self) -> Option<Worker> {
        self.named_by_env().or_else(|| beside_asc(self.tool.file)).or_else(|| self.managed()).or_else(|| on_path(self.tool.file))
    }

    /// The executable the tool's environment variable names.
    fn named_by_env(&self) -> Option<Worker> {
        let path = PathBuf::from(std::env::var_os(self.tool.env?).filter(|value| !value.is_empty())?);
        is_executable(&path).then_some(Worker { path, origin: WorkerOrigin::Env })
    }

    /// Why a missing worker is not installed on its own, if it is not:
    /// `decompile.auto_install` is off, asc was built without the installer,
    /// it is a debug build with the default release URL (tests and
    /// development builds stay off the network), or there is no data directory.
    pub fn auto_install_blocker(&self) -> Option<String> {
        if !self.tool.released {
            Some(format!("{} is not released, so asc does not install it", self.tool.stem()))
        } else if !self.auto_install {
            Some("decompile.auto_install is off".into())
        } else if !cfg!(feature = "installer") {
            Some("this asc was built without the installer".into())
        } else if cfg!(debug_assertions) && self.release_url == DEFAULT_RELEASE_URL {
            Some("a debug build of asc does not download it".into())
        } else if self.data_dir.is_none() {
            Some("there is no data directory ($XDG_DATA_HOME, %LOCALAPPDATA% on Windows, $HOME) to install it in".into())
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
        if !self.tool.released {
            return Err(InstallError::Unreleased { tool: self.tool.stem(), hint: self.build_hint() });
        }
        let dir = self.install_dir().ok_or_else(|| InstallError::Io {
            path: PathBuf::from("$XDG_DATA_HOME"),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no data directory: none of $XDG_DATA_HOME, %LOCALAPPDATA% (Windows) or $HOME is set",
            ),
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
            return Err(format!("{reason} (not retried for an hour; `asc install {}` tries now)", self.tool.backend));
        }
        let result = self.download();
        if let Err(reason) = &result {
            self.record_failure(reason);
        }
        result
    }

    #[cfg(feature = "installer")]
    fn download(&self) -> Result<Worker, String> {
        eprintln!("asc: {} not found; installing it from {}", self.tool.file, self.release().archive_url());
        match self.install(InstallMode::IfMissing) {
            Ok(worker) => {
                eprintln!("asc: installed {}", worker.path.display());
                Ok(worker)
            }
            Err(error @ InstallError::NotPublished { .. }) => {
                Err(format!("installing {} failed: {error}; {}", self.tool.file, WorkerSettings::unpublished_hint()))
            }
            Err(error) => Err(format!("installing {} failed: {error}", self.tool.file)),
        }
    }

    #[cfg(not(feature = "installer"))]
    fn download(&self) -> Result<Worker, String> {
        Err(self.missing_hint("this asc was built without the installer"))
    }

    /// The reason asc gives when there is no worker and it installs none:
    /// what it looked for, why it did not install it (`why`), and what to do.
    pub fn missing_hint(&self, why: &str) -> String {
        let tool = self.tool;
        if !tool.released {
            let env = tool.env.map(|env| format!("{env}, ")).unwrap_or_default();
            let set = tool.env.and_then(|env| Some((env, std::env::var_os(env).filter(|value| !value.is_empty())?)));
            let not_found = match set {
                Some((env, value)) => format!("{env}={} is not an executable file", Path::new(&value).display()),
                None => format!("{} not found ({env}next to asc, on PATH)", tool.file),
            };
            return format!("{not_found}; {}", self.build_hint());
        }
        let installed = self.install_dir().map(|dir| format!(", in {}", dir.display())).unwrap_or_default();
        format!(
            "{} not found (next to asc{installed}, on PATH) and not installed: {why}; \
             run `asc install {}`, or build it ({}) and put it next to asc or name it in [decompilers.{}] command",
            tool.file, tool.backend, tool.build_hint, tool.backend
        )
    }

    /// What to do to get a worker that is not released.
    pub fn build_hint(&self) -> String {
        let tool = self.tool;
        let env = tool.env.map(|env| format!("set {env} to it, ")).unwrap_or_default();
        format!("build it ({}) and {env}put it next to asc or name it in [decompilers.{}] command", tool.build_hint, tool.backend)
    }

    /// The hint for a release that has no worker for this asc (none speaks
    /// its protocol version yet, or none is built for its target).
    pub fn unpublished_hint() -> String {
        format!("no worker for this asc's protocol version and target is released; build it ({}) and put it next to asc", DEXDEC.build_hint)
    }
}

/// `$XDG_DATA_HOME/asc`, else on Windows `%LOCALAPPDATA%\\asc`, else
/// `~/.local/share/asc`.
fn default_data_dir() -> Option<PathBuf> {
    let var = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from);
    let base = var("XDG_DATA_HOME")
        .or_else(|| if cfg!(windows) { var("LOCALAPPDATA") } else { None })
        .or_else(|| var("HOME").map(|home| home.join(".local/share")))?;
    Some(base.join("asc"))
}

/// The worker `file` in the directory of the running asc (as started, then
/// with links resolved).
fn beside_asc(file: &str) -> Option<Worker> {
    let exe = std::env::current_exe().ok()?;
    let resolved = exe.canonicalize().ok();
    [Some(exe), resolved]
        .into_iter()
        .flatten()
        .filter_map(|exe| Some(exe.parent()?.join(file)))
        .find(|path| is_executable(path))
        .map(|path| Worker { path, origin: WorkerOrigin::BesideAsc })
}

fn on_path(file: &str) -> Option<Worker> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(file))
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
        assert!(hint.contains("asc install dexdec") && hint.contains(DEXDEC.build_hint), "{hint}");
    }

    #[test]
    fn arkdec_is_found_but_never_installed() {
        let data = tempfile::tempdir().unwrap();
        let arkdec = WorkerSettings { tool: &ARKDEC, data_dir: Some(data.path().into()), ..WorkerSettings::default() };
        assert_eq!(arkdec.install_dir().unwrap(), data.path().join(format!("tools/asc-arkdec-worker-p{PROTOCOL}-{TARGET}")));
        let blocker = arkdec.auto_install_blocker().unwrap();
        assert!(blocker.contains("not released"), "{blocker}");
        let hint = arkdec.auto_install().unwrap_err();
        assert!(hint.contains("ASC_ARKDEC_WORKER") && hint.contains("[decompilers.arkdec] command"), "{hint}");
        assert!(!hint.contains("asc install"), "nothing to install: {hint}");
        // A worker in the install directory is not one asc put there.
        let dir = arkdec.install_dir().unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(ARKDEC.file), "").unwrap();
        assert_eq!(arkdec.managed(), None);
        assert_eq!(Tool::of_backend("arkdec"), &ARKDEC);
        assert_eq!((Tool::of_backend("dexdec"), Tool::of_backend("jadx")), (&DEXDEC, &DEXDEC));
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
