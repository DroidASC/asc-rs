//! Installing `asc-dexdec-worker` from a release (docs/decompile-backends.md §12).
//!
//! The asset is `asc-dexdec-worker-p<protocol>-<target>.tar.gz` under
//! `<base>/`, next to its `.sha256`, as the worker's Release workflow
//! publishes them (DroidASC/asc-dexdec, whose latest release the default
//! base names): the worker's own version is not tied to asc's, only the
//! backend protocol version it speaks is. The archive is checked against the checksum before it is
//! opened, and only the worker comes out of it: an entry other than the
//! asset's directory, the worker and the files packaged with it (a link, a
//! path outside the directory) refuses the whole archive. The worker is
//! written to a temporary file in the install directory, run once with
//! `--protocol-version`, and renamed into place; a lock file in the directory keeps
//! two asc processes from installing at once.

use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use super::worker::{PROTOCOL, TARGET, VERSION, WORKER_FILE};

/// How long a connection may take to open.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The whole of one download, redirects included: a ~10 MB archive takes
/// seconds on a working line, and a stalled one must not hold a request up for long.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);
/// The archive is read into memory; a release one is ~10 MB.
const MAX_ARCHIVE_BYTES: u64 = 256 << 20;
/// `<hex>  <file name>\n`.
const MAX_CHECKSUM_BYTES: u64 = 4 << 10;
/// Files the Release workflow packages with the worker; skipped.
const PACKAGED: &[&str] = &["LICENSE", "README.md", "README.en.md"];
/// How long the check retries a new worker the kernel will not run yet
/// because something still holds it open for writing ([`output_once_not_busy`]).
const BUSY_RETRY: Duration = Duration::from_secs(1);

/// Why an install did not complete.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum InstallError {
    /// The release has no such asset (HTTP 404): no worker speaking this
    /// protocol version, or none for this target.
    #[error("{url} does not exist (no asc-dexdec-worker for protocol {protocol} on {target})")]
    NotPublished {
        /// The URL asked for.
        url: String,
        /// The protocol version looked for.
        protocol: u32,
        /// The target looked for.
        target: String,
    },
    /// The download failed: no connection, a timeout, an HTTP error.
    #[error("cannot download {url}: {message}")]
    Download {
        /// The URL asked for.
        url: String,
        /// What went wrong.
        message: String,
    },
    /// The archive is not the one its `.sha256` names.
    #[error("{url}: SHA-256 {actual} does not match the published {expected}")]
    Checksum {
        /// The archive's URL.
        url: String,
        /// The published checksum.
        expected: String,
        /// The checksum of what was downloaded.
        actual: String,
    },
    /// The archive is malformed or holds something other than the worker.
    #[error("{url}: {message}")]
    Archive {
        /// The archive's URL.
        url: String,
        /// What is wrong with it.
        message: String,
    },
    /// The installed file does not run, or speaks another protocol version.
    #[error("{path} does not work: {message}")]
    Check {
        /// The new worker.
        path: PathBuf,
        /// What it did.
        message: String,
    },
    /// The worker has no releases to install it from (arkdec).
    #[error("{tool} has no release to install; {hint}")]
    Unreleased {
        /// The worker.
        tool: &'static str,
        /// How to get one instead.
        hint: String,
    },
    /// The install directory could not be written.
    #[error("{path}: {source}")]
    Io {
        /// The file or directory.
        path: PathBuf,
        /// The failure.
        #[source]
        source: io::Error,
    },
}

/// What [`Release::install`] does when the worker is already there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InstallMode {
    /// Keep it: another process may have installed it while this one waited for the lock.
    IfMissing,
    /// Download and replace it.
    Replace,
}

/// A worker release asset: what to download and where it goes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Release {
    /// Where the release downloads are: `<base_url>/<asset>`.
    pub base_url: String,
    /// The backend protocol version the worker must speak.
    pub protocol: u32,
    /// The target triple.
    pub target: String,
}

impl Release {
    /// The worker of this asc's protocol version and target under `base_url`.
    pub fn current(base_url: impl Into<String>) -> Release {
        Release { base_url: base_url.into(), protocol: PROTOCOL, target: TARGET.to_string() }
    }

    /// `asc-dexdec-worker-p<protocol>-<target>`: the archive's stem and the
    /// directory inside it.
    pub fn stem(&self) -> String {
        format!("asc-dexdec-worker-p{}-{}", self.protocol, self.target)
    }

    /// The URL of the archive.
    pub fn archive_url(&self) -> String {
        format!("{}/{}.tar.gz", self.base_url.trim_end_matches('/'), self.stem())
    }

    /// Installs the worker into `dir` (created if missing) and returns its path.
    ///
    /// # Errors
    ///
    /// The asset is missing or cannot be downloaded, its checksum does not
    /// match, the archive holds anything but the worker and its packaged
    /// files, the worker does not run or speaks another protocol, or `dir`
    /// cannot be written. Nothing is left in `dir` but the lock file then.
    pub fn install(&self, dir: &Path, mode: InstallMode) -> Result<PathBuf, InstallError> {
        let io_error = |path: &Path| {
            let path = path.to_path_buf();
            move |source| InstallError::Io { path, source }
        };
        fs::create_dir_all(dir).map_err(io_error(dir))?;
        let lock_path = dir.join(".lock");
        let lock = File::create(&lock_path).map_err(io_error(&lock_path))?;
        lock.lock().map_err(io_error(&lock_path))?;
        let target = dir.join(WORKER_FILE);
        if mode == InstallMode::IfMissing && target.is_file() {
            return Ok(target);
        }
        let url = self.archive_url();
        let checksum = String::from_utf8_lossy(&self.get(&format!("{url}.sha256"), MAX_CHECKSUM_BYTES)?).into_owned();
        let expected = parse_checksum(&checksum)
            .ok_or_else(|| InstallError::Archive { url: format!("{url}.sha256"), message: "not a SHA-256 checksum".into() })?;
        let archive = self.get(&url, MAX_ARCHIVE_BYTES)?;
        let actual = hex(&Sha256::digest(&archive));
        if actual != expected {
            return Err(InstallError::Checksum { url, expected, actual });
        }
        let worker = extract_worker(&archive, &self.stem()).map_err(|message| InstallError::Archive { url, message })?;
        let partial = dir.join(format!(".{WORKER_FILE}.{}.tmp", std::process::id()));
        let installed = write_executable(&partial, &worker)
            .map_err(io_error(&partial))
            .and_then(|()| self.check(&partial))
            .and_then(|()| fs::rename(&partial, &target).map_err(io_error(&target)));
        if installed.is_err() {
            let _ = fs::remove_file(&partial);
        }
        installed.map(|()| target)
    }

    /// The body of `url`, at most `limit` bytes.
    fn get(&self, url: &str, limit: u64) -> Result<Vec<u8>, InstallError> {
        let download_error = |message: String| InstallError::Download { url: url.to_string(), message };
        let mut config = ureq::Agent::config_builder()
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_global(Some(DOWNLOAD_TIMEOUT))
            .user_agent(format!("asc/{VERSION}"))
            .http_status_as_error(false);
        // The `*_PROXY` variables apply (ureq reads them), except to a mirror on this machine.
        if is_loopback(url) {
            config = config.proxy(None);
        }
        let agent: ureq::Agent = config.build().into();
        let mut response = agent.get(url).call().map_err(|e| download_error(e.to_string()))?;
        match response.status().as_u16() {
            200 => response.body_mut().with_config().limit(limit).read_to_vec().map_err(|e| download_error(e.to_string())),
            404 => Err(InstallError::NotPublished { url: url.to_string(), protocol: self.protocol, target: self.target.clone() }),
            status => Err(download_error(format!("HTTP {status}"))),
        }
    }

    /// Runs the new worker with `--protocol-version`: it must start on this
    /// machine and speak the protocol version asked for.
    fn check(&self, path: &Path) -> Result<(), InstallError> {
        let check_error = |message: String| InstallError::Check { path: path.to_path_buf(), message };
        let output =
            output_once_not_busy(Command::new(path).arg("--protocol-version"), BUSY_RETRY).map_err(|e| check_error(e.to_string()))?;
        let said = String::from_utf8_lossy(&output.stdout);
        let expected = self.protocol.to_string();
        if !output.status.success() || said.trim() != expected {
            return Err(check_error(format!("`--protocol-version` said {:?} ({}), expected {expected:?}", said.trim(), output.status)));
        }
        Ok(())
    }
}

/// Whether `url` names this machine (`localhost`, `127.0.0.1`, `[::1]`).
fn is_loopback(url: &str) -> bool {
    let authority = url.split_once("://").map_or(url, |(_, rest)| rest).split('/').next().unwrap_or_default();
    let host = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    let host =
        if host.starts_with('[') { host.split_inclusive(']').next().unwrap_or(host) } else { host.split(':').next().unwrap_or(host) };
    matches!(host.to_ascii_lowercase().as_str(), "localhost" | "127.0.0.1" | "[::1]")
}

/// The checksum of a `shasum -a 256` line: 64 hex digits, lowercased.
fn parse_checksum(text: &str) -> Option<String> {
    let digest = text.split_whitespace().next()?;
    (digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit())).then(|| digest.to_ascii_lowercase())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The worker of a release archive: the regular file `<stem>/asc-dexdec-worker`.
///
/// The only other entries allowed are the directory `<stem>/` and the
/// regular files packaged with the worker ([`PACKAGED`]); anything else
/// (links, devices, paths outside `<stem>/`, a second worker) refuses the
/// archive, since a release never holds it.
fn extract_worker(archive: &[u8], stem: &str) -> Result<Vec<u8>, String> {
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    let mut worker = None;
    for entry in tar.entries().map_err(|e| e.to_string())? {
        let mut entry = entry.map_err(|e| e.to_string())?;
        let kind = entry.header().entry_type();
        if kind == tar::EntryType::XGlobalHeader {
            continue;
        }
        let path = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
        let name = path.strip_prefix(stem).and_then(|rest| rest.strip_prefix('/'));
        match (name, kind) {
            (Some(""), tar::EntryType::Directory) => {}
            (Some(WORKER_FILE), tar::EntryType::Regular) if worker.is_none() => {
                let mut bytes = Vec::new();
                (&mut entry).take(MAX_ARCHIVE_BYTES).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
                worker = Some(bytes);
            }
            (Some(name), tar::EntryType::Regular) if PACKAGED.contains(&name) => {}
            _ => return Err(format!("unexpected entry {path:?} ({kind:?}); a release archive holds only {stem}/{WORKER_FILE}")),
        }
    }
    worker.ok_or_else(|| format!("no {stem}/{WORKER_FILE} in the archive"))
}

/// Runs `command` to completion, retrying for up to `budget` while the kernel
/// refuses to run its executable because the file is open for writing
/// (`ETXTBSY`). The installer closes the new worker before running it, but a
/// child another thread spawned while the file was open got a copy of that
/// descriptor, and close-on-exec only closes it once the child itself execs;
/// until then the file counts as open for writing.
fn output_once_not_busy(command: &mut Command, budget: Duration) -> io::Result<Output> {
    let start = Instant::now();
    let mut pause = Duration::from_millis(5);
    loop {
        match command.output() {
            Err(e) if e.kind() == io::ErrorKind::ExecutableFileBusy && start.elapsed() + pause <= budget => {
                std::thread::sleep(pause);
                pause = (pause * 2).min(Duration::from_millis(100));
            }
            done => return done,
        }
    }
}

/// Writes `bytes` to `path` as an executable, flushed to disk.
fn write_executable(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o755))?;
    }
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_follow_the_release_assets() {
        let release = Release { base_url: "https://h/r/".into(), protocol: 3, target: "x86_64-unknown-linux-gnu".into() };
        assert_eq!(release.archive_url(), "https://h/r/asc-dexdec-worker-p3-x86_64-unknown-linux-gnu.tar.gz");
    }

    #[test]
    fn only_this_machine_bypasses_the_proxy() {
        for url in ["http://127.0.0.1:8080/r", "http://localhost/r", "http://[::1]:9/r", "https://u@LOCALHOST"] {
            assert!(is_loopback(url), "{url}");
        }
        for url in ["https://github.com/Ylarod/asc-rs/releases/download", "http://127.0.0.10/r", "http://localhost.example/"] {
            assert!(!is_loopback(url), "{url}");
        }
    }

    /// A script answering `ok`, and a descriptor holding it open for writing,
    /// as a child forked by another thread holds a just written worker.
    #[cfg(unix)]
    fn busy_script(dir: &Path) -> (PathBuf, File) {
        let path = dir.join("busy.sh");
        write_executable(&path, b"#!/bin/sh\necho ok\n").unwrap();
        let writer = fs::OpenOptions::new().write(true).open(&path).unwrap();
        let refused = Command::new(&path).output().unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::ExecutableFileBusy, "{refused}");
        (path, writer)
    }

    #[cfg(unix)]
    #[test]
    fn a_busy_executable_runs_once_released() {
        let dir = tempfile::tempdir().unwrap();
        let (path, writer) = busy_script(dir.path());
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(writer);
        });
        let output = output_once_not_busy(&mut Command::new(&path), BUSY_RETRY).unwrap();
        assert_eq!(output.stdout, b"ok\n");
        release.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_busy_executable_is_given_up_on_after_the_budget() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _writer) = busy_script(dir.path());
        let start = Instant::now();
        let refused = output_once_not_busy(&mut Command::new(&path), Duration::from_millis(50)).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::ExecutableFileBusy, "{refused}");
        assert!(start.elapsed() < Duration::from_secs(1), "retried for {:?}", start.elapsed());
    }

    #[test]
    fn checksums_parse_from_shasum_lines() {
        let digest = "AB".repeat(32);
        assert_eq!(parse_checksum(&format!("{digest}  a.tar.gz\n")), Some("ab".repeat(32)));
        assert_eq!(parse_checksum("abc  a.tar.gz"), None);
        assert_eq!(parse_checksum(""), None);
    }
}
