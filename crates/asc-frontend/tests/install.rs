//! Installing asc-dexdec-worker from a release served by a local server:
//! what is accepted, what is refused and leaves nothing behind.
#![cfg(unix)]

use asc_fixture::http::HttpServer;
use asc_frontend::decompile::WorkerSettings;
use asc_frontend::decompile::dexdec::{PROTOCOL, TARGET};
use asc_frontend::decompile::install::{InstallError, InstallMode, Release};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A stand-in worker: answers `--protocol-version` as the real one does,
/// with `protocol`.
fn script(protocol: &str) -> Vec<u8> {
    format!("#!/bin/sh\n[ \"$1\" = --protocol-version ] && echo '{protocol}'\n").into_bytes()
}

fn stem() -> String {
    format!("asc-dexdec-worker-p{PROTOCOL}-{TARGET}")
}

/// One tar entry, its name and link written as raw bytes so that the names a
/// release never has (`..`, absolute paths) can be built at all.
struct Entry<'a> {
    name: &'a str,
    kind: tar::EntryType,
    data: &'a [u8],
    link: &'a str,
}

impl<'a> Entry<'a> {
    fn file(name: &'a str, data: &'a [u8]) -> Entry<'a> {
        Entry { name, kind: tar::EntryType::Regular, data, link: "" }
    }

    fn dir(name: &'a str) -> Entry<'a> {
        Entry { name, kind: tar::EntryType::Directory, data: b"", link: "" }
    }

    fn link(name: &'a str, kind: tar::EntryType, target: &'a str) -> Entry<'a> {
        Entry { name, kind, data: b"", link: target }
    }
}

fn tar_gz(entries: &[Entry<'_>]) -> Vec<u8> {
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let mut builder = tar::Builder::new(gz);
    for entry in entries {
        let mut header = tar::Header::new_old();
        header.as_old_mut().name[..entry.name.len()].copy_from_slice(entry.name.as_bytes());
        header.as_old_mut().linkname[..entry.link.len()].copy_from_slice(entry.link.as_bytes());
        header.set_entry_type(entry.kind);
        header.set_mode(0o755);
        header.set_size(entry.data.len() as u64);
        header.set_cksum();
        builder.append(&header, entry.data).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

/// The archive of a good release: the directory, the worker, the license.
fn good_archive() -> Vec<u8> {
    let stem = stem();
    let worker = script(&PROTOCOL.to_string());
    tar_gz(&[
        Entry::dir(&format!("{stem}/")),
        Entry::file(&format!("{stem}/asc-dexdec-worker"), &worker),
        Entry::file(&format!("{stem}/LICENSE"), b"license"),
    ])
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

fn archive_path() -> String {
    format!("/{}.tar.gz", stem())
}

/// A server publishing `archive` with its checksum.
fn publish(archive: Vec<u8>) -> HttpServer {
    let server = HttpServer::start();
    server.route(&format!("{}.sha256", archive_path()), 200, format!("{}  {}.tar.gz\n", sha256(&archive), stem()));
    server.route(&archive_path(), 200, archive);
    server
}

fn files_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> =
        std::fs::read_dir(dir).map(|d| d.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect()).unwrap_or_default();
    names.sort();
    names
}

fn install(server: &HttpServer, dir: &Path) -> Result<PathBuf, InstallError> {
    Release::current(server.url()).install(dir, InstallMode::IfMissing)
}

#[test]
fn a_verified_worker_is_installed_executable() {
    let server = publish(good_archive());
    let dir = tempfile::tempdir().unwrap();
    let path = install(&server, dir.path()).unwrap();
    assert_eq!(path, dir.path().join("asc-dexdec-worker"));
    assert_eq!(std::fs::read(&path).unwrap(), script(&PROTOCOL.to_string()));
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o755);
    assert_eq!(files_in(dir.path()), [".lock", "asc-dexdec-worker"], "the license stays in the archive");
    assert_eq!(server.requests(), [format!("{}.sha256", archive_path()), archive_path()]);
    // Already there: kept, unless replaced.
    install(&server, dir.path()).unwrap();
    assert_eq!(server.requests().len(), 2);
    Release::current(server.url()).install(dir.path(), InstallMode::Replace).unwrap();
    assert_eq!(server.requests().len(), 4);
}

#[test]
fn a_checksum_mismatch_installs_nothing() {
    let server = publish(good_archive());
    server.route(&format!("{}.sha256", archive_path()), 200, format!("{}  x\n", "0".repeat(64)));
    let dir = tempfile::tempdir().unwrap();
    let error = install(&server, dir.path()).unwrap_err();
    assert!(matches!(&error, InstallError::Checksum { expected, .. } if *expected == "0".repeat(64)), "{error}");
    assert_eq!(files_in(dir.path()), [".lock"]);
    // Not a checksum at all.
    server.route(&format!("{}.sha256", archive_path()), 200, "<html>");
    assert!(matches!(install(&server, dir.path()), Err(InstallError::Archive { .. })));
}

#[test]
fn a_missing_release_is_not_published() {
    let server = HttpServer::start();
    let dir = tempfile::tempdir().unwrap();
    let error = install(&server, dir.path()).unwrap_err();
    assert!(matches!(&error, InstallError::NotPublished { protocol, .. } if *protocol == PROTOCOL), "{error}");
    assert!(error.to_string().contains(&format!("no asc-dexdec-worker for protocol {PROTOCOL} on {TARGET}")), "{error}");
    assert_eq!(server.requests().len(), 1, "nothing after the checksum");
    // Other HTTP errors are download errors.
    server.route(&format!("{}.sha256", archive_path()), 500, "boom");
    assert!(matches!(install(&server, dir.path()), Err(InstallError::Download { message, .. }) if message == "HTTP 500"));
}

#[test]
fn archives_holding_more_than_the_worker_are_refused() {
    let stem = stem();
    let worker = script(&PROTOCOL.to_string());
    let in_stem = |name: &str| format!("{stem}/{name}");
    let (worker_name, symlink, hardlink) = (in_stem("asc-dexdec-worker"), tar::EntryType::Symlink, tar::EntryType::Link);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("parent", tar_gz(&[Entry::file(&worker_name, &worker), Entry::file(&in_stem("../escaped"), b"x")])),
        ("absolute", tar_gz(&[Entry::file("/tmp/asc-dexdec-worker", &worker)])),
        ("outside", tar_gz(&[Entry::file("asc-dexdec-worker", &worker)])),
        ("symlink", tar_gz(&[Entry::link(&worker_name, symlink, "/bin/sh")])),
        ("hard link", tar_gz(&[Entry::link(&worker_name, hardlink, "/bin/sh")])),
        ("unexpected file", tar_gz(&[Entry::file(&worker_name, &worker), Entry::file(&in_stem("run.sh"), b"x")])),
        ("two workers", tar_gz(&[Entry::file(&worker_name, &worker), Entry::file(&worker_name, b"x")])),
        ("no worker", tar_gz(&[Entry::dir(&in_stem("")), Entry::file(&in_stem("LICENSE"), b"x")])),
        ("not gzip", b"plain bytes".to_vec()),
    ];
    for (case, archive) in cases {
        let server = publish(archive);
        let dir = tempfile::tempdir().unwrap();
        let error = install(&server, dir.path()).unwrap_err();
        assert!(matches!(error, InstallError::Archive { .. }), "{case}: {error}");
        assert_eq!(files_in(dir.path()), [".lock"], "{case}");
        assert!(!dir.path().parent().unwrap().join("escaped").exists(), "{case}");
    }
}

#[test]
fn a_worker_of_another_protocol_is_not_installed() {
    let stem = stem();
    let worker = script("9999");
    let server = publish(tar_gz(&[Entry::file(&format!("{stem}/asc-dexdec-worker"), &worker)]));
    let dir = tempfile::tempdir().unwrap();
    let error = install(&server, dir.path()).unwrap_err();
    assert!(matches!(error, InstallError::Check { .. }), "{error}");
    assert!(error.to_string().contains("\"9999\""), "{error}");
    assert_eq!(files_in(dir.path()), [".lock"]);
}

#[test]
fn concurrent_installs_download_once() {
    let server = publish(good_archive());
    server.delay(Duration::from_millis(200));
    let dir = tempfile::tempdir().unwrap();
    let paths: Vec<PathBuf> = std::thread::scope(|scope| {
        let installs: Vec<_> = (0..4).map(|_| scope.spawn(|| install(&server, dir.path()).unwrap())).collect();
        installs.into_iter().map(|install| install.join().unwrap()).collect()
    });
    assert!(paths.iter().all(|path| *path == dir.path().join("asc-dexdec-worker")), "{paths:?}");
    assert_eq!(server.requests().len(), 2, "one install downloads, the others find it: {:?}", server.requests());
    assert_eq!(files_in(dir.path()), [".lock", "asc-dexdec-worker"]);
}

/// Worker settings installing into `data` from `server`.
fn settings(server: &HttpServer, data: &Path) -> WorkerSettings {
    let mut settings = WorkerSettings::default();
    settings.release_url = server.url();
    settings.data_dir = Some(data.to_path_buf());
    settings
}

#[test]
fn auto_install_off_asks_nothing() {
    let server = publish(good_archive());
    let data = tempfile::tempdir().unwrap();
    let mut settings = settings(&server, data.path());
    settings.auto_install = false;
    let reason = settings.auto_install().unwrap_err();
    assert!(reason.contains("not installed: decompile.auto_install is off; run `asc install dexdec`"), "{reason}");
    assert!(server.requests().is_empty());
    assert!(settings.managed().is_none());
}

#[test]
fn auto_install_backs_off_after_a_failure() {
    let server = HttpServer::start();
    let data = tempfile::tempdir().unwrap();
    let unpublished = settings(&server, data.path());
    let reason = unpublished.auto_install().unwrap_err();
    assert!(reason.contains("does not exist") && reason.contains("is released; build it"), "{reason}");
    assert_eq!(server.requests().len(), 1);
    // Offline or unpublished: not asked again for a while.
    let again = unpublished.auto_install().unwrap_err();
    assert!(again.ends_with("(not retried for an hour; `asc install dexdec` tries now)"), "{again}");
    assert_eq!(server.requests().len(), 1);
    // An explicit install goes ahead, and clears the failure.
    let server = publish(good_archive());
    let published = settings(&server, data.path());
    let worker = published.install(InstallMode::Replace).unwrap();
    assert_eq!(Some(worker.clone()), published.managed());
    assert_eq!(published.recent_failure(), None);
    assert_eq!(worker.path, published.install_dir().unwrap().join("asc-dexdec-worker"));
}
