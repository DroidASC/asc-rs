//! Locating and loading the sample packages. They are not in the
//! repository: loaders return `None` when a file is absent.
//!
//! Locations: `$ASC_ABC_SAMPLES` (default `<workspace>/../ark/ReArk/samples`)
//! and `$ASC_ABC_LARGE_SAMPLE` (no default: a directory holding an app-store
//! `entry.hap` and its decrypted `modules.abc`).

// Each test binary uses its own subset.
#![allow(dead_code)]

use std::io::Read;
use std::path::{Path, PathBuf};

/// The workspace root (`crates/harmony/asc-pasm/../../..`).
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

pub fn samples_dir() -> PathBuf {
    std::env::var_os("ASC_ABC_SAMPLES").map_or_else(|| workspace_root().join("../ark/ReArk/samples"), PathBuf::from)
}

/// `$ASC_ABC_LARGE_SAMPLE`; `None` when the variable is not set.
pub fn large_sample_dir() -> Option<PathBuf> {
    std::env::var_os("ASC_ABC_LARGE_SAMPLE").map(PathBuf::from)
}

fn zip_entry(archive: Vec<u8>, name: &str) -> Vec<u8> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(archive)).expect("sample is a zip archive");
    let mut entry = zip.by_name(name).unwrap_or_else(|err| panic!("{name}: {err}"));
    let mut data = Vec::new();
    entry.read_to_end(&mut data).expect("zip entry reads");
    data
}

/// Entry `entry` of the `.hap` at `path`; for an `.app`, of its inner
/// `entry-default.hap`. `None` when the sample is not there.
pub fn load_abc(path: &Path, entry: &str) -> Option<Vec<u8>> {
    let mut archive = std::fs::read(path).ok()?;
    if path.extension().is_some_and(|ext| ext == "app") {
        archive = zip_entry(archive, "entry-default.hap");
    }
    Some(zip_entry(archive, entry))
}

/// `ets/modules.abc` of a ReArk sample.
pub fn load_sample(file: &str) -> Option<Vec<u8>> {
    load_abc(&samples_dir().join(file), "ets/modules.abc")
}
