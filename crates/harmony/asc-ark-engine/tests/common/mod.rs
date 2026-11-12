//! Where the real samples are, when they are on this machine.

#![allow(dead_code)] // each test binary uses its own part

use std::path::{Path, PathBuf};

/// The workspace root (`crates/harmony/asc-ark-engine/../../..`).
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// A ReArk sample: `$ASC_ABC_SAMPLES/<file>`, else
/// `<workspace>/../ark/ReArk/samples/<file>`. `None` when it is not there.
pub(crate) fn sample(file: &str) -> Option<PathBuf> {
    let dir = std::env::var_os("ASC_ABC_SAMPLES").map_or_else(|| workspace_root().join("../ark/ReArk/samples"), PathBuf::from);
    Some(dir.join(file)).filter(|path| path.is_file())
}

/// The directory of the large sample, `$ASC_ABC_LARGE_SAMPLE`: an
/// app-store package `entry.hap` and its decrypted `modules.abc`. There is
/// no default: `None` unless the variable is set and both files are there.
pub(crate) fn large_sample_dir() -> Option<PathBuf> {
    let dir = PathBuf::from(std::env::var_os("ASC_ABC_LARGE_SAMPLE")?);
    Some(dir).filter(|dir| dir.join("entry.hap").is_file() && dir.join("modules.abc").is_file())
}
