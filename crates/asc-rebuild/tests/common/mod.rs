//! Helpers shared by the integration tests.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

/// ART's `dexdump`, from `DEXDUMP=/path/to/dexdump` or the newest SDK
/// build-tools. Verifier tests skip when it is missing, so CI without an
/// Android SDK is unaffected.
pub fn dexdump() -> Option<PathBuf> {
    let found = std::env::var_os("DEXDUMP").map(PathBuf::from).or_else(|| {
        let home = std::env::var_os("HOME")?;
        let bt = Path::new(&home).join("Android/Sdk/build-tools");
        let mut dirs: Vec<_> = std::fs::read_dir(bt).ok()?.flatten().map(|e| e.path()).collect();
        dirs.sort();
        dirs.into_iter().rev().map(|d| d.join("dexdump")).find(|p| p.is_file())
    });
    if found.is_none() {
        eprintln!("dexdump not found; skipping");
    }
    found
}

/// Run `bytes` through `dexdump`, which verifies the file the way ART does,
/// and fail the test with its output when it rejects them.
pub fn assert_verifies(dexdump: &Path, name: &str, bytes: &[u8]) {
    // Tests run in parallel and may verify the same class: one file per call.
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    let call = CALLS.fetch_add(1, Ordering::Relaxed);
    let stem = name.trim_matches(|c| c == 'L' || c == ';').replace(['/', '$'], "_");
    let path = std::env::temp_dir().join(format!("asc-rebuild-dexdump-{}-{call}-{stem}.dex", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    let res = std::process::Command::new(dexdump).arg(&path).output().unwrap();
    let _ = std::fs::remove_file(&path);
    let stderr = String::from_utf8_lossy(&res.stderr);
    assert!(res.status.success() && !stderr.contains("Failure to verify"), "{name}: {stderr}");
}
