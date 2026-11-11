//! Where text too long for its reader goes: a private directory of files
//! named by their content, kept under a byte budget. The CLI writes a cut
//! output there, the MCP server a reply over its budget.

use asc_engine::asc_cache::LockExt;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

/// A directory of spilled text, kept under a byte budget (oldest first out).
pub struct SpillDir {
    dir: PathBuf,
    budget: u64,
    /// Serializes write + prune, so a prune never removes a file another
    /// call has just written and is about to name.
    lock: Mutex<()>,
}

impl SpillDir {
    pub fn new(dir: PathBuf, budget: u64) -> SpillDir {
        SpillDir { dir, budget, lock: Mutex::new(()) }
    }

    /// `out/` in the disk cache directory, else `$XDG_RUNTIME_DIR/asc/out`,
    /// else a per-user directory under the system temporary directory.
    pub fn default_dir(cache_dir: Option<&Path>) -> PathBuf {
        if let Some(d) = cache_dir {
            return d.join(asc_engine::asc_cache::SPILL_DIR);
        }
        if let Some(run) = std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
            return PathBuf::from(run).join("asc").join("out");
        }
        let user = std::env::var("USER").unwrap_or_else(|_| "user".into());
        std::env::temp_dir().join(format!("asc-{user}")).join("out")
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Write `text` (or find it already written: files are named by content)
    /// and return its path.
    pub fn write(&self, text: &str) -> io::Result<PathBuf> {
        // Guards no data: a panic under it poisons nothing.
        let _guard = self.lock.lock_or_default();
        create_private_dir(&self.dir)?;
        let digest = Sha256::digest(text.as_bytes());
        let name: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
        let path = self.dir.join(format!("{name}.txt"));
        if path.is_file() {
            // Reused: mark it recently used so the prune keeps it.
            fs::File::options().append(true).open(&path)?.set_modified(SystemTime::now())?;
        } else {
            let tmp = self.dir.join(format!("{name}.{}.tmp", std::process::id()));
            let mut f = private_file(&tmp)?;
            f.write_all(text.as_bytes())?;
            drop(f);
            fs::rename(&tmp, &path)?;
        }
        self.prune(&path);
        Ok(path)
    }

    /// Remove the least recently used files until the directory fits its
    /// budget; `keep` (just written) always stays.
    fn prune(&self, keep: &Path) {
        let Ok(rd) = fs::read_dir(&self.dir) else { return };
        let mut files: Vec<(SystemTime, PathBuf, u64)> = rd
            .flatten()
            .filter_map(|e| {
                let m = e.metadata().ok()?;
                m.is_file().then(|| (m.modified().unwrap_or(SystemTime::UNIX_EPOCH), e.path(), m.len()))
            })
            .collect();
        let mut total: u64 = files.iter().map(|f| f.2).sum();
        files.sort();
        for (_, path, len) in files {
            if total <= self.budget {
                break;
            }
            if path != keep && fs::remove_file(&path).is_ok() {
                total -= len;
            }
        }
    }
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if !dir.is_dir() {
        fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    }
    // Replies can quote an APK's strings and code: this user only.
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)
}

#[cfg(unix)]
fn private_file(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::File::options().write(true).create(true).truncate(true).mode(0o600).open(path)
}

#[cfg(not(unix))]
fn private_file(path: &Path) -> io::Result<fs::File> {
    fs::File::create(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spill_files_are_named_by_content_and_pruned() {
        let dir = tempfile::tempdir().unwrap();
        let spill = SpillDir::new(dir.path().join("out"), 40);
        let a = spill.write(&"a".repeat(30)).unwrap();
        assert_eq!(spill.write(&"a".repeat(30)).unwrap(), a, "same content, same file");
        let b = spill.write(&"b".repeat(30)).unwrap();
        // Over the 40-byte budget: the older file goes, the new one stays.
        assert!(!a.exists() && b.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&b).unwrap().permissions().mode() & 0o777, 0o600);
            assert_eq!(fs::metadata(dir.path().join("out")).unwrap().permissions().mode() & 0o777, 0o700);
        }
    }
}
