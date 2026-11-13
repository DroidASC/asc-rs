//! The file a backend reads for one ABC entry of a HarmonyOS program
//! (docs/decompile-backends.md §6.5).
//!
//! A backend is handed one ABC file and the SHA-256 of the bytes asc read.
//! An entry that is a file of its own (a bare `.abc`, a decrypted stand-in,
//! a file of an unpacked package) is passed as it is. An entry inside a zip
//! is written out once, under its content's name:
//! `<cache>/decompilers/abc/<sha[0..2]>/<sha>.abc`, never rewritten unless a
//! backend finds it is not what its name says. Without a disk cache the
//! files go to a temporary directory that lives as long as the
//! [`Decompilers`](super::Decompilers). Writing one prunes the oldest files
//! once the directory holds more than [`BUDGET`].

use asc_decompile::protocol::methods::ProgramInput;
use asc_engine::asc_cache::DECOMPILERS_DIR;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

/// Where the written entries go, under the backends' directory of the cache.
const DIR: &str = "abc";
/// What the written entries may take on disk before the oldest go.
const BUDGET: u64 = 2 << 30;

/// One ABC entry as a backend is handed it.
#[derive(Debug, Clone)]
pub(super) struct AbcFile<'a> {
    /// The file to read (absolute).
    pub(super) file: PathBuf,
    /// Lower-case hex SHA-256 of `bytes`.
    pub(super) sha256: String,
    /// The entry's name in the program (`entry.hap/ets/modules.abc`).
    pub(super) entry: &'a str,
    /// The bytes asc read for the entry.
    pub(super) bytes: &'a [u8],
}

impl<'a> AbcFile<'a> {
    /// The entry, read from `file` instead.
    pub(super) fn with_file(&self, file: PathBuf) -> AbcFile<'a> {
        AbcFile { file, ..self.clone() }
    }

    /// The `program/open` input.
    pub(super) fn program_input(&self) -> ProgramInput {
        ProgramInput::Abc { files: vec![self.file.clone()], sha256: Some(self.sha256.clone()), entry: Some(self.entry.to_string()) }
    }
}

/// The directory entries are written to.
pub(super) struct Store {
    /// In the disk cache; `None`: a temporary directory.
    dir: Option<PathBuf>,
    temp: Mutex<Option<tempfile::TempDir>>,
}

impl Store {
    /// Files under `cache` (the disk cache's directory), else in a temporary directory.
    pub(super) fn new(cache: Option<&Path>) -> Store {
        Store { dir: cache.map(|cache| cache.join(DECOMPILERS_DIR).join(DIR)), temp: Mutex::new(None) }
    }

    /// The entry `entry` with these `bytes` (whose SHA-256 is `sha256`), as
    /// a backend reads it: `own` when the entry is a file of its own, else
    /// the bytes written out.
    ///
    /// # Errors
    ///
    /// The directory or the file could not be written.
    pub(super) fn file<'a>(&self, entry: &'a str, bytes: &'a [u8], sha256: [u8; 32], own: Option<&Path>) -> io::Result<AbcFile<'a>> {
        let sha256 = hex(&sha256);
        let file = match own {
            Some(own) => std::path::absolute(own)?,
            None => self.write(bytes, &sha256, false)?,
        };
        Ok(AbcFile { file, sha256, entry, bytes })
    }

    /// `abc`'s bytes written out again, over whatever has their name: the
    /// backend found the file is not what asc hashed.
    ///
    /// # Errors
    ///
    /// The directory or the file could not be written.
    pub(super) fn rewrite(&self, abc: &AbcFile<'_>) -> io::Result<PathBuf> {
        self.write(abc.bytes, &abc.sha256, true)
    }

    fn root(&self) -> io::Result<PathBuf> {
        if let Some(dir) = &self.dir {
            return Ok(dir.clone());
        }
        let mut temp = self.temp.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if temp.is_none() {
            *temp = Some(tempfile::Builder::new().prefix("asc-abc-").tempdir()?);
        }
        Ok(temp.as_ref().map(|dir| dir.path().to_path_buf()).unwrap_or_default())
    }

    /// `<root>/<sha[0..2]>/<sha>.abc`, written unless it is there (`replace`: always).
    fn write(&self, bytes: &[u8], sha256: &str, replace: bool) -> io::Result<PathBuf> {
        let root = self.root()?;
        let dir = root.join(&sha256[..2]);
        let path = dir.join(format!("{sha256}.abc"));
        if !replace && fs::metadata(&path).is_ok_and(|m| m.is_file() && m.len() == bytes.len() as u64) {
            // Used now: the last to be pruned.
            let _ = fs::File::options().write(true).open(&path).and_then(|file| file.set_modified(SystemTime::now()));
            return Ok(path);
        }
        fs::create_dir_all(&dir)?;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let tmp = dir.join(format!("{sha256}.{}.{}.tmp", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
        let written = create_private(&tmp).and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        });
        if let Err(error) = written.and_then(|()| fs::rename(&tmp, &path)) {
            let _ = fs::remove_file(&tmp);
            return Err(error);
        }
        prune(&root, &path, BUDGET);
        Ok(path)
    }
}

/// A new file only its owner may read.
fn create_private(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::File::options();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// Removes the least recently used `.abc` files under `root` but `keep`
/// until they take at most `budget` bytes. A file that cannot be removed (a
/// backend has it mapped, on Windows) stays.
fn prune(root: &Path, keep: &Path, budget: u64) {
    let mut files: Vec<(SystemTime, u64, PathBuf)> = Vec::new();
    for dir in fs::read_dir(root).into_iter().flatten().flatten() {
        for file in fs::read_dir(dir.path()).into_iter().flatten().flatten() {
            let path = file.path();
            let Ok(metadata) = file.metadata() else { continue };
            if metadata.is_file() && path.extension().is_some_and(|extension| extension == "abc") {
                files.push((metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH), metadata.len(), path));
            }
        }
    }
    let mut total: u64 = files.iter().map(|(_, len, _)| len).sum();
    files.sort();
    for (_, len, path) in files {
        if total <= budget {
            break;
        }
        if path != keep && fs::remove_file(&path).is_ok() {
            total -= len;
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(bytes).into()
    }

    #[test]
    fn entries_are_written_once_under_their_content() {
        let cache = tempfile::tempdir().unwrap();
        let store = Store::new(Some(cache.path()));
        let bytes = b"PANDA\0\0\0 not really".as_slice();
        let abc = store.file("entry.hap/ets/modules.abc", bytes, sha256(bytes), None).unwrap();
        let hex = hex(&sha256(bytes));
        assert_eq!(abc.sha256, hex);
        assert_eq!(abc.file, cache.path().join(format!("decompilers/abc/{}/{hex}.abc", &hex[..2])));
        assert_eq!(fs::read(&abc.file).unwrap(), bytes);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&abc.file).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // There already: kept as it is, damaged or not, until a backend says so.
        fs::write(&abc.file, b"PANDA\0\0\0 not reallX").unwrap();
        let again = store.file("entry.hap/ets/modules.abc", bytes, sha256(bytes), None).unwrap();
        assert_eq!((again.file.as_path(), fs::read(&again.file).unwrap()), (abc.file.as_path(), b"PANDA\0\0\0 not reallX".to_vec()));
        assert_eq!(store.rewrite(&again).unwrap(), abc.file);
        assert_eq!(fs::read(&abc.file).unwrap(), bytes);
        assert_eq!(fs::read_dir(abc.file.parent().unwrap()).unwrap().count(), 1, "no temporary file is left");

        // A file of its own is read where it is.
        let own = cache.path().join("modules.abc");
        let input = store.file("modules.abc", bytes, sha256(bytes), Some(&own)).unwrap();
        assert_eq!(input.file, own);
        assert_eq!(
            serde_json::to_value(input.program_input()).unwrap(),
            serde_json::json!({"kind": "abc", "files": [own], "sha256": hex, "entry": "modules.abc"})
        );
    }

    #[test]
    fn without_a_cache_entries_go_to_a_temporary_directory() {
        let store = Store::new(None);
        let abc = store.file("e", b"abc", sha256(b"abc"), None).unwrap();
        assert_eq!(fs::read(&abc.file).unwrap(), b"abc");
        let temp = abc.file.parent().unwrap().parent().unwrap().to_path_buf();
        drop(store);
        assert!(!temp.exists(), "removed with the store");
    }

    #[test]
    fn the_oldest_files_go_past_the_budget() {
        let root = tempfile::tempdir().unwrap();
        let old = SystemTime::now() - Duration::from_secs(600);
        let mut paths = Vec::new();
        for (i, name) in ["aa", "bb", "cc"].iter().enumerate() {
            let dir = root.path().join(name);
            fs::create_dir_all(&dir).unwrap();
            let path = dir.join(format!("{name}.abc"));
            fs::write(&path, [0u8; 10]).unwrap();
            fs::File::options().write(true).open(&path).unwrap().set_modified(old + Duration::from_secs(i as u64)).unwrap();
            paths.push(path);
        }
        // `aa` is the oldest but the one just written: `bb` goes, then `cc`.
        prune(root.path(), &paths[0], 15);
        assert_eq!(paths.iter().map(|p| p.exists()).collect::<Vec<_>>(), [true, false, false]);
        prune(root.path(), &paths[0], 0);
        assert!(paths[0].exists());
    }
}
