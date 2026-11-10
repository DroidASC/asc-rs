//! Opening a HarmonyOS program: the ABC files a path names.
//!
//! A path is a `.hap` / `.hsp` (zip with `ets/*.abc`), an `.app` (zip of
//! such packages), a bare `.abc` file, a directory of those, or several
//! paths joined with `,`. Whatever it is, the result is a flat list of ABC
//! entries named like the DEX side names its entries: `ets/modules.abc` for a
//! lone package, `entry.hap/ets/modules.abc` when the program has several
//! packages or comes from an `.app`.
//!
//! Stored entries are used in place from the file mapping (also through a
//! stored inner package of an `.app`). A Deflate inner package or ABC entry is
//! inflated into memory and kept for the life of the program.

use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::SystemTime;

use asc_abc::{Abc, AbcError, Header};
use asc_apk::{Apk, Limits, METHOD_STORED};

use crate::manifest::Document;
use crate::{EngineError, Result};

/// Directory levels a walk descends.
const MAX_DEPTH: usize = 8;
/// Most bytes one Deflate entry (an inner package of an `.app`, or an ABC
/// entry someone recompressed) may inflate to: it is held in memory.
const MAX_INFLATED_BYTES: u64 = 1 << 30;
const ZIP_MAGIC: &[u8] = b"PK";

/// What kind of HarmonyOS input a file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// A bare ABC file.
    Abc,
    /// A module package: `.hap` or `.hsp`.
    Hap,
    /// An application package: a zip of module packages.
    App,
}

impl Format {
    /// The format of the file at `path`, by content first (the `PANDA` magic;
    /// a zip holding `module.json`, `ets/*.abc` or `*.hap` / `*.hsp`), then
    /// by extension. `None` for anything else, a directory included.
    pub fn detect(path: &Path) -> Option<Format> {
        if !path.is_file() {
            return None;
        }
        let mut magic = [0u8; 8];
        let read = fs::File::open(path).and_then(|mut file| file.read(&mut magic)).unwrap_or(0);
        if read == magic.len() && magic == asc_abc::MAGIC {
            return Some(Format::Abc);
        }
        let by_content = if magic.starts_with(ZIP_MAGIC) { Apk::open(path).ok().and_then(|zip| Format::of_zip(&zip)) } else { None };
        by_content.or_else(|| Format::of_extension(path))
    }

    /// Whether `spec` (a file, a directory, or paths joined with `,`) names
    /// at least one HarmonyOS input: what a front end asks before choosing
    /// this engine.
    pub fn accepts(spec: &Path) -> bool {
        sources(spec).is_ok_and(|files| files.iter().any(|file| Format::detect(&file.path).is_some()))
    }

    fn of_extension(path: &Path) -> Option<Format> {
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        match ext.as_str() {
            "abc" => Some(Format::Abc),
            "hap" | "hsp" => Some(Format::Hap),
            "app" => Some(Format::App),
            _ => None,
        }
    }

    fn of_zip(zip: &Apk) -> Option<Format> {
        let mut found = None;
        // Only the names are looked at; no entry is kept.
        let scan = zip.entries_filtered(|name| {
            if is_package(name) {
                found = Some(Format::App);
            } else if found.is_none() && (name == b"module.json" || is_abc(name)) {
                found = Some(Format::Hap);
            }
            false
        });
        scan.ok().and(found)
    }
}

/// `ets/<name>.abc`: the code of a module package.
fn is_abc(name: &[u8]) -> bool {
    name.strip_prefix(b"ets/").is_some_and(|rest| rest.ends_with(b".abc") && !rest.contains(&b'/'))
}

/// A root-level `*.hap` / `*.hsp`: a module package inside an `.app`.
fn is_package(name: &[u8]) -> bool {
    !name.contains(&b'/') && (name.ends_with(b".hap") || name.ends_with(b".hsp"))
}

/// Whether an ABC entry can be queried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryStatus {
    Readable,
    /// The header is plain, the body is ciphertext (app-store protection).
    Encrypted,
    /// Not an ABC file, or damaged; the reason.
    Unreadable(String),
}

/// One ABC entry of a program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryInfo {
    /// `ets/modules.abc`, `entry.hap/ets/modules.abc`, or a bare file's name.
    pub name: String,
    pub size: u64,
    /// `None` when not even the header could be read.
    pub version: Option<asc_abc::Version>,
    pub status: EntryStatus,
}

/// Where the bytes of an entry are.
enum Source {
    /// A stored zip entry, read in place.
    Stored { container: usize, entry: asc_apk::Entry },
    /// A bare `.abc` file: the whole mapping.
    Bare { container: usize, file_name: String },
    /// A Deflate zip entry, inflated when the program was opened.
    Inflated(Vec<u8>),
}

struct AbcEntry {
    info: EntryInfo,
    source: Source,
    header: Option<Header>,
    /// Index of the package the entry is part of; `None` for a bare file.
    package: Option<usize>,
    /// Whether its class index is sorted, asked once: a cross-file lookup
    /// misses in most files, and a miss in a sorted index costs a binary search.
    sorted: OnceLock<bool>,
}

/// The name of the compiled resource table at the root of a module package.
const RESOURCE_INDEX: &[u8] = b"resources.index";

/// A zip entry that is read when it is first asked for: in place when it is
/// stored, inflated once and kept when it is Deflate.
struct LazyEntry {
    container: usize,
    entry: asc_apk::Entry,
    /// The inflated bytes of a Deflate entry, or why it does not inflate.
    inflated: OnceLock<std::result::Result<Vec<u8>, String>>,
}

/// A module package (`.hap` / `.hsp`) or application package (`.app`) of a
/// program, with the metadata documents at its root.
pub(crate) struct Package {
    /// The prefix of its entries (`entry.hap`), or for a lone file, whose
    /// entries have none, the file's name.
    pub(crate) name: String,
    documents: Vec<(Document, Source)>,
    /// The zip the package is, in `Program::containers`.
    container: usize,
    /// Its `resources.index`, when it has one.
    resources: Option<LazyEntry>,
    /// Whether it holds other packages (an `.app`) instead of a module.
    pub(crate) is_bundle: bool,
}

/// One file of a program and the name its entries are prefixed with (empty
/// for a lone file).
struct SourceFile {
    path: PathBuf,
    label: String,
    /// Read while listing it, so a [`Stamp`] needs no second `stat`.
    meta: fs::Metadata,
}

/// Which files a program is read from, with their sizes and modification
/// times: what the DEX side calls the version of an opened program. Two
/// stamps of one path are equal when opening it again would read the same
/// files ([`Engine::is_current`](crate::Engine::is_current)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stamp(Vec<(PathBuf, u64, Option<SystemTime>)>);

impl Stamp {
    /// The files `spec` (as [`Engine::open`](crate::Engine::open) takes it)
    /// names now. Costs a directory walk and a `stat` per file, no mapping.
    ///
    /// # Errors
    /// As opening does for a path that is not there or names no HarmonyOS file.
    pub fn of(spec: &Path) -> Result<Stamp> {
        Ok(Stamp::of_sources(&sources(spec)?))
    }

    fn of_sources(files: &[SourceFile]) -> Stamp {
        Stamp(files.iter().map(|file| (file.path.clone(), file.meta.len(), file.meta.modified().ok())).collect())
    }
}

/// What a program holds in memory, in bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ProgramBytes {
    /// On the heap: Deflate inner packages and entries, inflated when the
    /// program was opened.
    pub(crate) inflated: usize,
    /// Read in place from the mapped files (code and documents; not the
    /// rest of a package): pages the system reads on demand and may drop again.
    pub(crate) mapped: usize,
}

/// The ABC entries of a program and the mappings they live in.
pub(crate) struct Program {
    path: PathBuf,
    /// Every opened file and inner package; entries index into it.
    containers: Vec<Apk>,
    entries: Vec<AbcEntry>,
    /// In the order they were opened: an `.app` ahead of its inner packages.
    packages: Vec<Package>,
    notes: Vec<String>,
    /// The files as they were listed, before any of them was mapped: a file
    /// replaced while the program opened makes the stamp stale, not wrong.
    stamp: Stamp,
}

impl Program {
    pub(crate) fn open(spec: &Path) -> Result<Program> {
        let files = sources(spec)?;
        let mut program = Program {
            path: spec.to_path_buf(),
            containers: Vec::new(),
            entries: Vec::new(),
            packages: Vec::new(),
            notes: Vec::new(),
            stamp: Stamp::of_sources(&files),
        };
        let lone = files.len() == 1;
        for file in &files {
            // One bad file of several is skipped; a lone one is the error.
            match program.add_file(file) {
                Ok(()) => {}
                Err(err) if lone => return Err(err),
                Err(err) => program.notes.push(format!("{}: skipped: {}", file.label, without_path(&err))),
            }
        }
        program.pair_decrypted();
        for entry in &program.entries {
            match &entry.info.status {
                EntryStatus::Readable => {}
                EntryStatus::Encrypted => {
                    program.notes.push(format!("{} is encrypted (app-store protection); supply the decrypted .abc", entry.info.name));
                }
                EntryStatus::Unreadable(reason) => program.notes.push(format!("{}: unreadable: {reason}", entry.info.name)),
            }
        }
        if program.entries.is_empty() {
            return Err(EngineError::NoCode { path: program.path, notes: program.notes });
        }
        Ok(program)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn notes(&self) -> &[String] {
        &self.notes
    }

    pub(crate) fn stamp(&self) -> &Stamp {
        &self.stamp
    }

    /// What the program holds: the inflated copies it owns, and the code and
    /// documents it reads in place from the mapped files.
    pub(crate) fn memory(&self) -> ProgramBytes {
        let sources = self
            .entries
            .iter()
            .map(|entry| &entry.source)
            .chain(self.packages.iter().flat_map(|package| package.documents.iter().map(|(_, source)| source)));
        let mut bytes = ProgramBytes { inflated: self.containers.iter().map(Apk::owned_bytes).sum(), mapped: 0 };
        for source in sources {
            match source {
                Source::Inflated(inflated) => bytes.inflated += inflated.capacity(),
                Source::Stored { .. } | Source::Bare { .. } => bytes.mapped += self.source_bytes(source).len(),
            }
        }
        for index in self.packages.iter().filter_map(|package| package.resources.as_ref()) {
            match index.inflated.get() {
                Some(inflated) => bytes.inflated += inflated.as_ref().map_or(0, Vec::capacity),
                None if index.entry.method == METHOD_STORED => bytes.mapped += usize::try_from(index.entry.uncomp_size).unwrap_or(0),
                // A Deflate index nobody asked for yet: nothing is held.
                None => {}
            }
        }
        bytes
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn info(&self, index: usize) -> Option<&EntryInfo> {
        self.entries.get(index).map(|entry| &entry.info)
    }

    pub(crate) fn infos(&self) -> impl Iterator<Item = &EntryInfo> {
        self.entries.iter().map(|entry| &entry.info)
    }

    /// The raw bytes of entry `index`; empty when it is out of range.
    pub(crate) fn bytes(&self, index: usize) -> &[u8] {
        self.entries.get(index).map_or(&[], |entry| self.source_bytes(&entry.source))
    }

    fn source_bytes<'p>(&'p self, source: &'p Source) -> &'p [u8] {
        match source {
            // Read once when the program was opened; the mapping has not changed since.
            Source::Stored { container, entry } => self.containers[*container].raw_payload(entry).unwrap_or_default(),
            Source::Bare { container, .. } => self.containers[*container].lone_data().unwrap_or_default(),
            Source::Inflated(bytes) => bytes,
        }
    }

    /// The packages of the program, in the order they were opened.
    pub(crate) fn packages(&self) -> &[Package] {
        &self.packages
    }

    /// The bytes of `document` at the root of package `package`, when the
    /// package has it: in place from the mapping when the entry is stored.
    pub(crate) fn document(&self, package: usize, document: Document) -> Option<&[u8]> {
        let (_, source) = self.packages.get(package)?.documents.iter().find(|(kind, _)| *kind == document)?;
        Some(self.source_bytes(source))
    }

    /// The package ABC entry `index` is part of; `None` for a bare file
    /// that stands in for no package entry.
    pub(crate) fn package_of(&self, index: usize) -> Option<usize> {
        self.entries.get(index)?.package
    }

    /// The bytes of `resources.index` of package `package`: `None` when the
    /// package has none, the reason when the entry cannot be read. A stored
    /// entry is read in place from the mapping; a Deflate one is inflated
    /// the first time and kept.
    pub(crate) fn resource_index(&self, package: usize) -> Option<std::result::Result<&[u8], String>> {
        let index = self.packages.get(package)?.resources.as_ref()?;
        let zip = &self.containers[index.container];
        if index.entry.method == METHOD_STORED {
            return Some(zip.raw_payload(&index.entry).map_err(|err| err.to_string()));
        }
        let inflated =
            index.inflated.get_or_init(|| zip.read_entry(&index.entry).map(std::borrow::Cow::into_owned).map_err(|err| err.to_string()));
        Some(inflated.as_deref().map_err(String::clone))
    }

    /// Whether package `package` has a file at `path`: only the names of
    /// its zip are looked at.
    pub(crate) fn has_file(&self, package: usize, path: &str) -> bool {
        let Some(package) = self.packages.get(package) else { return false };
        self.containers[package.container].entries_filtered(|name| name == path.as_bytes()).is_ok_and(|found| !found.is_empty())
    }

    /// The file `path` of package `package`, read from its zip now: `None`
    /// when the package has no such entry. Nothing of it is kept.
    pub(crate) fn file(&self, package: usize, path: &str) -> Result<Option<std::borrow::Cow<'_, [u8]>>> {
        let Some(package) = self.packages.get(package) else { return Ok(None) };
        let zip = &self.containers[package.container];
        // The zip of a package is one archive: an entry is found by its name alone.
        let Some(entry) = zip.entries_filtered(|name| name == path.as_bytes())?.pop() else { return Ok(None) };
        Ok(Some(zip.read_entry(&entry)?))
    }

    /// The entries of package `package` (`None`: the bare files that stand
    /// in for no package entry), by index.
    pub(crate) fn entries_of(&self, package: Option<usize>) -> impl Iterator<Item = usize> + '_ {
        self.entries.iter().enumerate().filter(move |(_, entry)| entry.package == package).map(|(index, _)| index)
    }

    /// Entry `index` as an ABC file, when it is readable. The layout was
    /// checked when the program was opened, so this only reads the header.
    pub(crate) fn abc(&self, index: usize) -> Option<Abc<'_>> {
        let entry = self.entries.get(index)?;
        match entry.info.status {
            EntryStatus::Readable => {
                let abc = Abc::parse_lenient(self.bytes(index)).ok()?;
                Some(abc.with_sorted_classes(*entry.sorted.get_or_init(|| abc.classes_are_sorted())))
            }
            EntryStatus::Encrypted | EntryStatus::Unreadable(_) => None,
        }
    }

    /// The readable entries with their index.
    pub(crate) fn readable(&self) -> impl Iterator<Item = (usize, Abc<'_>)> {
        (0..self.entries.len()).filter_map(|index| Some((index, self.abc(index)?)))
    }

    fn add_file(&mut self, file: &SourceFile) -> Result<()> {
        let apk = open_archive(&file.path)?;
        let data = apk.lone_data().unwrap_or_default();
        if data.starts_with(&asc_abc::MAGIC) {
            let file_name = name_of(&file.path);
            let name = if file.label.is_empty() { file_name.clone() } else { file.label.clone() };
            let container = self.push_container(apk);
            self.push_entry(name, Source::Bare { container, file_name }, None);
            return Ok(());
        }
        let shown = if file.label.is_empty() { name_of(&file.path) } else { file.label.clone() };
        let found = self.add_package(apk, &file.label, &shown, Nesting::Allowed)?;
        if found == 0 {
            self.notes.push(format!("{shown}: no ets/*.abc"));
        }
        Ok(())
    }

    /// Add a package, named `shown`: its ABC entries (prefixed with
    /// `prefix`), its metadata documents and, for an `.app`, its inner
    /// packages. Returns how many ABC entries were added.
    fn add_package(&mut self, zip: Apk, prefix: &str, shown: &str, nesting: Nesting) -> Result<usize> {
        let members = zip.entries_filtered(|name| {
            is_abc(name)
                || name == RESOURCE_INDEX
                || Document::of_entry(name).is_some()
                || (nesting == Nesting::Allowed && is_package(name))
        })?;
        let container = self.push_container(zip);
        self.packages.push(Package { name: shown.to_owned(), documents: Vec::new(), container, resources: None, is_bundle: false });
        let package = self.packages.len() - 1;
        let mut found = 0;
        for member in members {
            let name = if prefix.is_empty() { member.name.clone() } else { format!("{prefix}/{}", member.name) };
            if member.name.as_bytes() == RESOURCE_INDEX {
                // Read when a query asks for it.
                self.packages[package].resources = Some(LazyEntry { container, entry: member, inflated: OnceLock::new() });
                continue;
            }
            if is_package(member.name.as_bytes()) {
                self.packages[package].is_bundle = true;
                // A broken inner package does not take the others with it.
                let inner = self.containers[container].open_nested(&member).map_err(EngineError::from);
                match inner.and_then(|inner| self.add_package(inner, &name, &name, Nesting::Inner)) {
                    Ok(0) => self.notes.push(format!("{name}: no ets/*.abc")),
                    Ok(n) => found += n,
                    Err(err) => self.notes.push(format!("{name}: skipped: {err}")),
                }
                continue;
            }
            let document = Document::of_entry(member.name.as_bytes());
            let source = if member.method == METHOD_STORED {
                self.containers[container].raw_payload(&member).map(|_| Source::Stored { container, entry: member })
            } else {
                self.containers[container].read_entry(&member).map(|bytes| Source::Inflated(bytes.into_owned()))
            };
            match (source, document) {
                (Ok(source), Some(document)) => self.packages[package].documents.push((document, source)),
                (Ok(source), None) => {
                    self.push_entry(name, source, Some(package));
                    found += 1;
                }
                (Err(err), _) => self.notes.push(format!("{name}: skipped: {err}")),
            }
        }
        Ok(found)
    }

    fn push_container(&mut self, apk: Apk) -> usize {
        self.containers.push(apk);
        self.containers.len() - 1
    }

    fn push_entry(&mut self, name: String, source: Source, package: Option<usize>) {
        self.entries.push(AbcEntry {
            info: EntryInfo { name, size: 0, version: None, status: EntryStatus::Readable },
            source,
            header: None,
            package,
            sorted: OnceLock::new(),
        });
        let index = self.entries.len() - 1;
        let bytes = self.bytes(index);
        let header = Header::parse(bytes).ok();
        let status = match Abc::parse(bytes) {
            Ok(_) => EntryStatus::Readable,
            Err(AbcError::Encrypted { .. }) => EntryStatus::Encrypted,
            Err(err) => EntryStatus::Unreadable(err.to_string()),
        };
        let size = bytes.len() as u64;
        let entry = &mut self.entries[index];
        entry.info.size = size;
        entry.info.version = header.map(|header| header.version);
        entry.info.status = status;
        entry.header = header;
    }

    /// Let a bare decrypted `.abc` stand in for the encrypted package entry
    /// it was dumped from: the same version, size and checksum in the header,
    /// and a body that really has that checksum. Its file name does not
    /// matter (`modules.abc`, `entry.hap.abc`, ...). The bare file takes the
    /// entry's name, place and package.
    fn pair_decrypted(&mut self) {
        let mut used = HashSet::new();
        let mut replaced_by = Vec::with_capacity(self.entries.len());
        for encrypted in 0..self.entries.len() {
            let stand_in = self.stand_in_for(encrypted, &used);
            used.extend(stand_in);
            replaced_by.push(stand_in);
        }
        if used.is_empty() {
            return;
        }
        let mut slots: Vec<Option<AbcEntry>> = std::mem::take(&mut self.entries).into_iter().map(Some).collect();
        for (index, stand_in) in replaced_by.into_iter().enumerate() {
            if used.contains(&index) {
                continue;
            }
            let Some(mut entry) = slots[index].take() else { continue };
            if let Some(mut stand_in) = stand_in.and_then(|bare| slots[bare].take()) {
                stand_in.info.name = std::mem::take(&mut entry.info.name);
                stand_in.package = entry.package;
                entry = stand_in;
            }
            self.entries.push(entry);
        }
    }

    /// The bare entry that pairs with entry `encrypted`, if that one is
    /// encrypted and such a file is there; `used` are already paired. A file
    /// named as the entry that does not pair is reported in the notes.
    fn stand_in_for(&mut self, encrypted: usize, used: &HashSet<usize>) -> Option<usize> {
        let entry = &self.entries[encrypted];
        if entry.info.status != EntryStatus::Encrypted {
            return None;
        }
        let header = entry.header?;
        let name = entry.info.name.clone();
        let base = name.rsplit('/').next().unwrap_or_default();
        for bare in 0..self.entries.len() {
            let candidate = &self.entries[bare];
            let same_name = matches!(&candidate.source, Source::Bare { file_name, .. } if file_name == base);
            let is_bare = matches!(candidate.source, Source::Bare { .. });
            if !is_bare || candidate.info.status != EntryStatus::Readable || used.contains(&bare) {
                continue;
            }
            let same_header = candidate
                .header
                .is_some_and(|h| (h.version, h.file_size, h.checksum) == (header.version, header.file_size, header.checksum));
            let bare_name = &candidate.info.name;
            if !same_header {
                if same_name {
                    self.notes.push(format!("{bare_name} does not pair with the encrypted {name}: version, size or checksum differ"));
                }
            } else if self.abc(bare).is_some_and(|abc| abc.compute_checksum() != header.checksum) {
                self.notes.push(format!("{bare_name} does not pair with the encrypted {name}: its body does not have the checksum"));
            } else {
                self.notes.push(format!("{name} is encrypted in its package; served from the decrypted {bare_name}"));
                return Some(bare);
            }
        }
        None
    }
}

/// Whether a package may hold inner packages: an `.app` does, a package
/// inside one does not.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Nesting {
    Allowed,
    Inner,
}

/// `err` as a note about a labelled file says it: an I/O error without the
/// path, which the label already stands for. The note then reads the same
/// however the program's path was spelled (relative, absolute, through a
/// link), as the rest of what a program prints does.
fn without_path(err: &EngineError) -> String {
    match err {
        EngineError::Io { source, .. } | EngineError::Archive(asc_apk::ApkError::Io { source, .. }) => format!("io error: {source}"),
        other => other.to_string(),
    }
}

fn open_archive(path: &Path) -> Result<Apk> {
    let limits = Limits { max_entry_bytes: MAX_INFLATED_BYTES, ..Limits::default() };
    Ok(Apk::open(path)?.with_limits(limits))
}

fn name_of(path: &Path) -> String {
    path.file_name().map_or_else(|| path.to_string_lossy().into_owned(), |name| name.to_string_lossy().into_owned())
}

/// The paths `spec` joins with `,`, or `spec` itself when a file of that
/// name exists (or it has no comma).
fn parts(spec: &Path) -> Vec<PathBuf> {
    match spec.to_str() {
        Some(s) if s.contains(',') && !spec.exists() => s.split(',').map(str::trim).filter(|p| !p.is_empty()).map(PathBuf::from).collect(),
        _ => vec![spec.to_path_buf()],
    }
}

/// The files `spec` names, in order: a lone file as it is (unlabelled);
/// directories walked in path order, their files labelled by their path
/// below the directory (and the directory's own name when `spec` lists
/// several paths); listed files by their file name. Labels are unique, a
/// file listed twice is kept once. Same rules as the DEX side.
fn sources(spec: &Path) -> Result<Vec<SourceFile>> {
    let parts = parts(spec);
    let several = parts.len() > 1;
    let mut out = Vec::new();
    for part in parts {
        let io = |source| EngineError::Io { path: part.clone(), source };
        let meta = fs::metadata(&part).map_err(io)?;
        if !meta.is_dir() {
            let label = if several { name_of(&part) } else { String::new() };
            out.push(SourceFile { path: part, label, meta });
            continue;
        }
        let mut files = Vec::new();
        walk(&part, MAX_DEPTH, &mut files).map_err(io)?;
        files.sort_by(|a, b| a.0.cmp(&b.0));
        let top = several.then(|| name_of(&part));
        for (path, meta) in files {
            let below = path.strip_prefix(&part).unwrap_or(&path);
            let rel = below.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/");
            let label = top.as_ref().map_or_else(|| rel.clone(), |top| format!("{top}/{rel}"));
            out.push(SourceFile { path, label, meta });
        }
    }
    let mut seen = HashSet::new();
    out.retain(|file| seen.insert(fs::canonicalize(&file.path).unwrap_or_else(|_| file.path.clone())));
    let mut labels = HashSet::new();
    for file in &mut out {
        let base = file.label.clone();
        let mut n = 1;
        while !labels.insert(file.label.clone()) {
            n += 1;
            file.label = format!("{base}#{n}");
        }
    }
    match &mut out[..] {
        [] => Err(EngineError::NoCode {
            path: spec.to_path_buf(),
            notes: vec!["no HarmonyOS package (.hap, .hsp, .app) or ABC file in it".into()],
        }),
        [lone] => {
            // A directory holding one file is that file.
            lone.label.clear();
            Ok(out)
        }
        _ => Ok(out),
    }
}

/// The HarmonyOS files of `dir`, `depth` levels down: what [`Format::detect`]
/// recognizes, by content before the name, so a package or a dumped ABC file
/// is found whatever it is called. That reads the first bytes of every file,
/// and the names in every zip.
fn walk(dir: &Path, depth: usize, out: &mut Vec<(PathBuf, fs::Metadata)>) -> std::io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        // Follows links, like the DEX side.
        let Ok(meta) = fs::metadata(&path) else { continue };
        if meta.is_dir() {
            if depth > 0 {
                walk(&path, depth - 1, out)?;
            }
        } else if Format::detect(&path).is_some() {
            out.push((path, meta));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_and_package_names() {
        assert!(is_abc(b"ets/modules.abc") && is_abc(b"ets/widgets.abc"));
        assert!(!is_abc(b"modules.abc") && !is_abc(b"ets/sub/x.abc") && !is_abc(b"ets/sourceMaps.map") && !is_abc(b"libs/ets/a.abc"));
        assert!(is_package(b"entry-default.hap") && is_package(b"lib.hsp"));
        assert!(!is_package(b"dir/entry.hap") && !is_package(b"pack.info"));
    }

    #[test]
    fn specs_and_labels() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("pkg");
        fs::create_dir_all(root.join("sub")).unwrap();
        for file in ["entry.hap", "modules.abc", "sub/lib.hsp", "notes.txt", "classes.dex"] {
            fs::write(root.join(file), b"x").unwrap();
        }
        let labels = |spec: &Path| sources(spec).unwrap().into_iter().map(|file| file.label).collect::<Vec<_>>();
        assert_eq!(labels(&root), ["entry.hap", "modules.abc", "sub/lib.hsp"]);
        assert_eq!(labels(&root.join("entry.hap")), [""]);
        // A file is found by what it holds, whatever it is called.
        fs::write(root.join("dump.bin"), [&asc_abc::MAGIC[..], b"..."].concat()).unwrap();
        assert_eq!(labels(&root), ["dump.bin", "entry.hap", "modules.abc", "sub/lib.hsp"]);
        fs::remove_file(root.join("dump.bin")).unwrap();
        assert_eq!(labels(&root.join("sub")), [""]);
        // A listed file may have any extension; a file listed twice is kept once.
        let spec = format!("{0},{1},{0}", root.join("notes.txt").display(), root.join("sub").display());
        assert_eq!(labels(Path::new(&spec)), ["notes.txt", "sub/lib.hsp"]);
        assert!(matches!(sources(&root.join("missing.hap")), Err(EngineError::Io { .. })));
        let empty = dir.path().join("empty");
        fs::create_dir_all(&empty).unwrap();
        assert!(matches!(sources(&empty), Err(EngineError::NoCode { .. })));
    }
}
