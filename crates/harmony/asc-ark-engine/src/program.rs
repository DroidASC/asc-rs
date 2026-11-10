//! Opening a HarmonyOS program: the ABC files a path names.
//!
//! A path is a `.hap` / `.hsp` (zip with `ets/*.abc`), an `.app` (zip of
//! such packages) or any zip that holds those, a bare `.abc` file, a package
//! unpacked into a directory (`module.json` with `ets/*.abc` next to it), a
//! directory of those, or several paths joined with `,`. Whatever it is, the
//! result is a flat list of ABC entries named like the DEX side names its
//! entries: `ets/modules.abc` for a lone package, `entry.hap/ets/modules.abc`
//! when the program has several packages or comes from an `.app`,
//! `shop.app/entry.hap/ets/modules.abc` through every zip on the way.
//!
//! Stored entries are used in place from the file mapping (also through
//! stored inner packages). A Deflate inner package or ABC entry is inflated
//! into memory and kept for the life of the program; [`MAX_INFLATED_TOTAL`]
//! bounds what all of them take. The files of an unpacked package are mapped
//! one by one.

use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;
use std::time::SystemTime;

use asc_abc::{Abc, AbcError, Header};
use asc_apk::{Apk, Limits, Prefix, PrefixStep, METHOD_STORED};
use asc_hap::SourceMaps;

use crate::manifest::Document;
use crate::{EngineError, Result};

/// Directory levels a walk descends.
const MAX_DEPTH: usize = 8;
/// Most bytes one Deflate entry (an inner package of an `.app`, or an ABC
/// entry someone recompressed) may inflate to: it is held in memory.
const MAX_INFLATED_BYTES: u64 = 1 << 30;
/// Most bytes all Deflate inner packages and entries of one program may
/// inflate to together: what a zip of zips of zips can make the program hold.
const MAX_INFLATED_TOTAL: u64 = 4 << 30;
/// How many packages may lie inside one another below a file: an `.app` in
/// a zip with its `.hap` is two.
const MAX_NESTING: usize = 4;
/// A zip that is no package itself and has at most this many entries has
/// every one of them looked at for a package inside; a larger one only
/// those named like one ([`has_archive_extension`]).
const SNIFFED_ENTRIES: usize = 64;
/// A Deflate entry of such a zip that is larger than this, compressed, is
/// only looked into when it is named `.hap`, `.hsp` or `.app`.
const MAX_SNIFFED_DEFLATE: u64 = 64 << 20;
const ZIP_MAGIC: &[u8] = b"PK";
/// How a zip entry that is itself a zip starts.
const ZIP_LOCAL_HEADER: &[u8] = b"PK\x03\x04";

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
    /// a zip holding `module.json`, `ets/*.abc`, `*.hap` / `*.hsp`, or a zip
    /// that does, a few levels down), then by extension. `None` for
    /// anything else, a directory included.
    pub fn detect(path: &Path) -> Option<Format> {
        if !path.is_file() {
            return None;
        }
        let mut magic = [0u8; 8];
        let read = fs::File::open(path).and_then(|mut file| file.read(&mut magic)).unwrap_or(0);
        if read == magic.len() && magic == asc_abc::MAGIC {
            return Some(Format::Abc);
        }
        let by_content = if magic.starts_with(ZIP_MAGIC) { open_archive(path).ok().and_then(|zip| Format::of_zip(&zip)) } else { None };
        by_content.or_else(|| Format::of_extension(path))
    }

    /// Whether `spec` (a file, a directory, or paths joined with `,`) names
    /// at least one HarmonyOS input: what a front end asks before choosing
    /// this engine.
    pub fn accepts(spec: &Path) -> bool {
        sources(spec).is_ok_and(|files| files.iter().any(|file| file.unpacked.is_some() || Format::detect(&file.path).is_some()))
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
        let listing = Listing::of(zip).ok()?;
        if listing.entries.iter().any(|(_, role)| *role == Role::Package) {
            Some(Format::App)
        } else if listing.is_module {
            Some(Format::Hap)
        } else {
            let mut budget = MAX_INFLATED_TOTAL;
            listing.holds_packages(zip, MAX_NESTING, &mut budget).then_some(Format::App)
        }
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

fn has_extension(name: &[u8], extensions: &[&[u8]]) -> bool {
    let extension = name.rsplit(|&byte| byte == b'.').next().unwrap_or_default();
    extensions.iter().any(|known| extension.eq_ignore_ascii_case(known))
}

/// A name that says the entry is a package, wherever it lies in its zip.
fn has_package_extension(name: &[u8]) -> bool {
    has_extension(name, &[b"hap", b"hsp", b"app"])
}

/// A name that says the entry may be a package or hold some, wherever it
/// lies in its zip: `.hap`, `.hsp`, `.app`, `.zip`.
fn has_archive_extension(name: &[u8]) -> bool {
    has_package_extension(name) || has_extension(name, &[b"zip"])
}

/// A file of a module package that only some queries read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OnDemand {
    /// `resources.index`.
    Resources,
    /// `ets/sourceMaps.map`.
    SourceMaps,
}

/// What a file of a module package is to a program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    /// `ets/*.abc`.
    Code,
    Document(Document),
    OnDemand(OnDemand),
}

impl Part {
    /// Every file of a package the program opens, apart from its code.
    const BESIDE_CODE: [Part; 5] = [
        Part::Document(Document::Module),
        Part::Document(Document::Pack),
        Part::Document(Document::PkgContext),
        Part::OnDemand(OnDemand::Resources),
        Part::OnDemand(OnDemand::SourceMaps),
    ];

    fn file_name(self) -> Option<&'static str> {
        match self {
            Part::Code => None,
            Part::Document(document) => Some(document.file_name()),
            Part::OnDemand(OnDemand::Resources) => Some(RESOURCE_INDEX),
            Part::OnDemand(OnDemand::SourceMaps) => Some(SOURCE_MAPS),
        }
    }

    fn of_name(name: &[u8]) -> Option<Part> {
        if is_abc(name) {
            return Some(Part::Code);
        }
        let on_demand = |which: OnDemand| Part::OnDemand(which).file_name().is_some_and(|own| own.as_bytes() == name);
        let document = Document::of_entry(name).map(Part::Document);
        document.or_else(|| [OnDemand::Resources, OnDemand::SourceMaps].into_iter().find(|which| on_demand(*which)).map(Part::OnDemand))
    }
}

/// What an entry of a zip is to a program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Part(Part),
    /// A package by its name ([`is_package`]).
    Package,
    /// A package if its content says so.
    Maybe,
}

/// The entries of a zip a program may read, in central directory order.
struct Listing {
    entries: Vec<(asc_apk::Entry, Role)>,
    /// Whether the zip is a module package: `module.json` or `ets/*.abc` at
    /// its root.
    is_module: bool,
}

impl Listing {
    /// Only the names are looked at. A module package and an Android
    /// archive hold packages by name alone, as an `.app` does; in any
    /// other zip the entries that may be one by their content are kept too.
    fn of(zip: &Apk) -> asc_apk::Result<Listing> {
        let (mut total, mut is_module, mut is_android) = (0usize, false, false);
        let kept = zip.entries_filtered(|name| {
            total += 1;
            is_module |= name == b"module.json" || is_abc(name);
            is_android |= name == b"AndroidManifest.xml" || name == b"classes.dex";
            Part::of_name(name).is_some() || is_package(name) || has_archive_extension(name) || total <= SNIFFED_ENTRIES
        })?;
        let sniffs = !is_module && !is_android;
        let entries = kept
            .into_iter()
            .filter_map(|entry| {
                let name = entry.name.as_bytes();
                let role = match Part::of_name(name) {
                    Some(part) => Role::Part(part),
                    None if is_package(name) => Role::Package,
                    None if sniffs && (total <= SNIFFED_ENTRIES || has_archive_extension(name)) && Listing::may_open(&entry) => Role::Maybe,
                    None => return None,
                };
                Some((entry, role))
            })
            .collect();
        Ok(Listing { entries, is_module })
    }

    /// Whether an entry that is not a package by its name is worth opening
    /// to see: to tell, a Deflate one has to be inflated whole, which only
    /// a small one, or one named like a package, is worth.
    fn may_open(entry: &asc_apk::Entry) -> bool {
        let name = entry.name.as_bytes();
        !name.ends_with(b"/") && (entry.method == METHOD_STORED || entry.comp_size <= MAX_SNIFFED_DEFLATE || has_package_extension(name))
    }

    /// Whether one of the entries that may be a package is one, or holds
    /// one `depth` zips down. `budget` is what may still be inflated to find out.
    fn holds_packages(&self, zip: &Apk, depth: usize, budget: &mut u64) -> bool {
        self.entries.iter().filter(|(_, role)| *role == Role::Maybe).any(|(entry, _)| {
            if depth == 0 || !is_zip(zip, entry) || (entry.method != METHOD_STORED && entry.uncomp_size > *budget) {
                return false;
            }
            let Ok(inner) = zip.open_nested(entry) else { return false };
            *budget = budget.saturating_sub(inner.owned_bytes() as u64);
            Listing::of(&inner).is_ok_and(|listing| {
                listing.is_module
                    || listing.entries.iter().any(|(_, role)| *role == Role::Package)
                    || listing.holds_packages(&inner, depth - 1, budget)
            })
        })
    }
}

/// Whether `entry` of `zip` starts like a zip: a stored one is looked at in
/// place, of a Deflate one only the first block is inflated.
fn is_zip(zip: &Apk, entry: &asc_apk::Entry) -> bool {
    if entry.method == METHOD_STORED {
        return zip.raw_payload(entry).is_ok_and(|payload| payload.starts_with(ZIP_LOCAL_HEADER));
    }
    match zip.inflate_until(entry, |_| PrefixStep::Continue(ZIP_LOCAL_HEADER.len())) {
        Ok(Prefix::Complete(start) | Prefix::Partial(start) | Prefix::Aborted(start)) => start.starts_with(ZIP_LOCAL_HEADER),
        Err(_) => false,
    }
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

/// An encrypted package entry and the decrypted file that is read in its place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandIn {
    /// The entry, as rows name it: `entry.hap/ets/modules.abc`.
    pub entry: String,
    /// The bare `.abc` file next to the package, as the program labels it.
    pub file: String,
}

/// Where the bytes of an entry are.
enum Source {
    /// A stored zip entry, read in place.
    Stored { container: usize, entry: asc_apk::Entry },
    /// A bare `.abc` file: the whole mapping.
    Bare { container: usize, file_name: String },
    /// A file of an unpacked package: the whole mapping.
    Loose { container: usize },
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
const RESOURCE_INDEX: &str = "resources.index";
/// The name of the source maps a debug build packs with its code.
pub(crate) const SOURCE_MAPS: &str = "ets/sourceMaps.map";

/// A zip entry that is read when it is first asked for: in place when it is
/// stored, inflated once and kept when it is Deflate.
struct LazyEntry {
    container: usize,
    entry: asc_apk::Entry,
    /// The inflated bytes of a Deflate entry, or why it does not inflate.
    inflated: OnceLock<std::result::Result<Vec<u8>, String>>,
}

/// A file of a package that only some queries read.
enum Lazy {
    Entry(LazyEntry),
    /// A file of an unpacked package: mapped, so read when it is touched.
    Loose {
        container: usize,
    },
}

/// Where the files of a package are.
enum Root {
    /// A zip, in `Program::containers`.
    Zip(usize),
    /// The directory a package was unpacked into.
    Directory(PathBuf),
}

/// `ets/sourceMaps.map` of a package and what was found in it.
struct PackedSourceMaps {
    file: Lazy,
    /// Where each module is in the file, or why the file does not read;
    /// worked out the first time a query asks.
    index: OnceLock<std::result::Result<SourceMaps, String>>,
}

/// A module package (`.hap` / `.hsp`, or the directory one was unpacked
/// into), an application package (`.app`) or a zip of those, with the
/// metadata documents at its root.
pub(crate) struct Package {
    /// The prefix of its entries (`entry.hap`), or for a lone file, whose
    /// entries have none, the file's name.
    pub(crate) name: String,
    documents: Vec<(Document, Source)>,
    root: Root,
    /// Its `resources.index`, when it has one.
    resources: Option<Lazy>,
    /// Its `ets/sourceMaps.map`, when it has one.
    source_maps: Option<PackedSourceMaps>,
    /// Whether it holds other packages (an `.app`) instead of a module.
    pub(crate) is_bundle: bool,
    /// The `.app` it is inside of, by index, for an inner package.
    pub(crate) parent: Option<usize>,
}

/// One file of a program, or the directory of an unpacked package, and the
/// name its entries are prefixed with (empty for a lone one).
struct SourceFile {
    path: PathBuf,
    label: String,
    /// Read while listing it, so a [`Stamp`] needs no second `stat`.
    meta: fs::Metadata,
    /// The files of the package, when `path` is a directory one was
    /// unpacked into.
    unpacked: Option<Vec<Member>>,
}

/// One file of an unpacked package that the program opens.
struct Member {
    /// As the package names it: `ets/modules.abc`.
    name: String,
    part: Part,
    path: PathBuf,
    meta: fs::Metadata,
}

impl Member {
    fn at(dir: &Path, name: &str, part: Part) -> Option<Member> {
        let path = dir.join(name);
        // Follows links, as the walk does.
        let meta = fs::metadata(&path).ok().filter(fs::Metadata::is_file)?;
        Some(Member { name: name.to_owned(), part, path, meta })
    }

    /// The files of the package unpacked into `dir`; `None` when `dir` is
    /// not one: a package has `module.json` and, next to it, `ets/*.abc`.
    /// The code comes first, in name order, then the files beside it.
    fn of_package(dir: &Path) -> Option<Vec<Member>> {
        if !dir.join(Document::Module.file_name()).is_file() {
            return None;
        }
        let mut code: Vec<String> = fs::read_dir(dir.join("ets"))
            .ok()?
            .filter_map(|entry| Some(format!("ets/{}", entry.ok()?.file_name().to_str()?)))
            .filter(|name| is_abc(name.as_bytes()))
            .collect();
        code.sort();
        let mut members: Vec<Member> = code.iter().filter_map(|name| Member::at(dir, name, Part::Code)).collect();
        if members.is_empty() {
            return None;
        }
        members.extend(Part::BESIDE_CODE.into_iter().filter_map(|part| Member::at(dir, part.file_name()?, part)));
        Some(members)
    }
}

/// Which files a program is read from, with their sizes and modification
/// times: what the DEX side calls the version of an opened program. Of an
/// unpacked package these are its directory and the files a program opens
/// (code, documents, resource index, source maps); the files `xml` prints
/// are read anew every time. Two
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
        let of = |path: &Path, meta: &fs::Metadata| (path.to_path_buf(), meta.len(), meta.modified().ok());
        let mut stamp = Vec::with_capacity(files.len());
        for file in files {
            match &file.unpacked {
                None => stamp.push(of(&file.path, &file.meta)),
                // The size and time of a directory say nothing its files do not.
                Some(members) => {
                    stamp.push((file.path.clone(), 0, None));
                    stamp.extend(members.iter().map(|member| of(&member.path, &member.meta)));
                }
            }
        }
        Stamp(stamp)
    }
}

/// What a program holds in memory, in bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ProgramBytes {
    /// On the heap: Deflate inner packages and entries, inflated when the
    /// program was opened or when a query first read them.
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
    /// The encrypted entries a decrypted file stands in for, in program order.
    stand_ins: Vec<StandIn>,
    /// The files as they were listed, before any of them was mapped: a file
    /// replaced while the program opened makes the stamp stale, not wrong.
    stamp: Stamp,
    /// Bytes inflated while opening, against [`MAX_INFLATED_TOTAL`].
    inflated: u64,
    /// The first zip that lay too deep to be opened ([`MAX_NESTING`]).
    too_deep: Option<String>,
}

/// How much of a program there was at some point, to go back to.
struct Mark {
    containers: usize,
    packages: usize,
    entries: usize,
    notes: usize,
    inflated: u64,
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
            stand_ins: Vec::new(),
            stamp: Stamp::of_sources(&files),
            inflated: 0,
            too_deep: None,
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
        if let Some(name) = program.too_deep.take() {
            program.notes.push(format!("{name}: skipped: zips more than {MAX_NESTING} deep in a file are not opened"));
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

    /// The encrypted entries served from a decrypted file: not a note, the
    /// program reads as if the package were not encrypted.
    pub(crate) fn stand_ins(&self) -> &[StandIn] {
        &self.stand_ins
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
                Source::Stored { .. } | Source::Bare { .. } | Source::Loose { .. } => bytes.mapped += self.source_bytes(source).len(),
            }
        }
        let lazy =
            self.packages.iter().flat_map(|package| package.resources.iter().chain(package.source_maps.iter().map(|maps| &maps.file)));
        for file in lazy {
            match file {
                Lazy::Loose { container } => bytes.mapped += self.containers[*container].lone_data().map_or(0, <[u8]>::len),
                Lazy::Entry(entry) => match entry.inflated.get() {
                    Some(inflated) => bytes.inflated += inflated.as_ref().map_or(0, Vec::capacity),
                    None if entry.entry.method == METHOD_STORED => bytes.mapped += usize::try_from(entry.entry.uncomp_size).unwrap_or(0),
                    // A Deflate entry nobody asked for yet: nothing is held.
                    None => {}
                },
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
            Source::Bare { container, .. } | Source::Loose { container } => self.containers[*container].lone_data().unwrap_or_default(),
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

    /// The bytes of a file of a package that is read on demand: a stored
    /// entry and a loose file in place from the mapping, a Deflate entry
    /// inflated the first time and kept. The reason when it cannot be read.
    fn lazy_bytes<'p>(&'p self, file: &'p Lazy) -> std::result::Result<&'p [u8], String> {
        let entry = match file {
            Lazy::Loose { container } => return Ok(self.containers[*container].lone_data().unwrap_or_default()),
            Lazy::Entry(entry) => entry,
        };
        let zip = &self.containers[entry.container];
        if entry.entry.method == METHOD_STORED {
            return zip.raw_payload(&entry.entry).map_err(|err| err.to_string());
        }
        let inflated =
            entry.inflated.get_or_init(|| zip.read_entry(&entry.entry).map(std::borrow::Cow::into_owned).map_err(|err| err.to_string()));
        inflated.as_deref().map_err(String::clone)
    }

    /// The bytes of `resources.index` of package `package`: `None` when the
    /// package has none, the reason when the entry cannot be read.
    pub(crate) fn resource_index(&self, package: usize) -> Option<std::result::Result<&[u8], String>> {
        Some(self.lazy_bytes(self.packages.get(package)?.resources.as_ref()?))
    }

    /// `ets/sourceMaps.map` of package `package`, with its bytes: `None`
    /// when the package has none, the reason when it does not read. The
    /// file is walked once, the first time this is asked.
    pub(crate) fn source_maps(&self, package: usize) -> Option<std::result::Result<(&SourceMaps, &[u8]), String>> {
        let maps = self.packages.get(package)?.source_maps.as_ref()?;
        let bytes = match self.lazy_bytes(&maps.file) {
            Ok(bytes) => bytes,
            Err(reason) => return Some(Err(reason)),
        };
        let index = maps.index.get_or_init(|| SourceMaps::index(bytes).map_err(|err| err.to_string()));
        Some(index.as_ref().map(|index| (index, bytes)).map_err(String::clone))
    }

    /// The source map of the module `record` of ABC entry `entry` was
    /// compiled from, when the entry's package has source maps that read
    /// and name the record.
    pub(crate) fn module_map(&self, entry: &str, record: &str) -> Option<asc_hap::ModuleMap> {
        let index = self.entries.iter().position(|candidate| candidate.info.name == entry)?;
        let (maps, bytes) = self.source_maps(self.package_of(index)?)?.ok()?;
        maps.module(bytes, record)?.ok()
    }

    /// Whether package `package` has a file at `path`: only the names of
    /// its zip are looked at.
    pub(crate) fn has_file(&self, package: usize, path: &str) -> bool {
        match self.packages.get(package).map(|package| &package.root) {
            None => false,
            Some(Root::Zip(container)) => {
                self.containers[*container].entries_filtered(|name| name == path.as_bytes()).is_ok_and(|found| !found.is_empty())
            }
            Some(Root::Directory(dir)) => loose_file(dir, path).is_some(),
        }
    }

    /// The file `path` of package `package`, read from its zip or its
    /// directory now: `None` when the package has no such file. Nothing of
    /// it is kept.
    pub(crate) fn file(&self, package: usize, path: &str) -> Result<Option<std::borrow::Cow<'_, [u8]>>> {
        let Some(package) = self.packages.get(package) else { return Ok(None) };
        let zip = match &package.root {
            Root::Zip(container) => &self.containers[*container],
            Root::Directory(dir) => {
                let Some(file) = loose_file(dir, path) else { return Ok(None) };
                return match fs::read(&file) {
                    Ok(bytes) => Ok(Some(bytes.into())),
                    Err(source) => Err(EngineError::Io { path: file, source }),
                };
            }
        };
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
        let shown = if file.label.is_empty() { name_of(&file.path) } else { file.label.clone() };
        if let Some(members) = &file.unpacked {
            self.add_unpacked(file, members, &shown);
            return Ok(());
        }
        let apk = open_archive(&file.path)?;
        let data = apk.lone_data().unwrap_or_default();
        if data.starts_with(&asc_abc::MAGIC) {
            let container = self.push_container(apk);
            self.push_entry(shown, Source::Bare { container, file_name: name_of(&file.path) }, None);
            return Ok(());
        }
        let found = self.add_package(apk, &file.label, &shown, MAX_NESTING)?;
        if found == 0 {
            self.notes.push(format!("{shown}: no ets/*.abc"));
        }
        Ok(())
    }

    fn push_package(&mut self, name: &str, root: Root) -> usize {
        self.packages.push(Package {
            name: name.to_owned(),
            documents: Vec::new(),
            root,
            resources: None,
            source_maps: None,
            is_bundle: false,
            parent: None,
        });
        self.packages.len() - 1
    }

    /// Give package `package` a file that is read when a query asks for it.
    fn set_on_demand(&mut self, package: usize, which: OnDemand, file: Lazy) {
        let package = &mut self.packages[package];
        match which {
            OnDemand::Resources => package.resources = Some(file),
            OnDemand::SourceMaps => package.source_maps = Some(PackedSourceMaps { file, index: OnceLock::new() }),
        }
    }

    /// Add the package unpacked into the directory `file`, named `shown`:
    /// each of its files is mapped on its own. One that does not open is
    /// left out and noted.
    fn add_unpacked(&mut self, file: &SourceFile, members: &[Member], shown: &str) {
        let package = self.push_package(shown, Root::Directory(file.path.clone()));
        for member in members {
            let name = if file.label.is_empty() { member.name.clone() } else { format!("{}/{}", file.label, member.name) };
            let container = match open_archive(&member.path) {
                Ok(apk) => self.push_container(apk),
                Err(err) => {
                    self.notes.push(format!("{name}: skipped: {}", without_path(&err)));
                    continue;
                }
            };
            match member.part {
                Part::Code => self.push_entry(name, Source::Loose { container }, Some(package)),
                Part::Document(document) => self.packages[package].documents.push((document, Source::Loose { container })),
                Part::OnDemand(which) => self.set_on_demand(package, which, Lazy::Loose { container }),
            }
        }
    }

    fn mark(&self) -> Mark {
        Mark {
            containers: self.containers.len(),
            packages: self.packages.len(),
            entries: self.entries.len(),
            notes: self.notes.len(),
            inflated: self.inflated,
        }
    }

    /// Forget what was added since `mark`.
    fn rewind(&mut self, mark: &Mark) {
        self.containers.truncate(mark.containers);
        self.packages.truncate(mark.packages);
        self.entries.truncate(mark.entries);
        self.notes.truncate(mark.notes);
        self.inflated = mark.inflated;
    }

    /// Whether the Deflate entry `member` may still be inflated.
    ///
    /// # Errors
    /// When what it declares takes the program past [`MAX_INFLATED_TOTAL`].
    fn check_room(&self, member: &asc_apk::Entry) -> Result<()> {
        if self.inflated.saturating_add(member.uncomp_size) <= MAX_INFLATED_TOTAL {
            return Ok(());
        }
        Err(EngineError::Archive(asc_apk::ApkError::LimitExceeded {
            name: member.name.clone(),
            reason: format!("the program would inflate more than {MAX_INFLATED_TOTAL} bytes in all"),
        }))
    }

    /// `member` of zip `container` as bytes the program keeps: in place
    /// when it is stored, inflated now when it is Deflate.
    fn read_now(&mut self, container: usize, member: asc_apk::Entry) -> Result<Source> {
        if member.method == METHOD_STORED {
            self.containers[container].raw_payload(&member)?;
            return Ok(Source::Stored { container, entry: member });
        }
        self.check_room(&member)?;
        let bytes = self.containers[container].read_entry(&member)?.into_owned();
        self.inflated = self.inflated.saturating_add(bytes.len() as u64);
        Ok(Source::Inflated(bytes))
    }

    /// `member` of zip `container` as a zip of its own: in place when it
    /// is stored, inflated and kept when it is Deflate.
    fn open_inner(&mut self, container: usize, member: &asc_apk::Entry) -> Result<Apk> {
        if member.method != METHOD_STORED {
            self.check_room(member)?;
        }
        let inner = self.containers[container].open_nested(member)?;
        self.inflated = self.inflated.saturating_add(inner.owned_bytes() as u64);
        Ok(inner)
    }

    /// Add a package, named `shown`: its ABC entries (prefixed with
    /// `prefix`), its metadata documents and the packages inside it, down
    /// to `depth` more zips. Returns how many ABC entries were added.
    fn add_package(&mut self, zip: Apk, prefix: &str, shown: &str, depth: usize) -> Result<usize> {
        let listing = Listing::of(&zip)?;
        let container = self.push_container(zip);
        let package = self.push_package(shown, Root::Zip(container));
        let mut found = 0;
        for (member, role) in listing.entries {
            let name = if prefix.is_empty() { member.name.clone() } else { format!("{prefix}/{}", member.name) };
            let document = match role {
                Role::Package | Role::Maybe => {
                    found += self.add_inner(package, &member, &name, role, depth);
                    continue;
                }
                Role::Part(Part::OnDemand(which)) => {
                    self.set_on_demand(package, which, Lazy::Entry(LazyEntry { container, entry: member, inflated: OnceLock::new() }));
                    continue;
                }
                Role::Part(Part::Document(document)) => Some(document),
                Role::Part(Part::Code) => None,
            };
            match (self.read_now(container, member), document) {
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

    /// Add `member` of package `holder` as a package inside it, named
    /// `name`. One that is only a package if its content says so
    /// ([`Role::Maybe`]) has to be a zip with code or documents of its
    /// own, at some depth; anything else leaves no trace. Returns how many
    /// ABC entries were added.
    fn add_inner(&mut self, holder: usize, member: &asc_apk::Entry, name: &str, role: Role, depth: usize) -> usize {
        let Root::Zip(container) = self.packages[holder].root else { return 0 };
        let tentative = role == Role::Maybe;
        if tentative && !is_zip(&self.containers[container], member) {
            return 0;
        }
        if depth == 0 {
            // Kept apart from the notes: those of a zip that turns out to hold no package are dropped.
            self.too_deep.get_or_insert_with(|| name.to_owned());
            return 0;
        }
        // A holder of packages by name is one even if none of them opens.
        self.packages[holder].is_bundle |= !tentative;
        let mark = self.mark();
        let added = self.open_inner(container, member).and_then(|inner| self.add_package(inner, name, name, depth - 1));
        let has_documents = self.packages.iter().skip(mark.packages).any(|package| !package.documents.is_empty());
        let found = match added {
            Ok(0) if tentative && !has_documents => {
                self.rewind(&mark);
                return 0;
            }
            Ok(0) => {
                self.notes.push(format!("{name}: no ets/*.abc"));
                0
            }
            Ok(found) => found,
            // A broken inner package does not take the others with it.
            Err(err) => {
                self.rewind(&mark);
                // A zip of another kind that does not read is not this program's to report.
                if !tentative || has_archive_extension(name.as_bytes()) {
                    self.notes.push(format!("{name}: skipped: {err}"));
                }
                return 0;
            }
        };
        self.packages[holder].is_bundle = true;
        if let Some(inner) = self.packages.get_mut(mark.packages) {
            inner.parent = Some(holder);
        }
        found
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
                self.stand_ins.push(StandIn { entry: name, file: bare_name.clone() });
                return Some(bare);
            }
        }
        None
    }
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
            out.push(SourceFile { path: part, label, meta, unpacked: None });
            continue;
        }
        let mut files = Vec::new();
        walk(&part, MAX_DEPTH, &mut files).map_err(io)?;
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let top = several.then(|| name_of(&part));
        for mut file in files {
            let below = file.path.strip_prefix(&part).unwrap_or(&file.path);
            let rel = below.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/");
            file.label = match &top {
                // The directory itself, unpacked: it has no path below it.
                _ if rel.is_empty() => name_of(&part),
                Some(top) => format!("{top}/{rel}"),
                None => rel,
            };
            out.push(file);
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

/// The HarmonyOS files of `dir`, `depth` levels down, not yet labelled:
/// what [`Format::detect`] recognizes, by content before the name, so a
/// package or a dumped ABC file is found whatever it is called. That reads
/// the first bytes of every file, and the names in every zip.
///
/// A directory a package was unpacked into ([`Member::of_package`]) is one
/// package. Of what else it holds only the files right in it are looked at
/// (a decrypted `.abc` dropped next to `module.json`): what lies deeper are
/// the package's own files, as inside the zip it came from.
fn walk(dir: &Path, depth: usize, out: &mut Vec<SourceFile>) -> std::io::Result<()> {
    let unpacked = Member::of_package(dir);
    let is_package = unpacked.is_some();
    if let Some(members) = unpacked {
        out.push(SourceFile { path: dir.to_path_buf(), label: String::new(), meta: fs::metadata(dir)?, unpacked: Some(members) });
    }
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        // Follows links, like the DEX side.
        let Ok(meta) = fs::metadata(&path) else { continue };
        if meta.is_dir() {
            if depth > 0 && !is_package {
                walk(&path, depth - 1, out)?;
            }
        } else if Format::detect(&path).is_some() {
            out.push(SourceFile { path, label: String::new(), meta, unpacked: None });
        }
    }
    Ok(())
}

/// The file `inner` names inside the unpacked package at `root`: a plain
/// relative path that, links followed, stays inside the package.
fn loose_file(root: &Path, inner: &str) -> Option<PathBuf> {
    let relative = Path::new(inner);
    if inner.is_empty() || !relative.components().all(|part| matches!(part, Component::Normal(_))) {
        return None;
    }
    let root = fs::canonicalize(root).ok()?;
    let file = fs::canonicalize(root.join(relative)).ok()?;
    (file.starts_with(&root) && file.is_file()).then_some(file)
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
