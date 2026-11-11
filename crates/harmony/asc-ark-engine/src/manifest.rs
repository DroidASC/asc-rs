//! The manifest of a HarmonyOS program (`getmanifest`, `manifest-summary`):
//! the metadata documents at the root of each package, joined to the code.
//!
//! A module package carries `module.json` (the manifest proper), usually
//! `pack.info` and, when built with normalized OHM URLs,
//! `pkgContextInfo.json`; an `.app` carries a `pack.info` of its own. The
//! documents are parsed by `asc-hap` on every call: nothing is kept.
//!
//! The join: every `srcEntry` of a manifest (an ability's, an extension
//! ability's, the module's own) names a source file, and the compiler names
//! a record after that file. [`Engine::manifest`] looks the candidate record
//! names up in the package's ABC entries and says which one is there
//! ([`CodeLink::Record`], a name `getclass` takes) or why none is
//! ([`CodeLink::Missing`]). For a record that is there it also lists the
//! functions named like framework callbacks (`onCreate`, `onNewWant`,
//! `onAddForm` …): where the system enters the component.
//!
//! The code of a package is its readable ABC entries; when it has none
//! (they are encrypted and nothing stood in for them), the bare `.abc`
//! files of the program are searched instead.
//!
//! The same join is made for the pages of a module: the page list
//! (`pages`) and the navigation route table (`routerMap`) are profiles of
//! the package; each page and each route is a line with its record. A
//! route's page may be compiled into another package, so its record is
//! looked for in the whole program after the package's own code.
//!
//! `pack.info` is a document of the application: every package of one
//! build carries the same bytes. It is summarized once, by the first
//! package that has it ([`PackSharing`]); a module it describes has its
//! `$type:name` references resolved by the index of that module's package.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use asc_abc::{Abc, Class, ClassEntry};
use asc_hap::{Ability, HapError, ModuleJson, PackInfo, PageList, PkgContextInfo, RecordNames, Route, RouterMap};
use serde_json::{json, Value};

use crate::program::{EntryInfo, EntryStatus, Program, SOURCE_MAPS};
use crate::{resources, text, Engine, EngineError, Result};

/// The first words of the `pack.info` lines that are about one module;
/// their second word is the module's name.
const PACK_MODULE_LINES: [&str; 4] = ["pack-module", "pack-ability", "pack-extension", "pack-form"];

/// A metadata document at the root of a package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Document {
    /// `module.json`: the manifest of a module.
    Module,
    /// `pack.info`: the packing tool's digest of a bundle.
    Pack,
    /// `pkgContextInfo.json`: the packages compiled into a module's code.
    PkgContext,
}

impl Document {
    pub const ALL: [Document; 3] = [Document::Module, Document::Pack, Document::PkgContext];

    /// The name of the file in a package.
    pub fn file_name(self) -> &'static str {
        match self {
            Document::Module => "module.json",
            Document::Pack => "pack.info",
            Document::PkgContext => "pkgContextInfo.json",
        }
    }

    /// The document a zip entry called `name` is.
    pub(crate) fn of_entry(name: &[u8]) -> Option<Document> {
        Document::ALL.into_iter().find(|document| document.file_name().as_bytes() == name)
    }
}

impl fmt::Display for Document {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.file_name())
    }
}

impl FromStr for Document {
    type Err = EngineError;

    /// A file name, in any case, with or without its extension:
    /// `module.json`, `pack`, `pkgcontextinfo`.
    fn from_str(name: &str) -> Result<Document> {
        let wanted = name.trim();
        let stem = |file: &'static str| file.split('.').next().unwrap_or(file);
        Document::ALL
            .into_iter()
            .find(|document| {
                let file = document.file_name();
                wanted.eq_ignore_ascii_case(file) || wanted.eq_ignore_ascii_case(stem(file))
            })
            .ok_or_else(|| {
                let names = Document::ALL.map(Document::file_name).join(", ");
                EngineError::Query(format!("{wanted:?} is not a manifest document: use {names}"))
            })
    }
}

/// Where the code of a manifest `srcEntry` is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeLink {
    /// The record compiled from the source file.
    Record {
        /// Canonical record name, as `getclass` takes it.
        record: String,
        /// The ABC entry that defines it.
        entry: String,
        /// Restored names of its functions and class methods whose own name
        /// reads `onXxx`, the framework's convention for callbacks, in file
        /// order. Functions nested in others are left out.
        callbacks: Vec<String>,
    },
    /// No readable ABC entry of the package has the record; the reason.
    Missing { reason: String },
}

/// A `srcEntry` of a manifest and the code it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryCode {
    /// As the manifest writes it: `./ets/entryability/EntryAbility.ets`.
    pub src_entry: String,
    pub link: CodeLink,
}

/// A page of a module's page list and the code it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageCode {
    /// As the list writes it: `pages/Index`.
    pub page: String,
    pub link: CodeLink,
}

/// A route of a module's route table and the code of its page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCode {
    pub route: Route,
    pub link: CodeLink,
}

/// An ABC entry of a program, as a manifest lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeEntry {
    pub info: EntryInfo,
    /// The decrypted file read in place of the entry, which is encrypted
    /// in its package.
    pub served_from: Option<String>,
    /// A bare `.abc` file that is part of no package.
    pub bare: bool,
}

impl CodeEntry {
    fn of(program: &Program, index: usize) -> Option<CodeEntry> {
        let info = program.info(index)?.clone();
        let served_from = program.stand_ins().iter().find(|stand_in| stand_in.entry == info.name).map(|stand_in| stand_in.file.clone());
        Some(CodeEntry { info, served_from, bare: program.package_of(index).is_none() })
    }

    /// `abc NAME version=V bytes=N status=readable`, NAME as result rows
    /// and `--entry` spell the entry; then what a reader has to know of
    /// it: the file it is served from, what to do about an encrypted one,
    /// why it does not read, that a bare file has no manifest.
    fn line(&self) -> String {
        let info = &self.info;
        let version = info.version.map_or_else(|| "-".to_owned(), |version| version.to_string());
        let mut line = format!("abc {} version={version} bytes={}", text::value(&info.name), info.size);
        match &info.status {
            EntryStatus::Readable => line.push_str(" status=readable"),
            EntryStatus::Encrypted => line.push_str(" status=encrypted (not searched: put the decrypted .abc next to the package)"),
            EntryStatus::Unreadable(reason) => line.push_str(&format!(" status=unreadable ({reason})")),
        }
        if let Some(file) = &self.served_from {
            line.push_str(&format!(" served-from={} (encrypted in the package)", text::value(file)));
        }
        if self.bare {
            line.push_str(" bare (part of no package: no manifest, no resources)");
        }
        line
    }

    fn json(&self) -> Value {
        let status = match &self.info.status {
            EntryStatus::Readable => "readable",
            EntryStatus::Encrypted => "encrypted",
            EntryStatus::Unreadable(_) => "unreadable",
        };
        json!({
            "name": self.info.name,
            "version": self.info.version.map(|version| version.to_string()),
            "bytes": self.info.size,
            "status": status,
            "served_from": self.served_from,
        })
    }
}

/// How the `pack.info` of a package relates to those of the other
/// packages of the program.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum PackSharing {
    /// No other package has the same bytes (or the package has none).
    #[default]
    Own,
    /// The first of several packages with the same bytes: the others, in
    /// program order. The summary lists the document here.
    First { also_in: Vec<String> },
    /// The same bytes as the `pack.info` of this earlier package, where
    /// the summary lists it.
    SameAs(String),
}

/// How the records of a package's code spread over its package table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackageRecords {
    /// Records per package, parallel to [`PkgContextInfo::packages`].
    pub per_package: Vec<usize>,
    /// Records the table places in no package: other spellings of a record
    /// name (`bundle/module/ets/…`) and packages the table does not list.
    pub unlocated: usize,
    /// ABC entries of the package that were not counted and why, one line
    /// each (`ets/modules.abc is encrypted`).
    pub left_out: Vec<String>,
}

/// The metadata of one package and its join to the code.
#[derive(Debug, Clone)]
pub struct PackageManifest {
    /// The package as ABC entry names spell it (`entry.hap`,
    /// `shop.app/entry-default.hap`); the file name for a lone file.
    pub name: String,
    pub module: Option<ModuleJson>,
    pub pack: Option<PackInfo>,
    pub pkg_context: Option<PkgContextInfo>,
    /// The code of the module's own `srcEntry` (its ability stage).
    pub module_code: Option<EntryCode>,
    /// The code of each component, parallel to [`ModuleJson::components`];
    /// `None` for a component without `srcEntry`.
    pub component_code: Vec<Option<EntryCode>>,
    /// Present with [`PackageManifest::pkg_context`].
    pub records: Option<PackageRecords>,
    /// The pages of the module's page list (`pages`), in file order.
    pub pages: Vec<PageCode>,
    /// The routes of the module's route table (`routerMap`), in file order.
    pub routes: Vec<RouteCode>,
    /// The ABC entries of the package, in program order.
    pub code: Vec<CodeEntry>,
    /// How many modules `ets/sourceMaps.map` of the package maps to their
    /// source, for a package (of a debug build) that has the file.
    pub source_maps: Option<usize>,
    pub pack_sharing: PackSharing,
    /// Documents that could not be read, one line each.
    pub notes: Vec<String>,
    /// What stands behind `$type:name` references, from the package's
    /// `resources.index`: the reference and what a line puts right behind
    /// it, `("Shop")` for a string's `base` value,
    /// `(resources/base/profile/main_pages.json)` for a file. It has the
    /// references of the package's own summary lines and those of the
    /// `pack.info` lines about its module, whichever package lists them.
    /// References nothing is found for are not in it.
    pub references: HashMap<String, String>,
    /// Its index among the packages of the program.
    position: usize,
    /// For each module `pack.info` describes, by name, the package (an
    /// index into [`Manifest::packages`]) whose index resolves the
    /// references of its lines.
    pack_targets: HashMap<String, usize>,
}

/// One line of a manifest summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestLine {
    /// [`PackageManifest::name`] of the package the line is about.
    pub package: String,
    pub text: String,
}

impl ManifestLine {
    /// The line; `with_package` puts the package ahead of it, the way a
    /// findrefs row starts with its entry: `entry.hap | ability …`.
    pub fn line(&self, with_package: bool) -> String {
        if with_package {
            format!("{} | {}", self.package, self.text)
        } else {
            self.text.clone()
        }
    }
}

/// One document of one package, re-indented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentText {
    pub package: String,
    pub document: Document,
    pub text: String,
    /// The other packages whose document is byte for byte this one, and
    /// is not listed again (`pack.info` only).
    pub also_in: Vec<String>,
}

impl DocumentText {
    /// `PACKAGE/NAME`, the heading of the document in a program of several
    /// packages, with ` (the same in A, B)` for a document others share.
    pub fn heading(&self) -> String {
        let mut heading = format!("{}/{}", self.package, self.document);
        if !self.also_in.is_empty() {
            heading.push_str(&format!(" (the same in {})", self.also_in.join(", ")));
        }
        heading
    }
}

/// The manifests of a program: one [`PackageManifest`] per package that has
/// a metadata document, in program order (an `.app` ahead of its packages).
#[derive(Debug, Clone)]
pub struct Manifest {
    pub packages: Vec<PackageManifest>,
    /// The bare `.abc` files that are part of no package (a decrypted file
    /// that stands in for a package entry is listed with its package).
    pub bare: Vec<CodeEntry>,
    /// Whether the program has several ABC entries, so that a record needs
    /// its entry named next to it.
    several_entries: bool,
}

impl Engine {
    /// Read and join the manifests of the program.
    ///
    /// # Errors
    /// [`EngineError::NoManifest`] when no package of the program has a
    /// metadata document: a bare `.abc` has none. A document that is not
    /// JSON is not an error: it is reported in the package's notes.
    pub fn manifest(&self) -> Result<Manifest> {
        let program = &self.program;
        let mut packages: Vec<PackageManifest> =
            (0..program.packages().len()).filter_map(|index| PackageManifest::read(program, index)).collect();
        if packages.is_empty() {
            return Err(EngineError::NoManifest {
                path: program.path().to_path_buf(),
                document: None,
                bare: program.packages().is_empty(),
            });
        }
        share_pack_info(program, &mut packages);
        aim_pack_lines(program, &mut packages);
        // The references each package's index is asked for by `pack.info` lines, its own or another package's.
        let mut asked: Vec<Vec<String>> = vec![Vec::new(); packages.len()];
        for (own, package) in packages.iter().enumerate() {
            for line in package.pack_lines() {
                let target = package.pack_line_target(&line, own);
                asked[target].extend(resources::references_of(&line).map(str::to_owned));
            }
        }
        for (package, asked) in packages.iter_mut().zip(&asked) {
            package.read_resources(program, asked);
        }
        let bare = program.entries_of(None).filter_map(|index| CodeEntry::of(program, index)).collect();
        Ok(Manifest { packages, bare, several_entries: program.len() > 1 })
    }
}

/// Find the packages whose `pack.info` is byte for byte the same and say so
/// in each ([`PackageManifest::pack_sharing`]).
fn share_pack_info(program: &Program, packages: &mut [PackageManifest]) {
    let bytes_of = |package: &PackageManifest| package.pack.as_ref().and_then(|_| program.document(package.position, Document::Pack));
    for at in 0..packages.len() {
        let Some(bytes) = bytes_of(&packages[at]) else { continue };
        if packages[at].pack_sharing != PackSharing::Own {
            continue;
        }
        let same: Vec<usize> = (at + 1..packages.len()).filter(|&other| bytes_of(&packages[other]) == Some(bytes)).collect();
        if same.is_empty() {
            continue;
        }
        let first = packages[at].name.clone();
        let also_in = same.iter().map(|&other| packages[other].name.clone()).collect();
        packages[at].pack_sharing = PackSharing::First { also_in };
        for other in same {
            packages[other].pack_sharing = PackSharing::SameAs(first.clone());
        }
    }
}

/// For every module a `pack.info` describes, find the package of that
/// module ([`PackageManifest::pack_targets`]): the package itself, else one
/// inside it (an `.app` and its modules), else the only package of the
/// program whose `module.json` has that name.
fn aim_pack_lines(program: &Program, packages: &mut [PackageManifest]) {
    let module_of = |package: &PackageManifest| package.module.as_ref().and_then(|manifest| manifest.module.name.clone());
    let modules: Vec<Option<String>> = packages.iter().map(module_of).collect();
    for own in 0..packages.len() {
        let Some(pack) = &packages[own].pack else { continue };
        let holder = packages[own].position;
        let is_inside = |at: usize| program.packages().get(packages[at].position).is_some_and(|package| package.parent == Some(holder));
        let mut targets = HashMap::new();
        for name in pack.modules.iter().filter_map(|module| module.name.as_deref()) {
            let named: Vec<usize> = (0..packages.len()).filter(|&at| modules[at].as_deref() == Some(name)).collect();
            let nested = named.iter().copied().find(|&at| is_inside(at));
            let only = (named.len() == 1).then(|| named[0]);
            if let Some(target) = named.contains(&own).then_some(own).or(nested).or(only) {
                targets.insert(name.to_owned(), target);
            }
        }
        packages[own].pack_targets = targets;
    }
}

/// The ABC entries that hold the code of a package.
struct Code<'p> {
    program: &'p Program,
    /// Readable entries, by index: the package's own, else the bare files.
    readable: Vec<usize>,
    /// Why a record may be missing though the package has it: its entries
    /// that cannot be read.
    left_out: Vec<String>,
    /// Whether the package has ABC entries at all.
    has_entries: bool,
}

impl<'p> Code<'p> {
    fn of(program: &'p Program, package: usize) -> Code<'p> {
        let is_readable = |index: &usize| program.info(*index).is_some_and(|info| info.status == EntryStatus::Readable);
        let own: Vec<usize> = program.entries_of(Some(package)).collect();
        let mut readable: Vec<usize> = own.iter().copied().filter(is_readable).collect();
        if readable.is_empty() {
            readable = program.entries_of(None).filter(is_readable).collect();
        }
        let left_out = own
            .iter()
            .filter_map(|&index| program.info(index))
            .filter_map(|info| match &info.status {
                EntryStatus::Readable => None,
                EntryStatus::Encrypted => Some(format!("{} is encrypted", info.name)),
                EntryStatus::Unreadable(_) => Some(format!("{} is unreadable", info.name)),
            })
            .collect();
        Code { program, readable, left_out, has_entries: !own.is_empty() }
    }

    fn entries(&self) -> impl Iterator<Item = (&'p str, Abc<'p>)> + '_ {
        let program = self.program;
        self.readable.iter().filter_map(move |&index| Some((program.info(index)?.name.as_str(), program.abc(index)?)))
    }

    /// The readable entries of the program that are not this package's code.
    fn other_entries(&self) -> impl Iterator<Item = (&'p str, Abc<'p>)> + '_ {
        let program = self.program;
        program
            .readable()
            .filter(|(index, _)| !self.readable.contains(index))
            .filter_map(move |(index, abc)| Some((program.info(index)?.name.as_str(), abc)))
    }

    /// The first of `candidates` that one of `entries` defines.
    fn find(candidates: &[&str], entries: impl Iterator<Item = (&'p str, Abc<'p>)> + Clone) -> Option<CodeLink> {
        for candidate in candidates {
            for (entry, abc) in entries.clone() {
                // A class index that does not read holds no record to link to.
                if let Ok(Some(ClassEntry::Local(class))) = abc.find_record(candidate.as_bytes()) {
                    return Some(CodeLink::Record {
                        record: (*candidate).to_owned(),
                        entry: entry.to_owned(),
                        callbacks: callbacks(&class),
                    });
                }
            }
        }
        None
    }

    /// As [`Code::link`], looking in the rest of the program when the
    /// package's own code does not have the record: the page of a route
    /// may be compiled into another package.
    fn link_anywhere(&self, candidates: &[&str]) -> CodeLink {
        match self.link(candidates) {
            found @ CodeLink::Record { .. } => found,
            missing @ CodeLink::Missing { .. } => {
                let others: Vec<(&'p str, Abc<'p>)> = self.other_entries().collect();
                Code::find(candidates, others.iter().copied()).unwrap_or(missing)
            }
        }
    }

    /// The first of `candidates` that a readable entry defines.
    fn link(&self, candidates: &[&str]) -> CodeLink {
        let own: Vec<(&'p str, Abc<'p>)> = self.entries().collect();
        if let Some(found) = Code::find(candidates, own.iter().copied()) {
            return found;
        }
        let reason = if !self.left_out.is_empty() {
            self.left_out.join("; ")
        } else if !self.has_entries && self.readable.is_empty() {
            "the package has no abc".to_owned()
        } else if candidates.is_empty() {
            "the manifest names neither bundle nor module".to_owned()
        } else {
            format!("no record {}", candidates.join(" or "))
        };
        CodeLink::Missing { reason }
    }

    fn records(&self, table: &PkgContextInfo) -> PackageRecords {
        let index_of: HashMap<&str, usize> =
            table.packages().iter().enumerate().map(|(index, package)| (package.name.as_str(), index)).collect();
        let mut records = PackageRecords { per_package: vec![0; table.packages().len()], unlocated: 0, left_out: self.left_out.clone() };
        for (_, abc) in self.entries() {
            // As above: an unreadable class index contributes no records.
            for class in abc.classes().into_iter().flatten().flatten() {
                let ClassEntry::Local(class) = class else { continue };
                if class.kind() != asc_abc::RecordKind::Module {
                    continue;
                }
                let name = String::from_utf8_lossy(class.name());
                match table.locate(&name).and_then(|owner| index_of.get(owner.package.name.as_str())) {
                    Some(&index) => records.per_package[index] += 1,
                    None => records.unlocated += 1,
                }
            }
        }
        records
    }
}

/// Whether a function's own name follows the framework's callback
/// convention: `on` and a capital (`onCreate`, `onNewWant`, `onAddForm`).
fn is_callback(name: &str) -> bool {
    name.strip_prefix("on").is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_uppercase()))
}

/// The functions of `class` named like callbacks, by restored name: plain
/// functions (`onCreate`) and methods of a class (`EntryAbility.onCreate`),
/// not what is nested deeper (`EntryAbility.watch.onReceive`, a method of an
/// object literal inside `watch`).
fn callbacks(class: &Class<'_>) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    // A method that does not read is not listed; `getclass` reports it.
    for method in class.methods().into_iter().flatten().flatten() {
        let Ok(raw) = method.name() else { continue };
        let restored = class.restore_function_name(&raw.to_str());
        let own = restored.rsplit('.').next().unwrap_or(&restored);
        let nested = restored.matches('.').count() > 1;
        if is_callback(own) && !nested && !found.contains(&restored) {
            found.push(restored);
        }
    }
    found
}

/// `bytes` as `document`; one that does not parse leaves a note.
fn parse<T>(
    bytes: Option<&[u8]>,
    parse: fn(&[u8]) -> std::result::Result<T, HapError>,
    document: Document,
    notes: &mut Vec<String>,
) -> Option<T> {
    parse(bytes?).map_err(|error| notes.push(format!("{document}: {error}"))).ok()
}

impl PackageManifest {
    /// The documents of package `index` and their join to the code; `None`
    /// when it has no document. What the package's resources say
    /// ([`PackageManifest::read_resources`]) is not read yet.
    fn read(program: &Program, index: usize) -> Option<PackageManifest> {
        let name = program.packages()[index].name.clone();
        if Document::ALL.into_iter().all(|document| program.document(index, document).is_none()) {
            return None;
        }
        let mut notes = Vec::new();
        let module = parse(program.document(index, Document::Module), ModuleJson::parse, Document::Module, &mut notes);
        let pack = parse(program.document(index, Document::Pack), PackInfo::parse, Document::Pack, &mut notes);
        let pkg_context = parse(program.document(index, Document::PkgContext), PkgContextInfo::parse, Document::PkgContext, &mut notes);

        let code = Code::of(program, index);
        let link = |manifest: &ModuleJson, src_entry: &str| EntryCode {
            src_entry: src_entry.to_owned(),
            link: code.link(&manifest.record_names(src_entry, pkg_context.as_ref()).candidates()),
        };
        let module_code = module.as_ref().and_then(|manifest| Some(link(manifest, manifest.module.src_entry.as_deref()?)));
        let component_code = module.as_ref().map_or_else(Vec::new, |manifest| {
            manifest.components().map(|component| component.src_entry.as_deref().map(|src_entry| link(manifest, src_entry))).collect()
        });
        let records = pkg_context.as_ref().map(|table| code.records(table));
        let source_maps = match program.source_maps(index) {
            Some(Ok((maps, _))) => Some(maps.len()),
            Some(Err(reason)) => {
                notes.push(format!("{SOURCE_MAPS}: {reason}"));
                None
            }
            None => None,
        };
        Some(PackageManifest {
            name,
            module,
            pack,
            pkg_context,
            module_code,
            component_code,
            records,
            pages: Vec::new(),
            routes: Vec::new(),
            code: program.entries_of(Some(index)).filter_map(|entry| CodeEntry::of(program, entry)).collect(),
            source_maps,
            pack_sharing: PackSharing::Own,
            notes,
            references: HashMap::new(),
            position: index,
            pack_targets: HashMap::new(),
        })
    }

    /// The lines of the package's own `pack.info`; none for a package that
    /// has the bytes of an earlier one, which lists them.
    fn pack_lines(&self) -> Vec<String> {
        match (&self.pack, &self.pack_sharing) {
            (Some(pack), PackSharing::Own | PackSharing::First { .. }) => pack.summary_lines(),
            (Some(_), PackSharing::SameAs(_)) | (None, _) => Vec::new(),
        }
    }

    /// The package whose index resolves the references of `line`, a line
    /// of this package's `pack.info`: the package of the module the line
    /// is about, else this one (`own`, its index among the manifests).
    fn pack_line_target(&self, line: &str, own: usize) -> usize {
        let mut words = line.split(' ');
        let about_module = words.next().is_some_and(|word| PACK_MODULE_LINES.contains(&word));
        let target = words.next().filter(|_| about_module).and_then(|module| self.pack_targets.get(module));
        target.copied().unwrap_or(own)
    }

    /// Read what the package's resources say: what stands behind the
    /// references of its own `module.json` lines and behind `asked` (those
    /// of the `pack.info` lines this package's index is to resolve), and
    /// the pages and routes of the profiles the module names. The index is
    /// only read when something asks for it; one that does not read leaves
    /// a note. A profile the index does not list is looked for where the
    /// build puts the ones it generates.
    fn read_resources(&mut self, program: &Program, asked: &[String]) {
        let index = self.position;
        let lines = self.module.as_ref().map_or_else(Vec::new, ModuleJson::summary_lines);
        let mut wanted: Vec<&str> = lines.iter().flat_map(|line| resources::references_of(line)).collect();
        wanted.extend(asked.iter().map(String::as_str));
        if wanted.is_empty() {
            return;
        }
        let table = match resources::Table::read(program, index) {
            None => None,
            Some(Ok(table)) => Some(table),
            Some(Err(reason)) => {
                self.notes.push(format!("resources.index: {reason}"));
                None
            }
        };
        self.references = wanted
            .into_iter()
            .filter_map(|reference| {
                let listed = table.as_ref().and_then(|table| table.manifest_suffix(reference));
                let suffix = listed.or_else(|| Some(format!("({})", resources::generated_profile(program, index, reference)?)))?;
                Some((reference.to_owned(), suffix))
            })
            .collect();
        self.read_pages(program, table.as_ref());
    }

    /// The profile `reference` names, parsed; a file that does not read or
    /// parse leaves a note.
    fn profile<T>(
        &mut self,
        program: &Program,
        table: Option<&resources::Table<'_>>,
        reference: Option<&str>,
        parse: fn(&[u8]) -> std::result::Result<T, HapError>,
    ) -> Option<T> {
        let found = resources::profile(program, self.position, table, reference?)?;
        let parsed = found.and_then(|file| parse(&file.bytes).map_err(|error| format!("{}: {error}", file.path)));
        parsed.map_err(|reason| self.notes.push(reason)).ok()
    }

    /// The pages and routes of the module, each joined to its record.
    fn read_pages(&mut self, program: &Program, table: Option<&resources::Table<'_>>) {
        let Some(manifest) = self.module.take() else { return };
        let pages = self.profile(program, table, manifest.module.pages.as_deref(), PageList::parse);
        let routes = self.profile(program, table, manifest.module.router_map.as_deref(), RouterMap::parse);
        let code = Code::of(program, self.position);
        let packages = self.pkg_context.as_ref();
        if let Some(list) = pages {
            self.notes.extend(list.notes.iter().map(|note| format!("pages: {note}")));
            let link = |page: &String| code.link(&manifest.record_names(&PageList::src_entry(page), packages).candidates());
            self.pages = list.pages.into_iter().map(|page| PageCode { link: link(&page), page }).collect();
        }
        if let Some(table) = routes {
            self.notes.extend(table.notes.iter().map(|note| format!("routerMap: {note}")));
            let link = |route: &Route| {
                let names: RecordNames = manifest.route_record_names(route, packages);
                code.link_anywhere(&names.candidates())
            };
            self.routes = table.routes.into_iter().map(|route| RouteCode { link: link(&route), route }).collect();
        }
        self.module = Some(manifest);
    }

    fn has(&self, document: Document) -> bool {
        match document {
            Document::Module => self.module.is_some(),
            Document::Pack => self.pack.is_some(),
            Document::PkgContext => self.pkg_context.is_some(),
        }
    }

    /// ` record=NAME` (and ` abc=ENTRY` when the program has several), or
    /// ` record=- (REASON)`.
    fn record_suffix(link: &CodeLink, several_entries: bool) -> String {
        match link {
            CodeLink::Record { record, entry, .. } if several_entries => format!(" record={record} abc={entry}"),
            CodeLink::Record { record, .. } => format!(" record={record}"),
            CodeLink::Missing { reason } => format!(" record=- ({reason})"),
        }
    }

    /// `callbacks NAME record=… functions=a,b`, for a record that has some.
    fn callbacks_line(name: &str, code: &EntryCode) -> Option<String> {
        match &code.link {
            CodeLink::Record { record, callbacks, .. } if !callbacks.is_empty() => {
                Some(format!("callbacks {name} record={record} functions={}", callbacks.join(",")))
            }
            CodeLink::Record { .. } | CodeLink::Missing { .. } => None,
        }
    }

    /// The lines of `module.json` as `asc-hap` summarizes it, with the join:
    /// the `module`, `ability` and `extension` lines end with the record of
    /// their `srcEntry`, and a `callbacks` line follows each that has some.
    /// The `abc` lines of the package's code follow the `module` line (and a
    /// `source-maps` line those); the `page` and `route` lines come last.
    /// The `abc` lines of the package's code, and a `source-maps` line when
    /// the package has the file: `getclass` then names source files and lines.
    fn code_lines(&self) -> impl Iterator<Item = String> + '_ {
        let source_maps = self.source_maps.map(|modules| format!("source-maps {SOURCE_MAPS} modules={modules}"));
        self.code.iter().map(CodeEntry::line).chain(source_maps)
    }

    fn module_lines(&self, manifest: &ModuleJson, several_entries: bool) -> Vec<String> {
        let mut out = Vec::new();
        // The summary has one `ability` / `extension` line per component, in the order of `components()`.
        let mut components = manifest.components().zip(&self.component_code);
        for mut line in manifest.summary_lines() {
            let kind = line.split(' ').next().unwrap_or_default().to_owned();
            let code = match kind.as_str() {
                "module" => self.module_code.as_ref(),
                "ability" | "extension" => components.next().and_then(|(_, code)| code.as_ref()),
                _ => None,
            };
            let name = line.split(' ').nth(1).unwrap_or("-").to_owned();
            if let Some(code) = code {
                line.push_str(&Self::record_suffix(&code.link, several_entries));
            }
            out.push(line);
            out.extend(code.and_then(|code| Self::callbacks_line(&name, code)));
            if kind == "module" {
                out.extend(self.code_lines());
            }
        }
        out.extend(self.pages.iter().map(|page| PageList::line(&page.page) + &Self::record_suffix(&page.link, several_entries)));
        out.extend(self.routes.iter().map(|route| route.route.line() + &Self::record_suffix(&route.link, several_entries)));
        out
    }

    /// The `package` lines of the table, each with the number of records
    /// the package has in the code.
    fn package_table_lines(&self) -> Vec<String> {
        let Some(table) = &self.pkg_context else { return Vec::new() };
        let counts = self.records.as_ref().map(|records| records.per_package.as_slice()).unwrap_or_default();
        // One `package` line per package, in table order, then the notes of the document.
        table
            .summary_lines()
            .into_iter()
            .enumerate()
            .map(|(index, line)| match counts.get(index) {
                Some(count) => format!("{line} records={count}"),
                None => line,
            })
            .collect()
    }

    /// `package-table packages=N native=N with-records=N records=N unlocated=N file=NAME`,
    /// then in brackets the entries whose records could not be counted.
    fn package_table_digest(&self) -> Option<String> {
        let table = self.pkg_context.as_ref()?;
        let records = self.records.as_ref()?;
        let mut line = format!(
            "package-table packages={} native={} with-records={} records={} unlocated={} file={}",
            table.packages().len(),
            table.packages().iter().filter(|package| package.is_so).count(),
            records.per_package.iter().filter(|&&count| count > 0).count(),
            records.per_package.iter().sum::<usize>(),
            records.unlocated,
            Document::PkgContext
        );
        if !records.left_out.is_empty() {
            line.push_str(&format!(" ({})", records.left_out.join("; ")));
        }
        Some(line)
    }

    /// `line` with what `references` has for its `$type:name` references
    /// put behind them.
    fn named(line: String, references: &HashMap<String, String>) -> String {
        if references.is_empty() {
            return line;
        }
        match resources::with_references(&line, |reference| references.get(reference).cloned()) {
            Cow::Owned(named) => named,
            Cow::Borrowed(_) => line,
        }
    }

    /// The `pack.info` lines of the package: the document as `asc-hap`
    /// summarizes it, under a `pack-info` line when other packages have
    /// the same bytes; or, for one of those others, only a `pack-info`
    /// line that says where it is listed. The references of a line about a
    /// module are resolved by that module's package.
    fn pack_info_lines(&self, manifest: &Manifest, own: usize) -> Vec<String> {
        let mut out = Vec::new();
        match &self.pack_sharing {
            PackSharing::Own => {}
            PackSharing::First { also_in } => out.push(format!(
                "pack-info packages={} (pack.info is byte for byte the same in {}: listed once, here)",
                also_in.len() + 1,
                also_in.join(", ")
            )),
            PackSharing::SameAs(first) if self.pack.is_some() => {
                out.push(format!("pack-info same-as={} (pack.info is byte for byte the one listed there)", text::value(first)));
            }
            PackSharing::SameAs(_) => {}
        }
        out.extend(self.pack_lines().into_iter().map(|line| {
            let target = self.pack_line_target(&line, own);
            let references = manifest.packages.get(target).map_or(&self.references, |package| &package.references);
            Self::named(line, references)
        }));
        out
    }

    /// The summary lines of the package, which is `manifest.packages[own]`.
    fn lines(&self, document: Option<Document>, manifest: &Manifest, own: usize) -> Vec<String> {
        let own_names = |lines: Vec<String>| lines.into_iter().map(|line| Self::named(line, &self.references)).collect::<Vec<_>>();
        let module = || match &self.module {
            Some(module) => own_names(self.module_lines(module, manifest.several_entries)),
            // A package without a manifest still says what code it has.
            None => self.code_lines().collect(),
        };
        let mut lines = match document {
            Some(Document::Module) => module(),
            Some(Document::Pack) => self.pack_info_lines(manifest, own),
            Some(Document::PkgContext) => own_names(self.package_table_lines()),
            None => {
                let mut lines = module();
                lines.extend(self.pack_info_lines(manifest, own));
                lines.extend(self.package_table_digest());
                lines
            }
        };
        lines.extend(self.notes.iter().map(|note| format!("note {note}")));
        lines
    }

    fn component_json(component: &Ability, code: Option<&EntryCode>) -> Value {
        let mut v = json!({
            "kind": component.kind.as_str(),
            "name": component.name,
            "type": component.extension_type,
            "exported": component.is_exported(),
            "permissions": component.permissions,
            "skills": component.skills.len(),
            "deep_links": component.deep_links(),
            "src_entry": component.src_entry,
        });
        if let Some(code) = code {
            code.fill(&mut v);
        }
        v
    }

    fn json(&self) -> Value {
        let mut v = json!({"package": self.name, "notes": self.notes});
        v["documents"] = Document::ALL.into_iter().filter(|document| self.has(*document)).map(Document::file_name).collect();
        v["abc"] = self.code.iter().map(CodeEntry::json).collect();
        if let Some(modules) = self.source_maps {
            v["source_maps"] = json!({"path": SOURCE_MAPS, "modules": modules});
        }
        if let PackSharing::SameAs(first) = &self.pack_sharing {
            v["pack_info_same_as"] = json!(first);
        }
        if let Some(manifest) = &self.module {
            let module = &manifest.module;
            let mut described = json!({"name": module.name, "type": module.kind, "src_entry": module.src_entry});
            if let Some(code) = &self.module_code {
                code.fill(&mut described);
            }
            v["bundle"] = json!(manifest.app.bundle_name);
            v["version"] = json!(manifest.app.version_name);
            v["module"] = described;
            v["components"] = manifest
                .components()
                .zip(&self.component_code)
                .map(|(component, code)| Self::component_json(component, code.as_ref()))
                .collect();
            v["pages"] = self
                .pages
                .iter()
                .map(|page| {
                    let mut described = json!({"page": page.page});
                    page.link.fill(&mut described);
                    described
                })
                .collect();
            v["routes"] = self
                .routes
                .iter()
                .map(|found| {
                    let route = &found.route;
                    let mut described = json!({
                        "name": route.name,
                        "build_function": route.build_function,
                        "source": route.page_source_file,
                        "package": route.package_name,
                    });
                    found.link.fill(&mut described);
                    described
                })
                .collect();
            v["request_permissions"] = module.request_permissions.iter().map(|permission| permission.name.clone()).collect();
            v["define_permissions"] = module.define_permissions.iter().map(|permission| permission.name.clone()).collect();
        }
        if let (Some(table), Some(records)) = (&self.pkg_context, &self.records) {
            v["package_table"] = json!({
                "packages": table.packages().len(),
                "records": records.per_package.iter().sum::<usize>(),
                "unlocated": records.unlocated,
            });
        }
        v
    }
}

impl EntryCode {
    /// Add the link to the JSON object of what has the `srcEntry`.
    fn fill(&self, object: &mut Value) {
        self.link.fill(object);
    }
}

impl CodeLink {
    /// Add the link to the JSON object of what names the code.
    fn fill(&self, object: &mut Value) {
        match self {
            CodeLink::Record { record, entry, callbacks } => {
                object["record"] = json!(record);
                object["abc"] = json!(entry);
                object["callbacks"] = json!(callbacks);
            }
            CodeLink::Missing { reason } => {
                object["record"] = Value::Null;
                object["unresolved"] = json!(reason);
            }
        }
    }
}

impl Manifest {
    /// Whether lines need their package named to be told apart.
    pub fn has_several_packages(&self) -> bool {
        self.packages.len() > 1
    }

    /// Whether any package has `document`.
    pub fn has(&self, document: Document) -> bool {
        self.packages.iter().any(|package| package.has(document))
    }

    /// One fact per line, package by package. A `$type:name` reference is
    /// followed by what it stands for in the package's `resources.index`:
    /// `label=$string:EntryAbility_label("Shop")`,
    /// `pages=$profile:main_pages(resources/base/profile/main_pages.json)`.
    ///
    /// Without a `document`: `module.json` as `asc-hap` summarizes it, the
    /// `module`, `ability` and `extension` lines ending with
    /// `record=NAME` (`abc=ENTRY` after it in a program of several ABC
    /// entries) or `record=- (REASON)`, each followed by a
    /// `callbacks NAME record=NAME functions=A,B` line when the record has
    /// functions named `onXxx`; then `pack.info`; then one `package-table`
    /// line counting `pkgContextInfo.json`.
    ///
    /// With one: only that document. For `pkgContextInfo.json` that is the
    /// table itself, one `package` line each, ending with `records=N`: the
    /// records of the code that belong to the package.
    pub fn summary_lines(&self, document: Option<Document>) -> Vec<ManifestLine> {
        let of_packages = self.packages.iter().enumerate().flat_map(|(own, package)| {
            let lines = package.lines(document, self, own);
            lines.into_iter().map(|text| ManifestLine { package: package.name.clone(), text })
        });
        // A bare file has no document: it is listed with the code, not under one.
        let bare = self.bare.iter().filter(|_| matches!(document, None | Some(Document::Module)));
        of_packages.chain(bare.map(|entry| ManifestLine { package: entry.info.name.clone(), text: entry.line() })).collect()
    }

    /// `document` of every package that has it, re-indented. A `pack.info`
    /// several packages have byte for byte is there once, for the first of
    /// them, with the names of the others.
    pub fn documents(&self, document: Document) -> Vec<DocumentText> {
        self.packages
            .iter()
            .filter_map(|package| {
                let mut also_in = Vec::new();
                let text = match document {
                    Document::Module => package.module.as_ref()?.pretty(),
                    Document::Pack => match &package.pack_sharing {
                        PackSharing::Own => package.pack.as_ref()?.pretty(),
                        PackSharing::First { also_in: others } => {
                            also_in.clone_from(others);
                            package.pack.as_ref()?.pretty()
                        }
                        PackSharing::SameAs(_) => return None,
                    },
                    Document::PkgContext => package.pkg_context.as_ref()?.pretty(),
                };
                Some(DocumentText { package: package.name.clone(), document, text, also_in })
            })
            .collect()
    }

    /// The summary as JSON: `{"packages": [{package, documents, bundle,
    /// version, module, components, request_permissions, …}]}`; `module`
    /// and each component carry `record`, `abc` and `callbacks`, or
    /// `record: null` and `unresolved`.
    pub fn json(&self) -> Value {
        let mut v = json!({"packages": self.packages.iter().map(PackageManifest::json).collect::<Vec<_>>()});
        if !self.bare.is_empty() {
            v["bare_abc"] = self.bare.iter().map(CodeEntry::json).collect();
        }
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documents_by_name() {
        assert_eq!("module.json".parse::<Document>().unwrap(), Document::Module);
        assert_eq!("Pack".parse::<Document>().unwrap(), Document::Pack);
        assert_eq!(" pkgcontextinfo.JSON ".parse::<Document>().unwrap(), Document::PkgContext);
        let error = "AndroidManifest.xml".parse::<Document>().unwrap_err().to_string();
        assert_eq!(error, "\"AndroidManifest.xml\" is not a manifest document: use module.json, pack.info, pkgContextInfo.json");
        assert_eq!(Document::of_entry(b"pack.info"), Some(Document::Pack));
        assert_eq!(Document::of_entry(b"resources/module.json"), None);
    }

    #[test]
    fn callbacks_follow_the_naming_convention() {
        assert!(is_callback("onCreate") && is_callback("onNewWant") && is_callback("onAddForm"));
        assert!(!is_callback("on") && !is_callback("once") && !is_callback("online") && !is_callback("build") && !is_callback("OnCreate"));
    }

    #[test]
    fn lines_name_their_package_on_request() {
        let line = ManifestLine { package: "entry.hap".into(), text: "bundle com.x".into() };
        assert_eq!(line.line(false), "bundle com.x");
        assert_eq!(line.line(true), "entry.hap | bundle com.x");
    }
}
