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

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;

use asc_abc::{Abc, Class, ClassEntry};
use asc_hap::{Ability, HapError, ModuleJson, PackInfo, PkgContextInfo};
use serde_json::{json, Value};

use crate::program::{EntryStatus, Program};
use crate::{resources, Engine, EngineError, Result};

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
    /// Documents that could not be read, one line each.
    pub notes: Vec<String>,
    /// What stands behind the `$type:name` references of the summary
    /// lines, from the package's `resources.index`: the reference and what
    /// a line puts right behind it, `("Shop")` for a string's `base`
    /// value, `(resources/base/profile/main_pages.json)` for a file.
    /// References nothing is found for are not in it.
    pub references: HashMap<String, String>,
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
}

/// The manifests of a program: one [`PackageManifest`] per package that has
/// a metadata document, in program order (an `.app` ahead of its packages).
#[derive(Debug, Clone)]
pub struct Manifest {
    pub packages: Vec<PackageManifest>,
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
        let packages: Vec<PackageManifest> =
            (0..program.packages().len()).filter_map(|index| PackageManifest::read(program, index)).collect();
        if packages.is_empty() {
            return Err(EngineError::NoManifest {
                path: program.path().to_path_buf(),
                document: None,
                bare: program.packages().is_empty(),
            });
        }
        Ok(Manifest { packages, several_entries: program.len() > 1 })
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

    /// The first of `candidates` that a readable entry defines.
    fn link(&self, candidates: &[&str]) -> CodeLink {
        for candidate in candidates {
            for (entry, abc) in self.entries() {
                // A class index that does not read holds no record to link to.
                if let Ok(Some(ClassEntry::Local(class))) = abc.find_record(candidate.as_bytes()) {
                    return CodeLink::Record { record: (*candidate).to_owned(), entry: entry.to_owned(), callbacks: callbacks(&class) };
                }
            }
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
                let name = String::from_utf8_lossy(class.name());
                if asc_abc::RecordName::parse(&name).kind() != asc_abc::RecordKind::Module {
                    continue;
                }
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
    /// The manifest of package `index`; `None` when it has no document.
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
        let references = Self::references(program, index, module.as_ref(), pack.as_ref(), &mut notes);
        Some(PackageManifest { name, module, pack, pkg_context, module_code, component_code, records, notes, references })
    }

    /// What the references of the summary lines stand for. The index is
    /// only read when a line has a reference; one that does not read
    /// leaves a note. A profile the index does not list is looked for
    /// where the build puts the ones it generates.
    fn references(
        program: &Program,
        index: usize,
        module: Option<&ModuleJson>,
        pack: Option<&PackInfo>,
        notes: &mut Vec<String>,
    ) -> HashMap<String, String> {
        let mut lines = module.map_or_else(Vec::new, ModuleJson::summary_lines);
        lines.extend(pack.map_or_else(Vec::new, PackInfo::summary_lines));
        let mut wanted = lines.iter().flat_map(|line| resources::references_of(line)).peekable();
        if wanted.peek().is_none() {
            return HashMap::new();
        }
        let table = match resources::Table::read(program, index) {
            None => None,
            Some(Ok(table)) => Some(table),
            Some(Err(reason)) => {
                notes.push(format!("resources.index: {reason}"));
                None
            }
        };
        wanted
            .filter_map(|reference| {
                let listed = table.as_ref().and_then(|table| table.manifest_suffix(reference));
                let suffix = listed.or_else(|| Some(format!("({})", resources::generated_profile(program, index, reference)?)))?;
                Some((reference.to_owned(), suffix))
            })
            .collect()
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
    fn record_suffix(code: &EntryCode, several_entries: bool) -> String {
        match &code.link {
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
    fn module_lines(&self, manifest: &ModuleJson, several_entries: bool) -> Vec<String> {
        let mut out = Vec::new();
        // The summary has one `ability` / `extension` line per component, in the order of `components()`.
        let mut components = manifest.components().zip(&self.component_code);
        let mut module_code = self.module_code.as_ref();
        for mut line in manifest.summary_lines() {
            let word = |line: &str| line.split(' ').nth(1).unwrap_or("-").to_owned();
            let code = match line.split(' ').next() {
                Some("module") => module_code.take(),
                Some("ability" | "extension") => components.next().and_then(|(_, code)| code.as_ref()),
                _ => None,
            };
            let Some(code) = code else {
                out.push(line);
                continue;
            };
            let name = word(&line);
            line.push_str(&Self::record_suffix(code, several_entries));
            out.push(line);
            out.extend(Self::callbacks_line(&name, code));
        }
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

    fn lines(&self, document: Option<Document>, several_entries: bool) -> Vec<String> {
        let module = || self.module.as_ref().map_or_else(Vec::new, |manifest| self.module_lines(manifest, several_entries));
        let pack = || self.pack.as_ref().map_or_else(Vec::new, PackInfo::summary_lines);
        let mut lines = match document {
            Some(Document::Module) => module(),
            Some(Document::Pack) => pack(),
            Some(Document::PkgContext) => self.package_table_lines(),
            None => {
                let mut lines = module();
                lines.extend(pack());
                lines.extend(self.package_table_digest());
                lines
            }
        };
        if !self.references.is_empty() {
            for line in &mut lines {
                if let Cow::Owned(named) = resources::with_references(line, |reference| self.references.get(reference).cloned()) {
                    *line = named;
                }
            }
        }
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
        match &self.link {
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
        self.packages
            .iter()
            .flat_map(|package| {
                let lines = package.lines(document, self.several_entries);
                lines.into_iter().map(|text| ManifestLine { package: package.name.clone(), text })
            })
            .collect()
    }

    /// `document` of every package that has it, re-indented.
    pub fn documents(&self, document: Document) -> Vec<DocumentText> {
        self.packages
            .iter()
            .filter_map(|package| {
                let text = match document {
                    Document::Module => package.module.as_ref()?.pretty(),
                    Document::Pack => package.pack.as_ref()?.pretty(),
                    Document::PkgContext => package.pkg_context.as_ref()?.pretty(),
                };
                Some(DocumentText { package: package.name.clone(), document, text })
            })
            .collect()
    }

    /// The summary as JSON: `{"packages": [{package, documents, bundle,
    /// version, module, components, request_permissions, …}]}`; `module`
    /// and each component carry `record`, `abc` and `callbacks`, or
    /// `record: null` and `unresolved`.
    pub fn json(&self) -> Value {
        json!({"packages": self.packages.iter().map(PackageManifest::json).collect::<Vec<_>>()})
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
