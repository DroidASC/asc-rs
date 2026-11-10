//! The resources of a HarmonyOS program (`resources`, `xml`, the names
//! `getclass` and `manifest-summary` put behind resource ids and
//! references).
//!
//! Every module package carries a `resources.index`: the table from
//! resource ids to types, names and one value per qualifier set
//! (`asc-hap` reads it). [`Engine::resources`] parses the index of every
//! package for one command; nothing parsed is kept, and a stored index is
//! read in place from the file mapping. A package without an index, or
//! with one that does not read, is a note of the answer, never its failure.
//!
//! A value may name another resource (`$color:16777245`):
//! [`ResourceTables::resolve`] follows such references to the last value.
//! A `media` or `profile` resource is a file of the package:
//! [`Engine::package_files`] reads the text ones (`$profile:main_pages`,
//! the page list; `$profile:router_map`, the route table).

use std::borrow::Cow;
use std::collections::HashMap;
use std::str::FromStr;

use asc_abc::{Abc, Literal, Method};
use asc_arkisa::OperandKind;
use asc_hap::{Resource, ResourceIndex, ResourceRef, ResourceType, ResourceValue};
use serde_json::{json, Value};

use crate::program::Program;
use crate::refs::Pattern;
use crate::{records, text, ClassSource, Engine, EngineError, Result};

/// References a chain follows before it is cut: no well-formed index nests
/// this deep.
const MAX_CHAIN: usize = 32;
/// Most bytes of a text value shown behind a manifest reference.
const MANIFEST_VALUE_BYTES: usize = 200;
/// Most bytes of a text value shown behind a resource id in a listing: the
/// limit of a string literal there (`asc_pasm::Options::DEFAULT_STRING_LIMIT`).
const LISTING_VALUE_BYTES: usize = text::ROW_STRING_BYTES;

/// One value of one resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRow {
    /// The package whose index has it, as manifest lines name packages.
    pub package: String,
    pub id: u32,
    /// `string/app_name`.
    pub name: String,
    /// The qualifier set the value is for, as its directory name: `base`,
    /// `zh_CN`, `dark`.
    pub qualifiers: String,
    /// The value on one line, as `asc_hap::ResourceValue` displays it.
    pub value: String,
}

impl ResourceRow {
    fn of(package: &str, resource: &Resource<'_>) -> ResourceRow {
        ResourceRow {
            package: package.to_owned(),
            id: resource.id(),
            name: format!("{}/{}", resource.kind(), resource.name()),
            qualifiers: resource.qualifiers().to_string(),
            value: resource.value().to_string(),
        }
    }

    /// `0x01000003 string/EntryAbility_label [zh_CN] "Shop"`, as
    /// `asc_hap::Resource` displays itself; `with_package` puts the package
    /// ahead of it, the way a findrefs row starts with its entry.
    pub fn line(&self, with_package: bool) -> String {
        let row = format!("{:#010x} {} [{}] {}", self.id, self.name, self.qualifiers, self.value);
        if with_package {
            format!("{} | {row}", self.package)
        } else {
            row
        }
    }

    pub fn json(&self) -> Value {
        json!({
            "package": self.package,
            "id": format!("{:#010x}", self.id),
            "name": self.name,
            "config": self.qualifiers,
            "value": self.value,
        })
    }
}

/// What a resource search matches against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceField {
    /// `type/name` of every resource.
    Name,
    /// The texts of a value: a string, a file path, the items of an array,
    /// the forms of a plural, the attributes of a theme or pattern.
    Value,
    /// Either.
    Any,
}

impl FromStr for ResourceField {
    type Err = EngineError;

    fn from_str(field: &str) -> Result<ResourceField> {
        match field {
            "name" => Ok(ResourceField::Name),
            "value" => Ok(ResourceField::Value),
            "any" => Ok(ResourceField::Any),
            other => Err(EngineError::Query(format!("a search is in name, value or any, not {other}"))),
        }
    }
}

/// Where a reference chain stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainEnd {
    /// At a value that names no other resource.
    Value,
    /// At a reference the index has nothing for (a system resource, or a
    /// dangling one): the reference.
    Unresolved(String),
    /// At a reference back into the chain: the reference.
    Cycle(String),
    /// After [`MAX_CHAIN`] references.
    TooLong,
}

/// A resource followed through the references its value names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedResource {
    pub package: String,
    /// `$color:accent`, then what each value named in turn.
    pub chain: Vec<String>,
    pub end: ChainEnd,
    /// The last resource of the chain, with the value the chain stopped at.
    pub row: ResourceRow,
}

impl ResolvedResource {
    /// `chain $color:accent -> $color:accent_dark`, with why the chain
    /// stopped when that is not at a plain value: ` -> $color:x (not in
    /// the index)`, ` -> $color:accent (cycle)`.
    pub fn chain_line(&self, with_package: bool) -> String {
        let mut line = format!("chain {}", self.chain.join(" -> "));
        match &self.end {
            ChainEnd::Value => {}
            ChainEnd::Unresolved(reference) => line.push_str(&format!(" -> {reference} (not in the index)")),
            ChainEnd::Cycle(reference) => line.push_str(&format!(" -> {reference} (cycle)")),
            ChainEnd::TooLong => line.push_str(&format!(" -> ... (more than {MAX_CHAIN} references)")),
        }
        if with_package {
            format!("{} | {line}", self.package)
        } else {
            line
        }
    }
}

/// What a resource query names: an id, or a type and name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target<'q> {
    Id(u32),
    Named(ResourceRef<'q>),
}

impl<'q> Target<'q> {
    /// An id in hex (`0x01000003`) or decimal (`16777219`, as values inside
    /// the index and compiled code write it), or a name: `string/app_name`,
    /// `$string:app_name`, `app.string.app_name`.
    fn parse(query: &'q str) -> Result<Target<'q>> {
        let query = query.trim();
        let hex = query.strip_prefix("0x").or_else(|| query.strip_prefix("0X"));
        if let Some(id) = hex.and_then(|hex| u32::from_str_radix(hex, 16).ok()) {
            return Ok(Target::Id(id));
        }
        if let Ok(id) = query.parse() {
            return Ok(Target::Id(id));
        }
        if let Some(reference) = ResourceRef::parse(query) {
            return Ok(Target::Named(reference));
        }
        match query.split_once('/') {
            Some((kind, name)) if !name.is_empty() => {
                let kind = kind.parse().map_err(|e: asc_hap::UnknownResourceType| EngineError::Query(format!("{query}: {e}")))?;
                Ok(Target::Named(ResourceRef { kind, name }))
            }
            _ => Err(EngineError::Query(format!(
                "{query:?} is not a resource: give an id (0x01000003, 16777219) or a name (string/app_name, $string:app_name, \
                 app.string.app_name)"
            ))),
        }
    }
}

/// The index of one package.
pub(crate) struct Table<'e> {
    package: &'e str,
    index: ResourceIndex<'e>,
}

impl<'e> Table<'e> {
    /// The index of package `position`: `None` when the package has none,
    /// the reason when it does not read.
    pub(crate) fn read(program: &'e Program, position: usize) -> Option<std::result::Result<Table<'e>, String>> {
        let package = program.packages().get(position)?.name.as_str();
        let bytes = program.resource_index(position)?;
        Some(bytes.and_then(|bytes| ResourceIndex::parse(bytes).map_err(|err| err.to_string())).map(|index| Table { package, index }))
    }

    /// What stands behind `reference` (`$string:app_name`), for a manifest
    /// line: the `base` value in brackets, `("Shop")`; for a media or
    /// profile resource the file's path in the package,
    /// `(resources/base/profile/main_pages.json)`. `None` when the index
    /// has no such resource, or the resource no `base` value.
    pub(crate) fn manifest_suffix(&self, reference: &str) -> Option<String> {
        let value = self.base_value(Target::Named(ResourceRef::parse(reference)?))?.value();
        Some(match value.archive_path() {
            Some(path) => format!("({path})"),
            None => format!("({})", shown_value(&value, MANIFEST_VALUE_BYTES)),
        })
    }

    /// The path in the package of the file `reference` (`$profile:main_pages`)
    /// names by its `base` value; `None` when the index has no such
    /// resource or it is no file.
    pub(crate) fn file_path(&self, reference: &str) -> Option<String> {
        let value = self.base_value(Target::Named(ResourceRef::parse(reference)?))?.value();
        value.archive_path().map(str::to_owned)
    }

    /// The values `target` names, the `base` one first, the others in file order.
    fn values(&self, target: Target<'_>) -> Vec<Resource<'_>> {
        let mut values: Vec<Resource<'_>> = match target {
            Target::Id(id) => self.index.by_id(id).collect(),
            Target::Named(reference) => self.index.resolve(reference).collect(),
        };
        values.sort_by_key(|value| !value.qualifiers().is_base());
        values
    }

    /// The value of `target` used when no qualifier matches: the `base`
    /// one, else the first.
    fn default_value(&self, target: Target<'_>) -> Option<Resource<'_>> {
        self.values(target).into_iter().next()
    }

    /// The `base` value of `target`, when it has one.
    fn base_value(&self, target: Target<'_>) -> Option<Resource<'_>> {
        self.default_value(target).filter(|value| value.qualifiers().is_base())
    }

    fn resolve(&self, target: Target<'_>) -> Option<ResolvedResource> {
        let mut current = self.default_value(target)?;
        let mut chain = vec![reference_to(&current)];
        let mut seen = vec![current.id()];
        let end = loop {
            let ResourceValue::Text(text) = current.value() else { break ChainEnd::Value };
            let Some(reference) = ResourceRef::parse(&text) else { break ChainEnd::Value };
            let Some(next) = self.default_value(Target::Named(reference)) else { break ChainEnd::Unresolved(text.into_owned()) };
            if seen.contains(&next.id()) {
                break ChainEnd::Cycle(reference_to(&next));
            }
            if chain.len() > MAX_CHAIN {
                break ChainEnd::TooLong;
            }
            chain.push(reference_to(&next));
            seen.push(next.id());
            current = next;
        };
        Some(ResolvedResource { package: self.package.to_owned(), chain, end, row: ResourceRow::of(self.package, &current) })
    }
}

/// `$string:app_name`: the reference that names `resource`.
fn reference_to(resource: &Resource<'_>) -> String {
    format!("${}:{}", resource.kind(), resource.name())
}

/// Whether `pattern` matches one of the texts of `value`.
fn value_matches(pattern: &Pattern, value: &ResourceValue<'_>) -> bool {
    match value {
        ResourceValue::Text(text) | ResourceValue::File(text) => pattern.is_match(text),
        ResourceValue::Array(items) => items.iter().any(|item| pattern.is_match(item)),
        ResourceValue::Plural(forms) => forms.iter().any(|form| pattern.is_match(&form.value)),
        ResourceValue::Map { parent, attrs } => {
            parent.as_deref().is_some_and(|parent| pattern.is_match(parent)) || attrs.iter().any(|attr| pattern.is_match(&attr.value))
        }
        ResourceValue::Raw(_) => false,
    }
}

/// The value on one line, a text of at most `limit` bytes.
fn shown_value(value: &ResourceValue<'_>, limit: usize) -> String {
    match value {
        ResourceValue::Text(text) => text::quoted_cut(text, limit),
        other => other.to_string(),
    }
}

/// The resource indexes of a program, parsed for one command.
pub struct ResourceTables<'e> {
    tables: Vec<Table<'e>>,
    /// Whether the program has several packages.
    several: bool,
    notes: Vec<String>,
}

impl<'e> ResourceTables<'e> {
    fn read(program: &'e Program) -> ResourceTables<'e> {
        let mut tables = ResourceTables { tables: Vec::new(), several: program.packages().len() > 1, notes: Vec::new() };
        if program.packages().is_empty() {
            tables.notes.push("a bare .abc carries none: pass the .hap / .app it came from, or a directory holding both".to_owned());
        }
        for (position, package) in program.packages().iter().enumerate() {
            let name = package.name.as_str();
            match Table::read(program, position) {
                // An `.app` holds packages, not resources.
                None if package.is_bundle => {}
                None => tables.notes.push(format!("{name}: no resources.index")),
                Some(Ok(table)) => tables.tables.push(table),
                Some(Err(reason)) => tables.notes.push(format!("{name}: resources.index: {reason}")),
            }
        }
        tables
    }

    /// Whether rows need their package named to be told apart: the program
    /// has several packages (as manifest lines name theirs then).
    pub fn has_several_packages(&self) -> bool {
        self.several
    }

    /// Packages left out and why, one line each: `entry.hap: no
    /// resources.index`, `lib.hsp: resources.index: unknown resource index
    /// version …`.
    pub fn notes(&self) -> &[String] {
        &self.notes
    }

    /// Number of values in all the indexes.
    pub fn len(&self) -> usize {
        self.tables.iter().map(|table| table.index.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn table(&self, package: &str) -> Option<&Table<'e>> {
        self.tables.iter().find(|table| table.package == package)
    }

    /// Call `row` with every value: package by package, by id, a resource's
    /// `base` value ahead of its others.
    pub fn for_each(&self, mut row: impl FnMut(ResourceRow)) {
        for table in &self.tables {
            let mut values: Vec<Resource<'_>> = table.index.iter().collect();
            // Stable: the values of one id keep their file order behind `base`.
            values.sort_by_key(|value| (value.id(), !value.qualifiers().is_base()));
            values.iter().for_each(|value| row(ResourceRow::of(table.package, value)));
        }
    }

    /// Every value of the resource `query` names, in every package that has
    /// it: `base` first. `query` is an id (`0x01000003`, `16777219`) or a
    /// name (`string/app_name`, `$string:app_name`, `app.string.app_name`).
    ///
    /// # Errors
    /// [`EngineError::Query`] for a query that is neither;
    /// [`EngineError::NotFound`] when no index has the resource.
    pub fn lookup(&self, query: &str) -> Result<Vec<ResourceRow>> {
        let target = Target::parse(query)?;
        let rows: Vec<ResourceRow> = self
            .tables
            .iter()
            .flat_map(|table| table.values(target).into_iter().map(|value| ResourceRow::of(table.package, &value)).collect::<Vec<_>>())
            .collect();
        if rows.is_empty() {
            return Err(self.not_found(query));
        }
        Ok(rows)
    }

    /// The resource `query` names, followed through the references its
    /// value names (`$color:16777245`) to the last value, in every package
    /// that has it. Each step takes the `base` value (the first, for a
    /// resource without one). A chain that comes back to itself, or names
    /// what the index does not have, stops there and says so.
    ///
    /// # Errors
    /// As [`ResourceTables::lookup`].
    pub fn resolve(&self, query: &str) -> Result<Vec<ResolvedResource>> {
        let target = Target::parse(query)?;
        let resolved: Vec<ResolvedResource> = self.tables.iter().filter_map(|table| table.resolve(target)).collect();
        if resolved.is_empty() {
            return Err(self.not_found(query));
        }
        Ok(resolved)
    }

    fn not_found(&self, query: &str) -> EngineError {
        EngineError::NotFound { what: "resource", name: query.trim().to_owned(), notes: self.notes.clone() }
    }

    /// The values whose `type/name` (and / or one of whose texts, by
    /// `field`) `pattern` matches: at most `limit` rows, and how many
    /// matched. A resource matched by name lists every value it has.
    pub fn search(&self, pattern: &Pattern, field: ResourceField, limit: usize) -> (Vec<ResourceRow>, usize) {
        let mut rows = Vec::new();
        let mut total = 0;
        for table in &self.tables {
            let mut values: Vec<Resource<'_>> = table
                .index
                .iter()
                .filter(|value| {
                    let by_name = || pattern.is_match(&format!("{}/{}", value.kind(), value.name()));
                    let by_value = || value_matches(pattern, &value.value());
                    match field {
                        ResourceField::Name => by_name(),
                        ResourceField::Value => by_value(),
                        ResourceField::Any => by_name() || by_value(),
                    }
                })
                .collect();
            values.sort_by_key(|value| (value.id(), !value.qualifiers().is_base()));
            total += values.len();
            let room = limit.saturating_sub(rows.len());
            rows.extend(values.iter().take(room).map(|value| ResourceRow::of(table.package, value)));
        }
        (rows, total)
    }
}

/// A text file of a package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageFile {
    pub package: String,
    /// Its path in the package: `resources/base/profile/main_pages.json`.
    pub path: String,
    pub text: String,
}

impl Engine {
    /// The resource indexes of the program, parsed now.
    ///
    /// # Errors
    /// [`EngineError::NoResources`] when no package of the program has an
    /// index that reads; its notes say what was looked at. A package
    /// without an index next to one that has it is a note
    /// ([`ResourceTables::notes`]), not an error.
    pub fn resources(&self) -> Result<ResourceTables<'_>> {
        let tables = ResourceTables::read(&self.program);
        if tables.tables.is_empty() {
            return Err(EngineError::NoResources { path: self.path().to_path_buf(), notes: tables.notes });
        }
        Ok(tables)
    }

    /// Whether the program has several packages (an `.app` counts next to
    /// the packages in it), so that what is said of one needs its name.
    pub fn has_several_packages(&self) -> bool {
        self.program.packages().len() > 1
    }

    /// Text files of the program's packages, as they are in the zip.
    ///
    /// `target` is a reference to a file resource (`$profile:main_pages`,
    /// `app.profile.router_map`, `profile/main_pages`): the file its `base`
    /// value names, in every package that has the resource (for a profile
    /// the build generated without listing it in the index,
    /// `resources/base/profile/NAME.json`). Or it is a path
    /// in a package (`resources/base/profile/main_pages.json`, also
    /// `resources/rawfile/…`, `module.json`): that file of every package
    /// that has it, or of one package when the path starts with its name
    /// (`entry.hap/resources/…`).
    ///
    /// # Errors
    /// [`EngineError::NotFound`] when no package has the file;
    /// [`EngineError::Query`] for a resource that is not a file, and for a
    /// file that is not text.
    pub fn package_files(&self, target: &str) -> Result<Vec<PackageFile>> {
        let target = target.trim();
        let by_reference = ResourceRef::parse(target).or_else(|| {
            // `profile/main_pages`, as `resources` rows name it; a path with more parts is a path.
            let (kind, name) = target.split_once('/')?;
            let kind = kind.parse().ok()?;
            (!name.contains('/') && !name.is_empty()).then_some(ResourceRef { kind, name })
        });
        let found = match by_reference {
            Some(reference) => self.files_of_resource(target, reference)?,
            None => self.files_at(target)?,
        };
        found
            .into_iter()
            .map(|(package, path, bytes)| match String::from_utf8(bytes) {
                Ok(text) => Ok(PackageFile { package, path, text }),
                Err(err) => Err(EngineError::Query(format!(
                    "{package}: {path} is not text ({} bytes): only text files are printed",
                    err.as_bytes().len()
                ))),
            })
            .collect()
    }

    /// The files the `base` value of `reference` names, per package; for a
    /// profile the index of a package does not list, the file where the
    /// build puts the ones it generates ([`generated_profile`]).
    fn files_of_resource(&self, target: &str, reference: ResourceRef<'_>) -> Result<Vec<(String, String, Vec<u8>)>> {
        // A program without any index may still have generated profiles.
        let tables = ResourceTables::read(&self.program);
        let mut found = Vec::new();
        let mut not_files = Vec::new();
        for (position, package) in self.program.packages().iter().enumerate() {
            let Some(value) = tables.table(&package.name).and_then(|table| table.default_value(Target::Named(reference))) else {
                if let Some(path) = generated_profile(&self.program, position, target) {
                    let bytes = self.program.file(position, &path)?.unwrap_or_default();
                    found.push((package.name.clone(), path, bytes.into_owned()));
                }
                continue;
            };
            let value = value.value();
            let Some(path) = value.archive_path() else {
                not_files.push(format!("{}: {target} is {value}, not a file", package.name));
                continue;
            };
            match self.program.file(position, path)? {
                Some(bytes) => found.push((package.name.clone(), path.to_owned(), bytes.into_owned())),
                None => not_files.push(format!("{}: {target} names {path}, which the package does not have", package.name)),
            }
        }
        match (found.is_empty(), not_files.is_empty()) {
            (false, _) => Ok(found),
            (true, false) => Err(EngineError::Query(not_files.join("; "))),
            (true, true) => Err(EngineError::NotFound { what: "resource", name: target.to_owned(), notes: tables.notes.clone() }),
        }
    }

    /// The file at `path` of every module package that has it; of one
    /// package when `path` starts with that package's name.
    fn files_at(&self, path: &str) -> Result<Vec<(String, String, Vec<u8>)>> {
        let packages = self.program.packages();
        let named = packages
            .iter()
            .enumerate()
            .find_map(|(position, package)| Some((position, path.strip_prefix(package.name.as_str())?.strip_prefix('/')?)));
        let candidates: Vec<(usize, &str)> = match named {
            Some(named) => vec![named],
            None => (0..packages.len()).map(|position| (position, path)).collect(),
        };
        let mut found = Vec::new();
        for (position, inner) in candidates {
            if let Some(bytes) = self.program.file(position, inner)? {
                found.push((packages[position].name.clone(), inner.to_owned(), bytes.into_owned()));
            }
        }
        if found.is_empty() {
            let notes = if packages.is_empty() { vec!["a bare .abc has no files".to_owned()] } else { Vec::new() };
            return Err(EngineError::NotFound { what: "file", name: path.to_owned(), notes });
        }
        Ok(found)
    }

    /// Name the resources a disassembly builds: an instruction that creates
    /// the object `$r('app.string.x')` compiles to
    /// (`createobjectwithbuffer [ "id", 16777236, "type", 10003, … ]`) gets
    /// `  # string/x "its base value"` appended, when the index of the
    /// code's package has a resource of that id and type. A text value is
    /// cut as a string literal of the listing is.
    ///
    /// The text is left as it is when the package has no index that reads,
    /// or the record cannot be found again: names are a convenience, never
    /// a reason for the listing to fail.
    pub fn annotate_resource_ids(&self, source: &mut ClassSource) {
        let Some(index) = self.index_of_entry(&source.entry) else { return };
        let Ok(located) = records::resolve_record(&self.program, &source.record, Some(&source.entry)) else { return };
        let Ok(methods) = located.class.methods() else { return };
        // The names behind the instructions of each function, by its raw name and their offset.
        let mut names: HashMap<String, HashMap<usize, String>> = HashMap::new();
        for method in methods.flatten() {
            let Ok(raw) = method.name() else { continue };
            let raw = raw.to_str();
            if source.function.as_deref().is_some_and(|wanted| wanted != raw) {
                continue;
            }
            let found = resource_objects(&located.abc, &method, &index);
            if !found.is_empty() {
                names.entry(raw.into_owned()).or_default().extend(found);
            }
        }
        if !names.is_empty() {
            source.text = annotate(&source.text, &names);
        }
    }

    /// The index of the package ABC entry `entry` is part of; of the one
    /// package that has an index, for a bare file.
    fn index_of_entry(&self, entry: &str) -> Option<ResourceIndex<'_>> {
        let program = &self.program;
        let position = program.infos().position(|info| info.name == entry)?;
        let package = program.package_of(position).or_else(|| {
            let mut indexed = (0..program.packages().len()).filter(|&package| program.resource_index(package).is_some());
            indexed.next().filter(|_| indexed.next().is_none())
        })?;
        Some(Table::read(program, package)?.ok()?.index)
    }
}

/// The path of the profile `reference` (`$profile:default-router-map`)
/// names in package `package`, when the package has the file though its
/// index does not list it: the build writes some profiles (the route table
/// it merges from the module's dependencies) straight into
/// `resources/base/profile/` after the index is made.
pub(crate) fn generated_profile(program: &Program, package: usize, reference: &str) -> Option<String> {
    let reference = ResourceRef::parse(reference)?;
    let path = format!("resources/base/profile/{}.json", reference.name);
    (reference.kind == ResourceType::Profile && program.has_file(package, &path)).then_some(path)
}

/// A profile of a package, as it is in the zip.
pub(crate) struct ProfileFile<'p> {
    /// Its path in the package: `resources/base/profile/main_pages.json`.
    pub(crate) path: String,
    pub(crate) bytes: Cow<'p, [u8]>,
}

/// The file the profile `reference` (`$profile:main_pages`) names in
/// package `package`: by the package's index (`table`, when it has one that
/// reads), else where the build puts the profiles it generates. `None` when
/// the package has no such file; the reason when the file does not read.
pub(crate) fn profile<'p>(
    program: &'p Program,
    package: usize,
    table: Option<&Table<'_>>,
    reference: &str,
) -> Option<std::result::Result<ProfileFile<'p>, String>> {
    let path = table.and_then(|table| table.file_path(reference)).or_else(|| generated_profile(program, package, reference))?;
    match program.file(package, &path) {
        Ok(Some(bytes)) => Some(Ok(ProfileFile { path, bytes })),
        Ok(None) => None,
        Err(err) => Some(Err(format!("{path}: {err}"))),
    }
}

/// The instructions of `method` that create a resource object, by offset,
/// each with the text that names the resource.
fn resource_objects(abc: &Abc<'_>, method: &Method<'_>, index: &ResourceIndex<'_>) -> Vec<(usize, String)> {
    let Ok(Some(code)) = method.code() else { return Vec::new() };
    let mut found = Vec::new();
    // Code that does not decode is annotated up to the bad instruction.
    for insn in asc_arkisa::walk(code.instructions()).map_while(std::result::Result::ok) {
        if crate::ops::base_name(insn.opcode) != "createobjectwithbuffer" {
            continue;
        }
        let Some(id) = insn.literal_array_id() else { continue };
        // A 16-bit id indexes the region's table; a wider one is the offset itself.
        let wide = insn.opcode.operand_of(OperandKind::LiteralArrayId).is_some_and(|operand| operand.width > 16);
        let offset = if wide { Some(id) } else { u16::try_from(id).ok().and_then(|id| abc.resolve_entity(method.offset(), id).ok()) };
        let Some(name) = offset.and_then(|offset| resource_of_literal(abc, offset, index)) else { continue };
        found.push((insn.pc, name));
    }
    found
}

/// `string/x "value"` when the literal array at `offset` opens as a
/// compiled `$r(...)` does (`"id", N, "type", T`) and the index has
/// resource `N` with the type `T` stands for.
fn resource_of_literal(abc: &Abc<'_>, offset: u32, index: &ResourceIndex<'_>) -> Option<String> {
    let mut items = abc.literal_array(offset).ok()?.iter();
    let mut keyed = |key: &str| -> Option<u32> {
        let Literal::String(name) = items.next()?.ok()? else { return None };
        if abc.string(name).ok()?.to_str() != key {
            return None;
        }
        match items.next()?.ok()? {
            Literal::Integer(value) => u32::try_from(value).ok(),
            _ => None,
        }
    };
    let id = keyed("id")?;
    let kind = ResourceType::from_object_code(keyed("type")?)?;
    let mut values: Vec<Resource<'_>> = index.by_id(id).collect();
    if values.is_empty() || values.iter().any(|value| value.kind() != kind) {
        return None;
    }
    values.sort_by_key(|value| !value.qualifiers().is_base());
    let first = values[0];
    let mut name = format!("{kind}/{}", first.name());
    if first.qualifiers().is_base() {
        name.push(' ');
        name.push_str(&shown_value(&first.value(), LISTING_VALUE_BYTES));
    }
    Some(name)
}

/// `listing` with `  # NAME` appended to the instruction lines `names`
/// has a name for: by the raw name of the `.function` block they are in
/// and their offset, the hex number the line starts with.
fn annotate(listing: &str, names: &HashMap<String, HashMap<usize, String>>) -> String {
    let mut out = String::with_capacity(listing.len() + listing.len() / 32);
    let mut function: Option<&HashMap<usize, String>> = None;
    for line in listing.split_inclusive('\n') {
        let body = line.trim_end_matches('\n');
        if let Some(header) = body.strip_prefix(".function ") {
            // `.function RAW  ; restored`.
            let raw = header.split_once("  ; ").map_or(header, |(raw, _)| raw);
            function = names.get(raw);
        }
        let mut words = body.split_whitespace();
        let offset = words.next().and_then(|word| usize::from_str_radix(word, 16).ok());
        let creates = words.next().is_some_and(|mnemonic| mnemonic.ends_with("createobjectwithbuffer"));
        let name = offset.filter(|_| creates && body.starts_with(' ')).and_then(|offset| function?.get(&offset));
        match name {
            Some(name) => {
                out.push_str(body);
                out.push_str("  # ");
                out.push_str(name);
                out.push_str(&line[body.len()..]);
            }
            None => out.push_str(line),
        }
    }
    out
}

/// The `$type:name` references of a manifest summary line: the values of
/// its `key=$type:name` words, outside quoted text.
fn references(line: &str) -> Vec<std::ops::Range<usize>> {
    let mut found = Vec::new();
    let mut quoted = false;
    let mut escaped = false;
    let mut word = 0;
    let ends = line.char_indices().chain([(line.len(), ' ')]);
    for (at, c) in ends {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ' ' if !quoted => {
                let token = &line[word..at];
                let value = token.rfind('=').map_or(0, |eq| eq + 1);
                let candidate = &token[value..];
                let plain = candidate.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'$' | b':' | b'_' | b'.' | b'-'));
                if plain && candidate.starts_with('$') && ResourceRef::parse(candidate).is_some() {
                    found.push(word + value..at);
                }
                word = at + 1;
            }
            _ => {}
        }
    }
    found
}

/// The `$type:name` references of a manifest summary line.
pub(crate) fn references_of(line: &str) -> impl Iterator<Item = &str> {
    references(line).into_iter().map(move |range| &line[range])
}

/// `line` with what `suffix` gives for each of its references put right
/// behind the reference: `label=$string:EntryAbility_label("Shop")`. A
/// reference `suffix` has nothing for stays as it is.
pub(crate) fn with_references<'l>(line: &'l str, suffix: impl Fn(&str) -> Option<String>) -> Cow<'l, str> {
    let mut out = String::new();
    let mut copied = 0;
    for range in references(line) {
        let Some(suffix) = suffix(&line[range.clone()]) else { continue };
        out.push_str(&line[copied..range.end]);
        out.push_str(&suffix);
        copied = range.end;
    }
    if copied == 0 {
        return Cow::Borrowed(line);
    }
    out.push_str(&line[copied..]);
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_name_an_id_or_a_type_and_name() {
        assert_eq!(Target::parse("0x01000003").unwrap(), Target::Id(0x0100_0003));
        assert_eq!(Target::parse(" 16777219 ").unwrap(), Target::Id(0x0100_0003));
        let named = Target::Named(ResourceRef { kind: ResourceType::String, name: "app_name" });
        for spelling in ["string/app_name", "$string:app_name", "app.string.app_name"] {
            assert_eq!(Target::parse(spelling).unwrap(), named, "{spelling}");
        }
        assert_eq!(Target::parse("nothing/x").unwrap_err().to_string(), "nothing/x: unknown resource type \"nothing\"");
        let error = Target::parse("app_name").unwrap_err().to_string();
        assert!(error.starts_with("\"app_name\" is not a resource: give an id (0x01000003, 16777219) or a name"), "{error}");
        assert!(Target::parse("string/").is_err() && Target::parse("sys.string.ok").is_err());
        assert_eq!("value".parse::<ResourceField>().unwrap(), ResourceField::Value);
        assert_eq!("both".parse::<ResourceField>().unwrap_err().to_string(), "a search is in name, value or any, not both");
    }

    #[test]
    fn references_of_a_summary_line_get_their_value() {
        let values = |reference: &str| match reference {
            "$string:label" => Some("(\"Shop\")".to_owned()),
            "$profile:main_pages" => Some("(resources/base/profile/main_pages.json)".to_owned()),
            _ => None,
        };
        let line = "ability Main label=$string:label icon=$media:icon pages=$profile:main_pages";
        assert_eq!(
            with_references(line, values),
            "ability Main label=$string:label(\"Shop\") icon=$media:icon pages=$profile:main_pages(resources/base/profile/main_pages.json)"
        );
        assert_eq!(references_of(line).collect::<Vec<_>>(), ["$string:label", "$media:icon", "$profile:main_pages"]);
        assert_eq!(references_of("ability Main exported=true").count(), 0);
        // Nothing to add: the line itself. A reference inside quoted text, or a system one, is not one.
        assert!(matches!(with_references("a=$media:icon b=1", values), Cow::Borrowed(_)));
        for untouched in ["description=\"see label=$string:label there\"", "label=$ohos:string:label", "label=$string:", "cost=$5"] {
            assert_eq!(with_references(untouched, |_| Some("(x)".to_owned())), untouched);
        }
        assert_eq!(with_references("reason=\"a \\\" b\" label=$string:label", values), "reason=\"a \\\" b\" label=$string:label(\"Shop\")");
    }

    #[test]
    fn listings_name_resources_by_function_and_offset() {
        let listing =
            ".function #~@0>#build  ; Index.build\n  0004  createobjectwithbuffer [ \"id\", 0x1000003 (16777219) ]\n  0008  sta v0\n\
                       .end function\n\n.function other\n  0004  createobjectwithbuffer [ \"id\", 1 ]\n";
        let names = HashMap::from([("#~@0>#build".to_owned(), HashMap::from([(4, "string/app_name \"Shop\"".to_owned())]))]);
        let annotated = annotate(listing, &names);
        let lines: Vec<&str> = annotated.lines().collect();
        assert_eq!(lines[1], "  0004  createobjectwithbuffer [ \"id\", 0x1000003 (16777219) ]  # string/app_name \"Shop\"");
        assert_eq!(annotated.replace("  # string/app_name \"Shop\"", ""), listing, "nothing else changes");
    }
}
