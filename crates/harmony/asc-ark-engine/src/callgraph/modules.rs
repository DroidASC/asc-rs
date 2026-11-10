//! How the records of a program are linked: which record a module request
//! names, and where the binding behind an exported name is defined.
//!
//! Everything here comes from the module records; no code is read. A
//! request is resolved when a walk meets it; only the reverse direction
//! (who imports a record) reads every module record, once, when the first
//! callers walk asks.
//!
//! A request is turned into a record name by its spelling:
//!
//! | request | record |
//! |---|---|
//! | `@normalized:N&<module>&<bundle>&<path>&<version>` | `<bundle>&<path>&<version>`, in the package whose module is `<module>` |
//! | `@bundle:<name>`, `@package:<name>` | `<name>` |
//! | `./x`, `../x` | relative to the directory of the requesting record |
//! | a package name (`lib`, `@scope/lib`) | the entry file of that package, from `pkgContextInfo.json` of the requesting package |
//! | any other text not starting with `@` | that name |
//! | `@normalized:Y&…` (a native library), `@ohos:…`, `@hms:…`, `@native:…`, `@app:…` and other `@` forms | none: outside the program |
//!
//! Where the name is looked up: a request that names a module is looked up
//! in the package of the program whose `module.json` has that module name
//! (a library packed into several packages has a record of one name in
//! each); without a module, or when that package is not in the program or
//! has no such record, in the entry of the requesting record first, then in
//! the other entries of the program in order. A request that does not
//! resolve stays unresolved, and a call through it is an external leaf.
//!
//! The package tables ([`Packages`]) are read from the documents of the
//! packages when a request first needs them: the module names when a
//! request names a module, `pkgContextInfo.json` of one package when a
//! record of it requests a package by name.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::OnceLock;

use asc_abc::{Abc, Class, ClassEntry};
use asc_hap::{ModuleJson, PkgContextInfo};

use crate::manifest::Document;
use crate::program::Program;
use crate::refs::{chunks, run_units, RECORD_CHUNK};
use crate::{table_bytes, Result};

/// Re-exports followed from one record to the next before an export is
/// given up.
const MAX_EXPORT_HOPS: usize = 8;

/// A record of a program: the ABC entry and the offset of its class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct RecordId {
    pub entry: u32,
    pub class: u32,
}

/// How a module request is spelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum RequestForm {
    /// `@normalized:N&…`: a module of the program or of a library package.
    Normalized,
    /// `@normalized:Y&…`: a native library.
    NormalizedNative,
    /// `@bundle:…`.
    Bundle,
    /// `@package:…`.
    Package,
    /// `@ohos:…`, `@hms:…`, `@native:…`, `@app:…` and any other `@` form.
    System,
    /// `./…`, `../…`.
    Relative,
    /// Anything else: taken as a record name.
    Plain,
}

impl RequestForm {
    pub const fn label(self) -> &'static str {
        match self {
            RequestForm::Normalized => "@normalized:N",
            RequestForm::NormalizedNative => "@normalized:Y",
            RequestForm::Bundle => "@bundle:",
            RequestForm::Package => "@package:",
            RequestForm::System => "@ohos: / @hms: / other @",
            RequestForm::Relative => "relative",
            RequestForm::Plain => "plain name",
        }
    }
}

/// How many requests of one form there are and how many name a record of
/// the program.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FormCount {
    /// Requests, counted once per requesting record.
    pub requests: usize,
    pub resolved: usize,
}

/// What the spelling of a module request says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Spelled<'r> {
    pub form: RequestForm,
    /// The module a `@normalized:N` request names; empty when it names none.
    pub module: &'r str,
    /// The record name the request stands for, when its spelling gives one.
    pub record: Option<Cow<'r, str>>,
}

impl<'r> Spelled<'r> {
    /// Read `request`; `from` is the name of the requesting record.
    pub(crate) fn of(request: &'r str, from: &str) -> Spelled<'r> {
        let spelled = |form, record| Spelled { form, module: "", record };
        if let Some(rest) = request.strip_prefix("@normalized:") {
            let mut fields = rest.splitn(5, '&');
            let (kind, module, bundle, path, version) = (fields.next(), fields.next(), fields.next(), fields.next(), fields.next());
            return match (kind, bundle, path) {
                (Some("N"), Some(bundle), Some(path)) if !path.is_empty() => Spelled {
                    form: RequestForm::Normalized,
                    module: module.unwrap_or_default(),
                    record: Some(Cow::Owned(format!("{bundle}&{path}&{}", version.unwrap_or_default()))),
                },
                (Some("N"), _, _) => spelled(RequestForm::Normalized, None),
                _ => spelled(RequestForm::NormalizedNative, None),
            };
        }
        if let Some(name) = request.strip_prefix("@bundle:") {
            return spelled(RequestForm::Bundle, Some(Cow::Borrowed(name)));
        }
        if let Some(name) = request.strip_prefix("@package:") {
            return spelled(RequestForm::Package, Some(Cow::Borrowed(name)));
        }
        if request.starts_with('@') {
            return spelled(RequestForm::System, None);
        }
        if request.starts_with("./") || request.starts_with("../") {
            let mut segments: Vec<&str> = from.split('/').collect();
            segments.pop();
            for segment in request.split('/') {
                match segment {
                    "." | "" => {}
                    ".." => {
                        if segments.pop().is_none() {
                            return spelled(RequestForm::Relative, None);
                        }
                    }
                    name => segments.push(name),
                }
            }
            return spelled(RequestForm::Relative, Some(Cow::Owned(segments.join("/"))));
        }
        spelled(RequestForm::Plain, Some(Cow::Borrowed(request)))
    }

    /// Whether `request` may be the name of a package: a plain name, or a
    /// scoped one (`@scope/lib`), which has no `:` as the system forms do.
    fn may_name_a_package(&self, request: &str) -> bool {
        match self.form {
            RequestForm::Plain => true,
            RequestForm::System => !request.contains(':'),
            RequestForm::Normalized
            | RequestForm::NormalizedNative
            | RequestForm::Bundle
            | RequestForm::Package
            | RequestForm::Relative => false,
        }
    }
}

/// Where a request for a package by its name leads.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EntryPoint {
    /// The record of the package's entry file.
    record: String,
    /// The module whose package holds it; empty for the requesting one.
    module: String,
}

/// What the documents of the packages of a program say about where records
/// are: read when a request first needs it and kept with the call graph.
#[derive(Default)]
pub(crate) struct Packages {
    /// Per module name (`module.name` of `module.json`): the ABC entries of
    /// the packages of that name, in program order.
    by_module: OnceLock<HashMap<String, Vec<u32>>>,
    /// Per package of the program: the entry file of each package its
    /// `pkgContextInfo.json` lists, by the name requests use.
    entry_points: OnceLock<Vec<OnceLock<HashMap<String, EntryPoint>>>>,
    /// Heap bytes of what was read so far, roughly.
    bytes: AtomicUsize,
}

impl Packages {
    /// Bytes the tables read so far take on the heap, roughly.
    pub(crate) fn heap_bytes(&self) -> usize {
        self.bytes.load(Ordering::Relaxed)
    }

    /// The ABC entries of the packages whose module is called `module`.
    fn entries_of_module(&self, program: &Program, module: &str) -> &[u32] {
        let by_module = self.by_module.get_or_init(|| {
            let mut by_module: HashMap<String, Vec<u32>> = HashMap::new();
            for package in 0..program.packages().len() {
                // A package without a manifest, or with one that does not parse, has no module name.
                let manifest = program.document(package, Document::Module).and_then(|bytes| ModuleJson::parse(bytes).ok());
                let Some(name) = manifest.and_then(|manifest| manifest.module.name) else { continue };
                let entries = program.entries_of(Some(package)).filter_map(|entry| u32::try_from(entry).ok());
                by_module.entry(name).or_default().extend(entries);
            }
            let strings: usize = by_module.iter().map(|(name, entries)| name.capacity() + entries.capacity() * 4).sum();
            self.bytes.fetch_add(table_bytes(&by_module) + strings, Ordering::Relaxed);
            by_module
        });
        by_module.get(module).map_or(&[], Vec::as_slice)
    }

    /// Where a record of ABC entry `entry` that requests the package `name`
    /// is led: the entry file `pkgContextInfo.json` of its package gives.
    fn entry_point(&self, program: &Program, entry: u32, name: &str) -> Option<&EntryPoint> {
        let package = program.package_of(entry as usize)?;
        let tables = self.entry_points.get_or_init(|| (0..program.packages().len()).map(|_| OnceLock::new()).collect());
        let table = tables.get(package)?.get_or_init(|| {
            // A package without the table, or with one that does not parse, names no package.
            let context = program.document(package, Document::PkgContext).and_then(|bytes| PkgContextInfo::parse(bytes).ok());
            let mut table = HashMap::new();
            for listed in context.iter().flat_map(|context| context.packages()) {
                if let Some(record) = listed.entry_record_name() {
                    table.insert(listed.name.clone(), EntryPoint { record, module: listed.module_name.clone() });
                }
            }
            let strings: usize =
                table.iter().map(|(name, point)| name.capacity() + point.record.capacity() + point.module.capacity()).sum();
            self.bytes.fetch_add(table_bytes(&table) + strings, Ordering::Relaxed);
            table
        });
        table.get(name)
    }
}

/// The program as the links between its records see it.
#[derive(Clone, Copy)]
pub(crate) struct Layout<'s, 'e> {
    /// The entries by index; `None` for the unreadable ones.
    pub abcs: &'s [Option<Abc<'e>>],
    pub program: &'e Program,
    pub packages: &'s Packages,
}

/// The binding behind an exported name: the record that defines it and the
/// local export entries that share its local name (`stmodulevar` uses one
/// of their indexes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Binding {
    pub record: RecordId,
    pub exports: Vec<u32>,
}

/// Who imports each record of a program.
#[derive(Debug, Default)]
pub(crate) struct Importers {
    /// Per record: the records with a request that names it.
    importers: HashMap<RecordId, Vec<RecordId>>,
    /// Per record: the records that re-export from it (`export … from`).
    reexporters: HashMap<RecordId, Vec<RecordId>>,
    forms: BTreeMap<RequestForm, FormCount>,
}

/// What one record contributes to [`Importers`].
struct RecordLinks {
    id: RecordId,
    /// The records its requests name.
    targets: HashSet<RecordId>,
    reexports: HashSet<RecordId>,
    forms: Vec<(RequestForm, bool)>,
}

fn string<'a>(abc: &Abc<'a>, off: u32) -> Option<&'a [u8]> {
    abc.string(off).ok().map(|string| string.bytes)
}

impl Importers {
    /// Read the module record of every record of the program.
    pub(crate) fn build(layout: Layout<'_, '_>, workers: usize, cancel: &AtomicBool) -> Result<Importers> {
        let mut out = Importers::default();
        for (entry, abc) in layout.abcs.iter().enumerate() {
            let Some(abc) = abc else { continue };
            let entry = u32::try_from(entry).unwrap_or(u32::MAX);
            // An entry whose class index does not read has no records to link.
            let classes: Vec<u32> = abc.class_index().map(|index| index.iter().collect()).unwrap_or_default();
            let units: Vec<Range<usize>> = chunks(classes.len(), RECORD_CHUNK).collect();
            let linked = run_units(units.len(), workers, cancel, |unit| {
                let mut out = Vec::new();
                for &off in &classes[units[unit].clone()] {
                    let Ok(ClassEntry::Local(class)) = abc.class_entry(off) else { continue };
                    out.extend(layout.record_links(entry, &class));
                }
                out
            })?;
            for record in linked.into_iter().flatten() {
                for (form, resolved) in record.forms {
                    let count = out.forms.entry(form).or_default();
                    count.requests += 1;
                    count.resolved += usize::from(resolved);
                }
                for target in record.targets {
                    out.importers.entry(target).or_default().push(record.id);
                }
                for target in record.reexports {
                    out.reexporters.entry(target).or_default().push(record.id);
                }
            }
        }
        Ok(out)
    }

    /// Bytes this takes on the heap, roughly.
    pub(crate) fn heap_bytes(&self) -> usize {
        let lists = |map: &HashMap<RecordId, Vec<RecordId>>| {
            table_bytes(map) + map.values().map(|list| list.capacity() * std::mem::size_of::<RecordId>()).sum::<usize>()
        };
        lists(&self.importers) + lists(&self.reexporters)
    }

    pub(crate) fn forms(&self) -> &BTreeMap<RequestForm, FormCount> {
        &self.forms
    }

    /// Every record whose code can name a binding of `record` through an
    /// import: the records that request it, or that request a record which
    /// re-exports from it, however many re-exports lie between.
    pub(crate) fn importers_of(&self, record: RecordId) -> HashSet<RecordId> {
        let mut exporters = HashSet::from([record]);
        let mut work = vec![record];
        while let Some(exporter) = work.pop() {
            for &outer in self.reexporters.get(&exporter).into_iter().flatten() {
                if exporters.insert(outer) {
                    work.push(outer);
                }
            }
        }
        exporters.iter().flat_map(|exporter| self.importers.get(exporter).into_iter().flatten().copied()).collect()
    }
}

impl Layout<'_, '_> {
    /// The record request `index` of `record` names; `None` outside the program.
    pub(crate) fn request(&self, record: RecordId, index: u16) -> Option<RecordId> {
        let abc = self.abcs.get(record.entry as usize)?.as_ref()?;
        let class = abc.class(record.class).ok()?;
        let module = class.module_record().ok()??;
        let text = abc.string(module.request(index)?).ok()?.to_str();
        self.target(record.entry, &text, &String::from_utf8_lossy(class.name())).1
    }

    /// The form of `request`, made by record `from` of entry `entry`, and
    /// the record it names.
    fn target(&self, entry: u32, request: &str, from: &str) -> (RequestForm, Option<RecordId>) {
        let spelled = Spelled::of(request, from);
        if spelled.may_name_a_package(request) {
            if let Some(point) = self.packages.entry_point(self.program, entry, request) {
                // The table decides: a package whose entry file is not in the program is outside it.
                return (spelled.form, self.find_record(entry, &point.module, &point.record));
            }
        }
        let found = spelled.record.as_deref().and_then(|name| self.find_record(entry, spelled.module, name));
        (spelled.form, found)
    }

    /// Where the binding `record` exports as `name` is defined: its own
    /// local export, or the one an `export … from` chain ends at. `None`
    /// when the name is not exported, a link of the chain is outside the
    /// program, the chain is longer than [`MAX_EXPORT_HOPS`], or two
    /// `export *` provide the name from different bindings.
    pub(crate) fn export(&self, record: RecordId, name: &[u8]) -> Option<Binding> {
        self.export_at(record, name, 0)
    }

    fn export_at(&self, record: RecordId, name: &[u8], hops: usize) -> Option<Binding> {
        if hops > MAX_EXPORT_HOPS {
            return None;
        }
        let abc = self.abcs.get(record.entry as usize)?.as_ref()?;
        let module = abc.class(record.class).ok()?.module_record().ok()??;
        let named = |off: u32| string(abc, off) == Some(name);
        if let Some(export) = module.local_exports.iter().find(|export| named(export.export_name_off)) {
            let local = string(abc, export.local_name_off)?;
            let group = module.local_exports.iter().enumerate().filter(|(_, other)| string(abc, other.local_name_off) == Some(local));
            return Some(Binding { record, exports: group.filter_map(|(index, _)| u32::try_from(index).ok()).collect() });
        }
        if let Some(export) = module.indirect_exports.iter().find(|export| named(export.export_name_off)) {
            let target = self.request(record, export.module_request_idx)?;
            return self.export_at(target, string(abc, export.import_name_off)?, hops + 1);
        }
        // `export *` does not pass `default` on.
        if name == b"default" {
            return None;
        }
        let mut found: Option<Binding> = None;
        for star in module.star_exports.iter() {
            let Some(target) = self.request(record, star.module_request_idx) else { continue };
            let Some(binding) = self.export_at(target, name, hops + 1) else { continue };
            match &found {
                Some(known) if *known != binding => return None,
                Some(_) => {}
                None => found = Some(binding),
            }
        }
        found
    }

    /// Find the record called `name`: in the packages whose module is
    /// `module` when it names one of the program, else (or when they have
    /// no such record) in entry `first`, then in the others.
    fn find_record(&self, first: u32, module: &str, name: &str) -> Option<RecordId> {
        let lookup = |entry: usize| {
            let abc = self.abcs.get(entry)?.as_ref()?;
            let class = abc.find_record(name.as_bytes()).ok()??.local()?;
            Some(RecordId { entry: u32::try_from(entry).ok()?, class: class.offset() })
        };
        let named: &[u32] = if module.is_empty() { &[] } else { self.packages.entries_of_module(self.program, module) };
        named
            .iter()
            .find_map(|&entry| lookup(entry as usize))
            .or_else(|| lookup(first as usize))
            .or_else(|| (0..self.abcs.len()).filter(|&entry| entry != first as usize).find_map(lookup))
    }

    fn record_links(&self, entry: u32, class: &Class<'_>) -> Option<RecordLinks> {
        let abc = self.abcs.get(entry as usize)?.as_ref()?;
        let module = class.module_record().ok()??;
        let from = String::from_utf8_lossy(class.name());
        let mut forms = Vec::with_capacity(module.requests.len() as usize);
        let requests: Vec<Option<RecordId>> = module
            .requests
            .iter()
            .map(|off| {
                let request = abc.string(off).ok()?.to_str();
                let (form, target) = self.target(entry, &request, &from);
                forms.push((form, target.is_some()));
                target
            })
            .collect();
        let target = |index: u16| requests.get(usize::from(index)).copied().flatten();
        let indirect = module.indirect_exports.iter().filter_map(|export| target(export.module_request_idx));
        let star = module.star_exports.iter().filter_map(|export| target(export.module_request_idx));
        Some(RecordLinks {
            id: RecordId { entry, class: class.offset() },
            reexports: indirect.chain(star).collect(),
            targets: requests.iter().flatten().copied().collect(),
            forms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_name_records_by_their_spelling() {
        let name = |request| {
            let spelled = Spelled::of(request, "com.app/entry/ets/pages/Index");
            (spelled.form, spelled.record.map(Cow::into_owned))
        };
        let record = |name: &str| Some(name.to_owned());
        assert_eq!(
            name("@normalized:N&&&entry/src/main/ets/util/Util&"),
            (RequestForm::Normalized, record("&entry/src/main/ets/util/Util&"))
        );
        assert_eq!(
            name("@normalized:N&lib&com.other.app&@ohos/lib/index&1.2.0"),
            (RequestForm::Normalized, record("com.other.app&@ohos/lib/index&1.2.0"))
        );
        assert_eq!(name("@normalized:N&&"), (RequestForm::Normalized, None));
        assert_eq!(name("@normalized:Y&&&libentry.so&"), (RequestForm::NormalizedNative, None));
        assert_eq!(name("@bundle:com.app/entry/ets/model/Store"), (RequestForm::Bundle, record("com.app/entry/ets/model/Store")));
        assert_eq!(name("@package:pkg_modules/lib/index"), (RequestForm::Package, record("pkg_modules/lib/index")));
        assert_eq!(name("@ohos:net.http"), (RequestForm::System, None));
        assert_eq!(name("@app:com.app/entry/entry"), (RequestForm::System, None));
        assert_eq!(name("./Detail"), (RequestForm::Relative, record("com.app/entry/ets/pages/Detail")));
        assert_eq!(name("../model/./Store"), (RequestForm::Relative, record("com.app/entry/ets/model/Store")));
        assert_eq!(Spelled::of("../../x", "a/b").record, None);
        assert_eq!(name("some/record"), (RequestForm::Plain, record("some/record")));
    }

    #[test]
    fn requests_say_which_module_and_whether_they_may_name_a_package() {
        let spelled = |request| Spelled::of(request, "&entry/src/main/ets/pages/Index&");
        assert_eq!(spelled("@normalized:N&lib&&shared/src/main/ets/Tool&1.0.0").module, "lib");
        assert_eq!(spelled("@normalized:N&&&shared/src/main/ets/Tool&1.0.0").module, "");
        assert_eq!(spelled("@normalized:Y&lib&&libtool.so&").module, "");
        for (request, may) in [
            ("tool", true),
            ("@scope/tool", true),
            ("@ohos:net.http", false),
            ("@bundle:com.app/entry/ets/model/Store", false),
            ("./Detail", false),
            ("@normalized:N&&&shared/src/main/ets/Tool&1.0.0", false),
        ] {
            assert_eq!(spelled(request).may_name_a_package(request), may, "{request}");
        }
    }
}
