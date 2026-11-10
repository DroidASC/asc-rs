//! How the records of a program are linked: which record a module request
//! names, and where the binding behind an exported name is defined.
//!
//! Everything here comes from the module records; no code is read. A
//! request is resolved when a walk meets it; only the reverse direction
//! (who imports a record) reads every module record, once, when the first
//! callers walk asks.
//!
//! A request is turned into a record name by its spelling alone:
//!
//! | request | record |
//! |---|---|
//! | `@normalized:N&<module>&<bundle>&<path>&<version>` | `<bundle>&<path>&<version>` |
//! | `@bundle:<name>`, `@package:<name>` | `<name>` |
//! | `./x`, `../x` | relative to the directory of the requesting record |
//! | any other text not starting with `@` | that name |
//! | `@normalized:Y&…` (a native library), `@ohos:…`, `@hms:…`, `@native:…`, `@app:…` and other `@` forms | none: outside the program |
//!
//! The name is then looked up in the entry of the requesting record first,
//! then in the other entries of the program. Nothing else is tried: a
//! request that needs `pkgContextInfo.json` or an alias table to resolve
//! stays unresolved, and a call through it is an external leaf.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ops::Range;
use std::sync::atomic::AtomicBool;

use asc_abc::{Abc, Class, ClassEntry};

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

/// The form of `request` and the record name it stands for, when its
/// spelling gives one. `from` is the name of the requesting record.
pub(crate) fn record_name<'r>(request: &'r str, from: &str) -> (RequestForm, Option<Cow<'r, str>>) {
    if let Some(rest) = request.strip_prefix("@normalized:") {
        let mut fields = rest.splitn(5, '&');
        let (kind, _module, bundle, path, version) = (fields.next(), fields.next(), fields.next(), fields.next(), fields.next());
        return match (kind, bundle, path) {
            (Some("N"), Some(bundle), Some(path)) if !path.is_empty() => {
                (RequestForm::Normalized, Some(Cow::Owned(format!("{bundle}&{path}&{}", version.unwrap_or_default()))))
            }
            (Some("N"), _, _) => (RequestForm::Normalized, None),
            _ => (RequestForm::NormalizedNative, None),
        };
    }
    if let Some(name) = request.strip_prefix("@bundle:") {
        return (RequestForm::Bundle, Some(Cow::Borrowed(name)));
    }
    if let Some(name) = request.strip_prefix("@package:") {
        return (RequestForm::Package, Some(Cow::Borrowed(name)));
    }
    if request.starts_with('@') {
        return (RequestForm::System, None);
    }
    if request.starts_with("./") || request.starts_with("../") {
        let mut segments: Vec<&str> = from.split('/').collect();
        segments.pop();
        for segment in request.split('/') {
            match segment {
                "." | "" => {}
                ".." => {
                    if segments.pop().is_none() {
                        return (RequestForm::Relative, None);
                    }
                }
                name => segments.push(name),
            }
        }
        return (RequestForm::Relative, Some(Cow::Owned(segments.join("/"))));
    }
    (RequestForm::Plain, Some(Cow::Borrowed(request)))
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
    /// Read the module record of every record of the program. `abcs` are
    /// its entries by index, `None` for the unreadable ones.
    pub(crate) fn build(abcs: &[Option<Abc<'_>>], workers: usize, cancel: &AtomicBool) -> Result<Importers> {
        let mut out = Importers::default();
        for (entry, abc) in abcs.iter().enumerate() {
            let Some(abc) = abc else { continue };
            let entry = u32::try_from(entry).unwrap_or(u32::MAX);
            // An entry whose class index does not read has no records to link.
            let classes: Vec<u32> = abc.class_index().map(|index| index.iter().collect()).unwrap_or_default();
            let units: Vec<Range<usize>> = chunks(classes.len(), RECORD_CHUNK).collect();
            let linked = run_units(units.len(), workers, cancel, |unit| {
                let mut out = Vec::new();
                for &off in &classes[units[unit].clone()] {
                    let Ok(ClassEntry::Local(class)) = abc.class_entry(off) else { continue };
                    out.extend(record_links(abcs, entry, &class));
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

/// The record request `index` of `record` names; `None` outside the program.
pub(crate) fn request(abcs: &[Option<Abc<'_>>], record: RecordId, index: u16) -> Option<RecordId> {
    let abc = abcs.get(record.entry as usize)?.as_ref()?;
    let class = abc.class(record.class).ok()?;
    let module = class.module_record().ok()??;
    let text = abc.string(module.request(index)?).ok()?.to_str();
    let (_, name) = record_name(&text, &String::from_utf8_lossy(class.name()));
    find_record(abcs, record.entry, &name?)
}

/// Where the binding `record` exports as `name` is defined: its own local
/// export, or the one an `export … from` chain ends at. `None` when the
/// name is not exported, a link of the chain is outside the program, the
/// chain is longer than [`MAX_EXPORT_HOPS`], or two `export *` provide the
/// name from different bindings.
pub(crate) fn export(abcs: &[Option<Abc<'_>>], record: RecordId, name: &[u8]) -> Option<Binding> {
    export_at(abcs, record, name, 0)
}

fn export_at(abcs: &[Option<Abc<'_>>], record: RecordId, name: &[u8], hops: usize) -> Option<Binding> {
    if hops > MAX_EXPORT_HOPS {
        return None;
    }
    let abc = abcs.get(record.entry as usize)?.as_ref()?;
    let module = abc.class(record.class).ok()?.module_record().ok()??;
    let named = |off: u32| string(abc, off) == Some(name);
    if let Some(export) = module.local_exports.iter().find(|export| named(export.export_name_off)) {
        let local = string(abc, export.local_name_off)?;
        let group = module.local_exports.iter().enumerate().filter(|(_, other)| string(abc, other.local_name_off) == Some(local));
        return Some(Binding { record, exports: group.filter_map(|(index, _)| u32::try_from(index).ok()).collect() });
    }
    if let Some(export) = module.indirect_exports.iter().find(|export| named(export.export_name_off)) {
        let target = request(abcs, record, export.module_request_idx)?;
        return export_at(abcs, target, string(abc, export.import_name_off)?, hops + 1);
    }
    // `export *` does not pass `default` on.
    if name == b"default" {
        return None;
    }
    let mut found: Option<Binding> = None;
    for star in module.star_exports.iter() {
        let Some(target) = request(abcs, record, star.module_request_idx) else { continue };
        let Some(binding) = export_at(abcs, target, name, hops + 1) else { continue };
        match &found {
            Some(known) if *known != binding => return None,
            Some(_) => {}
            None => found = Some(binding),
        }
    }
    found
}

/// Find the record called `name`: in entry `first`, then in the others.
fn find_record(abcs: &[Option<Abc<'_>>], first: u32, name: &str) -> Option<RecordId> {
    let lookup = |entry: usize| {
        let abc = abcs.get(entry)?.as_ref()?;
        let class = abc.find_record(name.as_bytes()).ok()??.local()?;
        Some(RecordId { entry: u32::try_from(entry).ok()?, class: class.offset() })
    };
    lookup(first as usize).or_else(|| (0..abcs.len()).filter(|&entry| entry != first as usize).find_map(lookup))
}

fn record_links(abcs: &[Option<Abc<'_>>], entry: u32, class: &Class<'_>) -> Option<RecordLinks> {
    let abc = abcs.get(entry as usize)?.as_ref()?;
    let module = class.module_record().ok()??;
    let from = String::from_utf8_lossy(class.name());
    let mut forms = Vec::with_capacity(module.requests.len() as usize);
    let requests: Vec<Option<RecordId>> = module
        .requests
        .iter()
        .map(|off| {
            let request = abc.string(off).ok()?.to_str();
            let (form, name) = record_name(&request, &from);
            let target = name.and_then(|name| find_record(abcs, entry, &name));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_name_records_by_their_spelling() {
        let name = |request| record_name(request, "com.app/entry/ets/pages/Index");
        assert_eq!(
            name("@normalized:N&&&entry/src/main/ets/util/Util&"),
            (RequestForm::Normalized, Some("&entry/src/main/ets/util/Util&".into()))
        );
        assert_eq!(
            name("@normalized:N&lib&com.other.app&@ohos/lib/index&1.2.0"),
            (RequestForm::Normalized, Some("com.other.app&@ohos/lib/index&1.2.0".into()))
        );
        assert_eq!(name("@normalized:N&&"), (RequestForm::Normalized, None));
        assert_eq!(name("@normalized:Y&&&libentry.so&"), (RequestForm::NormalizedNative, None));
        assert_eq!(name("@bundle:com.app/entry/ets/model/Store"), (RequestForm::Bundle, Some("com.app/entry/ets/model/Store".into())));
        assert_eq!(name("@package:pkg_modules/lib/index"), (RequestForm::Package, Some("pkg_modules/lib/index".into())));
        assert_eq!(name("@ohos:net.http"), (RequestForm::System, None));
        assert_eq!(name("@app:com.app/entry/entry"), (RequestForm::System, None));
        assert_eq!(name("./Detail"), (RequestForm::Relative, Some("com.app/entry/ets/pages/Detail".into())));
        assert_eq!(name("../model/./Store"), (RequestForm::Relative, Some("com.app/entry/ets/model/Store".into())));
        assert_eq!(record_name("../../x", "a/b"), (RequestForm::Relative, None));
        assert_eq!(name("some/record"), (RequestForm::Plain, Some("some/record".into())));
    }
}
