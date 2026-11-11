//! Record enumeration (`listclass`) and name resolution (`getclass`).
//!
//! A record is one source module (plus a few compiler-made pseudo records).
//! Its canonical name is the one stored in the file, e.g.
//! `&entry/src/main/ets/pages/Index&`; queries may also spell it by a path
//! suffix (`pages/Index`, `pages/Index.ets`). An annotation interface is a
//! record of its own, named after its module: `pages/Index.Marked`.

use std::borrow::Cow;

use asc_abc::{Abc, Class, ClassEntry, Method, RecordKind, RecordName};
use regex::Regex;

use crate::program::Program;
use crate::{text, EngineError, Result};

/// Candidates an ambiguity error lists before it says how many more there are.
const MAX_CANDIDATES: usize = 20;
/// Source file extensions a record query may carry.
const SOURCE_EXTENSIONS: [&str; 3] = [".ets", ".ts", ".js"];

/// Which records [`crate::Engine::list_classes`] keeps, by record name.
#[derive(Debug, Clone)]
pub enum NameFilter {
    /// The name starts with this; the decoration of a normalized name is
    /// optional (`entry/src/main` matches `&entry/src/main/ets/pages/Index&`).
    Prefix(String),
    /// The name contains this.
    Contains(String),
    /// The regex matches somewhere in the name.
    Regex(Regex),
}

impl NameFilter {
    fn matches(&self, name: &str) -> bool {
        match self {
            NameFilter::Prefix(prefix) => name.starts_with(prefix.as_str()) || plain_name(name).starts_with(prefix.as_str()),
            NameFilter::Contains(part) => name.contains(part.as_str()),
            NameFilter::Regex(regex) => regex.is_match(name),
        }
    }
}

/// Options of [`crate::Engine::list_classes`].
#[derive(Debug, Clone, Default)]
pub struct ListOptions {
    pub filter: Option<NameFilter>,
    /// Also list pseudo records (the compiler's `_ES…` annotation records
    /// and system module placeholders such as `@ohos.app`) and records the
    /// file only declares. The annotation interfaces of the program are
    /// listed either way.
    pub all: bool,
    /// Only the records of the ABC entries this names: an entry or a
    /// package, as [`crate::Engine::find_refs_in`] takes it.
    pub entry: Option<String>,
}

/// One record of a program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordListing {
    /// The ABC entry that defines it.
    pub entry: String,
    /// Canonical name, as stored (without the `L…;` wrapper).
    pub name: String,
    pub kind: RecordKind,
    pub source_file: Option<String>,
    /// Number of functions (methods of the record).
    pub functions: u32,
    /// Declared here, defined in another file: a name and nothing else.
    pub foreign: bool,
}

impl RecordListing {
    /// `name | functions=N source=FILE`, with ` kind=…` for a record that
    /// is no module (a pseudo record, an annotation interface) and a third
    /// column naming the entry when `with_entry`.
    pub fn line(&self, with_entry: bool) -> String {
        let mut out = format!("{} | functions={}", self.name, self.functions);
        if let Some(source) = &self.source_file {
            out.push_str(" source=");
            out.push_str(&text::value(source));
        }
        match self.kind {
            RecordKind::Module => {}
            RecordKind::Service => out.push_str(" kind=service"),
            RecordKind::SystemModule => out.push_str(" kind=system-module"),
            RecordKind::Annotation => out.push_str(" kind=annotation"),
        }
        if self.foreign {
            out.push_str(" foreign");
        }
        if with_entry {
            out.push_str(" | ");
            out.push_str(&self.entry);
        }
        out
    }
}

/// The name without the decoration of the normalized form:
/// `entry/src/main/ets/pages/Index` for `&entry/src/main/ets/pages/Index&`,
/// `@ohos/crypto-js/index` for `&@ohos/crypto-js/index&2.0.0`. An annotation
/// interface keeps its own name after its module's:
/// `@ohos/lib/index.Marked` for `&@ohos/lib/index&1.2.0.Marked`.
fn plain_name(name: &str) -> Cow<'_, str> {
    match RecordName::parse(name) {
        RecordName::Normalized { bundle, version, .. } => Cow::Borrowed(undecorated(name, bundle, version)),
        RecordName::Annotation { module, interface } => match RecordName::parse(module) {
            RecordName::Normalized { bundle, version, .. } => Cow::Owned(format!("{}.{interface}", undecorated(module, bundle, version))),
            // The module of an interface is of the normalized form: nothing else is read as one.
            RecordName::Annotation { .. }
            | RecordName::Bundle { .. }
            | RecordName::Service(_)
            | RecordName::SystemModule(_)
            | RecordName::Other(_) => Cow::Borrowed(name),
        },
        RecordName::Bundle { .. } | RecordName::Service(_) | RecordName::SystemModule(_) | RecordName::Other(_) => Cow::Borrowed(name),
    }
}

/// What is between the two `&` of the normalized name
/// `<bundle>&<package>/<path>&<version>`.
fn undecorated<'n>(name: &'n str, bundle: &str, version: &str) -> &'n str {
    name.get(bundle.len() + 1..name.len() - version.len() - 1).unwrap_or(name)
}

/// The records `abc` defines, in class index order (the writer sorts it by
/// name).
fn local_records<'a>(abc: Abc<'a>, entry: &'a str) -> Result<impl Iterator<Item = Result<Class<'a>>> + 'a> {
    let wrap = move |source| EngineError::Abc { entry: entry.to_owned(), source };
    let classes = abc.classes().map_err(wrap)?;
    Ok(classes.filter_map(move |class| match class {
        Ok(ClassEntry::Local(class)) => Some(Ok(class)),
        Ok(ClassEntry::Foreign(_)) => None,
        Err(source) => Some(Err(wrap(source))),
    }))
}

pub(crate) fn list(program: &Program, options: &ListOptions) -> Result<Vec<RecordListing>> {
    let mut out = Vec::new();
    let selected = selected_entries(program, options.entry.as_deref())?;
    for (index, abc) in program.readable().filter(|(index, _)| selected.contains(index)) {
        let entry = program.info(index).map_or("", |info| info.name.as_str());
        let wrap = |source| EngineError::Abc { entry: entry.to_owned(), source };
        for class in abc.classes().map_err(wrap)? {
            let class = class.map_err(wrap)?;
            let name = String::from_utf8_lossy(class.name());
            let local = class.local();
            // A record of the file knows what it is; of one it only declares, the name is all there is.
            let kind = local.map_or_else(|| RecordName::parse(&name).kind(), |class| class.kind());
            let is_pseudo = matches!(kind, RecordKind::Service | RecordKind::SystemModule);
            let hidden = !options.all && (is_pseudo || local.is_none());
            if hidden || options.filter.as_ref().is_some_and(|filter| !filter.matches(&name)) {
                continue;
            }
            let source_file = local.map(|class| class.source_file()).transpose().map_err(wrap)?.flatten();
            out.push(RecordListing {
                entry: entry.to_owned(),
                name: name.into_owned(),
                kind,
                source_file: source_file.map(|file| file.to_str().into_owned()),
                functions: local.map_or(0, |class| class.num_methods),
                foreign: local.is_none(),
            });
        }
    }
    Ok(out)
}

/// A record found in a program.
#[derive(Clone, Copy)]
pub(crate) struct Located<'a> {
    pub entry: &'a str,
    pub abc: Abc<'a>,
    pub class: Class<'a>,
}

impl Located<'_> {
    fn candidate(&self) -> String {
        format!("{} | {}", self.entry, String::from_utf8_lossy(self.class.name()))
    }
}

/// Whether entry `name` is one `wanted` names: exactly, by a suffix that
/// starts at a `/` (`ets/widgets.abc` for `entry.hap/ets/widgets.abc`), or by
/// a prefix that ends at one, its package (`entry.hap`, `shop.app/entry.hap`).
fn entry_matches(name: &str, wanted: &str) -> bool {
    name == wanted
        || name.strip_suffix(wanted).is_some_and(|rest| rest.ends_with('/'))
        || name.strip_prefix(wanted).is_some_and(|rest| rest.starts_with('/'))
}

/// The ABC entries `wanted` names, by index, readable or not: every entry
/// when it is `None`; else the entries [`entry_matches`] accepts, and those
/// of the package called `wanted` (a lone package, whose entries carry no
/// prefix, is named by its file name).
///
/// # Errors
/// [`EngineError::NoEntry`] when `wanted` names no entry of the program.
pub(crate) fn selected_entries(program: &Program, wanted: Option<&str>) -> Result<Vec<usize>> {
    let Some(wanted) = wanted else { return Ok((0..program.len()).collect()) };
    let in_package = |index: usize| {
        program.package_of(index).and_then(|package| program.packages().get(package)).is_some_and(|package| package.name == wanted)
    };
    let selected: Vec<usize> = (0..program.len())
        .filter(|&index| program.info(index).is_some_and(|info| entry_matches(&info.name, wanted)) || in_package(index))
        .collect();
    if selected.is_empty() {
        return Err(EngineError::NoEntry(wanted.to_owned()));
    }
    Ok(selected)
}

/// Find the record `query` names: by its canonical name, or else by a path
/// suffix of its plain name. `entry` restricts the search to one ABC entry.
pub(crate) fn resolve_record<'a>(program: &'a Program, query: &str, entry: Option<&str>) -> Result<Located<'a>> {
    let query = query.trim();
    let canonical = query.strip_prefix('L').and_then(|rest| rest.strip_suffix(';')).filter(|_| query.len() > 2).unwrap_or(query);
    // An entry that is named but cannot be read holds no record to find.
    let selected = selected_entries(program, entry)?;
    let searched: Vec<(&str, Abc<'_>)> = program
        .readable()
        .filter(|(index, _)| selected.contains(index))
        .map(|(index, abc)| (program.info(index).map_or("", |info| info.name.as_str()), abc))
        .collect();
    let wrap = |entry: &str, source| EngineError::Abc { entry: entry.to_owned(), source };

    let mut found = Vec::new();
    for &(entry, abc) in &searched {
        for name in [canonical, query] {
            if let Some(ClassEntry::Local(class)) = abc.find_record(name.as_bytes()).map_err(|source| wrap(entry, source))? {
                found.push(Located { entry, abc, class });
                break;
            }
        }
    }
    if found.is_empty() {
        let path = SOURCE_EXTENSIONS.iter().find_map(|ext| query.strip_suffix(ext)).unwrap_or(query).trim_start_matches('/');
        if !path.is_empty() {
            for &(entry, abc) in &searched {
                for class in local_records(abc, entry)? {
                    let class = class?;
                    let name = String::from_utf8_lossy(class.name());
                    if is_path_of(&name, path) {
                        found.push(Located { entry, abc, class });
                    }
                }
            }
        }
    }
    match found.len() {
        0 => Err(EngineError::NotFound { what: "record", name: query.to_owned(), notes: program.notes().to_vec() }),
        1 => Ok(found[0]),
        _ => Err(ambiguous("record", query, found.iter().map(Located::candidate))),
    }
}

/// Whether `path` is the plain name of record `name` or a suffix of it that
/// starts at a `/`.
fn is_path_of(name: &str, path: &str) -> bool {
    let plain = plain_name(name);
    *plain == *path || plain.strip_suffix(path).is_some_and(|rest| rest.ends_with('/'))
}

/// Whether `query` names the record called `name`, by the rules of
/// [`resolve_record`]: its canonical name, or a path suffix of its plain
/// name with an optional source extension.
pub(crate) fn names_record(name: &str, query: &str) -> bool {
    let query = query.trim();
    let path = SOURCE_EXTENSIONS.iter().find_map(|ext| query.strip_suffix(ext)).unwrap_or(query).trim_start_matches('/');
    name == query || (!path.is_empty() && is_path_of(name, path))
}

/// A test of a function's `(raw, restored)` names against a query.
type NameTest<'t> = &'t dyn Fn(&str, &str) -> bool;

/// Find the function `query` names in `class`: by its raw name
/// (`#~@0>#build`), else by its restored name (`Index.build`), else by a
/// dotted suffix of the restored name (`build`).
pub(crate) fn resolve_function<'a>(located: &Located<'a>, query: &str) -> Result<Method<'a>> {
    let wrap = |source| EngineError::Abc { entry: located.entry.to_owned(), source };
    let mut methods = Vec::new();
    for method in located.class.methods().map_err(wrap)? {
        let method = method.map_err(wrap)?;
        let raw = method.name().map_err(wrap)?.to_str().into_owned();
        let restored = located.class.restore_function_name(&raw);
        methods.push((method, raw, restored));
    }
    let by_raw: NameTest<'_> = &|raw, _| raw == query;
    let by_restored: NameTest<'_> = &|_, restored| restored == query;
    let by_suffix: NameTest<'_> = &|_, restored| restored.strip_suffix(query).is_some_and(|rest| rest.ends_with('.'));
    for test in [by_raw, by_restored, by_suffix] {
        let hits: Vec<_> = methods.iter().filter(|(_, raw, restored)| test(raw, restored)).collect();
        match hits[..] {
            [] => {}
            [(method, _, _)] => return Ok(*method),
            _ => return Err(ambiguous("function", query, hits.iter().map(|(_, raw, restored)| format!("{raw} | {restored}")))),
        }
    }
    let record = String::from_utf8_lossy(located.class.name());
    Err(EngineError::NotFound { what: "function", name: format!("{query} of {record}"), notes: Vec::new() })
}

fn ambiguous(what: &'static str, name: &str, all: impl ExactSizeIterator<Item = String>) -> EngineError {
    let total = all.len();
    let mut candidates: Vec<String> = all.take(MAX_CANDIDATES).collect();
    if total > candidates.len() {
        candidates.push(format!("... and {} more", total - candidates.len()));
    }
    EngineError::Ambiguous { what, name: name.to_owned(), candidates }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_names_drop_the_normalized_decoration() {
        assert_eq!(plain_name("&entry/src/main/ets/pages/Index&"), "entry/src/main/ets/pages/Index");
        assert_eq!(plain_name("&@ohos/crypto-js/index&2.0.0"), "@ohos/crypto-js/index");
        assert_eq!(plain_name("com.other.app&lib/Index&1.0.0"), "lib/Index");
        assert_eq!(plain_name("com.hmos.exam5.pkg/entry/ets/pages/Home"), "com.hmos.exam5.pkg/entry/ets/pages/Home");
        assert_eq!(plain_name("_ESTypeAnnotation"), "_ESTypeAnnotation");
        assert_eq!(plain_name("&"), "&");
        // An annotation interface is found after its module, with or without a version.
        assert_eq!(plain_name("&entry/src/main/ets/Marks&.Marked"), "entry/src/main/ets/Marks.Marked");
        assert_eq!(plain_name("&@ohos/lib/index&1.2.0.Marked"), "@ohos/lib/index.Marked");
        assert!(is_path_of("&@ohos/lib/index&1.2.0.Marked", "index.Marked") && !is_path_of("&@ohos/lib/index&1.2.0.Marked", "index"));
        assert!(is_path_of("&@ohos/lib/index&1.2.0", "index") && names_record("&entry/src/main/ets/Marks&", "ets/Marks.ets"));
    }

    #[test]
    fn filters_follow_the_name() {
        let name = "&entry/src/main/ets/pages/Index&";
        assert!(NameFilter::Prefix("&entry/src".into()).matches(name));
        assert!(NameFilter::Prefix("entry/src/main".into()).matches(name));
        assert!(!NameFilter::Prefix("src/main".into()).matches(name));
        assert!(NameFilter::Contains("pages/".into()).matches(name));
        assert!(NameFilter::Regex(Regex::new("pages/[A-Z]\\w+&$").unwrap()).matches(name));
        assert!(entry_matches("entry.hap/ets/widgets.abc", "ets/widgets.abc") && entry_matches("a.abc", "a.abc"));
        assert!(!entry_matches("entry.hap/ets/widgets.abc", "widgets.abc/") && !entry_matches("xets/a.abc", "ets/a.abc"));
        // A package names its entries; part of a name does not.
        assert!(entry_matches("entry.hap/ets/widgets.abc", "entry.hap") && entry_matches("shop.app/entry.hap/ets/modules.abc", "shop.app"));
        assert!(entry_matches("shop.app/entry.hap/ets/modules.abc", "shop.app/entry.hap"));
        assert!(!entry_matches("entry.hap/ets/widgets.abc", "entry") && !entry_matches("entry.hap/ets/widgets.abc", "entry.hap/"));
    }

    #[test]
    fn listing_lines() {
        let mut row = RecordListing {
            entry: "entry.hap/ets/modules.abc".into(),
            name: "&entry/src/main/ets/pages/Index&".into(),
            kind: RecordKind::Module,
            source_file: Some("entry/src/main/ets/pages/Index.ets".into()),
            functions: 12,
            foreign: false,
        };
        assert_eq!(row.line(false), "&entry/src/main/ets/pages/Index& | functions=12 source=entry/src/main/ets/pages/Index.ets");
        row.kind = RecordKind::Service;
        row.source_file = None;
        assert!(row.line(true).ends_with("| functions=12 kind=service | entry.hap/ets/modules.abc"));
        row.kind = RecordKind::Annotation;
        assert!(row.line(false).ends_with("| functions=12 kind=annotation"));
    }
}
