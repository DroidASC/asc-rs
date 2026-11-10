//! From a manifest source path to the `.abc` record that holds its code.

use crate::module::ModuleJson;
use crate::pkg_context::PkgContextInfo;

/// Source root of a module's own package when `pkgContextInfo.json` is
/// not at hand; every sample that has the file says the same.
const DEFAULT_SOURCE_ROOT: &str = "src/main/";

/// Extensions the compiler drops when it names a record after a file.
const SOURCE_EXTENSIONS: &[&str] = &[".ets", ".ts", ".js", ".mjs", ".cjs"];

pub(crate) fn strip_source_extension(path: &str) -> &str {
    SOURCE_EXTENSIONS.iter().find_map(|ext| path.strip_suffix(ext)).unwrap_or(path)
}

/// The record names a manifest `srcEntry` can compile to. Which spelling
/// a package uses is a build option (normalized OHM URLs); packages built
/// with it carry a `pkgContextInfo.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordNames {
    /// `&<packageName>/<source root><path>&<version>`, e.g.
    /// `&entry/src/main/ets/entryability/EntryAbility&`. `None` when the
    /// manifest names neither a package nor a module.
    pub normalized: Option<String>,
    /// `<bundleName>/<moduleName>/<path>`, e.g.
    /// `com.x.y/entry/ets/entryability/EntryAbility`. `None` when the
    /// manifest lacks the bundle or module name.
    pub bundled: Option<String>,
    /// Whether the package table listed the module's package, which is
    /// what makes the normalized spelling the likely one.
    pub package_listed: bool,
}

impl RecordNames {
    /// The spellings, likeliest first.
    pub fn candidates(&self) -> Vec<&str> {
        let (first, second) = if self.package_listed { (&self.normalized, &self.bundled) } else { (&self.bundled, &self.normalized) };
        [first, second].into_iter().flatten().map(String::as_str).collect()
    }
}

impl ModuleJson {
    /// Record names for a `srcEntry` of this module (an ability's, an
    /// extension's or the module's own): `./ets/entryability/EntryAbility.ets`.
    ///
    /// Pass the package's `pkgContextInfo.json` when it has one: it
    /// supplies the module's source root and version, and its presence
    /// puts the normalized spelling first.
    pub fn record_names(&self, src_entry: &str, packages: Option<&PkgContextInfo>) -> RecordNames {
        let path = src_entry.strip_prefix("./").unwrap_or(src_entry).trim_start_matches('/');
        let path = strip_source_extension(path);
        let module = self.module.name.as_deref();
        let package_name = self.module.package_name.as_deref().or(module);
        let package = packages.zip(package_name).and_then(|(table, name)| table.get(name));
        let normalized = package_name.map(|name| match package {
            Some(p) => format!("&{name}/{}{path}&{}", p.entry_path, p.version),
            None => format!("&{name}/{DEFAULT_SOURCE_ROOT}{path}&"),
        });
        let bundled = self.app.bundle_name.as_deref().zip(module).map(|(bundle, module)| format!("{bundle}/{module}/{path}"));
        RecordNames { normalized, bundled, package_listed: package.is_some() }
    }
}
