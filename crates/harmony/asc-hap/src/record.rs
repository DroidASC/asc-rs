//! From a manifest source path to the `.abc` record that holds its code.

use crate::module::ModuleJson;
use crate::pkg_context::PkgContextInfo;
use crate::profile::Route;

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
#[non_exhaustive]
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
            // A shared package lists its entry file, or nothing, where a hap lists its source root.
            Some(p) if p.entry_path.ends_with('/') => format!("&{name}/{}{path}&{}", p.entry_path, p.version),
            Some(p) => format!("&{name}/{DEFAULT_SOURCE_ROOT}{path}&{}", p.version),
            None => format!("&{name}/{DEFAULT_SOURCE_ROOT}{path}&"),
        });
        let bundled = self.app.bundle_name.as_deref().zip(module).map(|(bundle, module)| format!("{bundle}/{module}/{path}"));
        RecordNames { normalized, bundled, package_listed: package.is_some() }
    }

    /// Record names for the page of a route of this module's route table.
    ///
    /// The route's `ohmurl` spells the record outright; without one the
    /// name is put together from `pageSourceFile` and the package that has
    /// it (`packageName`, else the module's own), with the version
    /// `packages` lists for that package. A page of the module itself has
    /// the `<bundle>/<module>/ets/…` spelling besides.
    pub fn route_record_names(&self, route: &Route, packages: Option<&PkgContextInfo>) -> RecordNames {
        let module = self.module.name.as_deref();
        let own_package = self.module.package_name.as_deref().or(module);
        let path = route.record_path(own_package);
        let listed = packages.zip(route.package_name.as_deref().or(own_package)).and_then(|(table, name)| table.get(name));
        let from_source = path.as_ref().map(|path| format!("&{path}&{}", listed.map_or("", |package| package.version.as_str())));
        let normalized = route.ohmurl_record().map(str::to_owned).or(from_source);
        let is_own = route.package_name.as_deref().is_none_or(|package| Some(package) == own_package);
        let source = route.page_source_file.as_deref().map(|source| source.trim_start_matches("./").trim_start_matches('/'));
        let below_root = source.and_then(|source| source.strip_prefix(DEFAULT_SOURCE_ROOT)).filter(|_| is_own);
        let bundled = self
            .app
            .bundle_name
            .as_deref()
            .zip(module)
            .zip(below_root)
            .map(|((bundle, module), path)| format!("{bundle}/{module}/{}", strip_source_extension(path)));
        // A route with an `ohmurl` comes from a build with normalized names.
        RecordNames { normalized, bundled, package_listed: listed.is_some() || route.ohmurl.is_some() }
    }
}
