//! `pkgContextInfo.json`: the table of every package (the module itself,
//! HARs, npm-style dependencies, native libraries) compiled into the
//! module's `.abc`.
//!
//! It is written when the build uses normalized OHM URLs, and it is what
//! links the manifest to the code: record names and import requests in
//! the `.abc` then read `[bundle]&<packageName>/<path>&<version>`.

use serde_json::Value;

use crate::HapError;
use crate::record;
use crate::value::{self, Findings, Line, Note, Obj};

/// A parsed `pkgContextInfo.json`.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct PkgContextInfo {
    /// Sorted by [`PkgContext::name`].
    packages: Vec<PkgContext>,
    /// Fields that were present but wrongly typed, and so skipped.
    pub notes: Vec<Note>,
    /// JSON paths of fields this model has no place for.
    pub unmodelled: Vec<String>,
    raw: Value,
}

/// One package. Strings the file leaves empty stay empty here: the file
/// itself writes `""` for "none".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PkgContext {
    /// The key of the entry: the name code refers to the package by.
    pub name: String,
    /// `packageName`; equal to [`PkgContext::name`] in every file seen.
    pub package_name: String,
    /// Owning bundle; empty for packages compiled into this module.
    pub bundle_name: String,
    pub module_name: String,
    /// Empty for the module itself and for native libraries.
    pub version: String,
    /// The package's entry file relative to its root (`Index.ets`), or
    /// for the module's own package its source root (`src/main/`).
    pub entry_path: String,
    /// A native library (`libfoo.so`) rather than compiled code.
    pub is_so: bool,
    pub dependency_alias: String,
}

impl PkgContext {
    /// The record a bare import of this package resolves to:
    /// `&<name>/<entryPath without extension>&<version>`. `None` for
    /// native libraries and packages without an entry file.
    ///
    /// The record may be absent from the `.abc` when nothing imports the
    /// package's entry.
    pub fn entry_record_name(&self) -> Option<String> {
        if self.is_so || self.entry_path.is_empty() || self.entry_path.ends_with('/') {
            return None;
        }
        Some(format!("&{}/{}&{}", self.name, record::strip_source_extension(&self.entry_path), self.version))
    }
}

/// A normalized record name split against the package table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecordOwner<'c, 'r> {
    pub package: &'c PkgContext,
    /// Text before the first `&`; empty for records of this bundle.
    pub bundle: &'r str,
    /// Path inside the package, without extension; empty when the record
    /// is the package name alone.
    pub path: &'r str,
    /// Text after the last `&`.
    pub version: &'r str,
}

impl PkgContextInfo {
    /// Read a `pkgContextInfo.json`.
    ///
    /// # Errors
    ///
    /// Only when `bytes` is not JSON or its root is not an object.
    pub fn parse(bytes: &[u8]) -> Result<Self, HapError> {
        let map = value::parse_object(bytes)?;
        let mut findings = Findings::default();
        let mut packages = Vec::with_capacity(map.len());
        for (name, entry) in &map {
            let Some(entry) = entry.as_object() else {
                findings.notes.push(Note { path: name.clone(), message: format!("expected object, found {}", value::kind(entry)) });
                continue;
            };
            // Each entry is read as its own root so that note paths start
            // at the package name.
            let mut scratch = Findings::default();
            let mut o = Obj::root(entry, &mut scratch);
            packages.push(PkgContext {
                name: name.clone(),
                package_name: o.str("packageName").unwrap_or_default(),
                bundle_name: o.str("bundleName").unwrap_or_default(),
                module_name: o.str("moduleName").unwrap_or_default(),
                version: o.text("version").unwrap_or_default(),
                entry_path: o.str("entryPath").unwrap_or_default(),
                is_so: o.bool("isSO").unwrap_or_default(),
                dependency_alias: o.str("dependencyAlias").unwrap_or_default(),
            });
            o.finish();
            findings.notes.extend(scratch.notes.into_iter().map(|n| Note { path: format!("{name}.{}", n.path), ..n }));
            findings.unmodelled.extend(scratch.unmodelled.into_iter().map(|path| format!("{name}.{path}")));
        }
        packages.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(PkgContextInfo { packages, notes: findings.notes, unmodelled: findings.unmodelled, raw: Value::Object(map) })
    }

    /// Every package, sorted by name.
    pub fn packages(&self) -> &[PkgContext] {
        &self.packages
    }

    /// The package code refers to as `name`.
    pub fn get(&self, name: &str) -> Option<&PkgContext> {
        self.packages.binary_search_by(|p| p.name.as_str().cmp(name)).ok().map(|i| &self.packages[i])
    }

    /// Split a normalized record name (`&@ohos/crypto-js/src/main/js/aes&2.0.0`)
    /// and find the package it belongs to: the longest package name that
    /// is a whole-segment prefix of the part between the `&`s. Import
    /// requests work too once their `@normalized:N&<module>&` head is cut
    /// off.
    ///
    /// `None` for names without two `&` (the `bundle/module/ets/…` form)
    /// and for packages missing from the table.
    pub fn locate<'r>(&self, record: &'r str) -> Option<RecordOwner<'_, 'r>> {
        let (bundle, rest) = record.split_once('&')?;
        let (body, version) = rest.rsplit_once('&')?;
        let boundaries = body.match_indices('/').map(|(i, _)| i).chain([body.len()]).collect::<Vec<_>>();
        boundaries.into_iter().rev().find_map(|end| {
            let package = self.get(&body[..end])?;
            Some(RecordOwner { package, bundle, path: body[end..].trim_start_matches('/'), version })
        })
    }

    /// The whole document as parsed.
    pub fn raw(&self) -> &Value {
        &self.raw
    }

    /// The document pretty-printed.
    pub fn pretty(&self) -> String {
        value::pretty(&self.raw)
    }

    /// One `package` line per package, sorted by name, then `unmodelled`
    /// and `note` lines.
    pub fn summary_lines(&self) -> Vec<String> {
        let text = |s: &str| if s.is_empty() { "-".to_owned() } else { value::token(s).into_owned() };
        let mut out: Vec<String> = self
            .packages
            .iter()
            .map(|p| {
                let mut line = Line::new("package")
                    .word(&p.name)
                    .raw("version", text(&p.version))
                    .raw("entryPath", text(&p.entry_path))
                    .raw("isSO", p.is_so)
                    .raw("bundleName", text(&p.bundle_name))
                    .raw("moduleName", text(&p.module_name))
                    .raw("dependencyAlias", text(&p.dependency_alias));
                if p.package_name != p.name {
                    line = line.raw("packageName", text(&p.package_name));
                }
                line.end()
            })
            .collect();
        out.extend(self.unmodelled.iter().map(|path| Line::new("unmodelled").word(path).end()));
        out.extend(self.notes.iter().map(|note| format!("note {note}")));
        out
    }

    /// [`PkgContextInfo::summary_lines`] joined, each line
    /// newline-terminated.
    pub fn summary(&self) -> String {
        crate::join_lines(&self.summary_lines())
    }
}
