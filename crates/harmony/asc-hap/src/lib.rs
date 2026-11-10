//! HarmonyOS package metadata: the descriptors at the root of a HAP/HSP,
//! read from bytes the caller supplies (no zip or file IO here).
//!
//! - [`ModuleJson`]: `module.json`, the manifest. Abilities and extension
//!   abilities with their `exported` flag, required permissions, skills
//!   and deep-link URIs; requested and defined permissions.
//! - [`PackInfo`]: `pack.info`, the packing tool's digest of the bundle.
//! - [`PkgContextInfo`]: `pkgContextInfo.json`, the package table that
//!   `.abc` record names and import requests refer to.
//! - [`ResourceIndex`]: `resources.index`, the compiled resource table:
//!   what the ids in compiled `$r(...)` calls and the `$string:name`
//!   references of `module.json` stand for.
//!
//! Every JSON type offers the same two texts: `summary()`, one fact per line
//! for `grep`, and `pretty()`, the document itself re-indented. The
//! summaries state what the documents say and pass no judgement.
//!
//! Parsing the JSON documents is tolerant: only input that is not a JSON object is an error.
//! A wrongly typed field is skipped and recorded in `notes`; a field the
//! model does not cover is listed in `unmodelled` and stays reachable
//! through `raw()`.
//!
//! ```
//! use asc_hap::ModuleJson;
//!
//! let manifest = ModuleJson::parse(
//!     br#"{"app": {"bundleName": "com.x.y"},
//!          "module": {"name": "entry", "abilities": [{
//!              "name": "EntryAbility", "exported": true, "srcEntry": "./ets/entryability/EntryAbility.ets",
//!              "skills": [{"actions": ["ohos.want.action.viewData"], "uris": [{"scheme": "xy", "host": "open"}]}]}]}}"#,
//! )?;
//! let ability = &manifest.module.abilities[0];
//! assert!(ability.is_exported());
//! assert_eq!(ability.deep_links(), ["xy://open"]);
//! assert!(manifest.summary().contains("deeplink EntryAbility xy://open\n"));
//! let records = manifest.record_names("./ets/entryability/EntryAbility.ets", None);
//! assert_eq!(records.candidates(), ["com.x.y/entry/ets/entryability/EntryAbility", "&entry/src/main/ets/entryability/EntryAbility&"]);
//! # Ok::<(), asc_hap::HapError>(())
//! ```

mod module;
mod pack;
mod pkg_context;
mod record;
mod resource;
mod value;

pub use module::{
    Ability, AbilityKind, ApiVersion, App, AtomicService, DefinePermission, Dependency, Metadata, Module, ModuleJson, NameValue, ProxyData,
    RequestPermission, Skill, SkillUri, TestRunner,
};
pub use pack::{PackAbility, PackApp, PackExtension, PackForm, PackInfo, PackModule, PackPackage};
pub use pkg_context::{PkgContext, PkgContextInfo, RecordOwner};
pub use record::RecordNames;
pub use resource::{
    Attr, IndexFormat, Qualifier, QualifierKey, Qualifiers, Resource, ResourceIndex, ResourceIndexError, ResourceRef, ResourceType,
    ResourceValue, Resources, UnknownResourceType,
};
pub use value::Note;

/// Why a metadata document could not be read at all.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HapError {
    /// Not JSON: empty, truncated, malformed, or nested past
    /// `serde_json`'s recursion limit.
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("expected a JSON object at the root, found {found}")]
    NotAnObject {
        /// JSON type of the root value.
        found: &'static str,
    },
}

fn join_lines(lines: &[String]) -> String {
    lines.iter().flat_map(|line| [line.as_str(), "\n"]).collect()
}

#[cfg(test)]
mod tests;
