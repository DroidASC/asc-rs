//! `pack.info`: the packing tool's digest of a HAP (one module) or of an
//! `.app` bundle (every module), written at the archive root.

use serde_json::Value;

use crate::HapError;
use crate::value::{self, Findings, Line, Note, Obj};

/// A parsed `pack.info`.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct PackInfo {
    /// `summary.app`.
    pub app: PackApp,
    /// `summary.modules`.
    pub modules: Vec<PackModule>,
    /// `packages`: the HAP/HSP files of the bundle.
    pub packages: Vec<PackPackage>,
    /// Fields that were present but wrongly typed, and so skipped.
    pub notes: Vec<Note>,
    /// JSON paths of fields this model has no place for.
    pub unmodelled: Vec<String>,
    raw: Value,
}

/// `summary.app`: bundle-wide facts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PackApp {
    /// `bundleName`.
    pub bundle_name: Option<String>,
    /// `bundleType`: `app`, `atomicService`, `shared`…
    pub bundle_type: Option<String>,
    /// `version.code`.
    pub version_code: Option<i64>,
    /// `version.name`.
    pub version_name: Option<String>,
}

/// An entry of `summary.modules`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PackModule {
    /// `distro.moduleName`.
    pub name: Option<String>,
    /// `distro.moduleType`.
    pub kind: Option<String>,
    /// `distro.installationFree`: whether the module runs without installation.
    pub installation_free: Option<bool>,
    /// `distro.deliveryWithInstall`: whether the module is installed with the app.
    pub delivery_with_install: Option<bool>,
    /// `mainAbility`: the ability that starts first.
    pub main_ability: Option<String>,
    /// `deviceType`: `phone`, `tablet`, `2in1`…
    pub device_types: Vec<String>,
    /// `apiVersion.compatible`: the minimum API level.
    pub api_compatible: Option<i64>,
    /// `apiVersion.target`.
    pub api_target: Option<i64>,
    /// `apiVersion.releaseType`.
    pub api_release_type: Option<String>,
    /// `abilities`.
    pub abilities: Vec<PackAbility>,
    /// `extensionAbilities`.
    pub extension_abilities: Vec<PackExtension>,
}

/// An entry of a module's `abilities`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PackAbility {
    /// `name`.
    pub name: Option<String>,
    /// `label`: usually a `$string:` resource reference.
    pub label: Option<String>,
}

/// An entry of a module's `extensionAbilities`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PackExtension {
    /// `name`.
    pub name: Option<String>,
    /// Service widgets (cards) a form extension offers.
    pub forms: Vec<PackForm>,
}

/// An entry of an extension's `forms`: one service widget.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PackForm {
    /// `name`.
    pub name: Option<String>,
    /// `type`: `JS` or `eTS`.
    pub kind: Option<String>,
    /// `updateEnabled`: whether the widget refreshes periodically.
    pub update_enabled: Option<bool>,
    /// `updateDuration`: the refresh period, in units of 30 minutes.
    pub update_duration: Option<i64>,
    /// `scheduledUpdateTime`: the time of day of the daily update, `10:30`.
    pub scheduled_update_time: Option<String>,
    /// `defaultDimension`: the default size, e.g. `2*2`.
    pub default_dimension: Option<String>,
    /// `supportDimensions`: every size offered.
    pub support_dimensions: Vec<String>,
}

/// An entry of `packages`: one HAP/HSP file of the bundle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PackPackage {
    /// File stem of the package inside the bundle (`entry-default`).
    pub name: Option<String>,
    /// `moduleType`: `entry`, `feature` or `shared`.
    pub module_type: Option<String>,
    /// `deviceType`.
    pub device_types: Vec<String>,
    /// `deliveryWithInstall`: whether the package is installed with the app.
    pub delivery_with_install: Option<bool>,
}

impl PackInfo {
    /// Read a `pack.info`.
    ///
    /// # Errors
    ///
    /// Only when `bytes` is not JSON or its root is not an object.
    pub fn parse(bytes: &[u8]) -> Result<Self, HapError> {
        let map = value::parse_object(bytes)?;
        let mut findings = Findings::default();
        let mut root = Obj::root(&map, &mut findings);
        let summary = root.object("summary", |s| (s.object("app", read_app).unwrap_or_default(), s.objects("modules", read_module)));
        let (app, modules) = summary.unwrap_or_default();
        let packages = root.objects("packages", |p| PackPackage {
            name: p.str("name"),
            module_type: p.str("moduleType"),
            device_types: p.strings("deviceType"),
            delivery_with_install: p.bool("deliveryWithInstall"),
        });
        root.finish();
        Ok(PackInfo { app, modules, packages, notes: findings.notes, unmodelled: findings.unmodelled, raw: Value::Object(map) })
    }

    /// The whole document as parsed.
    pub fn raw(&self) -> &Value {
        &self.raw
    }

    /// The document pretty-printed.
    pub fn pretty(&self) -> String {
        value::pretty(&self.raw)
    }

    /// One fact per line: `pack-app`, then per module `pack-module`,
    /// `pack-ability`, `pack-extension` and `pack-form` (each carrying the
    /// module name), then `pack-package`, `unmodelled` and `note`.
    pub fn summary_lines(&self) -> Vec<String> {
        let mut out = vec![
            Line::new("pack-app")
                .word(self.app.bundle_name.as_deref().unwrap_or("-"))
                .opt("bundleType", self.app.bundle_type.as_deref())
                .num("versionCode", self.app.version_code)
                .opt("versionName", self.app.version_name.as_deref())
                .end(),
        ];
        for module in &self.modules {
            let name = module.name.as_deref().unwrap_or("-");
            out.push(
                Line::new("pack-module")
                    .word(name)
                    .opt("type", module.kind.as_deref())
                    .opt("mainAbility", module.main_ability.as_deref())
                    .list("deviceTypes", &module.device_types)
                    .flag("installationFree", module.installation_free)
                    .flag("deliveryWithInstall", module.delivery_with_install)
                    .num("apiCompatible", module.api_compatible)
                    .num("apiTarget", module.api_target)
                    .opt("apiReleaseType", module.api_release_type.as_deref())
                    .end(),
            );
            out.extend(module.abilities.iter().map(|a| {
                Line::new("pack-ability").word(name).word(a.name.as_deref().unwrap_or("-")).opt("label", a.label.as_deref()).end()
            }));
            for extension in &module.extension_abilities {
                let extension_name = extension.name.as_deref().unwrap_or("-");
                out.push(Line::new("pack-extension").word(name).word(extension_name).raw("forms", extension.forms.len()).end());
                out.extend(extension.forms.iter().map(|f| {
                    Line::new("pack-form")
                        .word(name)
                        .word(extension_name)
                        .word(f.name.as_deref().unwrap_or("-"))
                        .opt("type", f.kind.as_deref())
                        .flag("updateEnabled", f.update_enabled)
                        .num("updateDuration", f.update_duration)
                        .opt_present("scheduledUpdateTime", f.scheduled_update_time.as_deref())
                        .opt("defaultDimension", f.default_dimension.as_deref())
                        .list("supportDimensions", &f.support_dimensions)
                        .end()
                }));
            }
        }
        out.extend(self.packages.iter().map(|p| {
            Line::new("pack-package")
                .word(p.name.as_deref().unwrap_or("-"))
                .opt("moduleType", p.module_type.as_deref())
                .list("deviceTypes", &p.device_types)
                .flag("deliveryWithInstall", p.delivery_with_install)
                .end()
        }));
        out.extend(self.unmodelled.iter().map(|path| Line::new("unmodelled").word(path).end()));
        out.extend(self.notes.iter().map(|note| format!("note {note}")));
        out
    }

    /// [`PackInfo::summary_lines`] joined, each line newline-terminated.
    pub fn summary(&self) -> String {
        crate::join_lines(&self.summary_lines())
    }
}

fn read_app(o: &mut Obj<'_, '_>) -> PackApp {
    let version = o.object("version", |v| (v.int("code"), v.str("name")));
    let (version_code, version_name) = version.unwrap_or_default();
    PackApp { bundle_name: o.str("bundleName"), bundle_type: o.str("bundleType"), version_code, version_name }
}

fn read_module(o: &mut Obj<'_, '_>) -> PackModule {
    let distro =
        o.object("distro", |d| (d.str("moduleName"), d.str("moduleType"), d.bool("installationFree"), d.bool("deliveryWithInstall")));
    let (name, kind, installation_free, delivery_with_install) = distro.unwrap_or_default();
    let api = o.object("apiVersion", |a| (a.int("compatible"), a.int("target"), a.str("releaseType")));
    let (api_compatible, api_target, api_release_type) = api.unwrap_or_default();
    PackModule {
        name,
        kind,
        installation_free,
        delivery_with_install,
        main_ability: o.str("mainAbility"),
        device_types: o.strings("deviceType"),
        api_compatible,
        api_target,
        api_release_type,
        abilities: o.objects("abilities", |a| PackAbility { name: a.str("name"), label: a.str("label") }),
        extension_abilities: o.objects("extensionAbilities", |e| PackExtension {
            name: e.str("name"),
            forms: e.objects("forms", |f| PackForm {
                name: f.str("name"),
                kind: f.str("type"),
                update_enabled: f.bool("updateEnabled"),
                update_duration: f.int("updateDuration"),
                scheduled_update_time: f.str("scheduledUpdateTime"),
                default_dimension: f.str("defaultDimension"),
                support_dimensions: f.strings("supportDimensions"),
            }),
        }),
    }
}
