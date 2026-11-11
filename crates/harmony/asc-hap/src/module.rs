//! `module.json`: the compiled module descriptor at the root of a HAP/HSP.
//!
//! This is the packed form, not the developer's `module.json5`: the `app`
//! object is merged in from `app.json5`, resource references are spelled
//! `$string:name` with a numeric sibling (`labelId`), and build facts such
//! as `virtualMachine` and `compileSdkVersion` are added.

use std::fmt;

use serde_json::Value;

use crate::HapError;
use crate::value::{self, Findings, Line, Note, Obj};

/// A parsed `module.json`.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ModuleJson {
    /// The `app` object.
    pub app: App,
    /// The `module` object.
    pub module: Module,
    /// Fields that were present but wrongly typed, and so skipped.
    pub notes: Vec<Note>,
    /// JSON paths of fields this model has no place for; read them from
    /// [`ModuleJson::raw`].
    pub unmodelled: Vec<String>,
    raw: Value,
}

/// `minAPIVersion` / `targetAPIVersion` as written.
///
/// Old packages write the API level itself (`9`); newer ones write an
/// eight-digit number whose last three digits are the level
/// (`50001013` is level 13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApiVersion(pub i64);

impl ApiVersion {
    /// The API level, as `pack.info` states it in `apiVersion.compatible`.
    pub fn level(self) -> i64 {
        self.0 % 1000
    }
}

/// `50001013(13)`, or just `9` when the value is the level.
impl fmt::Display for ApiVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.level() == self.0 { write!(f, "{}", self.0) } else { write!(f, "{}({})", self.0, self.level()) }
    }
}

/// The `app` object: bundle-wide facts.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct App {
    /// `bundleName`: the reverse-domain bundle identifier.
    pub bundle_name: Option<String>,
    /// `app`, `atomicService`, `shared`, `appService`…
    pub bundle_type: Option<String>,
    /// `versionCode`: the integer version compared on upgrade.
    pub version_code: Option<i64>,
    /// `versionName`: the version shown to users.
    pub version_name: Option<String>,
    /// `minCompatibleVersionCode`: the oldest version this one can replace across devices.
    pub min_compatible_version_code: Option<i64>,
    /// `vendor`.
    pub vendor: Option<String>,
    /// `debug`: whether the bundle was built debuggable.
    pub debug: Option<bool>,
    /// `minAPIVersion`: the lowest API level the bundle runs on.
    pub min_api_version: Option<ApiVersion>,
    /// `targetAPIVersion`: the API level the bundle was built against.
    pub target_api_version: Option<ApiVersion>,
    /// `targetMinorAPIVersion`.
    pub target_minor_api_version: Option<i64>,
    /// `targetPatchAPIVersion`.
    pub target_patch_api_version: Option<i64>,
    /// `minMinorAPIVersion`.
    pub min_minor_api_version: Option<i64>,
    /// `minPatchAPIVersion`.
    pub min_patch_api_version: Option<i64>,
    /// `apiReleaseType`: the SDK release channel (`Release`, `Beta1`…).
    pub api_release_type: Option<String>,
    /// `compileSdkType`: `HarmonyOS` or `OpenHarmony`.
    pub compile_sdk_type: Option<String>,
    /// `compileSdkVersion`: the SDK version string the bundle was compiled with.
    pub compile_sdk_version: Option<String>,
    /// `debug` or `release`.
    pub build_mode: Option<String>,
    /// `label`: usually a `$string:` resource reference.
    pub label: Option<String>,
    /// `description`: usually a `$string:` resource reference.
    pub description: Option<String>,
    /// `appEnvironments`: environment variables set for the app process.
    pub environments: Vec<NameValue>,
    /// `multiAppMode`: whether the bundle may be installed several times.
    pub multi_app_mode: Option<MultiAppMode>,
    /// `GWPAsanEnabled`: sampled heap checking in release builds.
    pub gwp_asan_enabled: Option<bool>,
}

/// `multiAppMode` of the `app` object.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MultiAppMode {
    /// `multiAppModeType`: `appClone` or `multiInstance`.
    pub kind: Option<String>,
    /// `maxCount`: how many clones or instances may exist.
    pub max_count: Option<i64>,
}

/// A `name` / `value` pair (`appEnvironments`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct NameValue {
    /// `name`.
    pub name: Option<String>,
    /// `value`, as text even when written as a number.
    pub value: Option<String>,
}

/// A `metadata` entry: a literal `value`, a `$profile:` `resource`, or both.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Metadata {
    /// `name`: the metadata key.
    pub name: Option<String>,
    /// `value`: a literal value, as text.
    pub value: Option<String>,
    /// `resource`: a `$profile:` reference to a JSON file under `resources/base/profile`.
    pub resource: Option<String>,
}

/// The `module` object.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct Module {
    /// `name`: the module name, unique within the bundle.
    pub name: Option<String>,
    /// `entry`, `feature`, `har` or `shared`.
    pub kind: Option<String>,
    /// The module's package name: its key in `pkgContextInfo.json`.
    pub package_name: Option<String>,
    /// Source of the module's `AbilityStage`.
    pub src_entry: Option<String>,
    /// `mainElement`: the ability or extension that starts first.
    pub main_element: Option<String>,
    /// `description`: usually a `$string:` resource reference.
    pub description: Option<String>,
    /// `process`: the process name the module runs in.
    pub process: Option<String>,
    /// `deviceTypes`: `phone`, `tablet`, `2in1`, `wearable`…
    pub device_types: Vec<String>,
    /// `virtualMachine`: the runtime the code targets, e.g. `ark12.0.2.0`.
    pub virtual_machine: Option<String>,
    /// `compileMode`: `esmodule` or `jsbundle`.
    pub compile_mode: Option<String>,
    /// `installationFree`: whether the module runs without installation (atomic service).
    pub installation_free: Option<bool>,
    /// `deliveryWithInstall`: whether the module is installed with the app.
    pub delivery_with_install: Option<bool>,
    /// `compressNativeLibs`: whether the `.so` files are stored compressed.
    pub compress_native_libs: Option<bool>,
    /// `isolationMode`: whether the module runs in an isolated process.
    pub isolation_mode: Option<String>,
    /// `$profile:` reference to the page list.
    pub pages: Option<String>,
    /// `$profile:` reference to the navigation route table.
    pub router_map: Option<String>,
    /// `$profile:` reference to the startup task configuration.
    pub app_startup: Option<String>,
    /// `targetModuleName`: the module an overlay module applies to.
    pub target_module_name: Option<String>,
    /// `targetPriority`: the overlay's priority over its target.
    pub target_priority: Option<i64>,
    /// `metadata`: custom key/value entries of the module.
    pub metadata: Vec<Metadata>,
    /// `dependencies`: shared packages the module links against.
    pub dependencies: Vec<Dependency>,
    /// `proxyData`: data the module shares through the data-share proxy.
    pub proxy_data: Vec<ProxyData>,
    /// URL schemes the module may probe with `canOpenLink`.
    pub query_schemes: Vec<String>,
    /// `abilities`: the module's UIAbilities.
    pub abilities: Vec<Ability>,
    /// `extensionAbilities`: the module's extension abilities.
    pub extension_abilities: Vec<Ability>,
    /// `requestPermissions`: permissions the module asks for.
    pub request_permissions: Vec<RequestPermission>,
    /// `definePermissions`: permissions the module declares for others.
    pub define_permissions: Vec<DefinePermission>,
    /// `testRunner`: the test runner of a test module.
    pub test_runner: Option<TestRunner>,
    /// `atomicService`: settings of an atomic-service module.
    pub atomic_service: Option<AtomicService>,
}

/// A shared package (HSP) the module depends on.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Dependency {
    /// `bundleName` of the shared package; `None` for one in the same bundle.
    pub bundle_name: Option<String>,
    /// `moduleName` of the shared package.
    pub module_name: Option<String>,
    /// `versionCode` the dependency requires.
    pub version_code: Option<i64>,
}

/// A `proxyData` entry: data shared through the data-share proxy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProxyData {
    /// `uri`: the `datashareproxy://` URI the data is published under.
    pub uri: Option<String>,
    /// `requiredReadPermission`: permission a reader must hold.
    pub required_read_permission: Option<String>,
    /// `requiredWritePermission`: permission a writer must hold.
    pub required_write_permission: Option<String>,
    /// `metadata`: the entry's single metadata object.
    pub metadata: Option<Metadata>,
}

/// Which array of the module an [`Ability`] comes from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AbilityKind {
    /// `abilities`: a UIAbility.
    #[default]
    Ability,
    /// `extensionAbilities`: form, service, data share, backup…
    Extension,
}

impl AbilityKind {
    /// The record word of the summary line: `ability` or `extension`.
    pub fn as_str(self) -> &'static str {
        match self {
            AbilityKind::Ability => "ability",
            AbilityKind::Extension => "extension",
        }
    }
}

/// An entry of `abilities` or `extensionAbilities`.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct Ability {
    /// Which array the entry comes from.
    pub kind: AbilityKind,
    /// `name`: the class name of the ability.
    pub name: Option<String>,
    /// Source file relative to the module (`./ets/entryability/EntryAbility.ets`);
    /// see [`ModuleJson::record_names`].
    pub src_entry: Option<String>,
    /// `type` of an extension ability (`form`, `service`, `dataShare`…).
    pub extension_type: Option<String>,
    /// As written; `None` when the field is absent.
    pub exported: Option<bool>,
    /// Permissions a caller must hold.
    pub permissions: Vec<String>,
    /// `skills`: the implicit wants the ability accepts.
    pub skills: Vec<Skill>,
    /// `launchType`: `singleton`, `multiton`, `specified` or `standard`.
    pub launch_type: Option<String>,
    /// `process`: the process name the ability runs in.
    pub process: Option<String>,
    /// `label`: usually a `$string:` resource reference.
    pub label: Option<String>,
    /// `description`: usually a `$string:` resource reference.
    pub description: Option<String>,
    /// `backgroundModes`: long-running task types the ability may start.
    pub background_modes: Vec<String>,
    /// `continuable`: whether the ability may migrate to another device.
    pub continuable: Option<bool>,
    /// `metadata`: custom key/value entries of the ability.
    pub metadata: Vec<Metadata>,
    /// Data URI served by a data extension.
    pub uri: Option<String>,
    /// `readPermission`: permission a caller needs to read from `uri`.
    pub read_permission: Option<String>,
    /// `writePermission`: permission a caller needs to write to `uri`.
    pub write_permission: Option<String>,
    /// `extensionProcessMode`: `instance`, `type` or `bundle`.
    pub extension_process_mode: Option<String>,
    /// `dataGroupIds`: data groups the extension may share files with.
    pub data_group_ids: Vec<String>,
    /// `removeMissionAfterTerminate`: whether the mission is dropped from recents when the ability ends.
    pub remove_mission_after_terminate: Option<bool>,
    /// The entry as written, for fields not modelled here.
    pub raw: Value,
}

impl Ability {
    /// The `exported` flag in effect: an absent field means not exported.
    pub fn is_exported(&self) -> bool {
        self.exported == Some(true)
    }

    /// URL patterns of every skill URI that names a scheme, in document
    /// order without repeats.
    pub fn deep_links(&self) -> Vec<String> {
        let mut links: Vec<String> = Vec::new();
        for link in self.skills.iter().flat_map(|s| &s.uris).flat_map(SkillUri::patterns) {
            if !links.contains(&link) {
                links.push(link);
            }
        }
        links
    }

    fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or("-")
    }

    fn line(&self) -> String {
        let reason = if self.exported.is_some() { "explicit" } else { "default" };
        let mut line = Line::new(self.kind.as_str()).word(self.display_name());
        if self.kind == AbilityKind::Extension || self.extension_type.is_some() {
            line = line.opt("type", self.extension_type.as_deref());
        }
        line = line
            .raw("exported", format_args!("{} ({reason})", self.is_exported()))
            .list("permissions", &self.permissions)
            .raw("skills", self.skills.len())
            .opt("srcEntry", self.src_entry.as_deref());
        if self.uri.is_some() || self.read_permission.is_some() || self.write_permission.is_some() {
            line = line
                .opt("uri", self.uri.as_deref())
                .opt("readPermission", self.read_permission.as_deref())
                .opt("writePermission", self.write_permission.as_deref());
        }
        line.opt_present("launchType", self.launch_type.as_deref())
            .opt_present("process", self.process.as_deref())
            .opt_present("extensionProcessMode", self.extension_process_mode.as_deref())
            .flag_present("continuable", self.continuable)
            .list_present("backgroundModes", &self.background_modes)
            .list_present("dataGroupIds", &self.data_group_ids)
            .flag_present("removeMissionAfterTerminate", self.remove_mission_after_terminate)
            .end()
    }
}

/// One entry of `skills`: the implicit wants an ability accepts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Skill {
    /// `actions`: want actions the skill matches.
    pub actions: Vec<String>,
    /// `entities`: want entities the skill matches.
    pub entities: Vec<String>,
    /// `uris`: URI patterns the skill matches.
    pub uris: Vec<SkillUri>,
    /// `permissions`: permissions a caller must hold to use the skill.
    pub permissions: Vec<String>,
    /// App Linking: the `https` hosts are verified against the bundle.
    pub domain_verify: Option<bool>,
}

/// One entry of a skill's `uris`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SkillUri {
    /// `scheme`, e.g. `https` or an app-private scheme.
    pub scheme: Option<String>,
    /// `host`.
    pub host: Option<String>,
    /// `port`, as text even when written as a number.
    pub port: Option<String>,
    /// `path`: an exact path.
    pub path: Option<String>,
    /// `pathStartWith`: a path prefix.
    pub path_start_with: Option<String>,
    /// `pathRegex`: a path regular expression.
    pub path_regex: Option<String>,
    /// MIME type of the data.
    pub mime_type: Option<String>,
    /// Uniform type descriptor of the data.
    pub utd: Option<String>,
    /// `maxFileSupported`: how many files of this type the ability accepts at once.
    pub max_file_supported: Option<i64>,
    /// `linkFeature`: the app-linking feature the URI serves (`Login`, `Pay`…).
    pub link_feature: Option<String>,
}

impl SkillUri {
    /// The URL patterns this entry spells, one per path form present:
    /// `scheme://host:port/path`, `…/prefix*` for `pathStartWith` and
    /// `…/regex:<re>` for `pathRegex`. A missing host prints as `*`, and
    /// so does everything after a bare scheme (`myapp://*`). Empty
    /// when the entry names no scheme.
    pub fn patterns(&self) -> Vec<String> {
        let Some(scheme) = &self.scheme else {
            return Vec::new();
        };
        let paths: Vec<String> = [
            self.path.as_ref().map(|p| p.trim_start_matches('/').to_owned()),
            self.path_start_with.as_ref().map(|p| format!("{}*", p.trim_start_matches('/'))),
            self.path_regex.as_ref().map(|p| format!("regex:{p}")),
        ]
        .into_iter()
        .flatten()
        .collect();
        let authority = match (&self.host, &self.port) {
            (Some(host), Some(port)) => format!("{host}:{port}"),
            (Some(host), None) => host.clone(),
            (None, Some(port)) => format!("*:{port}"),
            (None, None) if paths.is_empty() => return vec![format!("{scheme}://*")],
            (None, None) => "*".to_owned(),
        };
        if paths.is_empty() {
            return vec![format!("{scheme}://{authority}")];
        }
        paths.iter().map(|path| format!("{scheme}://{authority}/{path}")).collect()
    }

    fn line(&self, owner: &str, skill: usize) -> String {
        Line::new("uri")
            .word(owner)
            .raw("skill", skill)
            .opt_present("scheme", self.scheme.as_deref())
            .opt_present("host", self.host.as_deref())
            .opt_present("port", self.port.as_deref())
            .opt_present("path", self.path.as_deref())
            .opt_present("pathStartWith", self.path_start_with.as_deref())
            .opt_present("pathRegex", self.path_regex.as_deref())
            .opt_present("type", self.mime_type.as_deref())
            .opt_present("utd", self.utd.as_deref())
            .opt_present("maxFileSupported", self.max_file_supported.map(|n| n.to_string()).as_deref())
            .opt_present("linkFeature", self.link_feature.as_deref())
            .end()
    }
}

/// An entry of `requestPermissions`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RequestPermission {
    /// `name`: the permission requested.
    pub name: Option<String>,
    /// `reason`: usually a `$string:` resource reference shown to the user.
    pub reason: Option<String>,
    /// `usedScene.abilities`.
    pub used_abilities: Vec<String>,
    /// `usedScene.when`: `inuse` or `always`.
    pub used_when: Option<String>,
}

/// An entry of `definePermissions`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct DefinePermission {
    /// `name`: the permission declared.
    pub name: Option<String>,
    /// `system_grant` or `user_grant`.
    pub grant_mode: Option<String>,
    /// `normal`, `system_basic` or `system_core`.
    pub available_level: Option<String>,
    /// `provisionEnable`: whether the permission may be granted through the provision profile.
    pub provision_enable: Option<bool>,
    /// `distributedSceneEnable`: whether the permission applies in distributed scenarios.
    pub distributed_scene_enable: Option<bool>,
    /// `label`: usually a `$string:` resource reference.
    pub label: Option<String>,
    /// `description`: usually a `$string:` resource reference.
    pub description: Option<String>,
}

/// `testRunner`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TestRunner {
    /// `name`: the test runner's name.
    pub name: Option<String>,
    /// `srcPath`: source of the test runner.
    pub src_path: Option<String>,
}

/// `atomicService`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct AtomicService {
    /// `preloads[].moduleName`.
    pub preloads: Vec<String>,
}

/// Keys that only affect how a component looks.
const PRESENTATION_KEYS: &[&str] = &[
    "icon",
    "startWindow",
    "startWindowIcon",
    "startWindowBackground",
    "orientation",
    "supportWindowMode",
    "maxWindowRatio",
    "minWindowRatio",
    "maxWindowWidth",
    "minWindowWidth",
    "maxWindowHeight",
    "minWindowHeight",
];

impl ModuleJson {
    /// Read a `module.json`.
    ///
    /// # Errors
    ///
    /// Only when `bytes` is not JSON or its root is not an object. Missing,
    /// unknown and wrongly typed fields never fail the document: see
    /// [`ModuleJson::notes`] and [`ModuleJson::unmodelled`].
    pub fn parse(bytes: &[u8]) -> Result<Self, HapError> {
        let map = value::parse_object(bytes)?;
        let mut findings = Findings::default();
        let mut root = Obj::root(&map, &mut findings);
        let app = root.object("app", read_app).unwrap_or_default();
        let module = root.object("module", read_module).unwrap_or_default();
        root.finish();
        Ok(ModuleJson { app, module, notes: findings.notes, unmodelled: findings.unmodelled, raw: Value::Object(map) })
    }

    /// The whole document as parsed.
    pub fn raw(&self) -> &Value {
        &self.raw
    }

    /// The document pretty-printed, for `getmanifest`.
    pub fn pretty(&self) -> String {
        value::pretty(&self.raw)
    }

    /// Abilities, then extension abilities, in document order.
    pub fn components(&self) -> impl Iterator<Item = &Ability> {
        self.module.abilities.iter().chain(&self.module.extension_abilities)
    }

    /// One fact per line, the first word naming the record: `bundle`,
    /// `app-env`, `module`, `module-metadata`, `dependency`, `query-scheme`,
    /// `proxy-data`, `request-permission`, `define-permission`,
    /// `test-runner`, `atomic-service`, then per component `ability` or
    /// `extension` followed by its `skill`, `uri`, `deeplink` and
    /// `metadata` lines (each carrying the component name), and finally
    /// `unmodelled` and `note`.
    ///
    /// Absent values print as `-`; values with whitespace print as JSON
    /// string literals. `exported=` is always printed, with `(explicit)`
    /// or `(default)` telling whether the document said so.
    pub fn summary_lines(&self) -> Vec<String> {
        let app = &self.app;
        let module = &self.module;
        let mut bundle = Line::new("bundle")
            .word(app.bundle_name.as_deref().unwrap_or("-"))
            .opt("bundleType", app.bundle_type.as_deref())
            .num("versionCode", app.version_code)
            .opt("versionName", app.version_name.as_deref())
            .opt("vendor", app.vendor.as_deref())
            .flag("debug", app.debug)
            .num("minAPIVersion", app.min_api_version)
            .num("targetAPIVersion", app.target_api_version)
            .opt("apiReleaseType", app.api_release_type.as_deref())
            .opt("compileSdkType", app.compile_sdk_type.as_deref())
            .opt("compileSdkVersion", app.compile_sdk_version.as_deref())
            .opt("buildMode", app.build_mode.as_deref());
        if let Some(mode) = &app.multi_app_mode {
            bundle = bundle.opt("multiAppMode", mode.kind.as_deref()).num("multiAppMaxCount", mode.max_count);
        }
        let mut out = vec![bundle.flag_present("GWPAsanEnabled", app.gwp_asan_enabled).end()];
        out.extend(
            app.environments.iter().map(|e| Line::new("app-env").opt("name", e.name.as_deref()).opt("value", e.value.as_deref()).end()),
        );
        out.push(
            Line::new("module")
                .word(module.name.as_deref().unwrap_or("-"))
                .opt("type", module.kind.as_deref())
                .opt("packageName", module.package_name.as_deref())
                .opt("mainElement", module.main_element.as_deref())
                .opt("srcEntry", module.src_entry.as_deref())
                .list("deviceTypes", &module.device_types)
                .opt("virtualMachine", module.virtual_machine.as_deref())
                .opt("compileMode", module.compile_mode.as_deref())
                .flag("installationFree", module.installation_free)
                .flag("deliveryWithInstall", module.delivery_with_install)
                .opt("process", module.process.as_deref())
                .opt("pages", module.pages.as_deref())
                .opt_present("routerMap", module.router_map.as_deref())
                .opt_present("appStartup", module.app_startup.as_deref())
                .flag_present("compressNativeLibs", module.compress_native_libs)
                .opt_present("isolationMode", module.isolation_mode.as_deref())
                .opt_present("targetModuleName", module.target_module_name.as_deref())
                .opt_present("targetPriority", module.target_priority.map(|n| n.to_string()).as_deref())
                .end(),
        );
        out.extend(module.metadata.iter().map(|m| metadata_line(Line::new("module-metadata"), m)));
        out.extend(module.dependencies.iter().map(|d| {
            Line::new("dependency")
                .opt("bundleName", d.bundle_name.as_deref())
                .opt("moduleName", d.module_name.as_deref())
                .num("versionCode", d.version_code)
                .end()
        }));
        out.extend(module.query_schemes.iter().map(|s| Line::new("query-scheme").word(s).end()));
        out.extend(module.proxy_data.iter().map(|p| {
            let line = Line::new("proxy-data")
                .opt("uri", p.uri.as_deref())
                .opt("requiredReadPermission", p.required_read_permission.as_deref())
                .opt("requiredWritePermission", p.required_write_permission.as_deref());
            match &p.metadata {
                Some(m) => line.opt("metadataName", m.name.as_deref()).opt("metadataResource", m.resource.as_deref()).end(),
                None => line.end(),
            }
        }));
        out.extend(module.request_permissions.iter().map(|p| {
            Line::new("request-permission")
                .word(p.name.as_deref().unwrap_or("-"))
                .opt("reason", p.reason.as_deref())
                .opt("when", p.used_when.as_deref())
                .list("abilities", &p.used_abilities)
                .end()
        }));
        out.extend(module.define_permissions.iter().map(|p| {
            Line::new("define-permission")
                .word(p.name.as_deref().unwrap_or("-"))
                .opt("grantMode", p.grant_mode.as_deref())
                .opt("availableLevel", p.available_level.as_deref())
                .flag("provisionEnable", p.provision_enable)
                .flag("distributedSceneEnable", p.distributed_scene_enable)
                .end()
        }));
        if let Some(t) = &module.test_runner {
            out.push(Line::new("test-runner").opt("name", t.name.as_deref()).opt("srcPath", t.src_path.as_deref()).end());
        }
        if let Some(a) = &module.atomic_service {
            out.push(Line::new("atomic-service").list("preloads", &a.preloads).end());
        }
        for component in self.components() {
            let name = component.display_name();
            out.push(component.line());
            for (i, skill) in component.skills.iter().enumerate() {
                let number = i + 1;
                out.push(
                    Line::new("skill")
                        .word(name)
                        .raw("skill", number)
                        .list("actions", &skill.actions)
                        .list("entities", &skill.entities)
                        .raw("uris", skill.uris.len())
                        .list("permissions", &skill.permissions)
                        .flag_present("domainVerify", skill.domain_verify)
                        .end(),
                );
                out.extend(skill.uris.iter().map(|u| u.line(name, number)));
            }
            out.extend(component.deep_links().iter().map(|l| Line::new("deeplink").word(name).word(l).end()));
            out.extend(component.metadata.iter().map(|m| metadata_line(Line::new("metadata").word(name), m)));
        }
        out.extend(self.unmodelled.iter().map(|path| Line::new("unmodelled").word(path).end()));
        out.extend(self.notes.iter().map(|note| format!("note {note}")));
        out
    }

    /// [`ModuleJson::summary_lines`] joined, each line newline-terminated.
    pub fn summary(&self) -> String {
        crate::join_lines(&self.summary_lines())
    }
}

fn metadata_line(line: Line, m: &Metadata) -> String {
    line.opt("name", m.name.as_deref()).opt_present("value", m.value.as_deref()).opt_present("resource", m.resource.as_deref()).end()
}

fn read_app(o: &mut Obj<'_, '_>) -> App {
    o.ignore(&["icon"]);
    App {
        bundle_name: o.str("bundleName"),
        bundle_type: o.str("bundleType"),
        version_code: o.int("versionCode"),
        version_name: o.str("versionName"),
        min_compatible_version_code: o.int("minCompatibleVersionCode"),
        vendor: o.str("vendor"),
        debug: o.bool("debug"),
        min_api_version: o.int("minAPIVersion").map(ApiVersion),
        target_api_version: o.int("targetAPIVersion").map(ApiVersion),
        target_minor_api_version: o.int("targetMinorAPIVersion"),
        target_patch_api_version: o.int("targetPatchAPIVersion"),
        min_minor_api_version: o.int("minMinorAPIVersion"),
        min_patch_api_version: o.int("minPatchAPIVersion"),
        api_release_type: o.str("apiReleaseType"),
        compile_sdk_type: o.str("compileSdkType"),
        compile_sdk_version: o.text("compileSdkVersion"),
        build_mode: o.str("buildMode"),
        label: o.str("label"),
        description: o.str("description"),
        environments: o.objects("appEnvironments", |e| NameValue { name: e.str("name"), value: e.text("value") }),
        multi_app_mode: o.object("multiAppMode", |m| MultiAppMode { kind: m.str("multiAppModeType"), max_count: m.int("maxCount") }),
        gwp_asan_enabled: o.bool("GWPAsanEnabled"),
    }
}

fn read_metadata(o: &mut Obj<'_, '_>) -> Metadata {
    Metadata { name: o.str("name"), value: o.text("value"), resource: o.str("resource") }
}

fn read_module(o: &mut Obj<'_, '_>) -> Module {
    Module {
        name: o.str("name"),
        kind: o.str("type"),
        package_name: o.str("packageName"),
        src_entry: o.str("srcEntry"),
        main_element: o.str("mainElement"),
        description: o.str("description"),
        process: o.str("process"),
        device_types: o.strings("deviceTypes"),
        virtual_machine: o.str("virtualMachine"),
        compile_mode: o.str("compileMode"),
        installation_free: o.bool("installationFree"),
        delivery_with_install: o.bool("deliveryWithInstall"),
        compress_native_libs: o.bool("compressNativeLibs"),
        isolation_mode: o.str("isolationMode"),
        pages: o.str("pages"),
        router_map: o.str("routerMap"),
        app_startup: o.str("appStartup"),
        target_module_name: o.str("targetModuleName"),
        target_priority: o.int("targetPriority"),
        metadata: o.objects("metadata", read_metadata),
        dependencies: o.objects("dependencies", |d| Dependency {
            bundle_name: d.str("bundleName"),
            module_name: d.str("moduleName"),
            version_code: d.int("versionCode"),
        }),
        proxy_data: o.objects("proxyData", |p| ProxyData {
            uri: p.str("uri"),
            required_read_permission: p.str("requiredReadPermission"),
            required_write_permission: p.str("requiredWritePermission"),
            metadata: p.object("metadata", read_metadata),
        }),
        query_schemes: o.strings("querySchemes"),
        abilities: o.objects("abilities", |a| read_ability(a, AbilityKind::Ability)),
        extension_abilities: o.objects("extensionAbilities", |a| read_ability(a, AbilityKind::Extension)),
        request_permissions: o.objects("requestPermissions", |p| {
            let scene = p.object("usedScene", |s| (s.strings("abilities"), s.str("when")));
            let (used_abilities, used_when) = scene.unwrap_or_default();
            RequestPermission { name: p.str("name"), reason: p.str("reason"), used_abilities, used_when }
        }),
        define_permissions: o.objects("definePermissions", |p| DefinePermission {
            name: p.str("name"),
            grant_mode: p.str("grantMode"),
            available_level: p.str("availableLevel"),
            provision_enable: p.bool("provisionEnable"),
            distributed_scene_enable: p.bool("distributedSceneEnable"),
            label: p.str("label"),
            description: p.str("description"),
        }),
        test_runner: o.object("testRunner", |t| TestRunner { name: t.str("name"), src_path: t.str("srcPath") }),
        atomic_service: o.object("atomicService", |a| AtomicService {
            preloads: a.objects("preloads", |p| p.str("moduleName")).into_iter().flatten().collect(),
        }),
    }
}

fn read_ability(o: &mut Obj<'_, '_>, kind: AbilityKind) -> Ability {
    o.ignore(PRESENTATION_KEYS);
    Ability {
        kind,
        name: o.str("name"),
        src_entry: o.str("srcEntry"),
        extension_type: o.str("type"),
        exported: o.bool("exported"),
        permissions: o.strings("permissions"),
        skills: o.objects("skills", read_skill),
        launch_type: o.str("launchType"),
        process: o.str("process"),
        label: o.str("label"),
        description: o.str("description"),
        background_modes: o.strings("backgroundModes"),
        continuable: o.bool("continuable"),
        metadata: o.objects("metadata", read_metadata),
        uri: o.str("uri"),
        read_permission: o.str("readPermission"),
        write_permission: o.str("writePermission"),
        extension_process_mode: o.str("extensionProcessMode"),
        data_group_ids: o.strings("dataGroupIds"),
        remove_mission_after_terminate: o.bool("removeMissionAfterTerminate"),
        raw: o.to_value(),
    }
}

fn read_skill(o: &mut Obj<'_, '_>) -> Skill {
    Skill {
        actions: o.strings("actions"),
        entities: o.strings("entities"),
        uris: o.objects("uris", |u| SkillUri {
            scheme: u.str("scheme"),
            host: u.str("host"),
            port: u.text("port"),
            path: u.str("path"),
            path_start_with: u.str("pathStartWith"),
            path_regex: u.str("pathRegex"),
            mime_type: u.str("type"),
            utd: u.str("utd"),
            max_file_supported: u.int("maxFileSupported"),
            link_feature: u.str("linkFeature"),
        }),
        permissions: o.strings("permissions"),
        domain_verify: o.bool("domainVerify"),
    }
}
