//! Structured `AndroidManifest.xml` summary: the attack surface an audit
//! starts from (exported components, permissions, providers, deep links,
//! application flags, network security config).
//!
//! Every attribute that is a resource reference is resolved through
//! `resources.arsc` as a device on the newest SDK with no locale would see it
//! ([`asc_arsc::Config::any_device`]); when a referenced boolean differs
//! between configurations (e.g. `exported="@bool/x"` with a `values-v31`
//! override) every variant is reported next to the value.

use crate::resources::{plain_value, resolve_simple};
use crate::{Engine, Result};
use asc_arsc::{EntryValue, ResTable, TYPE_INT_BOOLEAN, TYPE_STRING};
use asc_axml::{Attribute, Element};
use serde_json::{json, Value as Json};

/// Android 12 (API 31) requires an explicit `android:exported` on every
/// component with an intent filter; before it such components were exported.
const SDK_EXPLICIT_EXPORTED: i64 = 31;
/// Before API 17 providers were exported unless they said otherwise.
const SDK_PROVIDER_PRIVATE: i64 = 17;
/// From API 28 cleartext traffic is off unless enabled.
const SDK_CLEARTEXT_OFF: i64 = 28;
const FILE_PROVIDER_PATHS: &str = "android.support.FILE_PROVIDER_PATHS";

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ManifestSummary {
    pub package: String,
    pub version_code: Option<String>,
    pub version_name: Option<String>,
    pub min_sdk: Option<i64>,
    pub target_sdk: Option<i64>,
    pub shared_user_id: Option<String>,
    pub application: Application,
    pub uses_permissions: Vec<String>,
    pub permissions: Vec<Permission>,
    pub components: Vec<Component>,
    /// Decoded `networkSecurityConfig`, one record per line.
    pub network_security: Vec<String>,
    /// Attributes that could not be resolved and similar notes.
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Application {
    pub class: Option<String>,
    pub debuggable: bool,
    pub allow_backup: bool,
    pub test_only: bool,
    pub uses_cleartext_traffic: Option<bool>,
    /// Whether cleartext HTTP is allowed by default, and what decided it.
    pub cleartext_effective: (bool, &'static str),
    /// Path of the network security config XML (`res/xml/...`).
    pub network_security_config: Option<String>,
    pub permission: Option<String>,
    pub full_backup_content: Option<String>,
    pub data_extraction_rules: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Permission {
    pub name: String,
    pub protection_level: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Component {
    /// `activity`, `activity-alias`, `service`, `receiver` or `provider`.
    pub kind: String,
    /// Fully qualified class name (for an alias: the alias name).
    pub class: String,
    /// `targetActivity` of an alias, fully qualified.
    pub target: Option<String>,
    pub exported: bool,
    /// `explicit`, `intent-filter` (implicit, targetSdk < 31), `provider-default`
    /// (targetSdk < 17) or `default`, plus `@ref` variants when the value differs
    /// between configurations.
    pub exported_reason: String,
    pub enabled: bool,
    /// Own permission, or the application's when the component sets none.
    pub permission: Option<String>,
    pub permission_from_app: bool,
    pub process: Option<String>,
    pub authorities: Vec<String>,
    pub grant_uri_permissions: bool,
    pub read_permission: Option<String>,
    pub write_permission: Option<String>,
    pub intent_filters: Vec<IntentFilter>,
    pub meta_data: Vec<(String, String)>,
    /// FileProvider path entries (`files-path name=x path=y`).
    pub provider_paths: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct IntentFilter {
    pub actions: Vec<String>,
    pub categories: Vec<String>,
    pub data: Vec<DataSpec>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DataSpec {
    pub scheme: Option<String>,
    pub host: Option<String>,
    pub port: Option<String>,
    /// `path`, `pathPrefix`, `pathPattern`, `pathAdvancedPattern` or
    /// `pathSuffix`, with its value.
    pub path: Option<(String, String)>,
    pub mime_type: Option<String>,
}

impl IntentFilter {
    /// Deep link URL patterns of a `VIEW` filter: every scheme combined with
    /// every host and path, as Android matches them (`*` for absent parts).
    pub fn deep_links(&self) -> Vec<String> {
        if !self.actions.iter().any(|a| a == "android.intent.action.VIEW") {
            return Vec::new();
        }
        let pick = |f: fn(&DataSpec) -> Option<String>| -> Vec<String> {
            let mut v: Vec<String> = self.data.iter().filter_map(f).collect();
            v.dedup();
            v
        };
        let schemes = pick(|d| d.scheme.clone());
        let hosts = pick(|d| {
            d.host.clone().map(|h| match &d.port {
                Some(p) => format!("{h}:{p}"),
                None => h,
            })
        });
        let paths = pick(|d| d.path.as_ref().map(|(k, v)| if k == "pathPrefix" { format!("{v}*") } else { v.clone() }));
        let mut out = Vec::new();
        for s in &schemes {
            if !matches!(s.as_str(), "http" | "https") && hosts.is_empty() {
                out.push(format!("{s}://*"));
                continue;
            }
            for h in if hosts.is_empty() { vec!["*".to_string()] } else { hosts.clone() } {
                if paths.is_empty() {
                    out.push(format!("{s}://{h}"));
                }
                for p in &paths {
                    let sep = if p.starts_with('/') { "" } else { "/" };
                    out.push(format!("{s}://{h}{sep}{p}"));
                }
            }
        }
        out
    }

    fn line(&self) -> String {
        let mut parts = Vec::new();
        if !self.actions.is_empty() {
            parts.push(format!("action={}", self.actions.join(",")));
        }
        if !self.categories.is_empty() {
            parts.push(format!("category={}", self.categories.join(",")));
        }
        for d in &self.data {
            let mut s = String::new();
            if let Some(v) = &d.scheme {
                s.push_str(&format!("scheme={v} "));
            }
            if let Some(v) = &d.host {
                s.push_str(&format!("host={v} "));
            }
            if let Some(v) = &d.port {
                s.push_str(&format!("port={v} "));
            }
            if let Some((k, v)) = &d.path {
                s.push_str(&format!("{k}={v} "));
            }
            if let Some(v) = &d.mime_type {
                s.push_str(&format!("mimeType={v} "));
            }
            parts.push(format!("data({})", s.trim_end()));
        }
        parts.join(" ")
    }

    fn json(&self) -> Json {
        json!({
            "actions": self.actions,
            "categories": self.categories,
            "data": self.data.iter().map(|d| json!({
                "scheme": d.scheme, "host": d.host, "port": d.port,
                "path_kind": d.path.as_ref().map(|p| &p.0), "path": d.path.as_ref().map(|p| &p.1),
                "mime_type": d.mime_type,
            })).collect::<Vec<_>>(),
        })
    }
}

/// `android:protectionLevel` flags as text (`signature|privileged`).
pub fn protection_level_name(level: u32) -> String {
    let base = match level & 0xf {
        0 => "normal".to_string(),
        1 => "dangerous".to_string(),
        2 => "signature".to_string(),
        3 => "signatureOrSystem".to_string(),
        4 => "internal".to_string(),
        b => format!("base{b}"),
    };
    const FLAGS: [(u32, &str); 18] = [
        (0x10, "privileged"),
        (0x20, "development"),
        (0x40, "appop"),
        (0x80, "pre23"),
        (0x100, "installer"),
        (0x200, "verifier"),
        (0x400, "preinstalled"),
        (0x800, "setup"),
        (0x1000, "instant"),
        (0x2000, "runtime"),
        (0x4000, "oem"),
        (0x8000, "vendorPrivileged"),
        (0x10000, "textClassifier"),
        (0x20000, "configurator"),
        (0x40000, "incidentReportApprover"),
        (0x80000, "appPredictor"),
        (0x100000, "module"),
        (0x200000, "companion"),
    ];
    let mut out = base;
    let mut rest = level & !0xf;
    for (bit, name) in FLAGS {
        if rest & bit != 0 {
            out.push('|');
            out.push_str(name);
            rest &= !bit;
        }
    }
    if rest != 0 {
        out.push_str(&format!("|0x{rest:x}"));
    }
    out
}

/// Attribute reading with references resolved through the resource table.
struct Reader<'a> {
    table: Option<&'a ResTable>,
    warnings: Vec<String>,
}

impl Reader<'_> {
    /// String value of `a`: literal strings as-is, references resolved to
    /// their (default-config) value.
    fn string(&mut self, a: &Attribute) -> String {
        if let (Some(id), Some(t)) = (a.reference(), self.table) {
            match resolve_simple(t, id) {
                Some(v) => return plain_value(t, &v),
                None => self.warnings.push(format!("{}={} does not resolve to a value", a.name, a.value)),
            }
        }
        a.value.clone()
    }

    fn str_attr(&mut self, el: &Element, name: &str) -> Option<String> {
        el.android(name).map(|a| self.string(a))
    }

    /// Boolean attribute, plus a note listing per-config values when it is a
    /// reference whose value differs between configurations.
    fn bool_attr(&mut self, el: &Element, name: &str) -> Option<(bool, Option<String>)> {
        let a = el.android(name)?;
        if let Some(b) = a.as_bool() {
            return Some((b, None));
        }
        let (Some(id), Some(t)) = (a.reference(), self.table) else {
            self.warnings.push(format!("{name}={} is not a boolean", a.value));
            return None;
        };
        let variants: Vec<(String, bool)> = t
            .values(id)
            .into_iter()
            .filter_map(|v| match v.value {
                EntryValue::Simple(x) if x.kind == TYPE_INT_BOOLEAN => Some((v.config.to_string(), x.data != 0)),
                EntryValue::Simple(x) if x.kind == TYPE_STRING => {
                    Some((v.config.to_string(), t.string(x.data).is_some_and(|s| s == "true")))
                }
                _ => None,
            })
            .collect();
        let resolved = resolve_simple(t, id).and_then(|v| match v.kind {
            TYPE_INT_BOOLEAN => Some(v.data != 0),
            TYPE_STRING => t.string(v.data).map(|s| s == "true"),
            _ => None,
        });
        let Some(b) = resolved else {
            self.warnings.push(format!("{name}={} does not resolve to a boolean", a.value));
            return None;
        };
        let differs = variants.iter().any(|(_, v)| *v != variants[0].1);
        let note = differs.then(|| {
            let list: Vec<String> = variants.iter().map(|(c, v)| format!("{}={v}", if c.is_empty() { "default" } else { c })).collect();
            format!("{} varies: {}", a.value, list.join(","))
        });
        Some((b, note))
    }

    fn int_attr(&mut self, el: &Element, name: &str) -> Option<i64> {
        let a = el.android(name)?;
        if let Some(i) = a.as_int() {
            return Some(i);
        }
        if let (Some(id), Some(t)) = (a.reference(), self.table) {
            if let Some(v) = resolve_simple(t, id) {
                return match v.kind {
                    TYPE_STRING => t.string(v.data).and_then(|s| s.trim().parse().ok()),
                    _ => Some(v.data as i32 as i64),
                };
            }
        }
        // A codename such as "Tiramisu" in a preview build.
        a.value.parse().ok()
    }

    /// Path in the APK of the XML resource an attribute points at.
    fn xml_path(&mut self, a: &Attribute) -> Option<String> {
        let (id, t) = (a.reference()?, self.table?);
        match resolve_simple(t, id) {
            Some(v) if v.kind == TYPE_STRING => t.string(v.data).map(|s| s.into_owned()),
            _ => {
                self.warnings.push(format!("{}={} is not a file resource", a.name, a.value));
                None
            }
        }
    }
}

/// `.Foo` / `Foo` / `com.x.Foo` → fully qualified against `package`.
fn class_name(package: &str, name: &str) -> String {
    if let Some(rest) = name.strip_prefix('.') {
        format!("{package}.{rest}")
    } else if !name.contains('.') && !package.is_empty() {
        format!("{package}.{name}")
    } else {
        name.to_string()
    }
}

impl Engine {
    /// Parse `AndroidManifest.xml` (and the XML resources it points at) into
    /// a [`ManifestSummary`].
    pub fn manifest_summary(&self) -> Result<ManifestSummary> {
        let apk = self.open()?;
        let data = apk.read("AndroidManifest.xml")?;
        let table = self.resources()?;
        let resolver = table.as_deref().map(|t| t as &dyn asc_axml::Resolver);
        let root = asc_axml::parse_tree(&data, resolver)?;
        let mut r = Reader { table: table.as_deref(), warnings: Vec::new() };
        let mut s = ManifestSummary {
            package: root.plain("package").map(|a| a.value.clone()).unwrap_or_default(),
            version_code: r.str_attr(&root, "versionCode"),
            version_name: r.str_attr(&root, "versionName"),
            shared_user_id: r.str_attr(&root, "sharedUserId"),
            ..ManifestSummary::default()
        };
        if table.is_none() {
            s.warnings.push("no resources.arsc: references are not resolved".into());
        }
        for sdk in root.children_named("uses-sdk") {
            s.min_sdk = r.int_attr(sdk, "minSdkVersion").or(s.min_sdk);
            s.target_sdk = r.int_attr(sdk, "targetSdkVersion").or(s.target_sdk);
        }
        // Without a targetSdkVersion Android uses minSdkVersion (default 1).
        let target = s.target_sdk.or(s.min_sdk).unwrap_or(1);
        for el in &root.children {
            match el.name.as_str() {
                "uses-permission" | "uses-permission-sdk-23" | "uses-permission-sdk-m" => {
                    if let Some(n) = r.str_attr(el, "name") {
                        s.uses_permissions.push(n);
                    }
                }
                "permission" => {
                    let level = el.android("protectionLevel").map_or(0, |a| a.data);
                    s.permissions.push(Permission {
                        name: r.str_attr(el, "name").unwrap_or_default(),
                        protection_level: protection_level_name(level),
                    });
                }
                _ => {}
            }
        }
        if let Some(app) = root.children_named("application").next() {
            let a = &mut s.application;
            a.class = r.str_attr(app, "name").map(|n| class_name(&s.package, &n));
            a.debuggable = r.bool_attr(app, "debuggable").is_some_and(|b| b.0);
            a.allow_backup = r.bool_attr(app, "allowBackup").is_none_or(|b| b.0);
            a.test_only = r.bool_attr(app, "testOnly").is_some_and(|b| b.0);
            a.uses_cleartext_traffic = r.bool_attr(app, "usesCleartextTraffic").map(|b| b.0);
            a.permission = r.str_attr(app, "permission");
            a.full_backup_content = app.android("fullBackupContent").map(|x| r.xml_path(x).unwrap_or_else(|| x.value.clone()));
            a.data_extraction_rules = app.android("dataExtractionRules").map(|x| r.xml_path(x).unwrap_or_else(|| x.value.clone()));
            a.network_security_config = app.android("networkSecurityConfig").and_then(|x| r.xml_path(x));
            let mut nsc_cleartext = None;
            if let Some(path) = a.network_security_config.clone() {
                match apk.read(&path).map_err(crate::EngineError::from).and_then(|d| Ok(asc_axml::parse_tree(&d, resolver)?)) {
                    Ok(doc) => nsc_cleartext = network_security(&doc, table.as_deref(), &mut s.network_security),
                    Err(e) => r.warnings.push(format!("networkSecurityConfig {path}: {e}")),
                }
            }
            a.cleartext_effective = match (nsc_cleartext, a.uses_cleartext_traffic) {
                (Some(b), _) => (b, "networkSecurityConfig"),
                (None, Some(b)) => (b, "usesCleartextTraffic"),
                (None, None) => (target < SDK_CLEARTEXT_OFF, "targetSdk default"),
            };
            let app_permission = a.permission.clone();
            for el in &app.children {
                let kind = el.name.as_str();
                if !matches!(kind, "activity" | "activity-alias" | "service" | "receiver" | "provider") {
                    continue;
                }
                let mut c = Component {
                    kind: kind.to_string(),
                    class: class_name(&s.package, &r.str_attr(el, "name").unwrap_or_default()),
                    target: r.str_attr(el, "targetActivity").map(|n| class_name(&s.package, &n)),
                    enabled: r.bool_attr(el, "enabled").is_none_or(|b| b.0),
                    process: r.str_attr(el, "process"),
                    ..Component::default()
                };
                c.permission = r.str_attr(el, "permission");
                if c.permission.is_none() && app_permission.is_some() {
                    c.permission = app_permission.clone();
                    c.permission_from_app = true;
                }
                for f in el.children_named("intent-filter") {
                    let mut filter = IntentFilter::default();
                    for x in &f.children {
                        match x.name.as_str() {
                            "action" => filter.actions.extend(r.str_attr(x, "name")),
                            "category" => filter.categories.extend(r.str_attr(x, "name")),
                            "data" => {
                                let mut d = DataSpec {
                                    scheme: r.str_attr(x, "scheme"),
                                    host: r.str_attr(x, "host"),
                                    port: r.str_attr(x, "port"),
                                    mime_type: r.str_attr(x, "mimeType"),
                                    path: None,
                                };
                                for k in ["path", "pathPrefix", "pathPattern", "pathAdvancedPattern", "pathSuffix"] {
                                    if let Some(v) = r.str_attr(x, k) {
                                        d.path = Some((k.to_string(), v));
                                    }
                                }
                                filter.data.push(d);
                            }
                            _ => {}
                        }
                    }
                    c.intent_filters.push(filter);
                }
                let (exported, reason) = match r.bool_attr(el, "exported") {
                    Some((b, note)) => (b, note.map_or("explicit".to_string(), |n| format!("explicit, {n}"))),
                    None if !c.intent_filters.is_empty() && target < SDK_EXPLICIT_EXPORTED => (true, "intent-filter".to_string()),
                    None if !c.intent_filters.is_empty() => (false, "missing (install fails on targetSdk>=31)".to_string()),
                    None if kind == "provider" && target < SDK_PROVIDER_PRIVATE => (true, "provider-default".to_string()),
                    None => (false, "default".to_string()),
                };
                c.exported = exported;
                c.exported_reason = reason;
                if kind == "provider" {
                    c.authorities = r.str_attr(el, "authorities").map(|a| a.split(';').map(str::to_string).collect()).unwrap_or_default();
                    c.grant_uri_permissions = r.bool_attr(el, "grantUriPermissions").is_some_and(|b| b.0);
                    c.read_permission = r.str_attr(el, "readPermission");
                    c.write_permission = r.str_attr(el, "writePermission");
                }
                for m in el.children_named("meta-data") {
                    let name = r.str_attr(m, "name").unwrap_or_default();
                    let value = m.android("value").or(m.android("resource")).map(|a| r.string(a));
                    if name == FILE_PROVIDER_PATHS {
                        if let Some(path) = m.android("resource").and_then(|a| r.xml_path(a)) {
                            match apk.read(&path).map_err(crate::EngineError::from).and_then(|d| Ok(asc_axml::parse_tree(&d, resolver)?)) {
                                Ok(doc) => c.provider_paths = provider_paths(&doc),
                                Err(e) => r.warnings.push(format!("{FILE_PROVIDER_PATHS} {path}: {e}")),
                            }
                        }
                    }
                    c.meta_data.push((name, value.unwrap_or_default()));
                }
                s.components.push(c);
            }
        }
        s.warnings.extend(r.warnings);
        Ok(s)
    }
}

/// Summarize a network security config into `out` records; returns the
/// base config's cleartext setting when it states one.
fn network_security(doc: &Element, table: Option<&ResTable>, out: &mut Vec<String>) -> Option<bool> {
    let cleartext = |el: &Element| el.plain("cleartextTrafficPermitted").and_then(|a| a.as_bool());
    let anchors = |el: &Element| -> String {
        let list: Vec<String> = el
            .children_named("trust-anchors")
            .flat_map(|t| t.children_named("certificates"))
            .map(|c| {
                let src = c.plain("src").map_or(String::new(), |a| match (a.reference(), table) {
                    (Some(id), Some(t)) => format!("@{}", t.ref_name(id)),
                    _ => a.value.clone(),
                });
                match c.plain("overridePins").and_then(|a| a.as_bool()) {
                    Some(true) => format!("{src}(overridePins)"),
                    _ => src,
                }
            })
            .collect();
        list.join(",")
    };
    let mut base_cleartext = None;
    for el in &doc.children {
        match el.name.as_str() {
            "base-config" => {
                base_cleartext = cleartext(el);
                out.push(format!("base-config cleartextTrafficPermitted={} trust-anchors={}", fmt_opt(cleartext(el)), anchors(el)));
            }
            "debug-overrides" => out.push(format!("debug-overrides trust-anchors={}", anchors(el))),
            "domain-config" => domain_config(el, &cleartext, &anchors, out),
            _ => {}
        }
    }
    base_cleartext
}

fn domain_config(el: &Element, cleartext: &dyn Fn(&Element) -> Option<bool>, anchors: &dyn Fn(&Element) -> String, out: &mut Vec<String>) {
    let domains: Vec<String> = el
        .children_named("domain")
        .map(|d| {
            let sub = d.plain("includeSubdomains").and_then(|a| a.as_bool()).unwrap_or(false);
            if sub {
                format!("*.{}", d.text)
            } else {
                d.text.clone()
            }
        })
        .collect();
    let pins: usize = el.children_named("pin-set").map(|p| p.children_named("pin").count()).sum();
    out.push(format!(
        "domain-config domains={} cleartextTrafficPermitted={} trust-anchors={} pins={pins}",
        domains.join(","),
        fmt_opt(cleartext(el)),
        anchors(el)
    ));
    for nested in el.children_named("domain-config") {
        domain_config(nested, cleartext, anchors, out);
    }
}

fn fmt_opt(b: Option<bool>) -> String {
    b.map_or("-".to_string(), |b| b.to_string())
}

/// `<paths>` children of a FileProvider config.
fn provider_paths(doc: &Element) -> Vec<String> {
    doc.children
        .iter()
        .map(|p| {
            let attr = |n: &str| p.plain(n).map_or("-".to_string(), |a| a.value.clone());
            format!("{} name={} path={}", p.name, attr("name"), attr("path"))
        })
        .collect()
}

impl Component {
    fn line(&self) -> String {
        let mut s = format!("{} {} exported={} ({})", self.kind, self.class, self.exported, self.exported_reason);
        if !self.enabled {
            s.push_str(" enabled=false");
        }
        if let Some(t) = &self.target {
            s.push_str(&format!(" target={t}"));
        }
        if let Some(p) = &self.permission {
            s.push_str(&format!(" permission={p}{}", if self.permission_from_app { "(application)" } else { "" }));
        }
        if self.kind == "provider" {
            s.push_str(&format!(" authorities={} grantUriPermissions={}", self.authorities.join(";"), self.grant_uri_permissions));
            if let Some(p) = &self.read_permission {
                s.push_str(&format!(" readPermission={p}"));
            }
            if let Some(p) = &self.write_permission {
                s.push_str(&format!(" writePermission={p}"));
            }
        }
        if let Some(p) = &self.process {
            s.push_str(&format!(" process={p}"));
        }
        s
    }

    pub fn json(&self) -> Json {
        json!({
            "kind": self.kind,
            "class": self.class,
            "target": self.target,
            "exported": self.exported,
            "exported_reason": self.exported_reason,
            "enabled": self.enabled,
            "permission": self.permission,
            "permission_from_application": self.permission_from_app,
            "process": self.process,
            "authorities": self.authorities,
            "grant_uri_permissions": self.grant_uri_permissions,
            "read_permission": self.read_permission,
            "write_permission": self.write_permission,
            "intent_filters": self.intent_filters.iter().map(IntentFilter::json).collect::<Vec<_>>(),
            "deep_links": self.deep_links(),
            "meta_data": self.meta_data.iter().map(|(k, v)| json!({ "name": k, "value": v })).collect::<Vec<_>>(),
            "provider_paths": self.provider_paths,
        })
    }

    pub fn deep_links(&self) -> Vec<String> {
        let mut v: Vec<String> = self.intent_filters.iter().flat_map(IntentFilter::deep_links).collect();
        v.dedup();
        v
    }
}

impl ManifestSummary {
    /// One record per line, the first word naming the record type:
    /// `package`, `application`, `uses-permission`, `permission`, a component
    /// kind, `intent-filter`, `deeplink`, `provider-path`, `nsc`, `warning`.
    /// Component lines carry the class so `grep exported=true` lists the
    /// attack surface directly.
    pub fn lines(&self) -> Vec<String> {
        let opt = |o: &Option<String>| o.clone().unwrap_or_else(|| "-".into());
        let opt_i = |o: Option<i64>| o.map_or("-".to_string(), |v| v.to_string());
        let mut out = vec![format!(
            "package {} versionCode={} versionName={} minSdk={} targetSdk={} sharedUserId={}",
            self.package,
            opt(&self.version_code),
            opt(&self.version_name),
            opt_i(self.min_sdk),
            opt_i(self.target_sdk),
            opt(&self.shared_user_id)
        )];
        let a = &self.application;
        out.push(format!(
            "application class={} debuggable={} allowBackup={} testOnly={} usesCleartextTraffic={} cleartext={}({}) networkSecurityConfig={} permission={} fullBackupContent={} dataExtractionRules={}",
            opt(&a.class),
            a.debuggable,
            a.allow_backup,
            a.test_only,
            a.uses_cleartext_traffic.map_or("-".to_string(), |b| b.to_string()),
            a.cleartext_effective.0,
            a.cleartext_effective.1,
            opt(&a.network_security_config),
            opt(&a.permission),
            opt(&a.full_backup_content),
            opt(&a.data_extraction_rules),
        ));
        out.extend(self.uses_permissions.iter().map(|p| format!("uses-permission {p}")));
        out.extend(self.permissions.iter().map(|p| format!("permission {} protectionLevel={}", p.name, p.protection_level)));
        for c in &self.components {
            out.push(c.line());
            for f in &c.intent_filters {
                out.push(format!("intent-filter {} {}", c.class, f.line()));
            }
            for l in c.deep_links() {
                out.push(format!("deeplink {} {l}", c.class));
            }
            for p in &c.provider_paths {
                out.push(format!("provider-path {} {p}", c.authorities.join(";")));
            }
        }
        out.extend(self.network_security.iter().map(|l| format!("nsc {l}")));
        out.extend(self.warnings.iter().map(|w| format!("warning {w}")));
        out
    }

    pub fn json(&self) -> Json {
        let a = &self.application;
        json!({
            "package": self.package,
            "version_code": self.version_code,
            "version_name": self.version_name,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "shared_user_id": self.shared_user_id,
            "application": {
                "class": a.class,
                "debuggable": a.debuggable,
                "allow_backup": a.allow_backup,
                "test_only": a.test_only,
                "uses_cleartext_traffic": a.uses_cleartext_traffic,
                "cleartext": a.cleartext_effective.0,
                "cleartext_source": a.cleartext_effective.1,
                "network_security_config": a.network_security_config,
                "permission": a.permission,
                "full_backup_content": a.full_backup_content,
                "data_extraction_rules": a.data_extraction_rules,
            },
            "uses_permissions": self.uses_permissions,
            "permissions": self.permissions.iter().map(|p| json!({ "name": p.name, "protection_level": p.protection_level })).collect::<Vec<_>>(),
            "components": self.components.iter().map(Component::json).collect::<Vec<_>>(),
            "network_security": self.network_security,
            "warnings": self.warnings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_names_and_levels() {
        assert_eq!(class_name("com.a", ".Main"), "com.a.Main");
        assert_eq!(class_name("com.a", "Main"), "com.a.Main");
        assert_eq!(class_name("com.a", "org.b.Main"), "org.b.Main");
        assert_eq!(protection_level_name(0), "normal");
        assert_eq!(protection_level_name(0x12), "signature|privileged");
        assert_eq!(protection_level_name(0x4000_0002), "signature|0x40000000");
    }

    #[test]
    fn deep_link_patterns() {
        let f = IntentFilter {
            actions: vec!["android.intent.action.VIEW".into()],
            categories: vec!["android.intent.category.BROWSABLE".into()],
            data: vec![
                DataSpec { scheme: Some("https".into()), ..Default::default() },
                DataSpec { host: Some("a.com".into()), ..Default::default() },
                DataSpec { path: Some(("pathPrefix".into(), "/x".into())), ..Default::default() },
                DataSpec { scheme: Some("myapp".into()), ..Default::default() },
            ],
        };
        assert_eq!(f.deep_links(), ["https://a.com/x*", "myapp://a.com/x*"]);
        let none = IntentFilter { actions: vec!["android.intent.action.MAIN".into()], ..Default::default() };
        assert!(none.deep_links().is_empty());
    }
}
