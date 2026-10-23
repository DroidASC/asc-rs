//! `resources.arsc` access and binary XML decoding with resource names.

use crate::{Engine, EngineError, Result};
use asc_apk::{Apk, METHOD_STORED};
use asc_arsc::{Config, EntryValue, ResTable, Value};
use std::borrow::Cow;
use std::sync::Arc;
use std::time::SystemTime;

/// File identity used to notice that the APK changed under a cached table.
pub(crate) type FileIdent = (u64, Option<SystemTime>);

/// A parsed table (or its absence) and the APK version it was read from.
pub(crate) type CachedTable = (Option<FileIdent>, Option<Arc<ResTable>>);

pub(crate) fn file_ident(apk: &Apk) -> Option<FileIdent> {
    let meta = std::fs::metadata(apk.path()).ok()?;
    Some((meta.len(), meta.modified().ok()))
}

/// A stored (uncompressed) entry, borrowed from the APK mapping.
struct MappedEntry {
    apk: Apk,
    start: usize,
    len: usize,
}

impl AsRef<[u8]> for MappedEntry {
    fn as_ref(&self) -> &[u8] {
        &self.apk.data()[self.start..self.start + self.len]
    }
}

/// One resource matching a [`Engine::search_resources`] query.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceRow {
    pub id: u32,
    /// `type/name` (or `package:type/name` outside the app package).
    pub name: String,
    /// Qualifier string, empty for the default configuration.
    pub config: String,
    /// The value as [`ResTable::format_entry`] renders it.
    pub value: String,
}

impl ResourceRow {
    /// `0x7f0d0001 | string/app_name [zh-rCN] | "应用"` (no brackets for the
    /// default configuration): the configuration names which value it is,
    /// so it stays with the name and the columns stay three.
    pub fn line(&self) -> String {
        if self.config.is_empty() {
            format!("0x{:08x} | {} | {}", self.id, self.name, self.value)
        } else {
            format!("0x{:08x} | {} [{}] | {}", self.id, self.name, self.config, self.value)
        }
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({ "id": format!("0x{:08x}", self.id), "name": self.name, "config": self.config, "value": self.value })
    }
}

/// What [`Engine::search_resources`] matches against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceField {
    /// `type/name` of every resource.
    Name,
    /// String values (simple strings, array and plurals items).
    Value,
    /// Either.
    Any,
}

impl Engine {
    /// The APK's resource table, parsed once per APK version and kept for
    /// later calls. `None` when the APK has no `resources.arsc`.
    pub fn resources(&self) -> Result<Option<Arc<ResTable>>> {
        let apk = self.open()?;
        let ident = file_ident(&apk);
        if let Some((cached_ident, table)) = &*self.resources.lock().unwrap() {
            if ident.is_some() && *cached_ident == ident {
                return Ok(table.clone());
            }
        }
        let t0 = std::time::Instant::now();
        let table = match apk.find_entry("resources.arsc")? {
            None => None,
            Some(entry) => {
                let bytes = apk.read_entry(&entry)?;
                // Stored tables (the norm since API 30) stay in the mapping.
                let table = match bytes {
                    Cow::Borrowed(b) if entry.method == METHOD_STORED => {
                        let (start, len) = (b.as_ptr() as usize - apk.data().as_ptr() as usize, b.len());
                        ResTable::parse(MappedEntry { apk, start, len })?
                    }
                    b => ResTable::parse(b.into_owned())?,
                };
                if self.debug {
                    self.log(format!(
                        "[APK] resources.arsc {} bytes packages={} warnings={} parse={} us",
                        entry.uncomp_size,
                        table.packages().len(),
                        table.warnings().len(),
                        t0.elapsed().as_micros()
                    ));
                }
                Some(Arc::new(table))
            }
        };
        *self.resources.lock().unwrap() = Some((ident, table.clone()));
        Ok(table)
    }

    /// Forget the parsed resource table (and its name index); the next
    /// resource query parses it again (about a millisecond even for Douyin).
    pub fn release_resources(&self) {
        self.resources.lock().unwrap().take();
    }

    /// Decode a binary XML file of the APK (`res/xml/...`, a layout, the
    /// manifest), naming references and app attributes from the resource table.
    pub fn xml(&self, path: &str) -> Result<String> {
        let data = match self.open()?.read(path) {
            Ok(d) => d,
            Err(asc_apk::ApkError::NotFound(_)) => {
                return Err(EngineError::Query(format!("entry {path} not found{}", self.entry_not_found_hint(path))))
            }
            Err(e) => return Err(e.into()),
        };
        let table = self.resources()?;
        Ok(asc_axml::decode_with(&data, table.as_deref().map(|t| t as &dyn asc_axml::Resolver))?)
    }

    /// [`Engine::manifest_xml`] with `@7F...` references shown by name.
    pub fn manifest_xml_resolved(&self) -> Result<String> {
        self.xml("AndroidManifest.xml")
    }

    /// Call `f` with every value of every resource, in id order (one row per
    /// resource and configuration).
    pub fn dump_resources(&self, mut f: impl FnMut(ResourceRow)) -> Result<()> {
        let table = self.resources()?.ok_or_else(|| EngineError::Query("APK has no resources.arsc".into()))?;
        for id in table.ids() {
            let name = table.ref_name(id);
            for v in table.values(id) {
                f(ResourceRow { id, name: name.clone(), config: v.config.to_string(), value: table.format_entry(id, &v.value) });
            }
        }
        Ok(())
    }

    /// Every configuration's value of the resource `query`: an id
    /// (`0x7f0d0001`) or a name (`string/app_name`, `@pkg:type/name`).
    pub fn resource(&self, query: &str) -> Result<Vec<ResourceRow>> {
        let table = self.resources()?.ok_or_else(|| EngineError::Query("APK has no resources.arsc".into()))?;
        let id = parse_id(query)
            .or_else(|| table.lookup(query))
            .ok_or_else(|| EngineError::Query(format!("no resource {query}{}", self.resource_not_found_hint(&table, query))))?;
        let name = table.ref_name(id);
        let rows: Vec<ResourceRow> = table
            .values(id)
            .into_iter()
            .map(|v| ResourceRow { id, name: name.clone(), config: v.config.to_string(), value: table.format_entry(id, &v.value) })
            .collect();
        if rows.is_empty() {
            return Err(EngineError::Query(format!("no resource {query}")));
        }
        Ok(rows)
    }

    /// Resolve the reference chain of `query` for a device described by
    /// `config` (default: [`Config::any_device`]). Returns the rendered
    /// chain (`@string/a -> @string/b`) and the final value.
    pub fn resolve_resource(&self, query: &str, config: Option<&Config>) -> Result<(Vec<String>, ResourceRow)> {
        let table = self.resources()?.ok_or_else(|| EngineError::Query("APK has no resources.arsc".into()))?;
        let id = parse_id(query)
            .or_else(|| table.lookup(query))
            .ok_or_else(|| EngineError::Query(format!("no resource {query}{}", self.resource_not_found_hint(&table, query))))?;
        let r = table.resolve(id, config.unwrap_or(&Config::any_device())).map_err(|e| EngineError::Query(e.to_string()))?;
        let last = *r.chain.last().expect("chain starts with id");
        let chain = r.chain.iter().map(|&id| format!("@{}", table.ref_name(id))).collect();
        Ok((
            chain,
            ResourceRow { id: last, name: table.ref_name(last), config: r.config.to_string(), value: table.format_entry(last, &r.value) },
        ))
    }

    /// Resources whose name and/or string value matches the regex `pattern`
    /// (a plain substring when `literal`), one row per matching configuration
    /// value (names: one row per configuration). At most `limit` rows; the
    /// second value is the total number of matches.
    pub fn search_resources(&self, pattern: &str, literal: bool, field: ResourceField, limit: usize) -> Result<(Vec<ResourceRow>, usize)> {
        let source = if literal { regex::escape(pattern) } else { pattern.to_string() };
        let pattern = regex::Regex::new(&source).map_err(|e| EngineError::Query(format!("bad pattern: {e}")))?;
        let table = self.resources()?.ok_or_else(|| EngineError::Query("APK has no resources.arsc".into()))?;
        let mut rows = Vec::new();
        let mut total = 0usize;
        if field != ResourceField::Value {
            for id in table.ids() {
                let name = table.ref_name(id);
                if pattern.is_match(&name) {
                    for v in table.values(id) {
                        total += 1;
                        if rows.len() < limit {
                            rows.push(ResourceRow {
                                id,
                                name: name.clone(),
                                config: v.config.to_string(),
                                value: table.format_entry(id, &v.value),
                            });
                        }
                    }
                }
            }
        }
        if field != ResourceField::Name {
            table.for_each_string(|id, config, text| {
                if pattern.is_match(text) {
                    // Already listed by the name pass.
                    if field == ResourceField::Any && pattern.is_match(&table.ref_name(id)) {
                        return;
                    }
                    total += 1;
                    if rows.len() < limit {
                        let mut value = String::new();
                        asc_arsc::quote(text, &mut value);
                        rows.push(ResourceRow { id, name: table.ref_name(id), config: config.to_string(), value });
                    }
                }
            });
        }
        Ok((rows, total))
    }
}

impl Engine {
    /// Name the resource ids of `smali`: a `const` (or `.array-data` element)
    /// whose literal is a resource of this APK gets `# @type/name` appended,
    /// e.g. `const v0, 0x7f0b001c  # @layout/activity_main`. Unchanged when
    /// the APK has no (readable) resource table: names are a convenience,
    /// never a reason for the class itself to fail.
    pub fn annotate_resource_ids(&self, smali: &str) -> String {
        match self.resources() {
            Ok(Some(table)) => annotate(&table, smali),
            Ok(None) => smali.to_string(),
            Err(e) => {
                if self.debug {
                    self.log(format!("[APK] resources.arsc unreadable, constants left unnamed: {e}"));
                }
                smali.to_string()
            }
        }
    }
}

fn annotate(table: &ResTable, smali: &str) -> String {
    let mut out = String::with_capacity(smali.len() + smali.len() / 16);
    for line in smali.split_inclusive('\n') {
        let body = line.trim_end_matches('\n');
        let t = body.trim_start();
        let literal = if t.starts_with("const ") || t.starts_with("const/high16 ") {
            t.rsplit(", ").next()
        } else if t.starts_with("0x") && !t.contains(' ') {
            Some(t)
        } else {
            None
        };
        let id = literal.and_then(|l| l.strip_prefix("0x")).filter(|h| h.len() == 8).and_then(|h| u32::from_str_radix(h, 16).ok());
        match id.filter(|&id| id >> 24 != 0 && table.contains(id)) {
            Some(id) => {
                out.push_str(body);
                out.push_str("  # @");
                out.push_str(&table.ref_name(id));
                out.push_str(&line[body.len()..]);
            }
            None => out.push_str(line),
        }
    }
    out
}

/// `0x7f0d0001` / `7f0d0001` / `@0x7f0d0001`.
pub fn parse_id(s: &str) -> Option<u32> {
    let s = s.trim_start_matches('@');
    let hex = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    (hex.len() == 8).then(|| u32::from_str_radix(hex, 16).ok()).flatten()
}

/// The value of `v` as a plain string: string values unquoted, others as
/// [`ResTable::format_value`] renders them.
pub(crate) fn plain_value(table: &ResTable, v: &Value) -> String {
    if v.kind == asc_arsc::TYPE_STRING {
        return table.string(v.data).map(|s| s.into_owned()).unwrap_or_default();
    }
    table.format_value(v)
}

/// The simple value `id` resolves to, if it resolves to one.
pub(crate) fn resolve_simple(table: &ResTable, id: u32) -> Option<Value> {
    match table.resolve_default(id).ok()?.value {
        EntryValue::Simple(v) => Some(v),
        EntryValue::Bag { .. } => None,
    }
}
