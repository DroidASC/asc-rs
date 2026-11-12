//! Decompiled classes in the L3 tier of the disk cache
//! (docs/decompile-backends.md §8).
//!
//! The key holds everything the backend's output depends on: the program
//! ([`ApkKey`], the directory the file sits in), the input (`archive:` and
//! the class descriptor; a slice would be its SHA-256), the backend's name
//! and version and the hash of its effective options as `initialize`
//! reported them, the hash of the mappings sent with `program/open`, the
//! language and `nested`. The payload is the unit as the backend sent it, so
//! a hit renders exactly as a fresh answer does.
//!
//! A unit answering for a nested class folded into its outer class (§6.3)
//! is stored once, under the outer class; the nested class's key holds a
//! reference to it. A nested class with neither is looked up in the units
//! of the classes its `$`-separated name says may hold it, and served from
//! one whose `nestedClasses` lists it.

use asc_decompile::protocol::methods::{ClassUnit, InitializeResult, InputKind, Language, UnitStatus};
use asc_engine::asc_cache::{ApkKey, DiskCache, Tier, rendered_key};
use asc_engine::names::MappingsHash;
use serde_json::{Value, json};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Producer name in the L3 key.
const PRODUCER: &str = "decompile";
/// Layout of the key and payload below; bumping it drops every stored unit.
const FORMAT: &str = "1";
/// A failed unit is served this long only: failures often come from a
/// timeout or a lack of memory, which the next attempt may not meet (§8).
pub(super) const FAILED_TTL: Duration = Duration::from_secs(10 * 60);

/// What one stored unit is keyed by.
#[derive(Debug, Clone, Copy)]
pub(super) struct UnitKey<'a> {
    pub(super) descriptor: &'a str,
    pub(super) input: InputKind,
    pub(super) backend: &'a str,
    pub(super) capabilities: &'a InitializeResult,
    /// Of the mappings sent; `None` when none were.
    pub(super) mappings: Option<MappingsHash>,
    pub(super) language: Language,
    pub(super) nested: bool,
}

impl UnitKey<'_> {
    /// The L3 query string.
    pub(super) fn query(&self) -> String {
        let input = match self.input {
            InputKind::Archive => "archive",
            InputKind::Slice => "slice",
            _ => "other",
        };
        let language = match self.language {
            Language::Java => "java",
            Language::Kotlin => "kotlin",
            _ => "other",
        };
        let mappings = self.mappings.map_or_else(|| "-".to_string(), |hash| hash.to_string());
        let query = format!(
            "input={input}:{}\0backend={}\0version={}\0options={}\0mappings={mappings}\0language={language}\0nested={}",
            self.descriptor, self.backend, self.capabilities.backend.version, self.capabilities.options_hash, self.nested
        );
        rendered_key(PRODUCER, FORMAT, &query)
    }
}

/// What one key holds.
enum Stored {
    Unit(ClassUnit),
    /// The class is folded into the unit of this class.
    FoldedInto(String),
}

/// The unit showing the class of `key`: stored under `key`, or a unit of
/// an outer class that folds it in. Failures older than [`FAILED_TTL`] are
/// not served.
pub(super) fn get(disk: &DiskCache, apk: &ApkKey, key: &UnitKey<'_>) -> Option<ClassUnit> {
    get_at(disk, apk, key, SystemTime::now())
}

fn get_at(disk: &DiskCache, apk: &ApkKey, key: &UnitKey<'_>, now: SystemTime) -> Option<ClassUnit> {
    match stored_at(disk, apk, key, now) {
        Some(Stored::Unit(unit)) => Some(unit),
        Some(Stored::FoldedInto(outer)) => folded_at(disk, apk, key, &outer, now),
        None => owners(key.descriptor).find_map(|outer| folded_at(disk, apk, key, &outer, now)),
    }
}

/// The unit of `outer`, keyed as `key` otherwise, when it shows the class of `key`.
fn folded_at(disk: &DiskCache, apk: &ApkKey, key: &UnitKey<'_>, outer: &str, now: SystemTime) -> Option<ClassUnit> {
    match stored_at(disk, apk, &UnitKey { descriptor: outer, ..*key }, now)? {
        Stored::Unit(unit) if unit.covers(key.descriptor) => Some(unit),
        Stored::Unit(_) | Stored::FoldedInto(_) => None,
    }
}

fn stored_at(disk: &DiskCache, apk: &ApkKey, key: &UnitKey<'_>, now: SystemTime) -> Option<Stored> {
    let bytes = disk.get_rendered_view(apk, &key.query())?;
    let payload: Value = serde_json::from_slice(bytes.as_ref()).ok()?;
    if let Some(outer) = payload.get("foldedInto").and_then(Value::as_str) {
        return Some(Stored::FoldedInto(outer.to_string()));
    }
    let unit: ClassUnit = serde_json::from_value(payload.get("unit")?.clone()).ok()?;
    if unit.status() == UnitStatus::Failed {
        let stored = UNIX_EPOCH + Duration::from_secs(payload.get("storedAt")?.as_u64()?);
        if now.duration_since(stored).is_ok_and(|age| age > FAILED_TTL) {
            return None;
        }
    }
    Some(Stored::Unit(unit))
}

/// The classes the name of nested class `descriptor` says may hold it,
/// outermost first: `La/B;` and `La/B$C;` for `La/B$C$D;`. A `$` that
/// starts the simple name separates nothing.
fn owners(descriptor: &str) -> impl Iterator<Item = String> + '_ {
    let body = descriptor.strip_suffix(';').unwrap_or(descriptor);
    let simple = body.rfind('/').map_or(1, |slash| slash + 1);
    body.match_indices('$').filter(move |&(at, _)| at > simple).map(move |(at, _)| format!("{};", &body[..at]))
}

/// Stores `unit`, the answer for the class of `key`; a unit of the outer
/// class it is folded into goes under that class's key. A failure to write
/// only costs the next request a backend call.
pub(super) fn put(disk: &DiskCache, apk: &ApkKey, key: &UnitKey<'_>, unit: &ClassUnit) {
    put_at(disk, apk, key, unit, SystemTime::now());
}

fn put_at(disk: &DiskCache, apk: &ApkKey, key: &UnitKey<'_>, unit: &ClassUnit, now: SystemTime) {
    let stored = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    if unit.class != key.descriptor && unit.covers(key.descriptor) {
        write(disk, apk, &UnitKey { descriptor: &unit.class, ..*key }, &json!({"storedAt": stored, "unit": unit}));
        write(disk, apk, key, &json!({"storedAt": stored, "foldedInto": unit.class}));
    } else {
        write(disk, apk, key, &json!({"storedAt": stored, "unit": unit}));
    }
}

fn write(disk: &DiskCache, apk: &ApkKey, key: &UnitKey<'_>, payload: &Value) {
    let Ok(payload) = serde_json::to_vec(payload) else { return };
    if disk.put_rendered(apk, &key.query(), &payload).is_ok() {
        disk.evict_lazily();
    }
}

/// A second handle on the cache directory of `disk`, with its budget and tiers.
pub(super) fn reopen(disk: &DiskCache) -> DiskCache {
    let tiers: Vec<Tier> = Tier::ALL.into_iter().filter(|tier| disk.uses(*tier)).collect();
    DiskCache::open(disk.dir()).with_capacity_mode(disk.capacity_mode()).with_tiers(&tiers).with_min_dex_bytes(disk.min_dex_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use asc_decompile::protocol::methods::{Implementation, UnitOutcome};
    use asc_engine::names::NameMappings;

    fn capabilities(version: &str, options: &str) -> InitializeResult {
        InitializeResult::new(1, Implementation::new("mock", version), options)
    }

    #[test]
    fn every_part_of_the_key_counts() {
        let caps = capabilities("1.0", "h");
        let base = UnitKey {
            descriptor: "La;",
            input: InputKind::Archive,
            backend: "dexdec",
            capabilities: &caps,
            mappings: None,
            language: Language::Java,
            nested: true,
        };
        let (v2, o2) = (capabilities("2.0", "h"), capabilities("1.0", "h2"));
        let mut mapped = NameMappings::new();
        mapped.insert_class("La;", "Lb;").unwrap();
        let variants = [
            UnitKey { descriptor: "Lb;", ..base },
            UnitKey { input: InputKind::Slice, ..base },
            UnitKey { backend: "jadx", ..base },
            UnitKey { capabilities: &v2, ..base },
            UnitKey { capabilities: &o2, ..base },
            UnitKey { mappings: Some(NameMappings::new().hash()), ..base },
            UnitKey { mappings: Some(mapped.hash()), ..base },
            UnitKey { language: Language::Kotlin, ..base },
            UnitKey { nested: false, ..base },
        ];
        let mut queries: Vec<String> = variants.iter().map(UnitKey::query).collect();
        queries.push(base.query());
        let count = queries.len();
        queries.sort();
        queries.dedup();
        assert_eq!(queries.len(), count, "two keys collide");
    }

    #[test]
    fn failures_expire_after_ten_minutes_and_results_do_not() {
        let dir = tempfile::tempdir().unwrap();
        let disk = DiskCache::open(dir.path().join("cache"));
        let apk = fixture_key(dir.path());
        let caps = capabilities("1.0", "h");
        let key = |descriptor| UnitKey {
            descriptor,
            input: InputKind::Archive,
            backend: "mock",
            capabilities: &caps,
            mappings: None,
            language: Language::Java,
            nested: true,
        };
        let then = SystemTime::now();
        let failed = ClassUnit::new("La;", UnitOutcome::Failed { reason: "timeout".into() });
        let ok = ClassUnit::new("Lb;", UnitOutcome::Ok { path: None, text: "class b {}".into() });
        put_at(&disk, &apk, &key("La;"), &failed, then);
        put_at(&disk, &apk, &key("Lb;"), &ok, then);
        let soon = then + Duration::from_secs(60);
        let later = then + FAILED_TTL + Duration::from_secs(1);
        assert_eq!(get_at(&disk, &apk, &key("La;"), soon), Some(failed));
        assert_eq!(get_at(&disk, &apk, &key("La;"), later), None, "a failure is kept 10 minutes only");
        assert_eq!(get_at(&disk, &apk, &key("Lb;"), later), Some(ok));
        assert_eq!(reopen(&disk).dir(), disk.dir());
    }

    #[test]
    fn nested_classes_are_served_from_the_unit_they_are_folded_into() {
        let dir = tempfile::tempdir().unwrap();
        let disk = DiskCache::open(dir.path().join("cache"));
        let apk = fixture_key(dir.path());
        let caps = capabilities("1.0", "h");
        let key = |descriptor| UnitKey {
            descriptor,
            input: InputKind::Archive,
            backend: "mock",
            capabilities: &caps,
            mappings: None,
            language: Language::Java,
            nested: true,
        };
        let now = SystemTime::now();
        let outer = ClassUnit::new("La/O;", UnitOutcome::Ok { path: None, text: "class O { class I { class J {} } }".into() })
            .nested_classes(vec!["La/O$I;".into(), "La/O$I$J;".into(), "Lx;".into()]);
        // Asked for as the outer class itself: by `$`, the nested names find it.
        put_at(&disk, &apk, &key("La/O;"), &outer, now);
        assert_eq!(get_at(&disk, &apk, &key("La/O$I$J;"), now).as_ref(), Some(&outer));
        assert_eq!(get_at(&disk, &apk, &key("La/O$K;"), now), None, "not folded in");
        // Answered for a nested class without `$` in its name: a reference to the outer unit.
        put_at(&disk, &apk, &key("Lx;"), &outer, now);
        assert_eq!(get_at(&disk, &apk, &key("Lx;"), now).as_ref(), Some(&outer));
        let alias = disk.get_rendered_view(&apk, &key("Lx;").query()).unwrap();
        assert!(!String::from_utf8_lossy(alias.as_ref()).contains("class O"), "the text is stored once");

        assert_eq!(owners("La/B$C$D;").collect::<Vec<_>>(), ["La/B;", "La/B$C;"]);
        assert_eq!(owners("La/$B;").count(), 0);
        assert_eq!(owners("LB;").count(), 0);
    }

    fn fixture_key(dir: &std::path::Path) -> ApkKey {
        let path = dir.join("app.apk");
        std::fs::write(&path, asc_fixture::make_apk(&[("classes.dex", &asc_fixture::make_dex())], true)).unwrap();
        let config = asc_engine::CacheConfig::default().disk(Some(DiskCache::open(dir.join("engine-cache"))));
        let engine = asc_engine::Engine::new(&path).with_cache(config);
        engine.apk_key(&engine.open().unwrap()).unwrap()
    }
}
