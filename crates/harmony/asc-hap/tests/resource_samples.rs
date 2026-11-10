//! `resources.index` of real packages, when they are on this machine:
//! `<workspace>/../ark/ReArk/samples` (or `$ASC_ABC_SAMPLES`) and the
//! app-store `entry.hap` in `$ASC_ABC_LARGE_SAMPLE`. Each test passes
//! vacuously when its files are absent.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use asc_hap::{IndexFormat, ResourceIndex, ResourceRef, ResourceType, ResourceValue};
use serde_json::Value;
use zip::ZipArchive;

/// `$ASC_ABC_SAMPLES`, else `<workspace>/../ark/ReArk/samples`.
fn samples() -> Option<PathBuf> {
    let path = match std::env::var_os("ASC_ABC_SAMPLES") {
        Some(path) => PathBuf::from(path),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../../ark/ReArk/samples"),
    };
    path.is_dir().then_some(path)
}

/// `$ASC_ABC_LARGE_SAMPLE`: the directory of an app-store `entry.hap`. No default.
fn large_sample_dir() -> Option<PathBuf> {
    std::env::var_os("ASC_ABC_LARGE_SAMPLE").map(PathBuf::from).filter(|path| path.is_dir())
}

/// What the tests need of one HAP.
struct Package {
    index: Vec<u8>,
    module: Value,
    entries: BTreeSet<String>,
}

impl Package {
    /// A `.hap`, or the `entry-default.hap` inside an `.app`.
    fn open(path: &Path) -> Option<Package> {
        let mut bytes = std::fs::read(path).ok()?;
        if path.extension().is_some_and(|e| e == "app") {
            bytes = Self::entry(&mut ZipArchive::new(Cursor::new(bytes)).unwrap(), "entry-default.hap");
        }
        let mut zip = ZipArchive::new(Cursor::new(bytes)).unwrap();
        Some(Package {
            index: Self::entry(&mut zip, "resources.index"),
            module: serde_json::from_slice(&Self::entry(&mut zip, "module.json")).unwrap(),
            entries: zip.file_names().map(str::to_owned).collect(),
        })
    }

    fn entry(zip: &mut ZipArchive<Cursor<Vec<u8>>>, name: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        zip.by_name(name).unwrap_or_else(|e| panic!("{name}: {e}")).read_to_end(&mut bytes).unwrap();
        bytes
    }

    fn sample(name: &str) -> Option<Package> {
        Package::open(&samples()?.join(name))
    }

    fn large_sample() -> Option<Package> {
        Package::open(&large_sample_dir()?.join("entry.hap"))
    }

    fn index(&self) -> ResourceIndex<'_> {
        ResourceIndex::parse(&self.index).unwrap()
    }

    /// Values per type.
    fn types(&self) -> BTreeMap<String, usize> {
        let mut types = BTreeMap::new();
        for resource in &self.index() {
            *types.entry(resource.kind().to_string()).or_insert(0) += 1;
        }
        types
    }

    fn qualifiers(&self) -> Vec<String> {
        self.index().qualifiers().iter().map(ToString::to_string).collect()
    }

    /// What must hold for an index next to the package it came from.
    /// Returns how many manifest references were followed.
    fn check(&self) -> usize {
        let index = self.index();
        for resource in &index {
            assert!(!matches!(resource.kind(), ResourceType::Other(_)), "{resource}");
            assert!(index.by_id(resource.id()).any(|r| r.qualifiers() == resource.qualifiers()));
            assert!(index.by_name(resource.kind(), &resource.name()).all(|r| r.id() == resource.id()), "{resource}");
            let value = resource.value();
            assert!(!matches!(value, ResourceValue::Raw(_)), "{resource}");
            // Every media and profile value names a file of the package.
            if let Some(path) = value.archive_path() {
                assert!(self.entries.contains(path), "{resource}: no entry {path}");
            }
        }
        let mut followed = 0;
        self.check_references(&self.module, &index, &mut followed);
        followed
    }

    /// Every `$type:name` of `module.json` is in the index, under the id
    /// the packing tool wrote next to it (`label` / `labelId`).
    fn check_references(&self, json: &Value, index: &ResourceIndex<'_>, followed: &mut usize) {
        match json {
            Value::Object(fields) => {
                for (key, value) in fields {
                    let Some(reference) = value.as_str().and_then(ResourceRef::parse) else {
                        self.check_references(value, index, followed);
                        continue;
                    };
                    let ids: BTreeSet<u32> = index.resolve(reference).map(|r| r.id()).collect();
                    assert_eq!(ids.len(), 1, "{key}: {reference}");
                    if let Some(id) = fields.get(&format!("{key}Id")).and_then(Value::as_u64) {
                        assert_eq!(ids.first().copied().map(u64::from), Some(id), "{key}: {reference}");
                    }
                    *followed += 1;
                }
            }
            Value::Array(items) => items.iter().for_each(|item| self.check_references(item, index, followed)),
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
}

fn counts(types: &[(&str, usize)]) -> BTreeMap<String, usize> {
    types.iter().map(|&(name, count)| (name.to_owned(), count)).collect()
}

#[test]
fn every_sample_index_agrees_with_its_package() {
    let Some(samples) = samples() else { return };
    let mut seen = 0;
    for file in std::fs::read_dir(samples).unwrap() {
        let path = file.unwrap().path();
        if !path.extension().is_some_and(|e| e == "hap" || e == "app") {
            continue;
        }
        let followed = Package::open(&path).unwrap().check();
        assert!(followed >= 9, "{}: only {followed} references in module.json", path.display());
        seen += 1;
    }
    assert!(seen >= 6, "only {seen} samples in the directory");
}

#[test]
fn bridge_uses_the_second_layout() {
    let Some(p) = Package::sample("Bridge.hap") else { return };
    let index = p.index();
    assert_eq!((index.format(), index.version(), index.len()), (IndexFormat::V2, "RestoolV2 6.0.0.001", 18));
    assert_eq!(p.qualifiers(), ["en_US", "zh_CN", "base"]);
    assert_eq!(p.types(), counts(&[("color", 1), ("media", 5), ("profile", 2), ("string", 10)]));
    let label: Vec<String> = index.resolve(ResourceRef::parse("$string:EntryAbility_label").unwrap()).map(|r| r.to_string()).collect();
    assert_eq!(
        label,
        [
            r#"0x01000003 string/EntryAbility_label [en_US] "label""#,
            r#"0x01000003 string/EntryAbility_label [zh_CN] "Bridge""#,
            r#"0x01000003 string/EntryAbility_label [base] "Bridge""#,
        ]
    );
    let pages = index.by_name(ResourceType::Profile, "main_pages").next().unwrap();
    assert_eq!(pages.value().archive_path(), Some("resources/base/profile/main_pages.json"));
}

#[test]
fn contacts_has_a_dark_colour() {
    let Some(p) = Package::sample("contacts.hap") else { return };
    let index = p.index();
    assert_eq!((index.format(), index.version(), index.len()), (IndexFormat::V1, "Restool 5.012", 121));
    assert_eq!(p.qualifiers(), ["base", "dark", "en_US", "zh_CN"]);
    assert_eq!(p.types(), counts(&[("color", 11), ("float", 86), ("media", 6), ("profile", 2), ("string", 16)]));
    // `$r('app.string.…')` in components/Header compiled to
    // `{ id: 0x1000014, type: 10003, … }`, and 10003 says string.
    let resource = index.by_id(0x0100_0014).next().unwrap();
    assert_eq!(Some(resource.kind()), ResourceType::from_object_code(10003));
    let dark: Vec<_> = index.iter().filter(|r| !r.qualifiers().is_base() && r.kind() == ResourceType::Color).collect();
    assert_eq!(dark.len(), 1);
    assert_eq!(index.by_id(dark[0].id()).len(), 2);
}

#[test]
fn the_oldest_and_newest_first_layout() {
    let Some(old) = Package::sample("EasyHap-default-unsigned.app") else { return };
    assert_eq!(
        (old.index().format(), old.index().version().to_owned(), old.index().len()),
        (IndexFormat::V1, "Restool 2.010".to_owned(), 14)
    );
    // A 6.0 tool still writes the first layout unless asked for the second.
    let Some(new) = Package::sample("fpt-default-signed.app") else { return };
    assert_eq!((new.index().format(), new.index().version().to_owned()), (IndexFormat::V1, "Restool 6.0.0.001".to_owned()));
    assert_eq!(new.qualifiers(), ["base", "dark"]);
}

#[test]
fn large_sample() {
    let Some(p) = Package::large_sample() else { return };
    // The app-store package encrypts its code, not its resource table.
    let index = p.index();
    assert!(index.len() > 100, "{} values", index.len());
    assert!(p.qualifiers().contains(&"base".to_owned()), "{:?}", p.qualifiers());
    let types = p.types();
    assert_eq!(types.values().sum::<usize>(), index.len());
    assert!(types.contains_key("string") && types.contains_key("media"), "{types:?}");
    // `"label": "$string:EntryAbility_label"` and friends resolve.
    assert!(p.check() >= 9);
    // A value per qualifier: fewer ids than values, and each id's values differ in qualifiers.
    let ids: BTreeSet<u32> = index.iter().map(|r| r.id()).collect();
    assert!(ids.len() < index.len());
    for &id in &ids {
        let qualifiers: BTreeSet<String> = index.by_id(id).map(|r| r.qualifiers().to_string()).collect();
        assert_eq!(qualifiers.len(), index.by_id(id).len(), "{id:#010x}");
    }
    // Ids are in one block, wherever the build configured it to start (not always 0x01000000).
    let (first, last) = (*ids.first().unwrap(), *ids.last().unwrap());
    assert_eq!(first >> 24, last >> 24, "{first:#010x}..{last:#010x}");
}
