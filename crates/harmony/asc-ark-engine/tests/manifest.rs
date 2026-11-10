//! `Engine::manifest` over synthetic packages: the documents of a hap, an
//! `.app` and a directory, and the join of each `srcEntry` to its record.
//!
//! The tests at the end run on real packages, which are not in the
//! repository (see `tests/samples.rs` for where they are looked for); each
//! returns early when its file is absent.

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use asc_ark_engine::{CodeLink, Document, Engine, EngineError, Manifest};
use asc_fixture::abc::{make_abc, make_multi_region_abc, sample_program, ENTRY_ABILITY};
use asc_fixture::hap::{make_app, make_hap, Compression, Hap, SAMPLE_MODULE_JSON};

/// The package table of the sample module, plus a library and a native one.
const PKG_CONTEXT: &str = r#"{
  "entry": {"packageName": "entry", "bundleName": "", "moduleName": "", "version": "", "entryPath": "src/main/", "isSO": false, "dependencyAlias": ""},
  "@ohos/lib": {"packageName": "@ohos/lib", "bundleName": "", "moduleName": "", "version": "1.0.0", "entryPath": "Index.ets", "isSO": false, "dependencyAlias": ""},
  "libnative.so": {"packageName": "libnative.so", "bundleName": "", "moduleName": "", "version": "", "entryPath": "", "isSO": true, "dependencyAlias": ""}
}"#;

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    path
}

fn manifest(path: &Path) -> Manifest {
    Engine::open(path).unwrap().manifest().unwrap()
}

fn lines(manifest: &Manifest, document: Option<Document>) -> Vec<String> {
    let several = manifest.has_several_packages();
    manifest.summary_lines(document).iter().map(|line| line.line(several)).collect()
}

/// The lines that start with `word`.
fn starting<'l>(lines: &'l [String], word: &str) -> Vec<&'l str> {
    lines.iter().map(String::as_str).filter(|line| line.split(' ').next() == Some(word)).collect()
}

#[test]
fn a_hap_joins_its_components_to_records() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "entry.hap", &make_hap(&make_abc()));
    let manifest = manifest(&path);
    assert!(!manifest.has_several_packages());
    let package = &manifest.packages[0];
    assert_eq!(package.name, "entry.hap");
    assert_eq!(package.module.as_ref().unwrap().app.bundle_name.as_deref(), Some("com.example.sample"));
    assert!(package.pack.is_some() && package.pkg_context.is_none() && package.records.is_none() && package.notes.is_empty());
    // The module has no srcEntry of its own; the ability's is the second spelling tried.
    assert_eq!(package.module_code, None);
    let code = package.component_code[0].as_ref().unwrap();
    assert_eq!(code.src_entry, "./ets/entryability/EntryAbility.ets");
    assert_eq!(
        code.link,
        CodeLink::Record { record: ENTRY_ABILITY.into(), entry: "ets/modules.abc".into(), callbacks: vec!["EntryAbility.onCreate".into()] }
    );

    let all = lines(&manifest, None);
    assert_eq!(
        starting(&all, "ability"),
        [format!("ability EntryAbility exported=true (explicit) permissions=- skills=1 srcEntry=./ets/entryability/EntryAbility.ets record={ENTRY_ABILITY}")]
    );
    assert_eq!(starting(&all, "callbacks"), [format!("callbacks EntryAbility record={ENTRY_ABILITY} functions=EntryAbility.onCreate")]);
    // The ability's lines stay together, the callbacks right after it.
    let at = all.iter().position(|line| line.starts_with("ability ")).unwrap();
    assert!(all[at + 1].starts_with("callbacks EntryAbility ") && all[at + 2].starts_with("skill EntryAbility "), "{all:?}");
    assert_eq!(starting(&all, "deeplink"), ["deeplink EntryAbility sample://open"]);
    assert_eq!(starting(&all, "request-permission").len(), 1);
    assert_eq!(starting(&all, "pack-app"), ["pack-app com.example.sample bundleType=- versionCode=1000000 versionName=1.0.0"]);
    assert!(starting(&all, "module")[0].starts_with("module entry type=entry ") && !starting(&all, "module")[0].contains("record="));
    assert!(starting(&all, "package-table").is_empty());

    // One document only; the documents themselves, re-indented.
    assert!(lines(&manifest, Some(Document::Pack)).iter().all(|line| line.starts_with("pack-")));
    assert!(lines(&manifest, Some(Document::Module)).iter().all(|line| !line.starts_with("pack-")));
    assert!(lines(&manifest, Some(Document::PkgContext)).is_empty() && !manifest.has(Document::PkgContext));
    let documents = manifest.documents(Document::Module);
    assert_eq!(documents.len(), 1);
    let reparsed: serde_json::Value = serde_json::from_str(&documents[0].text).unwrap();
    assert_eq!(reparsed, serde_json::from_str::<serde_json::Value>(SAMPLE_MODULE_JSON).unwrap());
    assert!(documents[0].text.starts_with("{\n  \"app\": {"), "{}", documents[0].text);

    let json = manifest.json();
    let component = &json["packages"][0]["components"][0];
    assert_eq!(component["record"], ENTRY_ABILITY);
    assert_eq!(component["callbacks"][0], "EntryAbility.onCreate");
    assert_eq!((component["exported"].as_bool(), component["deep_links"][0].as_str()), (Some(true), Some("sample://open")));
    assert_eq!(json["packages"][0]["request_permissions"][0], "ohos.permission.INTERNET");
}

#[test]
fn an_app_has_its_own_pack_info_and_one_section_per_package() {
    let dir = tempfile::tempdir().unwrap();
    let hap = make_hap(&make_abc());
    for inner in [Compression::Stored, Compression::Deflated] {
        let path = write(dir.path(), "shop.app", &make_app(&[("entry.hap", &hap), ("feature.hap", &hap)], inner));
        let manifest = manifest(&path);
        assert_eq!(
            manifest.packages.iter().map(|package| package.name.as_str()).collect::<Vec<_>>(),
            ["shop.app", "entry.hap", "feature.hap"]
        );
        let outer = &manifest.packages[0];
        assert!(outer.module.is_none() && outer.pack.is_some() && outer.component_code.is_empty());
        let all = lines(&manifest, None);
        assert_eq!(all[0], "shop.app | pack-app com.example.sample bundleType=- versionCode=1000000 versionName=1.0.0");
        // Each package resolves in its own code, and a program of several entries names the entry.
        let abilities: Vec<&str> = all.iter().filter(|line| line.contains(" | ability ")).map(String::as_str).collect();
        assert_eq!(abilities.len(), 2);
        assert!(abilities[0].starts_with("entry.hap | ability EntryAbility "), "{abilities:?}");
        assert!(abilities[0].ends_with(&format!(" record={ENTRY_ABILITY} abc=entry.hap/ets/modules.abc")), "{abilities:?}");
        assert!(abilities[1].starts_with("feature.hap | ability EntryAbility "), "{abilities:?}");
        assert!(abilities[1].ends_with(&format!(" record={ENTRY_ABILITY} abc=feature.hap/ets/modules.abc")), "{abilities:?}");
        // Sections follow one another whole.
        let packages: Vec<&str> = all.iter().map(|line| line.split(" | ").next().unwrap()).collect();
        let mut sections = packages.clone();
        sections.dedup();
        assert_eq!(sections, ["shop.app", "entry.hap", "feature.hap"]);
        assert_eq!(manifest.documents(Document::Pack).len(), 3);
        assert_eq!(
            manifest.documents(Document::Module).iter().map(|d| d.package.as_str()).collect::<Vec<_>>(),
            ["entry.hap", "feature.hap"]
        );
    }
}

#[test]
fn a_directory_names_packages_by_their_path() {
    let dir = tempfile::tempdir().unwrap();
    let hap = make_hap(&make_abc());
    write(dir.path(), "b/feature.hap", &hap);
    write(dir.path(), "a/entry.hap", &hap);
    write(dir.path(), "c/lib.abc", &make_abc());
    let first = lines(&manifest(dir.path()), None);
    let mut sections: Vec<&str> = first.iter().map(|line| line.split(" | ").next().unwrap()).collect();
    sections.dedup();
    assert_eq!(sections, ["a/entry.hap", "b/feature.hap"]);
    assert!(first.iter().any(|line| line.starts_with("b/feature.hap | ability ") && line.ends_with(" abc=b/feature.hap/ets/modules.abc")));
    // The same program gives the same lines.
    assert_eq!(lines(&manifest(dir.path()), None), first);
}

#[test]
fn a_bare_abc_has_no_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "modules.abc", &make_abc());
    let error = Engine::open(&path).unwrap().manifest().unwrap_err();
    assert!(matches!(error, EngineError::NoManifest { document: None, bare: true, .. }), "{error:?}");
    assert_eq!(
        error.to_string(),
        format!(
            "no manifest in {}: a bare .abc carries no module.json; pass the .hap / .app it came from, or a directory holding both",
            path.display()
        )
    );
    // A package without any of the documents is no bare file.
    let path = write(dir.path(), "plain.hap", &Hap::new().modules_abc(&make_abc()).build());
    let error = Engine::open(&path).unwrap().manifest().unwrap_err();
    assert_eq!(error.to_string(), format!("no manifest in {}", path.display()));
}

#[test]
fn an_encrypted_entry_leaves_the_component_unresolved_until_the_decrypted_file_is_there() {
    let dir = tempfile::tempdir().unwrap();
    let encrypted = sample_program().encrypted().build().bytes;
    let hap = Hap::new().modules_abc(&encrypted).module_json(SAMPLE_MODULE_JSON).entry(
        "pkgContextInfo.json",
        PKG_CONTEXT.as_bytes(),
        Compression::Stored,
    );
    write(dir.path(), "store/entry.hap", &hap.build());
    let store = dir.path().join("store");

    let alone = manifest(&store);
    let code = alone.packages[0].component_code[0].as_ref().unwrap();
    assert_eq!(code.link, CodeLink::Missing { reason: "ets/modules.abc is encrypted".into() });
    let all = lines(&alone, None);
    assert!(
        starting(&all, "ability")[0].ends_with(" srcEntry=./ets/entryability/EntryAbility.ets record=- (ets/modules.abc is encrypted)"),
        "{all:?}"
    );
    assert!(starting(&all, "callbacks").is_empty());
    assert_eq!(
        starting(&all, "package-table"),
        ["package-table packages=3 native=1 with-records=0 records=0 unlocated=0 file=pkgContextInfo.json (ets/modules.abc is encrypted)"]
    );
    assert_eq!(alone.json()["packages"][0]["components"][0]["unresolved"], "ets/modules.abc is encrypted");

    // The decrypted file stands in for the entry, and the join goes through it.
    write(dir.path(), "store/modules.abc", &make_abc());
    let paired = manifest(&store);
    let all = lines(&paired, None);
    assert!(starting(&all, "ability")[0].ends_with(&format!(" record={ENTRY_ABILITY}")), "{all:?}");
    assert_eq!(
        starting(&all, "package-table"),
        ["package-table packages=3 native=1 with-records=1 records=2 unlocated=0 file=pkgContextInfo.json"]
    );
    // Whatever the decrypted file is called: the header and the body pair it.
    fs::rename(store.join("modules.abc"), store.join("entry.hap.abc")).unwrap();
    let all = lines(&manifest(&store), None);
    assert!(starting(&all, "ability")[0].ends_with(&format!(" record={ENTRY_ABILITY}")), "{all:?}");
    // An unrelated bare file is searched when the package has nothing readable.
    fs::remove_file(store.join("entry.hap.abc")).unwrap();
    write(dir.path(), "store/dump.abc", &make_multi_region_abc());
    let all = lines(&manifest(&store), None);
    assert!(starting(&all, "ability")[0].ends_with(&format!(" record={ENTRY_ABILITY} abc=dump.abc")), "{all:?}");
}

#[test]
fn a_source_file_without_a_record_says_which_names_were_tried() {
    let dir = tempfile::tempdir().unwrap();
    let module_json = SAMPLE_MODULE_JSON
        .replace("./ets/entryability/EntryAbility.ets", "./ets/gone/Missing.ets")
        .replace("\"type\": \"entry\",", "\"type\": \"entry\", \"srcEntry\": \"./ets/entryability/EntryAbility.ets\",");
    let hap = Hap::new().modules_abc(&make_abc()).module_json(&module_json);
    let path = write(dir.path(), "entry.hap", &hap.build());
    let all = lines(&manifest(&path), None);
    let ability = starting(&all, "ability")[0];
    assert!(
        ability.ends_with(" record=- (no record com.example.sample/entry/ets/gone/Missing or &entry/src/main/ets/gone/Missing&)"),
        "{ability}"
    );
    // The module's own srcEntry is joined the same way.
    let module = starting(&all, "module")[0];
    assert!(module.ends_with(&format!(" record={ENTRY_ABILITY}")), "{module}");
    assert_eq!(starting(&all, "callbacks"), [format!("callbacks entry record={ENTRY_ABILITY} functions=EntryAbility.onCreate")]);

    // With a package table the normalized name is tried first.
    let path = write(dir.path(), "table.hap", &hap.entry("pkgContextInfo.json", PKG_CONTEXT.as_bytes(), Compression::Deflated).build());
    let all = lines(&manifest(&path), None);
    let ability = starting(&all, "ability")[0];
    assert!(ability.ends_with(" (no record &entry/src/main/ets/gone/Missing& or com.example.sample/entry/ets/gone/Missing)"), "{ability}");
}

#[test]
fn the_package_table_counts_the_records_of_each_package() {
    let dir = tempfile::tempdir().unwrap();
    let hap = Hap::new().modules_abc(&make_abc()).module_json(SAMPLE_MODULE_JSON).entry(
        "pkgContextInfo.json",
        PKG_CONTEXT.as_bytes(),
        Compression::Stored,
    );
    let path = write(dir.path(), "entry.hap", &hap.build());
    let manifest = manifest(&path);
    assert!(manifest.has(Document::PkgContext));
    assert_eq!(
        lines(&manifest, Some(Document::PkgContext)),
        [
            "package @ohos/lib version=1.0.0 entryPath=Index.ets isSO=false bundleName=- moduleName=- dependencyAlias=- records=0",
            "package entry version=- entryPath=src/main/ isSO=false bundleName=- moduleName=- dependencyAlias=- records=2",
            "package libnative.so version=- entryPath=- isSO=true bundleName=- moduleName=- dependencyAlias=- records=0",
        ]
    );
    let records = manifest.packages[0].records.as_ref().unwrap();
    assert_eq!((records.per_package.as_slice(), records.unlocated), (&[0, 2, 0][..], 0));
    assert_eq!(
        starting(&lines(&manifest, None), "package-table"),
        ["package-table packages=3 native=1 with-records=1 records=2 unlocated=0 file=pkgContextInfo.json"]
    );
    assert_eq!(manifest.json()["packages"][0]["package_table"]["records"], 2);
}

#[test]
fn a_document_that_is_not_json_is_a_note() {
    let dir = tempfile::tempdir().unwrap();
    let hap = Hap::new().modules_abc(&make_abc()).module_json("not json").pack_info(asc_fixture::hap::SAMPLE_PACK_INFO);
    let path = write(dir.path(), "entry.hap", &hap.build());
    let manifest = manifest(&path);
    assert!(!manifest.has(Document::Module) && manifest.has(Document::Pack));
    let all = lines(&manifest, None);
    assert!(all[0].starts_with("pack-app "), "{all:?}");
    assert!(all.last().unwrap().starts_with("note module.json: invalid JSON: "), "{all:?}");
}

/// `(what has the srcEntry, its record or the reason there is none)` for
/// every srcEntry of every package.
fn joins(manifest: &Manifest) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for package in &manifest.packages {
        let Some(module) = &package.module else { continue };
        let components = module.components().map(|component| component.name.clone().unwrap_or_default()).zip(&package.component_code);
        let all = std::iter::once(("module".to_owned(), &package.module_code)).chain(components);
        for (name, code) in all {
            match code.as_ref().map(|code| &code.link) {
                Some(CodeLink::Record { record, .. }) => out.push((name, record.clone())),
                Some(CodeLink::Missing { reason }) => out.push((name, format!("- ({reason})"))),
                None => {}
            }
        }
    }
    out
}

fn pairs(joins: &[(String, String)]) -> Vec<(&str, &str)> {
    joins.iter().map(|(name, record)| (name.as_str(), record.as_str())).collect()
}

#[test]
fn real_samples_resolve_every_component() {
    let expected: [(&str, &[(&str, &str)]); 6] = [
        ("Bridge.hap", &[("EntryAbility", "com.hmos.exam5.pkg/entry/ets/entryability/EntryAbility")]),
        (
            "contacts.hap",
            &[
                ("EntryAbility", "&entry/src/main/ets/entryability/EntryAbility&"),
                ("EntryBackupAbility", "&entry/src/main/ets/entrybackupability/EntryBackupAbility&"),
            ],
        ),
        ("遥遥领先.hap", &[("EntryAbility", "com.lenovo.bridgeclone/entry/ets/entryability/EntryAbility")]),
        ("EasyHap-default-unsigned.app", &[("EntryAbility", "com.zjuctf2024.easyhap/entry/ets/entryability/EntryAbility")]),
        (
            "fpt-default-signed.app",
            &[
                ("EntryAbility", "&entry/src/main/ets/entryability/EntryAbility&"),
                ("EntryBackupAbility", "&entry/src/main/ets/entrybackupability/EntryBackupAbility&"),
            ],
        ),
        (
            "shctf.app",
            &[
                ("EntryAbility", "com.welcome.shctf/entry/ets/entryability/EntryAbility"),
                ("EntryBackupAbility", "com.welcome.shctf/entry/ets/entrybackupability/EntryBackupAbility"),
            ],
        ),
    ];
    for (file, records) in expected {
        let Some(path) = common::sample(file) else { continue };
        let engine = Engine::open(&path).unwrap();
        let manifest = engine.manifest().unwrap();
        assert_eq!(pairs(&joins(&manifest)), records, "{file}");
        // Every record named is one getclass takes.
        for (_, record) in records {
            let query = asc_ark_engine::ClassQuery { record, ..Default::default() };
            assert_eq!(engine.get_class(&query).unwrap().record, *record, "{file}");
        }
        // An .app has a section of its own ahead of its package.
        assert_eq!(manifest.packages.len(), if file.ends_with(".app") { 2 } else { 1 }, "{file}");
        assert_eq!(manifest.packages[0].name, file);
    }
}

#[test]
fn large_sample_resolves_through_the_decrypted_file_only() {
    let Some(dir) = common::large_sample_dir() else { return };
    let paired = manifest(&dir);
    // The stage and every ability name a record of the decrypted code.
    let joined = joins(&paired);
    let resolved = pairs(&joined);
    assert!(resolved.len() > 1 && resolved[0].0 == "module", "{resolved:?}");
    let engine = Engine::open(&dir).unwrap();
    for (name, record) in &resolved {
        let query = asc_ark_engine::ClassQuery { record, ..Default::default() };
        assert_eq!(engine.get_class(&query).unwrap().record, *record, "{name}");
    }
    let all = lines(&paired, None);
    // Callbacks are the methods the system calls, one line per component.
    let callbacks = starting(&all, "callbacks");
    assert_eq!(callbacks.len(), resolved.len(), "{callbacks:?}");
    assert!(callbacks.iter().any(|line| line.contains(".onCreate")), "{callbacks:?}");
    assert!(callbacks.iter().all(|line| !line.contains("addEventWatcher")), "{callbacks:?}");
    // Every record of the code belongs to a package of the table.
    let table = starting(&all, "package-table")[0];
    assert!(table.ends_with(" unlocated=0 file=pkgContextInfo.json"), "{table}");
    let packages: usize = table.strip_prefix("package-table packages=").unwrap().split(' ').next().unwrap().parse().unwrap();
    assert_eq!(lines(&paired, Some(Document::PkgContext)).len(), packages);

    // The package alone: its code is encrypted, and the summary says so.
    let alone = manifest(&dir.join("entry.hap"));
    let unresolved = joins(&alone);
    assert_eq!(unresolved.len(), resolved.len());
    assert!(unresolved.iter().all(|(_, record)| record == "- (ets/modules.abc is encrypted)"), "{unresolved:?}");
}
