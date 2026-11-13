//! The shapes a program comes in beyond a package file: a package unpacked
//! into a directory, packages inside zips inside zips, and the source maps
//! of a debug build. Each answers as the package file itself does.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime};

use asc_ark_engine::{ClassQuery, Engine, EngineError, EntryStatus, Format, Query, Stamp};
use asc_fixture::abc::{INDEX_PAGE, make_abc, sample_program};
use asc_fixture::hap::{
    Compression, Hap, SAMPLE_MAIN_PAGES, SAMPLE_MODULE_JSON, make_app, make_debug_hap, make_hap, make_library_hsp, unpack,
};

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    path
}

fn entries(engine: &Engine) -> Vec<&str> {
    engine.entries().map(|entry| entry.name.as_str()).collect()
}

fn manifest_lines(engine: &Engine) -> Vec<String> {
    let manifest = engine.manifest().unwrap();
    let several = manifest.has_several_packages();
    manifest.summary_lines(None).iter().map(|line| line.line(several)).collect()
}

fn resource_lines(engine: &Engine) -> Vec<String> {
    let tables = engine.resources().unwrap();
    let mut lines = Vec::new();
    tables.for_each(|row| lines.push(row.line(tables.has_several_packages())));
    lines
}

fn string_rows(engine: &Engine, pattern: &str) -> Vec<String> {
    let mut rows = Vec::new();
    let query = Query::string_regex(pattern).unwrap();
    engine
        .find_refs(&query, &AtomicBool::new(false), &mut |batch| rows.extend(batch.rows.iter().map(|row| row.line(&batch.entry_name))))
        .unwrap();
    rows
}

fn listing(engine: &Engine, record: &str, function: Option<&str>) -> String {
    engine.get_class(&ClassQuery::new(record).function(function).entry(None)).unwrap().text
}

/// Everything a front end prints of a program, the files `xml` reads included.
fn answers(engine: &Engine) -> Vec<Vec<String>> {
    let files = |target: &str| engine.package_files(target).unwrap().into_iter().map(|file| file.text).collect::<Vec<_>>();
    vec![
        manifest_lines(engine),
        resource_lines(engine),
        string_rows(engine, "."),
        vec![listing(engine, "pages/Index", None), listing(engine, "pages/Index", Some("Index.build"))],
        files("$profile:main_pages"),
        files("resources/base/profile/main_pages.json"),
        files("ets/sourceMaps.map"),
    ]
}

#[test]
fn an_unpacked_package_answers_as_the_package_does() {
    let dir = tempfile::tempdir().unwrap();
    let hap = make_debug_hap(&make_abc());
    let packed = write(dir.path(), "packed/entry.hap", &hap);
    let unpacked = dir.path().join("entry");
    unpack(&hap, &unpacked);

    assert_eq!(Format::detect(&unpacked), None, "a directory has no format of its own");
    assert!(Format::accepts(&unpacked));
    let (of_file, of_directory) = (Engine::open(&packed).unwrap(), Engine::open(&unpacked).unwrap());
    assert_eq!(entries(&of_directory), ["ets/modules.abc"]);
    assert!(of_directory.notes().is_empty(), "{:?}", of_directory.notes());
    // The package is named after the directory as it is after the file; nothing else differs.
    let renamed = |answers: Vec<Vec<String>>| -> Vec<Vec<String>> {
        answers.into_iter().map(|lines| lines.into_iter().map(|line| line.replace("entry.hap", "entry")).collect()).collect()
    };
    assert_eq!(answers(&of_directory), renamed(answers(&of_file)));
    assert!(manifest_lines(&of_directory).iter().any(|line| line.starts_with("ability EntryAbility ") && line.contains(" record=&entry/")));
    assert_eq!(of_directory.package_files("$profile:main_pages").unwrap()[0].text, SAMPLE_MAIN_PAGES);
    assert_eq!(of_directory.manifest().unwrap().packages[0].name, "entry");

    // A directory that only looks like one in part is no package.
    let partial = dir.path().join("partial");
    fs::create_dir_all(partial.join("ets")).unwrap();
    fs::write(partial.join("module.json"), SAMPLE_MODULE_JSON).unwrap();
    assert!(!Format::accepts(&partial) && matches!(Engine::open(&partial), Err(EngineError::NoCode { .. })));
    // Without `module.json` the code is a bare file, as before.
    fs::remove_file(unpacked.join("module.json")).unwrap();
    let bare = Engine::open(&unpacked).unwrap();
    assert_eq!(entries(&bare), ["modules.abc"]);
    assert!(matches!(bare.manifest(), Err(EngineError::NoManifest { bare: true, .. })));
}

// Symbolic links need privileges on Windows.
#[cfg(unix)]
#[test]
fn files_of_an_unpacked_package_stay_inside_it() {
    let dir = tempfile::tempdir().unwrap();
    let unpacked = dir.path().join("entry");
    unpack(&make_hap(&make_abc()), &unpacked);
    write(dir.path(), "secret.txt", b"outside");
    std::os::unix::fs::symlink(dir.path().join("secret.txt"), unpacked.join("resources/base/profile/link.json")).unwrap();
    std::os::unix::fs::symlink("main_pages.json", unpacked.join("resources/base/profile/alias.json")).unwrap();
    let engine = Engine::open(&unpacked).unwrap();
    for outside in ["../secret.txt", "resources/../../secret.txt", "/etc/hostname", "resources/base/profile/link.json", "", "resources"] {
        assert!(matches!(engine.package_files(outside), Err(EngineError::NotFound { .. })), "{outside}");
    }
    // A link that stays inside reads; a file that is not text is refused as in a zip.
    assert_eq!(engine.package_files("resources/base/profile/alias.json").unwrap()[0].text, SAMPLE_MAIN_PAGES);
    assert!(matches!(engine.package_files("resources/base/media/icon.png"), Err(EngineError::Query(_))));
}

#[test]
fn unpacked_packages_in_one_directory_are_one_each() {
    let dir = tempfile::tempdir().unwrap();
    let sample = make_abc();
    let app = dir.path().join("app");
    unpack(&make_hap(&sample), &app.join("entry"));
    unpack(&make_library_hsp(), &app.join("library"));
    // What a package holds below its root is its own: no program reads it as a package.
    write(&app, "entry/resources/rawfile/inner.hap", &make_hap(&sample));
    write(&app, "entry/resources/rawfile/dump.abc", &sample);
    let engine = Engine::open(&app).unwrap();
    assert_eq!(entries(&engine), ["entry/ets/modules.abc", "library/ets/modules.abc"]);
    let manifest = engine.manifest().unwrap();
    assert_eq!(manifest.packages.iter().map(|package| package.name.as_str()).collect::<Vec<_>>(), ["entry", "library"]);
    assert!(resource_lines(&engine).iter().all(|line| line.starts_with("entry | ")), "only one of them has an index");
    assert_eq!(engine.package_files("entry/resources/base/profile/main_pages.json").unwrap()[0].package, "entry");
    assert_eq!(engine.entries_in(Some("library")).unwrap().len(), 1);

    // Listed with another file, the directory given is named like one.
    let other = write(dir.path(), "other.hap", &make_hap(&sample));
    let spec = format!("{},{}", app.join("entry").display(), other.display());
    assert_eq!(entries(&Engine::open(&spec).unwrap()), ["entry/ets/modules.abc", "other.hap/ets/modules.abc"]);
}

#[test]
fn an_unpacked_app_store_package_pairs_with_its_decrypted_code() {
    let dir = tempfile::tempdir().unwrap();
    let sample = make_abc();
    let store = Hap::new().modules_abc(&sample_program().encrypted().build().bytes).module_json(SAMPLE_MODULE_JSON).build();
    let unpacked = dir.path().join("store");
    unpack(&store, &unpacked);
    let alone = Engine::open(&unpacked).unwrap();
    assert_eq!(alone.entries().map(|entry| entry.status.clone()).collect::<Vec<_>>(), [EntryStatus::Encrypted]);

    // Next to `module.json`, or next to the directory: the decrypted file stands in.
    for decrypted in ["store/dump.abc", "dump.abc"] {
        let file = write(dir.path(), decrypted, &sample);
        let engine = Engine::open(dir.path()).unwrap();
        assert_eq!(entries(&engine), ["store/ets/modules.abc"], "{decrypted}");
        assert_eq!(engine.entries().next().unwrap().status, EntryStatus::Readable);
        assert_eq!(engine.stand_ins().len(), 1);
        assert!(manifest_lines(&engine).iter().any(|line| line.starts_with("ability EntryAbility ") && line.contains(" record=&entry/")));
        fs::remove_file(file).unwrap();
    }
}

#[test]
fn the_stamp_of_an_unpacked_package_follows_its_files() {
    let dir = tempfile::tempdir().unwrap();
    let unpacked = dir.path().join("entry");
    unpack(&make_debug_hap(&make_abc()), &unpacked);
    let touch = |name: &str| {
        let file = fs::File::options().write(true).open(unpacked.join(name)).unwrap();
        file.set_modified(SystemTime::now() + Duration::from_secs(5)).unwrap();
    };
    for name in ["module.json", "pack.info", "resources.index", "ets/modules.abc", "ets/sourceMaps.map"] {
        let engine = Engine::open(&unpacked).unwrap();
        assert!(engine.is_current());
        touch(name);
        assert!(!engine.is_current(), "{name}");
        assert_eq!(Stamp::of(&unpacked).unwrap(), *Engine::open(&unpacked).unwrap().stamp());
    }
    // A file that appears or goes away changes it too; one `xml` prints does not.
    let engine = Engine::open(&unpacked).unwrap();
    touch("resources/base/profile/main_pages.json");
    assert!(engine.is_current());
    fs::write(unpacked.join("ets/widgets.abc"), make_abc()).unwrap();
    assert!(!engine.is_current());
    let engine = Engine::open(&unpacked).unwrap();
    assert_eq!(entries(&engine), ["ets/modules.abc", "ets/widgets.abc"]);
    fs::remove_file(unpacked.join("pack.info")).unwrap();
    assert!(!engine.is_current());
}

#[test]
fn packages_are_found_through_zips_by_what_they_hold() {
    let dir = tempfile::tempdir().unwrap();
    let hap = make_hap(&make_abc());
    for inner in [Compression::Stored, Compression::Deflated] {
        let app = make_app(&[("entry.hap", &hap), ("feature.hap", &hap)], inner);
        // An `.app` in a zip, next to things that are no package: text, and a zip of text.
        let notes_zip = Hap::new().entry("readme.txt", b"hello", Compression::Deflated).build();
        let outer = Hap::new()
            .entry("readme.txt", b"PK is not all it takes", Compression::Stored)
            .entry("notes.zip", &notes_zip, inner)
            .entry("build/shop.app", &app, inner)
            .build();
        let path = write(dir.path(), "bundle.zip", &outer);
        assert_eq!(Format::detect(&path), Some(Format::App));
        let engine = Engine::open(&path).unwrap();
        assert_eq!(
            entries(&engine),
            ["build/shop.app/entry.hap/ets/modules.abc", "build/shop.app/feature.hap/ets/modules.abc"],
            "{inner:?}"
        );
        assert!(engine.notes().is_empty(), "{:?}", engine.notes());
        // The packages answer as those of the `.app` itself do, under their longer names.
        let direct = Engine::open(write(dir.path(), "shop.app", &app)).unwrap();
        // Alone, the `.app` does not prefix the names of its packages with its own.
        let prefixed = |lines: Vec<String>| -> Vec<String> {
            let longer =
                |line: String| ["entry.hap", "feature.hap"].iter().fold(line, |line, hap| line.replace(hap, &format!("shop.app/{hap}")));
            lines.into_iter().map(|line| longer(line).replace("shop.app", "build/shop.app")).collect()
        };
        assert_eq!(manifest_lines(&engine), prefixed(manifest_lines(&direct)));
        assert_eq!(resource_lines(&engine), prefixed(resource_lines(&direct)));
        assert_eq!(string_rows(&engine, "testTag"), prefixed(string_rows(&direct, "testTag")));
        assert_eq!(engine.entries_in(Some("build/shop.app/feature.hap")).unwrap().len(), 1);
        assert_eq!(engine.package_files("build/shop.app/entry.hap/module.json").unwrap().len(), 1);
    }

    // A package under any name, in a zip of few entries; and haps alone in a zip.
    let renamed = write(dir.path(), "renamed.zip", &Hap::new().entry("payload.bin", &hap, Compression::Deflated).build());
    assert_eq!(entries(&Engine::open(&renamed).unwrap()), ["payload.bin/ets/modules.abc"]);
    let plain = Hap::new().entry("a/entry.hap", &hap, Compression::Stored).entry("b/lib.hsp", &make_library_hsp(), Compression::Stored);
    let plain = write(dir.path(), "haps.zip", &plain.build());
    assert_eq!(entries(&Engine::open(&plain).unwrap()), ["a/entry.hap/ets/modules.abc", "b/lib.hsp/ets/modules.abc"]);
    // In a directory it is found like any package.
    let found = Engine::open(dir.path()).unwrap();
    assert!(entries(&found).contains(&"haps.zip/b/lib.hsp/ets/modules.abc"), "{:?}", entries(&found));
}

#[test]
fn zips_that_hold_no_package_are_not_harmony_programs() {
    let dir = tempfile::tempdir().unwrap();
    let hap = make_hap(&make_abc());
    let text_zip = Hap::new().entry("readme.txt", b"hello", Compression::Stored).build();
    let cases: [(&str, Hap); 4] = [
        ("texts.zip", Hap::new().entry("a.zip", &text_zip, Compression::Stored).entry("b.txt", b"x", Compression::Stored)),
        // An Android archive keeps to the DEX side whatever lies in it.
        (
            "android.zip",
            Hap::new().entry("classes.dex", b"dex\n035\0", Compression::Stored).entry("assets/x.zip", &hap, Compression::Stored),
        ),
        ("manifest.zip", Hap::new().entry("AndroidManifest.xml", b"\x03\0", Compression::Stored).entry("x.zip", &hap, Compression::Stored)),
        ("empty.zip", Hap::new()),
    ];
    for (name, zip) in cases {
        let path = write(dir.path(), name, &zip.build());
        assert_eq!(Format::detect(&path), None, "{name}");
        assert!(!Format::accepts(&path), "{name}");
    }
    assert!(matches!(Engine::open(dir.path()), Err(EngineError::NoCode { .. })));

    // Past the depth a program opens, a package is not looked for.
    let mut nested = hap.clone();
    for level in 0..5 {
        nested = Hap::new().entry(&format!("level{level}.zip"), &nested, Compression::Stored).build();
    }
    let deep = write(dir.path(), "deep.zip", &nested);
    assert_eq!(Format::detect(&deep), None);
    let lone = Engine::open(&deep);
    assert!(
        matches!(&lone, Err(EngineError::NoCode { notes, .. }) if notes.iter().any(|note| note.contains("zips more than 4 deep"))),
        "{:?}",
        lone.err()
    );
    // One level less, and it is.
    let mut nested = hap;
    for level in 0..4 {
        nested = Hap::new().entry(&format!("level{level}.zip"), &nested, Compression::Deflated).build();
    }
    let reachable = write(dir.path(), "reachable.zip", &nested);
    assert_eq!(Format::detect(&reachable), Some(Format::App));
    assert_eq!(entries(&Engine::open(&reachable).unwrap()), ["level3.zip/level2.zip/level1.zip/level0.zip/ets/modules.abc"]);
}

#[test]
fn source_maps_name_the_source_of_a_listing() {
    let dir = tempfile::tempdir().unwrap();
    let sample = make_abc();
    let mapped = Engine::open(write(dir.path(), "debug/entry.hap", &make_debug_hap(&sample))).unwrap();
    let plain = Engine::open(write(dir.path(), "release/entry.hap", &make_hap(&sample))).unwrap();

    let summary = manifest_lines(&mapped);
    let at = summary.iter().position(|line| line == "source-maps ets/sourceMaps.map modules=2").expect("the summary names the file");
    assert!(summary[at - 1].starts_with("abc ets/modules.abc "), "{summary:?}");
    assert_eq!(mapped.manifest().unwrap().json()["packages"][0]["source_maps"]["modules"], 2);
    assert!(manifest_lines(&plain).iter().all(|line| !line.starts_with("source-maps")));
    assert!(plain.manifest().unwrap().json()["packages"][0].get("source_maps").is_none());

    // The record names its source; a function says which line of it, or that it has none.
    let record = listing(&mapped, "pages/Index", None);
    let header: Vec<&str> = record.lines().take(3).collect();
    assert_eq!(header[0], format!(".record {INDEX_PAGE}"));
    assert!(header[2].starts_with("; source entry/src/main/ets/pages/Index.ets (by the source map: "), "{header:?}");
    assert!(record.contains(", line 12 (source line 4)\n"), "{record}");
    let function = listing(&mapped, "pages/Index", Some("Index.build"));
    assert!(function.lines().nth(1).unwrap().ends_with(", line 12 (source line 4)") && record.contains(function.trim_end()), "{function}");
    let appended = listing(&mapped, "entryability/EntryAbility", Some("EntryAbility.onCreate"));
    assert!(appended.lines().nth(1).unwrap().ends_with(", line 6 (no source line)"), "{appended}");
    // Without the file a listing is what it was, and with it nothing else changes.
    let unmapped = listing(&plain, "pages/Index", None);
    assert!(unmapped.contains(", line 12\n") && !unmapped.contains("source line"));
    let stripped: String = record.lines().filter(|line| !line.starts_with("; source ")).map(|line| format!("{line}\n")).collect();
    assert_eq!(stripped.replace(" (source line 4)", "").replace(" (no source line)", ""), unmapped);

    // A file that does not read costs a note, not the program.
    let broken = Hap::new().modules_abc(&sample).module_json(SAMPLE_MODULE_JSON).source_maps("{\"a\": ");
    let broken = Engine::open(write(dir.path(), "broken/entry.hap", &broken.build())).unwrap();
    assert!(manifest_lines(&broken).iter().any(|line| line.starts_with("note ets/sourceMaps.map: ")), "{:?}", manifest_lines(&broken));
    assert_eq!(listing(&broken, "pages/Index", None), unmapped);
}

#[test]
fn every_line_of_a_listing_is_written_when_asked() {
    use asc_ark_engine::ListingStyle;
    let dir = tempfile::tempdir().unwrap();
    let sample = make_abc();
    let lines = ListingStyle::default().lines(true);
    let get = |engine: &Engine, function| {
        engine.get_class_as(&ClassQuery::new("pages/Index").function(function).entry(None), lines).unwrap().text
    };

    // Without source maps: the lines of the debug info, where they change, and none in the header.
    let plain = Engine::open(write(dir.path(), "release/entry.hap", &make_hap(&sample))).unwrap();
    let function = get(&plain, Some("Index.build"));
    assert!(!function.lines().nth(1).unwrap().contains(", line "), "{function}");
    assert!(function.contains("\n  ; line 12\n") && !function.contains("source line"), "{function}");
    // Nothing else of the listing changes.
    let without: String = function.lines().filter(|line| !line.starts_with("  ; line ")).map(|line| format!("{line}\n")).collect();
    assert_eq!(without, listing(&plain, "pages/Index", Some("Index.build")).replace(", line 12\n", "\n"));
    assert!(get(&plain, None).contains(function.trim_end()));

    // With them each line says where it comes from, and the index of the file is counted.
    let mapped = Engine::open(write(dir.path(), "debug/entry.hap", &make_debug_hap(&sample))).unwrap();
    assert_eq!(mapped.memory_use().source_maps, 0, "nothing asked for the file yet");
    assert!(get(&mapped, Some("Index.build")).contains("\n  ; line 12 (source line 4)\n"));
    let held = mapped.memory_use();
    assert!(held.source_maps > 0 && held.heap() >= held.source_maps, "{held:?}");
    // It is not an analysis: it stays for as long as the program is open.
    mapped.release_analyses();
    assert_eq!(mapped.memory_use().source_maps, held.source_maps);
    assert_eq!(plain.memory_use().source_maps, 0);
}

/// A module made from several source files: the header numbers the ones
/// lines come from, and every source line says which it is a line of.
#[test]
fn a_listing_names_each_of_several_sources() {
    let dir = tempfile::tempdir().unwrap();
    // Line 12 of the compiled file is line 4 of the third source, line 13 line 4 of the first.
    let maps = format!(
        r#"{{"entry|entry|1.0.0|src/main/ets/pages/Index.ts": {{"version": 3, "sources": ["entry/src/main/ets/pages/Index.ets", "entry/src/main/ets/unused.ets", "entry/src/main/ets/pages/Part.ets"], "names": [], "mappings": "{}AEGA;AFAA"}}}}"#,
        ";".repeat(12)
    );
    let hap = Hap::new().modules_abc(&make_abc()).module_json(SAMPLE_MODULE_JSON).source_maps(&maps).build();
    let engine = Engine::open(write(dir.path(), "entry.hap", &hap)).unwrap();
    let record = listing(&engine, "pages/Index", None);
    let header = record.lines().nth(2).unwrap();
    let named = "; sources #0 entry/src/main/ets/pages/Index.ets, #2 entry/src/main/ets/pages/Part.ets (by the source map: ";
    assert!(header.starts_with(named) && header.ends_with("\"source #K line N\" is line N of source #K)"), "{header}");
    assert!(record.contains(", line 12 (source #2 line 4)\n"), "{record}");
    let style = asc_ark_engine::ListingStyle::default().lines(true);
    let woven = engine.get_class_as(&ClassQuery::new("pages/Index").function(Some("Index.build")).entry(None), style).unwrap().text;
    assert!(woven.contains("\n  ; line 12 (source #2 line 4)\n"), "{woven}");
}

#[test]
fn code_of_a_package_is_in_name_order_however_it_is_packed() {
    let dir = tempfile::tempdir().unwrap();
    let sample = make_abc();
    // The zip lists `widgets` ahead of `modules`; a directory lists by name.
    let hap = Hap::new().abc("widgets", &sample).module_json(SAMPLE_MODULE_JSON).modules_abc(&sample).build();
    let packed = Engine::open(write(dir.path(), "packed/entry.hap", &hap)).unwrap();
    let unpacked = dir.path().join("entry");
    unpack(&hap, &unpacked);
    let unpacked = Engine::open(&unpacked).unwrap();
    assert_eq!(entries(&packed), ["ets/modules.abc", "ets/widgets.abc"]);
    assert_eq!(entries(&unpacked), entries(&packed));
    assert_eq!(string_rows(&unpacked, "."), string_rows(&packed, "."));
    // An `.app` keeps its packages in the order it lists them, each with its code by name.
    let app = make_app(&[("b.hap", &hap), ("a.hap", &hap)], Compression::Stored);
    let app = Engine::open(write(dir.path(), "shop.app", &app)).unwrap();
    assert_eq!(entries(&app), ["b.hap/ets/modules.abc", "b.hap/ets/widgets.abc", "a.hap/ets/modules.abc", "a.hap/ets/widgets.abc"]);
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

#[test]
fn locate_agrees_with_get_class() {
    let dir = tempfile::tempdir().unwrap();
    let hap = write(dir.path(), "entry.hap", &make_hap(&make_abc()));
    let engine = Engine::open(&hap).unwrap();
    for (record, function) in [("pages/Index", None), ("pages/Index", Some("build")), (INDEX_PAGE, Some("#~@0>#aboutToAppear"))] {
        let query = ClassQuery::new(record).function(function);
        let located = engine.locate(&query).unwrap();
        let listed = engine.get_class(&query).unwrap();
        assert_eq!((&located.entry, &located.record, &located.function), (&listed.entry, &listed.record, &listed.function));
    }
    assert!(matches!(engine.locate(&ClassQuery::new("pages/Nothing")), Err(EngineError::NotFound { .. })));
    let missing = engine.locate(&ClassQuery::new("pages/Index").function(Some("nothing")));
    assert!(matches!(missing, Err(EngineError::NotFound { what: "function", .. })), "{missing:?}");
}

#[test]
fn entry_sha256_is_of_the_read_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let sample = make_abc();
    // A zip entry: no file of its own.
    let hap = write(dir.path(), "entry.hap", &make_hap(&sample));
    let engine = Engine::open(&hap).unwrap();
    assert_eq!(engine.entry_sha256("ets/modules.abc"), Some(sha256(&sample)));
    assert_eq!(engine.entry_file("ets/modules.abc"), None);
    assert_eq!((engine.entry_sha256("ets/other.abc"), engine.entry_file("ets/other.abc")), (None, None));

    // A bare file is its own file.
    let bare = write(dir.path(), "bare/modules.abc", &sample);
    let engine = Engine::open(&bare).unwrap();
    let name = engine.entries().next().unwrap().name.clone();
    assert_eq!((engine.entry_sha256(&name), engine.entry_file(&name)), (Some(sha256(&sample)), Some(bare.as_path())));

    // An encrypted entry served by a decrypted file: that file and its bytes.
    let store = dir.path().join("store");
    let encrypted = sample_program().encrypted().build().bytes;
    write(&store, "entry.hap", &Hap::new().modules_abc(&encrypted).module_json(SAMPLE_MODULE_JSON).build());
    let decrypted = write(&store, "modules.abc", &sample);
    let engine = Engine::open(&store).unwrap();
    assert_eq!(engine.stand_ins().len(), 1);
    assert_eq!(engine.entry_sha256("entry.hap/ets/modules.abc"), Some(sha256(&sample)));
    assert_ne!(sha256(&encrypted), sha256(&sample));
    let file = engine.entry_file("entry.hap/ets/modules.abc").unwrap();
    assert_eq!(fs::canonicalize(file).unwrap(), fs::canonicalize(&decrypted).unwrap());

    // An unpacked package: its code file.
    let unpacked = dir.path().join("unpacked");
    unpack(&make_hap(&sample), &unpacked);
    let engine = Engine::open(&unpacked).unwrap();
    let name = engine.entries().next().unwrap().name.clone();
    let file = engine.entry_file(&name).unwrap();
    assert_eq!(fs::canonicalize(file).unwrap(), fs::canonicalize(unpacked.join("ets/modules.abc")).unwrap());
    assert_eq!(engine.entry_sha256(&name), Some(sha256(&sample)));
}
