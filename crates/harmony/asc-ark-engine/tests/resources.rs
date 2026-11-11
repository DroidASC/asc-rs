//! `Engine::resources`, `Engine::package_files` and the resource names of
//! `Engine::manifest` / `Engine::annotate_resource_ids`, over synthetic
//! packages.

use std::fs;
use std::path::{Path, PathBuf};

use asc_ark_engine::{ChainEnd, ClassQuery, Engine, EngineError, Pattern, ResourceField, ResourceTables};
use asc_fixture::abc::make_abc;
use asc_fixture::hap::{
    Compression, Hap, LABELS_PAGE, ResourceTable, SAMPLE_MAIN_PAGES, SAMPLE_MODULE_JSON, make_app, make_hap, qualifier, resource_program,
    resource_type, sample_resources,
};

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, bytes).unwrap();
    path
}

/// Every row, as a front end prints them.
fn all(tables: &ResourceTables<'_>) -> Vec<String> {
    let mut rows = Vec::new();
    tables.for_each(|row| rows.push(row.line(tables.has_several_packages())));
    rows
}

const LABEL: &str = "0x01000000 string/EntryAbility_label [base] \"Sample\"";
const LABEL_ZH: &str = "0x01000000 string/EntryAbility_label [zh_CN] \"示例\"";
const BRAND: &str = "0x01000003 color/brand [base] \"#FF0000\"";

#[test]
fn a_hap_lists_looks_up_and_searches_its_index() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(write(dir.path(), "entry.hap", &make_hap(&make_abc()))).unwrap();
    let tables = engine.resources().unwrap();
    assert!(!tables.has_several_packages() && tables.notes().is_empty() && tables.len() == 8 && !tables.is_empty());
    // By id; of one resource the `base` value first, whatever the file order (zh_CN is the first set there).
    assert_eq!(
        all(&tables),
        [
            LABEL,
            LABEL_ZH,
            "0x01000001 profile/main_pages [base] entry/resources/base/profile/main_pages.json",
            "0x01000002 color/accent [base] \"$color:16777219\"",
            BRAND,
            "0x01000003 color/brand [dark] \"#00FF00\"",
            "0x01000004 media/icon [base] entry/resources/base/media/icon.png",
            "0x01000005 string/api_host [base] \"https://example.com\"",
        ]
    );
    let lookup = |query: &str| tables.lookup(query).map(|rows| rows.iter().map(|row| row.line(false)).collect::<Vec<_>>());
    for spelling in ["0x01000000", "16777216", "string/EntryAbility_label", "$string:EntryAbility_label", "app.string.EntryAbility_label"] {
        assert_eq!(lookup(spelling).unwrap(), [LABEL, LABEL_ZH], "{spelling}");
    }
    // A reference by id, as values inside the index spell it.
    assert_eq!(lookup("$color:16777219").unwrap()[0], BRAND);
    let row = &tables.lookup("string/api_host").unwrap()[0];
    assert_eq!(
        (row.package.as_str(), row.id, row.name.as_str(), row.qualifiers.as_str()),
        ("entry.hap", 0x0100_0005, "string/api_host", "base")
    );
    assert_eq!(row.json()["id"], "0x01000005");
    assert_eq!(lookup("string/nothing").unwrap_err().to_string(), "resource string/nothing not found");
    assert_eq!(lookup("0x7f010000").unwrap_err().to_string(), "resource 0x7f010000 not found");
    // An id of another type is not what a typed reference names.
    assert!(matches!(lookup("$string:16777219"), Err(EngineError::NotFound { .. })));
    assert!(matches!(lookup("label"), Err(EngineError::Query(_))));

    let search = |pattern: Pattern, field, limit| {
        let (rows, total) = tables.search(&pattern, field, limit);
        (rows.iter().map(|row| row.line(false)).collect::<Vec<_>>(), total)
    };
    // A resource matched by name lists every value; by value, the values that match.
    assert_eq!(search(Pattern::regex("^string/Entry").unwrap(), ResourceField::Name, 10), (vec![LABEL.to_owned(), LABEL_ZH.to_owned()], 2));
    assert_eq!(search(Pattern::regex("^示").unwrap(), ResourceField::Value, 10), (vec![LABEL_ZH.to_owned()], 1));
    assert_eq!(search(Pattern::regex("main_pages").unwrap(), ResourceField::Value, 10).1, 1, "a file path is a text of the value");
    assert_eq!(search(Pattern::regex("icon").unwrap(), ResourceField::Any, 10).1, 1, "matched by name and by value: one row");
    assert_eq!(search(Pattern::contains("#FF"), ResourceField::Any, 10).0, [BRAND]);
    assert_eq!(search(Pattern::regex("^https?://").unwrap(), ResourceField::Name, 10).1, 0);
    let (rows, total) = search(Pattern::regex(".").unwrap(), ResourceField::Name, 3);
    assert_eq!((rows.len(), total), (3, 8), "the limit cuts the rows, not the count");
}

#[test]
fn references_are_followed_to_the_last_value() {
    use resource_type::{COLOR, STRING};
    let index = ResourceTable::new()
        .value(0x0100_0000, COLOR, "a", &[], "$color:16777217")
        .value(0x0100_0001, COLOR, "b", &[qualifier::DARK], "#000000")
        .value(0x0100_0001, COLOR, "b", &[], "$color:c")
        .value(0x0100_0002, COLOR, "c", &[], "#FFFFFF")
        .value(0x0100_0003, COLOR, "loop_a", &[], "$color:loop_b")
        .value(0x0100_0004, COLOR, "loop_b", &[], "$color:16777219")
        .value(0x0100_0005, COLOR, "self", &[], "$color:self")
        .value(0x0100_0006, COLOR, "system", &[], "$ohos:color:id_color_primary")
        .value(0x0100_0007, COLOR, "dangling", &[], "$color:nothing")
        .value(0x0100_0008, STRING, "only_zh", &[qualifier::ZH], "中");
    let dir = tempfile::tempdir().unwrap();
    let hap = Hap::new().modules_abc(&make_abc()).module_json("{}").resource_index(&index).build();
    let engine = Engine::open(write(dir.path(), "entry.hap", &hap)).unwrap();
    let tables = engine.resources().unwrap();
    let resolve = |query: &str| {
        let mut resolved = tables.resolve(query).unwrap();
        assert_eq!(resolved.len(), 1, "{query}");
        let resolved = resolved.remove(0);
        (resolved.chain_line(false), resolved.row.line(false), resolved.end)
    };
    // By id and by name, through the `base` value at each step.
    let (chain, row, end) = resolve("color/a");
    assert_eq!(
        (chain.as_str(), row.as_str(), end),
        ("chain $color:a -> $color:b -> $color:c", "0x01000002 color/c [base] \"#FFFFFF\"", ChainEnd::Value)
    );
    assert_eq!(resolve("0x01000002").0, "chain $color:c");
    // A cycle ends at the last resource before it closes; so does a reference to itself.
    let (chain, row, end) = resolve("color/loop_a");
    assert_eq!(chain, "chain $color:loop_a -> $color:loop_b -> $color:loop_a (cycle)");
    assert_eq!(row, "0x01000004 color/loop_b [base] \"$color:16777219\"");
    assert_eq!(end, ChainEnd::Cycle("$color:loop_a".into()));
    assert_eq!(resolve("color/self").0, "chain $color:self -> $color:self (cycle)");
    // A system resource is no reference into the index; a dangling one says so.
    let (chain, row, end) = resolve("color/system");
    assert_eq!((chain.as_str(), end), ("chain $color:system", ChainEnd::Value));
    assert!(row.ends_with("\"$ohos:color:id_color_primary\""), "{row}");
    assert_eq!(resolve("color/dangling").0, "chain $color:dangling -> $color:nothing (not in the index)");
    // Without a `base` value the first one stands in.
    assert_eq!(resolve("string/only_zh").1, "0x01000008 string/only_zh [zh] \"中\"");
    assert!(matches!(tables.resolve("color/none"), Err(EngineError::NotFound { what: "resource", .. })));
    let resolved = &tables.resolve("color/a").unwrap()[0];
    assert_eq!(resolved.chain_line(true), "entry.hap | chain $color:a -> $color:b -> $color:c");
}

#[test]
fn packages_without_an_index_are_notes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("pkgs");
    let abc = make_abc();
    write(&root, "a.hap", &make_hap(&abc));
    write(&root, "b.hsp", &Hap::new().modules_abc(&abc).module_json(SAMPLE_MODULE_JSON).build());
    write(&root, "c.hsp", &Hap::new().modules_abc(&abc).entry("resources.index", b"Restool 9", Compression::Stored).build());
    write(
        &root,
        "d.hap",
        &Hap::new().modules_abc(&abc).entry("resources.index", &sample_resources().build(), Compression::Deflated).build(),
    );
    let engine = Engine::open(&root).unwrap();
    assert!(engine.notes().is_empty(), "nothing is said until resources are asked for: {:?}", engine.notes());
    let tables = engine.resources().unwrap();
    assert!(tables.has_several_packages());
    assert_eq!(tables.notes().len(), 2, "{:?}", tables.notes());
    assert_eq!(tables.notes()[0], "b.hsp: no resources.index");
    assert!(tables.notes()[1].starts_with("c.hsp: resources.index: "), "{:?}", tables.notes());
    // The stored index and the deflated one read alike; rows name their package.
    let rows = all(&tables);
    assert_eq!(rows.len(), 16);
    assert_eq!((rows[0].as_str(), rows[8].as_str()), (format!("a.hap | {LABEL}").as_str(), format!("d.hap | {LABEL}").as_str()));
    let both = tables.lookup("color/brand").unwrap();
    assert_eq!(both.iter().map(|row| row.package.as_str()).collect::<Vec<_>>(), ["a.hap", "a.hap", "d.hap", "d.hap"]);
    assert_eq!(tables.resolve("color/accent").unwrap().len(), 2);
    // A deflated index is held once it was read; a stored one stays in the mapping.
    assert!(engine.memory_use().inflated >= sample_resources().build().len());

    // No index that reads at all is the error, with what was looked at.
    let broken = Engine::open(root.join("c.hsp")).unwrap();
    let error = broken.resources().err().unwrap().to_string();
    assert!(error.starts_with("no resources.index in ") && error.contains("c.hsp (c.hsp: resources.index: "), "{error}");
    let bare = Engine::open(write(dir.path(), "bare.abc", &abc)).unwrap();
    assert!(
        bare.resources()
            .err()
            .unwrap()
            .to_string()
            .ends_with("(a bare .abc carries none: pass the .hap / .app it came from, or a directory holding both)")
    );
    assert!(matches!(bare.package_files("module.json"), Err(EngineError::NotFound { what: "file", .. })));
}

#[test]
fn an_app_reads_the_index_of_each_inner_package() {
    let dir = tempfile::tempdir().unwrap();
    let hap = make_hap(&make_abc());
    for inner in [Compression::Stored, Compression::Deflated] {
        let app = write(dir.path(), "shop.app", &make_app(&[("entry.hap", &hap), ("feature.hap", &hap)], inner));
        let engine = Engine::open(&app).unwrap();
        let tables = engine.resources().unwrap();
        assert!(tables.notes().is_empty(), "the bundle itself has no index to miss: {:?}", tables.notes());
        let rows = all(&tables);
        assert_eq!(rows.len(), 16);
        assert_eq!(rows[0], format!("entry.hap | {LABEL}"));
        assert_eq!(rows[8], format!("feature.hap | {LABEL}"));
        let files = engine.package_files("$profile:main_pages").unwrap();
        assert_eq!(files.iter().map(|file| file.package.as_str()).collect::<Vec<_>>(), ["entry.hap", "feature.hap"]);
        let one = engine.package_files("feature.hap/resources/base/profile/main_pages.json").unwrap();
        assert_eq!((one.len(), one[0].package.as_str(), one[0].text.as_str()), (1, "feature.hap", SAMPLE_MAIN_PAGES));
        // `pack.info` is at the root of the bundle and of neither package.
        assert_eq!(
            engine.package_files("pack.info").unwrap().iter().map(|file| file.package.as_str()).collect::<Vec<_>>(),
            ["shop.app", "entry.hap", "feature.hap"]
        );
    }
}

#[test]
fn file_resources_and_paths_read_text_files() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(write(dir.path(), "entry.hap", &make_hap(&make_abc()))).unwrap();
    assert!(!engine.has_several_packages());
    for target in ["$profile:main_pages", "app.profile.main_pages", "profile/main_pages", "resources/base/profile/main_pages.json"] {
        let files = engine.package_files(target).unwrap();
        assert_eq!(files.len(), 1, "{target}");
        let file = &files[0];
        assert_eq!(
            (file.package.as_str(), file.path.as_str(), file.text.as_str()),
            ("entry.hap", "resources/base/profile/main_pages.json", SAMPLE_MAIN_PAGES)
        );
    }
    assert!(engine.package_files("module.json").unwrap()[0].text.contains("\"bundleName\": \"com.example.sample\""));
    let error = |target: &str| engine.package_files(target).unwrap_err().to_string();
    assert_eq!(error("$media:icon"), "entry.hap: resources/base/media/icon.png is not text (8 bytes): only text files are printed");
    assert_eq!(error("$string:EntryAbility_label"), "entry.hap: $string:EntryAbility_label is \"Sample\", not a file");
    assert_eq!(error("$profile:nothing"), "resource $profile:nothing not found");
    assert_eq!(error("resources/base/profile/nothing.json"), "file resources/base/profile/nothing.json not found");
    // A resource that names a file the package does not have.
    let index = ResourceTable::new().value(0x0100_0000, resource_type::PROFILE, "gone", &[], "entry/resources/base/profile/gone.json");
    let hap = Hap::new().modules_abc(&make_abc()).resource_index(&index).build();
    let engine = Engine::open(write(dir.path(), "gone.hap", &hap)).unwrap();
    assert_eq!(
        engine.package_files("$profile:gone").unwrap_err().to_string(),
        "gone.hap: $profile:gone names resources/base/profile/gone.json, which the package does not have"
    );
}

#[test]
fn manifest_lines_say_what_references_stand_for() {
    let dir = tempfile::tempdir().unwrap();
    let lines = |path: &Path| -> Vec<String> {
        let manifest = Engine::open(path).unwrap().manifest().unwrap();
        manifest.summary_lines(None).into_iter().map(|line| line.text).collect()
    };
    let with = |lines: &[String], word: &str| lines.iter().find(|line| line.starts_with(word)).cloned().unwrap();
    let sample = lines(&write(dir.path(), "entry.hap", &make_hap(&make_abc())));
    assert!(with(&sample, "module ").ends_with(" pages=$profile:main_pages(resources/base/profile/main_pages.json)"), "{sample:?}");
    assert_eq!(with(&sample, "pack-ability "), "pack-ability entry EntryAbility label=$string:EntryAbility_label(\"Sample\")");
    assert!(!sample.iter().any(|line| line.starts_with("note ")), "{sample:?}");

    // What the index does not have, or has no `base` value for, stays as it is; so does everything without an index.
    let module = SAMPLE_MODULE_JSON.replace("$profile:main_pages", "$profile:other_pages");
    let index = ResourceTable::new().value(0x0100_0000, resource_type::STRING, "EntryAbility_label", &[qualifier::ZH], "示例");
    let partial = Hap::new().modules_abc(&make_abc()).module_json(&module).pack_info(asc_fixture::hap::SAMPLE_PACK_INFO);
    let found = lines(&write(dir.path(), "partial.hap", &partial.clone().resource_index(&index).build()));
    assert!(with(&found, "module ").ends_with(" pages=$profile:other_pages"), "{found:?}");
    assert_eq!(with(&found, "pack-ability "), "pack-ability entry EntryAbility label=$string:EntryAbility_label");
    assert_eq!(lines(&write(dir.path(), "none.hap", &partial.clone().build())), found);

    // An index that does not read is a note; the lines are those of a package without one.
    let broken = lines(&write(dir.path(), "broken.hap", &partial.entry("resources.index", b"", Compression::Stored).build()));
    let note = broken.last().unwrap();
    assert!(note.starts_with("note resources.index: version at 0x0 needs 128 bytes"), "{note}");
    assert_eq!(broken[..broken.len() - 1], found[..]);
    // A profile the build wrote without listing it in the index is found where the build puts it, index or not.
    let module = SAMPLE_MODULE_JSON.replace("$profile:main_pages", "$profile:generated-map");
    let generated = Hap::new().modules_abc(&make_abc()).module_json(&module).entry(
        "resources/base/profile/generated-map.json",
        b"{\"routerMap\":[]}",
        Compression::Deflated,
    );
    for hap in [generated.clone().build(), generated.resource_index(&sample_resources()).build()] {
        let path = write(dir.path(), "generated.hap", &hap);
        assert!(with(&lines(&path), "module ").ends_with(" pages=$profile:generated-map(resources/base/profile/generated-map.json)"));
        let files = Engine::open(&path).unwrap().package_files("$profile:generated-map").unwrap();
        assert_eq!((files[0].path.as_str(), files[0].text.as_str()), ("resources/base/profile/generated-map.json", "{\"routerMap\":[]}"));
    }
    // A long text is cut.
    let long = "长".repeat(100);
    let index = ResourceTable::new().value(0x0100_0000, resource_type::STRING, "EntryAbility_label", &[], &long);
    let hap = Hap::new().modules_abc(&make_abc()).pack_info(asc_fixture::hap::SAMPLE_PACK_INFO).resource_index(&index).build();
    let cut = with(&lines(&write(dir.path(), "long.hap", &hap)), "pack-ability ");
    assert!(cut.ends_with(&format!("label=$string:EntryAbility_label(\"{}\"… (+102 bytes))", "长".repeat(66))), "{cut}");
}

#[test]
fn listings_name_the_resources_they_build() {
    let dir = tempfile::tempdir().unwrap();
    let abc = resource_program().build().bytes;
    let engine = Engine::open(write(dir.path(), "entry.hap", &make_hap(&abc))).unwrap();
    let named = |function: Option<&str>| {
        let mut source = engine.get_class(&ClassQuery { record: LABELS_PAGE, function, entry: None }).unwrap();
        let plain = source.text.clone();
        engine.annotate_resource_ids(&mut source);
        assert_eq!(source.text.lines().count(), plain.lines().count());
        let added: Vec<String> =
            source.text.lines().zip(plain.lines()).filter(|(a, b)| a != b).map(|(a, b)| a[b.len()..].to_owned()).collect();
        (added, source.text.lines().filter(|line| line.contains("createobjectwithbuffer")).count())
    };
    // The string and the color; not the id with another type, the rawfile, or the plain object.
    let expected = ["  # string/EntryAbility_label \"Sample\"", "  # color/brand \"#FF0000\""];
    assert_eq!(named(None), (expected.map(String::from).to_vec(), 5));
    assert_eq!(named(Some("labels")), (expected.map(String::from).to_vec(), 5));

    // Without an index that reads the listing stays as it is; a bare file takes the index of the one package next to it.
    let unnamed = |path: PathBuf| {
        let engine = Engine::open(path).unwrap();
        let mut source = engine.get_class(&ClassQuery { record: LABELS_PAGE, function: None, entry: None }).unwrap();
        let plain = source.text.clone();
        engine.annotate_resource_ids(&mut source);
        source.text == plain
    };
    assert!(unnamed(write(dir.path(), "bare.abc", &abc)));
    assert!(unnamed(write(dir.path(), "none.hap", &Hap::new().modules_abc(&abc).build())));
    let root = dir.path().join("pair");
    write(&root, "entry.hap", &make_hap(&make_abc()));
    write(&root, "extra.abc", &abc);
    assert!(!unnamed(root));
}
