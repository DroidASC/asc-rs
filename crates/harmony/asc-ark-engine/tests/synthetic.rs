//! The engine over hand-built ABC files packed the ways real programs are:
//! lone packages, application packages with stored and Deflate inner
//! packages, bare files, directories, encrypted entries.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use asc_ark_engine::{ClassQuery, Engine, EngineError, EntryStatus, Format, ListOptions, NameFilter, Query, RefRow, RefSite};
use asc_fixture::abc::{
    ACC_STATIC, AbcAnnotation, AbcBuilder, AbcCode, AbcField, AbcFieldValue, AbcFile, AbcFunction, AbcModule, AbcRecord, AbcType, Asm, Op,
    seal,
};
use asc_fixture::make_apk;

const RECORD_A: &str = "&entry/src/main/ets/pages/Index&";
const RECORD_B: &str = "com.example.app/entry/ets/model/Util";

/// A two-region file, version 12.0.6.0, with a correct checksum. Region 0
/// holds record A, whose `func_main_0` loads `hello` and `#~@0>#build`
/// loads `world`; region 1 holds record B, whose three functions load
/// `world` under another 16-bit id. The second and third function of B
/// store a wrong region number (7, out of range, and 0, the other region).
fn synthetic_builder() -> AbcBuilder {
    let load = |text: &str| {
        let mut code = Asm::new();
        code.op("lda.str", [Op::str(text)]).op("return", []);
        AbcCode::new(1, 3, code)
    };
    // What the compiler adds to a record: its own annotation, also on a typed field.
    let annotation = || AbcAnnotation::new("_ESTypeAnnotation").element("SlotNumber", 5);
    let mut big = AbcField::new("big", AbcType::I64, AbcFieldValue::Wide(0x1122_3344_5566_7788)).annotation(annotation());
    big.access_flags = ACC_STATIC;
    let module = AbcModule::new().import("hilog", "default", "@ohos:hilog").export("Index", "default");
    let record_a = AbcRecord::new(RECORD_A)
        .field(AbcField::module_record(module))
        .field(AbcField::scope_names(["Index"]))
        .field(AbcField::new("isCommonjs", AbcType::U1, AbcFieldValue::Int(0)))
        .field(AbcField::new("pkgName@entry", AbcType::U1, AbcFieldValue::Int(0)))
        .field(big)
        .function(AbcFunction::new("func_main_0", load("hello")).annotation(annotation()))
        .function(AbcFunction::new("#~@0>#build", load("world")));
    let mut record_b = AbcRecord::new(RECORD_B);
    for (name, hint) in [("#*#helper", None), ("#*#helper^1", Some(7)), ("#*#", Some(0))] {
        let mut function = AbcFunction::new(name, load("world"));
        function.region_hint = hint;
        record_b = record_b.function(function);
    }
    let mut builder = AbcBuilder::new();
    builder.foreign_class("_ESTypeAnnotation").record(record_a).record(record_b).split_region_before(RECORD_B);
    builder
}

fn synthetic() -> AbcFile {
    synthetic_builder().build()
}

/// The synthetic file with string `from` replaced by the equally long `to`
/// and the checksum fixed: a second, different, valid ABC file.
fn variant(from: &str, to: &str) -> Vec<u8> {
    assert_eq!(from.len(), to.len());
    let mut data = synthetic().bytes;
    let at = data.windows(from.len()).position(|window| window == from.as_bytes()).expect("string is in the file");
    data[at..at + to.len()].copy_from_slice(to.as_bytes());
    seal(&mut data);
    data
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, bytes).unwrap();
    path
}

fn entry_names(engine: &Engine) -> Vec<&str> {
    engine.entries().map(|info| info.name.as_str()).collect()
}

fn record_names(engine: &Engine, all: bool) -> Vec<String> {
    let options = ListOptions::default().all(all);
    engine.list_classes(&options).unwrap().into_iter().map(|record| format!("{} | {}", record.entry, record.name)).collect()
}

fn find(engine: &Engine, query: &Query) -> Vec<String> {
    let mut lines = Vec::new();
    let summary = engine
        .find_refs(query, &AtomicBool::new(false), &mut |batch| {
            assert_eq!(batch.error, None);
            lines.extend(batch.rows.iter().map(|row| row.line(&batch.entry_name)));
        })
        .unwrap();
    assert_eq!(summary.total_results, lines.len());
    lines
}

#[test]
fn lone_package_with_two_abc_files() {
    let dir = tempfile::tempdir().unwrap();
    let abc = synthetic().bytes;
    let widgets = variant("hello", "jello");
    for deflate in [false, true] {
        let hap = make_apk(
            &[("module.json", b"{}"), ("ets/modules.abc", &abc), ("ets/widgets.abc", &widgets), ("ets/sourceMaps.map", b"{}")],
            deflate,
        );
        let path = write(dir.path(), "entry.hap", &hap);
        assert_eq!(Format::detect(&path), Some(Format::Hap));
        assert!(Format::accepts(&path));
        let engine = Engine::open(&path).unwrap();
        assert_eq!(entry_names(&engine), ["ets/modules.abc", "ets/widgets.abc"]);
        assert!(engine.notes().is_empty() && engine.has_several_entries());
        assert!(
            engine.entries().all(|info| info.status == EntryStatus::Readable && info.version.is_some_and(|v| v.to_string() == "12.0.6.0"))
        );
        assert_eq!(engine.entries().map(|info| info.size).collect::<Vec<_>>(), [abc.len() as u64; 2]);
        assert_eq!(
            record_names(&engine, false),
            [
                format!("ets/modules.abc | {RECORD_A}"),
                format!("ets/modules.abc | {RECORD_B}"),
                format!("ets/widgets.abc | {RECORD_A}"),
                format!("ets/widgets.abc | {RECORD_B}")
            ]
        );
        assert_eq!(
            find(&engine, &Query::string_literal("jello")),
            [format!("ets/widgets.abc | {RECORD_A}->func_main_0+0x0 | func_main_0 | lda.str \"jello\"")]
        );
        assert!(engine.abc("ets/widgets.abc").is_some() && engine.abc("ets/none.abc").is_none());
    }
}

#[test]
fn listing_filters_and_pseudo_records() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "modules.abc", &synthetic().bytes);
    assert_eq!(Format::detect(&path), Some(Format::Abc));
    let engine = Engine::open(&path).unwrap();
    assert_eq!(entry_names(&engine), ["modules.abc"]);
    assert!(!engine.has_several_entries());

    let all = engine.list_classes(&ListOptions::default().all(true)).unwrap();
    assert_eq!(all.iter().map(|record| record.name.as_str()).collect::<Vec<_>>(), [RECORD_A, "_ESTypeAnnotation", RECORD_B]);
    assert_eq!(all.iter().map(|record| (record.functions, record.foreign)).collect::<Vec<_>>(), [(2, false), (0, true), (3, false)]);
    assert_eq!(all[0].line(false), format!("{RECORD_A} | functions=2"));
    assert_eq!(all[1].line(true), "_ESTypeAnnotation | functions=0 kind=service foreign | modules.abc");

    let names = |filter: NameFilter| {
        let options = ListOptions::default().filter(Some(filter));
        engine.list_classes(&options).unwrap().into_iter().map(|record| record.name).collect::<Vec<_>>()
    };
    assert_eq!(names(NameFilter::Prefix("entry/src".into())), [RECORD_A]);
    assert_eq!(names(NameFilter::Prefix("&entry/".into())), [RECORD_A]);
    assert_eq!(names(NameFilter::Prefix("com.example".into())), [RECORD_B]);
    assert_eq!(names(NameFilter::Contains("/ets/".into())), [RECORD_A, RECORD_B]);
    assert_eq!(names(NameFilter::Regex(regex::Regex::new("Util$").unwrap())), [RECORD_B]);
    assert!(names(NameFilter::Prefix("_ES".into())).is_empty());
}

#[test]
fn application_package_with_stored_and_deflated_inner_packages() {
    let dir = tempfile::tempdir().unwrap();
    let abc = synthetic().bytes;
    let other = variant("world", "woild");
    let entry_hap = make_apk(&[("ets/modules.abc", &abc)], false);
    let feature_hap = make_apk(&[("ets/modules.abc", &other), ("module.json", b"{}")], true);
    let empty_hap = make_apk(&[("module.json", b"{}")], false);
    for deflate in [false, true] {
        let app = make_apk(
            &[
                ("entry-default.hap", &entry_hap),
                ("feature.hap", &feature_hap),
                ("res.hap", &empty_hap),
                ("broken.hsp", b"not a zip"),
                ("pack.info", b"{}"),
            ],
            deflate,
        );
        let path = write(dir.path(), "demo.app", &app);
        assert_eq!(Format::detect(&path), Some(Format::App));
        let engine = Engine::open(&path).unwrap();
        assert_eq!(entry_names(&engine), ["entry-default.hap/ets/modules.abc", "feature.hap/ets/modules.abc"]);
        assert_eq!(engine.notes().len(), 2, "{:?}", engine.notes());
        assert!(engine.notes().iter().any(|note| note == "res.hap: no ets/*.abc"));
        assert!(engine.notes().iter().any(|note| note.starts_with("broken.hsp: skipped: ")));
        let hits = find(&engine, &Query::string_regex("^wo.ld$").unwrap());
        assert_eq!(hits.len(), 8, "{hits:#?}");
        assert!(
            hits[0]
                .starts_with(&format!("entry-default.hap/ets/modules.abc | {RECORD_A}->#~@0>#build+0x0 | Index.build | lda.str \"world\""))
        );
        assert!(hits[7].starts_with(&format!("feature.hap/ets/modules.abc | {RECORD_B}->#*#+0x0 | <anonymous> | lda.str \"woild\"")));
    }
}

#[test]
fn directories_and_lists_are_one_program() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("program");
    fs::create_dir_all(root.join("libs")).unwrap();
    let abc = synthetic().bytes;
    write(&root, "entry.hap", &make_apk(&[("ets/modules.abc", &abc)], false));
    write(&root.join("libs"), "shared.hsp", &make_apk(&[("ets/modules.abc", &abc)], false));
    write(&root, "dump.abc", &variant("hello", "jello"));
    write(&root, "notes.txt", b"ignored");
    let app = write(dir.path(), "other.app", &make_apk(&[("feature.hap", &make_apk(&[("ets/modules.abc", &abc)], true))], false));

    assert!(Format::accepts(&root) && !Format::accepts(&root.join("notes.txt")) && Format::detect(&root).is_none());
    let engine = Engine::open(&root).unwrap();
    assert_eq!(entry_names(&engine), ["dump.abc", "entry.hap/ets/modules.abc", "libs/shared.hsp/ets/modules.abc"]);
    assert!(engine.notes().is_empty(), "{:?}", engine.notes());

    let spec = format!("{},{}", root.join("entry.hap").display(), app.display());
    let engine = Engine::open(&spec).unwrap();
    assert_eq!(entry_names(&engine), ["entry.hap/ets/modules.abc", "other.app/feature.hap/ets/modules.abc"]);

    // The same record in two entries: the entry has to be named.
    let query = ClassQuery::new("pages/Index");
    match engine.get_class(&query) {
        Err(EngineError::Ambiguous { what: "record", candidates, .. }) => {
            assert_eq!(
                candidates,
                [format!("entry.hap/ets/modules.abc | {RECORD_A}"), format!("other.app/feature.hap/ets/modules.abc | {RECORD_A}")]
            );
        }
        other => panic!("expected an ambiguity, got {other:?}"),
    }
    let source = engine.get_class(&query.entry(Some("feature.hap/ets/modules.abc"))).unwrap();
    assert_eq!((source.entry.as_str(), source.record.as_str()), ("other.app/feature.hap/ets/modules.abc", RECORD_A));
    assert!(matches!(engine.get_class(&query.entry(Some("nope.abc"))), Err(EngineError::NoEntry(_))));
}

#[test]
fn records_and_functions_resolve_by_several_spellings() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(write(dir.path(), "modules.abc", &synthetic().bytes)).unwrap();
    let get = |record, function| engine.get_class(&ClassQuery::new(record).function(function).entry(None));

    for spelling in
        [RECORD_A, "pages/Index", "pages/Index.ets", "Index", "/entry/src/main/ets/pages/Index", "L&entry/src/main/ets/pages/Index&;"]
    {
        let source = get(spelling, None).unwrap();
        assert_eq!((source.record.as_str(), source.function.as_deref()), (RECORD_A, None), "{spelling}");
        assert!(source.text.contains("func_main_0") && source.text.contains("#~@0>#build"), "{spelling}: {}", source.text);
    }
    assert_eq!(get("model/Util", None).unwrap().record, RECORD_B);
    assert!(matches!(get("ages/Index", None), Err(EngineError::NotFound { what: "record", .. })));
    assert!(matches!(get("", None), Err(EngineError::NotFound { what: "record", .. })));

    for spelling in ["#~@0>#build", "Index.build", "build"] {
        let source = get("pages/Index", Some(spelling)).unwrap();
        assert_eq!(source.function.as_deref(), Some("#~@0>#build"), "{spelling}");
        assert!(source.text.contains("lda.str \"world\"") && !source.text.contains("func_main_0"), "{spelling}: {}", source.text);
    }
    assert_eq!(get("model/Util", Some("helper^1")).unwrap().function.as_deref(), Some("#*#helper^1"));
    assert_eq!(get("model/Util", Some("<anonymous>")).unwrap().function.as_deref(), Some("#*#"));
    assert!(matches!(get("model/Util", Some("uild")), Err(EngineError::NotFound { what: "function", .. })));
    let error = get("pages/Index", Some("nope")).unwrap_err().to_string();
    assert_eq!(error, format!("function nope of {RECORD_A} not found"));
}

#[test]
fn string_references_come_from_operands_fields_and_every_region() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::open(write(dir.path(), "modules.abc", &synthetic().bytes)).unwrap();
    // Only record A loads `hello`.
    assert_eq!(
        find(&engine, &Query::string_literal("hello")),
        [format!("modules.abc | {RECORD_A}->func_main_0+0x0 | func_main_0 | lda.str \"hello\"")]
    );
    // `world` is id 1 of region 0 and id 0 of region 1; the third method of B
    // claims region 0 in its flags but lies in region 1.
    let at = synthetic().layout;
    let world_off = at.string("world");
    assert_eq!((at.entity_id(RECORD_A, "#~@0>#build", world_off), at.entity_id(RECORD_B, "#*#", world_off)), (Some(1), Some(0)));
    let world = [
        format!("modules.abc | {RECORD_A}->#~@0>#build+0x0 | Index.build | lda.str \"world\""),
        format!("modules.abc | {RECORD_B}->#*#helper+0x0 | helper | lda.str \"world\""),
        format!("modules.abc | {RECORD_B}->#*#helper^1+0x0 | helper^1 | lda.str \"world\""),
        format!("modules.abc | {RECORD_B}->#*#+0x0 | <anonymous> | lda.str \"world\""),
    ];
    assert_eq!(find(&engine, &Query::string_literal("orl")), world);
    assert_eq!(find(&engine, &Query::string_regex("^w.*d$").unwrap()), world);
    // The scope name table is a literal array reached from a record field.
    assert_eq!(
        find(&engine, &Query::string_regex("^Index$").unwrap()),
        [format!("modules.abc | {RECORD_A} field scopeNames | - | literal@{:#x} [0]=\"Index\"", synthetic().layout.scope_names(RECORD_A))]
    );
    assert!(find(&engine, &Query::string_literal("absent")).is_empty());
    assert!(find(&engine, &Query::string_regex("^ello").unwrap()).is_empty());

    // Rows do not depend on the thread count.
    let rows = |threads: usize| {
        let engine = Engine::open(dir.path().join("modules.abc")).unwrap().with_threads(threads);
        let mut rows: Vec<RefRow> = Vec::new();
        engine.find_refs(&Query::string_regex(".").unwrap(), &AtomicBool::new(false), &mut |batch| rows.extend(batch.rows)).unwrap();
        rows
    };
    let single = rows(1);
    assert_eq!(single.len(), 6);
    assert!(matches!(&single[0].site, RefSite::Field { name } if name == "scopeNames"));
    assert_eq!(single[1].matched, ["hello"]);
    assert_eq!(single, rows(7));

    let cancelled =
        engine.find_refs(&Query::string_regex(".").unwrap(), &AtomicBool::new(true), &mut |_| panic!("no batch after a cancellation"));
    assert!(matches!(cancelled, Err(EngineError::Cancelled)));
}

#[test]
fn encrypted_entries_are_reported_and_paired_with_a_decrypted_file() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("store");
    fs::create_dir_all(&root).unwrap();
    let abc = synthetic().bytes;
    let widgets = variant("hello", "jello");
    let hap = write(
        &root,
        "entry.hap",
        &make_apk(&[("ets/modules.abc", &synthetic_builder().encrypted().build().bytes), ("ets/widgets.abc", &widgets)], false),
    );

    // The package alone: the open succeeds, the entry is named, the rest works.
    let engine = Engine::open(&hap).unwrap();
    assert_eq!(
        engine.entries().map(|info| (info.name.as_str(), &info.status)).collect::<Vec<_>>(),
        [("ets/modules.abc", &EntryStatus::Encrypted), ("ets/widgets.abc", &EntryStatus::Readable)]
    );
    assert_eq!(engine.notes(), ["ets/modules.abc is encrypted (app-store protection); supply the decrypted .abc"]);
    assert_eq!(record_names(&engine, false), [format!("ets/widgets.abc | {RECORD_A}"), format!("ets/widgets.abc | {RECORD_B}")]);
    assert_eq!(find(&engine, &Query::string_literal("jello")).len(), 1);
    assert!(engine.abc("ets/modules.abc").is_none());
    let missing = engine.get_class(&ClassQuery::new("nope/Missing")).unwrap_err().to_string();
    assert!(missing.contains("ets/modules.abc is encrypted"), "{missing}");

    // A decrypted dump pairs whatever it is called, and takes the entry's name.
    write(&root, "entry.hap.abc", &abc);
    let engine = Engine::open(&root).unwrap();
    assert_eq!(entry_names(&engine), ["entry.hap/ets/modules.abc", "entry.hap/ets/widgets.abc"]);
    assert!(engine.notes().is_empty(), "{:?}", engine.notes());
    assert_eq!(
        engine.stand_in_note().as_deref(),
        Some("entry.hap/ets/modules.abc is encrypted in its package; served from the decrypted entry.hap.abc")
    );
    fs::remove_file(root.join("entry.hap.abc")).unwrap();

    // Neither file needs a telling name: both are found by their content.
    let odd = dir.path().join("odd");
    fs::create_dir_all(&odd).unwrap();
    fs::copy(&hap, odd.join("package_1")).unwrap();
    write(&odd, "decrypted.bin", &abc);
    write(&odd, "listing.pa", b"# source binary: decrypted.bin\n");
    let engine = Engine::open(&odd).unwrap();
    assert_eq!(entry_names(&engine), ["package_1/ets/modules.abc", "package_1/ets/widgets.abc"]);
    assert!(engine.notes().is_empty(), "{:?}", engine.notes());
    assert_eq!(
        engine.stand_in_note().as_deref(),
        Some("package_1/ets/modules.abc is encrypted in its package; served from the decrypted decrypted.bin")
    );

    // A bare file of other content and another name is just one more entry.
    write(&root, "dump.abc", &widgets);
    let engine = Engine::open(&root).unwrap();
    assert_eq!(entry_names(&engine), ["dump.abc", "entry.hap/ets/modules.abc", "entry.hap/ets/widgets.abc"]);
    assert_eq!(engine.notes(), ["entry.hap/ets/modules.abc is encrypted (app-store protection); supply the decrypted .abc"]);
    fs::remove_file(root.join("dump.abc")).unwrap();

    // Same name, other content: reported, not paired.
    write(&root, "modules.abc", &widgets);
    let engine = Engine::open(&root).unwrap();
    assert_eq!(entry_names(&engine), ["entry.hap/ets/modules.abc", "entry.hap/ets/widgets.abc", "modules.abc"]);
    assert_eq!(engine.notes().len(), 2, "{:?}", engine.notes());
    assert!(engine.notes()[0].starts_with("modules.abc does not pair with the encrypted entry.hap/ets/modules.abc"));

    // Header matches but the body does not have the checksum: not paired either.
    let mut tampered = abc.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    write(&root, "modules.abc", &tampered);
    let engine = Engine::open(&root).unwrap();
    assert_eq!(engine.entries().filter(|info| info.status == EntryStatus::Encrypted).count(), 1);
    assert!(engine.notes()[0].ends_with("its body does not have the checksum"), "{:?}", engine.notes());

    // The real dump: it takes the encrypted entry's name and place.
    write(&root, "modules.abc", &abc);
    let engine = Engine::open(&root).unwrap();
    assert_eq!(entry_names(&engine), ["entry.hap/ets/modules.abc", "entry.hap/ets/widgets.abc"]);
    assert!(engine.entries().all(|info| info.status == EntryStatus::Readable));
    assert!(engine.notes().is_empty(), "{:?}", engine.notes());
    assert_eq!(
        engine.stand_in_note().as_deref(),
        Some("entry.hap/ets/modules.abc is encrypted in its package; served from the decrypted modules.abc")
    );
    assert_eq!(
        find(&engine, &Query::string_literal("hello")),
        [format!("entry.hap/ets/modules.abc | {RECORD_A}->func_main_0+0x0 | func_main_0 | lda.str \"hello\"")]
    );
    let listed = format!("{},{}", hap.display(), root.join("modules.abc").display());
    assert_eq!(entry_names(&Engine::open(&listed).unwrap()), ["entry.hap/ets/modules.abc", "entry.hap/ets/widgets.abc"]);
}

#[test]
fn inputs_without_code_are_errors() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(Engine::open(dir.path().join("missing.hap")), Err(EngineError::Io { .. })));
    assert!(matches!(Engine::open(dir.path()), Err(EngineError::NoCode { .. })));
    let text = write(dir.path(), "readme.hap", b"plain text, neither a zip nor an ABC file");
    assert!(matches!(Engine::open(&text), Err(EngineError::Archive(_))));
    // Detection falls back on the extension when the content says nothing.
    assert_eq!(Format::detect(&text), Some(Format::Hap));
    let resources = write(dir.path(), "res.hap", &make_apk(&[("resources.index", b"x")], false));
    match Engine::open(&resources) {
        Err(EngineError::NoCode { notes, .. }) => assert_eq!(notes, ["res.hap: no ets/*.abc"]),
        other => panic!("expected NoCode, got {:?}", other.map(|_| ())),
    }
    let apk = write(dir.path(), "app.apk", &make_apk(&[("classes.dex", b"dex\n035\0"), ("AndroidManifest.xml", b"x")], false));
    assert_eq!(Format::detect(&apk), None);
    assert!(!Format::accepts(&apk));
    // A damaged ABC entry is reported per entry, not as a failure of the open.
    let mut damaged = synthetic().bytes;
    damaged.truncate(100);
    seal(&mut damaged);
    let engine = Engine::open(write(dir.path(), "bad.hap", &make_apk(&[("ets/modules.abc", &damaged)], false))).unwrap();
    assert!(matches!(engine.entries().next().map(|info| &info.status), Some(EntryStatus::Unreadable(_))));
    assert!(engine.notes()[0].starts_with("ets/modules.abc: unreadable: "));
    assert!(engine.list_classes(&ListOptions::default()).unwrap().is_empty());
}
