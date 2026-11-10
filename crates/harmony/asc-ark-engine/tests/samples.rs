//! The engine over real HarmonyOS packages. The samples are not in the
//! repository: every test returns early when its file is absent.
//!
//! Locations: `$ASC_ABC_SAMPLES` (default `<workspace>/../ark/ReArk/samples`)
//! and `$ASC_ABC_LARGE_SAMPLE` (no default: a directory holding an app-store
//! `entry.hap` and its decrypted `modules.abc`).
//!
//! The `findrefs` hit sets asserted here were checked against a separate
//! Python reader (own ABC parser, opcode lengths and id operand positions
//! taken from `isa.yaml`): same `(record, function, pc)` sets for every
//! query below.

mod common;

use std::path::Path;
use std::sync::atomic::AtomicBool;

use asc_ark_engine::{ClassQuery, Engine, EngineError, EntryStatus, Format, ListOptions, NameFilter, Query};
use common::{large_sample_dir, sample};

/// `(all records, pseudo or foreign ones)` per entry.
fn counts(engine: &Engine) -> Vec<(String, usize, usize)> {
    let all = engine.list_classes(&ListOptions { all: true, ..ListOptions::default() }).unwrap();
    let modules = engine.list_classes(&ListOptions::default()).unwrap();
    engine
        .entries()
        .filter(|info| info.status == EntryStatus::Readable)
        .map(|info| {
            let of = |rows: &[asc_ark_engine::RecordListing]| rows.iter().filter(|row| row.entry == info.name).count();
            (info.name.clone(), of(&all), of(&all) - of(&modules))
        })
        .collect()
}

fn find(engine: &Engine, query: &Query) -> Vec<String> {
    let mut lines = Vec::new();
    engine
        .find_refs(query, &AtomicBool::new(false), &mut |batch| {
            assert_eq!(batch.error, None, "{}", batch.entry_name);
            lines.extend(batch.rows.iter().map(|row| row.line(&batch.entry_name)));
        })
        .unwrap();
    lines
}

fn open(path: &Path, format: Format) -> Engine {
    assert_eq!(Format::detect(path), Some(format), "{}", path.display());
    let engine = Engine::open(path).unwrap();
    assert!(engine.notes().is_empty(), "{:?}", engine.notes());
    engine
}

#[test]
fn every_sample_opens_and_lists_its_records() {
    let expected = [
        ("Bridge.hap", Format::Hap, "ets/modules.abc", "13.0.1.0", 16, 10),
        ("contacts.hap", Format::Hap, "ets/modules.abc", "12.0.6.0", 25, 9),
        ("遥遥领先.hap", Format::Hap, "ets/modules.abc", "12.0.2.0", 16, 9),
        // The 6 include one record the file only declares (`_ESTypeAnnotation`).
        ("EasyHap-default-unsigned.app", Format::App, "entry-default.hap/ets/modules.abc", "9.0.0.0", 6, 3),
        ("fpt-default-signed.app", Format::App, "entry-default.hap/ets/modules.abc", "12.0.6.0", 22, 9),
        ("shctf.app", Format::App, "entry-default.hap/ets/modules.abc", "12.0.2.0", 14, 9),
    ];
    for (file, format, entry, version, records, pseudo) in expected {
        let Some(path) = sample(file) else { continue };
        let engine = open(&path, format);
        let infos: Vec<_> = engine.entries().collect();
        assert_eq!(infos.len(), 1, "{file}");
        assert_eq!((infos[0].name.as_str(), infos[0].version.map(|v| v.to_string()).as_deref()), (entry, Some(version)), "{file}");
        assert_eq!(counts(&engine), [(entry.to_owned(), records, pseudo)], "{file}");
        // Every listed record disassembles, and by its canonical name.
        for record in engine.list_classes(&ListOptions::default()).unwrap() {
            let source = engine.get_class(&ClassQuery { record: &record.name, ..ClassQuery::default() }).unwrap();
            assert_eq!(source.record, record.name);
            assert!(source.text.contains(".function") || record.functions == 0, "{file} {}", record.name);
        }
    }
}

#[test]
fn several_samples_are_one_program() {
    let (Some(bridge), Some(shctf)) = (sample("Bridge.hap"), sample("shctf.app")) else { return };
    let engine = Engine::open(format!("{},{}", bridge.display(), shctf.display())).unwrap();
    let names: Vec<_> = engine.entries().map(|info| info.name.as_str()).collect();
    assert_eq!(names, ["Bridge.hap/ets/modules.abc", "shctf.app/entry-default.hap/ets/modules.abc"]);
    assert_eq!(counts(&engine).iter().map(|(_, all, pseudo)| (*all, *pseudo)).collect::<Vec<_>>(), [(16, 10), (14, 9)]);
}

#[test]
fn contacts_records_resolve_by_every_spelling() {
    let Some(path) = sample("contacts.hap") else { return };
    let engine = open(&path, Format::Hap);
    let canonical = "&entry/src/main/ets/pages/Index&";
    let get = |record, function| engine.get_class(&ClassQuery { record, function, entry: None });

    let whole = get(canonical, None).unwrap();
    assert!(whole.text.starts_with(".record &entry/src/main/ets/pages/Index&"), "{}", &whole.text[..80.min(whole.text.len())]);
    for spelling in ["pages/Index", "pages/Index.ets", "entry/src/main/ets/pages/Index", "ets/pages/Index.ets"] {
        assert_eq!(get(spelling, None).unwrap(), whole, "{spelling}");
    }
    // `index` is the entry file of two bundled libraries.
    match get("index", None) {
        Err(EngineError::Ambiguous { candidates, .. }) => {
            assert_eq!(candidates, ["ets/modules.abc | &@ohos/crypto-js/index&2.0.0", "ets/modules.abc | &@ohos/jsonwebtoken/index&1.0.1"]);
        }
        other => panic!("expected an ambiguity, got {other:?}"),
    }
    assert_eq!(get("crypto-js/index", None).unwrap().record, "&@ohos/crypto-js/index&2.0.0");

    let by_raw = get("pages/Index", Some("#~@0>#initialRender")).unwrap();
    assert_eq!(by_raw.function.as_deref(), Some("#~@0>#initialRender"));
    assert!(by_raw.text.starts_with(".function #~@0>#initialRender") && by_raw.text.trim_end().ends_with(".end function"));
    assert!(whole.text.contains(by_raw.text.trim_end()));
    assert_eq!(get("pages/Index", Some("Index.initialRender")).unwrap(), by_raw);
    assert_eq!(get("pages/Index", Some("initialRender")).unwrap(), by_raw);
    // An exact restored name wins over a suffix: `<anonymous>` is the top-level one.
    assert_eq!(get("pages/Index", Some("<anonymous>")).unwrap().function.as_deref(), Some("#*#"));
    // Two closures are called `paramsLambda`, two components of `setIP` have a `rerender`.
    match get("pages/Index", Some("paramsLambda")) {
        Err(EngineError::Ambiguous { what: "function", candidates, .. }) => assert_eq!(
            candidates,
            [
                "#~@0>@1*^1*#paramsLambda | Index.initialRender.<anonymous>^1.paramsLambda",
                "#~@0>@1*^2*#paramsLambda | Index.initialRender.<anonymous>^2.paramsLambda"
            ]
        ),
        other => panic!("expected an ambiguity, got {other:?}"),
    }
    assert!(matches!(get("pages/setIP", Some("rerender")), Err(EngineError::Ambiguous { what: "function", .. })));
    assert_eq!(get("pages/setIP", Some("setIP.rerender")).unwrap().function.as_deref(), Some("#~@2>#rerender"));
    assert!(matches!(get("pages/Index", Some("build")), Err(EngineError::NotFound { what: "function", .. })));

    let pages =
        engine.list_classes(&ListOptions { filter: Some(NameFilter::Prefix("entry/src/main/ets/pages".into())), all: false }).unwrap();
    assert_eq!(
        pages.iter().map(|record| (record.name.as_str(), record.functions)).collect::<Vec<_>>(),
        [("&entry/src/main/ets/pages/Index&", 18), ("&entry/src/main/ets/pages/setIP&", 36)]
    );
}

#[test]
fn contacts_string_references() {
    let Some(path) = sample("contacts.hap") else { return };
    let engine = open(&path, Format::Hap);
    let hits = find(&engine, &Query::string_regex("http").unwrap());
    let locations: Vec<&str> = hits.iter().map(|line| line.split(" | ").nth(1).unwrap()).collect();
    assert_eq!(
        locations,
        [
            "&@ohos/jsonwebtoken/src/main/ets/dist/jsonwebtoken&1.0.1->#*^22*#+0x7ea",
            "&@ohos/jsonwebtoken/src/main/ets/dist/jsonwebtoken&1.0.1->#*^2f**#^b3+0x1d",
            "&@ohos/jsonwebtoken/src/main/ets/dist/jsonwebtoken&1.0.1->#*^2f**^b6*#^1+0xc",
            "&entry/src/main/ets/common/Utils/utils&->#~@0<@3*#+0x19",
            "&entry/src/main/ets/common/Utils/utils&->#~@0<@4*#+0x40",
            "&entry/src/main/ets/common/Utils/utils&->#~@0<@4**#+0x18",
            "&entry/src/main/ets/common/Utils/utils&->#~@0<#l1Lll1+0x12",
            "&entry/src/main/ets/common/Utils/utils&->#~@0<#l1Lll1+0x4b",
            "&entry/src/main/ets/common/Utils/utils&->#~@0<#o0O0OOoo+0x12",
            "&entry/src/main/ets/common/Utils/utils&->#~@0<#o0O0OOoo+0x4e",
            "&entry/src/main/ets/common/Utils/utils&->#~@0<#o0O0OOoo+0x7b",
        ]
    );
    assert_eq!(
        hits[6],
        "ets/modules.abc | &entry/src/main/ets/common/Utils/utils&->#~@0<#l1Lll1+0x12 | utils.l1Lll1 | lda.str \"http://\""
    );
    // A string inside a literal array, reached from the instruction that loads the array.
    assert!(
        hits[2].ends_with("| createarraywithbuffer literal@0xf3e09 [2]=\"https://github.com/crypto-browserify/crypto-browserify\""),
        "{}",
        hits[2]
    );
    // Anchors are the string's own edges.
    assert_eq!(find(&engine, &Query::string_regex("^http://$").unwrap()).len(), 2);
    assert_eq!(find(&engine, &Query::string_literal("http://")).len(), 2);
    assert_eq!(find(&engine, &Query::string_literal("Index")).len(), 100);
    assert_eq!(find(&engine, &Query::string_regex("^[a-z]{3}$").unwrap()).len(), 3611);
    assert!(find(&engine, &Query::string_literal("no such string anywhere")).is_empty());
}

#[test]
fn bridge_and_easyhap_string_references() {
    if let Some(path) = sample("Bridge.hap") {
        let hits = find(&open(&path, Format::Hap), &Query::string_regex("flag|Flag").unwrap());
        assert_eq!(hits.len(), 26);
        assert_eq!(hits[0], "ets/modules.abc | com.hmos.exam5.pkg/entry/ets/pages/Home->#~@0>@2*#^3+0x23 | HomePage.initialRender.<anonymous>^3 | ldobjbyname \"flagText\"");
        assert!(hits.iter().any(|line| line.ends_with("| createobjectwithbuffer literal@0x5918 [6]=\"flagText\"")));
    }
    // Bytecode 9.0.0.0, inside a stored inner package.
    if let Some(path) = sample("EasyHap-default-unsigned.app") {
        let engine = open(&path, Format::App);
        assert_eq!(find(&engine, &Query::string_regex(".").unwrap()).len(), 473);
        assert_eq!(find(&engine.with_threads(1), &Query::string_regex(".").unwrap()).len(), 473);
    }
}

/// A string query selective enough to list, common enough to hit.
fn url_query() -> Query {
    Query::string_literal("https://")
}

fn in_entry<'a>(hits: &'a [String], entry: &str) -> Vec<&'a str> {
    hits.iter().filter_map(|line| line.strip_prefix(entry)?.strip_prefix(" | ")).collect()
}

#[test]
fn large_sample_package_alone_reports_the_encrypted_entry() {
    let Some(dir) = large_sample_dir() else { return };
    let hap = dir.join("entry.hap");
    assert_eq!(Format::detect(&hap), Some(Format::Hap));
    let engine = Engine::open(&hap).unwrap();
    let entries: Vec<_> = engine.entries().map(|info| (info.name.as_str(), &info.status)).collect();
    assert_eq!(entries, [("ets/modules.abc", &EntryStatus::Encrypted), ("ets/widgets.abc", &EntryStatus::Readable)]);
    assert_eq!(engine.notes(), ["ets/modules.abc is encrypted (app-store protection); supply the decrypted .abc"]);
    // Only the readable entry has records, and every one of them disassembles.
    let listed = counts(&engine);
    assert!(matches!(&listed[..], [(entry, records, pseudo)] if entry == "ets/widgets.abc" && records > pseudo), "{listed:?}");
    for row in engine.list_classes(&ListOptions::default()).unwrap() {
        let source = engine.get_class(&ClassQuery { record: &row.name, function: None, entry: None }).unwrap();
        assert_eq!((source.entry.as_str(), source.record.as_str()), ("ets/widgets.abc", row.name.as_str()));
    }
    let hits = find(&engine, &Query::string_regex(".").unwrap());
    assert!(!hits.is_empty() && hits.iter().all(|line| line.starts_with("ets/widgets.abc | ")));
}

#[test]
fn large_sample_directory_pairs_the_decrypted_file_with_the_encrypted_entry() {
    let Some(dir) = large_sample_dir() else { return };
    assert!(Format::accepts(&dir));
    let engine = Engine::open(&dir).unwrap();
    let decrypted = std::fs::metadata(dir.join("modules.abc")).unwrap().len();
    let entries: Vec<_> = engine.entries().map(|info| (info.name.as_str(), &info.status)).collect();
    assert_eq!(entries, [("entry.hap/ets/modules.abc", &EntryStatus::Readable), ("entry.hap/ets/widgets.abc", &EntryStatus::Readable)]);
    assert_eq!(engine.entries().next().unwrap().size, decrypted);
    assert_eq!(engine.notes(), ["entry.hap/ets/modules.abc is encrypted in its package; served from the decrypted modules.abc"]);
    let listed = counts(&engine);
    assert_eq!(listed.len(), 2, "{listed:?}");

    // Several regions, tens of thousands of methods: the same rows on one thread and on many.
    let hits = find(&engine, &url_query());
    assert_eq!(find(&Engine::open(&dir).unwrap().with_threads(1), &url_query()), hits);
    // The second entry answers as it does in the package alone.
    let alone = find(&Engine::open(dir.join("entry.hap")).unwrap(), &url_query());
    assert_eq!(in_entry(&hits, "entry.hap/ets/widgets.abc"), in_entry(&alone, "ets/widgets.abc"));

    // A record both entries define needs its entry named.
    let rows = engine.list_classes(&ListOptions::default()).unwrap();
    let of = |entry: &str| rows.iter().filter(|row| row.entry == entry).map(|row| row.name.as_str()).collect::<Vec<_>>();
    let (main, widgets) = (of("entry.hap/ets/modules.abc"), of("entry.hap/ets/widgets.abc"));
    if let Some(shared) = widgets.iter().find(|record| main.contains(record)) {
        let query = ClassQuery { record: shared, function: None, entry: None };
        assert!(matches!(engine.get_class(&query), Err(EngineError::Ambiguous { what: "record", .. })));
        assert_eq!(engine.get_class(&ClassQuery { entry: Some("ets/widgets.abc"), ..query }).unwrap().entry, "entry.hap/ets/widgets.abc");
    }

    // The bare decrypted file on its own is a program too.
    let bare = Engine::open(dir.join("modules.abc")).unwrap();
    assert_eq!(counts(&bare), [("modules.abc".to_owned(), listed[0].1, listed[0].2)]);
    assert_eq!(in_entry(&find(&bare, &url_query()), "modules.abc"), in_entry(&hits, "entry.hap/ets/modules.abc"));
}

fn condition(spec: &str) -> Query {
    Query::condition(spec).unwrap()
}

#[test]
fn contacts_references_of_every_kind() {
    let Some(path) = sample("contacts.hap") else { return };
    let engine = open(&path, Format::Hap);
    let utils = "ets/modules.abc | &entry/src/main/ets/common/Utils/utils&";
    assert_eq!(
        find(&engine, &condition("prop:=createHttp")),
        [
            format!("{utils}->#~@0<#l1Lll1+0x53 | utils.l1Lll1 | ldobjbyname \"createHttp\" [call]"),
            format!("{utils}->#~@0<#o0O0OOoo+0x56 | utils.o0O0OOoo | ldobjbyname \"createHttp\" [call]"),
        ]
    );
    assert_eq!(
        find(&engine, &condition("call:^import:@ohos:net\\.http")),
        [
            // The client `l1Lll1` keeps in a captured variable, used by the closure it passes on.
            format!(
                "{utils}->#~@0<@4*#+0xe9 | utils.l1Lll1.<anonymous> | callthis2 v9, v10, v11 ; import:@ohos:net.http#default.createHttp().request(lex(0,1), expr)"
            ),
            format!(
                "{utils}->#~@0<@4*#+0x101 | utils.l1Lll1.<anonymous> | callthis1 v7, v8 ; import:@ohos:net.http#default.createHttp().request().then(local:#~@0<@4**#)"
            ),
            format!("{utils}->#~@0<#l1Lll1+0x5b | utils.l1Lll1 | callthis0 v9 ; import:@ohos:net.http#default.createHttp()"),
            format!("{utils}->#~@0<#o0O0OOoo+0x5e | utils.o0O0OOoo | callthis0 v8 ; import:@ohos:net.http#default.createHttp()"),
            // The client is followed through the call that made it, to its request and the callback of that.
            format!("{utils}->#~@0<#o0O0OOoo+0xef | utils.o0O0OOoo | callthis2 v10, v11, v12 ; import:@ohos:net.http#default.createHttp().request(expr, expr)"),
            format!(
                "{utils}->#~@0<#o0O0OOoo+0x107 | utils.o0O0OOoo | callthis1 v8, v9 ; import:@ohos:net.http#default.createHttp().request().then(local:#~@0<@3*#)"
            ),
        ]
    );
    let imports = find(&engine, &condition("import:@ohos:net\\.http#default"));
    assert_eq!(imports.len(), 7);
    assert_eq!(
        imports[0],
        format!("{utils} field moduleRecordIdx | - | regular import 4: import {{ default as http }} from \"@ohos:net.http\"")
    );
    assert_eq!(find(&engine, &condition("global:=console")).len(), 27);
    assert_eq!(
        find(&engine, &condition("method:=onCreate")),
        ["ets/modules.abc | &entry/src/main/ets/entryability/EntryAbility&->func_main_0+0x1d | func_main_0 | defineclasswithbuffer literal@0xe309f [1]=method #~@0>#onCreate"]
    );
    // One function that has the URL prefix and creates the HTTP client.
    let both = find(&engine, &Query::All(vec![condition("string:^http://"), condition("call:\\.createHttp$")]));
    assert_eq!(both.len(), 2, "{both:?}");
    assert!(both[0].starts_with(&format!("{utils}->#~@0<#l1Lll1+0x12 | utils.l1Lll1 | string +0x12 lda.str \"http://\"")), "{both:?}");

    let requests: Vec<String> = engine.module_requests(None).unwrap().iter().map(|request| request.line(false)).collect();
    assert!(requests.contains(&"@ohos:net.http | 1 record | default".to_owned()), "{requests:?}");
    assert!(requests.contains(&"@ohos:hilog | 3 records | *, default".to_owned()), "{requests:?}");
}

/// The hit sets of these queries were compared on a 32 MB store sample,
/// instruction offset by instruction offset, with sets derived from the
/// official `ark_disasm` listing of the same file (every by-name
/// instruction, `ldai` / `fldai` and literal items, method id operands and
/// literal method items, every call instruction) and, for imports, from the
/// raw module records. What is asserted here holds for any program: how the
/// hit sets of related queries contain and partition each other.
#[test]
fn large_sample_references_of_every_kind() {
    let Some(dir) = large_sample_dir() else { return };
    let engine = Engine::open(dir.join("modules.abc")).unwrap();
    let count = |query: &Query| find(&engine, query).len();
    let with_access = |access| Query::Prop { name: asc_ark_engine::Pattern::regex(".").unwrap(), access: Some(access) };
    use asc_ark_engine::Access;
    // Every property reference has exactly one access (on that sample: 267,353 loads, 57,645
    // stores, 45,356 definitions and 236,955 loads that are the callee of a call).
    let by_access = Access::ALL.map(|access| count(&with_access(access)));
    assert!(by_access.iter().all(|&rows| rows > 0), "{by_access:?}");
    assert_eq!(by_access.iter().sum::<usize>(), count(&condition("prop:.")));
    let narrows = |narrow: &str, wide: &str| {
        let (narrow, wide) = (count(&condition(narrow)), count(&condition(wide)));
        assert!(0 < narrow && narrow < wide, "{narrow} of {wide}");
    };
    narrows("global:=console", "global:.");
    narrows("method:=aboutToAppear", "method:.");
    narrows("number:1000", "number:1000..2000");
    narrows("import:@ohos:net\\.http#default", "import:@ohos:");

    // Every call instruction of the file is a row, whatever its callee.
    let mut callees = Vec::new();
    engine
        .find_refs(&condition("call:."), &AtomicBool::new(false), &mut |batch| {
            callees.extend(batch.rows.into_iter().map(|mut row| row.matched.swap_remove(0)));
        })
        .unwrap();
    let stats = engine.call_resolution(&asc_ark_engine::ResolutionOptions::default(), &AtomicBool::new(false)).unwrap();
    assert_eq!(callees.len() as u64, stats.call_sites as u64);
    // By the root of the callee, with captured variables resolved and values followed over
    // forward jumps. On that sample: imports 29.1 %, globals 26.3 %, `this` 22.0 % (7.6 % of them
    // the `this` of an enclosing function), the result of another call 9.0 % (whose path goes on
    // to the callee of that call), parameters 3.9 %, another block 2.4 %, captured variables
    // left 1.5 %.
    let through_a_call = callees.iter().filter(|callee| callee.contains("()")).count();
    let rooted = |prefix: &str| callees.iter().filter(|callee| !callee.contains("()") && callee.starts_with(prefix)).count();
    let roots = ["import:", "global:", "globalThis", "lex(", "slex(", "this", "?", "arg", "local:"].map(rooted);
    assert!(roots.iter().sum::<usize>() + through_a_call <= callees.len());
    assert!(rooted("import:") > 0 && rooted("this") > rooted("this@") && through_a_call > 0, "{roots:?}");
    // Captured variables are resolved more often than not.
    assert!(rooted("lex(") + rooted("slex(") < rooted("this@") + rooted("local:"), "{roots:?}");

    // What is done with the client `createHttp()` returned.
    let created = count(&condition("call:^import:@ohos:net\\.http#default\\.createHttp$"));
    assert!(0 < created && created <= count(&condition("prop:=createHttp")));
    let requests = find(&engine, &condition("call:^import:@ohos:net\\.http#default\\.createHttp\\(\\)\\.request$"));
    assert!(!requests.is_empty());
    assert!(requests.iter().all(|row| row.contains(" ; import:@ohos:net.http#default.createHttp().request(")), "{requests:?}");
    // The functions that hold an https URL and create an HTTP client.
    let both = find(&engine, &Query::All(vec![condition("string:^https://"), condition("call:^import:@ohos:net\\.http")]));
    assert!(!both.is_empty());
    assert!(both.iter().all(|row| row.contains(" | string +0x") && row.contains("\"https://") && row.contains(" && call +0x")), "{both:?}");
    let network: Vec<String> = engine
        .module_requests(Some(&asc_ark_engine::Pattern::regex("^@ohos:net\\.").unwrap()))
        .unwrap()
        .iter()
        .map(|request| request.line(false))
        .collect();
    assert!(network.iter().any(|line| line.starts_with("@ohos:net.http | ")), "{network:?}");
    assert!(network.iter().all(|line| line.starts_with("@ohos:net.")) && network.is_sorted(), "{network:?}");
}
