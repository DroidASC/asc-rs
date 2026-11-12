//! End-to-end tests of the `asc` binary on HarmonyOS inputs (synthetic
//! `.abc` / `.hap` / `.app` files).

use asc_fixture::abc::{
    CALLS_APP, CALLS_BOX, CALLS_INDEX, CALLS_UTIL, CLASSES_APP, CLASSES_BASE, ENTRY_ABILITY, INDEX_PAGE, SAMPLE_API_URL,
    annotations_program, call_graph_program, callable_names_program, class_hierarchy_program, make_abc, sample_program,
};
use asc_fixture::hap::{
    Compression, DETAIL_PAGE, Hap, LABELS_PAGE, LONG_MARKER, SAMPLE_BRAND_ID, SAMPLE_MAIN_PAGES, SAMPLE_MODULE_JSON, SAMPLE_PACK_INFO,
    SHARED_PAGE, make_app, make_hap, make_library_hsp, make_routed_hap, resource_program, sample_resources,
};
use asc_fixture::{make_apk, make_dex};
use std::path::PathBuf;
use std::process::{Command, Output};

/// A directory of inputs that lives as long as the test.
struct Inputs {
    _dir: tempfile::TempDir,
    /// The directory as asc names it back (canonical: on Windows the long
    /// name of a temporary directory, without a `\\?\` prefix).
    root: PathBuf,
}

impl Inputs {
    fn new() -> Inputs {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let root = match root.to_str().and_then(|r| r.strip_prefix(r"\\?\")) {
            Some(plain) => PathBuf::from(plain),
            None => root,
        };
        Inputs { _dir: dir, root }
    }

    /// `name` (`/`-separated) below the directory.
    fn join(&self, name: &str) -> PathBuf {
        name.split('/').fold(self.root.clone(), |path, part| path.join(part))
    }

    /// Write `bytes` as `name` (below the directory); its path.
    fn file(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        path.to_str().unwrap().to_owned()
    }

    fn path(&self, name: &str) -> PathBuf {
        self.join(name)
    }

    /// The sample program as `entry.hap`.
    fn sample_hap(&self) -> String {
        self.file("entry.hap", &make_hap(&make_abc()))
    }

    /// A hap whose `ets/modules.abc` and `ets/widgets.abc` are both the sample program.
    fn two_entry_hap(&self) -> String {
        let abc = make_abc();
        self.file("two.hap", &Hap::new().modules_abc(&abc).abc("widgets", &abc).module_json("{}").build())
    }

    /// A hap as an app store ships it: `ets/modules.abc` encrypted,
    /// `ets/widgets.abc` readable.
    fn store_hap(&self, name: &str) -> String {
        let encrypted = sample_program().encrypted().build().bytes;
        self.file(name, &Hap::new().modules_abc(&encrypted).abc("widgets", &make_abc()).module_json("{}").build())
    }

    /// Run the binary in its own process (no daemon), away from the user's
    /// config file and cache.
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_asc"))
            .env("ASC_CONFIG", "")
            .env("ASC_DAEMON", "off")
            .env_remove("ASC_LIMIT")
            .env_remove("ASC_MAX_BYTES")
            .arg("--cache-dir")
            .arg(self.path("cache"))
            .args(args)
            .output()
            .expect("run asc")
    }

    /// The stdout lines of a run that must succeed without a word on stderr.
    fn lines(&self, args: &[&str]) -> Vec<String> {
        let out = self.run(args);
        assert!(out.status.success(), "{args:?}: {}", stderr(&out));
        assert_eq!(stderr(&out), "", "{args:?}");
        stdout(&out).lines().map(String::from).collect()
    }

    /// The error of a run that must fail with status 1 and print nothing.
    fn error(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert_eq!(out.status.code(), Some(1), "{args:?}: {}", stderr(&out));
        assert_eq!(stdout(&out), "", "{args:?}");
        stderr(&out)
    }
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The first column of each row.
fn first_columns(lines: &[String]) -> Vec<&str> {
    lines.iter().map(|line| line.split(" | ").next().unwrap()).collect()
}

/// The `.function` headers of a disassembly: the raw names.
fn functions(lines: &[String]) -> Vec<&str> {
    lines.iter().filter_map(|line| line.strip_prefix(".function ")).map(|rest| rest.split_whitespace().next().unwrap()).collect()
}

#[test]
fn listclass_lists_the_records() {
    let inputs = Inputs::new();
    let hap = inputs.sample_hap();
    let rows = inputs.lines(&["listclass", &hap]);
    assert_eq!(first_columns(&rows), [ENTRY_ABILITY, INDEX_PAGE]);
    assert!(rows[0].contains(" | functions=3") && rows[1].contains(" | functions=5"), "{rows:?}");
    assert_eq!(inputs.lines(&["classes", &hap]), rows, "the alias answers alike");

    // A prefix with or without the decoration of the record name.
    for prefix in ["entry/src/main/ets/pages", "&entry/src/main/ets/pages"] {
        assert_eq!(first_columns(&inputs.lines(&["listclass", &hap, "--prefix", prefix])), [INDEX_PAGE]);
    }
    assert!(inputs.lines(&["listclass", &hap, "--prefix", "nope"]).is_empty());

    // Pseudo records only with --all.
    let all = inputs.lines(&["listclass", &hap, "--all"]);
    assert_eq!(all.len(), 3, "{all:?}");
    assert!(all.iter().any(|row| row.starts_with("_ESSlotNumberAnnotation | ")), "{all:?}");

    // -o writes the rows instead of printing them.
    let saved = inputs.path("records.txt");
    assert!(inputs.lines(&["listclass", &hap, "-o", saved.to_str().unwrap()]).is_empty());
    assert_eq!(std::fs::read_to_string(&saved).unwrap().lines().collect::<Vec<_>>(), rows);
}

#[test]
fn every_kind_of_input_opens() {
    let inputs = Inputs::new();
    let abc = inputs.file("modules.abc", &make_abc());
    assert_eq!(first_columns(&inputs.lines(&["listclass", &abc])), [ENTRY_ABILITY, INDEX_PAGE]);

    // An .app holds haps, here deflated as release bundles have them; rows
    // of a program with several ABC entries name theirs.
    let hap = make_hap(&make_abc());
    for (name, inner) in [("stored.app", Compression::Stored), ("deflated.app", Compression::Deflated)] {
        let app = inputs.file(name, &make_app(&[("entry.hap", &hap), ("feature.hap", &hap)], inner));
        let rows = inputs.lines(&["listclass", &app, "--prefix", "entry/src/main/ets/pages"]);
        assert_eq!(
            rows.iter().map(|row| row.rsplit(" | ").next().unwrap()).collect::<Vec<_>>(),
            ["entry.hap/ets/modules.abc", "feature.hap/ets/modules.abc"],
            "{name}"
        );
    }

    // A package under another extension is recognized by its content.
    let renamed = inputs.file("renamed.zip", &hap);
    assert_eq!(first_columns(&inputs.lines(&["listclass", &renamed])), [ENTRY_ABILITY, INDEX_PAGE]);

    // A directory and a comma list are one program.
    let dir = Inputs::new();
    let (first, second) = (dir.file("a/entry.hap", &hap), dir.file("b/feature.hap", &hap));
    assert_eq!(dir.lines(&["listclass", dir.root.as_path().to_str().unwrap()]).len(), 4);
    assert_eq!(dir.lines(&["listclass", &format!("{first},{second}")]).len(), 4);
}

#[test]
fn getclass_prints_a_record() {
    let inputs = Inputs::new();
    let hap = inputs.sample_hap();
    let whole = inputs.lines(&["getclass", &hap, INDEX_PAGE]);
    assert_eq!(whole[0], format!(".record {INDEX_PAGE}"));
    assert_eq!(functions(&whole), ["func_main_0", "#~@0=#Index", "#~@0>#build", "#~@0>#aboutToAppear", "#*#helper"]);
    assert!(whole.iter().any(|line| line.contains(SAMPLE_API_URL)), "{whole:?}");

    // The record by a path suffix, with or without the source extension, or wrapped as a class descriptor.
    for name in ["pages/Index", "pages/Index.ets", "Index", &format!("L{INDEX_PAGE};")] {
        assert_eq!(inputs.lines(&["getclass", &hap, name]), whole, "{name}");
    }
    // `--no-debug-info` asks for what the disassembly already is.
    assert_eq!(inputs.lines(&["getclass", &hap, "pages/Index", "--no-debug-info"]), whole);

    // disassemble: -o instead of stdout; getclass: -o as well as stdout.
    let saved = inputs.path("Index.pa");
    assert!(inputs.lines(&["disassemble", &hap, "pages/Index", "-o", saved.to_str().unwrap()]).is_empty());
    assert_eq!(std::fs::read_to_string(&saved).unwrap().lines().collect::<Vec<_>>(), whole);
    std::fs::remove_file(&saved).unwrap();
    assert_eq!(inputs.lines(&["getclass", &hap, "pages/Index", "-o", saved.to_str().unwrap()]), whole);
    assert_eq!(std::fs::read_to_string(&saved).unwrap().lines().collect::<Vec<_>>(), whole);

    let error = inputs.error(&["getclass", &hap, "pages/Missing"]);
    assert_eq!(error, "Error: record pages/Missing not found\n");
}

#[test]
fn getclass_prints_one_function() {
    let inputs = Inputs::new();
    let hap = inputs.sample_hap();
    let by_raw_name = inputs.lines(&["getclass", &hap, "pages/Index", "--method", "#~@0>#build"]);
    assert_eq!(functions(&by_raw_name), ["#~@0>#build"]);
    assert!(by_raw_name.iter().any(|line| line.contains(SAMPLE_API_URL)), "{by_raw_name:?}");
    assert!(!by_raw_name.iter().any(|line| line.starts_with(".record")), "{by_raw_name:?}");

    // The restored name, a suffix of it, and the location column of a findrefs row.
    for function in ["Index.build", "build"] {
        assert_eq!(inputs.lines(&["getclass", &hap, "pages/Index", "--method", function]), by_raw_name, "{function}");
        assert_eq!(inputs.lines(&["disassemble", &hap, "pages/Index", "--method", function]), by_raw_name, "{function}");
    }
    for location in [format!("{INDEX_PAGE}->#~@0>#build"), format!("{INDEX_PAGE}->#~@0>#build+0x1b"), "pages/Index->#~@0>#build".into()] {
        assert_eq!(inputs.lines(&["getclass", &hap, &location]), by_raw_name, "{location}");
    }
    assert_eq!(inputs.lines(&["getclass", &hap, "pages/Index", "--method", "#~@0>#build+0x1b"]), by_raw_name);

    // A function the record lacks: the error lists the ones it has.
    let error = inputs.error(&["getclass", &hap, "pages/Index", "--method", "render"]);
    assert!(error.starts_with(&format!("Error: function render of {INDEX_PAGE} not found; its functions: func_main_0, ")), "{error}");
    assert!(error.contains("#~@0>#build (Index.build)"), "{error}");

    // Long strings are cut at the length findrefs rows use.
    let routed = inputs.file("routed.hap", &make_routed_hap());
    let listing = inputs.lines(&["getclass", &routed, "pages/Long", "--method", "long"]);
    assert!(listing.iter().any(|line| line.ends_with(&format!("a\"… (+{} bytes)", 3000 + LONG_MARKER.len() + 8 - 2048))), "{listing:?}");
}

#[test]
fn an_ambiguous_name_lists_its_candidates() {
    let inputs = Inputs::new();
    let hap = inputs.two_entry_hap();
    // One record in two entries: the error says how to choose.
    let error = inputs.error(&["getclass", &hap, "pages/Index"]);
    assert_eq!(
        error.lines().collect::<Vec<_>>(),
        [
            "Error: record pages/Index is ambiguous, candidates:",
            &format!("ets/modules.abc | {INDEX_PAGE}"),
            &format!("ets/widgets.abc | {INDEX_PAGE}"),
            "(name the entry, the first column, with --entry)",
        ]
    );
    for entry in ["ets/widgets.abc", "ets/modules.abc"] {
        let text = inputs.lines(&["getclass", &hap, "pages/Index", "--entry", entry]);
        assert_eq!(text[0], format!(".record {INDEX_PAGE}"));
    }
    assert_eq!(inputs.error(&["getclass", &hap, "pages/Index", "--entry", "ets/nope.abc"]), "Error: no entry named ets/nope.abc\n");

    // Two records of one entry: more of the path tells them apart, --entry would not.
    let error = inputs.error(&["getclass", &inputs.sample_hap(), "entry/src/main/ets"]);
    assert!(error.starts_with("Error: record entry/src/main/ets not found"), "{error}");
    let mut program = sample_program();
    program.record(asc_fixture::abc::AbcRecord::new("&feature/src/main/ets/pages/Index&"));
    let abc = inputs.file("twice.abc", &program.build().bytes);
    let error = inputs.error(&["getclass", &abc, "pages/Index"]);
    assert_eq!(
        error.lines().collect::<Vec<_>>(),
        [
            "Error: record pages/Index is ambiguous, candidates:",
            &format!("twice.abc | {INDEX_PAGE}"),
            "twice.abc | &feature/src/main/ets/pages/Index&",
        ]
    );
}

#[test]
fn findrefs_string_finds_the_instructions() {
    let inputs = Inputs::new();
    let hap = inputs.sample_hap();
    // entry | record->function+0xPC | restored name | instruction
    let rows = inputs.lines(&["findrefs", &hap, "string", "https?://"]);
    let [row] = &rows[..] else { panic!("one reference expected: {rows:?}") };
    let columns: Vec<&str> = row.split(" | ").collect();
    assert_eq!(columns.len(), 4, "{row}");
    assert_eq!(columns[0], "ets/modules.abc");
    assert!(columns[1].starts_with(&format!("{INDEX_PAGE}->#~@0>#build+0x")), "{row}");
    assert_eq!(columns[2], "Index.build");
    assert!(columns[3].ends_with(&format!("\"{SAMPLE_API_URL}\"")), "{row}");
    // The location column is what getclass takes.
    assert_eq!(functions(&inputs.lines(&["getclass", &hap, columns[1]])), ["#~@0>#build"]);

    // A string two records use, in program order; `^` and `$` are the string's edges.
    let tagged = inputs.lines(&["findrefs", &hap, "string", "^testTag$"]);
    let locations: Vec<&str> = tagged.iter().map(|row| row.split(" | ").nth(1).unwrap().split("+0x").next().unwrap()).collect();
    assert_eq!(locations, [format!("{ENTRY_ABILITY}->#~@0>#onCreate"), format!("{INDEX_PAGE}->#*#helper")]);

    // --literal: the text as it is, not a regex.
    assert_eq!(inputs.lines(&["findrefs", &hap, "string", "login?token=", "--literal"]), rows);
    assert!(inputs.lines(&["findrefs", &hap, "string", "login?token="]).is_empty(), "as a regex `?` makes the `n` optional");
    let error = inputs.error(&["findrefs", &hap, "string", "a(b"]);
    assert!(error.starts_with("Error: invalid pattern: "), "{error}");

    // `all` with one condition is that query, in the condition syntax of the DEX side.
    assert_eq!(inputs.lines(&["findrefs", &hap, "all", "string:https?://"]), rows);
    assert_eq!(inputs.lines(&["findrefs", &hap, "all", "literal:login?token="]), rows);

    // -o gets every row, stdout as well.
    let saved = inputs.path("refs.txt");
    assert_eq!(inputs.lines(&["findrefs", &hap, "string", "testTag", "-o", saved.to_str().unwrap()]), tagged);
    assert_eq!(std::fs::read_to_string(&saved).unwrap().lines().collect::<Vec<_>>(), tagged);
}

/// Columns 2..4 of each row: `record->function` (without the pc), the restored name, the text.
fn short_rows(lines: &[String]) -> Vec<String> {
    let short = |line: &String| {
        let columns: Vec<&str> = line.split(" | ").collect();
        assert!(columns.len() >= 4 && columns[0] == "ets/modules.abc", "{line}");
        let location = columns[1].rsplit_once("+0x").map_or(columns[1], |(location, _)| location);
        format!("{} | {} | {}", location.rsplit_once("->").map_or(location, |(_, function)| function), columns[2], columns[3..].join(" | "))
    };
    lines.iter().map(short).collect()
}

#[test]
fn findrefs_prop_and_global_label_the_access() {
    let inputs = Inputs::new();
    let hap = inputs.sample_hap();
    // A load that is called in the same block is a call.
    let called = inputs.lines(&["findrefs", &hap, "prop", "createHttp", "--exact"]);
    assert_eq!(short_rows(&called), ["#~@0>#build | Index.build | ldobjbyname \"createHttp\" [call]"]);
    assert_eq!(inputs.lines(&["findrefs", &hap, "prop", "^createH"]), called);
    assert_eq!(inputs.lines(&["findrefs", &hap, "prop", "eateHtt", "--literal"]), called);
    assert_eq!(inputs.lines(&["findrefs", &hap, "prop", "createHttp", "--exact", "--access", "call"]), called);
    assert_eq!(inputs.lines(&["findrefs", &hap, "all", "prop:=createHttp"]), called);
    // The location column is what getclass takes.
    assert_eq!(functions(&inputs.lines(&["getclass", &hap, called[0].split(" | ").nth(1).unwrap()])), ["#~@0>#build"]);

    assert_eq!(
        short_rows(&inputs.lines(&["findrefs", &hap, "prop", ".", "--access", "write"])),
        [
            "#~@0>#aboutToAppear | Index.aboutToAppear | stobjbyname \"ratio\", a2 [write]",
            "#~@0>#aboutToAppear | Index.aboutToAppear | stobjbyname \"message\", a2 [write]",
        ]
    );
    assert_eq!(inputs.lines(&["findrefs", &hap, "prop", "."]).len(), 5);

    assert_eq!(
        short_rows(&inputs.lines(&["findrefs", &hap, "global", "console", "--exact"])),
        ["#~@0>#build | Index.build | tryldglobalbyname \"console\" [read]"]
    );
    assert_eq!(inputs.lines(&["findrefs", &hap, "global", ".", "--access", "read"]).len(), 1);

    // Nothing found: where the name is something else.
    let out = inputs.run(&["findrefs", &hap, "prop", "console", "--exact"]);
    assert_eq!((stdout(&out).as_str(), out.status.code()), ("", Some(0)));
    assert_eq!(stderr(&out), "hint: =console is a global name, used once: try `findrefs global`\n");
    let out = inputs.run(&["findrefs", &hap, "global", ".", "--access", "write"]);
    assert_eq!((stdout(&out).as_str(), stderr(&out).as_str()), ("", "hint: the global is accessed once in other ways: drop --access\n"));
}

#[test]
fn findrefs_import_lists_declarations_loads_and_requests() {
    let inputs = Inputs::new();
    let hap = inputs.sample_hap();
    let http = inputs.lines(&["findrefs", &hap, "import", "@ohos:net\\.http"]);
    assert_eq!(
        http,
        [
            format!(
                "ets/modules.abc | {INDEX_PAGE} field moduleRecordIdx | - | regular import 0: import {{ default as http }} from \"@ohos:net.http\""
            ),
            format!(
                "ets/modules.abc | {INDEX_PAGE}->#~@0>#build+0x0 | Index.build | ldexternalmodulevar 0  ; import {{ default as http }} from \"@ohos:net.http\""
            ),
        ]
    );
    assert_eq!(inputs.lines(&["findrefs", &hap, "import", "@ohos:net.http", "--literal"]), http);
    assert_eq!(inputs.lines(&["findrefs", &hap, "import", "net#default"]), http);
    assert_eq!(inputs.lines(&["findrefs", &hap, "all", "import:net#default"]), http);
    assert_eq!(inputs.lines(&["findrefs", &hap, "import", "@ohos:net", "--decl"]), http[..1]);
    assert_eq!(inputs.lines(&["findrefs", &hap, "import", "@ohos:", "--decl"]).len(), 3);
    let none = inputs.run(&["findrefs", &hap, "import", "@ohos:#request", "--decl"]);
    assert_eq!(stdout(&none), "");
    assert_eq!(stderr(&none), "hint: `findrefs import . --requests` lists the module requests of the program\n");

    // The modules the program asks for, without reading its code.
    assert_eq!(
        inputs.lines(&["findrefs", &hap, "import", ".", "--requests"]),
        ["@ohos:app.ability.UIAbility | 1 record | default", "@ohos:hilog | 1 record | default", "@ohos:net.http | 1 record | default"]
    );
    let saved = inputs.path("requests.txt");
    assert_eq!(
        inputs.lines(&["findrefs", &hap, "import", "net", "--requests", "-o", saved.to_str().unwrap()]),
        ["@ohos:net.http | 1 record | default"]
    );
    assert_eq!(std::fs::read_to_string(&saved).unwrap(), "@ohos:net.http | 1 record | default\n");
    assert_eq!(
        inputs.lines(&["findrefs", &inputs.two_entry_hap(), "import", "net", "--requests"]),
        ["ets/modules.abc | @ohos:net.http | 1 record | default", "ets/widgets.abc | @ohos:net.http | 1 record | default"]
    );

    // A module request is not a string operand: the string search says where to look.
    let out = inputs.run(&["findrefs", &hap, "string", "@ohos:net.http", "--literal"]);
    assert_eq!(stdout(&out), "");
    assert_eq!(
        stderr(&out),
        "hint: 1 module request matches (e.g. @ohos:net.http): imports are not string operands, try `findrefs import`\n"
    );
}

#[test]
fn findrefs_method_and_number_find_definitions_and_constants() {
    let inputs = Inputs::new();
    let hap = inputs.sample_hap();
    let build = inputs.lines(&["findrefs", &hap, "method", "Index.build", "--exact"]);
    let [row] = &build[..] else { panic!("one definition expected: {build:?}") };
    assert!(row.starts_with(&format!("ets/modules.abc | {INDEX_PAGE}->func_main_0+0x")), "{row}");
    assert!(
        row.contains(" | func_main_0 | defineclasswithbuffer literal@0x") && row.ends_with(" [1]=method #~@0>#build (Index.build)"),
        "{row}"
    );
    // The raw name, a result row's location, a dotted suffix, --class for the record.
    for name in ["#~@0>#build", &format!("{INDEX_PAGE}->#~@0>#build"), &format!("{INDEX_PAGE}->#~@0>#build+0x12"), "build"] {
        assert_eq!(inputs.lines(&["findrefs", &hap, "method", name, "--exact"]), build, "{name}");
    }
    assert_eq!(inputs.lines(&["findrefs", &hap, "method", "build", "--exact", "--class", "pages/Index"]), build);
    assert!(inputs.lines(&["findrefs", &hap, "method", "build", "--exact", "--class", "entryability/EntryAbility"]).is_empty());
    assert_eq!(
        short_rows(&inputs.lines(&["findrefs", &hap, "method", "^help"])),
        ["func_main_0 | func_main_0 | definefunc #*#helper, 1  ; helper"]
    );
    assert_eq!(inputs.lines(&["findrefs", &hap, "all", "method:=helper"]).len(), 1);
    let out = inputs.run(&["findrefs", &hap, "method", "createHttp"]);
    assert_eq!(
        stderr(&out),
        "hint: no function is defined under that name, but it is a property name, used once: try `findrefs prop` (--access call for its calls)\n"
    );

    let magic = inputs.lines(&["findrefs", &hap, "number", "0x1d4b42"]);
    assert_eq!(short_rows(&magic), ["#~@0>#build | Index.build | ldai 0x1d4b42 (1919810)"]);
    assert_eq!(inputs.lines(&["findrefs", &hap, "number", "1919810"]), magic);
    assert_eq!(inputs.lines(&["findrefs", &hap, "number", "1919000..1920000"]), magic);
    assert_eq!(inputs.lines(&["findrefs", &hap, "all", "number:1919810"]), magic);
    assert_eq!(short_rows(&inputs.lines(&["findrefs", &hap, "number", "1.5"])), ["#~@0>#aboutToAppear | Index.aboutToAppear | fldai 1.5"]);
    // 2 is an item of the array literal, and not the method count of a class literal or a cache slot.
    let two = inputs.lines(&["findrefs", &hap, "number", "2"]);
    assert_eq!(two.len(), 1, "{two:?}");
    assert!(two[0].contains(" | Index.build | createarraywithbuffer literal@0x") && two[0].ends_with(" [2]=2"), "{two:?}");
    // A negative number is a value, not an option.
    assert!(inputs.lines(&["findrefs", &hap, "number", "-1"]).is_empty());
    assert_eq!(inputs.lines(&["findrefs", &hap, "number", "-5..1"]).len(), 1);
    let error = inputs.error(&["findrefs", &hap, "number", "twelve"]);
    assert!(error.starts_with("Error: \"twelve\" is not a number: "), "{error}");
}

#[test]
fn findrefs_call_resolves_callees_and_arguments() {
    let inputs = Inputs::new();
    let hap = inputs.sample_hap();
    assert_eq!(
        short_rows(&inputs.lines(&["findrefs", &hap, "call", "."])),
        [
            "#~@0>#onCreate | EntryAbility.onCreate | callthis3 v0, v2, v3, v4 ; import:@ohos:hilog#default.info(1, \"testTag\", \"Ability onCreate\")".to_owned(),
            format!("#~@0>#build | Index.build | callthis1 v0, v2 ; import:@ohos:net.http#default.createHttp(\"{SAMPLE_API_URL}\")"),
            // The catch handler is its own block: what it loads there is known there.
            "#~@0>#build | Index.build | callthis1 v0, v2 ; global:console.error(\"request failed\")".to_owned(),
        ]
    );
    let http = inputs.lines(&["findrefs", &hap, "call", "^import:@ohos:net\\.http.*\\.createHttp$"]);
    assert_eq!(http.len(), 1);
    // The path of a row, pasted back as plain text.
    assert_eq!(inputs.lines(&["findrefs", &hap, "call", "import:@ohos:net.http#default.createHttp", "--literal"]), http);
    assert_eq!(inputs.lines(&["findrefs", &hap, "all", "call:^import:@ohos:net"]), http);
    assert_eq!(inputs.lines(&["findrefs", &hap, "call", "^global:console\\."]).len(), 1);

    // Several conditions: the functions all of them match in, one row each.
    let both = inputs.lines(&["findrefs", &hap, "all", "string:^https://", "call:createHttp", "number:0x1d4b42"]);
    let [row] = &both[..] else { panic!("one function expected: {both:?}") };
    assert!(row.starts_with(&format!("ets/modules.abc | {INDEX_PAGE}->#~@0>#build+0x")), "{row}");
    let text = row.split(" | ").nth(3).unwrap();
    let parts: Vec<&str> = text.split(" && ").collect();
    assert_eq!(parts.len(), 3, "{row}");
    assert!(parts[0].starts_with("string +0x") && parts[0].ends_with(&format!("lda.str \"{SAMPLE_API_URL}\"")), "{row}");
    assert!(parts[1].starts_with("call +0x") && parts[1].contains("import:@ohos:net.http#default.createHttp("), "{row}");
    assert!(parts[2].starts_with("number +0x") && parts[2].ends_with("ldai 0x1d4b42 (1919810)"), "{row}");
    assert_eq!(functions(&inputs.lines(&["getclass", &hap, row.split(" | ").nth(1).unwrap()])), ["#~@0>#build"]);
    assert!(inputs.lines(&["findrefs", &hap, "all", "string:^https://", "global:=hilog"]).is_empty());
    assert!(inputs.lines(&["findrefs", &hap, "all", "string:testTag", "call:createHttp"]).is_empty());

    let out = inputs.run(&["findrefs", &hap, "call", "createhttp"]);
    assert!(stderr(&out).starts_with("hint: a call is matched by its callee path (import:REQUEST#NAME.member, "), "{}", stderr(&out));
}

/// The rows of a call graph with the record names of the call graph program
/// shortened to their last path segment.
fn short_tree(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .map(|line| {
            let mut line = line.clone();
            for (record, name) in [(CALLS_APP, "App"), (CALLS_UTIL, "Util"), (CALLS_INDEX, "Index"), (CALLS_BOX, "Box")] {
                line = line.replace(&format!("{record}->"), &format!("{name}->"));
            }
            line.replace("@normalized:N&&&entry/src/main/ets/", "N:")
        })
        .collect()
}

#[test]
fn callgraph_walks_callees() {
    let inputs = Inputs::new();
    let abc = inputs.file("modules.abc", &call_graph_program().build().bytes);
    let callees = inputs.lines(&["callgraph", &abc, "pages/App", "run", "--callees", "--depth", "1"]);
    assert_eq!(
        short_tree(&callees),
        [
            "0 App->#*#run | run unresolved=1",
            "  1 -> Util->#*#helper | helper x3",
            "  1 -> Box->#~@0<#make | Box.make",
            "  1 -> Box->#~@0=#Box | Box.constructor [new]",
            "  1 -> Box->#~@0>#get | Box.get",
            "  1 -> Util->#*#star | star",
            "  1 -> import:@ohos:net.http#default.createHttp [external]",
            "  1 -> import:N:missing/Gone&#gone [external]",
            "  1 -> App->#*@0*#cb | run.cb [defines]",
            "  1 -> import:N:lib/Index&#Box.nothing [unlinked]",
            "# 10 rows, 7 distinct functions, 3 leaves (callees, depth 1); 1 records scanned",
        ]
    );
    // The root as a row prints it, with or without the offset of an instruction, and by its name alone.
    let location = format!("{CALLS_APP}->#*#run");
    for root in [&[location.as_str()][..], &[&format!("{location}+0x1c")], &["run"], &[CALLS_APP, "#*#run"]] {
        let mut argv = vec!["callgraph", abc.as_str(), "--callees", "--depth", "1"];
        argv.extend(root);
        assert_eq!(inputs.lines(&argv), callees, "{root:?}");
    }

    // The default depth is 2; `this.size()` is matched by name in the class.
    let deeper = short_tree(&inputs.lines(&["callgraph", &abc, "pages/App", "run", "--callees"]));
    assert!(deeper.contains(&"    2 -> Box->#~@0>#size | Box.size [this-class]".to_owned()), "{deeper:?}");
    assert!(deeper.contains(&"    2 -> global:console.log [external]".to_owned()), "{deeper:?}");
    assert!(deeper.last().unwrap().contains("(callees, depth 2)"), "{deeper:?}");

    // Unresolved call sites are counted, and listed on request; closures can be left out.
    let listed = short_tree(&inputs.lines(&["callgraph", &abc, "pages/App", "run", "--callees", "--depth", "1", "--unresolved"]));
    assert_eq!(listed.len(), callees.len() + 1);
    assert_eq!(listed[8], "  1 -> arg0.then [unresolved]");
    let plain = short_tree(&inputs.lines(&["callgraph", &abc, "pages/App", "run", "--callees", "--depth", "1", "--no-defines"]));
    assert_eq!(plain.len(), callees.len() - 1);
    assert!(!plain.iter().any(|line| line.contains("[defines]") || line.contains("cb")), "{plain:?}");

    // -o takes the tree instead of stdout.
    let saved = inputs.path("tree.txt");
    assert!(inputs.lines(&["callgraph", &abc, "pages/App", "run", "--callees", "--depth", "1", "-o", saved.to_str().unwrap()]).is_empty());
    assert_eq!(std::fs::read_to_string(&saved).unwrap().lines().collect::<Vec<_>>(), callees);
}

#[test]
fn callgraph_walks_callers_and_callee_paths() {
    let inputs = Inputs::new();
    let abc = inputs.file("modules.abc", &call_graph_program().build().bytes);
    let callers = short_tree(&inputs.lines(&["callgraph", &abc, "star"]));
    assert_eq!(
        callers,
        [
            "0 Util->#*#star | star",
            "  1 <- App->#*#run | run unresolved=1",
            "    2 <- App->func_main_0 | func_main_0 x2",
            "  1 <- Util->func_main_0 | func_main_0 [defines]",
            "  1 <- Util->#*#helper | helper",
            "    2 <- App->#*#run | run x3 unresolved=1 (repeated)",
            "    2 <- App->#*@0*#cb | run.cb",
            "    2 <- Util->func_main_0 | func_main_0 [defines]",
            "# 8 rows, 6 distinct functions, 0 leaves (callers, depth 2); 3 records scanned",
        ]
    );
    let without = short_tree(&inputs.lines(&["callgraph", &abc, "star", "--no-defines"]));
    assert!(without.len() == 7 && !without.iter().any(|line| line.contains("[defines]")), "{without:?}");
    assert_eq!(short_tree(&inputs.lines(&["callgraph", &abc, "util/Util", "helper", "--depth", "0"]))[0], "0 Util->#*#helper | helper");
    let capped = inputs.lines(&["callgraph", &abc, "util/Util", "helper", "--depth", "3", "--max-nodes", "2"]);
    assert_eq!(capped.len(), 3, "{capped:?}");
    assert!(capped[2].ends_with("; truncated (raise max_nodes or lower depth)"), "{capped:?}");

    // A callee path is a root: the callers of a system API.
    let http = ["callgraph", &abc, "--to", "call:^import:@ohos:net\\.http", "--depth", "3"];
    assert_eq!(
        short_tree(&inputs.lines(&http)),
        [
            "0 import:@ohos:net.http#default.createHttp [external]",
            "  1 <- App->#*#run | run unresolved=1",
            "    2 <- App->func_main_0 | func_main_0 x2",
            "# 3 rows, 2 distinct functions, 1 leaves (callers, depth 3); 4 records scanned",
        ]
    );
    // Unresolved paths are roots as well.
    assert_eq!(
        short_tree(&inputs.lines(&["callgraph", &abc, "--to", "call:^arg0\\.then$", "--depth", "1"]))[..2],
        ["0 arg0.then [unresolved]", "  1 <- App->#*#run | run unresolved=1"]
    );
    // --from keeps the paths that start at the functions it names.
    let from = short_tree(&inputs.lines(&["callgraph", &abc, "star", "--depth", "3", "--from", "method:=cb"]));
    assert_eq!(
        from,
        [
            "0 Util->#*#star | star",
            "  1 <- Util->#*#helper | helper",
            "    2 <- App->#*@0*#cb | run.cb [from]",
            "# 3 rows, 3 distinct functions, 0 leaves (callers, depth 3); 3 records scanned; 1 from functions reached",
        ]
    );
    // A rule about the code works the same: `run` is the function with `p.then()`, and a path ends there.
    let by_code = short_tree(&inputs.lines(&["callgraph", &abc, "star", "--depth", "3", "--from", "prop:=then"]));
    assert_eq!(by_code[1], "  1 <- App->#*#run | run unresolved=1 [from]");
    assert!(!by_code.iter().any(|line| line.contains("App->func_main_0")), "{by_code:?}");
    // --unless leaves functions out, with what only they reach (repeatable).
    assert_eq!(
        short_tree(&inputs.lines(&["callgraph", &abc, "star", "--unless", "method:=helper"])),
        [
            "0 Util->#*#star | star",
            "  1 <- App->#*#run | run unresolved=1",
            "    2 <- App->func_main_0 | func_main_0 x2",
            "  1 <- Util->func_main_0 | func_main_0 [defines]",
            "# 4 rows, 4 distinct functions, 0 leaves (callers, depth 2); 3 records scanned; 1 functions left out by unless",
        ]
    );
    let fenced = ["callgraph", &abc, "star", "--unless", "global:=console & prop:=log", "--unless", "method:^func_main"];
    assert_eq!(
        short_tree(&inputs.lines(&fenced)),
        [
            "0 Util->#*#star | star",
            "  1 <- App->#*#run | run unresolved=1",
            "# 2 rows, 2 distinct functions, 0 leaves (callers, depth 2); 3 records scanned; 3 functions left out by unless",
        ]
    );
    // --to takes any rule: the functions it matches are the roots; --from alone walks callees.
    assert_eq!(
        short_tree(&inputs.lines(&["callgraph", &abc, "--to", "prop:=log", "--depth", "1", "--no-defines"])),
        [
            "0 Util->#*#helper | helper",
            "  1 <- App->#*#run | run x3 unresolved=1",
            "  1 <- App->#*@0*#cb | run.cb",
            "# 3 rows, 3 distinct functions, 0 leaves (callers, depth 1); 3 records scanned",
        ]
    );
    assert_eq!(
        short_tree(&inputs.lines(&["callgraph", &abc, "--from", "method:=cb", "--depth", "1"])),
        [
            "0 App->#*@0*#cb | run.cb",
            "  1 -> Util->#*#helper | helper",
            "# 2 rows, 2 distinct functions, 0 leaves (callees, depth 1); 1 records scanned",
        ]
    );
    let out = inputs.run(&["callgraph", &abc, "--to", "prop:=nowhere"]);
    assert_eq!((out.status.code(), stderr(&out).as_str()), (Some(1), "Error: no function matches the root rule\n"));
    let nowhere = inputs.lines(&["callgraph", &abc, "star", "--from", "method:=make"]);
    assert_eq!(nowhere.len(), 2, "{nowhere:?}");
    assert!(nowhere[1].starts_with("# from: none of the 6 callers walked matches (depth 2); a path ends where "), "{nowhere:?}");

    // A pattern no callee path matches says where the paths are listed.
    let out = inputs.run(&["callgraph", &abc, "--to", "call:createhttp"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out), "# 0 rows, 0 distinct functions, 0 leaves (callers, depth 2); 4 records scanned\n");
    assert!(
        stderr(&out).starts_with("hint: no call site has a callee path matching call:createhttp: the paths are what findrefs call prints")
    );

    // A function nothing is seen to call says why that may be.
    let out = inputs.run(&["callgraph", &abc, "pages/App", "func_main_0"]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out).lines().count(), 2, "{}", stdout(&out));
    assert_eq!(
        stderr(&out),
        "hint: no caller was resolved: a function the system calls (a lifecycle or event callback) or one reached only through a value \
         (a property, an argument) has none; `findrefs prop NAME --exact --access call` lists call sites by member name\n"
    );

    // The window of the other commands.
    let paged = inputs.lines(&["callgraph", &abc, "star", "--limit", "3", "--spill-mb", "0"]);
    assert_eq!(short_tree(&paged)[..3], callers[..3]);
    assert_eq!(paged[3..], [callers[8].as_str(), "# records 1-3 of 8 shown; rerun with --offset 3"]);
    assert_eq!(short_tree(&inputs.lines(&["callgraph", &abc, "star", "--offset", "3"])), callers[3..]);
}

/// The rows of a hierarchy with the record names of the class hierarchy
/// program shortened to their last path segment.
fn short_classes(lines: &[String]) -> Vec<String> {
    lines.iter().map(|line| line.replace(&format!("{CLASSES_APP}->"), "App->").replace(&format!("{CLASSES_BASE}->"), "Base->")).collect()
}

#[test]
fn hierarchy_walks_subclasses_and_supertypes() {
    let inputs = Inputs::new();
    let abc = inputs.file("modules.abc", &class_hierarchy_program().build().bytes);
    let local = inputs.lines(&["hierarchy", &abc, "Local"]);
    assert_eq!(
        short_classes(&local),
        [
            "0 App->#~@1=#Local | Local",
            "  1 subclass App->#~@2=#Child | Child",
            "    2 subclass App->#~@3=#GrandChild | GrandChild",
            "  1 subclass App->#*@e~@9=#Inner | make.Inner",
            "# 4 rows, 4 distinct classes, 0 leaves (subclasses, depth 16); 3 records scanned",
        ]
    );
    // The root as a row prints it, by a path of its record, by the raw name of its constructor.
    for root in [format!("{CLASSES_APP}->#~@1=#Local"), "pages/App->Local".to_owned(), "#~@1=#Local".to_owned()] {
        assert_eq!(inputs.lines(&["hierarchy", &abc, &root]), local, "{root}");
    }
    assert_eq!(inputs.lines(&["hierarchy", &abc, "Local", "--depth", "1"]).len(), 4);
    let small = inputs.lines(&["hierarchy", &abc, "Local", "--max-nodes", "2"]);
    assert!(small.len() == 3 && small[2].ends_with("; truncated (raise max_nodes or lower depth)"), "{small:?}");

    // A parent outside the program, by its path or by a name no class of the program has; the method each subclass defines.
    let ability = inputs.lines(&["hierarchy", &abc, "import:@ohos:app\\.ability\\.UIAbility", "--method", "onCreate"]);
    assert_eq!(
        short_classes(&ability),
        [
            "0 import:@ohos:app.ability.UIAbility#default [external]",
            "  1 subclass App->#~@0=#EntryAbility | EntryAbility [defines #~@0>#onCreate]",
            "override App->#~@0>#onCreate | EntryAbility.onCreate",
            "# 2 rows, 1 distinct classes, 1 leaves (subclasses, depth 16); 3 records scanned; 1 subclasses define onCreate",
        ]
    );
    let by_name = inputs.lines(&["hierarchy", &abc, "UIAbility", "--method", "onCreate"]);
    assert_eq!(by_name[..4], ability[..]);
    assert_eq!(by_name[4], "# no class of the program has that name: the roots are the parent paths that contain it");
    // What a `defines` row names is a function `getclass` prints.
    let method = ability[2].strip_prefix("override ").and_then(|rest| rest.split(" | ").next()).unwrap();
    assert_eq!(inputs.lines(&["getclass", &abc, method])[0], ".function #~@0>#onCreate  ; EntryAbility.onCreate");

    // Across records, through a binding a decorator reassigns; and a parent that tracking lost.
    let card = short_classes(&inputs.lines(&["hierarchy", &abc, "Card", "--supers"]));
    assert_eq!(
        card,
        [
            "0 App->#~@5=#Card | Card",
            "  1 extends Base->#~@1=#Watched | Watched [no superclass] [reassigned]",
            "# 2 rows, 2 distinct classes, 0 leaves (supers, depth 16); 2 records scanned",
        ]
    );
    let run = short_classes(&inputs.lines(&["hierarchy", &abc, "GrandChild", "--supers", "--method", "run"]));
    assert_eq!(run[3..5], ["inherited App->#~@2>#run | Child.run", "inherited App->#~@1>#run | Local.run"]);
    assert_eq!(short_classes(&inputs.lines(&["hierarchy", &abc, "Mixed", "--supers"]))[1], "  1 extends arg0 [unresolved]");
    assert_eq!(
        short_classes(&inputs.lines(&["hierarchy", &abc, "Shared", "--supers"]))[0],
        "0 App->#~@c=#Shared | Shared [sendable] [no superclass]"
    );

    // -o takes the tree instead of stdout.
    let saved = inputs.path("tree.txt");
    assert!(inputs.lines(&["hierarchy", &abc, "Local", "-o", saved.to_str().unwrap()]).is_empty());
    assert_eq!(std::fs::read_to_string(&saved).unwrap().lines().collect::<Vec<_>>(), local);

    // A program of two entries: a name alone is every class of that name, and --entry picks one.
    let dir = inputs.path("two");
    for name in ["a.abc", "b.abc"] {
        inputs.file(&format!("two/{name}"), &class_hierarchy_program().build().bytes);
    }
    let dir = dir.to_str().unwrap();
    let both = short_classes(&inputs.lines(&["hierarchy", dir, "GrandChild", "--supers", "--depth", "1"]));
    assert_eq!(both[0], "0 App->#~@3=#GrandChild | GrandChild [a.abc]");
    assert_eq!(both[2], "0 App->#~@3=#GrandChild | GrandChild [b.abc]");
    let one = short_classes(&inputs.lines(&["hierarchy", dir, "GrandChild", "--supers", "--depth", "1", "--entry", "b.abc"]));
    assert_eq!(one[0], "0 App->#~@3=#GrandChild | GrandChild");
    assert!(one[2].ends_with("; all in b.abc"), "{one:?}");
    let ambiguous = inputs.error(&["hierarchy", dir, "pages/App->Local"]);
    assert!(ambiguous.ends_with("(name the entry, the first column, with --entry)\n"), "{ambiguous}");
}

#[test]
fn callgraph_names_the_entry_only_where_it_tells_rows_apart() {
    let inputs = Inputs::new();
    // One record in two entries: the root is ambiguous until the entry is named.
    let two = inputs.two_entry_hap();
    let error = inputs.error(&["callgraph", &two, "pages/Index", "Index.build", "--callees"]);
    assert!(error.starts_with("Error: record pages/Index is ambiguous, candidates:\n"), "{error}");
    assert!(error.ends_with("(name the entry, the first column, with --entry)\n"), "{error}");
    let tree = inputs.lines(&["callgraph", &two, "pages/Index", "Index.build", "--callees", "--entry", "ets/widgets.abc"]);
    assert_eq!(tree[0], format!("0 {INDEX_PAGE}->#~@0>#build | Index.build"));
    assert!(tree.last().unwrap().ends_with("; all in ets/widgets.abc"), "{tree:?}");
    // By name alone both are roots, and each row says which it is.
    let both = inputs.lines(&["callgraph", &two, "Index.build", "--callees", "--depth", "0"]);
    assert_eq!(
        both[..2],
        [
            format!("0 {INDEX_PAGE}->#~@0>#build | Index.build [ets/modules.abc]"),
            format!("0 {INDEX_PAGE}->#~@0>#build | Index.build [ets/widgets.abc]")
        ]
    );

    // An entry that cannot be read is named, and the status says the walk was partial.
    let store = inputs.store_hap("store.hap");
    let out = inputs.run(&["callgraph", &store, "Index.build", "--callees", "--depth", "1"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(stdout(&out).starts_with(&format!("0 {INDEX_PAGE}->#~@0>#build | Index.build")), "{}", stdout(&out));
    assert!(!stdout(&out).contains("encrypted"), "{}", stdout(&out));
    assert!(
        stderr(&out).contains("encrypted") && stderr(&out).ends_with("Warning: 1 ABC entry could not be searched\n"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn what_is_not_supported_yet_says_what_is() {
    let inputs = Inputs::new();
    let hap = inputs.sample_hap();
    let classes = "(a class is named as rows print it, RECORD->CLASS, or by its name alone; a parent outside the program by \
                   import:REGEX or global:REGEX over its path; findrefs method NAME lists the functions of a name, constructors among them)";
    let walks = "(callgraph takes: [RECORD] FUNCTION or --to RULE, --from RULE, --unless RULE, --callees, --depth, --max-nodes, \
                 --no-defines, --unresolved, --entry; RECORD->FUNCTION as result rows print it is a target too)";
    let no_rule = "bad rule \"type:x\": unknown kind \"type\": use one of string, literal, prop, global, import, method, number, call \
                   at column 1";
    let searches = "(supported: findrefs string, prop, global, import, method, number, call, all, rules)";
    let conditions = "(supported: string:, literal:, prop:, global:, import:, method:, number:, call:)";
    let not_yet = "is not supported for HarmonyOS programs yet";
    let cases: [(&[&str], String); 51] = [
        (
            &["getmanifest", "--resolve"],
            "getmanifest --resolve is DEX-only: module.json is printed as it is; manifest-summary puts what a $type:name reference \
             stands for behind it"
                .into(),
        ),
        (
            &["getmanifest", "--file", "AndroidManifest.xml"],
            "--file: \"AndroidManifest.xml\" is not a manifest document: use module.json, pack.info, pkgContextInfo.json".into(),
        ),
        (&["manifest-summary", "--file", "pkgContextInfo.json"], format!("no pkgContextInfo.json in {hap}")),
        (&["manifest-summary", "--json", "--file", "pack.info"], "--json is the whole summary: leave out --file".into()),
        (&["resources", "string/nothing"], "resource string/nothing not found (--search REGEX finds resources by name or value)".into()),
        (
            &["resources", "0x7f010000", "--resolve"],
            "resource 0x7f010000 not found (--search REGEX finds resources by name or value)".into(),
        ),
        (
            &["resources", "label"],
            "\"label\" is not a resource: give an id (0x01000003, 16777219) or a name (string/app_name, $string:app_name, \
             app.string.app_name)"
                .into(),
        ),
        (&["resources", "layout/main"], "layout/main: unknown resource type \"layout\"".into()),
        (&["resources", "--search", "x", "--in", "both"], "--in must be name, value or any, not both".into()),
        (&["resources", "--search", "("], "invalid pattern: regex parse error:\n    (\n    ^\nerror: unclosed group".into()),
        (
            &["xml", "res/xml/a.xml"],
            "file res/xml/a.xml not found (give a path inside the package, e.g. resources/base/profile/main_pages.json, or a file \
             resource: $profile:main_pages)"
                .into(),
        ),
        (&["xml", "$profile:nothing"], "resource $profile:nothing not found (--search REGEX finds resources by name or value)".into()),
        (&["xml", "$media:icon"], "entry.hap: resources/base/media/icon.png is not text (8 bytes): only text files are printed".into()),
        (&["hierarchy", "Nowhere"], format!("class Nowhere not found {classes}")),
        (&["hierarchy", "pages/Index->Nowhere"], format!("class pages/Index->Nowhere not found {classes}")),
        (&["hierarchy", "import:@ohos:nothing"], format!("parent path import:@ohos:nothing not found {classes}")),
        (&["hierarchy", "pages/Nope->Index"], "record pages/Nope not found".into()),
        (
            &["hierarchy", "import:@ohos:app", "--supers"],
            "a parent path outside the program has no supertypes here: it is a root for subclasses only".into(),
        ),
        (&["callgraph", "pages/Index", "build", "--virtual"], "--virtual is DEX-only".into()),
        (&["callgraph", "pages/Index", "build", "--unless", "type:x"], format!("--unless: {no_rule}")),
        (&["callgraph", "--to", "type:x"], format!("--to: {no_rule}")),
        (&["callgraph", "--to", "call:("], "--to: invalid pattern: regex parse error:\n    (\n    ^\nerror: unclosed group".into()),
        (&["callgraph", "--to", "call:x", "--callees"], "--to call:PATTERN walks the callers of a callee path: leave out --callees".into()),
        (
            &["callgraph", "--to", "call:x", "--entry", "ets/modules.abc"],
            "--entry picks the root function: it does not go with --to".into(),
        ),
        (&["callgraph", "pages/Index", "--to", "call:x"], "give the target as [RECORD] FUNCTION or as --to RULE, not both".into()),
        (&["callgraph"], format!("callgraph needs a target {walks}")),
        (&["callgraph", "pages/Index", "build", "--unresolved"], "--unresolved lists callees: add --callees".into()),
        (
            &["callgraph", "pages/Index", "build", "--callees", "--from", "method:x"],
            "--from keeps caller paths: leave out --callees".into(),
        ),
        (&["callgraph", "pages/Index", "build", "--from", "type:x"], format!("--from: {no_rule}")),
        (
            &["callgraph", "pages/Index", "build", "--from", "!string:x"],
            "--from: a rule needs a condition without `!` (`!` only removes functions)".into(),
        ),
        (
            &["callgraph", "pages/Index", "nowhere"],
            format!("function nowhere of {INDEX_PAGE} not found (`findrefs method NAME` lists the functions a name defines)"),
        ),
        (&["callgraph", "pages/Nope", "build"], "record pages/Nope not found".into()),
        (&["findrefs", "method", "build", "--fuzzy-class", "--class", "Index"], "--fuzzy-class is DEX-only".into()),
        (&["findrefs", "method"], "findrefs method needs a function name on a HarmonyOS program".into()),
        (&["findrefs", "field", "message"], format!("findrefs field {not_yet} {searches}")),
        (&["findrefs", "type", "Index"], format!("findrefs type {not_yet} {searches}")),
        (&["findrefs", "extends", "Index"], format!("findrefs extends {not_yet} {searches}")),
        (&["findrefs", "rules"], "findrefs rules needs at least one rule".into()),
        (&["findrefs", "rules", "string:a & type:Index"], format!("findrefs type: {not_yet} {conditions}")),
        (&["findrefs", "rules", "--file", "nowhere.txt"], "cannot read nowhere.txt: No such file or directory (os error 2)".into()),
        (&["findrefs", "all", "!string:b"], "a rule needs a condition without `!` (`!` only removes functions)".into()),
        (&["findrefs", "all", "string:a", "--none", "type:Index"], format!("findrefs type: {not_yet} {conditions}")),
        (&["findrefs", "all", "string:a & prop:b"], "\"string:a & prop:b\" is several conditions; give one KIND:VALUE here".into()),
        (&["findrefs", "all", "call:{string:a"], "bad rule \"call:{string:a\": expected `}` at column 15".into()),
        (&["findrefs", "call", "{@nowhere.txt}"], "cannot read function list nowhere.txt: No such file or directory (os error 2)".into()),
        (&["findrefs", "all", "type:Index"], format!("findrefs type: {not_yet} {conditions}")),
        (&["findrefs", "all", "prop:"], "bad rule \"prop:\": empty value at column 6".into()),
        (
            &["findrefs", "string", "token", "--access", "read"],
            "--access is only valid for `findrefs prop` and `findrefs global` on HarmonyOS programs".into(),
        ),
        (
            &["findrefs", "global", "console", "--access", "call"],
            "a global is read or written, not call: use `prop` or `call` for members".into(),
        ),
        (&["findrefs", "import", "@ohos:net.http#default", "--requests"], "--requests lists module requests: leave out the #NAME".into()),
        (&["getclass", "pages/Index", "--dump-dex", "out.dex"], "--dump-dex is DEX-only".into()),
    ];
    for (args, expected) in cases {
        // The program follows the command (and the findrefs kind follows the program).
        let mut argv = vec![args[0], hap.as_str()];
        argv.extend(&args[1..]);
        assert_eq!(inputs.error(&argv), format!("Error: {expected}\n"), "{argv:?}");
    }
    assert!(!inputs.path("out.dex").exists());
}

/// The package table of the sample module, plus a library.
const PKG_CONTEXT: &str = r#"{
  "entry": {"packageName": "entry", "bundleName": "", "moduleName": "", "version": "", "entryPath": "src/main/", "isSO": false, "dependencyAlias": ""},
  "@ohos/lib": {"packageName": "@ohos/lib", "bundleName": "", "moduleName": "", "version": "1.0.0", "entryPath": "Index.ets", "isSO": false, "dependencyAlias": ""}
}"#;

#[test]
fn manifest_summary_joins_each_component_to_its_record() {
    let inputs = Inputs::new();
    let hap = inputs.sample_hap();
    let summary = inputs.lines(&["manifest-summary", &hap]);
    assert_eq!(
        summary,
        [
            "bundle com.example.sample bundleType=- versionCode=1000000 versionName=1.0.0 vendor=example debug=- minAPIVersion=50000012(12) targetAPIVersion=50000012(12) apiReleaseType=- compileSdkType=- compileSdkVersion=- buildMode=-",
            "module entry type=entry packageName=- mainElement=EntryAbility srcEntry=- deviceTypes=phone virtualMachine=- compileMode=- installationFree=- deliveryWithInstall=- process=- pages=$profile:main_pages(resources/base/profile/main_pages.json)",
            "abc ets/modules.abc version=12.0.6.0 bytes=1928 status=readable",
            "request-permission ohos.permission.INTERNET reason=- when=- abilities=-",
            "ability EntryAbility exported=true (explicit) permissions=- skills=1 srcEntry=./ets/entryability/EntryAbility.ets record=&entry/src/main/ets/entryability/EntryAbility&",
            "callbacks EntryAbility record=&entry/src/main/ets/entryability/EntryAbility& functions=EntryAbility.onCreate",
            "skill EntryAbility skill=1 actions=action.system.home entities=entity.system.home uris=1 permissions=-",
            "uri EntryAbility skill=1 scheme=sample host=open",
            "deeplink EntryAbility sample://open",
            "page pages/Index record=&entry/src/main/ets/pages/Index&",
            "pack-app com.example.sample bundleType=- versionCode=1000000 versionName=1.0.0",
            "pack-module entry type=entry mainAbility=EntryAbility deviceTypes=phone installationFree=- deliveryWithInstall=true apiCompatible=- apiTarget=- apiReleaseType=-",
            "pack-ability entry EntryAbility label=$string:EntryAbility_label(\"Sample\")",
            "pack-package entry-default moduleType=entry deviceTypes=phone deliveryWithInstall=true",
        ]
    );
    // What the summary names is what getclass takes: the record, and a callback of it.
    let field = |line: &str, key: &str| line.split(' ').find_map(|word| word.strip_prefix(key)).unwrap().to_owned();
    let (record, callback) = (field(&summary[5], "record="), field(&summary[5], "functions="));
    assert_eq!(record, ENTRY_ABILITY);
    assert_eq!(functions(&inputs.lines(&["getclass", &hap, &record, "--method", &callback])), ["#~@0>#onCreate"]);

    // The alias, one document, -o and --json.
    assert_eq!(inputs.lines(&["manifest_summary", &hap]), summary);
    assert_eq!(inputs.lines(&["manifest-summary", &hap, "--file", "pack.info"]), summary[10..]);
    assert_eq!(inputs.lines(&["manifest-summary", &hap, "--file", "module"]), summary[..10]);
    // A page's record is what getclass takes, too.
    assert_eq!(field(&summary[9], "record="), INDEX_PAGE);
    let saved = inputs.path("summary.txt");
    assert_eq!(inputs.lines(&["manifest-summary", &hap, "-o", saved.to_str().unwrap()]), summary);
    assert_eq!(std::fs::read_to_string(&saved).unwrap().lines().collect::<Vec<_>>(), summary);
    assert_eq!(inputs.lines(&["manifest-summary", &hap, "--limit", "2", "--offset", "3"])[..2], summary[3..5]);
    let json: serde_json::Value = serde_json::from_str(&inputs.lines(&["manifest-summary", &hap, "--json"]).join("\n")).unwrap();
    let component = &json["packages"][0]["components"][0];
    assert_eq!((component["name"].as_str(), component["record"].as_str()), (Some("EntryAbility"), Some(ENTRY_ABILITY)));
    assert_eq!(component["callbacks"][0], "EntryAbility.onCreate");

    // The package table: a line in the summary, the table itself on request.
    let table = Hap::new().modules_abc(&make_abc()).module_json(SAMPLE_MODULE_JSON).entry(
        "pkgContextInfo.json",
        PKG_CONTEXT.as_bytes(),
        Compression::Stored,
    );
    let with_table = inputs.file("table.hap", &table.build());
    assert_eq!(
        inputs.lines(&["manifest-summary", &with_table]).last().unwrap(),
        "package-table packages=2 native=0 with-records=1 records=2 unlocated=0 file=pkgContextInfo.json"
    );
    assert_eq!(
        inputs.lines(&["manifest-summary", &with_table, "--file", "pkgContextInfo.json"]),
        [
            "package @ohos/lib version=1.0.0 entryPath=Index.ets isSO=false bundleName=- moduleName=- dependencyAlias=- records=0",
            "package entry version=- entryPath=src/main/ isSO=false bundleName=- moduleName=- dependencyAlias=- records=2",
        ]
    );
}

const LABEL: &str = "0x01000000 string/EntryAbility_label [base] \"Sample\"";
const LABEL_ZH: &str = "0x01000000 string/EntryAbility_label [zh_CN] \"示例\"";
const BRAND: &str = "0x01000003 color/brand [base] \"#FF0000\"";

#[test]
fn resources_lists_looks_up_and_searches_the_index() {
    let inputs = Inputs::new();
    let hap = inputs.sample_hap();
    let all = inputs.lines(&["resources", &hap]);
    assert_eq!(
        all,
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
    // One resource, however it is spelled; --resolve follows the references of its value.
    for query in ["0x01000000", "16777216", "string/EntryAbility_label", "$string:EntryAbility_label", "app.string.EntryAbility_label"] {
        assert_eq!(inputs.lines(&["resources", &hap, query]), [LABEL, LABEL_ZH], "{query}");
    }
    assert_eq!(inputs.lines(&["resources", &hap, "color/accent", "--resolve"]), ["chain $color:accent -> $color:brand", BRAND]);
    assert_eq!(inputs.lines(&["resources", &hap, "0x01000003", "--resolve"]), ["chain $color:brand", BRAND]);
    // --search over names and values, as on an APK.
    assert_eq!(inputs.lines(&["resources", &hap, "--search", "^string/Entry", "--in", "name"]), [LABEL, LABEL_ZH]);
    assert_eq!(inputs.lines(&["resources", &hap, "--search", "^https?://", "--in", "value"]), all[7..]);
    assert_eq!(inputs.lines(&["resources", &hap, "--search", "#FF", "--literal"]), [BRAND]);
    assert_eq!(inputs.lines(&["resources", &hap, "--search", "brand"]), all[4..6]);
    assert!(inputs.lines(&["resources", &hap, "--search", "nothing-like-this"]).is_empty());
    // -o takes the rows instead of stdout; --limit pages them.
    let saved = inputs.path("resources.txt");
    assert!(inputs.lines(&["resources", &hap, "-o", saved.to_str().unwrap()]).is_empty());
    assert_eq!(std::fs::read_to_string(&saved).unwrap().lines().collect::<Vec<_>>(), all);
    let page = inputs.lines(&["resources", &hap, "--limit", "2", "--offset", "4", "--spill-mb", "0"]);
    assert_eq!(page[..2], all[4..6]);
    assert!(page[2].starts_with("# records 5-6 of 8 shown"), "{page:?}");

    // Several packages: each row starts with its package; what a package lacks is said on stderr.
    let abc = make_abc();
    inputs.file("pkgs/a.hap", &make_hap(&abc));
    inputs.file("pkgs/b.hsp", &Hap::new().modules_abc(&abc).module_json(SAMPLE_MODULE_JSON).build());
    inputs.file("pkgs/c.hsp", &Hap::new().modules_abc(&abc).entry("resources.index", b"Restool 9", Compression::Stored).build());
    inputs.file(
        "pkgs/d.hap",
        &Hap::new().modules_abc(&abc).entry("resources.index", &sample_resources().build(), Compression::Deflated).build(),
    );
    let pkgs = inputs.path("pkgs");
    let out = inputs.run(&["resources", pkgs.to_str().unwrap(), "string/EntryAbility_label"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(
        stdout(&out).lines().collect::<Vec<_>>(),
        [format!("a.hap | {LABEL}"), format!("a.hap | {LABEL_ZH}"), format!("d.hap | {LABEL}"), format!("d.hap | {LABEL_ZH}")]
    );
    let warnings = stderr(&out);
    let warnings: Vec<&str> = warnings.lines().collect();
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert_eq!(warnings[0], "# warning: b.hsp: no resources.index");
    assert!(warnings[1].starts_with("# warning: c.hsp: resources.index: version at 0x0 needs 128 bytes, 9 are left"), "{warnings:?}");
    let out = inputs.run(&["resources", pkgs.to_str().unwrap(), "color/accent", "--resolve"]);
    assert_eq!(
        stdout(&out).lines().collect::<Vec<_>>(),
        [
            "a.hap | chain $color:accent -> $color:brand".to_owned(),
            format!("a.hap | {BRAND}"),
            "d.hap | chain $color:accent -> $color:brand".to_owned(),
            format!("d.hap | {BRAND}")
        ]
    );

    // No index that reads: an error that names what was looked at.
    let bare = inputs.file("bare.abc", &abc);
    assert_eq!(
        inputs.error(&["resources", &bare]),
        format!(
            "Error: no resources.index in {bare} (a bare .abc carries none: pass the .hap / .app it came from, or a directory holding both)\n"
        )
    );
    let none = inputs.file("none.hap", &Hap::new().modules_abc(&abc).build());
    assert_eq!(inputs.error(&["resources", &none]), format!("Error: no resources.index in {none} (none.hap: no resources.index)\n"));
}

#[test]
fn xml_prints_the_text_files_of_a_package() {
    let inputs = Inputs::new();
    let hap = inputs.sample_hap();
    let pages: Vec<&str> = SAMPLE_MAIN_PAGES.lines().collect();
    for target in ["$profile:main_pages", "app.profile.main_pages", "profile/main_pages", "resources/base/profile/main_pages.json"] {
        assert_eq!(inputs.lines(&["xml", &hap, target]), pages, "{target}");
    }
    let saved = inputs.path("pages.json");
    assert_eq!(inputs.lines(&["xml", &hap, "$profile:main_pages", "-o", saved.to_str().unwrap()]), pages);
    assert_eq!(std::fs::read_to_string(&saved).unwrap(), SAMPLE_MAIN_PAGES);
    assert!(inputs.lines(&["xml", &hap, "module.json"]).join("\n").contains("\"pages\": \"$profile:main_pages\""));

    // Several packages: every one that has the file, under its name; or the one the path names.
    let package = make_hap(&make_abc());
    let app = inputs.file("shop.app", &make_app(&[("entry.hap", &package), ("feature.hap", &package)], Compression::Deflated));
    let both = inputs.lines(&["xml", &app, "$profile:main_pages"]);
    let mut expected = vec!["# entry.hap/resources/base/profile/main_pages.json"];
    expected.extend(&pages);
    expected.push("# feature.hap/resources/base/profile/main_pages.json");
    expected.extend(&pages);
    assert_eq!(both, expected);
    assert_eq!(inputs.lines(&["xml", &app, "feature.hap/resources/base/profile/main_pages.json"]), expected[pages.len() + 1..]);
}

#[test]
fn getclass_names_the_resources_a_function_builds() {
    let inputs = Inputs::new();
    let abc = resource_program().build().bytes;
    let hap = inputs.file("entry.hap", &make_hap(&abc));
    let plain = inputs.lines(&["getclass", &hap, LABELS_PAGE]);
    assert!(!plain.iter().any(|line| line.contains("  # ")), "{plain:?}");
    for command in ["getclass", "disassemble"] {
        for function in [None, Some("labels")] {
            let mut args = vec![command, hap.as_str(), LABELS_PAGE, "--res-names"];
            args.extend(function.into_iter().flat_map(|function| ["--method", function]));
            let named = inputs.lines(&args);
            let objects: Vec<&str> = named.iter().filter(|line| line.contains("createobjectwithbuffer")).map(String::as_str).collect();
            assert_eq!(objects.len(), 5, "{named:?}");
            assert!(objects[0].ends_with("\"moduleName\", \"entry\" ]  # string/EntryAbility_label \"Sample\""), "{objects:?}");
            assert!(objects[1].ends_with(" ]  # color/brand \"#FF0000\""), "{objects:?}");
            assert!(objects[2..].iter().all(|line| line.ends_with(" ]")), "{objects:?}");
            if function.is_none() {
                let without: Vec<String> = named.iter().map(|line| line.split("  # ").next().unwrap().to_owned()).collect();
                assert_eq!(without, plain, "nothing else changes");
            }
        }
    }
    // The id is what findrefs number takes: the row is the instruction getclass names.
    let rows = inputs.lines(&["findrefs", &hap, "number", "0x01000000"]);
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(rows[0].starts_with(&format!("ets/modules.abc | {LABELS_PAGE}->#*#labels+0x0 | labels | createobjectwithbuffer ")), "{rows:?}");
    // Without an index the option changes nothing.
    let bare = inputs.file("bare.abc", &abc);
    assert_eq!(inputs.lines(&["getclass", &bare, LABELS_PAGE, "--res-names"]), plain);
}

#[test]
fn getmanifest_prints_the_documents() {
    let inputs = Inputs::new();
    let hap = inputs.sample_hap();
    let printed = inputs.lines(&["getmanifest", &hap]).join("\n");
    assert!(printed.starts_with("{\n  \"app\": {\n    \"bundleName\": \"com.example.sample\","), "{printed}");
    let parse = |text: &str| serde_json::from_str::<serde_json::Value>(text).unwrap();
    assert_eq!(parse(&printed), parse(SAMPLE_MODULE_JSON));
    assert_eq!(inputs.lines(&["manifest", &hap]).join("\n"), printed);
    assert_eq!(parse(&inputs.lines(&["getmanifest", &hap, "--file", "pack.info"]).join("\n")), parse(SAMPLE_PACK_INFO));
    let saved = inputs.path("module.json");
    inputs.lines(&["getmanifest", &hap, "-o", saved.to_str().unwrap()]);
    assert_eq!(std::fs::read_to_string(&saved).unwrap().trim_end(), printed);

    // An .app: its own pack.info, then each package under its name.
    let inner = make_hap(&make_abc());
    let app = inputs.file("shop.app", &make_app(&[("entry.hap", &inner), ("feature.hap", &inner)], Compression::Deflated));
    let headers = |lines: &[String]| lines.iter().filter(|line| line.starts_with('#')).cloned().collect::<Vec<_>>();
    assert_eq!(headers(&inputs.lines(&["getmanifest", &app])), ["# entry.hap/module.json", "# feature.hap/module.json"]);
    // The packages of one build carry the bytes of one pack.info: printed once, saying where else it is.
    let packs = inputs.lines(&["getmanifest", &app, "--file", "pack.info"]);
    assert_eq!(headers(&packs), ["# shop.app/pack.info (the same in entry.hap, feature.hap)"]);
    assert_eq!(parse(&packs[1..].join("\n")), parse(SAMPLE_PACK_INFO));
    let summary = inputs.lines(&["manifest-summary", &app]);
    assert_eq!(
        summary[..2],
        [
            "shop.app | pack-info packages=3 (pack.info is byte for byte the same in entry.hap, feature.hap: listed once, here)",
            "shop.app | pack-app com.example.sample bundleType=- versionCode=1000000 versionName=1.0.0"
        ]
    );
    // The app has no resources of its own: a module's label is named by the index of that module's package.
    assert!(summary.contains(&"shop.app | pack-ability entry EntryAbility label=$string:EntryAbility_label(\"Sample\")".to_owned()));
    assert_eq!(summary.iter().filter(|line| line.contains(" | pack-")).count(), 7, "{summary:?}");
    assert!(summary.contains(&"feature.hap | pack-info same-as=shop.app (pack.info is byte for byte the one listed there)".to_owned()));
    // A package whose pack.info has other bytes lists its own.
    let other = SAMPLE_PACK_INFO.replace("1.0.0", "1.0.1");
    let own = Hap::new().modules_abc(&make_abc()).module_json(SAMPLE_MODULE_JSON).pack_info(&other).build();
    let mixed = Inputs::new();
    mixed.file("a.hap", &inner);
    mixed.file("b.hap", &inner);
    mixed.file("c.hap", &own);
    let of_packs = mixed.lines(&["manifest-summary", mixed.root.as_path().to_str().unwrap(), "--file", "pack.info"]);
    assert_eq!(of_packs.len(), 10, "{of_packs:?}");
    assert_eq!(of_packs[0], "a.hap | pack-info packages=2 (pack.info is byte for byte the same in b.hap: listed once, here)");
    assert_eq!(of_packs[5], "b.hap | pack-info same-as=a.hap (pack.info is byte for byte the one listed there)");
    assert_eq!(of_packs[6], "c.hap | pack-app com.example.sample bundleType=- versionCode=1000000 versionName=1.0.1");
    let packs = mixed.lines(&["getmanifest", mixed.root.as_path().to_str().unwrap(), "--file", "pack.info"]);
    assert_eq!(headers(&packs), ["# a.hap/pack.info (the same in b.hap)", "# c.hap/pack.info"]);
    let abilities: Vec<&String> = summary.iter().filter(|line| line.contains(" | ability ")).collect();
    assert_eq!(abilities.len(), 2);
    assert!(abilities[0].starts_with("entry.hap | ability EntryAbility exported=true (explicit) "), "{abilities:?}");
    assert!(abilities[1].ends_with(&format!(" record={ENTRY_ABILITY} abc=feature.hap/ets/modules.abc")), "{abilities:?}");

    // A directory: one section per package, in path order.
    let dir = Inputs::new();
    dir.file("b/feature.hap", &inner);
    dir.file("a/entry.hap", &inner);
    let summary = dir.lines(&["manifest-summary", dir.root.as_path().to_str().unwrap()]);
    let mut sections: Vec<&str> = summary.iter().map(|line| line.split(" | ").next().unwrap()).collect();
    sections.dedup();
    assert_eq!(sections, ["a/entry.hap", "b/feature.hap"]);
    // A bare file that is part of no package is one line that says what it lacks.
    dir.file("c/dump.abc", &make_abc());
    let summary = dir.lines(&["manifest-summary", dir.root.as_path().to_str().unwrap()]);
    assert_eq!(
        summary.last().unwrap(),
        "c/dump.abc | abc c/dump.abc version=12.0.6.0 bytes=1928 status=readable bare (part of no package: no manifest, no resources)"
    );

    // A bare .abc has no manifest: the error names what has.
    let abc = inputs.file("modules.abc", &make_abc());
    for command in ["getmanifest", "manifest-summary"] {
        assert_eq!(
            inputs.error(&[command, &abc]),
            format!(
                "Error: no manifest in {abc}: a bare .abc carries no module.json; pass the .hap / .app it came from, or a directory holding both\n"
            )
        );
    }
}

#[test]
fn an_encrypted_entry_is_named_and_left_out() {
    let inputs = Inputs::new();
    let hap = inputs.store_hap("entry.hap");
    let warning = "# warning: ets/modules.abc is encrypted (app-store protection); supply the decrypted .abc\n";

    // The readable entry still answers.
    let out = inputs.run(&["listclass", &hap]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stderr(&out), warning);
    let rows: Vec<String> = stdout(&out).lines().map(String::from).collect();
    assert_eq!(first_columns(&rows), [ENTRY_ABILITY, INDEX_PAGE]);
    assert!(rows.iter().all(|row| row.ends_with(" | ets/widgets.abc")), "{rows:?}");

    // A search that could not look everywhere says so in its exit status, as for DEX entries.
    let out = inputs.run(&["findrefs", &hap, "string", "https?://"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert_eq!(stdout(&out).lines().count(), 1);
    assert_eq!(stderr(&out), format!("{warning}Warning: 1 ABC entry could not be searched\n"));

    let out = inputs.run(&["getclass", &hap, "pages/Missing"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("Error: record pages/Missing not found (ets/modules.abc is encrypted"), "{}", stderr(&out));

    // The decrypted file next to the package stands in for the entry.
    let dir = Inputs::new();
    dir.store_hap("entry.hap");
    dir.file("modules.abc", &make_abc());
    let out = dir.run(&["findrefs", dir.root.as_path().to_str().unwrap(), "string", "https?://"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let entries: Vec<String> = stdout(&out).lines().map(|row| row.split(" | ").next().unwrap().to_owned()).collect();
    assert_eq!(entries, ["entry.hap/ets/modules.abc", "entry.hap/ets/widgets.abc"]);
    // Nothing is left out, so this is a note, not a warning.
    assert_eq!(stderr(&out), "# note: entry.hap/ets/modules.abc is encrypted in its package; served from the decrypted modules.abc\n");

    // Several such packages are one line; an entry nothing stands in for is still a warning of its own.
    let many = Inputs::new();
    let encrypted = sample_program().encrypted().build().bytes;
    let other = asc_fixture::hap::library_program();
    let other_encrypted = asc_fixture::hap::library_program().encrypted().build().bytes;
    many.file("a.hap", &Hap::new().modules_abc(&encrypted).module_json(SAMPLE_MODULE_JSON).build());
    many.file("a.hap.abc", &make_abc());
    many.file("b.hsp", &Hap::new().modules_abc(&other_encrypted).module_json("{}").build());
    many.file("b.hsp.abc", &other.build().bytes);
    let root = many.root.as_path().to_str().unwrap().to_owned();
    let note = "# note: 2 encrypted abc entries are served from the decrypted files next to them (manifest-summary names each: its \
                `abc` lines)\n";
    let out = many.run(&["findrefs", &root, "string", "shared|testTag"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stderr(&out), note);
    many.file("c.hap", &Hap::new().modules_abc(&encrypted).abc("widgets", &make_abc()).module_json("{}").build());
    let out = many.run(&["findrefs", &root, "string", "shared|testTag"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert_eq!(
        stderr(&out),
        format!(
            "# warning: c.hap/ets/modules.abc is encrypted (app-store protection); supply the decrypted .abc\n{note}Warning: 1 ABC entry \
             could not be searched\n"
        )
    );
    // Kept to the packages that read whole, the search is complete.
    let out = many.run(&["findrefs", &root, "--entry", "a.hap", "string", "testTag"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(stdout(&out).lines().count() > 0 && stdout(&out).lines().all(|row| row.starts_with("a.hap/ets/modules.abc | ")));
    let out = many.run(&["findrefs", &root, "--entry", "c.hap", "string", "testTag"]);
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(stdout(&out).lines().all(|row| row.starts_with("c.hap/ets/widgets.abc | ")));
}

#[test]
fn an_apk_is_still_an_android_program() {
    let inputs = Inputs::new();
    let dex = make_dex();
    let apk = inputs.file("app.apk", &make_apk(&[("classes.dex", &dex)], true));
    assert_eq!(inputs.lines(&["listclass", &apk]), ["Lexample/Test;"]);
    let smali = inputs.lines(&["getclass", &apk, "example.Test"]);
    assert!(smali.contains(&".class public Lexample/Test;".to_owned()), "{smali:?}");
    assert_eq!(
        inputs.lines(&["findrefs", &apk, "string", "token"]),
        ["classes.dex | Lexample/Test;->first()V | \"token\"", "classes.dex | Lexample/Test;->second()V | \"token\""]
    );
    // What only a HarmonyOS program has is refused, not ignored.
    assert_eq!(
        inputs.error(&["listclass", &apk, "--all"]),
        "Error: --all applies to HarmonyOS programs only (a DEX program has no pseudo records)\n"
    );
    assert_eq!(
        inputs.error(&["getclass", &apk, "example.Test", "--entry", "classes.dex"]),
        "Error: --entry applies to HarmonyOS programs only\n"
    );
    assert_eq!(
        inputs.error(&["hierarchy", &apk, "java.lang.Object", "--entry", "classes.dex"]),
        "Error: --entry applies to HarmonyOS programs only\n"
    );
    for command in ["getmanifest", "manifest-summary"] {
        assert_eq!(inputs.error(&[command, &apk, "--file", "pack.info"]), "Error: --file applies to HarmonyOS programs only\n");
    }
    let harmony_only: [(&[&str], &str); 8] = [
        (&["prop", "token"], "findrefs prop"),
        (&["global", "console", "--access", "read"], "findrefs global"),
        (&["import", "@ohos:net.http", "--requests"], "findrefs import"),
        (&["number", "0x10"], "findrefs number"),
        (&["call", "import:"], "findrefs call"),
        (&["all", "string:token", "call:import:"], "findrefs call:"),
        (&["all", "string:token", "--none", "prop:x"], "findrefs prop:"),
        (&["field", "value", "--access", "define"], "--access define"),
    ];
    for (args, what) in harmony_only {
        let mut argv = vec!["findrefs", apk.as_str()];
        argv.extend(args);
        assert_eq!(inputs.error(&argv), format!("Error: {what} applies to HarmonyOS programs only\n"), "{argv:?}");
    }
    let tree = inputs.lines(&["callgraph", &apk, "example.Test", "first", "--callees"]);
    assert_eq!(tree, ["0 Lexample/Test;->first()V", "# 1 rows, 1 distinct methods (callees, depth 2)"]);
    for flag in [&["--no-defines"][..], &["--unresolved"], &["--entry", "classes.dex"]] {
        let mut argv = vec!["callgraph", apk.as_str(), "example.Test", "first", "--callees"];
        argv.extend(flag);
        assert_eq!(inputs.error(&argv), format!("Error: {} applies to HarmonyOS programs only\n", flag[0]), "{argv:?}");
    }

    // A program with DEX code stays a DEX program when a HarmonyOS file sits
    // next to it, and says that the file is left out.
    let mixed = Inputs::new();
    mixed.file("app.apk", &make_apk(&[("classes.dex", &dex)], true));
    let dir = mixed.root.as_path().to_str().unwrap().to_owned();
    let alone = mixed.lines(&["listclass", &dir]);
    assert_eq!(alone, ["Lexample/Test;"]);
    mixed.file("entry.hap", &make_hap(&make_abc()));
    let out = mixed.run(&["listclass", &dir]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out).lines().collect::<Vec<_>>(), alone);
    assert_eq!(
        stderr(&out),
        "# warning: HarmonyOS files (.hap, .hsp, .app, .abc) of this program are left out next to its DEX code; query them by their own path\n"
    );
}

/// A HarmonyOS program is answered by the daemon like an APK (one daemon
/// for both), and in the client process with `ASC_DAEMON=off`.
#[cfg(unix)]
#[test]
fn a_harmony_program_goes_to_the_daemon() {
    use std::os::unix::fs::PermissionsExt;
    let inputs = Inputs::new();
    let hap = inputs.sample_hap();
    let apk = inputs.file("app.apk", &make_apk(&[("classes.dex", &make_dex())], true));
    // Under /tmp: socket paths must stay short whatever `$TMPDIR` is.
    let runtime = tempfile::Builder::new().prefix("hmy").tempdir_in("/tmp").unwrap();
    std::fs::set_permissions(runtime.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_asc"))
            .env("ASC_CONFIG", "")
            .env("ASC_RUNTIME_DIR", runtime.path())
            .env_remove("ASC_DAEMON")
            .arg("--cache-dir")
            .arg(inputs.path("cache"))
            .args(args)
            .output()
            .expect("run asc")
    };
    let sockets = || {
        std::fs::read_dir(runtime.path().join("daemon"))
            .map(|entries| entries.flatten().filter(|entry| entry.path().extension().is_some_and(|ext| ext == "sock")).count())
            .unwrap_or(0)
    };

    let direct = inputs.lines(&["findrefs", &hap, "string", "testTag"]);
    assert_eq!(sockets(), 0, "ASC_DAEMON=off started a daemon");
    let out = run(&["findrefs", &hap, "string", "testTag"]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert_eq!(stdout(&out).lines().collect::<Vec<_>>(), direct);
    assert_eq!(sockets(), 1, "the HarmonyOS command did not start a daemon");

    let out = run(&["listclass", &apk]);
    assert_eq!(stdout(&out), "Lexample/Test;\n", "{}", stderr(&out));
    assert_eq!(sockets(), 1, "the APK command went to a daemon of its own");
    // A request counts as running until the daemon has also trimmed its pool,
    // which ends after the client got its output: wait for the count to drop.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let status = loop {
        let status = stdout(&run(&["daemon", "status"]));
        if status.contains("(0 running)") || std::time::Instant::now() > deadline {
            break status;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    assert!(status.contains(", 2 requests (0 running), 2 APKs open, "), "{status}");
    assert!(run(&["daemon", "stop"]).status.success());
}

#[test]
fn pages_and_routes_are_lines_with_their_records() {
    let inputs = Inputs::new();
    inputs.file("app/entry.hap", &make_routed_hap());
    inputs.file("app/lib.hsp", &make_library_hsp());
    let app = inputs.path("app").to_str().unwrap().to_owned();
    let summary = inputs.lines(&["manifest-summary", &app]);
    let of_kind = |kind: &str| -> Vec<&str> {
        summary.iter().filter_map(|line| line.strip_prefix("entry.hap | ")).filter(|line| line.split(' ').next() == Some(kind)).collect()
    };
    assert_eq!(of_kind("page"), [format!("page pages/Index record={INDEX_PAGE} abc=entry.hap/ets/modules.abc")]);
    assert_eq!(
        of_kind("route"),
        [
            format!(
                "route detail buildFunction=DetailBuilder source=src/main/ets/pages/Detail.ets record={DETAIL_PAGE} abc=entry.hap/ets/modules.abc"
            ),
            format!(
                "route lib/shared buildFunction=SharedBuilder source=src/main/ets/pages/Shared.ets package=@sample/lib record={SHARED_PAGE} \
                 abc=lib.hsp/ets/modules.abc"
            ),
            format!(
                "route index buildFunction=IndexBuilder source=src/main/ets/pages/Index.ets record={INDEX_PAGE} abc=entry.hap/ets/modules.abc"
            ),
            "route gone buildFunction=GoneBuilder source=src/main/ets/pages/Gone.ets record=- (no record \
             com.example.sample/entry/ets/pages/Gone or &entry/src/main/ets/pages/Gone&)"
                .to_owned(),
        ]
    );
    // What a route names is what getclass takes: the record, its entry and the builder function.
    let field = |line: &str, key: &str| line.split(' ').find_map(|word| word.strip_prefix(key)).unwrap().to_owned();
    for route in &of_kind("route")[..2] {
        let (record, entry, builder) = (field(route, "record="), field(route, "abc="), field(route, "buildFunction="));
        let listing = inputs.lines(&["getclass", &app, &record, "--entry", &entry, "--method", &builder]);
        assert_eq!(functions(&listing), [format!("#*#{builder}")], "{route}");
    }
    // The lines are records of the window like any other, and one document keeps them.
    let first = summary.iter().position(|line| line.starts_with("entry.hap | route detail ")).unwrap();
    let window = inputs.lines(&["manifest-summary", &app, "--limit", "2", "--offset", &first.to_string(), "--spill-mb", "0"]);
    assert_eq!(window[..2], summary[first..first + 2]);
    assert_eq!(window[2], format!("# records {}-{} of {} shown; rerun with --offset {}", first + 1, first + 2, summary.len(), first + 2));
    let module = inputs.lines(&["manifest-summary", &app, "--file", "module.json"]);
    assert_eq!(module.iter().filter(|line| line.contains(" | route ")).count(), 4);
    assert!(inputs.lines(&["manifest-summary", &app, "--file", "pack.info"]).iter().all(|line| !line.contains(" | route ")));
    let json: serde_json::Value = serde_json::from_str(&inputs.lines(&["manifest-summary", &app, "--json"]).join("\n")).unwrap();
    assert_eq!(json["packages"][0]["routes"][1]["abc"], "lib.hsp/ets/modules.abc");
    assert_eq!(json["packages"][0]["routes"][3]["unresolved"].as_str().map(|reason| reason.starts_with("no record ")), Some(true));
    assert_eq!(json["packages"][0]["pages"][0]["record"], INDEX_PAGE);
}

#[test]
fn findrefs_and_listclass_keep_to_an_entry_or_a_package() {
    let inputs = Inputs::new();
    inputs.file("pkgs/a.hap", &make_hap(&resource_program().build().bytes));
    inputs.file(
        "pkgs/b.hsp",
        &Hap::new().modules_abc(&resource_program().build().bytes).abc("widgets", &make_abc()).module_json("{}").build(),
    );
    let pkgs = inputs.path("pkgs").to_str().unwrap().to_owned();
    // A resource id is unique within one package only: both packages build an object with it.
    let id = format!("{SAMPLE_BRAND_ID:#x}");
    let entries = |rows: &[String]| rows.iter().map(|row| row.split(" | ").next().unwrap().to_owned()).collect::<Vec<_>>();
    assert_eq!(entries(&inputs.lines(&["findrefs", &pkgs, "number", &id])), ["a.hap/ets/modules.abc", "b.hsp/ets/modules.abc"]);
    assert_eq!(entries(&inputs.lines(&["findrefs", &pkgs, "number", &id, "--entry", "a.hap"])), ["a.hap/ets/modules.abc"]);
    assert_eq!(entries(&inputs.lines(&["findrefs", &pkgs, "--entry", "b.hsp", "number", &id])), ["b.hsp/ets/modules.abc"]);
    // An entry by its name or a suffix of it; `all` and `import --requests` take the option too.
    let in_widgets = inputs.lines(&["findrefs", &pkgs, "string", "testTag", "--entry", "ets/widgets.abc"]);
    assert!(!in_widgets.is_empty() && entries(&in_widgets).iter().all(|entry| entry == "b.hsp/ets/widgets.abc"), "{in_widgets:?}");
    let all = inputs.lines(&["findrefs", &pkgs, "all", "string:^https://", "call:createHttp", "--entry", "b.hsp"]);
    assert_eq!(entries(&all), ["b.hsp/ets/modules.abc", "b.hsp/ets/widgets.abc"]);
    let requests = inputs.lines(&["findrefs", &pkgs, "import", ".", "--requests", "--entry", "a.hap"]);
    assert!(!requests.is_empty() && requests.iter().all(|row| row.starts_with("a.hap/ets/modules.abc | ")), "{requests:?}");
    // Nothing there: the hint says the search was kept to part of the program.
    let out = inputs.run(&["findrefs", &pkgs, "string", "nothing-like-this", "--literal", "--entry", "a.hap"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(stderr(&out).ends_with("hint: --entry a.hap kept the search to 1 of the 3 abc entries\n"), "{}", stderr(&out));
    assert_eq!(
        inputs.error(&["findrefs", &pkgs, "string", "x", "--entry", "c.hap"]),
        "Error: no entry named c.hap (entries: a.hap/ets/modules.abc, b.hsp/ets/modules.abc, b.hsp/ets/widgets.abc; a package names all of \
         its entries)\n"
    );

    let last_columns = |rows: &[String]| {
        let mut entries: Vec<String> = rows.iter().map(|row| row.rsplit(" | ").next().unwrap().to_owned()).collect();
        entries.dedup();
        entries
    };
    assert_eq!(last_columns(&inputs.lines(&["listclass", &pkgs, "--entry", "b.hsp"])), ["b.hsp/ets/modules.abc", "b.hsp/ets/widgets.abc"]);
    assert_eq!(
        inputs.lines(&["listclass", &pkgs, "--entry", "a.hap", "--prefix", "entry/src/main/ets/pages/L"]),
        [format!("{LABELS_PAGE} | functions=1 | a.hap/ets/modules.abc")]
    );
    assert!(
        inputs.error(&["listclass", &pkgs, "--entry", "nope"]).starts_with("Error: no entry named nope (entries: a.hap/ets/modules.abc, ")
    );
    // A lone package is named by its file name; a DEX program has no such entries.
    let lone = inputs.path("pkgs/b.hsp").to_str().unwrap().to_owned();
    assert_eq!(inputs.lines(&["findrefs", &lone, "number", &id, "--entry", "b.hsp"]).len(), 1);
    let apk = inputs.file("app.apk", &make_apk(&[("classes.dex", &make_dex())], true));
    for args in [&["findrefs", &apk, "string", "x", "--entry", "classes.dex"][..], &["listclass", &apk, "--entry", "classes.dex"]] {
        assert_eq!(inputs.error(args), "Error: --entry applies to HarmonyOS programs only\n", "{args:?}");
    }
}

/// A package unpacked into a directory is that package; the source maps of
/// a debug build reach `getclass`.
#[test]
fn unpacked_packages_and_source_maps() {
    let inputs = Inputs::new();
    let debug = asc_fixture::hap::make_debug_hap(&make_abc());
    let hap = inputs.file("packed/entry.hap", &debug);
    let unpacked = inputs.path("entry");
    asc_fixture::hap::unpack(&debug, &unpacked);
    let unpacked = unpacked.to_str().unwrap();

    // The same answers, the package named after the directory instead of the file.
    for args in [
        &["manifest-summary"][..],
        &["manifest-summary", "--json"],
        &["resources"],
        &["listclass"],
        &["findrefs", "string", "."],
        &["getclass", "pages/Index"],
        &["callgraph", "pages/Index", "Index.build", "--callees"],
        &["xml", "$profile:main_pages"],
        &["xml", "ets/sourceMaps.map"],
    ] {
        let of_directory = inputs.lines(&[&args[..1], &[unpacked], &args[1..]].concat());
        let of_file = inputs.lines(&[&args[..1], &[hap.as_str()], &args[1..]].concat());
        let renamed: Vec<String> = of_file.iter().map(|line| line.replace("entry.hap", "entry")).collect();
        assert_eq!(of_directory, renamed, "{args:?}");
    }
    assert!(inputs.error(&["xml", unpacked, "../packed/entry.hap"]).contains("not found"));

    let function = inputs.lines(&["getclass", unpacked, "pages/Index", "--method", "Index.build"]);
    assert!(function[1].ends_with(", line 12 (source line 4)"), "{function:?}");

    // `--lines`: every change of line where it happens, instead of the first line in the header.
    let woven = inputs.lines(&["getclass", unpacked, "pages/Index", "--method", "Index.build", "--lines"]);
    assert!(!woven[1].contains(", line ") && woven.contains(&"  ; line 12 (source line 4)".to_owned()), "{woven:?}");
    let without: Vec<String> = woven.iter().filter(|line| !line.starts_with("  ; line ")).cloned().collect();
    assert_eq!(without[2..], function[2..], "nothing else of the listing changes");
    // `disassemble --debuginfo` asks for the same; an Android program has no such lines.
    for flag in ["--lines", "--debuginfo"] {
        assert_eq!(inputs.lines(&["disassemble", &hap, "pages/Index", "--method", "Index.build", flag]), woven, "{flag}");
    }
    let apk = inputs.file("app.apk", &make_apk(&[("classes.dex", &make_dex())], true));
    for command in ["getclass", "disassemble"] {
        assert!(inputs.error(&[command, &apk, "example.Test", "--lines"]).contains("--lines applies to HarmonyOS programs only"));
    }
}

/// Rows of the call graph program without the entry column, records shortened.
fn short_calls(lines: &[String]) -> Vec<String> {
    short_tree(lines).iter().map(|line| line.replace("modules.abc | ", "")).collect()
}

#[test]
fn findrefs_excludes_nests_and_runs_rule_sets() {
    let inputs = Inputs::new();
    let abc = inputs.file("modules.abc", &call_graph_program().build().bytes);
    let find = |args: &[&str]| {
        let mut argv = vec!["findrefs", abc.as_str()];
        argv.extend(args);
        short_calls(&inputs.lines(&argv))
    };
    // `!COND` and --none take functions away; one row per function is left.
    let props = find(&["all", "prop:=make", "prop:=then"]);
    assert_eq!(props, ["App->#*#run+0x6 | run | prop +0x6 ldobjbyname \"make\" [call] && prop +0x3a ldobjbyname \"then\" [call]"]);
    assert!(find(&["all", "prop:=make", "prop:=then", "!prop:=nothing"]).is_empty());
    assert!(find(&["all", "prop:=make", "prop:=then", "--none", "prop:=nothing"]).is_empty());
    assert_eq!(find(&["all", "prop:=make", "prop:=then", "!prop:=size", "--none", "string:no-such-text"]), props);
    assert_eq!(find(&["all", "prop:=get", "!prop:=then"]), ["Box->#~@0<#make+0x0 | Box.make | prop +0x0 ldthisbyname \"get\" [call]"]);
    // Among conditions `method:` is the function itself; alone it is where the function is defined.
    assert_eq!(find(&["all", "method:=run", "prop:=then"]), ["App->#*#run+0x3a | run | prop +0x3a ldobjbyname \"then\" [call]"]);
    assert_eq!(find(&["all", "prop:=get", "!method:^Box\\."]), ["App->#*#run+0x16 | run | prop +0x16 ldobjbyname \"get\" [call]"]);
    assert_eq!(find(&["all", "method:helper", "!prop:=then"]), ["Util->#*#helper+0x0 | helper | method"]);
    assert_eq!(find(&["all", "method:=helper"]), ["Util->func_main_0+0x0 | func_main_0 | definefunc #*#helper, 0  ; helper"]);

    // `call:{RULE}`: the calls that lead to a function the rule matches, to any depth of braces.
    let star = find(&["call", "{method:=star}"]);
    assert_eq!(
        star,
        [
            "App->#*#run+0x1e | run | callarg0 ; -> Util->#*#star (star)",
            "Util->#*#helper+0x2 | helper | callarg0 ; -> Util->#*#star (star)"
        ]
    );
    assert_eq!(find(&["all", "call:{method:=star}"]), star);
    assert_eq!(find(&["call", "{global:=console & prop:=log}"]).len(), 4);
    let two_up = find(&["all", "call:{call:{method:=star}}", "!method:=run"]);
    assert_eq!(two_up.len(), 2, "{two_up:?}");
    assert!(two_up[0].starts_with("App->func_main_0+0x9 | func_main_0 | call +0x9 callarg0 ; -> App->#*#run (run)"), "{two_up:?}");
    assert!(two_up[1].starts_with("App->#*@0*#cb+0x2 | run.cb | call +0x2 callarg0 ; -> Util->#*#helper (helper)"), "{two_up:?}");
    // `{@FILE}`: the functions a file lists, as earlier output prints them.
    let list = inputs.file("star.txt", &inputs.run(&["callgraph", &abc, "star", "--depth", "0"]).stdout);
    assert_eq!(find(&["call", &format!("{{@{list}}}")]), star);

    // `=NAME` is the exact name in a subcommand too, as --exact is.
    for kind in [&["prop", "then"][..], &["global", "console"], &["method", "helper"]] {
        let exact = find(&[kind[0], kind[1], "--exact"]);
        assert!(!exact.is_empty(), "{kind:?}");
        assert_eq!(find(&[kind[0], &format!("={}", kind[1])]), exact, "{kind:?}");
    }

    // rules: every rule one search, rows prefixed by rule between the `# rN` lines.
    let rules = inputs.file("rules.txt", b"# more rules\n\nprop:=nope\n");
    let out = inputs.run(&["findrefs", &abc, "rules", "prop:=then & !prop:=size", "call:{method:=star}", "--file", &rules]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(
        short_calls(&stdout(&out).lines().map(String::from).collect::<Vec<_>>()),
        [
            "# r1 prop:=then & !prop:=size",
            "# r2 call:{method:=star}",
            "# r3 prop:=nope",
            "r1 | App->#*#run+0x3a | run | prop +0x3a ldobjbyname \"then\" [call]",
            "r2 | App->#*#run+0x1e | run | callarg0 ; -> Util->#*#star (star)",
            "r2 | Util->#*#helper+0x2 | helper | callarg0 ; -> Util->#*#star (star)",
            "# r1 1 results",
            "# r2 2 results",
            "# r3 0 results",
        ]
    );
    assert_eq!(stderr(&out), "");
    // A rule alone is that search: the rows of `findrefs prop`, prefixed.
    let alone = find(&["rules", "prop:=then"]);
    assert_eq!(alone[1], format!("r1 | {}", find(&["prop", "then", "--exact"])[0]));
}

#[test]
fn findrefs_context_lists_the_code_around_each_hit() {
    let inputs = Inputs::new();
    let abc = inputs.file("modules.abc", &call_graph_program().build().bytes);
    let around = inputs.lines(&["findrefs", &abc, "prop", "then", "--exact", "--context", "1"]);
    assert_eq!(
        short_calls(&around),
        [
            "App->#*#run+0x3a | run | ldobjbyname \"then\" [call]",
            "  @ pc 0x3a",
            "      0038  lda a3",
            "  >   003a  ldobjbyname \"then\"",
            "      003e  callarg0",
        ]
    );
    // Every site of a conjunction, windows apart.
    let sites = inputs.lines(&["findrefs", &abc, "all", "prop:=make", "prop:=then", "--context", "0"]);
    assert_eq!(sites[1..], ["  @ pc 0x6, pc 0x3a", "  >   0006  ldobjbyname \"make\"", "  --", "  >   003a  ldobjbyname \"then\""]);
    // The whole function is what getclass prints, once for the rows that follow each other in it.
    let whole = inputs.lines(&["findrefs", &abc, "prop", "^(size|other)$", "--context-method"]);
    let listing = inputs.lines(&["getclass", &abc, "lib/Box", "--method", "Box.get"]);
    assert_eq!(whole[1], "  @ pc 0x0");
    let shown: Vec<&str> = whole[2..2 + listing.len()].iter().map(|line| &line[4..]).collect();
    assert_eq!(shown, listing);
    assert_eq!(whole[2 + listing.len() + 1..], ["  @ pc 0x6", "  # the function is listed with the row above"]);
    // A context is part of its record: --limit counts rows, and a rule set keeps the prefix.
    let cut = inputs.lines(&["findrefs", &abc, "prop", ".", "--context", "1", "--limit", "1", "--spill-mb", "0"]);
    assert!(cut.len() >= 4 && cut[1].starts_with("  @ pc ") && cut.last().unwrap().starts_with("# records 1-1 of "), "{cut:?}");
    let prefixed = inputs.lines(&["findrefs", &abc, "rules", "prop:=then", "--context", "0"]);
    assert_eq!(prefixed[2..4], ["r1 |  @ pc 0x3a", "r1 |  >   003a  ldobjbyname \"then\""]);
}

#[test]
fn annotations_are_listed_found_and_looked_up() {
    let inputs = Inputs::new();
    let abc = inputs.file("modules.abc", &annotations_program().build().bytes);
    // An annotation interface is a record of the program, named after its module.
    assert_eq!(
        inputs.lines(&["listclass", &abc]),
        [
            "&@ohos/lib/index&1.2.0 | functions=1",
            "&@ohos/lib/index&1.2.0.Marked | functions=0 kind=annotation",
            "&entry/src/main/ets/pages/Pay& | functions=3",
            "&entry/src/main/ets/pages/Pay&.Route | functions=0 kind=annotation",
        ]
    );
    assert_eq!(inputs.lines(&["listclass", &abc, "--prefix", "entry/src/main/ets/pages/Pay."]).len(), 1);
    assert_eq!(
        inputs.lines(&["getclass", &abc, "pages/Pay.Route"])[..2],
        [".record &entry/src/main/ets/pages/Pay&.Route", "; annotation interface, package entry, 5 fields, 0 functions",]
    );
    assert_eq!(inputs.lines(&["getclass", &abc, "pages/Pay"])[0], ".record &entry/src/main/ets/pages/Pay&");

    // A string of an annotation: on the function that carries it, or the field that declares its default.
    let found = inputs.lines(&["findrefs", &abc, "string", "pay"]);
    assert_eq!(
        found,
        [
            "modules.abc | &entry/src/main/ets/pages/Pay&->#~@0=#Pay | Pay.constructor | annotation @&entry/src/main/ets/pages/Pay&.Route \
             path=\"/pay\", tags[0]=\"pay\"",
            "modules.abc | &entry/src/main/ets/pages/Pay&->#~@0>#open | Pay.open | annotation @&@ohos/lib/index&1.2.0.Marked note=\"opens /pay\"",
            "modules.abc | &entry/src/main/ets/pages/Pay&->#~@0>#open+0x0 | Pay.open | lda.str \"/pay\"",
        ]
    );
    assert_eq!(inputs.lines(&["findrefs", &abc, "string", "pay", "--literal"]), found);
    assert_eq!(
        inputs.lines(&["findrefs", &abc, "string", "^(none|default)$"]),
        [
            "modules.abc | &@ohos/lib/index&1.2.0.Marked field note | - | annotation default \"none\"",
            "modules.abc | &entry/src/main/ets/pages/Pay&.Route field tags | - | annotation default [1]=\"default\"",
        ]
    );
    // The location column is what getclass takes, with or without an offset; the listing has the whole annotation.
    let listing = inputs.lines(&["getclass", &abc, found[1].split(" | ").nth(1).unwrap()]);
    assert_eq!(functions(&listing), ["#~@0>#open"]);
    assert!(listing.contains(&"; @&@ohos/lib/index&1.2.0.Marked(note=\"opens /pay\")".to_owned()), "{listing:?}");
    // Only the row of an instruction has code around it.
    let around = inputs.lines(&["findrefs", &abc, "string", "pay", "--context", "0"]);
    assert_eq!(around[..2], found[..2]);
    assert_eq!(around[2..], [found[2].as_str(), "  @ pc 0x0", "  >   0000  lda.str \"/pay\""]);
}

#[test]
fn a_call_compiled_with_its_name_is_one_call_row() {
    let inputs = Inputs::new();
    let abc = inputs.file("modules.abc", &callable_names_program().build().bytes);
    // Each row from its function on.
    let rows = |args: &[&str]| -> Vec<String> {
        let mut all = vec!["findrefs", &abc, "prop", "cut", "--exact"];
        all.extend_from_slice(args);
        inputs.lines(&all).iter().map(|line| line.split_once("->").unwrap().1.to_owned()).collect()
    };
    assert_eq!(
        rows(&[]),
        [
            "#*#named+0x2 | named | ldobjbyname \"cut\" [read]",
            "#*#named+0xe | named | callthis2withname \"cut\", a3, v1, v2 [call]",
            "#*#named+0x25 | named | callthisrangewithname 1, \"cut\", v5  ; v5..v6 [call]",
            "#*#named+0x3d | named | ldobjbyname \"cut\" [read]",
            "#*#plain+0x2 | plain | ldobjbyname \"cut\" [read]",
            "#*#plain+0xa | plain | ldobjbyname \"cut\" [call]",
            "#*#plain+0x17 | plain | ldobjbyname \"cut\" [call]",
        ]
    );
    assert_eq!(rows(&["--access", "read"]).len(), 3);
    let calls = rows(&["--access", "call"]);
    assert_eq!(calls.len(), 4);
    assert!(calls.iter().all(|row| row.ends_with(" [call]")), "{calls:?}");
    // The row is the call instruction: the one `findrefs call` has, and the one marked in its context.
    let sites = inputs.lines(&["findrefs", &abc, "call", "\\.cut$"]);
    assert!(sites[0].contains("->#*#named+0xe | ") && sites[1].contains("->#*#named+0x25 | "), "{sites:?}");
    let around = inputs.lines(&["findrefs", &abc, "prop", "cut", "--exact", "--access", "call", "--context", "1"]);
    assert_eq!(
        around[1..5],
        ["  @ pc 0xe", "      000a  ldobjbyname \"cut\"", "  >   000e  callthis2withname \"cut\", a3, v1, v2", "      0015  sta v3"]
    );
    let both = inputs.lines(&["findrefs", &abc, "all", "prop:=fold", "prop:=close", "--context", "0"]);
    assert_eq!(both[1], "  @ pc 0x31, pc 0x36, pc 0x41");
}
