//! MCP sessions against synthetic HarmonyOS programs (`.abc` / `.hap` /
//! `.app` files), driven through `serve`.

use asc_engine::CacheConfig;
use asc_fixture::abc::{
    call_graph_program, class_hierarchy_program, make_abc, sample_program, CALLS_APP, CALLS_BOX, CALLS_INDEX, CALLS_UTIL, CLASSES_APP,
    CLASSES_BASE, ENTRY_ABILITY, INDEX_PAGE, SAMPLE_API_URL,
};
use asc_fixture::hap::{
    make_app, make_hap, resource_program, Compression, Hap, LABELS_PAGE, SAMPLE_MAIN_PAGES, SAMPLE_MODULE_JSON, SAMPLE_PACK_INFO,
};
use asc_fixture::{make_apk, make_dex};
use serde_json::{json, Value};
use std::path::Path;

const TOOLS: &str = "listclass, getclass, getmanifest, manifest_summary, resources, callgraph, hierarchy, findrefs \
                     kind=string|literal|prop|global|import|method|number|call";
/// What the error of a class name that finds nothing ends with.
const CLASSES: &str = "(a class is named as rows print it, RECORD->CLASS, or by its name alone; a parent outside the program by \
                       import:REGEX or global:REGEX over its path; findrefs kind=method lists the functions of a name, constructors \
                       among them)";
const KINDS: &str = "(supported kinds: string, literal, prop, global, import, method, number, call)";
const NOT_YET: &str = "is not supported for HarmonyOS programs yet";
const ENCRYPTED: &str = "ets/modules.abc is encrypted (app-store protection); supply the decrypted .abc";

/// A directory of inputs that lives as long as the test.
struct Inputs {
    dir: tempfile::TempDir,
}

impl Inputs {
    fn new() -> Inputs {
        Inputs { dir: tempfile::tempdir().unwrap() }
    }

    /// Write `bytes` as `name` (below the directory); its path.
    fn file(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.dir.path().join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, bytes).unwrap();
        path.to_str().unwrap().to_owned()
    }

    fn path(&self, name: &str) -> String {
        self.dir.path().join(name).to_str().unwrap().to_owned()
    }

    /// The sample program as `entry.hap`.
    fn sample_hap(&self) -> String {
        self.file("entry.hap", &make_hap(&make_abc()))
    }

    /// A hap as an app store ships it: `ets/modules.abc` encrypted,
    /// `ets/widgets.abc` readable.
    fn store_hap(&self, name: &str) -> String {
        let encrypted = sample_program().encrypted().build().bytes;
        self.file(name, &Hap::new().modules_abc(&encrypted).abc("widgets", &make_abc()).module_json("{}").build())
    }
}

/// Replies past their budget are paged, unless `spill_dir` takes them.
fn opts(spill_dir: Option<&Path>) -> asc_mcp::Options {
    let mut o = asc_mcp::Options::new(2, false, CacheConfig { memory_bytes: 64 << 20, ..CacheConfig::default() });
    o.spill_dir = spill_dir.map(Path::to_path_buf);
    o
}

/// Run one session, a call at a time: one parsed reply per request, in
/// request order.
fn session_with(opts: asc_mcp::Options, messages: &[Value]) -> Vec<Value> {
    let server = asc_mcp::Server::new(opts);
    messages.iter().filter_map(|message| server.handle_line(&message.to_string())).collect()
}

fn session(messages: &[Value]) -> Vec<Value> {
    session_with(opts(None), messages)
}

/// Run one session through `serve`, where calls run concurrently: the
/// replies by request id.
fn served(messages: &[Value]) -> Vec<Value> {
    let input: String = messages.iter().map(|m| m.to_string() + "\n").collect();
    let mut out = Vec::new();
    asc_mcp::serve(input.as_bytes(), &mut out, opts(None)).unwrap();
    let mut replies: Vec<Value> = String::from_utf8(out).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    replies.sort_by_key(|r| r["id"].as_u64().unwrap_or(0));
    replies
}

fn call(id: u64, name: &str, args: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": {"name": name, "arguments": args}})
}

fn text(reply: &Value) -> &str {
    reply["result"]["content"][0]["text"].as_str().unwrap()
}

fn ok(reply: &Value) -> &Value {
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    &reply["result"]["structuredContent"]
}

/// The message of a call that failed as a tool error (not a protocol error).
fn error(reply: &Value) -> &str {
    assert_eq!(reply["result"]["isError"], true, "{reply}");
    assert!(reply.get("error").is_none(), "{reply}");
    text(reply).strip_prefix("Error: ").unwrap()
}

/// The lines of a reply that are not `#` comments.
fn rows(reply: &Value) -> Vec<&str> {
    text(reply).lines().filter(|line| !line.starts_with('#')).collect()
}

/// The `.function` headers of a disassembly: the raw names.
fn functions(reply: &Value) -> Vec<&str> {
    text(reply).lines().filter_map(|line| line.strip_prefix(".function ")).map(|rest| rest.split_whitespace().next().unwrap()).collect()
}

#[test]
fn a_hap_opens_and_answers_the_tools_that_carry_over() {
    let inputs = Inputs::new();
    let hap = inputs.sample_hap();
    let build = format!("{INDEX_PAGE}->#~@0>#build");
    let replies = session(&[
        call(1, "listclass", json!({"apk": hap})),
        call(2, "listclass", json!({"apk_id": "apk1", "prefix": "entry/src/main/ets/pages"})),
        call(3, "listclass", json!({"apk_id": "apk1", "all": true})),
        call(4, "getclass", json!({"apk_id": "apk1", "class": "pages/Index"})),
        call(5, "getclass", json!({"apk_id": "apk1", "class": INDEX_PAGE, "method": "#~@0>#build"})),
        call(6, "getclass", json!({"apk_id": "apk1", "class": "pages/Index.ets", "method": "Index.build"})),
        call(7, "getclass", json!({"apk_id": "apk1", "class": format!("{build}+0x12")})),
        call(8, "findrefs", json!({"apk_id": "apk1", "kind": "string", "value": "https?://"})),
        call(9, "findrefs", json!({"apk_id": "apk1", "kind": "string", "value": "login?token=", "literal": true})),
        call(10, "findrefs", json!({"apk_id": "apk1", "kind": "string", "value": "login?token="})),
        call(11, "findrefs", json!({"apk_id": "apk1", "kind": "string", "value": "testTag", "limit": 1})),
        call(12, "findrefs", json!({"apk_id": "apk1", "kind": "string", "value": "testTag", "limit": 1, "offset": 1})),
        call(13, "findrefs", json!({"apk": hap, "rule": "literal:testTag"})),
        call(14, "listclass", json!({"apk_id": "apk1", "prefix": "com.example"})),
    ]);

    // The first reply says what the program is; later ones do not repeat it.
    let listed = ok(&replies[0]);
    assert_eq!(listed["apk_id"], "apk1");
    let head: Vec<&str> = text(&replies[0]).lines().take(2).collect();
    assert_eq!(head[0], format!("# apk1: HarmonyOS program, 1 abc entry (tools: {TOOLS}; `class` is a record, `method` a function)"));
    let size = make_abc().len();
    assert_eq!(head[1], format!("# abc | ets/modules.abc | 12.0.6.0 | {size} bytes | readable"));
    assert_eq!(
        listed["program"],
        json!({
            "format": "harmony",
            "tools": TOOLS,
            "entries": [{"name": "ets/modules.abc", "version": "12.0.6.0", "size": size, "status": "readable"}],
        })
    );
    assert!(replies[1..]
        .iter()
        .all(|r| !text(r).contains("HarmonyOS program") && r["result"]["structuredContent"].get("program").is_none()));
    assert!(listed.get("notes").is_none(), "{listed}");

    // listclass: the CLI's rows, a footer with the total.
    assert_eq!(rows(&replies[0]), [format!("{ENTRY_ABILITY} | functions=3"), format!("{INDEX_PAGE} | functions=5")]);
    assert!(text(&replies[0]).ends_with("# 2 records\n"), "{}", text(&replies[0]));
    assert_eq!(
        (&listed["total"], &listed["classes"][1]["class"], &listed["classes"][1]["functions"]),
        (&json!(2), &json!(INDEX_PAGE), &json!(5))
    );
    assert_eq!(text(&replies[1]), format!("{INDEX_PAGE} | functions=5\n# 1 records\n"));
    assert_eq!(ok(&replies[2])["total"], 3);
    assert!(rows(&replies[2]).iter().any(|row| row.starts_with("_ESSlotNumberAnnotation | ")), "{}", text(&replies[2]));

    // getclass: a record by a suffix of its path, a function by its raw or
    // restored name, or by the location column of a findrefs row.
    let whole = ok(&replies[3]);
    assert_eq!((&whole["class"], &whole["entry"]), (&json!(INDEX_PAGE), &json!("ets/modules.abc")));
    assert_eq!(text(&replies[3]).lines().next(), Some(format!(".record {INDEX_PAGE}").as_str()));
    assert_eq!(functions(&replies[3]), ["func_main_0", "#~@0=#Index", "#~@0>#build", "#~@0>#aboutToAppear", "#*#helper"]);
    assert_eq!(whole["source"], text(&replies[3]));
    let by_raw_name = text(&replies[4]);
    assert_eq!(functions(&replies[4]), ["#~@0>#build"]);
    assert!(by_raw_name.contains(SAMPLE_API_URL) && !by_raw_name.contains(".record"), "{by_raw_name}");
    assert_eq!(ok(&replies[4])["methods"], json!(["#~@0>#build"]));
    for reply in &replies[5..7] {
        assert_eq!(text(reply), by_raw_name);
    }

    // findrefs: the CLI's rows; a regex or plain text; pages by offset.
    let found = ok(&replies[7]);
    let columns: Vec<&str> = rows(&replies[7])[0].split(" | ").collect();
    assert_eq!(columns[0], "ets/modules.abc");
    assert!(columns[1].starts_with(&format!("{build}+0x")), "{columns:?}");
    assert_eq!(columns[2], "Index.build");
    assert!(columns[3].ends_with(&format!("\"{SAMPLE_API_URL}\"")), "{columns:?}");
    assert_eq!((&found["total"], &found["next_offset"], &found["unsearched_entries"]), (&json!(1), &Value::Null, &json!(0)));
    let row = &found["results"][0];
    assert_eq!((&row["record"], &row["function"], &row["name"]), (&json!(INDEX_PAGE), &json!("#~@0>#build"), &json!("Index.build")));
    assert_eq!(row["matched"], json!([SAMPLE_API_URL]));
    assert_eq!(text(&replies[8]), text(&replies[7]));
    assert_eq!(text(&replies[9]), "# 0 results\n# hint: `value` is a regex; literal=true searches it as plain text\n");

    let first = ok(&replies[10]);
    assert_eq!((&first["total"], &first["returned"], &first["next_offset"]), (&json!(2), &json!(1), &json!(1)));
    assert!(rows(&replies[10])[0].contains(&format!("{ENTRY_ABILITY}->#~@0>#onCreate+0x")), "{}", text(&replies[10]));
    assert!(text(&replies[10]).ends_with("# results 0..1 of 2; call again with offset=1 for more\n"), "{}", text(&replies[10]));
    assert!(rows(&replies[11])[0].contains(&format!("{INDEX_PAGE}->#*#helper+0x")), "{}", text(&replies[11]));
    assert!(text(&replies[11]).ends_with("# results 1..2 of 2\n"), "{}", text(&replies[11]));
    // The same program by its path, the query as a rule.
    assert_eq!(ok(&replies[12])["apk_id"], "apk1");
    assert_eq!(rows(&replies[12]), [rows(&replies[10]), rows(&replies[11])].concat());

    // A prefix spelled as for a DEX program finds nothing and learns what names look like.
    assert_eq!(
        text(&replies[13]),
        format!("# 0 records\n# hint: no record name starts with \"com.example\"; the program has 2 records, e.g. {ENTRY_ABILITY}\n")
    );
}

#[test]
fn names_that_do_not_pick_one_say_what_there_is() {
    let inputs = Inputs::new();
    let abc = make_abc();
    let two = inputs.file("two.hap", &Hap::new().modules_abc(&abc).abc("widgets", &abc).module_json("{}").build());
    let replies = session(&[
        call(1, "getclass", json!({"apk": two, "class": "pages/Index"})),
        call(2, "getclass", json!({"apk": two, "class": "pages/Index", "entry": "ets/widgets.abc"})),
        call(3, "getclass", json!({"apk": two, "class": "pages/Index", "entry": "ets/nope.abc"})),
        call(4, "getclass", json!({"apk": two, "class": "pages/Missing"})),
        call(5, "getclass", json!({"apk": two, "class": "pages/Index", "method": "render", "entry": "ets/modules.abc"})),
        call(6, "listclass", json!({"apk": two})),
        call(7, "getclass", json!({"apk": two})),
    ]);
    assert_eq!(
        error(&replies[0]),
        format!(
            "record pages/Index is ambiguous, candidates:\nets/modules.abc | {INDEX_PAGE}\nets/widgets.abc | {INDEX_PAGE}\n\
             (name the entry, the first column, with `entry`)"
        )
    );
    let picked = ok(&replies[1]);
    assert_eq!((&picked["entry"], &picked["class"]), (&json!("ets/widgets.abc"), &json!(INDEX_PAGE)));
    assert_eq!(error(&replies[2]), "no entry named ets/nope.abc");
    assert_eq!(error(&replies[3]), "record pages/Missing not found");
    assert_eq!(
        error(&replies[4]),
        format!(
            "function render of {INDEX_PAGE} not found; its functions: func_main_0, #~@0=#Index (Index.constructor), \
             #~@0>#build (Index.build), #~@0>#aboutToAppear (Index.aboutToAppear), #*#helper (helper)"
        )
    );
    // Several entries: every row names its own.
    let listed = rows(&replies[5]);
    assert_eq!(listed.len(), 4);
    assert!(
        listed[..2].iter().all(|row| row.ends_with(" | ets/modules.abc"))
            && listed[2..].iter().all(|row| row.ends_with(" | ets/widgets.abc"))
    );
    assert_eq!(error(&replies[6]), "getclass needs `class` (a record, as listclass prints them)");
}

#[test]
fn every_kind_of_input_opens() {
    let inputs = Inputs::new();
    let abc = inputs.file("bare/modules.abc", &make_abc());
    let hap = make_hap(&make_abc());
    let app = inputs.file("app/sample.app", &make_app(&[("entry-default.hap", &hap), ("feature.hap", &hap)], Compression::Deflated));
    // Named by what it holds, not by its extension.
    let renamed = inputs.file("renamed/sample.zip", &hap);
    let replies = session(&[
        call(1, "listclass", json!({"apk": abc})),
        call(2, "listclass", json!({"apk": app})),
        call(3, "findrefs", json!({"apk": app, "kind": "literal", "value": SAMPLE_API_URL})),
        call(4, "getclass", json!({"apk": app, "class": "pages/Index", "method": "helper", "entry": "feature.hap/ets/modules.abc"})),
        call(5, "listclass", json!({"apk": renamed})),
        call(6, "listclass", json!({"apk_path": abc})),
    ]);
    assert_eq!(ok(&replies[0])["program"]["entries"][0]["name"], "modules.abc");
    assert_eq!(rows(&replies[0]), [format!("{ENTRY_ABILITY} | functions=3"), format!("{INDEX_PAGE} | functions=5")]);

    let bundle = ok(&replies[1]);
    assert_eq!(bundle["apk_id"], "apk2");
    let entries: Vec<&str> = bundle["program"]["entries"].as_array().unwrap().iter().map(|e| e["name"].as_str().unwrap()).collect();
    assert_eq!(entries, ["entry-default.hap/ets/modules.abc", "feature.hap/ets/modules.abc"]);
    assert!(text(&replies[1]).starts_with("# apk2: HarmonyOS program, 2 abc entries (tools: "), "{}", text(&replies[1]));
    assert_eq!(bundle["total"], 4);
    let found = rows(&replies[2]);
    assert_eq!(found.len(), 2);
    assert!(
        found[0].starts_with("entry-default.hap/ets/modules.abc | ") && found[1].starts_with("feature.hap/ets/modules.abc | "),
        "{found:?}"
    );
    assert_eq!(functions(&replies[3]), ["#*#helper"]);
    assert_eq!(ok(&replies[3])["entry"], "feature.hap/ets/modules.abc");

    assert_eq!(ok(&replies[4])["apk_id"], "apk3");
    assert_eq!(ok(&replies[4])["total"], 2);
    // The spellings models use for `apk` reach the same program.
    assert_eq!(ok(&replies[5])["apk_id"], "apk1");
}

#[test]
fn concurrent_calls_share_one_session_and_one_introduction() {
    let inputs = Inputs::new();
    let (hap, abc) = (inputs.sample_hap(), inputs.file("bare.abc", &make_abc()));
    let calls: Vec<Value> = (1..=12)
        .map(|id| call(id, "findrefs", json!({"apk": if id % 2 == 0 { &abc } else { &hap }, "kind": "string", "value": "testTag"})))
        .collect();
    let replies = served(&calls);
    assert_eq!(replies.len(), 12);
    for (reply, id) in replies.iter().zip(1..) {
        // Ids follow request order, whichever call finishes first.
        assert_eq!(ok(reply)["apk_id"], if id % 2 == 0 { "apk2" } else { "apk1" });
        assert_eq!(rows(reply).len(), 2, "{}", text(reply));
    }
    for program in ["apk1", "apk2"] {
        let introduced =
            replies.iter().filter(|reply| text(reply).starts_with(&format!("# {program}: HarmonyOS program, 1 abc entry"))).count();
        assert_eq!(introduced, 1, "{program}");
    }
    assert_eq!(replies.iter().filter(|reply| ok(reply).get("program").is_some()).count(), 2);
}

#[test]
fn what_is_not_supported_yet_says_what_is() {
    let inputs = Inputs::new();
    let hap = inputs.sample_hap();
    let kinds = KINDS;
    let to = "`to` takes call:PATTERN on a HarmonyOS program: a regex over callee paths as findrefs call prints them, e.g. \
              call:^import:@ohos:net\\.http";
    let cases: [(&str, Value, String); 36] = [
        (
            "getmanifest",
            json!({"resolve": true}),
            "`resolve` is DEX-only: module.json is printed as it is; manifest_summary puts what a $type:name reference stands for \
             behind it"
                .into(),
        ),
        (
            "getmanifest",
            json!({"file": "AndroidManifest.xml"}),
            "`file`: \"AndroidManifest.xml\" is not a manifest document: use module.json, pack.info, pkgContextInfo.json".into(),
        ),
        ("manifest_summary", json!({"file": "pkgContextInfo.json"}), format!("no pkgContextInfo.json in {hap}")),
        (
            "resources",
            json!({"query": "app_name"}),
            "\"app_name\" is not a resource: give an id (0x01000003, 16777219) or a name (string/app_name, $string:app_name, \
             app.string.app_name)"
                .into(),
        ),
        (
            "resources",
            json!({"query": "string/nothing"}),
            "resource string/nothing not found; `search` finds resources by name or value".into(),
        ),
        ("resources", json!({}), "resources needs `query` (an id or type/name), `search` or `xml`".into()),
        ("resources", json!({"search": "x", "in": "everywhere"}), "unknown in \"everywhere\": use name, value, any".into()),
        (
            "resources",
            json!({"xml": "res/xml/a.xml"}),
            "file res/xml/a.xml not found (give a path inside the package, e.g. resources/base/profile/main_pages.json, or a file \
             resource: $profile:main_pages)"
                .into(),
        ),
        (
            "resources",
            json!({"xml": "$media:icon"}),
            "entry.hap: resources/base/media/icon.png is not text (8 bytes): only text files are printed".into(),
        ),
        ("hierarchy", json!({"class": "Nowhere"}), format!("class Nowhere not found {CLASSES}")),
        ("hierarchy", json!({"class": "import:@ohos:nothing"}), format!("parent path import:@ohos:nothing not found {CLASSES}")),
        (
            "hierarchy",
            json!({"class": "import:@ohos:app", "direction": "supers"}),
            "a parent path outside the program has no supertypes here: it is a root for subclasses only".into(),
        ),
        ("hierarchy", json!({}), "hierarchy needs `class`: a class name, RECORD->CLASS as rows print it, or import:REGEX".into()),
        ("callgraph", json!({"class": "pages/Index", "method": "build", "virtual": true}), "`virtual` is DEX-only".into()),
        ("callgraph", json!({"to": "string:token"}), to.into()),
        ("callgraph", json!({"to": "method:java.lang.Runtime->exec"}), to.into()),
        (
            "callgraph",
            json!({"to": "call:x", "entry": "ets/modules.abc"}),
            "`entry` picks the root function: it does not go with `to`".into(),
        ),
        ("callgraph", json!({"class": "pages/Index", "to": "call:x"}), "give the target as `class` + `method` or as `to`, not both".into()),
        (
            "callgraph",
            json!({}),
            "callgraph needs `class` + `method` (or `class`: RECORD->FUNCTION as rows print it), or `to`: call:REGEX".into(),
        ),
        (
            "callgraph",
            json!({"class": "pages/Index", "method": "build", "direction": "callees", "from": "method:x"}),
            "`from` keeps caller paths: it goes with direction=callers (the default) or `to`".into(),
        ),
        (
            "callgraph",
            json!({"class": "pages/Index", "method": "build", "from": "string:x"}),
            "`from` takes method:[RECORD->]NAME on a HarmonyOS program: NAME a regex over function names, =NAME the exact name, e.g. \
             method:=EntryAbility.onNewWant"
                .into(),
        ),
        (
            "callgraph",
            json!({"class": "pages/Index", "method": "nowhere"}),
            format!("function nowhere of {INDEX_PAGE} not found (findrefs kind=method lists the functions a name defines)"),
        ),
        ("callgraph", json!({"class": "pages/Nope", "method": "build"}), "record pages/Nope not found".into()),
        (
            "callgraph",
            json!({"class": "pages/Index", "method": "build", "unless": "method:check"}),
            format!(
                "callgraph `unless` {NOT_YET} (callgraph takes: class + method or to=call:REGEX, from=method:NAME, direction, depth, \
                 max_nodes, defines, unresolved, entry)"
            ),
        ),
        ("findrefs", json!({"kind": "field", "name": "message"}), format!("findrefs kind=field {NOT_YET} {kinds}")),
        ("findrefs", json!({"kind": "extends", "value": "Index"}), format!("findrefs kind=extends {NOT_YET} {kinds}")),
        ("findrefs", json!({"rule": "type:Index"}), format!("findrefs kind=type {NOT_YET} {kinds}")),
        ("findrefs", json!({"rules": [{"kind": "string", "value": "token"}]}), format!("findrefs rules {NOT_YET} {kinds}")),
        ("findrefs", json!({"all": ["string:a", "!string:b"]}), format!("findrefs with excluded conditions (`!`) {NOT_YET} {kinds}")),
        ("findrefs", json!({"kind": "string", "value": "token", "context": 3}), format!("findrefs context {NOT_YET} {kinds}")),
        (
            "findrefs",
            json!({"kind": "string", "value": "token", "access": "read"}),
            "`access` is only valid for kind=prop and kind=global on HarmonyOS programs".into(),
        ),
        (
            "findrefs",
            json!({"kind": "global", "value": "console", "access": "call"}),
            "a global is read or written, not call: use `prop` or `call` for members".into(),
        ),
        (
            "findrefs",
            json!({"kind": "import", "value": "@ohos:net.http#default", "requests": true}),
            "`requests` lists module requests: leave out the #NAME".into(),
        ),
        ("findrefs", json!({"kind": "method", "name": "build", "class": "Index", "fuzzy_class": true}), "`fuzzy_class` is DEX-only".into()),
        ("findrefs", json!({"kind": "string", "value": "token", "collapse_sdks": true}), "`collapse_sdks` is DEX-only".into()),
        ("getclass", json!({"class": "pages/Index", "debug_info": true}), "`debug_info` is DEX-only".into()),
    ];
    let calls: Vec<Value> = (cases.iter().zip(1..))
        .map(|((tool, args, _), id)| {
            let mut args = args.clone();
            args["apk"] = json!(hap);
            call(id, tool, args)
        })
        .chain([
            // What a DEX-only argument turns off is how a HarmonyOS program answers anyway.
            call(
                90,
                "getclass",
                json!({"apk": hap, "class": "pages/Index", "method": "helper", "debug_info": false, "resource_names": false}),
            ),
            call(91, "findrefs", json!({"apk": hap, "kind": "string", "value": "a(b"})),
            call(92, "nosuchtool", json!({"apk": hap})),
        ])
        .collect();
    let replies = session(&calls);
    for ((tool, args, expected), reply) in cases.iter().zip(&replies) {
        assert_eq!(error(reply), expected, "{tool} {args}");
    }
    let rest = &replies[cases.len()..];
    assert_eq!(functions(&rest[0]), ["#*#helper"]);
    assert!(error(&rest[1]).starts_with("invalid pattern: "), "{}", rest[1]);
    // A tool that does not exist stays a protocol error, as for an APK.
    assert_eq!(rest[2]["error"]["code"], -32602);
}

#[test]
fn an_encrypted_entry_is_named_in_every_reply_and_left_out() {
    let inputs = Inputs::new();
    let hap = inputs.store_hap("entry.hap");
    let replies = session(&[
        call(1, "findrefs", json!({"apk": hap, "kind": "string", "value": "https?://"})),
        call(2, "listclass", json!({"apk": hap})),
        call(3, "getclass", json!({"apk": hap, "class": "pages/Missing"})),
    ]);
    let found = ok(&replies[0]);
    let lines: Vec<&str> = text(&replies[0]).lines().collect();
    let size = make_abc().len();
    assert!(lines[3].starts_with("# findrefs `value` by kind: ") && lines[4].starts_with("# manifest_summary: "), "{lines:?}");
    assert!(
        lines[5].starts_with("# resources: ") && lines[6].starts_with("# callgraph: ") && lines[7].starts_with("# hierarchy: "),
        "{lines:?}"
    );
    assert_eq!(
        [&lines[..3], &lines[8..9]].concat(),
        [
            &format!("# apk1: HarmonyOS program, 2 abc entries (tools: {TOOLS}; `class` is a record, `method` a function)"),
            &format!("# abc | ets/modules.abc | 12.0.6.0 | {size} bytes | encrypted"),
            &format!("# abc | ets/widgets.abc | 12.0.6.0 | {size} bytes | readable"),
            &format!("# warning: {ENCRYPTED}"),
        ]
    );
    assert_eq!((&found["total"], &found["unsearched_entries"], &found["notes"]), (&json!(1), &json!(1), &json!([ENCRYPTED])));
    assert_eq!(found["program"]["entries"][0]["status"], "encrypted");
    // An answer that leaves the entry out says so again.
    assert!(text(&replies[1]).starts_with(&format!("# warning: {ENCRYPTED}\n")), "{}", text(&replies[1]));
    assert!(rows(&replies[1]).iter().all(|row| row.ends_with(" | ets/widgets.abc")), "{}", text(&replies[1]));
    assert_eq!(ok(&replies[1])["notes"], json!([ENCRYPTED]));
    assert_eq!(error(&replies[2]), format!("record pages/Missing not found ({ENCRYPTED})"));
}

#[test]
fn a_decrypted_abc_next_to_its_package_stands_in() {
    let inputs = Inputs::new();
    inputs.store_hap("store/entry.hap");
    inputs.file("store/modules.abc", &make_abc());
    let replies = session(&[
        call(1, "listclass", json!({"apk": inputs.path("store")})),
        call(2, "findrefs", json!({"apk_id": "apk1", "kind": "string", "value": "https?://"})),
    ]);
    let listed = ok(&replies[0]);
    let entries = listed["program"]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2, "{entries:?}");
    assert!(entries.iter().all(|entry| entry["status"] == "readable"), "{entries:?}");
    let note = listed["notes"][0].as_str().unwrap();
    assert!(note.starts_with("entry.hap/ets/modules.abc is encrypted in its package; served from the decrypted "), "{note}");
    assert_eq!(listed["total"], 4);
    let found = ok(&replies[1]);
    assert_eq!((&found["total"], &found["unsearched_entries"]), (&json!(2), &json!(0)));
    // Nothing is left out: the note is not repeated.
    assert!(found.get("notes").is_none() && !text(&replies[1]).contains("# warning"), "{}", text(&replies[1]));
}

#[test]
fn a_large_record_goes_through_the_output_budget() {
    let inputs = Inputs::new();
    let hap = inputs.sample_hap();
    let record = json!({"apk": hap, "class": "pages/Index", "max_bytes": 600});

    // Paged: whole functions per page, the next call spelled out.
    let mut first = record.clone();
    first["spill"] = json!("never");
    let mut second = first.clone();
    second["page"] = json!(1);
    let replies = session(&[call(1, "getclass", first), call(2, "getclass", second)]);
    assert!(text(&replies[0]).starts_with("# apk1: HarmonyOS program"), "the introduction is part of what is paged");
    let page = ok(&replies[0]);
    assert_eq!(page["page"], 0);
    assert!(page["pages"].as_u64().unwrap() > 1, "{page}");
    assert_eq!(page["next"]["page"], 1);
    assert!(text(&replies[0]).contains("; next page: getclass {"), "{}", text(&replies[0]));
    assert_eq!(ok(&replies[1])["page"], 1);
    assert!(!text(&replies[1]).contains(".record "), "{}", text(&replies[1]));

    // Spilled: the head, the file and where each function is in it.
    let out = inputs.path("out");
    let replies = session_with(
        opts(Some(Path::new(&out))),
        &[call(1, "listclass", json!({"apk": hap})), call(2, "getclass", json!({"apk": hap, "class": "pages/Index", "spill": "always"}))],
    );
    // A short reply is not spilled.
    assert!(ok(&replies[0]).get("file").is_none());
    let spilled = ok(&replies[1]);
    let whole = std::fs::read_to_string(spilled["file"].as_str().unwrap()).unwrap();
    assert!(whole.starts_with(&format!(".record {INDEX_PAGE}\n")) && whole.contains("\n.function #*#helper"), "{whole}");
    assert!(text(&replies[1]).contains("# functions in that file (5), by line:\n"), "{}", text(&replies[1]));
    assert!(text(&replies[1]).contains(" #~@0>#build  ; Index.build\n"), "{}", text(&replies[1]));
    let index = spilled["index"].as_array().unwrap();
    assert_eq!(index.iter().map(|f| f["method"].as_str().unwrap()).collect::<Vec<_>>(), functions_of(&whole));
    let lines: Vec<&str> = whole.lines().collect();
    for function in index {
        let (first, last) = (function["lines"][0].as_u64().unwrap() as usize, function["lines"][1].as_u64().unwrap() as usize);
        assert!(lines[first - 1].starts_with(&format!(".function {}", function["method"].as_str().unwrap())), "{function}");
        assert!(!lines[last - 1].is_empty() && lines.get(last).is_none_or(|next| next.is_empty()), "{function}");
    }
}

/// The raw names of the `.function`s of a disassembly.
fn functions_of(source: &str) -> Vec<&str> {
    source.lines().filter_map(|line| line.strip_prefix(".function ")).map(|rest| rest.split("  ; ").next().unwrap()).collect()
}

#[test]
fn an_apk_session_is_untouched() {
    let inputs = Inputs::new();
    let dex = make_dex();
    let apk = inputs.file("app.apk", &make_apk(&[("classes.dex", &dex)], true));
    let hap = inputs.sample_hap();
    let android = |id: u64| {
        [
            call(id, "listclass", json!({"apk": apk})),
            call(id + 1, "getclass", json!({"apk": apk, "class": "example.Test"})),
            call(id + 2, "findrefs", json!({"apk": apk, "kind": "string", "value": "token"})),
            call(id + 3, "findrefs", json!({"apk": apk, "kind": "method", "name": "first", "class": "example.Test"})),
            call(id + 4, "hierarchy", json!({"apk": apk, "class": "java.lang.Object"})),
            call(id + 5, "callgraph", json!({"apk": apk, "class": "example.Test", "method": "first", "direction": "callees"})),
        ]
    };
    let alone = session(&android(1));
    let mut mixed = vec![call(1, "listclass", json!({"apk": hap}))];
    mixed.extend(android(2));
    mixed.push(call(8, "findrefs", json!({"apk": hap, "kind": "string", "value": "testTag"})));
    let together = session(&mixed);

    // One series of ids, in request order.
    assert_eq!(ok(&together[0])["apk_id"], "apk1");
    assert_eq!(ok(&together[7])["apk_id"], "apk1");
    assert_eq!(text(&alone[5]), "0 Lexample/Test;->first()V\n# 1 rows, 1 distinct methods (callees, depth 2)\n");
    assert_eq!(text(&alone[0]), "Lexample/Test;\n# 1 classes\n");
    assert_eq!(
        text(&alone[2]),
        "classes.dex | Lexample/Test;->first()V | \"token\"\nclasses.dex | Lexample/Test;->second()V | \"token\"\n# 2 results\n"
    );
    for (alone, together) in alone.iter().zip(&together[1..7]) {
        assert_eq!(text(alone), text(together));
        let (mut alone, mut together) = (ok(alone).clone(), ok(together).clone());
        assert_eq!((alone["apk_id"].take(), together["apk_id"].take()), (json!("apk1"), json!("apk2")));
        assert_eq!(alone, together);
    }

    // What only a HarmonyOS program has is refused on an APK, not ignored;
    // a HarmonyOS program is no part of a call over many APKs.
    let replies = session(&[
        call(1, "listclass", json!({"apk": apk, "all": true})),
        call(2, "getclass", json!({"apk": apk, "class": "example.Test", "entry": "classes.dex"})),
        call(3, "listclass", json!({"apk": apk, "all": false})),
        call(4, "listclass", json!({"apks": [apk, hap]})),
        call(5, "callgraph", json!({"apk": apk, "class": "example.Test", "method": "first", "defines": false})),
        call(6, "callgraph", json!({"apk": apk, "class": "example.Test", "method": "first", "unresolved": true})),
        call(7, "callgraph", json!({"apk": apk, "class": "example.Test", "method": "first", "entry": "classes.dex"})),
        call(8, "hierarchy", json!({"apk": apk, "class": "java.lang.Object", "entry": "classes.dex"})),
    ]);
    for (reply, arg) in replies[4..].iter().zip(["defines", "unresolved", "entry", "entry"]) {
        assert_eq!(error(reply), format!("`{arg}` applies to HarmonyOS programs only"));
    }
    assert_eq!(error(&replies[0]), "`all` applies to HarmonyOS programs only (a DEX program has no pseudo records)");
    assert_eq!(error(&replies[1]), "`entry` applies to HarmonyOS programs only");
    assert_eq!(text(&replies[2]), "Lexample/Test;\n# 1 classes\n");
    let swept = text(&replies[3]);
    assert!(swept.contains(" | 1 classes | ") && swept.contains("1 errors"), "{swept}");
    assert!(
        swept.contains(&format!(
            "- | error | {hap} | a HarmonyOS program: `apks` / `dir` take Android programs only; pass it alone as `apk`"
        )),
        "{swept}"
    );
}

#[test]
fn a_program_with_dex_code_stays_android_and_names_what_it_leaves_out() {
    let inputs = Inputs::new();
    inputs.file("mixed/app.apk", &make_apk(&[("classes.dex", &make_dex())], true));
    let dir = inputs.path("mixed");
    let alone = session(&[call(1, "listclass", json!({"apk": dir}))]);
    assert_eq!(text(&alone[0]), "Lexample/Test;\n# 1 classes\n");

    inputs.file("mixed/entry.hap", &make_hap(&make_abc()));
    let replies =
        session(&[call(1, "listclass", json!({"apk": dir})), call(2, "getmanifest", json!({"apk": inputs.path("mixed/entry.hap")}))]);
    let listed = ok(&replies[0]);
    assert_eq!(listed["classes"], ok(&alone[0])["classes"]);
    let notes: Vec<&str> = listed["notes"].as_array().unwrap().iter().map(|n| n.as_str().unwrap()).collect();
    assert_eq!(
        notes.last(),
        Some(&"HarmonyOS files (.hap, .hsp, .app, .abc) of this program are left out next to its DEX code; query them by their own path")
    );
    assert!(text(&replies[0]).ends_with("Lexample/Test;\n# 1 classes\n"), "{}", text(&replies[0]));
    // By its own path the file is a HarmonyOS program.
    assert!(text(&replies[1]).contains("\"bundleName\": \"com.example.sample\""), "{}", text(&replies[1]));
}

#[test]
fn resources_reads_the_index_and_the_files_it_names() {
    const LABEL: &str = "0x01000000 string/EntryAbility_label [base] \"Sample\"";
    const LABEL_ZH: &str = "0x01000000 string/EntryAbility_label [zh_CN] \"示例\"";
    const BRAND: &str = "0x01000003 color/brand [base] \"#FF0000\"";
    let inputs = Inputs::new();
    let hap = inputs.file("entry.hap", &make_hap(&resource_program().build().bytes));
    let replies = session(&[
        call(1, "resources", json!({"apk": hap, "query": "string/EntryAbility_label"})),
        call(2, "resources", json!({"apk_id": "apk1", "query": "16777218", "resolve": true})),
        call(3, "resources", json!({"apk_id": "apk1", "search": "^https?://", "in": "value"})),
        call(4, "resources", json!({"apk_id": "apk1", "search": ".", "in": "name", "limit": 2})),
        call(5, "resources", json!({"apk_id": "apk1", "search": "#FF", "literal": true})),
        call(6, "resources", json!({"apk_id": "apk1", "xml": "$profile:main_pages"})),
        call(7, "resources", json!({"apk_id": "apk1", "xml": "resources/base/profile/main_pages.json"})),
        call(8, "getclass", json!({"apk_id": "apk1", "class": LABELS_PAGE})),
        call(9, "getclass", json!({"apk_id": "apk1", "class": LABELS_PAGE, "resource_names": false})),
        call(10, "manifest_summary", json!({"apk_id": "apk1", "kind": "pack-ability"})),
    ]);
    // One resource: every value, `base` first.
    assert_eq!(rows(&replies[0]), [LABEL, LABEL_ZH]);
    assert!(text(&replies[0]).ends_with("# 2 rows\n"), "{}", text(&replies[0]));
    let found = ok(&replies[0]);
    assert_eq!((&found["total"], &found["chain"], &found["notes"]), (&json!(2), &json!([]), &json!([])));
    assert_eq!(
        found["rows"][1],
        json!({"package": "entry.hap", "id": "0x01000000", "name": "string/EntryAbility_label", "config": "zh_CN", "value": "\"示例\""})
    );
    // A decimal id, followed through the reference its value is.
    assert_eq!(text(&replies[1]), format!("chain $color:accent -> $color:brand\n{BRAND}\n# 1 rows\n"));
    assert_eq!(ok(&replies[1])["chain"], json!(["chain $color:accent -> $color:brand"]));
    assert_eq!(text(&replies[2]), "0x01000005 string/api_host [base] \"https://example.com\"\n# 1 rows\n");
    assert_eq!(text(&replies[3]), format!("{LABEL}\n{LABEL_ZH}\n# 2 of 8 rows; raise `limit` for more\n"));
    assert_eq!(ok(&replies[3])["total"], 8);
    assert_eq!(rows(&replies[4]), [BRAND]);
    // `xml` prints the file a profile resource names, or the file at a path, as it is.
    for reply in &replies[5..7] {
        assert_eq!(text(reply), SAMPLE_MAIN_PAGES);
        assert_eq!(ok(reply)["xml"], SAMPLE_MAIN_PAGES);
        assert_eq!(
            ok(reply)["files"],
            json!([{"package": "entry.hap", "path": "resources/base/profile/main_pages.json", "text": SAMPLE_MAIN_PAGES}])
        );
    }
    // getclass names the resources a function builds unless told not to, as for an APK.
    let named: Vec<&str> = text(&replies[7]).lines().filter(|line| line.contains("  # ")).collect();
    assert_eq!(named.len(), 2, "{}", text(&replies[7]));
    assert!(
        named[0].ends_with(" ]  # string/EntryAbility_label \"Sample\"") && named[1].ends_with(" ]  # color/brand \"#FF0000\""),
        "{named:?}"
    );
    assert!(!text(&replies[8]).contains("  # "), "{}", text(&replies[8]));
    assert_eq!(
        text(&replies[7]).replace("  # string/EntryAbility_label \"Sample\"", "").replace("  # color/brand \"#FF0000\"", ""),
        text(&replies[8])
    );
    assert_eq!(rows(&replies[9]), ["pack-ability entry EntryAbility label=$string:EntryAbility_label(\"Sample\")"]);

    // Several packages: rows name theirs, and a package without an index is a note of the reply.
    let abc = make_abc();
    inputs.file("pkgs/a.hap", &make_hap(&abc));
    inputs.file("pkgs/b.hsp", &Hap::new().modules_abc(&abc).module_json(SAMPLE_MODULE_JSON).build());
    let pkgs = inputs.path("pkgs");
    let replies = session(&[
        call(1, "resources", json!({"apk": pkgs, "query": "$color:brand", "limit": 1})),
        call(2, "resources", json!({"apk": pkgs, "xml": "$profile:main_pages"})),
        call(3, "resources", json!({"apk": inputs.file("bare.abc", &abc), "search": "x"})),
    ]);
    assert_eq!(rows(&replies[0]), [format!("a.hap | {BRAND}")]);
    assert!(
        text(&replies[0]).ends_with("# 1 of 2 rows; raise `limit` for more\n# warning: b.hsp: no resources.index\n"),
        "{}",
        text(&replies[0])
    );
    assert_eq!(ok(&replies[0])["notes"], json!(["b.hsp: no resources.index"]));
    assert_eq!(text(&replies[1]), format!("# a.hap/resources/base/profile/main_pages.json\n{SAMPLE_MAIN_PAGES}"));
    assert!(
        error(&replies[2]).starts_with("no resources.index in ") && error(&replies[2]).contains("a bare .abc carries none"),
        "{}",
        replies[2]
    );
}

#[test]
fn tool_definitions_mention_harmony_only_where_it_adds_an_argument() {
    let replies = session(&[
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {}}),
    ]);
    let tools = replies[0]["result"]["tools"].as_array().unwrap();
    let mentions: Vec<String> = tools
        .iter()
        .flat_map(|tool| {
            let name = tool["name"].as_str().unwrap();
            let properties = tool["inputSchema"]["properties"].as_object().unwrap();
            let in_properties =
                properties.iter().filter(|(_, p)| p.to_string().contains("HarmonyOS")).map(move |(arg, _)| format!("{name}.{arg}"));
            tool["description"].as_str().unwrap().contains("HarmonyOS").then(|| name.to_owned()).into_iter().chain(in_properties)
        })
        .collect();
    assert_eq!(mentions, ["getclass.entry", "listclass.all"], "schemas are read on every turn");
    assert!(replies[1]["result"]["instructions"].as_str().unwrap().contains("HarmonyOS: a .hap / .hsp / .app / .abc path"));
}

/// The rows the engine finds for `query`, as the CLI prints them.
fn engine_rows(path: &str, query: &asc_ark_engine::Query) -> Vec<String> {
    let engine = asc_ark_engine::Engine::open(path).unwrap();
    let mut rows = Vec::new();
    engine
        .find_refs(query, &std::sync::atomic::AtomicBool::new(false), &mut |batch| {
            rows.extend(batch.rows.iter().map(|row| row.line(&batch.entry_name)));
        })
        .unwrap();
    rows
}

#[test]
fn findrefs_answers_every_kind_the_cli_does() {
    use asc_ark_engine::{Access, Pattern, Query};
    let inputs = Inputs::new();
    let hap = inputs.sample_hap();
    let regex = |text: &str| Pattern::regex(text).unwrap();
    let import = |spec: &str, literal: bool, decl: bool| match Query::import(spec, literal).unwrap() {
        Query::Import { request, name, .. } => Query::Import { request, name, declarations_only: decl },
        other => other,
    };
    // (arguments, the query the CLI builds for the same flags, rows expected)
    let cases: Vec<(Value, Query, usize)> = vec![
        (
            json!({"kind": "prop", "value": "createHttp", "exact": true}),
            Query::Prop { name: Pattern::exact("createHttp"), access: None },
            1,
        ),
        (json!({"kind": "prop", "value": "^createH"}), Query::Prop { name: regex("^createH"), access: None }, 1),
        (json!({"kind": "prop", "value": "eateHtt", "literal": true}), Query::Prop { name: Pattern::contains("eateHtt"), access: None }, 1),
        (json!({"kind": "prop", "value": ".", "access": "write"}), Query::Prop { name: regex("."), access: Some(Access::Write) }, 2),
        (json!({"kind": "props", "value": ".", "access": "call"}), Query::Prop { name: regex("."), access: Some(Access::Call) }, 3),
        (json!({"kind": "prop", "value": "."}), Query::Prop { name: regex("."), access: None }, 5),
        (json!({"rule": "prop:=createHttp"}), Query::Prop { name: Pattern::exact("createHttp"), access: None }, 1),
        (json!({"kind": "global", "value": "console", "exact": true}), Query::global(Pattern::exact("console"), None).unwrap(), 1),
        (json!({"kind": "global", "value": ".", "access": "read"}), Query::global(regex("."), Some(Access::Read)).unwrap(), 1),
        (json!({"kind": "import", "value": "@ohos:net\\.http"}), import("@ohos:net\\.http", false, false), 2),
        (json!({"kind": "import", "value": "@ohos:net.http", "literal": true}), import("@ohos:net.http", true, false), 2),
        (json!({"kind": "import", "value": "net#default"}), import("net#default", false, false), 2),
        (json!({"kind": "import", "value": "@ohos:", "decl": true}), import("@ohos:", false, true), 3),
        (json!({"all": ["import:net#default"]}), import("net#default", false, false), 2),
        (
            json!({"kind": "method", "value": "Index.build", "exact": true}),
            Query::method("Index.build", |name| Ok(Pattern::exact(name))).unwrap(),
            1,
        ),
        (
            json!({"kind": "method", "value": format!("{INDEX_PAGE}->#~@0>#build+0x12"), "exact": true}),
            Query::method("Index.build", |name| Ok(Pattern::exact(name))).unwrap(),
            1,
        ),
        (
            json!({"kind": "method", "name": "build", "class": "pages/Index", "exact": true}),
            Query::method("pages/Index->build", |name| Ok(Pattern::exact(name))).unwrap(),
            1,
        ),
        (
            json!({"kind": "method", "name": "build", "class": "entryability/EntryAbility", "exact": true}),
            Query::method("entryability/EntryAbility->build", |name| Ok(Pattern::exact(name))).unwrap(),
            0,
        ),
        (json!({"kind": "method", "value": "^help"}), Query::method("^help", Pattern::regex).unwrap(), 1),
        (json!({"kind": "number", "value": "0x1d4b42"}), Query::Number("1919810".parse().unwrap()), 1),
        (json!({"kind": "number", "value": "1919000..1920000"}), Query::Number("1919000..1920000".parse().unwrap()), 1),
        (json!({"kind": "number", "value": "1.5"}), Query::Number("1.5".parse().unwrap()), 1),
        (json!({"rule": "number:-5..1"}), Query::Number("-5..1".parse().unwrap()), 1),
        (json!({"kind": "call", "value": "."}), Query::Call(regex(".")), 3),
        (
            json!({"kind": "call", "value": "import:@ohos:net.http#default.createHttp", "literal": true}),
            Query::Call(Pattern::contains("import:@ohos:net.http#default.createHttp")),
            1,
        ),
        (json!({"rule": "call:^global:console\\."}), Query::Call(regex("^global:console\\.")), 1),
        (
            json!({"all": ["string:^https://", "call:createHttp", "number:0x1d4b42"]}),
            Query::All(vec![
                Query::string_regex("^https://").unwrap(),
                Query::Call(regex("createHttp")),
                Query::Number("0x1d4b42".parse().unwrap()),
            ]),
            1,
        ),
        (
            json!({"rule": "string:^https:// & call:createHttp & number:0x1d4b42"}),
            Query::All(vec![
                Query::string_regex("^https://").unwrap(),
                Query::Call(regex("createHttp")),
                Query::Number("0x1d4b42".parse().unwrap()),
            ]),
            1,
        ),
        (
            json!({"all": [{"kind": "string", "value": "testTag"}, {"kind": "call", "value": "createHttp"}]}),
            Query::All(vec![Query::string_regex("testTag").unwrap(), Query::Call(regex("createHttp"))]),
            0,
        ),
    ];
    let calls: Vec<Value> = (cases.iter().zip(1..))
        .map(|((args, ..), id)| {
            let mut args = args.clone();
            args["apk"] = json!(hap);
            call(id, "findrefs", args)
        })
        .collect();
    let replies = session(&calls);
    for ((args, query, expected), reply) in cases.iter().zip(&replies) {
        let found = ok(reply);
        assert_eq!(rows(reply), engine_rows(&hap, query), "{args}");
        assert_eq!(found["total"], json!(expected), "{args}");
        assert_eq!(found["results"].as_array().unwrap().len(), *expected, "{args}");
    }

    // What the rows look like, and that a row's location is what getclass takes.
    let replies = session(&[
        call(1, "findrefs", json!({"apk": hap, "kind": "prop", "value": "createHttp", "exact": true})),
        call(2, "findrefs", json!({"apk": hap, "kind": "call", "value": "createHttp"})),
        call(3, "findrefs", json!({"apk": hap, "kind": "import", "value": ".", "requests": true})),
        call(4, "findrefs", json!({"apk": hap, "kind": "import", "value": ".", "requests": true, "limit": 1, "offset": 1})),
        call(5, "findrefs", json!({"apk": hap, "all": ["string:^https://", "call:createHttp"]})),
    ]);
    let row = &ok(&replies[0])["results"][0];
    assert_eq!((&row["record"], &row["name"], &row["matched"]), (&json!(INDEX_PAGE), &json!("Index.build"), &json!(["createHttp"])));
    assert!(rows(&replies[0])[0].ends_with(" | Index.build | ldobjbyname \"createHttp\" [call]"), "{}", text(&replies[0]));
    assert!(
        rows(&replies[1])[0].ends_with(&format!("callthis1 v0, v2 ; import:@ohos:net.http#default.createHttp(\"{SAMPLE_API_URL}\")")),
        "{}",
        text(&replies[1])
    );
    assert_eq!(
        text(&replies[2]).lines().skip_while(|line| line.starts_with('#')).collect::<Vec<_>>(),
        [
            "@ohos:app.ability.UIAbility | 1 record | default",
            "@ohos:hilog | 1 record | default",
            "@ohos:net.http | 1 record | default",
            "# 3 requests"
        ]
    );
    assert_eq!(text(&replies[3]), "@ohos:hilog | 1 record | default\n# requests 1..2 of 3; call again with offset=2 for more\n");
    assert_eq!(ok(&replies[3])["results"][0]["request"], "@ohos:hilog");
    let both = rows(&replies[4])[0].to_owned();
    assert!(both.contains(" && call +0x"), "{both}");
    let located = session(&[call(1, "getclass", json!({"apk": hap, "class": both.split(" | ").nth(1).unwrap()}))]);
    assert_eq!(functions(&located[0]), ["#~@0>#build"]);
}

#[test]
fn a_search_without_results_says_where_the_name_is() {
    let inputs = Inputs::new();
    let hap = inputs.sample_hap();
    let cases: [(Value, &str); 7] = [
        (json!({"kind": "prop", "value": "console", "exact": true}), "=console is a global name, used once: try `kind=global`"),
        (json!({"kind": "global", "value": ".", "access": "write"}), "the global is accessed once in other ways: drop access"),
        (
            json!({"kind": "method", "value": "createHttp"}),
            "no function is defined under that name, but it is a property name, used once: try `kind=prop` (access call for its calls)",
        ),
        (json!({"kind": "import", "value": "@ohos:#request", "decl": true}), "`kind=import . requests` lists the module requests of the program"),
        (
            json!({"kind": "string", "value": "@ohos:net.http", "literal": true}),
            "1 module request matches (e.g. @ohos:net.http): imports are not string operands, try `kind=import`",
        ),
        (json!({"kind": "string", "value": "login?token="}), "`value` is a regex; literal=true searches it as plain text"),
        (
            json!({"kind": "call", "value": "createhttp"}),
            "a call is matched by its callee path (import:REQUEST#NAME.member, global:NAME.member, this.member, local:FUNCTION, this@FUNCTION.member, argN@FUNCTION, lex(L,S), argN, callee().member, ?): `kind=call .` lists them all",
        ),
    ];
    let calls: Vec<Value> = (cases.iter().zip(1..))
        .map(|((args, _), id)| {
            let mut args = args.clone();
            args["apk"] = json!(hap);
            call(id, "findrefs", args)
        })
        .collect();
    for ((args, hint), reply) in cases.iter().zip(&session(&calls)) {
        assert_eq!(ok(reply)["hints"], json!([hint]), "{args}");
        assert!(text(reply).ends_with(&format!("# 0 results\n# hint: {hint}\n")), "{args}: {}", text(reply));
    }
}

#[test]
fn the_introduction_says_what_the_tools_take_once() {
    let inputs = Inputs::new();
    let hap = inputs.sample_hap();
    let replies = session(&[call(1, "listclass", json!({"apk": hap})), call(2, "listclass", json!({"apk": hap}))]);
    let head: Vec<&str> = text(&replies[0]).lines().take_while(|line| line.starts_with('#')).collect();
    assert_eq!(head.len(), 7, "{head:?}");
    assert_eq!(
        head[2],
        "# findrefs `value` by kind: string: regex (literal=true: text); literal: text; prop: property name regex (exact / literal), \
         access=read|write|define|call; global: global name regex (exact / literal), access=read|write; import: REQUEST[#NAME], REQUEST a \
         regex over the module request (@ohos:net.http), decl=true for the declarations only, requests=true for the distinct requests; method: \
         [RECORD->]FUNCTION, where it is defined (or `class` + `name`; exact); number: 1919810, 0x1d4b42, 1.5 or A..B; call: regex over \
         the resolved callee (import:@ohos:net.http#default.createHttp, global:console.log, this.x); all=[conditions]: functions \
         matching every one; entry=NAME (also listclass): only that abc entry or package (entry.hap), as rows name it: a resource id is \
         unique within one package only"
    );
    assert_eq!(
        head[3],
        "# manifest_summary: module.json, each ability / extension with record=NAME (what getclass takes) and its onXxx callbacks, a \
         `$type:name` reference followed by what it stands for (`label=$string:x(\"value\")`, `pages=$profile:main_pages(PATH)`); \
         kind=\"page\" / kind=\"route\": the page list and the route table, each with its record (`route NAME buildFunction=F \
         source=FILE record=NAME`); kind=\"abc\": the code entries; file=pack.info|pkgContextInfo.json for the other documents (also \
         getmanifest)"
    );
    assert_eq!(
        head[4],
        "# resources: resources.index rows `0x01000000 string/app_name [base] \"value\"` (`PACKAGE | ` ahead in a program of several \
         packages): query=ID (0x01000000 or decimal) or NAME (string/app_name, $string:app_name, app.string.app_name), resolve=true \
         follows `$type:id` values; search=REGEX in=name|value|any; xml=\"$profile:main_pages\" (or a path inside the package) prints \
         that text file: page lists, route tables. Code holds a resource as its id (findrefs kind=number) or as the string \
         `app.type.name`; getclass names the ids (`# string/app_name \"value\"`)"
    );
    assert_eq!(
        head[5],
        "# callgraph: class=RECORD + method=FUNCTION (or class=RECORD->FUNCTION as rows print it, or method alone), direction, depth, \
         max_nodes; or to=\"call:REGEX\" for the callers of every callee path matching (the paths of kind=call, e.g. \
         call:^import:@ohos:net\\.http); from=\"method:NAME\" keeps only the paths from the callers matching (`[from]`); defines=false \
         leaves out `[defines]` (a closure is created, not called); unresolved=true lists the unresolved call sites of callees; `entry`. \
         Rows: `[super]` proved; `[this-class]` / `[inherited]` / `[instance]` matched by name, `[reassigned]` through a \
         decorated class: not guaranteed; `[external]` / `[unresolved]` are leaves, no function of the program"
    );
    assert_eq!(
        head[6],
        "# hierarchy: class=NAME (EntryAbility) or RECORD->CLASS as rows print it, or \"import:REGEX\" / \"global:REGEX\" for the \
         subclasses of a parent outside the program (import:@ohos:app\\.ability\\.UIAbility, ^global:ViewPU$); direction, depth, \
         max_nodes, `entry`; method=NAME marks `[defines FUNCTION]` from the class literal. Rows: `[external]` / `[unresolved]` are \
         parents that are no class of the program (the path is where tracking stopped), `[reassigned]` a parent read from a binding a \
         decorator reassigns"
    );
    assert!(!text(&replies[1]).contains("findrefs `value`"), "{}", text(&replies[1]));
}

/// The package table of the sample module, plus a library.
const PKG_CONTEXT: &str = r#"{
  "entry": {"packageName": "entry", "bundleName": "", "moduleName": "", "version": "", "entryPath": "src/main/", "isSO": false, "dependencyAlias": ""},
  "@ohos/lib": {"packageName": "@ohos/lib", "bundleName": "", "moduleName": "", "version": "1.0.0", "entryPath": "Index.ets", "isSO": false, "dependencyAlias": ""}
}"#;

/// The lines of a reply about a program already introduced.
fn lines(reply: &Value) -> Vec<&str> {
    text(reply).lines().collect()
}

#[test]
fn manifest_summary_joins_components_to_records() {
    let inputs = Inputs::new();
    let table = Hap::new().modules_abc(&make_abc()).module_json(SAMPLE_MODULE_JSON).pack_info(SAMPLE_PACK_INFO).entry(
        "pkgContextInfo.json",
        PKG_CONTEXT.as_bytes(),
        Compression::Stored,
    );
    let hap = inputs.file("entry.hap", &table.build());
    let replies = session(&[
        call(1, "listclass", json!({"apk": hap})),
        call(2, "manifest_summary", json!({"apk": hap})),
        call(3, "manifest_summary", json!({"apk": hap, "filter": "all"})),
        call(4, "manifest_summary", json!({"apk": hap, "kind": "ability,deeplink"})),
        call(5, "manifest_summary", json!({"apk": hap, "name": "internet"})),
        call(6, "manifest_summary", json!({"apk": hap, "filter": "all", "offset": 13})),
        call(7, "manifest_summary", json!({"apk": hap, "file": "pkgContextInfo.json"})),
        call(8, "manifest_summary", json!({"apk": hap, "file": "pack"})),
        call(9, "getmanifest", json!({"apk": hap})),
        call(10, "getmanifest", json!({"apk": hap, "file": "pack.info"})),
    ]);
    let ability = format!(
        "ability EntryAbility exported=true (explicit) permissions=- skills=1 srcEntry=./ets/entryability/EntryAbility.ets record={ENTRY_ABILITY}"
    );
    let callbacks = format!("callbacks EntryAbility record={ENTRY_ABILITY} functions=EntryAbility.onCreate");
    // By default: what other applications reach, under a line that says so.
    let reachable = lines(&replies[1]);
    assert!(reachable[0].starts_with("# filter=exported (the default without kind / name / file): "), "{reachable:?}");
    assert!(
        reachable[1].starts_with("bundle com.example.sample ") && reachable[2].starts_with("module entry type=entry "),
        "{reachable:?}"
    );
    assert_eq!(
        reachable[3..],
        [
            ability.as_str(),
            callbacks.as_str(),
            "skill EntryAbility skill=1 actions=action.system.home entities=entity.system.home uris=1 permissions=-",
            "uri EntryAbility skill=1 scheme=sample host=open",
            "deeplink EntryAbility sample://open",
        ]
    );
    let summary = ok(&replies[1]);
    let component = &summary["packages"][0]["components"][0];
    assert_eq!(
        (&component["name"], &component["record"], &component["abc"]),
        (&json!("EntryAbility"), &json!(ENTRY_ABILITY), &json!("ets/modules.abc"))
    );
    assert_eq!(component["callbacks"], json!(["EntryAbility.onCreate"]));
    assert_eq!((&summary["apk_id"], &summary["records_total"]), (&json!("apk1"), &json!(7)));

    // Everything: the CLI's lines.
    let all = lines(&replies[2]);
    assert_eq!(all.len(), 14, "{all:?}");
    assert_eq!(all[2], format!("abc ets/modules.abc version=12.0.6.0 bytes={} status=readable", make_abc().len()));
    assert!(all.contains(&"request-permission ohos.permission.INTERNET reason=- when=- abilities=-"), "{all:?}");
    assert_eq!(all[13], "package-table packages=2 native=0 with-records=1 records=2 unlocated=0 file=pkgContextInfo.json");
    // Narrowed by kind or name: every line of that kind, and how many there are.
    assert_eq!(lines(&replies[3]), [ability.as_str(), "deeplink EntryAbility sample://open", "# records 0..2 of 2"]);
    assert_eq!(lines(&replies[4]), ["request-permission ohos.permission.INTERNET reason=- when=- abilities=-", "# records 0..1 of 1"]);
    assert_eq!(lines(&replies[5]), [all[13], "# records 13..14 of 14"]);
    // The other documents.
    assert_eq!(
        lines(&replies[6]),
        [
            "package @ohos/lib version=1.0.0 entryPath=Index.ets isSO=false bundleName=- moduleName=- dependencyAlias=- records=0",
            "package entry version=- entryPath=src/main/ isSO=false bundleName=- moduleName=- dependencyAlias=- records=2",
            "# records 0..2 of 2",
        ]
    );
    assert!(lines(&replies[7])[..4].iter().all(|line| line.starts_with("pack-")), "{}", text(&replies[7]));

    let parse = |text: &str| serde_json::from_str::<Value>(text).unwrap();
    assert_eq!(parse(text(&replies[8])), parse(SAMPLE_MODULE_JSON));
    let printed = ok(&replies[8]);
    assert_eq!((&printed["file"], &printed["documents"][0]["package"]), (&json!("module.json"), &json!("entry.hap")));
    assert_eq!(parse(printed["documents"][0]["text"].as_str().unwrap()), parse(SAMPLE_MODULE_JSON));
    assert_eq!(parse(text(&replies[9])), parse(SAMPLE_PACK_INFO));
}

#[test]
fn manifests_of_an_app_a_directory_and_what_has_none() {
    let inputs = Inputs::new();
    let hap = make_hap(&make_abc());
    let app = inputs.file("app/shop.app", &make_app(&[("entry.hap", &hap), ("feature.hap", &hap)], Compression::Deflated));
    inputs.file("dir/b/feature.hap", &hap);
    inputs.file("dir/a/entry.hap", &hap);
    let abc = inputs.file("bare/modules.abc", &make_abc());
    let encrypted = sample_program().encrypted().build().bytes;
    let store = inputs.file("store/entry.hap", &Hap::new().modules_abc(&encrypted).module_json(SAMPLE_MODULE_JSON).build());
    let renamed = SAMPLE_MODULE_JSON.replace("entryability/EntryAbility.ets", "gone/Missing.ets");
    let missing = inputs.file("missing/entry.hap", &Hap::new().modules_abc(&make_abc()).module_json(&renamed).build());
    let replies = session(&[
        call(1, "manifest_summary", json!({"apk": app, "kind": "ability,pack-app"})),
        call(2, "getmanifest", json!({"apk": app, "file": "pack.info"})),
        call(3, "manifest_summary", json!({"apk": inputs.path("dir"), "kind": "ability"})),
        call(4, "manifest_summary", json!({"apk": abc})),
        call(5, "getmanifest", json!({"apk": abc})),
        call(6, "manifest_summary", json!({"apk": store, "kind": "ability"})),
        call(7, "manifest_summary", json!({"apk": missing, "kind": "ability"})),
        call(8, "manifest_summary", json!({"apk": inputs.path("dir"), "apks": [app]})),
    ]);
    // An .app: its pack.info, which its packages carry byte for byte, is there once; then a section per
    // package, each line naming its package.
    let found = rows(&replies[0]);
    assert_eq!(found.len(), 3, "{found:?}");
    assert_eq!(found[0], "shop.app | pack-app com.example.sample bundleType=- versionCode=1000000 versionName=1.0.0");
    assert!(found[1].starts_with("entry.hap | ability EntryAbility exported=true (explicit) "), "{found:?}");
    assert!(found[1].ends_with(&format!(" record={ENTRY_ABILITY} abc=entry.hap/ets/modules.abc")), "{found:?}");
    assert!(
        found[2].starts_with("feature.hap | ability EntryAbility ") && found[2].ends_with(" abc=feature.hap/ets/modules.abc"),
        "{found:?}"
    );
    let headers: Vec<&str> = text(&replies[1]).lines().filter(|line| line.starts_with("# ") && line.contains("/pack.info")).collect();
    assert_eq!(headers, ["# shop.app/pack.info (the same in entry.hap, feature.hap)"]);
    assert_eq!(
        ok(&replies[1])["documents"].as_array().unwrap().iter().map(|document| &document["also_in"]).collect::<Vec<_>>(),
        [&json!(["entry.hap", "feature.hap"])]
    );
    // A directory: packages in path order.
    let found = rows(&replies[2]);
    assert!(found[0].starts_with("a/entry.hap | ability ") && found[1].starts_with("b/feature.hap | ability "), "{found:?}");

    // A bare .abc has no manifest: the error names what has.
    for reply in &replies[3..5] {
        assert_eq!(
            error(reply),
            format!(
                "no manifest in {abc}: a bare .abc carries no module.json; pass the .hap / .app it came from, or a directory holding both"
            )
        );
    }
    // No record, and why.
    let unresolved = rows(&replies[5]);
    assert!(
        unresolved[0].ends_with(" srcEntry=./ets/entryability/EntryAbility.ets record=- (ets/modules.abc is encrypted)"),
        "{unresolved:?}"
    );
    assert_eq!(ok(&replies[5])["packages"][0]["components"][0]["unresolved"], "ets/modules.abc is encrypted");
    assert!(
        rows(&replies[6])[0]
            .ends_with(" record=- (no record com.example.sample/entry/ets/gone/Missing or &entry/src/main/ets/gone/Missing&)"),
        "{}",
        text(&replies[6])
    );
    // Many programs at once stay an Android matter.
    assert!(!text(&replies[7]).contains("| ability "), "{}", text(&replies[7]));
}

/// The rows of a call graph with the record names of the call graph program
/// shortened to their last path segment.
fn short_tree(reply: &Value) -> Vec<String> {
    lines(reply)
        .into_iter()
        .map(|line| {
            let mut line = line.to_owned();
            for (record, name) in [(CALLS_APP, "App"), (CALLS_UTIL, "Util"), (CALLS_INDEX, "Index"), (CALLS_BOX, "Box")] {
                line = line.replace(&format!("{record}->"), &format!("{name}->"));
            }
            line.replace("@normalized:N&&&entry/src/main/ets/", "N:")
        })
        .collect()
}

/// The lines of a hierarchy with the record names of the class hierarchy
/// program shortened to their last path segment.
fn short_classes(reply: &Value) -> Vec<String> {
    lines(reply)
        .into_iter()
        .map(|line| line.replace(&format!("{CLASSES_APP}->"), "App->").replace(&format!("{CLASSES_BASE}->"), "Base->"))
        .collect()
}

#[test]
fn hierarchy_walks_both_ways_with_the_arguments_of_the_dex_tool() {
    let inputs = Inputs::new();
    let abc = inputs.file("modules.abc", &class_hierarchy_program().build().bytes);
    let local = format!("{CLASSES_APP}->#~@1=#Local");
    let replies = session(&[
        call(1, "listclass", json!({"apk": abc})),
        call(2, "hierarchy", json!({"apk_id": "apk1", "class": "Local"})),
        // The class as a row prints it: it must not come apart at its arrow.
        call(3, "hierarchy", json!({"apk_id": "apk1", "class": local})),
        call(4, "hierarchy", json!({"apk_id": "apk1", "class": "pages/App->Local", "direction": "down"})),
        call(5, "hierarchy", json!({"apk_id": "apk1", "class": "pages/App", "method": "Local"})),
        call(6, "hierarchy", json!({"apk_id": "apk1", "class": "import:@ohos:app.ability.UIAbility#default", "method": "onCreate"})),
        call(7, "hierarchy", json!({"apk_id": "apk1", "class": "UIAbility", "method": "onCreate"})),
        call(8, "hierarchy", json!({"apk_id": "apk1", "class": "GrandChild", "direction": "supers", "method": "run"})),
        call(9, "hierarchy", json!({"apk_id": "apk1", "class": "Card", "direction": "up"})),
        call(10, "hierarchy", json!({"apk_id": "apk1", "class": "Local", "depth": 1, "max_nodes": 2})),
        call(11, "hierarchy", json!({"apk_id": "apk1", "class": "Base", "method": "run"})),
        call(12, "hierarchy", json!({"apk_id": "apk1", "class_name": "Mixed", "direction": "supers"})),
    ]);
    assert!(text(&replies[0]).contains("\n# hierarchy: class=NAME (EntryAbility) or RECORD->CLASS"), "{}", text(&replies[0]));
    let tree = [
        "0 App->#~@1=#Local | Local",
        "  1 subclass App->#~@2=#Child | Child",
        "    2 subclass App->#~@3=#GrandChild | GrandChild",
        "  1 subclass App->#*@e~@9=#Inner | make.Inner",
        "# 4 rows, 4 distinct classes, 0 leaves (subclasses, depth 16); 3 records scanned",
    ];
    for reply in &replies[1..5] {
        assert_eq!(short_classes(reply), tree);
    }
    let down = ok(&replies[1]);
    assert_eq!(
        (&down["direction"], &down["depth"], &down["classes"], &down["leaves"]),
        (&json!("subclasses"), &json!(16), &json!(4), &json!(0))
    );
    assert_eq!((&down["truncated"], &down["records_scanned"]), (&json!(false), &json!(3)));
    assert_eq!(
        down["rows"][2],
        json!({
            "depth": 2, "parent": 1, "repeated": false, "class": format!("{CLASSES_APP}->#~@3=#GrandChild"), "name": "GrandChild",
            "entry": "modules.abc",
        })
    );

    // A parent outside the program: its path whole, or a name no class of the program has.
    let ability = [
        "0 import:@ohos:app.ability.UIAbility#default [external]",
        "  1 subclass App->#~@0=#EntryAbility | EntryAbility [defines #~@0>#onCreate]",
        "override App->#~@0>#onCreate | EntryAbility.onCreate",
        "# 2 rows, 1 distinct classes, 1 leaves (subclasses, depth 16); 3 records scanned; 1 subclasses define onCreate",
    ];
    assert_eq!(short_classes(&replies[5]), ability);
    assert_eq!(short_classes(&replies[6])[..4], ability);
    assert_eq!(short_classes(&replies[6])[4], "# no class of the program has that name: the roots are the parent paths that contain it");
    let by_path = ok(&replies[5]);
    assert_eq!(
        by_path["rows"][0],
        json!({"depth": 0, "parent": null, "repeated": false, "path": "import:@ohos:app.ability.UIAbility#default", "external": true})
    );
    assert_eq!(by_path["rows"][1]["defines"], json!([{"function": "#~@0>#onCreate", "name": "EntryAbility.onCreate", "static": false}]));
    assert_eq!(by_path["definitions"], json!([format!("override {CLASSES_APP}->#~@0>#onCreate | EntryAbility.onCreate")]));

    assert_eq!(
        short_classes(&replies[7]),
        [
            "0 App->#~@3=#GrandChild | GrandChild",
            "  1 extends App->#~@2=#Child | Child [defines #~@2>#run]",
            "    2 extends App->#~@1=#Local | Local [no superclass] [defines #~@1>#run]",
            "inherited App->#~@2>#run | Child.run",
            "inherited App->#~@1>#run | Local.run",
            "# 3 rows, 3 distinct classes, 0 leaves (supers, depth 16); 1 records scanned; 2 supertypes define run",
        ]
    );
    assert_eq!(ok(&replies[7])["rows"][2]["no_superclass"], true);
    assert_eq!(short_classes(&replies[8])[1], "  1 extends Base->#~@1=#Watched | Watched [no superclass] [reassigned]");
    assert_eq!(ok(&replies[8])["rows"][1]["reassigned"], true);
    let small = short_classes(&replies[9]);
    assert!(small.len() == 3 && small[2].ends_with("(subclasses, depth 1); 3 records scanned; truncated (raise max_nodes or lower depth)"));
    assert_eq!(ok(&replies[9])["truncated"], true);
    assert_eq!(
        short_classes(&replies[10])[..4],
        [
            "0 Base->#~@0=#Base | Base [defines #~@0>#run]",
            "  1 subclass App->#~@4=#Derived | Derived [defines #~@4>#run]",
            "  1 subclass App->#~@a=#Spaced | Spaced",
            "override App->#~@4>#run | Derived.run",
        ]
    );
    assert_eq!(short_classes(&replies[11])[1], "  1 extends arg0 [unresolved]");
}

#[test]
fn callgraph_walks_both_ways_with_the_arguments_of_the_dex_tool() {
    let inputs = Inputs::new();
    let abc = inputs.file("modules.abc", &call_graph_program().build().bytes);
    let run = format!("{CALLS_APP}->#*#run");
    let replies = session(&[
        call(1, "listclass", json!({"apk": abc})),
        call(2, "callgraph", json!({"apk_id": "apk1", "class": "pages/App", "method": "run", "direction": "callees", "depth": 1})),
        call(3, "callgraph", json!({"apk_id": "apk1", "class": format!("{run}+0x1c"), "direction": "down", "depth": 1})),
        call(4, "callgraph", json!({"apk_id": "apk1", "method": "#*#run", "direction": "callees", "depth": 1})),
        call(5, "callgraph", json!({"apk_id": "apk1", "class": run, "direction": "callees", "depth": 1, "unresolved": true})),
        call(6, "callgraph", json!({"apk_id": "apk1", "class": run, "direction": "callees", "depth": 1, "defines": false})),
        call(7, "callgraph", json!({"apk_id": "apk1", "class": "util/Util", "method": "star"})),
        call(8, "callgraph", json!({"apk_id": "apk1", "class": "util/Util", "method": "helper", "depth": 3, "max_nodes": 2})),
        call(9, "callgraph", json!({"apk_id": "apk1", "to": "call:^import:@ohos:net\\.http", "depth": 3})),
        call(10, "callgraph", json!({"apk_id": "apk1", "method": "star", "depth": 3, "from": "method:=cb"})),
        call(11, "callgraph", json!({"apk_id": "apk1", "to": "call:createhttp"})),
        // `to` walks callers whatever the direction says.
        call(12, "callgraph", json!({"apk_id": "apk1", "to": "call:^import:@ohos:net\\.http", "direction": "callees", "depth": 3})),
        call(13, "callgraph", json!({"apk_id": "apk1", "class": "pages/App", "method": "func_main_0"})),
    ]);
    let hints = ok(&replies[12])["hints"].as_array().unwrap();
    assert!(hints.len() == 1 && hints[0].as_str().unwrap().starts_with("no caller was resolved: "), "{hints:?}");
    assert!(text(&replies[12]).ends_with("; findrefs kind=prop value=NAME exact=true access=call lists call sites by member name\n"));
    assert!(text(&replies[0]).contains("\n# callgraph: class=RECORD + method=FUNCTION"), "{}", text(&replies[0]));
    assert_eq!(
        short_tree(&replies[1]),
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
            "  1 -> import:N:lib/Index&#Box.nothing [external]",
            "# 10 rows, 7 distinct functions, 3 leaves (callees, depth 1); 1 records scanned",
        ]
    );
    let callees = ok(&replies[1]);
    assert_eq!(
        (&callees["direction"], &callees["depth"], &callees["methods"], &callees["leaves"], &callees["truncated"]),
        (&json!("callees"), &json!(1), &json!(7), &json!(3), &json!(false))
    );
    assert_eq!(
        callees["rows"][0],
        json!({"depth": 0, "parent": null, "repeated": false, "method": run, "name": "run", "entry": "modules.abc", "unresolved": 1})
    );
    assert_eq!(
        callees["rows"][3],
        json!({
            "depth": 1, "parent": 0, "repeated": false, "method": format!("{CALLS_BOX}->#~@0=#Box"), "name": "Box.constructor",
            "entry": "modules.abc", "kind": "new", "sites": 1,
        })
    );
    assert_eq!(
        callees["rows"][6],
        json!({
            "depth": 1, "parent": 0, "repeated": false, "callee": "import:@ohos:net.http#default.createHttp", "external": true,
            "kind": "call", "sites": 1,
        })
    );
    // The root as a row prints it, and by its raw name alone.
    assert_eq!(text(&replies[2]), text(&replies[1]));
    assert_eq!(text(&replies[3]), text(&replies[1]));
    let listed = short_tree(&replies[4]);
    assert_eq!((listed.len(), listed[8].as_str()), (12, "  1 -> arg0.then [unresolved]"));
    let plain = short_tree(&replies[5]);
    assert!(plain.len() == 10 && !plain.iter().any(|line| line.contains("[defines]")), "{plain:?}");

    assert_eq!(
        short_tree(&replies[6]),
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
    assert_eq!(ok(&replies[6])["direction"], "callers");
    let capped = ok(&replies[7]);
    assert_eq!((&capped["truncated"], capped["rows"].as_array().unwrap().len()), (&json!(true), 2));
    assert!(text(&replies[7]).ends_with("; truncated (raise max_nodes or lower depth)\n"), "{}", text(&replies[7]));

    let http = [
        "0 import:@ohos:net.http#default.createHttp [external]",
        "  1 <- App->#*#run | run unresolved=1",
        "    2 <- App->func_main_0 | func_main_0 x2",
        "# 3 rows, 2 distinct functions, 1 leaves (callers, depth 3); 4 records scanned",
    ];
    assert_eq!(short_tree(&replies[8]), http);
    assert_eq!(short_tree(&replies[11]), http);
    assert_eq!(ok(&replies[11])["direction"], "callers");
    assert_eq!(
        short_tree(&replies[9]),
        [
            "0 Util->#*#star | star",
            "  1 <- Util->#*#helper | helper",
            "    2 <- App->#*@0*#cb | run.cb [from]",
            "# 9 rows, 6 distinct functions, 0 leaves (callers, depth 3); 3 records scanned",
            "# from: 3 of 9 rows shown: 1 path from 1 matching function",
        ]
    );
    // The rows shown point at each other.
    let kept = ok(&replies[9])["rows"].as_array().unwrap();
    assert_eq!(kept.iter().map(|row| &row["parent"]).collect::<Vec<_>>(), [&json!(null), &json!(0), &json!(1)]);
    let hint = "no call site has a callee path matching call:createhttp: the paths are what findrefs kind=call prints \
                (import:REQUEST#NAME.member, global:NAME.member, this.member); `findrefs kind=call .` lists them all";
    assert_eq!(ok(&replies[10])["hints"], json!([hint]));
    assert!(text(&replies[10]).ends_with(&format!("; 4 records scanned\n# hint: {hint}\n")), "{}", text(&replies[10]));
}

#[test]
fn a_call_graph_goes_through_the_output_budget_and_names_entries_that_differ() {
    let inputs = Inputs::new();
    let abc = inputs.file("modules.abc", &call_graph_program().build().bytes);
    // Paged: the next call is spelled out, and answers.
    let tree = json!({"apk": abc, "class": "pages/App", "method": "func_main_0", "direction": "callees", "depth": 3});
    let mut first = tree.clone();
    first["max_bytes"] = json!(700);
    first["spill"] = json!("never");
    let replies = session(&[call(1, "listclass", json!({"apk": abc})), call(2, "callgraph", tree), call(3, "callgraph", first)]);
    let whole = lines(&replies[1]);
    let page = ok(&replies[2]);
    assert!(page["pages"].as_u64().unwrap() > 1, "{page}");
    let next = page["next"].clone();
    assert_eq!(next["page"], 1);
    let more = session(&[call(1, "listclass", json!({"apk": abc})), call(2, "callgraph", next)]);
    let shown: Vec<&str> = lines(&replies[2]).into_iter().chain(lines(&more[1])).filter(|line| !line.starts_with('#')).collect();
    assert_eq!(shown[..4], whole[..4], "{shown:?}");
    assert!(shown.len() > 4 && shown.iter().all(|line| whole.contains(line)), "{shown:?}");

    // One record in two entries: ambiguous until `entry` picks one; by name alone both are roots.
    let abc = make_abc();
    let two = inputs.file("two.hap", &Hap::new().modules_abc(&abc).abc("widgets", &abc).module_json("{}").build());
    let replies = session(&[
        call(1, "listclass", json!({"apk": two})),
        call(2, "callgraph", json!({"apk": two, "class": "pages/Index", "method": "Index.build", "direction": "callees"})),
        call(
            3,
            "callgraph",
            json!({"apk": two, "class": "pages/Index", "method": "Index.build", "direction": "callees", "entry": "ets/widgets.abc"}),
        ),
        call(4, "callgraph", json!({"apk": two, "method": "Index.build", "direction": "callees", "depth": 0})),
    ]);
    assert!(error(&replies[1]).ends_with("(name the entry, the first column, with `entry`)"), "{}", error(&replies[1]));
    assert_eq!(lines(&replies[2])[0], format!("0 {INDEX_PAGE}->#~@0>#build | Index.build"));
    assert!(lines(&replies[2]).last().unwrap().ends_with("; all in ets/widgets.abc"), "{}", text(&replies[2]));
    assert_eq!(ok(&replies[2])["rows"][0]["entry"], "ets/widgets.abc");
    assert_eq!(
        lines(&replies[3])[..2],
        [
            format!("0 {INDEX_PAGE}->#~@0>#build | Index.build [ets/modules.abc]"),
            format!("0 {INDEX_PAGE}->#~@0>#build | Index.build [ets/widgets.abc]")
        ]
    );
}

#[test]
fn pages_routes_long_strings_and_one_package_of_several() {
    use asc_fixture::hap::{library_program, make_library_hsp, make_routed_hap, DETAIL_PAGE, LONG_FILLER_BYTES, SHARED_PAGE};
    let inputs = Inputs::new();
    inputs.file("app/entry.hap", &make_routed_hap());
    inputs.file("app/lib.hsp", &make_library_hsp());
    let app = inputs.path("app");
    // Two app-store packages next to their decrypted code.
    let encrypted = sample_program().encrypted().build().bytes;
    inputs.file("stores/a.hap", &Hap::new().modules_abc(&encrypted).module_json(SAMPLE_MODULE_JSON).build());
    inputs.file("stores/a.hap.abc", &make_abc());
    inputs.file("stores/b.hsp", &Hap::new().modules_abc(&library_program().encrypted().build().bytes).module_json("{}").build());
    inputs.file("stores/b.hsp.abc", &library_program().build().bytes);
    let stores = inputs.path("stores");
    let replies = session(&[
        call(1, "manifest_summary", json!({"apk": app})),
        call(2, "manifest_summary", json!({"apk": app, "kind": "route"})),
        call(3, "manifest_summary", json!({"apk": app, "kind": "page,pack-info", "filter": "all"})),
        call(4, "findrefs", json!({"apk": app, "kind": "literal", "value": "example.com/far"})),
        call(5, "findrefs", json!({"apk": app, "kind": "string", "value": "shared|detail", "entry": "lib.hsp"})),
        call(6, "findrefs", json!({"apk": app, "kind": "string", "value": "shared", "entry": "nope.hsp"})),
        call(7, "listclass", json!({"apk": app, "entry": "lib.hsp"})),
        call(8, "findrefs", json!({"apk": app, "kind": "string", "value": "nothing-like-this", "entry": "entry.hap"})),
        call(9, "listclass", json!({"apk": stores})),
        call(10, "findrefs", json!({"apk": stores, "kind": "string", "value": "shared"})),
        call(11, "manifest_summary", json!({"apk": stores, "kind": "abc"})),
    ]);
    // By default pages and routes are left out, of the lines and of the structured reply.
    assert!(lines(&replies[0]).iter().all(|line| !line.contains(" | route ") && !line.contains(" | page ")), "{}", text(&replies[0]));
    assert!(ok(&replies[0])["packages"][0].get("routes").is_none());
    let routes = lines(&replies[1]);
    assert_eq!(routes.len(), 5, "{routes:?}");
    assert_eq!(
        routes[..2],
        [
            format!(
                "entry.hap | route detail buildFunction=DetailBuilder source=src/main/ets/pages/Detail.ets record={DETAIL_PAGE} \
                 abc=entry.hap/ets/modules.abc"
            ),
            format!(
                "entry.hap | route lib/shared buildFunction=SharedBuilder source=src/main/ets/pages/Shared.ets package=@sample/lib \
                 record={SHARED_PAGE} abc=lib.hsp/ets/modules.abc"
            ),
        ]
    );
    assert!(routes[3].ends_with(" record=- (no record com.example.sample/entry/ets/pages/Gone or &entry/src/main/ets/pages/Gone&)"));
    assert_eq!(routes[4], "# records 0..4 of 4");
    assert_eq!(ok(&replies[1])["packages"][0]["routes"][1]["abc"], "lib.hsp/ets/modules.abc");
    assert_eq!(
        lines(&replies[2]),
        [
            format!("entry.hap | page pages/Index record={INDEX_PAGE} abc=entry.hap/ets/modules.abc"),
            "entry.hap | pack-info packages=2 (pack.info is byte for byte the same in lib.hsp: listed once, here)".to_owned(),
            "lib.hsp | pack-info same-as=entry.hap (pack.info is byte for byte the one listed there)".to_owned(),
            "# records 0..3 of 3".to_owned(),
        ]
    );

    // Long strings are cut in the rows and in the structured reply; the match is shown where it is.
    let limit = asc_ark_engine::text::ROW_STRING_BYTES;
    let found = rows(&replies[3]);
    assert_eq!(found.len(), 3, "{found:?}");
    assert!(found.iter().all(|row| row.len() < limit + 600 && row.contains(" match at byte ")), "{found:?}");
    let matched: Vec<&str> = ok(&replies[3])["results"].as_array().unwrap().iter().map(|row| row["matched"][0].as_str().unwrap()).collect();
    assert!(matched.iter().all(|text| text.len() < limit + 40 && text.contains("… (+")), "{matched:?}");
    assert!(
        matched[1].ends_with(&format!("a… (+{} bytes)", LONG_FILLER_BYTES + "https://example.com/far/operand".len() - limit)),
        "{}",
        matched[1]
    );

    // `entry` keeps a search or a listing to one package; one that is not there says what is.
    assert_eq!(
        rows(&replies[4]),
        [format!("lib.hsp/ets/modules.abc | {SHARED_PAGE}->#*#SharedBuilder+0x0 | SharedBuilder | lda.str \"shared\"")]
    );
    assert_eq!(
        error(&replies[5]),
        "no entry named nope.hsp (entries: entry.hap/ets/modules.abc, lib.hsp/ets/modules.abc; a package names all of its entries)"
    );
    assert_eq!(rows(&replies[6]), [format!("{SHARED_PAGE} | functions=1 | lib.hsp/ets/modules.abc")]);
    assert_eq!(ok(&replies[7])["hints"].as_array().unwrap().last().unwrap(), "entry=entry.hap kept the search to 1 of the 2 abc entries");

    // Decrypted files next to several packages: one note, once, and nothing is a warning.
    let note = "2 encrypted abc entries are served from the decrypted files next to them (manifest-summary names each: its `abc` lines)";
    let first = text(&replies[8]);
    assert_eq!(first.lines().filter(|line| line.starts_with("# note: ")).collect::<Vec<_>>(), [format!("# note: {note}")]);
    assert!(!first.contains("# warning"), "{first}");
    assert!(first.contains(" bytes | readable (encrypted in the package; served from the decrypted a.hap.abc)\n"), "{first}");
    assert_eq!(ok(&replies[8])["notes"], json!([note]));
    let later = text(&replies[9]);
    assert!(!later.contains("# note") && !later.contains("# warning") && ok(&replies[9]).get("notes").is_none(), "{later}");
    assert_eq!(ok(&replies[9])["unsearched_entries"], 0);
    let entries = lines(&replies[10]);
    assert!(
        entries[0].starts_with("a.hap | abc a.hap/ets/modules.abc ")
            && entries[0].ends_with(" served-from=a.hap.abc (encrypted in the package)")
    );
    assert!(
        entries[1].starts_with("b.hsp | abc b.hsp/ets/modules.abc ")
            && entries[1].ends_with(" served-from=b.hsp.abc (encrypted in the package)")
    );
}

#[test]
fn entry_is_refused_on_a_dex_program() {
    let inputs = Inputs::new();
    let apk = inputs.file("app.apk", &asc_fixture::make_apk(&[("classes.dex", &asc_fixture::make_dex())], true));
    let replies = session(&[
        call(1, "findrefs", json!({"apk": apk, "kind": "string", "value": "x", "entry": "classes.dex"})),
        call(2, "listclass", json!({"apk": apk, "entry": "classes.dex"})),
    ]);
    for reply in &replies {
        assert_eq!(error(reply), "`entry` applies to HarmonyOS programs only");
    }
}
