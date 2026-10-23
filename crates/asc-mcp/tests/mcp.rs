//! MCP sessions against synthetic APKs, driven through `serve`.

use asc_engine::CacheConfig;
use asc_fixture::{make_apk, make_class_only_dex, make_dex};
use serde_json::{json, Value};
use std::io::Write;

/// `bytes` as an `.apk` file that lives as long as the returned handle.
fn temp_apk_from(bytes: &[u8]) -> tempfile::NamedTempFile {
    let mut f = tempfile::Builder::new().suffix(".apk").tempfile().unwrap();
    f.write_all(bytes).unwrap();
    f.flush().unwrap();
    f
}

fn temp_apk() -> tempfile::NamedTempFile {
    let dex = make_dex();
    temp_apk_from(&make_apk(&[("classes.dex", &dex), ("classes2.dex", &dex)], true))
}

fn opts() -> asc_mcp::Options {
    asc_mcp::Options { threads: 2, debug: false, cache: CacheConfig { memory_bytes: 64 << 20, disk: None } }
}

/// Run one session: `messages` in, one parsed reply per request out.
fn session(messages: &[Value]) -> Vec<Value> {
    let input: String = messages.iter().map(|m| m.to_string() + "\n").collect();
    let mut out = Vec::new();
    asc_mcp::serve(input.as_bytes(), &mut out, opts()).unwrap();
    // Tool calls run concurrently, so replies come back in any order.
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

#[test]
fn full_session() {
    let apk = temp_apk();
    let path = apk.path().to_str().unwrap();
    let replies = session(&[
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        call(3, "open_apk", json!({"apk": path})),
        call(4, "findrefs", json!({"apk_id": "apk1", "kind": "string", "value": "token"})),
        call(5, "findrefs", json!({"apk_id": "apk1", "kind": "string", "value": "token", "limit": 3, "offset": 1})),
        call(6, "findrefs", json!({"apk_id": "apk1", "kind": "method", "name": "first", "class": "example.Test", "exact": true})),
        call(7, "getclass", json!({"apk_id": "apk1", "class": "example.Test"})),
        call(8, "listclass", json!({"apk_id": "apk1", "prefix": "example"})),
        call(9, "open_apk", json!({"apk": path})),
        call(10, "close_apk", json!({"apk_id": "apk1"})),
        json!({"jsonrpc": "2.0", "id": 11, "method": "ping"}),
    ]);
    // The notification gets no reply.
    assert_eq!(replies.len(), 11);
    assert_eq!(replies[0]["id"], 1);
    assert_eq!(replies[0]["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(replies[0]["result"]["serverInfo"]["name"], "droidasc");

    let tools: Vec<&str> = replies[1]["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(tools, ["open_apk", "close_apk", "getclass", "findrefs", "callgraph", "listclass", "getmanifest"]);

    let open = ok(&replies[2]);
    assert_eq!(open["apk_id"], "apk1");
    assert_eq!(open["dex_entries"], 2);
    assert_eq!(open["classes"], 2);
    assert!(open["memory_cache_bytes"].as_u64().unwrap() > 0);

    // CLI line format, stable order across entries, footer with the total.
    let all = ok(&replies[3]);
    assert_eq!(all["total"], 4);
    assert_eq!(all["next_offset"], Value::Null);
    let lines: Vec<&str> = text(&replies[3]).lines().collect();
    assert_eq!(lines.len(), 5);
    assert!(lines[..2].iter().all(|l| l.starts_with("classes.dex | Lexample/Test;->")), "{lines:?}");
    assert!(lines[2..4].iter().all(|l| l.starts_with("classes2.dex | ")), "{lines:?}");
    assert!(lines.contains(&"classes.dex | Lexample/Test;->first | matched=(token)"));
    assert_eq!(lines[4], "# 4 results");

    let page = ok(&replies[4]);
    assert_eq!((page["returned"].as_u64(), page["next_offset"].as_u64()), (Some(3), None));
    assert_eq!(text(&replies[4]).lines().next().unwrap(), lines[1]);
    assert_eq!(page["results"][0]["dex"], "classes.dex");

    // The fixture defines `first` but never invokes it.
    assert_eq!(ok(&replies[5])["total"], 0);
    assert_eq!(text(&replies[5]), "# 0 results\n");

    let class = ok(&replies[6]);
    assert_eq!(class["class"], "Lexample/Test;");
    assert!(text(&replies[6]).contains(".class public Lexample/Test;"));
    assert!(text(&replies[6]).contains("const-string v0, \"token\""));

    let classes = ok(&replies[7]);
    assert_eq!(classes["total"], 2);
    assert_eq!(text(&replies[7]), "Lexample/Test;\nLexample/Test;\n# 2 classes\n");

    // Same path → same session.
    assert_eq!(ok(&replies[8])["apk_id"], "apk1");
    let closed = ok(&replies[9]);
    assert_eq!(closed["closed"], true);
    assert!(closed["released_bytes"].as_u64().unwrap() > 0);
    assert_eq!(replies[10]["result"], json!({}));
}

#[test]
fn apk_path_opens_implicitly_and_apks_are_independent() {
    let (a, b) = (temp_apk(), temp_apk_from(&make_apk(&[("classes.dex", &make_class_only_dex(&["Lother/Only;"], 0, false))], true)));
    let replies = session(&[
        call(1, "listclass", json!({"apk": a.path().to_str().unwrap()})),
        call(2, "listclass", json!({"apk": b.path().to_str().unwrap()})),
        call(3, "findrefs", json!({"apk_id": "apk1", "kind": "type", "value": "Lexample/Test;"})),
    ]);
    assert_eq!(ok(&replies[0])["apk_id"], "apk1");
    assert_eq!(ok(&replies[1])["apk_id"], "apk2");
    assert_eq!(text(&replies[1]), "Lother/Only;\n# 1 classes\n");
    assert_eq!(ok(&replies[2])["apk_id"], "apk1");
}

#[test]
fn errors_keep_the_session_alive() {
    let apk = temp_apk();
    let path = apk.path().to_str().unwrap();
    let not_apk = temp_apk_from(b"not a zip");
    let replies = session(&[
        json!("just a string"),
        call(1, "getclass", json!({"apk": path, "class": "Lnope/Missing;"})),
        call(2, "findrefs", json!({"apk": path, "kind": "string", "value": "("})),
        call(3, "findrefs", json!({"apk": path, "kind": "bogus"})),
        call(4, "getclass", json!({"apk_id": "apk99", "class": "a.B"})),
        call(5, "open_apk", json!({"apk": "/nonexistent/x.apk"})),
        call(6, "open_apk", json!({"apk": not_apk.path().to_str().unwrap()})),
        call(7, "listclass", json!({"apk": path, "limit": 0})),
        call(8, "no_such_tool", json!({})),
        json!({"jsonrpc": "2.0", "id": 9, "method": "resources/list"}),
        call(10, "findrefs", json!({"apk": path, "kind": "string", "value": "token"})),
    ]);
    // Unparsable line and non-object message: JSON-RPC errors with a null id.
    let mut lines = Vec::new();
    asc_mcp::serve("{not json\n".as_bytes(), &mut lines, opts()).unwrap();
    let parse: Value = serde_json::from_slice(&lines).unwrap();
    assert_eq!(parse["error"]["code"], -32700);
    assert_eq!(replies[0]["error"]["code"], -32600);

    for (i, needle) in [(1, "not found"), (2, "pattern"), (3, "unknown kind"), (4, "apk99"), (5, "cannot open"), (6, ""), (7, "limit")] {
        let r = &replies[i];
        assert_eq!(r["result"]["isError"], true, "{r}");
        let msg = text(r);
        assert!(msg.starts_with("Error: ") && msg.contains(needle), "{msg}");
    }
    assert_eq!(replies[8]["error"]["code"], -32602);
    assert_eq!(replies[9]["error"]["code"], -32601);
    assert_eq!(ok(&replies[10])["total"], 4);
}

#[test]
fn findrefs_literal_and_class_relations_and_method_filter() {
    let apk = temp_apk();
    let path = apk.path().to_str().unwrap();
    let replies = session(&[
        call(1, "findrefs", json!({"apk": path, "kind": "string", "value": "tok.n"})),
        call(2, "findrefs", json!({"apk": path, "kind": "string", "value": "tok.n", "literal": true})),
        call(3, "findrefs", json!({"apk": path, "kind": "string", "value": "oke", "literal": true})),
        call(4, "findrefs", json!({"apk": path, "kind": "extends", "value": "java.lang.Object"})),
        call(5, "findrefs", json!({"apk": path, "kind": "impl", "value": "java.lang.Runnable"})),
        call(6, "getclass", json!({"apk": path, "class": "example.Test", "method": "nope()V"})),
    ]);
    // A regex dot matches; the same text taken literally does not.
    assert!(ok(&replies[0])["total"].as_u64().unwrap() > 0);
    assert_eq!(ok(&replies[1])["total"], 0);
    assert_eq!(ok(&replies[2])["total"], ok(&replies[0])["total"]);
    assert!(text(&replies[3]).contains("Lexample/Test; extends Ljava/lang/Object;"), "{}", text(&replies[3]));
    assert_eq!(ok(&replies[4])["total"], 0);
    assert_eq!(replies[5]["result"]["isError"], true, "{}", replies[5]);
}

#[test]
fn findrefs_context_and_callgraph() {
    let apk = temp_apk_from(&make_apk(&[("classes.dex", &asc_fixture::make_rich_dex())], true));
    let path = apk.path().to_str().unwrap();
    let replies = session(&[
        call(1, "findrefs", json!({"apk": path, "kind": "string", "value": "llo", "context": 0})),
        call(2, "findrefs", json!({"apk": path, "kind": "string", "value": "llo", "context": "method", "limit": 1})),
        call(3, "findrefs", json!({"apk": path, "kind": "string", "value": "llo", "context": "lots"})),
        call(4, "callgraph", json!({"apk": path, "class": "example.Rich", "method": "compute"})),
        call(5, "callgraph", json!({"apk": path, "class": "Lexample/Rich;", "method": "<init>()V", "direction": "callees"})),
        call(6, "callgraph", json!({"apk": path, "class": "example.Rich", "method": "compute", "direction": "up"})),
        call(7, "callgraph", json!({"apk": path, "class": "example.Rich", "method": "missing"})),
    ]);
    let r = ok(&replies[0]);
    let compute = r["results"].as_array().unwrap().iter().find(|r| r["method"] == "Lexample/Rich;->compute").unwrap();
    assert_eq!(compute["sites"], json!([{"pc": 16, "line": 14, "matched": asc_fixture::RICH_STRING}]));
    let ctx = compute["context"].as_str().unwrap();
    assert!(ctx.starts_with("  @ pc 0x10 line 14\n  >     const-string v0, "), "{ctx}");
    assert!(text(&replies[0]).contains("Lexample/Rich;->compute | matched=("), "{}", text(&replies[0]));
    let r = ok(&replies[1]);
    assert_eq!(r["returned"], 1);
    assert!(r["results"][0]["context"].as_str().unwrap().contains(".end method"));
    assert_eq!(replies[2]["result"]["isError"], true);

    assert_eq!(
        text(&replies[3]),
        "0 Lexample/Rich;->compute(II)I\n  1 <- Lexample/Rich;->compute(II)I (repeated)\n# 2 rows, 1 distinct methods (callers, depth 2)\n"
    );
    let r = ok(&replies[3]);
    assert_eq!((r["methods"].as_u64(), r["rows"][1]["parent"].as_u64()), (Some(1), Some(0)));
    assert_eq!(text(&replies[4]).lines().nth(1), Some("  1 -> Ljava/lang/Object;-><init>()V [no body]"));
    assert_eq!(replies[5]["result"]["isError"], true);
    assert!(text(&replies[6]).contains("no method Lexample/Rich;->missing"), "{}", text(&replies[6]));
}

#[test]
fn concurrent_calls_all_answer_and_close_waits_for_running_ones() {
    let apk = temp_apk();
    let path = apk.path().to_str().unwrap();
    let mut msgs = vec![call(1, "open_apk", json!({"apk": path}))];
    for id in 2..40 {
        msgs.push(if id % 3 == 0 {
            json!({"jsonrpc": "2.0", "id": id, "method": "ping"})
        } else {
            call(id, "findrefs", json!({"apk_id": "apk1", "kind": "string", "value": "token"}))
        });
    }
    msgs.push(call(40, "close_apk", json!({"apk_id": "apk1"})));
    msgs.push(call(41, "findrefs", json!({"apk_id": "apk1", "kind": "string", "value": "token"})));
    let replies = session(&msgs);
    let ids: Vec<u64> = replies.iter().map(|r| r["id"].as_u64().unwrap()).collect();
    assert_eq!(ids, (1..=41).collect::<Vec<_>>());
    let first = ok(&replies[1]).clone();
    for r in &replies[1..39] {
        if r["id"].as_u64().unwrap() % 3 == 0 {
            assert_eq!(r["result"], json!({}));
        } else {
            // Every call issued before close_apk ran against the open APK.
            assert_eq!(ok(r)["results"], first["results"]);
        }
    }
    assert_eq!(ok(&replies[39])["closed"], true);
    assert_eq!(replies[40]["result"]["isError"], true);
}
