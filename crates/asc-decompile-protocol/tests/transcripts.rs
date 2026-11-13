//! Recorded protocol sessions read into the typed messages and written back.
//!
//! Each line of `tests/data/*.jsonl` is `{"dir":"→"|"←","msg":{…}}`, `→` from
//! asc. Every message must decode into the typed params or result of its
//! method (a response by the method of the request with its id) and encode
//! back to the same JSON. Params and results go on the wire through
//! `serde_json::Value` (keys sorted), so the same value is the same bytes.
//!
//! `arkdec-session.jsonl` is written by hand from `docs/decompile-backends.md`
//! §6.5 until one is recorded from the real worker. `dexdec-session.jsonl` is
//! a P1 (DEX) session: the ABC additions must not change a byte of it.

use std::collections::HashMap;

use asc_decompile_protocol::methods::{
    Cancelled, ClassUnit, DecompileClasses, DecompileClassesParams, DecompileClassesResult, Initialize, InitializeResult, Initialized,
    InputKind, Language, Method, NotificationMethod, ProgramClose, ProgramInput, ProgramOpen, ProgramOpenParams, Progress, Shutdown,
};
use asc_decompile_protocol::{ErrorCode, FrameReader, FrameWriter, Message, Notification, Request, RequestId, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

/// A typed message of a session, with the direction it travelled.
struct Entry {
    from_asc: bool,
    message: Message,
}

fn session(name: &str) -> Vec<Entry> {
    let path = format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{path}: {err}"));
    let mut entries = Vec::new();
    // Requests by id per direction, so responses find their method.
    let mut methods: HashMap<(bool, RequestId), String> = HashMap::new();
    for (index, line) in text.lines().enumerate() {
        let at = format!("{name}:{}", index + 1);
        let line: Value = serde_json::from_str(line).unwrap_or_else(|err| panic!("{at}: {err}"));
        let from_asc = match line["dir"].as_str() {
            Some("→") => true,
            Some("←") => false,
            other => panic!("{at}: dir {other:?}"),
        };
        let wire = format!("{}\n", line["msg"]);
        let message = FrameReader::new(wire.as_bytes()).read_message().unwrap_or_else(|err| panic!("{at}: {err}")).unwrap();
        let typed = match &message {
            Message::Request(request) => {
                methods.insert((from_asc, request.id.clone()), request.method.clone());
                Message::Request(retyped_request(request).unwrap_or_else(|| panic!("{at}: unknown method {}", request.method)))
            }
            Message::Notification(notification) => Message::Notification(
                retyped_notification(notification).unwrap_or_else(|| panic!("{at}: unknown notification {}", notification.method)),
            ),
            Message::Response(response) => {
                let id = response.id.clone().unwrap_or_else(|| panic!("{at}: response without id"));
                let method = methods.remove(&(!from_asc, id)).unwrap_or_else(|| panic!("{at}: response to no request"));
                Message::Response(retyped_response(&method, response))
            }
        };
        // Written as asc / a backend writes it, the message is the recorded one.
        let mut written = FrameWriter::new(Vec::new());
        written.write_message(&typed).unwrap();
        let written: Value = serde_json::from_slice(&written.into_inner()).unwrap();
        assert_eq!(written, line["msg"], "{at}");
        entries.push(Entry { from_asc, message: typed });
    }
    assert!(methods.is_empty(), "{name}: requests without a response: {methods:?}");
    entries
}

/// `value` through `T` and back.
fn retyped<T: Serialize + DeserializeOwned>(value: &Value) -> Value {
    let typed: T = serde_json::from_value(value.clone()).unwrap_or_else(|err| panic!("{err} in {value}"));
    serde_json::to_value(typed).unwrap()
}

fn retyped_params<M: Method>(request: &Request) -> Request {
    Request { params: retyped::<M::Params>(&request.params), ..request.clone() }
}

fn retyped_request(request: &Request) -> Option<Request> {
    Some(match request.method.as_str() {
        Initialize::NAME => retyped_params::<Initialize>(request),
        ProgramOpen::NAME => retyped_params::<ProgramOpen>(request),
        ProgramClose::NAME => retyped_params::<ProgramClose>(request),
        DecompileClasses::NAME => retyped_params::<DecompileClasses>(request),
        Shutdown::NAME => retyped_params::<Shutdown>(request),
        _ => return None,
    })
}

fn retyped_notification(notification: &Notification) -> Option<Notification> {
    let params = match notification.method.as_str() {
        Initialized::NAME => retyped::<<Initialized as NotificationMethod>::Params>(&notification.params),
        Cancelled::NAME => retyped::<<Cancelled as NotificationMethod>::Params>(&notification.params),
        Progress::NAME => retyped::<<Progress as NotificationMethod>::Params>(&notification.params),
        _ => return None,
    };
    Some(Notification { params, ..notification.clone() })
}

fn retyped_response(method: &str, response: &Response) -> Response {
    let Ok(result) = &response.outcome else { return response.clone() };
    let result = match method {
        Initialize::NAME => retyped::<<Initialize as Method>::Result>(result),
        ProgramOpen::NAME => retyped::<<ProgramOpen as Method>::Result>(result),
        ProgramClose::NAME => retyped::<<ProgramClose as Method>::Result>(result),
        DecompileClasses::NAME => retyped::<<DecompileClasses as Method>::Result>(result),
        Shutdown::NAME => retyped::<<Shutdown as Method>::Result>(result),
        other => panic!("response to unknown method {other}"),
    };
    Response { outcome: Ok(result), ..response.clone() }
}

fn requests<'a, M: Method>(entries: &'a [Entry]) -> impl Iterator<Item = M::Params> + 'a {
    entries.iter().filter_map(|entry| match &entry.message {
        Message::Request(request) if entry.from_asc && request.method == M::NAME => Some(request.params().unwrap()),
        _ => None,
    })
}

fn results<T: DeserializeOwned>(entries: &[Entry]) -> impl Iterator<Item = T> + '_ {
    entries.iter().filter_map(|entry| match &entry.message {
        Message::Response(Response { outcome: Ok(result), .. }) if !entry.from_asc => serde_json::from_value(result.clone()).ok(),
        _ => None,
    })
}

fn errors(entries: &[Entry]) -> Vec<ErrorCode> {
    entries
        .iter()
        .filter_map(|entry| match &entry.message {
            Message::Response(Response { outcome: Err(error), .. }) => Some(error.code),
            _ => None,
        })
        .collect()
}

#[test]
fn arkdec_session_replays() {
    let entries = session("arkdec-session.jsonl");

    let capabilities: Vec<InitializeResult> = results(&entries).collect();
    let [capabilities] = capabilities.as_slice() else { panic!("one initialize result") };
    assert_eq!(capabilities.inputs, [InputKind::Abc]);
    assert_eq!(capabilities.languages, [Language::JavaScript]);

    for open in requests::<ProgramOpen>(&entries) {
        let ProgramOpenParams { input: ProgramInput::Abc { files, sha256, .. }, .. } = &open else { panic!("abc input: {open:?}") };
        assert_eq!(files.len(), 1, "one ABC file per program");
        assert!(sha256.as_ref().is_some_and(|sha| sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit())));
    }
    let asked: Vec<DecompileClassesParams> = requests::<DecompileClasses>(&entries).collect();
    assert_eq!(asked.len(), 3);
    for params in &asked {
        assert_eq!(params.language, Language::JavaScript);
        assert!(params.options.keys().all(|option| capabilities.honours(option)), "only declared options: {:?}", params.options);
    }

    let units: Vec<ClassUnit> = results(&entries).flat_map(|result: DecompileClassesResult| result.units).collect();
    assert_eq!(units.len(), 3);
    for unit in &units {
        let Some(text) = unit.text() else { continue };
        for method in &unit.methods {
            assert!(method.slice(text).is_some(), "{}: span {:?} not in the text", method.signature, method.span);
        }
    }
    let build = &units[0].methods[1];
    assert_eq!(build.restored.as_deref(), Some("Index.build"));
    assert!(build.slice(units[0].text().unwrap()).unwrap().starts_with("  build() {"));
    assert_eq!(units[0].diagnostics[0].pc, Some(88));

    assert_eq!(errors(&entries), [ErrorCode::INPUT_MISMATCH, ErrorCode::REQUEST_CANCELLED]);
}

#[test]
fn dexdec_session_is_unchanged_from_p1() {
    let entries = session("dexdec-session.jsonl");
    for params in requests::<DecompileClasses>(&entries) {
        assert!(params.options.is_empty());
        let wire = serde_json::to_value(&params).unwrap();
        assert!(wire.get("options").is_none(), "no options member for DEX: {wire}");
    }
    for result in results::<DecompileClassesResult>(&entries) {
        for method in result.units.iter().flat_map(|unit| &unit.methods) {
            assert!(method.restored.is_none() && method.level.is_none() && method.span.is_none());
        }
    }
    assert_eq!(errors(&entries), [ErrorCode::PROGRAM_NOT_FOUND]);
}
