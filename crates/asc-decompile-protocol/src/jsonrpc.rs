//! The untyped JSON-RPC 2.0 envelope.

use std::fmt;

use serde::de::{self, DeserializeOwned};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::methods::{Method, NotificationMethod};

/// Value of the `jsonrpc` member of every message.
pub const JSONRPC_VERSION: &str = "2.0";

/// Identifier correlating a request with its response.
///
/// asc always sends numbers; strings are accepted because JSON-RPC allows them.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    /// A numeric id, the form asc sends.
    Number(i64),
    /// A string id, echoed back verbatim.
    String(String),
}

impl From<i64> for RequestId {
    fn from(id: i64) -> Self {
        Self::Number(id)
    }
}

impl From<String> for RequestId {
    fn from(id: String) -> Self {
        Self::String(id)
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Number(id) => write!(f, "{id}"),
            Self::String(id) => write!(f, "{id:?}"),
        }
    }
}

/// A JSON-RPC error code.
///
/// Kept open (a newtype, not an enum) because backends may define their own
/// codes from `-33000` on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ErrorCode(pub i32);

impl ErrorCode {
    /// A line is not valid JSON.
    pub const PARSE_ERROR: Self = Self(-32700);
    /// The JSON is not a valid JSON-RPC message.
    pub const INVALID_REQUEST: Self = Self(-32600);
    /// The method is unknown to the receiver.
    pub const METHOD_NOT_FOUND: Self = Self(-32601);
    /// `params` does not match the method's schema.
    pub const INVALID_PARAMS: Self = Self(-32602);
    /// The receiver failed while handling a valid request.
    pub const INTERNAL_ERROR: Self = Self(-32603);
    /// The request was aborted after `notifications/cancelled`.
    pub const REQUEST_CANCELLED: Self = Self(-32800);
    /// `programId` does not name an open program session.
    pub const PROGRAM_NOT_FOUND: Self = Self(-33001);
    /// The backend does not accept this `input.kind`.
    pub const UNSUPPORTED_INPUT: Self = Self(-33002);
    /// A license or feature the request needs is not available.
    pub const UNAVAILABLE: Self = Self(-33003);

    /// The symbolic name of a code defined by the protocol, if it is one.
    pub fn name(self) -> Option<&'static str> {
        let name = match self {
            Self::PARSE_ERROR => "parse error",
            Self::INVALID_REQUEST => "invalid request",
            Self::METHOD_NOT_FOUND => "method not found",
            Self::INVALID_PARAMS => "invalid params",
            Self::INTERNAL_ERROR => "internal error",
            Self::REQUEST_CANCELLED => "request cancelled",
            Self::PROGRAM_NOT_FOUND => "program not found",
            Self::UNSUPPORTED_INPUT => "unsupported input",
            Self::UNAVAILABLE => "unavailable",
            _ => return None,
        };
        Some(name)
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => write!(f, "{} ({name})", self.0),
            None => write!(f, "{}", self.0),
        }
    }
}

/// The `error` member of a failed response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, thiserror::Error)]
#[error("{message} [{code}]")]
pub struct ErrorObject {
    /// `code`: what kind of failure this is.
    pub code: ErrorCode,
    /// `message`: a short human-readable description.
    pub message: String,
    /// `data`: optional backend-defined details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl ErrorObject {
    /// An error object without `data`.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), data: None }
    }
}

/// A call that expects a [`Response`] with the same id.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    /// `id`: echoed back in the response.
    pub id: RequestId,
    /// `method`: the method name, e.g. `program/open`.
    pub method: String,
    /// `Value::Null` when the message has no `params`.
    pub params: Value,
}

impl Request {
    /// Builds a request for a typed method.
    ///
    /// # Errors
    ///
    /// Fails when `params` cannot be represented as JSON (a non-UTF-8 path, for example).
    pub fn new<M: Method>(id: RequestId, params: &M::Params) -> Result<Self, serde_json::Error> {
        Ok(Self { id, method: M::NAME.to_owned(), params: serde_json::to_value(params)? })
    }

    /// Decodes `params` as `P`; a missing `params` reads as an empty object.
    ///
    /// # Errors
    ///
    /// Returns an `-32602 invalid params` error object ready to send back.
    pub fn params<P: DeserializeOwned>(&self) -> Result<P, ErrorObject> {
        decode_params(&self.params)
    }
}

/// A message that expects no response.
#[derive(Debug, Clone, PartialEq)]
pub struct Notification {
    /// `method`: the method name, e.g. `notifications/cancelled`.
    pub method: String,
    /// `Value::Null` when the message has no `params`.
    pub params: Value,
}

impl Notification {
    /// Builds a notification for a typed method.
    ///
    /// # Errors
    ///
    /// Fails when `params` cannot be represented as JSON.
    pub fn new<N: NotificationMethod>(params: &N::Params) -> Result<Self, serde_json::Error> {
        Ok(Self { method: N::NAME.to_owned(), params: serde_json::to_value(params)? })
    }

    /// Decodes `params` as `P`; a missing `params` reads as an empty object.
    ///
    /// # Errors
    ///
    /// Returns an `-32602 invalid params` error object.
    pub fn params<P: DeserializeOwned>(&self) -> Result<P, ErrorObject> {
        decode_params(&self.params)
    }
}

fn decode_params<P: DeserializeOwned>(params: &Value) -> Result<P, ErrorObject> {
    let decoded = match params {
        Value::Null => P::deserialize(Value::Object(Map::new())),
        params => P::deserialize(params),
    };
    decoded.map_err(|err| ErrorObject::new(ErrorCode::INVALID_PARAMS, err.to_string()))
}

/// The answer to a [`Request`].
#[derive(Debug, Clone, PartialEq)]
pub struct Response {
    /// `None` only when the request could not be parsed far enough to read its id.
    pub id: Option<RequestId>,
    /// The `result` member on success, the `error` member on failure.
    pub outcome: Result<Value, ErrorObject>,
}

impl Response {
    /// A successful response carrying `result`.
    ///
    /// # Errors
    ///
    /// Fails when `result` cannot be represented as JSON.
    pub fn success(id: RequestId, result: &impl Serialize) -> Result<Self, serde_json::Error> {
        Ok(Self { id: Some(id), outcome: Ok(serde_json::to_value(result)?) })
    }

    /// A failed response carrying `error`.
    pub fn error(id: Option<RequestId>, error: ErrorObject) -> Self {
        Self { id, outcome: Err(error) }
    }
}

/// Any message on the wire.
#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    /// Has `method` and `id`.
    Request(Request),
    /// Has `method` but no `id`.
    Notification(Notification),
    /// Has `result` or `error`.
    Response(Response),
}

impl From<Request> for Message {
    fn from(message: Request) -> Self {
        Self::Request(message)
    }
}

impl From<Notification> for Message {
    fn from(message: Notification) -> Self {
        Self::Notification(message)
    }
}

impl From<Response> for Message {
    fn from(message: Response) -> Self {
        Self::Response(message)
    }
}

/// The wire shape of an outgoing message; absent members are skipped.
#[derive(Serialize)]
struct WireOut<'a> {
    jsonrpc: &'static str,
    /// `Some(None)` writes `"id": null`, which a response must carry when its id is unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<Option<&'a RequestId>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<&'a Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<&'a Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a ErrorObject>,
}

impl Serialize for Message {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut wire = WireOut { jsonrpc: JSONRPC_VERSION, id: None, method: None, params: None, result: None, error: None };
        // JSON-RPC wants `params` to be structured, so a null one is omitted.
        fn params(params: &Value) -> Option<&Value> {
            (!params.is_null()).then_some(params)
        }
        match self {
            Self::Request(request) => {
                wire.id = Some(Some(&request.id));
                wire.method = Some(&request.method);
                wire.params = params(&request.params);
            }
            Self::Notification(notification) => {
                wire.method = Some(&notification.method);
                wire.params = params(&notification.params);
            }
            Self::Response(response) => {
                wire.id = Some(response.id.as_ref());
                match &response.outcome {
                    Ok(result) => wire.result = Some(result),
                    Err(error) => wire.error = Some(error),
                }
            }
        }
        wire.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Message {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut object = Map::<String, Value>::deserialize(deserializer)?;
        // Tolerate a missing `jsonrpc` member but reject a different version.
        if let Some(version) = object.remove("jsonrpc")
            && version != JSONRPC_VERSION
        {
            return Err(de::Error::custom(format_args!("unsupported jsonrpc version {version}")));
        }
        let id = match object.remove("id") {
            None | Some(Value::Null) => None,
            Some(id) => Some(RequestId::deserialize(id).map_err(de::Error::custom)?),
        };
        let params = object.remove("params").unwrap_or(Value::Null);
        if let Some(method) = object.remove("method") {
            let Value::String(method) = method else {
                return Err(de::Error::custom("`method` is not a string"));
            };
            return Ok(match id {
                Some(id) => Self::Request(Request { id, method, params }),
                None => Self::Notification(Notification { method, params }),
            });
        }
        let outcome = match (object.remove("result"), object.remove("error")) {
            (Some(result), None) => Ok(result),
            (None, Some(error)) => Err(ErrorObject::deserialize(error).map_err(de::Error::custom)?),
            (Some(_), Some(_)) => return Err(de::Error::custom("response has both `result` and `error`")),
            (None, None) => return Err(de::Error::custom("message has neither `method` nor `result` / `error`")),
        };
        Ok(Self::Response(Response { id, outcome }))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn parse(value: Value) -> Message {
        serde_json::from_value(value).unwrap()
    }

    #[test]
    fn classifies_messages() {
        let request = parse(json!({"jsonrpc": "2.0", "id": 1, "method": "shutdown"}));
        assert_eq!(request, Message::Request(Request { id: 1.into(), method: "shutdown".into(), params: Value::Null }));

        let notification = parse(json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 3}}));
        assert!(matches!(notification, Message::Notification(n) if n.params["requestId"] == 3));

        let response = parse(json!({"jsonrpc": "2.0", "id": "a", "result": null}));
        assert_eq!(response, Message::Response(Response { id: Some(RequestId::String("a".into())), outcome: Ok(Value::Null) }));

        let error = parse(json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": "bad"}}));
        assert_eq!(error, Message::Response(Response::error(None, ErrorObject::new(ErrorCode::PARSE_ERROR, "bad"))));
    }

    #[test]
    fn rejects_malformed_messages() {
        for bad in [
            json!({"jsonrpc": "1.0", "id": 1, "method": "x"}),
            json!({"jsonrpc": "2.0", "id": 1}),
            json!({"jsonrpc": "2.0", "id": 1, "result": 1, "error": {"code": 1, "message": ""}}),
            json!({"jsonrpc": "2.0", "method": 5}),
            json!([1, 2]),
        ] {
            assert!(serde_json::from_value::<Message>(bad.clone()).is_err(), "{bad} should be rejected");
        }
    }

    #[test]
    fn serializes_wire_shape() {
        let request = Message::Request(Request { id: 7.into(), method: "shutdown".into(), params: Value::Null });
        assert_eq!(serde_json::to_value(&request).unwrap(), json!({"jsonrpc": "2.0", "id": 7, "method": "shutdown"}));

        let response = Message::Response(Response::error(None, ErrorObject::new(ErrorCode::REQUEST_CANCELLED, "cancelled")));
        assert_eq!(
            serde_json::to_value(&response).unwrap(),
            json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32800, "message": "cancelled"}})
        );

        let null_result = Message::Response(Response { id: Some(1.into()), outcome: Ok(Value::Null) });
        assert_eq!(serde_json::to_value(&null_result).unwrap(), json!({"jsonrpc": "2.0", "id": 1, "result": null}));
    }

    #[test]
    fn missing_params_decode_as_empty_object() {
        #[derive(Debug, Deserialize)]
        struct Empty {}
        let request = Request { id: 1.into(), method: "x".into(), params: Value::Null };
        assert!(request.params::<Empty>().is_ok());
        let err = Request { id: 1.into(), method: "x".into(), params: json!(3) }.params::<Empty>().unwrap_err();
        assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
    }

    #[test]
    fn error_code_display_names_known_codes() {
        assert_eq!(ErrorCode::PROGRAM_NOT_FOUND.to_string(), "-33001 (program not found)");
        assert_eq!(ErrorCode(-33100).to_string(), "-33100");
    }
}
