//! Tolerant, by-hand reading of `serde_json` documents: a wrongly typed
//! field becomes a [`Note`] and is skipped, a field nobody asked for is
//! reported as unmodelled, and nothing fails the document.

use std::borrow::Cow;
use std::fmt;

use serde_json::{Map, Value};

use crate::HapError;

/// A field that was present but could not be used.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Note {
    /// JSON path of the field (`module.abilities[0].exported`).
    pub path: String,
    /// What was wrong: `expected string, found number`.
    pub message: String,
}

impl fmt::Display for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

/// What reading a document left behind besides the model.
#[derive(Debug, Default)]
pub(crate) struct Findings {
    pub notes: Vec<Note>,
    /// JSON paths of fields the model has no place for.
    pub unmodelled: Vec<String>,
}

/// Parse `bytes` as a JSON document whose root is an object. A UTF-8 byte
/// order mark is accepted.
pub(crate) fn parse_object(bytes: &[u8]) -> Result<Map<String, Value>, HapError> {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    match serde_json::from_slice(bytes)? {
        Value::Object(map) => Ok(map),
        other => Err(HapError::NotAnObject { found: kind(&other) }),
    }
}

/// The document re-serialized with two-space indentation and a trailing
/// newline.
pub(crate) fn pretty(raw: &Value) -> String {
    let mut text = serde_json::to_string_pretty(raw).expect("a serde_json::Value always serializes");
    text.push('\n');
    text
}

pub(crate) fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// One JSON object being read. Every accessor records the key as modelled;
/// [`Obj::finish`] reports the keys nobody asked for.
pub(crate) struct Obj<'v, 'f> {
    map: &'v Map<String, Value>,
    path: String,
    findings: &'f mut Findings,
    read: Vec<&'static str>,
}

impl<'v, 'f> Obj<'v, 'f> {
    pub(crate) fn root(map: &'v Map<String, Value>, findings: &'f mut Findings) -> Self {
        Obj { map, path: String::new(), findings, read: Vec::new() }
    }

    pub(crate) fn to_value(&self) -> Value {
        Value::Object(self.map.clone())
    }

    fn child_path(&self, key: &str) -> String {
        if self.path.is_empty() { key.to_owned() } else { format!("{}.{key}", self.path) }
    }

    /// The value under `key`; JSON `null` counts as absent.
    fn get(&mut self, key: &'static str) -> Option<&'v Value> {
        self.read.push(key);
        self.map.get(key).filter(|v| !v.is_null())
    }

    fn mismatch(&mut self, path: String, expected: &str, found: &Value) {
        self.findings.notes.push(Note { path, message: format!("expected {expected}, found {}", kind(found)) });
    }

    fn typed<T>(&mut self, key: &'static str, expected: &str, pick: impl FnOnce(&'v Value) -> Option<T>) -> Option<T> {
        let value = self.get(key)?;
        let picked = pick(value);
        if picked.is_none() {
            self.mismatch(self.child_path(key), expected, value);
        }
        picked
    }

    pub(crate) fn str(&mut self, key: &'static str) -> Option<String> {
        self.typed(key, "string", |v| v.as_str().map(str::to_owned))
    }

    /// A string, or a number or boolean spelled as text: for fields such
    /// as `port` and metadata values that tools write either way.
    pub(crate) fn text(&mut self, key: &'static str) -> Option<String> {
        self.typed(key, "string, number or boolean", |v| match v {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            Value::Null | Value::Array(_) | Value::Object(_) => None,
        })
    }

    pub(crate) fn bool(&mut self, key: &'static str) -> Option<bool> {
        self.typed(key, "boolean", Value::as_bool)
    }

    pub(crate) fn int(&mut self, key: &'static str) -> Option<i64> {
        self.typed(key, "integer", Value::as_i64)
    }

    /// An array of strings; elements of another type are noted and skipped.
    pub(crate) fn strings(&mut self, key: &'static str) -> Vec<String> {
        let Some(items) = self.typed(key, "array", Value::as_array) else {
            return Vec::new();
        };
        let mut out = Vec::with_capacity(items.len());
        for (i, item) in items.iter().enumerate() {
            match item.as_str() {
                Some(s) => out.push(s.to_owned()),
                None => self.mismatch(format!("{}[{i}]", self.child_path(key)), "string", item),
            }
        }
        out
    }

    pub(crate) fn object<T>(&mut self, key: &'static str, read: impl FnOnce(&mut Obj<'v, '_>) -> T) -> Option<T> {
        let map = self.typed(key, "object", Value::as_object)?;
        Some(self.descend(map, self.child_path(key), read))
    }

    /// An array of objects; elements of another type are noted and skipped.
    pub(crate) fn objects<T>(&mut self, key: &'static str, mut read: impl FnMut(&mut Obj<'v, '_>) -> T) -> Vec<T> {
        let Some(items) = self.typed(key, "array", Value::as_array) else {
            return Vec::new();
        };
        let mut out = Vec::with_capacity(items.len());
        for (i, item) in items.iter().enumerate() {
            let path = format!("{}[{i}]", self.child_path(key));
            match item.as_object() {
                Some(map) => out.push(self.descend(map, path, &mut read)),
                None => self.mismatch(path, "object", item),
            }
        }
        out
    }

    fn descend<T>(&mut self, map: &'v Map<String, Value>, path: String, read: impl FnOnce(&mut Obj<'v, '_>) -> T) -> T {
        let mut child = Obj { map, path, findings: self.findings, read: Vec::new() };
        let value = read(&mut child);
        child.finish();
        value
    }

    /// Mark presentation-only keys as known so they are not reported.
    pub(crate) fn ignore(&mut self, keys: &[&'static str]) {
        self.read.extend_from_slice(keys);
    }

    /// Report every key that no accessor asked for. `fooId`, the numeric
    /// resource id the packer writes next to a `$type:name` reference in
    /// `foo`, is not reported when `foo` is modelled.
    pub(crate) fn finish(self) {
        for key in self.map.keys() {
            let key = key.as_str();
            let known = |k: &str| self.read.contains(&k);
            if known(key) || key.strip_suffix("Id").is_some_and(known) {
                continue;
            }
            self.findings.unmodelled.push(self.child_path(key));
        }
    }
}

/// A value as one whitespace-free token: verbatim when it already is one,
/// otherwise as a JSON string literal ([`asc_query::text::quoted`]).
pub(crate) fn token(text: &str) -> Cow<'_, str> {
    if !text.is_empty() && !text.chars().any(|c| c.is_whitespace() || asc_query::text::must_escape(c) || c == '"') {
        return Cow::Borrowed(text);
    }
    Cow::Owned(asc_query::text::quoted(text))
}

/// `key=value` fragments of a summary line; absent values print as `-`.
pub(crate) struct Line(String);

impl Line {
    pub(crate) fn new(record: &str) -> Self {
        Line(record.to_owned())
    }

    /// A bare positional word.
    #[must_use]
    pub(crate) fn word(mut self, text: &str) -> Self {
        self.0.push(' ');
        self.0.push_str(&token(text));
        self
    }

    #[must_use]
    pub(crate) fn raw(mut self, key: &str, value: impl fmt::Display) -> Self {
        self.0.push_str(&format!(" {key}={value}"));
        self
    }

    #[must_use]
    pub(crate) fn opt(self, key: &str, value: Option<&str>) -> Self {
        match value {
            Some(v) => {
                let v = token(v);
                self.raw(key, v)
            }
            None => self.raw(key, "-"),
        }
    }

    #[must_use]
    pub(crate) fn flag(self, key: &str, value: Option<bool>) -> Self {
        self.num(key, value)
    }

    #[must_use]
    pub(crate) fn num<T: fmt::Display>(self, key: &str, value: Option<T>) -> Self {
        match value {
            Some(v) => self.raw(key, v),
            None => self.raw(key, "-"),
        }
    }

    #[must_use]
    pub(crate) fn list(self, key: &str, values: &[String]) -> Self {
        if values.is_empty() {
            return self.raw(key, "-");
        }
        let joined = values.iter().map(|v| token(v)).collect::<Vec<_>>().join(",");
        self.raw(key, joined)
    }

    /// Like [`Line::opt`], but prints nothing when the value is absent.
    #[must_use]
    pub(crate) fn opt_present(self, key: &str, value: Option<&str>) -> Self {
        if value.is_some() { self.opt(key, value) } else { self }
    }

    #[must_use]
    pub(crate) fn flag_present(self, key: &str, value: Option<bool>) -> Self {
        if value.is_some() { self.flag(key, value) } else { self }
    }

    #[must_use]
    pub(crate) fn list_present(self, key: &str, values: &[String]) -> Self {
        if values.is_empty() { self } else { self.list(key, values) }
    }

    pub(crate) fn end(self) -> String {
        self.0
    }
}
