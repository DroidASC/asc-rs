//! Resource types and the values stored for them.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use super::reader::Reader;

/// The type of a resource: the `string` of `$string:app_name` and of
/// `$r('app.string.app_name')`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResourceType {
    Integer,
    String,
    StrArray,
    IntArray,
    Boolean,
    Color,
    Id,
    Theme,
    Plural,
    Float,
    Media,
    Profile,
    Pattern,
    Symbol,
    /// A type number this crate has no name for.
    Other(u32),
}

struct TypeRow {
    kind: ResourceType,
    /// The number stored in the index.
    code: u32,
    name: &'static str,
    /// The `type` of the object `$r(...)` compiles to, for the types that
    /// have one.
    object_code: Option<u32>,
}

const fn row(kind: ResourceType, code: u32, name: &'static str, object_code: Option<u32>) -> TypeRow {
    TypeRow { kind, code, name, object_code }
}

const TYPES: &[TypeRow] = &[
    row(ResourceType::Integer, 8, "integer", Some(10007)),
    row(ResourceType::String, 9, "string", Some(10003)),
    row(ResourceType::StrArray, 10, "strarray", Some(10009)),
    row(ResourceType::IntArray, 11, "intarray", Some(10006)),
    row(ResourceType::Boolean, 12, "boolean", Some(10005)),
    row(ResourceType::Color, 14, "color", Some(10001)),
    row(ResourceType::Id, 15, "id", None),
    row(ResourceType::Theme, 16, "theme", None),
    row(ResourceType::Plural, 17, "plural", Some(10004)),
    row(ResourceType::Float, 18, "float", Some(10002)),
    row(ResourceType::Media, 19, "media", Some(20000)),
    row(ResourceType::Profile, 20, "profile", None),
    row(ResourceType::Pattern, 22, "pattern", Some(10008)),
    row(ResourceType::Symbol, 23, "symbol", Some(40000)),
];

impl ResourceType {
    fn row(self) -> Option<&'static TypeRow> {
        TYPES.iter().find(|row| row.kind == self)
    }

    /// From the number stored in the index.
    pub fn from_code(code: u32) -> ResourceType {
        TYPES.iter().find(|row| row.code == code).map_or(ResourceType::Other(code), |row| row.kind)
    }

    /// The number stored in the index.
    pub fn code(self) -> u32 {
        match self {
            ResourceType::Other(code) => code,
            named => named.row().map_or(0, |row| row.code),
        }
    }

    /// From the `type` of a compiled `$r(...)`: the compiler turns
    /// `$r('app.string.x')` into the object literal
    /// `{ id: 16777236, type: 10003, params: [], bundleName, moduleName }`,
    /// where 10003 says string. `None` for a number that names no index
    /// type, such as 30000 (`$rawfile`, which has no id).
    pub fn from_object_code(code: u32) -> Option<ResourceType> {
        TYPES.iter().find(|row| row.object_code == Some(code)).map(|row| row.kind)
    }

    /// The `type` a compiled `$r(...)` of this type carries.
    pub fn object_code(self) -> Option<u32> {
        self.row().and_then(|row| row.object_code)
    }
}

/// The name used in references: `string`, `media`, `profile`. An unnamed
/// type is `type<number>`.
impl fmt::Display for ResourceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.row() {
            Some(row) => f.write_str(row.name),
            None => write!(f, "type{}", self.code()),
        }
    }
}

/// The text was not the name of a resource type.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown resource type {0:?}")]
pub struct UnknownResourceType(String);

impl FromStr for ResourceType {
    type Err = UnknownResourceType;

    /// A type name (`string`), or `type<number>` as `Display` writes an
    /// unnamed one.
    fn from_str(s: &str) -> Result<ResourceType, UnknownResourceType> {
        if let Some(row) = TYPES.iter().find(|row| row.name == s) {
            return Ok(row.kind);
        }
        s.strip_prefix("type")
            .and_then(|code| code.parse().ok())
            .map(ResourceType::from_code)
            .ok_or_else(|| UnknownResourceType(s.to_owned()))
    }
}

/// A reference to a resource by type and name, as `module.json` writes
/// it (`$string:app_name`) or as source code does (`app.string.app_name`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceRef<'s> {
    pub kind: ResourceType,
    /// The resource name. Values inside the index refer by decimal id
    /// instead (`$color:16777245`); [`ResourceIndex::resolve`] takes both.
    ///
    /// [`ResourceIndex::resolve`]: super::ResourceIndex::resolve
    pub name: &'s str,
}

impl<'s> ResourceRef<'s> {
    /// `$type:name` or `app.type.name`. `None` for anything else,
    /// including system resources (`$ohos:string:x`, `sys.string.x`),
    /// which no package's index holds.
    pub fn parse(text: &'s str) -> Option<ResourceRef<'s>> {
        let (kind, name) = match text.strip_prefix('$') {
            Some(rest) => rest.split_once(':')?,
            None => text.strip_prefix("app.")?.split_once('.')?,
        };
        if name.is_empty() {
            return None;
        }
        Some(ResourceRef { kind: kind.parse().ok()?, name })
    }
}

/// `$type:name`.
impl fmt::Display for ResourceRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "${}:{}", self.kind, self.name)
    }
}

/// A name with its value: a plural form, or an attribute of a theme or
/// pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attr<'a> {
    pub name: Cow<'a, str>,
    pub value: Cow<'a, str>,
}

/// What the index stores for one resource under one qualifier set. Every
/// value is text in the file; text that is not UTF-8 is read lossily.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceValue<'a> {
    /// string, integer, boolean, color, float, symbol, id: the text as
    /// written in the source (`#FFFFFF`, `50fp`, `true`), or a reference
    /// to another resource by id (`$color:16777245`).
    Text(Cow<'a, str>),
    /// media, profile: where the file is, as the index spells it:
    /// `entry/resources/base/media/icon.png`.
    File(Cow<'a, str>),
    /// strarray, intarray.
    Array(Vec<Cow<'a, str>>),
    /// plural: one text per quantity (`one`, `other`).
    Plural(Vec<Attr<'a>>),
    /// theme, pattern.
    Map {
        /// The theme or pattern this one extends, as a reference.
        parent: Option<Cow<'a, str>>,
        attrs: Vec<Attr<'a>>,
    },
    /// The bytes of a value of an unnamed type, or of a list that does
    /// not read as one.
    Raw(&'a [u8]),
}

impl<'a> ResourceValue<'a> {
    /// `terminated` says the format ends every value with a NUL that its
    /// length counts (the first index format does).
    pub(super) fn decode(kind: ResourceType, bytes: &'a [u8], terminated: bool) -> ResourceValue<'a> {
        let bytes = match bytes.split_last() {
            Some((0, rest)) if terminated => rest,
            _ => bytes,
        };
        let text = || String::from_utf8_lossy(bytes);
        let raw = ResourceValue::Raw(bytes);
        match kind {
            ResourceType::Integer
            | ResourceType::String
            | ResourceType::Boolean
            | ResourceType::Color
            | ResourceType::Id
            | ResourceType::Float
            | ResourceType::Symbol => ResourceValue::Text(text()),
            ResourceType::Media | ResourceType::Profile => ResourceValue::File(text()),
            ResourceType::StrArray | ResourceType::IntArray => strings(bytes).map_or(raw, ResourceValue::Array),
            ResourceType::Plural => match strings(bytes) {
                Some(items) if items.len() % 2 == 0 => ResourceValue::Plural(pairs(items)),
                _ => raw,
            },
            ResourceType::Theme | ResourceType::Pattern => match strings(bytes) {
                // An odd count is how the format says the first string is the parent.
                Some(mut items) if items.len() % 2 == 1 => {
                    let parent = items.remove(0);
                    ResourceValue::Map { parent: Some(parent), attrs: pairs(items) }
                }
                Some(items) => ResourceValue::Map { parent: None, attrs: pairs(items) },
                None => raw,
            },
            ResourceType::Other(_) => raw,
        }
    }

    /// The zip entry of a [`File`](ResourceValue::File) value. The index
    /// prefixes the path with the module's name; the package does not.
    pub fn archive_path(&self) -> Option<&str> {
        match self {
            ResourceValue::File(path) => Some(path.split_once('/').map_or(path.as_ref(), |(_, rest)| rest)),
            ResourceValue::Text(_)
            | ResourceValue::Array(_)
            | ResourceValue::Plural(_)
            | ResourceValue::Map { .. }
            | ResourceValue::Raw(_) => None,
        }
    }
}

/// A list value: strings one after another, each a `u16` length, the
/// bytes and a NUL the length does not count.
fn strings(bytes: &[u8]) -> Option<Vec<Cow<'_, str>>> {
    let mut reader = Reader::new(bytes);
    let mut items = Vec::new();
    while reader.remaining() > 0 {
        items.push(String::from_utf8_lossy(reader.sized16("list item").ok()?));
        if reader.take(1, "list item terminator").ok()? != [0] {
            return None;
        }
    }
    Some(items)
}

fn pairs(items: Vec<Cow<'_, str>>) -> Vec<Attr<'_>> {
    let mut items = items.into_iter();
    std::iter::from_fn(|| Some(Attr { name: items.next()?, value: items.next()? })).collect()
}

/// A string in JSON quotes on one line: `\"`, `\\`, `\n`, `\t`, `\r`
/// escaped and every other control character as `\u001b`.
struct Quoted<'s>(&'s str);

impl fmt::Display for Quoted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"")?;
        for c in self.0.chars() {
            match c {
                '"' => f.write_str("\\\"")?,
                '\\' => f.write_str("\\\\")?,
                '\n' => f.write_str("\\n")?,
                '\t' => f.write_str("\\t")?,
                '\r' => f.write_str("\\r")?,
                c if c.is_control() => write!(f, "\\u{:04x}", u32::from(c))?,
                c => write!(f, "{c}")?,
            }
        }
        f.write_str("\"")
    }
}

fn write_attrs(f: &mut fmt::Formatter<'_>, attrs: &[Attr<'_>], mut first: bool) -> fmt::Result {
    for attr in attrs {
        if !first {
            f.write_str(", ")?;
        }
        first = false;
        write!(f, "{}: {}", Quoted(&attr.name), Quoted(&attr.value))?;
    }
    Ok(())
}

/// One line: text quoted as JSON (`"Bridge"`), a file path bare
/// (`entry/resources/base/media/icon.png`), an array `["a", "b"]`, a
/// plural `{"one": "%d file", "other": "%d files"}`, a theme or pattern
/// the same with its parent first (`{parent: "$theme:16777220", ...}`),
/// raw bytes as `<12 bytes>`.
impl fmt::Display for ResourceValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResourceValue::Text(text) => write!(f, "{}", Quoted(text)),
            ResourceValue::File(path) => f.write_str(path),
            ResourceValue::Array(items) => {
                f.write_str("[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{}", Quoted(item))?;
                }
                f.write_str("]")
            }
            ResourceValue::Plural(attrs) => {
                f.write_str("{")?;
                write_attrs(f, attrs, true)?;
                f.write_str("}")
            }
            ResourceValue::Map { parent, attrs } => {
                f.write_str("{")?;
                if let Some(parent) = parent {
                    write!(f, "parent: {}", Quoted(parent))?;
                }
                write_attrs(f, attrs, parent.is_none())?;
                f.write_str("}")
            }
            ResourceValue::Raw(bytes) => write!(f, "<{} bytes>", bytes.len()),
        }
    }
}
