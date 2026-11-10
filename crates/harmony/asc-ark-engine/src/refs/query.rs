//! What a reference search looks for, and the `KIND:VALUE` spelling of it.

use std::str::FromStr;

use regex::Regex;

use crate::ops::Access;
use crate::{EngineError, Result};

/// How a name or text is matched.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Pattern {
    /// The regex matches somewhere (`^` and `$` are the text's own edges).
    Regex(Regex),
    /// The text contains this.
    Contains(String),
    /// The text is this.
    Exact(String),
}

impl Pattern {
    /// # Errors
    /// [`EngineError::Pattern`] when `pattern` is not a valid regex.
    pub fn regex(pattern: &str) -> Result<Pattern> {
        Ok(Pattern::Regex(Regex::new(pattern)?))
    }

    pub fn contains(text: impl Into<String>) -> Pattern {
        Pattern::Contains(text.into())
    }

    pub fn exact(text: impl Into<String>) -> Pattern {
        Pattern::Exact(text.into())
    }

    /// The name syntax of the `prop:`, `global:` and `method:` conditions:
    /// a regex, or `=NAME` for exactly that name.
    ///
    /// # Errors
    /// [`EngineError::Pattern`] when the regex is not valid.
    pub fn name(spec: &str) -> Result<Pattern> {
        match spec.strip_prefix('=') {
            Some(name) => Ok(Pattern::exact(name)),
            None => Pattern::regex(spec),
        }
    }

    pub fn is_match(&self, text: &str) -> bool {
        match self {
            Pattern::Regex(regex) => regex.is_match(text),
            Pattern::Contains(part) => text.contains(part.as_str()),
            Pattern::Exact(whole) => text == whole,
        }
    }
}

/// A numeric constant, or an inclusive range of them.
///
/// Spelled in decimal (`1919810`, `-1`, `1.5`, `1e3`), in hex (`0x1d4b42`)
/// or as a range `A..B`. A single integer in `2^31..2^32` also finds the
/// negative 32-bit integer with the same bits: `0x9e3779b9` finds
/// `ldai -1640531527`.
#[derive(Debug, Clone, PartialEq)]
pub struct NumberQuery {
    low: f64,
    high: f64,
    /// The negative `i32` whose unsigned spelling the query is.
    wrapped: Option<i32>,
}

impl NumberQuery {
    /// Whether the query is one value, not a range.
    pub(crate) fn single(&self) -> Option<f64> {
        (self.low == self.high).then_some(self.low)
    }

    pub(crate) fn wrapped(&self) -> Option<i32> {
        self.wrapped
    }

    pub(crate) fn matches_int(&self, value: i32) -> bool {
        self.wrapped == Some(value) || self.matches_float(f64::from(value))
    }

    pub(crate) fn matches_float(&self, value: f64) -> bool {
        self.low <= value && value <= self.high
    }
}

/// One number: `-12`, `0x1F`, `1.5`, `2e-3`.
fn parse_number(text: &str) -> Option<f64> {
    let text = text.trim();
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text),
    };
    let magnitude = match digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
        // Wider than any constant the bytecode holds; the conversion rounds past 2^53.
        Some(hex) => u64::from_str_radix(hex, 16).ok()? as f64,
        // `f64::from_str` also takes `inf`, `nan` and a second sign: digits first.
        None if digits.starts_with(|c: char| c.is_ascii_digit() || c == '.') => digits.parse::<f64>().ok().filter(|n| n.is_finite())?,
        None => return None,
    };
    Some(if negative { -magnitude } else { magnitude })
}

impl FromStr for NumberQuery {
    type Err = EngineError;

    fn from_str(spec: &str) -> Result<NumberQuery> {
        let invalid =
            || EngineError::Query(format!("{spec:?} is not a number: write 1919810, -1, 0x1d4b42, 1.5 or a range such as 0x1000..0x1fff"));
        if let Some((low, high)) = spec.split_once("..") {
            let (low, high) = parse_number(low).zip(parse_number(high)).ok_or_else(invalid)?;
            if low > high {
                return Err(EngineError::Query(format!("{spec:?} is an empty range: its first number is the larger one")));
            }
            return Ok(NumberQuery { low, high, wrapped: None });
        }
        let value = parse_number(spec).ok_or_else(invalid)?;
        let unsigned = (value.fract() == 0.0 && (2_147_483_648.0..4_294_967_296.0).contains(&value)).then_some(value);
        // In `2^31..2^32` by the test above, so the conversion to `u32` is exact; the cast reinterprets the bits.
        let wrapped = unsigned.map(|value| (value as u32) as i32);
        Ok(NumberQuery { low: value, high: value, wrapped })
    }
}

/// What [`crate::Engine::find_refs`] searches for.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Query {
    /// Strings the regex matches somewhere (`^` and `$` are the string's
    /// own edges).
    StringRegex(Regex),
    /// Strings that contain this text.
    StringLiteral(String),
    /// Properties read, written, defined or called by name
    /// (`ldobjbyname`, `stobjbyname`, `definefieldbyname`,
    /// `callthis1withname` …), optionally of one [`Access`] only.
    Prop { name: Pattern, access: Option<Access> },
    /// Global bindings read or written by name (`tryldglobalbyname`,
    /// `stglobalvar` …).
    Global { name: Pattern, access: Option<Access> },
    /// Imported bindings: the declarations in each record's module record
    /// and the instructions that load them.
    Import {
        /// Matched against the module request (`@ohos:net.http`,
        /// `@normalized:N&&&entry/src/main/ets/pages/Index&`).
        request: Pattern,
        /// The imported name (`default`, `request`); `*` is the namespace.
        name: Option<String>,
        /// Only the declarations, without scanning code.
        declarations_only: bool,
    },
    /// Where a function is made a closure or attached to a class: method id
    /// operands (`definefunc`, `definemethod`, `defineclasswithbuffer` …)
    /// and method items of the literal arrays code refers to.
    Method {
        /// The record that defines the function: its canonical name or a
        /// path suffix of it, as for `getclass`.
        record: Option<String>,
        /// Matched against the raw name (`#~@0>#build`) and the restored
        /// one (`Index.build`); an exact name is also a dotted suffix of the
        /// restored name (`build`).
        name: Pattern,
    },
    /// Numeric constants: `ldai`, `fldai` and the numbers of array and
    /// object literals.
    Number(NumberQuery),
    /// Call sites whose resolved callee path matches, e.g.
    /// `import:@ohos:net.http#default.createHttp`.
    Call(Pattern),
    /// Functions that every one of the queries matches in.
    All(Vec<Query>),
}

impl Query {
    /// # Errors
    /// [`EngineError::Pattern`] when `pattern` is not a valid regex.
    pub fn string_regex(pattern: &str) -> Result<Query> {
        Ok(Query::StringRegex(Regex::new(pattern)?))
    }

    pub fn string_literal(text: impl Into<String>) -> Query {
        Query::StringLiteral(text.into())
    }

    /// # Errors
    /// [`EngineError::Query`] for an access a global cannot have (`define`, `call`).
    pub fn global(name: Pattern, access: Option<Access>) -> Result<Query> {
        match access {
            Some(access @ (Access::Define | Access::Call)) => {
                Err(EngineError::Query(format!("a global is read or written, not {access}: use `prop` or `call` for members")))
            }
            Some(Access::Read | Access::Write) | None => Ok(Query::Global { name, access }),
        }
    }

    /// An import query from its spelling `REQUEST` or `REQUEST#NAME`:
    /// `REQUEST` is a regex over the module request (`literal`: plain text
    /// it contains), `NAME` the imported name, `*` for the namespace. The
    /// last `#` separates the two; a regex that needs a `#` writes `\x23`.
    ///
    /// # Errors
    /// [`EngineError::Pattern`] when the regex is not valid.
    pub fn import(spec: &str, literal: bool) -> Result<Query> {
        let (request, name) = match spec.rsplit_once('#') {
            Some((request, name)) if !name.is_empty() => (request, Some(name.to_owned())),
            _ => (spec, None),
        };
        let request = if literal { Pattern::contains(request) } else { Pattern::regex(request)? };
        Ok(Query::Import { request, name, declarations_only: false })
    }

    /// A method query from its spelling `FUNCTION` or `RECORD->FUNCTION`
    /// (the location column of a result row without its `+0xPC`).
    pub fn method(spec: &str, name: impl FnOnce(&str) -> Result<Pattern>) -> Result<Query> {
        let (record, function) = match spec.split_once("->") {
            Some((record, function)) => (Some(record.to_owned()), function),
            None => (None, spec),
        };
        Ok(Query::Method { record, name: name(function)? })
    }

    /// A condition as `findrefs all` takes them: `string:REGEX`,
    /// `literal:TEXT`, `prop:NAME`, `global:NAME`, `import:REQUEST[#NAME]`,
    /// `method:[RECORD->]NAME`, `number:N`, `call:REGEX`. `NAME` is a regex,
    /// or `=NAME` for the exact name.
    ///
    /// # Errors
    /// [`EngineError::Query`] for an unknown kind or a missing value,
    /// [`EngineError::Pattern`] for an invalid regex.
    pub fn condition(spec: &str) -> Result<Query> {
        let unknown =
            || EngineError::Query(format!("{spec:?} is not a condition: write KIND:VALUE with KIND one of {}", Query::KINDS.join(", ")));
        let (kind, value) = spec.split_once(':').ok_or_else(unknown)?;
        if value.is_empty() {
            return Err(EngineError::Query(format!("{kind}: needs a value")));
        }
        match kind {
            "string" => Query::string_regex(value),
            "literal" => Ok(Query::string_literal(value)),
            "prop" => Ok(Query::Prop { name: Pattern::name(value)?, access: None }),
            "global" => Ok(Query::Global { name: Pattern::name(value)?, access: None }),
            "import" => Query::import(value, false),
            "method" => Query::method(value, Pattern::name),
            "number" => Ok(Query::Number(value.parse()?)),
            "call" => Ok(Query::Call(Pattern::regex(value)?)),
            _ => Err(unknown()),
        }
    }

    /// The condition kinds [`Query::condition`] takes.
    pub const KINDS: [&'static str; 8] = ["string", "literal", "prop", "global", "import", "method", "number", "call"];

    /// The kind as rows of a conjunction label it.
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Query::StringRegex(_) | Query::StringLiteral(_) => "string",
            Query::Prop { .. } => "prop",
            Query::Global { .. } => "global",
            Query::Import { .. } => "import",
            Query::Method { .. } => "method",
            Query::Number(_) => "number",
            Query::Call(_) => "call",
            Query::All(_) => "all",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn number(spec: &str) -> NumberQuery {
        spec.parse().unwrap()
    }

    #[test]
    fn numbers_in_every_spelling() {
        assert!(number("1919810").matches_int(1_919_810) && number("0x1d4b42").matches_int(1_919_810));
        assert!(number("0X1D4B42").matches_int(1_919_810) && !number("0x1d4b42").matches_int(1_919_811));
        assert!(number("-1").matches_int(-1) && number("-0x10").matches_int(-16));
        assert!(number("1.5").matches_float(1.5) && !number("1.5").matches_int(1) && number("1e3").matches_int(1000));
        // An integer constant and a float one of the same value are one number.
        assert!(number("3").matches_float(3.0) && number("3.0").matches_int(3));
        // The unsigned spelling of a negative 32-bit integer.
        assert_eq!(number("0x9e3779b9").wrapped(), Some(-1_640_531_527));
        assert!(number("0x9e3779b9").matches_int(-1_640_531_527) && number("2654435769").matches_int(-1_640_531_527));
        assert!(number("0xffffffff").matches_int(-1) && number("0xffffffff").matches_float(4_294_967_295.0));
        assert_eq!((number("0x7fffffff").wrapped(), number("0x100000000").wrapped(), number("-0x80000000").wrapped()), (None, None, None));
        assert!(number("-0x80000000").matches_int(i32::MIN));
    }

    #[test]
    fn ranges_are_inclusive() {
        let range = number("0x10..0x1f");
        assert_eq!(range.single(), None);
        assert!(range.matches_int(16) && range.matches_int(31) && !range.matches_int(32) && range.matches_float(16.5));
        assert!(number("-5..-1").matches_int(-3) && !number("-5..-1").matches_int(0));
        assert!(number("0.5..1.5").matches_int(1));
        for bad in ["", "abc", "0x", "1..", "..2", "inf", "nan", "--1", "+-1", "1..2..3", "0xg", "5..1"] {
            assert!(matches!(bad.parse::<NumberQuery>(), Err(EngineError::Query(_))), "{bad}");
        }
    }

    #[test]
    fn conditions_parse_by_kind() {
        assert!(matches!(Query::condition("string:^https?://"), Ok(Query::StringRegex(_))));
        assert!(matches!(Query::condition("literal:a:b"), Ok(Query::StringLiteral(text)) if text == "a:b"));
        assert!(
            matches!(Query::condition("prop:=request"), Ok(Query::Prop { name: Pattern::Exact(name), access: None }) if name == "request")
        );
        assert!(matches!(Query::condition("global:console"), Ok(Query::Global { name: Pattern::Regex(_), .. })));
        assert!(matches!(Query::condition("number:0x10..0x20"), Ok(Query::Number(_))));
        assert!(matches!(Query::condition("call:global:console\\."), Ok(Query::Call(Pattern::Regex(_)))));
        let import = Query::condition("import:@ohos:net\\.http#default").unwrap();
        assert!(
            matches!(&import, Query::Import { request: Pattern::Regex(_), name: Some(name), declarations_only: false } if name == "default")
        );
        assert!(matches!(Query::import("@ohos:net.http", true), Ok(Query::Import { request: Pattern::Contains(_), name: None, .. })));
        let method = Query::condition("method:&entry/src/main/ets/pages/Index&->=#~@0>#build").unwrap();
        assert!(matches!(&method, Query::Method { record: Some(record), name: Pattern::Exact(name) }
            if record == "&entry/src/main/ets/pages/Index&" && name == "#~@0>#build"));
        assert!(matches!(Query::condition("method:build"), Ok(Query::Method { record: None, name: Pattern::Regex(_) })));

        for bad in ["nokind", "type:Foo", "prop:", ":x"] {
            assert!(matches!(Query::condition(bad), Err(EngineError::Query(_))), "{bad}");
        }
        assert!(matches!(Query::condition("prop:("), Err(EngineError::Pattern(_))));
        assert!(matches!(Query::global(Pattern::exact("x"), Some(Access::Call)), Err(EngineError::Query(_))));
        assert!(Pattern::exact("ab").is_match("ab") && !Pattern::exact("ab").is_match("abc") && Pattern::contains("b").is_match("abc"));
    }
}
