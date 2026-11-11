//! The conditions of findrefs rules and callgraph endpoints on DEX code.
//!
//! The syntax is the one both engines read ([`asc_query::rule`]); here are
//! the kinds and what their values mean:
//!
//! ```text
//! method: ['=' | '*'] '{' rule '}' calls    calls of the methods whose code matches the rule
//!         ['=' | '*'] '{@' PATH '}' calls   calls of the methods listed in a file
//!         ['=' | '*'] '@' PATH calls        the same
//!         TARGET calls                      a method target, e.g. Lc;->m(I)V
//! in:     '{' CONDITION '}'                 the methods of a class the condition matches
//! other:  TEXT                              the kind's own syntax, e.g. a regex
//! calls := ( '[' constraint ( ',' constraint )* ']' )*
//! constraint := ( 'arg' N | 'this' ) ( '=' | '==' ) arg
//!             | 'ret' ( '=' | '==' ) ( 'used' | 'unused' )
//! arg   := '*' | INT | 'true' | 'false' | 'null' | '"' TEXT '"' | '~' REGEX
//!        | 'param' [ K ] | 'class:' TYPE | 'new:' TYPE | 'ret:' METHOD | 'field:' FIELD
//! ```
//!
//! A rule of one positive part is that condition; several parts make a
//! compound ([`Query::All`]) whose `!` parts are its `none` list.
//!
//! A `{rule}` or `@PATH` set also takes the calls that may dispatch to its
//! methods ([`Query::Virtual`]): those naming a method on a supertype of its
//! class, or on a subclass inheriting it. A supertype method more than
//! [`DEFAULT_FAN_OUT`](crate::compose::DEFAULT_FAN_OUT) classes define is
//! not followed (the search notes it); `*` in front follows every one, `=`
//! keeps only the calls naming the set's methods themselves.
//!
//! Constraints keep the calls whose values they accept ([`Query::Call`]):
//! `argN` is the Nth declared parameter of the called method (from 0),
//! `this` its receiver, `paramK` the calling method's own `pK` (smali
//! numbering), `ret:` / `field:` the result of a call / a field read the
//! target matches. Values are what the call site may hold: `=` keeps a site
//! the analysis cannot decide (marked `?`), `==` drops it. `*` only shows
//! the values. A REGEX runs to the next `,` / `]` outside `()` / `{}`, or is
//! quoted like TEXT (`\"`, `\\` escape).
//!
//! Sets (`method:{...}`, `in:{...}`) nest at most [`MAX_DEPTH`] deep.

use crate::names::{exact_method, format_class_name, member_query, parse_kind};
use crate::{EngineError, Result};
use asc_findrefs::{CallConstraint, Certainty, Defined, MemberQuery, Query, ResultWant, Slot, Want};
use asc_query::rule::{Grammar, Mode, Part, Rule, Set, SetFile, Shape, SyntaxError, Text, Value};
use std::path::Path;

pub use asc_query::rule::MAX_DEPTH;

/// The kinds of DEX code.
struct Dex;

impl Grammar for Dex {
    type Kind = &'static str;
    const KINDS: &'static str = "string, literal, type, method, field, extends, impl";

    fn kind(word: &str) -> std::result::Result<&'static str, String> {
        parse_kind(word).map_err(|e| e.to_string())
    }

    fn shape(kind: &'static str) -> Shape {
        match kind {
            "method" => Shape::Set { bare_file: true },
            "in" => Shape::Set { bare_file: false },
            _ => Shape::Text,
        }
    }
}

/// Parse a rule (see the module docs). `@PATH` files are read relative to
/// `dir` (the current directory when `None`).
pub fn parse_rule_in(spec: &str, dir: Option<&Path>) -> Result<Query> {
    let rule = Rule::parse::<Dex>(spec).map_err(syntax)?;
    Reader { src: spec, dir }.rule(&rule)
}

/// Parse one condition (a rule of a single part without `!`).
pub fn parse_condition_in(spec: &str, dir: Option<&Path>) -> Result<Query> {
    match parse_rule_in(spec, dir)? {
        Query::All { .. } => Err(EngineError::Query(format!("{spec:?} is several conditions; give one KIND:VALUE here"))),
        q => Ok(q),
    }
}

/// The methods of an `@file`: one per line, blank lines and `#` comments
/// skipped. A line may be any method target spelling, or a line findrefs or
/// callgraph printed: its first `Lcls;->name...` token is the method.
pub fn method_set(text: &str) -> Result<Vec<MemberQuery>> {
    let mut targets: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split('|').flat_map(str::split_whitespace).find(|t| t.len() > 2 && t.contains("->")).unwrap_or(l))
        .collect();
    targets.sort_unstable();
    targets.dedup();
    targets
        .into_iter()
        .map(|t| if t.contains(";->") && t.contains('(') { exact_method(t) } else { member_query("method", None, false, Some(t), false) })
        .collect()
}

fn syntax(error: SyntaxError) -> EngineError {
    EngineError::Query(error.to_string())
}

/// What the parts of a parsed rule mean on DEX code.
struct Reader<'a> {
    src: &'a str,
    dir: Option<&'a Path>,
}

impl Reader<'_> {
    fn error(&self, at: usize, message: &str) -> EngineError {
        syntax(SyntaxError::new(self.src, at, message))
    }

    fn rule(&self, rule: &Rule<'_, &'static str>) -> Result<Query> {
        let mut all = Vec::new();
        let mut none = Vec::new();
        for part in &rule.parts {
            let query = self.condition(part)?;
            if part.negated { none.push(query) } else { all.push(query) }
        }
        match (all.len(), none.is_empty()) {
            (0, _) => Err(self.error(rule.parts[0].at, "a rule needs a condition without `!` (`!` only removes methods)")),
            (1, true) => Ok(all.pop().expect("one condition")),
            _ => Ok(Query::All { all, none }),
        }
    }

    fn condition(&self, part: &Part<'_, &'static str>) -> Result<Query> {
        let text = match (part.kind, &part.value) {
            ("method", value) => return self.method(value),
            // `in:{CLASS-CONDITION}`: the methods of a matching class.
            ("in", Value::Set { mode: Mode::Plain, set: Set::Rule(inner), tail }) if tail.text.is_empty() => {
                return match inner.parts.as_slice() {
                    [one] if !one.negated => Ok(Query::Defined(Defined::In(Box::new(self.condition(one)?)))),
                    _ => Err(self.error(part.at, "in: takes one class condition, e.g. in:{extends:android.app.Activity}")),
                };
            }
            (_, Value::Text(text)) if part.kind != "in" => text.text,
            _ => return Err(self.error(part.at, "in: takes a class condition in braces, e.g. in:{extends:android.app.Activity}")),
        };
        Ok(match part.kind {
            "string" => Query::String(text.to_string()),
            "literal" => Query::StringLiteral(text.to_string()),
            "type" => Query::Type(text.to_string()),
            "extends" => Query::Extends(format_class_name(text)?),
            "impl" => Query::Implements(format_class_name(text)?),
            "override" => Query::Defined(Defined::Override(member_query("method", None, false, Some(text), false)?)),
            "annotation" => Query::Defined(Defined::Annotation(crate::defs::annotation_descriptor(text)?)),
            "flag" => Query::Defined(Defined::Flags(crate::defs::parse_flags(text)?)),
            _ => Query::Field(member_query("field", None, false, Some(text), false)?),
        })
    }

    /// The value of a `method:` condition: a set or a target, then its
    /// constraints.
    fn method(&self, value: &Value<'_, &'static str>) -> Result<Query> {
        let (target, calls) = match value {
            Value::Text(text) => {
                let (target, calls) = split_constraints(*text);
                if target.text.is_empty() {
                    return Err(self.error(target.at, "empty value"));
                }
                (Query::Method(member_query("method", None, false, Some(target.text), false)?), calls)
            }
            Value::Set { mode, set, tail } => {
                let (set, calls) = match set {
                    Set::Rule(rule) => (Query::Nested(Box::new(self.rule(rule)?)), *tail),
                    // A bare `@PATH` runs to the end of the part, its constraints included.
                    Set::File(file) if tail.text.is_empty() => {
                        let (path, calls) = split_constraints(file.path);
                        (self.method_file(SetFile { path })?, calls)
                    }
                    Set::File(file) => (self.method_file(*file)?, *tail),
                };
                let dispatched = match mode {
                    // `={...}` / `=@PATH`: the set's own methods, without dispatch.
                    Mode::Exact => set,
                    // `*{...}` / `*@PATH`: dispatch through every supertype.
                    Mode::Every => Query::Virtual { target: Box::new(set), via: Default::default(), fan_out: None },
                    Mode::Plain => {
                        Query::Virtual { target: Box::new(set), via: Default::default(), fan_out: Some(crate::compose::DEFAULT_FAN_OUT) }
                    }
                };
                (dispatched, calls)
            }
        };
        let constraints = Constraints { src: self.src, pos: calls.at, end: calls.at + calls.text.len() }.all()?;
        Ok(if constraints.is_empty() { target } else { Query::Call { target: Box::new(target), constraints } })
    }

    /// The method set of `method:@PATH`, read now so the query (and its
    /// cache key) holds the file's content.
    fn method_file(&self, file: SetFile<'_>) -> Result<Query> {
        let path = file.path.text;
        let text = file.read(self.dir).map_err(|e| EngineError::Query(format!("cannot read method set {path}: {e}")))?;
        Ok(Query::MethodSet(method_set(&text).map_err(|e| EngineError::Query(format!("{path}: {e}")))?))
    }
}

/// `text` split before its first call constraint: the target and the
/// constraints, each without the blanks around it.
fn split_constraints(text: Text<'_>) -> (Text<'_>, Text<'_>) {
    let at = constraint_start(text.text).unwrap_or(text.text.len());
    let calls = &text.text[at..];
    (Text { text: text.text[..at].trim_end(), at: text.at }, Text { text: calls, at: text.at + at })
}

/// The call constraints after a method target or set: `[...][...]`, the
/// cursor and end offsets in the rule `src`.
struct Constraints<'a> {
    src: &'a str,
    pos: usize,
    end: usize,
}

impl<'a> Constraints<'a> {
    fn rest(&self) -> &'a str {
        &self.src[self.pos..self.end]
    }

    fn skip_ws(&mut self) {
        self.pos = self.end - self.rest().trim_start().len();
    }

    /// The next non-blank character, not consumed.
    fn peek(&mut self) -> Option<char> {
        self.skip_ws();
        self.rest().chars().next()
    }

    fn eat(&mut self, c: char) -> bool {
        let found = self.peek() == Some(c);
        if found {
            self.pos += c.len_utf8();
        }
        found
    }

    fn error(&self, what: &str) -> EngineError {
        syntax(SyntaxError::new(self.src, self.pos, what))
    }

    /// Every constraint, up to the end.
    fn all(mut self) -> Result<Vec<CallConstraint>> {
        let mut constraints = Vec::new();
        while self.eat('[') {
            loop {
                constraints.push(self.constraint()?);
                if self.eat(']') {
                    break;
                }
                if !self.eat(',') {
                    return Err(self.error("expected `,` or `]` after a constraint"));
                }
            }
        }
        if self.peek().is_some() {
            return Err(self.error("unexpected text after the method"));
        }
        Ok(constraints)
    }

    /// One constraint inside `[...]`.
    fn constraint(&mut self) -> Result<CallConstraint> {
        self.skip_ws();
        let key_len = self.rest().find(|c: char| !c.is_ascii_alphanumeric()).unwrap_or(self.rest().len());
        let key = &self.rest()[..key_len];
        let slot = match key {
            "ret" => None,
            "this" => Some(Slot::This),
            _ => match key.strip_prefix("arg").and_then(|n| n.parse().ok()) {
                Some(n) => Some(Slot::Arg(n)),
                None => return Err(self.error("expected argN, this or ret in a constraint")),
            },
        };
        self.pos += key_len;
        let certainty = if self.eat('=') {
            if self.rest().starts_with('=') {
                self.pos += 1;
                Certainty::Must
            } else {
                Certainty::May
            }
        } else {
            return Err(self.error("expected `=` or `==` in a constraint"));
        };
        self.skip_ws();
        let Some(slot) = slot else {
            let len = item_len(self.rest());
            let want = match self.rest()[..len].trim() {
                "used" => ResultWant::Used,
                "unused" => ResultWant::Unused,
                _ => return Err(self.error("ret takes used or unused")),
            };
            self.pos += len;
            return Ok(CallConstraint::Result { want, certainty });
        };
        let want = self.want()?;
        Ok(CallConstraint::Value { slot, want, certainty })
    }

    /// The value an argument has to hold.
    fn want(&mut self) -> Result<Want> {
        if self.rest().starts_with('"') {
            return Ok(Want::Str(self.quoted()?));
        }
        let regex = self.rest().starts_with('~');
        if regex {
            self.pos += 1;
            if self.rest().starts_with('"') {
                return Ok(Want::StrRegex(self.quoted()?));
            }
        }
        let len = item_len(self.rest());
        let src: &'a str = self.src;
        let raw = src[self.pos..self.pos + len].trim();
        if raw.is_empty() {
            return Err(self.error("empty value in a constraint"));
        }
        self.pos += len;
        if regex {
            return Ok(Want::StrRegex(raw.to_string()));
        }
        let bad = |what: &str| EngineError::Query(format!("bad rule {:?}: {what} in constraint value {raw:?}", self.src));
        if let Some((kind, target)) = raw.split_once(':') {
            let target = target.trim();
            return Ok(match kind {
                "class" => Want::Class(format_class_name(target)?),
                "new" => Want::New(format_class_name(target)?),
                "ret" => Want::Ret(member_query("method", None, false, Some(target), false)?),
                "field" => Want::Field(member_query("field", None, false, Some(target), false)?),
                _ => return Err(bad("expected class:, new:, ret: or field:")),
            });
        }
        Ok(match raw {
            "*" => Want::Any,
            "true" => Want::Int(1),
            "false" | "null" => Want::Int(0),
            "param" => Want::Param(None),
            _ => match raw.strip_prefix("param") {
                Some(k) => Want::Param(Some(k.parse().map_err(|_| bad("expected paramK"))?)),
                None => Want::Int(
                    parse_int(raw).ok_or_else(|| bad("expected *, a number, \"text\", ~regex, param, class:, new:, ret: or field:"))?,
                ),
            },
        })
    }

    /// A `"..."` string at the cursor, its `\"` / `\\` unescaped.
    fn quoted(&mut self) -> Result<String> {
        let mut out = String::new();
        let mut chars = self.rest().char_indices().skip(1);
        while let Some((i, c)) = chars.next() {
            match c {
                '"' => {
                    self.pos += i + 1;
                    return Ok(out);
                }
                '\\' => match chars.next() {
                    Some((_, 'n')) => out.push('\n'),
                    Some((_, 't')) => out.push('\t'),
                    Some((_, c)) => out.push(c),
                    None => break,
                },
                c => out.push(c),
            }
        }
        Err(self.error("unterminated `\"`"))
    }
}

/// Whether a method target carries call constraints (`X[arg0=1]`).
pub fn has_constraints(target: &str) -> bool {
    constraint_start(target).is_some()
}

/// The offset of the first `[argN`, `[this` or `[ret` in a method target.
/// Dalvik names hold no `[`, and in a descriptor one is followed by a type
/// (`[B`, `[Lx;`, `[[I`), never by these words.
fn constraint_start(s: &str) -> Option<usize> {
    s.match_indices('[').map(|(i, _)| i).find(|&i| {
        let c = s[i + 1..].trim_start();
        c.starts_with("ret") || c.starts_with("this") || c.strip_prefix("arg").is_some_and(|n| n.starts_with(|d: char| d.is_ascii_digit()))
    })
}

/// Bytes of a constraint value at the start of `s`: up to a `,` or `]`
/// outside `()` / `{}`; `\` keeps the next character in.
fn item_len(s: &str) -> usize {
    let mut depth = 0usize;
    let mut chars = s.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '(' | '{' => depth += 1,
            ')' | '}' if depth > 0 => depth -= 1,
            ',' | ']' if depth == 0 => return i,
            _ => {}
        }
    }
    s.len()
}

/// A decimal or `0x` integer, maybe negative.
fn parse_int(s: &str) -> Option<i64> {
    let (neg, digits) = s.strip_prefix('-').map_or((false, s), |d| (true, d));
    let n = match digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
        // Hex is the bits of the value: 0xffffffff is -1 as an int.
        Some(hex) => {
            let n = u64::from_str_radix(hex, 16).ok()?;
            match u32::try_from(n) {
                Ok(int) => i64::from(i32::from_ne_bytes(int.to_ne_bytes())),
                Err(_) => i64::from_ne_bytes(n.to_ne_bytes()),
            }
        }
        None => digits.parse().ok()?,
    };
    Some(if neg { n.checked_neg()? } else { n })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::{format_class_name, parse_condition, parse_rule};

    fn method_query(spec: &str) -> MemberQuery {
        member_query("method", None, false, Some(spec), false).unwrap()
    }

    fn method(spec: &str) -> Query {
        Query::Method(method_query(spec))
    }

    /// A method set wrapped in its default (unresolved) dispatch query.
    fn vq(target: Query) -> Query {
        Query::Virtual { target: Box::new(target), via: Default::default(), fan_out: Some(crate::compose::DEFAULT_FAN_OUT) }
    }

    #[test]
    fn parts_split_at_top_level_ampersands_only() {
        let q = parse_rule(" string:a & !literal:b&method:Lc;->m(I)V ").unwrap();
        assert_eq!(
            q,
            Query::All { all: vec![Query::String("a".into()), method("Lc;->m(I)V")], none: vec![Query::StringLiteral("b".into())] }
        );
        // Inside `{}` / `()`, after `\` or where no KIND: follows, `&` is part of the value.
        assert_eq!(parse_rule("string:(a&b)").unwrap(), Query::String("(a&b)".into()));
        assert_eq!(
            parse_rule("string:a&b & literal:c&d").unwrap(),
            Query::All { all: vec![Query::String("a&b".into()), Query::StringLiteral("c&d".into())], none: vec![] }
        );
        assert_eq!(parse_rule("string:a & ").unwrap(), Query::String("a &".into()));
        assert_eq!(parse_rule(r"string:a{1}\&b").unwrap(), Query::String(r"a{1}\&b".into()));
        assert_eq!(
            parse_condition("extends:android.app.Activity").unwrap(),
            Query::Extends(format_class_name("android.app.Activity").unwrap())
        );
        // Array descriptors are not brackets.
        assert_eq!(
            parse_rule("method:Lc;->m([B)V & type:X").unwrap(),
            Query::All { all: vec![method("Lc;->m([B)V"), Query::Type("X".into())], none: vec![] }
        );
    }

    #[test]
    fn method_bodies_nest_whole_rules() {
        let inner = Query::All { all: vec![Query::StringLiteral("imei".into())], none: vec![Query::Type("Lx;".into())] };
        // A `{...}` body nests the rule and, by default, follows dispatch.
        assert_eq!(parse_rule("method:{literal:imei & !type:Lx;}").unwrap(), vq(Query::Nested(Box::new(inner.clone()))));
        let q = parse_rule("method:{ method:{literal:imei & !type:Lx;} } & string:http").unwrap();
        assert_eq!(
            q,
            Query::All {
                all: vec![vq(Query::Nested(Box::new(vq(Query::Nested(Box::new(inner)))))), Query::String("http".into())],
                none: vec![]
            }
        );
        // A regex brace inside the body stays in its value.
        assert_eq!(parse_rule("method:{string:a{2}}").unwrap(), vq(Query::Nested(Box::new(Query::String("a{2}".into())))));
    }

    fn call(target: Query, constraints: Vec<CallConstraint>) -> Query {
        Query::Call { target: Box::new(target), constraints }
    }

    fn arg(n: u16, want: Want, certainty: Certainty) -> CallConstraint {
        CallConstraint::Value { slot: Slot::Arg(n), want, certainty }
    }

    #[test]
    fn method_targets_take_call_constraints() {
        use Certainty::{May, Must};
        let target = || method("Lc;->m([BLjava/lang/String;)V");
        assert_eq!(
            parse_rule(r#"method:Lc;->m([BLjava/lang/String;)V [arg1="a,]\"b", this==new:x.Y][ret=unused]"#).unwrap(),
            call(
                target(),
                vec![
                    arg(1, Want::Str("a,]\"b".into()), May),
                    CallConstraint::Value { slot: Slot::This, want: Want::New("Lx/Y;".into()), certainty: Must },
                    CallConstraint::Result { want: ResultWant::Unused, certainty: May },
                ]
            )
        );
        for (value, want) in [
            ("*", Want::Any),
            ("-12", Want::Int(-12)),
            ("0x10", Want::Int(16)),
            ("0xffffffff", Want::Int(-1)),
            ("true", Want::Int(1)),
            ("null", Want::Int(0)),
            ("param", Want::Param(None)),
            ("param3", Want::Param(Some(3))),
            ("~^ro\\.(serial|boot){1,2}", Want::StrRegex("^ro\\.(serial|boot){1,2}".into())),
            ("~\"a]b\"", Want::StrRegex("a]b".into())),
            ("class:java.lang.String", Want::Class("Ljava/lang/String;".into())),
            ("ret:android.content.Context->getSystemService", Want::Ret(method_query("android.content.Context->getSystemService"))),
            ("field:Lc;->f:I", Want::Field(member_query("field", None, false, Some("Lc;->f:I"), false).unwrap())),
        ] {
            assert_eq!(parse_rule(&format!("method:x[arg0={value}]")).unwrap(), call(method("x"), vec![arg(0, want, May)]), "{value}");
        }
        // `&` inside a constraint stays in it; after `]` it joins the next part.
        assert_eq!(
            parse_rule("method:x[arg0=~a&b] & string:s").unwrap(),
            Query::All {
                all: vec![call(method("x"), vec![arg(0, Want::StrRegex("a&b".into()), May)]), Query::String("s".into())],
                none: vec![]
            }
        );
        // Nested bodies and method sets take them too, under the dispatch wrapper.
        let q = parse_rule("method:{literal:imei}[arg0=*]").unwrap();
        assert_eq!(q, call(vq(Query::Nested(Box::new(Query::StringLiteral("imei".into())))), vec![arg(0, Want::Any, May)]));
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("set.txt"), "Lc;->m()V\n").unwrap();
        let q = parse_rule_in("method:@set.txt[ret==used]", Some(dir.path())).unwrap();
        assert!(matches!(&q, Query::Call { target, .. } if matches!(**target, Query::Virtual { .. })), "{q:?}");
        // Array descriptors and regex classes are not constraints.
        assert!(!has_constraints("Lc;->m([B[Ljava/lang/String;)V") && has_constraints("x[ret=used]"));
        assert_eq!(parse_rule("string:[arg0]").unwrap(), Query::String("[arg0]".into()));
    }

    #[test]
    fn definition_predicates_parse_into_defined_queries() {
        use asc_dex::access;
        assert_eq!(parse_rule("flag:public,static").unwrap(), Query::Defined(Defined::Flags(access::PUBLIC | access::STATIC)));
        assert_eq!(parse_rule("annotation:a.B").unwrap(), Query::Defined(Defined::Annotation("La/B;".into())));
        let Query::Defined(Defined::Override(m)) = parse_rule("override:a.B->run").unwrap() else { panic!("an override") };
        assert_eq!((m.name.as_deref(), m.class.unwrap().pattern.as_str()), (Some("run"), "La/B;"));
        assert_eq!(parse_rule("in:{extends:a.Base}").unwrap(), Query::Defined(Defined::In(Box::new(format_extends("a.Base")))));
        // A definition predicate joins a code condition in a compound.
        let Query::All { all, none } = parse_rule("string:x & flag:native & !annotation:a.B").unwrap() else { panic!("a compound") };
        assert_eq!(all.len(), 2);
        assert_eq!(none, vec![Query::Defined(Defined::Annotation("La/B;".into()))]);
        // Bad spellings are reported at parse time; a non-class `in:{...}` is
        // caught later, when the engine resolves it over the hierarchy.
        for (spec, want) in [("flag:bogus", "use public"), ("in:extends:a.B", "in: takes a class condition")] {
            assert!(parse_rule(spec).unwrap_err().to_string().contains(want), "{spec}");
        }
        assert!(matches!(parse_rule("in:{string:x}").unwrap(), Query::Defined(Defined::In(_))));
    }

    fn format_extends(c: &str) -> Query {
        Query::Extends(format_class_name(c).unwrap())
    }

    #[test]
    fn method_sets_follow_dispatch_unless_prefixed_with_eq() {
        // `{...}` / `@` wrap the set in a dispatch query with the default
        // fan-out; `*` lifts it; `=` keeps the set exact.
        use crate::compose::DEFAULT_FAN_OUT;
        let Query::Virtual { target, via, fan_out } = parse_rule("method:{literal:x}").unwrap() else { panic!("a dispatch set") };
        assert!(matches!(*target, Query::Nested(_)) && via.is_empty() && fan_out == Some(DEFAULT_FAN_OUT));
        let Query::Virtual { fan_out, .. } = parse_rule("method:*{literal:x}").unwrap() else { panic!("a dispatch set") };
        assert_eq!(fan_out, None);
        assert!(matches!(parse_rule("method:={literal:x}").unwrap(), Query::Nested(_)));
        // A constraint applies to the dispatched calls.
        let Query::Call { target, .. } = parse_rule("method:{literal:x}[arg0=1]").unwrap() else { panic!("constrained") };
        assert!(matches!(*target, Query::Virtual { .. }));
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("s.txt"), "La/B;->m()V\n").unwrap();
        assert!(matches!(parse_rule_in("method:@s.txt", Some(dir.path())).unwrap(), Query::Virtual { .. }));
        assert!(matches!(parse_rule_in("method:=@s.txt", Some(dir.path())).unwrap(), Query::MethodSet(_)));
        assert!(matches!(parse_rule_in("method:*@s.txt", Some(dir.path())).unwrap(), Query::Virtual { fan_out: None, .. }));
        // The file may also go in the braces, as the HarmonyOS side writes it.
        assert_eq!(parse_rule_in("method:{@s.txt}", Some(dir.path())).unwrap(), parse_rule_in("method:@s.txt", Some(dir.path())).unwrap());
        assert_eq!(
            parse_rule_in("method:={ @s.txt }[arg0=1]", Some(dir.path())).unwrap(),
            parse_rule_in("method:=@s.txt[arg0=1]", Some(dir.path())).unwrap()
        );
    }

    #[test]
    fn errors_name_the_problem() {
        for (spec, want) in [
            ("bogus", "expected KIND:VALUE"),
            ("method:", "empty value"),
            ("metod:x", "closest: method"),
            ("method:{string:a", "expected `}`"),
            ("method:{string:a} x", "unexpected text after the method"),
            ("method:x[arg0=1] y", "unexpected text after the method"),
            ("method:x[arg0=1", "expected `,` or `]`"),
            ("method:x[arg0=1, foo=2]", "expected argN, this or ret"),
            ("method:x[arg0 1]", "expected `=` or `==`"),
            ("method:x[arg0=]", "empty value"),
            ("method:x[arg0=\"a]", "unterminated"),
            ("method:x[arg0=bogus:y]", "expected class:, new:, ret: or field:"),
            ("method:x[arg0=paramx]", "expected paramK"),
            ("method:x[arg0=1.5]", "expected *, a number"),
            ("method:x[ret=maybe]", "ret takes used or unused"),
            ("!string:a", "needs a condition without `!`"),
            ("string:a & bogus:b", "unknown kind \"bogus\""),
            ("in:{extends:a.B & !extends:c.D}", "in: takes one class condition"),
            ("method:@", "empty value"),
            ("method:@/nonexistent/set.txt", "cannot read method set"),
        ] {
            let e = parse_rule(spec).unwrap_err().to_string();
            assert!(e.contains(want), "{spec}: {e}");
        }
        assert!(parse_condition("string:a & string:b").unwrap_err().to_string().contains("several conditions"));
    }

    #[test]
    fn bodies_nest_up_to_the_limit() {
        let nest = |open: &str, n: usize, leaf: &str| format!("{}{leaf}{}", open.repeat(n), "}".repeat(n));
        for open in ["method:{", "method:={", "method:*{", "in:{"] {
            assert!(parse_rule(&nest(open, MAX_DEPTH, "string:a")).is_ok(), "{open} x{MAX_DEPTH}");
            // Far past the limit is an error, not a stack overflow.
            for n in [MAX_DEPTH + 1, 100_000] {
                let e = parse_rule(&nest(open, n, "string:a")).unwrap_err().to_string();
                assert!(e.contains(&format!("nested deeper than {MAX_DEPTH} levels")), "{open} x{n}: {}", &e[e.len().saturating_sub(80)..]);
            }
        }
        // Mixed kinds share one budget; siblings do not add up.
        let mixed = format!("{}string:a{}", "method:{in:{".repeat(MAX_DEPTH / 2 + 1), "}}".repeat(MAX_DEPTH / 2 + 1));
        assert!(parse_rule(&mixed).is_err());
        let wide = vec![nest("method:{", MAX_DEPTH, "string:a"); 50].join(" & ");
        assert!(parse_rule(&wide).is_ok());
    }

    #[test]
    fn method_files_take_any_listing() {
        let dir = tempfile::tempdir().unwrap();
        let text = "# from findrefs\n\
            classes2.dex | Lb/Lib;->sink()V | \"x->y\"\n\
            r1 | classes.dex | La/A;->run(I)V | Lb/Lib;->sink()V\n\
            \n\
            \x20 2 <- La/A;->run(I)V (via Lx;)\n\
            com.a.B.go\n";
        std::fs::write(dir.path().join("set.txt"), text).unwrap();
        let Query::Virtual { target, .. } = parse_rule_in("method:@set.txt", Some(dir.path())).unwrap() else { panic!("a dispatch set") };
        let Query::MethodSet(set) = *target else { panic!("a method set") };
        let want = [exact_method("La/A;->run(I)V").unwrap(), exact_method("Lb/Lib;->sink()V").unwrap(), method_query("com.a.B.go")];
        assert_eq!(set, want);
        // Obfuscated names go by the arrow, not as identifiers.
        let q = exact_method("LX/0TRC;->ʻ(I)Ljava/lang/String;").unwrap();
        assert_eq!((q.name.as_deref(), q.exact_name, q.class.unwrap().pattern.as_str()), (Some("ʻ"), true, "LX/0TRC;"));
    }
}
