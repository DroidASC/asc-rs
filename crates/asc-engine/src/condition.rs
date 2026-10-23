//! The condition language of findrefs rules and callgraph endpoints.
//!
//! ```text
//! rule  := part ( '&' part )*
//! part  := [ '!' ] KIND ':' value
//! value := '{' rule '}'      method only: calls of the methods whose code matches the rule
//!        | '@' PATH          method only: calls of the methods listed in a file
//!        | TEXT              the KIND's own syntax, e.g. a regex or Lc;->m(I)V
//! ```
//!
//! A rule of one positive part is that condition; several parts make a
//! compound ([`Query::All`]) whose `!` parts are its `none` list. TEXT runs
//! to the next `&` outside `{}` / `()`, or to the `}` closing the enclosing
//! body; `\` keeps the next character from ending it (`string:a\&b` is the
//! regex `a\&b`). `[...]` after a method target is reserved for argument
//! constraints (`[arg0=...]`, `[ret=...]`), not accepted yet.

use crate::names::{exact_method, member_query, parse_kind};
use crate::{EngineError, Result};
use asc_findrefs::{Defined, MemberQuery, Query};
use std::path::Path;

/// Parse a rule (see the module docs). `@PATH` files are read relative to
/// `dir` (the current directory when `None`).
pub fn parse_rule_in(spec: &str, dir: Option<&Path>) -> Result<Query> {
    let mut p = Parser { src: spec, pos: 0, dir };
    let q = p.rule(false)?;
    match p.peek() {
        None => Ok(q),
        Some(c) => Err(p.error(&format!("unexpected {c:?}"))),
    }
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

struct Parser<'a> {
    src: &'a str,
    pos: usize,
    dir: Option<&'a Path>,
}

impl<'a> Parser<'a> {
    fn rest(&self) -> &str {
        &self.src[self.pos..]
    }

    fn skip_ws(&mut self) {
        self.pos = self.src.len() - self.rest().trim_start().len();
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
        EngineError::Query(format!("bad rule {:?}: {what} at column {}", self.src, self.pos + 1))
    }

    /// `part ('&' part)*`, up to the end or (`nested`) the closing `}`.
    fn rule(&mut self, nested: bool) -> Result<Query> {
        let mut all = Vec::new();
        let mut none = Vec::new();
        loop {
            if self.eat('!') {
                none.push(self.condition(nested)?);
            } else {
                all.push(self.condition(nested)?);
            }
            if !self.eat('&') {
                break;
            }
        }
        match (all.len(), none.is_empty()) {
            (0, _) => Err(self.error("a rule needs a condition without `!` (`!` only removes methods)")),
            (1, true) => Ok(all.pop().expect("one condition")),
            _ => Ok(Query::All { all, none }),
        }
    }

    /// `KIND ':' value`.
    fn condition(&mut self, nested: bool) -> Result<Query> {
        self.skip_ws();
        let kind_len = self.rest().find(|c: char| !c.is_ascii_alphabetic()).unwrap_or(self.rest().len());
        if kind_len == 0 || !self.rest()[kind_len..].starts_with(':') {
            return Err(self.error("expected KIND:VALUE, KIND one of string, literal, type, method, field, extends, impl"));
        }
        let kind = parse_kind(&self.rest()[..kind_len])?;
        self.pos += kind_len + 1;
        self.skip_ws();
        if kind == "method" {
            if self.eat('{') {
                let inner = self.rule(true)?;
                if !self.eat('}') {
                    return Err(self.error("expected `}`"));
                }
                let trailing = self.rest()[..text_len(self.rest(), nested)].trim();
                if !trailing.is_empty() {
                    return Err(self.error(if is_constraint(trailing) { NO_CONSTRAINTS } else { "unexpected text after `}`" }));
                }
                return Ok(Query::Nested(Box::new(inner)));
            }
            if self.eat('@') {
                let path = self.text(nested)?.trim();
                return self.method_file(path);
            }
        }
        // `in:{CLASS-CONDITION}`: the methods of a matching class.
        if kind == "in" {
            if !self.eat('{') {
                return Err(self.error("in: takes a class condition in braces, e.g. in:{extends:android.app.Activity}"));
            }
            let inner = self.condition(true)?;
            if !self.eat('}') {
                return Err(self.error("expected `}`"));
            }
            return Ok(Query::Defined(Defined::In(Box::new(inner))));
        }
        let value = self.text(nested)?.trim();
        if kind == "method" && is_constraint(value) {
            return Err(self.error(NO_CONSTRAINTS));
        }
        Ok(match kind {
            "string" => Query::String(value.to_string()),
            "literal" => Query::StringLiteral(value.to_string()),
            "type" => Query::Type(value.to_string()),
            "extends" => Query::Extends(crate::names::format_class_name(value)?),
            "impl" => Query::Implements(crate::names::format_class_name(value)?),
            "override" => Query::Defined(Defined::Override(member_query("method", None, false, Some(value), false)?)),
            "annotation" => Query::Defined(Defined::Annotation(crate::defs::annotation_descriptor(value)?)),
            "flag" => Query::Defined(Defined::Flags(crate::defs::parse_flags(value)?)),
            "method" => Query::Method(member_query("method", None, false, Some(value), false)?),
            _ => Query::Field(member_query("field", None, false, Some(value), false)?),
        })
    }

    /// Consume TEXT: up to a `&` outside brackets, or the `}` that closes
    /// the enclosing body (`nested`).
    fn text(&mut self, nested: bool) -> Result<&'a str> {
        let start = self.pos;
        self.pos += text_len(self.rest(), nested);
        let value = &self.src[start..self.pos];
        if value.trim().is_empty() {
            return Err(self.error("empty value"));
        }
        Ok(value)
    }

    /// The method set of `method:@PATH`, read now so the query (and its
    /// cache key) holds the file's content.
    fn method_file(&self, path: &str) -> Result<Query> {
        // An absolute `path` replaces `dir` when joined.
        let full = self.dir.map_or_else(|| Path::new(path).to_path_buf(), |d| d.join(path));
        let text = std::fs::read_to_string(&full).map_err(|e| EngineError::Query(format!("cannot read method set {path}: {e}")))?;
        Ok(Query::MethodSet(method_set(&text).map_err(|e| EngineError::Query(format!("{path}: {e}")))?))
    }
}

const NO_CONSTRAINTS: &str = "argument constraints ([argN=...], [ret=...]) are not supported yet";

/// Whether `value` ends in an argument constraint, `[argN...]` or `[ret...]`
/// (an array descriptor such as `([B)V` has no closing `]`).
fn is_constraint(value: &str) -> bool {
    value
        .strip_suffix(']')
        .and_then(|v| v.rfind('[').map(|i| v[i + 1..].trim_start()))
        .is_some_and(|c| c.starts_with("ret") || c.strip_prefix("arg").is_some_and(|n| n.starts_with(|d: char| d.is_ascii_digit())))
}

/// Bytes of TEXT at the start of `s`: up to a `&` outside `{}` / `()`, or an
/// unmatched `}` when `nested`. A `\` keeps the next character in.
fn text_len(s: &str, nested: bool) -> usize {
    let mut depth = 0usize;
    let mut chars = s.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '\\' => {
                chars.next();
            }
            '{' | '(' => depth += 1,
            '}' | ')' if depth > 0 => depth -= 1,
            '}' if nested => return i,
            '&' if depth == 0 => return i,
            _ => {}
        }
    }
    s.len()
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

    #[test]
    fn parts_split_at_top_level_ampersands_only() {
        let q = parse_rule(" string:a & !literal:b&method:Lc;->m(I)V ").unwrap();
        assert_eq!(
            q,
            Query::All { all: vec![Query::String("a".into()), method("Lc;->m(I)V")], none: vec![Query::StringLiteral("b".into())] }
        );
        // Inside `{}` / `()` or after `\`, `&` is part of the value.
        assert_eq!(parse_rule("string:(a&b)").unwrap(), Query::String("(a&b)".into()));
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
        assert_eq!(parse_rule("method:{literal:imei & !type:Lx;}").unwrap(), Query::Nested(Box::new(inner.clone())));
        let q = parse_rule("method:{ method:{literal:imei & !type:Lx;} } & string:http").unwrap();
        assert_eq!(
            q,
            Query::All { all: vec![Query::Nested(Box::new(Query::Nested(Box::new(inner)))), Query::String("http".into())], none: vec![] }
        );
        // A regex brace inside the body stays in its value.
        assert_eq!(parse_rule("method:{string:a{2}}").unwrap(), Query::Nested(Box::new(Query::String("a{2}".into()))));
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
    fn errors_name_the_problem() {
        for (spec, want) in [
            ("bogus", "expected KIND:VALUE"),
            ("method:", "empty value"),
            ("metod:x", "closest: method"),
            ("method:{string:a", "expected `}`"),
            ("method:{string:a} x", "unexpected text after `}`"),
            ("method:{string:a}[arg0=1]", "not supported yet"),
            ("method:Lc;->m(I)V[arg0=true]", "not supported yet"),
            ("method:x[ret=unused]", "not supported yet"),
            ("!string:a", "needs a condition without `!`"),
            ("string:a & ", "expected KIND:VALUE"),
            ("method:@", "empty value"),
            ("method:@/nonexistent/set.txt", "cannot read method set"),
        ] {
            let e = parse_rule(spec).unwrap_err().to_string();
            assert!(e.contains(want), "{spec}: {e}");
        }
        assert!(parse_condition("string:a & string:b").unwrap_err().to_string().contains("several conditions"));
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
        let Query::MethodSet(set) = parse_rule_in("method:@set.txt", Some(dir.path())).unwrap() else { panic!("a method set") };
        let want = [exact_method("La/A;->run(I)V").unwrap(), exact_method("Lb/Lib;->sink()V").unwrap(), method_query("com.a.B.go")];
        assert_eq!(set, want);
        // Obfuscated names go by the arrow, not as identifiers.
        let q = exact_method("LX/0TRC;->ʻ(I)Ljava/lang/String;").unwrap();
        assert_eq!((q.name.as_deref(), q.exact_name, q.class.unwrap().pattern.as_str()), (Some("ʻ"), true, "LX/0TRC;"));
    }
}
