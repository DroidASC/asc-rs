//! The rules of `findrefs all` / `rules` and of the endpoints of a call
//! graph walk: the syntax both engines read ([`asc_query::rule`]), with the
//! kinds of this engine.
//!
//! ```text
//! call:  ['='] '{' rule '}'      call sites that lead to a function the rule matches
//!        ['='] '{@' PATH '}'     call sites that lead to a function the file lists
//!        TEXT                    a regex over the callee path
//! other: TEXT                    the kind's own syntax, e.g. a regex
//! ```
//!
//! `KIND` is one of [`Query::KINDS`] or another spelling of one
//! ([`Query::kind_named`]: `property:`, `functions:`), at every depth.
//!
//! A rule of one part without `!` is that condition; several make a
//! [`Query::All`] whose `!` parts are [`Query::Not`]. Record names and
//! module requests are full of `&` (`&entry/src/main/ets/pages/Index&`),
//! which the shared syntax keeps in the value: a `&` joins only ahead of
//! `KIND:` or `!KIND:`.
//!
//! The DEX side writes a set of methods `method:{RULE}`, because its
//! `method:` condition is a call. Here a call is `call:`, so the set goes
//! there. A callee path may start with `@` itself (`call:@ohos:net`), so a
//! file of functions always goes in the braces. Sets are exact, as a `=`
//! in front says on the DEX side; `*` (follow dispatch) is DEX-only.

use std::path::Path;

use asc_query::rule::{Grammar, Mode, Part, Rule, Set, Shape, SyntaxError, Value};

use super::{FunctionSet, NumberQuery, Pattern, Query};
use crate::{EngineError, Result};

/// The kinds of ArkCompiler code.
struct Ark;

impl Grammar for Ark {
    type Kind = &'static str;
    const KINDS: &'static str = "string, literal, prop, global, import, method, number, call";

    fn kind(word: &str) -> std::result::Result<&'static str, String> {
        Query::kind_named(word).ok_or_else(|| format!("unknown kind {word:?}: use one of {}", Ark::KINDS))
    }

    fn shape(kind: &'static str) -> Shape {
        match kind {
            "call" => Shape::Set { bare_file: false },
            _ => Shape::Text,
        }
    }
}

/// The parts of `rule`: what stands between the `&` that join conditions.
pub(crate) fn parts(rule: &str) -> Vec<&str> {
    asc_query::rule::parts(rule)
}

pub(super) fn parse(spec: &str, dir: Option<&Path>) -> Result<Query> {
    let rule = Rule::parse::<Ark>(spec).map_err(syntax)?;
    Reader { src: spec, dir }.rule(&rule)
}

fn syntax(error: SyntaxError) -> EngineError {
    EngineError::Query(error.to_string())
}

/// What the parts of a parsed rule mean on ArkCompiler code.
struct Reader<'a> {
    src: &'a str,
    dir: Option<&'a Path>,
}

impl Reader<'_> {
    fn error(&self, at: usize, message: &str) -> EngineError {
        syntax(SyntaxError::new(self.src, at, message))
    }

    fn rule(&self, rule: &Rule<'_, &'static str>) -> Result<Query> {
        let (mut all, mut none) = (Vec::new(), Vec::new());
        for part in &rule.parts {
            let query = self.condition(part)?;
            if part.negated { none.push(query) } else { all.push(query) }
        }
        Query::compound(all, none)
    }

    fn condition(&self, part: &Part<'_, &'static str>) -> Result<Query> {
        let value = match &part.value {
            Value::Text(text) => text.text,
            Value::Set { tail, .. } if !tail.text.is_empty() => return Err(self.error(tail.at, "unexpected text after the set")),
            Value::Set { mode: Mode::Every, .. } => {
                return Err(self.error(part.at, "`*` before a set follows dispatch, which only DEX code has"));
            }
            Value::Set { set: Set::Rule(rule), .. } => return Ok(Query::CallTo(FunctionSet::Matching(Box::new(self.rule(rule)?)))),
            Value::Set { set: Set::File(file), .. } => {
                let path = file.path.text;
                let text = file.read(self.dir).map_err(|e| EngineError::Query(format!("cannot read function list {path}: {e}")))?;
                return Ok(Query::CallTo(FunctionSet::listed(&text)));
            }
        };
        match part.kind {
            "string" => Query::string_regex(value),
            "literal" => Ok(Query::string_literal(value)),
            "prop" => Ok(Query::Prop { name: Pattern::name(value)?, access: None }),
            "global" => Ok(Query::Global { name: Pattern::name(value)?, access: None }),
            "import" => Query::import(value, false),
            "method" => Query::method(value, Pattern::name),
            "number" => Ok(Query::Number(value.parse::<NumberQuery>()?)),
            _ => Ok(Query::Call(Pattern::regex(value)?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asc_query::rule::MAX_DEPTH;

    fn shape(spec: &str) -> String {
        fn of(query: &Query) -> String {
            match query {
                Query::All(parts) => format!("all({})", parts.iter().map(of).collect::<Vec<_>>().join(", ")),
                Query::Not(part) => format!("!{}", of(part)),
                Query::CallTo(FunctionSet::Matching(rule)) => format!("call{{{}}}", of(rule)),
                Query::CallTo(FunctionSet::Listed(list)) => format!("call{{@{}}}", list.len()),
                other => other.kind().to_owned(),
            }
        }
        match Query::rule(spec, None) {
            Ok(query) => of(&query),
            Err(e) => format!("error: {e}"),
        }
    }

    #[test]
    fn parts_join_only_ahead_of_a_kind() {
        assert_eq!(
            parts("method:&a/b&->f & call:import:@normalized:N&&&a/b&#x"),
            ["method:&a/b&->f", "call:import:@normalized:N&&&a/b&#x"]
        );
        assert_eq!(parts("string:a&b"), ["string:a&b"]);
        assert_eq!(parts(r"string:a\&literal:b"), [r"string:a\&literal:b"]);
        assert_eq!(parts("string:a & !literal:b"), ["string:a", "!literal:b"]);
        assert_eq!(parts("string:a&! prop:b"), ["string:a", "! prop:b"]);
        // Inside braces a `&` belongs to the inner rule.
        assert_eq!(parts("call:{string:a & prop:b} & !number:1"), ["call:{string:a & prop:b}", "!number:1"]);
        assert_eq!(parts(r"string:a\{ & prop:b"), [r"string:a\{", "prop:b"]);
    }

    #[test]
    fn rules_nest_and_exclude() {
        assert_eq!(shape("string:a"), "string");
        assert_eq!(shape("string:a & !prop:=b"), "all(string, !prop)");
        assert_eq!(shape("string:a&prop:b&!global:c&!number:1"), "all(string, prop, !global, !number)");
        assert_eq!(shape("call:{string:a}"), "call{string}");
        assert_eq!(shape("call:{call:{literal:a & !prop:b}} & !method:=test"), "all(call{call{all(string, !prop)}}, !method)");
        assert_eq!(shape("call:^import:@ohos:net"), "call");
        assert_eq!(shape("call:@ohos:net"), "call");
        // A regex keeps its braces.
        assert_eq!(shape("string:^a{2,3}$ & prop:b"), "all(string, prop)");
    }

    #[test]
    fn other_spellings_of_a_kind_are_read_at_every_depth() {
        assert_eq!(Query::kind_named(" Properties "), Some("prop"));
        assert_eq!(Query::kind_named("calls"), Some("call"));
        assert_eq!((Query::kind_named("type"), Query::kind_named("s"), Query::kind_named("")), (None, None, None));
        for kind in Query::KINDS {
            assert_eq!(Query::kind_named(kind), Some(kind));
        }
        let spelled = |rule: &str| format!("{:?}", Query::rule(rule, None).unwrap());
        assert_eq!(spelled("property:=request & !Strings:a"), spelled("prop:=request & !string:a"));
        assert_eq!(
            spelled("call:{functions:=load & !text:a & call:{num:7 & property:b}}"),
            spelled("call:{method:=load & !string:a & call:{number:7 & prop:b}}")
        );
        assert_eq!(
            shape("call:{field:a}"),
            "error: bad rule \"call:{field:a}\": unknown kind \"field\": use one of string, literal, prop, global, import, method, number, \
             call at column 7"
        );
    }

    #[test]
    fn what_is_not_a_rule_says_why() {
        assert_eq!(shape("!string:a"), "error: a rule needs a condition without `!` (`!` only removes functions)");
        assert_eq!(shape("call:{string:a"), "error: bad rule \"call:{string:a\": expected `}` at column 15");
        assert_eq!(shape("call:{string:a} x"), "error: bad rule \"call:{string:a} x\": unexpected text after the set at column 17");
        assert_eq!(
            shape("call:*{string:a}"),
            "error: bad rule \"call:*{string:a}\": `*` before a set follows dispatch, which only DEX code has at column 1"
        );
        assert_eq!(shape("call:={string:a}"), shape("call:{string:a}"));
        assert_eq!(shape("call:{!string:a}"), "error: a rule needs a condition without `!` (`!` only removes functions)");
        assert!(shape("call:{type:La;}").contains(": unknown kind \"type\": use one of string, "));
        assert_eq!(shape("prop:"), "error: bad rule \"prop:\": empty value at column 6");
        assert!(shape("call:{@/nonexistent/list.txt}").starts_with("error: cannot read function list /nonexistent/list.txt: "));
        let deep = format!("{}string:a{}", "call:{".repeat(MAX_DEPTH + 1), "}".repeat(MAX_DEPTH + 1));
        assert!(shape(&deep).contains("nested deeper than 8 levels"), "{}", shape(&deep));
        assert!(
            matches!(Query::condition("string:a & prop:b"), Err(EngineError::Query(message)) if message.ends_with("give one KIND:VALUE here"))
        );
    }

    #[test]
    fn lists_take_result_rows() {
        let FunctionSet::Listed(list) = FunctionSet::listed(
            "# comment\n\nets/modules.abc | &a/b&->#~@0>#load+0x1f | B.load | callthis1 v1\n  1 <- &a/c&->#*#run | run x2\nIndex.build\n&a/c&->#*#run\n",
        ) else {
            panic!("a list")
        };
        let shown: Vec<String> =
            list.iter().map(|listed| format!("{}->{}", listed.record.as_deref().unwrap_or("*"), listed.function)).collect();
        assert_eq!(shown, ["*->Index.build", "&a/b&->#~@0>#load", "&a/c&->#*#run"]);
    }
}
