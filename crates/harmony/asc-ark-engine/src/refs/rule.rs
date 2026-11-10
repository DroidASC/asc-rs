//! The rule syntax of `findrefs all` / `rules` and of the endpoints of a
//! call graph walk, the one the DEX side has with the kinds of this engine.
//!
//! ```text
//! rule  := part ( '&' part )*
//! part  := [ '!' ] KIND ':' value
//! value := '{' rule '}'      call only: call sites that lead to a function the rule matches
//!        | '{@' PATH '}'     call only: to a function the file lists
//!        | TEXT              the kind's own syntax, e.g. a regex
//! ```
//!
//! A rule of one part without `!` is that condition; several make a
//! [`Query::All`] whose `!` parts are [`Query::Not`]. A `&` joins two parts
//! only where `KIND:` or `!KIND:` follows it, outside `{}`: record names and
//! module requests are full of `&` (`&entry/src/main/ets/pages/Index&`).
//! `\&` never joins, and `\{` / `\}` are not brackets.
//!
//! The DEX side writes a set of methods `method:{RULE}` / `method:@FILE`,
//! because its `method:` condition is a call. Here a call is `call:`, so
//! the set goes there, and the file inside the braces: a callee path may
//! start with `@` itself (`call:@ohos:net`).

use std::path::Path;

use super::{FunctionSet, NumberQuery, Pattern, Query};
use crate::{EngineError, Result};

/// Sets inside sets deeper than this are a mistake or hostile.
const MAX_DEPTH: usize = 8;

/// Where the next part of a rule starts after a `&`: at `KIND:` or `!KIND:`.
fn starts_part(rest: &str) -> bool {
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('!').unwrap_or(rest).trim_start();
    let word = rest.split(|c: char| !c.is_ascii_alphabetic()).next().unwrap_or_default();
    !word.is_empty() && rest[word.len()..].starts_with(':')
}

/// The parts of `rule`: what stands between the `&` that join conditions.
pub(crate) fn parts(rule: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut start, mut depth, mut escaped) = (0, 0usize, false);
    for (at, c) in rule.char_indices() {
        match c {
            _ if escaped => {}
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            '&' if depth == 0 && starts_part(&rule[at + 1..]) => {
                parts.push(rule[start..at].trim());
                start = at + 1;
            }
            _ => {}
        }
        escaped = c == '\\' && !escaped;
    }
    parts.push(rule[start..].trim());
    parts
}

fn unknown(spec: &str) -> EngineError {
    EngineError::Query(format!("{spec:?} is not a condition: write KIND:VALUE with KIND one of {}", Query::KINDS.join(", ")))
}

/// The value of a `call:` condition: a set in braces, or a callee path regex.
fn call(value: &str, dir: Option<&Path>, depth: usize) -> Result<Query> {
    let Some(body) = value.strip_prefix('{') else { return Ok(Query::Call(Pattern::regex(value)?)) };
    let Some(body) = body.strip_suffix('}') else {
        return Err(EngineError::Query(format!("call:{value}: expected `}}` at the end of the set")));
    };
    if depth >= MAX_DEPTH {
        return Err(EngineError::Query(format!("call:{value}: sets are nested deeper than {MAX_DEPTH} levels")));
    }
    let set = match body.trim().strip_prefix('@') {
        Some(path) => {
            let path = path.trim();
            // An absolute `path` replaces `dir` when joined.
            let full = dir.map_or_else(|| Path::new(path).to_path_buf(), |dir| dir.join(path));
            let text = std::fs::read_to_string(&full).map_err(|e| EngineError::Query(format!("cannot read function list {path}: {e}")))?;
            FunctionSet::listed(&text)
        }
        None => FunctionSet::Matching(Box::new(rule(body, dir, depth + 1)?)),
    };
    Ok(Query::CallTo(set))
}

/// One part without its `!`.
fn condition(spec: &str, dir: Option<&Path>, depth: usize) -> Result<Query> {
    let (kind, value) = spec.split_once(':').ok_or_else(|| unknown(spec))?;
    let (kind, value) = (kind.trim(), value.trim());
    if !Query::KINDS.contains(&kind) {
        return Err(unknown(spec));
    }
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
        "number" => Ok(Query::Number(value.parse::<NumberQuery>()?)),
        _ => call(value, dir, depth),
    }
}

fn rule(spec: &str, dir: Option<&Path>, depth: usize) -> Result<Query> {
    let (mut all, mut none) = (Vec::new(), Vec::new());
    for part in parts(spec) {
        match part.strip_prefix('!') {
            Some(excluded) => none.push(condition(excluded.trim_start(), dir, depth)?),
            None => all.push(condition(part, dir, depth)?),
        }
    }
    Query::compound(all, none)
}

pub(super) fn parse(spec: &str, dir: Option<&Path>) -> Result<Query> {
    rule(spec, dir, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn what_is_not_a_rule_says_why() {
        assert_eq!(shape("!string:a"), "error: a rule needs a condition without `!` (`!` only removes functions)");
        assert_eq!(shape("call:{string:a"), "error: call:{string:a: expected `}` at the end of the set");
        assert_eq!(shape("call:{!string:a}"), "error: a rule needs a condition without `!` (`!` only removes functions)");
        assert!(shape("call:{type:La;}").starts_with("error: \"type:La;\" is not a condition: write KIND:VALUE with KIND one of string, "));
        assert_eq!(shape("prop:"), "error: prop: needs a value");
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
