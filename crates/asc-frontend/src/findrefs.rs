//! A `findrefs` search of a DEX program as a query: what the CLI's
//! subcommands (`findrefs method NAME --class C --exact`) and the MCP tool's
//! arguments (`kind`, `value`, `name`, `class`, ...) mean, read once.

use asc_engine::{EngineError, condition, names};
use asc_findrefs::{FieldAccess, Query};
use std::path::Path;

/// One kind of search and what it looks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Target<'a> {
    /// Strings: a regex, or (`literal`) a substring.
    String {
        /// The pattern.
        value: &'a str,
        /// `value` is a plain substring, not a regex.
        literal: bool,
    },
    /// Type references by a fuzzy descriptor or name.
    Type(&'a str),
    /// Direct subclasses of a class.
    Extends(&'a str),
    /// Direct implementers of an interface.
    Impl(&'a str),
    /// Calls of methods.
    Method(Member<'a>),
    /// Field accesses, or only reads or writes.
    Field {
        /// The field searched for.
        member: Member<'a>,
        /// Only reads or only writes; `None` for both.
        access: Option<FieldAccess>,
    },
}

/// A method or field as a search names it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Member<'a> {
    /// The class: exact (`Lc;`, `c.B`), or a pattern with `fuzzy_class`.
    pub class: Option<&'a str>,
    /// `class` is a pattern matched against class names, not an exact class.
    pub fuzzy_class: bool,
    /// A name regex / substring, or the whole target (`Lc;->m(I)V`,
    /// `c.B.m`, `B#m`).
    pub name: Option<&'a str>,
    /// `name` is the exact name.
    pub exact: bool,
}

impl<'a> Member<'a> {
    /// The member with [`class`](#structfield.class) set.
    #[must_use]
    pub fn class(self, class: Option<&'a str>) -> Self {
        Member { class, ..self }
    }

    /// The member with [`fuzzy_class`](#structfield.fuzzy_class) set.
    #[must_use]
    pub fn fuzzy_class(self, fuzzy_class: bool) -> Self {
        Member { fuzzy_class, ..self }
    }

    /// The member with [`name`](#structfield.name) set.
    #[must_use]
    pub fn name(self, name: Option<&'a str>) -> Self {
        Member { name, ..self }
    }

    /// The member with [`exact`](#structfield.exact) set.
    #[must_use]
    pub fn exact(self, exact: bool) -> Self {
        Member { exact, ..self }
    }
}

impl Target<'_> {
    /// The query. A method target given without a class that is written as
    /// a condition value (a set `{RULE}` / `{@FILE}` / `@FILE`, maybe after
    /// `=` or `*`, or call constraints `X[arg0=1]`) reads as `method:TARGET`;
    /// its files are read relative to `dir` (the current directory when
    /// `None`).
    ///
    /// # Errors
    /// A class or member the names syntax does not take, or a condition that
    /// does not parse.
    pub fn query(&self, dir: Option<&Path>) -> Result<Query, EngineError> {
        Ok(match *self {
            Target::String { value, literal: false } => Query::String(value.to_owned()),
            Target::String { value, literal: true } => Query::StringLiteral(value.to_owned()),
            Target::Type(value) => Query::Type(value.to_owned()),
            // The class-def lookups need the precise Dalvik form.
            Target::Extends(class) => Query::Extends(names::format_class_name(class.trim())?),
            Target::Impl(class) => Query::Implements(names::format_class_name(class.trim())?),
            Target::Method(Member { class: None, name: Some(name), .. }) if is_condition(name) => {
                condition::parse_condition_in(&format!("method:{name}"), dir)?
            }
            Target::Method(member) => Query::Method(member.query("method")?),
            Target::Field { member, access: None } => Query::Field(member.query("field")?),
            Target::Field { member, access: Some(access) } => Query::FieldAccess { field: member.query("field")?, access },
        })
    }
}

impl Member<'_> {
    fn query(&self, kind: &str) -> Result<asc_findrefs::MemberQuery, EngineError> {
        names::member_query(kind, self.class, self.fuzzy_class, self.name, self.exact)
    }
}

/// Whether a method target is written as the value of a `method:` condition
/// rather than as a method: a set or call constraints.
fn is_condition(target: &str) -> bool {
    target.trim_start().trim_start_matches(['=', '*']).starts_with(['{', '@']) || condition::has_constraints(target)
}

/// The methods matching every query of `all` and none of `none`: one query
/// alone is that query itself, as one condition of a rule is.
///
/// # Errors
/// `all` is empty: exclusions only remove methods.
///
/// # Panics
/// Never: the single query is popped only when `all` has exactly one.
pub fn compound(mut all: Vec<Query>, none: Vec<Query>) -> Result<Query, EngineError> {
    match (all.len(), none.is_empty()) {
        (0, _) => Err(EngineError::Query("a rule needs a condition without `!` (`!` only removes methods)".into())),
        (1, true) => Ok(all.pop().expect("one query")),
        _ => Ok(Query::All { all, none }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn method(name: &str) -> Target<'_> {
        Target::Method(Member { name: Some(name), ..Member::default() })
    }

    #[test]
    fn each_kind_is_its_query() {
        let query = |target: Target<'_>| target.query(None).unwrap();
        assert_eq!(query(Target::String { value: "a.b", literal: false }), Query::String("a.b".into()));
        assert_eq!(query(Target::String { value: "a.b", literal: true }), Query::StringLiteral("a.b".into()));
        assert_eq!(query(Target::Extends(" android.app.Activity ")), Query::Extends("Landroid/app/Activity;".into()));
        assert_eq!(query(Target::Impl("Lx/I;")), Query::Implements("Lx/I;".into()));
        assert_eq!(
            query(method("Lc;->m(I)V")),
            Query::Method(names::member_query("method", None, false, Some("Lc;->m(I)V"), false).unwrap())
        );
        let field = Member { class: Some("Lc;"), name: Some("f"), ..Member::default() };
        assert!(matches!(query(Target::Field { member: field, access: Some(FieldAccess::Write) }), Query::FieldAccess { .. }));
        assert!(matches!(query(Target::Field { member: field, access: None }), Query::Field(_)));
    }

    #[test]
    fn a_method_written_as_a_condition_value_reads_as_one() {
        let query = |name| method(name).query(None).unwrap();
        assert_eq!(query("{literal:imei}"), names::parse_rule("method:{literal:imei}").unwrap());
        assert_eq!(query("={literal:imei}"), names::parse_rule("method:={literal:imei}").unwrap());
        assert_eq!(query("x[arg0=1]"), names::parse_rule("method:x[arg0=1]").unwrap());
        assert!(method("@/nonexistent/set.txt").query(None).unwrap_err().to_string().contains("cannot read method set"));
        // With a class the name is a method name.
        let named = Target::Method(Member { class: Some("Lc;"), name: Some("{x}"), ..Member::default() });
        assert!(matches!(named.query(None), Ok(Query::Method(_))));
    }

    #[test]
    fn compounds_of_one_are_that_query() {
        let a = Query::String("a".into());
        assert_eq!(compound(vec![a.clone()], vec![]).unwrap(), a);
        assert_eq!(compound(vec![a.clone()], vec![a.clone()]).unwrap(), Query::All { all: vec![a.clone()], none: vec![a.clone()] });
        assert!(compound(vec![], vec![a]).unwrap_err().to_string().contains("needs a condition without `!`"));
    }
}
