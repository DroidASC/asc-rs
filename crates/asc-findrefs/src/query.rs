//! Pre-compiled queries.
//!
//! A search over an APK runs the same [`Query`] against every DEX, so the
//! regexes it needs are compiled once here and reused by every
//! [`FindRefs`](crate::FindRefs) through `find_ref_compiled`.

use crate::{ClassQuery, ClassRelation, FindError, MemberQuery, Query, RefKind, Result};
use memchr::memmem::Finder;
use regex::bytes::Regex;

/// Class constraint of a member query, ready to run.
pub(crate) enum CompiledClass {
    /// Exact descriptor (MUTF-8 encoded), looked up with a binary search over
    /// the type table.
    Precise(Vec<u8>),
    /// Regex over the descriptor strings.
    Fuzzy(Regex),
}

/// Member-name constraint of a member query, ready to run.
pub(crate) enum CompiledName {
    /// Substring match on the decoded name (precise class only).
    Substring(String),
    /// Regex over the raw string table.
    Regex(Regex),
    /// Whole-name equality; `bytes` is the MUTF-8 encoding of `name`.
    Exact { name: String, bytes: Vec<u8> },
}

/// Member (method / field) query with its patterns compiled.
pub(crate) struct CompiledMember {
    pub class: Option<CompiledClass>,
    pub name: Option<CompiledName>,
}

pub(crate) enum Parts {
    /// String / type query; `None` when the pattern is empty (matches nothing).
    Pattern(Option<Regex>),
    /// Literal string query: the MUTF-8 encoded needle, `None` when empty.
    Literal(Option<Finder<'static>>),
    Member(CompiledMember),
    /// Class-definition query: the MUTF-8 encoded target descriptor.
    Relation(ClassRelation, Vec<u8>),
    Compound(Compound),
}

/// The compiled parts of a [`Query::All`].
pub struct Compound {
    /// Every one must match in a method.
    pub all: Vec<CompiledQuery>,
    /// None may match in it.
    pub none: Vec<CompiledQuery>,
}

/// A [`Query`] with every regular expression it needs compiled up front.
///
/// The string/type pattern, a fuzzy class pattern and a member name used as a
/// regex are compiled here; a member name matched as a substring (precise
/// class) or exactly (`exact_name`) is kept as the plain string. Empty patterns are kept as "no
/// constraint" exactly as [`FindRefs::locate`](crate::FindRefs::locate)
/// treats them.
pub struct CompiledQuery {
    query: Query,
    kind: RefKind,
    parts: Parts,
}

impl CompiledQuery {
    /// Compile `q`. Fails only when one of its patterns is not a valid regex.
    pub fn new(q: &Query) -> Result<CompiledQuery> {
        let parts = match q {
            Query::String(p) | Query::Type(p) => Parts::Pattern(compile_opt(p)?),
            // MUTF-8, like the string data it is searched in, so a supplementary
            // character (a surrogate pair there) is found too.
            Query::StringLiteral(p) => Parts::Literal((!p.is_empty()).then(|| Finder::new(&asc_dex::mutf8::encode(p)).into_owned())),
            Query::Method(m) | Query::Field(m) => Parts::Member(compile_member(m)?),
            Query::Extends(d) => Parts::Relation(ClassRelation::Extends, asc_dex::mutf8::encode(d)),
            Query::Implements(d) => Parts::Relation(ClassRelation::Implements, asc_dex::mutf8::encode(d)),
            Query::All { all, none } => {
                if all.is_empty() {
                    return Err(FindError::Invalid("a compound query needs at least one condition in `all`".into()));
                }
                let part = |q: &Query| match q {
                    Query::All { .. } => Err(FindError::Invalid("compound queries do not nest".into())),
                    Query::Extends(_) | Query::Implements(_) => {
                        Err(FindError::Invalid("extends / impl name classes, not code: they cannot be combined".into()))
                    }
                    q => CompiledQuery::new(q),
                };
                Parts::Compound(Compound {
                    all: all.iter().map(part).collect::<Result<_>>()?,
                    none: none.iter().map(part).collect::<Result<_>>()?,
                })
            }
        };
        Ok(CompiledQuery { query: q.clone(), kind: q.kind(), parts })
    }

    #[inline]
    pub fn kind(&self) -> RefKind {
        self.kind
    }

    #[inline]
    pub fn query(&self) -> &Query {
        &self.query
    }

    /// The class relation an `Extends` / `Implements` query asks for.
    #[inline]
    pub fn relation(&self) -> Option<ClassRelation> {
        self.query.relation()
    }

    /// The parts of a compound query ([`Query::All`]).
    #[inline]
    pub fn compound(&self) -> Option<&Compound> {
        match &self.parts {
            Parts::Compound(c) => Some(c),
            _ => None,
        }
    }

    #[inline]
    pub(crate) fn parts(&self) -> &Parts {
        &self.parts
    }
}

impl std::fmt::Debug for CompiledQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledQuery").field("query", &self.query).finish_non_exhaustive()
    }
}

fn compile_opt(pattern: &str) -> Result<Option<Regex>> {
    if pattern.is_empty() {
        Ok(None)
    } else {
        Ok(Some(Regex::new(pattern)?))
    }
}

fn compile_member(m: &MemberQuery) -> Result<CompiledMember> {
    let class = match m.class.as_ref().filter(|c| !c.pattern.is_empty()) {
        None => None,
        Some(ClassQuery { pattern, precise: true }) => Some(CompiledClass::Precise(asc_dex::mutf8::encode(pattern))),
        Some(ClassQuery { pattern, precise: false }) => Some(CompiledClass::Fuzzy(Regex::new(pattern)?)),
    };
    let name = match m.name.as_deref().filter(|n| !n.is_empty()) {
        None => None,
        Some(n) if m.exact_name => Some(CompiledName::Exact { name: n.to_string(), bytes: asc_dex::mutf8::encode(n) }),
        // With a precise class the member name is a substring match (as the
        // Python implementation does); otherwise it is a regex.
        Some(n) if matches!(class, Some(CompiledClass::Precise(_))) => Some(CompiledName::Substring(n.to_string())),
        Some(n) => Some(CompiledName::Regex(Regex::new(n)?)),
    };
    Ok(CompiledMember { class, name })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn compiled_query_is_send_sync() {
        assert_send_sync::<CompiledQuery>();
    }

    #[test]
    fn compiles_only_what_is_used() {
        let q = Query::Method(MemberQuery {
            class: Some(ClassQuery { pattern: "Lexample/Test;".into(), precise: true }),
            name: Some("(".into()), // invalid regex, but a substring here
            exact_name: false,
        });
        let c = CompiledQuery::new(&q).unwrap();
        assert_eq!(c.kind(), RefKind::Method);
        assert_eq!(c.query(), &q);
        let Parts::Member(m) = c.parts() else { panic!() };
        assert!(matches!(m.class, Some(CompiledClass::Precise(_))));
        assert!(matches!(m.name, Some(CompiledName::Substring(_))));

        // An exact name is never compiled as a regex, whatever the class.
        for class in [None, Some(ClassQuery { pattern: "Lexample/Test;".into(), precise: true })] {
            let q = Query::Field(MemberQuery { class, name: Some("a(".into()), exact_name: true });
            let c = CompiledQuery::new(&q).unwrap();
            let Parts::Member(m) = c.parts() else { panic!() };
            assert!(matches!(&m.name, Some(CompiledName::Exact { name, bytes }) if name == "a(" && bytes == b"a("));
        }
        let q = Query::Method(MemberQuery { class: None, name: Some("\u{1F600}".into()), exact_name: true });
        let c = CompiledQuery::new(&q).unwrap();
        let Parts::Member(m) = c.parts() else { panic!() };
        assert!(matches!(&m.name, Some(CompiledName::Exact { bytes, .. }) if bytes == &[0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80]));

        let q = Query::Field(MemberQuery { class: None, name: Some("(".into()), exact_name: false });
        assert!(CompiledQuery::new(&q).is_err());
        let q =
            Query::Field(MemberQuery { class: Some(ClassQuery { pattern: "(".into(), precise: false }), name: None, exact_name: false });
        assert!(CompiledQuery::new(&q).is_err());
        let q = Query::String("[".into());
        assert!(CompiledQuery::new(&q).is_err());

        // A literal is never a regex; an empty one matches nothing.
        let c = CompiledQuery::new(&Query::StringLiteral("[".into())).unwrap();
        assert_eq!(c.kind(), RefKind::String);
        assert!(matches!(c.parts(), Parts::Literal(Some(f)) if f.needle() == b"["));
        let c = CompiledQuery::new(&Query::StringLiteral("\u{1F600}".into())).unwrap();
        assert!(matches!(c.parts(), Parts::Literal(Some(f)) if f.needle() == [0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80]));
        assert!(matches!(CompiledQuery::new(&Query::StringLiteral(String::new())).unwrap().parts(), Parts::Literal(None)));

        let c = CompiledQuery::new(&Query::Implements("Lexample/Iface;".into())).unwrap();
        assert_eq!(c.relation(), Some(ClassRelation::Implements));
        assert!(matches!(c.parts(), Parts::Relation(ClassRelation::Implements, d) if d == b"Lexample/Iface;"));
        assert_eq!(CompiledQuery::new(&Query::String("x".into())).unwrap().relation(), None);

        let c = CompiledQuery::new(&Query::Type(String::new())).unwrap();
        assert!(matches!(c.parts(), Parts::Pattern(None)));
        let q = Query::Method(MemberQuery {
            class: Some(ClassQuery { pattern: String::new(), precise: false }),
            name: None,
            exact_name: false,
        });
        let c = CompiledQuery::new(&q).unwrap();
        let Parts::Member(m) = c.parts() else { panic!() };
        assert!(m.class.is_none() && m.name.is_none());
    }
}
