//! Pre-compiled queries.
//!
//! A search over an APK runs the same [`Query`] against every DEX, so the
//! regexes it needs are compiled once here and reused by every
//! [`FindRefs`](crate::FindRefs) through `find_ref_compiled`.

use crate::calls::CompiledCall;
use crate::{ClassQuery, ClassRelation, Defined, FindError, MemberQuery, MemberSignature, Query, RefKind, Result, TypeMatch};
use memchr::memmem::Finder;
use regex::bytes::Regex;
use std::collections::BTreeMap;

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

/// A [`TypeMatch`], MUTF-8 encoded like the descriptors it is compared with.
pub(crate) struct CompiledType {
    /// The whole descriptor, or `Name;` of a simple name.
    bytes: Vec<u8>,
    /// Array levels in front of a simple name; `None` for a descriptor.
    simple_dims: Option<usize>,
}

impl CompiledType {
    pub(crate) fn new(t: &TypeMatch) -> CompiledType {
        match t {
            TypeMatch::Descriptor(d) => CompiledType { bytes: asc_dex::mutf8::encode(d), simple_dims: None },
            TypeMatch::Simple { name, dims } => {
                CompiledType { bytes: asc_dex::mutf8::encode(&format!("{name};")), simple_dims: Some(*dims) }
            }
        }
    }

    /// Whether the raw descriptor `d` is of this type.
    pub(crate) fn matches(&self, d: &[u8]) -> bool {
        let Some(dims) = self.simple_dims else { return d == self.bytes };
        // `[[Lpkg/Name;` for dims 2: the array levels, then `L`, any package
        // ending in `/` (or none), then `Name;`.
        let Some(class) = d.get(dims..).filter(|_| d[..dims].iter().all(|&b| b == b'[')) else { return false };
        let Some(class) = class.strip_prefix(b"L") else { return false };
        class.ends_with(&self.bytes) && (class.len() == self.bytes.len() || class[class.len() - self.bytes.len() - 1] == b'/')
    }
}

/// A [`MemberSignature`] ready to run.
pub(crate) enum CompiledSignature {
    Method { params: Vec<CompiledType>, ret: Option<CompiledType> },
    Field(CompiledType),
}

/// Member (method / field) query with its patterns compiled.
pub(crate) struct CompiledMember {
    pub class: Option<CompiledClass>,
    pub name: Option<CompiledName>,
    pub signature: Option<CompiledSignature>,
}

pub(crate) enum Parts {
    /// String / type query; `None` when the pattern is empty (matches nothing).
    Pattern(Option<Regex>),
    /// Literal string query: the MUTF-8 encoded needle, `None` when empty.
    Literal(Option<Finder<'static>>),
    Member(CompiledMember),
    /// Any of several method queries ([`Query::MethodSet`]).
    MemberSet(Vec<CompiledMember>),
    /// Class-definition query: the MUTF-8 encoded target descriptor.
    Relation(ClassRelation, Vec<u8>),
    /// Method-definition predicate ([`Query::Defined`]), resolved. It names no
    /// constant pool index, so the engine answers it from the class
    /// definitions rather than a code scan.
    Defined(Defined),
    Compound(Compound),
    /// A method query whose call sites are judged by their values.
    Call(CompiledCall),
    /// A method set and the dispatch aliases among it ([`Query::Virtual`]).
    Virtual(Box<CompiledQuery>, BTreeMap<String, String>),
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
            Query::Method(m) => Parts::Member(compile_member(m, RefKind::Method)?),
            Query::MethodSet(set) => Parts::MemberSet(set.iter().map(|m| compile_member(m, RefKind::Method)).collect::<Result<_>>()?),
            Query::Nested(_) => {
                return Err(FindError::Invalid(
                    "method:{...} has to be resolved over every DEX first (by the engine), not compiled for one".into(),
                ))
            }
            Query::Call { target, constraints } => Parts::Call(CompiledCall::new(target, constraints)?),
            Query::Virtual { target, via } => Parts::Virtual(Box::new(CompiledQuery::new(target)?), via.clone()),
            Query::Defined(Defined::Override(_) | Defined::In(_)) => {
                return Err(FindError::Invalid(
                    "override: / in:{...} need the class hierarchy (every DEX); the engine resolves them before a search".into(),
                ))
            }
            Query::Defined(d) => Parts::Defined(d.clone()),
            Query::Field(m) => Parts::Member(compile_member(m, RefKind::Field)?),
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

    /// The resolved method-definition predicate of a [`Query::Defined`].
    #[inline]
    pub fn defined(&self) -> Option<&Defined> {
        match &self.parts {
            Parts::Defined(d) => Some(d),
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

fn compile_member(m: &MemberQuery, kind: RefKind) -> Result<CompiledMember> {
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
    let signature = match (&m.signature, kind) {
        (None, _) => None,
        (Some(MemberSignature::Method { params, ret }), RefKind::Method) => Some(CompiledSignature::Method {
            params: params.iter().map(CompiledType::new).collect(),
            ret: ret.as_ref().map(CompiledType::new),
        }),
        (Some(MemberSignature::Field(t)), RefKind::Field) => Some(CompiledSignature::Field(CompiledType::new(t))),
        (Some(sig), _) => return Err(FindError::Invalid(format!("signature {sig} does not fit a {} query", kind.as_str()))),
    };
    Ok(CompiledMember { class, name, signature })
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
            signature: None,
        });
        let c = CompiledQuery::new(&q).unwrap();
        assert_eq!(c.kind(), RefKind::Method);
        assert_eq!(c.query(), &q);
        let Parts::Member(m) = c.parts() else { panic!() };
        assert!(matches!(m.class, Some(CompiledClass::Precise(_))));
        assert!(matches!(m.name, Some(CompiledName::Substring(_))));

        // An exact name is never compiled as a regex, whatever the class.
        for class in [None, Some(ClassQuery { pattern: "Lexample/Test;".into(), precise: true })] {
            let q = Query::Field(MemberQuery { class, name: Some("a(".into()), exact_name: true, signature: None });
            let c = CompiledQuery::new(&q).unwrap();
            let Parts::Member(m) = c.parts() else { panic!() };
            assert!(matches!(&m.name, Some(CompiledName::Exact { name, bytes }) if name == "a(" && bytes == b"a("));
        }
        let q = Query::Method(MemberQuery { class: None, name: Some("\u{1F600}".into()), exact_name: true, signature: None });
        let c = CompiledQuery::new(&q).unwrap();
        let Parts::Member(m) = c.parts() else { panic!() };
        assert!(matches!(&m.name, Some(CompiledName::Exact { bytes, .. }) if bytes == &[0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80]));

        let q = Query::Field(MemberQuery { class: None, name: Some("(".into()), exact_name: false, signature: None });
        assert!(CompiledQuery::new(&q).is_err());
        let q = Query::Field(MemberQuery {
            class: Some(ClassQuery { pattern: "(".into(), precise: false }),
            name: None,
            exact_name: false,
            signature: None,
        });
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
            signature: None,
        });
        let c = CompiledQuery::new(&q).unwrap();
        let Parts::Member(m) = c.parts() else { panic!() };
        assert!(m.class.is_none() && m.name.is_none());
    }
}
