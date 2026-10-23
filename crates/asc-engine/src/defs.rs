//! Method-definition predicates ([`Query::Defined`]): `flag:`, `annotation:`,
//! `override:` and `in:{...}`.
//!
//! `override:` and `in:{...}` need the class hierarchy, which spans every DEX,
//! so [`Engine::resolve_defined`] turns them into a [`Defined::Members`] set
//! of declaring classes up front (like a nested rule). [`defined_methods`]
//! then answers every predicate against one DEX's class definitions, reading
//! no code.

use crate::hierarchy::ClassGraph;
use crate::{names, DexView, Engine, EngineError, Lineage, Result};
use asc_dex::annotations::AnnotationsDirectory;
use asc_dex::{encoded, Dex};
use asc_findrefs::{Defined, Query};
use regex::bytes::Regex;
use std::collections::BTreeSet;
use std::sync::atomic::AtomicBool;

/// The method ids of `dex` whose declaration matches `d`, sorted. `d` must be
/// resolved (`Flags` / `Annotation` / `Members`): [`Engine::resolve_defined`]
/// replaces `override:` / `in:{...}` beforehand.
pub(crate) fn defined_methods(dex: &Dex<'_>, d: &Defined) -> Result<Vec<u32>> {
    let mut out = Vec::new();
    match d {
        Defined::Flags(mask) => {
            for def in dex.class_defs() {
                let def = def?;
                if def.class_data_off == 0 {
                    continue;
                }
                for m in dex.class_data(def.class_data_off)?.methods() {
                    if m.access_flags & mask == *mask {
                        out.push(m.method_idx);
                    }
                }
            }
        }
        Defined::Annotation(a) => {
            let Some(want) = dex.find_type_idx(&asc_dex::mutf8::encode(a))? else { return Ok(out) };
            for def in dex.class_defs() {
                let def = def?;
                if def.annotations_off == 0 {
                    continue;
                }
                let dir = AnnotationsDirectory::parse(dex.buf(), def.annotations_off as usize)?;
                for (method_idx, set_off) in dir.method_annotations {
                    if annotation_set_has(dex, set_off, want)? {
                        out.push(method_idx);
                    }
                }
            }
        }
        Defined::Members { classes, name, proto } => {
            let name = name.as_deref();
            for class in classes {
                let Some((_, def)) = dex.find_class_def(&asc_dex::mutf8::encode(class))? else { continue };
                if def.class_data_off == 0 {
                    continue;
                }
                for m in dex.class_data(def.class_data_off)?.methods() {
                    let id = dex.method_id(m.method_idx)?;
                    if name.is_some_and(|n| dex.string_bytes(id.name_idx).map(|b| b != n.as_bytes()).unwrap_or(true)) {
                        continue;
                    }
                    if let Some(want) = proto {
                        if asc_smali::proto_descriptor(dex, id.proto_idx as u32)? != *want {
                            continue;
                        }
                    }
                    out.push(m.method_idx);
                }
            }
        }
        Defined::Override(_) | Defined::In(_) => {
            return Err(EngineError::Query("override: / in:{...} must be resolved before a search".into()))
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// Whether the `annotation_set_item` at `off` holds an annotation of type
/// `want`.
fn annotation_set_has(dex: &Dex<'_>, off: u32, want: u32) -> Result<bool> {
    if off == 0 {
        return Ok(false);
    }
    for item_off in asc_dex::annotations::parse_annotation_set(dex.buf(), off as usize)? {
        let (item, _) = encoded::parse_annotation_item(dex.buf(), item_off as usize)?;
        if item.annotation.type_idx == want {
            return Ok(true);
        }
    }
    Ok(false)
}

impl Engine {
    /// `queries` with every `override:` / `in:{...}` replaced by the
    /// [`Defined::Members`] of the classes it names, resolved over the class
    /// hierarchy; `None` when none has one. Nested bodies are left untouched
    /// (resolved on their own pass when the engine runs them).
    pub(crate) fn resolve_defined(&self, queries: &[Query], cancel: &AtomicBool) -> Result<Option<Vec<Query>>> {
        if !queries.iter().any(has_predicate) {
            return Ok(None);
        }
        let (views, mut errors) = self.load_views(None, cancel)?;
        let graph = self.class_graph(&views, &mut errors, cancel)?;
        let resolved = queries.iter().map(|q| rewrite(q, &graph, &views)).collect::<Result<_>>()?;
        Ok(Some(resolved))
    }
}

/// Whether `q` carries an `override:` / `in:{...}` outside a nested body.
fn has_predicate(q: &Query) -> bool {
    match q {
        Query::Defined(Defined::Override(_) | Defined::In(_)) => true,
        Query::All { all, none } => all.iter().chain(none).any(has_predicate),
        _ => false,
    }
}

/// `q` with each `override:` / `in:{...}` resolved to its classes.
fn rewrite(q: &Query, graph: &ClassGraph, views: &[DexView]) -> Result<Query> {
    Ok(match q {
        Query::Defined(Defined::Override(target)) => Query::Defined(resolve_override(target, graph)?),
        Query::Defined(Defined::In(inner)) => Query::Defined(resolve_in(inner, graph, views)?),
        Query::All { all, none } => Query::All {
            all: all.iter().map(|p| rewrite(p, graph, views)).collect::<Result<_>>()?,
            none: none.iter().map(|p| rewrite(p, graph, views)).collect::<Result<_>>()?,
        },
        q => q.clone(),
    })
}

/// `override:TARGET` → the methods of `TARGET`'s class and of every subtype,
/// with that name and proto. The declaring class is included: its own
/// definition overrides the same name, and an interface method is matched on
/// its implementers.
fn resolve_override(target: &asc_findrefs::MemberQuery, graph: &ClassGraph) -> Result<Defined> {
    let class = target
        .class
        .as_ref()
        .filter(|c| c.precise && !c.pattern.is_empty())
        .ok_or_else(|| EngineError::Query("override: needs a concrete class, e.g. override:android.os.IInterface->asBinder".into()))?;
    let name = target.name.clone().ok_or_else(|| EngineError::Query("override: needs a method name".into()))?;
    let proto = target.signature.as_ref().and_then(descriptor_proto);
    let mut classes = vec![class.pattern.clone()];
    classes.extend(graph.reachable(&class.pattern, Lineage::Subclasses, MAX_CLASSES));
    Ok(Defined::Members { classes, name: Some(name), proto })
}

/// The Dalvik proto string (`(I)Ljava/lang/String;`) of an override
/// signature, but only when every part is a concrete descriptor and the
/// return type is given — otherwise the override matches on the name alone
/// (every overload), since a bare `String` names a type in any package.
fn descriptor_proto(sig: &asc_findrefs::MemberSignature) -> Option<String> {
    use asc_findrefs::{MemberSignature, TypeMatch};
    let MemberSignature::Method { params, ret: Some(ret) } = sig else { return None };
    fn descriptor(t: &TypeMatch) -> Option<&str> {
        match t {
            TypeMatch::Descriptor(d) => Some(d.as_str()),
            TypeMatch::Simple { .. } => None,
        }
    }
    let mut out = String::from("(");
    for p in params {
        out.push_str(descriptor(p)?);
    }
    out.push(')');
    out.push_str(descriptor(ret)?);
    Some(out)
}

/// `in:{CLASS-RULE}` → the classes the rule names. `extends:` / `impl:` take
/// the whole subtree; `type:` matches the defined class descriptors by
/// regex; `annotation:` the classes carrying that class annotation.
fn resolve_in(inner: &Query, graph: &ClassGraph, views: &[DexView]) -> Result<Defined> {
    let classes = match inner {
        Query::Extends(c) | Query::Implements(c) => {
            let mut set = vec![c.clone()];
            set.extend(graph.reachable(c, Lineage::Subclasses, MAX_CLASSES));
            set
        }
        Query::Type(pattern) => {
            let re = Regex::new(pattern).map_err(|e| EngineError::Query(format!("in:{{type:...}}: bad regex: {e}")))?;
            graph.defined_classes_matching(&re)
        }
        Query::Defined(Defined::Annotation(a)) => classes_with_annotation(views, a)?,
        _ => return Err(EngineError::Query("in:{...} takes a class condition: extends:, impl:, type: or annotation:".into())),
    };
    Ok(Defined::Members { classes, name: None, proto: None })
}

/// Descriptors of the classes in `views` carrying the class annotation `a`.
fn classes_with_annotation(views: &[DexView], a: &str) -> Result<Vec<String>> {
    let want_bytes = asc_dex::mutf8::encode(a);
    let mut out = BTreeSet::new();
    for v in views {
        let dex = Dex::with_name(&v.data, &v.name)?;
        let Some(want) = dex.find_type_idx(&want_bytes)? else { continue };
        for def in dex.class_defs() {
            let def = def?;
            if def.annotations_off == 0 {
                continue;
            }
            let dir = AnnotationsDirectory::parse(dex.buf(), def.annotations_off as usize)?;
            if annotation_set_has(&dex, dir.class_annotations_off, want)? {
                out.insert(dex.type_descriptor(def.class_idx)?);
            }
        }
    }
    Ok(out.into_iter().collect())
}

/// Most classes an `override:` / `in:` predicate expands to; a wider subtree
/// is truncated rather than left to grow without bound.
const MAX_CLASSES: usize = 100_000;

/// Parse the access flags of a `flag:` value (`public`, `static`, ...),
/// comma separated, into a mask every matched method must carry.
pub(crate) fn parse_flags(value: &str) -> Result<u32> {
    use asc_dex::access;
    let mut mask = 0;
    for raw in value.split(',') {
        let name = raw.trim();
        mask |= match name.to_ascii_lowercase().as_str() {
            "public" => access::PUBLIC,
            "private" => access::PRIVATE,
            "protected" => access::PROTECTED,
            "static" => access::STATIC,
            "final" => access::FINAL,
            "synchronized" => access::SYNCHRONIZED,
            "bridge" => access::BRIDGE,
            "varargs" => access::VARARGS,
            "native" => access::NATIVE,
            "interface" => access::INTERFACE,
            "abstract" => access::ABSTRACT,
            "synthetic" => access::SYNTHETIC,
            "annotation" => access::ANNOTATION,
            "enum" => access::ENUM,
            "constructor" => access::CONSTRUCTOR,
            _ => {
                return Err(EngineError::Query(format!(
                    "flag:{name:?}: use public, private, protected, static, final, synchronized, native, abstract, synthetic, constructor"
                )))
            }
        };
    }
    if mask == 0 {
        return Err(EngineError::Query("flag: needs at least one access flag".into()));
    }
    Ok(mask)
}

/// The annotation / class descriptor of an `annotation:` or `in:{annotation:}`
/// value: `com.a.B`, `La/B;` or `a/B` all become `La/B;`.
pub(crate) fn annotation_descriptor(value: &str) -> Result<String> {
    names::format_class_name(value.trim())
}
