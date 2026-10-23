//! Conditions answered over the whole APK before a search uses them:
//! `method:{RULE}` ([`Query::Nested`]) becomes the set of methods whose code
//! matches RULE, a [`Query::Virtual`] set gains the calls that may dispatch
//! to its methods, and callgraph endpoints become method signatures.
//!
//! Every condition of one call is answered by one rule-set pass
//! ([`Engine::find_refs_rules`]), which also keeps each of them in L3.

use crate::hierarchy::ClassGraph;
use crate::{names, CacheConfig, DexView, Engine, EngineError, FindOptions, Lineage, Result};
use asc_findrefs::{ClassQuery, CompiledQuery, Defined, MemberQuery, Query};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::AtomicBool;

/// Most subclasses one method of a dispatch set is followed into.
const MAX_INHERITORS: usize = 10_000;
/// Most supertypes of one class a dispatch alias is made on.
const MAX_SUPERS: usize = 1_000;
/// Classes a `(dispatch ...)` note names before it counts the rest.
const MAX_LABEL_CLASSES: usize = 3;

impl Engine {
    /// The signatures (`Lcls;->name(params)ret`) of the methods whose code
    /// matches each query, all queries in one pass.
    pub fn matching_methods(&self, queries: &[Query], cancel: &AtomicBool) -> Result<Vec<BTreeSet<String>>> {
        if queries.iter().any(|q| q.relation().is_some()) {
            return Err(EngineError::Query(
                "extends: / impl: name classes, not code: a method condition needs string, literal, type, method or field conditions"
                    .into(),
            ));
        }
        let mut sets = vec![BTreeSet::new(); queries.len()];
        let mut errors = Vec::new();
        self.find_refs_rules(queries, FindOptions::default(), cancel, &mut |i, batch| {
            if let Some(e) = batch.error {
                errors.push(format!("{}: {e}", batch.entry_name));
            }
            sets[i].extend(batch.results.into_iter().map(|r| r.signature));
        })?;
        // A method missing from the set would silently drop rows downstream.
        if !errors.is_empty() {
            return Err(EngineError::Query(format!("cannot answer a method condition: {}", errors.join("; "))));
        }
        Ok(sets)
    }

    /// `queries` with every condition that needs the whole program resolved:
    /// `override:` / `in:{...}` over the class hierarchy, `method:{RULE}`
    /// over the code, then the dispatch aliases of each [`Query::Virtual`]
    /// set. `None` when nothing had to be resolved.
    pub(crate) fn resolve(&self, queries: &[Query], cancel: &AtomicBool) -> Result<Option<Vec<Query>>> {
        let defs = self.resolve_defined(queries, cancel)?;
        let nested = self.resolve_nested(defs.as_deref().unwrap_or(queries), cancel)?;
        let base = nested.as_deref().or(defs.as_deref()).unwrap_or(queries);
        let dispatched = self.resolve_dispatch(base, cancel)?;
        Ok(dispatched.or(nested).or(defs))
    }

    /// For a call that reads every DEX more than once (conditions resolved
    /// over the program, then the search) on an engine without a cache: an
    /// engine like this one whose memory cache keeps the DEX files the first
    /// pass inflated for the next ones. `None` when this engine has a cache
    /// or `needed` is false.
    pub(crate) fn transient(&self, needed: bool) -> Result<Option<Engine>> {
        if !needed || self.cache.is_some() {
            return Ok(None);
        }
        // Room for every DEX and its tables, so no pass evicts what the next reads.
        let dex_bytes: u64 = self.open()?.dex_entries()?.iter().map(|e| e.uncomp_size).sum();
        let memory_bytes = usize::try_from(dex_bytes.saturating_mul(2)).unwrap_or(usize::MAX).max(64 << 20);
        let mut engine = Engine::new(&self.apk_path).with_threads(self.threads).with_limits(self.limits).with_debug(self.debug);
        // Logged and counted as this engine.
        engine.logger = self.logger.clone();
        engine.stats = self.stats.clone();
        Ok(Some(engine.with_cache(CacheConfig { memory_bytes, ..Default::default() })))
    }

    /// `queries` with each [`Query::Virtual`] set extended by the calls that
    /// may dispatch to its methods ([`dispatch_aliases`]); `None` when none
    /// has one.
    pub(crate) fn resolve_dispatch(&self, queries: &[Query], cancel: &AtomicBool) -> Result<Option<Vec<Query>>> {
        let mut sets = Vec::new();
        for q in queries {
            virtual_sets(q, &mut sets);
        }
        if sets.is_empty() {
            return Ok(None);
        }
        // Constructors, initializers and members without one class and an
        // exact name dispatch nowhere: they need no hierarchy.
        let graph = if sets.iter().flat_map(|s| s.iter()).any(|m| dispatch_target(m).is_some()) {
            let (views, mut errors) = self.load_views(None, cancel)?;
            let graph = self.class_graph(&views, &mut errors, cancel)?;
            Some((views, graph))
        } else {
            None
        };
        let expanded = sets
            .into_iter()
            .map(|set| match &graph {
                Some((views, graph)) => dispatch_aliases(set, graph, views),
                None => Ok((set.to_vec(), BTreeMap::new())),
            })
            .collect::<Result<Vec<_>>>()?;
        let mut expanded = expanded.into_iter();
        Ok(Some(queries.iter().map(|q| with_aliases(q, &mut expanded)).collect()))
    }

    /// `queries` with every `method:{RULE}` replaced by the methods RULE
    /// matches (`None` when none has one).
    pub(crate) fn resolve_nested(&self, queries: &[Query], cancel: &AtomicBool) -> Result<Option<Vec<Query>>> {
        let mut inner = Vec::new();
        for q in queries {
            nested_rules(q, &mut inner);
        }
        if inner.is_empty() {
            return Ok(None);
        }
        let inner: Vec<Query> = inner.into_iter().cloned().collect();
        let mut sets = self.matching_methods(&inner, cancel)?.into_iter();
        let resolved = queries.iter().map(|q| substitute(q, &mut sets)).collect::<Result<_>>()?;
        Ok(Some(resolved))
    }
}

/// Whether answering `q` reads the whole program before its search:
/// `method:{RULE}`, a dispatch set, `override:` or `in:{...}`.
pub(crate) fn needs_program(q: &Query) -> bool {
    match q {
        Query::Nested(_) | Query::Virtual { .. } | Query::Defined(Defined::Override(_) | Defined::In(_)) => true,
        Query::All { all, none } => all.iter().chain(none).any(needs_program),
        Query::Call { target, .. } => needs_program(target),
        Query::String(_)
        | Query::StringLiteral(_)
        | Query::Type(_)
        | Query::Method(_)
        | Query::MethodSet(_)
        | Query::Defined(_)
        | Query::Field(_)
        | Query::Extends(_)
        | Query::Implements(_) => false,
    }
}

/// Compile `q` and its inner rules, each `method:{RULE}` standing for no
/// method: a bad pattern anywhere fails before any search runs.
pub(crate) fn check_patterns(q: &Query) -> Result<()> {
    let mut inner = Vec::new();
    nested_rules(q, &mut inner);
    for rule in inner {
        check_patterns(rule)?;
    }
    CompiledQuery::new(&substitute(q, &mut std::iter::repeat_with(BTreeSet::new))?)?;
    Ok(())
}

/// The inner rules of the `method:{RULE}` conditions of `q`, in the order
/// [`substitute`] replaces them.
fn nested_rules<'q>(q: &'q Query, out: &mut Vec<&'q Query>) {
    match q {
        Query::Nested(inner) => out.push(inner),
        Query::All { all, none } => all.iter().chain(none).for_each(|p| nested_rules(p, out)),
        Query::Call { target, .. } | Query::Virtual { target, .. } => nested_rules(target, out),
        Query::String(_)
        | Query::StringLiteral(_)
        | Query::Type(_)
        | Query::Method(_)
        | Query::MethodSet(_)
        | Query::Defined(_)
        | Query::Field(_)
        | Query::Extends(_)
        | Query::Implements(_) => {}
    }
}

/// `q` with each `method:{RULE}` replaced by the next method set of `sets`.
fn substitute(q: &Query, sets: &mut impl Iterator<Item = BTreeSet<String>>) -> Result<Query> {
    Ok(match q {
        Query::Nested(_) => {
            let methods = sets.next().expect("one method set per nested rule");
            Query::MethodSet(methods.iter().map(|m| names::exact_method(m)).collect::<Result<_>>()?)
        }
        Query::All { all, none } => Query::All {
            all: all.iter().map(|p| substitute(p, sets)).collect::<Result<_>>()?,
            none: none.iter().map(|p| substitute(p, sets)).collect::<Result<_>>()?,
        },
        Query::Call { target, constraints } => {
            Query::Call { target: Box::new(substitute(target, sets)?), constraints: constraints.clone() }
        }
        Query::Virtual { target, via } => Query::Virtual { target: Box::new(substitute(target, sets)?), via: via.clone() },
        // `check_patterns` compiles before resolution: stand an unresolved
        // predicate in for its resolved form so compiling does not reject it.
        Query::Defined(Defined::Override(_) | Defined::In(_)) => {
            Query::Defined(Defined::Members { classes: Vec::new(), name: None, proto: None })
        }
        q => q.clone(),
    })
}

/// The method sets of the [`Query::Virtual`] conditions of `q` not yet
/// resolved, in the order [`with_aliases`] replaces them. Their targets are
/// method sets by now: [`Engine::resolve_nested`] runs first.
fn virtual_sets<'q>(q: &'q Query, out: &mut Vec<&'q [MemberQuery]>) {
    match q {
        Query::Virtual { target, via } if via.is_empty() => {
            if let Query::MethodSet(set) = &**target {
                out.push(set);
            }
        }
        Query::All { all, none } => all.iter().chain(none).for_each(|p| virtual_sets(p, out)),
        Query::Call { target, .. } => virtual_sets(target, out),
        _ => {}
    }
}

/// `q` with each set [`virtual_sets`] found replaced by the next of `sets`.
fn with_aliases(q: &Query, sets: &mut impl Iterator<Item = (Vec<MemberQuery>, BTreeMap<String, String>)>) -> Query {
    match q {
        Query::Virtual { target, via } if via.is_empty() && matches!(**target, Query::MethodSet(_)) => {
            let (set, via) = sets.next().expect("one expansion per dispatch set");
            Query::Virtual { target: Box::new(Query::MethodSet(set)), via }
        }
        Query::All { all, none } => Query::All {
            all: all.iter().map(|p| with_aliases(p, sets)).collect(),
            none: none.iter().map(|p| with_aliases(p, sets)).collect(),
        },
        Query::Call { target, constraints } => {
            Query::Call { target: Box::new(with_aliases(target, sets)), constraints: constraints.clone() }
        }
        q => q.clone(),
    }
}

/// What a set member dispatches on: its class, its exact name and, when
/// concrete, its proto (`(I)V`). `None` for a member naming no single class
/// and name, and for constructors and initializers.
fn dispatch_target(m: &MemberQuery) -> Option<(&str, &str, Option<String>)> {
    let class = m.class.as_ref().filter(|c| c.precise)?;
    let name = m.name.as_deref().filter(|n| m.exact_name && !n.starts_with('<'))?;
    Some((&class.pattern, name, m.signature.as_ref().and_then(crate::defs::descriptor_proto)))
}

/// `set` plus the calls that may dispatch to one of its methods, and the
/// label of each one added. A call may land on `C->m` when it names `m` on
/// a subclass of `C` that inherits it, or on a supertype of `C` or of such
/// a subclass (an interface it implements, say): each of those becomes an
/// alias of `C`, keyed `Lsup;->m(params)ret` (`Lsup;->m` when the set names
/// no proto). `java.lang.Object` is left out: every class has its methods,
/// so its calls would match whatever the set holds.
fn dispatch_aliases(set: &[MemberQuery], graph: &ClassGraph, views: &[DexView]) -> Result<(Vec<MemberQuery>, BTreeMap<String, String>)> {
    let key = |class: &str, name: &str, proto: Option<&str>| format!("{class}->{name}{}", proto.unwrap_or(""));
    let originals: BTreeSet<String> = set.iter().filter_map(dispatch_target).map(|(c, n, p)| key(c, n, p.as_deref())).collect();
    // alias key -> its query and the set's classes it stands for
    let mut aliases: BTreeMap<String, (MemberQuery, BTreeSet<&str>)> = BTreeMap::new();
    for m in set {
        let Some((class, name, proto)) = dispatch_target(m) else { continue };
        let inheritors = graph.inheritors(views, class, name, proto.as_deref(), MAX_INHERITORS)?;
        let supers = inheritors.iter().flat_map(|c| graph.reachable(c, Lineage::Supers, MAX_SUPERS));
        for on in inheritors.iter().skip(1).cloned().chain(supers) {
            let k = key(&on, name, proto.as_deref());
            if on == "Ljava/lang/Object;" || originals.contains(&k) {
                continue;
            }
            let (_, stands_for) = aliases
                .entry(k)
                .or_insert_with(|| (MemberQuery { class: Some(ClassQuery { pattern: on, precise: true }), ..m.clone() }, BTreeSet::new()));
            stands_for.insert(class);
        }
    }
    let mut out = set.to_vec();
    let mut via = BTreeMap::new();
    for (k, (q, stands_for)) in aliases {
        out.push(q);
        via.insert(k, label(&stands_for));
    }
    Ok((out, via))
}

/// `La;|Lb;`, or the first [`MAX_LABEL_CLASSES`] then `+N`.
fn label(classes: &BTreeSet<&str>) -> String {
    let mut out = classes.iter().take(MAX_LABEL_CLASSES).copied().collect::<Vec<_>>().join("|");
    if classes.len() > MAX_LABEL_CLASSES {
        out.push_str(&format!(" +{}", classes.len() - MAX_LABEL_CLASSES));
    }
    out
}
