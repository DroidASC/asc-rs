//! Conditions answered over the whole APK before a search uses them:
//! `method:{RULE}` ([`Query::Nested`]) becomes the set of methods whose code
//! matches RULE, a [`Query::Virtual`] set gains the calls that may dispatch
//! to its methods, and callgraph endpoints become method signatures.
//!
//! Every condition of one call is answered by one rule-set pass
//! ([`Engine::find_refs_rules`]), which also keeps each of them in L3.

use crate::hierarchy::{ClassGraph, Defining};
use crate::{names, CacheConfig, DexView, Engine, EngineError, FindOptions, Lineage, Result};
use asc_dex::Dex;
use asc_findrefs::{ClassQuery, CompiledQuery, Defined, MemberQuery, Query};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::AtomicBool;

/// Most classes of the program that may define a supertype's method for a
/// dispatch set to follow the calls naming it ([`Query::Virtual`]'s
/// `fan_out`). An AIDL interface has its `Stub`, `Stub.Proxy`, `Default`
/// and a service or two; an abstract base a handful of subclasses. A
/// functional interface (`Runnable`, Kotlin's `FunctionN`) or a lifecycle
/// callback has hundreds to thousands, and its calls say nothing about
/// which of them runs.
pub const DEFAULT_FAN_OUT: usize = 16;
/// Most subclasses one method of a dispatch set is followed into.
const MAX_INHERITORS: usize = 10_000;
/// Most supertypes of one class a dispatch alias is made on.
const MAX_SUPERS: usize = 1_000;
/// Most classes of a supertype's subtree walked to count the classes
/// defining its method. A broader supertype is not followed whatever the
/// count: its calls may land on any of thousands of receivers (a Kotlin
/// lambda base, `Serializable`), and walking it per method is most of the
/// cost of a dispatch set.
const MAX_WALK: usize = 1_024;
/// Classes a `(dispatch ...)` note names before it counts the rest.
const MAX_LABEL_CLASSES: usize = 3;

/// The methods whose code matches each query of a
/// [`Engine::matching_methods`] call, and its notes.
pub struct MatchingMethods {
    /// `Lcls;->name(params)ret` per query.
    pub sets: Vec<BTreeSet<String>>,
    /// The supertype methods whose calls a dispatch set did not follow.
    pub notes: Vec<String>,
}

/// Queries resolved over the whole program, and the notes of what the
/// resolution left out.
pub(crate) struct Resolved {
    /// `None` when nothing had to be resolved.
    pub queries: Option<Vec<Query>>,
    /// Per query, sorted and each once.
    pub notes: Vec<Vec<String>>,
}

impl Resolved {
    fn nothing(queries: usize) -> Resolved {
        Resolved { queries: None, notes: vec![Vec::new(); queries] }
    }
}

impl Engine {
    /// The signatures (`Lcls;->name(params)ret`) of the methods whose code
    /// matches each query, all queries in one pass.
    pub fn matching_methods(&self, queries: &[Query], cancel: &AtomicBool) -> Result<MatchingMethods> {
        if queries.iter().any(|q| q.relation().is_some()) {
            return Err(EngineError::Query(
                "extends: / impl: name classes, not code: a method condition needs string, literal, type, method or field conditions"
                    .into(),
            ));
        }
        let mut sets = vec![BTreeSet::new(); queries.len()];
        let mut errors = Vec::new();
        let summary = self.find_refs_rules(queries, FindOptions::default(), cancel, &mut |i, batch| {
            if let Some(e) = batch.error {
                errors.push(format!("{}: {e}", batch.entry_name));
            }
            sets[i].extend(batch.results.into_iter().map(|r| r.signature));
        })?;
        // A method missing from the set would silently drop rows downstream.
        if !errors.is_empty() {
            return Err(EngineError::Query(format!("cannot answer a method condition: {}", errors.join("; "))));
        }
        Ok(MatchingMethods { sets, notes: summary.notes })
    }

    /// `queries` with every condition that needs the whole program resolved:
    /// `override:` / `in:{...}` over the class hierarchy, `method:{RULE}`
    /// over the code, then the dispatch aliases of each [`Query::Virtual`]
    /// set.
    pub(crate) fn resolve(&self, queries: &[Query], cancel: &AtomicBool) -> Result<Resolved> {
        let defs = self.resolve_defined(queries, cancel)?;
        let nested = self.resolve_nested(defs.as_deref().unwrap_or(queries), cancel)?;
        let base = nested.queries.as_deref().or(defs.as_deref()).unwrap_or(queries);
        let dispatched = self.resolve_dispatch(base, cancel)?;
        let notes = nested.notes.into_iter().zip(dispatched.notes).map(|(a, b)| merge_notes(a.into_iter().chain(b).collect())).collect();
        Ok(Resolved { queries: dispatched.queries.or(nested.queries).or(defs), notes })
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
    /// may dispatch to its methods ([`Hierarchy::dispatch_aliases`]).
    pub(crate) fn resolve_dispatch(&self, queries: &[Query], cancel: &AtomicBool) -> Result<Resolved> {
        // (query index, set, fan-out) of every unresolved dispatch set
        let mut sets = Vec::new();
        for (i, q) in queries.iter().enumerate() {
            let mut own = Vec::new();
            virtual_sets(q, &mut own);
            sets.extend(own.into_iter().map(|(set, fan_out)| (i, set, fan_out)));
        }
        if sets.is_empty() {
            return Ok(Resolved::nothing(queries.len()));
        }
        // Constructors, initializers and members without one class and an
        // exact name dispatch nowhere: they need no hierarchy.
        let graph = if sets.iter().flat_map(|(_, s, _)| s.iter()).any(|m| dispatch_target(m).is_some()) {
            let (views, mut errors) = self.load_views(None, cancel)?;
            let graph = self.class_graph(&views, &mut errors, cancel)?;
            Some((views, graph))
        } else {
            None
        };
        let mut hierarchy = graph.as_ref().map(|(views, graph)| Hierarchy::new(graph, views)).transpose()?;
        let mut notes = vec![Vec::new(); queries.len()];
        let mut expanded = Vec::with_capacity(sets.len());
        for (i, set, fan_out) in sets {
            expanded.push(match hierarchy.as_mut() {
                Some(h) => {
                    let e = h.dispatch_aliases(set, fan_out)?;
                    notes[i].extend(e.skipped.iter().map(|(alias, n)| skipped_note(alias, *n)));
                    (e.set, e.via)
                }
                None => (set.to_vec(), BTreeMap::new()),
            });
        }
        let mut expanded = expanded.into_iter();
        let queries = queries.iter().map(|q| with_aliases(q, &mut expanded)).collect();
        Ok(Resolved { queries: Some(queries), notes: notes.into_iter().map(merge_notes).collect() })
    }

    /// `queries` with every `method:{RULE}` replaced by the methods RULE
    /// matches. The notes of the inner rules go to each query holding one.
    pub(crate) fn resolve_nested(&self, queries: &[Query], cancel: &AtomicBool) -> Result<Resolved> {
        let mut inner = Vec::new();
        let mut holds = Vec::with_capacity(queries.len());
        for q in queries {
            let before = inner.len();
            nested_rules(q, &mut inner);
            holds.push(inner.len() > before);
        }
        if inner.is_empty() {
            return Ok(Resolved::nothing(queries.len()));
        }
        let inner: Vec<Query> = inner.into_iter().cloned().collect();
        let matching = self.matching_methods(&inner, cancel)?;
        let mut sets = matching.sets.into_iter();
        let resolved = queries.iter().map(|q| substitute(q, &mut sets)).collect::<Result<_>>()?;
        let notes = holds.into_iter().map(|h| if h { matching.notes.clone() } else { Vec::new() }).collect();
        Ok(Resolved { queries: Some(resolved), notes })
    }
}

/// The note of a supertype method a dispatch set did not follow.
fn skipped_note(alias: &str, defining: Defining) -> String {
    let why = match defining {
        Defining { count, complete: true } => format!("{count} implementers"),
        Defining { count, complete: false } => format!("over {MAX_WALK} subclasses, {count}+ implementers"),
    };
    format!("dispatch not followed via {alias} ({why}): name it explicitly, or write method:*{{...}}, to include")
}

/// `notes` sorted, each once.
pub(crate) fn merge_notes(mut notes: Vec<String>) -> Vec<String> {
    notes.sort();
    notes.dedup();
    notes
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
        Query::Virtual { target, via, fan_out } => {
            Query::Virtual { target: Box::new(substitute(target, sets)?), via: via.clone(), fan_out: *fan_out }
        }
        // `check_patterns` compiles before resolution: stand an unresolved
        // predicate in for its resolved form so compiling does not reject it.
        Query::Defined(Defined::Override(_) | Defined::In(_)) => {
            Query::Defined(Defined::Members { classes: Vec::new(), name: None, proto: None })
        }
        q => q.clone(),
    })
}

/// The method sets (and fan-out limits) of the [`Query::Virtual`]
/// conditions of `q` not yet resolved, in the order [`with_aliases`]
/// replaces them. Their targets are method sets by now:
/// [`Engine::resolve_nested`] runs first.
fn virtual_sets<'q>(q: &'q Query, out: &mut Vec<(&'q [MemberQuery], Option<usize>)>) {
    match q {
        Query::Virtual { target, via, fan_out } if via.is_empty() => {
            if let Query::MethodSet(set) = &**target {
                out.push((set, *fan_out));
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
        Query::Virtual { target, via, fan_out } if via.is_empty() && matches!(**target, Query::MethodSet(_)) => {
            let (set, via) = sets.next().expect("one expansion per dispatch set");
            Query::Virtual { target: Box::new(Query::MethodSet(set)), via, fan_out: *fan_out }
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

/// A dispatch set resolved by [`Hierarchy::dispatch_aliases`].
struct Expansion {
    /// The set's methods, then its aliases.
    set: Vec<MemberQuery>,
    /// Alias key -> the `(dispatch ...)` label of its calls.
    via: BTreeMap<String, String>,
    /// Supertype aliases left out by the fan-out limit, with how many
    /// classes define them.
    skipped: BTreeMap<String, Defining>,
}

/// The class hierarchy of the program, with what each class declares read
/// at most once: the dispatch sets of a call walk the same subtrees (a
/// Kotlin lambda base, say) for many methods.
struct Hierarchy<'g> {
    graph: &'g ClassGraph,
    /// One per view, parsed once.
    dexes: Vec<Dex<'g>>,
    /// Class -> its view and the `method_idx` of every method it defines.
    declared: HashMap<String, (usize, Vec<u32>)>,
    /// Alias key -> the classes defining it in its class's subtree.
    defining: HashMap<String, Defining>,
}

impl<'g> Hierarchy<'g> {
    fn new(graph: &'g ClassGraph, views: &'g [DexView]) -> Result<Hierarchy<'g>> {
        let dexes = views.iter().map(|v| Dex::with_name(&v.data, &v.name)).collect::<std::result::Result<_, _>>()?;
        Ok(Hierarchy { graph, dexes, declared: HashMap::new(), defining: HashMap::new() })
    }

    /// Whether `class` defines `name` (with `proto`, or any overload). Names
    /// are compared as bytes; a proto is only formatted for a matching name.
    fn defines(&mut self, class: &str, name: &str, proto: Option<&str>) -> Result<bool> {
        if !self.declared.contains_key(class) {
            let methods = match self.graph.definition(class) {
                Some((view, def_idx)) => {
                    let dex = &self.dexes[view];
                    let def = dex.class_def(def_idx)?;
                    let ids = if def.class_data_off == 0 {
                        Vec::new()
                    } else {
                        let data = dex.class_data(def.class_data_off)?;
                        data.direct_methods.iter().chain(&data.virtual_methods).map(|m| m.method_idx).collect()
                    };
                    (view, ids)
                }
                None => (0, Vec::new()),
            };
            self.declared.insert(class.to_string(), methods);
        }
        let (view, ids) = &self.declared[class];
        let Some(dex) = self.dexes.get(*view) else { return Ok(false) };
        for &idx in ids {
            let mid = dex.method_id(idx)?;
            if dex.string_bytes(mid.name_idx)? == name.as_bytes()
                && proto.is_none_or(|want| asc_smali::proto_descriptor(dex, u32::from(mid.proto_idx)).is_ok_and(|p| p == want))
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Whether `name` (`proto`) is a member of `class`: it or a supertype
    /// declares it. A class outside the program may declare anything, so
    /// one among them (`class` included) answers yes.
    fn has_member(&mut self, class: &str, name: &str, proto: Option<&str>) -> Result<bool> {
        let graph = self.graph;
        for c in std::iter::once(class.to_string()).chain(graph.reachable(class, Lineage::Supers, MAX_SUPERS)) {
            if c == "Ljava/lang/Object;" {
                continue;
            }
            if graph.definition(&c).is_none() || self.defines(&c, name, proto)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// `set` plus the calls that may dispatch to one of its methods, and the
    /// label of each one added. A call may land on `C->m` when it names `m`
    /// on a subclass of `C` that inherits it, or on a supertype of `C` or of
    /// such a subclass (an interface it implements, say): each of those
    /// becomes an alias of `C`, keyed `Lsup;->m(params)ret` (`Lsup;->m` when
    /// the set names no proto). `java.lang.Object` is left out: every class
    /// has its methods, so its calls would match whatever the set holds.
    ///
    /// A supertype's method that more than `fan_out` classes of the program
    /// define is skipped instead: its calls may run any of them. Calls
    /// naming an inheriting subclass are always kept, since they can only
    /// reach `C`'s method.
    fn dispatch_aliases(&mut self, set: &[MemberQuery], fan_out: Option<usize>) -> Result<Expansion> {
        let key = |class: &str, name: &str, proto: Option<&str>| format!("{class}->{name}{}", proto.unwrap_or(""));
        let originals: BTreeSet<String> = set.iter().filter_map(dispatch_target).map(|(c, n, p)| key(c, n, p.as_deref())).collect();
        // alias key -> its query and the set's classes it stands for
        let mut aliases: BTreeMap<String, (MemberQuery, BTreeSet<&str>)> = BTreeMap::new();
        let mut skipped = BTreeMap::new();
        let graph = self.graph;
        for m in set {
            let Some((class, name, proto)) = dispatch_target(m) else { continue };
            let proto = proto.as_deref();
            let inheritors = graph.inheritors(class, MAX_INHERITORS, |c| self.defines(c, name, proto))?;
            let subclasses = inheritors.iter().skip(1).map(|c| (c.clone(), false));
            let supers = inheritors.iter().flat_map(|c| graph.reachable(c, Lineage::Supers, MAX_SUPERS)).map(|s| (s, true));
            for (on, is_super) in subclasses.chain(supers) {
                let k = key(&on, name, proto);
                if on == "Ljava/lang/Object;" || originals.contains(&k) || skipped.contains_key(&k) {
                    continue;
                }
                // No call names a method its class neither declares nor inherits.
                if is_super && !self.has_member(&on, name, proto)? {
                    continue;
                }
                if let (true, Some(limit)) = (is_super, fan_out) {
                    let n = match self.defining.get(&k) {
                        Some(&n) => n,
                        None => {
                            let n = graph.defining(&on, MAX_WALK, |c| self.defines(c, name, proto))?;
                            self.defining.insert(k.clone(), n);
                            n
                        }
                    };
                    if !n.complete || n.count > limit {
                        aliases.remove(&k);
                        skipped.insert(k, n);
                        continue;
                    }
                }
                let (_, stands_for) = aliases.entry(k).or_insert_with(|| {
                    (MemberQuery { class: Some(ClassQuery { pattern: on, precise: true }), ..m.clone() }, BTreeSet::new())
                });
                stands_for.insert(class);
            }
        }
        let mut out = set.to_vec();
        let mut via = BTreeMap::new();
        for (k, (q, stands_for)) in aliases {
            out.push(q);
            via.insert(k, label(&stands_for));
        }
        Ok(Expansion { set: out, via, skipped })
    }
}

/// `La;|Lb;`, or the first [`MAX_LABEL_CLASSES`] then `+N`.
fn label(classes: &BTreeSet<&str>) -> String {
    let mut out = classes.iter().take(MAX_LABEL_CLASSES).copied().collect::<Vec<_>>().join("|");
    if classes.len() > MAX_LABEL_CLASSES {
        out.push_str(&format!(" +{}", classes.len() - MAX_LABEL_CLASSES));
    }
    out
}
