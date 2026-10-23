//! Conditions answered over the whole APK before a search uses them:
//! `method:{RULE}` ([`Query::Nested`]) becomes the set of methods whose code
//! matches RULE, and callgraph endpoints become method signatures.
//!
//! Every condition of one call is answered by one rule-set pass
//! ([`Engine::find_refs_rules`]), which also keeps each of them in L3.

use crate::{names, Engine, EngineError, FindOptions, Result};
use asc_findrefs::{CompiledQuery, Defined, Query};
use std::collections::BTreeSet;
use std::sync::atomic::AtomicBool;

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
    /// `override:` / `in:{...}` over the class hierarchy, then `method:{RULE}`
    /// over the code. `None` when nothing had to be resolved.
    pub(crate) fn resolve(&self, queries: &[Query], cancel: &AtomicBool) -> Result<Option<Vec<Query>>> {
        let defs = self.resolve_defined(queries, cancel)?;
        let base: &[Query] = defs.as_deref().unwrap_or(queries);
        let nested = self.resolve_nested(base, cancel)?;
        Ok(nested.or(defs))
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
        Query::Call { target, .. } => nested_rules(target, out),
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
        // `check_patterns` compiles before resolution: stand an unresolved
        // predicate in for its resolved form so compiling does not reject it.
        Query::Defined(Defined::Override(_) | Defined::In(_)) => {
            Query::Defined(Defined::Members { classes: Vec::new(), name: None, proto: None })
        }
        q => q.clone(),
    })
}
