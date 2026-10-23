//! Callers / callees of a method across every DEX of an APK.
//!
//! Each DEX has its own static call graph ([`asc_findrefs::CallGraph`], built
//! on first use and kept with the cached entry's locator tables). Method ids
//! are local to a DEX, so the walk keys methods by signature
//! (`Lcls;->name(params)ret`) and, level by level, looks each frontier method
//! up in every DEX (binary search over the sorted `method_id` table), then
//! follows that DEX's edges. Calls are static references: a call through
//! `Lsub;->m()V` does not count as a call of `Lbase;->m()V`, unless the query
//! asks for virtual dispatch ([`CallQuery::virtual_calls`]): then the callers
//! of a method also include the callers of the same signature on each of its
//! supertypes (marked `via`), and the callees of a method also include the
//! overrides of each callee in its subclasses (marked `override of`).

use crate::hierarchy::{ClassGraph, Lineage};
use crate::{cancelled, DexView, Engine, EngineError, Result, NOT_CANCELLED};
use asc_dex::Dex;
use asc_findrefs::FindRefs;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;

/// Which way to walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Methods whose body invokes the target.
    Callers,
    /// Methods the target's body invokes.
    Callees,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Callers => "callers",
            Direction::Callees => "callees",
        }
    }

    fn arrow(self) -> &'static str {
        match self {
            Direction::Callers => "<-",
            Direction::Callees => "->",
        }
    }
}

/// A call graph query.
#[derive(Debug, Clone)]
pub struct CallQuery {
    /// Declaring class, as a Dalvik descriptor (`Lcom/poc/Main;`).
    pub class: String,
    /// Method name (every overload) or exact `name(params)ret`.
    pub method: String,
    pub direction: Direction,
    /// Levels to expand (1 = direct callers / callees).
    pub depth: usize,
    /// Stop discovering methods beyond this many (roots included).
    pub max_nodes: usize,
    /// Follow virtual dispatch through the class hierarchy (see the module docs).
    pub virtual_calls: bool,
}

/// One line of the tree, in depth-first order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallRow {
    /// 0 for a root.
    pub depth: usize,
    /// Index of the parent row (`None` for a root).
    pub parent: Option<usize>,
    /// `Lcls;->name(params)ret`
    pub method: String,
    /// DEX files defining a body for it (empty when none does).
    pub dex: Vec<String>,
    /// Shown again: expanded at another row.
    pub repeated: bool,
    /// Reached through virtual dispatch: the supertype whose method this
    /// caller invokes, or (callees) the class of the callee this overrides.
    pub via: Option<String>,
}

/// Result of [`Engine::call_graph`].
#[derive(Debug, Clone)]
pub struct CallTree {
    pub direction: Direction,
    pub depth: usize,
    pub rows: Vec<CallRow>,
    /// Distinct methods discovered (roots included).
    pub methods: usize,
    /// More callers / callees exist than `max_nodes` allowed.
    pub truncated: bool,
    /// DEX entries that could not be loaded or searched.
    pub errors: Vec<String>,
}

impl CallTree {
    /// One line per row: indentation and the depth number, an arrow
    /// (`<-` caller, `->` callee), the signature and flags:
    /// `[no body]` (defined in no DEX of the APK, e.g. a framework method)
    /// and `(repeated)` (expanded elsewhere in the tree).
    pub fn lines(&self) -> Vec<String> {
        self.rows
            .iter()
            .map(|r| {
                let mut s = "  ".repeat(r.depth);
                if r.depth == 0 {
                    s.push_str(&format!("0 {}", r.method));
                } else {
                    s.push_str(&format!("{} {} {}", r.depth, self.direction.arrow(), r.method));
                }
                if r.dex.is_empty() {
                    s.push_str(" [no body]");
                }
                if let Some(v) = &r.via {
                    match self.direction {
                        Direction::Callers => s.push_str(&format!(" (via {v})")),
                        Direction::Callees => s.push_str(&format!(" (override of {v})")),
                    }
                }
                if r.repeated {
                    s.push_str(" (repeated)");
                }
                s
            })
            .collect()
    }

    /// Footer comment summarising the walk.
    pub fn footer(&self) -> String {
        let mut s =
            format!("# {} rows, {} distinct methods ({}, depth {})", self.rows.len(), self.methods, self.direction.as_str(), self.depth);
        if self.truncated {
            s.push_str("; truncated (raise max_nodes or lower depth)");
        }
        s
    }
}

/// `Lcls;->name(params)ret` split into its parts.
struct Signature<'s> {
    class: &'s str,
    name: &'s str,
    proto: &'s str,
}

fn split_signature(sig: &str) -> Option<Signature<'_>> {
    let (class, rest) = sig.split_once("->")?;
    let p = rest.find('(')?;
    Some(Signature { class, name: &rest[..p], proto: &rest[p..] })
}

/// Method ids of `dex` declared by `class` named `name`, with the proto
/// `proto` when given. `method_id`s are sorted by (class, name, proto).
fn method_ids(dex: &Dex<'_>, class: &str, name: &str, proto: Option<&str>) -> Result<Vec<u32>> {
    let Some(class_idx) = dex.find_type_idx(&asc_dex::mutf8::encode(class))? else { return Ok(Vec::new()) };
    let Some(name_idx) = dex.find_string_idx(&asc_dex::mutf8::encode(name))? else { return Ok(Vec::new()) };
    let target = (class_idx, name_idx);
    let (mut lo, mut hi) = (0u32, dex.method_count());
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let id = dex.method_id(mid)?;
        if ((id.class_idx as u32), id.name_idx) < target {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let mut out = Vec::new();
    for i in lo..dex.method_count() {
        let id = dex.method_id(i)?;
        if ((id.class_idx as u32), id.name_idx) != target {
            break;
        }
        if proto.is_none_or(|p| asc_smali::proto_descriptor(dex, id.proto_idx as u32).is_ok_and(|d| d == p)) {
            out.push(i);
        }
    }
    Ok(out)
}

/// Subclasses checked for overrides of one callee (`virtual_calls`).
const MAX_OVERRIDE_SCAN: usize = 4096;
/// Supertypes whose signature stands for a frontier method (`virtual_calls`).
const MAX_SUPERS: usize = 256;

/// What one DEX says about one frontier method.
#[derive(Default)]
struct Found {
    /// Neighbours (callers or callees), as signatures.
    next: BTreeSet<String>,
    /// DEX files with a body for the method.
    bodies: BTreeSet<String>,
}

impl Engine {
    /// Callers or callees of a method, `depth` levels deep, as a tree.
    ///
    /// The roots are every overload of `method` declared by `class` (or the
    /// exact signature) that some DEX references; an unknown method is an
    /// error. Each method is expanded once, at its shallowest occurrence;
    /// other occurrences are marked `repeated`.
    pub fn call_graph(&self, q: &CallQuery) -> Result<CallTree> {
        self.call_graph_cancellable(q, &NOT_CANCELLED)
    }

    /// [`Engine::call_graph`] that stops, with `ApkError::Cancelled`, once
    /// `cancel` is raised.
    pub fn call_graph_cancellable(&self, q: &CallQuery, cancel: &AtomicBool) -> Result<CallTree> {
        let (name, proto) = match q.method.find('(') {
            Some(p) => {
                let sig = asc_smali::normalize_method_signature(&q.method)?;
                let p2 = sig.find('(').unwrap_or(p);
                (sig[..p2].to_string(), Some(sig[p2..].to_string()))
            }
            None => (q.method.clone(), None),
        };
        let t0 = std::time::Instant::now();
        let _query = self.prebuild.query();
        let (views, mut errors) = self.load_views(None, cancel)?;
        // The tables built before a cancellation stay charged to the cache.
        let stop = |views: &[DexView], e: EngineError| {
            self.recharge_views(views);
            e
        };
        let graph = if q.virtual_calls { Some(self.class_graph(&views, &mut errors, cancel).map_err(|e| stop(&views, e))?) } else { None };
        let load_us = t0.elapsed().as_micros();
        // Roots: every matching signature any DEX knows.
        let mut roots = BTreeSet::new();
        for v in &views {
            let dex = Dex::with_name(&v.data, &v.name)?;
            for m in method_ids(&dex, &q.class, &name, proto.as_deref())? {
                roots.insert(asc_smali::method_signature(&dex, m)?);
            }
        }
        if roots.is_empty() {
            let hint = self.member_not_found_hint(&q.class, Some(&name), true);
            return Err(EngineError::Query(format!("no method {}->{} in this APK{hint}", q.class, q.method)));
        }
        let max_nodes = q.max_nodes.max(roots.len());
        // Breadth-first: `depth_of` is each method's shallowest level, `next`
        // its neighbours, `bodies` where it is defined.
        let mut depth_of: HashMap<String, usize> = roots.iter().map(|r| (r.clone(), 0)).collect();
        let mut next: HashMap<String, Vec<String>> = HashMap::new();
        let mut bodies: HashMap<String, Vec<String>> = HashMap::new();
        // (parent, child) -> the class virtual dispatch went through
        let mut via: HashMap<(String, String), String> = HashMap::new();
        let mut frontier: Vec<String> = roots.iter().cloned().collect();
        let mut truncated = false;
        for level in 0..=q.depth {
            if frontier.is_empty() {
                break;
            }
            // The last level is only looked up (for `bodies`), not expanded.
            let expand = level < q.depth;
            // Callers through a supertype: look its signatures up too.
            let aliases = match (&graph, q.direction) {
                (Some(g), Direction::Callers) if expand => super_aliases(g, &frontier),
                _ => HashMap::new(),
            };
            let mut lookup = frontier.clone();
            lookup.extend(aliases.values().flatten().map(|(alias, _)| alias.clone()));
            lookup.sort();
            lookup.dedup();
            let found = self.expand(&views, &lookup, q.direction, expand, &mut errors, cancel);
            if cancel.load(Ordering::Relaxed) {
                return Err(stop(&views, cancelled()));
            }
            let mut following = Vec::new();
            for sig in &frontier {
                let f = found.get(sig);
                bodies.insert(sig.clone(), f.map(|f| f.bodies.iter().cloned().collect()).unwrap_or_default());
                if !expand {
                    continue;
                }
                let mut neighbours: Vec<(String, Option<String>)> =
                    f.map(|f| f.next.iter()).into_iter().flatten().map(|n| (n.clone(), None)).collect();
                for (alias, class) in aliases.get(sig).into_iter().flatten() {
                    for n in found.get(alias).map(|f| f.next.iter()).into_iter().flatten() {
                        neighbours.push((n.clone(), Some(class.clone())));
                    }
                }
                if let (Some(g), Direction::Callees) = (&graph, q.direction) {
                    let direct: Vec<String> = neighbours.iter().map(|(n, _)| n.clone()).collect();
                    for n in direct {
                        if cancel.load(Ordering::Relaxed) {
                            return Err(stop(&views, cancelled()));
                        }
                        let (overrides, cut) = overrides_of(g, &views, &n, &mut errors);
                        truncated |= cut;
                        neighbours.extend(overrides.into_iter().map(|o| (o, split_signature(&n).map(|p| p.class.to_string()))));
                    }
                }
                // A direct edge wins over the same edge through dispatch.
                let mut seen = HashSet::new();
                neighbours.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.is_some().cmp(&b.1.is_some())));
                neighbours.retain(|(n, _)| seen.insert(n.clone()));
                let mut kept = Vec::new();
                for (n, through) in &neighbours {
                    if let Some(c) = through {
                        via.insert((sig.clone(), n.clone()), c.clone());
                    }
                    if depth_of.contains_key(n) {
                        kept.push(n.clone());
                    } else if depth_of.len() < max_nodes {
                        depth_of.insert(n.clone(), level + 1);
                        following.push(n.clone());
                        kept.push(n.clone());
                    } else {
                        truncated = true;
                    }
                }
                next.insert(sig.clone(), kept);
            }
            frontier = following;
        }
        self.recharge_views(&views);
        if self.debug {
            let graphs: Vec<_> = views.iter().filter_map(|v| v.state.call_graph()).collect();
            self.log(format!(
                "[APK] callgraph load={load_us} us total={} us dex={} graphs={} edges={} graph_bytes={}",
                t0.elapsed().as_micros(),
                views.len(),
                graphs.len(),
                graphs.iter().map(|g| g.edge_count()).sum::<usize>(),
                graphs.iter().map(|g| g.heap_bytes()).sum::<usize>()
            ));
        }

        // Depth-first rendering, expanding each method once at its BFS depth.
        let mut rows: Vec<CallRow> = Vec::new();
        let mut expanded = HashSet::new();
        let mut stack: Vec<(String, usize, Option<usize>)> = roots.iter().rev().map(|r| (r.clone(), 0, None)).collect();
        while let Some((sig, depth, parent)) = stack.pop() {
            let expand_here = depth_of.get(&sig) == Some(&depth) && !expanded.contains(&sig);
            let has_children = next.get(&sig).is_some_and(|n| !n.is_empty());
            rows.push(CallRow {
                depth,
                parent,
                method: sig.clone(),
                dex: bodies.get(&sig).cloned().unwrap_or_default(),
                repeated: !expand_here && has_children,
                via: parent.and_then(|p| via.get(&(rows[p].method.clone(), sig.clone())).cloned()),
            });
            if expand_here {
                expanded.insert(sig.clone());
                let me = rows.len() - 1;
                for n in next.get(&sig).into_iter().flatten().rev() {
                    stack.push((n.clone(), depth + 1, Some(me)));
                }
            }
        }
        errors.sort();
        errors.dedup();
        Ok(CallTree { direction: q.direction, depth: q.depth, rows, methods: depth_of.len(), truncated, errors })
    }

    /// Look every frontier method up in every DEX (in parallel) and collect
    /// where it has a body and, when `expand`, its neighbours.
    fn expand(
        &self,
        views: &[DexView],
        frontier: &[String],
        dir: crate::Direction,
        expand: bool,
        errors: &mut Vec<String>,
        cancel: &AtomicBool,
    ) -> HashMap<String, Found> {
        let next_view = AtomicUsize::new(0);
        let merged: Mutex<HashMap<String, Found>> = Mutex::new(HashMap::new());
        let errs = Mutex::new(Vec::new());
        let workers = self.threads().min(views.len()).max(1);
        std::thread::scope(|s| {
            for _ in 0..workers {
                s.spawn(|| loop {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let i = next_view.fetch_add(1, Ordering::Relaxed);
                    let Some(v) = views.get(i) else { break };
                    match view_neighbours(v, frontier, dir, expand) {
                        Ok(local) => {
                            let mut m = merged.lock().unwrap();
                            for (sig, f) in local {
                                let e = m.entry(sig).or_default();
                                e.next.extend(f.next);
                                e.bodies.extend(f.bodies);
                            }
                        }
                        Err(e) => errs.lock().unwrap().push(format!("{}: {e}", v.name)),
                    }
                });
            }
        });
        errors.extend(errs.into_inner().unwrap());
        merged.into_inner().unwrap()
    }
}

/// For each frontier method (not a constructor / initializer), the same
/// signature on each supertype of its class: `sig -> [(alias, supertype)]`.
fn super_aliases(g: &ClassGraph, frontier: &[String]) -> HashMap<String, Vec<(String, String)>> {
    let mut out = HashMap::new();
    for sig in frontier {
        let Some(p) = split_signature(sig) else { continue };
        if p.name.starts_with('<') {
            continue;
        }
        let aliases: Vec<(String, String)> =
            g.reachable(p.class, Lineage::Supers, MAX_SUPERS).into_iter().map(|s| (format!("{s}->{}{}", p.name, p.proto), s)).collect();
        if !aliases.is_empty() {
            out.insert(sig.clone(), aliases);
        }
    }
    out
}

/// Methods overriding `sig` in subclasses of its class (a constructor /
/// initializer has none), and whether the subclass scan was cut short.
fn overrides_of(g: &ClassGraph, views: &[DexView], sig: &str, errors: &mut Vec<String>) -> (Vec<String>, bool) {
    let Some(p) = split_signature(sig) else { return (Vec::new(), false) };
    if p.name.starts_with('<') {
        return (Vec::new(), false);
    }
    let subs = g.reachable(p.class, Lineage::Subclasses, MAX_OVERRIDE_SCAN);
    let cut = subs.len() >= MAX_OVERRIDE_SCAN;
    let mut out = Vec::new();
    for s in subs {
        match g.defines(views, &s, p.name, Some(p.proto)) {
            Ok(d) if !d.is_empty() => out.push(format!("{s}->{}{}", p.name, p.proto)),
            Ok(_) => {}
            Err(e) => errors.push(format!("{s}: {e}")),
        }
    }
    (out, cut)
}

fn view_neighbours(v: &DexView, frontier: &[String], dir: Direction, expand: bool) -> Result<HashMap<String, Found>> {
    let dex = Dex::with_name(&v.data, &v.name)?;
    let fr = FindRefs::with_state(&dex, &v.state);
    let mut out: HashMap<String, Found> = HashMap::new();
    // Building the graph walks every body; skip it for a DEX that defines and
    // references none of the frontier.
    let mut graph = None;
    for sig in frontier {
        let Some(parts) = split_signature(sig) else { continue };
        for m in method_ids(&dex, parts.class, parts.name, Some(parts.proto))? {
            let g = match graph {
                Some(g) => g,
                None => *graph.insert(fr.call_graph()?),
            };
            let f = out.entry(sig.clone()).or_default();
            if g.has_body(m) {
                f.bodies.insert(v.name.clone());
            }
            if !expand {
                continue;
            }
            let ids = match dir {
                Direction::Callers => g.callers(m),
                Direction::Callees => g.callees(m),
            };
            for &n in ids {
                f.next.insert(asc_smali::method_signature(&dex, n as u32)?);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_split_at_the_arrow_and_paren() {
        let s = split_signature("Lcom/a;->run(ILjava/lang/String;)V").unwrap();
        assert_eq!((s.class, s.name, s.proto), ("Lcom/a;", "run", "(ILjava/lang/String;)V"));
        assert!(split_signature("Lcom/a;->run").is_none());
        assert!(split_signature("run()V").is_none());
    }
}
