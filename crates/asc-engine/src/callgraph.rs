//! Callers / callees of a method across every DEX of an APK.
//!
//! Each DEX has its own static call graph ([`asc_findrefs::CallGraph`], built
//! on first use and kept with the cached entry's locator tables). Method ids
//! are local to a DEX, so the walk keys methods by signature
//! (`Lcls;->name(params)ret`) and, level by level, looks each frontier method
//! up in every DEX (binary search over the sorted `method_id` table), then
//! follows that DEX's edges. Calls are static references: a call through
//! `Lsub;->m()V` does not count as a call of `Lbase;->m()V`.

use crate::{DexView, Engine, EngineError, Result};
use asc_dex::Dex;
use asc_findrefs::FindRefs;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
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
        let (name, proto) = match q.method.find('(') {
            Some(p) => {
                let sig = asc_smali::normalize_method_signature(&q.method)?;
                let p2 = sig.find('(').unwrap_or(p);
                (sig[..p2].to_string(), Some(sig[p2..].to_string()))
            }
            None => (q.method.clone(), None),
        };
        let t0 = std::time::Instant::now();
        let (views, mut errors) = self.load_views(None)?;
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
            return Err(EngineError::Query(format!("no method {}->{} in this APK", q.class, q.method)));
        }
        let max_nodes = q.max_nodes.max(roots.len());
        // Breadth-first: `depth_of` is each method's shallowest level, `next`
        // its neighbours, `bodies` where it is defined.
        let mut depth_of: HashMap<String, usize> = roots.iter().map(|r| (r.clone(), 0)).collect();
        let mut next: HashMap<String, Vec<String>> = HashMap::new();
        let mut bodies: HashMap<String, Vec<String>> = HashMap::new();
        let mut frontier: Vec<String> = roots.iter().cloned().collect();
        let mut truncated = false;
        for level in 0..=q.depth {
            if frontier.is_empty() {
                break;
            }
            // The last level is only looked up (for `bodies`), not expanded.
            let expand = level < q.depth;
            let found = self.expand(&views, &frontier, q.direction, expand, &mut errors);
            let mut following = Vec::new();
            for sig in &frontier {
                let f = found.get(sig);
                bodies.insert(sig.clone(), f.map(|f| f.bodies.iter().cloned().collect()).unwrap_or_default());
                if !expand {
                    continue;
                }
                let mut kept = Vec::new();
                for n in f.map(|f| f.next.iter()).into_iter().flatten() {
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
        let mut rows = Vec::new();
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
    ) -> HashMap<String, Found> {
        let next_view = AtomicUsize::new(0);
        let merged: Mutex<HashMap<String, Found>> = Mutex::new(HashMap::new());
        let errs = Mutex::new(Vec::new());
        let workers = self.threads.min(views.len()).max(1);
        std::thread::scope(|s| {
            for _ in 0..workers {
                s.spawn(|| loop {
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
