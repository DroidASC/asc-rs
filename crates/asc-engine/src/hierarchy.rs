//! Class hierarchy across every DEX of an APK: transitive subclasses /
//! implementers, supertypes, and which of them define (override) a method.
//!
//! The graph is built from the `class_def_item`s of every DEX (superclass and
//! interface list per class, interned descriptors, edges sorted both ways)
//! and kept on the engine for later queries until the APK changes or
//! [`Engine::release_memory_cache`] drops it. A type the APK only references
//! (a framework class) is a node without a definition: its own supertypes are
//! unknown.

use crate::resources::{file_ident, FileIdent};
use crate::{cancelled, DexView, Engine, EngineError, Result, NOT_CANCELLED};
use asc_dex::Dex;
use asc_findrefs::ClassRelation;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

/// No `superclass_idx` (`java.lang.Object` itself).
const NO_INDEX: u32 = u32::MAX;

/// Which way to walk the hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lineage {
    /// Classes extending / implementing the target, transitively.
    Subclasses,
    /// The target's superclasses and interfaces, transitively.
    Supers,
}

impl Lineage {
    pub fn as_str(self) -> &'static str {
        match self {
            Lineage::Subclasses => "subclasses",
            Lineage::Supers => "supers",
        }
    }

    /// The word before a class reached through `rel`.
    fn word(self, rel: ClassRelation) -> &'static str {
        match (self, rel) {
            (Lineage::Subclasses, ClassRelation::Extends) => "subclass",
            (Lineage::Subclasses, ClassRelation::Implements) => "implementer",
            (Lineage::Supers, rel) => rel.verb(),
        }
    }
}

/// A hierarchy query.
#[derive(Debug, Clone)]
pub struct HierarchyQuery {
    /// Dalvik descriptor (`Lcom/poc/Base;`).
    pub class: String,
    pub direction: Lineage,
    /// Levels to walk (1 = direct subclasses / supertypes).
    pub depth: usize,
    /// Stop discovering classes beyond this many (the root included).
    pub max_nodes: usize,
    /// Mark the classes that define this method: a name (every overload) or
    /// exact `name(params)ret`.
    pub method: Option<String>,
}

/// One line of the tree, in depth-first order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HierarchyRow {
    /// 0 for the root.
    pub depth: usize,
    /// Index of the parent row (`None` for the root).
    pub parent: Option<usize>,
    pub class: String,
    /// How the row relates to its parent row (`extends` / `implements`, from
    /// the subclass's side).
    pub relation: Option<ClassRelation>,
    /// The DEX defining the class; `None` when the APK only references it.
    pub dex: Option<String>,
    /// Shown again: expanded at another row.
    pub repeated: bool,
    /// Signatures (`name(params)ret`) of the queried method this class defines.
    pub defines: Vec<String>,
}

/// Result of [`Engine::hierarchy`].
#[derive(Debug, Clone)]
pub struct HierarchyTree {
    pub direction: Lineage,
    pub depth: usize,
    pub rows: Vec<HierarchyRow>,
    /// Distinct classes discovered (the root included).
    pub classes: usize,
    /// More classes exist than `max_nodes` allowed.
    pub truncated: bool,
    /// The queried method, as given.
    pub method: Option<String>,
    /// DEX entries that could not be loaded or read.
    pub errors: Vec<String>,
}

impl HierarchyTree {
    /// One line per row: indentation and depth, how it relates to its parent
    /// (`subclass` / `implementer` going down, `extends` / `implements` going
    /// up), the class, its DEX or `[not in APK]`, `[defines m(..)V]` and
    /// `(repeated)` flags.
    pub fn lines(&self) -> Vec<String> {
        self.rows
            .iter()
            .map(|r| {
                let mut s = "  ".repeat(r.depth);
                match r.relation {
                    Some(rel) if r.depth > 0 => s.push_str(&format!("{} {} {}", r.depth, self.direction.word(rel), r.class)),
                    _ => s.push_str(&format!("0 {}", r.class)),
                }
                match &r.dex {
                    Some(d) => s.push_str(&format!(" {d}")),
                    None => s.push_str(" [not in APK]"),
                }
                for d in &r.defines {
                    s.push_str(&format!(" [defines {d}]"));
                }
                if r.repeated {
                    s.push_str(" (repeated)");
                }
                s
            })
            .collect()
    }

    /// `Lcls;->m(..)V dex` of every definition of the queried method below
    /// (or above) the root, one per line, prefixed `override` / `inherited`.
    pub fn definition_lines(&self) -> Vec<String> {
        let word = match self.direction {
            Lineage::Subclasses => "override",
            Lineage::Supers => "inherited",
        };
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for r in self.rows.iter().filter(|r| r.depth > 0 && seen.insert(&r.class)) {
            for d in &r.defines {
                out.push(format!("{word} {}->{d} {}", r.class, r.dex.as_deref().unwrap_or("-")));
            }
        }
        out
    }

    pub fn footer(&self) -> String {
        let mut s =
            format!("# {} rows, {} distinct classes ({}, depth {})", self.rows.len(), self.classes, self.direction.as_str(), self.depth);
        if let Some(m) = &self.method {
            let n = self.definition_lines().len();
            s.push_str(&format!("; {n} define {m}"));
        }
        if self.truncated {
            s.push_str("; truncated (raise max_nodes or lower depth)");
        }
        s
    }
}

/// `(child, parent, relation)` between class ids.
type Edge = (u32, u32, ClassRelation);

/// Every class the APK defines or references through a class definition,
/// with the edges between them.
pub(crate) struct ClassGraph {
    names: Vec<Arc<str>>,
    ids: HashMap<Arc<str>, u32>,
    /// Per class: `(view + 1, class_def index)` of its first definition, `(0, 0)` if none.
    defined: Vec<(u32, u32)>,
    /// `(child, parent, relation)` sorted by child.
    up: Vec<Edge>,
    /// The same edges sorted by parent.
    down: Vec<Edge>,
    /// DEX names, by view index.
    dex_names: Vec<String>,
}

/// One class definition of a DEX, by descriptor.
struct DefinedClass {
    class: String,
    superclass: Option<String>,
    interfaces: Vec<String>,
    /// Its index in the DEX's `class_defs`.
    def_idx: u32,
}

fn dex_classes(v: &DexView) -> Result<Vec<DefinedClass>> {
    let dex = Dex::with_name(&v.data, &v.name)?;
    let mut out = Vec::with_capacity(dex.class_def_count() as usize);
    for i in 0..dex.class_def_count() {
        let def = dex.class_def(i)?;
        let sup = (def.superclass_idx != NO_INDEX).then(|| dex.type_descriptor(def.superclass_idx)).transpose()?;
        let ifaces = if def.interfaces_off == 0 {
            Vec::new()
        } else {
            dex.type_list(def.interfaces_off)?.into_iter().map(|t| dex.type_descriptor(t as u32)).collect::<std::result::Result<_, _>>()?
        };
        out.push(DefinedClass { class: dex.type_descriptor(def.class_idx)?, superclass: sup, interfaces: ifaces, def_idx: i });
    }
    Ok(out)
}

impl ClassGraph {
    /// Heap held by the graph, roughly.
    pub(crate) fn heap_bytes(&self) -> usize {
        use std::mem::size_of;
        // Each name is an `Arc<str>` (two counters ahead of the bytes), held
        // by `names` and as a key of `ids` (one more word of id and padding,
        // plus a control byte, per hash slot).
        let names: usize = self.names.iter().map(|n| n.len() + 2 * size_of::<usize>()).sum();
        names
            + self.names.capacity() * size_of::<Arc<str>>()
            + self.ids.capacity() * (size_of::<(Arc<str>, u32)>() + 1)
            + self.defined.capacity() * size_of::<(u32, u32)>()
            + (self.up.capacity() + self.down.capacity()) * size_of::<Edge>()
            + self.dex_names.iter().map(|n| n.capacity() + size_of::<String>()).sum::<usize>()
    }

    /// `None` once `cancel` is raised.
    fn build(views: &[DexView], threads: usize, errors: &mut Vec<String>, cancel: &AtomicBool) -> Option<ClassGraph> {
        let next = AtomicUsize::new(0);
        let parsed: Mutex<Vec<(usize, Vec<DefinedClass>)>> = Mutex::new(Vec::new());
        let errs = Mutex::new(Vec::new());
        std::thread::scope(|s| {
            for _ in 0..threads.min(views.len()).max(1) {
                s.spawn(|| loop {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(v) = views.get(i) else { break };
                    match dex_classes(v) {
                        Ok(c) => parsed.lock().unwrap().push((i, c)),
                        Err(e) => errs.lock().unwrap().push(format!("{}: {e}", v.name)),
                    }
                });
            }
        });
        if cancel.load(Ordering::Relaxed) {
            return None;
        }
        errors.extend(errs.into_inner().unwrap());
        let mut parsed = parsed.into_inner().unwrap();
        // Views in entry order, so "first definition" means the first DEX.
        parsed.sort_by_key(|(i, _)| *i);
        let mut g = ClassGraph {
            names: Vec::new(),
            ids: HashMap::new(),
            defined: Vec::new(),
            up: Vec::new(),
            down: Vec::new(),
            dex_names: views.iter().map(|v| v.name.clone()).collect(),
        };
        let mut seen_edges = HashSet::new();
        for (view, classes) in parsed {
            for DefinedClass { class, superclass, interfaces, def_idx } in classes {
                let c = g.intern(&class);
                if g.defined[c as usize].0 != 0 {
                    continue; // a duplicate definition: the first one wins
                }
                g.defined[c as usize] = (view as u32 + 1, def_idx);
                let parents =
                    superclass.iter().map(|s| (s, ClassRelation::Extends)).chain(interfaces.iter().map(|i| (i, ClassRelation::Implements)));
                for (p, rel) in parents {
                    let p = g.intern(p);
                    if seen_edges.insert((c, p, rel)) {
                        g.up.push((c, p, rel));
                    }
                }
            }
        }
        g.up.sort_unstable_by_key(|&(c, p, _)| (c, p));
        g.down = g.up.clone();
        g.down.sort_unstable_by_key(|&(c, p, _)| (p, c));
        Some(g)
    }

    fn intern(&mut self, name: &str) -> u32 {
        if let Some(&id) = self.ids.get(name) {
            return id;
        }
        let id = self.names.len() as u32;
        let name: Arc<str> = Arc::from(name);
        self.names.push(name.clone());
        self.ids.insert(name, id);
        self.defined.push((0, 0));
        id
    }

    fn id(&self, name: &str) -> Option<u32> {
        self.ids.get(name).copied()
    }

    fn name(&self, id: u32) -> &str {
        &self.names[id as usize]
    }

    /// Neighbours of `id` one level up or down.
    fn neighbours(&self, id: u32, dir: Lineage) -> impl Iterator<Item = (u32, ClassRelation)> + '_ {
        let (edges, key): (&[Edge], fn(&Edge) -> u32) = match dir {
            Lineage::Supers => (&self.up, |e| e.0),
            Lineage::Subclasses => (&self.down, |e| e.1),
        };
        let start = edges.partition_point(|e| key(e) < id);
        edges[start..].iter().take_while(move |e| key(e) == id).map(move |&(c, p, rel)| match dir {
            Lineage::Supers => (p, rel),
            Lineage::Subclasses => (c, rel),
        })
    }

    /// Every class reachable from `class` going `dir` (not `class` itself),
    /// nearest first; at most `limit`.
    pub(crate) fn reachable(&self, class: &str, dir: Lineage, limit: usize) -> Vec<String> {
        let Some(root) = self.id(class) else { return Vec::new() };
        let mut seen = HashSet::from([root]);
        let mut queue = VecDeque::from([root]);
        let mut out = Vec::new();
        while let Some(c) = queue.pop_front() {
            for (n, _) in self.neighbours(c, dir) {
                if out.len() >= limit {
                    return out;
                }
                if seen.insert(n) {
                    out.push(self.name(n).to_string());
                    queue.push_back(n);
                }
            }
        }
        out
    }

    fn dex_of(&self, id: u32) -> Option<&str> {
        let (view, _) = self.defined[id as usize];
        (view != 0).then(|| self.dex_names[view as usize - 1].as_str())
    }

    /// `name(params)ret` of the methods `class` defines whose name is `name`
    /// (and proto `proto` when given).
    pub(crate) fn defines(&self, views: &[DexView], class: &str, name: &str, proto: Option<&str>) -> Result<Vec<String>> {
        let Some(id) = self.id(class) else { return Ok(Vec::new()) };
        let (view, def_idx) = self.defined[id as usize];
        if view == 0 {
            return Ok(Vec::new());
        }
        let v = &views[view as usize - 1];
        let dex = Dex::with_name(&v.data, &v.name)?;
        let def = dex.class_def(def_idx)?;
        let data = dex.class_data(def.class_data_off)?;
        let mut out = Vec::new();
        for m in data.direct_methods.iter().chain(&data.virtual_methods) {
            let mid = dex.method_id(m.method_idx)?;
            if dex.string_bytes(mid.name_idx)? != name.as_bytes() {
                continue;
            }
            let p = asc_smali::proto_descriptor(&dex, mid.proto_idx as u32)?;
            if proto.is_none_or(|want| want == p) {
                out.push(format!("{name}{p}"));
            }
        }
        Ok(out)
    }
}

/// The cached graph and the APK file it was built from.
pub(crate) type CachedGraph = (Option<FileIdent>, Arc<ClassGraph>);

/// `name` or `name(params)ret` split into name and normalised proto.
pub(crate) fn split_method(method: &str) -> Result<(String, Option<String>)> {
    match method.find('(') {
        Some(_) => {
            let sig = asc_smali::normalize_method_signature(method)?;
            let p = sig.find('(').expect("normalised signature has a paren");
            Ok((sig[..p].to_string(), Some(sig[p..].to_string())))
        }
        None => Ok((method.to_string(), None)),
    }
}

impl Engine {
    /// The class graph of the APK, built over `views` unless one built from
    /// the same APK file is kept. A cancelled build is not kept.
    pub(crate) fn class_graph(&self, views: &[DexView], errors: &mut Vec<String>, cancel: &AtomicBool) -> Result<Arc<ClassGraph>> {
        let ident = file_ident(&self.open()?);
        let mut slot = self.class_graph.lock().unwrap();
        if let Some((id, g)) = slot.as_ref() {
            if ident.is_some() && *id == ident {
                return Ok(g.clone());
            }
        }
        let g = Arc::new(ClassGraph::build(views, self.threads(), errors, cancel).ok_or_else(cancelled)?);
        *slot = Some((ident, g.clone()));
        Ok(g)
    }

    /// Transitive subclasses / implementers (or supertypes) of a class, as a
    /// tree, with the classes defining `method` marked.
    pub fn hierarchy(&self, q: &HierarchyQuery) -> Result<HierarchyTree> {
        self.hierarchy_cancellable(q, &NOT_CANCELLED)
    }

    /// [`Engine::hierarchy`] that stops, with `ApkError::Cancelled`, once
    /// `cancel` is raised.
    pub fn hierarchy_cancellable(&self, q: &HierarchyQuery, cancel: &AtomicBool) -> Result<HierarchyTree> {
        let method = q.method.as_deref().map(split_method).transpose()?;
        let (views, mut errors) = self.load_views(None, cancel)?;
        let g = self.class_graph(&views, &mut errors, cancel)?;
        let Some(root) = g.id(&q.class) else {
            return Err(EngineError::Query(format!("no class {} in this APK", q.class)));
        };
        // Breadth-first: each class's shallowest depth and its children.
        let max_nodes = q.max_nodes.max(1);
        let mut depth_of: HashMap<u32, usize> = HashMap::from([(root, 0)]);
        let mut children: HashMap<u32, Vec<(u32, ClassRelation)>> = HashMap::new();
        let mut frontier = vec![root];
        let mut truncated = false;
        for level in 0..q.depth {
            let mut following = Vec::new();
            for &c in &frontier {
                let mut kept = Vec::new();
                for (n, rel) in g.neighbours(c, q.direction) {
                    if depth_of.contains_key(&n) {
                        kept.push((n, rel));
                    } else if depth_of.len() < max_nodes {
                        depth_of.insert(n, level + 1);
                        following.push(n);
                        kept.push((n, rel));
                    } else {
                        truncated = true;
                    }
                }
                children.insert(c, kept);
            }
            if following.is_empty() {
                break;
            }
            frontier = following;
        }
        // Classes at the last level may still have neighbours.
        truncated |= frontier.iter().any(|&c| !children.contains_key(&c) && g.neighbours(c, q.direction).next().is_some());

        let mut defines: HashMap<u32, Vec<String>> = HashMap::new();
        if let Some((name, proto)) = &method {
            for &c in depth_of.keys() {
                if cancel.load(Ordering::Relaxed) {
                    return Err(cancelled());
                }
                match g.defines(&views, g.name(c), name, proto.as_deref()) {
                    Ok(d) if !d.is_empty() => {
                        defines.insert(c, d);
                    }
                    Ok(_) => {}
                    Err(e) => errors.push(format!("{}: {e}", g.name(c))),
                }
            }
        }

        // Depth-first rendering, expanding each class once at its BFS depth.
        let mut rows = Vec::new();
        let mut expanded = HashSet::new();
        let mut stack: Vec<(u32, usize, Option<usize>, Option<ClassRelation>)> = vec![(root, 0, None, None)];
        while let Some((c, depth, parent, relation)) = stack.pop() {
            let expand_here = depth_of.get(&c) == Some(&depth) && !expanded.contains(&c);
            let has_children = children.get(&c).is_some_and(|n| !n.is_empty());
            rows.push(HierarchyRow {
                depth,
                parent,
                class: g.name(c).to_string(),
                relation,
                dex: g.dex_of(c).map(String::from),
                repeated: !expand_here && has_children,
                defines: defines.get(&c).cloned().unwrap_or_default(),
            });
            if expand_here {
                expanded.insert(c);
                let me = rows.len() - 1;
                let mut kids: Vec<_> = children.get(&c).cloned().unwrap_or_default();
                kids.sort_by(|a, b| g.name(b.0).cmp(g.name(a.0)));
                for (n, rel) in kids {
                    stack.push((n, depth + 1, Some(me), Some(rel)));
                }
            }
        }
        errors.sort();
        errors.dedup();
        Ok(HierarchyTree {
            direction: q.direction,
            depth: q.depth,
            rows,
            classes: depth_of.len(),
            truncated,
            method: q.method.clone(),
            errors,
        })
    }
}
