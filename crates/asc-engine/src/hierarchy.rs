//! Class hierarchy across every DEX of an APK: transitive subclasses /
//! implementers, supertypes, and which of them define (override) a method.
//!
//! The graph is built from the `class_def_item`s of every DEX (superclass and
//! interface list per class, interned descriptors, edges sorted both ways,
//! the class annotations of each class) and kept on the engine for later
//! queries until the APK changes or [`Engine::release_memory_cache`] drops
//! it. With a disk cache it is also persisted to L2 ([`GRAPH_KIND`]), so a
//! later process maps it back instead of reading every class definition. A type the APK only references
//! (a framework class) is a node without a definition: its own supertypes are
//! unknown.

use crate::resources::{file_ident, FileIdent};
use crate::{cancelled, DexView, Engine, EngineError, Job, Result, WriteJob, NOT_CANCELLED};
use asc_cache::Tier;
use asc_dex::Dex;
use asc_findrefs::ClassRelation;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

mod packed;

use packed::{Builder, Packed};

/// No `superclass_idx` (`java.lang.Object` itself).
const NO_INDEX: u32 = u32::MAX;

/// L2 kind of the persisted class graph, stored under [`GRAPH_NAME`].
pub(crate) const GRAPH_KIND: &str = "classgraph";
/// The graph spans the whole APK (or program): one per APK key.
pub(crate) const GRAPH_NAME: &str = "apk";
/// Layout version of [`ClassGraph::bytes`]; bump on any change.
pub(crate) const GRAPH_FORMAT: u32 = 1;

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

/// Every class the APK defines or references through a class definition,
/// with the edges between them and the class annotations of each.
pub(crate) struct ClassGraph(Packed);

/// One class definition of a DEX, by descriptor.
struct DefinedClass {
    class: String,
    superclass: Option<String>,
    interfaces: Vec<String>,
    /// Its index in the DEX's `class_defs`.
    def_idx: u32,
    /// Descriptors of its class annotations (any visibility).
    annotations: Vec<String>,
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
        let annotations = class_annotations(&dex, def.annotations_off)?;
        out.push(DefinedClass { class: dex.type_descriptor(def.class_idx)?, superclass: sup, interfaces: ifaces, def_idx: i, annotations });
    }
    Ok(out)
}

/// Descriptors of the class annotations of the `annotations_directory_item`
/// at `off` (0: none). Only the directory's first word is read: the member
/// annotations it lists are left alone.
fn class_annotations(dex: &Dex<'_>, off: u32) -> Result<Vec<String>> {
    if off == 0 {
        return Ok(Vec::new());
    }
    let buf = dex.buf();
    let set_off = buf
        .get(off as usize..off as usize + 4)
        .map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")))
        .ok_or(asc_dex::DexError::BadRange { what: "annotations_directory_item", offset: off as usize })?;
    if set_off == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for item_off in asc_dex::annotations::parse_annotation_set(buf, set_off as usize)? {
        let (item, _) = asc_dex::encoded::parse_annotation_item(buf, item_off as usize)?;
        out.push(dex.type_descriptor(item.annotation.type_idx)?);
    }
    Ok(out)
}

impl ClassGraph {
    /// Heap held by the graph, roughly: none once mapped from L2.
    pub(crate) fn heap_bytes(&self) -> usize {
        self.0.heap_bytes()
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
        let mut b = Builder::default();
        for (view, classes) in parsed {
            for DefinedClass { class, superclass, interfaces, def_idx, annotations } in classes {
                let c = b.intern(&class);
                if !b.define(c, view as u32, def_idx) {
                    continue; // a duplicate definition: the first one wins
                }
                for a in annotations {
                    b.annotate(c, a);
                }
                let parents =
                    superclass.iter().map(|s| (s, ClassRelation::Extends)).chain(interfaces.iter().map(|i| (i, ClassRelation::Implements)));
                for (p, rel) in parents {
                    let p = b.intern(p);
                    b.edge(c, p, rel);
                }
            }
        }
        Some(ClassGraph(b.finish(views.iter().map(|v| v.name.as_str()))))
    }

    /// The graph as persisted in L2 (read back by [`ClassGraph::from_mapped`]).
    pub(crate) fn bytes(&self) -> &[u8] {
        self.0.bytes()
    }

    /// A graph [`ClassGraph::bytes`] stored, used in place; `None` for bytes
    /// that are not one.
    fn from_mapped(d: asc_cache::Derived) -> Option<ClassGraph> {
        Packed::from_mapped(d).map(ClassGraph)
    }

    fn id(&self, name: &str) -> Option<u32> {
        self.0.id(name)
    }

    fn name(&self, id: u32) -> &str {
        self.0.name(id)
    }

    /// Neighbours of `id` one level up or down.
    fn neighbours(&self, id: u32, dir: Lineage) -> impl Iterator<Item = (u32, ClassRelation)> + '_ {
        self.0.edges_of(id, dir == Lineage::Subclasses).map(move |(c, p, rel)| match dir {
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
        let (view, _) = self.0.defined(id);
        (view != 0).then(|| self.0.dex_name(view as usize - 1))
    }

    /// Descriptors of the classes this APK defines whose descriptor matches
    /// `re` (for `in:{type:...}`).
    pub(crate) fn defined_classes_matching(&self, re: &regex::bytes::Regex) -> Vec<String> {
        (0..self.0.classes() as u32)
            .filter(|&id| self.0.defined(id).0 != 0)
            .map(|id| self.name(id))
            .filter(|name| re.is_match(name.as_bytes()))
            .map(String::from)
            .collect()
    }

    /// Descriptors of the classes carrying the class annotation `annotation`
    /// (for `in:{annotation:...}`), sorted.
    pub(crate) fn classes_annotated(&self, annotation: &str) -> Vec<String> {
        let mut out: Vec<String> = self.0.annotated(annotation).map(|id| self.name(id).to_string()).collect();
        out.sort_unstable();
        out
    }

    /// `name(params)ret` of the methods `class` defines whose name is `name`
    /// (and proto `proto` when given).
    pub(crate) fn defines(&self, views: &[DexView], class: &str, name: &str, proto: Option<&str>) -> Result<Vec<String>> {
        let Some(id) = self.id(class) else { return Ok(Vec::new()) };
        let (view, def_idx) = self.0.defined(id);
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

    /// Where the program first defines `class`: `(view index, class_def
    /// index)`; `None` when it does not.
    pub(crate) fn definition(&self, class: &str) -> Option<(usize, u32)> {
        let (view, def_idx) = self.0.defined(self.id(class)?);
        (view != 0).then(|| (view as usize - 1, def_idx))
    }

    /// The classes of `class`'s subtree (itself included) `defines` says
    /// define the method: those a call naming it on `class` may run. The
    /// walk stops after `max_classes` classes.
    pub(crate) fn defining(&self, class: &str, max_classes: usize, mut defines: impl FnMut(&str) -> Result<bool>) -> Result<Defining> {
        let Some(root) = self.id(class) else { return Ok(Defining { count: 0, complete: true }) };
        let mut seen = HashSet::from([root]);
        let mut queue = VecDeque::from([root]);
        let mut count = usize::from(defines(class)?);
        while let Some(c) = queue.pop_front() {
            for (n, _) in self.neighbours(c, Lineage::Subclasses) {
                if seen.len() >= max_classes {
                    return Ok(Defining { count, complete: false });
                }
                if seen.insert(n) {
                    count += usize::from(defines(self.name(n))?);
                    queue.push_back(n);
                }
            }
        }
        Ok(Defining { count, complete: true })
    }

    /// `class` and the subclasses that inherit the method from it: a subtree
    /// stops at a class `defines` says defines it itself. Nearest first, at
    /// most `limit`.
    pub(crate) fn inheritors(&self, class: &str, limit: usize, mut defines: impl FnMut(&str) -> Result<bool>) -> Result<Vec<String>> {
        let Some(root) = self.id(class) else { return Ok(Vec::new()) };
        let mut seen = HashSet::from([root]);
        let mut queue = VecDeque::from([root]);
        let mut out = vec![class.to_string()];
        while let Some(c) = queue.pop_front() {
            for (n, _) in self.neighbours(c, Lineage::Subclasses) {
                if out.len() >= limit {
                    return Ok(out);
                }
                if seen.insert(n) && !defines(self.name(n))? {
                    out.push(self.name(n).to_string());
                    queue.push_back(n);
                }
            }
        }
        Ok(out)
    }
}

/// The classes defining a method in a subtree, as [`ClassGraph::defining`]
/// counted them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Defining {
    pub count: usize,
    /// The whole subtree was walked: `count` is exact, not a lower bound.
    pub complete: bool,
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
    /// the same APK file is kept, in memory or in L2. A cancelled build is
    /// not kept; one that met unreadable DEX files is not persisted (a later
    /// process should report them too).
    pub(crate) fn class_graph(&self, views: &[DexView], errors: &mut Vec<String>, cancel: &AtomicBool) -> Result<Arc<ClassGraph>> {
        let apk = self.open()?;
        let ident = file_ident(&apk);
        let mut slot = self.class_graph.lock().unwrap();
        if let Some((id, g)) = slot.as_ref() {
            if ident.is_some() && *id == ident {
                return Ok(g.clone());
            }
        }
        let disk = self.cache.as_ref().and_then(|c| c.disk.as_deref()).filter(|d| d.uses(Tier::Derived));
        let key = disk.and_then(|_| self.apk_key(&apk));
        if let (Some(disk), Some(key)) = (disk, &key) {
            let stored = disk.get_derived(key, GRAPH_NAME, GRAPH_KIND, GRAPH_FORMAT).and_then(ClassGraph::from_mapped);
            // The key covers the archives; the DEX names pin the view order
            // the definitions index.
            if let Some(g) = stored.filter(|g| g.0.dex_names().eq(views.iter().map(|v| v.name.as_str()))) {
                self.stats.derived_hits.fetch_add(1, Ordering::Relaxed);
                let g = Arc::new(g);
                *slot = Some((ident, g.clone()));
                return Ok(g);
            }
        }
        let t0 = Instant::now();
        let errors_before = errors.len();
        let g = Arc::new(ClassGraph::build(views, self.threads(), errors, cancel).ok_or_else(cancelled)?);
        let cost = t0.elapsed();
        if let (Some(disk), Some(key)) = (disk, key) {
            if errors.len() == errors_before && disk.admits_derived(cost) {
                let job = WriteJob { key, apk: Arc::from(apk.path()), kind: Job::Graph { graph: g.clone(), cost } };
                self.cache.as_ref().expect("a disk implies a cache").put_async(job);
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// `B extends A implements I`, `C extends B` (in the second DEX), `D`
    /// with a non-ASCII name; `B` and `C` carry `@M`; `I` is only referenced.
    fn sample() -> ClassGraph {
        let mut b = Builder::default();
        let [a, bb, c, i, d] = ["LA;", "LB;", "LC;", "LI;", "Lé;"].map(|n| b.intern(n));
        assert!(b.define(a, 0, 0) && b.define(bb, 0, 1) && b.define(c, 1, 0) && b.define(d, 0, 2));
        assert!(!b.define(c, 0, 9), "the first definition wins");
        b.edge(bb, a, ClassRelation::Extends);
        b.edge(bb, i, ClassRelation::Implements);
        b.edge(c, bb, ClassRelation::Extends);
        b.edge(c, bb, ClassRelation::Extends);
        b.annotate(c, "LM;".into());
        b.annotate(bb, "LM;".into());
        b.annotate(bb, "LN;".into());
        ClassGraph(b.finish(["classes.dex", "lib.jar/classes.dex"].into_iter()))
    }

    fn check(g: &ClassGraph) {
        assert_eq!(g.reachable("LA;", Lineage::Subclasses, 10), ["LB;", "LC;"]);
        assert_eq!(g.reachable("LC;", Lineage::Supers, 10), ["LB;", "LA;", "LI;"]);
        assert_eq!(g.reachable("LC;", Lineage::Supers, 2), ["LB;", "LA;"]);
        assert!(g.reachable("LZ;", Lineage::Supers, 10).is_empty());
        assert_eq!(g.classes_annotated("LM;"), ["LB;", "LC;"]);
        assert_eq!(g.classes_annotated("LN;"), ["LB;"]);
        assert!(g.classes_annotated("LL;").is_empty() && g.classes_annotated("LZ;").is_empty());
        assert_eq!(g.dex_of(g.id("LC;").unwrap()), Some("lib.jar/classes.dex"));
        assert_eq!(g.dex_of(g.id("LI;").unwrap()), None);
        assert_eq!(g.name(g.id("Lé;").unwrap()), "Lé;");
        let re = regex::bytes::Regex::new("^L[A-C];$").unwrap();
        assert_eq!(
            g.defined_classes_matching(&re).into_iter().collect::<BTreeSet<_>>(),
            BTreeSet::from(["LA;".into(), "LB;".into(), "LC;".into()])
        );
        assert_eq!(g.0.dex_names().collect::<Vec<_>>(), ["classes.dex", "lib.jar/classes.dex"]);
    }

    /// An L2 directory to hand bytes back as the disk cache would.
    struct Store {
        _dir: tempfile::TempDir,
        disk: asc_cache::DiskCache,
        key: asc_cache::ApkKey,
    }

    impl Store {
        fn new() -> Store {
            let dir = tempfile::tempdir().unwrap();
            let disk = asc_cache::DiskCache::open(dir.path().join("cache")).with_capacity(1 << 30);
            let apk = dir.path().join("a.apk");
            std::fs::write(&apk, asc_fixture::make_apk(&[("classes.dex", &asc_fixture::make_rich_dex())], true)).unwrap();
            let key = asc_cache::ApkKey::for_apk(&asc_apk::Apk::open(&apk).unwrap()).unwrap();
            Store { _dir: dir, disk, key }
        }

        fn mapped(&self, bytes: &[u8]) -> Option<ClassGraph> {
            self.disk.put_derived(&self.key, GRAPH_NAME, GRAPH_KIND, GRAPH_FORMAT, std::time::Duration::ZERO, bytes).unwrap();
            ClassGraph::from_mapped(self.disk.get_derived(&self.key, GRAPH_NAME, GRAPH_KIND, GRAPH_FORMAT).unwrap())
        }
    }

    #[test]
    fn graphs_answer_alike_built_and_mapped() {
        let store = Store::new();
        let g = sample();
        check(&g);
        let back = store.mapped(g.bytes()).unwrap();
        check(&back);
        assert_eq!(back.heap_bytes(), 0);
        assert!(g.heap_bytes() >= g.bytes().len());
        // No classes at all.
        let empty = ClassGraph(Builder::default().finish(std::iter::empty()));
        assert!(store.mapped(empty.bytes()).unwrap().reachable("LA;", Lineage::Supers, 1).is_empty());
        // Enough classes to grow the table, all still found.
        let mut b = Builder::default();
        let names: Vec<String> = (0..5000).map(|i| format!("Lc{i};")).collect();
        let ids: Vec<u32> = names.iter().map(|n| b.intern(n)).collect();
        assert_eq!(names.iter().map(|n| b.intern(n)).collect::<Vec<_>>(), ids);
        let g = store.mapped(ClassGraph(b.finish(std::iter::empty())).bytes()).unwrap();
        assert!(names.iter().zip(&ids).all(|(n, &id)| g.id(n) == Some(id) && g.name(id) == n));
    }

    #[test]
    fn damaged_bytes_never_index_out_of_bounds() {
        let store = Store::new();
        let bytes = sample().bytes().to_vec();
        for n in 0..bytes.len() {
            assert!(store.mapped(&bytes[..n]).is_none(), "truncated to {n}");
        }
        // Any single-byte change is rejected or still answers without
        // panicking.
        let any = regex::bytes::Regex::new(".").unwrap();
        for at in 0..bytes.len() {
            let mut b = bytes.clone();
            b[at] ^= 0xa5;
            if let Some(g) = store.mapped(&b) {
                for name in ["LA;", "LB;", "LC;", "LI;", "Lé;"] {
                    g.reachable(name, Lineage::Subclasses, 10);
                    g.reachable(name, Lineage::Supers, 10);
                    g.id(name).map(|id| g.dex_of(id));
                }
                g.classes_annotated("LM;");
                g.defined_classes_matching(&any);
            }
        }
    }
}
