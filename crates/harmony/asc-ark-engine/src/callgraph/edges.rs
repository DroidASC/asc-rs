//! The call edges of one record: for every call site of every function,
//! the function it calls when that can be proved, else a leaf with the
//! callee path as text.
//!
//! An edge to a function needs the callee to be, after captured variables
//! are resolved ([`crate::scopes`]):
//!
//! - a function or class this record defines (`local:`), directly, through
//!   a module-level binding with one writer, or as a method the literal of
//!   such a class lists;
//! - an imported binding whose request names a record of the program and
//!   whose export chain ends at a local export with one writer, the value
//!   written being such a function, class or class method;
//! - `this.name` in a method (or in a closure that captured the `this` of
//!   one) of a class whose literal lists `name` on the same side (instance
//!   or static): [`EdgeKind::ThisClass`], an edge by name. The object may
//!   be of a subclass that overrides the method, or hold an own property
//!   of that name; the edge says so by its kind.
//!
//! Everything else is a leaf: *external* when the path starts at an import
//! or a global (`import:@ohos:net.http#default.createHttp`, a system API,
//! or a program import that did not resolve to a function), *unresolved*
//! otherwise (`this.cfg.get`, `arg0.then`, `lex(0,1)`, `?`). No call site
//! is dropped.
//!
//! Creating a function object is not calling it, but it is how control
//! gets into callbacks: every `definefunc` / `definemethod`, class
//! definition and method of an object literal is a [`EdgeKind::Defines`]
//! edge from the function that holds the instruction.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ops::Range;
use std::rc::Rc;
use std::sync::Arc;

use asc_abc::{Abc, Class, ModuleRecord};

use super::modules::{self, RecordId};
use super::{Session, Slot};
use crate::path::{FrameOf, Link, Names, Origin, Path, PathBuilder, MAX_PATH_LINKS};
use crate::refs::pc_of;
use crate::scopes::{find_member, DefinitionKind, Reader, Scopes};
use crate::table_bytes;
use crate::track::Tracker;

/// Bindings followed from one to the next (a module-level binding assigned
/// from another, an import) before a callee is left a leaf.
const MAX_HOPS: usize = 8;

/// A function of a program: the ABC entry and the offset of its method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct FnRef {
    pub entry: u32,
    pub method: u32,
}

/// What an edge of the call graph stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum EdgeKind {
    /// A call whose callee is proved to be the function.
    Call,
    /// `new C(...)`: the function is the constructor of the class.
    New,
    /// `this.name(...)` matched by name against the class of the calling
    /// method: a subclass may override it.
    ThisClass,
    /// The function object is created here (a closure, a class, a method of
    /// an object literal), not called.
    Defines,
}

impl EdgeKind {
    /// The flag a row carries; a plain call has none.
    pub const fn label(self) -> Option<&'static str> {
        match self {
            EdgeKind::Call => None,
            EdgeKind::New => Some("new"),
            EdgeKind::ThisClass => Some("this-class"),
            EdgeKind::Defines => Some("defines"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Target {
    Function(FnRef),
    /// A callee that is not a function of the program; `text` indexes
    /// [`RecordEdges::texts`].
    Leaf {
        text: u32,
        external: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Edge {
    pub pc: u32,
    pub kind: EdgeKind,
    pub target: Target,
    /// For an edge through an import: the callee path as the call site
    /// spells it, an index into [`RecordEdges::texts`].
    pub via: Option<u32>,
}

/// The edges of every function of one record.
#[derive(Debug, Default)]
pub(crate) struct RecordEdges {
    /// Per method offset: its run of `edges`, in code order.
    functions: HashMap<u32, Range<usize>>,
    /// Method offsets in file order.
    order: Vec<u32>,
    edges: Vec<Edge>,
    texts: Vec<String>,
}

impl RecordEdges {
    /// The edges of the function at method offset `method`, in code order.
    pub(crate) fn of(&self, method: u32) -> &[Edge] {
        self.functions.get(&method).and_then(|run| self.edges.get(run.clone())).unwrap_or_default()
    }

    /// Every function of the record with code, in file order, with its edges.
    pub(crate) fn functions(&self) -> impl Iterator<Item = (u32, &[Edge])> {
        self.order.iter().map(|&method| (method, self.of(method)))
    }

    pub(crate) fn text(&self, id: u32) -> &str {
        self.texts.get(id as usize).map_or("?", String::as_str)
    }

    /// The texts of the record, by id.
    pub(crate) fn texts(&self) -> impl Iterator<Item = &str> {
        self.texts.iter().map(String::as_str)
    }

    pub(crate) fn len(&self) -> usize {
        self.edges.len()
    }

    /// Bytes this takes on the heap, roughly.
    pub(crate) fn heap_bytes(&self) -> usize {
        self.edges.capacity() * std::mem::size_of::<Edge>()
            + self.order.capacity() * 4
            + table_bytes(&self.functions)
            + self.texts.capacity() * std::mem::size_of::<String>()
            + self.texts.iter().map(String::capacity).sum::<usize>()
    }
}

/// Interns the leaf texts of one record.
#[derive(Default)]
struct Texts {
    ids: HashMap<String, u32>,
    list: Vec<String>,
}

impl Texts {
    fn id(&mut self, text: &str) -> u32 {
        if let Some(&id) = self.ids.get(text) {
            return id;
        }
        let id = u32::try_from(self.list.len()).unwrap_or(u32::MAX);
        self.list.push(text.to_owned());
        self.ids.insert(text.to_owned(), id);
        id
    }
}

/// The record a callee is resolved in.
struct Home<'s, 'a> {
    id: RecordId,
    abc: Abc<'a>,
    class: Class<'a>,
    module: Option<ModuleRecord<'a>>,
    scopes: &'s Scopes,
    /// Where the binding behind each import of the record is defined, as
    /// far as call sites asked: per regular import index, and per module
    /// request and member name (a file offset) for namespaces.
    imports: Bindings<u32>,
    namespaces: Bindings<(u32, u32)>,
}

/// Bindings resolved so far, by what names them; `None` for the ones that
/// do not resolve.
type Bindings<K> = RefCell<HashMap<K, Option<Rc<Bound>>>>;

/// An exported binding an import leads to.
struct Bound {
    /// The record that defines it.
    record: RecordId,
    slot: Arc<Slot>,
    /// Its local export entries.
    exports: Vec<u32>,
}

/// The local export entries that share the local name of entry `index`.
fn export_group(abc: &Abc<'_>, module: &ModuleRecord<'_>, index: u32) -> Option<Vec<u32>> {
    let local = module.local_exports.get(index as usize)?.local_name_off;
    let name = abc.string(local).ok()?.bytes;
    let same = |off: u32| off == local || abc.string(off).is_ok_and(|other| other.bytes == name);
    Some(
        module
            .local_exports
            .iter()
            .enumerate()
            .filter(|(_, export)| same(export.local_name_off))
            .filter_map(|(index, _)| u32::try_from(index).ok())
            .collect(),
    )
}

/// `stored`, the value of a binding, followed by `links`.
fn joined(stored: &Path, links: &[Link]) -> Option<Path> {
    if stored.cut || stored.links.len() + links.len() > MAX_PATH_LINKS {
        return None;
    }
    let mut path = stored.clone();
    path.links.extend_from_slice(links);
    Some(path)
}

impl<'e> Session<'e> {
    /// The function the callee `path` of a call in `function` (a method
    /// offset of `home`) is, when that is proved.
    fn callee(&self, home: &Home<'_, 'e>, function: u32, path: &Path, construct: bool) -> Option<(FnRef, EdgeKind, bool)> {
        let mut path = path.clone();
        // The record the path is read in: `home`, until an import is followed.
        let mut abroad: Option<(RecordId, Arc<Slot>)> = None;
        for _ in 0..MAX_HOPS {
            if path.cut {
                return None;
            }
            let at = abroad.as_ref().map_or(home.id, |(id, _)| *id);
            let crossed = abroad.is_some();
            match path.origin {
                Origin::Definition(Some(method)) if path.links.is_empty() => {
                    let kind = if construct { EdgeKind::New } else { EdgeKind::Call };
                    return Some((FnRef { entry: at.entry, method }, kind, crossed));
                }
                Origin::ModuleLocal(index) => {
                    let (abc, module, scopes) = match &abroad {
                        None => (home.abc, home.module, home.scopes),
                        Some((id, slot)) => {
                            let abc = self.abc(id.entry)?;
                            (abc, abc.class(id.class).ok()?.module_record().ok()?, self.scopes(slot, *id)?)
                        }
                    };
                    let written = scopes.module_binding(&export_group(&abc, module.as_ref()?, index)?).ok()?;
                    // The names of the value's own links are strings of the file it is in.
                    if at.entry != home.id.entry && !written.path.links.is_empty() {
                        return None;
                    }
                    path = joined(&written.path, &path.links)?;
                    scopes.reduce_named(&abc, &mut path, &home.abc);
                }
                // An import met in another record is not followed: the records that can reach a
                // function are then the ones whose own requests lead to its record.
                Origin::Import(index) if !crossed => {
                    let bound = home.imports.borrow_mut().entry(index).or_insert_with(|| self.bound_import(home, index)).clone()?;
                    path = self.enter(home, &bound, &path.links)?;
                    abroad = Some((bound.record, Arc::clone(&bound.slot)));
                }
                Origin::Namespace(index) if !crossed => {
                    let [Link::Property(Some(name)), rest @ ..] = &path.links[..] else { return None };
                    let known =
                        home.namespaces.borrow_mut().entry((index, *name)).or_insert_with(|| self.bound_member(home, index, *name)).clone();
                    let bound = known?;
                    path = self.enter(home, &bound, rest)?;
                    abroad = Some((bound.record, Arc::clone(&bound.slot)));
                }
                Origin::This(frame) if !crossed => {
                    let [Link::Property(Some(name))] = path.links[..] else { return None };
                    let of = match frame {
                        FrameOf::Own => function,
                        FrameOf::Captured(outer) => outer,
                    };
                    let membership = home.scopes.membership(of)?;
                    let info = home.scopes.class(membership.class)?;
                    let members = if membership.is_static { &info.statics } else { &info.instance };
                    let member = find_member(&home.abc, members, home.abc.string(name).ok()?.bytes)?;
                    return Some((FnRef { entry: home.id.entry, method: member.method }, EdgeKind::ThisClass, false));
                }
                _ => return None,
            }
        }
        None
    }

    /// The binding regular import `index` of `home` names.
    fn bound_import(&self, home: &Home<'_, 'e>, index: u32) -> Option<Rc<Bound>> {
        let import = home.module.as_ref()?.regular_imports.get(index as usize)?;
        let target = modules::request(&self.abcs, home.id, import.module_request_idx)?;
        self.bound(target, home.abc.string(import.import_name_off).ok()?.bytes)
    }

    /// The binding the member at name offset `name` of the namespace of
    /// request `request` of `home` is.
    fn bound_member(&self, home: &Home<'_, 'e>, request: u32, name: u32) -> Option<Rc<Bound>> {
        let target = modules::request(&self.abcs, home.id, u16::try_from(request).ok()?)?;
        self.bound(target, home.abc.string(name).ok()?.bytes)
    }

    fn bound(&self, target: RecordId, name: &[u8]) -> Option<Rc<Bound>> {
        let binding = modules::export(&self.abcs, target, name)?;
        Some(Rc::new(Bound { record: binding.record, slot: self.slot(binding.record), exports: binding.exports }))
    }

    /// The value of `bound`, a binding an import of `home` leads to,
    /// followed by `links`.
    fn enter(&self, home: &Home<'_, 'e>, bound: &Bound, links: &[Link]) -> Option<Path> {
        let scopes = self.scopes(&bound.slot, bound.record)?;
        let written = scopes.module_binding(&bound.exports).ok()?;
        // The names of the value's own links are strings of the file it is in.
        if bound.record.entry != home.id.entry && !written.path.links.is_empty() {
            return None;
        }
        let mut path = joined(&written.path, links)?;
        scopes.reduce_named(&self.abc(bound.record.entry)?, &mut path, &home.abc);
        Some(path)
    }

    /// The edges of record `id`; `scopes` are its own.
    pub(super) fn build_edges(&self, id: RecordId, scopes: &Scopes) -> RecordEdges {
        let mut out = RecordEdges::default();
        let Some((abc, regions)) = self.abc(id.entry).zip(self.regions(id.entry)) else { return out };
        let Ok(class) = abc.class(id.class) else { return out };
        let module = class.module_record().ok().flatten();
        let home = Home { id, abc, class, module, scopes, imports: RefCell::default(), namespaces: RefCell::default() };
        let names = Names { abc: &abc, module: home.module.as_ref() };
        let mut texts = Texts::default();
        let mut tracker = Tracker::default();
        let (mut path, mut text) = (Path::default(), String::new());
        let mut definitions = scopes.definitions().iter().peekable();
        // A malformed member list ends the record's functions.
        for method in home.class.methods().into_iter().flatten().map_while(|method| method.ok()) {
            let Some(function) = regions.function(abc, &method) else { continue };
            let offset = method.offset();
            let start = out.edges.len();
            let reader = Reader::new(scopes, offset);
            let entity = |entity_id: u32| function.entity(entity_id);
            // Code that does not decode has no call sites to show.
            let _ = tracker.run(self.tables.effects(), &function.code, |frame, insn, site| {
                match &reader {
                    Some(reader) => {
                        PathBuilder { frame, function: offset, entity: &entity, lexicals: reader }.build(site.callee, &mut path)
                    }
                    None => PathBuilder { frame, function: offset, entity: &entity, lexicals: &crate::path::NoLexicals }
                        .build(site.callee, &mut path),
                }
                scopes.reduce(&abc, &mut path);
                text.clear();
                names.write(&mut text, &path);
                let edge = match self.callee(&home, offset, &path, site.construct) {
                    Some((target, kind, through_import)) => {
                        Edge { pc: pc_of(insn), kind, target: Target::Function(target), via: through_import.then(|| texts.id(&text)) }
                    }
                    None => {
                        let named =
                            matches!(path.origin, Origin::Import(_) | Origin::Namespace(_) | Origin::Global(_) | Origin::GlobalObject);
                        let kind = if site.construct { EdgeKind::New } else { EdgeKind::Call };
                        Edge {
                            pc: pc_of(insn),
                            kind,
                            target: Target::Leaf { text: texts.id(&text), external: named && path.is_known() },
                            via: None,
                        }
                    }
                };
                out.edges.push(edge);
            });
            while let Some(definition) = definitions.next_if(|definition| definition.parent == offset) {
                // The methods of a class come with the class.
                if definition.kind != DefinitionKind::ClassMember {
                    let target = Target::Function(FnRef { entry: id.entry, method: definition.child });
                    out.edges.push(Edge { pc: definition.pc, kind: EdgeKind::Defines, target, via: None });
                }
            }
            out.edges[start..].sort_by_key(|edge| edge.pc);
            out.functions.insert(offset, start..out.edges.len());
            out.order.push(offset);
        }
        out.edges.shrink_to_fit();
        out.texts = texts.list;
        out
    }
}
