//! The call edges of one record: for every call site of every function,
//! the function it calls when that can be told, else a leaf with the
//! callee path as text.
//!
//! An edge to a function needs the callee to be, after captured variables
//! are resolved ([`crate::scopes`]), one of the following. What is proved
//! and what is matched by name is said by the kind of the edge
//! ([`EdgeKind`]).
//!
//! - A function or class this record defines (`local:`), directly, through
//!   a module-level binding with one writer, or as a method the literal of
//!   such a class lists: a plain call, or [`EdgeKind::New`].
//! - An imported binding whose request names a record of the program and
//!   whose export chain ends at a local export with one writer, the value
//!   written being such a function, class or class method: the same kinds.
//! - Either of those through a binding that is written more than once the
//!   way a class decorator does it (`C = decorator(C) || C`, the rule of
//!   [`crate::scopes::ExportedDefinitions`]): [`EdgeKind::Reassigned`]. The
//!   edge leads to the class as it is defined; at run time the binding
//!   holds that class or what the decorator returned for it.
//! - `this.name` in a method (or in a closure that captured the `this` of
//!   one) of a class whose literal lists `name` on the same side (instance
//!   or static): [`EdgeKind::ThisClass`], an edge by name. The object may
//!   be of a subclass that overrides the method, or hold an own property
//!   of that name.
//! - A method the class the call names does not list, found in the nearest
//!   ancestor that lists it, up the parent links [`crate::hierarchy`]
//!   proves (`this.name` as above, `C.name`, `new C().name`):
//!   [`EdgeKind::Inherited`]. The walk stops, and the call site stays a
//!   leaf, at a class without parent, a parent outside the program or one
//!   that was not resolved, a class whose literal was not understood, and a
//!   class that lists the name as an accessor or twice.
//! - `super(...)` in a constructor: the parent class's constructor;
//!   `super.name(...)` in a method: the method of the nearest ancestor
//!   that lists `name`, on the side of the calling method:
//!   [`EdgeKind::Super`]. Proved as far as the parent links are: `super`
//!   does not depend on the object the method runs on.
//! - `binding.name`, where the module-level binding (of this record or
//!   imported) has one writer that stores `new C(...)`:
//!   [`EdgeKind::Instance`], the method `name` of `C` or of its nearest
//!   ancestor that lists it. That the binding holds an object made by that
//!   `new C` is proved; the method is matched by name (the constructor or
//!   later code may have given the object an own property of that name).
//!   This is the one place where an import met in another record is
//!   followed: the class a record imports only to make the object it
//!   exports.
//!
//! A parent link through a reassigned binding makes the edge
//! [`EdgeKind::Reassigned`] whatever else it is.
//!
//! - `F().name`, `C.getter().name`, `C.property.name`, where the function
//!   returns, or the static property holds, objects of one class
//!   ([`super::made`], the rules are there): [`EdgeKind::Instance`] as
//!   well, the method `name` of that class or of its nearest ancestor that
//!   lists it. Here the class of the object is told from the code of the
//!   record that hands it out, not proved. `C.getter` has to be a static
//!   method `C` itself lists.
//!
//! Everything else is a leaf ([`LeafKind`]): *external* when the path
//! starts outside the program, at a global or at an import whose request
//! names no record of it (`import:@ohos:net.http#default.createHttp`, a
//! system API, a native library); *unlinked* when it starts at an import
//! of a record of the program and led to no function (a member of what a
//! call returned, a static member no class of the chain lists, a binding
//! with several writers); *unresolved* otherwise (`this.cfg.get`,
//! `arg0.then`, `lex(0,1)`, `?`). No call site is dropped.
//!
//! Creating a function object is not calling it, but it is how control
//! gets into callbacks: every `definefunc` / `definemethod`, class
//! definition and method of an object literal is a [`EdgeKind::Defines`]
//! edge from the function that holds the instruction.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::rc::Rc;
use std::sync::Arc;

use asc_abc::{Abc, Class, ModuleRecord};

use super::modules::RecordId;
use super::{Session, Slot};
use crate::hierarchy::ClassRef;
use crate::path::{FrameOf, Link, MAX_PATH_LINKS, Names, Origin, Path, PathBuilder};
use crate::refs::pc_of;
use crate::scopes::{DefinitionKind, Named, Reader, Scopes, Unresolved, export_group, member_named};
use crate::table_bytes;
use crate::track::Tracker;

/// Bindings followed from one to the next (a module-level binding assigned
/// from another, an import) before a callee is left a leaf.
const MAX_HOPS: usize = 8;
/// Parent links followed from a class upward before a member is given up.
const MAX_ANCESTORS: usize = 32;
/// `new value(...)`.
pub(super) const NEW: Link = Link::Call { construct: true };

/// A function of a program: the ABC entry and the offset of its method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct FnRef {
    pub entry: u32,
    pub method: u32,
}

/// What an edge of the call graph stands for, from the strongest claim to
/// the weakest: when several call sites link two functions, a row shows the
/// first of their kinds in this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum EdgeKind {
    /// A call whose callee is proved to be the function.
    Call,
    /// `new C(...)`: the function is the constructor of the class.
    New,
    /// `super(...)` or `super.name(...)`: the constructor of the parent
    /// class, or the method of the nearest ancestor that lists the name.
    /// Proved as far as the parent links of the hierarchy are.
    Super,
    /// A call on an object of class `C`: the method of `C`, or of its
    /// nearest ancestor that lists the name, matched by name. The object is
    /// a module-level binding whose one writer stores `new C(...)` (proved
    /// to be one that `new C` made), or what a function returned or a
    /// static property holds (`C.getInstance().name(...)`), its class told
    /// from the code of the record that hands it out.
    Instance,
    /// `this.name(...)` matched by name against the class of the calling
    /// method: a subclass may override it.
    ThisClass,
    /// The class the call names (for `this.name(...)`, the class of the
    /// calling method; else `C` of `C.name(...)` / `new C().name(...)`)
    /// does not list the method: it is the one of the nearest ancestor that
    /// does. By name, like [`EdgeKind::ThisClass`], when the call is on
    /// `this`.
    Inherited,
    /// Any of the above through a binding that is assigned a class and then
    /// a value computed at run time (a class decorator): the function is of
    /// the class as defined, which the decorator may have replaced.
    Reassigned,
    /// The function object is created here (a closure, a class, a method of
    /// an object literal), not called.
    Defines,
}

impl EdgeKind {
    /// Every kind, in order.
    pub const ALL: [EdgeKind; 8] = [
        EdgeKind::Call,
        EdgeKind::New,
        EdgeKind::Super,
        EdgeKind::Instance,
        EdgeKind::ThisClass,
        EdgeKind::Inherited,
        EdgeKind::Reassigned,
        EdgeKind::Defines,
    ];

    /// The flag a row carries; a plain call has none.
    pub const fn label(self) -> Option<&'static str> {
        match self {
            EdgeKind::Call => None,
            EdgeKind::New => Some("new"),
            EdgeKind::Super => Some("super"),
            EdgeKind::Instance => Some("instance"),
            EdgeKind::ThisClass => Some("this-class"),
            EdgeKind::Inherited => Some("inherited"),
            EdgeKind::Reassigned => Some("reassigned"),
            EdgeKind::Defines => Some("defines"),
        }
    }
}

/// Why a call site leads to no function of the program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum LeafKind {
    /// The callee path starts outside the program: at a global, or at an
    /// import whose request names no record of it (a system module, a
    /// native library, a package that is not there).
    External,
    /// The path starts at an import of a record of the program, and what
    /// follows led to no function: a member of what a call returned, a
    /// member no class of the chain lists, a binding with several writers.
    Unlinked,
    /// Tracking stopped: a parameter, a property of `this`, a value from
    /// another block.
    Unresolved,
}

impl LeafKind {
    /// Every kind, in order.
    pub const ALL: [LeafKind; 3] = [LeafKind::External, LeafKind::Unlinked, LeafKind::Unresolved];

    /// The flag a row carries.
    pub const fn label(self) -> &'static str {
        match self {
            LeafKind::External => "external",
            LeafKind::Unlinked => "unlinked",
            LeafKind::Unresolved => "unresolved",
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
        kind: LeafKind,
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

    /// Whether a call site of the record (not a definition) leads to one of `functions`.
    pub(crate) fn calls_any_of(&self, functions: &HashSet<FnRef>) -> bool {
        self.edges
            .iter()
            .any(|edge| edge.kind != EdgeKind::Defines && matches!(edge.target, Target::Function(to) if functions.contains(&to)))
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
pub(super) struct Home<'s, 'a> {
    pub id: RecordId,
    pub abc: Abc<'a>,
    pub class: Class<'a>,
    pub module: Option<ModuleRecord<'a>>,
    pub slot: &'s Slot,
    pub scopes: &'s Scopes,
    /// Where the binding behind each import of the record is defined, as
    /// far as call sites asked: per regular import index, and per module
    /// request and member name (a file offset) for namespaces.
    imports: Bindings<u32>,
    namespaces: Bindings<(u32, u32)>,
    /// The same for the imports of other records that hold a class an
    /// exported object is made of.
    foreign: Bindings<(RecordId, u32)>,
    /// The methods looked for in ancestors so far: per class, side (`true`:
    /// static) and name (an offset in the file of the record).
    inherited: RefCell<HashMap<(ClassRef, bool, u32), Option<Found>>>,
    /// Per module request of the record asked about so far: whether it
    /// names a record of the program.
    requests: RefCell<HashMap<u32, bool>>,
    /// What the functions call sites asked about return, per record and
    /// method offset ([`super::made`]).
    pub returned: RefCell<HashMap<(RecordId, u32), Option<super::made::Made>>>,
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

/// A method found in a class or one of its ancestors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Found {
    pub method: FnRef,
    /// It is listed by an ancestor, not by the class the lookup started at.
    inherited: bool,
    /// A parent link on the way goes through a reassigned binding.
    pub reassigned: bool,
}

/// What weakens the claim of an edge, collected while its callee is followed.
#[derive(Debug, Clone, Copy, Default)]
pub(super) struct Caveats {
    /// A binding on the way is reassigned.
    reassigned: bool,
    /// The value was read from a module-level binding that holds a freshly
    /// made object.
    held: bool,
    /// The import of another record was followed already.
    hopped: bool,
}

/// What a call instruction says besides its callee.
#[derive(Debug, Clone, Copy)]
pub(super) struct Site {
    /// `new callee(...)`.
    pub construct: bool,
    /// `super(...)` of the running function.
    pub own_super: bool,
}

/// What a call site leads to.
pub(super) struct Callee {
    pub target: FnRef,
    pub kind: EdgeKind,
    through_import: bool,
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
    /// offset of `home`) is, when that can be told.
    pub(super) fn callee(&self, home: &Home<'_, 'e>, function: u32, path: &Path, site: Site) -> Option<Callee> {
        let Site { construct, own_super } = site;
        let mut path = path.clone();
        // The record the path is read in: `home`, until an import is followed.
        let mut abroad: Option<(RecordId, Arc<Slot>)> = None;
        let mut caveats = Caveats::default();
        let plain = if construct { EdgeKind::New } else { EdgeKind::Call };
        for _ in 0..MAX_HOPS {
            if path.cut {
                return None;
            }
            let at = abroad.as_ref().map_or(home.id, |(id, _)| *id);
            let crossed = abroad.is_some();
            match path.origin {
                Origin::Definition(Some(method)) if path.links.is_empty() => {
                    let kind = if caveats.reassigned { EdgeKind::Reassigned } else { plain };
                    return Some(Callee { target: FnRef { entry: at.entry, method }, kind, through_import: crossed });
                }
                // A member of a class: the one its own literal lists, as `Scopes::reduce` takes it for
                // a path that starts at the class (so that here such a path is left with the
                // members the class inherits), or the one of an ancestor.
                Origin::Definition(Some(class)) => {
                    let (slot, scopes) = match &abroad {
                        None => (home.slot, home.scopes),
                        Some((id, slot)) => (&**slot, self.scopes(slot, *id)?),
                    };
                    let (is_static, name) = match path.links[..] {
                        [Link::Property(Some(name))] => (true, name),
                        [NEW, Link::Property(Some(name))] => (false, name),
                        // A method of the object a function returned or a static property holds.
                        _ if !construct => {
                            let (target, reassigned) = self.method_of_made(home, at, slot, scopes, class, &path.links)?;
                            let kind = if caveats.reassigned || reassigned { EdgeKind::Reassigned } else { EdgeKind::Instance };
                            return Some(Callee { target, kind, through_import: crossed });
                        }
                        _ => return None,
                    };
                    let found = self.method_of(home, ClassRef { entry: at.entry, ctor: class }, scopes, is_static, name, false)?;
                    let kind = match found {
                        _ if caveats.reassigned || found.reassigned => EdgeKind::Reassigned,
                        _ if caveats.held && !is_static => EdgeKind::Instance,
                        _ if found.inherited => EdgeKind::Inherited,
                        _ => plain,
                    };
                    return Some(Callee { target: found.method, kind, through_import: crossed });
                }
                Origin::ModuleLocal(index) => {
                    let stored = match &abroad {
                        None => {
                            let group = export_group(&home.abc, home.module.as_ref()?, index)?;
                            self.stored(home.id, home.slot, home.scopes, &group, &mut caveats)?
                        }
                        Some((id, slot)) => {
                            let abc = self.abc(id.entry)?;
                            let module = abc.class(id.class).ok()?.module_record().ok()??;
                            let group = export_group(&abc, &module, index)?;
                            self.stored(*id, slot, self.scopes(slot, *id)?, &group, &mut caveats)?
                        }
                    };
                    path = Self::read_back(home, at, &stored, &path.links, &mut caveats)?;
                }
                // An import met in another record is not followed (but see below): the records that
                // can reach a function are then the ones whose own requests lead to its record.
                Origin::Import(index) if !crossed => {
                    let bound = home.imports.borrow_mut().entry(index).or_insert_with(|| self.bound_import(home.id, index)).clone()?;
                    path = self.enter(home, &bound, &path.links, &mut caveats)?;
                    abroad = Some((bound.record, Arc::clone(&bound.slot)));
                }
                Origin::Namespace(index) if !crossed => {
                    let [Link::Property(Some(name)), rest @ ..] = &path.links[..] else { return None };
                    let known =
                        home.namespaces.borrow_mut().entry((index, *name)).or_insert_with(|| self.bound_member(home, index, *name)).clone();
                    let bound = known?;
                    path = self.enter(home, &bound, rest, &mut caveats)?;
                    abroad = Some((bound.record, Arc::clone(&bound.slot)));
                }
                // The object another record exports, made of a class that record imports: the one
                // import of another record that is followed, once.
                Origin::Import(index) if caveats.held && !caveats.hopped && matches!(path.links[..], [NEW, Link::Property(Some(_))]) => {
                    let bound = home.foreign.borrow_mut().entry((at, index)).or_insert_with(|| self.bound_import(at, index)).clone()?;
                    caveats.hopped = true;
                    // The object is the one read from the first binding, whatever this one holds.
                    let mut class = Caveats { held: false, ..caveats };
                    path = self.enter(home, &bound, &path.links, &mut class)?;
                    caveats.reassigned = class.reassigned;
                    abroad = Some((bound.record, Arc::clone(&bound.slot)));
                }
                Origin::This(frame) if !crossed => {
                    let membership = home.scopes.membership(frame_function(frame, function))?;
                    let [Link::Property(Some(name))] = path.links[..] else {
                        // In a static method `this` is the class: `this.getInstance().name`.
                        if construct || !membership.is_static || !matches!(path.links[..], [Link::Property(_), _, ..]) {
                            return None;
                        }
                        let (target, reassigned) =
                            self.method_of_made(home, home.id, home.slot, home.scopes, membership.class, &path.links)?;
                        let kind = if reassigned { EdgeKind::Reassigned } else { EdgeKind::Instance };
                        return Some(Callee { target, kind, through_import: false });
                    };
                    let class = ClassRef { entry: home.id.entry, ctor: membership.class };
                    let found = self.method_of(home, class, home.scopes, membership.is_static, name, false)?;
                    let kind = match found {
                        _ if found.reassigned => EdgeKind::Reassigned,
                        _ if found.inherited => EdgeKind::Inherited,
                        _ => EdgeKind::ThisClass,
                    };
                    return Some(Callee { target: found.method, kind, through_import: false });
                }
                Origin::Super(frame) if !crossed => {
                    let of = frame_function(frame, function);
                    // An arrow function has the `super` of the method around it.
                    let membership = home.scopes.membership(home.scopes.home_member(of)?)?;
                    let class = ClassRef { entry: home.id.entry, ctor: membership.class };
                    let (target, reassigned) = match path.links[..] {
                        // `super(...)`: of the constructor that runs, not of a function inside it.
                        [] if own_super && frame == FrameOf::Own && membership.class == of => {
                            let (parent, reassigned) = self.classes().superclass(class)?;
                            (FnRef { entry: parent.entry, method: parent.ctor }, reassigned)
                        }
                        [Link::Property(Some(name))] => {
                            let found = self.method_of(home, class, home.scopes, membership.is_static, name, true)?;
                            (found.method, found.reassigned)
                        }
                        _ => return None,
                    };
                    let kind = if reassigned { EdgeKind::Reassigned } else { EdgeKind::Super };
                    return Some(Callee { target, kind, through_import: false });
                }
                _ => return None,
            }
        }
        None
    }

    /// The method class `class` has under the name at offset `name` of the
    /// file of `home`, on its static or instance side: its own, or the one
    /// of its nearest ancestor that lists the name; of an ancestor only
    /// with `above`. `scopes` are those of the record of `class`.
    pub(super) fn method_of(
        &self,
        home: &Home<'_, 'e>,
        class: ClassRef,
        scopes: &Scopes,
        is_static: bool,
        name: u32,
        above: bool,
    ) -> Option<Found> {
        let bytes = home.abc.string(name).ok()?.bytes;
        if !above && let Some(method) = listed(&self.abc(class.entry)?, scopes, class, is_static, bytes)? {
            return Some(Found { method, inherited: false, reassigned: false });
        }
        // The ancestors are the same for every call site of the record that asks.
        let key = (class, is_static, name);
        if let Some(known) = home.inherited.borrow().get(&key) {
            return *known;
        }
        let found = self.inherited(class, is_static, bytes);
        home.inherited.borrow_mut().insert(key, found);
        found
    }

    /// The method the nearest ancestor of `class` that lists `name` on one
    /// side has under it.
    fn inherited(&self, class: ClassRef, is_static: bool, name: &[u8]) -> Option<Found> {
        let mut class = class;
        let mut reassigned = false;
        for _ in 0..MAX_ANCESTORS {
            let (parent, weak) = self.classes().superclass(class)?;
            reassigned |= weak;
            let record = self.record_of(FnRef { entry: parent.entry, method: parent.ctor })?;
            let slot = self.slot(record);
            match listed(&self.abc(parent.entry)?, self.scopes(&slot, record)?, parent, is_static, name)? {
                Some(method) => return Some(Found { method, inherited: true, reassigned }),
                None => class = parent,
            }
        }
        None
    }

    /// The binding regular import `index` of record `of` names.
    fn bound_import(&self, of: RecordId, index: u32) -> Option<Rc<Bound>> {
        let abc = self.abc(of.entry)?;
        let module = abc.class(of.class).ok()?.module_record().ok()??;
        let import = module.regular_imports.get(index as usize)?;
        let target = self.layout().request(of, import.module_request_idx)?;
        self.bound(target, abc.string(import.import_name_off).ok()?.bytes)
    }

    /// The binding the member at name offset `name` of the namespace of
    /// request `request` of `home` is.
    fn bound_member(&self, home: &Home<'_, 'e>, request: u32, name: u32) -> Option<Rc<Bound>> {
        let target = self.layout().request(home.id, u16::try_from(request).ok()?)?;
        self.bound(target, home.abc.string(name).ok()?.bytes)
    }

    fn bound(&self, target: RecordId, name: &[u8]) -> Option<Rc<Bound>> {
        let binding = self.layout().export(target, name)?;
        Some(Rc::new(Bound { record: binding.record, slot: self.slot(binding.record), exports: binding.exports }))
    }

    /// The value of the module-level binding of record `id` whose local
    /// export entries are `group`: what its one writer stores, or the class
    /// a decorator reassigns (and `caveats` then says so).
    pub(super) fn stored<'s>(
        &self,
        id: RecordId,
        slot: &'s Slot,
        scopes: &'s Scopes,
        group: &[u32],
        caveats: &mut Caveats,
    ) -> Option<Cow<'s, Path>> {
        match scopes.module_binding(group) {
            Ok(written) => Some(Cow::Borrowed(&written.path)),
            Err(Unresolved::MultipleWriters) => {
                // The entries of a binding share one variable: any of them names it.
                let exported = self.exported(slot, id, scopes)?.get(*group.first()?).filter(|exported| exported.reassigned)?;
                caveats.reassigned = true;
                Some(Cow::Owned(Path { origin: Origin::Definition(Some(exported.method)), links: Vec::new(), cut: false }))
            }
            Err(_) => None,
        }
    }

    /// `stored`, the value of a binding of record `of`, followed by
    /// `links`, which a call site of `home` reads it with.
    fn read_back(home: &Home<'_, 'e>, of: RecordId, stored: &Path, links: &[Link], caveats: &mut Caveats) -> Option<Path> {
        // The names of the value's own links are strings of the file it is in.
        if of.entry != home.id.entry && stored.links.iter().any(|link| matches!(link, Link::Property(_))) {
            return None;
        }
        caveats.held |= stored.links.last() == Some(&NEW);
        joined(stored, links)
    }

    /// The value of `bound`, a binding an import leads to, followed by
    /// `links`.
    fn enter(&self, home: &Home<'_, 'e>, bound: &Bound, links: &[Link], caveats: &mut Caveats) -> Option<Path> {
        let scopes = self.scopes(&bound.slot, bound.record)?;
        let stored = self.stored(bound.record, &bound.slot, scopes, &bound.exports, caveats)?;
        Self::read_back(home, bound.record, &stored, links, caveats)
    }

    /// Whether a module-level binding of record `id` (whose slot is `slot`,
    /// with its scopes built) holds an object made of one of `classes`: what
    /// [`EdgeKind::Instance`] edges of the records that import `id` go
    /// through. A binding is followed here as [`Session::callee`] follows
    /// it from a call site, so one whose class is not told here leads to
    /// no edge there.
    pub(super) fn holds_instance_of(&self, id: RecordId, slot: &Slot, classes: &HashSet<ClassRef>) -> bool {
        let Some(scopes) = slot.scopes.get() else { return false };
        let mut bindings = scopes.instance_bindings().peekable();
        if bindings.peek().is_none() {
            return false;
        }
        let Some(home) = self.home(id, slot, scopes) else { return true };
        bindings.any(|(index, _)| {
            // The binding as a call site of its own record reads it: an import is followed from
            // here as it is from a record that imports the binding.
            let mut path = Path { origin: Origin::ModuleLocal(index), links: Vec::new(), cut: false };
            let mut at = id;
            let mut caveats = Caveats::default();
            for _ in 0..MAX_HOPS {
                match (path.origin, &path.links[..]) {
                    (Origin::Definition(Some(class)), [NEW]) => return classes.contains(&ClassRef { entry: at.entry, ctor: class }),
                    (Origin::ModuleLocal(index), _) => {
                        let Some(next) = self.binding_value(&home, at, index, &path.links, &mut caveats) else { return false };
                        path = next;
                    }
                    (Origin::Import(index), _) if !caveats.hopped => {
                        let Some(bound) = self.bound_import(at, index) else { return false };
                        caveats.hopped = true;
                        let Some(next) = self.enter(&home, &bound, &path.links, &mut caveats) else { return false };
                        path = next;
                        at = bound.record;
                    }
                    _ => return false,
                }
            }
            false
        })
    }

    /// The value of the binding of local export `index` of record `of`,
    /// followed by `links`.
    fn binding_value(&self, home: &Home<'_, 'e>, of: RecordId, index: u32, links: &[Link], caveats: &mut Caveats) -> Option<Path> {
        let abc = self.abc(of.entry)?;
        let module = abc.class(of.class).ok()?.module_record().ok()??;
        let group = export_group(&abc, &module, index)?;
        let slot = self.slot(of);
        let scopes = self.scopes(&slot, of)?;
        let stored = self.stored(of, &slot, scopes, &group, caveats)?;
        Self::read_back(home, of, &stored, links, caveats)
    }

    pub(super) fn home<'s>(&self, id: RecordId, slot: &'s Slot, scopes: &'s Scopes) -> Option<Home<'s, 'e>> {
        let abc = self.abc(id.entry)?;
        let class = abc.class(id.class).ok()?;
        Some(Home {
            id,
            abc,
            class,
            module: class.module_record().ok().flatten(),
            slot,
            scopes,
            imports: RefCell::default(),
            namespaces: RefCell::default(),
            foreign: RefCell::default(),
            inherited: RefCell::default(),
            requests: RefCell::default(),
            returned: RefCell::default(),
        })
    }

    /// What kind of leaf `path`, a callee of record `home` that led to no
    /// function, is.
    fn leaf_kind(&self, home: &Home<'_, 'e>, path: &Path) -> LeafKind {
        if !path.is_known() {
            return LeafKind::Unresolved;
        }
        let request = match path.origin {
            Origin::Global(_) | Origin::GlobalObject => return LeafKind::External,
            Origin::Import(index) => {
                let import = home.module.as_ref().and_then(|module| module.regular_imports.get(index as usize));
                import.map(|import| u32::from(import.module_request_idx))
            }
            Origin::Namespace(index) => Some(index),
            _ => return LeafKind::Unresolved,
        };
        // An import that does not read names nothing of the program.
        let Some(request) = request else { return LeafKind::External };
        let in_program = *home
            .requests
            .borrow_mut()
            .entry(request)
            .or_insert_with(|| u16::try_from(request).ok().and_then(|request| self.layout().request(home.id, request)).is_some());
        if in_program { LeafKind::Unlinked } else { LeafKind::External }
    }

    /// The edges of record `id`; `slot` is its slot and `scopes` are its own.
    pub(super) fn build_edges(&self, id: RecordId, slot: &Slot, scopes: &Scopes) -> RecordEdges {
        let mut out = RecordEdges::default();
        let Some(regions) = self.regions(id.entry) else { return out };
        let Some(home) = self.home(id, slot, scopes) else { return out };
        let abc = home.abc;
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
                let edge = match self.callee(&home, offset, &path, Site { construct: site.construct, own_super: site.own_super }) {
                    Some(Callee { target, kind, through_import }) => {
                        Edge { pc: pc_of(insn), kind, target: Target::Function(target), via: through_import.then(|| texts.id(&text)) }
                    }
                    None => {
                        let kind = if site.construct { EdgeKind::New } else { EdgeKind::Call };
                        let target = Target::Leaf { text: texts.id(&text), kind: self.leaf_kind(&home, &path) };
                        Edge { pc: pc_of(insn), kind, target, via: None }
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

/// The function whose frame `frame` is, for a value read in `function`.
pub(super) fn frame_function(frame: FrameOf, function: u32) -> u32 {
    match frame {
        FrameOf::Own => function,
        FrameOf::Captured(outer) => outer,
    }
}

/// The method the literal of `class` (of file `abc`, whose record has
/// `scopes`) lists as `name` on one side: `Some(None)` when it lists none of
/// that name, `None` when that is not decided (the literal was not
/// understood, the class is a plain function, the name is an accessor or
/// listed twice).
pub(super) fn listed(abc: &Abc<'_>, scopes: &Scopes, class: ClassRef, is_static: bool, name: &[u8]) -> Option<Option<FnRef>> {
    let info = scopes.class(class.ctor)?;
    match member_named(abc, if is_static { &info.statics } else { &info.instance }, name) {
        Named::One(member) => Some(Some(FnRef { entry: class.entry, method: member.method })),
        Named::Absent => Some(None),
        Named::Undecided => None,
    }
}
