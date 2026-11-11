//! The objects one record hands out: which class the value a function
//! returns, or a static property holds, is an object of.
//!
//! `Store.getInstance().load()` names no class for `load`: the call is on
//! what `getInstance` returned. That is an object of a known class when the
//! body of the function says so, by these rules, all of them over the
//! tracked values of [`crate::track`] with captured variables resolved:
//!
//! - **A function returns objects of class `K`** when every `return` of it
//!   hands back `new K(...)`, the value of a static property that holds
//!   objects of `K`, or `undefined` / `null`, and at least one of them is
//!   not the latter. `K` is told as for any `new` call site: a class of the
//!   record, or an imported one. A `return` of anything else (a parameter,
//!   a local set on two paths, the result of another call, the promise of
//!   an async function) leaves the function without a class.
//! - **A static property `C.p` holds objects of class `K`**, for a class `C`
//!   of the record, when every store of the record into a property `p` of
//!   `C` (`C.p = …`, `this.p = …` in a static method or in the static
//!   initializer of `C`) writes `new K(...)`, `undefined` or `null`, at
//!   least one of them the former, and no store of the record writes a
//!   property of that name on an object that is not known: any such store
//!   could be one into `C`. Stores on `this` of an instance method and on a
//!   freshly made object are stores into objects, not into `C`.
//! - `new this()` in a static method is the class the method is called on
//!   ([`Maker::Receiver`]): `C` itself for `C.getInstance()`.
//!
//! - The `return` of a hot-patch stub is not a `return` of the function. A
//!   build that can be patched in the field has its functions open with
//!   `const answer = PATCHER.ask(NUMBER, this, ...parameters); if
//!   (answer.replaced) return answer.value;`: what a patch would return, if
//!   one is ever installed. [`super::stub`] tells such a stub by its exact
//!   shape at the head of the function, and only in a record where at least
//!   [`super::stub::FAMILY`] functions open with the same one. What the
//!   function returns is then what its other `return`s say: what the code
//!   as shipped does, which is all a static reading can tell.
//!
//! What this does not see: a store into `C.p` from another record, a store
//! with a computed name, a subclass that reads the property through its
//! parent, a patch that replaces a function at run time. An edge made of it
//! is by name ([`super::EdgeKind::Instance`]), with or without a stub in
//! the way: the edge does not say which.
//!
//! What a function returns is read from that function alone when a call
//! site asks; only one that returns the value of a static property has the
//! stores of its whole record looked at ([`RecordObjects`], built once per
//! record and kept with the edges).

use std::collections::{HashMap, HashSet};

use super::edges::{FnRef, Home, NEW, Site, frame_function, listed};
use super::modules::RecordId;
use super::stub::{self, StubKey};
use super::{EdgeKind, Session, Slot};
use crate::hierarchy::ClassRef;
use crate::path::{Link, NoLexicals, Origin, Path, PathBuilder};
use crate::refs::Function;
use crate::scopes::{Reader, Scopes, export_group};
use crate::table_bytes;
use crate::track::{Event, StringRef, Tracker, Watch};

/// The class an object is made of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Maker {
    Class(ClassRef),
    /// The class the static method that made it was called on (`new this()`).
    Receiver,
}

/// What a returned or held value is an object of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Made {
    pub of: Maker,
    /// The class was read from a binding a decorator reassigns.
    pub reassigned: bool,
}

/// A static property of a class that holds objects of one class.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Held {
    name: Box<[u8]>,
    made: Made,
}

/// See the module documentation.
#[derive(Debug, Default)]
pub(crate) struct RecordObjects {
    /// Per function (a method offset): what it returns.
    returned: HashMap<u32, Made>,
    /// Per class (its constructor): its static properties that hold objects.
    held: HashMap<u32, Vec<Held>>,
}

impl RecordObjects {
    /// What the function at method offset `function` returns.
    pub(crate) fn returned(&self, function: u32) -> Option<Made> {
        self.returned.get(&function).copied()
    }

    /// What the static property `name` of the class whose constructor is
    /// `class` holds.
    pub(crate) fn held(&self, class: u32, name: &[u8]) -> Option<Made> {
        self.held.get(&class)?.iter().find(|held| *held.name == *name).map(|held| held.made)
    }

    /// Whether a function or a static property of the record hands out
    /// objects of one of `classes`.
    pub(crate) fn makes_any_of(&self, classes: &HashSet<ClassRef>) -> bool {
        let held = self.held.values().flatten().map(|held| &held.made);
        self.returned.values().chain(held).any(|made| matches!(made.of, Maker::Class(class) if classes.contains(&class)))
    }

    /// Bytes this takes on the heap, roughly.
    pub(crate) fn heap_bytes(&self) -> usize {
        let held =
            |list: &Vec<Held>| list.capacity() * std::mem::size_of::<Held>() + list.iter().map(|held| held.name.len()).sum::<usize>();
        table_bytes(&self.returned) + table_bytes(&self.held) + self.held.values().map(held).sum::<usize>()
    }
}

/// What a `return` hands back or a store writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Value<'a> {
    Made(Made),
    /// `undefined`, `null`: no object.
    Empty,
    /// The static property `name` of class `class` of the record;
    /// `through_this`: read as `this.name` in a static method.
    Held {
        class: u32,
        name: &'a [u8],
        through_this: bool,
    },
    Other,
}

/// The object a store writes a property of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Holder {
    /// A class of the record, by its constructor.
    Class(u32),
    /// An object that is not a class: `this` of an instance method, a
    /// freshly made object.
    Object,
    Unknown,
}

/// A class of the record a value is read in.
#[derive(Debug, Clone, Copy)]
struct OwnClass {
    /// Its constructor.
    ctor: u32,
    /// It is named as `this` of one of its static methods.
    through_this: bool,
}

/// The object the first links of a callee path lead to.
struct Handed<'l> {
    /// The class it is made of.
    class: ClassRef,
    /// The class was read from a binding a decorator reassigns.
    reassigned: bool,
    /// The links after it.
    rest: &'l [Link],
}

/// One class every value of `values` that is an object is of: `None` when
/// one of them is not known, two differ, or none is an object.
fn agreed(values: impl IntoIterator<Item = Option<Made>>, is_empty: impl Fn(usize) -> bool) -> Option<Made> {
    let mut agreed: Option<Made> = None;
    for (index, value) in values.into_iter().enumerate() {
        match value {
            Some(made) if agreed.is_none_or(|known| known == made) => agreed = Some(made),
            Some(_) => return None,
            None if is_empty(index) => {}
            None => return None,
        }
    }
    agreed
}

impl<'e> Session<'e> {
    /// The class of record `home` that `origin`, read in `function`, is.
    fn own_class(&self, home: &Home<'_, 'e>, function: u32, origin: Origin) -> Option<OwnClass> {
        let named = |ctor: u32| home.scopes.class(ctor).map(|_| OwnClass { ctor, through_this: false });
        match origin {
            Origin::This(frame) => {
                let membership = home.scopes.membership(frame_function(frame, function)).filter(|membership| membership.is_static)?;
                Some(OwnClass { ctor: membership.class, through_this: true })
            }
            Origin::Definition(Some(class)) => named(class),
            Origin::ModuleLocal(index) => {
                let group = export_group(&home.abc, home.module.as_ref()?, index)?;
                let stored = self.stored(home.id, home.slot, home.scopes, &group, &mut Default::default())?;
                match (stored.origin, stored.links.is_empty() && !stored.cut) {
                    (Origin::Definition(Some(class)), true) => named(class),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// What `path`, a value of `function` of record `home`, is.
    fn value_of(&self, home: &Home<'_, 'e>, function: u32, path: &Path) -> Value<'e> {
        if path.cut {
            return Value::Other;
        }
        match (path.origin, &path.links[..]) {
            (Origin::Constant("undefined" | "null"), []) => Value::Empty,
            (Origin::This(_), [NEW]) => match self.own_class(home, function, path.origin) {
                Some(_) => Value::Made(Made { of: Maker::Receiver, reassigned: false }),
                None => Value::Other,
            },
            (origin, [class @ .., NEW]) => {
                let class = Path { origin, links: class.to_vec(), cut: false };
                match self.callee(home, function, &class, Site { construct: true, own_super: false }) {
                    Some(made) if matches!(made.kind, EdgeKind::New | EdgeKind::Reassigned) => Value::Made(Made {
                        of: Maker::Class(ClassRef { entry: made.target.entry, ctor: made.target.method }),
                        reassigned: made.kind == EdgeKind::Reassigned,
                    }),
                    _ => Value::Other,
                }
            }
            (origin, [Link::Property(Some(name))]) => {
                let class = self.own_class(home, function, origin);
                match class.zip(home.abc.string(*name).ok()) {
                    Some((class, name)) => Value::Held { class: class.ctor, name: name.bytes, through_this: class.through_this },
                    None => Value::Other,
                }
            }
            _ => Value::Other,
        }
    }

    /// The object `path`, the target of a property store in `function` of
    /// record `home`, is.
    fn holder_of(&self, home: &Home<'_, 'e>, function: u32, path: &Path) -> Holder {
        if path.cut {
            return Holder::Unknown;
        }
        match (path.origin, &path.links[..]) {
            (origin, []) => match (self.own_class(home, function, origin), origin) {
                (Some(class), _) => Holder::Class(class.ctor),
                // `this` of a method of the instance side.
                (None, Origin::This(frame)) if home.scopes.membership(frame_function(frame, function)).is_some() => Holder::Object,
                _ => Holder::Unknown,
            },
            (_, [.., NEW]) => Holder::Object,
            _ => Holder::Unknown,
        }
    }

    /// The hot-patch stub the functions of record `there` open with
    /// ([`stub::family`]); the heads of its functions are read on first use.
    fn stubs_of(&self, there: &Home<'_, 'e>) -> Option<StubKey> {
        *there.slot.stubs.get_or_init(|| {
            let regions = self.regions(there.id.entry)?;
            let methods = there.class.methods().into_iter().flatten().map_while(|method| method.ok());
            stub::family(methods.filter_map(|method| {
                let function = regions.function(there.abc, &method)?;
                stub::entry_stub(&function.code, |id| function.entity(id))
            }))
        })
    }

    /// The offset of the `return` that is not one of `function`, a function
    /// of record `there`: the one of the hot-patch stub it opens with.
    fn stub_return(&self, there: &Home<'_, 'e>, function: &Function<'_, 'e>) -> Option<usize> {
        let stub = stub::entry_stub(&function.code, |id| function.entity(id))?;
        (self.stubs_of(there) == Some(stub.key)).then_some(stub.return_pc)
    }

    /// What each `return` of the function at method offset `function` of
    /// record `there` hands back, but the one of a hot-patch stub: `None`
    /// for code that does not decode.
    fn returns_of(&self, there: &Home<'_, 'e>, function: u32) -> Option<Vec<Value<'e>>> {
        let regions = self.regions(there.id.entry)?;
        let method = there.abc.method(function).ok()?;
        let code = regions.function(there.abc, &method)?;
        let reader = Reader::new(there.scopes, function);
        let entity = |entity_id: u32| code.entity(entity_id);
        let patched = self.stub_return(there, &code);
        let (mut path, mut returned) = (Path::default(), Vec::new());
        let walked = Tracker::default().run_events(self.tables.effects(), &code.code, Watch::Objects, |frame, insn, event| {
            let Event::Return { value } = event else { return };
            if patched == Some(insn.pc) {
                return;
            }
            match &reader {
                Some(reader) => PathBuilder { frame, function, entity: &entity, lexicals: reader }.build(value, &mut path),
                None => PathBuilder { frame, function, entity: &entity, lexicals: &NoLexicals }.build(value, &mut path),
            }
            returned.push(self.value_of(there, function, &path));
        });
        walked.ok().map(|()| returned)
    }

    /// What the function at method offset `function` of record `at` (whose
    /// slot is `slot`, with scopes `scopes`) returns, for a call site of
    /// `home`. The function alone decides when it returns no static
    /// property; the stores of its record are looked at only when it does.
    fn returned_by(&self, home: &Home<'_, 'e>, at: RecordId, slot: &Slot, scopes: &Scopes, function: u32) -> Option<Made> {
        if let Some(known) = home.returned.borrow().get(&(at, function)) {
            return *known;
        }
        let returned = (|| {
            if !scopes.all_code_read() {
                return None;
            }
            let values = self.returns_of(&self.home(at, slot, scopes)?, function)?;
            if values.contains(&Value::Other) {
                return None;
            }
            if values.iter().any(|value| matches!(value, Value::Held { .. })) {
                return self.objects(slot, at)?.returned(function);
            }
            agreed(values.iter().map(|value| if let Value::Made(made) = value { Some(*made) } else { None }), |index| {
                values[index] == Value::Empty
            })
        })();
        home.returned.borrow_mut().insert((at, function), returned);
        returned
    }

    /// The objects record `id` hands out; `slot` is its slot and `scopes`
    /// are its own.
    pub(super) fn build_objects(&self, id: RecordId, slot: &Slot, scopes: &Scopes) -> RecordObjects {
        let mut out = RecordObjects::default();
        // A function that was not read could store anywhere.
        if !scopes.all_code_read() {
            return out;
        }
        let Some(regions) = self.regions(id.entry) else { return out };
        let Some(home) = self.home(id, slot, scopes) else { return out };
        let abc = home.abc;
        let mut tracker = Tracker::default();
        let mut path = Path::default();
        let mut returns: Vec<(u32, Vec<Value<'e>>)> = Vec::new();
        let mut stores: HashMap<(u32, &'e [u8]), Vec<Value<'e>>> = HashMap::new();
        // The names some store writes on an object that is not known.
        let mut loose: HashSet<&'e [u8]> = HashSet::new();
        // A malformed member list ends the record's functions.
        for method in home.class.methods().into_iter().flatten().map_while(|method| method.ok()) {
            let Some(function) = regions.function(abc, &method) else { continue };
            let offset = method.offset();
            let reader = Reader::new(scopes, offset);
            let entity = |entity_id: u32| function.entity(entity_id);
            let patched = self.stub_return(&home, &function);
            let mut returned = Vec::new();
            let walked = tracker.run_events(self.tables.effects(), &function.code, Watch::Objects, |frame, insn, event| {
                let read = |value, path: &mut Path| match &reader {
                    Some(reader) => PathBuilder { frame, function: offset, entity: &entity, lexicals: reader }.build(value, path),
                    None => PathBuilder { frame, function: offset, entity: &entity, lexicals: &NoLexicals }.build(value, path),
                };
                match event {
                    Event::Return { .. } if patched == Some(insn.pc) => {}
                    Event::Return { value } => {
                        read(value, &mut path);
                        returned.push(self.value_of(&home, offset, &path));
                    }
                    Event::PropertyStore { object, name, value } => {
                        let name = match name {
                            StringRef::Id(name) => entity(name),
                            StringRef::Offset(name) => Some(name),
                        };
                        let Some(name) = name.and_then(|name| abc.string(name).ok()).map(|name| name.bytes) else { return };
                        read(object, &mut path);
                        match self.holder_of(&home, offset, &path) {
                            Holder::Class(class) => {
                                read(value, &mut path);
                                let value = match self.value_of(&home, offset, &path) {
                                    value @ (Value::Made(_) | Value::Empty) => value,
                                    Value::Held { .. } | Value::Other => Value::Other,
                                };
                                stores.entry((class, name)).or_default().push(value);
                            }
                            Holder::Object => {}
                            Holder::Unknown => {
                                loose.insert(name);
                            }
                        }
                    }
                    _ => {}
                }
            });
            // Code that does not decode may store anywhere: nothing of the record is told.
            if walked.is_err() {
                return RecordObjects::default();
            }
            if returned.iter().any(|value| matches!(value, Value::Made(_) | Value::Held { .. })) {
                returns.push((offset, returned));
            }
        }
        let made = |value: &Value<'e>| if let Value::Made(made) = value { Some(*made) } else { None };
        for ((class, name), values) in stores.iter().filter(|((_, name), _)| !loose.contains(name)) {
            if let Some(held) = agreed(values.iter().map(made), |index| values[index] == Value::Empty) {
                out.held.entry(*class).or_default().push(Held { name: (*name).into(), made: held });
            }
        }
        for (function, values) in &returns {
            let returned = values.iter().map(|value| match *value {
                Value::Held { class, name, through_this } => out.held(class, name).map(|held| match held.of {
                    // What `C.p` holds was made by `new this()` with `C` as `this`.
                    Maker::Receiver if !through_this => Made { of: Maker::Class(ClassRef { entry: id.entry, ctor: class }), ..held },
                    Maker::Receiver | Maker::Class(_) => held,
                }),
                other => made(&other),
            });
            if let Some(returned) = agreed(returned, |index| values[index] == Value::Empty) {
                out.returned.insert(*function, returned);
            }
        }
        out.returned.shrink_to_fit();
        out.held.shrink_to_fit();
        out
    }

    /// Whether a function or a static property of record `at` (whose slot
    /// is `slot`) hands out objects of one of `classes`: the records that
    /// import `at` can then call the methods of those classes on them.
    pub(super) fn hands_out(&self, at: RecordId, slot: &Slot, classes: &HashSet<ClassRef>) -> bool {
        self.objects(slot, at).is_some_and(|objects| objects.makes_any_of(classes))
    }

    /// The object the first of `links` lead to, with the links that are
    /// left, for a path that starts at the function or class at
    /// method offset `start` of record `at` (whose slot is `slot`, with
    /// scopes `scopes`): `F().…`, `C.getter().…` for a static method the
    /// class itself lists, `C.property.…`. The names of `links` are strings
    /// of the file of `home`.
    fn made_by<'l>(
        &self,
        home: &Home<'_, 'e>,
        at: RecordId,
        slot: &Slot,
        scopes: &Scopes,
        start: u32,
        links: &'l [Link],
    ) -> Option<Handed<'l>> {
        const CALL: Link = Link::Call { construct: false };
        let name = |name: u32| home.abc.string(name).ok().map(|name| name.bytes);
        // The object, the class `new this()` stands for in it, and the links that are left.
        let (made, receiver, rest) = match links {
            [CALL, rest @ ..] => {
                let receiver = scopes.membership(start).filter(|membership| membership.is_static).map(|membership| membership.class);
                (self.returned_by(home, at, slot, scopes, start)?, receiver, rest)
            }
            [Link::Property(Some(getter)), CALL, rest @ ..] => {
                let class = ClassRef { entry: at.entry, ctor: start };
                let getter = listed(&self.abc(at.entry)?, scopes, class, true, name(*getter)?)??;
                (self.returned_by(home, at, slot, scopes, getter.method)?, Some(start), rest)
            }
            [Link::Property(Some(held)), rest @ ..] => {
                scopes.class(start)?;
                (self.objects(slot, at)?.held(start, name(*held)?)?, Some(start), rest)
            }
            _ => return None,
        };
        let class = match made.of {
            Maker::Class(class) => class,
            Maker::Receiver => ClassRef { entry: at.entry, ctor: receiver? },
        };
        Some(Handed { class, reassigned: made.reassigned, rest })
    }

    /// The function of the program [`Session::made_by`] leads to for a path
    /// that ends in one more name: the method of that name of the class,
    /// or of its nearest ancestor that lists it.
    pub(super) fn method_of_made(
        &self,
        home: &Home<'_, 'e>,
        at: RecordId,
        slot: &Slot,
        scopes: &Scopes,
        start: u32,
        links: &[Link],
    ) -> Option<(FnRef, bool)> {
        // One more name after the object, or the record is not asked what it hands out.
        let [.., Link::Call { construct: false } | Link::Property(Some(_)), Link::Property(Some(name))] = *links else { return None };
        if links.len() > 3 {
            return None;
        }
        let Handed { class, reassigned, rest } = self.made_by(home, at, slot, scopes, start, links)?;
        if rest.len() != 1 {
            return None;
        }
        let record = self.record_of(FnRef { entry: class.entry, method: class.ctor })?;
        let class_slot = self.slot(record);
        let found = self.method_of(home, class, self.scopes(&class_slot, record)?, false, name, false)?;
        Some((found.method, reassigned || found.reassigned))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_agree_on_one_class_or_none() {
        let made = |ctor| Made { of: Maker::Class(ClassRef { entry: 0, ctor }), reassigned: false };
        let empty_at = |empty: &'static [usize]| move |index: usize| empty.contains(&index);
        assert_eq!(agreed([Some(made(8)), None, Some(made(8))], empty_at(&[1])), Some(made(8)));
        // Something that is not known, two classes, no object at all.
        assert_eq!(agreed([Some(made(8)), None], empty_at(&[])), None);
        assert_eq!(agreed([Some(made(8)), Some(made(9))], empty_at(&[])), None);
        assert_eq!(agreed([None, None], empty_at(&[0, 1])), None);
        // `new this()` is not `new C()`, whichever class runs it.
        let receiver = Made { of: Maker::Receiver, reassigned: false };
        assert_eq!(agreed([Some(receiver), Some(made(8))], empty_at(&[])), None);
        assert_eq!(agreed([Some(receiver), Some(receiver)], empty_at(&[])), Some(receiver));
    }

    #[test]
    fn a_record_says_which_classes_it_hands_out() {
        let class = |ctor| ClassRef { entry: 0, ctor };
        let made = |ctor| Made { of: Maker::Class(class(ctor)), reassigned: false };
        let mut objects = RecordObjects::default();
        objects.returned.insert(40, made(8));
        objects.returned.insert(44, Made { of: Maker::Receiver, reassigned: false });
        objects.held.insert(8, vec![Held { name: b"instance".as_slice().into(), made: made(12) }]);
        assert_eq!((objects.returned(40), objects.returned(48)), (Some(made(8)), None));
        assert_eq!((objects.held(8, b"instance"), objects.held(8, b"other"), objects.held(9, b"instance")), (Some(made(12)), None, None));
        assert!(objects.makes_any_of(&HashSet::from([class(8)])) && objects.makes_any_of(&HashSet::from([class(12)])));
        assert!(!objects.makes_any_of(&HashSet::from([class(44), class(40)])));
    }
}
