//! The members of a class: the methods its definition lists, and the ones
//! instructions after it add.
//!
//! The literal array of `defineclasswithbuffer` holds one `name, method,
//! parameter count` triple per method that has a plain name, the instance
//! methods first, then the static ones, then the number of instance methods
//! (`es2panda`; every class literal of the samples has this shape). It
//! stops at the first member that is not such a method: from an accessor
//! or a method with a computed name on, the members of the class body are
//! defined one by one after the class (checked against what the official
//! compiler emits):
//!
//! - a method: `lda HOME; definemethod M; stownbyname NAME, HOME`, where
//!   `HOME` is the class (a static method) or its `prototype`;
//! - an accessor: `definemethod M` for the getter and / or the setter, then
//!   `definegettersetterbyvalue HOME, NAME, GETTER, SETTER`;
//! - the field initializers: `definemethod` of `static_initializer` (called
//!   at once with the class as `this`) and `instance_initializer`.
//!
//! [`super::Scopes`] reads those when the home object is tracked to a class
//! of the record: the named ones become members (an accessor one that is
//! not callable), and every such function is a method of its class, with
//! its `this` and `super`. Fields and methods with computed names are not
//! members.

use asc_abc::{Abc, Literal};

use crate::refs::MAX_LITERAL_DEPTH;

/// A method of a class literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Member {
    /// File offset of its name.
    pub name: u32,
    pub method: u32,
    /// Not a getter or setter: calling the property calls this function.
    pub callable: bool,
}

/// The methods a class definition lists in its literal array.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ClassInfo {
    pub instance: Vec<Member>,
    pub statics: Vec<Member>,
}

/// Which side of a class a function is a method of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Membership {
    /// Method offset of the class constructor.
    pub class: u32,
    pub is_static: bool,
}

/// What the members of one side of a class say about a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Named<'m> {
    /// No member has the name: a lookup goes on to the parent class.
    Absent,
    /// One callable member has it.
    One(&'m Member),
    /// The name is listed twice (a getter and a setter, a redefinition) or
    /// names an accessor: what calling it runs is not decided here.
    Undecided,
}

/// What `members` (of a class of `abc`) list under `name`.
pub(crate) fn member_named<'m>(abc: &Abc<'_>, members: &'m [Member], name: &[u8]) -> Named<'m> {
    let mut named = members.iter().filter(|member| abc.string(member.name).is_ok_and(|other| other.bytes == name));
    match (named.next(), named.next()) {
        (None, _) => Named::Absent,
        (Some(only), None) if only.callable => Named::One(only),
        (Some(_), _) => Named::Undecided,
    }
}

/// Every method item of the literal array at `off`, nested arrays included.
pub(super) fn literal_methods(abc: &Abc<'_>, off: u32, depth: usize, found: &mut dyn FnMut(u32)) {
    let Ok(array) = abc.literal_array(off) else { return };
    for literal in array.iter().map_while(|literal| literal.ok()) {
        match literal {
            Literal::LiteralArray(nested) if depth < MAX_LITERAL_DEPTH => literal_methods(abc, nested, depth + 1, found),
            other => {
                if let Some(method) = other.method_off() {
                    found(method);
                }
            }
        }
    }
}

/// The members of a class literal: `name, method, parameter count` triples,
/// the instance methods first, then the number of instance methods.
pub(super) fn class_literal(abc: &Abc<'_>, off: u32) -> Option<ClassInfo> {
    let array = abc.literal_array(off).ok()?;
    let mut items = array.iter();
    let mut members = Vec::new();
    let instance_count = loop {
        match items.next()?.ok()? {
            Literal::String(name) => {
                let method = items.next()?.ok()?;
                let callable = matches!(method, Literal::Method(_) | Literal::GeneratorMethod(_) | Literal::AsyncGeneratorMethod(_));
                let Literal::MethodAffiliate(_) = items.next()?.ok()? else { return None };
                members.push(Member { name, method: method.method_off()?, callable });
            }
            Literal::Integer(count) => break usize::try_from(count).ok()?,
            _ => return None,
        }
    };
    if instance_count > members.len() {
        return None;
    }
    let statics = members.split_off(instance_count);
    Some(ClassInfo { instance: members, statics })
}
