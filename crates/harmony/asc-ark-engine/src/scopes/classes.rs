//! Class literals: the methods a class definition lists.
//!
//! The literal array of `defineclasswithbuffer` holds one `name, method,
//! parameter count` triple per method that has a plain name, the instance
//! methods first, then the static ones, then the number of instance methods
//! (`es2panda`; every class literal of the samples has this shape).
//! Accessors, fields and methods with computed names are defined by
//! instructions after it and are not in the literal.

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

/// The callable member of `members` (of a class of `abc`) called `name`.
pub(crate) fn find_member<'m>(abc: &Abc<'_>, members: &'m [Member], name: &[u8]) -> Option<&'m Member> {
    let mut named = members.iter().filter(|member| abc.string(member.name).is_ok_and(|other| other.bytes == name));
    // A name listed twice (a getter and a setter, a redefinition) is not decided here.
    let first = named.next()?;
    (first.callable && named.next().is_none()).then_some(first)
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
