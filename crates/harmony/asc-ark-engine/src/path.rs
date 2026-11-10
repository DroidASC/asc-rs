//! Value paths: what a tracked value is, in a form that does not depend on
//! the frame it was tracked in.
//!
//! The tracker ([`crate::track`]) describes a value by links inside one
//! function's arena, with string and method ids of that function's region.
//! A [`Path`] is the same description with file offsets instead of ids and
//! the owning function spelled out for what is relative to a frame (`this`,
//! the parameters), so it can be stored for a captured variable by the
//! function that writes it and read back in another function
//! ([`crate::scopes`]), and so a call graph can look at the callee of a call
//! as data rather than as text.
//!
//! Printed (see [`crate::refs`], `call:`), a path is its origin followed by
//! its links: `import:@ohos:net.http#default.createHttp().request`.

use std::fmt::Write as _;

use asc_abc::{Abc, ModuleRecord};

use crate::text;
use crate::track::{Frame, Source, StringRef, ValueId};

/// Links of a path that are kept; a longer chain is cut and prints `…`.
pub(crate) const MAX_PATH_LINKS: usize = 16;
/// Characters of a string value that are printed.
const MAX_STRING_CHARS: usize = 96;

/// Whose `this` / parameters a path starts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum FrameOf {
    /// The running invocation of the function the path is read in.
    Own,
    /// Some invocation of the function at this method offset: the value was
    /// captured there and read through a lexical environment.
    Captured(u32),
}

/// Where a path starts.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) enum Origin {
    /// Set in another block.
    #[default]
    Unknown,
    /// Computed in the block by something the tracker does not model.
    Computed,
    This(FrameOf),
    Super(FrameOf),
    /// The function object of the frame.
    Function(FrameOf),
    NewTarget(FrameOf),
    Argument(FrameOf, u32),
    GlobalObject,
    /// A captured variable that was not resolved.
    Lexical {
        level: u32,
        slot: u32,
        sendable: bool,
    },
    /// A captured variable by the environment that holds it: an
    /// intermediate form of [`crate::scopes`], never printed.
    Slot {
        env: u32,
        slot: u32,
    },
    /// Regular import `n` of the record's module record.
    Import(u32),
    /// The namespace of module request `n`.
    Namespace(u32),
    /// Local export `n` of the record's module record.
    ModuleLocal(u32),
    /// A global binding; the file offset of its name.
    Global(Option<u32>),
    /// A function or class defined in this record; the offset of its method.
    Definition(Option<u32>),
    Str(Option<u32>),
    Int(i32),
    Float(f64),
    Constant(&'static str),
}

impl Origin {
    /// Whether the origin says what the value is, as opposed to where
    /// tracking stopped.
    pub(crate) fn is_known(self) -> bool {
        !matches!(self, Origin::Unknown | Origin::Computed | Origin::Lexical { .. } | Origin::Slot { .. })
    }

    /// The origin as a function that reads it through a lexical environment
    /// sees it: what was relative to the frame of `function` says so.
    fn captured_in(self, function: u32) -> Origin {
        let of = |frame| match frame {
            FrameOf::Own => FrameOf::Captured(function),
            captured @ FrameOf::Captured(_) => captured,
        };
        match self {
            Origin::This(frame) => Origin::This(of(frame)),
            Origin::Super(frame) => Origin::Super(of(frame)),
            Origin::Function(frame) => Origin::Function(of(frame)),
            Origin::NewTarget(frame) => Origin::NewTarget(of(frame)),
            Origin::Argument(frame, index) => Origin::Argument(of(frame), index),
            other => other,
        }
    }

    /// The origin as the invocation of `function` that owns the environment
    /// sees it: its own captured `this` is its `this`.
    fn owned_by(self, function: u32) -> Origin {
        let of = |frame| if frame == FrameOf::Captured(function) { FrameOf::Own } else { frame };
        match self {
            Origin::This(frame) => Origin::This(of(frame)),
            Origin::Super(frame) => Origin::Super(of(frame)),
            Origin::Function(frame) => Origin::Function(of(frame)),
            Origin::NewTarget(frame) => Origin::NewTarget(of(frame)),
            Origin::Argument(frame, index) => Origin::Argument(of(frame), index),
            other => other,
        }
    }
}

/// One step from a value to a value derived from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Link {
    /// `.name`; the file offset of the name.
    Property(Option<u32>),
    /// `[index]`, or `[]` for a key that is not a constant.
    Element(Option<u32>),
    /// `()`: what calling the value returned; `new value()` for a constructor.
    Call { construct: bool },
}

/// A value: its origin, then the links from the origin outward.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Path {
    pub origin: Origin,
    pub links: Vec<Link>,
    /// The chain was longer than [`MAX_PATH_LINKS`]: the origin is not the
    /// start of the value and `links` are its outermost ones.
    pub cut: bool,
}

impl Path {
    /// Whether the path names the value from a known origin on.
    pub(crate) fn is_known(&self) -> bool {
        !self.cut && self.origin.is_known()
    }

    /// `stored`, a value some function put in a captured variable, followed
    /// by the links of `self` — which is that variable read back. `own` is
    /// the reading function when the environment belongs to its own
    /// invocation.
    fn through(&mut self, stored: &Path, own: Option<u32>) {
        self.origin = own.map_or(stored.origin, |function| stored.origin.owned_by(function));
        self.links.splice(0..0, stored.links.iter().copied());
        if self.links.len() > MAX_PATH_LINKS {
            self.links.drain(..self.links.len() - MAX_PATH_LINKS);
            self.cut = true;
        }
    }

    /// The path a store of this value leaves for other functions to read:
    /// `function` is the one that stores it.
    pub(crate) fn into_captured(mut self, function: u32) -> Path {
        self.origin = self.origin.captured_in(function);
        self
    }

    /// `inner` followed by the links of `self`, for a variable (`self`)
    /// written from another captured variable (`inner`).
    pub(crate) fn after(&self, inner: &Path) -> Path {
        let mut out = Path { origin: inner.origin, links: inner.links.clone(), cut: inner.cut };
        out.links.extend_from_slice(&self.links);
        if out.links.len() > MAX_PATH_LINKS {
            out.links.drain(..out.links.len() - MAX_PATH_LINKS);
            out.cut = true;
        }
        out
    }
}

/// What a captured variable holds, as far as it is known.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Stored<'s> {
    pub path: &'s Path,
    /// The environment was made by the reading invocation itself.
    pub own_frame: bool,
}

/// How [`PathBuilder`] treats `ldlexvar level, slot` at `pc`.
pub(crate) trait Lexicals {
    /// The value the variable holds, when exactly one store can write it.
    fn stored(&self, pc: u32, level: u32, slot: u32) -> Option<Stored<'_>>;

    /// The environment that holds the variable, for the intermediate form
    /// [`Origin::Slot`].
    fn slot(&self, _pc: u32, _level: u32, _slot: u32) -> Option<Origin> {
        None
    }
}

/// Leaves every captured variable as `lex(level,slot)`.
pub(crate) struct NoLexicals;

impl Lexicals for NoLexicals {
    fn stored(&self, _: u32, _: u32, _: u32) -> Option<Stored<'_>> {
        None
    }
}

/// Turns tracked values of one function into paths.
pub(crate) struct PathBuilder<'s, L: Lexicals + ?Sized> {
    pub frame: &'s Frame,
    /// Offset of the function's method.
    pub function: u32,
    /// The file offset of an entity id of the function's region.
    pub entity: &'s dyn Fn(u32) -> Option<u32>,
    pub lexicals: &'s L,
}

impl<L: Lexicals + ?Sized> PathBuilder<'_, L> {
    fn string(&self, string: StringRef) -> Option<u32> {
        match string {
            StringRef::Id(id) => (self.entity)(id),
            StringRef::Offset(off) => Some(off),
        }
    }

    /// The path of `id`, written over `out` (whose buffer is reused).
    pub(crate) fn build(&self, id: ValueId, out: &mut Path) {
        out.links.clear();
        out.cut = false;
        let mut root = id;
        loop {
            let link = match self.frame.value(root).source {
                Source::Property { base, name } => (base, Link::Property(self.string(name))),
                Source::Element { base, index } => (base, Link::Element(index)),
                Source::CallResult { callee, construct } => (callee, Link::Call { construct }),
                _ => break,
            };
            if out.links.len() == MAX_PATH_LINKS {
                out.cut = true;
                break;
            }
            out.links.push(link.1);
            root = link.0;
        }
        out.links.reverse();
        let value = self.frame.value(root);
        out.origin = match value.source {
            Source::Unknown => Origin::Unknown,
            // Links, not origins: reached only when the chain is cut.
            Source::Computed | Source::Property { .. } | Source::Element { .. } | Source::CallResult { .. } => Origin::Computed,
            Source::This => Origin::This(FrameOf::Own),
            Source::Super => Origin::Super(FrameOf::Own),
            Source::Function => Origin::Function(FrameOf::Own),
            Source::NewTarget => Origin::NewTarget(FrameOf::Own),
            Source::GlobalObject => Origin::GlobalObject,
            Source::Argument(index) => Origin::Argument(FrameOf::Own, index),
            Source::Lexical { level, slot, sendable } => Origin::Lexical { level, slot, sendable },
            Source::Import(index) => Origin::Import(index),
            Source::Namespace(index) => Origin::Namespace(index),
            Source::ModuleLocal(index) => Origin::ModuleLocal(index),
            Source::Global(name) => Origin::Global(self.string(name)),
            Source::Definition(id) => Origin::Definition((self.entity)(id)),
            Source::Str(string) => Origin::Str(self.string(string)),
            Source::Int(value) => Origin::Int(value),
            Source::Float(value) => Origin::Float(value),
            Source::Constant(text) => Origin::Constant(text),
        };
        if out.cut {
            return;
        }
        if let Origin::Lexical { level, slot, sendable: false } = out.origin {
            if let Some(stored) = self.lexicals.stored(value.pc, level, slot) {
                out.through(stored.path, stored.own_frame.then_some(self.function));
            } else if let Some(origin) = self.lexicals.slot(value.pc, level, slot) {
                out.origin = origin;
            }
        }
    }
}

/// What printing a path reads names from.
pub(crate) struct Names<'s, 'a> {
    pub abc: &'s Abc<'a>,
    /// The module record of the record the path belongs to.
    pub module: Option<&'s ModuleRecord<'a>>,
}

impl Names<'_, '_> {
    fn string(&self, off: Option<u32>) -> String {
        off.and_then(|off| self.abc.string(off).ok()).map_or_else(|| "?".to_owned(), |name| name.to_str().into_owned())
    }

    fn request(&self, index: u16) -> String {
        self.string(self.module.and_then(|module| module.request(index)))
    }

    /// The raw name of the function at method offset `off`.
    pub(crate) fn function(&self, off: Option<u32>) -> String {
        let method = off.and_then(|off| self.abc.method(off).ok());
        method.and_then(|method| method.name().ok()).map_or_else(|| "?".to_owned(), |name| name.to_str().into_owned())
    }

    /// `REQUEST#NAME` of regular import `index`.
    pub(crate) fn import(&self, out: &mut String, index: u32) {
        let import = self.module.and_then(|module| module.regular_imports.get(index as usize));
        // Writing to a String cannot fail.
        let _ = match import {
            Some(import) => write!(out, "{}#{}", self.request(import.module_request_idx), self.string(Some(import.import_name_off))),
            None => write!(out, "?#{index}"),
        };
    }

    /// `REQUEST#*` of module request `index`.
    pub(crate) fn namespace(&self, out: &mut String, index: u32) {
        match u16::try_from(index) {
            Ok(index) => {
                out.push_str(&self.request(index));
                out.push_str("#*");
            }
            Err(_) => out.push_str("?#*"),
        }
    }

    fn frame(&self, out: &mut String, what: &str, frame: FrameOf) {
        out.push_str(what);
        if let FrameOf::Captured(function) = frame {
            out.push('@');
            out.push_str(&self.function(Some(function)));
        }
    }

    fn origin(&self, out: &mut String, origin: Origin) {
        // Writing to a String cannot fail.
        let _ = match origin {
            Origin::Unknown => out.write_str("?"),
            Origin::Computed => out.write_str("expr"),
            Origin::This(frame) => {
                self.frame(out, "this", frame);
                Ok(())
            }
            Origin::Super(frame) => {
                self.frame(out, "super", frame);
                Ok(())
            }
            Origin::Function(frame) => {
                self.frame(out, "func", frame);
                Ok(())
            }
            Origin::NewTarget(frame) => {
                self.frame(out, "new.target", frame);
                Ok(())
            }
            Origin::Argument(frame, index) => {
                self.frame(out, &format!("arg{index}"), frame);
                Ok(())
            }
            Origin::GlobalObject => out.write_str("globalThis"),
            Origin::Lexical { level, slot, sendable } => write!(out, "{}lex({level},{slot})", if sendable { "s" } else { "" }),
            Origin::Slot { env, slot } => write!(out, "lex(env{env},{slot})"),
            Origin::Import(index) => {
                out.push_str("import:");
                self.import(out, index);
                Ok(())
            }
            Origin::Namespace(index) => {
                out.push_str("import:");
                self.namespace(out, index);
                Ok(())
            }
            Origin::ModuleLocal(index) => {
                let export = self.module.and_then(|module| module.local_exports.get(index as usize));
                write!(out, "module:{}", self.string(export.map(|export| export.local_name_off)))
            }
            Origin::Global(name) => write!(out, "global:{}", self.string(name)),
            Origin::Definition(method) => write!(out, "local:{}", self.function(method)),
            Origin::Str(string) => {
                match string.and_then(|off| self.abc.string(off).ok()) {
                    Some(string) => quote_short(out, &string.to_str()),
                    None => out.push_str("\"?\""),
                }
                Ok(())
            }
            Origin::Int(value) => write!(out, "{value}"),
            Origin::Float(value) => write!(out, "{value}"),
            Origin::Constant(text) => out.write_str(text),
        };
    }

    /// Append `path` as text.
    pub(crate) fn write(&self, out: &mut String, path: &Path) {
        // `new a.B().c` reads as JavaScript does: the member of the object `new a.B()` made.
        for link in path.links.iter().rev() {
            if matches!(link, Link::Call { construct: true }) {
                out.push_str("new ");
            }
        }
        if path.cut {
            out.push('…');
        } else {
            self.origin(out, path.origin);
        }
        // Writing to a String cannot fail.
        for link in &path.links {
            match *link {
                Link::Property(name) => {
                    let _ = write!(out, ".{}", self.string(name));
                }
                Link::Element(Some(index)) => {
                    let _ = write!(out, "[{index}]");
                }
                Link::Element(None) => out.push_str("[]"),
                Link::Call { .. } => out.push_str("()"),
            }
        }
    }
}

/// `text` quoted, cut after [`MAX_STRING_CHARS`] characters.
fn quote_short(out: &mut String, text: &str) {
    match text.char_indices().nth(MAX_STRING_CHARS) {
        Some((end, _)) => {
            text::quote_into(out, &text[..end]);
            out.push('…');
        }
        None => text::quote_into(out, text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_strings_are_cut_on_a_character() {
        let mut out = String::new();
        quote_short(&mut out, "short");
        assert_eq!(out, "\"short\"");
        out.clear();
        quote_short(&mut out, &"é".repeat(MAX_STRING_CHARS + 5));
        assert_eq!(out, format!("\"{}\"…", "é".repeat(MAX_STRING_CHARS)));
    }

    #[test]
    fn captured_values_keep_their_frame() {
        let stored = Path { origin: Origin::This(FrameOf::Own), links: vec![Link::Property(Some(7))], cut: false }.into_captured(40);
        assert_eq!(stored.origin, Origin::This(FrameOf::Captured(40)));
        // Read back by the invocation that owns the environment, it is its own `this` again …
        let mut read = Path {
            origin: Origin::Lexical { level: 0, slot: 1, sendable: false },
            links: vec![Link::Call { construct: false }],
            cut: false,
        };
        read.through(&stored, Some(40));
        assert_eq!(read.origin, Origin::This(FrameOf::Own));
        assert_eq!(read.links, [Link::Property(Some(7)), Link::Call { construct: false }]);
        // … by anything else, the `this` of that function.
        let mut other = Path::default();
        other.through(&stored, None);
        assert_eq!(other.origin, Origin::This(FrameOf::Captured(40)));
        let mut nested = Path::default();
        nested.through(&stored, Some(41));
        assert_eq!(nested.origin, Origin::This(FrameOf::Captured(40)));
        // Imports and definitions are the same wherever they are read.
        assert_eq!(Origin::Import(3).captured_in(40), Origin::Import(3));
    }

    #[test]
    fn joined_paths_are_bounded() {
        let long = Path { origin: Origin::Import(0), links: vec![Link::Property(None); MAX_PATH_LINKS], cut: false };
        let mut read = Path { origin: Origin::Unknown, links: vec![Link::Element(None)], cut: false };
        read.through(&long, None);
        assert!(read.cut && read.links.len() == MAX_PATH_LINKS && read.links.last() == Some(&Link::Element(None)));
        assert!(!read.is_known() && long.is_known());
        assert!(long.after(&long).cut);
    }
}
