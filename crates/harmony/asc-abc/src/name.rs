//! Names of the dynamic flavour: mangled function names and record names.
//!
//! # Function names
//!
//! Since API 12 the compiler names a function after the scopes it is nested
//! in: `#<scope chain>#<name>`. The chain is a sequence of elements, each a
//! tag character followed by a name; the tag of the last element describes
//! the function itself, whose name follows the second `#`:
//!
//! | tag | scope |
//! |-----|-------|
//! | `~` | class |
//! | `&` | namespace |
//! | `%` | enum |
//! | `*` | function |
//! | `>` | instance method |
//! | `<` | static method |
//! | `=` | constructor |
//!
//! A name is empty (anonymous), plain, or `@<hex>`: an index into the
//! record's `scopeNames` literal array, used for names that are long or
//! contain tag characters. `^<hex>` after a name tells apart several scopes
//! of the same name in the same parent. So `#~@0>@1*#^1` is the second
//! anonymous function inside instance method `scopeNames[1]` of class
//! `scopeNames[0]`.
//!
//! Older files use `#<number>#<name>` (the number identifies the scope and
//! cannot be taken apart) or plain names; `func_main_0` is always the module
//! body.
//!
//! Sources: `libabckit/src/adapter_dynamic/abckit_dynamic.cpp`
//! (`GetParentKindAndName`, `DemangleScope`) and
//! `panda_guard/obfuscate/function.cpp` (`FUNCTION_TYPE_MAP`).

use std::borrow::Cow;
use std::fmt::Write as _;

/// What a scope chain element is (its tag character).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopeKind {
    Class,
    Namespace,
    Enum,
    Function,
    InstanceMethod,
    StaticMethod,
    Constructor,
}

impl ScopeKind {
    fn from_tag(tag: u8) -> Option<ScopeKind> {
        Some(match tag {
            b'~' => ScopeKind::Class,
            b'&' => ScopeKind::Namespace,
            b'%' => ScopeKind::Enum,
            b'*' => ScopeKind::Function,
            b'>' => ScopeKind::InstanceMethod,
            b'<' => ScopeKind::StaticMethod,
            b'=' => ScopeKind::Constructor,
            _ => return None,
        })
    }
}

/// The name part of a scope chain element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopeIdent<'a> {
    Anonymous,
    Named(&'a str),
    /// `@<hex>`: index into the record's `scopeNames` literal array.
    Indexed(u32),
}

/// One element of a scope chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Scope<'a> {
    pub kind: ScopeKind,
    pub ident: ScopeIdent<'a>,
    /// The `^<hex>` suffix: which of several same-named scopes this is.
    pub duplicate: Option<u32>,
}

impl<'a> Scope<'a> {
    /// Parse the text after a tag character. Text that does not follow the
    /// `@<hex>` / `^<hex>` forms is kept as a plain name.
    fn parse(kind: ScopeKind, text: &'a str) -> Scope<'a> {
        let (base, duplicate) = match text.rsplit_once('^').and_then(|(base, n)| Some((base, parse_hex(n)?))) {
            Some((base, n)) => (base, Some(n)),
            None => (text, None),
        };
        let ident = match base.strip_prefix('@').and_then(parse_hex) {
            Some(index) => ScopeIdent::Indexed(index),
            None if base.is_empty() => ScopeIdent::Anonymous,
            None => ScopeIdent::Named(base),
        };
        Scope { kind, ident, duplicate }
    }
}

/// Lowercase hex without sign or prefix, as the compiler writes indexes.
fn parse_hex(text: &str) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    u32::from_str_radix(text, 16).ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Form<'a> {
    /// Not mangled.
    Plain,
    /// `#<number>#<name>`.
    Numbered { scope: &'a str, name: &'a str },
    /// `#<scope chain>#<name>`; `chain` ends with the function's own tag.
    Scoped { chain: &'a str, name: &'a str },
}

/// A function name taken apart. The raw name stays available: it is the
/// canonical one, the only form that can be looked up in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionName<'a> {
    raw: &'a str,
    form: Form<'a>,
}

impl<'a> FunctionName<'a> {
    /// Name of the function holding a module's top-level code.
    pub const MAIN: &'static str = "func_main_0";

    /// Take a raw method name apart. Never fails: a name that does not
    /// follow a known scheme is kept as a plain name.
    pub fn parse(raw: &'a str) -> FunctionName<'a> {
        // The chain cannot contain `#` (names with special characters go
        // through `scopeNames`), so the second `#` ends it.
        let form = match raw.strip_prefix('#').and_then(|rest| rest.split_once('#')) {
            Some((chain, name)) if chain.bytes().next().is_some_and(|tag| ScopeKind::from_tag(tag).is_some()) => {
                Form::Scoped { chain, name }
            }
            Some((scope, name)) if !scope.is_empty() => Form::Numbered { scope, name },
            Some(_) | None => Form::Plain,
        };
        FunctionName { raw, form }
    }

    #[inline]
    pub fn raw(&self) -> &'a str {
        self.raw
    }

    /// Whether this is the module body, `func_main_0`.
    pub fn is_main(&self) -> bool {
        self.raw == Self::MAIN
    }

    /// Whether the name follows the scope chain scheme.
    pub fn is_scoped(&self) -> bool {
        matches!(self.form, Form::Scoped { .. })
    }

    /// The scope chain from the outermost scope to the function itself (the
    /// last element). Empty for names without a scope chain.
    pub fn scopes(&self) -> impl Iterator<Item = Scope<'a>> + 'a + use<'a> {
        let (mut chain, name) = match self.form {
            Form::Scoped { chain, name } => (chain, name),
            Form::Plain | Form::Numbered { .. } => ("", ""),
        };
        std::iter::from_fn(move || {
            let kind = ScopeKind::from_tag(*chain.as_bytes().first()?)?;
            // Tags are ASCII, so slicing after the first byte is on a boundary.
            let rest = &chain[1..];
            let end = rest.bytes().position(|b| ScopeKind::from_tag(b).is_some());
            let text = match end {
                Some(end) => &rest[..end],
                // The last tag belongs to the function; its name follows the `#`.
                None => name,
            };
            chain = end.map_or("", |end| &rest[end..]);
            Some(Scope::parse(kind, text))
        })
    }

    /// The function's own scope element: its kind, name and duplicate index.
    /// `None` for names without a scope chain.
    pub fn function(&self) -> Option<Scope<'a>> {
        self.scopes().last()
    }

    /// The function's own name without scopes or duplicate suffix; empty
    /// for an anonymous function.
    pub fn base_name(&self) -> &'a str {
        match self.form {
            Form::Plain => self.raw,
            Form::Numbered { name, .. } => name,
            Form::Scoped { .. } => match self.function().map(|scope| scope.ident) {
                Some(ScopeIdent::Named(name)) => name,
                Some(ScopeIdent::Anonymous | ScopeIdent::Indexed(_)) | None => "",
            },
        }
    }

    /// A readable dotted name such as `EntryAbility.onCreate`.
    ///
    /// `scope_name` resolves a `scopeNames` index (see
    /// [`crate::Class::scope_name`]); an index it cannot resolve is printed
    /// as `@<hex>`. Anonymous scopes print as `<anonymous>`, a constructor
    /// inside a class as `constructor`, duplicate suffixes are kept
    /// (`^1`). Names without a scope chain print their own name.
    pub fn restore<'s>(&self, mut scope_name: impl FnMut(u32) -> Option<Cow<'s, str>>) -> String {
        let anonymous = |name: &'a str| if name.is_empty() { "<anonymous>" } else { name };
        let mut out = String::with_capacity(self.raw.len());
        match self.form {
            Form::Plain => out.push_str(self.raw),
            Form::Numbered { name, .. } => out.push_str(anonymous(name)),
            Form::Scoped { .. } => {
                let mut parent = None;
                for scope in self.scopes() {
                    if parent.is_some() {
                        out.push('.');
                    }
                    match scope.ident {
                        _ if scope.kind == ScopeKind::Constructor && parent == Some(ScopeKind::Class) => out.push_str("constructor"),
                        ScopeIdent::Anonymous => out.push_str(anonymous("")),
                        ScopeIdent::Named(name) => out.push_str(name),
                        ScopeIdent::Indexed(index) => match scope_name(index) {
                            Some(name) => out.push_str(&name),
                            None => {
                                // Writing to a String cannot fail.
                                let _ = write!(out, "@{index:x}");
                            }
                        },
                    }
                    if let Some(n) = scope.duplicate {
                        let _ = write!(out, "^{n:x}");
                    }
                    parent = Some(scope.kind);
                }
            }
        }
        out
    }
}

/// What a record stands for, judged by its name ([`RecordName::kind`]) or,
/// for a record of the file, by the record ([`crate::Class::kind`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    /// A source module (one `.ets` / `.ts` / `.js` file).
    Module,
    /// A compiler-internal record: the `_ES…` annotation interfaces and
    /// tables (`_ESSlotNumberAnnotation`, `_ESTypeInfoRecord` …).
    Service,
    /// A placeholder for a native system module (`@ohos.app`,
    /// `@system.router` …): no code, one `@native.…` field.
    SystemModule,
    /// An annotation interface the program declares (`@interface`): no
    /// code, one field per element with its default value.
    Annotation,
}

/// A record name taken apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordName<'a> {
    /// Normalized OHM URL form `<bundle>&<package>/<path>&<version>`:
    /// `&entry/src/main/ets/pages/Index&`, `&@ohos/crypto-js/index&2.0.0`.
    /// `bundle` is empty for the application's own bundle, `version` for
    /// its own modules.
    Normalized { bundle: &'a str, package: &'a str, path: &'a str, version: &'a str },
    /// Bundle form `<bundle>/<module>/<path>`:
    /// `com.hmos.exam5.pkg/entry/ets/pages/Home`.
    Bundle { bundle: &'a str, module: &'a str, path: &'a str },
    /// An annotation interface declared in a module of the normalized
    /// form, `<module record>.<Interface>`:
    /// `&entry/src/main/ets/Marks&.Marked`, `&@ohos/lib/index&1.2.0.Marked`.
    /// `module` is the record name of the module, itself of the
    /// [`RecordName::Normalized`] form. Wherever in the module it is
    /// declared, the interface has no qualifier.
    ///
    /// A name alone does not always tell: `&lib/index&1.0.0-beta.rc` is a
    /// module of version `1.0.0-beta.rc` or the interface `rc` of version
    /// `1.0.0-beta`, and is read as the interface. [`crate::Class::is_annotation`]
    /// says which it is for a record of the file.
    Annotation { module: &'a str, interface: &'a str },
    /// See [`RecordKind::Service`].
    Service(&'a str),
    /// See [`RecordKind::SystemModule`].
    SystemModule(&'a str),
    /// Anything else; treated as a module.
    Other(&'a str),
}

impl<'a> RecordName<'a> {
    /// Classify and split a record name (a class descriptor without its
    /// `L` … `;`, see [`crate::Class::name`]).
    pub fn parse(name: &'a str) -> RecordName<'a> {
        if name.starts_with("_ES") {
            return RecordName::Service(name);
        }
        if let Some((bundle, rest)) = name.split_once('&')
            && let Some((module_path, version)) = rest.rsplit_once('&')
        {
            if let Some(interface) = interface_after(version) {
                return RecordName::Annotation { module: &name[..name.len() - interface.len() - 1], interface };
            }
            // A scoped package (`@ohos/crypto-js`) spans two segments.
            let package_segments = if module_path.starts_with('@') { 2 } else { 1 };
            let split = module_path.match_indices('/').nth(package_segments - 1).map_or(module_path.len(), |(i, _)| i);
            let (package, path) = module_path.split_at(split);
            return RecordName::Normalized { bundle, package, path: path.strip_prefix('/').unwrap_or(path), version };
        }
        if name.starts_with('@') && !name.contains('/') {
            return RecordName::SystemModule(name);
        }
        let mut segments = name.splitn(3, '/');
        match (segments.next(), segments.next(), segments.next()) {
            (Some(bundle), Some(module), Some(path)) if !name.contains('&') => RecordName::Bundle { bundle, module, path },
            _ => RecordName::Other(name),
        }
    }

    pub fn kind(&self) -> RecordKind {
        match self {
            RecordName::Normalized { .. } | RecordName::Bundle { .. } | RecordName::Other(_) => RecordKind::Module,
            RecordName::Annotation { .. } => RecordKind::Annotation,
            RecordName::Service(_) => RecordKind::Service,
            RecordName::SystemModule(_) => RecordKind::SystemModule,
        }
    }

    /// Whether the record is compiler furniture rather than application
    /// code; a class listing hides these by default.
    pub fn is_pseudo(&self) -> bool {
        match self.kind() {
            RecordKind::Module | RecordKind::Annotation => false,
            RecordKind::Service | RecordKind::SystemModule => true,
        }
    }

    /// The module an annotation interface is declared in; `None` for any
    /// other record.
    pub fn module(&self) -> Option<RecordName<'a>> {
        match *self {
            RecordName::Annotation { module, .. } => Some(RecordName::parse(module)),
            RecordName::Normalized { .. }
            | RecordName::Bundle { .. }
            | RecordName::Service(_)
            | RecordName::SystemModule(_)
            | RecordName::Other(_) => None,
        }
    }

    /// The package (`entry`, `@ohos/crypto-js`) or module the record
    /// belongs to; `None` for names that do not say.
    pub fn package(&self) -> Option<&'a str> {
        match *self {
            RecordName::Normalized { package, .. } => Some(package),
            RecordName::Bundle { module, .. } => Some(module),
            RecordName::Annotation { .. } => self.module().and_then(|module| module.package()),
            RecordName::Service(_) | RecordName::SystemModule(_) | RecordName::Other(_) => None,
        }
    }

    /// The path of the source file inside its package, without extension
    /// (`src/main/ets/pages/Index`, `ets/pages/Home`), for an annotation
    /// interface the one of its module; the whole name when it has no such
    /// structure.
    pub fn path(&self) -> &'a str {
        match *self {
            RecordName::Normalized { path, .. } | RecordName::Bundle { path, .. } => path,
            RecordName::Annotation { module, .. } => self.module().map_or(module, |module| module.path()),
            RecordName::Service(name) | RecordName::SystemModule(name) | RecordName::Other(name) => name,
        }
    }
}

/// The interface name `tail` ends with, `tail` being what follows the
/// second `&` of a normalized name: `Marked` of `.Marked` and of
/// `1.2.0.Marked`, nothing of `1.2.0` or `1.0.0-rc.1` (a name does not
/// start with a digit, the last part of a version mostly does).
fn interface_after(tail: &str) -> Option<&str> {
    let (_, interface) = tail.rsplit_once('.')?;
    let mut chars = interface.chars();
    let starts = chars.next().is_some_and(|first| first == '_' || first == '$' || first.is_alphabetic());
    (starts && chars.all(|c| c == '_' || c == '$' || c.is_alphanumeric())).then_some(interface)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scopes(raw: &str) -> Vec<(ScopeKind, ScopeIdent<'_>, Option<u32>)> {
        FunctionName::parse(raw).scopes().map(|s| (s.kind, s.ident, s.duplicate)).collect()
    }

    #[test]
    fn parses_scope_chains() {
        use ScopeIdent::{Anonymous, Indexed, Named};
        use ScopeKind::{Class, Constructor, Enum, Function, InstanceMethod, Namespace, StaticMethod};

        assert_eq!(scopes("#~@0>#build"), [(Class, Indexed(0), None), (InstanceMethod, Named("build"), None)]);
        assert_eq!(scopes("#~@0>@1*#^1"), [(Class, Indexed(0), None), (InstanceMethod, Indexed(1), None), (Function, Anonymous, Some(1))]);
        assert_eq!(scopes("#~@0=#EntryAbility"), [(Class, Indexed(0), None), (Constructor, Named("EntryAbility"), None)]);
        assert_eq!(scopes("#~i<#j"), [(Class, Named("i"), None), (StaticMethod, Named("j"), None)]);
        assert_eq!(scopes("#*#"), [(Function, Anonymous, None)]);
        assert_eq!(scopes("#%#Color"), [(Enum, Named("Color"), None)]);
        assert_eq!(scopes("#&@1f*#helper"), [(Namespace, Indexed(0x1f), None), (Function, Named("helper"), None)]);
        assert_eq!(
            scopes("#*^2f**^10*#exports^a"),
            [
                (Function, Anonymous, Some(0x2f)),
                (Function, Anonymous, None),
                (Function, Anonymous, Some(0x10)),
                (Function, Named("exports"), Some(0xa))
            ]
        );
        // Not hex: the caret stays part of the name.
        assert_eq!(scopes("#*#a^G"), [(Function, Named("a^G"), None)]);
        assert_eq!(scopes("#*#?4f7e"), [(Function, Named("?4f7e"), None)]);
        assert_eq!(scopes("func_main_0"), []);
        assert_eq!(scopes("#14695981039346656037#"), []);
    }

    #[test]
    fn classifies_name_schemes() {
        let main = FunctionName::parse("func_main_0");
        assert!(main.is_main() && !main.is_scoped());
        assert_eq!((main.base_name(), main.function()), ("func_main_0", None));

        let numbered = FunctionName::parse("#9779998206303373654#errorText");
        assert!(!numbered.is_scoped());
        assert_eq!(numbered.base_name(), "errorText");
        assert_eq!(FunctionName::parse("#1016906796659230483_1#").base_name(), "");

        let method = FunctionName::parse("#~@0>#onCreate");
        assert_eq!(method.raw(), "#~@0>#onCreate");
        assert_eq!(method.base_name(), "onCreate");
        assert_eq!(method.function().map(|s| s.kind), Some(ScopeKind::InstanceMethod));
        assert_eq!(FunctionName::parse("#~@0>@1*#^1").base_name(), "");

        // Degenerate input stays a plain name.
        for raw in ["", "#", "##", "##x", "#abc", "~@0>#x"] {
            let name = FunctionName::parse(raw);
            assert!(!name.is_scoped(), "{raw}");
            assert_eq!(name.scopes().count(), 0, "{raw}");
        }
    }

    #[test]
    fn restores_readable_names() {
        let names = ["EntryAbility", "onWindowStageCreate"];
        let lookup = |i: u32| names.get(i as usize).map(|&n| Cow::Borrowed(n));
        let restore = |raw: &str| FunctionName::parse(raw).restore(lookup);
        assert_eq!(restore("#~@0>#onCreate"), "EntryAbility.onCreate");
        assert_eq!(restore("#~@0>@1*#^1"), "EntryAbility.onWindowStageCreate.<anonymous>^1");
        assert_eq!(restore("#~@0=#EntryAbility"), "EntryAbility.constructor");
        assert_eq!(restore("#~@0=@1*#cb"), "EntryAbility.constructor.cb");
        assert_eq!(restore("#~@7>#x"), "@7.x");
        assert_eq!(restore("#*#"), "<anonymous>");
        assert_eq!(restore("#=#Legacy"), "Legacy");
        assert_eq!(restore("#*#exports^a"), "exports^a");
        assert_eq!(restore("func_main_0"), "func_main_0");
        assert_eq!(restore("#5#cipherTool"), "cipherTool");
        assert_eq!(restore("#8#"), "<anonymous>");
    }

    #[test]
    fn parses_record_names() {
        assert_eq!(
            RecordName::parse("&entry/src/main/ets/pages/Index&"),
            RecordName::Normalized { bundle: "", package: "entry", path: "src/main/ets/pages/Index", version: "" }
        );
        assert_eq!(
            RecordName::parse("&@ohos/crypto-js/index&2.0.0"),
            RecordName::Normalized { bundle: "", package: "@ohos/crypto-js", path: "index", version: "2.0.0" }
        );
        assert_eq!(
            RecordName::parse("com.other.app&lib/Index&1.0.0"),
            RecordName::Normalized { bundle: "com.other.app", package: "lib", path: "Index", version: "1.0.0" }
        );
        assert_eq!(RecordName::parse("&entry&"), RecordName::Normalized { bundle: "", package: "entry", path: "", version: "" });
        let bundle = RecordName::parse("com.hmos.exam5.pkg/entry/ets/pages/Home");
        assert_eq!(bundle, RecordName::Bundle { bundle: "com.hmos.exam5.pkg", module: "entry", path: "ets/pages/Home" });
        assert_eq!((bundle.kind(), bundle.package(), bundle.path()), (RecordKind::Module, Some("entry"), "ets/pages/Home"));

        for name in ["_ESSlotNumberAnnotation", "_ESTypeAnnotation", "_ESTypeInfoRecord", "_ESConcurrentModuleRequestsAnnotation"] {
            assert_eq!(RecordName::parse(name), RecordName::Service(name));
            assert!(RecordName::parse(name).is_pseudo());
        }
        assert_eq!(RecordName::parse("@ohos.app"), RecordName::SystemModule("@ohos.app"));
        assert_eq!(RecordName::parse("@system.router").kind(), RecordKind::SystemModule);
        assert!(!RecordName::parse("&@ohos/crypto-js/index&2.0.0").is_pseudo());
        assert_eq!(RecordName::parse("a/b"), RecordName::Other("a/b"));
        assert_eq!(RecordName::parse("only&one"), RecordName::Other("only&one"));
        assert_eq!(RecordName::parse(""), RecordName::Other(""));
        assert_eq!(RecordName::parse("&"), RecordName::Other("&"));
    }

    #[test]
    fn parses_annotation_interface_names() {
        let own = RecordName::parse("&entry/src/main/ets/Marks&.Marked");
        assert_eq!(own, RecordName::Annotation { module: "&entry/src/main/ets/Marks&", interface: "Marked" });
        assert_eq!((own.kind(), own.is_pseudo()), (RecordKind::Annotation, false));
        assert_eq!((own.package(), own.path()), (Some("entry"), "src/main/ets/Marks"));
        assert_eq!(own.module(), Some(RecordName::Normalized { bundle: "", package: "entry", path: "src/main/ets/Marks", version: "" }));

        // After a version, and after one whose last part is not a name.
        let library = RecordName::parse("&@ohos/lib/src/marks&1.2.3.Marked");
        assert_eq!(library, RecordName::Annotation { module: "&@ohos/lib/src/marks&1.2.3", interface: "Marked" });
        assert_eq!(
            library.module(),
            Some(RecordName::Normalized { bundle: "", package: "@ohos/lib", path: "src/marks", version: "1.2.3" })
        );
        assert_eq!(
            RecordName::parse("com.other.app&lib/marks&1.0.0-rc.1._$Mark2"),
            RecordName::Annotation { module: "com.other.app&lib/marks&1.0.0-rc.1", interface: "_$Mark2" }
        );
        assert_eq!(RecordName::parse("com.other.app&lib/marks&1.0.0-rc.1._$Mark2").package(), Some("lib"));

        // A version is not an interface, whatever it ends with.
        for (name, version) in [
            ("&lib/index&1.0.0-rc.1", "1.0.0-rc.1"),
            ("&lib/index&2.0.0", "2.0.0"),
            ("&lib/index&1.0.", "1.0."),
            ("&lib/index&beta", "beta"),
        ] {
            assert_eq!(RecordName::parse(name), RecordName::Normalized { bundle: "", package: "lib", path: "index", version }, "{name}");
            assert_eq!(RecordName::parse(name).module(), None);
        }
        // Only the normalized form says where the module name ends.
        assert_eq!(RecordName::parse("Marked"), RecordName::Other("Marked"));
        assert_eq!(RecordName::parse("com.example.app/entry/ets/Marks.Marked").kind(), RecordKind::Module);
    }
}
