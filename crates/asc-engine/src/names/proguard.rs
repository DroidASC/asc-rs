//! R8 / ProGuard `mapping.txt` → [`NameMappings`], the only way names other
//! than the DEX's own reach decompiled source.
//!
//! A mapping file lists each class as `original -> obfuscated:` followed by
//! indented member lines (`type name -> obf`, `[a:b:]ret name(args)[:c[:d]] -> obf`).
//! Member lines spell types with their original names, while
//! [`NameMappings`] keys use the DEX's, so every type is translated through
//! the whole class map, or taken from R8's `residualsignature` when given.
//! The class map is therefore read first: the text is scanned twice, once
//! for class lines and once for members, borrowing from it throughout.

use super::mappings::{MappingError, NameMappings, NameResolver, is_class_descriptor};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// Why a mapping file could not be read at all.
#[derive(Debug, thiserror::Error)]
pub enum ProguardError {
    #[error("reading mapping file: {0}")]
    Io(#[from] io::Error),
    #[error("reading mapping file {}: {source}", path.display())]
    File { path: PathBuf, source: io::Error },
    #[error("mapping file line {line}: {reason}")]
    Syntax { line: usize, reason: &'static str },
}

/// An entry of a mapping file that was read but not used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProguardWarning {
    /// 1-based line in the mapping file.
    pub line: usize,
    pub kind: WarningKind,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WarningKind {
    /// The same DEX name was given a second, different name; the first wins.
    #[error("{key} mapped again to {ignored}; keeping {kept}")]
    Conflict { key: String, kept: String, ignored: String },
    /// Two DEX classes claim one original name; member types written with it
    /// translate to the first.
    #[error("original class {original} mapped again from {ignored}; keeping {kept}")]
    DuplicateOriginal { original: String, kept: String, ignored: String },
    #[error(transparent)]
    Rejected(#[from] MappingError),
}

impl fmt::Display for ProguardWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "mapping file line {}: {}", self.line, self.kind)
    }
}

/// A parsed mapping file: the names, and what was skipped on the way.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProguardMapping {
    pub mappings: NameMappings,
    pub warnings: Vec<ProguardWarning>,
}

/// R8 marks classes it removed with these names; nothing in the DEX has them.
const REMOVED_CLASS: &str = "R8$$REMOVED$$CLASS$$";
const RESIDUAL_SIGNATURE: &str = "com.android.tools.r8.residualsignature";

impl NameMappings {
    /// Parse an R8 / ProGuard mapping file. Only the outermost frame of an R8
    /// inline stack names the method; members that R8 moved in from another
    /// class, identity entries and removed classes are skipped silently.
    /// Duplicates and unusable names become warnings; only lines that are
    /// not mapping syntax at all fail the parse.
    pub fn from_proguard(text: &str) -> Result<ProguardMapping, ProguardError> {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut parser = Parser::default();
        let classes = parser.read_classes(text)?;
        parser.read_members(text, &classes)?;
        Ok(ProguardMapping { mappings: parser.mappings, warnings: parser.warnings })
    }

    /// [`NameMappings::from_proguard`] on everything `reader` yields (UTF-8).
    pub fn from_proguard_reader(mut reader: impl Read) -> Result<ProguardMapping, ProguardError> {
        let mut text = String::new();
        reader.read_to_string(&mut text)?;
        NameMappings::from_proguard(&text)
    }

    /// [`NameMappings::from_proguard`] on the file at `path`.
    pub fn from_proguard_file(path: impl AsRef<Path>) -> Result<ProguardMapping, ProguardError> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path).map_err(|source| ProguardError::File { path: path.to_path_buf(), source })?;
        NameMappings::from_proguard(&text)
    }
}

/// Numbered lines with CR and trailing whitespace dropped.
fn lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines().enumerate().map(|(i, l)| (i + 1, l.trim_end()))
}

/// A class line: not indented and not a comment.
fn is_class_line(line: &str) -> bool {
    !line.is_empty() && !line.starts_with(|c: char| c.is_whitespace() || c == '#')
}

/// `orig.Name -> obf.Name:` → `(orig.Name, obf.Name)`.
fn parse_class_line(line: &str) -> Option<(&str, &str)> {
    let (original, obfuscated) = line.strip_suffix(':')?.split_once("->")?;
    let (original, obfuscated) = (original.trim(), obfuscated.trim());
    let word = |s: &str| !s.is_empty() && !s.contains(char::is_whitespace);
    (word(original) && word(obfuscated)).then_some((original, obfuscated))
}

/// `com.a.B$C` → `Lcom/a/B$C;`.
fn descriptor(binary_name: &str) -> String {
    let mut out = String::with_capacity(binary_name.len() + 2);
    push_descriptor(&mut out, binary_name);
    out
}

fn push_descriptor(out: &mut String, binary_name: &str) {
    out.push('L');
    out.extend(binary_name.chars().map(|c| if c == '.' { '/' } else { c }));
    out.push(';');
}

/// A class line as the member pass needs it.
struct Class<'a> {
    original: &'a str,
    /// The class's descriptor in the DEX, the prefix of its members' keys.
    descriptor: String,
}

#[derive(Default)]
struct Parser<'a> {
    mappings: NameMappings,
    warnings: Vec<ProguardWarning>,
    /// Original binary name → binary name in the DEX.
    obfuscated: HashMap<&'a str, &'a str>,
}

#[derive(Clone, Copy)]
enum Section {
    Class,
    Field,
    Method,
}

impl<'a> Parser<'a> {
    /// The first pass: every class line, in order (`None` for classes whose
    /// members are of no use), and the class map.
    fn read_classes(&mut self, text: &'a str) -> Result<Vec<Option<Class<'a>>>, ProguardError> {
        let mut classes = Vec::new();
        for (line, l) in lines(text).filter(|(_, l)| is_class_line(l)) {
            let (original, obfuscated) =
                parse_class_line(l).ok_or(ProguardError::Syntax { line, reason: "expected `original -> obfuscated:`" })?;
            classes.push(self.class(line, original, obfuscated));
        }
        Ok(classes)
    }

    fn class(&mut self, line: usize, original: &'a str, obfuscated: &'a str) -> Option<Class<'a>> {
        if obfuscated.starts_with(REMOVED_CLASS) {
            return None;
        }
        let dex_descriptor = descriptor(obfuscated);
        if !is_class_descriptor(&dex_descriptor) {
            self.warn(line, MappingError::Class(dex_descriptor).into());
            return None;
        }
        match self.obfuscated.entry(original) {
            Entry::Vacant(e) => {
                e.insert(obfuscated);
            }
            Entry::Occupied(e) if *e.get() != obfuscated => {
                let kind = WarningKind::DuplicateOriginal {
                    original: original.to_string(),
                    kept: e.get().to_string(),
                    ignored: obfuscated.to_string(),
                };
                self.warn(line, kind);
            }
            Entry::Occupied(_) => {}
        }
        if original != obfuscated {
            self.insert(line, Section::Class, &dex_descriptor, &descriptor(original));
        }
        Some(Class { original, descriptor: dex_descriptor })
    }

    /// The second pass: member lines, each under the class line before it.
    fn read_members(&mut self, text: &'a str, classes: &[Option<Class<'a>>]) -> Result<(), ProguardError> {
        let mut classes = classes.iter();
        let mut class: Option<&Class<'a>> = None;
        let mut seen_class = false;
        let mut pending: Option<Pending<'a>> = None;
        let mut previous: Option<Previous<'a>> = None;
        for (line, l) in lines(text) {
            let body = l.trim_start();
            if body.is_empty() {
                continue;
            }
            if let Some(comment) = body.strip_prefix('#') {
                if let (Some(p), Some(residual)) = (pending.as_mut(), residual_signature(comment)) {
                    p.residual = Some(residual);
                }
                continue;
            }
            if is_class_line(l) {
                self.flush(class, pending.take(), &mut previous);
                previous = None;
                class = classes.next().and_then(Option::as_ref);
                seen_class = true;
                continue;
            }
            if !seen_class {
                return Err(ProguardError::Syntax { line, reason: "member line before any class line" });
            }
            let member = Member::parse(body).ok_or(ProguardError::Syntax { line, reason: "expected a field or method mapping" })?;
            match (pending.as_mut(), member) {
                (Some(p), Member::Method(m)) if p.member.is_inlined_into(&m) => {
                    p.member = Member::Method(m);
                    p.line = line;
                }
                (_, member) => {
                    self.flush(class, pending.take(), &mut previous);
                    pending = Some(Pending { member, line, residual: None });
                }
            }
        }
        self.flush(class, pending, &mut previous);
        Ok(())
    }

    /// Record the member `pending` (for a method, its outermost frame).
    fn flush(&mut self, class: Option<&Class<'a>>, pending: Option<Pending<'a>>, previous: &mut Option<Previous<'a>>) {
        let (Some(class), Some(Pending { member, line, residual })) = (class, pending) else { return };
        match member {
            Member::Field(f) => {
                let Some(name) = own_name(class, f.name) else { return };
                if name == f.obfuscated {
                    return;
                }
                let mut key = format!("{}->{}:", class.descriptor, f.obfuscated);
                match &residual {
                    Some(ty) => key.push_str(ty),
                    None => self.push_type(&mut key, f.ty),
                }
                self.insert(line, Section::Field, &key, name);
            }
            Member::Method(m) => {
                // R8 writes the residual signature once, under the first
                // line range of a method; later ranges of it inherit it.
                let residual = residual.or_else(|| previous.take().filter(|p| p.method.same_method(&m)).and_then(|p| p.residual));
                *previous = Some(Previous { method: m, residual });
                let residual = previous.as_ref().and_then(|p| p.residual.as_deref());
                let Some(name) = own_name(class, m.name) else { return };
                if name == m.obfuscated || m.obfuscated.starts_with('<') {
                    return;
                }
                let mut key = format!("{}->{}", class.descriptor, m.obfuscated);
                match residual {
                    Some(proto) => key.push_str(proto),
                    None => {
                        key.push('(');
                        m.args.split(',').filter(|a| !a.trim().is_empty()).for_each(|a| self.push_type(&mut key, a));
                        key.push(')');
                        self.push_type(&mut key, m.ret);
                    }
                }
                self.insert(line, Section::Method, &key, name);
            }
        }
    }

    /// Append the DEX descriptor of the Java type `java` (`int`,
    /// `com.a.B[][]`), whose class part is an original name.
    fn push_type(&self, out: &mut String, java: &str) {
        let mut base = java.trim();
        while let Some(element) = base.strip_suffix("[]") {
            out.push('[');
            base = element.trim_end();
        }
        let primitive = match base {
            "void" => 'V',
            "boolean" => 'Z',
            "byte" => 'B',
            "char" => 'C',
            "short" => 'S',
            "int" => 'I',
            "long" => 'J',
            "float" => 'F',
            "double" => 'D',
            _ => return push_descriptor(out, self.obfuscated.get(base).copied().unwrap_or(base)),
        };
        out.push(primitive);
    }

    /// Insert unless `key` already has a name: the first entry wins, and a
    /// different second one is a warning.
    fn insert(&mut self, line: usize, section: Section, key: &str, name: &str) {
        let existing = match section {
            Section::Class => self.mappings.class(key),
            Section::Field => self.mappings.field(key),
            Section::Method => self.mappings.method(key),
        };
        if let Some(kept) = existing {
            if kept != name {
                let kind = WarningKind::Conflict { key: key.to_string(), kept: kept.to_string(), ignored: name.to_string() };
                self.warn(line, kind);
            }
            return;
        }
        let inserted = match section {
            Section::Class => self.mappings.insert_class(key, name),
            Section::Field => self.mappings.insert_field(key, name),
            Section::Method => self.mappings.insert_method(key, name),
        };
        if let Err(e) = inserted {
            self.warn(line, e.into());
        }
    }

    fn warn(&mut self, line: usize, kind: WarningKind) {
        self.warnings.push(ProguardWarning { line, kind });
    }
}

/// The simple name of a member of `class`: `name` as written, or with the
/// class's own original name as qualifier. `None` for a member qualified
/// with another class (an inlined or moved method), which this class's
/// member was not called.
fn own_name<'a>(class: &Class<'_>, name: &'a str) -> Option<&'a str> {
    match name.rsplit_once('.') {
        None => Some(name),
        Some((owner, simple)) => (owner == class.original).then_some(simple),
    }
}

/// The signature in `# {"id":"com.android.tools.r8.residualsignature","signature":"(I)V"}`.
/// Other comments, R8 metadata of other kinds included, are `None`.
fn residual_signature(comment: &str) -> Option<String> {
    let json = comment.trim_start();
    if !json.starts_with('{') || !json.contains(RESIDUAL_SIGNATURE) {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    if value.get("id")?.as_str()? != RESIDUAL_SIGNATURE {
        return None;
    }
    value.get("signature")?.as_str().map(str::to_string)
}

/// The member line the next lines may still turn out to be inlined into.
struct Pending<'a> {
    member: Member<'a>,
    /// The line of the outermost frame read so far.
    line: usize,
    residual: Option<String>,
}

/// The last method recorded in the current class, whose residual signature
/// later line ranges of the same method inherit.
struct Previous<'a> {
    method: MethodLine<'a>,
    residual: Option<String>,
}

enum Member<'a> {
    Field(FieldLine<'a>),
    Method(MethodLine<'a>),
}

/// `type name -> obfuscated`.
struct FieldLine<'a> {
    ty: &'a str,
    name: &'a str,
    obfuscated: &'a str,
}

/// `[a:b:]ret name(args)[:c[:d]] -> obfuscated`.
#[derive(Clone, Copy)]
struct MethodLine<'a> {
    /// `a:b`, the line range in the DEX; empty when absent.
    range: &'a str,
    ret: &'a str,
    /// Possibly qualified (`orig.Class.method`) for inlined frames.
    name: &'a str,
    args: &'a str,
    /// The original position is one line (`:c`), as R8 writes it for the
    /// call sites of an inline stack.
    call_site: bool,
    obfuscated: &'a str,
}

impl<'a> Member<'a> {
    fn parse(body: &'a str) -> Option<Member<'a>> {
        let (lhs, obfuscated) = body.rsplit_once("->")?;
        let (lhs, obfuscated) = (lhs.trim_end(), obfuscated.trim());
        if obfuscated.is_empty() || obfuscated.contains(char::is_whitespace) {
            return None;
        }
        let digits = lhs.find(|c: char| !(c.is_ascii_digit() || c == ':')).unwrap_or(lhs.len());
        let (range, rest) = match lhs.split_at(digits) {
            ("", rest) => ("", rest),
            (prefix, rest) => (prefix.strip_suffix(':')?, rest),
        };
        let (ty, rest) = rest.split_once(' ')?;
        let rest = rest.trim_start();
        if ty.is_empty() || rest.is_empty() {
            return None;
        }
        let Some((name, rest)) = rest.split_once('(') else {
            return (range.is_empty() && !rest.contains(char::is_whitespace)).then_some(Member::Field(FieldLine {
                ty,
                name: rest,
                obfuscated,
            }));
        };
        let (args, position) = rest.split_once(')')?;
        let numbers = match position {
            "" => 0,
            p => {
                let p = p.strip_prefix(':')?;
                if !p.split(':').all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())) {
                    return None;
                }
                p.split(':').count()
            }
        };
        if name.is_empty() || numbers > 2 {
            return None;
        }
        Some(Member::Method(MethodLine { range, ret: ty, name, args, call_site: numbers == 1, obfuscated }))
    }

    /// `next` is a caller frame of this method's inline stack: it shares the
    /// DEX method and line range and gives a single call-site line.
    fn is_inlined_into(&self, next: &MethodLine<'_>) -> bool {
        match self {
            Member::Method(m) => !m.range.is_empty() && m.range == next.range && m.obfuscated == next.obfuscated && next.call_site,
            Member::Field(_) => false,
        }
    }
}

impl MethodLine<'_> {
    /// Another line range of the same DEX method.
    fn same_method(&self, other: &MethodLine<'_>) -> bool {
        (self.obfuscated, self.ret, self.name, self.args) == (other.obfuscated, other.ret, other.name, other.args)
    }
}

#[cfg(test)]
mod tests;
