//! Class-name normalisation shared by the CLI and MCP.

use crate::{EngineError, Result};
use asc_findrefs::{ClassQuery, MemberQuery, MemberSignature, Query, TypeMatch};

/// Turn `com.poc.Main` / `com/poc/Main` / `Lcom/poc/Main;` into a Dalvik descriptor.
/// Array descriptors (`[Ljava/lang/Object;`, whose methods such as `clone`
/// are referenced like any class's) are kept as they are.
pub fn format_class_name(name: &str) -> Result<String> {
    if name.is_empty() {
        return Err(EngineError::Query("Class name cannot be empty".into()));
    }
    if (name.starts_with('L') && name.ends_with(';') && name.contains('/')) || name.starts_with('[') {
        return Ok(name.to_string());
    }
    let mut n = name.replace('.', "/");
    if !n.starts_with('L') {
        n.insert(0, 'L');
    }
    if !n.ends_with(';') {
        n.push(';');
    }
    Ok(n)
}

/// `Lcom/poc/Main;` → `com/poc/Main`: the descriptor's own `L` / `;` removed,
/// package separators kept. Only the leading `L` is syntax, so
/// `Lpkg/LLoader;` → `pkg/LLoader` while `LLoader;` is class `Loader`.
pub fn class_inner(descriptor: &str) -> &str {
    let d = descriptor.strip_prefix('L').unwrap_or(descriptor);
    d.strip_suffix(';').unwrap_or(d)
}

/// `Lcom/poc/Main;` → `com.poc.Main` (other inputs unchanged).
pub fn dalvik_to_dot(name: &str) -> String {
    if name.starts_with('L') && name.ends_with(';') {
        name[1..name.len() - 1].replace('/', ".")
    } else {
        name.to_string()
    }
}

/// Normalise a `listclass` prefix: `com.poc` / `com/poc` become `Lcom/poc`,
/// a prefix already starting with `L` is used as is (like the Python tool).
pub fn class_prefix(prefix: &str) -> Result<String> {
    let p = prefix.trim();
    if p.is_empty() {
        return Err(EngineError::Query("Class prefix cannot be empty".into()));
    }
    if p.starts_with('L') {
        return Ok(p.to_string());
    }
    Ok(format!("L{}", p.replace('.', "/")))
}

/// Normalise a class query: fuzzy patterns only get their dots swapped for
/// slashes, precise names become full descriptors.
pub fn normalize_class_query(name: &str, fuzzy: bool) -> Result<String> {
    if fuzzy {
        if name.contains('.') && !name.contains('/') {
            return Ok(name.replace('.', "/"));
        }
        return Ok(name.to_string());
    }
    format_class_name(name)
}

/// A method / field target as agents write it, split into its parts. Every
/// field borrows from the spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberTarget<'a> {
    /// The class part, as written (`Lcom/a/B;`, `com.a.B`, `B`, `~pattern`).
    pub class: Option<&'a str>,
    /// The member name (or name pattern).
    pub name: &'a str,
    /// What followed the name: `(params)ret` of a method, `:T` of a field.
    pub signature: Option<&'a str>,
}

impl<'a> MemberTarget<'a> {
    /// Split `Lcom/a/B;->name(sig)ret`, `Lcom/a/B;->name`, `Lc;->f:T`,
    /// `com.a.B->name`, `com.a.B#name`, `com.a.B.name` or `B.name`; a bare
    /// name (or name pattern) has no class. A dot only separates the class
    /// when what precedes it reads as a class (identifiers, the last one
    /// capitalised: `WebView.loadUrl`, not the regex `get.*Id`).
    pub fn parse(spec: &'a str) -> MemberTarget<'a> {
        let s = spec.trim();
        let (class, member) = if let Some((c, m)) = s.split_once("->") {
            (Some(c.trim()), m.trim())
        } else if let Some((c, m)) = s.rsplit_once('#') {
            (Some(c.trim()), m.trim())
        } else if let Some(i) = dotted_member_split(s) {
            (Some(&s[..i]), &s[i + 1..])
        } else {
            (None, s)
        };
        let (name, signature) = match member.find(['(', ':']) {
            Some(i) if is_member_name(&member[..i]) => (&member[..i], Some(&member[i..])),
            _ => (member, None),
        };
        MemberTarget { class: class.filter(|c| !c.is_empty()), name, signature }
    }
}

/// `[A-Za-z_$][A-Za-z0-9_$]*`, the identifiers of Java class paths and members
/// (obfuscators stay within it; non-ASCII names are left to `->`).
fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_' || c == '$')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

fn is_member_name(s: &str) -> bool {
    is_identifier(s) || s == "<init>" || s == "<clinit>"
}

/// The index of the dot separating `com.a.B` from `name` in `com.a.B.name`
/// (also `com/a/B.name`), if `spec` reads that way.
fn dotted_member_split(spec: &str) -> Option<usize> {
    let head_end = spec.find(['(', ':']).unwrap_or(spec.len());
    let head = &spec[..head_end];
    let i = head.rfind('.')?;
    let (class, name) = (&head[..i], &head[i + 1..]);
    let segments: Vec<&str> = class.split(['.', '/']).collect();
    let capitalised = segments.last().is_some_and(|l| l.starts_with(|c: char| c.is_ascii_uppercase()));
    let classlike = segments.iter().all(|s| is_identifier(s));
    // A signature or a constructor name settles it; otherwise Java naming does.
    let member_evident = head_end < spec.len() || name.starts_with('<');
    (classlike && is_member_name(name) && (capitalised || member_evident)).then_some(i)
}

/// Whether `spec` names a class rather than a member: `Lcom/a/B;` or a dotted
/// `com.a.B` whose last part is capitalised.
pub fn looks_like_class(spec: &str) -> bool {
    let s = spec.trim();
    if s.starts_with('L') && s.ends_with(';') && !s.contains("->") {
        return true;
    }
    let segments: Vec<&str> = s.split('.').collect();
    segments.len() > 1
        && segments.iter().all(|seg| is_identifier(seg))
        && segments.last().is_some_and(|l| l.starts_with(|c: char| c.is_ascii_uppercase()))
}

/// A class written without its package (`WebView`, `Build$VERSION`): a fuzzy
/// pattern for every class of that simple name. Fuzzy patterns run over the
/// whole string data, so the descriptor's end is its `;` and NUL terminator.
/// A descriptor (`Lx;`) is exact even without a package.
fn simple_class_pattern(name: &str) -> Option<String> {
    (is_identifier(name) && name != "L").then(|| format!("[/L]{};\\x00", regex::escape(name)))
}

/// Build a member (method/field) query from CLI-style arguments; `exact_name`
/// matches the member name as a whole instead of as a substring / regex.
///
/// Lenient about where the class is written: `name` may carry it
/// ([`MemberTarget::parse`] forms, used when `class` is not given), `class`
/// may carry `->name`, and a `name` that is only a class becomes the class.
/// A signature after the name (`run(I)V`, `f:I`) makes the name exact; the
/// rows show each overload's signature. In the class, `~` in front means
/// fuzzy; in the name, `=` in front means exact. A class without package
/// (`WebView`) matches that simple name in any package.
///
/// A signature after the name also narrows the query to it
/// ([`parse_signature`]): `run(I)V` is that overload, `run(I)` any return
/// type, `f:I` the field of that type.
pub fn member_query(kind: &str, class: Option<&str>, fuzzy_class: bool, name: Option<&str>, exact_name: bool) -> Result<MemberQuery> {
    let mut class = class.map(str::trim).filter(|c| !c.is_empty());
    let mut name = name.map(str::trim).filter(|n| !n.is_empty());
    let mut exact_name = exact_name;
    let mut signature = None;
    // `class: "Lc;->m"`: the whole target, read as one below.
    if let (Some(c), None) = (class, name) {
        if c.contains("->") || c.contains('#') {
            (class, name) = (None, Some(c));
        }
    }
    if let Some(n) = name {
        let t = MemberTarget::parse(n);
        match t.class {
            Some(c) => {
                class = class.or(Some(c));
                name = Some(t.name).filter(|n| !n.is_empty());
            }
            None if class.is_none() && looks_like_class(n) => (class, name) = (Some(n), None),
            None => name = Some(t.name),
        }
        if let Some(sig) = t.signature {
            exact_name = true;
            signature = Some(parse_signature(sig, kind == "method")?);
        }
    }
    if let Some(n) = name.and_then(|n| n.strip_prefix('=')) {
        (name, exact_name) = (Some(n), true);
    }
    if class.is_none() && name.is_none() {
        return Err(EngineError::Query(format!(
            "{kind} query needs a class or a {kind} name, e.g. Landroid/webkit/WebView;->loadUrl, android.webkit.WebView.loadUrl or just loadUrl"
        )));
    }
    let class = match class {
        Some(c) => Some(match c.strip_prefix('~') {
            Some(f) => ClassQuery { pattern: normalize_class_query(f, true)?, precise: false },
            None if fuzzy_class => ClassQuery { pattern: normalize_class_query(c, true)?, precise: false },
            None => match simple_class_pattern(c) {
                Some(pattern) => ClassQuery { pattern, precise: false },
                None => ClassQuery { pattern: format_class_name(c)?, precise: true },
            },
        }),
        None => None,
    };
    Ok(MemberQuery { class, name: name.map(String::from), exact_name, signature })
}

/// The findrefs kinds, as conditions spell them (`literal` is a string
/// matched as plain text).
pub const KINDS: &[&str] = &["string", "literal", "type", "method", "field", "extends", "impl"];

/// The canonical kind for what an agent wrote: case and plurals do not
/// matter (`Methods`), nor common synonyms (`implements`, `class`, `call`).
/// Unknown kinds fail with the valid ones and the closest of them.
pub fn parse_kind(kind: &str) -> Result<&'static str> {
    let k = kind.trim().to_ascii_lowercase();
    let alias = |k: &str| -> Option<&'static str> {
        Some(match k {
            "string" | "str" | "text" => "string",
            "literal" => "literal",
            "type" | "class" => "type",
            "method" | "call" | "invoke" => "method",
            "field" => "field",
            "extends" | "extend" | "subclass" | "superclass" => "extends",
            "impl" | "implements" | "implement" | "interface" | "implementer" => "impl",
            _ => return None,
        })
    };
    alias(&k).or_else(|| k.strip_suffix("es").and_then(alias)).or_else(|| k.strip_suffix('s').and_then(alias)).ok_or_else(|| {
        let closest = KINDS.iter().min_by_key(|c| edit_distance(&k, c, usize::MAX).unwrap_or(usize::MAX)).copied().unwrap_or("string");
        EngineError::Query(format!("unknown kind {kind:?}: use string, type, method, field, extends or impl (closest: {closest})"))
    })
}

/// The Levenshtein distance of `a` and `b`, or `None` once it exceeds `max`.
pub fn edit_distance(a: &str, b: &str, max: usize) -> Option<usize> {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    if a.len().abs_diff(b.len()) > max {
        return None;
    }
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut prev = row[0];
        row[0] = i + 1;
        let mut best = row[0];
        for (j, cb) in b.iter().enumerate() {
            let cur = row[j + 1];
            row[j + 1] = if ca == cb { prev } else { 1 + prev.min(cur).min(row[j]) };
            prev = cur;
            best = best.min(row[j + 1]);
        }
        if best > max {
            return None;
        }
    }
    Some(row[b.len()]).filter(|&d| d <= max)
}

/// `loadUrl(java.lang.String, int)` → `loadUrl(Ljava/lang/String;I)`: a
/// signature with Java parameter types in Dalvik form (a return type, if
/// any, likewise). `None` when it has no parameter list or a type is not
/// recognisable.
pub fn java_signature_to_dalvik(signature: &str) -> Option<String> {
    let (name, rest) = signature.trim().split_once('(')?;
    let (params, ret) = rest.split_once(')')?;
    let params: String = params.split(',').map(str::trim).filter(|p| !p.is_empty()).map(java_type).collect::<Option<_>>()?;
    let ret = match ret.trim() {
        "" => String::new(),
        r => java_type(r)?,
    };
    Some(format!("{}({params}){ret}", name.trim()))
}

/// `int` → `I`, `java.lang.String[]` → `[Ljava/lang/String;`, descriptors as they are.
fn java_type(t: &str) -> Option<String> {
    let t = t.trim();
    if let Some(inner) = t.strip_suffix("[]") {
        return Some(format!("[{}", java_type(inner)?));
    }
    let primitive = match t {
        "void" => "V",
        "boolean" => "Z",
        "byte" => "B",
        "short" => "S",
        "char" => "C",
        "int" => "I",
        "long" => "J",
        "float" => "F",
        "double" => "D",
        _ => "",
    };
    if !primitive.is_empty() {
        return Some(primitive.to_string());
    }
    if (t.starts_with('L') && t.ends_with(';')) || t.starts_with('[') || (t.len() == 1 && "VZBSCIJFD".contains(t)) {
        return Some(t.to_string());
    }
    t.split('.').all(is_identifier).then(|| format!("L{};", t.replace('.', "/")))
}

/// The signature written after a member name: `(params)ret` or `(params)`
/// of a method, `:T` of a field. Types are Dalvik descriptors run together
/// (`(ILjava/lang/String;)V`) or Java types separated by commas
/// (`(int, java.lang.String) void`); a Java class without package
/// (`String`) is that simple name in any package.
pub fn parse_signature(signature: &str, method: bool) -> Result<MemberSignature> {
    let bad = |why: &str| {
        EngineError::Query(format!(
            "bad signature {signature:?}: {why}; write a method's as (params)ret, e.g. (ILjava/lang/String;)V or (int, String), \
             a field's as :T, e.g. :I"
        ))
    };
    let s = signature.trim();
    if !method {
        let t = s.strip_prefix(':').ok_or_else(|| bad("a field takes :T"))?;
        return type_match(t).map(MemberSignature::Field).ok_or_else(|| bad("unknown type"));
    }
    let (params, ret) = s.strip_prefix('(').and_then(|r| r.split_once(')')).ok_or_else(|| bad("a method takes (params)"))?;
    let params = params.trim();
    let params = if params.is_empty() {
        Vec::new()
    } else if let Some(descriptors) = (!params.contains([',', ' '])).then(|| dalvik_types(params)).flatten() {
        descriptors.into_iter().map(|d| TypeMatch::Descriptor(d.to_string())).collect()
    } else {
        params.split(',').map(type_match).collect::<Option<_>>().ok_or_else(|| bad("unknown parameter type"))?
    };
    let ret = match ret.trim() {
        "" => None,
        r => Some(type_match(r).ok_or_else(|| bad("unknown return type"))?),
    };
    Ok(MemberSignature::Method { params, ret })
}

/// `ILjava/lang/String;[B` → `["I", "Ljava/lang/String;", "[B"]`; `None`
/// unless all of `s` is descriptors.
pub(crate) fn dalvik_types(s: &str) -> Option<Vec<&str>> {
    let mut out = Vec::new();
    let mut rest = s;
    while !rest.is_empty() {
        let dims = rest.len() - rest.trim_start_matches('[').len();
        let end = match rest[dims..].chars().next()? {
            'Z' | 'B' | 'S' | 'C' | 'I' | 'J' | 'F' | 'D' | 'V' => dims + 1,
            'L' => dims + rest[dims..].find(';')? + 1,
            _ => return None,
        };
        out.push(&rest[..end]);
        rest = &rest[end..];
    }
    Some(out)
}

/// One type as written in a signature: a descriptor, a Java primitive, a
/// dotted or slashed class (`java.lang.String`), a class without package
/// (`String`, any package), each optionally followed by `[]`s.
fn type_match(t: &str) -> Option<TypeMatch> {
    let t = t.trim();
    if let Some([d]) = dalvik_types(t).as_deref() {
        return Some(TypeMatch::Descriptor(d.to_string()));
    }
    let (mut base, mut dims) = (t, 0);
    while let Some(b) = base.strip_suffix("[]") {
        (base, dims) = (b.trim_end(), dims + 1);
    }
    let arrays = "[".repeat(dims);
    let primitive = match base {
        "void" => "V",
        "boolean" => "Z",
        "byte" => "B",
        "short" => "S",
        "char" => "C",
        "int" => "I",
        "long" => "J",
        "float" => "F",
        "double" => "D",
        _ => "",
    };
    if !primitive.is_empty() {
        return Some(TypeMatch::Descriptor(format!("{arrays}{primitive}")));
    }
    if base.contains(['.', '/']) {
        return base.split(['.', '/']).all(is_identifier).then(|| TypeMatch::Descriptor(format!("{arrays}L{};", base.replace('.', "/"))));
    }
    is_identifier(base).then(|| TypeMatch::Simple { name: base.to_string(), dims })
}

/// The query of exactly the method `signature` names, `Lcls;->name(params)ret`
/// as findrefs and callgraph print it (whatever characters the name holds).
pub fn exact_method(signature: &str) -> Result<MemberQuery> {
    let bad = || EngineError::Query(format!("not a method signature: {signature:?} (want Lcls;->name(params)ret)"));
    let (class, member) = signature.trim().split_once("->").ok_or_else(bad)?;
    let p = member.find('(').ok_or_else(bad)?;
    Ok(MemberQuery {
        class: Some(ClassQuery { pattern: class.to_string(), precise: true }),
        name: Some(member[..p].to_string()),
        exact_name: true,
        signature: Some(parse_signature(&member[p..], true)?),
    })
}

/// Parse a one-word findrefs condition, as the CLI's compound and rule
/// options take them:
///
/// - `string:REGEX`, `literal:TEXT`, `type:PATTERN`
/// - `method:TARGET`, `field:TARGET`: any [`MemberTarget::parse`] form, e.g.
///   `android.webkit.WebView->loadUrl`; the class is exact unless prefixed
///   `~` (fuzzy) or written without package, the name a regex / substring
///   unless prefixed `=` or followed by a signature (exact)
/// - `method:{RULE}`: calls of the methods whose code matches RULE
/// - `method:@FILE`: calls of the methods FILE lists, one per line
/// - `extends:CLASS`, `impl:CLASS`
///
/// The kind is read by [`parse_kind`] (`methods:`, `Method:` work too); the
/// grammar is [`crate::condition`]'s.
pub fn parse_condition(spec: &str) -> Result<Query> {
    crate::condition::parse_condition_in(spec, None)
}

/// One rule of a rule set: a [`parse_condition`] condition, or several
/// joined with `&` (a compound: every part must match in one method, none
/// of the `!` parts).
pub fn parse_rule(spec: &str) -> Result<Query> {
    crate::condition::parse_rule_in(spec, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_names() {
        assert_eq!(format_class_name("com.poc.Main").unwrap(), "Lcom/poc/Main;");
        assert_eq!(format_class_name("Lcom/poc/Main;").unwrap(), "Lcom/poc/Main;");
        assert_eq!(format_class_name("com/poc/Main").unwrap(), "Lcom/poc/Main;");
        assert_eq!(format_class_name("[Ljava/lang/Object;").unwrap(), "[Ljava/lang/Object;");
        assert_eq!(dalvik_to_dot("Lcom/poc/Main;"), "com.poc.Main");
        assert_eq!(normalize_class_query("com.poc", true).unwrap(), "com/poc");
        assert_eq!(normalize_class_query("poc", true).unwrap(), "poc");
        assert!(format_class_name("").is_err());
        for p in ["com.xxx", "com/xxx", "Lcom/xxx", " com.xxx\t"] {
            assert_eq!(class_prefix(p).unwrap(), "Lcom/xxx");
        }
        assert_eq!(class_prefix("a").unwrap(), "La");
        assert_eq!(class_prefix(" ").unwrap_err().to_string(), "Class prefix cannot be empty");
        assert!(member_query("method", None, false, None, false).is_err());
        let q = member_query("method", Some("com.poc.Main"), false, Some("on"), false).unwrap();
        assert!(!q.exact_name);
        assert_eq!(q.class.unwrap(), ClassQuery { pattern: "Lcom/poc/Main;".into(), precise: true });
        assert!(member_query("field", None, false, Some("f"), true).unwrap().exact_name);
    }

    fn precise(c: &str) -> Option<ClassQuery> {
        Some(ClassQuery { pattern: c.into(), precise: true })
    }

    #[test]
    fn member_targets_in_every_spelling() {
        let t = |s| MemberTarget::parse(s);
        assert_eq!(t("Lcom/a/B;->run(I)V"), MemberTarget { class: Some("Lcom/a/B;"), name: "run", signature: Some("(I)V") });
        assert_eq!(t("Lc;->f:I"), MemberTarget { class: Some("Lc;"), name: "f", signature: Some(":I") });
        assert_eq!(t("com.a.B->run"), MemberTarget { class: Some("com.a.B"), name: "run", signature: None });
        assert_eq!(t("com.a.B#run"), MemberTarget { class: Some("com.a.B"), name: "run", signature: None });
        assert_eq!(
            t("android.webkit.WebView.loadUrl"),
            MemberTarget { class: Some("android.webkit.WebView"), name: "loadUrl", signature: None }
        );
        assert_eq!(t("com/a/B.run(I)V"), MemberTarget { class: Some("com/a/B"), name: "run", signature: Some("(I)V") });
        assert_eq!(t("java.lang.Thread.<init>"), MemberTarget { class: Some("java.lang.Thread"), name: "<init>", signature: None });
        assert_eq!(t("Build$VERSION.SDK_INT").class, Some("Build$VERSION"));
        // Patterns and lowercase dotted names stay names.
        for name in ["get.*Id", "(get|set)Foo", "a.b", "exec"] {
            assert_eq!(t(name), MemberTarget { class: None, name, signature: None }, "{name}");
        }
        assert!(looks_like_class("android.webkit.WebView") && looks_like_class("Lcom/a/B;"));
        assert!(!looks_like_class("loadUrl") && !looks_like_class("com.a.b") && !looks_like_class("Lc;->m"));
    }

    #[test]
    fn member_queries_from_any_spelling_agree() {
        let want =
            MemberQuery { class: precise("Landroid/webkit/WebView;"), name: Some("loadUrl".into()), exact_name: false, signature: None };
        for spec in [
            "Landroid/webkit/WebView;->loadUrl",
            "android.webkit.WebView.loadUrl",
            "android.webkit.WebView->loadUrl",
            "android.webkit.WebView#loadUrl",
        ] {
            assert_eq!(member_query("method", None, false, Some(spec), false).unwrap(), want, "{spec}");
        }
        // The class may also carry the member, or come on its own.
        assert_eq!(member_query("method", Some("Landroid/webkit/WebView;->loadUrl"), false, None, false).unwrap(), want);
        assert_eq!(member_query("method", Some("android.webkit.WebView"), false, Some("loadUrl"), false).unwrap(), want);
        let class_only = member_query("method", None, false, Some("android.webkit.WebView"), false).unwrap();
        assert_eq!(class_only, MemberQuery { class: precise("Landroid/webkit/WebView;"), name: None, exact_name: false, signature: None });
        // A signature or `=` makes the name exact; an explicit class wins.
        let q = member_query("method", None, false, Some("Lc;->run(I)V"), false).unwrap();
        assert_eq!((q.name.as_deref(), q.exact_name), (Some("run"), true));
        let q = member_query("field", Some("Lx;"), false, Some("Lc;->f:I"), false).unwrap();
        assert_eq!((q.class, q.name.as_deref(), q.exact_name), (precise("Lx;"), Some("f"), true));
        let q = member_query("method", None, false, Some("~Foo->=bar"), false).unwrap();
        assert_eq!(
            q,
            MemberQuery {
                class: Some(ClassQuery { pattern: "Foo".into(), precise: false }),
                name: Some("bar".into()),
                exact_name: true,
                signature: None
            }
        );
        // Without a package: that simple name in any package.
        let q = member_query("method", None, false, Some("WebView.loadUrl"), false).unwrap();
        assert_eq!(q.class, Some(ClassQuery { pattern: "[/L]WebView;\\x00".into(), precise: false }));
        let e = member_query("method", None, false, Some(" "), false).unwrap_err().to_string();
        assert!(e.contains("needs a class or a method name"), "{e}");
    }

    #[test]
    fn kinds_tolerate_case_plurals_and_synonyms() {
        for (k, want) in [
            ("Methods", "method"),
            ("strings", "string"),
            ("TYPE", "type"),
            ("implements", "impl"),
            ("classes", "type"),
            ("fields", "field"),
            ("literal", "literal"),
        ] {
            assert_eq!(parse_kind(k).unwrap(), want, "{k}");
        }
        let e = parse_kind("metod").unwrap_err().to_string();
        assert!(e.contains("unknown kind \"metod\"") && e.contains("closest: method"), "{e}");
        assert_eq!(
            parse_condition("Methods:android.webkit.WebView.loadUrl").unwrap(),
            parse_condition("method:Landroid/webkit/WebView;->loadUrl").unwrap()
        );
        assert!(matches!(parse_rule("string:a & method:b").unwrap(), Query::All { all, .. } if all.len() == 2));
    }

    #[test]
    fn signatures_in_dalvik_and_java_form() {
        let d = |s: &str| TypeMatch::Descriptor(s.into());
        let method = |params: Vec<TypeMatch>, ret: Option<TypeMatch>| MemberSignature::Method { params, ret };
        let sig = |s| parse_signature(s, true).unwrap();
        assert_eq!(sig("(I)V"), method(vec![d("I")], Some(d("V"))));
        assert_eq!(sig("(I)"), method(vec![d("I")], None));
        assert_eq!(sig("()"), method(vec![], None));
        assert_eq!(sig("(ILjava/lang/String;[B)Z"), method(vec![d("I"), d("Ljava/lang/String;"), d("[B")], Some(d("Z"))));
        assert_eq!(sig("(int)"), method(vec![d("I")], None));
        assert_eq!(sig("(int, java.lang.String[]) void"), method(vec![d("I"), d("[Ljava/lang/String;")], Some(d("V"))));
        assert_eq!(
            sig("(String, Map[][])"),
            method(vec![TypeMatch::Simple { name: "String".into(), dims: 0 }, TypeMatch::Simple { name: "Map".into(), dims: 2 }], None)
        );
        assert_eq!(parse_signature(":I", false).unwrap(), MemberSignature::Field(d("I")));
        assert_eq!(parse_signature(":java.lang.String", false).unwrap(), MemberSignature::Field(d("Ljava/lang/String;")));
        for (bad, method) in [("(I", true), ("(%)V", true), (":I", true), ("(I)V", false), (":", false)] {
            let e = parse_signature(bad, method).unwrap_err().to_string();
            assert!(e.contains("bad signature"), "{bad}: {e}");
        }
        // A signature after the name narrows the query to it.
        for spec in ["Lc;->run(I)V", "c.run(int)void", "Lc;->run(I)V "] {
            let q = member_query("method", None, false, Some(spec), false).unwrap();
            assert_eq!(q.signature, Some(method(vec![d("I")], Some(d("V")))), "{spec}");
        }
        assert_eq!(
            member_query("method", None, false, Some("WebView.loadUrl(String)"), false).unwrap().signature.unwrap().to_string(),
            "(String)"
        );
        assert_eq!(member_query("method", None, false, Some("loadUrl"), false).unwrap().signature, None);
        assert!(member_query("field", None, false, Some("Lc;->f(I)V"), false).is_err());
        assert_eq!(
            parse_condition("method:Lc;->m(I)").unwrap(),
            Query::Method(member_query("method", None, false, Some("Lc;->m(I)"), false).unwrap())
        );
    }

    #[test]
    fn java_signatures_and_edit_distance() {
        assert_eq!(java_signature_to_dalvik("loadUrl(java.lang.String, int)").as_deref(), Some("loadUrl(Ljava/lang/String;I)"));
        assert_eq!(java_signature_to_dalvik("f(byte[], Lx;) void").as_deref(), Some("f([BLx;)V"));
        assert_eq!(java_signature_to_dalvik("run()").as_deref(), Some("run()"));
        assert_eq!(java_signature_to_dalvik("run"), None);
        assert_eq!(edit_distance("kitten", "sitting", 5), Some(3));
        assert_eq!(edit_distance("kitten", "sitting", 2), None);
        assert_eq!(edit_distance("a", "a", 0), Some(0));
    }
}
