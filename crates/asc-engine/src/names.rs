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
    if let Some(inner) = s.strip_prefix('`').and_then(|r| r.strip_suffix('`')) {
        return !inner.is_empty() && !inner.contains('`');
    }
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
    let capitalised = segments.last().is_some_and(|l| l.trim_matches('`').starts_with(|c: char| c.is_ascii_uppercase()));
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
        && segments.last().is_some_and(|l| l.trim_matches('`').starts_with(|c: char| c.is_ascii_uppercase()))
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
pub const KINDS: &[&str] = &["string", "literal", "type", "method", "field", "extends", "impl", "override", "annotation", "flag", "in"];

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
            "override" | "overrides" | "implementor" => "override",
            "annotation" | "annotated" | "anno" => "annotation",
            "flag" | "flags" | "access" | "modifier" => "flag",
            "in" | "inclass" => "in",
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

/// Whether `value` is a Java reserved keyword or literal that `dexdec` prefixes
/// with `C` when sanitizing DEX identifiers.
pub fn is_java_reserved(value: &str) -> bool {
    matches!(
        value,
        "abstract"
            | "assert"
            | "boolean"
            | "break"
            | "byte"
            | "case"
            | "catch"
            | "char"
            | "class"
            | "const"
            | "continue"
            | "default"
            | "do"
            | "double"
            | "else"
            | "enum"
            | "extends"
            | "final"
            | "finally"
            | "float"
            | "for"
            | "goto"
            | "if"
            | "implements"
            | "import"
            | "instanceof"
            | "int"
            | "interface"
            | "long"
            | "native"
            | "new"
            | "package"
            | "private"
            | "protected"
            | "public"
            | "return"
            | "short"
            | "static"
            | "strictfp"
            | "super"
            | "switch"
            | "synchronized"
            | "this"
            | "throw"
            | "throws"
            | "transient"
            | "try"
            | "void"
            | "volatile"
            | "while"
            | "true"
            | "false"
            | "null"
            | "_"
    )
}

/// `name(params)` without a return type — a Java-style or abbreviated target
/// such as `run(int)` or `entry(com.app.Outer.Inner)`. Anything unbalanced
/// (`run(I`, `run`) is not a signature and returns `None`.
pub(crate) fn partial_signature(spec: &str) -> Option<(&str, &str)> {
    let open = spec.find('(')?;
    let tail = &spec[open..];
    let balanced = tail.ends_with(')') && tail.matches('(').count() == 1 && tail.matches(')').count() == 1;
    let name = spec[..open].trim();
    (balanced && !name.is_empty()).then_some((name, tail))
}

/// [`partial_signature`] with its Java-style or normalized parameter types put
/// into Dalvik form: `onEvent(int)` -> `("onEvent", "(I)")`,
/// `entry(com.app.Outer.Inner)` -> `("entry", "(Lcom/app/Outer$Inner;)")`.
pub(crate) fn partial_proto(spec: &str) -> Option<(String, String)> {
    let (name, tail) = partial_signature(spec)?;
    let tail = java_signature_to_dalvik(spec)
        .and_then(|dalvik| dalvik.find('(').map(|i| dalvik[i..].to_string()))
        .unwrap_or_else(|| tail.to_string());
    Some((name.to_string(), denormalize_signature_types(&tail)))
}

fn push_unique(out: &mut Vec<String>, item: String) {
    if !item.is_empty() && !out.contains(&item) {
        out.push(item);
    }
}

/// Decode Kotlin `_dex_<HEX>_` escaped identifier, if `s` has that shape.
fn decode_kotlin_dex_hex(s: &str) -> Option<String> {
    let rest = s.strip_prefix("_dex_")?;
    if rest == "empty" {
        return Some(String::new());
    }
    let rest = rest.strip_suffix('_')?;
    let mut out = String::new();
    for part in rest.split('_') {
        let code = u32::from_str_radix(part, 16).ok()?;
        out.push(char::from_u32(code)?);
    }
    (!out.is_empty()).then_some(out)
}

/// Produce fallback de-normalized forms of a single `dexdec` identifier
/// (excluding `ident` itself):
/// - Kotlin backticks `` `in` `` -> `in`
/// - Kotlin `_dex_<HEX>_` -> decoded characters
/// - Collision suffix `name$2`, `name$3` -> `name`
/// - Java reserved/numeric prefix `Cdo`, `Cif`, `C_`, `C1a` -> `do`, `if`, `_`, `1a`
pub fn denormalize_identifier(ident: &str) -> Vec<String> {
    let mut out = Vec::new();
    let stripped = ident.strip_prefix('`').and_then(|s| s.strip_suffix('`')).unwrap_or(ident);
    let mut seeds = Vec::new();
    if stripped != ident {
        push_unique(&mut out, stripped.to_string());
        seeds.push(stripped.to_string());
    } else {
        seeds.push(ident.to_string());
    }
    if let Some(decoded) = decode_kotlin_dex_hex(stripped) {
        push_unique(&mut out, decoded.clone());
        seeds.push(decoded);
    }
    if let Some((base, num)) = stripped.rsplit_once('$') {
        if !base.is_empty() && num.parse::<u32>().is_ok_and(|n| n >= 2) {
            push_unique(&mut out, base.to_string());
            seeds.push(base.to_string());
        }
    }
    for s in seeds {
        if let Some(rest) = s.strip_prefix('C') {
            if is_java_reserved(rest) || rest.starts_with(|c: char| c.is_ascii_digit()) {
                push_unique(&mut out, rest.to_string());
            }
        }
    }
    out.retain(|c| c != ident);
    out
}

/// Produce fallback Dalvik class descriptors for a class name or descriptor
/// that may have been normalized by `dexdec`:
/// - Nested class dot separator (`Lcom/a/Outer/Inner;` -> `Lcom/a/Outer$Inner;`)
/// - Anonymous class placeholder (`Anonymous1` -> `$1`)
/// - Sanitized package/class segments (`Cdo` -> `do`, `` `in` `` -> `in`)
pub fn denormalize_class_candidates(input: &str) -> Vec<String> {
    let Ok(formatted) = format_class_name(input) else {
        return Vec::new();
    };
    let dims = formatted.len() - formatted.trim_start_matches('[').len();
    let array_prefix = &formatted[..dims];
    let core = &formatted[dims..];
    if !core.starts_with('L') || !core.ends_with(';') {
        return Vec::new();
    }
    let inner = class_inner(core);
    // Split into tokens coupled with the separator ('/' or '$') preceding each token.
    let mut tokens: Vec<(char, &str)> = Vec::new();
    for (i, slash_seg) in inner.split('/').enumerate() {
        for (j, dollar_seg) in slash_seg.split('$').enumerate() {
            let sep = if i == 0 && j == 0 {
                '/'
            } else if j > 0 {
                '$'
            } else {
                '/'
            };
            tokens.push((sep, dollar_seg));
        }
    }
    if tokens.is_empty() {
        return Vec::new();
    }

    // Expand each token into `(token_text, force_dollar_before_it)`.
    let mut token_variants: Vec<Vec<(String, bool)>> = Vec::with_capacity(tokens.len());
    for &(_, raw_tok) in &tokens {
        let mut vars = Vec::new();
        let unquoted = raw_tok.strip_prefix('`').and_then(|s| s.strip_suffix('`')).unwrap_or(raw_tok);
        if let Some(num) = unquoted.strip_prefix("Anonymous").filter(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit())) {
            vars.push((num.to_string(), true));
        }
        for d in denormalize_identifier(raw_tok) {
            if !vars.iter().any(|(v, _)| v == &d) {
                vars.push((d, false));
            }
        }
        if !vars.iter().any(|(v, _)| v == raw_tok) {
            vars.push((raw_tok.to_string(), false));
        }
        token_variants.push(vars);
    }

    // Generate token sequences (combining primary de-normalized variants and original).
    let mut seqs: Vec<Vec<(String, bool)>> = vec![Vec::new()];
    for vars in &token_variants {
        let mut next = Vec::new();
        for prefix in &seqs {
            for v in vars.iter().take(2) {
                let mut p = prefix.clone();
                p.push(v.clone());
                next.push(p);
            }
        }
        seqs = next;
        if seqs.len() > 16 {
            seqs.truncate(16);
        }
    }

    let mut out = Vec::new();
    for seq in &seqs {
        let build_with_split = |dollar_from: Option<usize>| -> String {
            let mut s = format!("{array_prefix}L");
            for (idx, (tok, force_dollar)) in seq.iter().enumerate() {
                if idx > 0 {
                    let orig_sep = tokens[idx].0;
                    let use_dollar = orig_sep == '$' || *force_dollar || dollar_from.is_some_and(|df| idx > df);
                    s.push(if use_dollar { '$' } else { '/' });
                }
                s.push_str(tok);
            }
            s.push(';');
            s
        };

        // 1. Keep original '/' vs '$', only applying forced '$' for AnonymousN -> $N.
        let base_desc = build_with_split(None);
        if base_desc != formatted {
            push_unique(&mut out, base_desc);
        }

        // 2. If a capitalised segment (in the de-normalized token or the name
        //    as written) is followed by more segments, treat those as nested
        //    classes ('$' instead of '/'). Obfuscated code often has none, so
        //    the last two segments are always tried as an outer/inner split.
        let upper = seq
            .iter()
            .position(|(t, _)| t.starts_with(|c: char| c.is_ascii_uppercase()))
            .or_else(|| tokens.iter().position(|&(_, raw)| raw.trim_matches('`').starts_with(|c: char| c.is_ascii_uppercase())));
        let mut splits = Vec::new();
        if let Some(first_upper) = upper {
            splits.extend(first_upper..seq.len().saturating_sub(1));
        }
        // Obfuscated lowercase outer classes (`com/app/a/B`) still nest: only a
        // path with package segments to spare is split blindly.
        if seq.len() >= 3 {
            splits.push(seq.len() - 2);
        }
        splits.sort_unstable();
        splits.dedup();
        for split_at in splits {
            let cand = build_with_split(Some(split_at));
            if cand != formatted {
                push_unique(&mut out, cand);
            }
        }
    }
    out
}

/// Possible simple source names for `class_descriptor` (used to detect constructor queries).
fn class_constructor_names(class_descriptor: &str) -> Vec<String> {
    let mut names = vec!["constructor".to_string()];
    let inner = class_inner(class_descriptor.trim_start_matches('['));
    let binary_cls = inner.rsplit('/').next().unwrap_or(inner);
    let last = binary_cls.rsplit('$').next().unwrap_or(binary_cls);
    if !last.is_empty() {
        push_unique(&mut names, last.to_string());
        if last.chars().all(|c| c.is_ascii_digit()) {
            push_unique(&mut names, format!("Anonymous{last}"));
        }
        if is_java_reserved(last) || last.starts_with(|c: char| c.is_ascii_digit()) {
            push_unique(&mut names, format!("C{last}"));
        }
    }
    if binary_cls != last {
        push_unique(&mut names, binary_cls.to_string());
    }
    names
}

/// Produce fallback method names or signatures for a method query that may use
/// `dexdec`-normalized names (`Cdo`, `m$2`, `` `in` ``, `Anonymous1`, class constructor name).
pub fn denormalize_method_candidates(class_descriptor: Option<&str>, method: &str) -> Vec<String> {
    let trimmed = method.trim();
    let (_, member) = trimmed.rsplit_once("->").unwrap_or(("", trimmed));
    let (raw_name, sig_tail) = match member.find('(') {
        Some(i) => (member[..i].trim(), Some(&member[i..])),
        None => (member.trim(), None),
    };
    let mut name_cands = Vec::new();
    push_unique(&mut name_cands, raw_name.to_string());
    for d in denormalize_identifier(raw_name) {
        push_unique(&mut name_cands, d);
    }
    if let Some(cls) = class_descriptor {
        let ctor_names = class_constructor_names(cls);
        for c in denormalize_class_candidates(cls) {
            for extra in class_constructor_names(&c) {
                if !ctor_names.contains(&extra) && (raw_name == extra || raw_name.trim_matches('`') == extra) {
                    push_unique(&mut name_cands, "<init>".to_string());
                }
            }
        }
        if ctor_names.iter().any(|n| n == raw_name || n == raw_name.trim_matches('`')) {
            push_unique(&mut name_cands, "<init>".to_string());
        }
    } else if raw_name == "constructor"
        || raw_name.strip_prefix("Anonymous").is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
    {
        push_unique(&mut name_cands, "<init>".to_string());
    }

    let mut sig_cands = Vec::new();
    match sig_tail {
        None => sig_cands.push(String::new()),
        Some(sig) => {
            sig_cands.push(sig.to_string());
            let denorm_sig = denormalize_signature_types(sig);
            if denorm_sig != sig {
                push_unique(&mut sig_cands, denorm_sig);
            }
            if let Some(dalvik_full) = java_signature_to_dalvik(&format!("m{sig}")) {
                if let Some(dalvik_sig) = dalvik_full.strip_prefix('m') {
                    push_unique(&mut sig_cands, dalvik_sig.to_string());
                    let denorm_dalvik = denormalize_signature_types(dalvik_sig);
                    if denorm_dalvik != dalvik_sig {
                        push_unique(&mut sig_cands, denorm_dalvik);
                    }
                }
            }
        }
    }

    let mut out = Vec::new();
    for n in &name_cands {
        for s in &sig_cands {
            let combined = format!("{n}{s}");
            if combined != member && combined != trimmed {
                push_unique(&mut out, combined.clone());
            }
            // `<init>(I)` and other return-less signatures: constructors return
            // void, and every lookup wants a full `(params)ret` proto.
            if (n == "<init>" || n == "constructor") && s.ends_with(')') {
                push_unique(&mut out, format!("{combined}V"));
            }
        }
    }
    out
}

/// Replace normalized class descriptors inside a signature `(params)ret` or `:type`.
pub(crate) fn denormalize_signature_types(sig: &str) -> String {
    let mut out = String::with_capacity(sig.len());
    let mut rest = sig;
    while let Some(l_pos) = rest.find('L') {
        out.push_str(&rest[..l_pos]);
        let after_l = &rest[l_pos..];
        if let Some(semi) = after_l.find(';') {
            let desc = &after_l[..=semi];
            if let Some(first) = denormalize_class_candidates(desc).into_iter().next() {
                out.push_str(&first);
            } else {
                out.push_str(desc);
            }
            rest = &after_l[semi + 1..];
        } else {
            out.push_str(after_l);
            rest = "";
        }
    }
    out.push_str(rest);
    out
}

fn denormalize_type_match(tm: &TypeMatch) -> Vec<TypeMatch> {
    match tm {
        TypeMatch::Descriptor(d) => denormalize_class_candidates(d).into_iter().map(TypeMatch::Descriptor).collect(),
        TypeMatch::Simple { name, dims } => {
            let mut out = Vec::new();
            if let Some(num) = name.strip_prefix("Anonymous").filter(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit())) {
                out.push(TypeMatch::Simple { name: format!("${num}"), dims: *dims });
            }
            for d in denormalize_identifier(name) {
                out.push(TypeMatch::Simple { name: d, dims: *dims });
            }
            out
        }
    }
}

fn denormalize_member_signature(sig: &MemberSignature) -> Option<MemberSignature> {
    match sig {
        MemberSignature::Field(tm) => denormalize_type_match(tm).into_iter().next().map(MemberSignature::Field),
        MemberSignature::Method { params, ret } => {
            let mut changed = false;
            let new_params: Vec<TypeMatch> = params
                .iter()
                .map(|p| match denormalize_type_match(p).into_iter().next() {
                    Some(np) => {
                        changed = true;
                        np
                    }
                    None => p.clone(),
                })
                .collect();
            let new_ret = match ret {
                Some(r) => match denormalize_type_match(r).into_iter().next() {
                    Some(nr) => {
                        changed = true;
                        Some(nr)
                    }
                    None => Some(r.clone()),
                },
                None => None,
            };
            changed.then_some(MemberSignature::Method { params: new_params, ret: new_ret })
        }
    }
}

fn denormalize_member_query(mq: &MemberQuery, is_method: bool) -> Vec<MemberQuery> {
    let mut class_cands: Vec<Option<ClassQuery>> = vec![mq.class.clone()];
    if let Some(cq) = &mq.class {
        if cq.precise {
            for c in denormalize_class_candidates(&cq.pattern) {
                class_cands.push(Some(ClassQuery { pattern: c, precise: true }));
            }
        } else if let Some(inner) = cq.pattern.strip_prefix("[/L]").and_then(|s| s.strip_suffix(";\\x00")) {
            let unescaped = inner.replace("\\$", "$");
            if let Some(num) = unescaped.strip_prefix("Anonymous").filter(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit())) {
                class_cands.push(Some(ClassQuery { pattern: format!("\\${num};\\x00"), precise: false }));
            }
            for d in denormalize_identifier(&unescaped) {
                class_cands.push(Some(ClassQuery { pattern: format!("[/L]{};\\x00", regex::escape(&d)), precise: false }));
            }
        } else {
            for c in denormalize_class_candidates(&cq.pattern) {
                let inner = class_inner(&c).to_string();
                class_cands.push(Some(ClassQuery { pattern: regex::escape(&inner), precise: false }));
            }
        }
    }

    let cls_desc = mq.class.as_ref().map(|c| c.pattern.as_str());
    let mut name_cands: Vec<Option<String>> = vec![mq.name.clone()];
    if let Some(name) = &mq.name {
        let extras = if is_method { denormalize_method_candidates(cls_desc, name) } else { denormalize_identifier(name) };
        for e in extras {
            let opt = Some(e);
            if !name_cands.contains(&opt) {
                name_cands.push(opt);
            }
        }
    }

    let mut sig_cands: Vec<Option<MemberSignature>> = vec![mq.signature.clone()];
    if let Some(sig) = &mq.signature {
        if let Some(ns) = denormalize_member_signature(sig) {
            sig_cands.push(Some(ns));
        }
    }

    let mut out = Vec::new();
    for c in &class_cands {
        for n in &name_cands {
            for s in &sig_cands {
                // A name this fallback invented (`a$2` -> `a`, `Cdo` -> `do`)
                // is matched whole: a substring match on a precise class would
                // also hit every member whose name merely contains it.
                let exact_name = mq.exact_name || n != &mq.name || n.as_deref() == Some("<init>");
                let cand = MemberQuery { class: c.clone(), name: n.clone(), exact_name, signature: s.clone() };
                if &cand != mq && !out.contains(&cand) {
                    out.push(cand);
                }
            }
        }
    }
    out
}

/// Construct a fallback [`Query`] with de-normalized class, method, or field
/// identifiers when the original query matched 0 results.
pub fn denormalize_query(q: &Query) -> Option<Query> {
    match q {
        Query::Type(pat) => {
            let cands = denormalize_class_candidates(pat);
            if cands.is_empty() {
                let id_cands = denormalize_identifier(pat);
                if id_cands.is_empty() {
                    return None;
                }
                let joined = id_cands.into_iter().map(|c| regex::escape(&c)).collect::<Vec<_>>().join("|");
                return Some(Query::Type(format!("(?:{joined})")));
            }
            let joined = cands.into_iter().map(|c| regex::escape(&c)).collect::<Vec<_>>().join("|");
            Some(Query::Type(format!("(?:{joined})")))
        }
        Query::Extends(cls) => denormalize_class_candidates(cls).into_iter().next().map(Query::Extends),
        Query::Implements(cls) => denormalize_class_candidates(cls).into_iter().next().map(Query::Implements),
        Query::Method(mq) => {
            let vars = denormalize_member_query(mq, true);
            match vars.len() {
                0 => None,
                1 => Some(Query::Method(vars.into_iter().next().unwrap())),
                _ => Some(Query::MethodSet(vars)),
            }
        }
        Query::Field(mq) => {
            let vars = denormalize_member_query(mq, false);
            collapse_field_variants(vars).map(Query::Field)
        }
        Query::FieldAccess { field, access } => {
            let vars = denormalize_member_query(field, false);
            collapse_field_variants(vars).map(|f| Query::FieldAccess { field: f, access: *access })
        }
        Query::Call { target, constraints } => {
            denormalize_query(target).map(|t| Query::Call { target: Box::new(t), constraints: constraints.clone() })
        }
        Query::All { all, none } => {
            let mut changed = false;
            let new_all = all
                .iter()
                .map(|part| match denormalize_query(part) {
                    Some(np) => {
                        changed = true;
                        np
                    }
                    None => part.clone(),
                })
                .collect();
            changed.then_some(Query::All { all: new_all, none: none.clone() })
        }
        _ => None,
    }
}

fn collapse_field_variants(vars: Vec<MemberQuery>) -> Option<MemberQuery> {
    if vars.is_empty() {
        return None;
    }
    if vars.len() == 1 {
        return vars.into_iter().next();
    }
    let first = &vars[0];
    let mut classes = Vec::new();
    let mut names = Vec::new();
    for v in &vars {
        if let Some(c) = &v.class {
            let pat = if c.precise { format!("^{}\\x00", regex::escape(&c.pattern)) } else { c.pattern.clone() };
            push_unique(&mut classes, pat);
        }
        if let Some(n) = &v.name {
            let pat = if v.exact_name { format!("^{}\\x00", regex::escape(n)) } else { regex::escape(n) };
            push_unique(&mut names, pat);
        }
    }
    let class = if classes.is_empty() {
        None
    } else if classes.len() == 1 && first.class.as_ref().is_some_and(|c| c.precise) {
        first.class.clone()
    } else {
        Some(ClassQuery { pattern: format!("(?:{})", classes.join("|")), precise: false })
    };
    // A precise class compiles a non-exact name as a literal substring, so an
    // alternation is only usable as a regex: keep `precise` only when there is
    // exactly one name to match.
    let precise_class = class.as_ref().is_some_and(|c| c.precise);
    let (name, exact_name) = if names.is_empty() {
        (None, false)
    } else if names.len() == 1 && precise_class {
        (first.name.clone(), first.exact_name)
    } else {
        let class = if precise_class && names.len() > 1 {
            first.class.as_ref().map(|c| ClassQuery { pattern: format!("^{}\\x00", regex::escape(&c.pattern)), precise: false })
        } else {
            class
        };
        return Some(MemberQuery {
            class,
            name: Some(format!("(?:{})", names.join("|"))),
            exact_name: false,
            signature: vars.iter().rev().find_map(|v| v.signature.clone()),
        });
    };
    Some(MemberQuery { class, name, exact_name, signature: vars.iter().rev().find_map(|v| v.signature.clone()) })
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
