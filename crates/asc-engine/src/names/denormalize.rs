//! Names as decompiled Java / Kotlin source spells them, mapped back to the
//! DEX names they stand for.
//!
//! Decompilers rename what the source language cannot spell: a nested class
//! is `Outer.Inner` (DEX `Outer$Inner`), an anonymous one `AnonymousN`
//! (`$N`), a reserved word or a name starting with a digit gets a `C` in
//! front (`Cdo`, `Cif`, `C_`, `C1a`), same-named members a collision suffix
//! (`a$2`), a constructor the class name, and Kotlin backticks a keyword
//! (`` `in` ``) or escapes other characters as `_dex_<HEX>_`. An agent
//! reading such source writes these names back into queries.
//!
//! Everything here produces *fallback candidates*: callers look the name up
//! as written first and only try these when that finds nothing, so a DEX
//! that really has a class `Cdo` or a method `m$2` is never second-guessed.

use super::{class_inner, format_class_name, java_signature_to_dalvik};
use asc_findrefs::{ClassQuery, MemberQuery, MemberSignature, Query, TypeMatch};

/// Whether `value` is a Java reserved keyword or literal, which decompilers
/// prefix with `C` when a DEX identifier is spelled like one.
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
fn partial_signature(spec: &str) -> Option<(&str, &str)> {
    let open = spec.find('(')?;
    let tail = &spec[open..];
    let balanced = tail.ends_with(')') && tail.matches('(').count() == 1 && tail.matches(')').count() == 1;
    let name = spec[..open].trim();
    (balanced && !name.is_empty()).then_some((name, tail))
}

/// [`partial_signature`] with its Java-style or source-spelled parameter
/// types put into Dalvik form: `onEvent(int)` → `("onEvent", "(I)")`,
/// `entry(com.app.Outer.Inner)` → `("entry", "(Lcom/app/Outer$Inner;)")`.
/// The proto has no return type: callers match it as a prefix.
pub(crate) fn partial_proto(spec: &str) -> Option<(String, String)> {
    let (name, tail) = partial_signature(spec)?;
    let tail = java_signature_to_dalvik(spec)
        .and_then(|dalvik| dalvik.find('(').map(|i| dalvik[i..].to_string()))
        .unwrap_or_else(|| tail.split_whitespace().collect());
    Some((name.to_string(), denormalize_signature_types(&tail)))
}

/// Whether DEX proto `have` (`(I)V`) is what `want` asks for: equal, or
/// `want` is a return-less `(params)` prefix of it.
pub(crate) fn proto_matches(have: &str, want: &str) -> bool {
    have == want || (want.ends_with(')') && have.len() > want.len() && have.starts_with(want))
}

fn push_unique(out: &mut Vec<String>, item: String) {
    if !item.is_empty() && !out.contains(&item) {
        out.push(item);
    }
}

/// `N` of `AnonymousN`, the decompiled name of anonymous class `$N`.
fn anonymous_number(name: &str) -> Option<&str> {
    name.strip_prefix("Anonymous").filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// The identifier a Kotlin `_dex_<HEX>_` escape stands for (`_dex_61_2D_62_`
/// → `a-b`, `_dex_empty` → the empty name), if `s` has that shape.
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

/// The DEX identifiers a decompiled identifier may stand for (`ident`
/// itself excluded):
/// - Kotlin backticks `` `in` `` → `in`
/// - Kotlin `_dex_<HEX>_` → the decoded characters
/// - a collision suffix `name$2`, `name$3` → `name`
/// - a reserved-word or digit escape `Cdo`, `Cif`, `C_`, `C1a` → `do`, `if`, `_`, `1a`
pub fn denormalize_identifier(ident: &str) -> Vec<String> {
    let mut out = Vec::new();
    let stripped = ident.strip_prefix('`').and_then(|s| s.strip_suffix('`')).unwrap_or(ident);
    let mut seeds = Vec::new();
    if stripped != ident {
        push_unique(&mut out, stripped.to_string());
    }
    seeds.push(stripped.to_string());
    if let Some(decoded) = decode_kotlin_dex_hex(stripped) {
        push_unique(&mut out, decoded.clone());
        seeds.push(decoded);
    }
    if let Some((base, num)) = stripped.rsplit_once('$')
        && !base.is_empty()
        && num.parse::<u32>().is_ok_and(|n| n >= 2)
    {
        push_unique(&mut out, base.to_string());
        seeds.push(base.to_string());
    }
    for s in seeds {
        if let Some(rest) = s.strip_prefix('C')
            && (is_java_reserved(rest) || rest.starts_with(|c: char| c.is_ascii_digit()))
        {
            push_unique(&mut out, rest.to_string());
        }
    }
    out.retain(|c| c != ident);
    out
}

/// Most token sequences [`denormalize_class_candidates`] combines.
const MAX_CLASS_SEQUENCES: usize = 16;

/// The Dalvik descriptors a class written as decompiled source spells it may
/// stand for, most likely first (the name as written excluded):
/// - nested classes written with dots (`com.a.Outer.Inner` → `Lcom/a/Outer$Inner;`)
/// - anonymous classes (`Outer.Anonymous1` → `Lcom/a/Outer$1;`)
/// - escaped package / class segments (`Cdo` → `do`, `` `in` `` → `in`)
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
    // Each token with the separator ('/' or '$') that precedes it.
    let mut tokens: Vec<(char, &str)> = Vec::new();
    for slash_seg in inner.split('/') {
        for (j, dollar_seg) in slash_seg.split('$').enumerate() {
            tokens.push((if j > 0 { '$' } else { '/' }, dollar_seg));
        }
    }

    // Each token's readings, `(text, a '$' must precede it)`, the
    // denormalized ones first and the token as written last.
    let token_variants: Vec<Vec<(String, bool)>> = tokens
        .iter()
        .map(|&(_, raw)| {
            let mut vars = Vec::new();
            let unquoted = raw.strip_prefix('`').and_then(|s| s.strip_suffix('`')).unwrap_or(raw);
            if let Some(num) = anonymous_number(unquoted) {
                vars.push((num.to_string(), true));
            }
            for d in denormalize_identifier(raw) {
                if !vars.iter().any(|(v, _)| v == &d) {
                    vars.push((d, false));
                }
            }
            if !vars.iter().any(|(v, _)| v == raw) {
                vars.push((raw.to_string(), false));
            }
            vars
        })
        .collect();

    // Sequences of the first two readings of each token, bounded.
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
        next.truncate(MAX_CLASS_SEQUENCES);
        seqs = next;
    }

    let mut out = Vec::new();
    for seq in &seqs {
        // `dollar_from`: every token after this one is a nested class.
        let build = |dollar_from: Option<usize>| -> String {
            let mut s = format!("{array_prefix}L");
            for (idx, (tok, force_dollar)) in seq.iter().enumerate() {
                if idx > 0 {
                    let nested = tokens[idx].0 == '$' || *force_dollar || dollar_from.is_some_and(|df| idx > df);
                    s.push(if nested { '$' } else { '/' });
                }
                s.push_str(tok);
            }
            s.push(';');
            s
        };
        let mut push = |cand: String| {
            if cand != formatted {
                push_unique(&mut out, cand);
            }
        };

        // 1. The separators as written, `AnonymousN` alone becoming `$N`.
        push(build(None));

        // 2. After the first capitalised segment (in the denormalized token
        //    or as written) every segment is a nested class. Obfuscated code
        //    may have no capitals at all, so the last two segments are
        //    always tried as outer / inner too.
        let upper = seq
            .iter()
            .position(|(t, _)| t.starts_with(|c: char| c.is_ascii_uppercase()))
            .or_else(|| tokens.iter().position(|&(_, raw)| raw.trim_matches('`').starts_with(|c: char| c.is_ascii_uppercase())));
        let mut splits: Vec<usize> = upper.map(|first| (first..seq.len().saturating_sub(1)).collect()).unwrap_or_default();
        // A lowercase outer class (`com/app/a/B`) still nests, but only a
        // path with a package segment to spare is split blindly.
        if seq.len() >= 3 {
            splits.push(seq.len() - 2);
        }
        splits.sort_unstable();
        splits.dedup();
        for split_at in splits {
            push(build(Some(split_at)));
        }
    }
    out
}

/// The source names a constructor of `class_descriptor` may be written as.
fn class_constructor_names(class_descriptor: &str) -> Vec<String> {
    let mut names = vec!["constructor".to_string()];
    let inner = class_inner(class_descriptor.trim_start_matches('['));
    let binary_cls = inner.rsplit('/').next().unwrap_or(inner);
    let last = binary_cls.rsplit('$').next().unwrap_or(binary_cls);
    if !last.is_empty() {
        push_unique(&mut names, last.to_string());
        if last.bytes().all(|b| b.is_ascii_digit()) {
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

/// The DEX names or `name(params)ret` signatures a method written as
/// decompiled source spells it may stand for (`Cdo`, `m$2`, `` `in` ``, the
/// class name or `constructor` for `<init>`, Java parameter types), in the
/// class `class_descriptor` when it is known. The method as written is
/// excluded.
pub fn denormalize_method_candidates(class_descriptor: Option<&str>, method: &str) -> Vec<String> {
    let trimmed = method.trim();
    let member = trimmed.rsplit_once("->").map_or(trimmed, |(_, m)| m);
    let (raw_name, sig_tail) = match member.find('(') {
        Some(i) => (member[..i].trim(), Some(&member[i..])),
        None => (member.trim(), None),
    };
    let unquoted = raw_name.trim_matches('`');
    let mut name_cands = vec![raw_name.to_string()];
    for d in denormalize_identifier(raw_name) {
        push_unique(&mut name_cands, d);
    }
    let constructor = match class_descriptor {
        Some(cls) => {
            let as_written = class_constructor_names(cls);
            as_written.iter().any(|n| n == raw_name || n == unquoted)
                || denormalize_class_candidates(cls)
                    .iter()
                    .any(|c| class_constructor_names(c).iter().any(|n| !as_written.contains(n) && (n == raw_name || n == unquoted)))
        }
        None => raw_name == "constructor" || anonymous_number(raw_name).is_some(),
    };
    if constructor {
        push_unique(&mut name_cands, "<init>".to_string());
    }

    let mut sig_cands = Vec::new();
    match sig_tail {
        None => sig_cands.push(String::new()),
        Some(sig) => {
            sig_cands.push(sig.to_string());
            push_unique(&mut sig_cands, denormalize_signature_types(sig));
            if let Some(dalvik_sig) = java_signature_to_dalvik(&format!("m{sig}")).and_then(|d| d.strip_prefix('m').map(str::to_string)) {
                push_unique(&mut sig_cands, denormalize_signature_types(&dalvik_sig));
                push_unique(&mut sig_cands, dalvik_sig);
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
            // A constructor returns void, and every lookup wants a full
            // `(params)ret` proto.
            if n == "<init>" && s.ends_with(')') {
                push_unique(&mut out, format!("{combined}V"));
            }
        }
    }
    out
}

/// `sig` (`(params)ret` or `:type`) with each class descriptor in it
/// replaced by its most likely DEX descriptor.
pub(crate) fn denormalize_signature_types(sig: &str) -> String {
    let mut out = String::with_capacity(sig.len());
    let mut rest = sig;
    while let Some(l_pos) = rest.find('L') {
        out.push_str(&rest[..l_pos]);
        let after_l = &rest[l_pos..];
        let Some(semi) = after_l.find(';') else {
            out.push_str(after_l);
            rest = "";
            break;
        };
        let desc = &after_l[..=semi];
        match denormalize_class_candidates(desc).into_iter().next() {
            Some(first) => out.push_str(&first),
            None => out.push_str(desc),
        }
        rest = &after_l[semi + 1..];
    }
    out.push_str(rest);
    out
}

fn denormalize_type_match(tm: &TypeMatch) -> Option<TypeMatch> {
    match tm {
        TypeMatch::Descriptor(d) => denormalize_class_candidates(d).into_iter().next().map(TypeMatch::Descriptor),
        TypeMatch::Simple { name, dims } => {
            let name = match anonymous_number(name) {
                Some(num) => format!("${num}"),
                None => denormalize_identifier(name).into_iter().next()?,
            };
            Some(TypeMatch::Simple { name, dims: *dims })
        }
    }
}

fn denormalize_member_signature(sig: &MemberSignature) -> Option<MemberSignature> {
    match sig {
        MemberSignature::Field(tm) => denormalize_type_match(tm).map(MemberSignature::Field),
        MemberSignature::Method { params, ret } => {
            let mut changed = false;
            let mut map = |t: &TypeMatch| match denormalize_type_match(t) {
                Some(n) => {
                    changed = true;
                    n
                }
                None => t.clone(),
            };
            let params = params.iter().map(&mut map).collect();
            let ret = ret.as_ref().map(&mut map);
            changed.then_some(MemberSignature::Method { params, ret })
        }
    }
}

/// The simple class name of a `[/L]Name;\x00` pattern (what
/// `member_query` makes of a class without package), unescaped.
fn simple_class_name(pattern: &str) -> Option<String> {
    pattern.strip_prefix("[/L]").and_then(|s| s.strip_suffix(";\\x00")).map(|s| s.replace('\\', ""))
}

/// `mq` and its readings as decompiled source names, `mq` first.
fn denormalize_member_query(mq: &MemberQuery, is_method: bool) -> Vec<MemberQuery> {
    let mut class_cands: Vec<Option<ClassQuery>> = vec![mq.class.clone()];
    // The class as a descriptor, to recognise constructor names.
    let mut class_descriptor = None;
    if let Some(cq) = &mq.class {
        if cq.precise {
            class_descriptor = Some(cq.pattern.clone());
            class_cands.extend(denormalize_class_candidates(&cq.pattern).into_iter().map(|c| Some(ClassQuery::exact(c))));
        } else if let Some(simple) = simple_class_name(&cq.pattern) {
            class_descriptor = Some(format!("L{simple};"));
            if let Some(num) = anonymous_number(&simple) {
                class_cands.push(Some(ClassQuery::fuzzy(format!("\\${num};\\x00"))));
            }
            for d in denormalize_identifier(&simple) {
                class_cands.push(Some(ClassQuery::fuzzy(format!("[/L]{};\\x00", regex::escape(&d)))));
            }
        } else {
            for c in denormalize_class_candidates(&cq.pattern) {
                class_cands.push(Some(ClassQuery::fuzzy(regex::escape(class_inner(&c)))));
            }
        }
    }

    let mut name_cands: Vec<Option<String>> = vec![mq.name.clone()];
    if let Some(name) = &mq.name {
        let extras =
            if is_method { denormalize_method_candidates(class_descriptor.as_deref(), name) } else { denormalize_identifier(name) };
        for e in extras {
            // A method candidate may carry a signature (`<init>(I)V`): the
            // query's own signature constraint covers that.
            let e = if is_method { e.split('(').next().unwrap_or(&e).to_string() } else { e };
            let opt = Some(e);
            if !name_cands.contains(&opt) {
                name_cands.push(opt);
            }
        }
    }

    let mut sig_cands: Vec<Option<MemberSignature>> = vec![mq.signature.clone()];
    if let Some(ns) = mq.signature.as_ref().and_then(denormalize_member_signature) {
        sig_cands.push(Some(ns));
    }

    let mut out = vec![mq.clone()];
    for c in &class_cands {
        for n in &name_cands {
            for s in &sig_cands {
                // A name this fallback made up (`a$2` → `a`, `Cdo` → `do`) is
                // matched whole: as a substring on a precise class it would
                // also hit every member whose name merely contains it.
                let exact_name = mq.exact_name || n != &mq.name;
                let cand =
                    MemberQuery::default().with_class(c.clone()).with_name(n.clone()).with_exact_name(exact_name).with_signature(s.clone());
                if !out.contains(&cand) {
                    out.push(cand);
                }
            }
        }
    }
    out
}

/// `q` with its class, method and field names also read as decompiled
/// Java / Kotlin source spells them (see [`denormalize_class_candidates`],
/// [`denormalize_method_candidates`], [`denormalize_identifier`]); `None`
/// when no part of `q` reads differently. The result still matches what
/// `q` matches: it is meant to be run when `q` found nothing.
pub fn denormalize_query(q: &Query) -> Option<Query> {
    match q {
        Query::Type(pat) => {
            let mut cands = denormalize_class_candidates(pat);
            if cands.is_empty() {
                cands = denormalize_identifier(pat);
            }
            if cands.is_empty() {
                return None;
            }
            let alternatives: Vec<String> = std::iter::once(format!("(?:{pat})")).chain(cands.iter().map(|c| regex::escape(c))).collect();
            Some(Query::Type(format!("(?:{})", alternatives.join("|"))))
        }
        Query::Extends(cls) => denormalize_class_candidates(cls).into_iter().next().map(Query::Extends),
        Query::Implements(cls) => denormalize_class_candidates(cls).into_iter().next().map(Query::Implements),
        Query::Method(mq) => {
            let vars = denormalize_member_query(mq, true);
            (vars.len() > 1).then_some(Query::MethodSet(vars))
        }
        Query::Field(mq) => {
            let vars = denormalize_member_query(mq, false);
            (vars.len() > 1).then(|| collapse_field_variants(&vars)).map(Query::Field)
        }
        Query::FieldAccess { field, access } => {
            let vars = denormalize_member_query(field, false);
            (vars.len() > 1).then(|| Query::FieldAccess { field: collapse_field_variants(&vars), access: *access })
        }
        Query::Call { target, constraints } => {
            denormalize_query(target).map(|t| Query::Call { target: Box::new(t), constraints: constraints.clone() })
        }
        Query::All { all, none } => {
            let mut changed = false;
            let all = all
                .iter()
                .map(|part| match denormalize_query(part) {
                    Some(np) => {
                        changed = true;
                        np
                    }
                    None => part.clone(),
                })
                .collect();
            changed.then(|| Query::All { all, none: none.clone() })
        }
        _ => None,
    }
}

/// One field query matching any of `vars` (there is no field set): class and
/// name become alternations of whole-string patterns. The signature of the
/// last variant that has one is kept.
fn collapse_field_variants(vars: &[MemberQuery]) -> MemberQuery {
    let anchored = |s: &str| format!("^{}\\x00", regex::escape(s));
    let mut classes = Vec::new();
    let mut names = Vec::new();
    for v in vars {
        if let Some(c) = &v.class {
            push_unique(&mut classes, if c.precise { anchored(&c.pattern) } else { c.pattern.clone() });
        }
        if let Some(n) = &v.name {
            push_unique(&mut names, if v.exact_name { anchored(n) } else { regex::escape(n) });
        }
    }
    let first = &vars[0];
    let signature = vars.iter().rev().find_map(|v| v.signature.clone());
    let single_precise = classes.len() == 1 && first.class.as_ref().is_some_and(|c| c.precise);
    if single_precise && names.len() <= 1 {
        // One class and at most one name: keep the query as precise as it was.
        return first.clone().with_signature(signature);
    }
    let class = (!classes.is_empty()).then(|| ClassQuery::fuzzy(format!("(?:{})", classes.join("|"))));
    let name = (!names.is_empty()).then(|| format!("(?:{})", names.join("|")));
    MemberQuery::default().with_class(class).with_name(name).with_signature(signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_lose_their_source_escapes() {
        assert_eq!(denormalize_identifier("Cdo"), ["do"]);
        assert_eq!(denormalize_identifier("C_"), ["_"]);
        assert_eq!(denormalize_identifier("C1a"), ["1a"]);
        assert_eq!(denormalize_identifier("`in`"), ["in"]);
        assert_eq!(denormalize_identifier("_dex_61_2D_62_"), ["a-b"]);
        assert_eq!(denormalize_identifier("m$2"), ["m"]);
        assert_eq!(denormalize_identifier("Cdo$2"), ["Cdo", "do"]);
        assert!(denormalize_identifier("Class").is_empty());
        assert!(denormalize_identifier("m$1").is_empty());
        assert!(denormalize_identifier("plain").is_empty());
    }

    #[test]
    fn dotted_nested_and_anonymous_classes_become_descriptors() {
        let c = denormalize_class_candidates("com.app.Outer.Inner");
        assert_eq!(c.first().map(String::as_str), Some("Lcom/app/Outer$Inner;"));
        let c = denormalize_class_candidates("com.app.Outer.Inner.Deep");
        assert_eq!(c.first().map(String::as_str), Some("Lcom/app/Outer$Inner$Deep;"));
        assert!(denormalize_class_candidates("com.app.Outer.Anonymous1").contains(&"Lcom/app/Outer$1;".to_string()));
        assert!(denormalize_class_candidates("com.Cpkg.Cdo.Cif").contains(&"Lcom/Cpkg/do/if;".to_string()));
        assert!(denormalize_class_candidates("com.kt.`in`.When").contains(&"Lcom/kt/in/When;".to_string()));
        // Arrays keep their dimensions; the name as written is left out.
        assert_eq!(denormalize_class_candidates("[Lcom/a/Outer/Inner;").first().map(String::as_str), Some("[Lcom/a/Outer$Inner;"));
        assert!(!denormalize_class_candidates("Lcom/a/Outer$Inner;").contains(&"Lcom/a/Outer$Inner;".to_string()));
        assert!(denormalize_class_candidates("I").is_empty());
    }

    #[test]
    fn methods_read_as_constructors_escapes_and_java_signatures() {
        let m = denormalize_method_candidates(Some("Lcom/app/Outer;"), "Outer");
        assert!(m.contains(&"<init>".to_string()), "{m:?}");
        let m = denormalize_method_candidates(Some("Lcom/app/Outer;"), "Outer(int)");
        assert!(m.contains(&"<init>(I)V".to_string()), "{m:?}");
        let m = denormalize_method_candidates(Some("Lcom/app/Outer$1;"), "Anonymous1");
        assert!(m.contains(&"<init>".to_string()), "{m:?}");
        assert_eq!(denormalize_method_candidates(None, "Cwhile"), ["while"]);
        let m = denormalize_method_candidates(None, "entry(com.app.Outer.Inner)");
        assert!(m.contains(&"entry(Lcom/app/Outer$Inner;)".to_string()), "{m:?}");
        assert!(denormalize_method_candidates(Some("Lcom/app/Outer;"), "run").is_empty());
    }

    #[test]
    fn return_less_signatures_become_proto_prefixes() {
        assert_eq!(partial_proto("run(int)"), Some(("run".into(), "(I)".into())));
        assert_eq!(partial_proto("entry(com.app.Outer.Inner)"), Some(("entry".into(), "(Lcom/app/Outer$Inner;)".into())));
        assert_eq!(partial_proto("run(I"), None);
        assert_eq!(partial_proto("run"), None);
        assert!(proto_matches("(I)V", "(I)"));
        assert!(proto_matches("(I)V", "(I)V"));
        assert!(!proto_matches("(II)V", "(I)"));
        assert!(!proto_matches("(I)V", "(I)Z"));
    }

    #[test]
    fn queries_keep_what_they_matched_and_add_the_readings() {
        let mq = MemberQuery::default().with_class(Some(ClassQuery::exact("Lcom/app/Outer/Inner;"))).with_name(Some("work".into()));
        let Some(Query::MethodSet(set)) = denormalize_query(&Query::Method(mq.clone())) else { panic!("a method set") };
        assert_eq!(set[0], mq);
        assert!(set.iter().any(|m| m.class == Some(ClassQuery::exact("Lcom/app/Outer$Inner;"))), "{set:?}");
        // Nothing to read differently: no fallback.
        let plain = MemberQuery::default().with_name(Some("work".into()));
        assert_eq!(denormalize_query(&Query::Method(plain)), None);
        assert_eq!(denormalize_query(&Query::String("x".into())), None);
        let Some(Query::Field(f)) = denormalize_query(&Query::Field(
            MemberQuery::default().with_class(Some(ClassQuery::exact("Lcom/app/C;"))).with_name(Some("a$2".into())).with_exact_name(true),
        )) else {
            panic!("a field query")
        };
        assert_eq!(f.name.as_deref(), Some("(?:^a\\$2\\x00|^a\\x00)"));
        assert!(!f.exact_name);
    }
}
