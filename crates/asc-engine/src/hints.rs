//! What to tell an agent when a lookup comes up empty: that a class belongs
//! to the framework, the classes or members it probably meant, why a search
//! found nothing. Only computed on those paths, so it may scan the APK.

use crate::{names, Engine, Result};
use asc_dex::Dex;
use asc_findrefs::{MemberQuery, MemberSignature, Query};

/// Suggestions per hint.
const MAX_SUGGESTIONS: usize = 5;
/// Members listed in one hint.
const MAX_MEMBERS: usize = 8;
/// Packages an APK uses but does not define (the framework and the JDK).
const FRAMEWORK: &[&str] = &["Landroid/", "Ljava/", "Ljavax/", "Lkotlin/", "Ldalvik/", "Lorg/json/", "Lorg/xml/", "Lorg/w3c/", "Lsun/"];

/// Whether `descriptor` is in a package the Android runtime provides.
pub fn is_framework_class(descriptor: &str) -> bool {
    FRAMEWORK.iter().any(|p| descriptor.starts_with(p))
}

/// `Lcom/a/B$Inner;` → `inner`: what a class is called without its package
/// or outer classes, lowercased.
fn simple_name(descriptor: &str) -> String {
    let inner = names::class_inner(descriptor);
    inner.rsplit(['/', '$']).next().unwrap_or(inner).to_ascii_lowercase()
}

/// The classes of `all` closest to `target`: same simple name first, then by
/// edit distance; at most [`MAX_SUGGESTIONS`].
fn similar_classes<'a>(target: &str, all: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
    let want = simple_name(target);
    let max = (target.len() / 8).max(2);
    let mut scored: Vec<(usize, &str)> = all
        .filter_map(|d| if simple_name(d) == want { Some((0, d)) } else { names::edit_distance(target, d, max).map(|k| (k, d)) })
        .collect();
    scored.sort_unstable();
    scored.dedup();
    scored.into_iter().take(MAX_SUGGESTIONS).map(|(_, d)| d).collect()
}

/// `name(params)ret` (methods) or `name:T` (fields) of every member of
/// `class` that `dex` references or defines, in id order.
fn class_members(dex: &Dex<'_>, class: &str, methods: bool) -> Result<Vec<String>> {
    let Some(class_idx) = dex.find_type_idx(&asc_dex::mutf8::encode(class))? else { return Ok(Vec::new()) };
    let count = if methods { dex.method_count() } else { dex.field_count() };
    let class_of = |i: u32| -> Result<u32> { Ok(if methods { dex.method_id(i)?.class_idx } else { dex.field_id(i)?.class_idx } as u32) };
    // Both id tables are sorted by class first.
    let (mut lo, mut hi) = (0, count);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if class_of(mid)? < class_idx {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let mut out = Vec::new();
    for i in lo..count {
        if class_of(i)? != class_idx {
            break;
        }
        let signature = if methods { asc_smali::method_signature(dex, i)? } else { asc_smali::field_signature(dex, i)? };
        out.push(signature.split_once("->").map_or(signature.clone(), |(_, m)| m.to_string()));
    }
    Ok(out)
}

/// `a, b, c` for at most [`MAX_MEMBERS`] items, then how many were left out.
fn list_some<S: AsRef<str>>(items: &[S]) -> String {
    let mut out = items.iter().take(MAX_MEMBERS).map(AsRef::as_ref).collect::<Vec<_>>().join(", ");
    if items.len() > MAX_MEMBERS {
        out.push_str(&format!(" … ({} in all)", items.len()));
    }
    out
}

/// Whether the member `m` as [`class_members`] writes it (`name(params)ret`
/// or `name:T`) has `signature`.
fn has_signature(m: &str, signature: &MemberSignature) -> bool {
    match signature {
        MemberSignature::Method { params, ret } => {
            let Some((have, have_ret)) = m.split_once('(').and_then(|(_, r)| r.split_once(')')) else { return false };
            let Some(have) = names::dalvik_types(have) else { return false };
            have.len() == params.len()
                && have.iter().zip(params).all(|(h, p)| p.matches(h))
                && ret.as_ref().is_none_or(|r| r.matches(have_ret))
        }
        MemberSignature::Field(t) => m.split_once(':').is_some_and(|(_, have)| t.matches(have)),
    }
}

/// The members of `members` worth showing for `name`: the same name (any
/// case), then names within a small edit distance, else all of them.
fn closest_members(members: &[String], name: Option<&str>) -> Vec<String> {
    let member_name = |m: &str| m.split(['(', ':']).next().unwrap_or(m).to_string();
    let mut picked: Vec<String> = match name {
        Some(n) => {
            let want = n.to_ascii_lowercase();
            let mut scored: Vec<(usize, &String)> = members
                .iter()
                .filter_map(|m| {
                    let have = member_name(m).to_ascii_lowercase();
                    if have == want || have.contains(&want) {
                        Some((0, m))
                    } else {
                        names::edit_distance(&want, &have, 3).map(|k| (k, m))
                    }
                })
                .collect();
            scored.sort();
            scored.into_iter().map(|(_, m)| m.clone()).collect()
        }
        None => Vec::new(),
    };
    if picked.is_empty() {
        picked = members.to_vec();
    }
    picked.dedup();
    picked
}

/// `res/xml-v21/file.xml` → `xml/file`: the resource a file path names.
fn resource_name_of(path: &str) -> Option<String> {
    let rest = path.strip_prefix("res/")?;
    let (dir, file) = rest.split_once('/')?;
    let type_name = dir.split('-').next()?;
    let stem = file.split('.').next()?;
    (!stem.is_empty()).then(|| format!("{type_name}/{stem}"))
}

/// Where a shrunk APK keeps the files `res/<dir>/` would hold: the
/// directories holding entries of `path`'s extension, largest first.
fn renamed_resources_hint(entries: &[String], path: &str) -> String {
    let ext = path.rsplit_once('.').map_or("", |(_, e)| e);
    let mut dirs: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for e in entries.iter().filter(|e| !ext.is_empty() && e.ends_with(&format!(".{ext}")) && e.as_str() != "AndroidManifest.xml") {
        *dirs.entry(e.rsplit_once('/').map_or("", |(d, _)| d)).or_default() += 1;
    }
    let mut dirs: Vec<(&str, usize)> = dirs.into_iter().collect();
    dirs.sort_by_key(|d| std::cmp::Reverse(d.1));
    let listed: Vec<String> = dirs.iter().take(3).map(|(d, n)| format!("{d}/ ({n})")).collect();
    format!(
        "resource files may be renamed by a shrinker; .{ext} files here live in {}: the manifest (manifest_summary) names the ones it uses",
        if listed.is_empty() { "no directory".to_string() } else { listed.join(", ") }
    )
}

impl Engine {
    /// Why `descriptor` is not in the APK and what to try, appended to
    /// "class … not found in APK": framework classes are only used, other
    /// names get the closest classes the APK defines.
    pub(crate) fn class_not_found_hint(&self, descriptor: &str) -> String {
        let classes = self.list_classes(None).unwrap_or_default();
        // Apps bundle and obfuscators reuse some of these packages (Douyin
        // defines classes under `kotlin/jvm/internal/`): framework only when
        // the APK defines nothing in the class's package.
        let package = descriptor.rfind('/').map_or("L", |i| &descriptor[..=i]);
        if is_framework_class(descriptor) && !classes.iter().any(|c| c.descriptor.starts_with(package)) {
            return format!(
                ": it is an Android / Java framework class, which the APK uses but does not define. \
                 Find its uses with findrefs type {descriptor} (or method / field with class {descriptor}), \
                 subclasses with findrefs extends {descriptor}"
            );
        }
        let similar = similar_classes(descriptor, classes.iter().map(|c| c.descriptor.as_str()));
        if similar.is_empty() {
            String::new()
        } else {
            format!("; did you mean {}", similar.join(", "))
        }
    }

    /// For "entry … not found": entries with the same file name or a close
    /// path, and where the resource of a `res/<type>/<name>.<ext>` path is
    /// really stored (shrinkers rename resource files, e.g. `res/7dm.xml`).
    pub(crate) fn entry_not_found_hint(&self, path: &str) -> String {
        let mut hints = Vec::new();
        if let Some(stored) = self.resource_file(path) {
            hints.push(format!("resource {} is stored at {stored}", resource_name_of(path).unwrap_or_default()));
        }
        let entries: Vec<String> =
            self.open().and_then(|a| Ok(a.entries()?)).map(|e| e.into_iter().map(|e| e.name).collect()).unwrap_or_default();
        let file = path.rsplit('/').next().unwrap_or(path);
        let mut similar: Vec<(usize, &str)> = entries
            .iter()
            .filter_map(|e| {
                if e.rsplit('/').next() == Some(file) {
                    Some((0, e.as_str()))
                } else {
                    names::edit_distance(path, e, 3).map(|k| (k, e.as_str()))
                }
            })
            .collect();
        similar.sort_unstable();
        if !similar.is_empty() {
            hints.push(format!("did you mean {}", similar.iter().take(MAX_SUGGESTIONS).map(|(_, e)| *e).collect::<Vec<_>>().join(", ")));
        }
        if hints.is_empty() && path.starts_with("res/") {
            hints.push(renamed_resources_hint(&entries, path));
        }
        hints.iter().map(|h| format!("; {h}")).collect()
    }

    /// The entry the resource `res/<type>/<name>.<ext>` names is stored at,
    /// when resources.arsc maps it elsewhere.
    fn resource_file(&self, path: &str) -> Option<String> {
        let name = resource_name_of(path)?;
        let table = self.resources().ok()??;
        let id = table.lookup(&name)?;
        table
            .values(id)
            .into_iter()
            .map(|v| table.format_entry(id, &v.value))
            .map(|v| v.trim_matches('"').to_string())
            .find(|v| v != path && v.starts_with("res/"))
    }

    /// For "no resource …": resources of a close name, the same type first.
    pub(crate) fn resource_not_found_hint(&self, table: &asc_arsc::ResTable, query: &str) -> String {
        let want = query.trim_start_matches('@');
        let want_type = want.split_once('/').map(|(t, _)| t);
        let mut scored: Vec<(usize, String)> = table
            .ids()
            .into_iter()
            .filter_map(|id| {
                let name = table.ref_name(id);
                let same_type = want_type.is_some_and(|t| name.split_once('/').is_some_and(|(nt, _)| nt == t));
                let k = names::edit_distance(&want.to_ascii_lowercase(), &name.to_ascii_lowercase(), 3)?;
                Some((k + usize::from(!same_type), name))
            })
            .collect();
        scored.sort();
        scored.dedup();
        match scored.len() {
            0 => "; resource names may be obfuscated: the manifest (manifest_summary) names the files it uses, and search finds names and values".into(),
            _ => format!("; did you mean {}", scored.into_iter().take(MAX_SUGGESTIONS).map(|(_, n)| n).collect::<Vec<_>>().join(", ")),
        }
    }

    /// The members of `class` near `name` that the APK knows, for "no method
    /// …" errors: `"; Lc; has a(I)V, b()V"`, or the class hint when no DEX
    /// references `class` at all.
    pub(crate) fn member_not_found_hint(&self, class: &str, name: Option<&str>, methods: bool) -> String {
        let members = self.class_member_list(class, methods);
        if members.is_empty() {
            return format!("; no DEX references {class}{}", self.class_not_found_hint(class));
        }
        format!("; {class} has {}", list_some(&closest_members(&members, name)))
    }

    /// Every member of `class` any DEX references or defines, sorted.
    fn class_member_list(&self, class: &str, methods: bool) -> Vec<String> {
        let Ok((views, _)) = self.load_views(None) else { return Vec::new() };
        let mut members = Vec::new();
        for v in &views {
            if let Ok(dex) = Dex::with_name(&v.data, &v.name) {
                members.extend(class_members(&dex, class, methods).unwrap_or_default());
            }
        }
        members.sort();
        members.dedup();
        members
    }

    /// One line each on why a search over `entries` DEX entries found
    /// nothing and what to change: case-sensitive patterns, a class no DEX
    /// references, members that do exist, direct relations only.
    pub fn no_results_hints(&self, query: &Query, entries: usize) -> Vec<String> {
        let mut out = vec![format!("searched {entries} DEX entr{}", if entries == 1 { "y" } else { "ies" })];
        match query {
            Query::Method(m) | Query::Field(m) => {
                out.extend(self.member_query_hint(m, matches!(query, Query::Method(_))).or_else(|| query_hint(query)));
            }
            _ => out.extend(query_hint(query)),
        }
        out
    }

    /// For a member query with an exact class: whether the class or the
    /// member is absent, or the member exists but no code references it.
    fn member_query_hint(&self, m: &MemberQuery, methods: bool) -> Option<String> {
        let class = &m.class.as_ref().filter(|c| c.precise)?.pattern;
        let kind = if methods { "method" } else { "field" };
        let members = self.class_member_list(class, methods);
        if members.is_empty() {
            return Some(format!("no DEX references {class}{}", self.class_not_found_hint(class)));
        }
        let Some(name) = &m.name else {
            return Some(format!("{class} is known, but no code references its {kind}s"));
        };
        let member_name = |s: &str| s.split(['(', ':']).next().unwrap_or(s).to_string();
        let defined: Vec<&String> = members.iter().filter(|s| member_name(s) == *name).collect();
        let access = if methods { "calls it" } else { "reads or writes it" };
        Some(match &m.signature {
            _ if defined.is_empty() => {
                format!("{class} has no {kind} {name:?}; it has {}", list_some(&closest_members(&members, Some(name))))
            }
            Some(sig) if !defined.iter().any(|d| has_signature(d, sig)) => match sig {
                MemberSignature::Method { .. } => {
                    format!("{class}->{name} has no overload {sig}; it has {}: drop the signature for every overload", list_some(&defined))
                }
                MemberSignature::Field(_) => format!("{class}->{name} is {}, not {sig}: drop the type to match it", list_some(&defined)),
            },
            _ => format!(
                "{class}->{name} exists ({}), but no code {access}: findrefs lists references, not definitions",
                list_some(&defined)
            ),
        })
    }
}

/// What a zero-result `query` itself suggests, without looking at an APK
/// (so also for searches over many APKs).
pub fn query_hint(query: &Query) -> Option<String> {
    Some(match query {
        Query::String(p) if p.chars().any(char::is_alphabetic) && !p.starts_with("(?i") => {
            "string patterns are case-sensitive regexes: prefix (?i) to ignore case".into()
        }
        Query::StringLiteral(_) => "literal matches are case-sensitive; a string regex with (?i) ignores case".into(),
        Query::Method(MemberQuery { signature: Some(sig), .. }) | Query::Field(MemberQuery { signature: Some(sig), .. }) => {
            format!("only members of signature {sig} match: drop it for every overload")
        }
        Query::Method(MemberQuery { exact_name: true, .. }) | Query::Field(MemberQuery { exact_name: true, .. }) => {
            "findrefs lists references, not definitions; the name is matched exactly (without = or a signature it is a pattern)".into()
        }
        Query::Extends(_) | Query::Implements(_) => {
            "only direct subclasses / implementers are listed: hierarchy walks the whole tree".into()
        }
        Query::All { .. } => "every `all` condition must match inside the same method".into(),
        Query::String(_) | Query::Type(_) | Query::Method(_) | Query::Field(_) => return None,
    })
}

/// The first hint line of a search over many APKs that found nothing.
pub fn searched_hint(apks: usize, entries: usize) -> String {
    format!("searched {apks} APK{} ({entries} DEX entr{})", if apks == 1 { "" } else { "s" }, if entries == 1 { "y" } else { "ies" })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn similar_classes_rank_simple_names_then_edits() {
        let all = ["Lcom/a/WebViewHelper;", "Lcom/a/B$Inner;", "Lcom/b/Main;", "Lcom/a/Mian;", "Lx/y/Z;"];
        assert_eq!(similar_classes("Lcom/a/B/Inner;", all.into_iter()), ["Lcom/a/B$Inner;"]);
        assert_eq!(similar_classes("Lcom/a/Main;", all.into_iter()), ["Lcom/b/Main;", "Lcom/a/Mian;"]);
        assert!(similar_classes("Lorg/nothing/Like;", all.into_iter()).is_empty());
    }

    #[test]
    fn closest_members_prefer_the_name() {
        let members: Vec<String> = ["a()V", "loadUrl(Ljava/lang/String;)V", "loadData()V", "zz()V"].map(String::from).into();
        assert_eq!(closest_members(&members, Some("loadurl")), ["loadUrl(Ljava/lang/String;)V"]);
        assert_eq!(closest_members(&members, Some("loadDta"))[0], "loadData()V");
        assert_eq!(closest_members(&members, Some("nothing")), members);
        let many: Vec<String> = (0..20).map(|i| format!("f{i}:I")).collect();
        assert_eq!(list_some(&many), "f0:I, f1:I, f2:I, f3:I, f4:I, f5:I, f6:I, f7:I … (20 in all)");
        assert_eq!(list_some(&members[..2]), "a()V, loadUrl(Ljava/lang/String;)V");
        let sig = names::parse_signature("(String)", true).unwrap();
        assert!(has_signature("loadUrl(Ljava/lang/String;)V", &sig) && !has_signature("a()V", &sig));
        assert!(has_signature("f:I", &names::parse_signature(":int", false).unwrap()));
        assert!(is_framework_class("Landroid/app/Activity;") && !is_framework_class("Landroidx/core/A;"));
        assert_eq!(resource_name_of("res/xml-v21/file_paths.xml").as_deref(), Some("xml/file_paths"));
        assert_eq!(resource_name_of("AndroidManifest.xml"), None);
    }
}
