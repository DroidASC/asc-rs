//! Class-name normalisation shared by the CLI and GUI.

use crate::{EngineError, Result};
use asc_findrefs::{ClassQuery, MemberQuery};

/// Turn `com.poc.Main` / `com/poc/Main` / `Lcom/poc/Main;` into a Dalvik descriptor.
pub fn format_class_name(name: &str) -> Result<String> {
    if name.is_empty() {
        return Err(EngineError::Query("Class name cannot be empty".into()));
    }
    if name.starts_with('L') && name.ends_with(';') && name.contains('/') {
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

/// Build a member (method/field) query from CLI-style arguments.
pub fn member_query(kind: &str, class: Option<&str>, fuzzy_class: bool, name: Option<&str>) -> Result<MemberQuery> {
    let class = class.filter(|c| !c.is_empty());
    let name = name.filter(|n| !n.is_empty());
    if class.is_none() && name.is_none() {
        return Err(EngineError::Query(format!("{kind} query needs at least one of class or {kind} name")));
    }
    let class = match class {
        Some(c) => Some(ClassQuery { pattern: normalize_class_query(c, fuzzy_class)?, precise: !fuzzy_class }),
        None => None,
    };
    Ok(MemberQuery { class, name: name.map(String::from) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_names() {
        assert_eq!(format_class_name("com.poc.Main").unwrap(), "Lcom/poc/Main;");
        assert_eq!(format_class_name("Lcom/poc/Main;").unwrap(), "Lcom/poc/Main;");
        assert_eq!(format_class_name("com/poc/Main").unwrap(), "Lcom/poc/Main;");
        assert_eq!(dalvik_to_dot("Lcom/poc/Main;"), "com.poc.Main");
        assert_eq!(normalize_class_query("com.poc", true).unwrap(), "com/poc");
        assert_eq!(normalize_class_query("poc", true).unwrap(), "poc");
        assert!(format_class_name("").is_err());
        assert!(member_query("method", None, false, None).is_err());
        let q = member_query("method", Some("com.poc.Main"), false, Some("on")).unwrap();
        assert_eq!(q.class.unwrap(), ClassQuery { pattern: "Lcom/poc/Main;".into(), precise: true });
    }
}
