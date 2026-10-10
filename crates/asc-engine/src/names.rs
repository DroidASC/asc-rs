//! Class-name normalisation shared by the CLI and GUI.

use crate::{EngineError, Result};
use asc_findrefs::{ClassQuery, MemberQuery};

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

/// Build a member (method/field) query from CLI-style arguments; `exact_name`
/// matches the member name as a whole instead of as a substring / regex.
pub fn member_query(kind: &str, class: Option<&str>, fuzzy_class: bool, name: Option<&str>, exact_name: bool) -> Result<MemberQuery> {
    let class = class.filter(|c| !c.is_empty());
    let name = name.filter(|n| !n.is_empty());
    if class.is_none() && name.is_none() {
        return Err(EngineError::Query(format!("{kind} query needs at least one of class or {kind} name")));
    }
    let class = match class {
        Some(c) => Some(ClassQuery { pattern: normalize_class_query(c, fuzzy_class)?, precise: !fuzzy_class }),
        None => None,
    };
    Ok(MemberQuery { class, name: name.map(String::from), exact_name })
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
}
