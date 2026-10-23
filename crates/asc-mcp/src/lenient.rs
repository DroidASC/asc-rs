//! Arguments as models write them, rewritten to the documented ones before a
//! tool runs: key aliases (`class_name`, `apk_path`, `methodName`), a bare
//! number as the cursor, a whole `Lc;->m` target given as the class. Only
//! keys the canonical spelling leaves free are filled, so a correct call is
//! never changed.

use serde_json::{Map, Value};

/// `(alias, canonical)` for every tool.
const COMMON: &[(&str, &str)] = &[
    ("apk_path", "apk"),
    ("apkPath", "apk"),
    ("apk_file", "apk"),
    ("class_name", "class"),
    ("className", "class"),
    ("class_descriptor", "class"),
    ("cls", "class"),
    ("maxBytes", "max_bytes"),
];

/// `(alias, canonical)` for findrefs (and each of its conditions).
const FINDREFS: &[(&str, &str)] = &[
    ("type", "kind"),
    ("query_kind", "kind"),
    ("method_name", "name"),
    ("methodName", "name"),
    ("field_name", "name"),
    ("fieldName", "name"),
    ("member", "name"),
    ("pattern", "value"),
    ("target", "value"),
    ("fuzzyClass", "fuzzy_class"),
];

/// `(alias, canonical)` for the tools naming one method of a class.
const METHOD_TOOLS: &[(&str, &str)] = &[("method_name", "method"), ("methodName", "method"), ("signature", "method")];

/// `args` with the aliases of `tool` renamed and model habits undone, or
/// `None` when nothing needed changing.
pub fn normalize(tool: &str, args: &Value) -> Option<Value> {
    let mut out = args.as_object()?.clone();
    let mut changed = rename(&mut out, COMMON);
    match tool {
        "findrefs" => changed |= findrefs(&mut out),
        "getclass" | "callgraph" | "hierarchy" => {
            changed |= rename(&mut out, METHOD_TOOLS);
            changed |= split_class_member(&mut out);
        }
        _ => {}
    }
    changed |= numeric_cursor(&mut out);
    changed.then_some(Value::Object(out))
}

fn rename(args: &mut Map<String, Value>, aliases: &[(&str, &str)]) -> bool {
    let mut changed = false;
    for (alias, canonical) in aliases {
        if !args.contains_key(*canonical) {
            if let Some(v) = args.remove(*alias) {
                args.insert((*canonical).to_string(), v);
                changed = true;
            }
        }
    }
    changed
}

fn findrefs(args: &mut Map<String, Value>) -> bool {
    // `type` is an alias of `kind` only when it is not the kind's value.
    let mut changed = if args.contains_key("kind") { false } else { rename(args, FINDREFS) };
    if args.contains_key("kind") {
        changed |= rename(args, &FINDREFS[1..]);
    }
    for key in ["all", "none", "rules"] {
        if let Some(Value::Array(list)) = args.get_mut(key) {
            for c in list.iter_mut() {
                if let Value::Object(o) = c {
                    changed |= findrefs(o);
                }
            }
        }
    }
    changed
}

/// `class: "Lc;->m(I)V"` with no `method`: the class and the method apart;
/// `method: "Lc;->m"` with no `class` likewise.
fn split_class_member(args: &mut Map<String, Value>) -> bool {
    let class = args.get("class").and_then(Value::as_str).map(str::to_string);
    let method = args.get("method").and_then(Value::as_str).map(str::to_string);
    let split = |s: &str| s.split_once("->").or_else(|| s.rsplit_once('#')).map(|(c, m)| (c.trim().to_string(), m.trim().to_string()));
    match (class, method) {
        (Some(c), None) => match split(&c) {
            Some((c, m)) if !c.is_empty() && !m.is_empty() => {
                args.insert("class".into(), Value::String(c));
                args.insert("method".into(), Value::String(m));
                true
            }
            _ => false,
        },
        (None, Some(m)) => match split(&m) {
            Some((c, m)) if !c.is_empty() && !m.is_empty() => {
                args.insert("class".into(), Value::String(c));
                args.insert("method".into(), Value::String(m));
                true
            }
            _ => false,
        },
        _ => false,
    }
}

/// A bare number as the cursor (`"100"`, `100`) is the offset to continue at.
fn numeric_cursor(args: &mut Map<String, Value>) -> bool {
    let offset = match args.get("cursor") {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(s)) => s.trim().parse::<u64>().ok(),
        _ => None,
    };
    match offset {
        Some(n) if !args.contains_key("offset") => {
            args.remove("cursor");
            args.insert("offset".into(), Value::from(n));
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn aliases_fill_only_free_keys() {
        let a = normalize("getclass", &json!({"apk_path": "x.apk", "class_name": "Lc;", "methodName": "m"})).unwrap();
        assert_eq!(a, json!({"apk": "x.apk", "class": "Lc;", "method": "m"}));
        // The canonical key wins; the alias is left alone.
        let a = normalize("getclass", &json!({"apk": "x.apk", "apk_path": "y.apk", "class": "Lc;"}));
        assert_eq!(a, None);
        assert_eq!(normalize("findrefs", &json!({"kind": "method", "class": "Lc;", "name": "m"})), None);
    }

    #[test]
    fn findrefs_aliases_reach_conditions() {
        let a = normalize("findrefs", &json!({"type": "method", "class_name": "Lc;", "method_name": "m"})).unwrap();
        assert_eq!(a, json!({"kind": "method", "class": "Lc;", "name": "m"}));
        // With a kind, `type` is not touched.
        let a = normalize("findrefs", &json!({"kind": "type", "pattern": "Lc;"})).unwrap();
        assert_eq!(a, json!({"kind": "type", "value": "Lc;"}));
        let a =
            normalize("findrefs", &json!({"all": [{"kind": "method", "methodName": "m"}, {"kind": "string", "pattern": "x"}]})).unwrap();
        assert_eq!(a, json!({"all": [{"kind": "method", "name": "m"}, {"kind": "string", "value": "x"}]}));
    }

    #[test]
    fn targets_and_cursors() {
        let a = normalize("callgraph", &json!({"class": "Lc;->run()V"})).unwrap();
        assert_eq!(a, json!({"class": "Lc;", "method": "run()V"}));
        let a = normalize("getclass", &json!({"method": "com.a.B#run"})).unwrap();
        assert_eq!(a, json!({"class": "com.a.B", "method": "run"}));
        assert_eq!(normalize("getclass", &json!({"class": "Lc;", "method": "Lc;->run"})), None);
        let a = normalize("manifest_summary", &json!({"cursor": "100"})).unwrap();
        assert_eq!(a, json!({"offset": 100}));
        assert_eq!(normalize("findrefs", &json!({"cursor": "3:2"})), None);
    }
}
