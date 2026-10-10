//! Phase 3: canonical id tables for the rebuilt DEX.

use crate::collect::RefSet;
use crate::{RebuildError, Result};
use asc_dex::{mutf8, Dex};
use std::collections::HashMap;

/// New id tables. Each `Vec` lists original indexes in new-index order and
/// each map goes from original index to new index.
#[derive(Debug, Default, Clone)]
pub struct Tables {
    pub strings: Vec<u32>,
    pub string_map: HashMap<u32, u32>,
    pub types: Vec<u32>,
    pub type_map: HashMap<u32, u32>,
    pub protos: Vec<u32>,
    pub proto_map: HashMap<u32, u32>,
    pub fields: Vec<u32>,
    pub field_map: HashMap<u32, u32>,
    pub methods: Vec<u32>,
    pub method_map: HashMap<u32, u32>,
}

fn lookup(map: &HashMap<u32, u32>, what: &'static str, idx: u32) -> Result<u32> {
    map.get(&idx).copied().ok_or_else(|| RebuildError::Internal(format!("{what} index {idx} was referenced but never collected")))
}

/// Sort `(key, original index)` pairs and number the distinct keys: the new
/// table (one original index per key, the lowest) and the map from every
/// original index to its new index.
fn assign<K: Ord>(mut items: Vec<(K, u32)>) -> (Vec<u32>, HashMap<u32, u32>) {
    items.sort_unstable();
    let mut order = Vec::with_capacity(items.len());
    let mut map = HashMap::with_capacity(items.len());
    let mut last: Option<K> = None;
    for (key, orig) in items {
        if last.as_ref() != Some(&key) {
            order.push(orig);
            last = Some(key);
        }
        map.insert(orig, order.len() as u32 - 1);
    }
    (order, map)
}

fn check_limit(what: &'static str, count: usize) -> Result<()> {
    if count > 0xFFFF {
        Err(RebuildError::TooManyItems { what, count })
    } else {
        Ok(())
    }
}

impl Tables {
    pub(crate) fn build(dex: &Dex<'_>, refs: &RefSet) -> Result<Tables> {
        let mut t = Tables::default();

        // Strings: sorted by UTF-16 code unit order, as the spec requires.
        // The writer re-encodes them canonically, so strings that only differ
        // in encoding (a malformed input) collapse into one id; the key of
        // every later table is built from new indexes and collapses with it.
        let mut strings: Vec<(Vec<u16>, u32)> = Vec::with_capacity(refs.strings.len());
        for &s in &refs.strings {
            strings.push((mutf8::to_utf16(dex.string_bytes(s)?), s));
        }
        (t.strings, t.string_map) = assign(strings);

        // Types: sorted by descriptor string index.
        let mut types: Vec<(u32, u32)> = Vec::with_capacity(refs.types.len());
        for &ty in &refs.types {
            types.push((t.map_string(dex.type_string_idx(ty)?)?, ty));
        }
        (t.types, t.type_map) = assign(types);
        check_limit("types", t.types.len())?;

        // Protos: sorted by return type then parameter list.
        let mut protos: Vec<((u32, Vec<u32>), u32)> = Vec::with_capacity(refs.protos.len());
        for &p in &refs.protos {
            let id = dex.proto_id(p)?;
            let params = dex.type_list(id.parameters_off)?.iter().map(|&x| t.map_type(x as u32)).collect::<Result<Vec<u32>>>()?;
            protos.push(((t.map_type(id.return_type_idx)?, params), p));
        }
        (t.protos, t.proto_map) = assign(protos);
        check_limit("protos", t.protos.len())?;

        // Fields: sorted by class, name, type.
        let mut fields: Vec<((u32, u32, u32), u32)> = Vec::with_capacity(refs.fields.len());
        for &f in &refs.fields {
            let id = dex.field_id(f)?;
            fields.push(((t.map_type(id.class_idx as u32)?, t.map_string(id.name_idx)?, t.map_type(id.type_idx as u32)?), f));
        }
        (t.fields, t.field_map) = assign(fields);
        check_limit("fields", t.fields.len())?;

        // Methods: sorted by class, name, proto.
        let mut methods: Vec<((u32, u32, u32), u32)> = Vec::with_capacity(refs.methods.len());
        for &m in &refs.methods {
            let id = dex.method_id(m)?;
            methods.push(((t.map_type(id.class_idx as u32)?, t.map_string(id.name_idx)?, t.map_proto(id.proto_idx as u32)?), m));
        }
        (t.methods, t.method_map) = assign(methods);
        check_limit("methods", t.methods.len())?;
        Ok(t)
    }

    /// New index of original string `idx`; `RebuildError::Internal` when it
    /// was never collected.
    #[inline]
    pub fn map_string(&self, idx: u32) -> Result<u32> {
        lookup(&self.string_map, "string", idx)
    }
    #[inline]
    pub fn map_type(&self, idx: u32) -> Result<u32> {
        lookup(&self.type_map, "type", idx)
    }
    #[inline]
    pub fn map_proto(&self, idx: u32) -> Result<u32> {
        lookup(&self.proto_map, "proto", idx)
    }
    #[inline]
    pub fn map_field(&self, idx: u32) -> Result<u32> {
        lookup(&self.field_map, "field", idx)
    }
    #[inline]
    pub fn map_method(&self, idx: u32) -> Result<u32> {
        lookup(&self.method_map, "method", idx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assign_numbers_distinct_keys() {
        // Original 7 and 3 share a key (one string in two encodings).
        let (order, map) = assign(vec![("b", 7), ("a", 5), ("b", 3), ("c", 1)]);
        assert_eq!(order, [5, 3, 1]);
        assert_eq!(map, HashMap::from([(5, 0), (3, 1), (7, 1), (1, 2)]));
    }
}
