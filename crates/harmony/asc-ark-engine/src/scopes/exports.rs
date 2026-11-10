//! Which class or function each module-level binding of a record holds.
//!
//! A binding with one writer holds what that store writes
//! ([`Scopes::module_binding`]). A class with a class decorator is written
//! twice: the class, then `C = decorator(C) || C`. The rule for those lives
//! here, once, for the hierarchy and the call graph alike: a binding with
//! several writers holds a class or function of the record when the writes
//! that store a definition all store that one, at least one other write
//! stores a value computed at run time (the result of a call, a member,
//! something the tracker lost), and no write stores anything else (another
//! binding, a constant, a captured variable that did not resolve). Such a
//! binding is *reassigned*: it holds the definition or whatever the
//! decorator returned for it, and whoever follows it says so.

use std::collections::HashMap;

use asc_abc::{Abc, Class, ModuleRecord};

use super::{Reader, ScopeTables, Scopes, Unresolved};
use crate::path::{NoLexicals, Origin, Path, PathBuilder};
use crate::refs::Regions;
use crate::table_bytes;
use crate::track::{Event, StoreTarget, Tracker, Watch};

/// The class or function a module-level binding holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Exported {
    /// Offset of its method (of a class: its constructor).
    pub method: u32,
    /// The binding is written again, with values computed at run time.
    pub reassigned: bool,
}

/// What a store into a module-level binding writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wrote {
    /// A class or function of the record, by its method offset.
    Definition(u32),
    /// A value computed at run time: the result of a call, a member, or
    /// something the tracker lost.
    Computed,
    /// Another binding or a constant.
    Other,
}

impl Wrote {
    /// What kind of value `path` is.
    fn of(path: &Path) -> Wrote {
        match path.origin {
            Origin::Definition(Some(method)) if path.links.is_empty() && !path.cut => Wrote::Definition(method),
            Origin::Unknown | Origin::Computed => Wrote::Computed,
            // A captured variable that did not resolve may hold another class.
            Origin::Lexical { .. } | Origin::Slot { .. } => Wrote::Other,
            _ if path.cut || !path.links.is_empty() => Wrote::Computed,
            _ => Wrote::Other,
        }
    }
}

/// The local export entries that share the local name of entry `index`:
/// they share one variable, and `stmodulevar` uses any of their indexes.
pub(crate) fn export_group(abc: &Abc<'_>, module: &ModuleRecord<'_>, index: u32) -> Option<Vec<u32>> {
    let local = module.local_exports.get(index as usize)?.local_name_off;
    let name = abc.string(local).ok()?.bytes;
    let same = |off: u32| off == local || abc.string(off).is_ok_and(|other| other.bytes == name);
    Some(
        module
            .local_exports
            .iter()
            .enumerate()
            .filter(|(_, export)| same(export.local_name_off))
            .filter_map(|(index, _)| u32::try_from(index).ok())
            .collect(),
    )
}

/// The local export entries of `module`, grouped by local name.
fn export_groups(abc: &Abc<'_>, module: &ModuleRecord<'_>) -> Vec<Vec<u32>> {
    let mut by_name: HashMap<&[u8], usize> = HashMap::new();
    let mut groups: Vec<Vec<u32>> = Vec::new();
    for (index, export) in module.local_exports.iter().enumerate() {
        let Ok(index) = u32::try_from(index) else { break };
        // An entry whose name does not read shares its variable with nothing.
        let group = match abc.string(export.local_name_off) {
            Ok(name) => *by_name.entry(name.bytes).or_insert_with(|| {
                groups.push(Vec::new());
                groups.len() - 1
            }),
            Err(_) => {
                groups.push(Vec::new());
                groups.len() - 1
            }
        };
        groups[group].push(index);
    }
    groups
}

/// Per local export entry of one record: the class or function of the
/// record its binding holds, when that is known. See the module
/// documentation for the bindings that are written more than once.
#[derive(Debug, Default)]
pub(crate) struct ExportedDefinitions {
    by_export: HashMap<u32, Exported>,
}

impl ExportedDefinitions {
    /// Work out the bindings of `class`, whose scopes are `scopes`. Only a
    /// record with a binding that has several writers is walked again, for
    /// what each of those stores writes.
    pub(crate) fn build<'a>(abc: Abc<'a>, regions: &Regions<'a>, class: &Class<'a>, scopes: &Scopes, tables: &ScopeTables) -> Self {
        let mut out = ExportedDefinitions::default();
        let Some(module) = class.module_record().ok().flatten() else { return out };
        let groups = export_groups(&abc, &module);
        let mut rewritten: Vec<&Vec<u32>> = Vec::new();
        for group in &groups {
            match scopes.module_binding(group) {
                Ok(written) => {
                    if let Wrote::Definition(method) = Wrote::of(&written.path) {
                        out.by_export.extend(group.iter().map(|&index| (index, Exported { method, reassigned: false })));
                    }
                }
                Err(Unresolved::MultipleWriters) => rewritten.push(group),
                Err(_) => {}
            }
        }
        if rewritten.is_empty() {
            return out;
        }
        let stores = stores_of(abc, regions, class, scopes, tables);
        for group in rewritten {
            let mut found = None;
            let mut computed = false;
            let mut decided = true;
            for wrote in group.iter().filter_map(|index| stores.get(index)).flatten() {
                match *wrote {
                    Wrote::Definition(method) if found.is_none_or(|known| known == method) => found = Some(method),
                    Wrote::Definition(_) | Wrote::Other => decided = false,
                    Wrote::Computed => computed = true,
                }
            }
            if let Some(method) = found.filter(|_| decided && computed) {
                out.by_export.extend(group.iter().map(|&index| (index, Exported { method, reassigned: true })));
            }
        }
        out.by_export.shrink_to_fit();
        out
    }

    /// The class or function the binding of local export `index` holds.
    pub(crate) fn get(&self, index: u32) -> Option<Exported> {
        self.by_export.get(&index).copied()
    }

    /// Bytes this takes on the heap, roughly.
    pub(crate) fn heap_bytes(&self) -> usize {
        table_bytes(&self.by_export)
    }
}

/// What every `stmodulevar` of the record writes, per local export entry.
fn stores_of<'a>(
    abc: Abc<'a>,
    regions: &Regions<'a>,
    class: &Class<'a>,
    scopes: &Scopes,
    tables: &ScopeTables,
) -> HashMap<u32, Vec<Wrote>> {
    let mut stores: HashMap<u32, Vec<Wrote>> = HashMap::new();
    let mut tracker = Tracker::default();
    let mut path = Path::default();
    // A malformed member list ends the record's functions; `Scopes::module_binding` gave up on its bindings then.
    for method in class.methods().into_iter().flatten().map_while(|method| method.ok()) {
        let Some(function) = regions.function(abc, &method) else { continue };
        let offset = method.offset();
        let reader = Reader::new(scopes, offset);
        let entity = |entity_id: u32| function.entity(entity_id);
        // Code that does not decode: `Scopes::module_binding` gives up on the record's bindings then.
        let _ = tracker.run_events(tables.effects(), &function.code, Watch::Stores, |frame, _, event| {
            let Event::Store { target: StoreTarget::Module(index), value } = event else { return };
            match &reader {
                Some(reader) => PathBuilder { frame, function: offset, entity: &entity, lexicals: reader }.build(value, &mut path),
                None => PathBuilder { frame, function: offset, entity: &entity, lexicals: &NoLexicals }.build(value, &mut path),
            }
            stores.entry(index).or_default().push(Wrote::of(&path));
        });
    }
    stores
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::Link;

    #[test]
    fn stores_are_told_apart_by_what_they_write() {
        let path = |origin, links: &[Link]| Path { origin, links: links.to_vec(), cut: false };
        assert_eq!(Wrote::of(&path(Origin::Definition(Some(8)), &[])), Wrote::Definition(8));
        // `decorator(C)`, `ns.member`: computed when the binding is written.
        assert_eq!(Wrote::of(&path(Origin::Global(Some(4)), &[Link::Call { construct: false }])), Wrote::Computed);
        assert_eq!(Wrote::of(&path(Origin::Definition(Some(8)), &[Link::Property(Some(4))])), Wrote::Computed);
        assert_eq!(Wrote::of(&path(Origin::Unknown, &[])), Wrote::Computed);
        // Another binding, a constant, an unresolved captured variable: possibly another class.
        assert_eq!(Wrote::of(&path(Origin::Import(1), &[])), Wrote::Other);
        assert_eq!(Wrote::of(&path(Origin::Constant("undefined"), &[])), Wrote::Other);
        assert_eq!(Wrote::of(&path(Origin::Lexical { level: 0, slot: 1, sendable: false }, &[])), Wrote::Other);
    }
}
