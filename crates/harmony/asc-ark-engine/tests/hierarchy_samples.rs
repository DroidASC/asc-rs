//! The class hierarchy on the real samples (skipped when they are not
//! there). The numbers reported for a large sample were checked against the
//! official `ark_disasm` listing by an independent re-derivation: the parent
//! register of 5,830 of its 5,842 class definitions followed backwards to
//! `ldhole`, a global, a definition, a module-level binding or an import
//! (whose export chain and writers were read from the raw module records);
//! the other 12 go through captured variables or a parameter. And every
//! constructor calls `super` exactly when its class has a parent.

mod common;

use std::collections::BTreeMap;
use std::sync::atomic::AtomicBool;

use asc_ark_engine::{ClassDefinition, ClassNode, Engine, HierarchyQuery, Lineage, ParentKind};
use common::{large_sample_dir, sample};

fn definitions(engine: &Engine) -> Vec<ClassDefinition> {
    let mut out = Vec::new();
    engine.class_definitions(&AtomicBool::new(false), &mut |definition| out.push(definition)).unwrap();
    out
}

fn census(all: &[ClassDefinition]) -> [usize; 5] {
    let mut kinds: BTreeMap<ParentKind, usize> = BTreeMap::new();
    for definition in all {
        *kinds.entry(definition.kind).or_default() += 1;
    }
    ParentKind::ALL.map(|kind| kinds.get(&kind).copied().unwrap_or(0))
}

fn tree(engine: &Engine, query: &HierarchyQuery) -> Vec<String> {
    let tree = engine.hierarchy(query, &AtomicBool::new(false)).unwrap();
    let (mut lines, footer) = tree.text(engine.has_several_entries());
    lines.push(footer);
    lines
}

#[test]
fn contacts_classes() {
    let Some(path) = sample("contacts.hap") else { return };
    let engine = Engine::open(path).unwrap();
    let all = definitions(&engine);
    // None, same record, other record, external, unresolved: the unresolved ones are in a bundled library
    // that builds its classes in functions (`class NodeError extends Base`, with `Base` a parameter).
    assert_eq!(census(&all), [9, 0, 0, 12, 10]);
    assert!(all.iter().all(|definition| definition.methods.is_some() && !definition.reassigned));
    let abilities =
        tree(&engine, &HierarchyQuery { method: Some("onCreate".into()), ..HierarchyQuery::new("Ability", Lineage::Subclasses) });
    assert_eq!(
        abilities[..5],
        [
            "0 import:@ohos:app.ability.UIAbility#default [external]",
            "  1 subclass &entry/src/main/ets/entryability/EntryAbility&->#~@0=#EntryAbility | EntryAbility [defines #~@0>#onCreate]",
            "0 import:@ohos:application.BackupExtensionAbility#default [external]",
            "  1 subclass &entry/src/main/ets/entrybackupability/EntryBackupAbility&->#~@0=#EntryBackupAbility | EntryBackupAbility",
            "override &entry/src/main/ets/entryability/EntryAbility&->#~@0>#onCreate | EntryAbility.onCreate",
        ]
    );
}

/// `N` of a footer's `; N records scanned`.
fn records_scanned(footer: &str) -> usize {
    let (head, _) = footer.split_once(" records scanned").unwrap();
    head.rsplit(' ').next().unwrap().parse().unwrap()
}

fn class_of(node: &ClassNode) -> Option<String> {
    match node {
        ClassNode::Class { record, function, .. } => Some(format!("{record}->{function}")),
        ClassNode::Leaf { .. } => None,
    }
}

/// On a 32 MB store sample: 5,843 definitions, 3,872 without a parent, 158
/// and 596 with one in their own and in another record, 1,215 external, 2
/// unresolved (`arg2`, `lex(0,0)`); 477 sendable, 137 through a reassigned
/// binding.
#[test]
fn large_sample_classes() {
    let Some(dir) = large_sample_dir() else { return };
    let engine = Engine::open(dir.join("modules.abc")).unwrap();
    let all = definitions(&engine);
    let kinds = census(&all);
    assert_eq!(kinds.iter().sum::<usize>(), all.len());
    assert!(kinds[..4].iter().all(|&count| count > 0), "{kinds:?}");
    // Nearly every parent is found: less than one definition in a hundred is left unresolved.
    assert!(kinds[4] * 100 < all.len(), "{kinds:?}");
    assert!(all.iter().all(|definition| definition.methods.is_some()));
    assert!(all.iter().all(|definition| definition.parent.is_some() != (definition.kind == ParentKind::None)));
    for definition in all.iter().filter(|definition| definition.kind == ParentKind::Unresolved) {
        assert!(matches!(&definition.parent, Some(ClassNode::Leaf { external: false, .. })), "{definition:?}");
    }
    let total = engine.list_classes(&asc_ark_engine::ListOptions { all: true, ..Default::default() }).unwrap().len();

    // A system class.
    let ability =
        tree(&engine, &HierarchyQuery { method: Some("onCreate".into()), ..HierarchyQuery::new("UIAbility", Lineage::Subclasses) });
    assert_eq!(ability[0], "0 import:@ohos:app.ability.UIAbility#default [external]");
    assert!(ability[1].starts_with("  1 subclass "), "{ability:?}");
    assert!(ability.iter().any(|line| line.starts_with("override ") && line.ends_with(".onCreate")), "{ability:?}");

    // The class of the program with the most direct subclasses: each is a row under it.
    let mut children: BTreeMap<String, Vec<&ClassDefinition>> = BTreeMap::new();
    for definition in &all {
        if let Some(parent) = definition.parent.as_ref().and_then(class_of) {
            children.entry(parent).or_default().push(definition);
        }
    }
    let (parent, direct) = children.iter().max_by_key(|(_, direct)| direct.len()).unwrap();
    let down = tree(&engine, &HierarchyQuery { depth: 1, ..HierarchyQuery::new(parent.clone(), Lineage::Subclasses) });
    let rows: Vec<&String> = down.iter().filter(|line| line.starts_with("  1 subclass ")).collect();
    assert_eq!(rows.len(), direct.len(), "{down:?}");
    for definition in direct {
        let class = class_of(&definition.class).unwrap();
        let row = rows.iter().find(|line| line["  1 subclass ".len()..].starts_with(&format!("{class} | "))).unwrap();
        assert_eq!(row.contains(" [reassigned]"), definition.reassigned, "{row}");
    }
    assert_eq!(records_scanned(down.last().unwrap()), total);

    // Upward, only the records along the chain are read.
    let child = all.iter().find(|definition| definition.kind == ParentKind::OtherRecord).unwrap();
    let up = tree(&engine, &HierarchyQuery::new(class_of(&child.class).unwrap(), Lineage::Supers));
    assert!(up[0].starts_with(&format!("0 {} | ", class_of(&child.class).unwrap())), "{up:?}");
    assert!(up[1].starts_with(&format!("  1 extends {}", class_of(child.parent.as_ref().unwrap()).unwrap())), "{up:?}");
    let chain = up.iter().filter(|line| line.contains(" extends ")).count();
    assert!(records_scanned(up.last().unwrap()) <= chain + 1, "{up:?}");
}
