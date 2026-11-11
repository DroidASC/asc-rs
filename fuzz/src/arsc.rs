//! `asc-arsc`: index a `resources.arsc`, then name, list, format and
//! resolve every resource it defines.

use asc_arsc::{Config, ResTable};

pub fn run(data: &[u8]) {
    walk_configs(data);
    let Ok(table) = ResTable::parse(data.to_vec()) else { return };
    let _ = (table.warnings(), table.index_bytes());
    for package in table.packages() {
        for type_id in package.type_ids().collect::<Vec<_>>() {
            let _ = (package.type_chunks(type_id), table.type_name(package, type_id));
        }
        let _ = table.package_by_id(package.id);
    }
    let any = Config::any_device();
    let ids = table.ids();
    for &id in ids.iter().take(crate::MAX_ITEMS as usize) {
        let _ = (table.contains(id), table.spec_flags(id), table.type_name_of(id), table.ref_name(id), table.attr_name(id));
        if let Some(name) = table.name(id) {
            let _ = table.lookup(&name.to_string());
            let _ = table.lookup(&name.short());
        }
        for value in table.values(id) {
            let _ = table.format_entry(id, &value.value);
        }
        let _ = table.best_value(id, &any);
        if let Ok(resolved) = table.resolve_default(id) {
            let _ = table.format_entry(id, &resolved.value);
        }
        let _ = table.resolve(id, &any);
    }
    // Ids the table does not define, including the framework's.
    for id in [0, 0x0101_0000, 0x7f01_0000, 0x7fff_ffff, u32::MAX] {
        let _ = (table.name(id), table.resolve_default(id), table.ref_name(id));
    }
    let mut strings = 0usize;
    table.for_each_string(|_, _, s| strings += s.len());
    for idx in 0..64 {
        let _ = table.string(idx);
    }
}

/// `ResTable_config` blobs of every length, matched against each other.
fn walk_configs(data: &[u8]) {
    let configs: Vec<Config> = data.chunks(64).take(8).map(Config::parse).collect();
    for a in &configs {
        let _ = (a.is_default(), a.language(), a.region(), a.to_string());
        for b in &configs {
            let _ = (a.matches(b), a.is_better_than(b, &Config::any_device()));
        }
    }
}
