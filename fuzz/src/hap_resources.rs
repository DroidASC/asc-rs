//! `asc-hap`: `resources.index` in both formats: every resource with its
//! value, and the lookups by id, by name and by `$type:name` reference.

use asc_hap::{ResourceIndex, ResourceRef};

pub fn run(data: &[u8]) {
    let Ok(index) = ResourceIndex::parse(data) else { return };
    let _ = (index.version(), index.format(), index.len(), index.is_empty());
    for qualifiers in index.qualifiers() {
        let _ = qualifiers.to_string();
    }
    for resource in index.iter().take(crate::MAX_ITEMS as usize) {
        let _ = (resource.to_string(), resource.raw_value(), resource.value().archive_path());
        let _ = index.by_id(resource.id()).count();
        let _ = index.by_name(resource.kind(), &resource.name()).count();
        let reference = format!("${}:{}", resource.kind(), resource.name());
        if let Some(reference) = ResourceRef::parse(&reference) {
            let _ = index.resolve(reference).count();
        }
    }
    let _ = index.iter().rev().take(4).count();
}
