//! Malformed DEX files return errors: deterministic mutants of every
//! fixture are parsed and walked as deep as the API reaches, and none of
//! them may panic. `fuzz/` runs the same walk under libFuzzer.

use asc_dex::annotations::{AnnotationsDirectory, parse_annotation_set, parse_annotation_set_ref_list};
use asc_dex::debug_info::DebugInfo;
use asc_dex::encoded::{self, Identity};
use asc_dex::{ClassDef, Dex, container, quick};
use asc_fixture::mutate::mutants;

/// Most items of one table walked: a damaged count may claim billions.
const MAX_ITEMS: u32 = 256;

fn seeds() -> Vec<Vec<u8>> {
    vec![
        asc_fixture::make_dex(),
        asc_fixture::make_static_field_dex(),
        asc_fixture::make_field_access_dex(),
        asc_fixture::make_short_static_values_dex(),
        asc_fixture::make_class_only_dex(&["LA;", "LA$1;", "LB;"], 0, true),
        asc_fixture::make_dex041_container(),
        asc_fixture::make_rich_dex(),
        asc_fixture::make_truncated_insn_dex(),
    ]
}

fn exercise(data: &[u8]) {
    let _ = (quick::probe_needed_len(data), quick::id_tables_needed_len(data), quick::leading_string_data_off(data));
    let _ = (quick::dex_defines_class(data, b"Lexample/Test;"), quick::class_defs_contain_type_idx(data, 1));
    for (_, logical) in container::logical_dex_iter("classes.dex", data).take(4) {
        if let Ok(dex) = Dex::parse(&logical) {
            walk(&dex);
        }
    }
}

fn walk(dex: &Dex<'_>) {
    let _ = dex.map_list();
    for idx in 0..dex.string_count().min(MAX_ITEMS) {
        if let Ok(bytes) = dex.string_bytes(idx) {
            let _ = dex.find_string_idx(bytes);
        }
    }
    for idx in 0..dex.type_count().min(MAX_ITEMS) {
        if let Ok(bytes) = dex.type_bytes(idx) {
            let _ = dex.find_class_def(bytes);
        }
        if let Ok(range) = dex.nested_type_idx_range(idx) {
            let _ = dex.find_class_defs_by_type_range(range);
        }
    }
    for idx in 0..dex.proto_count().min(MAX_ITEMS) {
        let _ = dex.proto_params(idx);
    }
    for idx in 0..dex.field_count().min(MAX_ITEMS) {
        let _ = dex.field_display(idx);
    }
    for idx in 0..dex.method_count().min(MAX_ITEMS) {
        let _ = dex.method_display(idx);
    }
    for class in dex.class_defs().take(MAX_ITEMS as usize).flatten() {
        walk_class(dex, &class);
    }
}

fn walk_class(dex: &Dex<'_>, class: &ClassDef) {
    let buf = dex.buf();
    let _ = dex.type_list(class.interfaces_off);
    if class.static_values_off != 0
        && let Ok((values, _)) = encoded::parse_array(buf, class.static_values_off as usize)
    {
        let mut out = Vec::new();
        encoded::write_array(&mut out, &values, &Identity);
    }
    if class.annotations_off != 0
        && let Ok(dir) = AnnotationsDirectory::parse(buf, class.annotations_off as usize)
    {
        let lists =
            dir.parameter_annotations.iter().flat_map(|&(_, list)| parse_annotation_set_ref_list(buf, list as usize).unwrap_or_default());
        let sets =
            [dir.class_annotations_off].into_iter().chain(dir.field_annotations.iter().chain(&dir.method_annotations).map(|&(_, set)| set));
        for set in sets.chain(lists).filter(|&off| off != 0).take(MAX_ITEMS as usize) {
            for item in parse_annotation_set(buf, set as usize).unwrap_or_default().into_iter().take(MAX_ITEMS as usize) {
                let _ = encoded::parse_annotation_item(buf, item as usize);
            }
        }
    }
    let Ok(data) = dex.class_data(class.class_data_off) else { return };
    for method in data.methods().filter(|m| m.code_off != 0) {
        let Ok(code) = dex.code_item(method.code_off) else { continue };
        if code.debug_info_off != 0
            && let Ok((debug, _)) = DebugInfo::parse(buf, code.debug_info_off as usize)
        {
            let _ = debug.positions();
        }
    }
}

#[test]
fn mutated_fixtures_never_panic() {
    for (i, seed) in seeds().iter().enumerate() {
        exercise(seed);
        for mutant in mutants(seed, 0xde5 + i as u64, 800) {
            exercise(&mutant);
        }
    }
}

#[test]
fn every_truncation_never_panics() {
    let rich = asc_fixture::make_rich_dex();
    for len in 0..rich.len() {
        exercise(&rich[..len]);
    }
}
