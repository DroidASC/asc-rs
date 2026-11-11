//! `asc-dex`: the header, every id table, class definitions, class data,
//! code items, debug info, annotations and static values, as the engine and
//! the rebuild reach them; DEX041 containers are split first.

use asc_dex::annotations::{AnnotationsDirectory, parse_annotation_set, parse_annotation_set_ref_list};
use asc_dex::debug_info::DebugInfo;
use asc_dex::encoded::{self, EncodedValue, Identity};
use asc_dex::{ClassDef, Dex, container, map_type, quick};

use crate::MAX_ITEMS;

pub fn run(data: &[u8]) {
    let _ = quick::probe_needed_len(data);
    let _ = quick::leading_string_data_off(data);
    let _ = quick::id_tables_needed_len(data);
    let _ = quick::find_type_idx(data, b"Lexample/Test;");
    let _ = quick::dex_defines_class(data, b"Lexample/Test;");
    let _ = quick::class_defs_contain_type_idx(data, 1);
    for (_, logical) in container::logical_dex_iter("classes.dex", data).take(4) {
        if let Ok(dex) = Dex::parse(&logical) {
            walk(&dex);
        }
    }
}

/// Everything reachable from the header of one logical DEX.
pub fn walk(dex: &Dex<'_>) {
    let _ = dex.map_list();
    let _ = dex.map_item(map_type::CLASS_DATA);
    for idx in 0..dex.string_count().min(MAX_ITEMS) {
        if let Ok(bytes) = dex.string_bytes(idx) {
            let _ = dex.find_string_idx(bytes);
        }
        let _ = dex.string(idx);
    }
    for idx in 0..dex.type_count().min(MAX_ITEMS) {
        if let Ok(bytes) = dex.type_bytes(idx) {
            let _ = dex.find_type_idx(bytes);
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
    for idx in 0..dex.method_handle_count().unwrap_or(0).min(MAX_ITEMS) {
        let _ = dex.method_handle(idx);
    }
    for idx in 0..dex.call_site_count().unwrap_or(0).min(MAX_ITEMS) {
        let _ = dex.call_site_off(idx);
        let _ = dex.call_site(idx);
    }
    for class in dex.class_defs().take(MAX_ITEMS as usize).flatten() {
        walk_class(dex, &class);
    }
}

fn walk_class(dex: &Dex<'_>, class: &ClassDef) {
    let buf = dex.buf();
    let _ = dex.find_class_def_by_type(class.class_idx);
    let _ = dex.type_list(class.interfaces_off);
    if class.static_values_off != 0
        && let Ok((values, _)) = encoded::parse_array(buf, class.static_values_off as usize)
    {
        values.iter().for_each(round_trip);
    }
    if class.annotations_off != 0
        && let Ok(dir) = AnnotationsDirectory::parse(buf, class.annotations_off as usize)
    {
        walk_annotation_set(buf, dir.class_annotations_off);
        for &(_, set) in dir.field_annotations.iter().chain(&dir.method_annotations) {
            walk_annotation_set(buf, set);
        }
        for &(_, list) in &dir.parameter_annotations {
            for set in parse_annotation_set_ref_list(buf, list as usize).unwrap_or_default().into_iter().take(MAX_ITEMS as usize) {
                walk_annotation_set(buf, set);
            }
        }
    }
    let Ok(data) = dex.class_data(class.class_data_off) else { return };
    let _ = data.fields().count();
    for method in data.methods() {
        if method.code_off == 0 {
            continue;
        }
        let Ok(code) = dex.code_item(method.code_off) else { continue };
        for try_item in &code.tries {
            let _ = code.handler_for(try_item);
        }
        if code.debug_info_off != 0
            && let Ok((debug, _)) = DebugInfo::parse(buf, code.debug_info_off as usize)
        {
            let _ = debug.positions();
            debug.visit_refs(&mut |_| {}, &mut |_| {});
            let mut out = Vec::new();
            debug.write(&mut out, &|s| s, &|t| t);
        }
    }
    let mut count = 0;
    let _ = asc_dex::class_data::walk_methods(buf, class.class_data_off as usize, |_, _| count += 1);
}

fn walk_annotation_set(buf: &[u8], off: u32) {
    if off == 0 {
        return;
    }
    for item in parse_annotation_set(buf, off as usize).unwrap_or_default().into_iter().take(MAX_ITEMS as usize) {
        if let Ok((item, _)) = encoded::parse_annotation_item(buf, item as usize) {
            let mut out = Vec::new();
            encoded::write_annotation_item(&mut out, &item, &Identity);
            encoded::visit_annotation_refs(&item.annotation, &mut |_, _| {});
            let reparsed = encoded::parse_annotation_item(&out, 0).map(|(again, _)| again);
            assert_eq!(reparsed.as_ref(), Ok(&item), "annotation item does not survive a write");
        }
    }
}

/// A value written back and parsed again is the same value.
fn round_trip(value: &EncodedValue) {
    let _ = (value.as_i64(), value.as_f64(), value.as_f32(), value.kind());
    encoded::visit_refs(value, &mut |_, _| {});
    let mut out = Vec::new();
    encoded::write_value(&mut out, value, &Identity);
    let reparsed = encoded::parse_value(&out, 0).map(|(again, _)| again);
    assert_eq!(reparsed.as_ref(), Ok(value), "encoded value does not survive a write");
}
