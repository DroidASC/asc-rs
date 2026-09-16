use asc_dex::checksum::{adler32, sha1};
use asc_dex::encoded::parse_array;
use asc_dex::Dex;
use asc_fixture::{make_dex, make_static_field_dex};
use asc_rebuild::rebuild_class_bytes;

#[test]
fn rebuilt_dex_has_valid_checksum_and_signature() {
    let out = rebuild_class_bytes(&make_dex(), "Lexample/Test;").unwrap();
    let data = out.bytes;
    assert_eq!(&data[..8], b"dex\n035\0");
    assert_eq!(u32::from_le_bytes(data[8..12].try_into().unwrap()), adler32(&data[12..]));
    assert_eq!(&data[12..32], &sha1(&data[32..]));
    assert_eq!(u32::from_le_bytes(data[0x20..0x24].try_into().unwrap()) as usize, data.len());
    let dex = Dex::parse(&data).unwrap();
    assert_eq!(dex.class_def_count(), 1);
    let (_, def) = dex.find_class_def(b"Lexample/Test;").unwrap().unwrap();
    let cd = dex.class_data(def.class_data_off).unwrap();
    assert_eq!(cd.direct_methods.len(), 2);
    let names: Vec<String> = cd.methods().map(|m| dex.string(dex.method_id(m.method_idx).unwrap().name_idx).unwrap()).collect();
    assert_eq!(names, ["first", "second"]);
    let code = dex.code_item(cd.direct_methods[0].code_off).unwrap();
    // const-string v0, string@N where N now points at "token"
    let idx = u16::from_le_bytes([code.insns[2], code.insns[3]]) as u32;
    assert_eq!(dex.string(idx).unwrap(), "token");
    // string ids are sorted by UTF-16 order
    let strings: Vec<String> = (0..dex.string_count()).map(|i| dex.string(i).unwrap()).collect();
    let mut sorted = strings.clone();
    sorted.sort();
    assert_eq!(strings, sorted);
    let map = dex.map_list();
    assert!(map.windows(2).all(|w| w[0].offset < w[1].offset), "map list sorted by offset: {map:?}");
}

#[test]
fn rebuild_keeps_static_values_and_field_operands_aligned() {
    let out = rebuild_class_bytes(&make_static_field_dex(), "Lexample/Statics;").unwrap();
    let data = out.bytes;
    let dex = Dex::parse(&data).unwrap();
    let def = dex.class_def(0).unwrap();
    let cd = dex.class_data(def.class_data_off).unwrap();
    let static_names: Vec<String> =
        cd.static_fields.iter().map(|f| dex.string(dex.field_id(f.field_idx).unwrap().name_idx).unwrap()).collect();
    assert_eq!(static_names, ["FIRST", "SECOND"]);
    let (values, _) = parse_array(&data, def.static_values_off as usize).unwrap();
    let ints: Vec<i64> = values.iter().map(|v| v.as_i64().unwrap()).collect();
    assert_eq!(ints, [11, 22]);
    let m = cd.direct_methods.iter().find(|m| dex.string(dex.method_id(m.method_idx).unwrap().name_idx).unwrap() == "getSecond").unwrap();
    let code = dex.code_item(m.code_off).unwrap();
    let field_idx = u16::from_le_bytes([code.insns[2], code.insns[3]]) as u32;
    assert_eq!(dex.string(dex.field_id(field_idx).unwrap().name_idx).unwrap(), "SECOND");
}

#[test]
fn missing_class_is_an_error() {
    assert!(rebuild_class_bytes(&make_dex(), "Lnope;").is_err());
}

// ---------------------------------------------------------------------------
// Rich fixture: payloads, try/catch, annotations, debug info, MUTF-8
// ---------------------------------------------------------------------------

use asc_dex::class_data::{ClassData, EncodedMethod};
use asc_dex::code::CodeItem;
use asc_dex::debug_info::DebugInfo;
use asc_dex::encoded::EncodedValue;
use asc_dex::ClassDef;
use asc_fixture::{
    make_many_members_dex, make_rich_dex, make_short_static_values_dex, make_truncated_insn_dex, make_unsorted_static_field_dex,
    RICH_STRING,
};
use asc_rebuild::RebuildError;

const RICH: &str = "Lexample/Rich;";

fn class<'a>(dex: &Dex<'a>, descriptor: &str) -> (ClassDef, ClassData) {
    let (_, def) = dex.find_class_def(descriptor.as_bytes()).unwrap().unwrap();
    let cd = dex.class_data(def.class_data_off).unwrap();
    (def, cd)
}

fn method_named<'a>(dex: &Dex<'a>, cd: &ClassData, name: &str) -> EncodedMethod {
    *cd.methods().find(|m| dex.string(dex.method_id(m.method_idx).unwrap().name_idx).unwrap() == name).unwrap()
}

fn code_of<'a>(dex: &Dex<'a>, descriptor: &str, name: &str) -> CodeItem<'a> {
    let (_, cd) = class(dex, descriptor);
    let m = method_named(dex, &cd, name);
    dex.code_item(m.code_off).unwrap()
}

fn u16_at(b: &[u8], o: usize) -> u32 {
    u16::from_le_bytes([b[o], b[o + 1]]) as u32
}

#[test]
fn rich_rebuild_is_valid_and_idempotent() {
    let data = make_rich_dex();
    let first = rebuild_class_bytes(&data, RICH).unwrap();
    assert_eq!(&first.bytes[..8], b"dex\n038\0");
    assert_eq!(u32::from_le_bytes(first.bytes[8..12].try_into().unwrap()), adler32(&first.bytes[12..]));
    assert_eq!(&first.bytes[12..32], &sha1(&first.bytes[32..]));
    assert_eq!(first.stats.methods_with_code, 5);
    assert_eq!(first.stats.fields, 3);
    let dex = Dex::parse(&first.bytes).unwrap();
    assert_eq!(dex.class_def_count(), 1);
    let strings: Vec<Vec<u16>> = (0..dex.string_count()).map(|i| asc_dex::mutf8::to_utf16(dex.string_bytes(i).unwrap())).collect();
    assert!(strings.windows(2).all(|w| w[0] < w[1]), "string ids sorted and unique");
    assert!(dex.string_count() < Dex::parse(&data).unwrap().string_count());

    let second = rebuild_class_bytes(&first.bytes, RICH).unwrap();
    assert_eq!(second.bytes, first.bytes, "rebuilding the rebuilt DEX is a fixed point");
    assert_eq!(second.stats, first.stats);
}

#[test]
fn rich_class_def_keeps_interface_source_and_instance_field() {
    let out = rebuild_class_bytes(&make_rich_dex(), RICH).unwrap();
    let dex = Dex::parse(&out.bytes).unwrap();
    let (def, cd) = class(&dex, RICH);
    assert_eq!(def.access_flags, 0x401);
    assert_eq!(dex.string(def.source_file_idx).unwrap(), "Rich.java");
    assert_eq!(dex.type_descriptor(def.superclass_idx).unwrap(), "Ljava/lang/Object;");
    let ifaces: Vec<String> = dex.type_list(def.interfaces_off).unwrap().iter().map(|&t| dex.type_descriptor(t as u32).unwrap()).collect();
    assert_eq!(ifaces, ["Lexample/Iface;"]);
    let names = |list: &[asc_dex::class_data::EncodedField]| -> Vec<String> {
        list.iter().map(|f| dex.string(dex.field_id(f.field_idx).unwrap().name_idx).unwrap()).collect()
    };
    assert_eq!(names(&cd.static_fields), ["COUNT", "NAME"]);
    assert_eq!(names(&cd.instance_fields), ["value"]);
    let (values, _) = parse_array(&out.bytes, def.static_values_off as usize).unwrap();
    assert_eq!(values[0].as_i64(), Some(7));
    let EncodedValue::String(s) = values[1] else { panic!("{:?}", values[1]) };
    assert_eq!(dex.string(s).unwrap(), RICH_STRING);
    let abstract_handle = method_named(&dex, &cd, "handle");
    assert_eq!(abstract_handle.code_off, 0);
    assert_eq!(abstract_handle.access_flags, 0x401);
}

#[test]
fn try_catch_handlers_survive_remapping() {
    let data = make_rich_dex();
    let out = rebuild_class_bytes(&data, RICH).unwrap();
    let dex = Dex::parse(&out.bytes).unwrap();
    let code = code_of(&dex, RICH, "compute");
    assert_eq!(code.tries.len(), 1);
    let t = code.tries[0];
    assert_eq!((t.start_addr, t.insn_count), (8, 4));
    let h = code.handler_for(&t).expect("handler offset resolves in the rebuilt list");
    let catches: Vec<(String, u32)> = h.catches.iter().map(|(ty, a)| (dex.type_descriptor(*ty).unwrap(), *a)).collect();
    assert_eq!(catches, [("Ljava/lang/Exception;".to_string(), 0x2e / 2), ("Ljava/lang/RuntimeException;".to_string(), 0x34 / 2)]);
    assert_eq!(h.catch_all_addr, Some(0x3a / 2));
    // The catch types were remapped: they differ from the original indexes.
    let orig = Dex::parse(&data).unwrap();
    let orig_code = code_of(&orig, RICH, "compute");
    let orig_types: Vec<u32> = orig_code.handlers[0].catches.iter().map(|c| c.0).collect();
    let new_types: Vec<u32> = h.catches.iter().map(|c| c.0).collect();
    assert_ne!(orig_types, new_types);
}

#[test]
fn payload_before_switch_keeps_table_and_remaps_following_operands() {
    let data = make_rich_dex();
    let orig = Dex::parse(&data).unwrap();
    let before = code_of(&orig, RICH, "compute");
    let out = rebuild_class_bytes(&data, RICH).unwrap();
    let dex = Dex::parse(&out.bytes).unwrap();
    let after = code_of(&dex, RICH, "compute");
    let (a, b) = (before.insns, after.insns);
    assert_eq!(a.len(), b.len());
    assert_eq!(&a[..0x10], &b[..0x10], "packed-switch payload bytes are untouched");
    assert_eq!(&a[0x10..0x1c], &b[0x10..0x1c], "switch instruction and const/4 untouched");
    // sget v0, COUNT
    assert_eq!(dex.string(dex.field_id(u16_at(b, 0x1c)).unwrap().name_idx).unwrap(), "COUNT");
    // const-string v0, RICH_STRING (a non-ASCII MUTF-8 string)
    assert_eq!(dex.string(u16_at(b, 0x22)).unwrap(), RICH_STRING);
    // invoke-static {v2, v3}, compute
    assert_eq!(dex.string(dex.method_id(u16_at(b, 0x26)).unwrap().name_idx).unwrap(), "compute");
    assert_eq!(&a[0x28..], &b[0x28..]);
    // and the operands really were rewritten (the rebuilt pool is smaller)
    assert!(u16_at(a, 0x22) != u16_at(b, 0x22) || u16_at(a, 0x1c) != u16_at(b, 0x1c) || u16_at(a, 0x26) != u16_at(b, 0x26));
}

#[test]
fn sparse_switch_and_fill_array_payloads_are_intact() {
    let data = make_rich_dex();
    let orig = Dex::parse(&data).unwrap();
    let before = code_of(&orig, RICH, "table");
    let out = rebuild_class_bytes(&data, RICH).unwrap();
    let dex = Dex::parse(&out.bytes).unwrap();
    let after = code_of(&dex, RICH, "table");
    let (a, b) = (before.insns, after.insns);
    assert_eq!(&a[..0x0c], &b[..0x0c]);
    assert_eq!(dex.type_descriptor(u16_at(b, 0x0c)).unwrap(), "[I");
    assert_eq!(&a[0x0e..], &b[0x0e..], "everything after new-array, including both payloads, is byte-identical");
}

#[test]
fn const_string_jumbo_is_remapped() {
    let out = rebuild_class_bytes(&make_rich_dex(), RICH).unwrap();
    let dex = Dex::parse(&out.bytes).unwrap();
    let code = code_of(&dex, RICH, "jumbo");
    assert_eq!(code.insns[0], 0x1b);
    let idx = u32::from_le_bytes(code.insns[2..6].try_into().unwrap());
    assert_eq!(dex.string(idx).unwrap(), RICH_STRING);
}

#[test]
fn debug_info_is_rewritten_with_new_string_indexes() {
    let out = rebuild_class_bytes(&make_rich_dex(), RICH).unwrap();
    let dex = Dex::parse(&out.bytes).unwrap();
    let code = code_of(&dex, RICH, "compute");
    assert_ne!(code.debug_info_off, 0);
    let (info, _) = DebugInfo::parse(&out.bytes, code.debug_info_off as usize).unwrap();
    assert_eq!(info.line_start, 10);
    let names: Vec<String> = info.parameter_names.iter().map(|n| dex.string(n.unwrap()).unwrap()).collect();
    assert_eq!(names, ["a", "b"]);
    assert_eq!(info.positions(), [(8, 10), (13, 12), (16, 14)]);
    // methods without debug info keep a zero offset
    assert_eq!(code_of(&dex, RICH, "jumbo").debug_info_off, 0);
}

#[test]
fn annotations_directory_is_rebuilt_for_class_field_method_and_parameters() {
    use asc_dex::annotations::{parse_annotation_set, parse_annotation_set_ref_list, AnnotationsDirectory};
    use asc_dex::encoded::parse_annotation_item;
    let out = rebuild_class_bytes(&make_rich_dex(), RICH).unwrap();
    let buf = &out.bytes;
    let dex = Dex::parse(buf).unwrap();
    let (def, cd) = class(&dex, RICH);
    let dir = AnnotationsDirectory::parse(buf, def.annotations_off as usize).unwrap();
    let value_of = |set_off: u32| -> Vec<String> {
        parse_annotation_set(buf, set_off as usize)
            .unwrap()
            .iter()
            .map(|&item| {
                let (item, _) = parse_annotation_item(buf, item as usize).unwrap();
                assert_eq!(dex.type_descriptor(item.annotation.type_idx).unwrap(), "Lexample/Marker;");
                assert_eq!(item.visibility, 1);
                let (name, v) = &item.annotation.elements[0];
                assert_eq!(dex.string(*name).unwrap(), "value");
                let EncodedValue::String(s) = v else { panic!("{v:?}") };
                dex.string(*s).unwrap()
            })
            .collect()
    };
    assert_eq!(value_of(dir.class_annotations_off), ["c"]);
    assert_eq!(dir.field_annotations.len(), 1);
    let count = cd.static_fields.iter().find(|f| dex.string(dex.field_id(f.field_idx).unwrap().name_idx).unwrap() == "COUNT").unwrap();
    assert_eq!(dir.field_annotations[0].0, count.field_idx);
    assert_eq!(value_of(dir.field_annotations[0].1), ["f"]);
    let handle = method_named(&dex, &cd, "handle");
    assert_eq!(dir.method_annotations, [(handle.method_idx, dir.method_annotations[0].1)]);
    assert_eq!(value_of(dir.method_annotations[0].1), ["m"]);
    assert_eq!(dir.parameter_annotations.len(), 1);
    assert_eq!(dir.parameter_annotations[0].0, handle.method_idx);
    let sets = parse_annotation_set_ref_list(buf, dir.parameter_annotations[0].1 as usize).unwrap();
    assert_eq!(sets.len(), 2);
    assert_eq!(value_of(sets[0]), ["p"]);
    assert_eq!(value_of(sets[1]), Vec::<String>::new());
}

// ---------------------------------------------------------------------------
// static_values alignment
// ---------------------------------------------------------------------------

#[test]
fn static_values_follow_non_canonical_field_order() {
    let out = rebuild_class_bytes(&make_unsorted_static_field_dex(), "Lexample/Unsorted;").unwrap();
    let dex = Dex::parse(&out.bytes).unwrap();
    let (def, cd) = class(&dex, "Lexample/Unsorted;");
    let names: Vec<String> = cd.static_fields.iter().map(|f| dex.string(dex.field_id(f.field_idx).unwrap().name_idx).unwrap()).collect();
    assert_eq!(names, ["ALPHA", "ZETA"], "fields are re-sorted canonically");
    let (values, _) = parse_array(&out.bytes, def.static_values_off as usize).unwrap();
    let ints: Vec<i64> = values.iter().map(|v| v.as_i64().unwrap()).collect();
    assert_eq!(ints, [22, 11], "ALPHA keeps 22 and ZETA keeps 11 after the swap");
    let m = method_named(&dex, &cd, "getAlpha");
    let code = dex.code_item(m.code_off).unwrap();
    assert_eq!(dex.string(dex.field_id(u16_at(code.insns, 2)).unwrap().name_idx).unwrap(), "ALPHA");
}

#[test]
fn short_static_values_are_padded_with_typed_zeros() {
    let out = rebuild_class_bytes(&make_short_static_values_dex(), "Lexample/Short;").unwrap();
    let dex = Dex::parse(&out.bytes).unwrap();
    let (def, cd) = class(&dex, "Lexample/Short;");
    let names: Vec<String> = cd.static_fields.iter().map(|f| dex.string(dex.field_id(f.field_idx).unwrap().name_idx).unwrap()).collect();
    assert_eq!(names, ["ALPHA", "MID", "ZETA"]);
    let (values, _) = parse_array(&out.bytes, def.static_values_off as usize).unwrap();
    assert_eq!(values.len(), 3);
    assert_eq!(values[0], EncodedValue::Boolean(false), "ALPHA:Z hole");
    assert_eq!(values[1], EncodedValue::Null, "MID:Ljava/lang/String; hole");
    assert_eq!(values[2].as_i64(), Some(5), "ZETA:I keeps its initialiser");
}

// ---------------------------------------------------------------------------
// Limits and errors
// ---------------------------------------------------------------------------

#[test]
fn too_many_fields_or_methods_is_an_error() {
    match rebuild_class_bytes(&make_many_members_dex(0x10000, false), "Lexample/Big;") {
        Err(RebuildError::TooManyItems { what: "fields", count: 0x10000 }) => {}
        other => panic!("{other:?}"),
    }
    match rebuild_class_bytes(&make_many_members_dex(0x10000, true), "Lexample/Big;") {
        Err(RebuildError::TooManyItems { what: "methods", count: 0x10000 }) => {}
        other => panic!("{other:?}"),
    }
    let ok = rebuild_class_bytes(&make_many_members_dex(0xFFFF, false), "Lexample/Big;").unwrap();
    assert_eq!(ok.stats.fields, 0xFFFF);
    assert_eq!(Dex::parse(&ok.bytes).unwrap().field_count(), 0xFFFF);
}

#[test]
fn invoke_custom_is_reported_as_unsupported() {
    match rebuild_class_bytes(&make_rich_dex(), "Lexample/Custom;") {
        Err(RebuildError::Unsupported(msg)) => assert!(msg.contains("invoke-custom"), "{msg}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn undefined_opcode_is_a_bytecode_error() {
    match rebuild_class_bytes(&make_rich_dex(), "Lexample/Broken;") {
        Err(RebuildError::Bytecode { pc: 0, reason, .. }) => assert!(reason.contains("0x3e"), "{reason}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn truncated_instruction_is_a_bytecode_error() {
    match rebuild_class_bytes(&make_truncated_insn_dex(), "Lexample/Cut;") {
        Err(RebuildError::Bytecode { pc: 2, reason, .. }) => assert!(reason.contains("past the end"), "{reason}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn dangling_try_handler_offset_is_an_internal_error() {
    let mut data = make_rich_dex();
    let code = code_of(&Dex::parse(&data).unwrap(), RICH, "compute");
    // tries start after the (odd-length, hence padded) instruction array
    let tries = code.offset + CodeItem::HEADER_SIZE + code.insns.len() + 2;
    data[tries + 6..tries + 8].copy_from_slice(&0x77u16.to_le_bytes());
    match rebuild_class_bytes(&data, RICH) {
        Err(RebuildError::Internal(msg)) => assert!(msg.contains("handler offset 119"), "{msg}"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn malformed_offsets_are_errors_not_panics() {
    let base = make_rich_dex();
    let dex = Dex::parse(&base).unwrap();
    let code = code_of(&dex, RICH, "compute");
    // debug_info_off pointing past the file
    let mut data = base.clone();
    data[code.offset + 8..code.offset + 12].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
    assert!(rebuild_class_bytes(&data, RICH).is_err());
    // insns_size larger than the file (truncated code item)
    let mut data = base.clone();
    data[code.offset + 12..code.offset + 16].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
    assert!(rebuild_class_bytes(&data, RICH).is_err());
    // class_data_off past the file
    let (i, _) = dex.find_class_def(RICH.as_bytes()).unwrap().unwrap();
    let def_off = dex.class_def_off(i);
    let mut data = base.clone();
    data[def_off + 24..def_off + 28].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
    assert!(rebuild_class_bytes(&data, RICH).is_err());
}

#[test]
fn single_byte_corruption_never_panics() {
    let base = make_rich_dex();
    let data_off = Dex::parse(&base).unwrap().header().data_off as usize;
    let mut data = base.clone();
    for pos in data_off..base.len() {
        for flip in [0xffu8, 0x80, 0x01] {
            data[pos] = base[pos] ^ flip;
            for class in [RICH, "Lexample/Iface;", "Lexample/Broken;", "Lexample/Custom;"] {
                let _ = rebuild_class_bytes(&data, class);
            }
        }
        data[pos] = base[pos];
    }
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

/// The spec requires `*_off == 0` whenever `*_size == 0`; ART's DexFileVerifier
/// rejects the file otherwise ("Offset(N) should be zero when size is zero").
#[test]
fn empty_id_tables_have_zero_offsets() {
    // Interface with one abstract method: no fields at all.
    let out = rebuild_class_bytes(&make_rich_dex(), "Lexample/Iface;").unwrap();
    let d = &out.bytes;
    assert_eq!(u32_at(d, 0x50), 0, "field_ids_size");
    assert_eq!(u32_at(d, 0x54), 0, "field_ids_off must be 0 when size is 0");
    assert_ne!(u32_at(d, 0x48), 0, "proto_ids_size");
    assert_ne!(u32_at(d, 0x4C), 0);
    assert_ne!(u32_at(d, 0x5C), 0);
    assert_eq!(Dex::parse(d).unwrap().class_def_count(), 1);

    // Static fields only: no methods, hence no protos and no method ids.
    let out = rebuild_class_bytes(&make_many_members_dex(3, false), "Lexample/Big;").unwrap();
    let d = &out.bytes;
    assert_eq!(u32_at(d, 0x48), 0, "proto_ids_size");
    assert_eq!(u32_at(d, 0x4C), 0, "proto_ids_off must be 0 when size is 0");
    assert_eq!(u32_at(d, 0x58), 0, "method_ids_size");
    assert_eq!(u32_at(d, 0x5C), 0, "method_ids_off must be 0 when size is 0");
    assert_ne!(u32_at(d, 0x54), 0, "field_ids_off");
    assert_eq!(u32_at(d, 0x8), adler32(&d[12..]));
    let dex = Dex::parse(d).unwrap();
    assert_eq!(dex.class_def_count(), 1);
    assert_eq!(dex.header().proto_ids.size, 0);
    assert_eq!(dex.header().method_ids.size, 0);
}

/// Runs the rebuilt fixtures through ART's verifier when a `dexdump` binary is
/// available (`DEXDUMP=/path/to/dexdump`, or the SDK's build-tools); skipped
/// otherwise so CI without an Android SDK is unaffected.
#[test]
fn rebuilt_dex_passes_dexdump_verifier_when_available() {
    let dexdump = std::env::var_os("DEXDUMP").map(std::path::PathBuf::from).or_else(|| {
        let home = std::env::var_os("HOME")?;
        let bt = std::path::Path::new(&home).join("Android/Sdk/build-tools");
        let mut dirs: Vec<_> = std::fs::read_dir(bt).ok()?.flatten().map(|e| e.path()).collect();
        dirs.sort();
        dirs.into_iter().rev().map(|d| d.join("dexdump")).find(|p| p.is_file())
    });
    let Some(dexdump) = dexdump else {
        eprintln!("dexdump not found; skipping");
        return;
    };
    let dir = std::env::temp_dir().join(format!("asc-rebuild-dexdump-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for (data, class) in [
        (make_dex(), "Lexample/Test;"),
        (make_static_field_dex(), "Lexample/Statics;"),
        (make_rich_dex(), "Lexample/Iface;"),
        (make_rich_dex(), "Lexample/Rich;"),
        (make_many_members_dex(3, false), "Lexample/Big;"),
    ] {
        let out = rebuild_class_bytes(&data, class).unwrap();
        let path = dir.join(format!("{}.dex", class.trim_matches(|c| c == 'L' || c == ';').replace('/', "_")));
        std::fs::write(&path, &out.bytes).unwrap();
        let res = std::process::Command::new(&dexdump).arg(&path).output().unwrap();
        let stderr = String::from_utf8_lossy(&res.stderr);
        assert!(res.status.success() && !stderr.contains("Failure to verify"), "{class}: {stderr}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
