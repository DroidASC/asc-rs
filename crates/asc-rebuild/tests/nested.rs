//! Rebuilding a class together with its nested classes: `$`-boundary
//! selection, per-class remapping of code and metadata, shared annotation
//! sets, and dropping nested classes that cannot be read.

mod common;

use asc_dex::annotations::{AnnotationsDirectory, parse_annotation_set, parse_annotation_set_ref_list};
use asc_dex::checksum::{adler32, sha1};
use asc_dex::debug_info::{DebugInfo, DebugOp};
use asc_dex::encoded::{AnnotationItem, EncodedAnnotation, EncodedValue, parse_annotation_item, parse_array};
use asc_dex::{ClassDef, Dex, map_type, mutf8};
use asc_fixture::{ClassSpec, CodeSpec, DexBuilder, MethodSpec, TrySpec};
use asc_rebuild::{RebuildError, Rebuilt, rebuild_class_bytes};

const ROOT: &str = "Lclass/A;";
const CHILD: &str = "Lclass/A$a;";
const GRANDCHILD: &str = "Lclass/A$a$b;";
const FAMILY: [&str; 3] = [ROOT, CHILD, GRANDCHILD];
const OBJECT: &str = "Ljava/lang/Object;";
const MARKER: &str = "Lclass/Marker;";
const IFACE: &str = "Lclass/Iface;";
const EXCEPTION: &str = "Ljava/lang/Exception;";

fn definition(dex: &Dex<'_>, descriptor: &str) -> ClassDef {
    dex.find_class_def(&mutf8::encode(descriptor)).unwrap().unwrap().1
}

fn descriptors(dex: &Dex<'_>) -> Vec<String> {
    dex.class_defs().map(|d| dex.type_descriptor(d.unwrap().class_idx).unwrap()).collect()
}

fn code<'a>(dex: &Dex<'a>, descriptor: &str, name: &str) -> asc_dex::code::CodeItem<'a> {
    let def = definition(dex, descriptor);
    let data = dex.class_data(def.class_data_off).unwrap();
    let method = data.methods().find(|m| dex.string(dex.method_id(m.method_idx).unwrap().name_idx).unwrap() == name).unwrap();
    dex.code_item(method.code_off).unwrap()
}

fn index_at(bytes: &[u8], offset: usize) -> u32 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap()) as u32
}

fn field(dex: &Dex<'_>, index: u32) -> (String, String, String) {
    let id = dex.field_id(index).unwrap();
    (dex.type_descriptor(id.class_idx as u32).unwrap(), dex.string(id.name_idx).unwrap(), dex.type_descriptor(id.type_idx as u32).unwrap())
}

fn method(dex: &Dex<'_>, index: u32) -> (String, String, String, Vec<String>) {
    let id = dex.method_id(index).unwrap();
    let proto = dex.proto_id(id.proto_idx as u32).unwrap();
    (
        dex.type_descriptor(id.class_idx as u32).unwrap(),
        dex.string(id.name_idx).unwrap(),
        dex.type_descriptor(proto.return_type_idx).unwrap(),
        dex.type_list(proto.parameters_off).unwrap().iter().map(|&t| dex.type_descriptor(t as u32).unwrap()).collect(),
    )
}

/// The three classes share ID tables but have different code, debug names,
/// annotations and static values. Cross references form A -> a -> b -> A.
fn family_dex() -> Vec<u8> {
    let mut builder = DexBuilder::new();
    for ty in [OBJECT, MARKER, IFACE, EXCEPTION] {
        builder.type_(ty);
    }
    for name in ["value", "peer", "field", "method", "shared"] {
        builder.string(name);
    }
    for (i, class) in FAMILY.iter().enumerate() {
        let peer = FAMILY[(i + 1) % FAMILY.len()];
        builder
            .field(class, "ALPHA", "I")
            .field(class, "NAME", "Ljava/lang/String;")
            .field(class, "ZETA", "I")
            .field(class, "peer", peer)
            .method(class, "value", "I", &[])
            .method(class, "echo", "I", &["I"])
            .method(class, "consume", "V", &[peer])
            .string(&format!("source-{i}.java"))
            .string(&format!("arg-{i}"))
            .string(&format!("local-{i}"))
            .string(class);
    }
    // Remove these unused IDs during rebuilding to force operand remapping.
    builder.field("Laaa/Unused;", "unused", "I").method("Laaa/Unused;", "unused", "V", &[]).type_("Laaa/UnusedType;");
    let mut ids = builder.resolve();
    for (i, class) in FAMILY.iter().enumerate() {
        let peer = FAMILY[(i + 1) % FAMILY.len()];
        let peer_field = ids.field(peer, "ZETA", "I");
        let peer_method = ids.method(peer, "echo", "I", &["I"]);
        let value = ids.method(class, "value", "I", &[]);
        let echo = ids.method(class, "echo", "I", &["I"]);
        let consume = ids.method(class, "consume", "V", &[peer]);
        let annotation = AnnotationItem {
            visibility: 1,
            annotation: EncodedAnnotation {
                type_idx: ids.type_(MARKER) as u32,
                elements: vec![
                    (ids.string("field"), EncodedValue::Field(peer_field)),
                    (ids.string("method"), EncodedValue::Method(peer_method)),
                    (ids.string("peer"), EncodedValue::Type(ids.type_(peer) as u32)),
                    (ids.string("value"), EncodedValue::String(ids.string(class))),
                ],
            },
        };
        let mut insns = vec![0x60, 0]; // sget v0, peer.ZETA
        insns.extend_from_slice(&(peer_field as u16).to_le_bytes());
        insns.extend_from_slice(&[0x71, 0x10]); // invoke-static {v0}, peer.echo(I)I
        insns.extend_from_slice(&(peer_method as u16).to_le_bytes());
        insns.extend_from_slice(&[0, 0, 0x0a, 0, 0x0f, 0]); // move-result v0; return v0
        insns.extend_from_slice(&[0x0d, 1, 0x12, 0, 0x0f, 0]); // handler at pc 7
        ids.add_class(ClassSpec {
            descriptor: class.to_string(),
            access: 0x401,
            superclass: Some(OBJECT.into()),
            interfaces: vec![IFACE.into()],
            source_file: Some(format!("source-{i}.java")),
            static_fields: vec![
                (ids.field(class, "ALPHA", "I"), 9),
                (ids.field(class, "NAME", "Ljava/lang/String;"), 9),
                (ids.field(class, "ZETA", "I"), 9),
            ],
            instance_fields: vec![(ids.field(class, "peer", peer), 1)],
            static_values: vec![
                EncodedValue::Primitive { kind: asc_dex::encoded::VALUE_INT, raw: vec![11 + i as u8] },
                EncodedValue::String(ids.string(class)),
                EncodedValue::Primitive { kind: asc_dex::encoded::VALUE_INT, raw: vec![22 + i as u8] },
            ],
            direct_methods: vec![
                MethodSpec {
                    idx: value,
                    access: 9,
                    code: Some(CodeSpec {
                        registers: 2,
                        outs: 1,
                        insns,
                        tries: vec![TrySpec {
                            start_addr: 0,
                            insn_count: 5,
                            catches: vec![(ids.type_(EXCEPTION) as u32, 7)],
                            catch_all: Some(7),
                        }],
                        debug: Some(DebugInfo {
                            line_start: 20 + i as u32,
                            ops: vec![
                                DebugOp::StartLocal {
                                    reg: 1,
                                    name: Some(ids.string(&format!("local-{i}"))),
                                    type_: Some(ids.type_(peer) as u32),
                                },
                                DebugOp::SetFile(Some(ids.string(&format!("source-{i}.java")))),
                                asc_fixture::dbg_special(0, 0),
                                DebugOp::EndSequence,
                            ],
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                },
                MethodSpec {
                    idx: echo,
                    access: 9,
                    code: Some(CodeSpec {
                        registers: 1,
                        ins: 1,
                        insns: vec![0x0f, 0],
                        debug: Some(DebugInfo {
                            line_start: 30 + i as u32,
                            parameter_names: vec![Some(ids.string(&format!("arg-{i}")))],
                            ops: vec![DebugOp::EndSequence],
                        }),
                        ..Default::default()
                    }),
                },
            ],
            virtual_methods: vec![MethodSpec { idx: consume, access: 0x401, code: None }],
            class_annotations: vec![annotation.clone()],
            field_annotations: vec![(ids.field(class, "ZETA", "I"), vec![annotation.clone()])],
            method_annotations: vec![(consume, vec![annotation.clone()])],
            parameter_annotations: vec![(consume, vec![vec![annotation]])],
        });
    }
    ids.finish()
}

fn annotation_text(dex: &Dex<'_>, set: u32) -> Vec<String> {
    parse_annotation_set(dex.buf(), set as usize)
        .unwrap()
        .into_iter()
        .map(|off| {
            let item = parse_annotation_item(dex.buf(), off as usize).unwrap().0;
            assert_eq!(dex.type_descriptor(item.annotation.type_idx).unwrap(), MARKER);
            assert_eq!(item.visibility, 1);
            item.annotation
                .elements
                .into_iter()
                .map(|(name, value)| {
                    let value = match value {
                        EncodedValue::String(s) => dex.string(s).unwrap(),
                        EncodedValue::Type(t) => dex.type_descriptor(t).unwrap(),
                        EncodedValue::Field(f) => format!("{:?}", field(dex, f)),
                        EncodedValue::Method(m) => format!("{:?}", method(dex, m)),
                        value => panic!("unexpected annotation value: {value:?}"),
                    };
                    format!("{}={value}", dex.string(name).unwrap())
                })
                .collect::<Vec<_>>()
                .join(",")
        })
        .collect()
}

fn class_only_dex(names: &[&str]) -> Vec<u8> {
    let mut builder = DexBuilder::new();
    builder.type_(OBJECT);
    for name in names {
        builder.type_(name);
    }
    let mut ids = builder.resolve();
    for name in names {
        ids.add_class(ClassSpec {
            descriptor: name.to_string(),
            access: 1,
            superclass: Some(if *name == "Lclass/Subclass;" { ROOT } else { OBJECT }.into()),
            ..Default::default()
        });
    }
    ids.finish()
}

#[test]
fn nested_selection_uses_dollar_boundaries_and_preserves_definition_order() {
    let names =
        [GRANDCHILD, ROOT, "Lclass/A$ab;", CHILD, "Lclass/A$c;", "Lclass/AB;", "Lclass/A$a$b$c;", "Lclass/A$1;", "Lclass/Subclass;"];
    let bytes = class_only_dex(&names);
    for (target, expected) in [
        (ROOT, vec![GRANDCHILD, ROOT, "Lclass/A$ab;", CHILD, "Lclass/A$c;", "Lclass/A$a$b$c;", "Lclass/A$1;"]),
        (CHILD, vec![GRANDCHILD, CHILD, "Lclass/A$a$b$c;"]),
        (GRANDCHILD, vec![GRANDCHILD, "Lclass/A$a$b$c;"]),
        ("Lclass/A$c;", vec!["Lclass/A$c;"]),
    ] {
        let out = rebuild_class_bytes(&bytes, target).unwrap();
        let dex = Dex::parse(&out.bytes).unwrap();
        assert_eq!(descriptors(&dex), expected);
        assert!(dex.class_defs().all(|d| d.unwrap().class_data_off == 0));
        let again = rebuild_class_bytes(&out.bytes, target).unwrap();
        assert_eq!(out.bytes, again.bytes);
    }
    let orphan = class_only_dex(&[CHILD]);
    assert!(matches!(rebuild_class_bytes(&orphan, ROOT), Err(RebuildError::ClassNotFound(_))));
    // Missing intermediate definitions do not hide a deeper nested class.
    let missing_parent = class_only_dex(&[ROOT, GRANDCHILD]);
    let out = rebuild_class_bytes(&missing_parent, ROOT).unwrap();
    assert_eq!(descriptors(&Dex::parse(&out.bytes).unwrap()), [ROOT, GRANDCHILD]);
    assert!(matches!(rebuild_class_bytes(&missing_parent, CHILD), Err(RebuildError::ClassNotFound(_))));
}

#[test]
fn nested_unicode_descriptors_are_matched_as_mutf8() {
    let root = "Lclass/外😀;";
    let child = "Lclass/外😀$内;";
    let sibling = "Lclass/外😀x;";
    let bytes = class_only_dex(&[root, child, sibling]);
    let out = rebuild_class_bytes(&bytes, root).unwrap();
    assert_eq!(descriptors(&Dex::parse(&out.bytes).unwrap()), [root, child]);
}

#[test]
fn nested_rebuild_remaps_each_classes_code_and_metadata_without_mixing_them() {
    let bytes = family_dex();
    let original = Dex::parse(&bytes).unwrap();
    for (target, expected) in [(ROOT, FAMILY.to_vec()), (CHILD, vec![CHILD, GRANDCHILD]), (GRANDCHILD, vec![GRANDCHILD])] {
        let out = rebuild_class_bytes(&bytes, target).unwrap();
        let dex = Dex::parse(&out.bytes).unwrap();
        assert_eq!(descriptors(&dex), expected);
        assert!(out.dropped.is_empty());
        assert_eq!(out.stats.methods_with_code, 2 * expected.len());
        assert_eq!(&out.bytes[12..32], sha1(&out.bytes[32..]));
        assert_eq!(u32::from_le_bytes(out.bytes[8..12].try_into().unwrap()), adler32(&out.bytes[12..]));
        let map = dex.map_list();
        assert!(map.windows(2).all(|w| w[0].offset < w[1].offset));
        let mut kinds: Vec<_> = map.iter().map(|m| m.kind).collect();
        kinds.sort();
        kinds.dedup();
        assert_eq!(kinds.len(), map.len(), "one map entry per section");
        for (kind, count) in [
            (map_type::CLASS_DEF, expected.len()),
            (map_type::CLASS_DATA, expected.len()),
            (map_type::CODE, 2 * expected.len()),
            (map_type::DEBUG_INFO, 2 * expected.len()),
            (map_type::ANNOTATIONS_DIRECTORY, expected.len()),
            (map_type::ENCODED_ARRAY, expected.len()),
        ] {
            assert_eq!(map.iter().find(|m| m.kind == kind).unwrap().size as usize, count);
        }
        for class in &expected {
            let i = FAMILY.iter().position(|c| c == class).unwrap();
            let peer = FAMILY[(i + 1) % FAMILY.len()];
            let def = definition(&dex, class);
            assert_eq!(def.access_flags, 0x401);
            assert_eq!(dex.type_descriptor(def.superclass_idx).unwrap(), OBJECT);
            assert_eq!(dex.type_descriptor(dex.type_list(def.interfaces_off).unwrap()[0] as u32).unwrap(), IFACE);
            assert_eq!(dex.string(def.source_file_idx).unwrap(), format!("source-{i}.java"));
            let data = dex.class_data(def.class_data_off).unwrap();
            assert_eq!(data.fields().count(), 4);
            assert_eq!(data.methods().count(), 3);
            assert!(data.fields().all(|f| field(&dex, f.field_idx).0 == *class));
            assert!(data.methods().all(|m| method(&dex, m.method_idx).0 == *class));
            let values = parse_array(&out.bytes, def.static_values_off as usize).unwrap().0;
            assert_eq!(values[0].as_i64(), Some(11 + i as i64));
            assert!(matches!(values[1], EncodedValue::String(s) if dex.string(s).unwrap() == *class));
            assert_eq!(values[2].as_i64(), Some(22 + i as i64));
            assert_eq!(data.static_fields.iter().map(|f| field(&dex, f.field_idx).1).collect::<Vec<_>>(), ["ALPHA", "NAME", "ZETA"]);

            let item = code(&dex, class, "value");
            assert_eq!(field(&dex, index_at(item.insns, 2)), (peer.into(), "ZETA".into(), "I".into()));
            assert_eq!(method(&dex, index_at(item.insns, 6)), (peer.into(), "echo".into(), "I".into(), vec!["I".into()]));
            assert_ne!(index_at(item.insns, 2), index_at(code(&original, class, "value").insns, 2));
            assert_eq!((item.registers_size, item.ins_size, item.outs_size), (2, 0, 1));
            let tr = &item.tries[0];
            assert_eq!((tr.start_addr, tr.insn_count), (0, 5));
            let handler = item.handler_for(tr).unwrap();
            assert_eq!(
                handler.catches.iter().map(|(t, pc)| (dex.type_descriptor(*t).unwrap(), *pc)).collect::<Vec<_>>(),
                [(EXCEPTION.into(), 7)]
            );
            assert_eq!(handler.catch_all_addr, Some(7));
            let info = DebugInfo::parse(&out.bytes, item.debug_info_off as usize).unwrap().0;
            assert_eq!(info.line_start, 20 + i as u32);
            assert!(
                matches!(info.ops[0], DebugOp::StartLocal { name: Some(n), type_: Some(t), .. } if dex.string(n).unwrap() == format!("local-{i}") && dex.type_descriptor(t).unwrap() == peer)
            );
            assert!(matches!(info.ops[1], DebugOp::SetFile(Some(s)) if dex.string(s).unwrap() == format!("source-{i}.java")));
            assert_eq!(info.positions(), [(0, 20 + i as u32)]);
            let echo = code(&dex, class, "echo");
            let debug = DebugInfo::parse(&out.bytes, echo.debug_info_off as usize).unwrap().0;
            assert_eq!(dex.string(debug.parameter_names[0].unwrap()).unwrap(), format!("arg-{i}"));
            assert_eq!(data.virtual_methods[0].code_off, 0);

            let directory = AnnotationsDirectory::parse(&out.bytes, def.annotations_off as usize).unwrap();
            let old_directory = AnnotationsDirectory::parse(&bytes, definition(&original, class).annotations_off as usize).unwrap();
            assert_eq!(
                annotation_text(&dex, directory.class_annotations_off),
                annotation_text(&original, old_directory.class_annotations_off)
            );
            assert_eq!(field(&dex, directory.field_annotations[0].0), (class.to_string(), "ZETA".into(), "I".into()));
            assert_eq!(directory.method_annotations[0].0, data.virtual_methods[0].method_idx);
            assert_eq!(directory.parameter_annotations[0].0, data.virtual_methods[0].method_idx);
            let class_annotation = annotation_text(&dex, directory.class_annotations_off);
            assert_eq!(annotation_text(&dex, directory.field_annotations[0].1), class_annotation);
            assert_eq!(annotation_text(&dex, directory.method_annotations[0].1), class_annotation);
            let params = parse_annotation_set_ref_list(&out.bytes, directory.parameter_annotations[0].1 as usize).unwrap();
            assert_eq!(annotation_text(&dex, params[0]), class_annotation);
        }
        assert_eq!(rebuild_class_bytes(&out.bytes, target).unwrap().bytes, out.bytes);
    }
}

#[test]
fn nested_classes_can_share_annotation_sets() {
    let mut bytes = family_dex();
    let dex = Dex::parse(&bytes).unwrap();
    let root_dir = definition(&dex, ROOT).annotations_off;
    let child_dir = definition(&dex, CHILD).annotations_off;
    let shared = AnnotationsDirectory::parse(&bytes, root_dir as usize).unwrap().class_annotations_off;
    bytes[child_dir as usize..child_dir as usize + 4].copy_from_slice(&shared.to_le_bytes());
    let out = rebuild_class_bytes(&bytes, ROOT).unwrap();
    let dex = Dex::parse(&out.bytes).unwrap();
    let dir = |class| AnnotationsDirectory::parse(&out.bytes, definition(&dex, class).annotations_off as usize).unwrap();
    assert_eq!(dir(ROOT).class_annotations_off, dir(CHILD).class_annotations_off);
    assert_ne!(dir(CHILD).class_annotations_off, dir(GRANDCHILD).class_annotations_off);
    assert_eq!(dex.map_list().iter().find(|m| m.kind == map_type::ANNOTATION).unwrap().size, 11);
    assert_eq!(rebuild_class_bytes(&out.bytes, ROOT).unwrap().bytes, out.bytes);
}

fn dropped(out: &Rebuilt) -> Vec<&str> {
    out.dropped.iter().map(|d| d.descriptor.as_str()).collect()
}

#[test]
fn malformed_nested_code_drops_that_class_and_keeps_the_target() {
    let mut bytes = family_dex();
    let dex = Dex::parse(&bytes).unwrap();
    let offset = code(&dex, GRANDCHILD, "value").offset + asc_dex::code::CodeItem::HEADER_SIZE;
    bytes[offset] = 0x3e; // undefined opcode
    let dexdump = common::dexdump();
    for (target, kept) in [(ROOT, vec![ROOT, CHILD]), (CHILD, vec![CHILD])] {
        let out = rebuild_class_bytes(&bytes, target).unwrap();
        assert_eq!(descriptors(&Dex::parse(&out.bytes).unwrap()), kept);
        assert_eq!(dropped(&out), [GRANDCHILD]);
        assert!(out.dropped[0].reason.starts_with("malformed bytecode"), "{}", out.dropped[0]);
        // The child still references the dropped class without defining it.
        let dex = Dex::parse(&out.bytes).unwrap();
        assert_eq!(field(&dex, index_at(code(&dex, CHILD, "value").insns, 2)), (GRANDCHILD.into(), "ZETA".into(), "I".into()));
        if let Some(dexdump) = &dexdump {
            common::assert_verifies(dexdump, target, &out.bytes);
        }
    }
    // The requested class itself still has to rebuild.
    assert!(matches!(rebuild_class_bytes(&bytes, GRANDCHILD), Err(RebuildError::Bytecode { .. })));
}

#[test]
fn unreadable_nested_class_data_drops_that_class() {
    let mut bytes = family_dex();
    let dex = Dex::parse(&bytes).unwrap();
    let (i, _) = dex.find_class_def(&mutf8::encode(CHILD)).unwrap().unwrap();
    let class_data_off = dex.class_def_off(i) + 24;
    bytes[class_data_off..class_data_off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    let out = rebuild_class_bytes(&bytes, ROOT).unwrap();
    assert_eq!(descriptors(&Dex::parse(&out.bytes).unwrap()), [ROOT, GRANDCHILD]);
    assert_eq!(dropped(&out), [CHILD]);
    assert!(rebuild_class_bytes(&bytes, CHILD).is_err());
}

/// `LA;` with two fields and two nested classes of 0x7FFF fields each: the
/// nested pair fits a DEX, all three together do not.
fn oversized_family_dex() -> Vec<u8> {
    let members = |class: &str| if class == ROOT { 2 } else { 0x7FFF };
    let mut builder = DexBuilder::new();
    for class in FAMILY {
        for f in 0..members(class) {
            builder.field(class, &format!("f{f}"), "I");
        }
    }
    let mut ids = builder.resolve();
    for class in FAMILY {
        let static_fields = (0..members(class)).map(|f| (ids.field(class, &format!("f{f}"), "I"), 9)).collect();
        ids.add_class(ClassSpec { descriptor: class.into(), access: 1, static_fields, ..Default::default() });
    }
    ids.finish()
}

#[test]
fn nested_classes_that_only_fail_together_leave_the_target_alone() {
    let bytes = oversized_family_dex();
    let out = rebuild_class_bytes(&bytes, ROOT).unwrap();
    assert_eq!(descriptors(&Dex::parse(&out.bytes).unwrap()), [ROOT]);
    assert_eq!(out.stats.fields, 2);
    assert_eq!(dropped(&out), [CHILD, GRANDCHILD]);
    assert!(out.dropped.iter().all(|d| d.reason.contains("16-bit index limits")), "{:?}", out.dropped);
    // A selection that fits keeps every class.
    let out = rebuild_class_bytes(&bytes, CHILD).unwrap();
    assert_eq!(descriptors(&Dex::parse(&out.bytes).unwrap()), [CHILD, GRANDCHILD]);
    assert!(out.dropped.is_empty());
}

#[test]
fn nested_rebuilds_pass_dexdump_verifier_when_available() {
    let Some(dexdump) = common::dexdump() else { return };
    let family = family_dex();
    for target in FAMILY {
        common::assert_verifies(&dexdump, target, &rebuild_class_bytes(&family, target).unwrap().bytes);
    }
    let names = [GRANDCHILD, ROOT, "Lclass/A$ab;", CHILD, "Lclass/A$1;", "Lclass/Subclass;"];
    common::assert_verifies(&dexdump, "class-only", &rebuild_class_bytes(&class_only_dex(&names), ROOT).unwrap().bytes);
}
