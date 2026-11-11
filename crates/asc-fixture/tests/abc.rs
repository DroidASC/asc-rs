//! What `AbcBuilder` writes is read back with `asc-abc` and `asc-arkisa`
//! and compared with what was declared; the layout is compared with real
//! compiler output when the samples are there.

// The full walk (and the real-sample loader) of asc-abc's integration tests.
#[path = "../../harmony/asc-abc/tests/common/mod.rs"]
mod common;

use asc_abc::{
    Abc, AbcError, CatchBlock, ClassEntry, ClassTag, FieldTag, FieldType, FieldValue, FunctionKind, LineOp, Literal, Method, MethodTag,
    Version,
};
use asc_fixture::abc::{
    adler32, make_abc, make_multi_region_abc, sample_program, AbcAnnotation, AbcBuilder, AbcCatch, AbcCode, AbcDebugInfo, AbcElementValue,
    AbcField, AbcFieldValue, AbcFile, AbcFunction, AbcLayout, AbcLineOp, AbcLiteral, AbcModule, AbcRecord, AbcTry, AbcType, AnnotationKind,
    Asm, Catch, MethodRef, Op, RegionHint, ACC_STATIC, ENTRY_ABILITY, INDEX_PAGE, SAMPLE_API_URL, SAMPLE_MAGIC, VERSION_12_0_6_0,
    VERSION_13_0_1_0, VERSION_9_0_0_0,
};
use common::{load_large_sample, load_large_sample_entry, load_sample, walk, Stats};

const VERSIONS: [[u8; 4]; 3] = [VERSION_9_0_0_0, VERSION_12_0_6_0, VERSION_13_0_1_0];

fn text(abc: &Abc<'_>, off: u32) -> String {
    abc.string(off).unwrap().to_str().into_owned()
}

/// Offset of the entity a symbolic operand of `record`'s code names.
fn entity_off(at: &AbcLayout, record: &str, operand: &Op) -> u32 {
    match operand {
        Op::Str(text) => at.string(text),
        Op::Method(name) => at.method(record, name),
        Op::MethodIn { record, name } => at.method(record, name),
        Op::Literal(id) => at.literal_array(*id),
        other => panic!("not a symbolic id: {other:?}"),
    }
}

fn expected_type(at: &AbcLayout, ty: &AbcType) -> FieldType {
    match ty {
        AbcType::U1 => FieldType::U1,
        AbcType::I8 => FieldType::I8,
        AbcType::U8 => FieldType::U8,
        AbcType::I16 => FieldType::I16,
        AbcType::U16 => FieldType::U16,
        AbcType::I32 => FieldType::I32,
        AbcType::U32 => FieldType::U32,
        AbcType::F32 => FieldType::F32,
        AbcType::F64 => FieldType::F64,
        AbcType::I64 => FieldType::I64,
        AbcType::U64 => FieldType::U64,
        AbcType::Reference => FieldType::Reference,
        AbcType::Any => FieldType::Any,
        AbcType::Record(name) => FieldType::Class(at.class(name)),
    }
}

fn expected_literal(at: &AbcLayout, literal: &AbcLiteral, data_off: u32) -> Literal {
    let method = |method: &MethodRef| at.method(&method.record, &method.name);
    match literal {
        AbcLiteral::TagValue(v) => Literal::TagValue(*v),
        AbcLiteral::Bool(v) => Literal::Bool(*v),
        AbcLiteral::Integer(v) => Literal::Integer(*v),
        AbcLiteral::Float(v) => Literal::Float(*v),
        AbcLiteral::Double(v) => Literal::Double(*v),
        AbcLiteral::String(v) => Literal::String(at.string(v)),
        AbcLiteral::Method(v) => Literal::Method(method(v)),
        AbcLiteral::GeneratorMethod(v) => Literal::GeneratorMethod(method(v)),
        AbcLiteral::AsyncGeneratorMethod(v) => Literal::AsyncGeneratorMethod(method(v)),
        AbcLiteral::Getter(v) => Literal::Getter(method(v)),
        AbcLiteral::Setter(v) => Literal::Setter(method(v)),
        AbcLiteral::Accessor(v) => Literal::Accessor(*v),
        AbcLiteral::MethodAffiliate(v) => Literal::MethodAffiliate(*v),
        AbcLiteral::LiteralBufferIndex(v) => Literal::LiteralBufferIndex(*v),
        AbcLiteral::LiteralArray(id) => Literal::LiteralArray(at.literal_array(*id)),
        AbcLiteral::BuiltinTypeIndex(v) => Literal::BuiltinTypeIndex(*v),
        AbcLiteral::EtsImplements(v) => Literal::EtsImplements(at.string(v)),
        AbcLiteral::Null => Literal::Null(0),
        AbcLiteral::TypedArray { tag, .. } => Literal::TypedArray { tag: *tag, data_off },
        AbcLiteral::Raw { tag, .. } => panic!("raw literal {tag:#x} has no expected value"),
    }
}

fn check_literal_array(abc: &Abc<'_>, at: &AbcLayout, off: u32, declared: &[AbcLiteral]) {
    let array = abc.literal_array(off).unwrap();
    assert_eq!(array.len() as usize, declared.len());
    let mut items = array.iter();
    for literal in declared {
        // Where a typed array's data starts: one tag byte past the current position.
        let data_off = items.offset() + 1;
        assert_eq!(items.next().unwrap().unwrap(), expected_literal(at, literal, data_off));
    }
    assert!(items.next().is_none());
}

fn check_module(abc: &Abc<'_>, off: u32, declared: &AbcModule) {
    let module = abc.module_record(off).unwrap();
    let text = |off| text(abc, off);
    assert_eq!(module.requests.iter().map(text).collect::<Vec<_>>(), declared.requests);
    let regular: Vec<_> =
        module.regular_imports.iter().map(|i| (text(i.local_name_off), text(i.import_name_off), i.module_request_idx)).collect();
    assert_eq!(
        regular,
        declared.regular_imports.iter().map(|i| (i.local_name.clone(), i.import_name.clone(), i.request)).collect::<Vec<_>>()
    );
    let namespace: Vec<_> = module.namespace_imports.iter().map(|i| (text(i.local_name_off), i.module_request_idx)).collect();
    assert_eq!(namespace, declared.namespace_imports.iter().map(|i| (i.local_name.clone(), i.request)).collect::<Vec<_>>());
    let local: Vec<_> = module.local_exports.iter().map(|e| (text(e.local_name_off), text(e.export_name_off))).collect();
    assert_eq!(local, declared.local_exports.iter().map(|e| (e.local_name.clone(), e.export_name.clone())).collect::<Vec<_>>());
    let indirect: Vec<_> =
        module.indirect_exports.iter().map(|e| (text(e.export_name_off), text(e.import_name_off), e.module_request_idx)).collect();
    assert_eq!(
        indirect,
        declared.indirect_exports.iter().map(|e| (e.export_name.clone(), e.import_name.clone(), e.request)).collect::<Vec<_>>()
    );
    assert_eq!(module.star_exports.iter().map(|e| e.module_request_idx).collect::<Vec<_>>(), declared.star_exports);
}

/// `found` is in file order, which is by tag; within a kind it is the declared order.
fn check_annotations(abc: &Abc<'_>, at: &AbcLayout, found: &[(AnnotationKind, u32)], declared: &[AbcAnnotation]) {
    assert_eq!(found.len(), declared.len());
    let (mut found, mut declared) = (found.to_vec(), declared.iter().collect::<Vec<_>>());
    found.sort_by_key(|&(kind, _)| kind);
    declared.sort_by_key(|annotation| annotation.kind);
    for ((kind, off), declared) in found.into_iter().zip(declared) {
        let annotation = abc.annotation(off).unwrap();
        assert_eq!((kind, annotation.class_off(abc).unwrap()), (declared.kind, at.class(&declared.class)));
        let elements: Vec<_> = annotation.elements().map(|e| (text(abc, e.name_off), e.value, e.tag)).collect();
        let stored = |value: &AbcElementValue| match value {
            AbcElementValue::Raw(value) => *value,
            AbcElementValue::String(value) => at.string(value),
            AbcElementValue::Array(id) => at.literal_array(*id),
        };
        assert_eq!(elements, declared.elements.iter().map(|e| (e.name.clone(), stored(&e.value), e.tag)).collect::<Vec<_>>());
    }
}

fn expected_line_op(abc: &Abc<'_>, op: LineOp) -> AbcLineOp {
    let text = |off| text(abc, off);
    match op {
        LineOp::AdvancePc(v) => AbcLineOp::AdvancePc(v),
        LineOp::AdvanceLine(v) => AbcLineOp::AdvanceLine(v),
        LineOp::StartLocal { reg, name_off, type_off } => AbcLineOp::StartLocal { reg, name: text(name_off), ty: text(type_off) },
        LineOp::StartLocalExtended { reg, name_off, type_off, signature_off } => {
            AbcLineOp::StartLocalExtended { reg, name: text(name_off), ty: text(type_off), signature: text(signature_off) }
        }
        LineOp::EndLocal { reg } => AbcLineOp::EndLocal(reg),
        LineOp::RestartLocal { reg } => AbcLineOp::RestartLocal(reg),
        LineOp::SetPrologueEnd => AbcLineOp::SetPrologueEnd,
        LineOp::SetEpilogueBegin => AbcLineOp::SetEpilogueBegin,
        LineOp::SetFile(off) => AbcLineOp::SetFile(text(off)),
        LineOp::SetSourceCode(off) => AbcLineOp::SetSourceCode(text(off)),
        LineOp::SetColumn(v) => AbcLineOp::SetColumn(v),
        LineOp::Special { pc_delta, line_delta } => AbcLineOp::Special { pc_delta, line_delta },
    }
}

/// Instructions walked and symbolic ids resolved by [`check_code`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct CodeStats {
    instructions: usize,
    ids: usize,
}

fn check_code(abc: &Abc<'_>, at: &AbcLayout, record: &str, method: &Method<'_>, declared: &AbcCode, stats: &mut CodeStats) {
    let code = method.code().unwrap().unwrap();
    assert_eq!((code.num_vregs, code.num_args), (declared.num_vregs, declared.num_args));
    let region = abc.region_of(method.offset()).unwrap();
    let assembled = declared.asm.assemble(|operand| region.entity_idx(entity_off(at, record, operand)).unwrap().unwrap());
    assert_eq!(code.instructions(), assembled.bytes);

    // The instruction stream walks to exactly `code_size`, and every id resolves to what was declared.
    let mut symbolic = declared.asm.symbolic_ids();
    let mut instructions = asc_arkisa::walk(code.instructions());
    for insn in instructions.by_ref() {
        let insn = insn.unwrap();
        stats.instructions += 1;
        for id in [insn.string_id(), insn.method_id(), insn.literal_array_id()].into_iter().flatten() {
            let operand = symbolic.next().expect("more ids in the code than declared");
            let off = method.resolve(u16::try_from(id).unwrap()).unwrap();
            match operand {
                Op::Str(expected) => assert_eq!(&text(abc, off), expected),
                Op::Method(name) | Op::MethodIn { name, .. } => assert_eq!(&text(abc, abc.method(off).unwrap().name_off), name),
                Op::Literal(id) => assert_eq!(off, at.literal_array(*id)),
                other => panic!("{other:?}"),
            }
            assert_eq!(off, entity_off(at, record, operand));
            stats.ids += 1;
        }
        if let Some(target) = insn.jump_target() {
            assert!(assembled.labels.values().any(|&label| label as usize == target), "jump to {target}, which is no label");
        }
    }
    assert_eq!(instructions.pc(), code.instructions().len());
    assert!(symbolic.next().is_none());

    let mut expected: Vec<AbcTry> = Vec::new();
    for catch in declared.asm.catches() {
        let (start_pc, handler_pc) = (assembled.label(&catch.try_start), assembled.label(&catch.handler));
        let length = assembled.label(&catch.try_end) - start_pc;
        let block = AbcCatch { type_idx: catch.type_idx, handler_pc, code_size: assembled.label(&catch.handler_end) - handler_pc };
        match expected.iter_mut().find(|known| (known.start_pc, known.length) == (start_pc, length)) {
            Some(known) => known.catches.push(block),
            None => expected.push(AbcTry { start_pc, length, catches: vec![block] }),
        }
    }
    expected.extend(declared.tries.iter().cloned());
    let found: Vec<AbcTry> = code
        .try_blocks()
        .map(|block| {
            let block = block.unwrap();
            let catches =
                block.catch_blocks().map(|CatchBlock { type_idx, handler_pc, code_size }| AbcCatch { type_idx, handler_pc, code_size });
            AbcTry { start_pc: block.start_pc, length: block.length, catches: catches.collect() }
        })
        .collect();
    assert_eq!(found, expected);
}

fn check_debug_info(abc: &Abc<'_>, method: &Method<'_>, declared: &AbcDebugInfo) {
    let debug = method.debug_info().unwrap().unwrap();
    assert_eq!(debug.line_start, declared.line_start);
    let params: Vec<Option<String>> = debug.params().map(|off| (off != 0).then(|| text(abc, off))).collect();
    assert_eq!(params, declared.params);
    let ops: Vec<AbcLineOp> = debug.line_ops().unwrap().map(|op| expected_line_op(abc, op.unwrap())).collect();
    assert_eq!(ops, declared.program);
}

/// Open `file` strictly, walk all of it, and compare every declared
/// element with what the reader finds.
fn verify(builder: &AbcBuilder, file: &AbcFile) -> (Stats, CodeStats) {
    let at = &file.layout;
    let abc = Abc::parse(&file.bytes).unwrap();
    assert_eq!(abc.compute_checksum(), abc.header().checksum);
    assert_eq!(abc.header().file_size as usize, file.bytes.len());
    let stats = walk(&abc, true).unwrap();
    let mut code_stats = CodeStats::default();

    assert_eq!(stats.classes as usize - stats.foreign_classes as usize, builder.records().len());
    for record in builder.records() {
        let name = record.name.as_str();
        let class = abc.find_record(name.as_bytes()).unwrap().unwrap().local().unwrap();
        assert_eq!((class.offset(), class.name()), (at.class(name), name.as_bytes()));
        assert_eq!((class.access_flags, class.super_class_off), (record.access_flags, 0));
        assert_eq!(class.source_lang().unwrap().map(|lang| lang.0), record.source_lang);
        assert_eq!(class.source_file().unwrap().map(|file| file.to_str().into_owned()), record.source_file);
        let region = abc.region_of(class.offset()).unwrap();
        let (mut annotations, mut interfaces) = (Vec::new(), Vec::new());
        for tag in class.tags() {
            match tag.unwrap() {
                ClassTag::Annotation(off) => annotations.push((AnnotationKind::Plain, off)),
                ClassTag::RuntimeAnnotation(off) => annotations.push((AnnotationKind::Runtime, off)),
                ClassTag::TypeAnnotation(off) => annotations.push((AnnotationKind::Type, off)),
                ClassTag::RuntimeTypeAnnotation(off) => annotations.push((AnnotationKind::RuntimeType, off)),
                ClassTag::Interfaces(list) => interfaces.extend(list.iter().map(|idx| region.class_entry(idx).unwrap())),
                ClassTag::SourceLang(_) | ClassTag::SourceFile(_) => {}
            }
        }
        check_annotations(&abc, at, &annotations, &record.annotations);
        assert_eq!(interfaces, record.interfaces.iter().map(|name| at.class(name)).collect::<Vec<_>>());

        let fields: Vec<_> = class.fields().unwrap().map(Result::unwrap).collect();
        assert_eq!(fields.len(), record.fields.len());
        for (field, declared) in fields.iter().zip(&record.fields) {
            assert_eq!((text(&abc, field.name_off), field.access_flags), (declared.name.clone(), declared.access_flags));
            assert_eq!(field.field_type().unwrap(), expected_type(at, &declared.ty), "{}", declared.name);
            assert_eq!(region.class_entry(field.class_idx).unwrap(), class.offset());
            let expected = match &declared.value {
                AbcFieldValue::None => None,
                AbcFieldValue::Int(value) => Some(FieldValue::Int(*value)),
                AbcFieldValue::Raw(value) => Some(FieldValue::Raw(*value)),
                AbcFieldValue::Wide(value) => {
                    assert_eq!(field.wide_value().unwrap(), Some(*value));
                    field.value()
                }
                AbcFieldValue::String(value) => Some(FieldValue::Raw(at.string(value))),
                AbcFieldValue::Array(id) => Some(FieldValue::Raw(at.literal_array(*id))),
                AbcFieldValue::ModuleRequestPhases(phases) => {
                    assert_eq!(class.module_request_phases().unwrap(), Some(phases.as_slice()));
                    assert_eq!(abc.module_request_phases(at.module_request_phases(name)).unwrap(), phases.as_slice());
                    Some(FieldValue::Raw(at.module_request_phases(name)))
                }
                AbcFieldValue::ScopeNames(names) => {
                    let off = at.scope_names(name);
                    let found: Vec<String> =
                        abc.literal_array(off).unwrap().iter().map(|literal| text(&abc, literal.unwrap().string_off().unwrap())).collect();
                    assert_eq!(&found, names);
                    Some(FieldValue::Raw(off))
                }
                AbcFieldValue::Module(module) => {
                    check_module(&abc, at.module_record(name), module);
                    Some(FieldValue::Raw(at.module_record(name)))
                }
            };
            assert_eq!(field.value(), expected, "{}", declared.name);
            let annotations: Vec<_> = field
                .tags()
                .filter_map(|tag| match tag.unwrap() {
                    FieldTag::Annotation(off) => Some((AnnotationKind::Plain, off)),
                    FieldTag::RuntimeAnnotation(off) => Some((AnnotationKind::Runtime, off)),
                    FieldTag::TypeAnnotation(off) => Some((AnnotationKind::Type, off)),
                    FieldTag::RuntimeTypeAnnotation(off) => Some((AnnotationKind::RuntimeType, off)),
                    FieldTag::IntValue(_) | FieldTag::Value(_) => None,
                })
                .collect();
            check_annotations(&abc, at, &annotations, &declared.annotations);
        }

        let methods: Vec<_> = class.methods().unwrap().map(Result::unwrap).collect();
        assert_eq!(methods.len(), record.functions.len());
        for (method, declared) in methods.iter().zip(&record.functions) {
            assert_eq!(text(&abc, method.name_off), declared.name);
            assert_eq!((method.access_flags & 0xff, method.function_kind().0), (declared.access_flags, declared.kind));
            assert_eq!(method.source_lang().map(|lang| lang.0), declared.source_lang);
            assert_eq!(method.class_off().unwrap(), class.offset());
            let region = method.region().unwrap();
            assert!(region.contains(method.offset()));
            if abc.method(at.method(name, &declared.name)).unwrap().offset() == method.offset() {
                assert_eq!(region.index(), at.method_region(name, &declared.name));
            }
            // Before 12 every method has a prototype; from 12 on none has.
            assert_eq!(method.proto_off().unwrap().is_some(), abc.header().version < Version([12, 0, 0, 0]));
            assert_eq!(method.proto_idx == u16::MAX, abc.header().version >= Version([12, 0, 0, 0]));
            match &declared.code {
                Some(code) => check_code(&abc, at, name, method, code, &mut code_stats),
                None => assert!(method.code_off().is_none()),
            }
            match &declared.debug {
                Some(debug) => check_debug_info(&abc, method, debug),
                None => assert!(method.debug_info_off().is_none()),
            }
            let annotations: Vec<_> = method
                .tags()
                .filter_map(|tag| match tag.unwrap() {
                    MethodTag::Annotation(off) => Some((AnnotationKind::Plain, off)),
                    MethodTag::RuntimeAnnotation(off) => Some((AnnotationKind::Runtime, off)),
                    MethodTag::TypeAnnotation(off) => Some((AnnotationKind::Type, off)),
                    MethodTag::RuntimeTypeAnnotation(off) => Some((AnnotationKind::RuntimeType, off)),
                    MethodTag::Code(_)
                    | MethodTag::SourceLang(_)
                    | MethodTag::DebugInfo(_)
                    | MethodTag::RuntimeParamAnnotation(_)
                    | MethodTag::ParamAnnotation(_) => None,
                })
                .collect();
            check_annotations(&abc, at, &annotations, &declared.annotations);
        }
    }
    for (id, declared) in builder.literal_arrays() {
        check_literal_array(&abc, at, at.literal_array(id), declared);
    }
    (stats, code_stats)
}

/// Layout rules of the official writer that hold for every real sample
/// (any version) and that the builder is expected to follow too.
fn layout_violations(abc: &Abc<'_>) -> Vec<String> {
    let mut violations = Vec::new();
    let mut check = |ok: bool, what: &str| {
        if !ok {
            violations.push(what.to_owned());
        }
    };
    let header = abc.header();
    let regions: Vec<_> = abc.regions().unwrap().iter().collect();
    let modern = header.version >= Version([12, 0, 0, 0]);

    check(abc.compute_checksum() == header.checksum, "checksum");
    check(header.file_size as usize == abc.bytes().len(), "file size");
    check(header.class_idx_off == 60, "class index follows the header");
    let class_index_end = 60 + 4 * header.num_classes;
    if header.has_literal_array_index() {
        check(header.literalarray_idx_off == class_index_end, "literal array index follows the class index");
        check(header.index_section_off == class_index_end + 4 * header.num_literalarrays, "region headers follow the literal array index");
    } else {
        check((header.num_literalarrays, header.literalarray_idx_off) == (u32::MAX, u32::MAX), "no literal array index");
        check(header.index_section_off == class_index_end, "region headers follow the class index");
    }
    check(header.lnp_idx_off % 4 == 0, "line number program index is aligned");
    check(header.lnp_idx_off + 4 * header.num_lnps == header.file_size, "line number program index ends the file");

    // Region tables: class table, entity table, (field table, proto table), one region after the other.
    let mut cursor = header.index_section_off + 40 * header.num_indexes;
    for region in &regions {
        let h = region.header();
        check(h.class_idx_off == cursor, "region class table position");
        check(h.method_idx_off == h.class_idx_off + 4 * h.class_idx_size, "region entity table follows its class table");
        cursor = h.method_idx_off + 4 * h.method_idx_size;
        if modern {
            check(
                [h.field_idx_size, h.field_idx_off, h.proto_idx_size, h.proto_idx_off] == [u32::MAX; 4],
                "no field / proto tables from 12 on",
            );
        } else {
            check((h.field_idx_size, h.field_idx_off, h.proto_idx_off) == (0, cursor, cursor), "empty field table, then the proto table");
            cursor += 4 * h.proto_idx_size;
        }
        let table: Vec<u32> = region.class_table().unwrap().iter().collect();
        let primitives = table.iter().take_while(|&&entry| entry <= 0x0c).count();
        check(table[..primitives].windows(2).all(|pair| pair[0] < pair[1]), "class table: primitive types ascending");
        check(table[primitives..].windows(2).all(|pair| pair[0] < pair[1]), "class table: classes in file order");
        check(table[primitives..].iter().all(|&entry| entry > 60), "class table: classes after primitives");
    }
    if let (Some(first), Some(last)) = (regions.first(), regions.last()) {
        check(first.header().start == cursor, "first region starts right after the tables");
        check(header.foreign_size == 0 || header.foreign_off == first.header().start, "foreign classes start the first region");
        check(last.header().end == header.file_size, "last region ends with the file");
        check(regions.windows(2).all(|pair| pair[0].header().end == pair[1].header().start), "regions are contiguous");
    }

    let descriptors: Vec<&[u8]> = abc.classes().unwrap().map(|entry| entry.unwrap().descriptor().bytes).collect();
    check(descriptors.windows(2).all(|pair| pair[0] < pair[1]), "class index sorted by descriptor");

    // Items: tag order inside classes and methods; in newer files (`ItemContainer::ReLayout`) classes,
    // then strings, then everything else, with code before debug info.
    let (mut class_end, mut first_name, mut last_name) = (0u32, u32::MAX, 0u32);
    let (mut code, mut debug, mut annotation) = ((u32::MAX, 0u32), (u32::MAX, 0u32), (u32::MAX, 0u32));
    let note = |range: &mut (u32, u32), off: u32| *range = (range.0.min(off), range.1.max(off));
    let (mut class_tags_ordered, mut method_tags_ordered, mut hints_exact) = (true, true, true);
    for entry in abc.classes().unwrap() {
        let ClassEntry::Local(class) = entry.unwrap() else { continue };
        let tags: Vec<u8> = class
            .tags()
            .map(|tag| match tag.unwrap() {
                ClassTag::Interfaces(_) => 1,
                ClassTag::SourceLang(_) => 2,
                ClassTag::RuntimeAnnotation(_) => 3,
                ClassTag::Annotation(_) => 4,
                ClassTag::RuntimeTypeAnnotation(_) => 5,
                ClassTag::TypeAnnotation(_) => 6,
                ClassTag::SourceFile(_) => 7,
            })
            .collect();
        class_tags_ordered &= tags.windows(2).all(|pair| pair[0] <= pair[1]);
        let mut fields = class.fields().unwrap();
        for field in fields.by_ref() {
            let name_off = field.unwrap().name_off;
            (first_name, last_name) = (first_name.min(name_off), last_name.max(name_off));
        }
        for method in fields.into_methods().unwrap() {
            let method = method.unwrap();
            (first_name, last_name) = (first_name.min(method.name_off), last_name.max(method.name_off));
            let mut tags = Vec::new();
            for tag in method.tags() {
                tags.push(match tag.unwrap() {
                    MethodTag::Code(off) => {
                        note(&mut code, off);
                        1
                    }
                    MethodTag::SourceLang(_) => 2,
                    MethodTag::RuntimeAnnotation(_) => 3,
                    MethodTag::RuntimeParamAnnotation(_) => 4,
                    MethodTag::DebugInfo(off) => {
                        note(&mut debug, off);
                        5
                    }
                    MethodTag::Annotation(off) => {
                        note(&mut annotation, off);
                        6
                    }
                    MethodTag::ParamAnnotation(_) => 7,
                    MethodTag::TypeAnnotation(_) => 8,
                    MethodTag::RuntimeTypeAnnotation(_) => 9,
                });
            }
            method_tags_ordered &= tags.windows(2).all(|pair| pair[0] <= pair[1]);
            hints_exact &= method.region_hint() == method.region().unwrap().index();
            // The byte after a method's terminating zero tag: one past its last tag byte.
            class_end = class_end.max(method.offset() + 8);
        }
    }
    check(class_tags_ordered, "class tags in ascending order");
    check(method_tags_ordered, "method tags in ascending order");
    check(hints_exact, "methods store the number of their region");
    // 12.0.2.0 files still interleave classes and strings.
    if header.version >= Version([12, 0, 6, 0]) && first_name != u32::MAX {
        check(class_end <= first_name, "classes come before strings");
        check(annotation.1 == 0 || last_name < annotation.0, "strings come before annotations");
        check(code.1 == 0 || annotation.1 < code.0, "annotations come before code");
        check(debug.1 == 0 || code.1 < debug.0, "code comes before debug info");
        check(debug.1 == 0 || debug.1 < header.lnp_idx_off, "debug info comes before the line number program index");
    }
    violations
}

#[test]
fn sample_round_trips_in_every_version_and_region_split() {
    type Split = fn(&mut AbcBuilder);
    let splits: [(&str, Split); 5] = [
        ("one region", |_| ()),
        ("per record", |b| _ = b.split_region_before(INDEX_PAGE)),
        ("every function", |b| _ = b.split_region_every(1)),
        ("every 3 functions", |b| _ = b.split_region_every(3)),
        ("7 entities per region", |b| _ = b.max_region_entities(7)),
    ];
    for version in VERSIONS {
        for (label, split) in splits {
            let mut builder = sample_program();
            split(builder.version(version));
            let file = builder.build();
            let (stats, code) = verify(&builder, &file);
            let abc = Abc::parse(&file.bytes).unwrap();
            assert_eq!(layout_violations(&abc), Vec::<String>::new(), "{version:?} {label}");
            println!("{version:?} {label}: {} bytes, regions {:?}, {code:?}", file.bytes.len(), stats.methods_per_region);

            assert_eq!((stats.classes, stats.pseudo_records, stats.fields, stats.methods), (3, 1, 12, 8), "{label}");
            assert_eq!((stats.code_bytes, stats.try_blocks, stats.catch_blocks), (188, 1, 1));
            assert_eq!((stats.annotations, stats.debug_infos, stats.line_rows), (8, 2, 9));
            assert_eq!((stats.module_records, stats.module_entries, stats.scope_name_tables, stats.scoped_names), (2, 5, 2, 6));
            assert_eq!(stats.region_hint_mismatches, 0);
            assert_eq!(code, CodeStats { instructions: 69, ids: 19 });
            let regions = match label {
                "one region" => vec![8],
                "per record" => vec![3, 5],
                "every function" => vec![1; 8],
                "every 3 functions" => vec![3, 3, 2],
                _ => vec![3, 2, 1, 2],
            };
            assert_eq!(stats.methods_per_region, regions, "{label}");
            // Up to 12.0.6.0 the header lists the literal arrays: 3 declared, 2 scope name tables (and the 2 module records).
            let listed = if Version(version) <= Version::LAST_WITH_LITERAL_INDEX { (5, 17) } else { (0, 0) };
            assert_eq!((stats.literal_arrays, stats.literals), listed);
            assert_eq!(abc.literal_array_index().unwrap().map(|index| index.len()), (listed.0 > 0).then_some(7));
        }
    }
}

#[test]
fn sample_contains_what_its_documentation_says() {
    let file = sample_program().build();
    assert_eq!(file.bytes, make_abc());
    let at = &file.layout;
    let abc = Abc::parse(&file.bytes).unwrap();
    assert_eq!(abc.header().version, Version(VERSION_12_0_6_0));
    let names: Vec<String> = abc.classes().unwrap().map(|entry| String::from_utf8_lossy(entry.unwrap().name()).into_owned()).collect();
    assert_eq!(names, [ENTRY_ABILITY, INDEX_PAGE, "_ESSlotNumberAnnotation"]);

    let index = abc.find_record(INDEX_PAGE.as_bytes()).unwrap().unwrap().local().unwrap();
    assert_eq!(index.package_name().unwrap(), Some(&b"entry"[..]));
    let methods: Vec<String> = index.methods().unwrap().map(|m| m.unwrap().name().unwrap().to_str().into_owned()).collect();
    assert_eq!(methods, ["func_main_0", "#~@0=#Index", "#~@0>#build", "#~@0>#aboutToAppear", "#*#helper"]);
    assert_eq!(
        methods.iter().map(|raw| index.restore_function_name(raw)).collect::<Vec<_>>()[1..4],
        ["Index.constructor", "Index.build", "Index.aboutToAppear"]
    );
    let module = index.module_record().unwrap().unwrap();
    assert_eq!(text(&abc, module.request(0).unwrap()), "@ohos:net.http");
    let import = module.regular_imports.get(0).unwrap();
    assert_eq!((text(&abc, import.local_name_off), text(&abc, import.import_name_off)), ("http".to_owned(), "default".to_owned()));

    // `build`: the import, the property, the call; the constant; the literal array; the try block and both jumps.
    let build = abc.method(at.method(INDEX_PAGE, "#~@0>#build")).unwrap();
    assert_eq!(build.function_kind().base(), FunctionKind::NONE);
    let code = build.code().unwrap().unwrap();
    let insns: Vec<_> = asc_arkisa::walk(code.instructions()).map(Result::unwrap).collect();
    let listing: Vec<(usize, &str)> = insns.iter().map(|insn| (insn.pc, insn.opcode.name)).collect();
    assert_eq!(listing[..4], [(0, "ldexternalmodulevar"), (2, "sta"), (4, "lda"), (6, "ldobjbyname")]);
    assert_eq!(insns[0].operand(0), Some(asc_arkisa::Value::Imm(0)));
    let string_at = |index: usize| text(&abc, build.resolve(u16::try_from(insns[index].string_id().unwrap()).unwrap()).unwrap());
    assert_eq!((string_at(3), string_at(5)), ("createHttp".to_owned(), SAMPLE_API_URL.to_owned()));
    assert_eq!((listing[8], insns[8].operands().collect::<Vec<_>>().len()), ((19, "callthis1"), 3));
    assert_eq!((listing[10], insns[10].jump_target()), ((25, "jmp"), Some(54)));
    assert_eq!((listing[21], insns[21].operand(0)), ((54, "ldai"), Some(asc_arkisa::Value::Imm(i64::from(SAMPLE_MAGIC)))));
    assert_eq!(SAMPLE_MAGIC, 0x1d4b42);
    assert_eq!(listing[23], (61, "createarraywithbuffer"));
    let methods_array = abc.literal_array(build.resolve(u16::try_from(insns[23].literal_array_id().unwrap()).unwrap()).unwrap()).unwrap();
    let items: Vec<Literal> = methods_array.iter().map(Result::unwrap).collect();
    assert_eq!(items, [Literal::String(at.string("GET")), Literal::String(at.string("POST")), Literal::Integer(2), Literal::Bool(true)]);
    assert_eq!((listing[25], insns[25].jump_target(), listing[27]), ((67, "jeqz"), Some(72), (72, "returnundefined")));
    let block = code.try_blocks().next().unwrap().unwrap();
    assert_eq!((block.start_pc, block.length), (0, 25));
    assert_eq!(block.catch_blocks().collect::<Vec<_>>(), [CatchBlock { type_idx: None, handler_pc: 27, code_size: 27 }]);
    let rows: Vec<(u32, u32)> =
        build.debug_info().unwrap().unwrap().line_rows().unwrap().map(|row| row.map(|row| (row.pc, row.line)).unwrap()).collect();
    assert_eq!(rows, [(0, 12), (12, 13), (25, 14), (27, 16), (54, 18), (72, 19)]);

    // `func_main_0` defines the class and the helper function.
    let main = abc.method(at.method(INDEX_PAGE, "func_main_0")).unwrap();
    let defined: Vec<(&str, String)> = asc_arkisa::walk(main.code().unwrap().unwrap().instructions())
        .map(Result::unwrap)
        .filter_map(|insn| Some((insn.opcode.name, main.resolve(u16::try_from(insn.method_id()?).ok()?).ok()?)))
        .map(|(name, off)| (name, text(&abc, abc.method(off).unwrap().name_off)))
        .collect();
    assert_eq!(defined, [("defineclasswithbuffer", "#~@0=#Index".to_owned()), ("definefunc", "#*#helper".to_owned())]);

    // One region: `testTag` has one id. Two: one per region.
    let test_tag = at.string("testTag");
    assert_eq!(
        (at.entity_id(ENTRY_ABILITY, "#~@0>#onCreate", test_tag), at.entity_id(INDEX_PAGE, "#*#helper", test_tag)),
        (Some(3), Some(3))
    );
    assert_eq!(at.regions[0].entities.len(), 18);
    let split = sample_program().split_region_before(INDEX_PAGE).build();
    assert_eq!(split.bytes, make_multi_region_abc());
    let at = &split.layout;
    let test_tag = at.string("testTag");
    assert_eq!(
        (at.entity_id(ENTRY_ABILITY, "#~@0>#onCreate", test_tag), at.entity_id(INDEX_PAGE, "#*#helper", test_tag)),
        (Some(3), Some(13))
    );
    assert_eq!((at.regions[0].entities.len(), at.regions[1].entities.len()), (5, 14));
    assert_eq!((at.method_region(ENTRY_ABILITY, "func_main_0"), at.method_region(INDEX_PAGE, "func_main_0")), (0, 1));
}

/// A file using everything the sample does not.
fn kitchen_sink(version: [u8; 4]) -> AbcBuilder {
    const RECORD: &str = "com.example.app/entry/ets/model/Kitchen";
    const OTHER: &str = "&@ohos/library/index&1.2.0";
    let mut builder = AbcBuilder::new();
    builder.version(version).foreign_class("_ESTypeAnnotation").foreign_class("std.core.Object").string("unreferenced");
    builder.record(AbcRecord::annotation_interface("_ESSlotNumberAnnotation"));

    let method = || MethodRef::new(RECORD, "#*#target");
    let nested = builder.literal_array([AbcLiteral::str("nested"), AbcLiteral::Null]);
    let empty = builder.literal_array([]);
    let everything = builder.literal_array([
        AbcLiteral::TagValue(7),
        AbcLiteral::Bool(false),
        AbcLiteral::Integer(i32::MIN),
        AbcLiteral::Float(-0.5),
        AbcLiteral::Double(f64::MAX),
        AbcLiteral::str("\u{4f60}\u{597d}, \u{1f600} and a NUL: \0."),
        AbcLiteral::Method(method()),
        AbcLiteral::GeneratorMethod(method()),
        AbcLiteral::AsyncGeneratorMethod(method()),
        AbcLiteral::Getter(method()),
        AbcLiteral::Setter(MethodRef::new(OTHER, "#*#exported")),
        AbcLiteral::Accessor(3),
        AbcLiteral::MethodAffiliate(0xfffe),
        AbcLiteral::LiteralBufferIndex(9),
        AbcLiteral::LiteralArray(nested),
        AbcLiteral::BuiltinTypeIndex(4),
        AbcLiteral::EtsImplements("L&entry/src/main/ets/Iface&;".to_owned()),
        AbcLiteral::Null,
        AbcLiteral::TypedArray { tag: 0x0d, data: vec![2, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd] },
    ]);

    let mut target = Asm::new();
    target.op("createobjectwithbuffer", [0.into(), everything.into()]).op("createarraywithbuffer", [1.into(), empty.into()]);
    target.insn(asc_arkisa::opcode(0x90).unwrap(), [0x1234.into(), Op::str("\u{4f60}\u{597d}, \u{1f600} and a NUL: \0.")]);
    target.op("wide.ldexternalmodulevar", [0x1ff.into()]).op("definemethod", [2.into(), Op::method_in(OTHER, "#*#exported"), 1.into()]);
    target.op("ldlexvar", [1.into(), 2.into()]).op("ldlexvar", [1.into(), 0x20.into()]).op("mov", [0x1234.into(), 0x4321.into()]);
    target.op("throw", []);
    let debug = AbcDebugInfo {
        line_start: u32::MAX,
        params: vec![Some("first".to_owned()), None, Some("third".to_owned())],
        program: vec![
            AbcLineOp::SetFile("entry/src/main/ets/model/Kitchen.ets".to_owned()),
            AbcLineOp::SetSourceCode("let x = 1".to_owned()),
            AbcLineOp::SetPrologueEnd,
            AbcLineOp::StartLocal { reg: 0, name: "x".to_owned(), ty: "any".to_owned() },
            AbcLineOp::StartLocalExtended { reg: -1, name: "y".to_owned(), ty: "any".to_owned(), signature: "sig".to_owned() },
            AbcLineOp::AdvanceLine(5),
            AbcLineOp::AdvancePc(300),
            AbcLineOp::SetColumn(40),
            AbcLineOp::Special { pc_delta: 15, line_delta: 10 },
            AbcLineOp::EndLocal(0),
            AbcLineOp::RestartLocal(0),
            AbcLineOp::Special { pc_delta: 0, line_delta: -4 },
            AbcLineOp::SetEpilogueBegin,
        ],
    };
    let mut raw_tries = AbcCode::raw(4, 3, &[0x62, 1, 0, 0, 0, 0x64]);
    raw_tries.tries.push(AbcTry {
        start_pc: 0,
        length: 5,
        catches: vec![
            AbcCatch { type_idx: Some(2), handler_pc: 5, code_size: 1 },
            AbcCatch { type_idx: None, handler_pc: 5, code_size: 1 },
        ],
    });
    let mut two_ranges = Asm::new();
    two_ranges.label("a").op("ldtrue", []).label("b").op("ldfalse", []).label("c").op("returnundefined", []).label("d");
    two_ranges.catch(Catch::all(("a", "b"), ("c", "d"))).catch(Catch::all(("b", "c"), ("c", "d")));
    two_ranges.catch(Catch::all(("a", "b"), ("b", "c")).typed(1));

    let annotation = |kind: AnnotationKind| AbcAnnotation { kind, ..AbcAnnotation::slot_number(3) };
    let mut wide = AbcField::new("big", AbcType::U64, AbcFieldValue::Wide(u64::MAX - 1)).annotation(annotation(AnnotationKind::Runtime));
    wide.access_flags = ACC_STATIC;
    let mut record = AbcRecord::new(RECORD)
        .source_file("entry/src/main/ets/model/Kitchen.ets")
        .annotation(annotation(AnnotationKind::Plain))
        .annotation(annotation(AnnotationKind::RuntimeType))
        .field(AbcField::flag("pkgName@entry", 0))
        .field(AbcField::new("flag", AbcType::U1, AbcFieldValue::Int(-1)))
        .field(AbcField::new("ratio", AbcType::F64, AbcFieldValue::Wide(2.5f64.to_bits())))
        .field(AbcField::new("bits", AbcType::F32, AbcFieldValue::Raw(1.5f32.to_bits())))
        .field(AbcField::new("jsonFileContent", AbcType::U32, AbcFieldValue::String("{\"a\":1}".to_owned())))
        .field(AbcField::new("other", AbcType::Record(OTHER.to_owned()), AbcFieldValue::None).annotation(annotation(AnnotationKind::Type)))
        .field(AbcField::new("object", AbcType::Record("std.core.Object".to_owned()), AbcFieldValue::None))
        .field(AbcField::new("dynamic", AbcType::Any, AbcFieldValue::None))
        .field(wide)
        .function(
            AbcFunction::new("#*#target", AbcCode::new(2, 5, target))
                .kind(FunctionKind::ASYNC_FUNCTION | FunctionKind::SENDABLE)
                .debug(debug.clone())
                .annotation(annotation(AnnotationKind::Plain))
                .annotation(annotation(AnnotationKind::Runtime))
                .annotation(annotation(AnnotationKind::Type))
                .annotation(annotation(AnnotationKind::RuntimeType)),
        )
        .function(AbcFunction::new("#*#tries", raw_tries).debug(debug))
        .function(AbcFunction::new("#*#ranges", AbcCode::new(0, 3, two_ranges)));
    record.interfaces = vec![OTHER.to_owned(), "std.core.Object".to_owned()];
    record.access_flags = 0;
    record.source_lang = Some(asc_abc::SourceLang::ARKTS.0);
    builder.record(record);

    let module = AbcModule::new()
        .import("a", "default", "@ohos:hilog")
        .namespace_import("ns", "@normalized:N&&&entry/src/main/ets/model/Kitchen&")
        .export("local", "exported")
        .indirect_export("again", "inner", "@ohos:hilog")
        .star_export("@normalized:N&&&entry/src/main/ets/model/Kitchen&");
    let mut exported = Asm::new();
    exported.op("callruntime.ldlazymodulevar", [1.into()]).op("lda.str", [Op::str("nested")]).op("return", []);
    let mut function = AbcFunction::new("#*#exported", AbcCode::new(0, 3, exported));
    function.access_flags = 0;
    function.source_lang = None;
    // The second request is a lazy import.
    builder.record(AbcRecord::ets_module(OTHER, "library", &[], module).field(AbcField::module_request_phases(&[0, 1])).function(function));
    builder
}

#[test]
fn annotation_values_round_trip() {
    use asc_abc::ElementValue;
    use asc_fixture::abc::{annotations_program, callable_names_program, MARKS_APP, MARKS_ROUTE};
    let named = callable_names_program();
    let file = named.build();
    verify(&named, &file);
    assert_eq!(layout_violations(&Abc::parse(&file.bytes).unwrap()), Vec::<String>::new());
    // As in a file of the compiler, the class index is in the order of the names, which with
    // an interface named after its module (`&m&.Route` after `&m&`) is not that of the descriptors.
    let annotated = annotations_program();
    let file = annotated.build();
    verify(&annotated, &file);
    assert_eq!(layout_violations(&Abc::parse(&file.bytes).unwrap()), ["class index sorted by descriptor"]);

    let abc = Abc::parse(&file.bytes).unwrap();
    // A string, an array and a number, each read by its type tag.
    let constructor = abc.method(file.layout.method(MARKS_APP, "#~@0=#Pay")).unwrap();
    let annotations: Vec<u32> = constructor
        .tags()
        .filter_map(|tag| match tag.unwrap() {
            MethodTag::Annotation(off) => Some(off),
            _ => None,
        })
        .collect();
    let route = abc.annotation(annotations[1]).unwrap();
    assert_eq!(route.class_off(&abc).unwrap(), file.layout.class(MARKS_ROUTE));
    let values: Vec<ElementValue> = route.elements().map(|element| element.typed(&abc).unwrap()).collect();
    let [ElementValue::String(path), ElementValue::Array(tags), ElementValue::Int(2)] = values[..] else { panic!("{values:?}") };
    assert_eq!(text(&abc, path), "/pay");
    let tags: Vec<String> = abc.literal_array(tags).unwrap().iter().map(|item| text(&abc, item.unwrap().string_off().unwrap())).collect();
    assert_eq!(tags, ["pay", "checkout"]);
    // An array type is declared by its descriptor, as the compiler does.
    let descriptors: Vec<String> = abc.classes().unwrap().map(|class| class.unwrap().descriptor().to_str().into_owned()).collect();
    assert!(descriptors.contains(&"[Lpanda.String;".to_owned()) && descriptors.contains(&"Lpanda.String;".to_owned()), "{descriptors:?}");
}

#[test]
fn every_structure_round_trips() {
    for version in VERSIONS {
        for split in [false, true] {
            let mut builder = kitchen_sink(version);
            if split {
                builder.split_region_every(1);
            }
            let file = builder.build();
            let (stats, code) = verify(&builder, &file);
            let abc = Abc::parse(&file.bytes).unwrap();
            assert_eq!(layout_violations(&abc), Vec::<String>::new(), "{version:?} split {split}");
            assert_eq!((stats.classes, stats.foreign_classes, stats.pseudo_records), (5, 2, 2));
            assert_eq!((stats.fields, stats.methods, stats.try_blocks, stats.catch_blocks), (16, 4, 3, 5));
            assert_eq!((stats.annotations, stats.debug_infos, stats.line_rows), (8, 2, 4));
            assert_eq!((stats.module_records, stats.module_entries), (1, 5));
            assert_eq!(code, CodeStats { instructions: 9 + 2 + 3 + 3, ids: 5 });
            assert_eq!(stats.methods_per_region, if split { vec![1; 4] } else { vec![4] });

            // The phase table is listed in the header literal array index (when there is one) and skipped by the walk.
            let phases = file.layout.module_request_phases("&@ohos/library/index&1.2.0");
            assert_eq!((abc.module_request_phases(phases).unwrap(), stats.phase_tables), (&[0u8, 1][..], 1));
            assert_eq!(&file.bytes[phases as usize..][..6], [2, 0, 0, 0, 0, 1]);
            if let Some(index) = abc.literal_array_index().unwrap() {
                assert!(index.position(phases).is_some());
                assert_eq!(u64::from(index.len()), stats.literal_arrays + stats.module_records + stats.phase_tables);
            }
            // Two functions with the same line number program share it.
            assert_eq!(abc.line_program_index().unwrap().len(), 1);
            // A string nothing refers to is still in the file, and non-ASCII text is MUTF-8.
            assert_eq!(text(&abc, file.layout.string("unreferenced")), "unreferenced");
            let odd = abc.string(file.layout.string("\u{4f60}\u{597d}, \u{1f600} and a NUL: \0.")).unwrap();
            assert_eq!((odd.is_ascii, odd.utf16_len, odd.to_str().as_ref()), (false, 20, "\u{4f60}\u{597d}, \u{1f600} and a NUL: \0."));
            assert!(abc.string(file.layout.string("nested")).unwrap().is_ascii);
            // Foreign classes sit in the foreign region, in declaration order.
            let foreign: Vec<u32> = ["_ESTypeAnnotation", "std.core.Object"].map(|name| file.layout.class(name)).to_vec();
            assert_eq!(abc.header().foreign_off, foreign[0]);
            assert!(
                foreign.iter().all(|&off| abc.header().is_foreign(off))
                    && !abc.header().is_foreign(file.layout.class("_ESSlotNumberAnnotation"))
            );
        }
    }
}

#[test]
fn versions_decide_tables_and_literal_index() {
    for version in VERSIONS {
        let file = sample_program().version(version).split_region_before(INDEX_PAGE).build();
        let at = &file.layout;
        let abc = Abc::parse(&file.bytes).unwrap();
        let header = abc.header();
        assert_eq!(header.version, Version(version));
        assert_eq!((header.class_idx_off, header.num_classes, header.num_indexes), (60, 3, 2));
        assert_eq!((header.foreign_off, header.foreign_size), (0, 0));

        // The literal array index lists module records too.
        let listed = abc.literal_array_index().unwrap().map(|index| index.iter().collect::<Vec<_>>());
        if version == VERSION_13_0_1_0 {
            assert_eq!((listed, at.literal_array_index_off), (None, None));
            assert_eq!((header.num_literalarrays, header.literalarray_idx_off, header.index_section_off), (u32::MAX, u32::MAX, 72));
        } else {
            let listed = listed.unwrap();
            assert_eq!((header.literalarray_idx_off, header.index_section_off), (72, 72 + 4 * 7));
            assert_eq!(
                listed[..4],
                [at.scope_names(ENTRY_ABILITY), at.module_record(ENTRY_ABILITY), at.scope_names(INDEX_PAGE), at.module_record(INDEX_PAGE)]
            );
            assert!(listed.windows(2).all(|pair| pair[0] < pair[1]));
        }

        for region in abc.regions().unwrap().iter() {
            let h = region.header();
            if version == VERSION_9_0_0_0 {
                // An empty field table, and one prototype per argument count: 3 and 5 in the first region, 3 and 4 in the second.
                assert_eq!((h.field_idx_size, h.field_idx_off, h.proto_idx_size), (0, h.proto_idx_off, 2));
                let protos: Vec<u32> = region.proto_table().unwrap().iter().collect();
                // `any` (0xe) for the return value and each argument, then a zero nibble.
                assert_eq!(&file.bytes[protos[0] as usize..][..2], [0xee, 0xee]);
                assert!(protos.iter().all(|off| off % 2 == 0));
            } else {
                assert_eq!([h.field_idx_size, h.field_idx_off, h.proto_idx_size, h.proto_idx_off], [u32::MAX; 4]);
                assert!(region.proto_table().unwrap().is_empty() && region.field_table().unwrap().is_empty());
            }
        }
        if version == VERSION_9_0_0_0 {
            let on_create = abc.method(at.method(ENTRY_ABILITY, "#~@0>#onCreate")).unwrap();
            // Five arguments: six `any` nibbles and the terminator.
            assert_eq!(&file.bytes[on_create.proto_off().unwrap().unwrap() as usize..][..4], [0xee, 0xee, 0xee, 0x00]);
            assert_eq!(on_create.proto_idx, 1);
        }
    }
}

#[test]
fn regions_split_where_asked_and_hints_can_lie() {
    // Three functions per region: the second and third region start in the middle of the page record.
    let mut builder = sample_program();
    let file = builder.split_region_every(3).build();
    let at = &file.layout;
    let abc = Abc::parse(&file.bytes).unwrap();
    let regions: Vec<_> = abc.regions().unwrap().iter().collect();
    let bounds: Vec<(u32, u32)> = regions.iter().map(|region| (region.header().start, region.header().end)).collect();
    assert_eq!(bounds.len(), 3);
    assert_eq!(bounds, at.regions.iter().map(|region| (region.start, region.end)).collect::<Vec<_>>());
    // The page's class item and fields still belong to the first region: a region is closed by a function.
    assert_eq!(bounds[0], (at.class("_ESSlotNumberAnnotation"), at.method(INDEX_PAGE, "func_main_0")));
    assert_eq!(bounds[1], (at.method(INDEX_PAGE, "func_main_0"), at.method(INDEX_PAGE, "#~@0>#aboutToAppear")));
    assert_eq!(bounds[2], (at.method(INDEX_PAGE, "#~@0>#aboutToAppear"), abc.header().file_size));
    // All three regions hold part of the page and list its class; the field types are needed in the first only.
    // Annotations sit in the last region, which lists their class.
    let page = at.class(INDEX_PAGE);
    assert_eq!(at.regions[0].classes, [0x02, 0x06, at.class("_ESSlotNumberAnnotation"), at.class(ENTRY_ABILITY), page]);
    assert_eq!(at.regions[1].classes, [page]);
    assert_eq!(at.regions[2].classes, [at.class("_ESSlotNumberAnnotation"), page]);
    for (region, layout) in regions.iter().zip(&at.regions) {
        assert_eq!(region.entity_table().unwrap().iter().collect::<Vec<_>>(), layout.entities);
        assert_eq!(region.class_table().unwrap().iter().collect::<Vec<_>>(), layout.classes);
    }
    for (name, region) in [("func_main_0", 1), ("#~@0=#Index", 1), ("#~@0>#build", 1), ("#~@0>#aboutToAppear", 2), ("#*#helper", 2)] {
        let method = abc.method(at.method(INDEX_PAGE, name)).unwrap();
        assert_eq!((method.region_hint(), method.region().unwrap().index(), at.method_region(INDEX_PAGE, name)), (region, region, region));
    }
    // An id of one region is another entity, or nothing, in the next.
    let helper = abc.method(at.method(INDEX_PAGE, "#*#helper")).unwrap();
    assert_eq!(text(&abc, helper.resolve(3).unwrap()), "testTag");
    assert_eq!(text(&abc, abc.resolve_entity(at.method(ENTRY_ABILITY, "#~@0>#onCreate"), 3).unwrap()), "testTag");
    assert_eq!(text(&abc, abc.resolve_entity(at.method(INDEX_PAGE, "#~@0>#build"), 3).unwrap()), "createHttp");
    assert!(matches!(helper.resolve(4), Err(AbcError::IndexOutOfRange { index: 4, size: 4, .. })));

    // A wrong region number in every method: out of range, or the number of another region.
    for (hint, wrong) in [(0xffff, 8), (2, 6), (0, 5)] {
        let file = builder.region_hint(RegionHint::Fixed(hint)).build();
        let abc = Abc::parse(&file.bytes).unwrap();
        let stats = walk(&abc, true).unwrap();
        assert_eq!((stats.methods_per_region.as_slice(), stats.region_hint_mismatches), (&[3, 3, 2][..], wrong), "hint {hint}");
        verify(&builder, &file);
    }
    // One method lying on its own.
    let mut lone = AbcBuilder::new();
    lone.record(AbcRecord::new("a").function(AbcFunction::new("f", AbcCode::raw(0, 3, &[0x65])).region_hint(5)));
    let file = lone.build();
    let abc = Abc::parse(&file.bytes).unwrap();
    let method = abc.method(file.layout.method("a", "f")).unwrap();
    assert_eq!((method.region_hint(), method.region().unwrap().index(), method.access_flags), (5, 0, 5 << 16 | 0x08));

    // The official mechanism: a region is closed when its id table is full.
    let mut builder = sample_program();
    let file = builder.max_region_entities(13).build();
    assert_eq!(file.layout.regions.iter().map(|region| region.entities.len()).collect::<Vec<_>>(), [8, 11]);
    assert_eq!(file.layout.regions[1].start, file.layout.method(INDEX_PAGE, "#~@0>#build"));
    verify(&builder, &file);
}

#[test]
#[should_panic(expected = "refers to 7 entities, a region holds 6")]
fn a_function_too_large_for_a_region_is_rejected() {
    sample_program().max_region_entities(6).build();
}

#[test]
fn hostile_files() {
    let plain = sample_program().build();
    let at = &plain.layout;

    // Unsorted class index: reverse name order, everything else unchanged.
    let unsorted = sample_program().unsorted_class_index().build();
    assert_eq!(unsorted.layout, plain.layout);
    let abc = Abc::parse(&unsorted.bytes).unwrap();
    assert_eq!(abc.compute_checksum(), abc.header().checksum);
    assert_eq!(
        abc.class_index().unwrap().iter().collect::<Vec<_>>(),
        [at.class("_ESSlotNumberAnnotation"), at.class(INDEX_PAGE), at.class(ENTRY_ABILITY)]
    );
    assert_eq!(layout_violations(&abc), ["class index sorted by descriptor"]);
    assert_eq!(abc.find_record(ENTRY_ABILITY.as_bytes()).unwrap().map(|entry| entry.offset()), Some(at.class(ENTRY_ABILITY)));

    // Stale checksum: only the checksum field differs.
    let stale = sample_program().stale_checksum().build().bytes;
    assert_eq!((&stale[..8], &stale[12..]), (&plain.bytes[..8], &plain.bytes[12..]));
    let abc = Abc::parse(&stale).unwrap();
    assert_ne!(abc.header().checksum, abc.compute_checksum());
    assert_eq!(layout_violations(&abc), ["checksum"]);
    walk(&abc, true).unwrap();

    // Encrypted: the plain header (checksum of the plain file included), then noise.
    let encrypted = sample_program().encrypted().build();
    assert_eq!(encrypted.layout, plain.layout);
    assert_eq!((encrypted.bytes.len(), &encrypted.bytes[..60]), (plain.bytes.len(), &plain.bytes[..60]));
    let differing = encrypted.bytes[60..].iter().zip(&plain.bytes[60..]).filter(|(a, b)| a != b).count();
    assert!(differing * 100 > (plain.bytes.len() - 60) * 99, "{differing} of {} body bytes differ", plain.bytes.len() - 60);
    let stored = adler32(&plain.bytes[12..]);
    assert_eq!(Abc::parse(&encrypted.bytes).unwrap_err(), AbcError::Encrypted { stored, computed: adler32(&encrypted.bytes[12..]) });
    assert_eq!(Abc::parse_lenient(&encrypted.bytes).unwrap().header(), Abc::parse(&plain.bytes).unwrap().header());

    // Truncated: a prefix of the plain file whose header still claims the full size.
    for len in [0, 59, 60, 61, 200, plain.bytes.len() - 1] {
        let cut = sample_program().truncated(len).build().bytes;
        assert_eq!(cut, &plain.bytes[..len]);
        match Abc::parse_lenient(&cut) {
            Ok(abc) => {
                assert_eq!(abc.header().file_size as usize, plain.bytes.len());
                let _ = walk(&abc, false);
                assert!(Abc::parse(&cut).is_err() || len > 200);
            }
            Err(err) => assert_eq!(err, AbcError::TooSmall(len)),
        }
    }

    // Code that is not instructions, a function without code, ids that resolve to nothing, a literal with an unknown tag.
    let mut builder = AbcBuilder::new();
    let odd = builder.literal_array([AbcLiteral::Integer(1), AbcLiteral::Raw { tag: 0x55, value: vec![1, 2, 3] }]);
    let mut dangling = Asm::new();
    dangling.op("lda.str", [Op::Id(0x7777)]).op("createarraywithbuffer", [0.into(), odd.into()]).op("returnundefined", []);
    let mut no_code = AbcFunction::new("#*#native", AbcCode::default());
    no_code.code = None;
    builder.record(
        AbcRecord::new("odd")
            .function(AbcFunction::new("#*#garbage", AbcCode::raw(0, 3, &[0x3e, 0x00, 0xe2, 0xff])))
            .function(no_code)
            .function(AbcFunction::new("#*#dangling", AbcCode::new(0, 3, dangling))),
    );
    let file = builder.build();
    let abc = Abc::parse(&file.bytes).unwrap();
    // The header index lists the odd literal array, and the walk stops at its unknown tag.
    assert!(matches!(walk(&abc, false), Err(AbcError::Malformed { what: "literal", .. })));
    let methods: Vec<_> = abc.class(file.layout.class("odd")).unwrap().methods().unwrap().map(Result::unwrap).collect();
    let garbage: Vec<_> = asc_arkisa::walk(methods[0].code().unwrap().unwrap().instructions()).collect();
    assert!(garbage.len() == 2 && garbage[0].is_ok() && garbage[1].is_err());
    assert!(methods[1].code().unwrap().is_none() && methods[1].tags().count() == 1);
    assert_eq!(methods[2].resolve(0x7777), Err(AbcError::IndexOutOfRange { what: "region method index", index: 0x7777, size: 1 }));
    let items: Vec<_> = abc.literal_array(methods[2].resolve(0).unwrap()).unwrap().iter().collect();
    assert_eq!((items.len(), &items[0]), (2, &Ok(Literal::Integer(1))));
    assert!(matches!(items[1], Err(AbcError::Malformed { what: "literal", .. })));
}

#[test]
fn an_empty_file_is_a_header_and_nothing_else() {
    let file = AbcBuilder::new().build();
    assert_eq!(file.bytes.len(), 60);
    let abc = Abc::parse(&file.bytes).unwrap();
    assert_eq!(layout_violations(&abc), Vec::<String>::new());
    let stats = walk(&abc, true).unwrap();
    assert_eq!((stats.classes, stats.methods_per_region.len(), abc.header().lnp_idx_off), (0, 0, 60));
}

/// The layout rules the builder follows are the official writer's: they
/// hold for every real sample, and for what the builder writes. Skipped
/// file by file when the samples are not there.
#[test]
fn layout_matches_real_files() {
    let samples = ["Bridge.hap", "contacts.hap", "遥遥领先.hap", "EasyHap-default-unsigned.app", "fpt-default-signed.app", "shctf.app"];
    let mut real: Vec<(String, Vec<u8>)> = samples.iter().filter_map(|name| Some(((*name).to_owned(), load_sample(name)?))).collect();
    real.extend(load_large_sample().map(|data| ("large sample modules.abc".to_owned(), data)));
    real.extend(load_large_sample_entry("ets/widgets.abc").map(|data| ("large sample widgets.abc".to_owned(), data)));
    let mut versions = Vec::new();
    for (name, data) in &real {
        let abc = Abc::parse(data).unwrap();
        assert_eq!(layout_violations(&abc), Vec::<String>::new(), "{name}");
        versions.push(format!("{name} {} ({} regions)", abc.header().version, abc.header().num_indexes));
    }
    println!("layout rules hold for {} real files: {versions:?}", real.len());

    let mut synthetic = 0;
    for version in VERSIONS {
        for builder in [sample_program(), kitchen_sink(version)] {
            for per_region in [None, Some(1), Some(2)] {
                let mut builder = builder.clone();
                builder.version(version);
                if let Some(methods) = per_region {
                    builder.split_region_every(methods);
                }
                let file = builder.build();
                assert_eq!(layout_violations(&Abc::parse(&file.bytes).unwrap()), Vec::<String>::new(), "{version:?} {per_region:?}");
                synthetic += 1;
            }
        }
    }
    println!("and for {synthetic} synthetic files");
}
