//! Tests on a synthetic file built with `asc-fixture`: every structure, the
//! multi-region paths the real samples cannot exercise, and malformed input.

mod common;

use asc_abc::{
    Abc, AbcError, CatchBlock, ClassEntry, FieldType, FieldValue, FunctionKind, LineOp, LineRow, Literal, LocalExport, RecordName,
    RegularImport, SourceLang, Version,
};
use asc_fixture::abc::{
    adler32, seal, AbcBuilder, AbcCode, AbcDebugInfo, AbcFunction, AbcLineOp, AbcLiteral, AbcRecord, Asm, MethodRef, VERSION_13_0_1_0,
};
use common::{synthetic, synthetic_builder, walk, BIG, FOREIGN, RECORD_A, RECORD_B};

#[test]
fn full_walk_of_the_synthetic_file() {
    let (file, _) = synthetic();
    let abc = Abc::parse(&file.bytes).unwrap();
    let stats = walk(&abc, true).unwrap();
    assert_eq!((stats.classes, stats.foreign_classes, stats.pseudo_records), (3, 1, 1));
    assert_eq!((stats.fields, stats.methods, stats.code_bytes), (5, 5, 16 + 6 + 3 * 12));
    assert_eq!((stats.try_blocks, stats.catch_blocks, stats.annotations), (1, 2, 2));
    assert_eq!((stats.debug_infos, stats.line_rows), (1, 2));
    assert_eq!((stats.module_records, stats.module_entries, stats.scope_name_tables), (1, 5, 1));
    assert_eq!((stats.literal_arrays, stats.literals), (2, 5));
    assert_eq!(stats.methods_per_region, [2, 3]);
    assert_eq!(stats.region_hint_mismatches, 2);
}

#[test]
fn header_and_class_index() {
    let (file, _) = synthetic();
    let (data, at) = (&file.bytes, &file.layout);
    let (class_a, class_b, foreign_class) = (at.class(RECORD_A), at.class(RECORD_B), at.class(FOREIGN));
    let abc = Abc::parse(data).unwrap();
    let header = abc.header();
    assert_eq!(header.version, Version([12, 0, 6, 0]));
    assert_eq!(header.file_size as usize, data.len());
    assert_eq!((header.foreign_off, header.class_idx_off), (foreign_class, at.class_index_off));
    assert_eq!((header.num_classes, header.num_indexes), (3, 2));
    assert!(header.has_literal_array_index());
    assert_eq!(abc.compute_checksum(), header.checksum);

    // Sorted by descriptor: `L&…` < `L_…` < `Lc…`.
    assert_eq!(abc.class_index().unwrap().iter().collect::<Vec<_>>(), [class_a, foreign_class, class_b]);
    let names: Vec<String> = abc.classes().unwrap().map(|entry| String::from_utf8_lossy(entry.unwrap().name()).into_owned()).collect();
    assert_eq!(names, [RECORD_A, "_ESTypeAnnotation", RECORD_B]);

    let found = abc.find_record(RECORD_B.as_bytes()).unwrap().unwrap();
    assert_eq!(found.offset(), class_b);
    assert!(matches!(abc.find_class(b"L_ESTypeAnnotation;").unwrap(), Some(ClassEntry::Foreign(class)) if class.off == foreign_class));
    assert!(abc.find_record(b"missing").unwrap().is_none());
    assert!(abc.find_class(RECORD_B.as_bytes()).unwrap().is_none(), "find_class takes the full descriptor");
    assert!(matches!(abc.class(foreign_class), Err(AbcError::Malformed { .. })));
    assert!(RecordName::parse("_ESTypeAnnotation").is_pseudo());
}

#[test]
fn class_lookup_survives_an_unsorted_index() {
    // The class index in reverse order: binary search now misses, the scan must not.
    let file = synthetic_builder().0.unsorted_class_index().build();
    let at = &file.layout;
    let abc = Abc::parse(&file.bytes).unwrap();
    assert_eq!(abc.class_index().unwrap().iter().collect::<Vec<_>>(), [at.class(RECORD_B), at.class(FOREIGN), at.class(RECORD_A)]);
    for name in [RECORD_A, RECORD_B, FOREIGN] {
        assert_eq!(abc.find_record(name.as_bytes()).unwrap().map(|entry| entry.offset()), Some(at.class(name)), "{name}");
    }
    assert!(abc.find_record(b"missing").unwrap().is_none());
    assert!(!abc.classes_are_sorted());

    // A sorted index says so, and a file known to be sorted answers alike
    // without the scan.
    let sorted = synthetic_builder().0.build();
    let abc = Abc::parse(&sorted.bytes).unwrap();
    assert!(abc.classes_are_sorted());
    let known = abc.with_sorted_classes(true);
    for name in [RECORD_A, RECORD_B, FOREIGN] {
        assert_eq!(
            known.find_record(name.as_bytes()).unwrap().map(|e| e.offset()),
            abc.find_record(name.as_bytes()).unwrap().map(|e| e.offset())
        );
    }
    assert!(known.find_record(b"missing").unwrap().is_none());
}

#[test]
fn record_fields_and_members() {
    let (file, _) = synthetic();
    let at = &file.layout;
    let abc = Abc::parse(&file.bytes).unwrap();
    let class = abc.class(at.class(RECORD_A)).unwrap();
    assert_eq!(class.name(), RECORD_A.as_bytes());
    assert_eq!(class.descriptor().to_str(), format!("L{RECORD_A};"));
    assert_eq!((class.num_fields, class.num_methods, class.access_flags), (5, 2, 1));
    assert_eq!(class.source_lang().unwrap(), Some(SourceLang::ARKTS));
    assert_eq!(class.source_file().unwrap(), None);
    assert_eq!(class.package_name().unwrap(), Some(&b"entry"[..]));

    let fields: Vec<_> = class.fields().unwrap().map(Result::unwrap).collect();
    let described: Vec<_> = fields.iter().map(|f| (f.name().unwrap().to_str().into_owned(), f.field_type().unwrap(), f.value())).collect();
    assert_eq!(
        described,
        [
            ("moduleRecordIdx".to_owned(), FieldType::U32, Some(FieldValue::Raw(at.module_record(RECORD_A)))),
            ("scopeNames".to_owned(), FieldType::U32, Some(FieldValue::Raw(at.scope_names(RECORD_A)))),
            ("isCommonjs".to_owned(), FieldType::U1, Some(FieldValue::Int(0))),
            ("pkgName@entry".to_owned(), FieldType::U1, Some(FieldValue::Int(0))),
            ("big".to_owned(), FieldType::I64, Some(FieldValue::Raw(fields[4].raw_value().unwrap()))),
        ]
    );
    assert_eq!(fields[4].wide_value().unwrap(), Some(BIG));
    assert_eq!(
        fields.iter().map(|f| f.offset()).collect::<Vec<_>>(),
        described.iter().map(|(name, ..)| at.field(RECORD_A, name)).collect::<Vec<_>>()
    );
    assert!(fields[4].is_static() && !fields[0].is_static());
    assert_eq!(fields[4].tags().count(), 2);
    assert_eq!(abc.field(fields[2].offset()).unwrap().name_off, fields[2].name_off);
    assert!(class.field(b"isCommonjs").unwrap().is_some() && class.field(b"nope").unwrap().is_none());

    assert_eq!(class.scope_name(0).unwrap().unwrap().to_str(), "Index");
    assert_eq!(class.scope_name(1).unwrap(), None);
    assert_eq!(class.restore_function_name("#~@0>#build"), "Index.build");
    assert_eq!(class.restore_function_name("#~@1>#build"), "@1.build");

    let methods: Vec<_> = class.methods().unwrap().map(Result::unwrap).collect();
    assert_eq!(
        methods.iter().map(|m| m.offset()).collect::<Vec<_>>(),
        [at.method(RECORD_A, "func_main_0"), at.method(RECORD_A, "#~@0>#build")]
    );
    assert_eq!(methods[0].name().unwrap().to_str(), "func_main_0");
    assert_eq!(methods[0].function_kind(), FunctionKind(FunctionKind::FUNCTION));
    assert_eq!(methods[1].function_kind().base(), FunctionKind::NONE);
    assert_eq!(methods[0].source_lang(), Some(SourceLang::ARKTS));
    assert_eq!((methods[0].code_off(), methods[1].debug_info_off()), (Some(at.code(RECORD_A, "func_main_0")), None));
    assert_eq!((methods[0].debug_info_off(), methods[1].source_lang()), (Some(at.debug_info(RECORD_A, "func_main_0")), None));
    assert!(methods[0].is_static() && !methods[0].is_foreign());
    assert_eq!(methods[0].proto_off().unwrap(), None);
    assert_eq!(methods[0].tags().count(), 4);

    let other = abc.class(at.class(RECORD_B)).unwrap();
    assert_eq!((other.module_record().unwrap().is_none(), other.scope_names().unwrap().is_none()), (true, true));
    assert_eq!(other.package_name().unwrap(), None);
}

#[test]
fn code_and_try_blocks() {
    let (file, _) = synthetic();
    let (data, at) = (&file.bytes, &file.layout);
    let abc = Abc::parse(data).unwrap();
    let code = abc.code(at.code(RECORD_A, "func_main_0")).unwrap();
    assert_eq!((code.num_vregs, code.num_args, code.tries_size), (1, 3, 0));
    // lda.str 0; lda.str 1; createarraywithbuffer 0, 2; definefunc 0, 3, 0; return
    assert_eq!(code.instructions(), [0x3e, 0, 0, 0x3e, 1, 0, 0x06, 0, 2, 0, 0x33, 0, 3, 0, 0, 0x64]);
    assert_eq!(&data[code.instructions_off() as usize..][..16], code.instructions());
    assert_eq!(code.try_blocks().count(), 0);

    let code = abc.method(at.method(RECORD_A, "#~@0>#build")).unwrap().code().unwrap().unwrap();
    assert_eq!(code.offset(), at.code(RECORD_A, "#~@0>#build"));
    // lda.str 1; ldundefined; ldnull; return
    assert_eq!(code.instructions(), [0x3e, 1, 0, 0x00, 0x01, 0x64]);
    assert_eq!((code.num_vregs, code.instructions().len(), code.tries_size), (2, 6, 1));
    let blocks: Vec<_> = code.try_blocks().map(Result::unwrap).collect();
    assert_eq!((blocks.len(), blocks[0].start_pc, blocks[0].length, blocks[0].num_catches), (1, 0, 3, 2));
    assert_eq!(
        blocks[0].catch_blocks().collect::<Vec<_>>(),
        [CatchBlock { type_idx: Some(0), handler_pc: 3, code_size: 3 }, CatchBlock { type_idx: None, handler_pc: 4, code_size: 2 }]
    );
}

#[test]
fn literal_arrays_by_index_and_offset() {
    let (file, literal_array) = synthetic();
    let at = &file.layout;
    let abc = Abc::parse(&file.bytes).unwrap();
    // The index lists the module record too; the writer puts what record fields own first.
    let index = abc.literal_array_index().unwrap().unwrap();
    assert_eq!(index.iter().collect::<Vec<_>>(), [at.module_record(RECORD_A), at.scope_names(RECORD_A), literal_array]);
    assert_eq!(abc.header().literalarray_idx_off, at.literal_array_index_off.unwrap());

    let array = abc.literal_array(index.get(2).unwrap()).unwrap();
    assert_eq!((array.num, array.len(), array.offset()), (8, 4, literal_array));
    let hello = at.string("hello");
    let items: Vec<Literal> = array.iter().map(Result::unwrap).collect();
    assert_eq!(items, [Literal::Integer(1_919_810), Literal::String(hello), Literal::Bool(true), Literal::Double(1.5)]);
    assert_eq!(items.iter().map(Literal::tag).collect::<Vec<_>>(), [0x02, 0x05, 0x01, 0x04]);
    assert_eq!((items[1].string_off(), items[0].string_off(), items[1].method_off()), (Some(hello), None, None));
    assert_eq!(array.get(2).unwrap(), Some(Literal::Bool(true)));
    assert_eq!(array.get(4).unwrap(), None);
    // The iterator ends exactly where the items end: integer, string, bool, double.
    let mut items = array.iter();
    items.by_ref().for_each(drop);
    assert_eq!(items.offset(), literal_array + 4 + 5 + 5 + 2 + 9);
    // The scope names end where the next item (the declared array) starts.
    let mut names = abc.literal_array(at.scope_names(RECORD_A)).unwrap().iter();
    names.by_ref().for_each(drop);
    assert_eq!(names.offset(), literal_array);

    // Files newer than 12.0.6.0 have no index; arrays stay reachable by offset.
    let newer = synthetic_builder().0.version(VERSION_13_0_1_0).build();
    let abc = Abc::parse(&newer.bytes).unwrap();
    assert_eq!((abc.header().num_literalarrays, abc.header().literalarray_idx_off), (u32::MAX, u32::MAX));
    assert!(abc.literal_array_index().unwrap().is_none());
    let scope_names = abc.literal_array(newer.layout.scope_names(RECORD_A)).unwrap();
    assert_eq!(scope_names.get(0).unwrap().and_then(|l| l.string_off()).map(|o| abc.string(o).unwrap().bytes), Some(&b"Index"[..]));
}

#[test]
fn literal_value_kinds() {
    // Every tag once, then a typed array.
    let (mut builder, nested) = synthetic_builder();
    let method = || MethodRef::new(RECORD_A, "#~@0>#build");
    let array = builder.literal_array([
        AbcLiteral::TagValue(7),
        AbcLiteral::Integer(-1),
        AbcLiteral::Float(2.5),
        AbcLiteral::Method(method()),
        AbcLiteral::GeneratorMethod(method()),
        AbcLiteral::AsyncGeneratorMethod(method()),
        AbcLiteral::Getter(method()),
        AbcLiteral::Setter(method()),
        AbcLiteral::LiteralBufferIndex(0x117),
        AbcLiteral::LiteralArray(nested),
        AbcLiteral::EtsImplements("world".to_owned()),
        AbcLiteral::Accessor(1),
        AbcLiteral::MethodAffiliate(3),
        AbcLiteral::BuiltinTypeIndex(2),
        AbcLiteral::Null,
        AbcLiteral::TypedArray { tag: 0x0f, data: vec![1, 0, 0, 0, 2, 0, 0, 0] },
    ]);
    let file = builder.build();
    let at = &file.layout;
    let (off, build, world) = (at.literal_array(array), at.method(RECORD_A, "#~@0>#build"), at.string("world"));
    let array = Abc::parse(&file.bytes).unwrap().literal_array(off).unwrap();
    assert_eq!((array.num, array.len()), (32, 16));
    let items: Vec<Literal> = array.iter().map(Result::unwrap).collect();
    assert_eq!(
        items,
        [
            Literal::TagValue(7),
            Literal::Integer(-1),
            Literal::Float(2.5),
            Literal::Method(build),
            Literal::GeneratorMethod(build),
            Literal::AsyncGeneratorMethod(build),
            Literal::Getter(build),
            Literal::Setter(build),
            Literal::LiteralBufferIndex(0x117),
            Literal::LiteralArray(at.literal_array(nested)),
            Literal::EtsImplements(world),
            Literal::Accessor(1),
            Literal::MethodAffiliate(3),
            Literal::BuiltinTypeIndex(2),
            Literal::Null(0),
            Literal::TypedArray { tag: 0x0f, data_off: off + 4 + 2 + 5 + 5 + 8 * 5 + 2 + 3 + 2 + 2 + 1 },
        ]
    );
    assert_eq!(items.iter().filter_map(Literal::method_off).count(), 5);
    assert_eq!(items[9].literal_array_off(), Some(at.literal_array(nested)));

    // An unknown tag is an error, not a guess at its size.
    let mut bad = file.bytes.clone();
    bad[off as usize + 4] = 0x55;
    let array = Abc::parse(&bad).unwrap().literal_array(off).unwrap();
    let mut items = array.iter();
    assert!(matches!(items.next(), Some(Err(AbcError::Malformed { what: "literal", .. }))));
    assert!(items.next().is_none());
}

#[test]
fn module_record_sections() {
    let (file, _) = synthetic();
    let at = &file.layout;
    let abc = Abc::parse(&file.bytes).unwrap();
    let module = abc.class(at.class(RECORD_A)).unwrap().module_record().unwrap().unwrap();
    assert_eq!(module.offset(), at.module_record(RECORD_A));
    // Six counts, one request, and 3 + 2 + 2 + 3 + 1 values in the five sections.
    assert_eq!(module.num_literals, 18);
    let request = |idx: u16| abc.string(module.request(idx).unwrap()).unwrap().to_str();
    assert_eq!((module.requests.len(), request(0)), (1, "@ohos:hilog".into()));
    assert_eq!(module.request(1), None);

    let text = |off: u32| abc.string(off).unwrap().to_str();
    let RegularImport { local_name_off, import_name_off, module_request_idx } = module.regular_imports.get(0).unwrap();
    assert_eq!((text(local_name_off), text(import_name_off), module_request_idx), ("hilog".into(), "default".into(), 0));
    assert_eq!(module.regular_imports.get(1), None);
    assert_eq!(module.namespace_imports.iter().map(|i| text(i.local_name_off)).collect::<Vec<_>>(), ["hilog"]);
    let LocalExport { local_name_off, export_name_off } = module.local_exports.get(0).unwrap();
    assert_eq!((text(local_name_off), text(export_name_off)), ("Index".into(), "default".into()));
    assert_eq!((module.indirect_exports.len(), module.star_exports.len()), (1, 1));
    assert_eq!(module.star_exports.get(0).unwrap().module_request_idx, 0);
    assert!(!module.local_exports.is_empty());
}

#[test]
fn debug_info_and_line_program() {
    let (file, _) = synthetic();
    let (data, at) = (&file.bytes, &file.layout);
    let method_main = at.method(RECORD_A, "func_main_0");
    let abc = Abc::parse(data).unwrap();
    let debug = abc.method(method_main).unwrap().debug_info().unwrap().unwrap();
    assert_eq!((debug.line_start, debug.num_params, debug.line_program_idx), (10, 1, 0));
    assert_eq!(abc.header().lnp_idx_off, at.line_program_index_off);
    assert_eq!(debug.params().map(|off| abc.string(off).unwrap().to_str().into_owned()).collect::<Vec<_>>(), ["arg0"]);
    assert_eq!(debug.constant_pool(), [2, 0x7f, 7]);
    let ops: Vec<LineOp> = debug.line_ops().unwrap().map(Result::unwrap).collect();
    assert_eq!(
        ops,
        [
            LineOp::AdvancePc(2),
            LineOp::AdvanceLine(-1),
            LineOp::Special { pc_delta: 1, line_delta: 1 },
            LineOp::SetColumn(7),
            LineOp::Special { pc_delta: 0, line_delta: 0 },
        ]
    );
    let rows: Vec<LineRow> = debug.line_rows().unwrap().map(Result::unwrap).collect();
    assert_eq!(rows, [LineRow { pc: 3, line: 10, column: 0 }, LineRow { pc: 3, line: 10, column: 7 }]);
    assert_eq!(debug.first_line().unwrap(), Some(10));

    // A program that asks for more constants than the pool holds fails
    // instead of reading whatever follows the pool.
    let mut short = data.clone();
    let program = debug.line_program_off().unwrap() as usize;
    short[program..program + 6].copy_from_slice(&[0x01, 0x02, 0x0b, 0x0b, 0x0b, 0x00]);
    let abc = Abc::parse(&short).unwrap();
    let debug = abc.method(method_main).unwrap().debug_info().unwrap().unwrap();
    let ops: Vec<_> = debug.line_ops().unwrap().collect();
    assert_eq!(ops.len(), 4);
    assert!(matches!(ops[3], Err(AbcError::Truncated { .. })));
    assert!(debug.line_rows().unwrap().any(|row| row.is_err()));
}

#[test]
fn local_variables_of_the_line_program() {
    let local = |reg: i32, name: &str| AbcLineOp::StartLocal { reg, name: name.to_owned(), ty: "any".to_owned() };
    let mut code = Asm::new();
    code.op("ldundefined", []).op("sta", [0.into()]).op("lda", [0.into()]).op("return", []);
    let debug = AbcDebugInfo {
        line_start: 1,
        params: vec![Some("first".to_owned()), None],
        program: vec![
            // Ended where it starts, at 0.
            local(2, "early"),
            AbcLineOp::EndLocal(2),
            AbcLineOp::Special { pc_delta: 1, line_delta: 1 },
            local(0, "count"),
            AbcLineOp::StartLocalExtended { reg: -1, name: "result".to_owned(), ty: "any".to_owned(), signature: "Lstring;".to_owned() },
            AbcLineOp::AdvancePc(2),
            AbcLineOp::EndLocal(0),
            // No variable in the register: nothing to end or to restart.
            AbcLineOp::EndLocal(7),
            AbcLineOp::RestartLocal(7),
            // The register changes hands, and the first holder comes back.
            local(0, "other"),
            AbcLineOp::Special { pc_delta: 2, line_delta: 0 },
            AbcLineOp::EndLocal(0),
            AbcLineOp::RestartLocal(0),
        ],
    };
    let mut builder = AbcBuilder::new();
    builder.record(
        AbcRecord::new("&entry/src/main/ets/Locals&").function(AbcFunction::new("#*#locals", AbcCode::new(3, 5, code)).debug(debug)),
    );
    let file = builder.build();
    let abc = Abc::parse(&file.bytes).unwrap();
    let debug = abc.method(file.layout.method("&entry/src/main/ets/Locals&", "#*#locals")).unwrap().debug_info().unwrap().unwrap();

    let text = |off: u32| abc.string(off).unwrap().to_str().into_owned();
    let locals: Vec<_> = debug
        .locals()
        .unwrap()
        .iter()
        .map(|local| (local.reg, text(local.name_off), local.signature_off.map(text), local.start_pc, local.end_pc))
        .collect();
    assert_eq!(
        locals,
        [
            (2, "early".to_owned(), None, 0, Some(0)),
            (0, "count".to_owned(), None, 1, Some(3)),
            (-1, "result".to_owned(), Some("Lstring;".to_owned()), 1, None),
            (0, "other".to_owned(), None, 3, Some(5)),
            (0, "other".to_owned(), None, 5, None),
        ]
    );
    assert!(debug.locals().unwrap().iter().all(|local| text(local.type_off) == "any"));
    assert_eq!(debug.params().collect::<Vec<_>>().len(), 2);

    // A program that runs out of constants is an error, not a partial table:
    // thirteen operations taking one each, where the pool holds ten.
    let mut starved = file.bytes.clone();
    let program = debug.line_program_off().unwrap() as usize;
    starved[program..program + 13].fill(0x0b);
    let abc = Abc::parse(&starved).unwrap();
    let debug = abc.method(file.layout.method("&entry/src/main/ets/Locals&", "#*#locals")).unwrap().debug_info().unwrap().unwrap();
    assert!(matches!(debug.locals(), Err(AbcError::Truncated { .. })));
}

#[test]
fn ids_resolve_through_the_region_of_the_method() {
    let (file, literal_array) = synthetic();
    let at = &file.layout;
    let (hello, world) = (at.string("hello"), at.string("world"));
    let (method_main, method_build) = (at.method(RECORD_A, "func_main_0"), at.method(RECORD_A, "#~@0>#build"));
    let methods_b = ["#*#helper", "#*#helper^1", "#*#"].map(|name| at.method(RECORD_B, name));
    let abc = Abc::parse(&file.bytes).unwrap();
    let regions = abc.regions().unwrap();
    assert_eq!(regions.len(), 2);
    let (r0, r1) = (regions.get(0).unwrap(), regions.get(1).unwrap());
    assert_eq!(r0.header().end, r1.header().start);
    // Like the official writer's: the first region starts at the foreign classes, the last ends with the file.
    assert_eq!((r0.header().start, r1.header().start, r1.header().end), (at.class(FOREIGN), at.class(RECORD_B), abc.header().file_size));
    // The header tables come before the first region.
    assert!(regions.get(2).is_none() && regions.containing(at.class_index_off).is_none());

    // The same 16-bit id means different things in the two regions.
    let main = abc.method(method_main).unwrap();
    let helper = abc.method(methods_b[0]).unwrap();
    assert_eq!((main.region().unwrap().index(), helper.region().unwrap().index()), (0, 1));
    assert_eq!((main.resolve(0).unwrap(), helper.resolve(0).unwrap()), (hello, world));
    assert_eq!((main.resolve(2).unwrap(), helper.resolve(2).unwrap()), (literal_array, hello));
    assert_eq!(main.resolve(3).unwrap(), method_build);
    assert_eq!(abc.resolve_entity(method_build, 1).unwrap(), world);
    assert_eq!(helper.resolve(3), Err(AbcError::IndexOutOfRange { what: "region method index", index: 3, size: 3 }));
    assert_eq!(abc.resolve_entity(at.class_index_off, 0), Err(AbcError::NoRegion { offset: at.class_index_off }));

    // Reverse lookup: per region, the id of an offset.
    assert_eq!((r0.entity_idx(hello).unwrap(), r1.entity_idx(hello).unwrap()), (Some(0), Some(2)));
    assert_eq!((r0.entity_idx(literal_array).unwrap(), r1.entity_idx(literal_array).unwrap()), (Some(2), None));
    assert_eq!((r0.entity_idx(methods_b[0]).unwrap(), r1.entity_idx(methods_b[0]).unwrap()), (None, Some(1)));
    assert_eq!((at.entity_id(RECORD_A, "func_main_0", world), at.entity_id(RECORD_B, "#*#", world)), (Some(1), Some(0)));

    // The region number in the access flags is only a hint: out of range
    // (7) or pointing at a region that does not contain the method (0), the
    // offset decides.
    for (off, hint) in methods_b.into_iter().zip([1, 7, 0]) {
        let method = abc.method(off).unwrap();
        assert_eq!(method.region_hint(), hint);
        assert_eq!(method.region().unwrap().index(), 1, "hint {hint}");
        assert_eq!(method.resolve(0).unwrap(), world, "hint {hint}");
        assert_eq!(method.class_off().unwrap(), at.class(RECORD_B));
    }
}

#[test]
fn encrypted_body_is_recognized() {
    let (plain, _) = synthetic();
    // Plain header, scrambled body.
    let data = synthetic_builder().0.encrypted().build().bytes;
    assert_eq!((data.len(), &data[..asc_abc::HEADER_SIZE]), (plain.bytes.len(), &plain.bytes[..asc_abc::HEADER_SIZE]));
    let stored = u32::from_le_bytes(plain.bytes[8..12].try_into().unwrap());
    assert_eq!(stored, adler32(&plain.bytes[12..]));
    assert_eq!(Abc::parse(&data).unwrap_err(), AbcError::Encrypted { stored, computed: adler32(&data[12..]) });
    // The lenient open still works and reports ordinary errors.
    let abc = Abc::parse_lenient(&data).unwrap();
    assert_eq!(abc.header().num_classes, 3);
    assert!(walk(&abc, false).is_err());

    // Damage with a matching checksum is damage, not encryption.
    let mut damaged = plain.bytes.clone();
    damaged[plain.layout.class_index_off as usize..][..4].copy_from_slice(&u32::MAX.to_le_bytes());
    seal(&mut damaged);
    assert_eq!(Abc::parse(&damaged).unwrap_err(), AbcError::BadOffset { what: "class", offset: u32::MAX });

    // A stale checksum alone is not an error: tools patch files without fixing it.
    let stale = synthetic_builder().0.stale_checksum().build().bytes;
    let abc = Abc::parse(&stale).unwrap();
    assert_ne!(abc.header().checksum, abc.compute_checksum());
    assert_eq!(&stale[12..], &plain.bytes[12..]);
    assert!(walk(&abc, true).is_ok());
}

#[test]
fn malformed_headers_and_tables() {
    let (file, _) = synthetic();
    let (data, at) = (&file.bytes, &file.layout);
    let class_a = at.class(RECORD_A);
    let patched = |at: usize, value: u32| {
        let mut data = data.clone();
        data[at..at + 4].copy_from_slice(&value.to_le_bytes());
        data
    };
    // Counts and offsets that point far outside the file.
    for (field, value) in [
        (28, u32::MAX),
        (28, 0x4000_0000),
        (32, u32::MAX - 2),
        (36, u32::MAX),
        (40, 0xffff_fff0),
        (44, 0x7fff_ffff),
        (52, u32::MAX),
        (56, u32::MAX - 39),
    ] {
        let data = patched(field, value);
        assert!(Abc::parse(&data).is_err(), "header field at {field} = {value:#x}");
        let abc = Abc::parse_lenient(&data).unwrap();
        // Whatever happens, it is an answer, not a panic.
        let _ = walk(&abc, false);
        let _ = abc.find_record(RECORD_A.as_bytes());
    }
    // A region whose table sizes are absurd.
    for word in [2, 4, 6, 8] {
        let data = patched(at.region_headers_off as usize + 4 * word, 0x3fff_ffff);
        assert!(Abc::parse(&data).is_err(), "region word {word}");
        let _ = walk(&Abc::parse_lenient(&data).unwrap(), false);
    }
    // Entities at offsets inside the header or past the end.
    let abc = Abc::parse(data).unwrap();
    for off in [0, 1, 59, 60, data.len() as u32, u32::MAX] {
        assert!(matches!(abc.string(off), Err(AbcError::BadOffset { .. })), "{off}");
        assert!(abc.class_entry(off).is_err() && abc.method(off).is_err() && abc.field(off).is_err());
        assert!(abc.code(off).is_err() && abc.literal_array(off).is_err() && abc.module_record(off).is_err());
        assert!(abc.debug_info(off).is_err() && abc.annotation(off).is_err());
    }
    // Huge member counts end at the first member that does not parse.
    let mut huge = data.clone();
    let class = abc.class(class_a).unwrap();
    let counts = class_a as usize + class.descriptor().bytes.len() + 2 + 4 + 1;
    assert_eq!(&huge[counts..counts + 2], [5, 2]);
    huge[counts] = 0x7f;
    let class = Abc::parse(&huge).unwrap().class(class_a).unwrap();
    assert_eq!(class.num_fields, 127);
    let fields: Vec<_> = class.fields().unwrap().collect();
    assert!(fields.len() <= 127 && fields.last().unwrap().is_err());
    assert!(class.methods().is_err());
}

#[test]
fn truncation_never_panics() {
    let (file, _) = synthetic();
    let (mut builder, _) = synthetic_builder();
    for len in 0..file.bytes.len() {
        let cut = &builder.truncated(len).build().bytes[..];
        assert_eq!(cut, &file.bytes[..len]);
        match Abc::parse_lenient(cut) {
            Ok(abc) => {
                assert!(len >= asc_abc::HEADER_SIZE);
                let _ = walk(&abc, false);
                let _ = abc.check_layout();
            }
            Err(err) => assert_eq!(err, AbcError::TooSmall(len)),
        }
    }
}

#[test]
fn byte_flips_never_panic() {
    let data = synthetic().0.bytes;
    let mut survivors = 0;
    for pos in 8..data.len() {
        for flip in [0x01, 0x80, 0xff, 0x7f] {
            let mut mutated = data.clone();
            mutated[pos] ^= flip;
            let Ok(abc) = Abc::parse_lenient(&mutated) else { continue };
            let _ = abc.check_layout();
            survivors += usize::from(walk(&abc, false).is_ok());
        }
    }
    // Most single-byte changes leave a file that still walks (a different
    // name, a different constant); the point is that none of them panics.
    assert!(survivors > 0);
}
