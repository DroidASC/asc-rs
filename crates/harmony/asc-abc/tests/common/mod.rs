//! Shared by the integration tests (and by `asc-fixture`'s own): a walk
//! over everything a file contains, the real-sample loader and a synthetic
//! file built with `asc-fixture`.

// Each test binary uses its own part of this module.
#![allow(dead_code)]

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use asc_abc::{
    Abc, AbcError, ClassEntry, ClassTag, FieldTag, FieldValue, FunctionKind, FunctionName, Literal, LiteralArray, MethodTag, RecordName,
    SourceLang,
};
use asc_fixture::abc::{
    AbcAnnotation, AbcBuilder, AbcCode, AbcDebugInfo, AbcField, AbcFieldValue, AbcFile, AbcFunction, AbcLineOp, AbcLiteral, AbcModule,
    AbcRecord, AbcType, Asm, Catch, LiteralArrayId, Op, ACC_STATIC,
};

/// What a full walk saw.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Stats {
    pub classes: u32,
    pub foreign_classes: u32,
    pub pseudo_records: u32,
    pub fields: u64,
    pub methods: u64,
    pub code_bytes: u64,
    pub try_blocks: u64,
    pub catch_blocks: u64,
    pub annotations: u64,
    pub debug_infos: u64,
    pub locals: u64,
    pub line_rows: u64,
    pub module_records: u64,
    pub module_entries: u64,
    /// Module request phase tables (`moduleRequestPhaseIdx`).
    pub phase_tables: u64,
    pub scope_name_tables: u64,
    /// Literal arrays listed in the header index (module records and phase tables excluded).
    pub literal_arrays: u64,
    pub literals: u64,
    pub scoped_names: u64,
    /// Methods whose `access_flags >> 16` is not the region containing them.
    pub region_hint_mismatches: u64,
    pub methods_per_region: Vec<u64>,
}

/// Touch every structure reachable in `abc`. Returns the first error; never
/// panics on malformed input. With `strict`, also asserts the invariants a
/// compiler-produced file satisfies.
pub fn walk(abc: &Abc<'_>, strict: bool) -> Result<Stats, AbcError> {
    let mut stats = Stats::default();
    let len = abc.bytes().len();
    let in_file = |off: u32| (off as usize) < len;

    let regions = abc.regions()?;
    stats.methods_per_region = vec![0; regions.len() as usize];
    for region in regions.iter() {
        region.class_table()?;
        region.field_table()?;
        region.proto_table()?;
        let entities = region.entity_table()?;
        if strict {
            assert!(region.header().start <= region.header().end);
            for (idx, off) in entities.iter().enumerate() {
                assert!(in_file(off), "region {} entity {idx} at {off:#x}", region.index());
                assert_eq!(region.entity_offset(idx as u16)?, off);
            }
        }
    }

    // Listed in the header literal array index without being literal arrays.
    let mut not_literal_arrays = HashSet::new();
    let mut previous: &[u8] = b"";
    for entry in abc.classes()? {
        let entry = entry?;
        stats.classes += 1;
        let descriptor = entry.descriptor().to_str();
        if strict {
            // The writer sorts the class index by name; byte order is enough for these files.
            assert!(previous < entry.name(), "class index out of order at {descriptor}");
            previous = entry.name();
        }
        let name = String::from_utf8_lossy(entry.name()).into_owned();
        let record_name = RecordName::parse(&name);
        stats.pseudo_records += u32::from(record_name.is_pseudo());
        if strict {
            // A record, or an array type, which is declared and never defined.
            let is_array = descriptor.starts_with('[') && matches!(entry, ClassEntry::Foreign(_));
            assert!(is_array || (descriptor.starts_with('L') && descriptor.ends_with(';')), "{descriptor}");
            assert_eq!(abc.find_class(entry.descriptor().bytes)?.map(|found| found.offset()), Some(entry.offset()));
            if !is_array {
                assert_eq!(abc.find_record(entry.name())?.map(|found| found.offset()), Some(entry.offset()));
            }
        }
        let ClassEntry::Local(class) = entry else {
            stats.foreign_classes += 1;
            continue;
        };
        class.source_lang()?;
        if let Some(file) = class.source_file()? {
            file.to_str();
        }
        for tag in class.tags() {
            match tag? {
                ClassTag::Annotation(off)
                | ClassTag::RuntimeAnnotation(off)
                | ClassTag::TypeAnnotation(off)
                | ClassTag::RuntimeTypeAnnotation(off) => {
                    stats.annotations += walk_annotation(abc, off)?;
                }
                ClassTag::Interfaces(list) => drop(list.iter().count()),
                ClassTag::SourceLang(_) | ClassTag::SourceFile(_) => {}
            }
        }

        let mut fields = class.fields()?;
        for field in fields.by_ref() {
            let field = field?;
            stats.fields += 1;
            field.name()?.to_str();
            let ty = field.field_type()?;
            if ty.is_wide() {
                field.wide_value()?;
            }
            if strict && matches!(field.value(), Some(FieldValue::Raw(_))) {
                assert!(!matches!(ty, asc_abc::FieldType::U1 | asc_abc::FieldType::U8), "{ty:?}");
            }
            for tag in field.tags() {
                match tag? {
                    FieldTag::Annotation(off)
                    | FieldTag::RuntimeAnnotation(off)
                    | FieldTag::TypeAnnotation(off)
                    | FieldTag::RuntimeTypeAnnotation(off) => stats.annotations += walk_annotation(abc, off)?,
                    FieldTag::IntValue(_) | FieldTag::Value(_) => {}
                }
            }
        }
        class.package_name()?;

        if let Some(module) = class.module_record()? {
            stats.module_records += 1;
            not_literal_arrays.insert(module.offset());
            for request in module.requests.iter() {
                abc.string(request)?.to_str();
            }
            let request_ok = |idx: u16| module.request(idx).is_some();
            for import in module.regular_imports.iter() {
                abc.string(import.local_name_off)?;
                abc.string(import.import_name_off)?;
                assert!(!strict || request_ok(import.module_request_idx));
                stats.module_entries += 1;
            }
            for import in module.namespace_imports.iter() {
                abc.string(import.local_name_off)?;
                assert!(!strict || request_ok(import.module_request_idx));
                stats.module_entries += 1;
            }
            for export in module.local_exports.iter() {
                abc.string(export.local_name_off)?;
                abc.string(export.export_name_off)?;
                stats.module_entries += 1;
            }
            for export in module.indirect_exports.iter() {
                abc.string(export.export_name_off)?;
                abc.string(export.import_name_off)?;
                assert!(!strict || request_ok(export.module_request_idx));
                stats.module_entries += 1;
            }
            for export in module.star_exports.iter() {
                assert!(!strict || request_ok(export.module_request_idx));
                stats.module_entries += 1;
            }
            if strict {
                assert_eq!(module.regular_imports.len(), module.regular_imports.iter().count());
                assert_eq!(module.regular_imports.get(0), module.regular_imports.iter().next());
            }
        }
        if let Some(phases) = class.module_request_phases()? {
            stats.phase_tables += 1;
            not_literal_arrays.extend(class.field(asc_abc::record_field::MODULE_REQUEST_PHASE_IDX)?.and_then(|field| field.raw_value()));
            if strict {
                // One phase per module request of the record.
                assert_eq!(Some(phases.len()), class.module_record()?.map(|module| module.requests.len() as usize));
            }
        }
        let scope_names = class.scope_names()?;
        if let Some(names) = &scope_names {
            stats.scope_name_tables += 1;
            for literal in names {
                let literal = literal?;
                assert!(!strict || literal.string_off().is_some(), "{literal:?}");
            }
        }

        for method in fields.into_methods()? {
            let method = method?;
            stats.methods += 1;
            let raw = method.name()?.to_str();
            let parsed = FunctionName::parse(&raw);
            let restored = class.restore_function_name(&raw);
            if parsed.is_scoped() {
                stats.scoped_names += 1;
                if strict {
                    assert!(!restored.contains('@') && !restored.contains('#'), "{raw} -> {restored}");
                }
            }
            let region = method.region()?;
            stats.methods_per_region[region.index() as usize] += 1;
            stats.region_hint_mismatches += u64::from(region.index() != method.region_hint());
            if strict {
                assert_eq!(method.class_off()?, class.offset(), "{raw}");
                assert_eq!(abc.region_of(method.offset())?.index(), region.index());
                assert_eq!(abc.method(method.offset())?.name_off, method.name_off);
            }
            for tag in method.tags() {
                match tag? {
                    MethodTag::Annotation(off)
                    | MethodTag::RuntimeAnnotation(off)
                    | MethodTag::TypeAnnotation(off)
                    | MethodTag::RuntimeTypeAnnotation(off) => stats.annotations += walk_annotation(abc, off)?,
                    MethodTag::Code(_)
                    | MethodTag::SourceLang(_)
                    | MethodTag::DebugInfo(_)
                    | MethodTag::RuntimeParamAnnotation(_)
                    | MethodTag::ParamAnnotation(_) => {}
                }
            }
            if let Some(code) = method.code()? {
                let size = code.instructions().len();
                stats.code_bytes += size as u64;
                if strict {
                    assert!(code.instructions_off() as usize + size <= len);
                    assert!(size > 0, "{raw}");
                }
                for block in code.try_blocks() {
                    let block = block?;
                    stats.try_blocks += 1;
                    if strict {
                        assert!(block.start_pc as usize + block.length as usize <= size, "{raw}: {block:?}");
                        assert_eq!(block.catch_blocks().count(), block.num_catches as usize);
                    }
                    for catch in block.catch_blocks() {
                        stats.catch_blocks += 1;
                        assert!(!strict || (catch.handler_pc as usize) < size, "{raw}: {catch:?}");
                    }
                }
            } else if strict {
                panic!("{raw}: local method without code");
            }
            if let Some(debug) = method.debug_info()? {
                stats.debug_infos += 1;
                for name_off in debug.params() {
                    if name_off != 0 {
                        abc.string(name_off)?;
                    }
                }
                for row in debug.line_rows()? {
                    row?;
                    stats.line_rows += 1;
                }
                debug.first_line()?;
                for local in debug.locals()? {
                    abc.string(local.name_off)?;
                    stats.locals += 1;
                }
            }
        }
    }

    if let Some(index) = abc.literal_array_index()? {
        for off in index.iter() {
            // Module records and phase tables are listed in the same index but are not literal arrays.
            if not_literal_arrays.contains(&off) {
                continue;
            }
            stats.literal_arrays += 1;
            stats.literals += walk_literal_array(abc, &abc.literal_array(off)?, strict)?;
        }
    }
    Ok(stats)
}

fn walk_annotation(abc: &Abc<'_>, off: u32) -> Result<u64, AbcError> {
    let annotation = abc.annotation(off)?;
    abc.class_entry(annotation.class_off(abc)?)?;
    for element in annotation.elements() {
        abc.string(element.name_off)?;
    }
    Ok(1)
}

fn walk_literal_array(abc: &Abc<'_>, array: &LiteralArray<'_>, strict: bool) -> Result<u64, AbcError> {
    let mut count = 0;
    for literal in array {
        let literal = literal?;
        count += 1;
        match literal {
            Literal::String(off) => drop(abc.string(off)?.to_str()),
            Literal::LiteralArray(off) => drop(abc.literal_array(off)?),
            _ => {
                if let Some(off) = literal.method_off() {
                    abc.method(off)?.name()?;
                }
            }
        }
    }
    assert!(!strict || count == u64::from(array.len()));
    Ok(count)
}

/// The workspace root: the directory above the crate that holds `Cargo.lock`
/// (this module is also compiled into `asc-fixture`'s tests, at another depth).
fn workspace_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.ancestors().find(|dir| dir.join("Cargo.lock").is_file()).unwrap_or(manifest_dir).to_path_buf()
}

/// Directory of the ReArk samples: `$ASC_ABC_SAMPLES`, else
/// `<workspace>/../ark/ReArk/samples`.
pub fn samples_dir() -> PathBuf {
    std::env::var_os("ASC_ABC_SAMPLES").map_or_else(|| workspace_root().join("../ark/ReArk/samples"), PathBuf::from)
}

/// Directory of the large sample, `$ASC_ABC_LARGE_SAMPLE`: an app-store
/// package `entry.hap` and its decrypted `modules.abc`. There is no
/// default: `None` when the variable is not set.
pub fn large_sample_dir() -> Option<PathBuf> {
    std::env::var_os("ASC_ABC_LARGE_SAMPLE").map(PathBuf::from)
}

/// The decrypted `modules.abc` of the large sample.
pub fn load_large_sample() -> Option<Vec<u8>> {
    std::fs::read(large_sample_dir()?.join("modules.abc")).ok()
}

/// Entry `entry` of the large sample's `entry.hap`.
pub fn load_large_sample_entry(entry: &str) -> Option<Vec<u8>> {
    load_abc(&large_sample_dir()?.join("entry.hap"), entry)
}

fn zip_entry(archive: Vec<u8>, name: &str) -> Vec<u8> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(archive)).expect("sample is a zip archive");
    let mut entry = zip.by_name(name).unwrap_or_else(|err| panic!("{name}: {err}"));
    let mut data = Vec::new();
    entry.read_to_end(&mut data).expect("zip entry reads");
    data
}

/// Entry `entry` of the `.hap` at `path`; for an `.app`, of its inner
/// `entry-default.hap`. `None` when the sample is not there (CI).
pub fn load_abc(path: &Path, entry: &str) -> Option<Vec<u8>> {
    let mut archive = std::fs::read(path).ok()?;
    if path.extension().is_some_and(|ext| ext == "app") {
        archive = zip_entry(archive, "entry-default.hap");
    }
    Some(zip_entry(archive, entry))
}

/// `ets/modules.abc` of a ReArk sample.
pub fn load_sample(file: &str) -> Option<Vec<u8>> {
    load_abc(&samples_dir().join(file), "ets/modules.abc")
}

pub const RECORD_A: &str = "&entry/src/main/ets/pages/Index&";
pub const RECORD_B: &str = "com.example.app/entry/ets/model/Util";
/// The foreign class of [`synthetic`]; also the class of its annotations.
pub const FOREIGN: &str = "_ESTypeAnnotation";
/// The `i64` field `big` of record A.
pub const BIG: u64 = 0x1122_3344_5566_7788;

/// Description of [`synthetic`]: a two-region file, version 12.0.6.0
/// (literal array index present), with a correct checksum.
///
/// Region 0 holds record A, whose `func_main_0` names, in this order,
/// `hello`, `world`, the returned literal array and `#~@0>#build`. Region 1
/// holds record B, whose three functions name `world`, `#*#helper` and
/// `hello`: the same strings under different 16-bit ids. The second and
/// third function of B store a wrong region number (7, out of range, and
/// 0, the other region).
pub fn synthetic_builder() -> (AbcBuilder, LiteralArrayId) {
    let mut builder = AbcBuilder::new();
    builder.foreign_class(FOREIGN);
    let literal_array =
        builder.literal_array([AbcLiteral::Integer(0x1d4b42), AbcLiteral::str("hello"), AbcLiteral::Bool(true), AbcLiteral::Double(1.5)]);
    let annotation = || AbcAnnotation::new(FOREIGN).element("SlotNumber", 5);
    let module = AbcModule::new()
        .import("hilog", "default", "@ohos:hilog")
        .namespace_import("hilog", "@ohos:hilog")
        .export("Index", "default")
        .indirect_export("default", "default", "@ohos:hilog")
        .star_export("@ohos:hilog");

    let mut main = Asm::new();
    main.op("lda.str", [Op::str("hello")]).op("lda.str", [Op::str("world")]);
    main.op("createarraywithbuffer", [0.into(), literal_array.into()]).op("definefunc", [0.into(), Op::method("#~@0>#build"), 0.into()]);
    main.op("return", []);
    let debug = AbcDebugInfo {
        line_start: 10,
        params: vec![Some("arg0".to_owned())],
        program: vec![
            AbcLineOp::AdvancePc(2),
            AbcLineOp::AdvanceLine(-1),
            AbcLineOp::Special { pc_delta: 1, line_delta: 1 },
            AbcLineOp::SetColumn(7),
            AbcLineOp::Special { pc_delta: 0, line_delta: 0 },
        ],
    };
    // One try block over the first instruction with a typed catch and a catch-all.
    let mut build = Asm::new();
    build.label("try").op("lda.str", [Op::str("world")]).label("typed").op("ldundefined", []);
    build.label("all").op("ldnull", []).op("return", []).label("end");
    build.catch(Catch::all(("try", "typed"), ("typed", "end")).typed(0)).catch(Catch::all(("try", "typed"), ("all", "end")));

    let mut big = AbcField::new("big", AbcType::I64, AbcFieldValue::Wide(BIG)).annotation(annotation());
    big.access_flags = ACC_STATIC;
    let mut record_a = AbcRecord::new(RECORD_A)
        .field(AbcField::module_record(module))
        .field(AbcField::scope_names(["Index"]))
        .field(AbcField::new("isCommonjs", AbcType::U1, AbcFieldValue::Int(0)))
        .field(AbcField::new("pkgName@entry", AbcType::U1, AbcFieldValue::Int(0)))
        .field(big);
    record_a.source_lang = Some(SourceLang::ARKTS.0);
    let mut func_main =
        AbcFunction::new("func_main_0", AbcCode::new(1, 3, main)).kind(FunctionKind::FUNCTION).debug(debug).annotation(annotation());
    func_main.source_lang = Some(SourceLang::ARKTS.0);
    let mut func_build = AbcFunction::new("#~@0>#build", AbcCode::new(2, 3, build));
    func_build.source_lang = None;
    builder.record(record_a.function(func_main).function(func_build));

    let mut helper = Asm::new();
    helper.op("lda.str", [Op::str("world")]).op("definefunc", [0.into(), Op::method("#*#helper"), 0.into()]);
    helper.op("lda.str", [Op::str("hello")]).op("return", []);
    let mut record_b = AbcRecord::new(RECORD_B);
    record_b.source_lang = None;
    for (name, hint) in [("#*#helper", None), ("#*#helper^1", Some(7)), ("#*#", Some(0))] {
        let mut function = AbcFunction::new(name, AbcCode::new(1, 3, helper.clone())).kind(FunctionKind::NC_FUNCTION);
        function.source_lang = None;
        function.region_hint = hint;
        record_b = record_b.function(function);
    }
    builder.record(record_b).split_region_before(RECORD_B);
    (builder, literal_array)
}

/// The file [`synthetic_builder`] describes and the offset of its declared
/// literal array.
pub fn synthetic() -> (AbcFile, u32) {
    let (builder, literal_array) = synthetic_builder();
    let file = builder.build();
    let literal_array = file.layout.literal_array(literal_array);
    (file, literal_array)
}

/// Deterministic xorshift generator for the mutation tests.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}
