//! What a file is described with: records, fields, functions, code, debug
//! info, literal arrays, module records and annotations.

use super::{Asm, ACC_ANNOTATION, ACC_PUBLIC, ACC_STATIC, LANG_ECMASCRIPT};

/// Type of a field: a primitive, or a record of this file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbcType {
    U1,
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    F32,
    F64,
    I64,
    U64,
    Reference,
    Any,
    /// A record or foreign class, by name; an array type by its descriptor
    /// (`[Lpanda.String;`), declared as a foreign class.
    Record(String),
}

impl AbcType {
    /// The class table code of a primitive type.
    pub(super) fn primitive_code(&self) -> Option<u8> {
        Some(match self {
            AbcType::U1 => 0x00,
            AbcType::I8 => 0x01,
            AbcType::U8 => 0x02,
            AbcType::I16 => 0x03,
            AbcType::U16 => 0x04,
            AbcType::I32 => 0x05,
            AbcType::U32 => 0x06,
            AbcType::F32 => 0x07,
            AbcType::F64 => 0x08,
            AbcType::I64 => 0x09,
            AbcType::U64 => 0x0a,
            AbcType::Reference => 0x0b,
            AbcType::Any => 0x0c,
            AbcType::Record(_) => return None,
        })
    }
}

/// Which tagged value list entry an annotation is attached with. Whatever
/// order they are declared in, the annotations of an item are written kind
/// by kind in ascending tag order, as the official writer does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum AnnotationKind {
    /// `ANNOTATION`: what the ArkTS compiler emits.
    #[default]
    Plain,
    Runtime,
    Type,
    RuntimeType,
}

/// The value of an annotation element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbcElementValue {
    /// The four value bytes, as stored.
    Raw(u32),
    /// The offset of this string.
    String(String),
    /// The offset of a literal array declared with
    /// [`AbcBuilder::literal_array`](super::AbcBuilder::literal_array).
    Array(LiteralArrayId),
}

/// One `name = value` of an annotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbcAnnotationElement {
    pub name: String,
    pub value: AbcElementValue,
    /// The type tag byte (`b'7'` is `u32`, `b'C'` a string, `b'K'` to
    /// `b'Z'` and `b'#'` arrays).
    pub tag: u8,
}

/// An annotation on a record, field or function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbcAnnotation {
    /// Name of the annotation's record, which must be declared in the file
    /// (see [`AbcRecord::annotation_interface`]) or as a foreign class.
    pub class: String,
    pub kind: AnnotationKind,
    pub elements: Vec<AbcAnnotationElement>,
}

impl AbcAnnotation {
    pub fn new(class: &str) -> AbcAnnotation {
        AbcAnnotation { class: class.to_owned(), kind: AnnotationKind::Plain, elements: Vec::new() }
    }

    /// Add a `u32` element.
    #[must_use]
    pub fn element(mut self, name: &str, value: u32) -> AbcAnnotation {
        self.elements.push(AbcAnnotationElement { name: name.to_owned(), value: AbcElementValue::Raw(value), tag: b'7' });
        self
    }

    /// Add a string element.
    #[must_use]
    pub fn string(mut self, name: &str, value: &str) -> AbcAnnotation {
        self.elements.push(AbcAnnotationElement { name: name.to_owned(), value: AbcElementValue::String(value.to_owned()), tag: b'C' });
        self
    }

    /// Add an array element with type tag `tag` (`b'K'` to `b'Z'`, `b'#'`):
    /// the items are those of `array`.
    #[must_use]
    pub fn array(mut self, name: &str, tag: u8, array: LiteralArrayId) -> AbcAnnotation {
        self.elements.push(AbcAnnotationElement { name: name.to_owned(), value: AbcElementValue::Array(array), tag });
        self
    }

    /// `_ESSlotNumberAnnotation { SlotNumber = slots }`, which the compiler
    /// puts on every function.
    pub fn slot_number(slots: u32) -> AbcAnnotation {
        AbcAnnotation::new("_ESSlotNumberAnnotation").element("SlotNumber", slots)
    }
}

/// One item of a literal array.
#[derive(Debug, Clone, PartialEq)]
pub enum AbcLiteral {
    TagValue(u8),
    Bool(bool),
    Integer(i32),
    Float(f32),
    Double(f64),
    String(String),
    Method(MethodRef),
    GeneratorMethod(MethodRef),
    AsyncGeneratorMethod(MethodRef),
    Getter(MethodRef),
    Setter(MethodRef),
    Accessor(u8),
    MethodAffiliate(u16),
    LiteralBufferIndex(u32),
    LiteralArray(LiteralArrayId),
    BuiltinTypeIndex(u8),
    /// Stored as the offset of the string.
    EtsImplements(String),
    Null,
    /// A typed array (`tag` in `0x0a..=0x15`): takes up the rest of the
    /// literal array, so it has to be the last item. `data` is written as is.
    TypedArray {
        tag: u8,
        data: Vec<u8>,
    },
    /// Any tag byte followed by any bytes: for tags readers do not know.
    Raw {
        tag: u8,
        value: Vec<u8>,
    },
}

impl AbcLiteral {
    pub fn str(text: &str) -> AbcLiteral {
        AbcLiteral::String(text.to_owned())
    }

    pub fn method(record: &str, name: &str) -> AbcLiteral {
        AbcLiteral::Method(MethodRef::new(record, name))
    }
}

/// A function, named by its record and raw name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MethodRef {
    pub record: String,
    pub name: String,
}

impl MethodRef {
    pub fn new(record: &str, name: &str) -> MethodRef {
        MethodRef { record: record.to_owned(), name: name.to_owned() }
    }
}

/// Handle of a literal array declared with [`AbcBuilder::literal_array`](super::AbcBuilder::literal_array).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LiteralArrayId(pub(crate) usize);

/// `import { import_name as local_name } from requests[request]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbcRegularImport {
    pub local_name: String,
    pub import_name: String,
    pub request: u16,
}

/// `import * as local_name from requests[request]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbcNamespaceImport {
    pub local_name: String,
    pub request: u16,
}

/// `export { local_name as export_name }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbcLocalExport {
    pub local_name: String,
    pub export_name: String,
}

/// `export { import_name as export_name } from requests[request]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbcIndirectExport {
    pub export_name: String,
    pub import_name: String,
    pub request: u16,
}

/// The module record of an ES module: what it imports and exports.
/// `ldexternalmodulevar k` reads regular import `k`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AbcModule {
    /// Module requests (`@ohos:net.http`, `@normalized:N&&&entry/src/main/ets/x&`).
    pub requests: Vec<String>,
    pub regular_imports: Vec<AbcRegularImport>,
    pub namespace_imports: Vec<AbcNamespaceImport>,
    pub local_exports: Vec<AbcLocalExport>,
    pub indirect_exports: Vec<AbcIndirectExport>,
    /// `export * from requests[i]`.
    pub star_exports: Vec<u16>,
}

impl AbcModule {
    pub fn new() -> AbcModule {
        AbcModule::default()
    }

    /// Add a module request; returns its index.
    ///
    /// # Panics
    /// When the module already has 65536 requests.
    pub fn request(&mut self, request: &str) -> u16 {
        self.requests.push(request.to_owned());
        u16::try_from(self.requests.len() - 1).expect("at most 65536 module requests")
    }

    /// `import { import_name as local_name } from <request>`, adding the
    /// request when it is new.
    #[must_use]
    pub fn import(mut self, local_name: &str, import_name: &str, request: &str) -> AbcModule {
        let request = self.request_index(request);
        self.regular_imports.push(AbcRegularImport { local_name: local_name.to_owned(), import_name: import_name.to_owned(), request });
        self
    }

    /// `import * as local_name from <request>`.
    #[must_use]
    pub fn namespace_import(mut self, local_name: &str, request: &str) -> AbcModule {
        let request = self.request_index(request);
        self.namespace_imports.push(AbcNamespaceImport { local_name: local_name.to_owned(), request });
        self
    }

    /// `export { local_name as export_name }`.
    #[must_use]
    pub fn export(mut self, local_name: &str, export_name: &str) -> AbcModule {
        self.local_exports.push(AbcLocalExport { local_name: local_name.to_owned(), export_name: export_name.to_owned() });
        self
    }

    /// `export { import_name as export_name } from <request>`.
    #[must_use]
    pub fn indirect_export(mut self, export_name: &str, import_name: &str, request: &str) -> AbcModule {
        let request = self.request_index(request);
        self.indirect_exports.push(AbcIndirectExport { export_name: export_name.to_owned(), import_name: import_name.to_owned(), request });
        self
    }

    /// `export * from <request>`.
    #[must_use]
    pub fn star_export(mut self, request: &str) -> AbcModule {
        let request = self.request_index(request);
        self.star_exports.push(request);
        self
    }

    fn request_index(&mut self, request: &str) -> u16 {
        match self.requests.iter().position(|known| known == request) {
            Some(index) => u16::try_from(index).expect("at most 65536 module requests"),
            None => self.request(request),
        }
    }
}

/// Stored value of a field.
#[derive(Debug, Clone, PartialEq)]
pub enum AbcFieldValue {
    None,
    /// `INT_VALUE` tag.
    Int(i32),
    /// `VALUE` tag with these four bytes.
    Raw(u32),
    /// `VALUE` tag pointing at this 8-byte value (`i64` / `u64` / `f64` fields).
    Wide(u64),
    /// `VALUE` tag pointing at a string (`jsonFileContent`).
    String(String),
    /// `VALUE` tag pointing at a module request phase table
    /// (`moduleRequestPhaseIdx`): `u32 count`, then one untagged byte per
    /// module request of the record (0 ordinary, 1 lazy import). Not a
    /// literal array, although the header literal array index lists it.
    ModuleRequestPhases(Vec<u8>),
    /// `VALUE` tag pointing at a literal array of these strings (`scopeNames`).
    ScopeNames(Vec<String>),
    /// `VALUE` tag pointing at a declared literal array: the default value
    /// of an array field of an annotation interface.
    Array(LiteralArrayId),
    /// `VALUE` tag pointing at a module record (`moduleRecordIdx`).
    Module(AbcModule),
}

/// A field of a record.
#[derive(Debug, Clone, PartialEq)]
pub struct AbcField {
    pub name: String,
    pub ty: AbcType,
    pub access_flags: u32,
    pub value: AbcFieldValue,
    pub annotations: Vec<AbcAnnotation>,
}

impl AbcField {
    pub fn new(name: &str, ty: AbcType, value: AbcFieldValue) -> AbcField {
        AbcField { name: name.to_owned(), ty, access_flags: 0, value, annotations: Vec::new() }
    }

    /// A `u8` field with an `INT_VALUE`: `isCommonjs`, `pkgName@entry`, …
    pub fn flag(name: &str, value: i32) -> AbcField {
        AbcField::new(name, AbcType::U8, AbcFieldValue::Int(value))
    }

    /// `scopeNames`: what `@<hex>` in the record's function names stands for.
    pub fn scope_names<S: AsRef<str>>(names: impl IntoIterator<Item = S>) -> AbcField {
        let names = names.into_iter().map(|name| name.as_ref().to_owned()).collect();
        AbcField::new("scopeNames", AbcType::U32, AbcFieldValue::ScopeNames(names))
    }

    /// `moduleRequestPhaseIdx`: the phase of each module request, in
    /// request order (1 marks a lazy import, read with
    /// `callruntime.ldlazymodulevar`).
    pub fn module_request_phases(phases: &[u8]) -> AbcField {
        AbcField::new("moduleRequestPhaseIdx", AbcType::U32, AbcFieldValue::ModuleRequestPhases(phases.to_vec()))
    }

    /// `moduleRecordIdx`.
    pub fn module_record(module: AbcModule) -> AbcField {
        AbcField::new("moduleRecordIdx", AbcType::U32, AbcFieldValue::Module(module))
    }

    #[must_use]
    pub fn annotation(mut self, annotation: AbcAnnotation) -> AbcField {
        self.annotations.push(annotation);
        self
    }
}

/// A try block given by code offsets, for ranges labels cannot express
/// (out of bounds, overlapping an instruction). See [`Catch`](super::Catch) for the
/// usual, label-based form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbcTry {
    pub start_pc: u32,
    pub length: u32,
    pub catches: Vec<AbcCatch>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbcCatch {
    pub type_idx: Option<u32>,
    pub handler_pc: u32,
    pub code_size: u32,
}

/// A code item.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AbcCode {
    pub num_vregs: u32,
    /// The ArkTS compiler counts three implicit arguments (function, new
    /// target, `this`) before the declared ones.
    pub num_args: u32,
    pub asm: Asm,
    /// Written after the try blocks of the assembler's [`Catch`](super::Catch)es.
    pub tries: Vec<AbcTry>,
}

impl AbcCode {
    pub fn new(num_vregs: u32, num_args: u32, asm: Asm) -> AbcCode {
        AbcCode { num_vregs, num_args, asm, tries: Vec::new() }
    }

    /// Code made of these bytes, whatever they are.
    pub fn raw(num_vregs: u32, num_args: u32, instructions: &[u8]) -> AbcCode {
        let mut asm = Asm::new();
        asm.raw(instructions);
        AbcCode::new(num_vregs, num_args, asm)
    }
}

/// One opcode of a line number program. Constants (and string offsets) go
/// to the debug info's constant pool, as the format wants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbcLineOp {
    AdvancePc(u32),
    AdvanceLine(i32),
    StartLocal {
        reg: i32,
        name: String,
        ty: String,
    },
    StartLocalExtended {
        reg: i32,
        name: String,
        ty: String,
        signature: String,
    },
    EndLocal(i32),
    RestartLocal(i32),
    SetPrologueEnd,
    SetEpilogueBegin,
    SetFile(String),
    SetSourceCode(String),
    SetColumn(u32),
    /// Advance both registers and emit a row: `pc_delta` in `0..=15`,
    /// `line_delta` in `-4..=10`.
    Special {
        pc_delta: u32,
        line_delta: i32,
    },
}

/// Debug info of a function. Functions with byte-identical line number
/// programs share one, like in compiler output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AbcDebugInfo {
    pub line_start: u32,
    /// Parameter names; `None` is stored as offset 0.
    pub params: Vec<Option<String>>,
    pub program: Vec<AbcLineOp>,
}

impl AbcDebugInfo {
    /// Debug info whose line program names `source_file` and then yields
    /// one row per `(pc, line)` pair, starting from line `line_start`.
    ///
    /// # Panics
    /// When the pcs go backwards.
    pub fn rows(source_file: &str, line_start: u32, rows: &[(u32, u32)]) -> AbcDebugInfo {
        let mut program = vec![AbcLineOp::SetFile(source_file.to_owned())];
        let (mut pc, mut line) = (0u32, line_start);
        for &(row_pc, row_line) in rows {
            let mut pc_delta = row_pc.checked_sub(pc).expect("line rows are ordered by pc");
            let mut line_delta = i64::from(row_line) - i64::from(line);
            if !(-4..=10).contains(&line_delta) {
                program.push(AbcLineOp::AdvanceLine(i32::try_from(line_delta).expect("line delta fits in 32 bits")));
                line_delta = 0;
            }
            if pc_delta > 15 {
                program.push(AbcLineOp::AdvancePc(pc_delta));
                pc_delta = 0;
            }
            program.push(AbcLineOp::Special { pc_delta, line_delta: i32::try_from(line_delta).expect("checked to be in -4..=10") });
            (pc, line) = (row_pc, row_line);
        }
        AbcDebugInfo { line_start, params: Vec::new(), program }
    }

    #[must_use]
    pub fn param(mut self, name: &str) -> AbcDebugInfo {
        self.params.push(Some(name.to_owned()));
        self
    }
}

/// A function of a record (a `Method` item). In the dynamic flavour every
/// function, method and closure of a module belongs to the module's record.
#[derive(Debug, Clone, PartialEq)]
pub struct AbcFunction {
    /// The raw name: `func_main_0`, `#~@0>#build`, `#*#helper^1`, …
    pub name: String,
    /// Bits 0–7 of the access flags; [`ACC_STATIC`] by default.
    pub access_flags: u32,
    /// `asc_abc::FunctionKind` byte (bits 8–15 of the access flags).
    pub kind: u8,
    pub source_lang: Option<u8>,
    pub code: Option<AbcCode>,
    pub debug: Option<AbcDebugInfo>,
    pub annotations: Vec<AbcAnnotation>,
    /// Region number to store in `access_flags >> 16` instead of what
    /// [`AbcBuilder::region_hint`](super::AbcBuilder::region_hint) says.
    pub region_hint: Option<u32>,
}

impl AbcFunction {
    pub fn new(name: &str, code: AbcCode) -> AbcFunction {
        AbcFunction {
            name: name.to_owned(),
            access_flags: ACC_STATIC,
            kind: 0,
            source_lang: Some(LANG_ECMASCRIPT),
            code: Some(code),
            debug: None,
            annotations: Vec::new(),
            region_hint: None,
        }
    }

    /// Set the function kind (`asc_abc::FunctionKind::FUNCTION` …).
    #[must_use]
    pub fn kind(mut self, kind: u8) -> AbcFunction {
        self.kind = kind;
        self
    }

    #[must_use]
    pub fn debug(mut self, debug: AbcDebugInfo) -> AbcFunction {
        self.debug = Some(debug);
        self
    }

    #[must_use]
    pub fn annotation(mut self, annotation: AbcAnnotation) -> AbcFunction {
        self.annotations.push(annotation);
        self
    }

    #[must_use]
    pub fn region_hint(mut self, region: u32) -> AbcFunction {
        self.region_hint = Some(region);
        self
    }
}

/// A record (a `Class` item): one per source module, plus pseudo records
/// such as annotation interfaces.
#[derive(Debug, Clone, PartialEq)]
pub struct AbcRecord {
    /// The record name; the class descriptor is `L<name>;`.
    pub name: String,
    pub access_flags: u32,
    pub source_lang: Option<u8>,
    /// `SOURCE_FILE` tag. The ArkTS compiler does not write one (it names
    /// the file in the line number program, see [`AbcLineOp::SetFile`]).
    pub source_file: Option<String>,
    /// Names of records listed in the `INTERFACES` tag.
    pub interfaces: Vec<String>,
    pub annotations: Vec<AbcAnnotation>,
    pub fields: Vec<AbcField>,
    pub functions: Vec<AbcFunction>,
}

impl AbcRecord {
    /// An empty public record.
    pub fn new(name: &str) -> AbcRecord {
        AbcRecord {
            name: name.to_owned(),
            access_flags: ACC_PUBLIC,
            source_lang: Some(LANG_ECMASCRIPT),
            source_file: None,
            interfaces: Vec::new(),
            annotations: Vec::new(),
            fields: Vec::new(),
            functions: Vec::new(),
        }
    }

    /// An annotation interface such as `_ESSlotNumberAnnotation`.
    pub fn annotation_interface(name: &str) -> AbcRecord {
        AbcRecord { access_flags: ACC_PUBLIC | ACC_ANNOTATION, ..AbcRecord::new(name) }
    }

    /// A record with the fields the compiler gives an ES module since
    /// 12.0.6.0, in its order: `pkgName@<package>`, `isCommonjs`,
    /// `hasTopLevelAwait`, `isSharedModule`, `scopeNames`, `moduleRecordIdx`.
    pub fn ets_module(name: &str, package: &str, scope_names: &[&str], module: AbcModule) -> AbcRecord {
        AbcRecord::new(name)
            .field(AbcField::flag(&format!("pkgName@{package}"), 0))
            .field(AbcField::flag("isCommonjs", 0))
            .field(AbcField::flag("hasTopLevelAwait", 0))
            .field(AbcField::flag("isSharedModule", 0))
            .field(AbcField::scope_names(scope_names))
            .field(AbcField::module_record(module))
    }

    #[must_use]
    pub fn field(mut self, field: AbcField) -> AbcRecord {
        self.fields.push(field);
        self
    }

    #[must_use]
    pub fn function(mut self, function: AbcFunction) -> AbcRecord {
        self.functions.push(function);
        self
    }

    #[must_use]
    pub fn source_file(mut self, file: &str) -> AbcRecord {
        self.source_file = Some(file.to_owned());
        self
    }

    #[must_use]
    pub fn annotation(mut self, annotation: AbcAnnotation) -> AbcRecord {
        self.annotations.push(annotation);
        self
    }
}
