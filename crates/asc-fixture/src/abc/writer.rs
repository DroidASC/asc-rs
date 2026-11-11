//! Turns an [`AbcBuilder`] into bytes.
//!
//! Two steps. [`Plan`] decides what does not depend on offsets: which
//! region every class and method belongs to and the content of each
//! region's tables. `Emitter` then writes the items in file order;
//! references to items are 32-bit placeholders patched once every offset is
//! known. The only offsets needed while writing are those of strings (debug
//! info stores them as LEB128), which is why the emitter runs twice: the
//! first run only finds out which strings the file needs.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::ops::RangeInclusive;

use asc_abc::leb128::{write_sleb128, write_uleb128};
use asc_abc::{HEADER_SIZE, INVALID_OFFSET, MAGIC, RegionHeader, literal_tag};
use asc_dex::mutf8;

use super::layout::MethodLayout;
use super::plan::{Holder, LiteralItem, Plan, Region, RegionStart, Sym};
use super::{
    AbcAnnotation, AbcBuilder, AbcCatch, AbcDebugInfo, AbcElementValue, AbcField, AbcFieldValue, AbcFile, AbcFunction, AbcLayout,
    AbcLineOp, AbcLiteral, AbcModule, AbcRecord, AbcRegionLayout, AbcTry, AbcType, MethodRef, RegionHint, adler32, scramble_body,
};

/// The descriptor of the class called `name`: `L<name>;`, an array type
/// (`[Lpanda.String;`) being its own.
fn descriptor(name: &str) -> String {
    if name.starts_with('[') { name.to_owned() } else { format!("L{name};") }
}

/// `MethodTag::DEBUG_INFO`: runtime annotations are written before it, the
/// other kinds after.
const DEBUG_INFO_TAG: u8 = 0x05;

/// Positions of the tables between the header and the first item.
#[derive(Debug, Default)]
struct Tables {
    class_index: usize,
    literal_index: Option<usize>,
    region_headers: usize,
    /// Per region: class, entity, field and proto table.
    regions: Vec<[usize; 4]>,
    /// Offset and size of the foreign classes.
    foreign: (u32, u32),
    line_program_index: usize,
}

struct Emitter<'a> {
    plan: &'a Plan<'a>,
    buf: Vec<u8>,
    /// Positions of 32-bit placeholders and what they refer to.
    fixups: Vec<(usize, Sym)>,
    offsets: HashMap<Sym, u32>,
    /// The string pool, in the order strings were first needed.
    strings: Vec<String>,
    known_strings: HashSet<String>,
    /// Whether `strings` is complete. In the first run it is not, and
    /// string offsets needed while writing are placeholders.
    final_run: bool,
    tables: Tables,
    class_offsets: Vec<u32>,
    method_offsets: Vec<Vec<u32>>,
    field_offsets: Vec<Vec<u32>>,
    /// Distinct line number programs and their offsets.
    line_programs: Vec<(Vec<u8>, u32)>,
    /// Running index into [`Plan::annotations`].
    next_annotation: usize,
}

impl<'a> Emitter<'a> {
    fn new(plan: &'a Plan<'a>, strings: Vec<String>, final_run: bool) -> Emitter<'a> {
        Emitter {
            plan,
            buf: Vec::new(),
            fixups: Vec::new(),
            offsets: HashMap::new(),
            known_strings: strings.iter().cloned().collect(),
            strings,
            final_run,
            tables: Tables::default(),
            class_offsets: Vec::new(),
            method_offsets: Vec::new(),
            field_offsets: Vec::new(),
            line_programs: Vec::new(),
            next_annotation: 0,
        }
    }

    fn pos(&self) -> u32 {
        u32::try_from(self.buf.len()).expect("ABC files are smaller than 4 GiB")
    }

    fn u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    fn uleb(&mut self, value: u32) {
        write_uleb128(&mut self.buf, value);
    }

    fn sleb(&mut self, value: i32) {
        write_sleb128(&mut self.buf, value);
    }

    fn count(&mut self, len: usize) {
        self.uleb(u32::try_from(len).expect("counts fit in 32 bits"));
    }

    fn align(&mut self, to: usize) {
        self.buf.resize(self.buf.len().next_multiple_of(to), 0);
    }

    /// Reserve `words` zeroed 32-bit slots; returns their position.
    fn reserve(&mut self, words: usize) -> usize {
        let at = self.buf.len();
        self.buf.resize(at + 4 * words, 0);
        at
    }

    fn patch(&mut self, at: usize, value: u32) {
        self.buf[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// A `String` item: `uleb (utf16_len << 1 | is_ascii)`, MUTF-8, NUL.
    fn string_item(&mut self, text: &str) {
        let data = mutf8::encode(text);
        let utf16_len = u32::try_from(text.encode_utf16().count()).expect("string length fits in 32 bits");
        self.uleb(utf16_len << 1 | u32::from(data.is_ascii()));
        self.buf.extend_from_slice(&data);
        self.u8(0);
    }

    fn intern(&mut self, text: &str) {
        if self.known_strings.insert(text.to_owned()) {
            assert!(!self.final_run, "string {text:?} was not seen by the first run");
            self.strings.push(text.to_owned());
        }
    }

    fn define(&mut self, sym: Sym) {
        let at = self.pos();
        // Of functions sharing a name, references mean the first.
        self.offsets.entry(sym).or_insert(at);
    }

    /// A 32-bit reference to `sym`, patched when all offsets are known.
    fn reference(&mut self, sym: Sym) {
        if let Sym::Str(text) = &sym {
            self.intern(text);
        }
        self.fixups.push((self.buf.len(), sym));
        self.u32(0);
    }

    fn string_ref(&mut self, text: &str) {
        self.reference(Sym::Str(text.to_owned()));
    }

    fn offset_of(&self, sym: &Sym) -> u32 {
        *self.offsets.get(sym).unwrap_or_else(|| panic!("reference to {sym:?}, which the file does not define"))
    }

    /// Offset of a string that was already written. Only the final run
    /// knows it; the first run answers 0, which merely makes its LEB128
    /// encodings shorter.
    fn string_offset(&mut self, text: &str) -> u32 {
        self.intern(text);
        if self.final_run { self.offset_of(&Sym::Str(text.to_owned())) } else { 0 }
    }

    fn run(mut self) -> Emitter<'a> {
        let plan = self.plan;
        let builder = plan.builder;
        builder.strings.iter().for_each(|text| self.intern(text));
        // Strings only instructions name are referred to by id, never through a placeholder.
        for sym in plan.regions.iter().flat_map(|region| &region.entities) {
            if let Sym::Str(text) = sym {
                self.intern(text);
            }
        }

        self.buf.resize(HEADER_SIZE, 0);
        self.tables.class_index = self.reserve(plan.class_names.len());
        self.tables.literal_index = plan.has_literal_index.then(|| self.reserve(plan.literals.len()));
        self.tables.region_headers = self.reserve(plan.regions.len() * RegionHeader::SIZE / 4);
        for region in &plan.regions {
            let class_table = self.reserve(region.class_table_len());
            let entity_table = self.reserve(region.entities.len());
            // Before 12 the field table exists and is empty; the proto table follows it.
            let field_table = self.buf.len();
            let proto_table = self.reserve(region.protos.len());
            self.tables.regions.push([class_table, entity_table, field_table, proto_table]);
        }

        let foreign_start = self.pos();
        for name in &builder.foreign_classes {
            self.define(Sym::Class(name.clone()));
            self.string_item(&descriptor(name));
        }
        self.tables.foreign = if builder.foreign_classes.is_empty() { (0, 0) } else { (foreign_start, self.pos() - foreign_start) };

        for (r, record) in builder.records.iter().enumerate() {
            self.class(r, record);
        }
        for index in 0.. {
            // The pool grows while the first run writes later sections; those strings are written by the final run.
            let Some(text) = self.strings.get(index).cloned() else { break };
            self.define(Sym::Str(text.clone()));
            self.string_item(&text);
        }
        for (position, item) in plan.literals.iter().enumerate() {
            self.define(Sym::Literal(position));
            match *item {
                LiteralItem::Array(items) => self.literal_array(items),
                LiteralItem::ScopeNames(names) => {
                    self.count_u32(2 * names.len());
                    for name in names {
                        self.u8(literal_tag::STRING);
                        self.string_ref(name);
                    }
                }
                LiteralItem::Module(module) => self.module_record(module),
                LiteralItem::Phases(phases) => {
                    self.count_u32(phases.len());
                    self.buf.extend_from_slice(phases);
                }
            }
        }
        for (r, record) in builder.records.iter().enumerate() {
            for (f, field) in record.fields.iter().enumerate() {
                if let AbcFieldValue::Wide(value) = field.value {
                    self.define(Sym::WideValue(r, f));
                    self.buf.extend_from_slice(&value.to_le_bytes());
                }
            }
        }
        self.protos();
        for (index, annotation) in plan.annotations.iter().enumerate() {
            self.annotation(index, annotation);
        }
        for (r, record) in builder.records.iter().enumerate() {
            for (f, function) in record.functions.iter().enumerate() {
                if let Some(code) = &function.code {
                    self.code(r, f, record, code);
                }
            }
        }
        for (r, record) in builder.records.iter().enumerate() {
            for (f, function) in record.functions.iter().enumerate() {
                if let Some(debug) = &function.debug {
                    self.debug_info(r, f, debug);
                }
            }
        }
        self.align(4);
        self.tables.line_program_index = self.reserve(self.line_programs.len());
        self
    }

    fn count_u32(&mut self, len: usize) {
        self.u32(u32::try_from(len).expect("counts fit in 32 bits"));
    }

    /// Write the annotation tags of `holder` whose tag number is in `tags`.
    fn annotation_tags(&mut self, holder: Holder, annotations: &[AbcAnnotation], tags: RangeInclusive<u8>) {
        for tag in holder.ordered(annotations).into_iter().map(|annotation| holder.annotation_tag(annotation.kind)) {
            if tags.contains(&tag) {
                self.u8(tag);
                self.reference(Sym::Annotation(self.next_annotation));
                self.next_annotation += 1;
            }
        }
    }

    /// A class item with its fields and methods inline. Tag order as in
    /// `ClassItem::WriteTaggedData`.
    fn class(&mut self, r: usize, record: &AbcRecord) {
        let plan = self.plan;
        let region = &plan.regions[plan.class_region[r]];
        self.class_offsets.push(self.pos());
        self.define(Sym::Class(record.name.clone()));
        self.string_item(&descriptor(&record.name));
        self.u32(0);
        self.uleb(record.access_flags);
        self.count(record.fields.len());
        self.count(record.functions.len());
        if !record.interfaces.is_empty() {
            self.u8(0x01);
            self.count(record.interfaces.len());
            for interface in &record.interfaces {
                self.u16(region.class_idx(plan.order_of(interface)));
            }
        }
        if let Some(lang) = record.source_lang {
            self.u8(0x02);
            self.u8(lang);
        }
        self.annotation_tags(Holder::Class, &record.annotations, 0..=u8::MAX);
        if let Some(file) = &record.source_file {
            self.u8(0x07);
            self.string_ref(file);
        }
        self.u8(0x00);

        let class_idx = region.class_idx(plan.order_of(&record.name));
        let mut field_offsets = Vec::with_capacity(record.fields.len());
        for (f, field) in record.fields.iter().enumerate() {
            field_offsets.push(self.pos());
            self.field(r, f, field, region, class_idx);
        }
        self.field_offsets.push(field_offsets);

        let mut method_offsets = Vec::with_capacity(record.functions.len());
        for (f, function) in record.functions.iter().enumerate() {
            method_offsets.push(self.pos());
            self.method(r, f, record, function);
        }
        self.method_offsets.push(method_offsets);
    }

    fn field(&mut self, r: usize, f: usize, field: &AbcField, region: &Region, class_idx: u16) {
        let plan = self.plan;
        self.u16(class_idx);
        self.u16(match (&field.ty, field.ty.primitive_code()) {
            (_, Some(code)) => region.primitive_idx(code),
            (AbcType::Record(name), None) => region.class_idx(plan.order_of(name)),
            (_, None) => unreachable!("every type but `Record` has a primitive code"),
        });
        self.string_ref(&field.name);
        self.uleb(field.access_flags);
        let value = match &field.value {
            AbcFieldValue::None => None,
            AbcFieldValue::Int(value) => {
                self.u8(0x01);
                self.sleb(*value);
                None
            }
            AbcFieldValue::Raw(value) => {
                self.u8(0x02);
                self.u32(*value);
                None
            }
            AbcFieldValue::Wide(_) => Some(Sym::WideValue(r, f)),
            AbcFieldValue::String(text) => Some(Sym::Str(text.clone())),
            AbcFieldValue::Array(id) => Some(Sym::Literal(plan.declared_literals_base + id.0)),
            AbcFieldValue::ScopeNames(_) | AbcFieldValue::Module(_) | AbcFieldValue::ModuleRequestPhases(_) => {
                Some(Sym::Literal(plan.field_literals[&(r, f)]))
            }
        };
        if let Some(sym) = value {
            self.u8(0x02);
            self.reference(sym);
        }
        self.annotation_tags(Holder::Field, &field.annotations, 0..=u8::MAX);
        self.u8(0x00);
    }

    /// A method item. Tag order as in `MethodItem::WriteTaggedData`: code,
    /// source language, runtime annotations, debug info, the other annotations.
    fn method(&mut self, r: usize, f: usize, record: &AbcRecord, function: &AbcFunction) {
        let plan = self.plan;
        let region_index = plan.method_region[r][f];
        let region = &plan.regions[region_index];
        self.define(Sym::Method(record.name.clone(), function.name.clone()));
        self.u16(region.class_idx(plan.order_of(&record.name)));
        let num_args = function.code.as_ref().map_or(0, |code| code.num_args);
        let proto_idx = region.protos.iter().position(|&args| args == num_args).filter(|_| plan.has_protos);
        self.u16(proto_idx.map_or(u16::MAX, |idx| u16::try_from(idx).expect("proto table index fits in 16 bits")));
        self.string_ref(&function.name);
        let hint = function.region_hint.unwrap_or(match plan.builder.region_hint {
            RegionHint::Exact => u32::try_from(region_index).expect("region count fits in 32 bits"),
            RegionHint::Fixed(hint) => hint,
        });
        self.uleb((function.access_flags & 0xff) | u32::from(function.kind) << 8 | (hint & 0xffff) << 16);
        if function.code.is_some() {
            self.u8(0x01);
            self.reference(Sym::Code(r, f));
        }
        if let Some(lang) = function.source_lang {
            self.u8(0x02);
            self.u8(lang);
        }
        self.annotation_tags(Holder::Method, &function.annotations, 0..=DEBUG_INFO_TAG - 1);
        if function.debug.is_some() {
            self.u8(DEBUG_INFO_TAG);
            self.reference(Sym::DebugInfo(r, f));
        }
        self.annotation_tags(Holder::Method, &function.annotations, DEBUG_INFO_TAG + 1..=u8::MAX);
        self.u8(0x00);
    }

    fn method_ref(&mut self, tag: u8, method: &MethodRef) {
        self.u8(tag);
        self.reference(Sym::Method(method.record.clone(), method.name.clone()));
    }

    /// `u32 num` (twice the number of items), then `(u8 tag, value)` items.
    fn literal_array(&mut self, items: &[AbcLiteral]) {
        let plan = self.plan;
        self.count_u32(2 * items.len());
        for item in items {
            match item {
                AbcLiteral::TagValue(value) => self.buf.extend([literal_tag::TAGVALUE, *value]),
                AbcLiteral::Bool(value) => self.buf.extend([literal_tag::BOOL, u8::from(*value)]),
                AbcLiteral::Integer(value) => {
                    self.u8(literal_tag::INTEGER);
                    self.buf.extend_from_slice(&value.to_le_bytes());
                }
                AbcLiteral::Float(value) => {
                    self.u8(literal_tag::FLOAT);
                    self.buf.extend_from_slice(&value.to_le_bytes());
                }
                AbcLiteral::Double(value) => {
                    self.u8(literal_tag::DOUBLE);
                    self.buf.extend_from_slice(&value.to_le_bytes());
                }
                AbcLiteral::String(text) => {
                    self.u8(literal_tag::STRING);
                    self.string_ref(text);
                }
                AbcLiteral::Method(method) => self.method_ref(literal_tag::METHOD, method),
                AbcLiteral::GeneratorMethod(method) => self.method_ref(literal_tag::GENERATORMETHOD, method),
                AbcLiteral::AsyncGeneratorMethod(method) => self.method_ref(literal_tag::ASYNCGENERATORMETHOD, method),
                AbcLiteral::Getter(method) => self.method_ref(literal_tag::GETTER, method),
                AbcLiteral::Setter(method) => self.method_ref(literal_tag::SETTER, method),
                AbcLiteral::Accessor(value) => self.buf.extend([literal_tag::ACCESSOR, *value]),
                AbcLiteral::MethodAffiliate(value) => {
                    self.u8(literal_tag::METHODAFFILIATE);
                    self.u16(*value);
                }
                AbcLiteral::LiteralBufferIndex(value) => {
                    self.u8(literal_tag::LITERALBUFFERINDEX);
                    self.u32(*value);
                }
                AbcLiteral::LiteralArray(id) => {
                    self.u8(literal_tag::LITERALARRAY);
                    self.reference(Sym::Literal(plan.declared_literals_base + id.0));
                }
                AbcLiteral::BuiltinTypeIndex(value) => self.buf.extend([literal_tag::BUILTINTYPEINDEX, *value]),
                AbcLiteral::EtsImplements(text) => {
                    self.u8(literal_tag::ETS_IMPLEMENTS);
                    self.string_ref(text);
                }
                AbcLiteral::Null => self.buf.extend([literal_tag::NULLVALUE, 0]),
                AbcLiteral::TypedArray { tag, data: value } | AbcLiteral::Raw { tag, value } => {
                    self.u8(*tag);
                    self.buf.extend_from_slice(value);
                }
            }
        }
    }

    /// `u32 num_literals` (the number of values that follow, counts
    /// included), the module requests, then the five import / export
    /// sections, each a `u32` count and fixed-size entries.
    fn module_record(&mut self, module: &AbcModule) {
        let values = 6
            + module.requests.len()
            + 3 * module.regular_imports.len()
            + 2 * module.namespace_imports.len()
            + 2 * module.local_exports.len()
            + 3 * module.indirect_exports.len()
            + module.star_exports.len();
        self.count_u32(values);
        self.count_u32(module.requests.len());
        module.requests.iter().for_each(|request| self.string_ref(request));
        self.count_u32(module.regular_imports.len());
        for import in &module.regular_imports {
            self.string_ref(&import.local_name);
            self.string_ref(&import.import_name);
            self.u16(import.request);
        }
        self.count_u32(module.namespace_imports.len());
        for import in &module.namespace_imports {
            self.string_ref(&import.local_name);
            self.u16(import.request);
        }
        self.count_u32(module.local_exports.len());
        for export in &module.local_exports {
            self.string_ref(&export.local_name);
            self.string_ref(&export.export_name);
        }
        self.count_u32(module.indirect_exports.len());
        for export in &module.indirect_exports {
            self.string_ref(&export.export_name);
            self.string_ref(&export.import_name);
            self.u16(export.request);
        }
        self.count_u32(module.star_exports.len());
        module.star_exports.iter().for_each(|&request| self.u16(request));
    }

    /// Proto items of versions before 12: a shorty of 4-bit type codes
    /// (`any` for the return value and every argument) ending with a zero
    /// nibble, padded to 16-bit units (`ProtoItem::AddType`).
    fn protos(&mut self) {
        const ANY: u16 = 0x0e;
        let plan = self.plan;
        let arg_counts: BTreeSet<u32> = plan.regions.iter().flat_map(|region| &region.protos).copied().collect();
        for num_args in arg_counts {
            self.align(2);
            self.define(Sym::Proto(num_args));
            let nibbles = usize::try_from(num_args).expect("argument count fits in usize") + 1;
            let mut units = vec![0u16; (nibbles + 1).div_ceil(4)];
            for nibble in 0..nibbles {
                units[nibble / 4] |= ANY << (4 * (nibble % 4));
            }
            units.into_iter().for_each(|unit| self.u16(unit));
        }
    }

    /// `u16 class_idx, u16 count`, `count` × `(u32 name, u32 value)`, then
    /// `count` type tag bytes.
    fn annotation(&mut self, index: usize, annotation: &AbcAnnotation) {
        let plan = self.plan;
        let region = plan.regions.last().expect("annotations have holders, and holders a region");
        self.define(Sym::Annotation(index));
        self.u16(region.class_idx(plan.order_of(&annotation.class)));
        self.u16(u16::try_from(annotation.elements.len()).expect("at most 65535 annotation elements"));
        for element in &annotation.elements {
            self.string_ref(&element.name);
            match &element.value {
                AbcElementValue::Raw(value) => self.u32(*value),
                AbcElementValue::String(text) => self.string_ref(text),
                AbcElementValue::Array(id) => self.reference(Sym::Literal(plan.declared_literals_base + id.0)),
            }
        }
        annotation.elements.iter().for_each(|element| self.u8(element.tag));
    }

    /// `uleb num_vregs, num_args, code_size, tries_size`, the instructions,
    /// then the try blocks.
    fn code(&mut self, r: usize, f: usize, record: &AbcRecord, code: &super::AbcCode) {
        let plan = self.plan;
        let region = &plan.regions[plan.method_region[r][f]];
        let assembled = code.asm.assemble(|operand| region.ids[&plan.entity_sym(record, operand)]);

        // Catches of one try range form one try block.
        let mut tries: Vec<AbcTry> = Vec::new();
        for catch in code.asm.catches() {
            let (start_pc, end_pc) = (assembled.label(&catch.try_start), assembled.label(&catch.try_end));
            let (handler_pc, handler_end) = (assembled.label(&catch.handler), assembled.label(&catch.handler_end));
            let length = end_pc.checked_sub(start_pc).expect("a try range ends after it starts");
            let code_size = handler_end.checked_sub(handler_pc).expect("a handler ends after it starts");
            let block = AbcCatch { type_idx: catch.type_idx, handler_pc, code_size };
            match tries.iter_mut().find(|known| (known.start_pc, known.length) == (start_pc, length)) {
                Some(known) => known.catches.push(block),
                None => tries.push(AbcTry { start_pc, length, catches: vec![block] }),
            }
        }
        tries.extend(code.tries.iter().cloned());

        self.define(Sym::Code(r, f));
        self.uleb(code.num_vregs);
        self.uleb(code.num_args);
        self.count(assembled.bytes.len());
        self.count(tries.len());
        self.buf.extend_from_slice(&assembled.bytes);
        for block in &tries {
            self.uleb(block.start_pc);
            self.uleb(block.length);
            self.count(block.catches.len());
            for catch in &block.catches {
                // The type index is stored plus one; zero is a catch-all.
                self.uleb(catch.type_idx.map_or(0, |idx| idx + 1));
                self.uleb(catch.handler_pc);
                self.uleb(catch.code_size);
            }
        }
    }

    /// The opcode bytes of a line number program and the constant pool its
    /// opcodes read their arguments from.
    fn line_program(&mut self, ops: &[AbcLineOp]) -> (Vec<u8>, Vec<u8>) {
        const OPCODE_BASE: i64 = 0x0c;
        const LINE_BASE: i64 = -4;
        const LINE_RANGE: i64 = 15;
        let (mut program, mut pool) = (Vec::new(), Vec::new());
        for op in ops {
            match op {
                AbcLineOp::AdvancePc(delta) => {
                    program.push(0x01);
                    write_uleb128(&mut pool, *delta);
                }
                AbcLineOp::AdvanceLine(delta) => {
                    program.push(0x02);
                    write_sleb128(&mut pool, *delta);
                }
                AbcLineOp::StartLocal { reg, name, ty } => {
                    program.push(0x03);
                    write_sleb128(&mut program, *reg);
                    for text in [name, ty] {
                        write_uleb128(&mut pool, self.string_offset(text));
                    }
                }
                AbcLineOp::StartLocalExtended { reg, name, ty, signature } => {
                    program.push(0x04);
                    write_sleb128(&mut program, *reg);
                    for text in [name, ty, signature] {
                        write_uleb128(&mut pool, self.string_offset(text));
                    }
                }
                AbcLineOp::EndLocal(reg) => {
                    program.push(0x05);
                    write_sleb128(&mut program, *reg);
                }
                AbcLineOp::RestartLocal(reg) => {
                    program.push(0x06);
                    write_sleb128(&mut program, *reg);
                }
                AbcLineOp::SetPrologueEnd => program.push(0x07),
                AbcLineOp::SetEpilogueBegin => program.push(0x08),
                AbcLineOp::SetFile(file) => {
                    program.push(0x09);
                    write_uleb128(&mut pool, self.string_offset(file));
                }
                AbcLineOp::SetSourceCode(source) => {
                    program.push(0x0a);
                    write_uleb128(&mut pool, self.string_offset(source));
                }
                AbcLineOp::SetColumn(column) => {
                    program.push(0x0b);
                    write_uleb128(&mut pool, *column);
                }
                AbcLineOp::Special { pc_delta, line_delta } => {
                    let line = i64::from(*line_delta) - LINE_BASE;
                    assert!((0..LINE_RANGE).contains(&line), "special opcode: line delta {line_delta} is outside -4..=10");
                    let opcode = u8::try_from(OPCODE_BASE + line + i64::from(*pc_delta) * LINE_RANGE);
                    program.push(opcode.unwrap_or_else(|_| panic!("special opcode: pc delta {pc_delta} is outside 0..=15")));
                }
            }
        }
        program.push(0x00);
        (program, pool)
    }

    /// The line number program (unless an identical one was written
    /// already), then `uleb line_start, num_params, params…, pool_size`,
    /// the constant pool and `uleb line_program_idx`.
    fn debug_info(&mut self, r: usize, f: usize, debug: &AbcDebugInfo) {
        let (program, pool) = self.line_program(&debug.program);
        let program_idx = match self.line_programs.iter().position(|(known, _)| *known == program) {
            Some(idx) => idx,
            None => {
                let at = self.pos();
                self.buf.extend_from_slice(&program);
                self.line_programs.push((program, at));
                self.line_programs.len() - 1
            }
        };
        let params: Vec<u32> = debug.params.iter().map(|name| name.as_ref().map_or(0, |name| self.string_offset(name))).collect();
        self.define(Sym::DebugInfo(r, f));
        self.uleb(debug.line_start);
        self.count(params.len());
        params.into_iter().for_each(|name_off| self.uleb(name_off));
        self.count(pool.len());
        self.buf.extend_from_slice(&pool);
        self.count(program_idx);
    }

    /// Fill the tables and the header, resolve the references.
    fn finish(mut self) -> AbcFile {
        let plan = self.plan;
        let builder = plan.builder;
        for (at, sym) in std::mem::take(&mut self.fixups) {
            let offset = self.offset_of(&sym);
            self.patch(at, offset);
        }

        // `ItemContainer::class_map_` is a `std::map` keyed by name: byte order. A module comes
        // before the annotation interfaces named after it (`&m&` before `&m&.Marked`), which
        // is not the order of their descriptors (`L&m&.Marked;` before `L&m&;`).
        let mut by_name: Vec<(Vec<u8>, u32)> =
            plan.class_names.iter().map(|&name| (mutf8::encode(name), self.offset_of(&Sym::Class(name.to_owned())))).collect();
        by_name.sort();
        if builder.unsorted_class_index {
            by_name.reverse();
        }
        for (slot, (_, offset)) in by_name.into_iter().enumerate() {
            self.patch(self.tables.class_index + 4 * slot, offset);
        }

        let literal_offsets: Vec<u32> = (0..plan.literals.len()).map(|position| self.offset_of(&Sym::Literal(position))).collect();
        if let Some(index) = self.tables.literal_index {
            for (slot, &offset) in literal_offsets.iter().enumerate() {
                self.patch(index + 4 * slot, offset);
            }
        }
        for (slot, offset) in self.line_programs.iter().map(|&(_, offset)| offset).collect::<Vec<_>>().into_iter().enumerate() {
            self.patch(self.tables.line_program_index + 4 * slot, offset);
        }

        let file_size = self.pos();
        let region_layouts = self.regions(file_size);

        let word = |value: usize| u32::try_from(value).expect("ABC files are smaller than 4 GiB");
        let (literal_count, literal_index) = match self.tables.literal_index {
            Some(index) => (word(plan.literals.len()), word(index)),
            None => (INVALID_OFFSET, INVALID_OFFSET),
        };
        let header = [
            file_size,
            self.tables.foreign.0,
            self.tables.foreign.1,
            word(plan.class_names.len()),
            word(self.tables.class_index),
            word(self.line_programs.len()),
            word(self.tables.line_program_index),
            literal_count,
            literal_index,
            word(plan.regions.len()),
            word(self.tables.region_headers),
        ];
        self.buf[..8].copy_from_slice(&MAGIC);
        self.buf[12..16].copy_from_slice(&builder.version);
        for (slot, value) in header.into_iter().enumerate() {
            self.patch(16 + 4 * slot, value);
        }

        let layout = self.layout(region_layouts, &literal_offsets);
        let mut bytes = self.buf;
        let checksum = adler32(&bytes[12..]);
        // Any value but the right one will do for a stale checksum.
        let stored = if builder.stale_checksum { !checksum } else { checksum };
        bytes[8..12].copy_from_slice(&stored.to_le_bytes());
        if builder.encrypted {
            scramble_body(&mut bytes);
        }
        if let Some(len) = builder.truncated {
            bytes.truncate(len);
        }
        AbcFile { bytes, layout }
    }

    /// Write the region headers and tables. A region runs from its first
    /// item to the first item of the next one; the first also covers the
    /// foreign classes and the last runs to the end of the file, as
    /// `ItemContainer::RebuildIndexSection` has it.
    fn regions(&mut self, file_size: u32) -> Vec<AbcRegionLayout> {
        let plan = self.plan;
        let mut starts: Vec<u32> = plan
            .regions
            .iter()
            .map(|region| match region.start {
                RegionStart::Class(r) => self.class_offsets[r],
                RegionStart::Method(r, f) => self.method_offsets[r][f],
            })
            .collect();
        if let (Some(first), true) = (starts.first_mut(), self.tables.foreign.1 > 0) {
            *first = self.tables.foreign.0;
        }

        let word = |value: usize| u32::try_from(value).expect("ABC files are smaller than 4 GiB");
        let mut layouts = Vec::with_capacity(plan.regions.len());
        for (index, region) in plan.regions.iter().enumerate() {
            let [class_table, entity_table, field_table, proto_table] = self.tables.regions[index];
            let classes: Vec<u32> = region
                .primitives
                .iter()
                .map(|&code| u32::from(code))
                .chain(region.classes.iter().map(|&order| self.offset_of(&Sym::Class(plan.class_names[order].to_owned()))))
                .collect();
            let entities: Vec<u32> = region.entities.iter().map(|sym| self.offset_of(sym)).collect();
            let protos: Vec<u32> = region.protos.iter().map(|&args| self.offset_of(&Sym::Proto(args))).collect();
            for (table, entries) in [(class_table, &classes), (entity_table, &entities), (proto_table, &protos)] {
                for (slot, &entry) in entries.iter().enumerate() {
                    self.patch(table + 4 * slot, entry);
                }
            }
            let end = starts.get(index + 1).copied().unwrap_or(file_size);
            let (field_words, proto_words) = if plan.has_protos {
                ([0, word(field_table)], [word(protos.len()), word(proto_table)])
            } else {
                ([INVALID_OFFSET; 2], [INVALID_OFFSET; 2])
            };
            let header = [
                starts[index],
                end,
                word(classes.len()),
                word(class_table),
                word(entities.len()),
                word(entity_table),
                field_words[0],
                field_words[1],
                proto_words[0],
                proto_words[1],
            ];
            for (slot, value) in header.into_iter().enumerate() {
                self.patch(self.tables.region_headers + index * RegionHeader::SIZE + 4 * slot, value);
            }
            layouts.push(AbcRegionLayout { start: starts[index], end, entities, classes });
        }
        layouts
    }

    fn layout(&self, regions: Vec<AbcRegionLayout>, literal_offsets: &[u32]) -> AbcLayout {
        let plan = self.plan;
        let word = |value: usize| u32::try_from(value).expect("ABC files are smaller than 4 GiB");
        let mut layout = AbcLayout {
            class_index_off: word(self.tables.class_index),
            literal_array_index_off: self.tables.literal_index.map(word),
            region_headers_off: word(self.tables.region_headers),
            line_program_index_off: word(self.tables.line_program_index),
            regions,
            literal_arrays: literal_offsets[plan.declared_literals_base..].to_vec(),
            ..AbcLayout::default()
        };
        for (sym, &offset) in &self.offsets {
            match sym {
                Sym::Str(text) => drop(layout.strings.insert(text.clone(), offset)),
                Sym::Class(name) => drop(layout.classes.insert(name.clone(), offset)),
                Sym::Method(..)
                | Sym::Literal(_)
                | Sym::WideValue(..)
                | Sym::Proto(_)
                | Sym::Annotation(_)
                | Sym::Code(..)
                | Sym::DebugInfo(..) => {}
            }
        }
        for (r, record) in plan.builder.records.iter().enumerate() {
            for (f, field) in record.fields.iter().enumerate() {
                layout.fields.entry((record.name.clone(), field.name.clone())).or_insert(self.field_offsets[r][f]);
                let Some(&position) = plan.field_literals.get(&(r, f)) else { continue };
                let by_record = match plan.literals[position] {
                    LiteralItem::ScopeNames(_) => &mut layout.scope_names,
                    LiteralItem::Module(_) => &mut layout.module_records,
                    LiteralItem::Phases(_) => &mut layout.module_request_phases,
                    LiteralItem::Array(_) => unreachable!("fields do not own declared literal arrays"),
                };
                by_record.entry(record.name.clone()).or_insert(literal_offsets[position]);
            }
            for (f, function) in record.functions.iter().enumerate() {
                let method = MethodLayout {
                    offset: self.method_offsets[r][f],
                    region: word(plan.method_region[r][f]),
                    code: self.offsets.get(&Sym::Code(r, f)).copied(),
                    debug_info: self.offsets.get(&Sym::DebugInfo(r, f)).copied(),
                };
                layout.methods.entry((record.name.clone(), function.name.clone())).or_insert(method);
            }
        }
        layout
    }
}

pub(super) fn write(builder: &AbcBuilder) -> AbcFile {
    let plan = Plan::new(builder);
    let strings = Emitter::new(&plan, Vec::new(), false).run().strings;
    Emitter::new(&plan, strings, true).run().finish()
}
