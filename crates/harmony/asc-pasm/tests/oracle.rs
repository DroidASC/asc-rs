//! Cross-check against the official disassembler.
//!
//! `$ASC_ABC_PA` names files and directories holding ABC files and
//! `ark_disasm` listings of them: the tool's output as it comes, one file
//! per ABC file, with or without `--verbose`. A listing is paired with the
//! ABC file whose strings it dumps, whatever the files are called; listings
//! are read as a stream, they run to gigabytes. A part cut out of a listing
//! (it starts like one and lacks the string dump) is skipped and counted.
//! `$ASC_ABC_PA_ONLY` keeps the listings whose path contains it.
//!
//! `$ASC_ABC_PA_DIR` is the older input: a directory of `*.pa` parts that a
//! `--verbose` listing of `$ASC_ABC_PA_ABC` (default: `modules.abc` in
//! `$ASC_ABC_LARGE_SAMPLE`) was split into by hand. Without the variables
//! its test does nothing.
//!
//! `$ASC_ARK_DISASM` is the official tool itself: with it the files
//! `asc-fixture` writes are disassembled on the spot and compared the same
//! way, which checks the fixture writer too: the tool has to accept its
//! files.
//!
//! The oracle is compared with what `asc-abc` and `asc-arkisa` decode
//! (every function, instruction, operand, literal array, try block, field,
//! module record and source language; with `--verbose` also file offsets,
//! instruction bytes, line rows, column rows and the local variable table
//! with its parameter rows), and the structure of the `asc-pasm` listing
//! (offsets, mnemonics, labels, try ranges, source lines, variable names)
//! is compared with the oracle in turn. Divergences are counted per class;
//! the ones listed in [`KNOWN`] are not ours to fix.

mod common;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use asc_abc::{Abc, Class, ClassEntry, Code, ElementValue, FieldType, FieldValue, LineOp, Literal, Method, MethodTag, ModuleRecord};
use asc_arkisa::{Instruction, OperandKind, Value, walk};
use asc_fixture::abc::{
    AbcBuilder, AbcCode, AbcDebugInfo, AbcFunction, AbcLineOp, AbcRecord, Asm, INDEX_PAGE, Op, VERSION_13_0_1_0, call_graph_program,
    class_calls_program, class_hierarchy_program, packaged_entry_program, packaged_library_program, sample_program,
};
use asc_pasm::{Options, write_function};

/// Divergence classes that are not ours to fix, with the reason.
const KNOWN: &[(&str, &str)] = &[
    (
        "text: equal only after the oracle's re-encoding",
        "not the official tool: the hand-split parts were re-encoded on the way (undecodable bytes became U+FFFD, \\r became \\n); \
         the tool's own output has the bytes as they are",
    ),
    (
        "record: oracle prints a field name from its last `/` on",
        "Disassembler::SerializeFields passes field names through GetFileNameByPath",
    ),
];

#[derive(Default)]
struct Report {
    counts: BTreeMap<&'static str, u64>,
    divergences: BTreeMap<String, (u64, String)>,
}

impl Report {
    fn count(&mut self, what: &'static str) {
        *self.counts.entry(what).or_default() += 1;
    }

    fn add(&mut self, what: &'static str, n: u64) {
        *self.counts.entry(what).or_default() += n;
    }

    fn diverge(&mut self, class: &str, example: impl FnOnce() -> String) {
        let entry = self.divergences.entry(class.to_owned()).or_insert_with(|| (0, example()));
        entry.0 += 1;
    }

    fn check(&mut self, ok: bool, class: &str, example: impl FnOnce() -> String) -> bool {
        if !ok {
            self.diverge(class, example);
        }
        ok
    }
}

/// A record name the way the oracle writes it.
fn dotted(name: &[u8]) -> Vec<u8> {
    name.iter().map(|&b| if b == b'/' { b'.' } else { b }).collect()
}

/// `.language` of a record or function without a source language tag is
/// `DEFUALT_SOURCE_LANG`.
fn language_name(lang: Option<asc_abc::SourceLang>) -> &'static [u8] {
    match lang.map_or(0, |lang| lang.0) {
        0 => b"ECMAScript",
        1 => b"PandaAssembly",
        2 => b"JavaScript",
        3 => b"TypeScript",
        4 => b"ArkTS",
        _ => b"<unknown language>",
    }
}

fn lossy(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    if text.len() > 300 {
        let mut end = 300;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &text[..end])
    } else {
        text.into_owned()
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).rposition(|window| window == needle)
}

fn parse_hex(text: &[u8]) -> Option<u64> {
    let text = std::str::from_utf8(text).ok()?;
    u64::from_str_radix(text.strip_prefix("0x")?, 16).ok()
}

fn parse_dec(text: &[u8]) -> Option<u64> {
    std::str::from_utf8(text).ok()?.parse().ok()
}

/// C's `%g` with the default precision of 6, which is how a C++ stream
/// prints a double.
fn g6(value: f64) -> String {
    if value.is_nan() {
        return if value.is_sign_negative() { "-nan".into() } else { "nan".into() };
    }
    if value.is_infinite() {
        return if value > 0.0 { "inf".into() } else { "-inf".into() };
    }
    if value == 0.0 {
        return if value.is_sign_negative() { "-0".into() } else { "0".into() };
    }
    let sci = format!("{value:.5e}");
    let (mantissa, exponent) = sci.split_once('e').unwrap();
    let exponent: i32 = exponent.parse().unwrap();
    let strip = |digits: &str| {
        if digits.contains('.') { digits.trim_end_matches('0').trim_end_matches('.').to_owned() } else { digits.to_owned() }
    };
    if !(-4..6).contains(&exponent) {
        format!("{}e{}{:02}", strip(mantissa), if exponent < 0 { '-' } else { '+' }, exponent.abs())
    } else {
        strip(&format!("{value:.*}", usize::try_from(5 - exponent).unwrap()))
    }
}

/// How the listing writes an integer: one digit as is, otherwise hex and
/// decimal; a negative `i32` constant in decimal with its bit pattern.
/// Restated here, independently of the crate, as the format's definition.
fn listed_int(value: i64, signed_32: bool) -> String {
    match value {
        -9..=9 => value.to_string(),
        10.. => format!("{value:#x} ({value})"),
        _ if signed_32 => format!("{value} (u32 {:#x})", value as u32),
        _ => format!("-{:#x} ({value})", value.unsigned_abs()),
    }
}

fn listed_f64(value: f64) -> String {
    if value.is_nan() {
        "NaN".into()
    } else if value.is_infinite() {
        if value > 0.0 { "Infinity" } else { "-Infinity" }.into()
    } else if value.fract() == 0.0 && (10.0..9_007_199_254_740_992.0).contains(&value) {
        format!("{value:?} ({:#x})", value as u64)
    } else {
        format!("{value:?}")
    }
}

fn listed_name(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') => write!(out, "\\u{:04x}", u32::from(c)).unwrap(),
            c => out.push(c),
        }
    }
    out
}

fn listed_string(text: &str) -> String {
    format!("\"{}\"", listed_name(&text.replace('\\', "\\\\").replace('"', "\\\"")))
}

/// Everything of the file the oracle is compared with, keyed the way the
/// oracle names it: by file offset.
struct Subject<'a> {
    abc: Abc<'a>,
    classes: HashMap<u32, Class<'a>>,
    methods: HashMap<u32, (Class<'a>, Method<'a>)>,
    module_records: HashSet<u32>,
    /// Offsets of module request phase tables.
    phase_tables: HashSet<u32>,
    /// Methods by the `.function` line the oracle heads them with, and
    /// classes by their `.record` name, both in file order: the official
    /// tool keeps the first of each and drops the rest.
    signatures: HashMap<Vec<u8>, Vec<u32>>,
    records: HashMap<Vec<u8>, Vec<u32>>,
    /// Names of the classes the file only declares, as `.record` names.
    foreign: HashSet<Vec<u8>>,
}

impl<'a> Subject<'a> {
    fn load(abc: Abc<'a>) -> Subject<'a> {
        let mut subject = Subject {
            abc,
            classes: HashMap::new(),
            methods: HashMap::new(),
            module_records: HashSet::new(),
            phase_tables: HashSet::new(),
            signatures: HashMap::new(),
            records: HashMap::new(),
            foreign: HashSet::new(),
        };
        for entry in abc.classes().unwrap() {
            let class = match entry.unwrap() {
                ClassEntry::Local(class) => class,
                ClassEntry::Foreign(class) => {
                    subject.foreign.insert(dotted(ClassEntry::Foreign(class).name()));
                    continue;
                }
            };
            subject.classes.insert(class.offset(), class);
            subject.records.entry(dotted(class.name())).or_default().push(class.offset());
            if let Some(module) = class.module_record().unwrap() {
                subject.module_records.insert(module.offset());
            }
            if let Some(field) = class.field(asc_abc::record_field::MODULE_REQUEST_PHASE_IDX).unwrap() {
                let off = field.raw_value().unwrap();
                // One phase per module request.
                let requests = class.module_record().unwrap().map_or(0, |module| module.requests.len());
                assert_eq!(abc.module_request_phases(off).unwrap().len(), requests as usize, "phase table @{off:#x}");
                subject.phase_tables.insert(off);
            }
            for method in class.methods().unwrap() {
                let method = method.unwrap();
                subject.methods.insert(method.offset(), (class, method));
                let header = subject.function_header(&method);
                subject.signatures.entry(header).or_default().push(method.offset());
            }
        }
        subject
    }

    fn string(&self, off: u32) -> &'a [u8] {
        self.abc.string(off).map_or(b"<bad string>", |string| string.bytes)
    }

    /// The items of the array an annotation value is, `["a", "b"]`, and the
    /// type its items say it has, `panda.String[]`: an empty one says none.
    fn array_text(&self, off: u32) -> (String, Vec<u8>) {
        let mut kind = String::new();
        let mut text = b"[".to_vec();
        for (index, literal) in self.abc.literal_array(off).unwrap().iter().enumerate() {
            let (item_kind, item) = match literal.unwrap() {
                Literal::Bool(value) => ("u1".to_owned(), format!("{}", u8::from(value)).into_bytes()),
                Literal::Double(value) => ("f64".to_owned(), g6(value).into_bytes()),
                Literal::String(off) => ("panda.String".to_owned(), [b"\"", self.string(off), b"\""].concat()),
                Literal::LiteralArray(off) => self.array_text(off),
                other => (format!("<{other:?}>"), Vec::new()),
            };
            if index > 0 {
                text.extend_from_slice(b", ");
            }
            text.extend_from_slice(&item);
            kind = format!("{item_kind}[]");
        }
        text.push(b']');
        (kind, text)
    }

    /// The type and value of an annotation element as the oracle writes
    /// them: `f64` and `3`, `panda.String[]` and `["x"]`.
    fn element_text(&self, element: &asc_abc::AnnotationElement) -> (String, Vec<u8>) {
        match element.typed(&self.abc).unwrap() {
            ElementValue::Bool(value) => ("u1".to_owned(), format!("{}", u8::from(value)).into_bytes()),
            ElementValue::Int(value) => ("u32".to_owned(), format!("{value:#x}").into_bytes()),
            ElementValue::F64(value) => ("f64".to_owned(), g6(value).into_bytes()),
            ElementValue::String(off) => ("panda.String".to_owned(), [b"\"", self.string(off), b"\""].concat()),
            ElementValue::Array(off) => self.array_text(off),
            ElementValue::Other(value) => (format!("<tag {:?}>", char::from(element.tag)), format!("{value:#x}").into_bytes()),
        }
    }

    /// The type and default value of a field of an annotation interface as
    /// the oracle writes them; `None` for a field without a value.
    fn default_text(&self, field: &asc_abc::Field<'a>) -> Option<(String, Vec<u8>)> {
        let raw = match field.value()? {
            FieldValue::Int(value) => u32::from_le_bytes(value.to_le_bytes()),
            FieldValue::Raw(value) => value,
        };
        Some(match field.field_type().unwrap() {
            FieldType::U1 => ("u1".to_owned(), format!("{raw}").into_bytes()),
            FieldType::F64 => ("f64".to_owned(), g6(f64::from_bits(field.wide_value().unwrap()?)).into_bytes()),
            FieldType::Class(off) => match self.string(off) {
                b"Lpanda.String;" => ("panda.String".to_owned(), [b"\"", self.string(raw), b"\""].concat()),
                descriptor if descriptor.starts_with(b"[") => {
                    let depth = descriptor.iter().take_while(|&&b| b == b'[').count();
                    let item = match &descriptor[depth..] {
                        b"D" => "f64",
                        b"Z" => "u1",
                        b"Lpanda.String;" => "panda.String",
                        _ => "<unknown>",
                    };
                    (format!("{item}{}", "[]".repeat(depth)), self.array_text(raw).1)
                }
                _ => return None,
            },
            _ => return None,
        })
    }

    /// The module record of `_GLOBAL`, the record of a file that was not merged.
    fn unmerged_module_record(&self) -> Option<u32> {
        let global = self.abc.find_record(asc_abc::unmerged::GLOBAL).ok()??.local()?;
        Some(global.module_record().ok()??.offset())
    }

    /// `{ N [ tag:value, ... ]}` as `Disassembler::SerializeLiteralArray`
    /// writes it; nothing at all for an empty array.
    fn literal_text(&self, off: u32, flags: &mut LiteralFlags) -> Vec<u8> {
        let array = self.abc.literal_array(off).unwrap();
        let mut items = Vec::new();
        let mut count = 0;
        let quoted = |tag: &str, off: u32| [tag.as_bytes(), b":\"", self.string(off), b"\""].concat();
        let named = |tag: &str, off: u32| {
            let name = self.abc.method(off).and_then(|method| method.name()).map_or(&b"<bad method>"[..], |name| name.bytes);
            [tag.as_bytes(), b":", name].concat()
        };
        for literal in &array {
            let item = match literal.unwrap() {
                Literal::Bool(value) => format!("u1:{}", u8::from(value)).into_bytes(),
                Literal::Integer(value) => format!("i32:{value}").into_bytes(),
                Literal::Double(value) => format!("f64:{}", g6(value)).into_bytes(),
                Literal::String(off) => quoted("string", off),
                Literal::Method(off) => named("method", off),
                Literal::Getter(off) => named("getter", off),
                Literal::Setter(off) => named("setter", off),
                Literal::GeneratorMethod(off) => named("generator_method", off),
                Literal::MethodAffiliate(params) => format!("method_affiliate:{params}").into_bytes(),
                Literal::Null(value) => format!("null_value:{}", i8::from_le_bytes([value])).into_bytes(),
                Literal::Accessor(value) => format!("accessor:{}", i8::from_le_bytes([value])).into_bytes(),
                Literal::LiteralBufferIndex(index) => format!("lit_index:{}", i32::from_le_bytes(index.to_le_bytes())).into_bytes(),
                Literal::LiteralArray(off) => format!("lit_offset:{off:#x}").into_bytes(),
                Literal::BuiltinTypeIndex(index) => format!("builtin_type:{index}").into_bytes(),
                Literal::EtsImplements(off) => quoted("ets_implements", off),
                // `FillLiteralData` drops these.
                Literal::TagValue(_) => {
                    flags.tag_values += 1;
                    continue;
                }
                // The official tool has no rendering for these (`UNREACHABLE`).
                Literal::Float(_) | Literal::AsyncGeneratorMethod(_) | Literal::TypedArray { .. } => {
                    flags.unrenderable += 1;
                    b"<unrenderable>".to_vec()
                }
            };
            items.extend_from_slice(&item);
            items.extend_from_slice(b", ");
            count += 1;
        }
        if count == 0 {
            return Vec::new();
        }
        let mut text = format!("{{ {count} [ ").into_bytes();
        text.extend_from_slice(&items);
        text.extend_from_slice(b"]}");
        text
    }

    /// The literal array as the listing writes it, unbounded.
    fn listed_literal(&self, off: u32) -> String {
        let array = self.abc.literal_array(off).unwrap();
        if array.is_empty() {
            return "[]".into();
        }
        let text = |off: u32| listed_string(&self.abc.string(off).unwrap().to_str());
        let name = |off: u32| listed_name(&self.abc.method(off).unwrap().name().unwrap().to_str());
        let items: Vec<String> = array
            .iter()
            .map(|literal| match literal.unwrap() {
                Literal::Bool(value) => value.to_string(),
                Literal::Integer(value) => listed_int(i64::from(value), true),
                Literal::Double(value) => listed_f64(value),
                Literal::Float(value) => format!("{}f", listed_f64(f64::from(value))),
                Literal::String(off) => text(off),
                Literal::Null(_) => "null".into(),
                Literal::Method(off) => format!("method:{}", name(off)),
                Literal::Getter(off) => format!("getter:{}", name(off)),
                Literal::Setter(off) => format!("setter:{}", name(off)),
                Literal::GeneratorMethod(off) => format!("generator_method:{}", name(off)),
                Literal::AsyncGeneratorMethod(off) => format!("async_generator_method:{}", name(off)),
                Literal::MethodAffiliate(params) => format!("method_affiliate:{params}"),
                Literal::Accessor(value) => format!("accessor:{value}"),
                Literal::LiteralBufferIndex(index) => format!("lit_index:{index}"),
                Literal::LiteralArray(off) => format!("literal_array:@{off:#x}"),
                Literal::BuiltinTypeIndex(index) => format!("builtin_type:{index}"),
                Literal::EtsImplements(off) => format!("ets_implements:{}", text(off)),
                Literal::TagValue(value) => format!("tag_value:{value}"),
                Literal::TypedArray { tag, data_off } => format!("typed_array:{tag:#x}@{data_off:#x}"),
            })
            .collect();
        format!("[ {} ]", items.join(", "))
    }

    /// A module record as `Disassembler::SerializeModuleLiteralArray`
    /// writes it.
    fn module_text(&self, module: &ModuleRecord<'a>) -> Vec<u8> {
        let request = |idx: u16| module.request(idx).map_or(&b"<bad request>"[..], |off| self.string(off));
        let mut entries: Vec<Vec<u8>> = Vec::new();
        let entry = |fields: &[(&str, &[u8])]| {
            let mut text = Vec::new();
            for (i, (key, value)) in fields.iter().enumerate() {
                text.extend_from_slice(if i == 0 { b"" } else { b", " });
                text.extend_from_slice(key.as_bytes());
                text.extend_from_slice(b": ");
                text.extend_from_slice(value);
            }
            text
        };
        for import in module.regular_imports.iter() {
            entries.push(entry(&[
                ("ModuleTag", b"REGULAR_IMPORT"),
                ("local_name", self.string(import.local_name_off)),
                ("import_name", self.string(import.import_name_off)),
                ("module_request", request(import.module_request_idx)),
            ]));
        }
        for import in module.namespace_imports.iter() {
            entries.push(entry(&[
                ("ModuleTag", b"NAMESPACE_IMPORT"),
                ("local_name", self.string(import.local_name_off)),
                ("module_request", request(import.module_request_idx)),
            ]));
        }
        for export in module.local_exports.iter() {
            entries.push(entry(&[
                ("ModuleTag", b"LOCAL_EXPORT"),
                ("local_name", self.string(export.local_name_off)),
                ("export_name", self.string(export.export_name_off)),
            ]));
        }
        for export in module.indirect_exports.iter() {
            entries.push(entry(&[
                ("ModuleTag", b"INDIRECT_EXPORT"),
                ("export_name", self.string(export.export_name_off)),
                ("import_name", self.string(export.import_name_off)),
                ("module_request", request(export.module_request_idx)),
            ]));
        }
        for export in module.star_exports.iter() {
            entries.push(entry(&[("ModuleTag", b"STAR_EXPORT"), ("module_request", request(export.module_request_idx))]));
        }
        let mut text = format!("{{ {} [\n\tMODULE_REQUEST_ARRAY: {{\n", entries.len()).into_bytes();
        for (i, off) in module.requests.iter().enumerate() {
            text.extend_from_slice(format!("\t\t{i} : ").as_bytes());
            text.extend_from_slice(self.string(off));
            text.extend_from_slice(b",\n");
        }
        text.extend_from_slice(b"\t};\n");
        for entry in entries {
            text.push(b'\t');
            text.extend_from_slice(&entry);
            text.extend_from_slice(b";\n");
        }
        text.extend_from_slice(b"]}");
        text
    }

    /// `<record with dots>.<raw name>`, the way the oracle names a function;
    /// the raw name alone for a function of `_GLOBAL`, the record of a file
    /// that was not merged (`GetFullMethodName` leaves that one out).
    fn full_method_name(&self, method: &Method<'a>) -> Vec<u8> {
        let mut name: Vec<u8> = match method.class_off().ok().and_then(|off| self.abc.string(off).ok()) {
            Some(descriptor) => {
                let record = descriptor.bytes.strip_prefix(b"L").and_then(|d| d.strip_suffix(b";")).unwrap_or(descriptor.bytes);
                if record == asc_abc::unmerged::GLOBAL {
                    return method.name().map_or(b"<bad name>".to_vec(), |name| name.bytes.to_vec());
                }
                record.iter().map(|&b| if b == b'/' { b'.' } else { b }).collect()
            }
            None => b"<bad class>".to_vec(),
        };
        name.push(b'.');
        name.extend_from_slice(method.name().map_or(b"<bad name>", |name| name.bytes));
        name
    }

    /// `.function any <name>(any a0, any a1) <static>`
    fn function_header(&self, method: &Method<'a>) -> Vec<u8> {
        let mut header = b".function any ".to_vec();
        header.extend_from_slice(&self.full_method_name(method));
        header.push(b'(');
        for i in 0..method.code().ok().flatten().map_or(0, |code| code.num_args) {
            header.extend_from_slice(format!("{}any a{i}", if i == 0 { "" } else { ", " }).as_bytes());
        }
        header.extend_from_slice(b") <static>");
        header
    }

    /// `name:(any,any,...)`, one `any` per argument of the code item.
    fn method_signature(&self, off: u32) -> Vec<u8> {
        let Ok(method) = self.abc.method(off) else { return b"<bad method>".to_vec() };
        let mut text = self.full_method_name(&method);
        let args = method.code().ok().flatten().map_or(0, |code| code.num_args);
        text.extend_from_slice(b":(");
        for i in 0..args {
            text.extend_from_slice(if i == 0 { b"any" } else { b",any" });
        }
        text.push(b')');
        text
    }
}

#[derive(Default)]
struct LiteralFlags {
    tag_values: u64,
    unrenderable: u64,
}

/// One instruction of the oracle.
struct OracleInsn<'t> {
    text: &'t [u8],
    /// File offset: stated by a `--verbose` listing, otherwise ours.
    offset: u32,
    /// The bytes a `--verbose` listing states.
    raw: Option<Vec<u8>>,
}

/// Split `<text> # offset: 0x…, [FORMAT]....[0x.. 0x..]`.
fn parse_insn(line: &[u8]) -> Option<OracleInsn<'_>> {
    let marker = b" # offset: 0x";
    let at = rfind(line, marker)?;
    let rest = &line[at + marker.len() - 2..];
    let comma = find(rest, b", [")?;
    let offset = u32::try_from(parse_hex(&rest[..comma])?).ok()?;
    let rest = &rest[comma + 3..];
    let rest = &rest[find(rest, b"]")? + 1..];
    let rest = &rest[rest.iter().position(|&b| b != b'.')?..];
    let bytes = rest.strip_prefix(b"[")?.strip_suffix(b"]")?;
    let raw = bytes.split(|&b| b == b' ').map(|byte| parse_hex(byte).and_then(|v| u8::try_from(v).ok())).collect::<Option<Vec<u8>>>()?;
    let mut text = &line[..at];
    while let Some(trimmed) = text.strip_suffix(b" ") {
        text = trimmed;
    }
    Some(OracleInsn { text: text.strip_prefix(b"\t").unwrap_or(text), offset, raw: Some(raw) })
}

/// A `.catchall` / `.catch` line: the type of a `.catch`, then the label names.
type OracleCatch<'t> = (Option<&'t [u8]>, Vec<&'t [u8]>);

/// One `.function` block of the oracle.
#[derive(Default)]
struct OracleFunction<'t> {
    header: &'t [u8],
    /// From a `--verbose` listing: offsets, bytes and the line tables are stated.
    verbose: bool,
    /// A `:` line follows the last instruction: `AddLabels` writes a label
    /// that stands at the end of the code without its name.
    end_label: bool,
    insns: Vec<OracleInsn<'t>>,
    /// Label name and the index of the instruction it stands in front of.
    labels: HashMap<&'t [u8], usize>,
    /// The label names of each `.catchall` / `.catch` line, with the type of a `.catch`.
    catches: Vec<OracleCatch<'t>>,
    lines: Vec<(u64, u64)>,
    columns: Vec<(u64, u64)>,
    /// The text under `LOCAL_VARIABLE_TABLE:`, heading and rows; a name is
    /// written as it is, line feeds included.
    locals: Option<&'t [u8]>,
}

/// Heads the last table of a `--verbose` function.
const LOCALS_TITLE: &[u8] = b"#   LOCAL_VARIABLE_TABLE:";

/// `File::EntityId::IsValid`: an offset inside the file header names nothing.
const HEADER_SIZE: u32 = 60;

fn is_label_name(name: &[u8]) -> bool {
    let known = [&b"jump_label_"[..], b"try_begin_label_", b"try_end_label_", b"handler_begin_label_", b"handler_end_label_"];
    known.iter().any(|prefix| {
        name.strip_prefix(*prefix).is_some_and(|rest| !rest.is_empty() && rest.iter().all(|b| b.is_ascii_digit() || *b == b'_'))
    })
}

fn is_label(line: &[u8]) -> Option<&[u8]> {
    line.strip_suffix(b":").filter(|name| is_label_name(name))
}

/// What splitting a listing into parts by hand did to its text: undecodable
/// bytes (MUTF-8 surrogates, the two-byte NUL) became U+FFFD, and carriage
/// returns became line feeds. The official tool writes the bytes as they are.
fn reencoded(bytes: &[u8]) -> Vec<u8> {
    String::from_utf8_lossy(bytes).replace("\r\n", "\n").replace('\r', "\n").into_bytes()
}

/// Length of `expected` at the start of `rest`, as is or re-encoded.
fn match_prefix(report: &mut Report, rest: &[u8], expected: &[u8]) -> Option<usize> {
    if rest.starts_with(expected) {
        return Some(expected.len());
    }
    let reencoded = reencoded(expected);
    rest.starts_with(&reencoded).then(|| {
        report.diverge("text: equal only after the oracle's re-encoding", || lossy(expected));
        reencoded.len()
    })
}

/// The lines of a listing of any size, one at a time.
struct Lines<R> {
    reader: R,
    line: Vec<u8>,
    held: bool,
}

impl<R: BufRead> Lines<R> {
    fn new(reader: R) -> Lines<R> {
        Lines { reader, line: Vec::new(), held: false }
    }

    /// The next line without its line feed.
    fn next(&mut self) -> Option<&[u8]> {
        if self.held {
            self.held = false;
            return Some(&self.line);
        }
        self.line.clear();
        if self.reader.read_until(b'\n', &mut self.line).unwrap() == 0 {
            return None;
        }
        if self.line.last() == Some(&b'\n') {
            self.line.pop();
        }
        Some(&self.line)
    }

    /// Have [`Lines::next`] return the same line once more.
    fn unread(&mut self) {
        self.held = true;
    }
}

fn trim_line_feeds(mut text: &[u8]) -> &[u8] {
    while let Some(trimmed) = text.strip_suffix(b"\n") {
        text = trimmed;
    }
    text
}

fn catch_line(line: &[u8]) -> Option<OracleCatch<'_>> {
    fn labels(rest: &[u8]) -> impl Iterator<Item = &[u8]> {
        rest.split(|&b| b == b',').map(|label| label.strip_prefix(b" ").unwrap_or(label))
    }
    if let Some(rest) = line.strip_prefix(b".catchall ") {
        Some((None, labels(rest).collect()))
    } else if let Some(rest) = line.strip_prefix(b".catch ") {
        let mut parts = labels(rest);
        let kind = parts.next();
        Some((kind, parts.collect()))
    } else {
        None
    }
}

struct Comparer<'a> {
    subject: Subject<'a>,
    report: Report,
    seen_methods: HashSet<u32>,
    seen_classes: HashSet<u32>,
    seen_literals: HashSet<u32>,
    /// Literal arrays an instruction of a compared function names.
    used_literals: HashSet<u32>,
    opcodes: BTreeMap<(Option<u8>, u8), (&'static str, u64)>,
    literal_flags: LiteralFlags,
    listing: String,
    /// The instruction lines the listing of the current function should have.
    listed: Vec<String>,
}

impl<'a> Comparer<'a> {
    fn new(abc: Abc<'a>) -> Comparer<'a> {
        Comparer {
            subject: Subject::load(abc),
            report: Report::default(),
            seen_methods: HashSet::new(),
            seen_classes: HashSet::new(),
            seen_literals: HashSet::new(),
            used_literals: HashSet::new(),
            opcodes: BTreeMap::new(),
            literal_flags: LiteralFlags::default(),
            listing: String::new(),
            listed: Vec::new(),
        }
    }

    /// One listing file: the tool's whole output, or a part of one.
    fn file<R: BufRead>(&mut self, name: &str, lines: &mut Lines<R>) {
        enum Section {
            Top,
            Literals,
            Strings,
        }
        let mut section = Section::Top;
        // The literal or string entry being collected; either may span lines.
        let mut entry: Option<Vec<u8>> = None;
        let mut annotations: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        // The `.language` line in front of a record or function; the split
        // parts do not have one everywhere.
        let mut language: Option<Vec<u8>> = None;

        while let Some(line) = lines.next() {
            match section {
                Section::Literals => {
                    let starts = {
                        let mut parts = line.splitn(3, |&b| b == b' ');
                        matches!((parts.next().map(parse_dec), parts.next().map(parse_hex)), (Some(Some(_)), Some(Some(_))))
                    };
                    let ends = line.starts_with(b"# ====");
                    if starts || ends {
                        let next = (!ends).then(|| line.to_vec());
                        if let Some(done) = std::mem::replace(&mut entry, next) {
                            self.literal_entry(trim_line_feeds(&done));
                        }
                        if ends {
                            section = Section::Top;
                        }
                    } else if let Some(entry) = &mut entry {
                        entry.push(b'\n');
                        entry.extend_from_slice(line);
                    }
                    continue;
                }
                Section::Strings => {
                    // `[offset:0x…, name_value:<text>]`
                    if line.starts_with(b"[offset:0x") {
                        let next = Some(line.to_vec());
                        if let Some(done) = std::mem::replace(&mut entry, next) {
                            self.string_entry(&done);
                        }
                    } else if let Some(entry) = &mut entry {
                        entry.push(b'\n');
                        entry.extend_from_slice(line);
                    }
                    continue;
                }
                Section::Top => {}
            }

            if line.starts_with(b".function ") {
                let header = line.to_vec();
                if let Some(method) = self.read_function(&header, language.take().as_deref(), lines) {
                    for (class, value) in &annotations {
                        self.annotation(method, class, value);
                    }
                }
                annotations.clear();
            } else if let Some(name) = line.strip_prefix(b".record ").and_then(|rest| rest.strip_suffix(b" <external>")) {
                // A class the file only declares: a header without a body.
                self.report.count("external records in oracle");
                let ours = self.subject.foreign.contains(name);
                self.report.check(ours, "record: external in the oracle, not a foreign class of ours", || lossy(name));
                language = None;
                annotations.clear();
            } else if line.starts_with(b".record ") {
                let header = line.to_vec();
                let mut fields: Vec<Vec<u8>> = Vec::new();
                while let Some(field) = lines.next() {
                    if field == b"}" {
                        break;
                    }
                    fields.push(field.to_vec());
                }
                self.record(&header, &fields, language.take().as_deref());
                annotations.clear();
            } else if line.starts_with(b"L") && line.ends_with(b":") {
                // An annotation block stands in front of the function it belongs to.
                let class = line[..line.len() - 1].to_vec();
                loop {
                    match lines.next().map(|value| value.starts_with(b"\t").then(|| value.to_vec())) {
                        Some(Some(value)) => annotations.push((class.clone(), value)),
                        Some(None) => {
                            lines.unread();
                            break;
                        }
                        None => break,
                    }
                }
            } else if let Some(stated) = line.strip_prefix(b".language ") {
                language = Some(stated.to_vec());
            } else if line == b"# LITERALS" {
                section = Section::Literals;
            } else if line == b"# STRING" {
                section = Section::Strings;
            } else if !(line.is_empty() || line.starts_with(b"#")) {
                let shape: String = lossy(line).chars().take(12).collect();
                let example = format!("{name}: {}", lossy(line));
                self.report.diverge(&format!("oracle: unknown top-level line `{shape}`"), || example);
            }
        }
        match (section, entry) {
            (Section::Strings, Some(done)) => self.string_entry(&done),
            (Section::Literals, Some(done)) => self.literal_entry(trim_line_feeds(&done)),
            _ => {}
        }
    }

    /// A `.function` block from its header to the closing brace; returns the
    /// method offset when the function is one of ours.
    fn read_function<R: BufRead>(&mut self, header: &[u8], language: Option<&[u8]>, lines: &mut Lines<R>) -> Option<u32> {
        if find(header, b" { # offset: 0x").is_some() {
            // `--verbose`: every instruction line ends in its offset and
            // bytes, which is what tells a line break inside a string operand
            // from the end of the instruction.
            let mut body = Vec::new();
            let (mut pending, mut code) = (false, true);
            loop {
                let line = lines.next().expect("unterminated function");
                if pending {
                    pending = parse_insn(line).is_none();
                } else if line == b"}" {
                    break;
                } else if line == b"#   CODE:" {
                    code = true;
                } else if line == b"#   LINE_NUMBER_TABLE:" || line == b"#   COLUMN_NUMBER_TABLE:" || line == LOCALS_TITLE {
                    code = false;
                } else if code && line.starts_with(b"\t") {
                    pending = parse_insn(line).is_none();
                }
                body.extend_from_slice(line);
                body.push(b'\n');
            }
            let oracle = self.verbose_function(header, &body);
            return self.function(&oracle, None, language);
        }

        // Without offsets a function is found by its signature, and an
        // instruction spans as many lines as its operands have line feeds.
        let signature = header.strip_suffix(b" {").unwrap_or(header);
        let Some(method_off) = self.subject.signatures.get(signature).map(|methods| methods[0]) else {
            self.report.count("functions in oracle");
            self.report.diverge("function: signature is not a method of ours", || lossy(header));
            Self::skip_block(lines);
            return None;
        };
        let (_, method) = self.subject.methods[&method_off];
        let code = method.code().unwrap();
        let ours: Vec<Instruction<'_>> = match code.as_ref().map_or(Ok(Vec::new()), |code| walk(code.instructions()).collect()) {
            Ok(insns) => insns,
            Err(error) => {
                self.report.count("functions in oracle");
                self.seen_methods.insert(method_off);
                self.report.diverge("instructions: our walk fails", || format!("{}: {error}", lossy(header)));
                Self::skip_block(lines);
                return Some(method_off);
            }
        };
        let insns_off = code.as_ref().map_or(0, Code::instructions_off);

        let mut text: Vec<u8> = Vec::new();
        let mut insns: Vec<(usize, usize, usize)> = Vec::new();
        let mut labels: Vec<(usize, usize, usize)> = Vec::new();
        let mut catches: Vec<(usize, usize)> = Vec::new();
        let mut stray = 0u64;
        let (mut ended, mut end_label) = (false, false);
        'insns: for insn in &ours {
            let extra = self.operand_line_feeds(&method, insn);
            loop {
                let line = lines.next().expect("unterminated function");
                let start = text.len();
                if let Some(label) = is_label(line) {
                    text.extend_from_slice(label);
                    labels.push((start, text.len(), insns.len()));
                } else if let Some(first) = line.strip_prefix(b"\t") {
                    text.extend_from_slice(first);
                    for _ in 0..extra {
                        text.push(b'\n');
                        text.extend_from_slice(lines.next().expect("unterminated function"));
                    }
                    insns.push((start, text.len(), insn.pc));
                    break;
                } else {
                    ended = line == b"}";
                    if !ended {
                        lines.unread();
                    }
                    break 'insns;
                }
            }
        }
        while !ended {
            let line = lines.next().expect("unterminated function");
            let start = text.len();
            if line == b"}" {
                ended = true;
            } else if line == b":" {
                end_label = true;
            } else if let Some(label) = is_label(line) {
                text.extend_from_slice(label);
                labels.push((start, text.len(), insns.len()));
            } else if line.starts_with(b".catchall ") || line.starts_with(b".catch ") {
                text.extend_from_slice(line);
                catches.push((start, text.len()));
            } else if !line.is_empty() {
                stray += 1;
            }
        }
        if insns.len() != ours.len() || stray != 0 {
            self.report.count("functions in oracle");
            self.seen_methods.insert(method_off);
            self.report.diverge("instructions: count differs", || {
                format!("{}: oracle {} and {stray} more lines, ours {}", lossy(header), insns.len(), ours.len())
            });
            return Some(method_off);
        }
        let oracle = OracleFunction {
            header,
            verbose: false,
            end_label,
            insns: insns
                .iter()
                .map(|&(from, to, pc)| OracleInsn { text: &text[from..to], offset: insns_off + u32::try_from(pc).unwrap(), raw: None })
                .collect(),
            labels: labels.iter().map(|&(from, to, index)| (&text[from..to], index)).collect(),
            catches: catches.iter().filter_map(|&(from, to)| catch_line(&text[from..to])).collect(),
            lines: Vec::new(),
            columns: Vec::new(),
            locals: None,
        };
        self.function(&oracle, Some(method_off), language)
    }

    /// Skip to the closing brace of a block that cannot be followed.
    fn skip_block<R: BufRead>(lines: &mut Lines<R>) {
        while lines.next().is_some_and(|line| line != b"}") {}
    }

    /// How many line feeds the oracle's text of the instruction's operands has.
    fn operand_line_feeds(&self, method: &Method<'a>, insn: &Instruction<'_>) -> usize {
        let feeds = |text: &[u8]| text.iter().filter(|&&b| b == b'\n').count();
        insn.operands()
            .map(|value| match value {
                Value::StringId(id) => feeds(self.subject.string(Self::resolve(method, id))),
                Value::MethodId(id) => feeds(&self.subject.method_signature(Self::resolve(method, id))),
                Value::LiteralArrayId(id) => feeds(&self.subject.literal_text(Self::resolve(method, id), &mut LiteralFlags::default())),
                _ => 0,
            })
            .sum()
    }

    /// The body of a `--verbose` function, line by line.
    fn verbose_function<'t>(&mut self, header: &'t [u8], body: &'t [u8]) -> OracleFunction<'t> {
        #[derive(PartialEq)]
        enum Mode {
            Code,
            Lines,
            Columns,
        }
        let mut current = OracleFunction { header, verbose: true, ..OracleFunction::default() };
        let mut mode = Mode::Code;
        let mut pending: Option<usize> = None;
        let mut offset = 0usize;
        for line in body.split(|&b| b == b'\n') {
            let start = offset;
            offset += line.len() + 1;
            if let Some(from) = pending {
                // Inside an instruction whose string operand contains line breaks.
                if parse_insn(line).is_some() {
                    match parse_insn(&body[from..start + line.len()]) {
                        Some(insn) => current.insns.push(insn),
                        None => self.report.diverge("oracle: unparsable instruction", || lossy(&body[from..start + line.len()])),
                    }
                    pending = None;
                }
            } else if line == b"#   CODE:" {
                mode = Mode::Code;
            } else if line == b"#   LINE_NUMBER_TABLE:" {
                mode = Mode::Lines;
            } else if line == b"#   COLUMN_NUMBER_TABLE:" {
                mode = Mode::Columns;
            } else if line == LOCALS_TITLE {
                // The last table of a function, up to its closing brace.
                current.locals = Some(body.get(offset..).unwrap_or_default());
                break;
            } else if let Some(row) = line.strip_prefix(b"#\tline ").or_else(|| line.strip_prefix(b"#\tcolumn ")) {
                let mut parts = row.split(|&b| b == b':');
                match (parts.next().and_then(parse_dec), parts.next().and_then(|pc| parse_dec(pc.strip_prefix(b" ")?))) {
                    (Some(value), Some(pc)) if mode == Mode::Lines => current.lines.push((value, pc)),
                    (Some(value), Some(pc)) => current.columns.push((value, pc)),
                    _ => self.report.diverge("oracle: unparsable table row", || lossy(line)),
                }
            } else if let Some(catch) = catch_line(line) {
                current.catches.push(catch);
            } else if line == b":" {
                current.end_label = true;
            } else if let Some(label) = is_label(line) {
                current.labels.insert(label, current.insns.len());
            } else if line.starts_with(b"\t") && mode == Mode::Code {
                match parse_insn(line) {
                    Some(insn) => current.insns.push(insn),
                    None => pending = Some(start),
                }
            } else if !line.is_empty() {
                self.report.diverge("oracle: unknown line in a function", || lossy(line));
            }
        }
        current
    }

    /// `[offset:0x<offset>, name_value:<text>]` of the string dump.
    fn string_entry(&mut self, entry: &[u8]) {
        let mut entry = entry;
        while let Some(trimmed) = entry.strip_suffix(b"\n") {
            entry = trimmed;
        }
        self.report.count("strings compared (dump)");
        let parsed = entry.strip_prefix(b"[offset:").and_then(|rest| rest.strip_suffix(b"]")).and_then(|rest| {
            let comma = find(rest, b", name_value:")?;
            Some((u32::try_from(parse_hex(&rest[..comma])?).ok()?, &rest[comma + 13..]))
        });
        let Some((off, text)) = parsed else {
            return self.report.diverge("oracle: unparsable string entry", || lossy(entry));
        };
        let ours = self.subject.abc.string(off).map(|string| string.bytes);
        let same = ours.as_ref().is_ok_and(|ours| match_prefix(&mut self.report, text, ours) == Some(text.len()));
        if self
            .report
            .check(same, "string dump: contents differ", || format!("@{off:#x} oracle `{}` ours {:?}", lossy(text), ours.map(lossy)))
        {
            self.report.count("string dump entries identical");
        }
    }

    /// `<index> 0x<offset> <array>` of the literal dump.
    fn literal_entry(&mut self, entry: &[u8]) {
        let mut parts = entry.splitn(3, |&b| b == b' ');
        let (Some(index), Some(off), Some(text)) = (parts.next().and_then(parse_dec), parts.next().and_then(parse_hex), parts.next())
        else {
            return self.report.diverge("oracle: unparsable literal entry", || lossy(entry));
        };
        let off = u32::try_from(off).unwrap();
        self.seen_literals.insert(off);
        // Without the header's index the official tool numbers the arrays it
        // collects in the order of an unordered set.
        if let Some(table) = self.subject.abc.literal_array_index().unwrap() {
            let named = table.get(u32::try_from(index).unwrap());
            self.report.check(named == Some(off), "literal dump: index does not name this offset", || lossy(entry));
        }
        let ours = if self.subject.module_records.contains(&off) {
            self.report.count("module records compared");
            self.subject.module_text(&self.subject.abc.module_record(off).unwrap())
        } else {
            self.report.count("literal arrays compared (dump)");
            self.subject.literal_text(off, &mut self.literal_flags)
        };
        let same = match_prefix(&mut self.report, text, &ours) == Some(text.len());
        if self
            .report
            .check(same, "literal dump: contents differ", || format!("@{off:#x} oracle `{}` ours `{}`", lossy(text), lossy(&ours)))
        {
            self.report.count("literal dump entries identical");
        }
    }

    fn record(&mut self, header: &[u8], fields: &[Vec<u8>], language: Option<&[u8]>) {
        self.report.count("records in oracle");
        let marker = b" { # offset: 0x";
        // A listing without offsets names the record only.
        let (stated_name, off) = match rfind(header, marker) {
            Some(at) => {
                let rest = &header[at + marker.len() - 2..];
                let off = u32::try_from(parse_hex(&rest[..find(rest, b",").unwrap_or(rest.len())]).unwrap()).unwrap();
                (&header[b".record ".len()..at], Some(off))
            }
            None => {
                let name = header[b".record ".len()..].strip_suffix(b" {").unwrap_or(header);
                (name, self.subject.records.get(name).map(|classes| classes[0]))
            }
        };
        let verbose = rfind(header, marker).is_some();
        let Some(class) = off.and_then(|off| self.subject.classes.get(&off).copied()) else {
            return self.report.diverge("record: not a class of ours", || lossy(header));
        };
        self.seen_classes.insert(class.offset());
        self.report.check(stated_name == dotted(class.name()).as_slice(), "record: name differs", || lossy(header));
        let ours = language_name(class.source_lang().unwrap());
        if let Some(language) = language {
            self.report.count("languages compared");
            self.report.check(language == ours, "record: language differs", || {
                format!("{}: oracle `{}` ours `{}`", lossy(header), lossy(language), lossy(ours))
            });
        }

        let ours: Vec<_> = class.fields().unwrap().map(Result::unwrap).collect();
        if !self.report.check(ours.len() == fields.len(), "record: field count differs", || lossy(header)) {
            return;
        }
        for (field, line) in ours.iter().zip(fields) {
            self.report.count("fields compared");
            let kind = match field.field_type().unwrap() {
                FieldType::U1 => "u1",
                FieldType::I8 => "i8",
                FieldType::U8 => "u8",
                FieldType::I16 => "i16",
                FieldType::U16 => "u16",
                FieldType::I32 => "i32",
                FieldType::U32 => "u32",
                FieldType::F32 => "f32",
                FieldType::F64 => "f64",
                FieldType::I64 => "i64",
                FieldType::U64 => "u64",
                FieldType::Reference => "ref",
                FieldType::Any => "any",
                FieldType::Class(_) => "class",
            };
            let value = match field.value() {
                Some(FieldValue::Int(value)) => format!(" = {:#x}", u32::from_le_bytes(value.to_le_bytes())),
                Some(FieldValue::Raw(value)) => format!(" = {value:#x}"),
                None => String::new(),
            };
            // A field of an annotation interface is written with its type and its default value.
            let typed = if class.is_annotation() { self.subject.default_text(field) } else { None };
            let (kind, value) = match &typed {
                Some((kind, value)) => (kind.as_str(), [b" = ", value.as_slice()].concat()),
                None => (kind, value.into_bytes()),
            };
            let value = value.as_slice();
            let mut expected = format!("\t{kind} ").into_bytes();
            expected.extend_from_slice(field.name().unwrap().bytes);
            expected.extend_from_slice(value);
            // `SerializeFields` passes the name through `GetFileNameByPath`.
            let name = field.name().unwrap().bytes;
            let mut shortened = format!("\t{kind} ").into_bytes();
            shortened.extend_from_slice(name.rsplit(|&b| b == b'/').next().unwrap_or(name));
            shortened.extend_from_slice(value);
            let stated = if verbose {
                rfind(line, b"# offset: 0x").map(|at| (&line[..at], parse_hex(&line[at + 10..])))
            } else {
                Some((line.as_slice(), None))
            };
            let matches = |expected: &[u8]| {
                stated.is_some_and(|(text, off)| {
                    let mut text = text;
                    while let Some(trimmed) = text.strip_suffix(b" ") {
                        text = trimmed;
                    }
                    text == expected && (!verbose || off == Some(u64::from(field.offset())))
                })
            };
            let mut ok = matches(&expected);
            if !ok && matches(&shortened) {
                self.report.diverge("record: oracle prints a field name from its last `/` on", || {
                    format!("oracle `{}` ours `{}`", lossy(line), lossy(&expected))
                });
                ok = true;
            }
            if self.report.check(ok, "record: field differs", || {
                format!("oracle `{}` ours `{}` @{:#x}", lossy(line), lossy(&expected), field.offset())
            }) {
                self.report.count("fields identical");
            }
        }
    }

    /// `u32 SlotNumber { 0xa }` under `L_ESSlotNumberAnnotation:`.
    fn annotation(&mut self, method_off: u32, class: &[u8], value: &[u8]) {
        self.report.count("annotations compared");
        let (_, method) = self.subject.methods[&method_off];
        let abc = self.subject.abc;
        let mut ours = Vec::new();
        for tag in method.tags().map(Result::unwrap) {
            let MethodTag::Annotation(off) = tag else { continue };
            let annotation = abc.annotation(off).unwrap();
            let descriptor = abc.string(annotation.class_off(&abc).unwrap()).unwrap().bytes;
            for element in annotation.elements() {
                let (kind, value) = self.subject.element_text(&element);
                let mut text = format!("\t{kind} ").into_bytes();
                text.extend_from_slice(abc.string(element.name_off).unwrap().bytes);
                text.extend_from_slice(b" { ");
                text.extend_from_slice(&value);
                text.extend_from_slice(b" }");
                ours.push((descriptor.strip_suffix(b";").unwrap_or(descriptor).to_vec(), text));
            }
        }
        let found = ours.iter().any(|(descriptor, text)| descriptor == class && text == value);
        if self.report.check(found, "annotation: not among the method's annotations", || {
            format!(
                "method @{method_off:#x}: oracle `{}` `{}`, ours {:?}",
                lossy(class),
                lossy(value),
                ours.iter().map(|(c, t)| (lossy(c), lossy(t))).collect::<Vec<_>>()
            )
        }) {
            self.report.count("annotations identical");
        }
    }

    /// Compare one function; returns its method offset when it is one of ours.
    /// `located` is the method a listing without offsets was matched to.
    fn function(&mut self, oracle: &OracleFunction<'_>, located: Option<u32>, language: Option<&[u8]>) -> Option<u32> {
        self.report.count("functions in oracle");
        let header = oracle.header;
        let (signature, method_off, code_off) = match located {
            Some(method_off) => (header.strip_suffix(b" {").unwrap_or(header), method_off, None),
            None => {
                let marker = b" { # offset: 0x";
                let Some(at) = rfind(header, marker) else {
                    self.report.diverge("oracle: function without offset", || lossy(header));
                    return None;
                };
                let rest = &header[at + marker.len() - 2..];
                let comma = find(rest, b", code offset: ").unwrap_or(rest.len());
                let method_off = u32::try_from(parse_hex(&rest[..comma]).unwrap()).unwrap();
                (&header[..at], method_off, Some(rest.get(comma + 15..).and_then(parse_hex)))
            }
        };
        let Some(&(class, method)) = self.subject.methods.get(&method_off) else {
            self.report.diverge("function: offset is not a method of ours", || lossy(header));
            return None;
        };
        if !self.seen_methods.insert(method_off) {
            self.report.diverge("function: listed twice in the oracle", || lossy(header));
        }
        let label = format!("{} @{method_off:#x}", lossy(&self.subject.full_method_name(&method)));
        let context = || label.clone();

        let code = method.code().unwrap();
        let expected = self.subject.function_header(&method);
        let mut ok = self.report.check(signature == expected.as_slice(), "function: name, argument count or attributes differ", || {
            format!("oracle `{}` ours `{}`", lossy(signature), lossy(&expected))
        });
        if let Some(code_off) = code_off {
            ok &= self.report.check(code_off == method.code_off().map(u64::from), "function: code offset differs", context);
        }
        let ours = language_name(method.source_lang());
        if let Some(language) = language {
            self.report.count("languages compared");
            ok &= self.report.check(language == ours, "function: language differs", || {
                format!("{}: oracle `{}` ours `{}`", context(), lossy(language), lossy(ours))
            });
        }

        if oracle.end_label {
            self.report.count("functions with a label after the last instruction (written without its name)");
        }
        let Some(code) = code else {
            self.report.check(oracle.insns.is_empty(), "function: oracle has code, we have none", context);
            return Some(method_off);
        };
        ok &= self.instructions(oracle, &method, &code, &context);
        ok &= self.tries(oracle, &code, &context);
        if oracle.verbose {
            ok &= self.line_table(oracle, &method, &context);
        }
        ok &= self.listing(oracle, &class, &method, &code, &context);
        if ok {
            self.report.count("functions identical");
        }
        Some(method_off)
    }

    /// Code offset a label stands for.
    fn label_pc(oracle: &OracleFunction<'_>, code: &Code<'_>, label: &[u8]) -> Option<usize> {
        let index = match oracle.labels.get(label) {
            Some(index) => *index,
            None if oracle.end_label => oracle.insns.len(),
            None => return None,
        };
        Some(match oracle.insns.get(index) {
            Some(insn) => (insn.offset - code.instructions_off()) as usize,
            None => code.instructions().len(),
        })
    }

    fn instructions(&mut self, oracle: &OracleFunction<'_>, method: &Method<'a>, code: &Code<'a>, context: &dyn Fn() -> String) -> bool {
        let ours: Vec<Instruction<'_>> = match walk(code.instructions()).collect() {
            Ok(insns) => insns,
            Err(error) => {
                self.report.diverge("instructions: our walk fails", || format!("{}: {error}", context()));
                return false;
            }
        };
        if !self.report.check(ours.len() == oracle.insns.len(), "instructions: count differs", || {
            format!("{}: oracle {}, ours {}", context(), oracle.insns.len(), ours.len())
        }) {
            return false;
        }
        let mut all = true;
        self.listed.clear();
        for (insn, stated) in ours.iter().zip(&oracle.insns) {
            self.report.count("instructions compared");
            let entry =
                self.opcodes.entry((insn.opcode.prefix.map(asc_arkisa::Prefix::byte), insn.opcode.value)).or_insert((insn.opcode.name, 0));
            entry.1 += 1;
            let at = || format!("{} +{:#x}: `{}`", context(), insn.pc, lossy(stated.text));
            let mut ok = self.report.check(
                u64::from(stated.offset) == u64::from(code.instructions_off()) + insn.pc as u64
                    && stated.raw.as_ref().is_none_or(|raw| raw == insn.bytes()),
                "instruction: offset or bytes differ",
                at,
            );
            ok &= self.operands(oracle, method, code, insn, stated.text, &at);
            if ok {
                self.report.count("instructions identical");
            }
            all &= ok;
        }
        all
    }

    /// Check mnemonic and operands of one instruction against the oracle's
    /// text, operand by operand in `isa.yaml` order.
    fn operands(
        &mut self,
        oracle: &OracleFunction<'_>,
        method: &Method<'a>,
        code: &Code<'a>,
        insn: &Instruction<'_>,
        text: &[u8],
        at: &dyn Fn() -> String,
    ) -> bool {
        let name = insn.opcode.name.as_bytes();
        let Some(mut rest) = text.strip_prefix(name).filter(|rest| rest.is_empty() || rest.starts_with(b" ")) else {
            self.report.diverge("instruction: mnemonic differs", || format!("{}, ours {}", at(), insn.opcode.name));
            return false;
        };
        let mut ok = true;
        let mut listed = format!("  {:04x}  {}", insn.pc, insn.opcode.name);
        for (i, (field, value)) in insn.opcode.operands.iter().zip(insn.operands()).enumerate() {
            let Some(after) = rest.strip_prefix(if i == 0 { &b" "[..] } else { b", " }) else {
                self.report.diverge("instruction: fewer operands in oracle", at);
                return false;
            };
            rest = after;
            // A token ends at the next separator; strings, names and literal
            // arrays may contain one, so those are matched as a prefix instead.
            let token_end = find(rest, b", ").unwrap_or(rest.len());
            let consumed = match value {
                Value::Reg(reg) => {
                    self.report.count("operands compared: register");
                    let reg = u32::from(reg);
                    let expected = match reg.checked_sub(code.num_vregs) {
                        Some(arg) => format!("a{arg}"),
                        None => format!("v{reg}"),
                    };
                    ok &= self.report.check(&rest[..token_end] == expected.as_bytes(), "operand: register differs", || {
                        format!("{}, ours {expected}", at())
                    });
                    token_end
                }
                Value::Imm(imm) => {
                    self.report.count("operands compared: immediate");
                    ok &= self.immediate(&rest[..token_end], imm, at);
                    token_end
                }
                Value::IcSlot(slot) => {
                    self.report.count("operands compared: ic slot");
                    ok &= self.immediate(&rest[..token_end], i64::from(slot), at);
                    token_end
                }
                Value::Float(float) => {
                    self.report.count("operands compared: float");
                    let stated: Option<f64> = std::str::from_utf8(&rest[..token_end]).ok().and_then(|token| token.parse().ok());
                    let same = stated.is_some_and(|stated| {
                        (stated.is_nan() && float.is_nan()) || stated == float || ((stated - float) / float).abs() < 1e-6
                    });
                    ok &= self.report.check(same, "operand: float differs", || format!("{}, ours {float:e}", at()));
                    token_end
                }
                Value::JumpOffset(_) => {
                    self.report.count("operands compared: jump target");
                    let stated = Self::label_pc(oracle, code, &rest[..token_end]);
                    ok &= self.report.check(stated.is_some() && stated == insn.jump_target(), "operand: jump target differs", || {
                        format!("{}, oracle {stated:x?}, ours {:x?}", at(), insn.jump_target())
                    });
                    token_end
                }
                Value::StringId(id) => {
                    self.report.count("operands compared: string");
                    let mut expected = vec![b'"'];
                    expected.extend_from_slice(self.subject.string(Self::resolve(method, id)));
                    expected.push(b'"');
                    let matched = match_prefix(&mut self.report, rest, &expected);
                    ok &=
                        self.report.check(matched.is_some(), "operand: string differs", || format!("{}, ours {}", at(), lossy(&expected)));
                    matched.unwrap_or(expected.len())
                }
                Value::MethodId(id) => {
                    self.report.count("operands compared: method");
                    let expected = self.subject.method_signature(Self::resolve(method, id));
                    let matched = match_prefix(&mut self.report, rest, &expected);
                    ok &=
                        self.report.check(matched.is_some(), "operand: method differs", || format!("{}, ours {}", at(), lossy(&expected)));
                    matched.unwrap_or(expected.len())
                }
                Value::LiteralArrayId(id) => {
                    self.report.count("operands compared: literal array");
                    self.used_literals.insert(Self::resolve(method, id));
                    let expected = self.subject.literal_text(Self::resolve(method, id), &mut self.literal_flags);
                    let matched = match_prefix(&mut self.report, rest, &expected);
                    ok &= self
                        .report
                        .check(matched.is_some(), "operand: literal array differs", || format!("{}, ours {}", at(), lossy(&expected)));
                    matched.unwrap_or(expected.len())
                }
            };
            // The same operand as the listing is expected to show it, derived
            // from the oracle's token wherever the token carries the value.
            let token = &rest[..consumed.min(rest.len())];
            listed.push_str(if i == 0 { " " } else { ", " });
            match value {
                Value::Reg(_) | Value::IcSlot(_) => listed.push_str(&String::from_utf8_lossy(token)),
                Value::Imm(ours) => {
                    let stated = parse_hex(token).and_then(|v| i64::try_from(v).ok()).unwrap_or(ours);
                    listed.push_str(&listed_int(stated, field.kind == OperandKind::ImmSigned));
                }
                Value::Float(ours) => listed.push_str(&listed_f64(ours)),
                Value::JumpOffset(_) => {
                    let target = Self::label_pc(oracle, code, token).unwrap_or(usize::MAX);
                    write!(listed, "L_{target:04x}").unwrap();
                }
                Value::StringId(id) => {
                    listed.push_str(
                        &self.subject.abc.string(Self::resolve(method, id)).map_or(String::new(), |string| listed_string(&string.to_str())),
                    );
                }
                Value::MethodId(id) => {
                    let name = self.subject.abc.method(Self::resolve(method, id)).and_then(|method| method.name());
                    listed.push_str(&name.map_or(String::new(), |name| listed_name(&name.to_str())));
                }
                Value::LiteralArrayId(id) => listed.push_str(&self.subject.listed_literal(Self::resolve(method, id))),
            }
            rest = rest.get(consumed..).unwrap_or_default();
        }
        self.listed.push(listed);
        ok & self.report.check(rest.is_empty(), "instruction: more operands in oracle", at)
    }

    /// The header lines of the listing that name registers: the variables
    /// the oracle's table was compared with, one `; locals [start, end): `
    /// line per code range in the order the ranges first occur, each
    /// variable with its register, name and type other than `any`; then the
    /// named parameters.
    fn listed_locals(&self, method: &Method<'a>, code: &Code<'a>) -> Vec<String> {
        const SHOWN: usize = 256;
        let Some(info) = method.debug_info().unwrap() else { return Vec::new() };
        let name = |off: u32| self.subject.abc.string(off).map_or_else(|_| "<bad string>".to_owned(), |text| listed_name(&text.to_str()));
        let reg = |reg: i64| match u32::try_from(reg) {
            Err(_) => "acc".to_owned(),
            Ok(reg) => reg.checked_sub(code.num_vregs).map_or_else(|| format!("v{reg}"), |arg| format!("a{arg}")),
        };
        // Without the compiler's own variables, whose names start with a digit.
        let own = |off: u32| self.subject.abc.string(off).is_ok_and(|text| text.bytes.first().is_some_and(u8::is_ascii_digit));
        let locals: Vec<_> = info.locals().unwrap().into_iter().filter(|local| !own(local.name_off)).collect();
        let mut ranges: Vec<((usize, usize), Vec<String>)> = Vec::new();
        for local in locals.iter().take(SHOWN) {
            let range = (local.start_pc as usize, local.end_pc.map_or(code.instructions().len(), |end| end as usize));
            let kind = name(local.signature_off.unwrap_or(local.type_off));
            let kind = if kind.is_empty() || kind == "any" { String::new() } else { format!(": {kind}") };
            let item = format!("{} {}{kind}", reg(i64::from(local.reg)), name(local.name_off));
            match ranges.iter_mut().find(|(known, _)| *known == range) {
                Some((_, items)) => items.push(item),
                None => ranges.push((range, vec![item])),
            }
        }
        let mut lines: Vec<String> =
            ranges.iter().map(|((start, end), items)| format!("; locals [{start:04x}, {end:04x}): {}", items.join(", "))).collect();
        if locals.len() > SHOWN {
            lines.push(format!("; locals: … (+{} more)", locals.len() - SHOWN));
        }
        let params = (i64::from(code.num_vregs)..).zip(info.params()).filter(|&(_, off)| off != 0).take(SHOWN);
        let params: Vec<String> = params.map(|(at, off)| format!("{} {}", reg(at), name(off))).collect();
        if !params.is_empty() {
            lines.push(format!("; params: {}", params.join(", ")));
        }
        lines
    }

    fn resolve(method: &Method<'a>, id: u32) -> u32 {
        u16::try_from(id).ok().and_then(|idx| method.resolve(idx).ok()).unwrap_or(u32::MAX)
    }

    fn immediate(&mut self, token: &[u8], ours: i64, at: &dyn Fn() -> String) -> bool {
        let stated = match token.strip_prefix(b"-") {
            Some(magnitude) => parse_hex(magnitude).and_then(|v| i64::try_from(v).ok()).map(|v| -v),
            None => parse_hex(token).and_then(|v| i64::try_from(v).ok()),
        };
        if ours < 0 {
            self.report.count("operands compared: immediate, negative");
        }
        if stated == Some(ours) {
            return true;
        }
        // The same bits read with the other signedness.
        let same_bits = stated.is_some_and(|stated| stated as u32 == ours as u32);
        self.report.diverge(if same_bits { "operand: immediate has the other sign" } else { "operand: immediate differs" }, || {
            format!("{}, ours {ours}", at())
        });
        false
    }

    fn tries(&mut self, oracle: &OracleFunction<'_>, code: &Code<'a>, context: &dyn Fn() -> String) -> bool {
        let mut ours = Vec::new();
        for block in code.try_blocks() {
            let block = block.unwrap();
            self.report.count("try blocks compared");
            for catch in block.catch_blocks() {
                ours.push((
                    catch.type_idx,
                    block.start_pc as usize,
                    (block.start_pc + block.length) as usize,
                    catch.handler_pc as usize,
                    catch.code_size as usize,
                ));
            }
        }
        let mut stated = Vec::new();
        for (kind, labels) in &oracle.catches {
            if kind.is_some() {
                self.report.count("typed catches in oracle");
            }
            let pcs: Vec<Option<usize>> = labels.iter().map(|label| Self::label_pc(oracle, code, label)).collect();
            stated.push((kind.is_some(), pcs));
        }
        let same = ours.len() == stated.len()
            && ours.iter().zip(&stated).all(|(ours, (typed, pcs))| {
                let head = [Some(ours.1), Some(ours.2), Some(ours.3)];
                ours.0.is_some() == *typed && pcs.get(..3) == Some(&head[..]) && pcs.get(3).is_none_or(|end| *end == Some(ours.3 + ours.4))
            });
        if self.report.check(same, "try blocks differ", || format!("{}: oracle {stated:x?}, ours {ours:x?}", context())) {
            self.report.add("catch blocks identical", ours.len() as u64);
        }
        same
    }

    fn line_table(&mut self, oracle: &OracleFunction<'_>, method: &Method<'a>, context: &dyn Fn() -> String) -> bool {
        let Some(info) = method.debug_info().unwrap() else {
            return self.report.check(
                oracle.lines.is_empty() && oracle.columns.is_empty() && oracle.locals.is_none(),
                "line table: oracle has one, we have no debug info",
                context,
            );
        };
        // The line and column registers are 32 bits wide and hold -1 for
        // "none"; the oracle keeps them in a `size_t` (`LineProgramState::
        // SetColumn` casts the `int32_t`), so it prints -1 as 2^64 - 1.
        let widen = |line: u32| i64::from(i32::from_le_bytes(line.to_le_bytes())) as u64;
        let mut lines = vec![(widen(info.line_start), 0u64)];
        for row in info.line_rows().unwrap() {
            let row = row.unwrap();
            lines.push((widen(row.line), u64::from(row.pc)));
        }
        // The official column table has a row per `SET_COLUMN`, at the address reached so far.
        let mut columns = Vec::new();
        let mut pc = 0u64;
        for op in info.line_ops().unwrap() {
            match op.unwrap() {
                LineOp::AdvancePc(delta) => pc += u64::from(delta),
                LineOp::Special { pc_delta, .. } => pc += u64::from(pc_delta),
                LineOp::SetColumn(column) => {
                    if column == u32::MAX {
                        self.report.count("column rows of -1 (printed as 2^64 - 1)");
                    }
                    columns.push((widen(column), pc));
                }
                _ => {}
            }
        }
        self.report.add("line rows compared", oracle.lines.len() as u64);
        self.report.add("column rows compared", oracle.columns.len() as u64);
        // Rows that change nothing are not news.
        fn collapse(rows: &[(u64, u64)]) -> Vec<(u64, u64)> {
            let mut out: Vec<(u64, u64)> = Vec::new();
            for &(value, pc) in rows {
                match out.last_mut() {
                    Some(last) if last.1 == pc => last.0 = value,
                    Some(last) if last.0 == value => {}
                    _ => out.push((value, pc)),
                }
            }
            out
        }
        let mut ok = true;
        if oracle.lines != lines {
            let collapsed = collapse(&oracle.lines) == collapse(&lines);
            self.report.diverge(if collapsed { "line table: oracle rows repeat" } else { "line table differs" }, || {
                format!("{}: oracle {:?}, ours {:?}", context(), &oracle.lines[..oracle.lines.len().min(12)], &lines[..lines.len().min(12)])
            });
            ok = collapsed;
        } else {
            self.report.add("line rows identical", lines.len() as u64);
        }
        if oracle.columns == columns {
            self.report.add("column rows identical", columns.len() as u64);
        } else {
            self.report.diverge("column table differs", || {
                format!(
                    "{}: oracle {:?}, ours {:?}",
                    context(),
                    &oracle.columns[..oracle.columns.len().min(12)],
                    &columns[..columns.len().min(12)]
                )
            });
            ok = false;
        }
        ok & self.local_table(oracle, method, &info, pc, context)
    }

    /// The local variable table as `Disassembler::SerializeLocalVariableTable`
    /// writes it: the variables of the line number program in the order it
    /// starts them, then one row per parameter of the debug info.
    /// `end_address` is where the line number program stops.
    fn local_table(
        &mut self,
        oracle: &OracleFunction<'_>,
        method: &Method<'a>,
        info: &asc_abc::DebugInfo<'a>,
        end_address: u64,
        context: &dyn Fn() -> String,
    ) -> bool {
        let Some(code) = method.code().unwrap() else { return true };
        let string = |off: u32| self.subject.string(off);
        let mut rows: Vec<Vec<u8>> = Vec::new();
        let mut row = |start: u64, end: u64, reg: i64, name: &[u8], kind: &[u8], signature: Option<&[u8]>| {
            let place = match u32::try_from(reg) {
                Err(_) => "acc".to_owned(),
                Ok(reg) => match reg.checked_sub(code.num_vregs) {
                    Some(arg) => format!("a{arg}"),
                    None => format!("v{reg}"),
                },
            };
            let mut text = format!("#\t {start:>5}  {end:>4}  {:>8} ", format!("{reg}({place})")).into_bytes();
            // `std::setw` counts bytes.
            text.resize(text.len() + 14usize.saturating_sub(name.len()), b' ');
            text.extend_from_slice(name);
            text.extend_from_slice(b"   ");
            text.extend_from_slice(kind);
            if let Some(signature) = signature.filter(|signature| !signature.is_empty() && *signature != kind) {
                text.extend_from_slice(b" (");
                text.extend_from_slice(signature);
                text.push(b')');
            }
            text.push(b'\n');
            rows.push(text);
        };
        let locals = info.locals().unwrap();
        for local in &locals {
            // `ProcessVars` takes an end of 0 for "not ended" and puts the
            // last address there, also when the variable was ended at 0.
            let end = local.end_pc.filter(|&end| end != 0).map_or(end_address, u64::from);
            row(
                u64::from(local.start_pc),
                end,
                i64::from(local.reg),
                string(local.name_off),
                string(local.type_off),
                local.signature_off.map(string),
            );
        }
        let mut params = 0u64;
        let mut modelled = true;
        for (reg, name_off) in (i64::from(code.num_vregs)..).zip(info.params()) {
            params += 1;
            // `ExtractMethodParams`: a nameless parameter has no type either;
            // a method without a proto has parameters of type `any`.
            let (name, kind): (&[u8], &[u8]) = if name_off <= HEADER_SIZE {
                (b"", b"")
            } else {
                modelled &= method.proto_idx == u16::MAX;
                (string(name_off), b"A")
            };
            row(0, code.instructions().len() as u64, reg, name, kind, None);
        }
        if !modelled {
            // Named parameters typed by a proto: not modelled here.
            self.report.count("local variable tables with proto-typed parameters (not compared)");
            return true;
        }
        self.report.add("local variable rows compared", locals.len() as u64);
        self.report.add("parameter rows compared", params);
        let expected = if rows.is_empty() {
            None
        } else {
            let mut text = b"#\t Start   End  Register           Name   Signature\n".to_vec();
            text.extend(rows.iter().flatten());
            Some(text)
        };
        let same = oracle.locals == expected.as_deref();
        if same {
            self.report.add("local variable rows identical", locals.len() as u64);
            self.report.add("parameter rows identical", params);
        } else {
            self.report.diverge("local variable table differs", || {
                format!("{}: oracle {:?}, ours {:?}", context(), oracle.locals.map(lossy), expected.as_deref().map(lossy))
            });
        }
        same
    }

    /// The `asc-pasm` listing of the function against the oracle: offsets,
    /// mnemonics, labels, try ranges and source lines.
    fn listing(
        &mut self,
        oracle: &OracleFunction<'_>,
        class: &Class<'a>,
        method: &Method<'a>,
        code: &Code<'a>,
        context: &dyn Fn() -> String,
    ) -> bool {
        let opts = Options { lines: true, locals: true, ic_slots: true, literal_limit: usize::MAX, string_limit: usize::MAX, source: None };
        self.listing.clear();
        write_function(&mut self.listing, &self.subject.abc, class, method, &opts).unwrap();
        let listing = std::mem::take(&mut self.listing);
        // A string operand may contain the marker's text itself.
        let markers = |text: &str| text.matches("<error").count();
        let quoted: usize = self.listed.iter().map(|line| markers(line)).sum();
        let mut ok = self.report.check(markers(&listing) == quoted, "listing: has an error marker", || {
            format!("{}: {}", context(), listing.lines().find(|line| line.contains("<error")).unwrap_or_default())
        });

        let insns_off = code.instructions_off();
        let pc_of = |insn: &OracleInsn<'_>| (insn.offset - insns_off) as usize;
        // A branch may name a try label that already stands at its target.
        let mut stated_labels: Vec<usize> = oracle
            .insns
            .iter()
            .filter_map(|insn| insn.text.rsplit(|&b| b == b' ').next())
            .filter(|token| is_label_name(token))
            .filter_map(|label| Self::label_pc(oracle, code, label))
            .chain(oracle.catches.iter().filter_map(|(_, labels)| labels.get(2).and_then(|label| Self::label_pc(oracle, code, label))))
            .collect();
        stated_labels.sort_unstable();
        stated_labels.dedup();
        let mut stated_tries: Vec<(usize, usize, usize)> = oracle
            .catches
            .iter()
            .filter_map(|(_, labels)| {
                let pc = |i: usize| labels.get(i).and_then(|label| Self::label_pc(oracle, code, label));
                Some((pc(0)?, pc(1)?, pc(2)?))
            })
            .collect();
        stated_tries.sort_unstable();
        // The line the oracle's table gives each instruction.
        let stated_line = |pc: usize| oracle.lines.iter().rfind(|&&(_, at)| at <= pc as u64).map(|&(line, _)| line);

        let (mut labels, mut tries, mut insns, mut line) = (Vec::new(), Vec::new(), oracle.insns.iter(), None::<u64>);
        let expected_lines = std::mem::take(&mut self.listed);
        let mut listed = expected_lines.iter();
        let mut lines_ok = true;
        let mut locals_lines = Vec::new();
        for text in listing.lines().skip(2) {
            if text.starts_with("; locals") || text.starts_with("; params: ") {
                locals_lines.push(text);
            } else if let Some(label) = text.strip_prefix("L_") {
                labels.push(usize::from_str_radix(&label[..label.find(':').unwrap()], 16).unwrap());
            } else if let Some(range) = text.strip_prefix("  .try ") {
                let hex = |text: &str| usize::from_str_radix(text, 16).unwrap();
                let (bounds, catches) = range.split_once(") ").unwrap();
                let (start, end) = bounds.split_once('[').unwrap().1.split_once(", ").unwrap();
                for handler in catches.split(" -> L_").skip(1) {
                    let handler = handler.split(' ').next().unwrap();
                    tries.push((hex(start), hex(end), hex(handler)));
                }
            } else if let Some(number) = text.strip_prefix("  ; line ") {
                line = number.parse().ok();
            } else if text.starts_with("; @") {
                // An annotation of the program: its values are compared from the file.
                self.report.count("listing: annotation lines");
            } else if text.starts_with("  .endtry ") || text == ".end function" {
            } else if let Some((pc, rest)) = text.strip_prefix("  ").and_then(|text| text.split_once("  ")) {
                let _ = rest;
                let pc = usize::from_str_radix(pc, 16).unwrap();
                let expected = listed.next();
                // Offset, mnemonic and every operand; only a `;` note may follow.
                let same = insns.next().is_some_and(|stated| pc_of(stated) == pc)
                    && expected.is_some_and(|expected| {
                        text.strip_prefix(expected.as_str()).is_some_and(|note| note.is_empty() || note.starts_with("  ; "))
                    });
                if same {
                    self.report.count("listing lines identical");
                }
                ok &= self
                    .report
                    .check(same, "listing: instruction line differs", || format!("{}: `{text}`, expected `{expected:?}`", context()));
                // Lines the compiler marks as generated (-1) are not shown, the previous one stays.
                let stated = stated_line(pc).filter(|&line| i32::try_from(line).is_ok());
                if stated.is_some() && stated != line {
                    lines_ok = false;
                }
            } else {
                ok &= self.report.check(false, "listing: unexpected line", || format!("{}: `{text}`", context()));
            }
        }
        ok &= self.report.check(insns.next().is_none(), "listing: ends before the oracle", context);
        tries.sort_unstable();
        ok &= self.report.check(labels == stated_labels, "listing: labels differ", || {
            format!("{}: oracle {stated_labels:x?}, ours {labels:x?}", context())
        });
        ok &= self.report.check(tries == stated_tries, "listing: try ranges differ", || {
            format!("{}: oracle {stated_tries:x?}, ours {tries:x?}", context())
        });
        ok &= self.report.check(lines_ok, "listing: source lines differ", context);
        let expected = self.listed_locals(method, code);
        if !expected.is_empty() {
            self.report.count("listing: functions with locals lines");
        }
        ok &= self.report.check(locals_lines == expected, "listing: locals lines differ", || {
            format!("{}: `{locals_lines:?}`, expected `{expected:?}`", context())
        });
        self.listing = listing;
        self.listed = expected_lines;
        ok
    }
}

type Opcodes = BTreeMap<(Option<u8>, u8), (&'static str, u64)>;

/// What comparing one file with its listing came to.
struct Outcome {
    counts: BTreeMap<&'static str, u64>,
    /// Class, occurrences, whether it is in [`KNOWN`].
    divergences: Vec<(String, u64, bool)>,
    opcodes: Opcodes,
    report: String,
}

impl Outcome {
    fn count(&self, what: &str) -> u64 {
        self.counts.get(what).copied().unwrap_or(0)
    }

    fn unknown(&self) -> Vec<&str> {
        self.divergences.iter().filter(|(_, _, known)| !known).map(|(class, ..)| class.as_str()).collect()
    }
}

fn opcode_lines(out: &mut String, opcodes: &Opcodes) {
    writeln!(out, "== opcodes: {} of {} table rows occur", opcodes.len(), asc_arkisa::opcodes().count()).unwrap();
    for ((prefix, value), (name, count)) in opcodes {
        match prefix {
            Some(prefix) => write!(out, "{name}[{prefix:02x} {value:02x}]:{count} "),
            None => write!(out, "{name}[{value:02x}]:{count} "),
        }
        .unwrap();
    }
    let missing: Vec<String> = asc_arkisa::opcodes()
        .filter(|op| !opcodes.contains_key(&(op.prefix.map(asc_arkisa::Prefix::byte), op.value)))
        .map(|op| format!("{}[{:02x}]", op.name, op.value))
        .collect();
    writeln!(out, "\n== absent: {}", missing.join(" ")).unwrap();
}

/// Compare the file `data` with its listing, given as one file or in parts.
fn compare(data: &[u8], listings: &[PathBuf]) -> Outcome {
    let abc = Abc::parse(data).unwrap();
    let mut comparer = Comparer::new(abc);
    for path in listings {
        let file = std::fs::File::open(path).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
        comparer.file(&path.file_name().unwrap().to_string_lossy(), &mut Lines::new(BufReader::with_capacity(1 << 20, file)));
    }

    let Comparer { subject, mut report, seen_methods, seen_classes, seen_literals, used_literals, opcodes, literal_flags, .. } = comparer;
    for methods in subject.signatures.values() {
        let (first, rest) = methods.split_first().unwrap();
        report.check(seen_methods.contains(first), "function: missing in oracle", || {
            format!("{} @{first:#x}", lossy(&subject.full_method_name(&subject.methods[first].1)))
        });
        // `Disassembler::AddMethodToTables` keeps one function per signature.
        report.add("functions the official tool drops (signature already taken)", rest.len() as u64);
        for off in rest {
            report.check(!seen_methods.contains(off), "function: a second one of its signature is in the oracle", || format!("@{off:#x}"));
        }
    }
    for (name, classes) in &subject.records {
        let (first, rest) = classes.split_first().unwrap();
        // `Disassembler::GetRecords` passes over the record of an unmerged file.
        if name == asc_abc::unmerged::GLOBAL {
            report.count("records the official tool leaves out (_GLOBAL)");
            report.check(!seen_classes.contains(first), "record: _GLOBAL is in the oracle", || format!("@{first:#x}"));
            continue;
        }
        report.check(seen_classes.contains(first), "record: missing in oracle", || {
            format!("{} @{first:#x}", lossy(subject.classes[first].name()))
        });
        // `Disassembler::GetRecords` keeps one record per name.
        report.add("records the official tool drops (name already taken)", rest.len() as u64);
    }
    match abc.literal_array_index().unwrap() {
        Some(index) => {
            report.add("literal index entries of the file", u64::from(index.len()));
            for off in index.iter() {
                // `GetLiteralArrays` skips the phase tables; they are not literal arrays.
                if subject.phase_tables.contains(&off) {
                    report.count("module request phase tables (not in the oracle's dump)");
                    report.check(!seen_literals.contains(&off), "literal dump: a phase table is dumped", || format!("@{off:#x}"));
                    continue;
                }
                report.check(seen_literals.contains(&off), "literal dump: entry missing in oracle", || format!("@{off:#x}"));
            }
        }
        // No index in the header: the dump is what the official tool collects. It finds
        // module records by the `moduleRecordIdx` field, which an unmerged file has not.
        None if !seen_literals.is_empty() => {
            let unmerged = subject.unmerged_module_record();
            if let Some(off) = unmerged {
                report.count("module records the official tool does not find (unmerged, no literal index)");
                report.check(!seen_literals.contains(&off), "literal dump: the module record of an unmerged file is dumped", || {
                    format!("@{off:#x}")
                });
            }
            for off in subject.module_records.iter().filter(|off| Some(**off) != unmerged).chain(&used_literals) {
                report.check(seen_literals.contains(off), "literal dump: entry missing in oracle", || format!("@{off:#x}"));
            }
            for off in &subject.phase_tables {
                report.count("module request phase tables (not in the oracle's dump)");
                report.check(!seen_literals.contains(off), "literal dump: a phase table is dumped", || format!("@{off:#x}"));
            }
        }
        None => {}
    }
    report.add("literal items the official tool drops (TAGVALUE)", literal_flags.tag_values);
    report.add("literal items the official tool cannot render", literal_flags.unrenderable);

    let mut out = String::new();
    writeln!(out, "== coverage").unwrap();
    for (what, count) in &report.counts {
        writeln!(out, "{count:>10}  {what}").unwrap();
    }
    opcode_lines(&mut out, &opcodes);
    writeln!(out, "== divergences").unwrap();
    let mut divergences = Vec::new();
    for (class, (count, example)) in &report.divergences {
        let known = KNOWN.iter().find(|(known, _)| known == class);
        let note = known.map_or(String::new(), |(_, why)| format!("  [known: {why}]"));
        writeln!(out, "{count:>10}  {class}{note}\n            e.g. {example}").unwrap();
        divergences.push((class.clone(), *count, known.is_some()));
    }
    Outcome { counts: report.counts, divergences, opcodes, report: out }
}

/// The official tool's output for one file, split into a directory of
/// `*.pa` parts by hand.
#[test]
fn official_disassembly_agrees() {
    let Some(dir) = std::env::var_os("ASC_ABC_PA_DIR").map(PathBuf::from) else { return };
    let large = || Some(common::large_sample_dir()?.join("modules.abc"));
    let Some(abc_path) = std::env::var_os("ASC_ABC_PA_ABC").map(PathBuf::from).or_else(large) else { return };
    let data = std::fs::read(&abc_path).unwrap_or_else(|err| panic!("{}: {err}", abc_path.display()));
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "pa"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no .pa files in {}", dir.display());
    let outcome = compare(&data, &files);
    print!("{}", outcome.report);
    assert!(outcome.unknown().is_empty(), "divergences from the official disassembler: {:?}", outcome.unknown());
}

const ABC_MAGIC: &[u8] = b"PANDA\0\0\0";
const LISTING_HEAD: &[u8] = b"# source binary: ";

fn starts_with(path: &Path, head: &[u8]) -> bool {
    let mut buf = vec![0; head.len()];
    std::fs::File::open(path).and_then(|mut file| file.read_exact(&mut buf)).is_ok() && buf == head
}

/// Every regular file under the given files and directories.
fn files_under(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending: Vec<PathBuf> = roots.to_vec();
    while let Some(path) = pending.pop() {
        match std::fs::metadata(&path) {
            Ok(meta) if meta.is_dir() => pending.extend(std::fs::read_dir(&path).unwrap().map(|entry| entry.unwrap().path())),
            Ok(meta) if meta.is_file() => files.push(path),
            _ => {}
        }
    }
    files.sort();
    files
}

/// Strings with their file offsets.
type Fingerprint = Vec<(u32, Vec<u8>)>;

/// Strings of the listing's trailing string dump with their file offsets:
/// what tells which file a listing is of, whatever the two are called.
fn fingerprint(path: &Path) -> Fingerprint {
    const WINDOW: u64 = 64 << 10;
    let mut file = std::fs::File::open(path).unwrap();
    let len = file.metadata().unwrap().len();
    file.seek(SeekFrom::Start(len.saturating_sub(WINDOW))).unwrap();
    let mut tail = Vec::new();
    file.read_to_end(&mut tail).unwrap();
    let lines: Vec<&[u8]> = tail.split(|&b| b == b'\n').skip(1).filter(|line| !line.is_empty()).collect();
    let entry = |line: &[u8]| {
        let rest = line.strip_prefix(b"[offset:")?.strip_suffix(b"]")?;
        let comma = find(rest, b", name_value:")?;
        Some((u32::try_from(parse_hex(&rest[..comma])?).ok()?, rest[comma + 13..].to_vec()))
    };
    // An entry whose text spans lines is not taken: the next line has to start one too.
    let mut entries = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if lines.get(i + 1).is_none_or(|next| next.starts_with(b"[offset:0x")) {
            entries.extend(entry(line));
        }
    }
    entries
}

/// Whether the listing has the string dump the official tool ends its
/// output with. A file that starts like a listing and has none is a part
/// somebody cut out of one.
fn has_string_dump(path: &Path) -> bool {
    let mut lines = Lines::new(BufReader::with_capacity(1 << 20, std::fs::File::open(path).unwrap()));
    std::iter::from_fn(|| lines.next().map(|line| line == b"# STRING")).any(|found| found)
}

/// `$ASC_ABC_PA` names files and directories (separated like `$PATH`) with
/// ABC files and the official tool's listings of them, `ark_disasm` output
/// as it comes: one file each, with or without `--verbose`. Which listing
/// belongs to which file is decided by content. A file that starts like a
/// listing and lacks the string dump is a part of one: it cannot be paired,
/// and is skipped and counted. Without the variable the test does nothing.
#[test]
fn official_listings_agree() {
    let Some(roots) = std::env::var_os("ASC_ABC_PA") else { return };
    let only = std::env::var("ASC_ABC_PA_ONLY").ok();
    let files = files_under(&std::env::split_paths(&roots).collect::<Vec<_>>());
    let (mut listings, parts): (Vec<_>, Vec<_>) = files
        .iter()
        .filter(|path| starts_with(path, LISTING_HEAD))
        .filter(|path| only.as_ref().is_none_or(|only| path.to_string_lossy().contains(only.as_str())))
        .map(|path| (path, fingerprint(path), false))
        .partition(|(path, strings, _)| !strings.is_empty() || has_string_dump(path));
    assert!(!listings.is_empty(), "no whole listing under $ASC_ABC_PA");

    let mut rows = Vec::new();
    let mut opcodes = Opcodes::new();
    let mut failed = Vec::new();
    for abc_path in files.iter().filter(|path| starts_with(path, ABC_MAGIC)) {
        let data = std::fs::read(abc_path).unwrap();
        let Ok(abc) = Abc::parse(&data) else { continue };
        for (listing, strings, taken) in &mut listings {
            let same = !strings.is_empty() && strings.iter().all(|(off, text)| abc.string(*off).is_ok_and(|string| string.bytes == text));
            if !same {
                continue;
            }
            *taken = true;
            let started = std::time::Instant::now();
            let outcome = compare(&data, std::slice::from_ref(*listing));
            println!("==== {} <- {} ({:?})", abc_path.display(), listing.display(), started.elapsed());
            print!("{}", outcome.report);
            for (key, (name, count)) in &outcome.opcodes {
                opcodes.entry(*key).or_insert((name, 0)).1 += count;
            }
            let unknown: u64 = outcome.divergences.iter().filter(|(_, _, known)| !known).map(|(_, count, _)| count).sum();
            let known: u64 = outcome.divergences.iter().filter(|(_, _, known)| *known).map(|(_, count, _)| count).sum();
            // Compared and, when it is not all of them, identical.
            let pair = |compared: &str, identical: &str| match (outcome.count(compared), outcome.count(identical)) {
                (compared, identical) if compared == identical => compared.to_string(),
                (compared, identical) => format!("{compared}/{identical}"),
            };
            rows.push(format!(
                "{:>3}.{:<3} {:>8} {:>8} {:>9} {:>9} {:>8} {:>8} {:>7} {:>6} {:>7} {:>7}  {}",
                abc.header().version.0[0],
                abc.header().version.0[1..].iter().map(u8::to_string).collect::<Vec<_>>().join("."),
                outcome.count("functions in oracle"),
                outcome.count("functions identical"),
                outcome.count("instructions compared"),
                outcome.count("instructions identical"),
                pair("line rows compared", "line rows identical"),
                pair("column rows compared", "column rows identical"),
                pair("local variable rows compared", "local variable rows identical"),
                pair("parameter rows compared", "parameter rows identical"),
                known,
                unknown,
                listing.display()
            ));
            if !outcome.unknown().is_empty() {
                failed.push(format!("{}: {:?}", listing.display(), outcome.unknown()));
            }
        }
    }
    println!("==== all listings");
    println!("version  functions identical     insns identical    lines  columns  locals params   known unknown  listing");
    for row in &rows {
        println!("{row}");
    }
    let mut union = String::new();
    opcode_lines(&mut union, &opcodes);
    print!("{union}");
    println!("==== {} listings compared; {} files skipped, parts of a listing (no string dump)", rows.len(), parts.len());
    for (part, ..) in &parts {
        println!("skipped: {}", part.display());
    }
    for (listing, ..) in listings.iter().filter(|(_, _, taken)| !taken) {
        failed.push(format!("{}: no ABC file under $ASC_ABC_PA has its strings", listing.display()));
    }
    assert!(failed.is_empty(), "divergences from the official disassembler:\n{}", failed.join("\n"));
}

/// A function whose debug info has everything the official tool tabulates:
/// variables started plainly and with a signature, ended, left open and
/// ended at address 0, a register that changes hands, the accumulator,
/// columns including -1, named and nameless parameters.
fn debug_program() -> AbcBuilder {
    const RECORD: &str = "&entry/src/main/ets/pages/Debug&";
    let local = |reg: i32, name: &str| AbcLineOp::StartLocal { reg, name: name.to_owned(), ty: "any".to_owned() };
    let mut code = Asm::new();
    code.op("ldai", [7.into()]).op("sta", [0.into()]).op("lda.str", [Op::str("label")]).op("sta", [1.into()]);
    code.op("lda", [0.into()]).op("sta", [2.into()]).op("lda", [1.into()]).op("return", []);
    let debug = AbcDebugInfo {
        line_start: 3,
        params: vec![Some("request".to_owned()), None, Some("a much longer parameter name".to_owned())],
        program: vec![
            AbcLineOp::SetFile("entry/src/main/ets/pages/Debug.ets".to_owned()),
            local(3, "early"),
            AbcLineOp::EndLocal(3),
            AbcLineOp::SetColumn(4),
            AbcLineOp::Special { pc_delta: 5, line_delta: 1 },
            local(0, "count"),
            AbcLineOp::StartLocalExtended { reg: 1, name: "label".to_owned(), ty: "any".to_owned(), signature: "Lstring;".to_owned() },
            AbcLineOp::SetColumn(u32::MAX),
            AbcLineOp::Special { pc_delta: 4, line_delta: -4 },
            AbcLineOp::EndLocal(0),
            local(0, "other"),
            local(-1, "result"),
            AbcLineOp::AdvancePc(4),
            AbcLineOp::AdvanceLine(40),
            AbcLineOp::SetColumn(12),
            AbcLineOp::Special { pc_delta: 0, line_delta: 0 },
            AbcLineOp::EndLocal(1),
            AbcLineOp::Special { pc_delta: 2, line_delta: 1 },
        ],
    };
    let mut plain = Asm::new();
    plain.op("ldundefined", []).op("return", []);
    let mut builder = AbcBuilder::new();
    builder.record(
        AbcRecord::new(RECORD)
            .function(AbcFunction::new("#*#debug", AbcCode::new(4, 6, code)).debug(debug))
            .function(AbcFunction::new("#*#plain", AbcCode::new(0, 3, plain))),
    );
    builder
}

/// `$ASC_ARK_DISASM` is the official disassembler (`ark_disasm [--verbose]
/// input.abc output.pa`). It is run on the files `asc-fixture` writes, and
/// its listings are compared like any other. Without the variable the test
/// does nothing.
#[test]
fn official_tool_agrees_on_fixtures() {
    let Some(tool) = std::env::var_os("ASC_ARK_DISASM") else { return };
    let mut programs: Vec<(&str, AbcBuilder)> = vec![
        ("sample", sample_program()),
        ("regions", sample_program()),
        ("calls", call_graph_program()),
        ("classes", class_hierarchy_program()),
        ("lineage", class_calls_program()),
        ("entry", packaged_entry_program()),
        ("library", packaged_library_program()),
        ("debug", debug_program()),
        ("debug-13", debug_program()),
    ];
    programs[1].1.split_region_before(INDEX_PAGE);
    programs[8].1.version(VERSION_13_0_1_0);

    let dir = std::env::temp_dir().join(format!("asc-pasm-oracle-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap_or_else(|err| panic!("{}: {err}", dir.display()));
    let mut failed = Vec::new();
    for (name, builder) in &programs {
        let data = builder.build().bytes;
        let abc_path = dir.join(format!("{name}.abc"));
        std::fs::write(&abc_path, &data).unwrap();
        for verbose in [false, true] {
            let listing = dir.join(format!("{name}{}.pa", if verbose { "-verbose" } else { "" }));
            let mut command = std::process::Command::new(&tool);
            if verbose {
                command.arg("--verbose");
            }
            let run = command.arg(&abc_path).arg(&listing).output().unwrap_or_else(|err| panic!("{}: {err}", Path::new(&tool).display()));
            if !run.status.success() || !starts_with(&listing, LISTING_HEAD) {
                let said = String::from_utf8_lossy(&run.stderr);
                failed.push(format!("{name}: the official tool rejects the file ({}): {}", run.status, said.trim()));
                continue;
            }
            let outcome = compare(&data, std::slice::from_ref(&listing));
            println!("==== {name}{}", if verbose { " --verbose" } else { "" });
            print!("{}", outcome.report);
            if !outcome.unknown().is_empty() {
                failed.push(format!("{name}: {:?}", outcome.unknown()));
            }
            let functions = outcome.count("functions in oracle");
            if functions == 0 || functions != outcome.count("functions identical") {
                failed.push(format!("{name}: {functions} functions, {} identical", outcome.count("functions identical")));
            }
            if verbose && name.starts_with("debug") {
                // Every table of the debug function was there to compare.
                let compared = ["line rows", "column rows", "local variable rows", "parameter rows"]
                    .map(|what| (outcome.count(&format!("{what} compared")), outcome.count(&format!("{what} identical"))));
                if compared != [(5, 5), (3, 3), (5, 5), (3, 3)] {
                    failed.push(format!("{name}: debug tables compared and identical: {compared:?}"));
                }
            }
        }
    }
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(failed.is_empty(), "the official disassembler on fixture files:\n{}", failed.join("\n"));
}

/// The sources in `tests/es2abc` every compiler target takes. They import
/// one another by relative path.
const SOURCES: [&str; 7] = ["classes.ts", "closures.js", "extras.ts", "flow.js", "lib.ts", "main.ts", "other.ts"];
/// Those and the one that declares annotations, which API 20 brought.
const ANNOTATED: [&str; 8] = ["annotations.ts", "classes.ts", "closures.js", "extras.ts", "flow.js", "lib.ts", "main.ts", "other.ts"];
/// The sources that are scripts as well as modules: no `import`, no `export`.
const SCRIPTS: [&str; 2] = ["closures.js", "flow.js"];

/// `--target-api-version` and `--target-api-sub-version` of the builds:
/// one per bytecode version the compiler of API 26 writes (9.0.0.0,
/// 11.0.2.0, 12.0.2.0, 12.0.6.0, 13.0.1.0, 24.0.0.0). A compiler that maps
/// them otherwise is believed: it is asked which version each one is.
const TARGETS: [(u32, Option<&str>); 6] = [(9, None), (11, None), (12, Some("beta1")), (12, Some("beta3")), (20, None), (24, None)];

/// How files are built from the sources.
struct Build {
    name: &'static str,
    sources: &'static [&'static str],
    /// All sources in one file, as an application is packed, or one file
    /// per source.
    merged: bool,
    flags: &'static [&'static str],
    /// The first API version the compiler takes the flags or the sources for.
    since: u32,
}

const MODULE: &str = "--module";
const BUILDS: [Build; 13] = [
    Build { name: "merged", sources: &SOURCES, merged: true, flags: &[MODULE], since: 0 },
    Build { name: "merged-debug", sources: &SOURCES, merged: true, flags: &[MODULE, "--debug-info"], since: 0 },
    Build { name: "merged-unoptimized", sources: &SOURCES, merged: true, flags: &[MODULE, "--opt-level", "0"], since: 0 },
    Build { name: "merged-columns", sources: &SOURCES, merged: true, flags: &[MODULE, "--enable-release-column"], since: 0 },
    Build { name: "single", sources: &SOURCES, merged: false, flags: &[MODULE], since: 0 },
    Build { name: "single-debug", sources: &SOURCES, merged: false, flags: &[MODULE, "--debug-info"], since: 0 },
    Build { name: "commonjs", sources: &SCRIPTS, merged: false, flags: &["--commonjs"], since: 0 },
    Build { name: "script", sources: &SCRIPTS, merged: false, flags: &[], since: 0 },
    Build { name: "annotated", sources: &ANNOTATED, merged: true, flags: &[MODULE, "--enable-annotations"], since: 20 },
    Build {
        name: "annotated-debug",
        sources: &ANNOTATED,
        merged: true,
        flags: &[MODULE, "--enable-annotations", "--debug-info"],
        since: 20,
    },
    Build { name: "annotated-single", sources: &["annotations.ts"], merged: false, flags: &[MODULE, "--enable-annotations"], since: 20 },
    Build { name: "implements", sources: &SOURCES, merged: true, flags: &[MODULE, "--enable-ets-implements"], since: 20 },
    Build { name: "callable-names", sources: &SOURCES, merged: true, flags: &[MODULE, "--enable-callable-name"], since: 24 },
];

/// Run `command`; what it printed when it failed.
fn run(command: &mut std::process::Command) -> Result<String, String> {
    let program = command.get_program().to_string_lossy().into_owned();
    let out = command.output().map_err(|err| format!("{program}: {err}"))?;
    let said = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    if out.status.success() { Ok(said) } else { Err(format!("{program}: {}: {}", out.status, said.trim())) }
}

/// `$ASC_ES2ABC` is the official compiler (`es2abc`), `$ASC_ARK_DISASM` the
/// official disassembler. The sources in `tests/es2abc` are compiled on the
/// spot for every bytecode version the compiler targets, in every way
/// [`BUILDS`] lists; each file is disassembled by the official tool and
/// compared like any other listing. Without both variables the test does
/// nothing.
#[test]
fn official_compiler_output_agrees_in_every_version() {
    let (Some(compiler), Some(tool)) = (std::env::var_os("ASC_ES2ABC"), std::env::var_os("ASC_ARK_DISASM")) else { return };
    let sources = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/es2abc");
    let dir = std::env::temp_dir().join(format!("asc-pasm-es2abc-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap_or_else(|err| panic!("{}: {err}", dir.display()));

    let mut failed = Vec::new();
    let mut versions = Vec::new();
    let mut summary = String::new();
    let mut opcodes = Opcodes::new();
    for (api, sub) in TARGETS {
        let target = || {
            let mut command = std::process::Command::new(&compiler);
            command.arg("--target-api-version").arg(api.to_string());
            if let Some(sub) = sub {
                command.args(["--target-api-sub-version", sub]);
            }
            command
        };
        let label = format!("api-{api}{}", sub.map_or(String::new(), |sub| format!("-{sub}")));
        let stated = match run(target().arg("--target-bc-version")) {
            Ok(stated) => stated.trim().to_owned(),
            Err(why) => {
                failed.push(format!("{label}: {why}"));
                continue;
            }
        };
        versions.push(stated.clone());
        for build in BUILDS.iter().filter(|build| build.since <= api) {
            let inputs: Vec<(String, PathBuf, &str)> = if build.merged {
                // One line per source: path;record;module kind;source file;package;shared.
                let list = dir.join(format!("{label}-{}.txt", build.name));
                let line = |file: &&str| {
                    let stem = file.rsplit_once('.').map_or(*file, |(stem, _)| stem);
                    format!("{};&entry/src/main/ets/{stem}&;esm;entry/src/main/ets/{file};entry;false\n", sources.join(file).display())
                };
                std::fs::write(&list, build.sources.iter().map(line).collect::<String>()).unwrap();
                vec![(build.name.to_owned(), PathBuf::from(format!("@{}", list.display())), "ts")]
            } else {
                let named = |file: &&'static str| {
                    let (stem, extension) = file.rsplit_once('.').unwrap();
                    (format!("{}-{stem}", build.name), sources.join(file), extension)
                };
                build.sources.iter().map(named).collect()
            };
            for (name, input, extension) in inputs {
                let name = format!("{label}-{name}");
                let (abc_path, listing) = (dir.join(format!("{name}.abc")), dir.join(format!("{name}.pa")));
                let mut compile = target();
                compile.args(["--extension", extension]).args(build.flags);
                if build.merged {
                    compile.arg("--merge-abc");
                }
                compile.arg("--output").arg(&abc_path).arg(&input);
                let disassembled =
                    run(&mut compile).and_then(|_| run(std::process::Command::new(&tool).arg("--verbose").arg(&abc_path).arg(&listing)));
                if let Err(why) = disassembled {
                    failed.push(format!("{name}: {why}"));
                    continue;
                }
                let data = std::fs::read(&abc_path).unwrap();
                let version = Abc::parse(&data).map(|abc| abc.header().version.to_string());
                if version.as_ref().ok() != Some(&stated) {
                    failed.push(format!("{name}: the compiler says {stated}, the header reads {version:?}"));
                    continue;
                }
                let outcome = compare(&data, std::slice::from_ref(&listing));
                println!("==== {name} ({stated})");
                print!("{}", outcome.report);
                let (functions, identical) = (outcome.count("functions in oracle"), outcome.count("functions identical"));
                let unknown: u64 = outcome.divergences.iter().filter(|(.., known)| !known).map(|(_, count, _)| count).sum();
                writeln!(
                    summary,
                    "{name} ({stated}): {functions} functions ({identical} identical), {} instructions ({} identical), {} opcodes, \
                     {unknown} divergences",
                    outcome.count("instructions compared"),
                    outcome.count("instructions identical"),
                    outcome.opcodes.len(),
                )
                .unwrap();
                if !outcome.unknown().is_empty() {
                    failed.push(format!("{name}: {:?}", outcome.unknown()));
                }
                if functions == 0 || functions != identical {
                    failed.push(format!("{name}: {functions} functions, {identical} identical"));
                }
                for (key, (mnemonic, count)) in outcome.opcodes {
                    opcodes.entry(key).or_insert((mnemonic, 0)).1 += count;
                }
            }
        }
    }
    println!("==== summary\n{summary}");
    let mut seen = String::new();
    opcode_lines(&mut seen, &opcodes);
    print!("{seen}");
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(failed.is_empty(), "the official compiler's files:\n{}", failed.join("\n"));
    versions.dedup();
    assert!(versions.len() > 1, "one bytecode version only: {versions:?}");
}

#[test]
fn listing_lines_are_read_one_at_a_time() {
    let mut lines = Lines::new(&b"first\n\n\tsecond\r\nlast"[..]);
    assert_eq!(lines.next(), Some(&b"first"[..]));
    assert_eq!(lines.next(), Some(&b""[..]));
    lines.unread();
    assert_eq!(lines.next(), Some(&b""[..]));
    // Only the line feed ends a line: the tool writes strings as they are.
    assert_eq!(lines.next(), Some(&b"\tsecond\r"[..]));
    assert_eq!(lines.next(), Some(&b"last"[..]));
    assert_eq!(lines.next(), None);
}

#[test]
fn catch_lines_name_their_labels() {
    let (kind, labels) =
        catch_line(b".catchall try_begin_label_0, try_end_label_0, handler_begin_label_0_0, handler_end_label_0_0").unwrap();
    assert_eq!(kind, None);
    assert_eq!(labels, [&b"try_begin_label_0"[..], b"try_end_label_0", b"handler_begin_label_0_0", b"handler_end_label_0_0"]);
    let (kind, labels) = catch_line(b".catch Error, try_begin_label_1, try_end_label_1, try_end_label_1").unwrap();
    assert_eq!(kind, Some(&b"Error"[..]));
    assert_eq!(labels.len(), 3);
    assert!(catch_line(b"\tlda v0").is_none());
    assert!(labels.iter().all(|label| is_label_name(label)));
    // The label `AddLabels` writes after the last instruction has no name.
    assert_eq!(is_label(b":"), None);
    assert_eq!(is_label(b"jump_label_12:"), Some(&b"jump_label_12"[..]));
}
