//! baksmali-style disassembly of one class.
//!
//! This is the built-in "decompile" backend of the Rust port: the rebuilt
//! single-class DEX is rendered as smali so the output is always available
//! without an external Java decompiler. The rebuilt DEX itself is a valid
//! file that external tools (jadx, baksmali, dexdump) can consume as well.

mod format;
mod insn;

use asc_dex::annotations::{parse_annotation_set, parse_annotation_set_ref_list, AnnotationsDirectory};
use asc_dex::class_data::{EncodedField, EncodedMethod};
use asc_dex::debug_info::DebugInfo;
use asc_dex::encoded::{parse_annotation_item, parse_array, AnnotationItem, EncodedValue};
use asc_dex::{access, ClassDef, Dex, NO_INDEX};
use std::collections::HashMap;
use std::fmt::Write as _;

pub use format::{escape_string, method_signature, proto_descriptor};

#[derive(Debug, thiserror::Error)]
pub enum SmaliError {
    #[error(transparent)]
    Dex(#[from] asc_dex::DexError),
    #[error("class {0} not found")]
    ClassNotFound(String),
}

pub type Result<T> = std::result::Result<T, SmaliError>;

/// Rendering options.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Emit `.line` directives from debug info.
    pub line_numbers: bool,
    /// Emit `.param` names from debug info.
    pub param_names: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options { line_numbers: true, param_names: true }
    }
}

/// Disassemble the class with the given descriptor.
pub fn disassemble_class(dex: &Dex<'_>, descriptor: &str, opts: Options) -> Result<String> {
    let (index, _) = dex.find_class_def(descriptor.as_bytes())?.ok_or_else(|| SmaliError::ClassNotFound(descriptor.to_string()))?;
    disassemble_class_def(dex, index, opts)
}

/// Disassemble class definition number `index`.
pub fn disassemble_class_def(dex: &Dex<'_>, index: u32, opts: Options) -> Result<String> {
    let def = dex.class_def(index)?;
    let mut w = Writer { names: Names::new(dex), out: String::with_capacity(16 * 1024), opts };
    w.class(&def)?;
    Ok(w.out)
}

/// Per-class memo of rendered type descriptors, prototypes and member
/// signatures, keyed by index (the same method or field is typically
/// referenced many times inside one class).
pub(crate) struct Names<'d, 'a> {
    pub dex: &'d Dex<'a>,
    types: HashMap<u32, String>,
    protos: HashMap<u32, String>,
    fields: HashMap<u32, String>,
    methods: HashMap<u32, String>,
}

impl<'d, 'a> Names<'d, 'a> {
    fn new(dex: &'d Dex<'a>) -> Self {
        Names { dex, types: HashMap::new(), protos: HashMap::new(), fields: HashMap::new(), methods: HashMap::new() }
    }

    pub fn type_(&mut self, idx: u32) -> Result<&str> {
        if !self.types.contains_key(&idx) {
            self.types.insert(idx, self.dex.type_descriptor(idx)?);
        }
        Ok(self.types[&idx].as_str())
    }

    pub fn proto(&mut self, idx: u32) -> Result<&str> {
        if !self.protos.contains_key(&idx) {
            self.protos.insert(idx, proto_descriptor(self.dex, idx)?);
        }
        Ok(self.protos[&idx].as_str())
    }

    pub fn field(&mut self, idx: u32) -> Result<&str> {
        if !self.fields.contains_key(&idx) {
            self.fields.insert(idx, format::field_signature(self.dex, idx)?);
        }
        Ok(self.fields[&idx].as_str())
    }

    pub fn method(&mut self, idx: u32) -> Result<&str> {
        if !self.methods.contains_key(&idx) {
            self.methods.insert(idx, method_signature(self.dex, idx)?);
        }
        Ok(self.methods[&idx].as_str())
    }
}

struct Annotations {
    class: Vec<AnnotationItem>,
    fields: HashMap<u32, Vec<AnnotationItem>>,
    methods: HashMap<u32, Vec<AnnotationItem>>,
    params: HashMap<u32, Vec<Vec<AnnotationItem>>>,
}

struct Writer<'d, 'a> {
    names: Names<'d, 'a>,
    out: String,
    opts: Options,
}

const CLASS_FLAGS: &[(u32, &str)] = &[
    (access::PUBLIC, "public"),
    (access::PRIVATE, "private"),
    (access::PROTECTED, "protected"),
    (access::STATIC, "static"),
    (access::FINAL, "final"),
    (access::INTERFACE, "interface"),
    (access::ABSTRACT, "abstract"),
    (access::SYNTHETIC, "synthetic"),
    (access::ANNOTATION, "annotation"),
    (access::ENUM, "enum"),
];

const FIELD_FLAGS: &[(u32, &str)] = &[
    (access::PUBLIC, "public"),
    (access::PRIVATE, "private"),
    (access::PROTECTED, "protected"),
    (access::STATIC, "static"),
    (access::FINAL, "final"),
    (access::VOLATILE, "volatile"),
    (access::TRANSIENT, "transient"),
    (access::SYNTHETIC, "synthetic"),
    (access::ENUM, "enum"),
];

const METHOD_FLAGS: &[(u32, &str)] = &[
    (access::PUBLIC, "public"),
    (access::PRIVATE, "private"),
    (access::PROTECTED, "protected"),
    (access::STATIC, "static"),
    (access::FINAL, "final"),
    (access::SYNCHRONIZED, "synchronized"),
    (access::BRIDGE, "bridge"),
    (access::VARARGS, "varargs"),
    (access::NATIVE, "native"),
    (access::ABSTRACT, "abstract"),
    (access::STRICT, "strictfp"),
    (access::SYNTHETIC, "synthetic"),
    (access::CONSTRUCTOR, "constructor"),
    (access::DECLARED_SYNCHRONIZED, "declared-synchronized"),
];

fn flags(value: u32, table: &[(u32, &str)]) -> String {
    let mut s = String::new();
    for (bit, name) in table {
        if value & bit != 0 {
            s.push_str(name);
            s.push(' ');
        }
    }
    s
}

impl<'d, 'a> Writer<'d, 'a> {
    fn load_annotations(&self, def: &ClassDef) -> Result<Annotations> {
        let mut ann = Annotations { class: Vec::new(), fields: HashMap::new(), methods: HashMap::new(), params: HashMap::new() };
        if def.annotations_off == 0 {
            return Ok(ann);
        }
        let buf = self.names.dex.buf();
        let dir = AnnotationsDirectory::parse(buf, def.annotations_off as usize)?;
        let load_set = |off: u32| -> Result<Vec<AnnotationItem>> {
            if off == 0 {
                return Ok(Vec::new());
            }
            let mut items = Vec::new();
            for item_off in parse_annotation_set(buf, off as usize)? {
                if item_off != 0 {
                    items.push(parse_annotation_item(buf, item_off as usize)?.0);
                }
            }
            Ok(items)
        };
        ann.class = load_set(dir.class_annotations_off)?;
        for (f, off) in dir.field_annotations {
            ann.fields.insert(f, load_set(off)?);
        }
        for (m, off) in dir.method_annotations {
            ann.methods.insert(m, load_set(off)?);
        }
        for (m, off) in dir.parameter_annotations {
            if off == 0 {
                continue;
            }
            let mut params = Vec::new();
            for set_off in parse_annotation_set_ref_list(buf, off as usize)? {
                params.push(load_set(set_off)?);
            }
            ann.params.insert(m, params);
        }
        Ok(ann)
    }

    fn class(&mut self, def: &ClassDef) -> Result<()> {
        let dex = self.names.dex;
        let _ = writeln!(self.out, ".class {}{}", flags(def.access_flags, CLASS_FLAGS), self.names.type_(def.class_idx)?);
        if def.superclass_idx != NO_INDEX {
            let _ = writeln!(self.out, ".super {}", self.names.type_(def.superclass_idx)?);
        }
        if def.source_file_idx != NO_INDEX {
            let _ = writeln!(self.out, ".source \"{}\"", escape_string(&dex.string(def.source_file_idx)?));
        }
        let interfaces = dex.type_list(def.interfaces_off)?;
        if !interfaces.is_empty() {
            self.out.push_str("\n\n# interfaces\n");
            for t in interfaces {
                let _ = writeln!(self.out, ".implements {}", self.names.type_(t as u32)?);
            }
        }
        let ann = self.load_annotations(def)?;
        if !ann.class.is_empty() {
            self.out.push_str("\n\n# annotations\n");
            for (i, item) in ann.class.iter().enumerate() {
                if i > 0 {
                    self.out.push('\n');
                }
                self.annotation(item, 0)?;
            }
        }

        let cd = dex.class_data(def.class_data_off)?;
        let static_values = if def.static_values_off != 0 { parse_array(dex.buf(), def.static_values_off as usize)?.0 } else { Vec::new() };

        if !cd.static_fields.is_empty() {
            self.out.push_str("\n\n# static fields\n");
            for (i, f) in cd.static_fields.iter().enumerate() {
                if i > 0 {
                    self.out.push('\n');
                }
                self.field(f, static_values.get(i), ann.fields.get(&f.field_idx))?;
            }
        }
        if !cd.instance_fields.is_empty() {
            self.out.push_str("\n\n# instance fields\n");
            for (i, f) in cd.instance_fields.iter().enumerate() {
                if i > 0 {
                    self.out.push('\n');
                }
                self.field(f, None, ann.fields.get(&f.field_idx))?;
            }
        }
        if !cd.direct_methods.is_empty() {
            self.out.push_str("\n\n# direct methods\n");
            for (i, m) in cd.direct_methods.iter().enumerate() {
                if i > 0 {
                    self.out.push('\n');
                }
                self.method(m, &ann)?;
            }
        }
        if !cd.virtual_methods.is_empty() {
            self.out.push_str("\n\n# virtual methods\n");
            for (i, m) in cd.virtual_methods.iter().enumerate() {
                if i > 0 {
                    self.out.push('\n');
                }
                self.method(m, &ann)?;
            }
        }
        Ok(())
    }

    fn field(&mut self, f: &EncodedField, value: Option<&EncodedValue>, annotations: Option<&Vec<AnnotationItem>>) -> Result<()> {
        let dex = self.names.dex;
        let id = dex.field_id(f.field_idx)?;
        let _ = write!(
            self.out,
            ".field {}{}:{}",
            flags(f.access_flags, FIELD_FLAGS),
            dex.string(id.name_idx)?,
            self.names.type_(id.type_idx as u32)?
        );
        if let Some(v) = value {
            let _ = write!(self.out, " = {}", format::value(dex, v)?);
        }
        self.out.push('\n');
        if let Some(items) = annotations.filter(|a| !a.is_empty()) {
            for item in items {
                self.annotation(item, 1)?;
            }
            self.out.push_str(".end field\n");
        }
        Ok(())
    }

    fn method(&mut self, m: &EncodedMethod, ann: &Annotations) -> Result<()> {
        let dex = self.names.dex;
        let id = dex.method_id(m.method_idx)?;
        let _ = writeln!(
            self.out,
            ".method {}{}{}",
            flags(m.access_flags, METHOD_FLAGS),
            dex.string(id.name_idx)?,
            self.names.proto(id.proto_idx as u32)?
        );
        let code = if m.code_off != 0 { Some(dex.code_item(m.code_off)?) } else { None };
        if let Some(code) = &code {
            let _ = writeln!(self.out, "    .registers {}", code.registers_size);
            if code.ins_size > code.registers_size {
                let _ = writeln!(
                    self.out,
                    "    # malformed code_item: ins_size {} exceeds registers_size {}",
                    code.ins_size, code.registers_size
                );
            }
        }
        let debug = match &code {
            Some(c) if c.debug_info_off != 0 => DebugInfo::parse(dex.buf(), c.debug_info_off as usize).ok().map(|d| d.0),
            _ => None,
        };
        // Parameters: names from debug info, annotations from the directory.
        // Methods without code (abstract / native) still carry both, and their
        // parameter registers start at 0 (or 1 after `this`), exactly as if
        // `registers_size == ins_size` (baksmali's `writeEmptyMethodTo`).
        let params = dex.proto_params(id.proto_idx as u32)?;
        let param_annotations = ann.params.get(&m.method_idx);
        let is_static = m.access_flags & access::STATIC != 0;
        let mut reg = code.as_ref().map_or(0, |c| c.registers_size.saturating_sub(c.ins_size) as usize);
        if !is_static {
            reg += 1;
        }
        for (i, &pt) in params.iter().enumerate() {
            let name = debug.as_ref().and_then(|d| d.parameter_names.get(i).copied().flatten());
            let anns = param_annotations.and_then(|p| p.get(i)).filter(|a| !a.is_empty());
            let desc = self.names.type_(pt as u32)?;
            let wide = desc == "J" || desc == "D";
            if (self.opts.param_names && name.is_some()) || anns.is_some() {
                let _ = write!(self.out, "    .param v{reg}");
                if let Some(n) = name.filter(|_| self.opts.param_names) {
                    let _ = write!(self.out, ", \"{}\"", escape_string(&dex.string(n)?));
                }
                let _ = writeln!(self.out, "    # {desc}");
                if let Some(items) = anns {
                    for item in items {
                        self.annotation(item, 2)?;
                    }
                    self.out.push_str("    .end param\n");
                }
            }
            reg += if wide { 2 } else { 1 };
        }
        if let Some(items) = ann.methods.get(&m.method_idx) {
            for item in items {
                self.annotation(item, 1)?;
            }
        }
        if let Some(code) = &code {
            self.out.push('\n');
            insn::method_body(&mut self.names, code, debug.as_ref(), self.opts, &mut self.out)?;
        }
        self.out.push_str(".end method\n");
        Ok(())
    }

    fn annotation(&mut self, item: &AnnotationItem, depth: usize) -> Result<()> {
        let vis = match item.visibility {
            0 => "build",
            1 => "runtime",
            2 => "system",
            _ => "runtime",
        };
        let indent = "    ".repeat(depth);
        let _ = writeln!(self.out, "{indent}.annotation {vis} {}", self.names.type_(item.annotation.type_idx)?);
        let dex = self.names.dex;
        for (name, value) in &item.annotation.elements {
            let _ = writeln!(self.out, "{indent}    {} = {}", dex.string(*name)?, format::value_indented(dex, value, depth + 1)?);
        }
        let _ = writeln!(self.out, "{indent}.end annotation");
        Ok(())
    }
}
