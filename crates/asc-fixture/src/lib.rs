//! Hand-built DEX files for tests (ported from the Python `dex_fixture.py`).
//!
//! `make_dex`, `make_static_field_dex` and `make_apk` are byte-stable: other
//! crates' tests depend on their exact layout. Richer fixtures are produced by
//! [`DexBuilder`], a small two-phase assembler (declare the constant pool,
//! resolve it to canonical sorted ids, then add classes with bytecode that
//! uses those ids).

use asc_dex::checksum::seal;
use asc_dex::debug_info::{DebugInfo, DebugOp, DBG_FIRST_SPECIAL, DBG_LINE_BASE, DBG_LINE_RANGE};
use asc_dex::encoded::{write_annotation_item, write_array, AnnotationItem, EncodedAnnotation, EncodedValue, Identity};
use asc_dex::leb128::{write_sleb128, write_uleb128};
use asc_dex::{mutf8, NO_INDEX};
use std::collections::{BTreeMap, HashMap};
use std::io::Write;

fn uleb(value: u32) -> Vec<u8> {
    let mut v = Vec::new();
    write_uleb128(&mut v, value);
    v
}

struct Builder {
    buf: Vec<u8>,
    sections: Vec<(u16, u32, u32)>,
}

impl Builder {
    fn new() -> Self {
        Builder { buf: vec![0u8; 112], sections: vec![(0, 1, 0)] }
    }

    fn section(&mut self, kind: u16, size: u32, data: &[u8], align: usize) -> u32 {
        while self.buf.len() % align != 0 {
            self.buf.push(0);
        }
        let off = self.buf.len() as u32;
        self.sections.push((kind, size, off));
        self.buf.extend_from_slice(data);
        off
    }

    fn put_u32(&mut self, off: usize, v: u32) {
        self.buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn finish(mut self, ids: [(u32, u32); 6], data_off: u32) -> Vec<u8> {
        while self.buf.len() % 4 != 0 {
            self.buf.push(0);
        }
        let map_off = self.buf.len() as u32;
        self.sections.push((0x1000, 1, map_off));
        let count = self.sections.len() as u32;
        self.buf.extend_from_slice(&count.to_le_bytes());
        for (kind, size, off) in self.sections.clone() {
            self.buf.extend_from_slice(&kind.to_le_bytes());
            self.buf.extend_from_slice(&0u16.to_le_bytes());
            self.buf.extend_from_slice(&size.to_le_bytes());
            self.buf.extend_from_slice(&off.to_le_bytes());
        }
        self.buf[..8].copy_from_slice(b"dex\n035\0");
        let file_size = self.buf.len() as u32;
        self.put_u32(32, file_size);
        self.put_u32(36, 112);
        self.put_u32(40, 0x12345678);
        self.put_u32(44, 0);
        self.put_u32(48, 0);
        self.put_u32(52, map_off);
        let mut p = 56;
        for (size, off) in ids {
            self.put_u32(p, size);
            self.put_u32(p + 4, off);
            p += 8;
        }
        self.put_u32(104, file_size - data_off);
        self.put_u32(108, data_off);
        seal(&mut self.buf);
        self.buf
    }
}

fn string_data(strings: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for s in strings {
        out.extend(uleb(s.len() as u32));
        out.extend_from_slice(s);
        out.push(0);
    }
    out
}

fn fill_string_ids(b: &mut Builder, string_ids: u32, strings: &[&[u8]], mut off: u32) {
    for (i, s) in strings.iter().enumerate() {
        b.put_u32(string_ids as usize + 4 * i, off);
        off += uleb(s.len() as u32).len() as u32 + s.len() as u32 + 1;
    }
}

fn pack_u32s(vals: &[u32]) -> Vec<u8> {
    vals.iter().flat_map(|v| v.to_le_bytes()).collect()
}

fn pack_hhi(items: &[(u16, u16, u32)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (a, b, c) in items {
        out.extend_from_slice(&a.to_le_bytes());
        out.extend_from_slice(&b.to_le_bytes());
        out.extend_from_slice(&c.to_le_bytes());
    }
    out
}

fn code_item(regs: u16, insns: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&regs.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&((insns.len() / 2) as u32).to_le_bytes());
    out.extend_from_slice(insns);
    out
}

/// A DEX with class `Lexample/Test;` whose two static methods `first` and
/// `second` share one `code_item` (`const-string v0, "token"; return-void`).
pub fn make_dex() -> Vec<u8> {
    let strings: [&[u8]; 6] = [b"Lexample/Test;", b"Ljava/lang/Object;", b"V", b"first", b"second", b"token"];
    let mut b = Builder::new();
    let string_ids = b.section(1, 6, &[0u8; 24], 4);
    let type_ids = b.section(2, 3, &pack_u32s(&[0, 1, 2]), 4);
    let proto_ids = b.section(3, 1, &pack_u32s(&[2, 2, 0]), 4);
    let method_ids = b.section(5, 2, &pack_hhi(&[(0, 0, 3), (0, 0, 4)]), 4);
    let class_defs = b.section(6, 1, &[0u8; 32], 4);
    let data_off = b.buf.len() as u32;
    let sd = string_data(&strings);
    let off = b.section(0x2002, 6, &sd, 1);
    fill_string_ids(&mut b, string_ids, &strings, off);
    let code = b.section(0x2001, 1, &code_item(1, b"\x1a\x00\x05\x00\x0e\x00"), 4);
    let mut cd = vec![0, 0, 2, 0, 0, 9];
    cd.extend(uleb(code));
    cd.extend([1, 9]);
    cd.extend(uleb(code));
    let class_data = b.section(0x2000, 1, &cd, 1);
    let cdef = pack_u32s(&[0, 1, 1, 0, 0xffff_ffff, 0, class_data, 0]);
    b.buf[class_defs as usize..class_defs as usize + 32].copy_from_slice(&cdef);
    b.finish([(6, string_ids), (3, type_ids), (1, proto_ids), (0, 0), (2, method_ids), (1, class_defs)], data_off)
}

/// A DEX whose `static_values` and `sget` field operand must stay aligned:
/// class `Lexample/Statics;` with static ints `FIRST = 11`, `SECOND = 22` and
/// `getSecond()` returning `SECOND`.
pub fn make_static_field_dex() -> Vec<u8> {
    let strings: [&[u8]; 6] = [b"Lexample/Statics;", b"Ljava/lang/Object;", b"I", b"FIRST", b"SECOND", b"getSecond"];
    let mut b = Builder::new();
    let string_ids = b.section(1, 6, &[0u8; 24], 4);
    let type_ids = b.section(2, 3, &pack_u32s(&[0, 1, 2]), 4);
    let proto_ids = b.section(3, 1, &pack_u32s(&[2, 2, 0]), 4);
    let field_ids = b.section(4, 2, &pack_hhi(&[(0, 2, 3), (0, 2, 4)]), 4);
    let method_ids = b.section(5, 1, &pack_hhi(&[(0, 0, 5)]), 4);
    let class_defs = b.section(6, 1, &[0u8; 32], 4);
    let data_off = b.buf.len() as u32;
    let sd = string_data(&strings);
    let off = b.section(0x2002, 6, &sd, 1);
    fill_string_ids(&mut b, string_ids, &strings, off);
    // sget v0, field@1 (SECOND); return v0
    let code = b.section(0x2001, 1, &code_item(1, b"\x60\x00\x01\x00\x0f\x00"), 4);
    let mut cd = vec![2, 0, 1, 0, 0, 9, 1, 9, 0, 9];
    cd.extend(uleb(code));
    let class_data = b.section(0x2000, 1, &cd, 1);
    let static_values = b.section(0x2005, 1, b"\x02\x04\x0b\x04\x16", 1);
    let cdef = pack_u32s(&[0, 1, 1, 0, 0xffff_ffff, 0, class_data, static_values]);
    b.buf[class_defs as usize..class_defs as usize + 32].copy_from_slice(&cdef);
    b.finish([(6, string_ids), (3, type_ids), (1, proto_ids), (2, field_ids), (1, method_ids), (1, class_defs)], data_off)
}

/// Build an in-memory APK (zip) from `(name, bytes)` entries.
pub fn make_apk(entries: &[(&str, &[u8])], deflate: bool) -> Vec<u8> {
    let cursor = std::io::Cursor::new(Vec::new());
    let mut zw = zip::ZipWriter::new(cursor);
    let method = if deflate { zip::CompressionMethod::Deflated } else { zip::CompressionMethod::Stored };
    let opts = zip::write::SimpleFileOptions::default().compression_method(method);
    for (name, data) in entries {
        zw.start_file(*name, opts).expect("start_file");
        zw.write_all(data).expect("write");
    }
    zw.finish().expect("finish").into_inner()
}

// ---------------------------------------------------------------------------
// Hand-built static_values edge cases
// ---------------------------------------------------------------------------

/// Like [`make_static_field_dex`] but with the field ids in non-canonical
/// order (`field@0 = ZETA`, `field@1 = ALPHA`) so `class_data` lists
/// `ZETA` first while the rebuilt (sorted) table puts `ALPHA` first:
/// `ZETA = 11`, `ALPHA = 22`, `getAlpha()` returns `ALPHA`.
pub fn make_unsorted_static_field_dex() -> Vec<u8> {
    let strings: [&[u8]; 6] = [b"ALPHA", b"I", b"Lexample/Unsorted;", b"Ljava/lang/Object;", b"ZETA", b"getAlpha"];
    let mut b = Builder::new();
    let string_ids = b.section(1, 6, &[0u8; 24], 4);
    let type_ids = b.section(2, 3, &pack_u32s(&[2, 3, 1]), 4);
    let proto_ids = b.section(3, 1, &pack_u32s(&[1, 2, 0]), 4);
    // field@0 = ZETA, field@1 = ALPHA (canonical order would be the reverse)
    let field_ids = b.section(4, 2, &pack_hhi(&[(0, 2, 4), (0, 2, 0)]), 4);
    let method_ids = b.section(5, 1, &pack_hhi(&[(0, 0, 5)]), 4);
    let class_defs = b.section(6, 1, &[0u8; 32], 4);
    let data_off = b.buf.len() as u32;
    let sd = string_data(&strings);
    let off = b.section(0x2002, 6, &sd, 1);
    fill_string_ids(&mut b, string_ids, &strings, off);
    // sget v0, field@1 (ALPHA); return v0
    let code = b.section(0x2001, 1, &code_item(1, b"\x60\x00\x01\x00\x0f\x00"), 4);
    let mut cd = vec![2, 0, 1, 0, 0, 9, 1, 9, 0, 9];
    cd.extend(uleb(code));
    let class_data = b.section(0x2000, 1, &cd, 1);
    // ZETA = 11, ALPHA = 22 (positional over class_data order)
    let static_values = b.section(0x2005, 1, b"\x02\x04\x0b\x04\x16", 1);
    let cdef = pack_u32s(&[0, 1, 1, 0, 0xffff_ffff, 0, class_data, static_values]);
    b.buf[class_defs as usize..class_defs as usize + 32].copy_from_slice(&cdef);
    b.finish([(6, string_ids), (3, type_ids), (1, proto_ids), (2, field_ids), (1, method_ids), (1, class_defs)], data_off)
}

/// Three static fields with non-canonical ids (`field@0 = ZETA:I`,
/// `field@1 = ALPHA:Z`, `field@2 = MID:Ljava/lang/String;`) and a
/// `static_values` array holding only `ZETA = 5`: after canonical sorting
/// `ZETA` is last, so the rebuilt array must pad `ALPHA` and `MID` with their
/// zero values instead of shifting `5` onto `ALPHA`.
pub fn make_short_static_values_dex() -> Vec<u8> {
    let strings: [&[u8]; 8] = [b"ALPHA", b"I", b"Lexample/Short;", b"Ljava/lang/Object;", b"Ljava/lang/String;", b"MID", b"Z", b"ZETA"];
    let mut b = Builder::new();
    let string_ids = b.section(1, 8, &[0u8; 32], 4);
    // type@0 = I, type@1 = Lexample/Short;, type@2 = Object, type@3 = String, type@4 = Z
    let type_ids = b.section(2, 5, &pack_u32s(&[1, 2, 3, 4, 6]), 4);
    let field_ids = b.section(4, 3, &pack_hhi(&[(1, 0, 7), (1, 4, 0), (1, 3, 5)]), 4);
    let class_defs = b.section(6, 1, &[0u8; 32], 4);
    let data_off = b.buf.len() as u32;
    let sd = string_data(&strings);
    let off = b.section(0x2002, 8, &sd, 1);
    fill_string_ids(&mut b, string_ids, &strings, off);
    let cd = vec![3, 0, 0, 0, 0, 9, 1, 9, 1, 9];
    let class_data = b.section(0x2000, 1, &cd, 1);
    let static_values = b.section(0x2005, 1, b"\x01\x04\x05", 1);
    let cdef = pack_u32s(&[1, 1, 2, 0, 0xffff_ffff, 0, class_data, static_values]);
    b.buf[class_defs as usize..class_defs as usize + 32].copy_from_slice(&cdef);
    b.finish([(8, string_ids), (5, type_ids), (0, 0), (3, field_ids), (0, 0), (1, class_defs)], data_off)
}

// ---------------------------------------------------------------------------
// General two-phase builder
// ---------------------------------------------------------------------------

/// Shorty descriptor of a method prototype.
fn shorty(ret: &str, params: &[String]) -> String {
    let c = |d: &str| match d.as_bytes()[0] {
        b'L' | b'[' => 'L',
        b => b as char,
    };
    let mut s = String::from(c(ret));
    s.extend(params.iter().map(|p| c(p)));
    s
}

/// `DBG_*` special opcode advancing the address by `addr_delta` code units
/// and the line by `line_delta` (`-4..=10`).
pub fn dbg_special(addr_delta: u32, line_delta: i32) -> DebugOp {
    let adjusted = (line_delta - DBG_LINE_BASE) as u32 + DBG_LINE_RANGE * addr_delta;
    assert!(adjusted + DBG_FIRST_SPECIAL as u32 <= 0xff, "special opcode out of range");
    DebugOp::Special(DBG_FIRST_SPECIAL + adjusted as u8)
}

/// Runtime-visible annotation `Ltype; value = "text"`.
pub fn string_annotation(type_idx: u32, name_idx: u32, value_idx: u32) -> AnnotationItem {
    AnnotationItem {
        visibility: 1,
        annotation: EncodedAnnotation { type_idx, elements: vec![(name_idx, EncodedValue::String(value_idx))] },
    }
}

/// One try block with its own handler.
#[derive(Debug, Clone, Default)]
pub struct TrySpec {
    pub start_addr: u32,
    pub insn_count: u16,
    /// `(type_idx, handler_addr)` pairs.
    pub catches: Vec<(u32, u32)>,
    pub catch_all: Option<u32>,
}

/// A `code_item`.
#[derive(Debug, Clone, Default)]
pub struct CodeSpec {
    pub registers: u16,
    pub ins: u16,
    pub outs: u16,
    pub insns: Vec<u8>,
    pub tries: Vec<TrySpec>,
    pub debug: Option<DebugInfo>,
}

/// An `encoded_method` (with `code: None` for abstract / native methods).
#[derive(Debug, Clone)]
pub struct MethodSpec {
    pub idx: u32,
    pub access: u32,
    pub code: Option<CodeSpec>,
}

/// A `class_def_item` with everything it owns.
#[derive(Debug, Clone, Default)]
pub struct ClassSpec {
    pub descriptor: String,
    pub access: u32,
    pub superclass: Option<String>,
    pub interfaces: Vec<String>,
    pub source_file: Option<String>,
    /// `(field_idx, access_flags)`; sorted by index on emission.
    pub static_fields: Vec<(u32, u32)>,
    pub instance_fields: Vec<(u32, u32)>,
    pub direct_methods: Vec<MethodSpec>,
    pub virtual_methods: Vec<MethodSpec>,
    /// Positional over the sorted static fields.
    pub static_values: Vec<EncodedValue>,
    pub class_annotations: Vec<AnnotationItem>,
    pub field_annotations: Vec<(u32, Vec<AnnotationItem>)>,
    pub method_annotations: Vec<(u32, Vec<AnnotationItem>)>,
    /// `(method_idx, one annotation set per parameter)`.
    pub parameter_annotations: Vec<(u32, Vec<Vec<AnnotationItem>>)>,
}

/// Phase 1: declare the constant pool by name. Everything an item needs
/// transitively (type strings, shorties, parameter types) is added
/// automatically; [`DexBuilder::resolve`] sorts the tables canonically.
#[derive(Debug, Default)]
pub struct DexBuilder {
    strings: Vec<String>,
    types: Vec<String>,
    protos: Vec<(String, Vec<String>)>,
    fields: Vec<(String, String, String)>,
    methods: Vec<(String, String, String, Vec<String>)>,
}

impl DexBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn string(&mut self, s: &str) -> &mut Self {
        self.strings.push(s.to_string());
        self
    }

    pub fn type_(&mut self, desc: &str) -> &mut Self {
        self.types.push(desc.to_string());
        self
    }

    pub fn proto(&mut self, ret: &str, params: &[&str]) -> &mut Self {
        self.protos.push((ret.to_string(), params.iter().map(|p| p.to_string()).collect()));
        self
    }

    pub fn field(&mut self, class: &str, name: &str, ty: &str) -> &mut Self {
        self.fields.push((class.to_string(), name.to_string(), ty.to_string()));
        self
    }

    pub fn method(&mut self, class: &str, name: &str, ret: &str, params: &[&str]) -> &mut Self {
        self.methods.push((class.to_string(), name.to_string(), ret.to_string(), params.iter().map(|p| p.to_string()).collect()));
        self
    }

    /// Close the pool over its dependencies and sort every table as the DEX
    /// specification requires.
    #[allow(clippy::type_complexity)]
    pub fn resolve(&self) -> Ids {
        let mut strings: Vec<String> = self.strings.clone();
        let mut types: Vec<String> = self.types.clone();
        let mut protos: Vec<(String, Vec<String>)> = self.protos.clone();
        for (c, _, t) in &self.fields {
            types.push(c.clone());
            types.push(t.clone());
        }
        for (c, _, r, p) in &self.methods {
            types.push(c.clone());
            protos.push((r.clone(), p.clone()));
        }
        for (r, p) in &protos {
            types.push(r.clone());
            types.extend(p.iter().cloned());
            strings.push(shorty(r, p));
        }
        strings.extend(types.iter().cloned());
        strings.extend(self.fields.iter().map(|f| f.1.clone()));
        strings.extend(self.methods.iter().map(|m| m.1.clone()));
        let mut encoded: Vec<(Vec<u16>, Vec<u8>, String)> =
            strings.into_iter().map(|s| (mutf8::to_utf16(&mutf8::encode(&s)), mutf8::encode(&s), s)).collect();
        encoded.sort();
        encoded.dedup_by(|a, b| a.1 == b.1);
        let mut ids = Ids::default();
        for (n, (_, bytes, text)) in encoded.into_iter().enumerate() {
            ids.string_index.insert(text, n as u32);
            ids.strings.push(bytes);
        }
        types.sort_by_key(|t| ids.string_index[t]);
        types.dedup();
        for (n, t) in types.into_iter().enumerate() {
            ids.types.push(ids.string_index[&t]);
            ids.type_index.insert(t, n as u16);
        }
        let mut protos: Vec<(u16, Vec<u16>, String, Vec<String>)> =
            protos.into_iter().map(|(r, p)| (ids.type_index[&r], p.iter().map(|x| ids.type_index[x]).collect(), r, p)).collect();
        protos.sort();
        protos.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);
        for (n, (ret, params, r, p)) in protos.into_iter().enumerate() {
            ids.protos.push((ids.string_index[&shorty(&r, &p)], ret, params));
            ids.proto_index.insert((r, p), n as u16);
        }
        let mut fields: Vec<(u16, u32, u16, (String, String, String))> = self
            .fields
            .iter()
            .map(|(c, n, t)| (ids.type_index[c], ids.string_index[n], ids.type_index[t], (c.clone(), n.clone(), t.clone())))
            .collect();
        fields.sort();
        fields.dedup();
        for (n, (c, name, t, key)) in fields.into_iter().enumerate() {
            ids.fields.push((c, t, name));
            ids.field_index.insert(key, n as u32);
        }
        let mut methods: Vec<(u16, u32, u16, (String, String, String, Vec<String>))> = self
            .methods
            .iter()
            .map(|(c, n, r, p)| {
                (
                    ids.type_index[c],
                    ids.string_index[n],
                    ids.proto_index[&(r.clone(), p.clone())],
                    (c.clone(), n.clone(), r.clone(), p.clone()),
                )
            })
            .collect();
        methods.sort();
        methods.dedup();
        for (n, (c, name, p, key)) in methods.into_iter().enumerate() {
            ids.methods.push((c, p, name));
            ids.method_index.insert(key, n as u32);
        }
        ids
    }
}

/// Phase 2: resolved, canonically sorted id tables plus the classes to emit.
#[derive(Debug, Default)]
pub struct Ids {
    strings: Vec<Vec<u8>>,
    string_index: HashMap<String, u32>,
    /// string idx per type
    types: Vec<u32>,
    type_index: HashMap<String, u16>,
    /// (shorty string idx, return type idx, parameter type idxs)
    protos: Vec<(u32, u16, Vec<u16>)>,
    proto_index: HashMap<(String, Vec<String>), u16>,
    /// (class type idx, type idx, name string idx)
    fields: Vec<(u16, u16, u32)>,
    field_index: HashMap<(String, String, String), u32>,
    /// (class type idx, proto idx, name string idx)
    methods: Vec<(u16, u16, u32)>,
    method_index: HashMap<(String, String, String, Vec<String>), u32>,
    classes: Vec<ClassSpec>,
    magic: [u8; 8],
}

impl Ids {
    pub fn string(&self, s: &str) -> u32 {
        *self.string_index.get(s).unwrap_or_else(|| panic!("string {s:?} was not declared"))
    }
    pub fn type_(&self, desc: &str) -> u16 {
        *self.type_index.get(desc).unwrap_or_else(|| panic!("type {desc:?} was not declared"))
    }
    pub fn proto(&self, ret: &str, params: &[&str]) -> u16 {
        let key = (ret.to_string(), params.iter().map(|p| p.to_string()).collect());
        *self.proto_index.get(&key).unwrap_or_else(|| panic!("proto ({params:?}){ret} was not declared"))
    }
    pub fn field(&self, class: &str, name: &str, ty: &str) -> u32 {
        let key = (class.to_string(), name.to_string(), ty.to_string());
        *self.field_index.get(&key).unwrap_or_else(|| panic!("field {class}->{name}:{ty} was not declared"))
    }
    pub fn method(&self, class: &str, name: &str, ret: &str, params: &[&str]) -> u32 {
        let key = (class.to_string(), name.to_string(), ret.to_string(), params.iter().map(|p| p.to_string()).collect());
        *self.method_index.get(&key).unwrap_or_else(|| panic!("method {class}->{name}({params:?}){ret} was not declared"))
    }

    pub fn add_class(&mut self, class: ClassSpec) -> &mut Self {
        self.classes.push(class);
        self
    }

    /// Override the magic (`dex\n035\0` by default), e.g. for a 038 DEX.
    pub fn magic(&mut self, magic: &[u8; 8]) -> &mut Self {
        self.magic = *magic;
        self
    }

    /// Emit the DEX (sealed with checksum and signature).
    pub fn finish(&self) -> Vec<u8> {
        let magic = if self.magic == [0; 8] { *b"dex\n035\0" } else { self.magic };
        let mut b = Builder::new();
        let n_str = self.strings.len() as u32;
        let string_ids = b.section(1, n_str, &vec![0u8; 4 * self.strings.len()], 4);
        let type_ids = b.section(2, self.types.len() as u32, &pack_u32s(&self.types), 4);
        let proto_ids =
            if self.protos.is_empty() { 0 } else { b.section(3, self.protos.len() as u32, &vec![0u8; 12 * self.protos.len()], 4) };
        let field_ids = if self.fields.is_empty() { 0 } else { b.section(4, self.fields.len() as u32, &pack_hhi(&self.fields), 4) };
        let method_ids = if self.methods.is_empty() { 0 } else { b.section(5, self.methods.len() as u32, &pack_hhi(&self.methods), 4) };
        let class_defs = b.section(6, self.classes.len() as u32, &vec![0u8; 32 * self.classes.len()], 4);
        let data_off = b.buf.len() as u32;

        // string data
        let mut sd = Vec::new();
        let mut string_offs = Vec::with_capacity(self.strings.len());
        for s in &self.strings {
            string_offs.push(sd.len() as u32);
            write_uleb128(&mut sd, mutf8::to_utf16(s).len() as u32);
            sd.extend_from_slice(s);
            sd.push(0);
        }
        let sd_off = b.section(0x2002, n_str, &sd, 1);
        for (i, off) in string_offs.iter().enumerate() {
            b.put_u32(string_ids as usize + 4 * i, sd_off + off);
        }

        // type lists (protos + interfaces), deduplicated, 4-aligned
        let mut lists: BTreeMap<Vec<u16>, u32> = BTreeMap::new();
        let mut tl = Vec::new();
        let mut list_off = |list: &[u16], tl: &mut Vec<u8>| -> Option<u32> {
            if list.is_empty() {
                return None;
            }
            if let Some(&o) = lists.get(list) {
                return Some(o);
            }
            while tl.len() % 4 != 0 {
                tl.push(0);
            }
            let o = tl.len() as u32;
            tl.extend_from_slice(&(list.len() as u32).to_le_bytes());
            for x in list {
                tl.extend_from_slice(&x.to_le_bytes());
            }
            lists.insert(list.to_vec(), o);
            Some(o)
        };
        let proto_param_offs: Vec<Option<u32>> = self.protos.iter().map(|p| list_off(&p.2, &mut tl)).collect();
        let iface_offs: Vec<Option<u32>> =
            self.classes.iter().map(|c| list_off(&c.interfaces.iter().map(|i| self.type_(i)).collect::<Vec<_>>(), &mut tl)).collect();
        let n_lists = lists.len() as u32;
        let tl_off = if n_lists > 0 { b.section(0x1001, n_lists, &tl, 4) } else { 0 };
        for (i, (shorty_idx, ret, _)) in self.protos.iter().enumerate() {
            let p = proto_ids as usize + 12 * i;
            b.put_u32(p, *shorty_idx);
            b.put_u32(p + 4, *ret as u32);
            b.put_u32(p + 8, proto_param_offs[i].map_or(0, |o| tl_off + o));
        }

        // debug info, then code items (which point at it)
        let all_methods = || self.classes.iter().flat_map(|c| c.direct_methods.iter().chain(c.virtual_methods.iter()));
        let mut dbg = Vec::new();
        let mut dbg_offs: HashMap<u32, u32> = HashMap::new();
        for m in all_methods() {
            if let Some(info) = m.code.as_ref().and_then(|c| c.debug.as_ref()) {
                dbg_offs.insert(m.idx, dbg.len() as u32);
                info.write(&mut dbg, &|s| s, &|t| t);
            }
        }
        let dbg_base = if dbg.is_empty() { 0 } else { b.section(0x2003, dbg_offs.len() as u32, &dbg, 1) };
        let mut code = Vec::new();
        let mut code_offs: HashMap<u32, u32> = HashMap::new();
        for m in all_methods() {
            if let Some(c) = &m.code {
                while code.len() % 4 != 0 {
                    code.push(0);
                }
                code_offs.insert(m.idx, code.len() as u32);
                let debug_off = dbg_offs.get(&m.idx).map_or(0, |o| dbg_base + o);
                code.extend(code_item_bytes(c, debug_off));
            }
        }
        let code_base = if code.is_empty() { 0 } else { b.section(0x2001, code_offs.len() as u32, &code, 4) };

        // class data
        let mut cds = Vec::new();
        let mut cd_offs = Vec::with_capacity(self.classes.len());
        for c in &self.classes {
            cd_offs.push(cds.len() as u32);
            let mut sf = c.static_fields.clone();
            sf.sort();
            let mut inf = c.instance_fields.clone();
            inf.sort();
            let mut dm: Vec<&MethodSpec> = c.direct_methods.iter().collect();
            dm.sort_by_key(|m| m.idx);
            let mut vm: Vec<&MethodSpec> = c.virtual_methods.iter().collect();
            vm.sort_by_key(|m| m.idx);
            write_uleb128(&mut cds, sf.len() as u32);
            write_uleb128(&mut cds, inf.len() as u32);
            write_uleb128(&mut cds, dm.len() as u32);
            write_uleb128(&mut cds, vm.len() as u32);
            for list in [&sf, &inf] {
                let mut last = 0;
                for (idx, access) in list {
                    write_uleb128(&mut cds, idx - last);
                    write_uleb128(&mut cds, *access);
                    last = *idx;
                }
            }
            for list in [&dm, &vm] {
                let mut last = 0;
                for m in list {
                    write_uleb128(&mut cds, m.idx - last);
                    write_uleb128(&mut cds, m.access);
                    write_uleb128(&mut cds, code_offs.get(&m.idx).map_or(0, |o| code_base + o));
                    last = m.idx;
                }
            }
        }
        let cd_base = b.section(0x2000, self.classes.len() as u32, &cds, 1);

        // annotations: items, sets, set ref lists, directories
        let mut items = Vec::new();
        let mut sets = Vec::new();
        let mut set_count = 0u32;
        let mut ref_lists = Vec::new();
        let mut ref_count = 0u32;
        // A set is emitted as (item offsets); offsets are resolved once the
        // item section offset is known, so remember the pending patches.
        let mut set_patches: Vec<(usize, u32)> = Vec::new(); // (position in `sets`, item offset within `items`)
        let mut ref_patches: Vec<(usize, u32)> = Vec::new(); // (position in `ref_lists`, set offset within `sets`)
        let mut item_count = 0u32;
        let mut emit_set = |anns: &[AnnotationItem], items: &mut Vec<u8>, sets: &mut Vec<u8>| -> u32 {
            while sets.len() % 4 != 0 {
                sets.push(0);
            }
            let off = sets.len() as u32;
            set_count += 1;
            sets.extend_from_slice(&(anns.len() as u32).to_le_bytes());
            for a in anns {
                let item_off = items.len() as u32;
                item_count += 1;
                write_annotation_item(items, a, &Identity);
                set_patches.push((sets.len(), item_off));
                sets.extend_from_slice(&0u32.to_le_bytes());
            }
            off
        };
        struct Dir {
            class_set: Option<u32>,
            fields: Vec<(u32, u32)>,
            methods: Vec<(u32, u32)>,
            params: Vec<(u32, u32)>,
        }
        let mut dirs: Vec<Option<Dir>> = Vec::with_capacity(self.classes.len());
        for c in &self.classes {
            let has = !c.class_annotations.is_empty()
                || !c.field_annotations.is_empty()
                || !c.method_annotations.is_empty()
                || !c.parameter_annotations.is_empty();
            if !has {
                dirs.push(None);
                continue;
            }
            let class_set = if c.class_annotations.is_empty() { None } else { Some(emit_set(&c.class_annotations, &mut items, &mut sets)) };
            let mut fields: Vec<(u32, u32)> = c.field_annotations.iter().map(|(f, a)| (*f, emit_set(a, &mut items, &mut sets))).collect();
            let mut methods: Vec<(u32, u32)> = c.method_annotations.iter().map(|(m, a)| (*m, emit_set(a, &mut items, &mut sets))).collect();
            let mut params = Vec::new();
            for (m, per_param) in &c.parameter_annotations {
                while ref_lists.len() % 4 != 0 {
                    ref_lists.push(0);
                }
                let off = ref_lists.len() as u32;
                ref_count += 1;
                ref_lists.extend_from_slice(&(per_param.len() as u32).to_le_bytes());
                for anns in per_param {
                    let set_off = emit_set(anns, &mut items, &mut sets);
                    ref_patches.push((ref_lists.len(), set_off));
                    ref_lists.extend_from_slice(&0u32.to_le_bytes());
                }
                params.push((*m, off));
            }
            fields.sort();
            methods.sort();
            params.sort();
            dirs.push(Some(Dir { class_set, fields, methods, params }));
        }
        let items_base = if items.is_empty() { 0 } else { b.section(0x2004, item_count, &items, 1) };
        for (pos, item_off) in set_patches {
            sets[pos..pos + 4].copy_from_slice(&(items_base + item_off).to_le_bytes());
        }
        let sets_base = if sets.is_empty() { 0 } else { b.section(0x1003, set_count, &sets, 4) };
        for (pos, set_off) in ref_patches {
            ref_lists[pos..pos + 4].copy_from_slice(&(sets_base + set_off).to_le_bytes());
        }
        let refs_base = if ref_lists.is_empty() { 0 } else { b.section(0x1002, ref_count, &ref_lists, 4) };
        let mut dir_bytes = Vec::new();
        let mut dir_offs: Vec<u32> = Vec::with_capacity(self.classes.len());
        let mut dir_count = 0u32;
        for d in &dirs {
            let Some(d) = d else {
                dir_offs.push(0);
                continue;
            };
            while dir_bytes.len() % 4 != 0 {
                dir_bytes.push(0);
            }
            dir_offs.push(dir_bytes.len() as u32);
            dir_count += 1;
            dir_bytes.extend_from_slice(&d.class_set.map_or(0, |o| sets_base + o).to_le_bytes());
            dir_bytes.extend_from_slice(&(d.fields.len() as u32).to_le_bytes());
            dir_bytes.extend_from_slice(&(d.methods.len() as u32).to_le_bytes());
            dir_bytes.extend_from_slice(&(d.params.len() as u32).to_le_bytes());
            for (i, o) in d.fields.iter().chain(d.methods.iter()) {
                dir_bytes.extend_from_slice(&i.to_le_bytes());
                dir_bytes.extend_from_slice(&(sets_base + o).to_le_bytes());
            }
            for (i, o) in &d.params {
                dir_bytes.extend_from_slice(&i.to_le_bytes());
                dir_bytes.extend_from_slice(&(refs_base + o).to_le_bytes());
            }
        }
        let dirs_base = if dir_count > 0 { b.section(0x2006, dir_count, &dir_bytes, 4) } else { 0 };

        // static values
        let mut arrays = Vec::new();
        let mut array_offs: Vec<u32> = Vec::with_capacity(self.classes.len());
        let mut array_count = 0u32;
        for c in &self.classes {
            if c.static_values.is_empty() {
                array_offs.push(0);
                continue;
            }
            array_offs.push(arrays.len() as u32);
            array_count += 1;
            write_array(&mut arrays, &c.static_values, &Identity);
        }
        let arrays_base = if array_count > 0 { b.section(0x2005, array_count, &arrays, 1) } else { 0 };

        // class defs
        for (i, c) in self.classes.iter().enumerate() {
            let cdef = pack_u32s(&[
                self.type_(&c.descriptor) as u32,
                c.access,
                c.superclass.as_deref().map_or(NO_INDEX, |s| self.type_(s) as u32),
                iface_offs[i].map_or(0, |o| tl_off + o),
                c.source_file.as_deref().map_or(NO_INDEX, |s| self.string(s)),
                if dirs[i].is_none() { 0 } else { dirs_base + dir_offs[i] },
                cd_base + cd_offs[i],
                if c.static_values.is_empty() { 0 } else { arrays_base + array_offs[i] },
            ]);
            let p = class_defs as usize + 32 * i;
            b.buf[p..p + 32].copy_from_slice(&cdef);
        }
        let mut out = b.finish(
            [
                (n_str, string_ids),
                (self.types.len() as u32, type_ids),
                (self.protos.len() as u32, proto_ids),
                (self.fields.len() as u32, field_ids),
                (self.methods.len() as u32, method_ids),
                (self.classes.len() as u32, class_defs),
            ],
            data_off,
        );
        out[..8].copy_from_slice(&magic);
        seal(&mut out);
        out
    }
}

fn code_item_bytes(c: &CodeSpec, debug_off: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&c.registers.to_le_bytes());
    out.extend_from_slice(&c.ins.to_le_bytes());
    out.extend_from_slice(&c.outs.to_le_bytes());
    out.extend_from_slice(&(c.tries.len() as u16).to_le_bytes());
    out.extend_from_slice(&debug_off.to_le_bytes());
    out.extend_from_slice(&((c.insns.len() / 2) as u32).to_le_bytes());
    out.extend_from_slice(&c.insns);
    if c.tries.is_empty() {
        return out;
    }
    if (c.insns.len() / 2) % 2 == 1 {
        out.extend_from_slice(&[0, 0]);
    }
    let mut list = Vec::new();
    write_uleb128(&mut list, c.tries.len() as u32);
    let mut handler_offs = Vec::with_capacity(c.tries.len());
    for t in &c.tries {
        handler_offs.push(list.len() as u16);
        let n = t.catches.len() as i32;
        write_sleb128(&mut list, if t.catch_all.is_some() { -n } else { n });
        for (ty, addr) in &t.catches {
            write_uleb128(&mut list, *ty);
            write_uleb128(&mut list, *addr);
        }
        if let Some(a) = t.catch_all {
            write_uleb128(&mut list, a);
        }
    }
    for (t, h) in c.tries.iter().zip(handler_offs) {
        out.extend_from_slice(&t.start_addr.to_le_bytes());
        out.extend_from_slice(&t.insn_count.to_le_bytes());
        out.extend_from_slice(&h.to_le_bytes());
    }
    out.extend_from_slice(&list);
    out
}

// ---------------------------------------------------------------------------
// Rich fixture
// ---------------------------------------------------------------------------

/// Non-ASCII string used by [`make_rich_dex`] (stored as MUTF-8).
pub const RICH_STRING: &str = "héllo wörld";

/// A DEX exercising most of the rebuild / disassembly surface:
///
/// * `Lexample/Iface;` — interface with abstract `run()V`;
/// * `Lexample/Rich;` (`public abstract`, implements `Iface`, source
///   `Rich.java`, class annotation `Lexample/Marker; value = "c"`):
///   - static `COUNT:I = 7` (field annotation `value = "f"`) and
///     `NAME:Ljava/lang/String; = RICH_STRING`; instance `value:I`;
///   - `<init>()V`;
///   - `static compute(II)I`: a packed-switch whose payload sits at pc 0
///     *before* the switch, inside a try block with two typed handlers
///     (`Exception`, `RuntimeException`) and a catch-all; debug info with
///     parameter names `a`, `b` and `.line` 10 / 12 / 14;
///   - `static jumbo()Ljava/lang/String;`: `const-string/jumbo`;
///   - `static table()[I`: sparse-switch + fill-array-data (payloads after
///     the code, separated by a `nop` for alignment);
///   - virtual `run()V` (`iget` of `value`);
///   - `abstract handle(Ljava/lang/String;I)V` with a method annotation
///     (`value = "m"`) and a parameter annotation on parameter 0 (`"p"`);
/// * `Lexample/Broken;` — `static broken()V` starts with undefined opcode
///   `0x3e`;
/// * `Lexample/Custom;` — `static custom()V` uses `invoke-custom`.
pub fn make_rich_dex() -> Vec<u8> {
    const OBJ: &str = "Ljava/lang/Object;";
    const STR: &str = "Ljava/lang/String;";
    const RICH: &str = "Lexample/Rich;";
    const IFACE: &str = "Lexample/Iface;";
    const MARKER: &str = "Lexample/Marker;";
    const EXC: &str = "Ljava/lang/Exception;";
    const RTE: &str = "Ljava/lang/RuntimeException;";
    const BROKEN: &str = "Lexample/Broken;";
    const CUSTOM: &str = "Lexample/Custom;";

    let mut d = DexBuilder::new();
    for s in ["Rich.java", RICH_STRING, "a", "b", "value", "c", "f", "m", "p"] {
        d.string(s);
    }
    for t in [MARKER, EXC, RTE, "[I"] {
        d.type_(t);
    }
    d.field(RICH, "COUNT", "I").field(RICH, "NAME", STR).field(RICH, "value", "I");
    d.method(OBJ, "<init>", "V", &[])
        .method(RICH, "<init>", "V", &[])
        .method(RICH, "compute", "I", &["I", "I"])
        .method(RICH, "jumbo", STR, &[])
        .method(RICH, "table", "[I", &[])
        .method(RICH, "run", "V", &[])
        .method(RICH, "handle", "V", &[STR, "I"])
        .method(IFACE, "run", "V", &[])
        .method(BROKEN, "broken", "V", &[])
        .method(CUSTOM, "custom", "V", &[]);
    let ids = d.resolve();

    let le16 = |v: u32| (v as u16).to_le_bytes();
    let count = ids.field(RICH, "COUNT", "I");
    let name = ids.field(RICH, "NAME", STR);
    let value = ids.field(RICH, "value", "I");
    let hello = ids.string(RICH_STRING);
    let compute = ids.method(RICH, "compute", "I", &["I", "I"]);

    // compute(II)I — see the byte-offset map in the crate tests.
    let mut c = Vec::new();
    c.extend_from_slice(&[0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00]); // 0x00 packed-switch payload, 2 cases, first key 0
    c.extend_from_slice(&5i32.to_le_bytes()); //                              case 0 -> 0x1a
    c.extend_from_slice(&8i32.to_le_bytes()); //                              case 1 -> 0x20
    c.extend_from_slice(&[0x2b, 0x02]); //                                    0x10 packed-switch v2, :payload(-8)
    c.extend_from_slice(&(-8i32).to_le_bytes());
    c.extend_from_slice(&[0x12, 0x70]); //                                    0x16 const/4 v0, 7
    c.extend_from_slice(&[0x0f, 0x00]); //                                    0x18 return v0
    c.extend_from_slice(&[0x60, 0x00]); //                                    0x1a sget v0, COUNT
    c.extend_from_slice(&le16(count));
    c.extend_from_slice(&[0x0f, 0x00]); //                                    0x1e return v0
    c.extend_from_slice(&[0x1a, 0x00]); //                                    0x20 const-string v0, RICH_STRING
    c.extend_from_slice(&le16(hello));
    c.extend_from_slice(&[0x71, 0x20]); //                                    0x24 invoke-static {v2, v3}, compute
    c.extend_from_slice(&le16(compute));
    c.extend_from_slice(&[0x32, 0x00]);
    c.extend_from_slice(&[0x0a, 0x00]); //                                    0x2a move-result v0
    c.extend_from_slice(&[0x0f, 0x00]); //                                    0x2c return v0
    c.extend_from_slice(&[0x0d, 0x01, 0x12, 0xf0, 0x0f, 0x00]); //            0x2e catch Exception: move-exception v1; const/4 v0, -1; return v0
    c.extend_from_slice(&[0x0d, 0x01, 0x12, 0xe0, 0x0f, 0x00]); //            0x34 catch RuntimeException: ...; const/4 v0, -2; return v0
    c.extend_from_slice(&[0x0d, 0x01, 0x27, 0x01]); //                        0x3a catchall: move-exception v1; throw v1
    assert_eq!(c.len(), 0x3e);
    let compute_code = CodeSpec {
        registers: 4,
        ins: 2,
        outs: 2,
        insns: c,
        tries: vec![TrySpec {
            start_addr: 8,
            insn_count: 4,
            catches: vec![(ids.type_(EXC) as u32, 0x2e / 2), (ids.type_(RTE) as u32, 0x34 / 2)],
            catch_all: Some(0x3a / 2),
        }],
        debug: Some(DebugInfo {
            line_start: 10,
            parameter_names: vec![Some(ids.string("a")), Some(ids.string("b"))],
            ops: vec![dbg_special(8, 0), dbg_special(5, 2), dbg_special(3, 2), DebugOp::EndSequence],
        }),
    };

    // jumbo()Ljava/lang/String;
    let mut j = vec![0x1b, 0x00];
    j.extend_from_slice(&hello.to_le_bytes());
    j.extend_from_slice(&[0x11, 0x00]);
    let jumbo_code = CodeSpec { registers: 1, insns: j, ..Default::default() };

    // table()[I
    let mut t = Vec::new();
    t.extend_from_slice(&[0x12, 0x11]); //                                    0x00 const/4 v1, 1
    t.extend_from_slice(&[0x2c, 0x01]); //                                    0x02 sparse-switch v1, :payload(+13)
    t.extend_from_slice(&13i32.to_le_bytes());
    t.extend_from_slice(&[0x12, 0x30]); //                                    0x08 const/4 v0, 3
    t.extend_from_slice(&[0x23, 0x00]); //                                    0x0a new-array v0, v0, [I
    t.extend_from_slice(&le16(ids.type_("[I") as u32));
    t.extend_from_slice(&[0x26, 0x00]); //                                    0x0e fill-array-data v0, :payload(+13)
    t.extend_from_slice(&13i32.to_le_bytes());
    t.extend_from_slice(&[0x11, 0x00]); //                                    0x14 return-object v0
    t.extend_from_slice(&[0x12, 0x00, 0x11, 0x00]); //                        0x16 const/4 v0, 0; return-object v0
    t.extend_from_slice(&[0x00, 0x00]); //                                    0x1a nop (payload alignment)
    t.extend_from_slice(&[0x00, 0x02, 0x01, 0x00]); //                        0x1c sparse-switch payload, 1 case
    t.extend_from_slice(&0x2ai32.to_le_bytes()); //                           key 42
    t.extend_from_slice(&10i32.to_le_bytes()); //                             -> 0x16
    t.extend_from_slice(&[0x00, 0x03, 0x04, 0x00, 0x03, 0x00, 0x00, 0x00]); // 0x28 fill-array-data payload, width 4, 3 elements
    for v in [1i32, 2, 3] {
        t.extend_from_slice(&v.to_le_bytes());
    }
    assert_eq!(t.len(), 0x3c);
    let table_code = CodeSpec { registers: 2, insns: t, ..Default::default() };

    // <init>()V
    let mut i = vec![0x70, 0x10];
    i.extend_from_slice(&le16(ids.method(OBJ, "<init>", "V", &[])));
    i.extend_from_slice(&[0x00, 0x00, 0x0e, 0x00]);
    let init_code = CodeSpec { registers: 1, ins: 1, outs: 1, insns: i, ..Default::default() };

    // run()V
    let mut r = vec![0x52, 0x10];
    r.extend_from_slice(&le16(value));
    r.extend_from_slice(&[0x0e, 0x00]);
    let run_code = CodeSpec { registers: 2, ins: 1, insns: r, ..Default::default() };

    let marker = ids.type_(MARKER) as u32;
    let value_name = ids.string("value");
    let ann = |v: u32| string_annotation(marker, value_name, v);
    let (ann_c, ann_f, ann_m, ann_p) = (ann(ids.string("c")), ann(ids.string("f")), ann(ids.string("m")), ann(ids.string("p")));
    let handle = ids.method(RICH, "handle", "V", &[STR, "I"]);

    let mut ids = ids;
    ids.add_class(ClassSpec {
        descriptor: IFACE.into(),
        access: 0x1 | 0x200 | 0x400,
        superclass: Some(OBJ.into()),
        virtual_methods: vec![MethodSpec { idx: ids.method(IFACE, "run", "V", &[]), access: 0x1 | 0x400, code: None }],
        ..Default::default()
    });
    ids.add_class(ClassSpec {
        descriptor: RICH.into(),
        access: 0x1 | 0x400,
        superclass: Some(OBJ.into()),
        interfaces: vec![IFACE.into()],
        source_file: Some("Rich.java".into()),
        static_fields: vec![(count, 0x1 | 0x8), (name, 0x1 | 0x8)],
        instance_fields: vec![(value, 0x1)],
        direct_methods: vec![
            MethodSpec { idx: ids.method(RICH, "<init>", "V", &[]), access: 0x1 | 0x10000, code: Some(init_code) },
            MethodSpec { idx: compute, access: 0x1 | 0x8, code: Some(compute_code) },
            MethodSpec { idx: ids.method(RICH, "jumbo", STR, &[]), access: 0x1 | 0x8, code: Some(jumbo_code) },
            MethodSpec { idx: ids.method(RICH, "table", "[I", &[]), access: 0x1 | 0x8, code: Some(table_code) },
        ],
        virtual_methods: vec![
            MethodSpec { idx: handle, access: 0x1 | 0x400, code: None },
            MethodSpec { idx: ids.method(RICH, "run", "V", &[]), access: 0x1, code: Some(run_code) },
        ],
        static_values: vec![EncodedValue::Primitive { kind: 0x04, raw: vec![7] }, EncodedValue::String(hello)],
        class_annotations: vec![ann_c],
        field_annotations: vec![(count, vec![ann_f])],
        method_annotations: vec![(handle, vec![ann_m])],
        parameter_annotations: vec![(handle, vec![vec![ann_p], vec![]])],
    });
    ids.add_class(ClassSpec {
        descriptor: BROKEN.into(),
        access: 0x1,
        superclass: Some(OBJ.into()),
        direct_methods: vec![MethodSpec {
            idx: ids.method(BROKEN, "broken", "V", &[]),
            access: 0x1 | 0x8,
            code: Some(CodeSpec { registers: 1, insns: vec![0x3e, 0x00, 0x0e, 0x00], ..Default::default() }),
        }],
        ..Default::default()
    });
    ids.add_class(ClassSpec {
        descriptor: CUSTOM.into(),
        access: 0x1,
        superclass: Some(OBJ.into()),
        direct_methods: vec![MethodSpec {
            idx: ids.method(CUSTOM, "custom", "V", &[]),
            access: 0x1 | 0x8,
            code: Some(CodeSpec { registers: 1, insns: vec![0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00], ..Default::default() }),
        }],
        ..Default::default()
    });
    ids.magic(b"dex\n038\0");
    ids.finish()
}

/// `Lexample/Big;` declaring `n` static `I` fields (`f0`, `f1`, ...) or, with
/// `methods == true`, `n` abstract `mN()V` methods — used to hit the 16-bit
/// id limits of the rebuilt DEX.
pub fn make_many_members_dex(n: usize, methods: bool) -> Vec<u8> {
    const BIG: &str = "Lexample/Big;";
    let mut d = DexBuilder::new();
    let names: Vec<String> = (0..n).map(|i| if methods { format!("m{i}") } else { format!("f{i}") }).collect();
    for name in &names {
        if methods {
            d.method(BIG, name, "V", &[]);
        } else {
            d.field(BIG, name, "I");
        }
    }
    let mut ids = d.resolve();
    let class = ClassSpec {
        descriptor: BIG.into(),
        access: 0x1 | 0x400,
        static_fields: if methods { Vec::new() } else { names.iter().map(|n| (ids.field(BIG, n, "I"), 0x9)).collect() },
        virtual_methods: if methods {
            names.iter().map(|n| MethodSpec { idx: ids.method(BIG, n, "V", &[]), access: 0x401, code: None }).collect()
        } else {
            Vec::new()
        },
        ..Default::default()
    };
    ids.add_class(class);
    ids.finish()
}

/// `Lexample/Cut;` whose only method `cut()V` ends in the middle of a
/// `const-string` instruction.
pub fn make_truncated_insn_dex() -> Vec<u8> {
    const CUT: &str = "Lexample/Cut;";
    let mut d = DexBuilder::new();
    d.string("s").method(CUT, "cut", "V", &[]);
    let mut ids = d.resolve();
    let m = ids.method(CUT, "cut", "V", &[]);
    ids.add_class(ClassSpec {
        descriptor: CUT.into(),
        access: 0x1,
        direct_methods: vec![MethodSpec {
            idx: m,
            access: 0x9,
            code: Some(CodeSpec { registers: 1, insns: vec![0x0e, 0x00, 0x1a, 0x00], ..Default::default() }),
        }],
        ..Default::default()
    });
    ids.finish()
}
