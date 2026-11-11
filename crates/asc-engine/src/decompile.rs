//! High-level class and method decompilation via `dexdec` (Java / Kotlin) and
//! `asc-smali` (Smali), backed by minimal closure DEX reconstruction and
//! full-input MD5 + class disk caching.

use crate::{names, EngineError, Result, SmaliOptions};
use asc_dex::annotations::{parse_annotation_set, AnnotationsDirectory};
use asc_dex::encoded::{parse_annotation_item, EncodedValue};
use asc_dex::{ClassDef, Dex};
use asc_rebuild::Rebuilt;
use std::collections::{BTreeMap, BTreeSet};
/// Target output language for `getclass` / decompilation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SourceLang {
    #[default]
    Java,
    Kotlin,
    Auto,
    Smali,
}

impl SourceLang {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Java => "java",
            Self::Kotlin => "kotlin",
            Self::Auto => "auto",
            Self::Smali => "smali",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "java" => Some(Self::Java),
            "kotlin" | "kt" => Some(Self::Kotlin),
            "auto" => Some(Self::Auto),
            "smali" | "baksmali" => Some(Self::Smali),
            _ => None,
        }
    }
}

impl std::fmt::Display for SourceLang {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Options for [` crate::Engine::decompile_class_method_cancellable`].
#[derive(Debug, Clone, Copy)]
pub struct DecompileOptions {
    pub lang: SourceLang,
    pub smali: SmaliOptions,
    pub include_nested: bool,
}

impl Default for DecompileOptions {
    fn default() -> Self {
        Self { lang: SourceLang::Java, smali: SmaliOptions::default(), include_nested: true }
    }
}

/// Output of decompiling a class or method from a DEX buffer.
pub struct DecompiledDex {
    pub rebuilt: Option<Rebuilt>,
    pub source: String,
    pub lang: SourceLang,
    pub methods: Vec<String>,
    pub warning: Option<String>,
}

/// Method metadata `(name, proto_descriptor, full_signature)` in a DEX class.
#[derive(Debug, Clone)]
pub struct MethodEntry {
    pub name: String,
    pub proto: String,
    pub signature: String,
}

/// Collect all methods declared on `descriptor` in `dex`.
pub fn class_method_entries(dex: &Dex<'_>, descriptor: &str) -> Result<Vec<MethodEntry>> {
    let (_, def) = dex
        .find_class_def(&asc_dex::mutf8::encode(descriptor))?
        .ok_or_else(|| EngineError::Rebuild(asc_rebuild::RebuildError::ClassNotFound(descriptor.to_string())))?;
    let cd = dex.class_data(def.class_data_off)?;
    let mut out = Vec::with_capacity(cd.direct_methods.len() + cd.virtual_methods.len());
    for m in cd.direct_methods.iter().chain(&cd.virtual_methods) {
        let id = dex.method_id(m.method_idx)?;
        let name = dex.string(id.name_idx)?;
        let proto = asc_smali::proto_descriptor(dex, id.proto_idx as u32)?;
        let signature = format!("{name}{proto}");
        out.push(MethodEntry { name, proto, signature });
    }
    Ok(out)
}

/// Select methods of `descriptor` matching `query` (exact signature, bare name,
/// signature prefix, or Java-style signature). Returns an error listing the
/// class's methods when none match.
pub fn select_methods<'a>(descriptor: &str, all: &'a [MethodEntry], query: &str) -> Result<Vec<&'a MethodEntry>> {
    let picked = try_select_methods(all, query);
    if !picked.is_empty() {
        return Ok(picked);
    }
    for candidate in names::denormalize_method_candidates(Some(descriptor), query) {
        let picked = try_select_methods(all, &candidate);
        if !picked.is_empty() {
            return Ok(picked);
        }
    }
    Err(EngineError::Query(format!("{descriptor} has no method {query:?}; its methods: {}", format_signatures(all, 4 << 10))))
}

fn try_select_methods<'a>(all: &'a [MethodEntry], query: &str) -> Vec<&'a MethodEntry> {
    let q: String = query.split_whitespace().collect();
    let q = q.rsplit_once("->").map_or(q.as_str(), |(_, m)| m);
    let exact: Vec<_> = all.iter().filter(|m| m.signature == q).collect();
    if !exact.is_empty() {
        return exact;
    }
    if !q.contains('(') {
        let by_name: Vec<_> = all.iter().filter(|m| m.name == q).collect();
        if !by_name.is_empty() {
            return by_name;
        }
    } else {
        let prefixed: Vec<_> = all.iter().filter(|m| m.signature.starts_with(q)).collect();
        if !prefixed.is_empty() {
            return prefixed;
        }
        let member = query.rsplit_once("->").map_or(query, |(_, m)| m);
        if let Some(dalvik) = names::java_signature_to_dalvik(member) {
            let matched: Vec<_> = all.iter().filter(|m| m.signature == dalvik || m.signature.starts_with(&dalvik)).collect();
            if !matched.is_empty() {
                return matched;
            }
        }
    }
    Vec::new()
}

fn format_signatures(methods: &[MethodEntry], max: usize) -> String {
    let mut out = String::new();
    for (i, m) in methods.iter().enumerate() {
        if out.len() + m.signature.len() + 2 > max {
            out.push_str(&format!(", ... {} more", methods.len() - i));
            break;
        }
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&m.signature);
    }
    out
}

/// Rebuild `descriptor` (plus nested classes when `opts.include_nested`) out of
/// `buf` and decompile or disassemble it according to `opts`.
pub fn decompile_dex_source(
    buf: &[u8],
    dex_name: &str,
    descriptor: &str,
    opts: DecompileOptions,
    method: Option<&str>,
) -> Result<DecompiledDex> {
    let dex = Dex::with_name(buf, dex_name)?;
    if opts.lang == SourceLang::Smali {
        return decompile_smali(&dex, descriptor, opts.smali, method);
    }

    let all_methods = class_method_entries(&dex, descriptor)?;
    let selected: Vec<MethodEntry> = match method {
        Some(m) => select_methods(descriptor, &all_methods, m)?.into_iter().cloned().collect(),
        None => Vec::new(),
    };
    let picked_sigs: Vec<String> = selected.iter().map(|m| m.signature.clone()).collect();

    let rebuild_res = if opts.include_nested && method.is_none() {
        asc_rebuild::rebuild_class_closure(&dex, descriptor)
    } else {
        asc_rebuild::rebuild_class(&dex, descriptor)
    };

    match rebuild_res {
        Ok(rebuilt) => {
            let whole_closure = opts.include_nested && method.is_none();
            match run_dexdec(&rebuilt.bytes, descriptor, opts, &selected, whole_closure) {
                Ok((source, lang)) => Ok(DecompiledDex { rebuilt: Some(rebuilt), source, lang, methods: picked_sigs, warning: None }),
                Err(dec_err) => {
                    // The closure rebuild succeeded but `dexdec` refused it
                    // (e.g. an outer class the closure does not carry): retry
                    // the single class, then fall back to smali.
                    if opts.include_nested {
                        if let Ok(single) = asc_rebuild::rebuild_class(&dex, descriptor) {
                            let no_nested = DecompileOptions { include_nested: false, ..opts };
                            if let Ok((source, lang)) = run_dexdec(&single.bytes, descriptor, no_nested, &selected, false) {
                                return Ok(DecompiledDex { rebuilt: Some(single), source, lang, methods: picked_sigs, warning: None });
                            }
                        }
                    }
                    let smali_src = render_smali_fallback(&dex, descriptor, opts.smali, method)?;
                    Ok(DecompiledDex {
                        rebuilt: Some(rebuilt),
                        source: smali_src,
                        lang: SourceLang::Smali,
                        methods: picked_sigs,
                        warning: Some(format!("decompilation failed ({dec_err}); disassembled as smali instead")),
                    })
                }
            }
        }
        Err(e) if e.is_input_limitation() => {
            // A nested class the closure pulled in may be what this DEX
            // feature or index count refuses: retry the class on its own
            // before giving up on the rebuild.
            let single = if opts.include_nested && method.is_none() { asc_rebuild::rebuild_class(&dex, descriptor).ok() } else { None };
            if let Some(single) = single {
                let no_nested = DecompileOptions { include_nested: false, ..opts };
                if let Ok((source, lang)) = run_dexdec(&single.bytes, descriptor, no_nested, &selected, false) {
                    return Ok(DecompiledDex {
                        rebuilt: Some(single),
                        source,
                        lang,
                        methods: picked_sigs,
                        warning: Some(format!("nested classes not rebuilt ({e}); decompiled the class alone instead")),
                    });
                }
            }
            // For unsupported DEX features like invoke-custom, try decompiling directly
            // from the original DEX buffer before falling back to smali disassembly.
            if !matches!(e, asc_rebuild::RebuildError::Bytecode { .. }) {
                if let Ok((source, lang)) = run_dexdec(buf, descriptor, opts, &selected, false) {
                    return Ok(DecompiledDex {
                        rebuilt: None,
                        source,
                        lang,
                        methods: picked_sigs,
                        warning: Some(format!("class not rebuilt ({e}); decompiled from the original DEX instead")),
                    });
                }
            }
            let smali_src = render_smali_fallback(&dex, descriptor, opts.smali, method)?;
            Ok(DecompiledDex {
                rebuilt: None,
                source: smali_src,
                lang: SourceLang::Smali,
                methods: picked_sigs,
                warning: Some(format!("class not rebuilt ({e}); disassembled from the original DEX instead")),
            })
        }
        Err(e) => Err(EngineError::Rebuild(e)),
    }
}

fn decompile_smali(dex: &Dex<'_>, descriptor: &str, opts: SmaliOptions, method: Option<&str>) -> Result<DecompiledDex> {
    let all_methods = class_method_entries(dex, descriptor)?;
    let selected: Vec<MethodEntry> = match method {
        Some(m) => select_methods(descriptor, &all_methods, m)?.into_iter().cloned().collect(),
        None => Vec::new(),
    };
    let picked_sigs: Vec<String> = selected.iter().map(|m| m.signature.clone()).collect();
    let exact_one = (selected.len() == 1).then(|| selected[0].signature.as_str());

    let (rebuilt, full_or_one, warning) = match asc_rebuild::rebuild_class(dex, descriptor) {
        Ok(rebuilt) => {
            let new_dex = Dex::parse(&rebuilt.bytes)?;
            let src = asc_smali::disassemble_class_method(&new_dex, descriptor, opts, exact_one)?;
            (Some(rebuilt), src, None)
        }
        Err(e) if e.is_input_limitation() => {
            let src = asc_smali::disassemble_class_method(dex, descriptor, opts, exact_one)?;
            let warning = format!("class not rebuilt ({e}); disassembled from the original DEX instead");
            (None, src, Some(warning))
        }
        Err(e) => return Err(EngineError::Rebuild(e)),
    };

    let source = if selected.len() > 1 { filter_smali_methods(&full_or_one, &picked_sigs) } else { full_or_one };
    Ok(DecompiledDex { rebuilt, source, lang: SourceLang::Smali, methods: picked_sigs, warning })
}

fn render_smali_fallback(dex: &Dex<'_>, descriptor: &str, opts: SmaliOptions, method: Option<&str>) -> Result<String> {
    let all_methods = class_method_entries(dex, descriptor)?;
    let selected: Vec<MethodEntry> = match method {
        Some(m) => select_methods(descriptor, &all_methods, m)?.into_iter().cloned().collect(),
        None => Vec::new(),
    };
    let picked_sigs: Vec<String> = selected.iter().map(|m| m.signature.clone()).collect();
    let exact_one = (selected.len() == 1).then(|| selected[0].signature.as_str());
    let raw = asc_smali::disassemble_class_method(dex, descriptor, opts, exact_one)?;
    Ok(if selected.len() > 1 { filter_smali_methods(&raw, &picked_sigs) } else { raw })
}

/// Keep only the class header and the `.method` blocks whose signature is in `wanted`.
fn filter_smali_methods(smali: &str, wanted: &[String]) -> String {
    const SECTIONS: &[&str] = &["# static fields", "# instance fields", "# direct methods", "# virtual methods"];
    let mut header_end = None;
    let mut blocks = Vec::new();
    let mut open: Option<(usize, &str)> = None;
    let mut pos = 0;
    for line in smali.split_inclusive('\n') {
        let t = line.trim_end();
        let starts_body = t.starts_with(".field") || t.starts_with(".method ") || SECTIONS.contains(&t);
        if header_end.is_none() && starts_body {
            header_end = Some(pos);
        }
        if t.starts_with(".method ") {
            open = Some((pos, t));
        } else if t == ".end method" {
            if let Some((start, decl)) = open.take() {
                let sig = decl.split_whitespace().last().unwrap_or(decl);
                if wanted.iter().any(|w| w == sig) {
                    blocks.push(&smali[start..pos + line.len()]);
                }
            }
        }
        pos += line.len();
    }
    let header = &smali[..header_end.unwrap_or(smali.len())];
    let mut out = header.trim_end().to_string();
    out.push('\n');
    for b in blocks {
        out.push('\n');
        out.push_str(b);
    }
    out
}

fn run_dexdec(
    dex_bytes: &[u8],
    descriptor: &str,
    opts: DecompileOptions,
    selected_methods: &[MethodEntry],
    whole_closure: bool,
) -> std::result::Result<(String, SourceLang), String> {
    let mut decompiler = dexdec::Decompiler::from_bytes(dex_bytes).map_err(|e| e.to_string())?;
    let target_lang = match opts.lang {
        SourceLang::Java => dexdec::SourceLanguage::Java,
        SourceLang::Kotlin => dexdec::SourceLanguage::Kotlin,
        SourceLang::Auto => decompiler.source_language(descriptor.to_string()).unwrap_or(dexdec::SourceLanguage::Java),
        SourceLang::Smali => unreachable!(),
    };
    let resolved_lang = match target_lang {
        dexdec::SourceLanguage::Java => SourceLang::Java,
        dexdec::SourceLanguage::Kotlin => SourceLang::Kotlin,
    };
    let dec_opts = dexdec::DecompileOptions::default().with_language(target_lang).with_nested(opts.include_nested);
    decompiler.set_options(dec_opts.clone());

    let header_map = build_dex_symbol_map(dex_bytes, descriptor, resolved_lang, selected_methods, whole_closure);
    if selected_methods.is_empty() {
        let unit = match decompiler.class(descriptor.to_string()) {
            Ok(u) => u,
            Err(_) if opts.include_nested => {
                decompiler.set_options(dec_opts.with_nested(false));
                decompiler.class(descriptor.to_string()).map_err(|e| e.to_string())?
            }
            Err(e) => return Err(e.to_string()),
        };
        let mut s = if header_map.is_empty() { unit.source } else { format!("{header_map}{}", unit.source) };
        if !s.ends_with('\n') {
            s.push('\n');
        }
        return Ok((s, resolved_lang));
    }

    let mut parts = Vec::with_capacity(selected_methods.len());
    let mut outline_cache: Option<dexdec::ClassOutline> = None;
    for m in selected_methods {
        let req = dexdec::MethodRequest::new(descriptor.to_string(), m.name.clone()).with_descriptor(m.proto.clone());
        let out = decompiler.method(req).map_err(|e| e.to_string())?;
        match out.source {
            Some(body) => parts.push(body.trim_end().to_string()),
            None => {
                if outline_cache.is_none() {
                    outline_cache = decompiler.class_outline(descriptor.to_string()).ok();
                }
                let fallback = outline_cache
                    .as_ref()
                    .and_then(|o| o.methods.iter().find(|om| om.name == m.name && om.descriptor == m.proto))
                    .map(|om| format!("{};", om.display_signature))
                    .unwrap_or_else(|| format!("// {}{}", m.name, m.proto));
                parts.push(fallback);
            }
        }
    }
    let body_text = parts.join("\n\n");
    let mut joined = if header_map.is_empty() { body_text } else { format!("{header_map}{body_text}") };
    if !joined.ends_with('\n') {
        joined.push('\n');
    }
    Ok((joined, resolved_lang))
}

fn norm_ident(raw: &str, lang: SourceLang) -> String {
    match lang {
        SourceLang::Kotlin => dexdec::language::kotlin::KotlinIdentifier::from_dex(raw).to_string(),
        _ => dexdec::language::java::JavaIdentifier::from_dex(raw).to_string(),
    }
}

/// Check `Ldalvik/annotation/InnerClass;` on `def` for an explicit `name`.
fn inner_class_annotation_name(dex: &Dex<'_>, def: &ClassDef) -> Option<String> {
    if def.annotations_off == 0 {
        return None;
    }
    let buf = dex.buf();
    let dir = AnnotationsDirectory::parse(buf, def.annotations_off as usize).ok()?;
    if dir.class_annotations_off == 0 {
        return None;
    }
    for item_off in parse_annotation_set(buf, dir.class_annotations_off as usize).ok()? {
        let (item, _) = parse_annotation_item(buf, item_off as usize).ok()?;
        if dex.type_bytes(item.annotation.type_idx).ok()? != b"Ldalvik/annotation/InnerClass;" {
            continue;
        }
        for (name_idx, val) in &item.annotation.elements {
            if dex.string_bytes(*name_idx).ok()? == b"name" {
                if let EncodedValue::String(s_idx) = val {
                    return dex.string(*s_idx).ok();
                }
            }
        }
    }
    None
}

/// Find a nested class of `outer_descriptor` in `dex_bytes` whose
/// `Ldalvik/annotation/InnerClass;` simple name (or its normalized form)
/// equals `wanted_simple_name`.
pub fn find_inner_class_by_annotation(dex_bytes: &[u8], outer_descriptor: &str, wanted_simple_name: &str) -> Option<String> {
    let stem = outer_descriptor.strip_suffix(';')?;
    let prefix = format!("{stem}$");
    let dex = Dex::parse(dex_bytes).ok()?;
    let wanted_unquoted = wanted_simple_name.trim_matches('`');
    for i in 0..dex.class_def_count() {
        let def = dex.class_def(i).ok()?;
        let desc = dex.type_descriptor(def.class_idx).ok()?;
        if !desc.starts_with(&prefix) {
            continue;
        }
        if let Some(ann_name) = inner_class_annotation_name(&dex, &def) {
            if ann_name == wanted_unquoted
                || norm_ident(&ann_name, SourceLang::Java) == wanted_unquoted
                || norm_ident(&ann_name, SourceLang::Kotlin).trim_matches('`') == wanted_unquoted
            {
                return Some(desc);
            }
        }
    }
    None
}

/// Source-level display name of a DEX class descriptor and whether any package
/// or class segment was renamed by `dexdec`.
fn source_class_info(dex: &Dex<'_>, def: Option<&ClassDef>, raw_desc: &str, lang: SourceLang) -> (String, String, bool) {
    let inner = names::class_inner(raw_desc);
    let (pkg, binary_cls) = inner.rsplit_once('/').unwrap_or(("", inner));
    let mut pkg_changed = false;
    let mut norm_pkg_segs = Vec::new();
    if !pkg.is_empty() {
        for seg in pkg.split('/') {
            let n = norm_ident(seg, lang);
            if n != seg {
                pkg_changed = true;
            }
            norm_pkg_segs.push(n);
        }
    }
    let mut cls_changed = false;
    let ann_simple = def.and_then(|d| inner_class_annotation_name(dex, d));
    let last_seg = binary_cls.rsplit('$').next().unwrap_or(binary_cls);
    let simple_display = if let Some(ann) = &ann_simple {
        let n = norm_ident(ann, lang);
        if n != last_seg || ann != last_seg {
            cls_changed = true;
        }
        n
    } else if last_seg.is_empty() || last_seg.chars().all(|c| c.is_ascii_digit()) {
        cls_changed = true;
        let id = binary_cls.rsplit('$').find_map(|s| s.parse::<u32>().ok()).unwrap_or(1);
        format!("Anonymous{id}")
    } else {
        let n = norm_ident(last_seg, lang);
        if n != last_seg {
            cls_changed = true;
        }
        n
    };

    let mut nested_parts = Vec::new();
    let raw_parts: Vec<&str> = binary_cls.split('$').collect();
    for (i, &p) in raw_parts.iter().enumerate() {
        if i + 1 == raw_parts.len() {
            nested_parts.push(simple_display.clone());
        } else if p.is_empty() || p.chars().all(|c| c.is_ascii_digit()) {
            cls_changed = true;
            nested_parts.push(format!("Anonymous{}", if p.is_empty() { "1" } else { p }));
        } else {
            let n = norm_ident(p, lang);
            if n != p {
                cls_changed = true;
            }
            nested_parts.push(n);
        }
    }
    let cls_path = nested_parts.join(".");
    let full_display =
        if pkg_changed && !norm_pkg_segs.is_empty() { format!("{}.{}", norm_pkg_segs.join("."), cls_path) } else { cls_path };
    (full_display, simple_display, pkg_changed || cls_changed)
}

/// `dexdec`'s `ArgType` ordering: primitives by variant, then objects by
/// internal name, then arrays of their element. Colliding member names get
/// `$2`, `$3`... in this order, so the map must use the same key.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum TypeOrder {
    Prim(u8),
    Obj(String),
    Arr(Box<TypeOrder>),
}

fn type_order(desc: &str) -> TypeOrder {
    let bytes = desc.as_bytes();
    if bytes.len() == 1 {
        let rank = match bytes[0] {
            b'V' => 0,
            b'Z' => 1,
            b'B' => 2,
            b'S' => 3,
            b'C' => 4,
            b'I' => 5,
            b'J' => 6,
            b'F' => 7,
            b'D' => 8,
            _ => 9,
        };
        return TypeOrder::Prim(rank);
    }
    if let Some(element) = desc.strip_prefix('[') {
        return TypeOrder::Arr(Box::new(type_order(element)));
    }
    TypeOrder::Obj(names::class_inner(desc).to_string())
}

/// Parameters of a `(params)ret` descriptor as ordered keys.
fn proto_param_orders(proto: &str) -> Vec<TypeOrder> {
    let Some((params, _)) = proto.split_once(')') else { return Vec::new() };
    let params = params.strip_prefix('(').unwrap_or(params);
    names::dalvik_types(params).unwrap_or_default().into_iter().map(type_order).collect()
}

/// Build the `// [dex-map]` header comment listing every class, field, method,
/// or external reference whose `dexdec` source name differs from its raw DEX name.
///
/// `whole_closure` covers every class of a rebuilt closure DEX; otherwise only
/// `root_descriptor` and its nested classes are inspected.
pub fn build_dex_symbol_map(
    dex_bytes: &[u8],
    root_descriptor: &str,
    lang: SourceLang,
    selected_methods: &[MethodEntry],
    whole_closure: bool,
) -> String {
    let Ok(dex) = Dex::parse(dex_bytes) else {
        return String::new();
    };
    let mut lines = Vec::new();
    let mut defined_class_idxs = BTreeSet::new();
    let nested_prefix = root_descriptor.strip_suffix(';').map(|stem| format!("{stem}$")).unwrap_or_default();

    for i in 0..dex.class_def_count() {
        let Ok(def) = dex.class_def(i) else { continue };
        let Ok(cls_desc) = dex.type_descriptor(def.class_idx) else { continue };
        if !whole_closure && cls_desc != root_descriptor && !cls_desc.starts_with(&nested_prefix) {
            continue;
        }
        defined_class_idxs.insert(def.class_idx);
        let (cls_display, cls_simple, cls_renamed) = source_class_info(&dex, Some(&def), &cls_desc, lang);
        if cls_renamed {
            lines.push(format!("//   class  {cls_display} => {cls_desc}"));
        }
        let Ok(cd) = dex.class_data(def.class_data_off) else { continue };

        if selected_methods.is_empty() {
            // Fields: replicate dexdec's FieldNameAllocation, which walks the
            // class's fields sorted by (normalized name, type).
            let mut fields = Vec::new();
            for f in cd.fields() {
                let Ok(fid) = dex.field_id(f.field_idx) else { continue };
                let Ok(raw_name) = dex.string(fid.name_idx) else { continue };
                let Ok(ty_desc) = dex.type_descriptor(fid.type_idx as u32) else { continue };
                let norm = norm_ident(&raw_name, lang);
                fields.push((norm, type_order(&ty_desc), ty_desc, raw_name));
            }
            fields.sort();
            fields.dedup();
            let mut field_occ: BTreeMap<String, usize> = BTreeMap::new();
            for (norm, _, ty_desc, raw_name) in fields {
                let occ = field_occ.entry(norm.clone()).or_default();
                let alloc = if *occ == 0 { norm } else { norm_ident(&format!("{norm}${}", *occ + 1), lang) };
                *occ += 1;
                if alloc != raw_name {
                    lines.push(format!("//   field  {cls_simple}.{alloc} => {cls_desc}->{raw_name}:{ty_desc}"));
                }
            }
        }

        // Methods: replicate dexdec's MethodNameAllocation, which orders
        // (normalized name, parameters, return type) like `ArgType`.
        let mut methods = Vec::new();
        for m in cd.methods() {
            let Ok(mid) = dex.method_id(m.method_idx) else { continue };
            let Ok(raw_name) = dex.string(mid.name_idx) else { continue };
            if raw_name == "<init>" || raw_name == "<clinit>" {
                continue;
            }
            let Ok(proto) = asc_smali::proto_descriptor(&dex, mid.proto_idx as u32) else { continue };
            let norm = norm_ident(&raw_name, lang);
            let params = proto_param_orders(&proto);
            let ret = proto.split_once(')').map_or(TypeOrder::Prim(0), |(_, r)| type_order(r));
            methods.push((norm, params, ret, proto, raw_name));
        }
        methods.sort();
        methods.dedup();
        let mut method_occ: BTreeMap<(String, Vec<TypeOrder>), usize> = BTreeMap::new();
        for (norm, params, _, proto, raw_name) in methods {
            let occ = method_occ.entry((norm.clone(), params)).or_default();
            let alloc = if *occ == 0 { norm } else { norm_ident(&format!("{norm}${}", *occ + 1), lang) };
            *occ += 1;
            if !selected_methods.is_empty() && !selected_methods.iter().any(|sm| sm.name == raw_name && sm.proto == proto) {
                continue;
            }
            if alloc != raw_name {
                lines.push(format!("//   method {cls_simple}.{alloc} => {cls_desc}->{raw_name}{proto}"));
            }
        }
    }

    // External field and method references in a rebuilt closure DEX.
    if whole_closure {
        for f_idx in 0..dex.field_count() {
            let Ok(fid) = dex.field_id(f_idx) else { continue };
            if defined_class_idxs.contains(&(fid.class_idx as u32)) {
                continue;
            }
            let Ok(owner_desc) = dex.type_descriptor(fid.class_idx as u32) else { continue };
            let Ok(raw_name) = dex.string(fid.name_idx) else { continue };
            let Ok(ty_desc) = dex.type_descriptor(fid.type_idx as u32) else { continue };
            let (owner_disp, _, owner_changed) = source_class_info(&dex, None, &owner_desc, lang);
            let norm_name = norm_ident(&raw_name, lang);
            if norm_name != raw_name || owner_changed {
                lines.push(format!("//   ref    {owner_disp}.{norm_name} => {owner_desc}->{raw_name}:{ty_desc}"));
            }
        }
        for m_idx in 0..dex.method_count() {
            let Ok(mid) = dex.method_id(m_idx) else { continue };
            if defined_class_idxs.contains(&(mid.class_idx as u32)) {
                continue;
            }
            let Ok(owner_desc) = dex.type_descriptor(mid.class_idx as u32) else { continue };
            let Ok(raw_name) = dex.string(mid.name_idx) else { continue };
            let Ok(proto) = asc_smali::proto_descriptor(&dex, mid.proto_idx as u32) else { continue };
            let (owner_disp, owner_simple, owner_changed) = source_class_info(&dex, None, &owner_desc, lang);
            if raw_name == "<init>" || raw_name == "<clinit>" {
                if owner_changed {
                    lines.push(format!("//   ref    {owner_disp}.{owner_simple} => {owner_desc}->{raw_name}{proto}"));
                }
            } else {
                let norm_name = norm_ident(&raw_name, lang);
                if norm_name != raw_name || owner_changed {
                    lines.push(format!("//   ref    {owner_disp}.{norm_name} => {owner_desc}->{raw_name}{proto}"));
                }
            }
        }
    }

    if lines.is_empty() {
        String::new()
    } else {
        format!("// [dex-map]\n{}\n", lines.join("\n"))
    }
}

/// Binary format version for L3 cached decompilation payloads.
const DECOMPILE_CACHE_FORMAT: u32 = 3;

/// L2 name (fixed per APK) and kind of the persisted full-input MD5, and the
/// layout version of what is stored. A one-shot process then reads 32 bytes
/// instead of re-hashing the whole archive.
pub(crate) const MD5_NAME: &str = "apk";
pub(crate) const MD5_KIND: &str = "md5";
pub(crate) const MD5_FORMAT: u32 = 1;

/// L3 key of one decompilation. `input` addresses the archive cheaply
/// (`apk:<ApkKey>`) or its content (`md5:<hex>` for a copy under another
/// path).
pub(crate) fn cache_query_key(
    input: &str,
    descriptor: &str,
    lang: SourceLang,
    include_nested: bool,
    method: Option<&str>,
    smali_flags: u8,
) -> String {
    asc_cache::rendered_key(
        "decompile",
        crate::tiers::tool_version(),
        &format!(
            "{DECOMPILE_CACHE_FORMAT}\0{input}\0{descriptor}\0{}\0{}\0{}\0{smali_flags}",
            lang.as_str(),
            u8::from(include_nested),
            method.unwrap_or("")
        ),
    )
}

pub(crate) struct CachedDecompile {
    pub dex_name: String,
    pub lang: SourceLang,
    pub also_defined_in: Vec<String>,
    pub methods: Vec<String>,
    pub source: String,
}

pub(crate) fn encode_cached_decompile(c: &CachedDecompile) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + c.source.len());
    put_u32(&mut out, DECOMPILE_CACHE_FORMAT);
    put_str(&mut out, &c.dex_name);
    put_str(&mut out, c.lang.as_str());
    put_u32(&mut out, c.also_defined_in.len() as u32);
    for a in &c.also_defined_in {
        put_str(&mut out, a);
    }
    put_u32(&mut out, c.methods.len() as u32);
    for m in &c.methods {
        put_str(&mut out, m);
    }
    put_str(&mut out, &c.source);
    out
}

pub(crate) fn decode_cached_decompile(bytes: &[u8]) -> Option<CachedDecompile> {
    let mut pos = 0usize;
    let fmt = read_u32(bytes, &mut pos)?;
    if fmt != DECOMPILE_CACHE_FORMAT {
        return None;
    }
    let dex_name = read_str(bytes, &mut pos)?.to_string();
    let lang = SourceLang::parse(read_str(bytes, &mut pos)?)?;
    let also_len = read_u32(bytes, &mut pos)? as usize;
    let mut also_defined_in = Vec::with_capacity(also_len.min(64));
    for _ in 0..also_len {
        also_defined_in.push(read_str(bytes, &mut pos)?.to_string());
    }
    let methods_len = read_u32(bytes, &mut pos)? as usize;
    let mut methods = Vec::with_capacity(methods_len.min(256));
    for _ in 0..methods_len {
        methods.push(read_str(bytes, &mut pos)?.to_string());
    }
    let source = read_str(bytes, &mut pos)?.to_string();
    if pos != bytes.len() {
        return None;
    }
    Some(CachedDecompile { dex_name, lang, also_defined_in, methods, source })
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_u32(out, s.len() as u32);
    out.extend_from_slice(s.as_bytes());
}

fn read_u32(buf: &[u8], pos: &mut usize) -> Option<u32> {
    let end = pos.checked_add(4)?;
    let slice = buf.get(*pos..end)?;
    *pos = end;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

fn read_str<'a>(buf: &'a [u8], pos: &mut usize) -> Option<&'a str> {
    let len = read_u32(buf, pos)? as usize;
    let end = pos.checked_add(len)?;
    let slice = buf.get(*pos..end)?;
    *pos = end;
    std::str::from_utf8(slice).ok()
}
