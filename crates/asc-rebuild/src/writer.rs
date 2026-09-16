//! Phase 4: serialise the rebuilt DEX.

use crate::collect::{check_walk, UNSUPPORTED_CALL_SITES};
use crate::hollow::Hollow;
use crate::tables::Tables;
use crate::{RebuildError, Result};
use asc_dalvik::walk::walk_insns;
use asc_dalvik::{decode, Format, IndexKind, Opcode};
use asc_dex::checksum::seal;
use asc_dex::class_data::{EncodedField, EncodedMethod};
use asc_dex::code::CodeItem;
use asc_dex::encoded::{
    write_annotation_item, write_array, EncodedValue, IndexRemap, VALUE_BYTE, VALUE_CHAR, VALUE_DOUBLE, VALUE_FLOAT, VALUE_INT, VALUE_LONG,
    VALUE_SHORT,
};
use asc_dex::leb128::{write_sleb128, write_uleb128};
use asc_dex::{map_type, ClassDef, Dex, HEADER_SIZE, NO_INDEX};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};

struct Out {
    data: Vec<u8>,
    base: usize,
    map: Vec<(u16, u32, u32)>,
}

impl Out {
    fn pos(&self) -> u32 {
        (self.base + self.data.len()) as u32
    }
    fn align4(&mut self) {
        while (self.base + self.data.len()) & 3 != 0 {
            self.data.push(0);
        }
    }
    fn u16(&mut self, v: u16) {
        self.data.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.data.extend_from_slice(&v.to_le_bytes());
    }
    fn section(&mut self, kind: u16, count: usize, off: u32) {
        if count > 0 {
            self.map.push((kind, count as u32, off));
        }
    }
}

/// [`IndexRemap`] adapter over [`Tables`] for the `asc_dex` serialisers,
/// which cannot fail: a missing index is remembered and reported by
/// [`Remap::check`] after the value has been written.
struct Remap<'t> {
    t: &'t Tables,
    err: RefCell<Option<RebuildError>>,
}

impl<'t> Remap<'t> {
    fn new(t: &'t Tables) -> Self {
        Remap { t, err: RefCell::new(None) }
    }
    fn note(&self, r: Result<u32>, idx: u32) -> u32 {
        match r {
            Ok(v) => v,
            Err(e) => {
                self.err.borrow_mut().get_or_insert(e);
                idx
            }
        }
    }
    fn check(&self) -> Result<()> {
        match self.err.borrow_mut().take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl IndexRemap for Remap<'_> {
    fn string(&self, idx: u32) -> u32 {
        self.note(self.t.map_string(idx), idx)
    }
    fn type_(&self, idx: u32) -> u32 {
        self.note(self.t.map_type(idx), idx)
    }
    fn field(&self, idx: u32) -> u32 {
        self.note(self.t.map_field(idx), idx)
    }
    fn method(&self, idx: u32) -> u32 {
        self.note(self.t.map_method(idx), idx)
    }
    fn proto(&self, idx: u32) -> u32 {
        self.note(self.t.map_proto(idx), idx)
    }
    fn method_handle(&self, idx: u32) -> u32 {
        self.note(Err(RebuildError::Unsupported(UNSUPPORTED_CALL_SITES)), idx)
    }
}

/// Remap the constant-pool operand of the instruction at `pc`. `src` is the
/// original code (read), `dst` the copy being rewritten (written).
fn rewrite_one(src: &[u8], dst: &mut [u8], pc: usize, op: &Opcode, t: &Tables) -> Result<()> {
    match op.index {
        IndexKind::StringRef => {
            let idx = t.map_string(decode::get_index(src, pc, op))?;
            // Strings are the one table `Tables::build` does not cap at 16 bits
            // (const-string/jumbo is 31c); a narrow const-string cannot take a
            // remapped index above u16.
            if op.format != Format::K31c && idx > u16::MAX as u32 {
                return Err(RebuildError::TooManyItems { what: "strings", count: t.strings.len() });
            }
            decode::set_index(dst, pc, op, idx)
        }
        IndexKind::TypeRef => decode::set_index(dst, pc, op, t.map_type(decode::get_index(src, pc, op))?),
        IndexKind::FieldRef => decode::set_index(dst, pc, op, t.map_field(decode::get_index(src, pc, op))?),
        IndexKind::MethodRef => decode::set_index(dst, pc, op, t.map_method(decode::get_index(src, pc, op))?),
        IndexKind::MethodAndProtoRef => {
            decode::set_index(dst, pc, op, t.map_method(decode::get_index(src, pc, op))?);
            decode::set_proto_index(dst, pc, t.map_proto(decode::get_proto_index(src, pc) as u32)? as u16);
        }
        IndexKind::ProtoRef => decode::set_index(dst, pc, op, t.map_proto(decode::get_index(src, pc, op))?),
        IndexKind::CallSiteRef | IndexKind::MethodHandleRef => return Err(RebuildError::Unsupported(UNSUPPORTED_CALL_SITES)),
        IndexKind::None | IndexKind::Unknown => {}
    }
    Ok(())
}

/// Append `insns` to the output and rewrite its operands in place with a
/// single payload-aware walk over the original bytes.
fn write_insns(out: &mut Out, method_idx: u32, insns: &[u8], t: &Tables) -> Result<()> {
    let start = out.data.len();
    out.data.extend_from_slice(insns);
    let dst = &mut out.data[start..];
    let mut first_err: Option<RebuildError> = None;
    let walk = walk_insns(insns, |step| {
        if first_err.is_none() {
            if let Err(e) = rewrite_one(insns, dst, step.pc, step.opcode, t) {
                first_err = Some(e);
            }
        }
    });
    if let Some(e) = first_err {
        return Err(e);
    }
    check_walk(method_idx, walk.stop)
}

fn write_code_item(out: &mut Out, method_idx: u32, item: &CodeItem<'_>, debug_off: u32, t: &Tables) -> Result<()> {
    out.align4();
    out.u16(item.registers_size);
    out.u16(item.ins_size);
    out.u16(item.outs_size);
    out.u16(item.tries.len() as u16);
    out.u32(debug_off);
    out.u32((item.insns.len() / 2) as u32);
    write_insns(out, method_idx, item.insns, t)?;
    if item.tries.is_empty() {
        return Ok(());
    }
    if (item.insns.len() / 2) & 1 == 1 {
        out.u16(0);
    }
    // Encode the handler list first to learn the new handler offsets.
    let mut list = Vec::new();
    let mut new_off: HashMap<u16, u16> = HashMap::new();
    write_uleb128(&mut list, item.handlers.len() as u32);
    for h in &item.handlers {
        new_off.insert(h.offset, list.len() as u16);
        let size = h.catches.len() as i32;
        write_sleb128(&mut list, if h.catch_all_addr.is_some() { -size } else { size });
        for (ty, addr) in &h.catches {
            write_uleb128(&mut list, t.map_type(*ty)?);
            write_uleb128(&mut list, *addr);
        }
        if let Some(addr) = h.catch_all_addr {
            write_uleb128(&mut list, addr);
        }
    }
    for tr in &item.tries {
        let off = *new_off.get(&tr.handler_off).ok_or_else(|| {
            RebuildError::Internal(format!(
                "try item of method {method_idx} references handler offset {} which does not exist",
                tr.handler_off
            ))
        })?;
        out.u32(tr.start_addr);
        out.u16(tr.insn_count);
        out.u16(off);
    }
    out.data.extend_from_slice(&list);
    Ok(())
}

/// Default initial value of a static field of type `descriptor`, used to pad
/// `static_values` holes.
fn zero_value(descriptor: &[u8]) -> EncodedValue {
    let kind = match descriptor.first() {
        Some(b'Z') => return EncodedValue::Boolean(false),
        Some(b'B') => VALUE_BYTE,
        Some(b'S') => VALUE_SHORT,
        Some(b'C') => VALUE_CHAR,
        Some(b'I') => VALUE_INT,
        Some(b'J') => VALUE_LONG,
        Some(b'F') => VALUE_FLOAT,
        Some(b'D') => VALUE_DOUBLE,
        _ => return EncodedValue::Null,
    };
    EncodedValue::Primitive { kind, raw: vec![0] }
}

/// `static_values` in the emitted static field order. The original array is
/// positional over the original `static_fields` list (and may be shorter);
/// fields that move behind a field without an initialiser get an explicit
/// zero so nothing shifts onto the wrong field.
fn order_static_values(dex: &Dex<'_>, h: &Hollow<'_>, values: &[EncodedValue], t: &Tables) -> Result<Vec<EncodedValue>> {
    let mut fields: Vec<(u32, usize)> = Vec::with_capacity(h.class_data.static_fields.len());
    for (i, f) in h.class_data.static_fields.iter().enumerate() {
        fields.push((t.map_field(f.field_idx)?, i));
    }
    fields.sort_unstable();
    let mut ordered = Vec::with_capacity(fields.len());
    let mut last_real = 0usize;
    for (n, &(_, orig)) in fields.iter().enumerate() {
        match values.get(orig) {
            Some(v) => {
                ordered.push(v.clone());
                last_real = n + 1;
            }
            None => {
                let f = &h.class_data.static_fields[orig];
                ordered.push(zero_value(dex.type_bytes(dex.field_id(f.field_idx)?.type_idx as u32)?));
            }
        }
    }
    ordered.truncate(last_real);
    Ok(ordered)
}

pub(crate) fn write(dex: &Dex<'_>, h: &Hollow<'_>, t: &Tables) -> Result<(Vec<u8>, usize)> {
    let n_str = t.strings.len();
    let n_type = t.types.len();
    let n_proto = t.protos.len();
    let n_field = t.fields.len();
    let n_method = t.methods.len();
    let string_ids_off = HEADER_SIZE;
    let type_ids_off = string_ids_off + n_str * 4;
    let proto_ids_off = type_ids_off + n_type * 4;
    let field_ids_off = proto_ids_off + n_proto * 12;
    let method_ids_off = field_ids_off + n_field * 8;
    let class_defs_off = method_ids_off + n_method * 8;
    let data_base = class_defs_off + ClassDef::SIZE;

    let mut out = Out { data: Vec::with_capacity(64 * 1024), base: data_base, map: Vec::new() };
    let remap = Remap::new(t);
    let map_type16 = |idx: u32| -> Result<u16> { Ok(t.map_type(idx)? as u16) };

    // --- string data ---------------------------------------------------
    let mut string_offs = Vec::with_capacity(n_str);
    let first = out.pos();
    for &s in &t.strings {
        let item = dex.string_item(s)?;
        string_offs.push(out.pos());
        write_uleb128(&mut out.data, item.utf16_len);
        out.data.extend_from_slice(item.bytes);
        out.data.push(0);
    }
    out.section(map_type::STRING_DATA, n_str, first);

    // --- type lists (deduplicated) ---------------------------------------
    let mut type_lists: BTreeMap<Vec<u16>, u32> = BTreeMap::new();
    let mut type_list_count = 0usize;
    let mut first_type_list = 0u32;
    let mut emit_type_list = |out: &mut Out, list: Vec<u16>| -> u32 {
        if list.is_empty() {
            return 0;
        }
        if let Some(&off) = type_lists.get(&list) {
            return off;
        }
        out.align4();
        let off = out.pos();
        if type_list_count == 0 {
            first_type_list = off;
        }
        type_list_count += 1;
        out.u32(list.len() as u32);
        for x in &list {
            out.u16(*x);
        }
        type_lists.insert(list, off);
        off
    };
    let interfaces = h.interfaces.iter().map(|&x| map_type16(x as u32)).collect::<Result<Vec<u16>>>()?;
    let interfaces_off = emit_type_list(&mut out, interfaces);
    let mut proto_param_offs = Vec::with_capacity(n_proto);
    for &p in &t.protos {
        let params = dex.proto_params(p)?.iter().map(|&x| map_type16(x as u32)).collect::<Result<Vec<u16>>>()?;
        proto_param_offs.push(emit_type_list(&mut out, params));
    }
    out.section(map_type::TYPE_LIST, type_list_count, first_type_list);

    // --- debug info ------------------------------------------------------
    let mut methods_sorted: Vec<(u32, &EncodedMethod)> =
        Vec::with_capacity(h.class_data.direct_methods.len() + h.class_data.virtual_methods.len());
    for m in h.class_data.methods() {
        methods_sorted.push((t.map_method(m.method_idx)?, m));
    }
    methods_sorted.sort_by_key(|x| x.0);
    let mut debug_offs: HashMap<u32, u32> = HashMap::new();
    let first = out.pos();
    let mut debug_count = 0;
    for (_, m) in &methods_sorted {
        if let Some(info) = h.debug.get(&m.method_idx) {
            debug_offs.insert(m.method_idx, out.pos());
            info.write(&mut out.data, &|s| remap.string(s), &|ty| remap.type_(ty));
            remap.check()?;
            debug_count += 1;
        }
    }
    out.section(map_type::DEBUG_INFO, debug_count, first);

    // --- code items ------------------------------------------------------
    let mut code_offs: HashMap<u32, u32> = HashMap::new();
    let mut first_code = 0u32;
    for (_, m) in &methods_sorted {
        if let Some(item) = h.code.get(&m.method_idx) {
            out.align4();
            if code_offs.is_empty() {
                first_code = out.pos();
            }
            code_offs.insert(m.method_idx, out.pos());
            write_code_item(&mut out, m.method_idx, item, *debug_offs.get(&m.method_idx).unwrap_or(&0), t)?;
        }
    }
    let methods_with_code = code_offs.len();
    out.section(map_type::CODE, methods_with_code, first_code);

    // --- class data ------------------------------------------------------
    let mut class_data_off = 0u32;
    if !h.class_data.is_empty() {
        class_data_off = out.pos();
        let sorted_fields = |list: &[EncodedField]| -> Result<Vec<(u32, EncodedField)>> {
            let mut v = list.iter().map(|f| Ok((t.map_field(f.field_idx)?, *f))).collect::<Result<Vec<_>>>()?;
            v.sort_by_key(|x| x.0);
            Ok(v)
        };
        let static_fields = sorted_fields(&h.class_data.static_fields)?;
        let instance_fields = sorted_fields(&h.class_data.instance_fields)?;
        let sorted_methods = |list: &[EncodedMethod]| -> Result<Vec<(u32, EncodedMethod)>> {
            let mut v = list.iter().map(|m| Ok((t.map_method(m.method_idx)?, *m))).collect::<Result<Vec<_>>>()?;
            v.sort_by_key(|x| x.0);
            Ok(v)
        };
        let direct = sorted_methods(&h.class_data.direct_methods)?;
        let virt = sorted_methods(&h.class_data.virtual_methods)?;
        write_uleb128(&mut out.data, static_fields.len() as u32);
        write_uleb128(&mut out.data, instance_fields.len() as u32);
        write_uleb128(&mut out.data, direct.len() as u32);
        write_uleb128(&mut out.data, virt.len() as u32);
        for list in [&static_fields, &instance_fields] {
            let mut last = 0u32;
            for (idx, f) in list {
                write_uleb128(&mut out.data, idx.wrapping_sub(last));
                last = *idx;
                write_uleb128(&mut out.data, f.access_flags);
            }
        }
        for list in [&direct, &virt] {
            let mut last = 0u32;
            for (idx, m) in list {
                write_uleb128(&mut out.data, idx.wrapping_sub(last));
                last = *idx;
                write_uleb128(&mut out.data, m.access_flags);
                write_uleb128(&mut out.data, *code_offs.get(&m.method_idx).unwrap_or(&0));
            }
        }
        out.section(map_type::CLASS_DATA, 1, class_data_off);
    }

    // --- annotations -----------------------------------------------------
    let mut ann_item_offs: HashMap<u32, u32> = HashMap::new();
    let first = out.pos();
    for (&old, item) in &h.ann_items {
        ann_item_offs.insert(old, out.pos());
        write_annotation_item(&mut out.data, item, &remap);
        remap.check()?;
    }
    out.section(map_type::ANNOTATION, h.ann_items.len(), first);

    let internal = |what: &str, off: u32| RebuildError::Internal(format!("{what} at offset {off:#x} was referenced but never hollowed"));
    let mut ann_set_offs: HashMap<u32, u32> = HashMap::new();
    if !h.ann_sets.is_empty() {
        out.align4();
        let first = out.pos();
        for (&old, items) in &h.ann_sets {
            out.align4();
            ann_set_offs.insert(old, out.pos());
            let mut entries: Vec<(u32, u32)> = Vec::with_capacity(items.len());
            for &i in items.iter().filter(|&&i| i != 0) {
                let item = h.ann_items.get(&i).ok_or_else(|| internal("annotation_item", i))?;
                entries
                    .push((t.map_type(item.annotation.type_idx)?, *ann_item_offs.get(&i).ok_or_else(|| internal("annotation_item", i))?));
            }
            entries.sort_unstable();
            out.u32(entries.len() as u32);
            for (_, off) in entries {
                out.u32(off);
            }
        }
        out.section(map_type::ANNOTATION_SET, h.ann_sets.len(), first);
    }
    let set_off = |old: u32| -> Result<u32> {
        if old == 0 {
            Ok(0)
        } else {
            ann_set_offs.get(&old).copied().ok_or_else(|| internal("annotation_set", old))
        }
    };

    let mut ann_ref_offs: HashMap<u32, u32> = HashMap::new();
    if !h.ann_ref_lists.is_empty() {
        out.align4();
        let first = out.pos();
        for (&old, sets) in &h.ann_ref_lists {
            out.align4();
            ann_ref_offs.insert(old, out.pos());
            out.u32(sets.len() as u32);
            for &s in sets {
                let off = set_off(s)?;
                out.u32(off);
            }
        }
        out.section(map_type::ANNOTATION_SET_REF_LIST, h.ann_ref_lists.len(), first);
    }

    let mut annotations_off = 0u32;
    if let Some(dir) = &h.ann_dir {
        out.align4();
        annotations_off = out.pos();
        let mut fields: Vec<(u32, u32)> = Vec::with_capacity(dir.field_annotations.len());
        for (f, s) in &dir.field_annotations {
            fields.push((t.map_field(*f)?, set_off(*s)?));
        }
        let mut methods: Vec<(u32, u32)> = Vec::with_capacity(dir.method_annotations.len());
        for (m, s) in &dir.method_annotations {
            methods.push((t.map_method(*m)?, set_off(*s)?));
        }
        let mut params: Vec<(u32, u32)> = Vec::with_capacity(dir.parameter_annotations.len());
        for (m, r) in &dir.parameter_annotations {
            let off = if *r == 0 { 0 } else { *ann_ref_offs.get(r).ok_or_else(|| internal("annotation_set_ref_list", *r))? };
            params.push((t.map_method(*m)?, off));
        }
        fields.sort_unstable();
        methods.sort_unstable();
        params.sort_unstable();
        out.u32(set_off(dir.class_annotations_off)?);
        out.u32(fields.len() as u32);
        out.u32(methods.len() as u32);
        out.u32(params.len() as u32);
        for (i, o) in fields.iter().chain(methods.iter()).chain(params.iter()) {
            out.u32(*i);
            out.u32(*o);
        }
        out.section(map_type::ANNOTATIONS_DIRECTORY, 1, annotations_off);
    }

    // --- static values ---------------------------------------------------
    let mut static_values_off = 0u32;
    if let Some(values) = &h.static_values {
        let ordered = order_static_values(dex, h, values, t)?;
        if !ordered.is_empty() {
            static_values_off = out.pos();
            write_array(&mut out.data, &ordered, &remap);
            remap.check()?;
            out.section(map_type::ENCODED_ARRAY, 1, static_values_off);
        }
    }

    // The id tables as `(map type, header size slot, count, offset)`. The spec
    // requires `*_off == 0` and no map entry whenever `*_size` is 0 (ART's
    // verifier rejects the file otherwise); one table keeps the map list and
    // the header in agreement.
    let id_tables = [
        (map_type::STRING_ID, 0x38, n_str, string_ids_off),
        (map_type::TYPE_ID, 0x40, n_type, type_ids_off),
        (map_type::PROTO_ID, 0x48, n_proto, proto_ids_off),
        (map_type::FIELD_ID, 0x50, n_field, field_ids_off),
        (map_type::METHOD_ID, 0x58, n_method, method_ids_off),
    ];

    // --- map list --------------------------------------------------------
    out.align4();
    let map_off = out.pos();
    let mut map = vec![(map_type::HEADER, 1u32, 0u32)];
    map.extend(id_tables.iter().filter(|t| t.2 > 0).map(|&(ty, _, n, off)| (ty, n as u32, off as u32)));
    map.push((map_type::CLASS_DEF, 1, class_defs_off as u32));
    map.extend(out.map.iter().copied());
    map.push((map_type::MAP_LIST, 1, map_off));
    map.sort_by_key(|m| m.2);
    out.u32(map.len() as u32);
    for (kind, size, off) in map {
        out.u16(kind);
        out.u16(0);
        out.u32(size);
        out.u32(off);
    }

    // --- assemble --------------------------------------------------------
    let file_size = data_base + out.data.len();
    let mut file = Vec::with_capacity(file_size);
    file.resize(HEADER_SIZE, 0);
    for off in &string_offs {
        file.extend_from_slice(&off.to_le_bytes());
    }
    for &ty in &t.types {
        file.extend_from_slice(&t.map_string(dex.type_string_idx(ty)?)?.to_le_bytes());
    }
    for (i, &p) in t.protos.iter().enumerate() {
        let id = dex.proto_id(p)?;
        file.extend_from_slice(&t.map_string(id.shorty_idx)?.to_le_bytes());
        file.extend_from_slice(&t.map_type(id.return_type_idx)?.to_le_bytes());
        file.extend_from_slice(&proto_param_offs[i].to_le_bytes());
    }
    for &f in &t.fields {
        let id = dex.field_id(f)?;
        file.extend_from_slice(&map_type16(id.class_idx as u32)?.to_le_bytes());
        file.extend_from_slice(&map_type16(id.type_idx as u32)?.to_le_bytes());
        file.extend_from_slice(&t.map_string(id.name_idx)?.to_le_bytes());
    }
    for &m in &t.methods {
        let id = dex.method_id(m)?;
        file.extend_from_slice(&map_type16(id.class_idx as u32)?.to_le_bytes());
        file.extend_from_slice(&(t.map_proto(id.proto_idx as u32)? as u16).to_le_bytes());
        file.extend_from_slice(&t.map_string(id.name_idx)?.to_le_bytes());
    }
    let def = &h.def;
    let superclass_idx = if def.superclass_idx == NO_INDEX { NO_INDEX } else { t.map_type(def.superclass_idx)? };
    let source_file_idx = if def.source_file_idx == NO_INDEX { NO_INDEX } else { t.map_string(def.source_file_idx)? };
    for v in [
        t.map_type(def.class_idx)?,
        def.access_flags,
        superclass_idx,
        interfaces_off,
        source_file_idx,
        annotations_off,
        class_data_off,
        static_values_off,
    ] {
        file.extend_from_slice(&v.to_le_bytes());
    }
    debug_assert_eq!(file.len(), data_base);
    file.extend_from_slice(&out.data);

    // Header.
    let version = dex.header().version();
    let magic: &[u8; 8] = if version >= 41 {
        b"dex\n040\0"
    } else if version >= 35 {
        &dex.header().magic
    } else {
        b"dex\n035\0"
    };
    file[..8].copy_from_slice(magic);
    let put = |file: &mut Vec<u8>, off: usize, v: u32| file[off..off + 4].copy_from_slice(&v.to_le_bytes());
    put(&mut file, 0x20, file_size as u32);
    put(&mut file, 0x24, HEADER_SIZE as u32);
    put(&mut file, 0x28, 0x12345678);
    put(&mut file, 0x2C, 0);
    put(&mut file, 0x30, 0);
    put(&mut file, 0x34, map_off);
    for &(_, slot, n, off) in &id_tables {
        put(&mut file, slot, n as u32);
        put(&mut file, slot + 4, if n == 0 { 0 } else { off as u32 });
    }
    put(&mut file, 0x60, 1);
    put(&mut file, 0x64, class_defs_off as u32);
    put(&mut file, 0x68, (file_size - data_base) as u32);
    put(&mut file, 0x6C, data_base as u32);
    seal(&mut file);
    Ok((file, methods_with_code))
}
