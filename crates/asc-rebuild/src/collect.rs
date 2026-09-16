//! Phase 2: gather every constant-pool index the class depends on.

use crate::hollow::Hollow;
use crate::{RebuildError, Result};
use asc_dalvik::walk::{walk_insns, Stop};
use asc_dalvik::{decode, IndexKind};
use asc_dex::encoded::{visit_annotation_refs, visit_refs, RefKind};
use asc_dex::{Dex, NO_INDEX};
use std::collections::BTreeSet;

/// Message of the [`RebuildError::Unsupported`] raised for DEX 038+ call
/// sites and method handles.
pub(crate) const UNSUPPORTED_CALL_SITES: &str = "invoke-custom / method handles (call_site_ids, method_handles)";

/// Original indexes referenced by the class, closed over the id tables.
#[derive(Debug, Default, Clone)]
pub(crate) struct RefSet {
    pub strings: BTreeSet<u32>,
    pub types: BTreeSet<u32>,
    pub protos: BTreeSet<u32>,
    pub fields: BTreeSet<u32>,
    pub methods: BTreeSet<u32>,
    /// Set when a `VALUE_METHOD_HANDLE` was met; reported as `Unsupported`.
    method_handles: bool,
}

impl RefSet {
    fn add(&mut self, kind: RefKind, idx: u32) {
        match kind {
            RefKind::String => {
                self.strings.insert(idx);
            }
            RefKind::Type => {
                self.types.insert(idx);
            }
            RefKind::Proto => {
                self.protos.insert(idx);
            }
            RefKind::Field => {
                self.fields.insert(idx);
            }
            RefKind::Method => {
                self.methods.insert(idx);
            }
            RefKind::MethodHandle => self.method_handles = true,
        }
    }

    /// Add everything an id-table item transitively needs.
    fn close(&mut self, dex: &Dex<'_>) -> Result<()> {
        for &m in &self.methods.clone() {
            let id = dex.method_id(m)?;
            self.types.insert(id.class_idx as u32);
            self.protos.insert(id.proto_idx as u32);
            self.strings.insert(id.name_idx);
        }
        for &f in &self.fields.clone() {
            let id = dex.field_id(f)?;
            self.types.insert(id.class_idx as u32);
            self.types.insert(id.type_idx as u32);
            self.strings.insert(id.name_idx);
        }
        for &p in &self.protos.clone() {
            let id = dex.proto_id(p)?;
            self.strings.insert(id.shorty_idx);
            self.types.insert(id.return_type_idx);
            for t in dex.type_list(id.parameters_off)? {
                self.types.insert(t as u32);
            }
        }
        for &t in &self.types.clone() {
            self.strings.insert(dex.type_string_idx(t)?);
        }
        Ok(())
    }
}

/// Convert a walk that did not reach the end of the code into an error.
pub(crate) fn check_walk(method_idx: u32, stop: Stop) -> Result<()> {
    match stop {
        Stop::End => Ok(()),
        Stop::Undefined { pc, opcode } => Err(RebuildError::Bytecode {
            method_idx,
            pc,
            reason: format!("undefined opcode {opcode:#04x} (odex / quickened or corrupt code)"),
        }),
        Stop::Truncated { pc } => {
            Err(RebuildError::Bytecode { method_idx, pc, reason: "instruction runs past the end of the code item".into() })
        }
    }
}

pub(crate) fn collect(dex: &Dex<'_>, h: &Hollow<'_>) -> Result<RefSet> {
    let mut refs = RefSet::default();
    let def = &h.def;
    refs.types.insert(def.class_idx);
    if def.superclass_idx != NO_INDEX {
        refs.types.insert(def.superclass_idx);
    }
    if def.source_file_idx != NO_INDEX {
        refs.strings.insert(def.source_file_idx);
    }
    for &t in &h.interfaces {
        refs.types.insert(t as u32);
    }
    for f in h.class_data.fields() {
        refs.fields.insert(f.field_idx);
    }
    for m in h.class_data.methods() {
        refs.methods.insert(m.method_idx);
    }

    for (&method_idx, code) in &h.code {
        let insns = code.insns;
        let mut unsupported = false;
        let walk = walk_insns(insns, |step| {
            let op = step.opcode;
            match op.index {
                IndexKind::StringRef => refs.add(RefKind::String, decode::get_index(insns, step.pc, op)),
                IndexKind::TypeRef => refs.add(RefKind::Type, decode::get_index(insns, step.pc, op)),
                IndexKind::FieldRef => refs.add(RefKind::Field, decode::get_index(insns, step.pc, op)),
                IndexKind::MethodRef => refs.add(RefKind::Method, decode::get_index(insns, step.pc, op)),
                IndexKind::MethodAndProtoRef => {
                    refs.add(RefKind::Method, decode::get_index(insns, step.pc, op));
                    refs.add(RefKind::Proto, decode::get_proto_index(insns, step.pc) as u32);
                }
                IndexKind::ProtoRef => refs.add(RefKind::Proto, decode::get_index(insns, step.pc, op)),
                IndexKind::CallSiteRef | IndexKind::MethodHandleRef => unsupported = true,
                IndexKind::None | IndexKind::Unknown => {}
            }
        });
        if unsupported {
            return Err(RebuildError::Unsupported(UNSUPPORTED_CALL_SITES));
        }
        check_walk(method_idx, walk.stop)?;
        for handler in &code.handlers {
            for (t, _) in &handler.catches {
                refs.types.insert(*t);
            }
        }
    }

    for info in h.debug.values() {
        let mut strings = |s: u32| {
            refs.strings.insert(s);
        };
        let mut types_sink = BTreeSet::new();
        info.visit_refs(&mut strings, &mut |t| {
            types_sink.insert(t);
        });
        refs.types.extend(types_sink);
    }

    if let Some(values) = &h.static_values {
        for v in values {
            visit_refs(v, &mut |k, i| refs.add(k, i));
        }
    }
    if let Some(dir) = &h.ann_dir {
        for (f, _) in &dir.field_annotations {
            refs.fields.insert(*f);
        }
        for (m, _) in dir.method_annotations.iter().chain(dir.parameter_annotations.iter()) {
            refs.methods.insert(*m);
        }
    }
    for item in h.ann_items.values() {
        visit_annotation_refs(&item.annotation, &mut |k, i| refs.add(k, i));
    }
    if refs.method_handles {
        return Err(RebuildError::Unsupported(UNSUPPORTED_CALL_SITES));
    }

    refs.close(dex)?;
    Ok(refs)
}
