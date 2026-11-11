//! Phase 2: gather the selected classes' constant-pool dependencies.

use crate::hollow::{Hollow, Selection};
use crate::{RebuildError, Result};
use asc_dalvik::walk::{Stop, walk_insns};
use asc_dalvik::{IndexKind, decode};
use asc_dex::encoded::{RefKind, visit_annotation_refs, visit_refs};
use asc_dex::{Dex, NO_INDEX};
use std::collections::BTreeSet;

/// Message of the [`RebuildError::Unsupported`] raised for DEX 038+ call
/// sites and method handles.
pub(crate) const UNSUPPORTED_CALL_SITES: &str = "invoke-custom / method handles (call_site_ids, method_handles)";

/// Original indexes referenced by the selected classes; [`RefSet::close`]
/// closes them over the id tables.
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
    pub(crate) fn close(&mut self, dex: &Dex<'_>) -> Result<()> {
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

/// The references of the selected classes, not yet closed. A nested class
/// whose own references cannot be collected (malformed bytecode, method
/// handles, ...) is dropped from `sel`; the requested class failing is an
/// error.
pub(crate) fn collect(dex: &Dex<'_>, sel: &mut Selection<'_>) -> Result<RefSet> {
    let mut refs = RefSet::of_class(sel.target())?;
    sel.retain_nested(dex, |h| RefSet::of_class(h).map(|r| refs.merge(r)))?;
    Ok(refs)
}

impl RefSet {
    /// Everything one class references directly.
    fn of_class(h: &Hollow<'_>) -> Result<RefSet> {
        let mut refs = RefSet::default();
        refs.collect_class(h)?;
        Ok(refs)
    }

    fn merge(&mut self, mut other: RefSet) {
        self.strings.append(&mut other.strings);
        self.types.append(&mut other.types);
        self.protos.append(&mut other.protos);
        self.fields.append(&mut other.fields);
        self.methods.append(&mut other.methods);
        self.method_handles |= other.method_handles;
    }

    fn collect_class(&mut self, h: &Hollow<'_>) -> Result<()> {
        let def = &h.def;
        self.types.insert(def.class_idx);
        if def.superclass_idx != NO_INDEX {
            self.types.insert(def.superclass_idx);
        }
        if def.source_file_idx != NO_INDEX {
            self.strings.insert(def.source_file_idx);
        }
        for &t in &h.interfaces {
            self.types.insert(t as u32);
        }
        for f in h.class_data.fields() {
            self.fields.insert(f.field_idx);
        }
        for m in h.class_data.methods() {
            self.methods.insert(m.method_idx);
        }

        // Methods sharing a code item share its references: walk it once.
        let mut walked = BTreeSet::new();
        for (&method_idx, code) in &h.code {
            if !walked.insert(code.offset) {
                continue;
            }
            let insns = code.insns;
            let mut unsupported = false;
            let walk = walk_insns(insns, |step| {
                let op = step.opcode;
                match op.index {
                    IndexKind::StringRef => self.add(RefKind::String, decode::get_index(insns, step.pc, op)),
                    IndexKind::TypeRef => self.add(RefKind::Type, decode::get_index(insns, step.pc, op)),
                    IndexKind::FieldRef => self.add(RefKind::Field, decode::get_index(insns, step.pc, op)),
                    IndexKind::MethodRef => self.add(RefKind::Method, decode::get_index(insns, step.pc, op)),
                    IndexKind::MethodAndProtoRef => {
                        self.add(RefKind::Method, decode::get_index(insns, step.pc, op));
                        self.add(RefKind::Proto, decode::get_proto_index(insns, step.pc) as u32);
                    }
                    IndexKind::ProtoRef => self.add(RefKind::Proto, decode::get_index(insns, step.pc, op)),
                    IndexKind::CallSiteRef | IndexKind::MethodHandleRef => unsupported = true,
                    IndexKind::None | IndexKind::Unknown => {}
                }
            });
            if unsupported {
                return Err(RebuildError::Unsupported(UNSUPPORTED_CALL_SITES));
            }
            check_walk(method_idx, walk.stop)?;
            if let Some(t) = code.tries.iter().find(|t| code.handler_for(t).is_none()) {
                let reason = format!("try item names handler offset {}, which is no handler", t.handler_off);
                return Err(RebuildError::Bytecode { method_idx, pc: t.start_addr as usize * 2, reason });
            }
            for handler in &code.handlers {
                for (t, _) in &handler.catches {
                    self.types.insert(*t);
                }
            }
        }

        let mut visited = BTreeSet::new();
        for info in h.debug.values().filter(|info| visited.insert(std::rc::Rc::as_ptr(info))) {
            let mut strings = |s: u32| {
                self.strings.insert(s);
            };
            let mut types_sink = BTreeSet::new();
            info.visit_refs(&mut strings, &mut |t| {
                types_sink.insert(t);
            });
            self.types.extend(types_sink);
        }

        if let Some(values) = &h.static_values {
            for v in values {
                visit_refs(v, &mut |k, i| self.add(k, i));
            }
        }
        if let Some(dir) = &h.ann_dir {
            for (f, _) in &dir.field_annotations {
                self.fields.insert(*f);
            }
            for (m, _) in dir.method_annotations.iter().chain(dir.parameter_annotations.iter()) {
                self.methods.insert(*m);
            }
        }
        for item in h.ann_items.values() {
            visit_annotation_refs(&item.annotation, &mut |k, i| self.add(k, i));
        }
        if self.method_handles {
            return Err(RebuildError::Unsupported(UNSUPPORTED_CALL_SITES));
        }

        Ok(())
    }
}
