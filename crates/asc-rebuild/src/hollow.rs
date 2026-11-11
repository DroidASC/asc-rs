//! Phase 1: pull every structure the class owns out of the original DEX.

use crate::{RebuildError, Result};
use asc_dex::annotations::{parse_annotation_set, parse_annotation_set_ref_list, AnnotationsDirectory};
use asc_dex::class_data::ClassData;
use asc_dex::code::CodeItem;
use asc_dex::debug_info::DebugInfo;
use asc_dex::encoded::{parse_annotation_item, parse_array, AnnotationItem, EncodedValue};
use asc_dex::{mutf8, ClassDef, Dex};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

pub(crate) struct Hollow<'a> {
    pub def: ClassDef,
    pub class_data: ClassData,
    pub interfaces: Vec<u16>,
    /// Methods with a body, keyed by original method idx.
    pub code: HashMap<u32, CodeItem<'a>>,
    pub debug: HashMap<u32, DebugInfo>,
    pub static_values: Option<Vec<EncodedValue>>,
    pub ann_dir: Option<AnnotationsDirectory>,
    /// annotation_set offset → annotation_item offsets
    pub ann_sets: BTreeMap<u32, Vec<u32>>,
    /// annotation_item offset → parsed item
    pub ann_items: BTreeMap<u32, AnnotationItem>,
    /// annotation_set_ref_list offset → annotation_set offsets
    pub ann_ref_lists: BTreeMap<u32, Vec<u32>>,
}

impl<'a> Hollow<'a> {
    pub fn extract(dex: &Dex<'a>, descriptor: &str) -> Result<Hollow<'a>> {
        let (_, def) =
            dex.find_class_def(&mutf8::encode(descriptor))?.ok_or_else(|| RebuildError::ClassNotFound(descriptor.to_string()))?;
        Self::from_def(dex, def)
    }

    pub fn from_def(dex: &Dex<'a>, def: ClassDef) -> Result<Hollow<'a>> {
        let buf = dex.buf();
        let class_data = dex.class_data(def.class_data_off)?;
        let interfaces = dex.type_list(def.interfaces_off)?;
        let mut code = HashMap::new();
        let mut debug = HashMap::new();
        for m in class_data.methods() {
            if m.code_off == 0 {
                continue;
            }
            let item = dex.code_item(m.code_off)?;
            // A malformed debug_info_item is an error, exactly like a
            // malformed code_item: the rebuild never silently drops data.
            if item.debug_info_off != 0 {
                let (info, _) = DebugInfo::parse(buf, item.debug_info_off as usize)?;
                debug.insert(m.method_idx, info);
            }
            code.insert(m.method_idx, item);
        }

        let static_values = if def.static_values_off != 0 { Some(parse_array(buf, def.static_values_off as usize)?.0) } else { None };

        let mut h = Hollow {
            def,
            class_data,
            interfaces,
            code,
            debug,
            static_values,
            ann_dir: None,
            ann_sets: BTreeMap::new(),
            ann_items: BTreeMap::new(),
            ann_ref_lists: BTreeMap::new(),
        };
        if def.annotations_off != 0 {
            let dir = AnnotationsDirectory::parse(buf, def.annotations_off as usize)?;
            h.hollow_set(buf, dir.class_annotations_off)?;
            for (_, off) in dir.field_annotations.iter().chain(dir.method_annotations.iter()) {
                h.hollow_set(buf, *off)?;
            }
            for (_, off) in &dir.parameter_annotations {
                h.hollow_ref_list(buf, *off)?;
            }
            h.ann_dir = Some(dir);
        }
        Ok(h)
    }

    fn hollow_set(&mut self, buf: &[u8], off: u32) -> Result<()> {
        if off == 0 || self.ann_sets.contains_key(&off) {
            return Ok(());
        }
        let items = parse_annotation_set(buf, off as usize)?;
        for &item_off in &items {
            if item_off != 0 && !self.ann_items.contains_key(&item_off) {
                let (item, _) = parse_annotation_item(buf, item_off as usize)?;
                self.ann_items.insert(item_off, item);
            }
        }
        self.ann_sets.insert(off, items);
        Ok(())
    }

    fn hollow_ref_list(&mut self, buf: &[u8], off: u32) -> Result<()> {
        if off == 0 || self.ann_ref_lists.contains_key(&off) {
            return Ok(());
        }
        let sets = parse_annotation_set_ref_list(buf, off as usize)?;
        for &set_off in &sets {
            self.hollow_set(buf, set_off)?;
        }
        self.ann_ref_lists.insert(off, sets);
        Ok(())
    }

    /// Extract `descriptor` together with every nested / synthetic class in
    /// `dex` owned by it (`Outer$*` descriptors and `dalvik.annotation.MemberClasses`
    /// entries, transitively).
    pub fn extract_closure(dex: &Dex<'a>, descriptor: &str) -> Result<Vec<Hollow<'a>>> {
        let root = Self::extract(dex, descriptor)?;
        let mut wanted = BTreeSet::new();
        collect_prefix_types(dex, descriptor, &mut wanted)?;
        collect_member_class_types(dex, &root, &mut wanted)?;
        wanted.remove(&root.def.class_idx);
        if wanted.is_empty() {
            return Ok(vec![root]);
        }

        let mut defs_by_type = HashMap::with_capacity(dex.class_def_count() as usize);
        for def in dex.class_defs() {
            let def = def?;
            defs_by_type.insert(def.class_idx, def);
        }

        let mut seen = BTreeSet::from([root.def.class_idx]);
        let mut queue: VecDeque<u32> = wanted.into_iter().collect();
        let mut out = vec![root];
        while let Some(type_idx) = queue.pop_front() {
            if !seen.insert(type_idx) {
                continue;
            }
            let Some(&def) = defs_by_type.get(&type_idx) else {
                continue;
            };
            let h = Self::from_def(dex, def)?;
            let mut nested = BTreeSet::new();
            if let Ok(desc) = dex.type_descriptor(type_idx) {
                collect_prefix_types(dex, &desc, &mut nested)?;
            }
            collect_member_class_types(dex, &h, &mut nested)?;
            for next in nested {
                if !seen.contains(&next) {
                    queue.push_back(next);
                }
            }
            out.push(h);
        }
        Ok(out)
    }
}

/// Find all `type_idx`s in `dex` whose descriptor starts with `<stem>$` where
/// `descriptor` is `<stem>;`. Since `type_ids` is sorted by UTF-16 code units,
/// this binary-searches the lower bound and scans only the matching prefix range.
fn collect_prefix_types(dex: &Dex<'_>, descriptor: &str, out: &mut BTreeSet<u32>) -> Result<()> {
    let Some(stem) = descriptor.strip_suffix(';') else {
        return Ok(());
    };
    let prefix = mutf8::encode(&format!("{stem}$"));
    let count = dex.type_count();
    let (mut left, mut right) = (0u32, count);
    while left < right {
        let mid = left + (right - left) / 2;
        if mutf8::cmp_utf16(dex.type_bytes(mid)?, &prefix).is_lt() {
            left = mid + 1;
        } else {
            right = mid;
        }
    }
    for idx in left..count {
        let bytes = dex.type_bytes(idx)?;
        if !bytes.starts_with(&prefix) {
            break;
        }
        out.insert(idx);
    }
    Ok(())
}

/// Collect type indexes listed in `Ldalvik/annotation/MemberClasses;` on `h`.
fn collect_member_class_types(dex: &Dex<'_>, h: &Hollow<'_>, out: &mut BTreeSet<u32>) -> Result<()> {
    let Some(dir) = &h.ann_dir else {
        return Ok(());
    };
    let Some(items) = h.ann_sets.get(&dir.class_annotations_off) else {
        return Ok(());
    };
    for &item_off in items {
        let Some(item) = h.ann_items.get(&item_off) else {
            continue;
        };
        if dex.type_bytes(item.annotation.type_idx)? != b"Ldalvik/annotation/MemberClasses;" {
            continue;
        }
        for (_, value) in &item.annotation.elements {
            if let EncodedValue::Array(values) = value {
                for v in values {
                    if let EncodedValue::Type(t) = *v {
                        out.insert(t);
                    }
                }
            }
        }
    }
    Ok(())
}
