//! Phase 1: pull every structure the class owns out of the original DEX.

use crate::{RebuildError, Result};
use asc_dex::annotations::{parse_annotation_set, parse_annotation_set_ref_list, AnnotationsDirectory};
use asc_dex::class_data::ClassData;
use asc_dex::code::CodeItem;
use asc_dex::debug_info::DebugInfo;
use asc_dex::encoded::{parse_annotation_item, parse_array, AnnotationItem, EncodedValue};
use asc_dex::{ClassDef, Dex};
use std::collections::{BTreeMap, HashMap};

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
            dex.find_class_def(&asc_dex::mutf8::encode(descriptor))?.ok_or_else(|| RebuildError::ClassNotFound(descriptor.to_string()))?;
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
}
