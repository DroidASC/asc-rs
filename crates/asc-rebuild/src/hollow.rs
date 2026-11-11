//! Phase 1: pull the requested class and its nested classes out of the DEX.

use crate::{DroppedClass, RebuildError, Result};
use asc_dex::annotations::{AnnotationsDirectory, parse_annotation_set, parse_annotation_set_ref_list};
use asc_dex::class_data::ClassData;
use asc_dex::code::CodeItem;
use asc_dex::debug_info::DebugInfo;
use asc_dex::encoded::{AnnotationItem, EncodedValue, parse_annotation_item, parse_array};
use asc_dex::{ClassDef, Dex, mutf8};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Display;
use std::rc::Rc;

pub(crate) struct Hollow<'a> {
    pub def: ClassDef,
    pub class_data: ClassData,
    pub interfaces: Vec<u16>,
    /// Methods with a body, keyed by original method idx. Methods may
    /// share a code item (and so its debug info): it is parsed once.
    pub code: HashMap<u32, Rc<CodeItem<'a>>>,
    pub debug: HashMap<u32, Rc<DebugInfo>>,
    pub static_values: Option<Vec<EncodedValue>>,
    pub ann_dir: Option<AnnotationsDirectory>,
    /// annotation_set offset → annotation_item offsets
    pub ann_sets: BTreeMap<u32, Vec<u32>>,
    /// annotation_item offset → parsed item
    pub ann_items: BTreeMap<u32, AnnotationItem>,
    /// annotation_set_ref_list offset → annotation_set offsets
    pub ann_ref_lists: BTreeMap<u32, Vec<u32>>,
}

/// The requested class and its `$` nested classes, in input class_def order
/// (so superclass / interface definitions keep preceding their users).
pub(crate) struct Selection<'a> {
    pub classes: Vec<Hollow<'a>>,
    /// Position of the requested class in `classes`.
    pub target: usize,
    /// Nested classes left out, with the reason.
    pub dropped: Vec<DroppedClass>,
}

impl<'a> Selection<'a> {
    /// Hollow the class `descriptor` and every class of the DEX whose
    /// descriptor starts with its name followed by `$`. Enclosing classes and
    /// siblings stay out. A nested class that cannot be hollowed is dropped;
    /// the requested class failing fails the selection.
    pub(crate) fn extract(dex: &Dex<'a>, descriptor: &str) -> Result<Selection<'a>> {
        let (target_idx, target_def) =
            dex.find_class_def(&mutf8::encode(descriptor))?.ok_or_else(|| RebuildError::ClassNotFound(descriptor.to_string()))?;
        // Nested types sort as one run of type ids; most classes have none,
        // and then the class_defs are not scanned at all.
        let mut defs = dex.find_class_defs_by_type_range(dex.nested_type_idx_range(target_def.class_idx)?)?;
        let at = defs.partition_point(|&(i, _)| i < target_idx);
        defs.insert(at, (target_idx, target_def));

        let mut sel = Selection { classes: Vec::with_capacity(defs.len()), target: 0, dropped: Vec::new() };
        for (i, def) in defs {
            match Hollow::from_def(dex, def) {
                Ok(h) => {
                    if i == target_idx {
                        sel.target = sel.classes.len();
                    }
                    sel.classes.push(h);
                }
                Err(e) if i != target_idx => sel.dropped.push(DroppedClass::new(dex, def.class_idx, e.to_string())?),
                Err(e) => return Err(e),
            }
        }
        Ok(sel)
    }

    pub(crate) fn target(&self) -> &Hollow<'a> {
        &self.classes[self.target]
    }

    pub(crate) fn has_nested(&self) -> bool {
        self.classes.len() > 1
    }

    /// Drop each nested class `check` rejects, recording its error as the
    /// reason. The requested class is not checked.
    pub(crate) fn retain_nested<E: Display>(
        &mut self,
        dex: &Dex<'_>,
        mut check: impl FnMut(&Hollow<'a>) -> std::result::Result<(), E>,
    ) -> Result<()> {
        let target = self.target;
        let mut kept = Vec::with_capacity(self.classes.len());
        for (pos, h) in std::mem::take(&mut self.classes).into_iter().enumerate() {
            if pos == target {
                self.target = kept.len();
            } else if let Err(e) = check(&h) {
                self.dropped.push(DroppedClass::new(dex, h.def.class_idx, e.to_string())?);
                continue;
            }
            kept.push(h);
        }
        self.classes = kept;
        Ok(())
    }
}

impl<'a> Hollow<'a> {
    fn from_def(dex: &Dex<'a>, def: ClassDef) -> Result<Hollow<'a>> {
        let buf = dex.buf();
        let class_data = dex.class_data(def.class_data_off)?;
        let interfaces = dex.type_list(def.interfaces_off)?;

        let mut code = HashMap::new();
        let mut debug = HashMap::new();
        // By code_off: every method of a class may name one code item.
        let mut parsed: HashMap<u32, (Rc<CodeItem<'a>>, Option<Rc<DebugInfo>>)> = HashMap::new();
        for m in class_data.methods() {
            if m.code_off == 0 {
                continue;
            }
            let (item, info) = match parsed.get(&m.code_off) {
                Some(found) => found.clone(),
                None => {
                    let item = dex.code_item(m.code_off)?;
                    // A malformed debug_info_item is an error, exactly like a
                    // malformed code_item: the rebuild never silently drops data.
                    let info = match item.debug_info_off {
                        0 => None,
                        off => Some(Rc::new(DebugInfo::parse(buf, off as usize)?.0)),
                    };
                    let found = (Rc::new(item), info);
                    parsed.insert(m.code_off, found.clone());
                    found
                }
            };
            if let Some(info) = info {
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
