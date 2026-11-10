//! Where the writer put things: what tests assert offsets and ids against.

use std::collections::HashMap;

use super::LiteralArrayId;

/// Where one region ended up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbcRegionLayout {
    pub start: u32,
    pub end: u32,
    /// The entity table: entry `id` is the offset of the string, method or
    /// literal array instructions of this region call `id`.
    pub entities: Vec<u32>,
    /// The class table: primitive type codes, then class offsets.
    pub classes: Vec<u32>,
}

impl AbcRegionLayout {
    /// The id of the entity at `offset` in this region.
    pub fn entity_id(&self, offset: u32) -> Option<u16> {
        self.entities.iter().position(|&entry| entry == offset).and_then(|id| u16::try_from(id).ok())
    }
}

/// File offsets of what was declared, for tests to assert against. They
/// describe the complete plain file even when the builder was asked to
/// encrypt or truncate it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AbcLayout {
    pub class_index_off: u32,
    /// `None` for versions without a header literal array index.
    pub literal_array_index_off: Option<u32>,
    pub region_headers_off: u32,
    pub line_program_index_off: u32,
    pub regions: Vec<AbcRegionLayout>,
    pub(super) strings: HashMap<String, u32>,
    pub(super) classes: HashMap<String, u32>,
    pub(super) fields: HashMap<(String, String), u32>,
    pub(super) methods: HashMap<(String, String), MethodLayout>,
    pub(super) literal_arrays: Vec<u32>,
    pub(super) scope_names: HashMap<String, u32>,
    pub(super) module_request_phases: HashMap<String, u32>,
    pub(super) module_records: HashMap<String, u32>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct MethodLayout {
    pub(super) offset: u32,
    pub(super) region: u32,
    pub(super) code: Option<u32>,
    pub(super) debug_info: Option<u32>,
}

impl AbcLayout {
    fn method_layout(&self, record: &str, name: &str) -> &MethodLayout {
        self.methods.get(&(record.to_owned(), name.to_owned())).unwrap_or_else(|| panic!("no function `{name}` in record `{record}`"))
    }

    /// Offset of the string item holding `text`.
    ///
    /// # Panics
    /// This and the other lookups panic when nothing of that name was declared.
    pub fn string(&self, text: &str) -> u32 {
        *self.strings.get(text).unwrap_or_else(|| panic!("no string {text:?} in the file"))
    }

    /// Offset of the record or foreign class called `name`.
    pub fn class(&self, name: &str) -> u32 {
        *self.classes.get(name).unwrap_or_else(|| panic!("no record `{name}`"))
    }

    pub fn field(&self, record: &str, name: &str) -> u32 {
        *self.fields.get(&(record.to_owned(), name.to_owned())).unwrap_or_else(|| panic!("no field `{name}` in record `{record}`"))
    }

    /// Offset of a method item. Of functions sharing a name, the first.
    pub fn method(&self, record: &str, name: &str) -> u32 {
        self.method_layout(record, name).offset
    }

    /// Number of the region containing the method.
    pub fn method_region(&self, record: &str, name: &str) -> u32 {
        self.method_layout(record, name).region
    }

    /// Offset of the function's code item.
    pub fn code(&self, record: &str, name: &str) -> u32 {
        self.method_layout(record, name).code.unwrap_or_else(|| panic!("function `{name}` of `{record}` has no code"))
    }

    /// Offset of the function's debug info item.
    pub fn debug_info(&self, record: &str, name: &str) -> u32 {
        self.method_layout(record, name).debug_info.unwrap_or_else(|| panic!("function `{name}` of `{record}` has no debug info"))
    }

    pub fn literal_array(&self, id: LiteralArrayId) -> u32 {
        self.literal_arrays[id.0]
    }

    /// Offset of the phase table behind the record's `ModuleRequestPhases` field.
    pub fn module_request_phases(&self, record: &str) -> u32 {
        *self.module_request_phases.get(record).unwrap_or_else(|| panic!("record `{record}` has no module request phases"))
    }

    /// Offset of the literal array behind the record's `ScopeNames` field.
    pub fn scope_names(&self, record: &str) -> u32 {
        *self.scope_names.get(record).unwrap_or_else(|| panic!("record `{record}` has no scope names"))
    }

    /// Offset of the module record behind the record's `Module` field.
    pub fn module_record(&self, record: &str) -> u32 {
        *self.module_records.get(record).unwrap_or_else(|| panic!("record `{record}` has no module record"))
    }

    /// The id instructions of `record`'s function `name` use for the entity
    /// at `offset`.
    pub fn entity_id(&self, record: &str, name: &str, offset: u32) -> Option<u16> {
        self.regions[self.method_region(record, name) as usize].entity_id(offset)
    }
}

/// A written file and where its parts are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbcFile {
    pub bytes: Vec<u8>,
    pub layout: AbcLayout,
}
