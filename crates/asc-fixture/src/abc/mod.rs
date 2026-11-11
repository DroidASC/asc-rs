//! Synthetic ArkCompiler ABC (Panda file, dynamic flavour) files for tests.
//!
//! [`AbcBuilder`] takes a declarative description — records, their fields
//! and functions, code written with the [`Asm`] assembler, literal arrays,
//! module records, annotations — and writes a file laid out the way the
//! official writer (`libpandafile/file_item_container.cpp`) lays one out:
//!
//! ```text
//! header | class index | literal array index (<= 12.0.6.0) | region headers
//! | per region: class table, entity table, field table, proto table
//! | foreign classes | classes with their fields and methods | strings
//! | literal arrays and module records | field values | protos (< 12)
//! | annotations | code | line number programs and debug info
//! | line number program index
//! ```
//!
//! Strings, methods and literal arrays named by instructions get per-region
//! 16-bit ids in the order the region's code first mentions them.
//!
//! ```
//! use asc_fixture::abc::{AbcBuilder, AbcCode, AbcFunction, AbcRecord, Asm, Op};
//!
//! let mut asm = Asm::new();
//! asm.op("lda.str", [Op::str("hello")]).op("return", []);
//! let mut builder = AbcBuilder::new();
//! builder.record(AbcRecord::new("&entry/src/main/ets/pages/Index&").function(AbcFunction::new("func_main_0", AbcCode::new(1, 3, asm))));
//! let file = builder.build();
//!
//! let abc = asc_abc::Abc::parse(&file.bytes).unwrap();
//! let method = abc.method(file.layout.method("&entry/src/main/ets/pages/Index&", "func_main_0")).unwrap();
//! assert_eq!(method.resolve(0).unwrap(), file.layout.string("hello"));
//! ```

pub mod annotations;
mod asm;
mod calls;
mod classes;
mod layout;
mod lineage;
mod objects;
mod packages;
mod plan;
mod sample;
mod spec;
mod writer;

pub use annotations::{MARKS_APP, MARKS_LIB, MARKS_LIB_MARKED, MARKS_ROUTE, NAMED_APP, annotations_program, callable_names_program};
pub use asm::{Asm, Assembled, Catch, Op};
pub use calls::{CALLS_APP, CALLS_BOX, CALLS_INDEX, CALLS_UTIL, call_graph_program};
pub use classes::{CLASSES_APP, CLASSES_BASE, CLASSES_INDEX, class_hierarchy_program};
pub use layout::{AbcFile, AbcLayout, AbcRegionLayout};
pub use lineage::{LINEAGE_APP, LINEAGE_BASE, LINEAGE_LEAF, LINEAGE_MIDDLE, LINEAGE_SERVICE, class_calls_program};
pub use objects::{
    HANDED_APP, HANDED_KIND, HANDED_STORE, LATE_PANEL, LATE_SUB, PATCHED_APP, PATCHED_CACHE, PATCHED_RUNTIME, PATCHED_VAULT,
    handed_objects_program, late_members_program, patched_objects_program,
};
pub use packages::{
    PACKAGED_ENTRY_MODULE_JSON, PACKAGED_ENTRY_PKG_CONTEXT, PACKAGED_INDEX, PACKAGED_KIT, PACKAGED_LIBRARY_MODULE_JSON, PACKAGED_OWN,
    PACKAGED_TOOL, packaged_entry_program, packaged_library_program,
};
pub use sample::{ENTRY_ABILITY, INDEX_PAGE, SAMPLE_API_URL, SAMPLE_MAGIC, make_abc, make_multi_region_abc, sample_program};
pub use spec::{
    AbcAnnotation, AbcAnnotationElement, AbcCatch, AbcCode, AbcDebugInfo, AbcElementValue, AbcField, AbcFieldValue, AbcFunction,
    AbcIndirectExport, AbcLineOp, AbcLiteral, AbcLocalExport, AbcModule, AbcNamespaceImport, AbcRecord, AbcRegularImport, AbcTry, AbcType,
    AnnotationKind, LiteralArrayId, MethodRef,
};

/// 9.0.0.0: field / proto region tables and a header literal array index.
pub const VERSION_9_0_0_0: [u8; 4] = [9, 0, 0, 0];
/// 12.0.6.0: the last version with a header literal array index.
pub const VERSION_12_0_6_0: [u8; 4] = [12, 0, 6, 0];
/// 13.0.1.0: no header literal array index.
pub const VERSION_13_0_1_0: [u8; 4] = [13, 0, 1, 0];

/// `ACC_PUBLIC`.
pub const ACC_PUBLIC: u32 = 0x0001;
/// `ACC_STATIC`: set on every function the ArkTS compiler emits.
pub const ACC_STATIC: u32 = 0x0008;
/// `ACC_ANNOTATION`: the record is an annotation interface.
pub const ACC_ANNOTATION: u32 = 0x2000;

/// Source language tag `ECMASCRIPT`, the one real files carry.
pub const LANG_ECMASCRIPT: u8 = 0;

/// What goes into `access_flags >> 16` of every method: the number of the
/// region whose tables its instructions use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RegionHint {
    /// The real region number, as the official writer stores it.
    #[default]
    Exact,
    /// This number for every method, right or wrong: readers must then
    /// find the region by offset.
    Fixed(u32),
}

/// Declarative description of an ABC file; [`AbcBuilder::build`] writes it.
#[derive(Debug, Clone)]
pub struct AbcBuilder {
    version: [u8; 4],
    records: Vec<AbcRecord>,
    foreign_classes: Vec<String>,
    literal_arrays: Vec<Vec<AbcLiteral>>,
    strings: Vec<String>,
    region_starts: Vec<String>,
    methods_per_region: Option<usize>,
    max_region_entities: usize,
    region_hint: RegionHint,
    unsorted_class_index: bool,
    stale_checksum: bool,
    encrypted: bool,
    truncated: Option<usize>,
}

impl Default for AbcBuilder {
    fn default() -> AbcBuilder {
        AbcBuilder::new()
    }
}

impl AbcBuilder {
    /// The 16-bit ids of a region can name this many entities; the official
    /// writer starts a new region when a function would exceed it.
    pub const MAX_REGION_ENTITIES: usize = 0x1_0000;

    /// An empty file of version 12.0.6.0.
    pub fn new() -> AbcBuilder {
        AbcBuilder {
            version: VERSION_12_0_6_0,
            records: Vec::new(),
            foreign_classes: Vec::new(),
            literal_arrays: Vec::new(),
            strings: Vec::new(),
            region_starts: Vec::new(),
            methods_per_region: None,
            max_region_entities: Self::MAX_REGION_ENTITIES,
            region_hint: RegionHint::Exact,
            unsorted_class_index: false,
            stale_checksum: false,
            encrypted: false,
            truncated: None,
        }
    }

    /// Set the file version. It decides the layout like it does in the
    /// official writer: up to 12.0.6.0 the header has a literal array index
    /// (which also lists module records); before 12 regions have field and
    /// proto tables and methods a prototype, from 12 on those tables are
    /// stored as `0xFFFFFFFF` and `proto_idx` is `0xFFFF`.
    pub fn version(&mut self, version: [u8; 4]) -> &mut AbcBuilder {
        self.version = version;
        self
    }

    /// Add a record. Records are written in the order they are added; the
    /// class index is sorted by name regardless.
    pub fn record(&mut self, record: AbcRecord) -> &mut AbcBuilder {
        self.records.push(record);
        self
    }

    /// The records added so far.
    pub fn records(&self) -> &[AbcRecord] {
        &self.records
    }

    /// Declare a class defined in another file (listed in the class index,
    /// stored in the foreign region as a bare descriptor).
    pub fn foreign_class(&mut self, name: &str) -> &mut AbcBuilder {
        self.foreign_classes.push(name.to_owned());
        self
    }

    /// Declare a literal array; the handle names it in instructions
    /// ([`Op::Literal`]), fields and other literal arrays.
    pub fn literal_array(&mut self, items: impl IntoIterator<Item = AbcLiteral>) -> LiteralArrayId {
        self.literal_arrays.push(items.into_iter().collect());
        LiteralArrayId(self.literal_arrays.len() - 1)
    }

    /// The literal arrays declared so far.
    pub fn literal_arrays(&self) -> impl Iterator<Item = (LiteralArrayId, &[AbcLiteral])> {
        self.literal_arrays.iter().enumerate().map(|(index, items)| (LiteralArrayId(index), items.as_slice()))
    }

    /// Add a string nothing refers to.
    pub fn string(&mut self, text: &str) -> &mut AbcBuilder {
        self.strings.push(text.to_owned());
        self
    }

    /// Start a new region at the record called `record`.
    pub fn split_region_before(&mut self, record: &str) -> &mut AbcBuilder {
        self.region_starts.push(record.to_owned());
        self
    }

    /// Start a new region whenever the current one holds `methods`
    /// functions. Like in real files, such a split can fall in the middle
    /// of a record, whose class item then belongs to the earlier region.
    ///
    /// # Panics
    /// When `methods` is zero.
    pub fn split_region_every(&mut self, methods: usize) -> &mut AbcBuilder {
        assert!(methods > 0, "a region holds at least one function");
        self.methods_per_region = Some(methods);
        self
    }

    /// Lower the number of entities a region's id table can hold from
    /// [`AbcBuilder::MAX_REGION_ENTITIES`]: the mechanism that splits real
    /// files, at a size tests can afford.
    pub fn max_region_entities(&mut self, entities: usize) -> &mut AbcBuilder {
        self.max_region_entities = entities.min(Self::MAX_REGION_ENTITIES);
        self
    }

    /// Choose what methods store as their region number.
    pub fn region_hint(&mut self, hint: RegionHint) -> &mut AbcBuilder {
        self.region_hint = hint;
        self
    }

    /// Write the class index in reverse name order: lookups by binary
    /// search then miss.
    pub fn unsorted_class_index(&mut self) -> &mut AbcBuilder {
        self.unsorted_class_index = true;
        self
    }

    /// Store a checksum that does not match the content, as tools that
    /// patch files leave it.
    pub fn stale_checksum(&mut self) -> &mut AbcBuilder {
        self.stale_checksum = true;
        self
    }

    /// Replace everything after the header with pseudo-random bytes and
    /// keep the checksum of the plain file: what an app-store-encrypted
    /// `modules.abc` looks like.
    pub fn encrypted(&mut self) -> &mut AbcBuilder {
        self.encrypted = true;
        self
    }

    /// Cut the file to its first `len` bytes (header fields stay as they were).
    pub fn truncated(&mut self, len: usize) -> &mut AbcBuilder {
        self.truncated = Some(len);
        self
    }

    /// Write the file.
    ///
    /// # Panics
    /// When the description is inconsistent: a reference to a record,
    /// function or label that does not exist, a function with more entity
    /// references than a region can hold, a value outside its encoding.
    pub fn build(&self) -> AbcFile {
        writer::write(self)
    }
}

/// Adler-32 (zlib's definition): the header checksum covers everything
/// after the checksum field.
pub fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    // Longest run whose sums cannot overflow 32 bits before the modulo.
    const BLOCK: usize = 5552;
    let (mut a, mut b) = (1u32, 0u32);
    for block in data.chunks(BLOCK) {
        for &byte in block {
            a += u32::from(byte);
            b += a;
        }
        a %= MOD;
        b %= MOD;
    }
    (b << 16) | a
}

/// Recompute the header checksum of a file edited after it was built.
///
/// # Panics
/// When `file` is shorter than the checksum field.
pub fn seal(file: &mut [u8]) {
    let checksum = adler32(&file[12..]);
    file[8..12].copy_from_slice(&checksum.to_le_bytes());
}

/// Replace everything after the 60-byte header with pseudo-random bytes,
/// leaving the header (and so the plain file's checksum) alone.
pub fn scramble_body(file: &mut [u8]) {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for byte in file.iter_mut().skip(asc_abc::HEADER_SIZE) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state.to_le_bytes()[3];
    }
}
