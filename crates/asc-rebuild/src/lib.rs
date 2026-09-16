//! Single-class DEX reconstruction.
//!
//! Given a DEX buffer and a class descriptor, the pipeline
//!
//! 1. **hollows** the class: class_def, class_data, code items, debug info,
//!    annotations and static values are parsed out of the original buffer;
//! 2. **collects** every constant-pool index the class depends on (bytecode
//!    operands, prototypes, catch types, annotation values, ...) and closes
//!    the set over the id tables (a method needs its class type, prototype
//!    and name string, a prototype needs its shorty and parameter types, ...);
//! 3. **maps** the collected items onto new, canonically sorted id tables;
//! 4. **writes** a fresh DEX (`header`, id tables, one class_def, data section
//!    and map list) with rewritten bytecode operands, a valid Adler-32
//!    checksum and SHA-1 signature.
//!
//! The output is a spec-conformant DEX that only defines the requested class,
//! so it can be handed to any decompiler or disassembler.

mod collect;
mod hollow;
mod tables;
mod writer;

use asc_dex::Dex;
use std::time::Instant;

pub use tables::Tables;

/// Errors from the rebuild pipeline.
#[derive(Debug, thiserror::Error)]
pub enum RebuildError {
    #[error(transparent)]
    Dex(#[from] asc_dex::DexError),
    #[error("class {0} not found in DEX")]
    ClassNotFound(String),
    #[error("rebuilt DEX would exceed 16-bit index limits ({what}: {count})")]
    TooManyItems { what: &'static str, count: usize },
    /// The class uses a DEX feature the rebuild cannot reproduce faithfully
    /// (currently `call_site_ids` / `method_handles`: `invoke-custom`,
    /// `const-method-handle` and `VALUE_METHOD_HANDLE` annotation values).
    #[error("unsupported DEX feature: {0}")]
    Unsupported(&'static str),
    /// A method body could not be walked to its end (undefined / quickened
    /// opcode or an instruction running past the code item).
    #[error("malformed bytecode in method {method_idx} at {pc:#x}: {reason}")]
    Bytecode { method_idx: u32, pc: usize, reason: String },
    /// An index the writer needed was never collected; this is a bug in the
    /// rebuild pipeline, not in the input DEX.
    #[error("internal inconsistency while rebuilding: {0}")]
    Internal(String),
}

impl RebuildError {
    /// Whether the error means "this class exists but cannot be rebuilt
    /// faithfully" (as opposed to a corrupt DEX, a missing class or a bug in
    /// the pipeline). Hosts fall back to disassembling the class in place.
    pub fn is_input_limitation(&self) -> bool {
        matches!(self, RebuildError::Bytecode { .. } | RebuildError::Unsupported(_) | RebuildError::TooManyItems { .. })
    }
}

pub type Result<T> = std::result::Result<T, RebuildError>;

/// Per-phase timings in microseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timings {
    pub hollow_us: u128,
    pub collect_us: u128,
    pub map_us: u128,
    pub build_us: u128,
}

impl Timings {
    pub fn total_us(&self) -> u128 {
        self.hollow_us + self.collect_us + self.map_us + self.build_us
    }
}

/// Table sizes of the rebuilt DEX.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub strings: usize,
    pub types: usize,
    pub protos: usize,
    pub fields: usize,
    pub methods: usize,
    pub methods_with_code: usize,
    pub size: usize,
}

/// Result of a rebuild.
#[derive(Debug, Clone)]
pub struct Rebuilt {
    pub bytes: Vec<u8>,
    pub stats: Stats,
    pub timings: Timings,
}

/// Rebuild the class `descriptor` (e.g. `Lcom/poc/Main;`) from `dex`.
pub fn rebuild_class(dex: &Dex<'_>, descriptor: &str) -> Result<Rebuilt> {
    let t0 = Instant::now();
    let hollow = hollow::Hollow::extract(dex, descriptor)?;
    let t1 = Instant::now();
    let refs = collect::collect(dex, &hollow)?;
    let t2 = Instant::now();
    let tables = Tables::build(dex, &refs)?;
    let t3 = Instant::now();
    let (bytes, methods_with_code) = writer::write(dex, &hollow, &tables)?;
    let t4 = Instant::now();
    Ok(Rebuilt {
        stats: Stats {
            strings: tables.strings.len(),
            types: tables.types.len(),
            protos: tables.protos.len(),
            fields: tables.fields.len(),
            methods: tables.methods.len(),
            methods_with_code,
            size: bytes.len(),
        },
        bytes,
        timings: Timings {
            hollow_us: (t1 - t0).as_micros(),
            collect_us: (t2 - t1).as_micros(),
            map_us: (t3 - t2).as_micros(),
            build_us: (t4 - t3).as_micros(),
        },
    })
}

/// Convenience wrapper over raw bytes.
pub fn rebuild_class_bytes(buf: &[u8], descriptor: &str) -> Result<Rebuilt> {
    let dex = Dex::parse(buf)?;
    rebuild_class(&dex, descriptor)
}
