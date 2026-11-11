//! DEX reconstruction of a class and its `$` nested classes.
//!
//! Given a DEX buffer and a class descriptor, the pipeline
//!
//! 1. **hollows** the class and its nested classes: class_def, class_data, code items, debug info,
//!    annotations and static values are parsed out of the original buffer;
//! 2. **collects** every constant-pool index these classes depend on (bytecode
//!    operands, prototypes, catch types, annotation values, ...) and closes
//!    the set over the id tables (a method needs its class type, prototype
//!    and name string, a prototype needs its shorty and parameter types, ...);
//! 3. **maps** the collected items onto new, canonically sorted id tables;
//! 4. **writes** a fresh DEX (`header`, shared id tables, class_defs, data section
//!    and map list) with rewritten bytecode operands, a valid Adler-32
//!    checksum and SHA-1 signature.
//!
//! The output defines the requested class and every class in the same DEX
//! whose descriptor starts with its name followed by `$`. It can be handed
//! to any decompiler or disassembler. Only the requested class has to
//! rebuild: nested classes that cannot are left out and reported in
//! [`Rebuilt::dropped`].

mod collect;
mod hollow;
mod tables;
mod writer;

use asc_dex::Dex;
use std::fmt;
use std::time::Instant;

pub use tables::Tables;

/// Errors from the rebuild pipeline.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
pub struct Stats {
    pub strings: usize,
    pub types: usize,
    pub protos: usize,
    pub fields: usize,
    pub methods: usize,
    pub methods_with_code: usize,
    pub size: usize,
}

/// A nested class left out of a rebuilt DEX.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DroppedClass {
    /// Descriptor such as `Lcom/poc/Main$1;`.
    pub descriptor: String,
    /// Why it was left out (the rebuild error it caused).
    pub reason: String,
}

impl DroppedClass {
    fn new(dex: &Dex<'_>, class_idx: u32, reason: String) -> Result<DroppedClass> {
        Ok(DroppedClass { descriptor: dex.type_descriptor(class_idx)?, reason })
    }
}

impl fmt::Display for DroppedClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.descriptor, self.reason)
    }
}

/// Result of a rebuild.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Rebuilt {
    pub bytes: Vec<u8>,
    pub stats: Stats,
    pub timings: Timings,
    /// Nested classes that could not be rebuilt and are not defined in
    /// `bytes`, in input order. Other classes may still reference their types.
    pub dropped: Vec<DroppedClass>,
}

/// Rebuild the class `descriptor` (e.g. `Lcom/poc/Main;`) from `dex`.
///
/// Includes its `$` nested classes at every depth in this DEX. For example,
/// `LA;` includes `LA$a;` and `LA$a$b;`, while rebuilding `LA$a;` includes
/// `LA$a$b;` but no definition for `LA;` or siblings such as `LA$c;`.
///
/// Only the requested class has to rebuild: a nested class that cannot
/// (malformed bytecode, an unsupported feature, ...) is left out and listed
/// in [`Rebuilt::dropped`]. When the classes only fail together (16-bit index
/// limits, ...), the requested class is rebuilt alone and every nested class
/// is listed.
pub fn rebuild_class(dex: &Dex<'_>, descriptor: &str) -> Result<Rebuilt> {
    let mut timings = Timings::default();
    let mut sel = timed(&mut timings.hollow_us, || hollow::Selection::extract(dex, descriptor))?;
    let refs = timed(&mut timings.collect_us, || collect::collect(dex, &mut sel))?;
    let (tables, bytes, methods_with_code) = match assemble(dex, &sel.classes, refs, &mut timings) {
        Ok(out) => out,
        Err(e) if sel.has_nested() => {
            let reason = format!("the nested classes do not rebuild together: {e}");
            sel.retain_nested(dex, |_| Err(&reason))?;
            let refs = timed(&mut timings.collect_us, || collect::collect(dex, &mut sel))?;
            assemble(dex, &sel.classes, refs, &mut timings)?
        }
        Err(e) => return Err(e),
    };
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
        timings,
        dropped: sel.dropped,
    })
}

/// Close `refs`, map them and write the DEX defining `classes`; the steps
/// that can only fail for the selection as a whole.
fn assemble(
    dex: &Dex<'_>,
    classes: &[hollow::Hollow<'_>],
    mut refs: collect::RefSet,
    timings: &mut Timings,
) -> Result<(Tables, Vec<u8>, usize)> {
    timed(&mut timings.collect_us, || refs.close(dex))?;
    let tables = timed(&mut timings.map_us, || Tables::build(dex, &refs))?;
    let (bytes, methods_with_code) = timed(&mut timings.build_us, || writer::write(dex, classes, &tables))?;
    Ok((tables, bytes, methods_with_code))
}

/// Run `f`, adding its wall time to `slot`.
fn timed<T>(slot: &mut u128, f: impl FnOnce() -> T) -> T {
    let t0 = Instant::now();
    let out = f();
    *slot += t0.elapsed().as_micros();
    out
}

/// Convenience wrapper over raw bytes.
pub fn rebuild_class_bytes(buf: &[u8], descriptor: &str) -> Result<Rebuilt> {
    let dex = Dex::parse(buf)?;
    rebuild_class(&dex, descriptor)
}
