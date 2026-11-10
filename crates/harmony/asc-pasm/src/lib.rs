//! Pandasm-style disassembly of ArkCompiler ABC records and functions.
//!
//! The text is rendered on demand straight from the file: a record's
//! listing reads that record and what its operands name, nothing else, and
//! there is no pass over the whole file. Mnemonics and operand order are
//! those of `isa.yaml`; beyond that the output is laid out for a reader who
//! cannot look anything up:
//!
//! ```text
//! .function #~@0>#aboutToAppear  ; Index.aboutToAppear
//! ; vregs 4, args 3 (a0 func, a1 new.target, a2 this, 0 params), code 46 bytes, line 21
//!   0000  ldexternalmodulevar 1  ; import { default as hilog } from "@ohos:hilog"
//!   0002  sta v0
//!   0004  ldai 0x1d4b42 (1919810)
//!   0009  jeqz L_0020
//!   000b  createarraywithbuffer [ "a", 0x10 (16), … (+3 more) ]
//! L_0020:
//!   0020  returnundefined
//! .end function
//! ```
//!
//! - a function is headed by its raw name, the one queries take, with the
//!   restored name as a comment;
//! - string, method and literal-array ids are resolved in place;
//! - integers of more than one digit are written in hex and decimal;
//! - a branch names its target `L_<offset>`, the hex offset the target line
//!   starts with, and the label is repeated on its own line there;
//! - module instructions are annotated with the import or export they index;
//! - registers at or above the function's `vregs` are arguments, `a0` …;
//! - inline-cache slot operands are left out unless [`Options::ic_slots`].
//!
//! Malformed input never panics and never hides the rest of a record: what
//! cannot be read is replaced by `<error: …>` where it would have stood, and
//! an undecodable instruction ends its function's listing with such a
//! marker.

mod function;
mod insn;
mod literal;
mod module;
mod record;
mod text;

use std::fmt;

use asc_abc::{Abc, AbcError, Class, Method};
use asc_arkisa::{Instruction, OperandKind};

use insn::InsnPrinter;
use module::ModuleOperand;
use record::RecordInfo;
use text::write_error;

/// Rendering options. The defaults suit a language model reading the
/// listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Most items of a literal array shown inline; the rest is summed up as
    /// `… (+N more)`.
    pub literal_limit: usize,
    /// Most bytes of a string shown; the rest is summed up as
    /// `… (+N bytes)`. `usize::MAX` shows every string whole.
    pub string_limit: usize,
    /// Show inline-cache slot operands (`ldobjbyname 0x4, "name"`). They
    /// are runtime bookkeeping, so the default drops them.
    pub ic_slots: bool,
    /// Put a `; line N` comment where the source line changes, instead of
    /// only the function's first line in its header.
    pub lines: bool,
    /// Add header lines naming the registers the debug info names, grouped
    /// by the code range in which a register holds its variable: `; locals
    /// [0004, 0020): v0 count, v1 name`, and `; params: a3 url`. Release
    /// builds carry no such names and get no line.
    pub locals: bool,
}

impl Options {
    pub const DEFAULT_LITERAL_LIMIT: usize = 256;
    pub const DEFAULT_STRING_LIMIT: usize = 2048;
}

impl Default for Options {
    fn default() -> Self {
        Options {
            literal_limit: Self::DEFAULT_LITERAL_LIMIT,
            string_limit: Self::DEFAULT_STRING_LIMIT,
            ic_slots: false,
            lines: false,
            locals: false,
        }
    }
}

/// Why a listing could not be written. Damage inside the file is not an
/// error of this kind: it is reported in the listing, as `<error: …>`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A structure the whole request depends on cannot be read.
    #[error(transparent)]
    Abc(#[from] AbcError),
    /// The output sink failed.
    #[error(transparent)]
    Fmt(#[from] fmt::Error),
}

/// Write a whole record: its header (name, kind, package, source file,
/// module requests, imports and exports), its fields, then every function.
///
/// # Errors
/// [`Error::Fmt`] when `out` fails. Malformed members are reported inside
/// the listing.
pub fn write_record<W: fmt::Write>(out: &mut W, abc: &Abc<'_>, class: &Class<'_>, opts: &Options) -> Result<(), Error> {
    let info = RecordInfo::load(class);
    record::write_header(out, abc, class, &info)?;

    let mut fields = match class.fields() {
        Ok(fields) => fields,
        Err(error) => {
            out.write_str("; ")?;
            write_error(out, format_args!("record tags: {error}; fields and functions cannot be located"))?;
            out.write_char('\n')?;
            return Ok(());
        }
    };
    for field in fields.by_ref() {
        match field {
            Ok(field) => record::write_field(out, abc, &field, opts)?,
            Err(error) => {
                out.write_str("; ")?;
                write_error(out, format_args!("field: {error}"))?;
                out.write_char('\n')?;
            }
        }
    }
    let methods = match fields.into_methods() {
        Ok(methods) => methods,
        Err(error) => {
            out.write_str("; ")?;
            write_error(out, format_args!("{error}; functions cannot be located"))?;
            out.write_char('\n')?;
            return Ok(());
        }
    };
    for method in methods {
        out.write_char('\n')?;
        match method {
            Ok(method) => function::write_function(out, abc, &info, &method, opts)?,
            Err(error) => {
                out.write_str("; ")?;
                write_error(out, format_args!("function: {error}; the functions after it cannot be located"))?;
                out.write_char('\n')?;
            }
        }
    }
    Ok(())
}

/// Write one function of a record: header, listing with labels and try
/// ranges, `.end function`.
///
/// `method` must be a method of `class`: the record supplies the scope
/// names and the module record its instructions refer to.
///
/// # Errors
/// [`Error::Fmt`] when `out` fails. Malformed code is reported inside the
/// listing.
pub fn write_function<W: fmt::Write>(
    out: &mut W,
    abc: &Abc<'_>,
    class: &Class<'_>,
    method: &Method<'_>,
    opts: &Options,
) -> Result<(), Error> {
    function::write_function(out, abc, &RecordInfo::load(class), method, opts)?;
    Ok(())
}

/// Write one instruction of `method` as it appears in a listing, without
/// the offset column and without a line break: `lda.str "hello"`.
///
/// The method's record is only looked up for the instructions that need it
/// (function definitions and module variable accesses).
///
/// # Errors
/// [`Error::Fmt`] when `out` fails. Operands that cannot be resolved are
/// written as `<error: …>`.
pub fn write_instruction<W: fmt::Write>(
    out: &mut W,
    abc: &Abc<'_>,
    method: &Method<'_>,
    insn: &Instruction<'_>,
    opts: &Options,
) -> Result<(), Error> {
    let needs_record = ModuleOperand::of(insn.opcode).is_some() || insn.opcode.operand_of(OperandKind::MethodId).is_some();
    let info = if needs_record {
        match method.class_off().and_then(|off| abc.class(off)) {
            Ok(class) => RecordInfo::load(&class),
            Err(error) => RecordInfo::unresolved(error),
        }
    } else {
        RecordInfo::none()
    };
    // Without a code item there is no telling arguments from locals.
    let num_vregs = method.code().ok().flatten().map(|code| code.num_vregs);
    InsnPrinter::new(abc, method, &info, num_vregs, opts).write(out, insn)?;
    Ok(())
}
