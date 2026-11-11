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
//! - inline-cache slot operands are left out unless [`Options::ic_slots`];
//! - an annotation the program declares stands under the header of the
//!   function that carries it, `; @RECORD(name=value)`, and the fields of
//!   an annotation interface show their default values.
//!
//! Malformed input never panics and never hides the rest of a record: what
//! cannot be read is replaced by `<error: …>` where it would have stood, and
//! an undecodable instruction ends its function's listing with such a
//! marker.

mod annotation;
mod function;
mod insn;
mod literal;
mod module;
mod record;
mod text;

use std::fmt::{self, Write};

use asc_abc::{Abc, AbcError, Class, Method};
use asc_arkisa::{Instruction, OperandKind};

use insn::InsnPrinter;
use module::ModuleOperand;
use record::RecordInfo;
use text::write_error;

/// Rendering options. The defaults suit a language model reading the
/// listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Options<'a> {
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
    /// builds carry no such names and get no line. On by default: the names
    /// cost nothing where there are none, and make `v3` readable where there are.
    pub locals: bool,
    /// The source the record was compiled from, when a source map says:
    /// the record's header names the file, and the line of a function gets
    /// its line there, `line 116 (source line 21)`, or `(no source line)`
    /// for a function the build added. A record made from several files
    /// has them numbered in its header, and a line says which:
    /// `(source #2 line 21)`.
    pub source: Option<SourceLines<'a>>,
}

/// A line of one of the source files of a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceLine {
    /// Which of [`SourceLines::files`], by index.
    pub file: u32,
    /// The line of that file, counted from 1.
    pub line: u32,
}

/// What a source map says of the lines the debug info of a record names:
/// they are lines of the file the build compiled, not of the source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SourceLines<'a> {
    /// The source files, as the source map names them.
    pub files: &'a [String],
    /// The files the header of the record names, by index into `files`:
    /// those some line comes from. With more than one, every source line
    /// says which file it is a line of.
    pub named: &'a [u32],
    /// For each line of the compiled file, counted from 0 as the debug
    /// info counts: the source line it was made from.
    pub lines: &'a [Option<SourceLine>],
}

impl<'a> SourceLines<'a> {
    /// The source `files` of a source map, the ones of them the record's
    /// header names (`named`, indexes into `files`), and the source line of
    /// each line of the compiled file (`lines`, counted from 0).
    pub fn new(files: &'a [String], named: &'a [u32], lines: &'a [Option<SourceLine>]) -> SourceLines<'a> {
        SourceLines { files, named, lines }
    }
}

impl SourceLines<'_> {
    /// Most files the header of a record names; the rest is counted.
    const MAX_NAMED: usize = 8;

    /// The source line behind line `compiled` of the debug info.
    pub(crate) fn of(&self, compiled: u32) -> Option<SourceLine> {
        self.lines.get(usize::try_from(compiled).ok()?).copied().flatten()
    }

    fn several(&self) -> bool {
        self.named.len() > 1
    }

    /// `source line 21`, or `source #2 line 21` when the record has
    /// several source files.
    pub(crate) fn write_line<W: Write>(&self, out: &mut W, at: SourceLine) -> fmt::Result {
        if self.several() { write!(out, "source #{} line {}", at.file, at.line) } else { write!(out, "source line {}", at.line) }
    }

    /// The header line of a record: the file, or the numbered files, and
    /// how the lines of the listing are to be read.
    pub(crate) fn write_header<W: Write>(&self, out: &mut W) -> fmt::Result {
        let name = |index: u32| self.files.get(index as usize).map_or("", String::as_str);
        if !self.several() {
            out.write_str("; source ")?;
            text::write_name(out, name(self.named.first().copied().unwrap_or(0)))?;
            return out.write_str(
                " (by the source map: \"line N\" of a function is a line of the compiled file, from 0; \"source line\" is the line here)\n",
            );
        }
        out.write_str("; sources")?;
        for (nth, &index) in self.named.iter().take(Self::MAX_NAMED).enumerate() {
            write!(out, "{} #{index} ", if nth == 0 { "" } else { "," })?;
            text::write_name(out, name(index))?;
        }
        if let Some(more) = self.named.len().checked_sub(Self::MAX_NAMED).filter(|&more| more > 0) {
            write!(out, ", … (+{more} more)")?;
        }
        out.write_str(
            " (by the source map: \"line N\" of a function is a line of the compiled file, from 0; \"source #K line N\" is line N of source #K)\n",
        )
    }
}

impl Options<'_> {
    pub const DEFAULT_LITERAL_LIMIT: usize = 256;
    pub const DEFAULT_STRING_LIMIT: usize = 2048;
}

impl<'a> Options<'a> {
    /// These options with at most `items` of a literal array inline.
    #[must_use]
    pub fn literal_limit(self, items: usize) -> Self {
        Options { literal_limit: items, ..self }
    }

    /// These options with at most `bytes` of a string shown.
    #[must_use]
    pub fn string_limit(self, bytes: usize) -> Self {
        Options { string_limit: bytes, ..self }
    }

    /// These options with inline-cache slot operands shown or dropped.
    #[must_use]
    pub fn ic_slots(self, ic_slots: bool) -> Self {
        Options { ic_slots, ..self }
    }

    /// These options with a `; line N` wherever the line changes, or not.
    #[must_use]
    pub fn lines(self, lines: bool) -> Self {
        Options { lines, ..self }
    }

    /// These options with the `; locals` / `; params` header lines, or not.
    #[must_use]
    pub fn locals(self, locals: bool) -> Self {
        Options { locals, ..self }
    }

    /// These options with the source lines a source map gives, if any.
    #[must_use]
    pub fn source(self, source: Option<SourceLines<'a>>) -> Self {
        Options { source, ..self }
    }
}

impl Default for Options<'_> {
    fn default() -> Self {
        Options {
            literal_limit: Self::DEFAULT_LITERAL_LIMIT,
            string_limit: Self::DEFAULT_STRING_LIMIT,
            ic_slots: false,
            lines: false,
            locals: true,
            source: None,
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
pub fn write_record<W: fmt::Write>(out: &mut W, abc: &Abc<'_>, class: &Class<'_>, opts: &Options<'_>) -> Result<(), Error> {
    let info = RecordInfo::load(class);
    record::write_header(out, abc, class, &info, opts)?;

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
    opts: &Options<'_>,
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
    opts: &Options<'_>,
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
