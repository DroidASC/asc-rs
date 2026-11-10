//! One function: header, then the listing with labels, try ranges and
//! (optionally) source lines woven in at their code offsets.

use std::fmt::{self, Write};
use std::iter::Peekable;

use asc_abc::{Abc, CatchBlock, Code, DebugInfo, FunctionKind, LineRows, LocalVar, Method, TryBlock};
use asc_arkisa::walk;

use crate::insn::{write_label, InsnPrinter};
use crate::record::RecordInfo;
use crate::text::{write_count, write_error, write_name, ELLIPSIS};
use crate::Options;

/// Closes every function, so a listing cut short by the caller is
/// recognisable.
const END: &str = ".end function\n";

/// Most try blocks placed in one listing. Every instruction is checked
/// against every range, so a damaged count must not run away; real
/// functions have a handful.
const MAX_TRY_BLOCKS: usize = 4096;

/// Arguments every ArkTS function receives before its declared parameters:
/// the function object, `new.target` and `this`.
const IMPLICIT_ARGS: u32 = 3;

fn kind_text(kind: FunctionKind) -> Option<&'static str> {
    match kind.base() {
        FunctionKind::GENERATOR_FUNCTION => Some("generator"),
        FunctionKind::ASYNC_FUNCTION | FunctionKind::ASYNC_NC_FUNCTION => Some("async"),
        FunctionKind::ASYNC_GENERATOR_FUNCTION => Some("async generator"),
        FunctionKind::CONCURRENT_FUNCTION => Some("concurrent"),
        _ => None,
    }
}

/// `.function <raw name>  ; <restored name>` and the summary line.
fn write_header<W: Write>(
    out: &mut W,
    abc: &Abc<'_>,
    record: &RecordInfo<'_>,
    method: &Method<'_>,
    code: Option<&Code<'_>>,
    opts: &Options,
) -> fmt::Result {
    out.write_str(".function ")?;
    match method.name() {
        Ok(name) => {
            let raw = name.to_str();
            write_name(out, &raw)?;
            if let Some(restored) = record.restored_name(abc, &raw) {
                out.write_str("  ; ")?;
                write_name(out, &restored)?;
            }
        }
        Err(error) => write_error(out, format_args!("name: {error}"))?,
    }
    out.write_str("\n;")?;
    match code {
        Some(code) => {
            write!(out, " vregs {}, args {}", code.num_vregs, code.num_args)?;
            if let Some(params) = code.num_args.checked_sub(IMPLICIT_ARGS) {
                out.write_str(" (a0 func, a1 new.target, a2 this, ")?;
                write_count(out, params, "param")?;
                out.write_char(')')?;
            }
            out.write_str(", code ")?;
            // The size was read from a 32-bit field.
            write_count(out, u32::try_from(code.instructions().len()).unwrap_or(u32::MAX), "byte")?;
            if code.tries_size > 0 {
                out.write_str(", ")?;
                write_count(out, code.tries_size, "try block")?;
            }
        }
        None => out.write_str(" no code")?,
    }
    if !opts.lines {
        // With `lines` the listing itself carries every line.
        match method.debug_info().and_then(|info| info.map(|info| info.first_line()).transpose()) {
            Ok(Some(Some(line))) => write!(out, ", line {line}")?,
            Ok(Some(None) | None) => {}
            Err(error) => {
                out.write_str(", line ")?;
                write_error(out, error)?;
            }
        }
    }
    let kind = method.function_kind();
    if let Some(kind) = kind_text(kind) {
        write!(out, ", {kind}")?;
    }
    if kind.is_sendable() {
        out.write_str(", sendable")?;
    }
    out.write_char('\n')
}

/// Most variables named in one header. Line number programs are shared
/// and their length is whatever the file says; real functions have dozens.
const MAX_LOCALS: usize = 256;

/// The type every ArkTS variable has; not worth a word.
const ANY: &[u8] = b"any";

/// `v3` below `num_vregs`, `a1` from there on, `acc` for the accumulator.
fn write_local_reg<W: Write>(out: &mut W, code: &Code<'_>, reg: i64) -> fmt::Result {
    match u32::try_from(reg) {
        Err(_) => out.write_str("acc"),
        Ok(reg) => match reg.checked_sub(code.num_vregs) {
            Some(arg) => write!(out, "a{arg}"),
            None => write!(out, "v{reg}"),
        },
    }
}

fn write_local_name<W: Write>(out: &mut W, abc: &Abc<'_>, name_off: u32) -> fmt::Result {
    match abc.string(name_off) {
        Ok(name) => write_name(out, &name.to_str()),
        Err(error) => write_error(out, format_args!("name: {error}")),
    }
}

/// The header lines naming the registers, when the debug info names any:
///
/// ```text
/// ; locals [0004, 0020): v0 count, v1 name: string
/// ; locals [0010, 0018): v2 item
/// ; params: a3 url
/// ```
///
/// Variables are grouped by the code range in which their registers hold
/// them, one line per range in the order the ranges first occur; a
/// parameter holds its register throughout. The compiler's own variables
/// (`0this`, `4funcObj`: names no source identifier can have) are left out,
/// the function's header says where those values are.
/// Whether the variable named at `name_off` is one the compiler made: its
/// name starts with a digit.
fn is_compiler_name(abc: &Abc<'_>, name_off: u32) -> bool {
    abc.string(name_off).is_ok_and(|name| name.bytes.first().is_some_and(u8::is_ascii_digit))
}

fn write_locals<W: Write>(out: &mut W, abc: &Abc<'_>, code: &Code<'_>, info: &DebugInfo<'_>) -> fmt::Result {
    let locals = match info.locals() {
        Ok(locals) => locals,
        Err(error) => {
            out.write_str("; locals: ")?;
            write_error(out, error)?;
            return out.write_char('\n');
        }
    };
    let code_size = u32::try_from(code.instructions().len()).unwrap_or(u32::MAX);
    let range = |local: &&LocalVar| (local.start_pc, local.end_pc.unwrap_or(code_size));
    let locals: Vec<&LocalVar> = locals.iter().filter(|local| !is_compiler_name(abc, local.name_off)).collect();
    let shown = &locals[..locals.len().min(MAX_LOCALS)];
    for (first, local) in shown.iter().enumerate() {
        let (start, end) = range(local);
        if shown[..first].iter().any(|earlier| range(earlier) == (start, end)) {
            continue;
        }
        write!(out, "; locals [{start:04x}, {end:04x}): ")?;
        let group = shown[first..].iter().filter(|&local| range(local) == (start, end));
        for (i, local) in group.enumerate() {
            out.write_str(if i == 0 { "" } else { ", " })?;
            write_local_reg(out, code, i64::from(local.reg))?;
            out.write_char(' ')?;
            write_local_name(out, abc, local.name_off)?;
            // The signature is the type again unless the variable was started with one.
            match abc.string(local.signature_off.unwrap_or(local.type_off)) {
                Ok(kind) if kind.bytes == ANY || kind.bytes.is_empty() => {}
                Ok(kind) => {
                    out.write_str(": ")?;
                    write_name(out, &kind.to_str())?;
                }
                Err(error) => {
                    out.write_str(": ")?;
                    write_error(out, format_args!("type: {error}"))?;
                }
            }
        }
        out.write_char('\n')?;
    }
    if locals.len() > MAX_LOCALS {
        writeln!(out, "; locals: {ELLIPSIS} (+{} more)", locals.len() - MAX_LOCALS)?;
    }
    // A nameless parameter is stored as offset 0.
    let params = (i64::from(code.num_vregs)..).zip(info.params()).filter(|&(_, name_off)| name_off != 0);
    let mut named = 0usize;
    for (reg, name_off) in params.take(MAX_LOCALS) {
        named += 1;
        out.write_str(if named == 1 { "; params: " } else { ", " })?;
        write_local_reg(out, code, reg)?;
        out.write_char(' ')?;
        write_local_name(out, abc, name_off)?;
    }
    if named > 0 {
        out.write_char('\n')?;
    }
    Ok(())
}

/// A try block and how far the listing got with it.
struct TryRange<'a> {
    block: TryBlock<'a>,
    begun: bool,
    ended: bool,
}

impl TryRange<'_> {
    fn start(&self) -> usize {
        self.block.start_pc as usize
    }

    fn end(&self) -> usize {
        self.start().saturating_add(self.block.length as usize)
    }
}

fn write_catch<W: Write>(out: &mut W, method: &Method<'_>, abc: &Abc<'_>, catch: &CatchBlock) -> fmt::Result {
    match catch.type_idx {
        None => out.write_str("catchall"),
        Some(idx) => {
            out.write_str("catch ")?;
            let class_off = u16::try_from(idx).ok().and_then(|idx| method.region().and_then(|region| region.class_entry(idx)).ok());
            match class_off.map(|off| abc.string(off)) {
                Some(Ok(descriptor)) => write_name(out, &descriptor.to_str()),
                Some(Err(_)) | None => write!(out, "type#{idx}"),
            }
        }
    }
}

/// The source line table, consumed in step with the listing.
struct Lines<'a> {
    rows: Option<Peekable<LineRows<'a>>>,
    /// Line of the instructions before the next row.
    pending: u32,
    written: Option<u32>,
}

impl<'a> Lines<'a> {
    fn open<W: Write>(out: &mut W, method: &Method<'a>) -> Result<Lines<'a>, fmt::Error> {
        let mut lines = Lines { rows: None, pending: 0, written: None };
        match method.debug_info().and_then(|info| info.map(|info| Ok((info.line_start, info.line_rows()?))).transpose()) {
            Ok(Some((line_start, rows))) => {
                lines.pending = line_start;
                lines.rows = Some(rows.peekable());
            }
            Ok(None) => {}
            Err(error) => {
                out.write_str("  ; ")?;
                write_error(out, format_args!("line table: {error}"))?;
                out.write_char('\n')?;
            }
        }
        Ok(lines)
    }

    /// Write `; line N` when the instruction at `pc` starts a new line.
    fn advance<W: Write>(&mut self, out: &mut W, pc: usize) -> fmt::Result {
        let Some(rows) = &mut self.rows else { return Ok(()) };
        while let Some(row) = rows.next_if(|row| row.as_ref().map_or(true, |row| row.pc as usize <= pc)) {
            match row {
                Ok(row) => self.pending = row.line,
                Err(error) => {
                    out.write_str("  ; ")?;
                    write_error(out, format_args!("line table: {error}"))?;
                    out.write_char('\n')?;
                    self.rows = None;
                    return Ok(());
                }
            }
        }
        // Compiler-generated code carries line -1.
        if self.written != Some(self.pending) && i32::try_from(self.pending).is_ok() {
            self.written = Some(self.pending);
            writeln!(out, "  ; line {}", self.pending)?;
        }
        Ok(())
    }
}

/// Everything that is placed between instructions, keyed by code offset.
struct Markers<'a> {
    /// Branch targets and handler starts, sorted, without duplicates.
    labels: Vec<usize>,
    next_label: usize,
    tries: Vec<TryRange<'a>>,
}

impl<'a> Markers<'a> {
    /// One pass over the code for the branch targets, one over the try
    /// blocks. Functions without either allocate nothing.
    fn collect<W: Write>(out: &mut W, code: &Code<'a>) -> Result<Markers<'a>, fmt::Error> {
        let mut labels: Vec<usize> = walk(code.instructions())
            .map_while(Result::ok)
            .filter(|insn| insn.opcode.is_jump())
            .filter_map(|insn| insn.jump_target())
            .collect();
        let mut tries = Vec::new();
        for block in code.try_blocks() {
            match block {
                Ok(_) if tries.len() == MAX_TRY_BLOCKS => {
                    out.write_str("  ; ")?;
                    write_error(out, format_args!("{} try blocks, only the first {MAX_TRY_BLOCKS} are shown", code.tries_size))?;
                    out.write_char('\n')?;
                    break;
                }
                Ok(block) => {
                    labels.extend(block.catch_blocks().map(|catch| catch.handler_pc as usize));
                    tries.push(TryRange { block, begun: false, ended: false });
                }
                Err(error) => {
                    out.write_str("  ; ")?;
                    write_error(out, format_args!("try blocks: {error}"))?;
                    out.write_char('\n')?;
                }
            }
        }
        labels.sort_unstable();
        labels.dedup();
        Ok(Markers { labels, next_label: 0, tries })
    }

    /// Write what belongs in front of the instruction at `pc` (or, with `pc`
    /// at the code size, after the last one): ends of try ranges, the label,
    /// starts of try ranges.
    fn write_at<W: Write>(&mut self, out: &mut W, abc: &Abc<'_>, method: &Method<'_>, pc: usize) -> fmt::Result {
        while let Some(&target) = self.labels.get(self.next_label).filter(|&&target| target < pc) {
            out.write_str("  ; ")?;
            write_error(out, format_args!("branch or handler target {target:#06x} is not the start of an instruction"))?;
            out.write_char('\n')?;
            self.next_label += 1;
        }
        for (index, range) in self.tries.iter_mut().enumerate() {
            if range.begun && !range.ended && range.end() == pc {
                range.ended = true;
                writeln!(out, "  .endtry {index}")?;
            }
        }
        if self.labels.get(self.next_label) == Some(&pc) {
            self.next_label += 1;
            write_label(out, pc)?;
            out.write_char(':')?;
            let handled =
                self.tries.iter().enumerate().flat_map(|(index, range)| range.block.catch_blocks().map(move |catch| (index, catch)));
            for (index, catch) in handled.filter(|(_, catch)| catch.handler_pc as usize == pc) {
                write!(out, "  ; handler of try {index}, ")?;
                write_count(out, catch.code_size, "byte")?;
            }
            out.write_char('\n')?;
        }
        for (index, range) in self.tries.iter_mut().enumerate() {
            if !range.begun && range.start() == pc {
                range.begun = true;
                write!(out, "  .try {index} [{:04x}, {:04x})", range.start(), range.end())?;
                for catch in range.block.catch_blocks() {
                    out.write_char(' ')?;
                    write_catch(out, method, abc, &catch)?;
                    out.write_str(" -> ")?;
                    write_label(out, catch.handler_pc as usize)?;
                }
                // A range that covers nothing has no later offset to end at.
                if range.end() == pc {
                    range.ended = true;
                    out.write_str("  ; empty")?;
                }
                out.write_char('\n')?;
            }
        }
        Ok(())
    }

    /// Report what never found its place: targets past the code, try ranges
    /// whose bounds are not instruction starts.
    fn write_unplaced<W: Write>(&self, out: &mut W) -> fmt::Result {
        for target in self.labels.iter().skip(self.next_label) {
            out.write_str("  ; ")?;
            write_error(out, format_args!("branch or handler target {target:#06x} is past the end of the code"))?;
            out.write_char('\n')?;
        }
        for (index, range) in self.tries.iter().enumerate().filter(|(_, range)| !range.begun || !range.ended) {
            out.write_str("  ; ")?;
            let bound = if range.begun { "end" } else { "start" };
            write_error(
                out,
                format_args!("try {index} [{:04x}, {:04x}): its {bound} is not the start of an instruction", range.start(), range.end()),
            )?;
            out.write_char('\n')?;
        }
        Ok(())
    }
}

/// Write the function: header, listing, `.end function`.
pub(crate) fn write_function<W: Write>(
    out: &mut W,
    abc: &Abc<'_>,
    record: &RecordInfo<'_>,
    method: &Method<'_>,
    opts: &Options,
) -> fmt::Result {
    let code = match method.code() {
        Ok(code) => code,
        Err(error) => {
            write_header(out, abc, record, method, None, opts)?;
            out.write_str("  ; ")?;
            write_error(out, format_args!("code: {error}"))?;
            out.write_char('\n')?;
            return out.write_str(END);
        }
    };
    write_header(out, abc, record, method, code.as_ref(), opts)?;
    let Some(code) = code else { return out.write_str(END) };
    if opts.locals {
        // A debug info that cannot be read is reported where the line would stand.
        if let Ok(Some(info)) = method.debug_info() {
            write_locals(out, abc, &code, &info)?;
        }
    }

    let printer = InsnPrinter::new(abc, method, record, Some(code.num_vregs), opts);
    let mut markers = Markers::collect(out, &code)?;
    let mut lines = if opts.lines { Some(Lines::open(out, method)?) } else { None };
    let bytes = code.instructions();
    let mut complete = true;
    for insn in walk(bytes) {
        match insn {
            Ok(insn) => {
                markers.write_at(out, abc, method, insn.pc)?;
                if let Some(lines) = &mut lines {
                    lines.advance(out, insn.pc)?;
                }
                write!(out, "  {:04x}  ", insn.pc)?;
                printer.write(out, &insn)?;
                out.write_char('\n')?;
            }
            Err(error) => {
                complete = false;
                out.write_str("  ; ")?;
                write_error(
                    out,
                    format_args!(
                        "{error}; listing stops, {} of {} bytes not disassembled",
                        bytes.len() - error.pc().min(bytes.len()),
                        bytes.len()
                    ),
                )?;
                out.write_char('\n')?;
            }
        }
    }
    if complete {
        markers.write_at(out, abc, method, bytes.len())?;
        markers.write_unplaced(out)?;
    }
    out.write_str(END)
}
