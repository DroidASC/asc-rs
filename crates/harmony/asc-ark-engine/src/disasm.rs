//! The one place that calls `asc-pasm`.

use asc_abc::{Abc, Class, Method};
use asc_arkisa::Instruction;
use asc_hap::ModuleMap;
use asc_pasm::{Options, SourceLine, SourceLines};

use crate::{EngineError, Result};

fn failed(err: asc_pasm::Error) -> EngineError {
    EngineError::Disassembly(err.to_string())
}

/// What a listing shows besides the code.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Listing<'m> {
    /// The source map of the record, when its package has one: the listing
    /// then names the source files and the source line of each function.
    pub(crate) map: Option<&'m ModuleMap>,
    /// Whether every change of line is written where it happens
    /// ([`Options::lines`]).
    pub(crate) lines: bool,
}

/// The source lines of a listing whose record was compiled from what a
/// source map says, kept for as long as the listing is written.
struct Mapped<'m> {
    map: &'m ModuleMap,
    /// The sources the header names: those lines come from, or the first
    /// one of a map that maps no line.
    named: Vec<u32>,
    lines: Vec<Option<SourceLine>>,
}

impl<'m> Mapped<'m> {
    /// `None` for a map that names no source file: it says nothing a
    /// listing can show.
    fn of(map: &'m ModuleMap) -> Option<Mapped<'m>> {
        let named = match map.mapped_sources() {
            [] => vec![0],
            mapped => mapped.to_vec(),
        };
        if let [only] = named[..] {
            map.sources.get(only as usize).filter(|source| !source.is_empty())?;
        }
        let lines = map.source_lines().iter().map(|at| at.map(|at| SourceLine { file: at.source, line: at.line })).collect();
        Some(Mapped { map, named, lines })
    }

    fn source_lines(&self) -> SourceLines<'_> {
        SourceLines { files: &self.map.sources, named: &self.named, lines: &self.lines }
    }
}

impl Listing<'_> {
    fn write(self, write: impl FnOnce(&Options<'_>) -> std::result::Result<(), asc_pasm::Error>) -> Result<()> {
        let mapped = self.map.and_then(Mapped::of);
        let source = mapped.as_ref().map(Mapped::source_lines);
        write(&Options { source, lines: self.lines, ..Options::default() }).map_err(failed)
    }
}

/// A whole record: its fields and every function.
pub(crate) fn record_from(abc: &Abc<'_>, class: &Class<'_>, listing: Listing<'_>) -> Result<String> {
    let mut out = String::new();
    listing.write(|options| asc_pasm::write_record(&mut out, abc, class, options))?;
    Ok(out)
}

/// One function of a record.
pub(crate) fn function(abc: &Abc<'_>, class: &Class<'_>, method: &Method<'_>) -> Result<String> {
    function_from(abc, class, method, Listing::default())
}

/// As [`function`], with what [`record_from`] takes.
pub(crate) fn function_from(abc: &Abc<'_>, class: &Class<'_>, method: &Method<'_>, listing: Listing<'_>) -> Result<String> {
    let mut out = String::new();
    listing.write(|options| asc_pasm::write_function(&mut out, abc, class, method, options))?;
    Ok(out)
}

/// One instruction on one line, for a result row. An operand that cannot be
/// resolved must not cost the row: the mnemonic alone is printed then.
pub(crate) fn instruction(abc: &Abc<'_>, method: &Method<'_>, insn: &Instruction<'_>) -> String {
    instruction_with(abc, method, insn, &Options::default())
}

/// As [`instruction`], with the items of a literal array left out
/// (`[ … (+7 more) ]`): for rows that list the items they are about
/// themselves.
pub(crate) fn instruction_without_literals(abc: &Abc<'_>, method: &Method<'_>, insn: &Instruction<'_>) -> String {
    instruction_with(abc, method, insn, &Options { literal_limit: 0, ..Options::default() })
}

fn instruction_with(abc: &Abc<'_>, method: &Method<'_>, insn: &Instruction<'_>, options: &Options<'_>) -> String {
    let mut out = String::new();
    match asc_pasm::write_instruction(&mut out, abc, method, insn, options) {
        Ok(()) => out.trim().to_owned(),
        Err(_) => insn.opcode.name.to_owned(),
    }
}
