//! The one place that calls `asc-pasm`.

use asc_abc::{Abc, Class, Method};
use asc_arkisa::Instruction;
use asc_hap::ModuleMap;
use asc_pasm::{Options, SourceLines};

use crate::{EngineError, Result};

fn failed(err: asc_pasm::Error) -> EngineError {
    EngineError::Disassembly(err.to_string())
}

/// The options of a listing whose record was compiled from what `map`
/// says: a map that names no source file says nothing a listing can show.
fn with_source(map: Option<&ModuleMap>) -> Options<'_> {
    let source = map.and_then(|map| Some(SourceLines { file: map.source()?, lines: map.source_lines() }));
    Options { source, ..Options::default() }
}

/// A whole record: its fields and every function. `map` is the source
/// map of the record, when its package has one: the listing then names the
/// source file and the source line of each function.
pub(crate) fn record_from(abc: &Abc<'_>, class: &Class<'_>, map: Option<&ModuleMap>) -> Result<String> {
    let mut out = String::new();
    asc_pasm::write_record(&mut out, abc, class, &with_source(map)).map_err(failed)?;
    Ok(out)
}

/// One function of a record.
pub(crate) fn function(abc: &Abc<'_>, class: &Class<'_>, method: &Method<'_>) -> Result<String> {
    function_from(abc, class, method, None)
}

/// As [`function`], with the source map of its record ([`record_from`]).
pub(crate) fn function_from(abc: &Abc<'_>, class: &Class<'_>, method: &Method<'_>, map: Option<&ModuleMap>) -> Result<String> {
    let mut out = String::new();
    asc_pasm::write_function(&mut out, abc, class, method, &with_source(map)).map_err(failed)?;
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
