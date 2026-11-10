//! Module records as ECMAScript import / export statements, and the
//! annotation of the instructions that index them.
//!
//! Index spaces (`libabckit/src/adapter_dynamic/helpers_dynamic.cpp`,
//! `HasRegularImportIndexOperand` / `HasLocalExportIndexOperand`, and
//! `GetModuleIndex` for the namespace instructions):
//!
//! | instructions | operand indexes |
//! |---|---|
//! | `ldexternalmodulevar`, its `wide.` / sendable / lazy variants | regular imports |
//! | `ldlocalmodulevar`, `stmodulevar`, their `wide.` / sendable variants | local exports |
//! | `getmodulenamespace`, `wide.getmodulenamespace` | module requests |

use std::fmt::{self, Write};

use asc_abc::{Abc, IndirectExport, LocalExport, ModuleRecord, NamespaceImport, RegularImport, StarExport};
use asc_arkisa::{Opcode, Prefix};

use crate::text::{write_error, write_name, write_quoted};

/// Which section of the module record an instruction's immediate indexes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModuleOperand {
    RegularImport,
    LocalExport,
    Request,
}

impl ModuleOperand {
    /// Classify by opcode number; the unit tests pin the numbers to their
    /// mnemonics.
    pub(crate) fn of(opcode: &Opcode) -> Option<ModuleOperand> {
        match (opcode.prefix, opcode.value) {
            (None, 0x7e) | (Some(Prefix::Wide), 0x11) | (Some(Prefix::CallRuntime), 0x09 | 0x0a | 0x15..=0x18) => {
                Some(ModuleOperand::RegularImport)
            }
            (None, 0x7c | 0x7d) | (Some(Prefix::Wide), 0x0f | 0x10) | (Some(Prefix::CallRuntime), 0x1a | 0x1b) => {
                Some(ModuleOperand::LocalExport)
            }
            (None, 0x7b) | (Some(Prefix::Wide), 0x0e) => Some(ModuleOperand::Request),
            _ => None,
        }
    }
}

/// A module record together with the file its strings live in.
#[derive(Clone, Copy)]
pub(crate) struct ModuleText<'r, 'a> {
    pub abc: &'r Abc<'a>,
    pub module: &'r ModuleRecord<'a>,
}

impl ModuleText<'_, '_> {
    fn name<W: Write>(&self, out: &mut W, off: u32) -> fmt::Result {
        match self.abc.string(off) {
            Ok(name) => write_name(out, &name.to_str()),
            Err(error) => write_error(out, error),
        }
    }

    /// `{ imported as local }`, or `{ name }` when both are the same.
    fn binding<W: Write>(&self, out: &mut W, from_off: u32, to_off: u32) -> fmt::Result {
        out.write_str("{ ")?;
        self.name(out, from_off)?;
        let same =
            from_off == to_off || matches!((self.abc.string(from_off), self.abc.string(to_off)), (Ok(a), Ok(b)) if a.bytes == b.bytes);
        if !same {
            out.write_str(" as ")?;
            self.name(out, to_off)?;
        }
        out.write_str(" }")
    }

    fn request<W: Write>(&self, out: &mut W, idx: u16) -> fmt::Result {
        match self.module.request(idx).map(|off| self.abc.string(off)) {
            Some(Ok(request)) => write_quoted(out, &request.to_str(), usize::MAX),
            Some(Err(error)) => write_error(out, error),
            None => write_error(out, format_args!("no module request {idx}")),
        }
    }

    fn regular_import<W: Write>(&self, out: &mut W, import: &RegularImport) -> fmt::Result {
        out.write_str("import ")?;
        self.binding(out, import.import_name_off, import.local_name_off)?;
        out.write_str(" from ")?;
        self.request(out, import.module_request_idx)
    }

    fn namespace_import<W: Write>(&self, out: &mut W, import: &NamespaceImport) -> fmt::Result {
        out.write_str("import * as ")?;
        self.name(out, import.local_name_off)?;
        out.write_str(" from ")?;
        self.request(out, import.module_request_idx)
    }

    fn local_export<W: Write>(&self, out: &mut W, export: &LocalExport) -> fmt::Result {
        out.write_str("export ")?;
        self.binding(out, export.local_name_off, export.export_name_off)
    }

    fn indirect_export<W: Write>(&self, out: &mut W, export: &IndirectExport) -> fmt::Result {
        out.write_str("export ")?;
        self.binding(out, export.import_name_off, export.export_name_off)?;
        out.write_str(" from ")?;
        self.request(out, export.module_request_idx)
    }

    fn star_export<W: Write>(&self, out: &mut W, export: &StarExport) -> fmt::Result {
        out.write_str("export * from ")?;
        self.request(out, export.module_request_idx)
    }

    /// What operand `index` of a module instruction refers to, as the
    /// statement that declared it.
    pub(crate) fn write_operand<W: Write>(&self, out: &mut W, operand: ModuleOperand, index: usize) -> fmt::Result {
        let missing = |out: &mut W, what: &str, len: usize| write_error(out, format_args!("no {what} {index}, the module has {len}"));
        match operand {
            ModuleOperand::RegularImport => match self.module.regular_imports.get(index) {
                Some(import) => self.regular_import(out, &import),
                None => missing(out, "regular import", self.module.regular_imports.len()),
            },
            ModuleOperand::LocalExport => match self.module.local_exports.get(index) {
                Some(export) => self.local_export(out, &export),
                None => missing(out, "local export", self.module.local_exports.len()),
            },
            ModuleOperand::Request => {
                let Some(idx) = u16::try_from(index).ok().filter(|&idx| self.module.request(idx).is_some()) else {
                    return missing(out, "module request", self.module.requests.len() as usize);
                };
                match self.module.namespace_imports.iter().find(|import| import.module_request_idx == idx) {
                    Some(import) => self.namespace_import(out, &import),
                    None => {
                        out.write_str("import * from ")?;
                        self.request(out, idx)
                    }
                }
            }
        }
    }

    /// The whole record, one numbered statement per line, grouped by
    /// section; empty sections are left out.
    ///
    /// `phases` is the record's module request phase table (empty when it
    /// has none); a request with a non-zero phase is marked with it.
    pub(crate) fn write_sections<W: Write>(&self, out: &mut W, phases: &[u8]) -> fmt::Result {
        out.write_str(".module\n")?;
        let module = self.module;
        if !module.requests.is_empty() {
            out.write_str("  requests:\n")?;
            for index in 0..module.requests.len() {
                write!(out, "    {index}: ")?;
                // The table is sized by a `u32`, a request index is 16 bits wide.
                match u16::try_from(index) {
                    Ok(idx) => self.request(out, idx)?,
                    Err(_) => write_error(out, "unreachable by a 16-bit request index")?,
                }
                if let Some(phase) = phases.get(index as usize).filter(|&&phase| phase != 0) {
                    write!(out, "  ; phase {phase}")?;
                }
                out.write_char('\n')?;
            }
        }
        self.section(out, "regular imports:  ; ldexternalmodulevar N", module.regular_imports.iter(), Self::regular_import)?;
        self.section(out, "namespace imports:", module.namespace_imports.iter(), Self::namespace_import)?;
        self.section(out, "local exports:  ; ldlocalmodulevar N, stmodulevar N", module.local_exports.iter(), Self::local_export)?;
        self.section(out, "indirect exports:", module.indirect_exports.iter(), Self::indirect_export)?;
        self.section(out, "star exports:", module.star_exports.iter(), Self::star_export)
    }

    fn section<W: Write, T>(
        &self,
        out: &mut W,
        title: &str,
        entries: impl Iterator<Item = T>,
        write_entry: impl Fn(&Self, &mut W, &T) -> fmt::Result,
    ) -> fmt::Result {
        for (index, entry) in entries.enumerate() {
            if index == 0 {
                writeln!(out, "  {title}")?;
            }
            write!(out, "    {index}: ")?;
            write_entry(self, out, &entry)?;
            out.write_char('\n')?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_numbers_match_their_mnemonics() {
        let expected = |name: &str| {
            let name = name.rsplit('.').next().unwrap_or(name);
            if name.contains("externalmodulevar") || name.contains("ldlazy") {
                Some(ModuleOperand::RegularImport)
            } else if name.contains("localmodulevar") || name == "stmodulevar" {
                Some(ModuleOperand::LocalExport)
            } else if name == "getmodulenamespace" {
                Some(ModuleOperand::Request)
            } else {
                None
            }
        };
        let mut classified = 0;
        for opcode in asc_arkisa::opcodes() {
            // The `deprecated.*` forms take a name, not an index.
            let want = if opcode.prefix == Some(Prefix::Deprecated) { None } else { expected(opcode.name) };
            assert_eq!(ModuleOperand::of(opcode), want, "{}", opcode.name);
            classified += usize::from(want.is_some());
        }
        assert_eq!(classified, 16);
    }
}
