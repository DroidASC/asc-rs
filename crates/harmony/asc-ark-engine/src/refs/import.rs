//! `import:`: uses of imported bindings.
//!
//! A record's imports are in its module record: the module requests
//! (`@ohos:net.http`), and per binding the request it comes from and the
//! name it has there. Instructions name a binding by its index
//! (`ldexternalmodulevar 3` is regular import 3; `getmodulenamespace 1` is
//! the namespace of request 1). So per record the matching indexes are
//! found first, and its code is scanned only when there are any.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use asc_abc::{Abc, Class, ClassEntry, ModuleRecord};
use asc_arkisa::DecodeError;

use super::{Condition, Function, Hit, Pattern, Record, RecordHit, Worker, pc_of};
use crate::ops::{ModuleOperand, OpTable, immediate};
use crate::program::Program;
use crate::{EngineError, Result, text};

/// The name that stands for a whole module: `import * as ns`, `export *`.
const NAMESPACE: &str = "*";

/// A prepared `import:` search. Nothing is located up front: the module
/// records are per record.
pub(crate) struct Imports<'q> {
    request: &'q Pattern,
    name: Option<&'q str>,
    declarations_only: bool,
    operands: OpTable<Option<ModuleOperand>>,
}

impl<'q> Imports<'q> {
    pub(crate) fn new(request: &'q Pattern, name: Option<&'q str>, declarations_only: bool) -> Imports<'q> {
        Imports { request, name, declarations_only, operands: OpTable::build(ModuleOperand::of) }
    }
}

impl<'a> Condition<'a> for Imports<'_> {
    fn worker<'s>(&'s self) -> Box<dyn Worker<'a> + 's> {
        Box::new(ImportsWorker { query: self, bindings: Vec::new(), namespaces: Vec::new() })
    }
}

struct ImportsWorker<'s, 'q> {
    query: &'s Imports<'q>,
    /// Per regular import of the current record: its `REQUEST#NAME` when it matches.
    bindings: Vec<Option<String>>,
    /// Per module request of the current record: its `REQUEST#*` when it matches.
    namespaces: Vec<Option<String>>,
}

/// Module requests are indexed with 16 bits.
fn request_text(abc: &Abc<'_>, module: &ModuleRecord<'_>, index: u16) -> Option<String> {
    let off = module.request(index)?;
    Some(abc.string(off).ok()?.to_str().into_owned())
}

fn name_text(abc: &Abc<'_>, off: u32) -> String {
    abc.string(off).map_or_else(|_| "?".to_owned(), |name| name.to_str().into_owned())
}

/// `{ imported as local }`, or `{ name }` when both are the same.
fn binding_text(imported: &str, local: &str) -> String {
    if imported == local { format!("{{ {imported} }}") } else { format!("{{ {imported} as {local} }}") }
}

impl ImportsWorker<'_, '_> {
    fn wants(&self, name: &str) -> bool {
        self.query.name.is_none_or(|wanted| wanted == name)
    }

    /// The declarations of `module` that match, as rows, and the indexes
    /// the code scan looks for.
    fn declarations(&mut self, abc: &Abc<'_>, module: &ModuleRecord<'_>, hits: &mut Vec<RecordHit>) {
        let requests: Vec<Option<String>> = (0..module.requests.len())
            .map(|index| {
                let request = request_text(abc, module, u16::try_from(index).ok()?)?;
                self.query.request.is_match(&request).then_some(request)
            })
            .collect();
        let request = |index: u16| requests.get(usize::from(index)).and_then(Option::as_ref);
        let mut declared = vec![false; requests.len()];
        let mut declare = |index: u16, matched: String, text: String| {
            if let Some(seen) = declared.get_mut(usize::from(index)) {
                *seen = true;
            }
            hits.push(RecordHit { field: "moduleRecordIdx".to_owned(), matched: vec![matched], text });
        };

        self.bindings = vec![None; module.regular_imports.len()];
        for (index, import) in module.regular_imports.iter().enumerate() {
            let Some(request) = request(import.module_request_idx) else { continue };
            let imported = name_text(abc, import.import_name_off);
            if !self.wants(&imported) {
                continue;
            }
            let binding = format!("{request}#{imported}");
            let statement = binding_text(&imported, &name_text(abc, import.local_name_off));
            declare(
                import.module_request_idx,
                binding.clone(),
                format!("regular import {index}: import {statement} from {}", text::quoted(request)),
            );
            self.bindings[index] = Some(binding);
        }
        self.namespaces = vec![None; requests.len()];
        if self.wants(NAMESPACE) {
            for (slot, request) in self.namespaces.iter_mut().zip(&requests) {
                *slot = request.as_ref().map(|request| format!("{request}#{NAMESPACE}"));
            }
            for (index, import) in module.namespace_imports.iter().enumerate() {
                let Some(request) = request(import.module_request_idx) else { continue };
                let local = name_text(abc, import.local_name_off);
                let text = format!("namespace import {index}: import * as {local} from {}", text::quoted(request));
                declare(import.module_request_idx, format!("{request}#{NAMESPACE}"), text);
            }
        }
        for (index, export) in module.indirect_exports.iter().enumerate() {
            let Some(request) = request(export.module_request_idx) else { continue };
            let imported = name_text(abc, export.import_name_off);
            if !self.wants(&imported) {
                continue;
            }
            let statement = binding_text(&imported, &name_text(abc, export.export_name_off));
            let text = format!("indirect export {index}: export {statement} from {}", text::quoted(request));
            declare(export.module_request_idx, format!("{request}#{imported}"), text);
        }
        if self.wants(NAMESPACE) {
            for (index, export) in module.star_exports.iter().enumerate() {
                let Some(request) = request(export.module_request_idx) else { continue };
                let text = format!("star export {index}: export * from {}", text::quoted(request));
                declare(export.module_request_idx, format!("{request}#{NAMESPACE}"), text);
            }
        }
        // A request no binding refers to: `import "module"`, for its side effects.
        if self.query.name.is_none() {
            for (index, request) in requests.iter().enumerate() {
                if let (Some(request), false) = (request, declared[index]) {
                    let text = format!("request {index}: import {}", text::quoted(request));
                    hits.push(RecordHit { field: "moduleRecordIdx".to_owned(), matched: vec![request.clone()], text });
                }
            }
        }
    }
}

impl<'a> Worker<'a> for ImportsWorker<'_, '_> {
    fn record(&mut self, record: &Record<'_, 'a>, hits: &mut Vec<RecordHit>) -> bool {
        self.bindings.clear();
        self.namespaces.clear();
        // A record without a module record (or with a malformed one) imports nothing.
        let Ok(Some(module)) = record.class.module_record() else { return false };
        self.declarations(&record.abc, &module, hits);
        !self.query.declarations_only && self.bindings.iter().chain(&self.namespaces).any(Option::is_some)
    }

    fn function(&mut self, function: &Function<'_, 'a>, hits: &mut Vec<Hit>) -> std::result::Result<(), DecodeError> {
        for insn in asc_arkisa::walk(function.code.instructions()) {
            let insn = insn?;
            let table = match self.query.operands.of(insn.opcode) {
                Some(ModuleOperand::RegularImport) => &self.bindings,
                Some(ModuleOperand::Request) => &self.namespaces,
                Some(ModuleOperand::LocalExport) | None => continue,
            };
            let binding = immediate(&insn, 0).and_then(|index| table.get(index as usize)).and_then(Option::as_ref);
            if let Some(binding) = binding {
                hits.push(Hit { pc: pc_of(&insn), matched: vec![binding.clone()], text: function.text(&insn) });
            }
        }
        Ok(())
    }
}

/// One module request of a program and who asks for it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RequestListing {
    /// The ABC entry.
    pub entry: String,
    /// The module request, e.g. `@ohos:net.http`.
    pub request: String,
    /// Number of records of the entry that request it.
    pub records: usize,
    /// The names imported or re-exported from it, sorted; `*` is the whole
    /// namespace. Empty when it is only imported for its side effects.
    pub names: Vec<String>,
}

impl RequestListing {
    /// `[entry | ]request | N records | name, name`; `-` for no names.
    pub fn line(&self, with_entry: bool) -> String {
        let mut out = String::new();
        if with_entry {
            out.push_str(&self.entry);
            out.push_str(" | ");
        }
        let names = if self.names.is_empty() { "-".to_owned() } else { self.names.join(", ") };
        // Writing to a String cannot fail.
        let _ = write!(out, "{} | {} record{} | {names}", self.request, self.records, if self.records == 1 { "" } else { "s" });
        out
    }
}

/// What the records of one entry ask of one module request.
#[derive(Default)]
struct RequestUse {
    records: usize,
    names: Vec<String>,
}

fn requests_of_record(abc: &Abc<'_>, class: &Class<'_>, pattern: Option<&Pattern>, uses: &mut BTreeMap<String, RequestUse>) {
    let Ok(Some(module)) = class.module_record() else { return };
    let mut names: Vec<(u16, String)> = Vec::new();
    names.extend(module.regular_imports.iter().map(|import| (import.module_request_idx, name_text(abc, import.import_name_off))));
    names.extend(module.indirect_exports.iter().map(|export| (export.module_request_idx, name_text(abc, export.import_name_off))));
    names.extend(module.namespace_imports.iter().map(|import| (import.module_request_idx, NAMESPACE.to_owned())));
    names.extend(module.star_exports.iter().map(|export| (export.module_request_idx, NAMESPACE.to_owned())));
    for index in 0..module.requests.len() {
        let Some(index) = u16::try_from(index).ok() else { break };
        let Some(request) = request_text(abc, &module, index) else { continue };
        if pattern.is_some_and(|pattern| !pattern.is_match(&request)) {
            continue;
        }
        let entry = uses.entry(request).or_default();
        entry.records += 1;
        entry.names.extend(names.iter().filter(|(of, _)| *of == index).map(|(_, name)| name.clone()));
    }
}

/// The distinct module requests of the program, entry by entry, sorted by
/// request; `pattern` keeps the matching ones.
pub(crate) fn module_requests(program: &Program, pattern: Option<&Pattern>) -> Result<Vec<RequestListing>> {
    let mut out = Vec::new();
    for (index, abc) in program.readable() {
        let entry = program.info(index).map_or("", |info| info.name.as_str());
        let mut uses = BTreeMap::new();
        for class in abc.classes().map_err(|source| EngineError::Abc { entry: entry.to_owned(), source })? {
            // An unreadable record has no requests to list; `findrefs` reports it.
            if let Ok(ClassEntry::Local(class)) = class {
                requests_of_record(&abc, &class, pattern, &mut uses);
            }
        }
        out.extend(uses.into_iter().map(|(request, mut request_use)| {
            request_use.names.sort_unstable();
            request_use.names.dedup();
            RequestListing { entry: entry.to_owned(), request, records: request_use.records, names: request_use.names }
        }));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_lines() {
        let mut listing =
            RequestListing { entry: "ets/modules.abc".into(), request: "@ohos:net.http".into(), records: 2, names: vec!["default".into()] };
        assert_eq!(listing.line(false), "@ohos:net.http | 2 records | default");
        listing.records = 1;
        listing.names.clear();
        assert_eq!(listing.line(true), "ets/modules.abc | @ohos:net.http | 1 record | -");
        assert_eq!((binding_text("default", "http"), binding_text("a", "a")), ("{ default as http }".into(), "{ a }".into()));
    }
}
