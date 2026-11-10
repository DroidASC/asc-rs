//! `method:`: where a function is made a closure or attached to a class.
//!
//! Calls do not name their callee, so the only instructions with a method id
//! are the ones that create a function object: `definefunc`, `definemethod`,
//! `defineclasswithbuffer`, `callruntime.definesendableclass`. The methods of
//! a class and of an object literal are named by `METHOD` / `GETTER` /
//! `SETTER` / generator items of the literal array such an instruction
//! refers to.
//!
//! Located first: the functions whose name matches are found by walking the
//! records once, their offsets become region ids, and the code scan compares
//! ids.

use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::atomic::AtomicBool;

use asc_abc::{Abc, ClassEntry, Literal};
use asc_arkisa::{DecodeError, OperandKind};

use super::{
    chunks, pc_of, run_units, Condition, Env, Function, Hit, IdSet, ListedFunction, Pattern, Record, RecordHit, Worker, MAX_LITERAL_DEPTH,
    RECORD_CHUNK,
};
use crate::callgraph::{FnRef, Session};
use crate::ops::OpTable;
use crate::{records, EngineError, Result};

/// A prepared `method:` search of one ABC entry.
pub(crate) struct Methods<'a> {
    abc: Abc<'a>,
    /// File offsets of the functions the query names.
    offsets: HashSet<u32>,
    ids: IdSet,
    operands: OpTable<Operands>,
}

/// The id operands of an opcode that can name a function.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Operands {
    method: bool,
    /// The literal array operand: a 16-bit id, or the file offset the
    /// `deprecated.*` opcodes carry.
    literal: Option<IdWidth>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdWidth {
    Id,
    Offset,
}

impl Operands {
    fn of(opcode: &asc_arkisa::Opcode) -> Operands {
        let literal =
            opcode.operand_of(OperandKind::LiteralArrayId).map(|operand| if operand.width > 16 { IdWidth::Offset } else { IdWidth::Id });
        Operands { method: opcode.operand_of(OperandKind::MethodId).is_some(), literal }
    }
}

/// Whether a function named `raw` / `restored` is the one `name` asks for.
/// An exact name is the raw name, the restored one or a dotted suffix of
/// it, as for `getclass --method`.
pub(crate) fn name_matches(name: &Pattern, raw: &str, restored: impl FnOnce() -> String) -> bool {
    match name {
        Pattern::Exact(wanted) => {
            raw == wanted || {
                let restored = restored();
                restored == *wanted || restored.strip_suffix(wanted.as_str()).is_some_and(|rest| rest.ends_with('.'))
            }
        }
        Pattern::Regex(_) | Pattern::Contains(_) => name.is_match(raw) || name.is_match(&restored()),
    }
}

/// File offsets of the functions of the entry of `env` that `name` names,
/// in the records `record` names (all, when `None`).
pub(crate) fn named_functions(env: &Env<'_, '_>, record: Option<&str>, name: &Pattern) -> Result<HashSet<u32>> {
    let abc = env.abc;
    let classes: Vec<u32> = abc.class_index().map_err(|source| EngineError::Abc { entry: env.entry.to_owned(), source })?.iter().collect();
    let units: Vec<Range<usize>> = chunks(classes.len(), RECORD_CHUNK).collect();
    let found = run_units(units.len(), env.workers, env.cancel, |unit| {
        let mut offsets = Vec::new();
        for &off in &classes[units[unit].clone()] {
            // An unreadable record or function is reported by the code scan.
            let Ok(ClassEntry::Local(class)) = abc.class_entry(off) else { continue };
            if record.is_some_and(|wanted| !records::names_record(&String::from_utf8_lossy(class.name()), wanted)) {
                continue;
            }
            let Ok(methods) = class.methods() else { continue };
            for method in methods.map_while(|method| method.ok()) {
                let Ok(raw) = method.name() else { continue };
                let raw = raw.to_str();
                if name_matches(name, &raw, || class.restore_function_name(&raw)) {
                    offsets.push(method.offset());
                }
            }
        }
        offsets
    })?;
    Ok(found.into_iter().flatten().collect())
}

/// The functions of the program a list names: each line by its raw or its
/// restored name, in the record it gives (any, without one).
pub(crate) fn listed_functions(session: &Session<'_>, listed: &[ListedFunction], cancel: &AtomicBool) -> Result<HashSet<FnRef>> {
    let mut by_name: HashMap<&str, Vec<Option<&str>>> = HashMap::new();
    for function in listed {
        by_name.entry(function.function.as_str()).or_default().push(function.record.as_deref());
    }
    let mut out = HashSet::new();
    for (entry, abc) in session.readable() {
        let classes: Vec<u32> =
            abc.class_index().map_err(|source| EngineError::Abc { entry: session.entry_name(entry).to_owned(), source })?.iter().collect();
        let units: Vec<Range<usize>> = chunks(classes.len(), RECORD_CHUNK).collect();
        let found = run_units(units.len(), session.threads(), cancel, |unit| {
            let mut offsets = Vec::new();
            for &off in &classes[units[unit].clone()] {
                let Ok(ClassEntry::Local(class)) = abc.class_entry(off) else { continue };
                let record = String::from_utf8_lossy(class.name());
                let in_record = |wanted: &[Option<&str>]| {
                    wanted.iter().any(|wanted| wanted.is_none_or(|wanted| records::names_record(&record, wanted)))
                };
                let Ok(methods) = class.methods() else { continue };
                for method in methods.map_while(|method| method.ok()) {
                    let Ok(raw) = method.name() else { continue };
                    let raw = raw.to_str();
                    let by_raw = by_name.get(&*raw).is_some_and(|wanted| in_record(wanted));
                    if by_raw || by_name.get(class.restore_function_name(&raw).as_str()).is_some_and(|wanted| in_record(wanted)) {
                        offsets.push(method.offset());
                    }
                }
            }
            offsets
        })?;
        out.extend(found.into_iter().flatten().map(|method| FnRef { entry, method }));
    }
    Ok(out)
}

impl<'a> Methods<'a> {
    pub(crate) fn prepare(env: &Env<'_, 'a>, record: Option<&str>, name: &Pattern) -> Result<Methods<'a>> {
        let abc = env.abc;
        let offsets = named_functions(env, record, name)?;
        let ids = if offsets.is_empty() { IdSet::default() } else { IdSet::locate(env, |off| offsets.contains(&off))? };
        Ok(Methods { abc, offsets, ids, operands: OpTable::build(Operands::of) })
    }

    /// The matching method items of the literal array at `off`, as
    /// `[1]=method #~@0>#build`.
    fn literal_hits(&self, off: u32, prefix: &str, depth: usize, matched: &mut Vec<String>, out: &mut Vec<String>) {
        let Ok(array) = self.abc.literal_array(off) else { return };
        for (index, literal) in array.iter().map_while(|literal| literal.ok()).enumerate() {
            let kind = match literal {
                Literal::Method(_) => "method",
                Literal::GeneratorMethod(_) => "generator",
                Literal::AsyncGeneratorMethod(_) => "async generator",
                Literal::Getter(_) => "getter",
                Literal::Setter(_) => "setter",
                Literal::LiteralArray(nested) if depth < MAX_LITERAL_DEPTH => {
                    self.literal_hits(nested, &format!("{prefix}[{index}]"), depth + 1, matched, out);
                    continue;
                }
                _ => continue,
            };
            let Some(method_off) = literal.method_off().filter(|off| self.offsets.contains(off)) else { continue };
            let name =
                self.abc.method(method_off).and_then(|method| method.name()).map(|name| name.to_str().into_owned()).unwrap_or_default();
            out.push(format!("{prefix}[{index}]={kind} {name}"));
            matched.push(name);
        }
    }
}

impl<'a> Condition<'a> for Methods<'a> {
    fn worker<'s>(&'s self) -> Box<dyn Worker<'a> + 's> {
        Box::new(MethodsWorker(self))
    }

    fn is_impossible(&self) -> bool {
        self.offsets.is_empty()
    }
}

struct MethodsWorker<'s, 'a>(&'s Methods<'a>);

impl<'a> Worker<'a> for MethodsWorker<'_, 'a> {
    fn record(&mut self, _: &Record<'_, 'a>, _: &mut Vec<RecordHit>) -> bool {
        true
    }

    fn function(&mut self, function: &Function<'_, 'a>, hits: &mut Vec<Hit>) -> std::result::Result<(), DecodeError> {
        let methods = self.0;
        for insn in asc_arkisa::walk(function.code.instructions()) {
            let insn = insn?;
            let operands = methods.operands.of(insn.opcode);
            if operands == Operands::default() {
                continue;
            }
            let mut matched = Vec::new();
            let mut text = String::new();
            let named = insn.method_id().filter(|&id| operands.method && methods.ids.contains(function.region, id));
            if let Some(off) = named.and_then(|id| function.entity(id)) {
                matched.extend(methods.abc.method(off).and_then(|method| method.name()).map(|name| name.to_str().into_owned()));
                text = function.text_without_literals(&insn);
            }
            let array = operands.literal.zip(insn.literal_array_id()).and_then(|(width, id)| match width {
                IdWidth::Id => function.entity(id),
                IdWidth::Offset => Some(id),
            });
            if let Some(off) = array {
                let mut items = Vec::new();
                methods.literal_hits(off, "", 0, &mut matched, &mut items);
                if !items.is_empty() {
                    text.push_str(if text.is_empty() { insn.opcode.name } else { " ;" });
                    text.push_str(&format!(" literal@{off:#x} {}", items.join(", ")));
                }
            }
            if !matched.is_empty() {
                hits.push(Hit { pc: pc_of(&insn), matched, text });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operands_that_name_a_function() {
        let of = |name: &str| asc_arkisa::opcodes().find(|op| op.name == name).map(Operands::of).unwrap();
        assert_eq!(of("definefunc"), Operands { method: true, literal: None });
        assert_eq!(of("defineclasswithbuffer"), Operands { method: true, literal: Some(IdWidth::Id) });
        assert_eq!(of("callruntime.definesendableclass"), Operands { method: true, literal: Some(IdWidth::Id) });
        assert_eq!(of("createobjectwithbuffer"), Operands { method: false, literal: Some(IdWidth::Id) });
        assert_eq!(of("callthis1"), Operands::default());
        // The instructions with a method id, all of them definitions.
        let mut with_method: Vec<&str> = asc_arkisa::opcodes().filter(|op| Operands::of(op).method).map(|op| op.name).collect();
        with_method.sort_unstable();
        with_method.dedup();
        assert_eq!(
            with_method,
            ["callruntime.definesendableclass", "defineclasswithbuffer", "definefunc", "definemethod", "deprecated.defineclasswithbuffer"]
        );
    }

    #[test]
    fn names_match_raw_restored_and_suffix() {
        let restored = || "Index.build".to_owned();
        let exact = |name: &str| name_matches(&Pattern::exact(name), "#~@0>#build", restored);
        assert!(exact("#~@0>#build") && exact("Index.build") && exact("build"));
        assert!(!exact("uild") && !exact("Index") && !exact("ndex.build"));
        assert!(name_matches(&Pattern::regex("^Index\\.").unwrap(), "#~@0>#build", restored));
        assert!(name_matches(&Pattern::regex("@0>").unwrap(), "#~@0>#build", restored));
        assert!(name_matches(&Pattern::contains("x.b"), "#~@0>#build", restored));
        assert!(!name_matches(&Pattern::regex("^build").unwrap(), "#~@0>#build", restored));
    }
}
