//! `call:{RULE}` / `call:{@FILE}`: call sites that lead to a function of a set.
//!
//! The set is worked out before the search ([`super::Sets`]); the call
//! sites come from the edges of the call graph ([`crate::callgraph`]), so a
//! row is a call by any link the graph knows: proved (`import`, local, `new`,
//! `super`) or matched by name (`[this-class]`, `[inherited]`, `[instance]`,
//! `[reassigned]`), and says which. Creating a closure (`[defines]`) is not
//! a call. One level of a callers walk, as rows with their instruction:
//! `callarg0 ; -> RECORD->FUNCTION (restored name) [this-class]`.

use std::collections::HashSet;
use std::sync::Arc;

use asc_arkisa::DecodeError;

use super::{Condition, Function, Hit, Record, RecordHit, Worker, pc_of};
use crate::callgraph::{EdgeKind, FnRef, RecordId, Session, Slot};

/// A prepared search of one ABC entry for the calls into `functions`.
pub(crate) struct CallsTo<'q, 'a> {
    session: &'q Session<'a>,
    functions: &'q HashSet<FnRef>,
    /// Index of the entry in the program.
    entry: u32,
}

impl<'q, 'a> CallsTo<'q, 'a> {
    pub(crate) fn new(session: &'q Session<'a>, functions: &'q HashSet<FnRef>, entry: u32) -> CallsTo<'q, 'a> {
        CallsTo { session, functions, entry }
    }
}

impl<'a> Condition<'a> for CallsTo<'_, 'a> {
    fn worker<'s>(&'s self) -> Box<dyn Worker<'a> + 's> {
        Box::new(CallsToWorker { calls: self, record: 0, slot: None, found: Vec::new() })
    }

    fn is_impossible(&self) -> bool {
        self.functions.is_empty()
    }

    fn is_costly(&self) -> bool {
        true
    }
}

struct CallsToWorker<'s, 'q, 'a> {
    calls: &'s CallsTo<'q, 'a>,
    /// Class offset of the record being scanned.
    record: u32,
    /// Its slot in the cache, asked for by the first function scanned.
    slot: Option<Arc<Slot>>,
    /// Reused for the matching edges of a function.
    found: Vec<(u32, EdgeKind, FnRef)>,
}

impl<'a> Worker<'a> for CallsToWorker<'_, '_, 'a> {
    fn record(&mut self, record: &Record<'_, 'a>, _: &mut Vec<RecordHit>) -> bool {
        self.record = record.class.offset();
        self.slot = None;
        true
    }

    fn function(&mut self, function: &Function<'_, 'a>, hits: &mut Vec<Hit>) -> std::result::Result<(), DecodeError> {
        let calls = self.calls;
        let id = RecordId { entry: calls.entry, class: self.record };
        let slot = self.slot.get_or_insert_with(|| calls.session.slot(id));
        self.found.clear();
        calls.session.calls_into(slot, id, function.method.offset(), calls.functions, &mut self.found);
        if self.found.is_empty() {
            return Ok(());
        }
        // In code order, as the edges are.
        let mut found = self.found.iter().peekable();
        for insn in asc_arkisa::walk(function.code.instructions()) {
            let insn = insn?;
            let pc = pc_of(&insn);
            while let Some(&(_, kind, callee)) = found.next_if(|&&(at, _, _)| at <= pc) {
                let (location, restored) = calls.session.location(callee);
                // No ` | ` inside the column: `RECORD->FUNCTION (restored name)`.
                let mut text = format!("{} ; -> {location} ({restored})", function.text(&insn));
                if let Some(label) = kind.label() {
                    text.push_str(&format!(" [{label}]"));
                }
                hits.push(Hit { pc, matched: vec![location], text });
            }
            if found.peek().is_none() {
                break;
            }
        }
        Ok(())
    }
}
