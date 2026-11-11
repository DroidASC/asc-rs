//! The hot-patch stub a build can put at the head of its functions.
//!
//! A program that is patched in the field has every function it may want to
//! replace open by asking a patch runtime whether it was replaced:
//!
//! ```text
//! const answer = PATCHER.ask(NUMBER, this, ...parameters);
//! if (answer.replaced) return answer.value;
//! ```
//!
//! That `return` hands back whatever a patch says, which no static reading
//! knows; left as it is, it would leave every such function without a known
//! result ([`super::made`]). It says nothing of what the function as shipped
//! returns, so [`super::made`] leaves it out, and only it: a function is
//! told to open with the stub by its shape, and by the other functions of
//! its record.
//!
//! **The shape** ([`entry_stub`]), from the first instruction of the
//! function:
//!
//! - nothing before it but what the compiler puts at the head of a function
//!   for the function itself: `nop`, `asyncfunctionenter`, a new lexical
//!   environment and the copies of `this` and the parameters into it;
//! - one call, of a method of a regular import of the record, with that
//!   import as `this`. Its arguments are one integer constant and `this`
//!   (`undefined` where the function has none, a captured variable in an
//!   arrow function, which has the `this` of the function around it), then
//!   every declared parameter, in order and as it came in. Up to the call
//!   nothing else happens: registers are loaded and copied, and that is
//!   all;
//! - one property of what the call returned decides a forward branch over
//!   the next three instructions: load the same value again, read another
//!   property of it, `return` (after `asyncfunctionresolve` in an async
//!   function). The branch lands right behind that `return`.
//!
//! One instruction more, or one in another place, and the function does not
//! open with a stub.
//!
//! **The record** ([`family`]): a function that looks things up in a cache
//! and returns early can have that shape. A stub is put there by a tool, on
//! every function alike, so the shape counts only when at least
//! [`FAMILY`] functions of the record open with it, with the same import and
//! the same three names, each with an integer of its own. A record with
//! fewer such functions has no stubs, even when the rest of its program is
//! full of them: other records are not looked at, so that asking about one
//! function reads the heads of the functions of one record and no more.
//!
//! No name of a runtime, a method or a property is known here.

use std::collections::{HashMap, HashSet};

use asc_abc::Code;
use asc_arkisa::{Instruction, OperandKind, Value};

use crate::ops::{ModuleOperand, base_name, immediate, registers};

/// Functions of one record that have to open with the same stub for it to
/// be one. Two functions that share an early return are code somebody
/// wrote twice; a third with a third number is rare enough.
pub(crate) const FAMILY: usize = 3;

/// Instructions of a function that are looked at: the stub of a function
/// with a dozen captured parameters ends well before.
const MAX_HEAD: usize = 96;
/// Registers of a range call that are looked at.
const MAX_PASSED: u32 = 64;

/// What tells the stubs of one patch runtime from anything else: the import
/// asked, and the names of the method called and of the two properties read
/// (file offsets of strings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct StubKey {
    import: u32,
    method: u32,
    replaced: u32,
    value: u32,
}

/// The stub a function opens with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EntryStub {
    pub key: StubKey,
    /// The integer the function passes: its own.
    pub number: i32,
    /// Offset of the `return` of the stub.
    pub return_pc: usize,
}

/// What a register, or the accumulator, holds inside the stub.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    Unknown,
    /// The import that is asked.
    Patcher,
    /// Its method.
    Method,
    Undefined,
    Number(i32),
    /// What the function was entered with in argument register `n`: 2 is
    /// `this`, 3 the first declared parameter.
    Entry(u32),
    /// A variable of a lexical environment the function did not fill
    /// itself: `this` of the function around an arrow function is one.
    Outer,
    /// What the call returned.
    Answer,
    /// The function object of an async function.
    Async,
}

/// The registers of the function while the stub is read.
struct Registers {
    /// Locals of the function; the argument registers follow them.
    locals: u32,
    written: Vec<(u16, Held)>,
    /// Slots of the function's lexical environment that hold what it was
    /// entered with.
    captured: Vec<(u32, u32)>,
}

impl Registers {
    fn get(&self, reg: u16) -> Held {
        match u32::from(reg).checked_sub(self.locals) {
            Some(argument) => Held::Entry(argument),
            None => self.written.iter().rev().find(|(written, _)| *written == reg).map_or(Held::Unknown, |&(_, held)| held),
        }
    }

    /// `None` for an argument register: a stub writes none.
    fn set(&mut self, reg: u16, held: Held) -> Option<()> {
        if u32::from(reg) >= self.locals {
            return None;
        }
        self.written.push((reg, held));
        Some(())
    }
}

fn reg_in(insn: &Instruction<'_>) -> Option<u16> {
    registers(insn, OperandKind::RegIn).next()
}

fn reg_out(insn: &Instruction<'_>) -> Option<u16> {
    registers(insn, OperandKind::RegOut).next()
}

/// The stub the function with code `code` opens with, by its shape alone
/// (see the module documentation); `entity` resolves a 16-bit id of the
/// function to a file offset.
pub(crate) fn entry_stub(code: &Code<'_>, entity: impl Fn(u32) -> Option<u32>) -> Option<EntryStub> {
    let mut insns = asc_arkisa::walk(code.instructions()).take(MAX_HEAD).map_while(|insn| insn.ok()).peekable();
    let mut regs = Registers { locals: code.num_vregs, written: Vec::new(), captured: Vec::new() };
    let name_of = |insn: &Instruction<'_>| insn.string_id().and_then(&entity);

    // What the compiler opens the function with.
    let (mut is_async, mut has_environment) = (false, false);
    loop {
        let insn = *insns.peek()?;
        match base_name(insn.opcode) {
            "nop" => {
                insns.next();
            }
            "asyncfunctionenter" if !is_async && !has_environment => {
                insns.next();
                let store = insns.next().filter(|insn| base_name(insn.opcode) == "sta")?;
                regs.set(reg_out(&store)?, Held::Async)?;
                is_async = true;
            }
            "newlexenv" | "newlexenvwithname" if !has_environment => {
                insns.next();
                has_environment = true;
                while let Some(load) = insns.next_if(|insn| base_name(insn.opcode) == "lda") {
                    let Held::Entry(argument) = regs.get(reg_in(&load)?) else { return None };
                    let store = insns.next().filter(|insn| base_name(insn.opcode) == "stlexvar")?;
                    let (level, slot) = immediate(&store, 0).zip(immediate(&store, 1))?;
                    if level != 0 {
                        return None;
                    }
                    regs.captured.push((slot, argument));
                }
            }
            _ => break,
        }
    }

    // Up to the call: the import, its method, and registers loaded and copied.
    let (mut acc, mut import, mut method) = (Held::Unknown, None, None);
    let call = loop {
        let insn = insns.next()?;
        let opcode = insn.opcode;
        match base_name(opcode) {
            "sta" => regs.set(reg_out(&insn)?, acc)?,
            "lda" => acc = regs.get(reg_in(&insn)?),
            "mov" => regs.set(reg_out(&insn)?, regs.get(reg_in(&insn)?))?,
            "ldundefined" => acc = Held::Undefined,
            "ldai" => match insn.operand(0) {
                Some(Value::Imm(number)) => acc = Held::Number(i32::try_from(number).ok()?),
                _ => return None,
            },
            "ldlexvar" => {
                let (level, slot) = immediate(&insn, 0).zip(immediate(&insn, 1))?;
                let own = regs.captured.iter().find(|&&(captured, _)| level == 0 && captured == slot);
                acc = own.map_or(Held::Outer, |&(_, argument)| Held::Entry(argument));
            }
            // The check the compiler puts after the load of an import: it reads the accumulator only.
            "throw.undefinedifholewithname" => {}
            "ldobjbyname" if acc == Held::Patcher && method.is_none() => {
                method = Some(name_of(&insn)?);
                acc = Held::Method;
            }
            "callthis0" | "callthis1" | "callthis2" | "callthis3" | "callthisrange" if acc == Held::Method => break insn,
            _ if import.is_none() && opcode.writes_acc() && ModuleOperand::of(opcode) == Some(ModuleOperand::RegularImport) => {
                import = Some(immediate(&insn, 0)?);
                acc = Held::Patcher;
            }
            _ => return None,
        }
    };

    // `PATCHER.method(NUMBER, this, ...parameters)`, the first two in either order.
    let passed: Vec<Held> = match call.reg_range() {
        Some(range) => {
            let first = u32::from(range.first);
            let end = first.checked_add(range.count).filter(|&end| end - first <= MAX_PASSED)?;
            (first..end).map(|reg| u16::try_from(reg).map_or(Held::Unknown, |reg| regs.get(reg))).collect()
        }
        None => registers(&call, OperandKind::RegIn).map(|reg| regs.get(reg)).collect(),
    };
    let [Held::Patcher, first, second, parameters @ ..] = &passed[..] else { return None };
    let receiver = |held: &Held| matches!(held, Held::Undefined | Held::Entry(2) | Held::Outer);
    let number = match (first, second) {
        (Held::Number(number), other) | (other, Held::Number(number)) if receiver(other) => *number,
        _ => return None,
    };
    let declared = code.num_args.checked_sub(3)?;
    if parameters.len() != declared as usize || !parameters.iter().zip(3..).all(|(held, argument)| *held == Held::Entry(argument)) {
        return None;
    }

    // `if (answer.replaced) return answer.value`.
    let answer = reg_out(&insns.next().filter(|insn| base_name(insn.opcode) == "sta")?)?;
    regs.set(answer, Held::Answer)?;
    let replaced = name_of(&insns.next().filter(|insn| base_name(insn.opcode) == "ldobjbyname")?)?;
    let test = insns.next()?;
    let branch = match base_name(test.opcode) {
        "jeqz" => test,
        "isfalse" => insns.next().filter(|insn| base_name(insn.opcode) == "jnez")?,
        "istrue" => insns.next().filter(|insn| base_name(insn.opcode) == "jeqz")?,
        _ => return None,
    };
    let load = insns.next().filter(|insn| base_name(insn.opcode) == "lda")?;
    if regs.get(reg_in(&load)?) != Held::Answer {
        return None;
    }
    let value = name_of(&insns.next().filter(|insn| base_name(insn.opcode) == "ldobjbyname")?)?;
    let mut last = insns.next()?;
    if is_async {
        if base_name(last.opcode) != "asyncfunctionresolve" || regs.get(reg_in(&last)?) != Held::Async {
            return None;
        }
        last = insns.next()?;
    }
    if base_name(last.opcode) != "return" || branch.jump_target() != Some(last.next_pc()) {
        return None;
    }
    Some(EntryStub { key: StubKey { import: import?, method: method?, replaced, value }, number, return_pc: last.pc })
}

/// The stubs of one record, given what each of its functions opens with:
/// the key at least [`FAMILY`] of them share, each with a number of its
/// own. `None` when there is none; of two, the one with more functions.
pub(crate) fn family(stubs: impl IntoIterator<Item = EntryStub>) -> Option<StubKey> {
    let mut numbers: HashMap<StubKey, HashSet<i32>> = HashMap::new();
    for stub in stubs {
        numbers.entry(stub.key).or_default().insert(stub.number);
    }
    let (key, _) = numbers
        .into_iter()
        .map(|(key, numbers)| (key, numbers.len()))
        .filter(|&(_, functions)| functions >= FAMILY)
        .max_by_key(|&(key, functions)| (functions, std::cmp::Reverse(key)))?;
    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stub(method: u32, number: i32) -> EntryStub {
        EntryStub { key: StubKey { import: 0, method, replaced: 20, value: 24 }, number, return_pc: 40 }
    }

    #[test]
    fn a_record_has_stubs_when_three_functions_open_alike() {
        assert_eq!(family([stub(8, 1), stub(8, 2), stub(8, 3)]), Some(stub(8, 0).key));
        // Two functions, a number used twice, three functions that ask three methods.
        assert_eq!(family([stub(8, 1), stub(8, 2)]), None);
        assert_eq!(family([stub(8, 1), stub(8, 2), stub(8, 2)]), None);
        assert_eq!(family([stub(8, 1), stub(9, 2), stub(10, 3)]), None);
        assert_eq!(family([]), None);
        // The larger of two; the first of two alike.
        let mixed = [stub(9, 1), stub(9, 2), stub(9, 3), stub(8, 4), stub(8, 5), stub(8, 6), stub(8, 7)];
        assert_eq!(family(mixed), Some(stub(8, 0).key));
        assert_eq!(family(mixed.into_iter().take(6)), Some(stub(8, 0).key));
    }
}
