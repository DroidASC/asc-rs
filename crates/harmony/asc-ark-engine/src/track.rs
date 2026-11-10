//! Method-local source tracking: where the value in the accumulator and in
//! each register came from.
//!
//! ArkTS calls carry no callee id: the callee is whatever value is in the
//! accumulator (`ldobjbyname "foo"` … `callthis1`). [`Tracker::run`] walks one
//! function forward and keeps one [`Source`] per register and for the
//! accumulator, so that a call site can be described as
//! `import:@ohos:net.http#default.createHttp`.
//!
//! The precision contract (`docs/ark-abc-design.md` §7):
//!
//! - Tracking is per basic block. At a catch handler, at a jump target some
//!   backward jump reaches (a loop head) and at code nothing flows into,
//!   all sources are forgotten ([`Source::Unknown`]).
//! - Two exceptions, both sound. A register written only in the prologue
//!   (the straight-line code before the first branch, jump target, handler
//!   or try range) holds the same value wherever it is read later, so it
//!   keeps its source across blocks: compilers copy `this`, the arguments
//!   and imports into such registers. And a jump target that only forward
//!   jumps (and the instruction before it) reach starts with what all of
//!   them agree on: a register, or the accumulator, keeps its value when
//!   every way in arrives with the very same tracked value, and is unknown
//!   otherwise. Nothing is guessed at a merge: two different values, even
//!   of the same kind, are unknown.
//! - A source the walk cannot name is labelled, never guessed: a captured
//!   variable is [`Source::Lexical`], a parameter [`Source::Argument`], the
//!   result of a call [`Source::CallResult`] (of that callee, itself a
//!   tracked value), anything else computed in the block
//!   [`Source::Computed`].
//!
//! Values live in an arena per function: a register holds a [`ValueId`], a
//! property load makes a new value that points at its base. Each value
//! remembers the instruction that made it, so "is this load the callee of a
//! call" is a lookup.
//!
//! The tracker knows instructions only: ids stay raw ([`StringRef`], method
//! and module indexes) and are resolved by whoever prints a value.

use asc_abc::Code;
use asc_arkisa::{DecodeError, Instruction, Opcode, OperandKind, Prefix};

use crate::ops::{base_name, immediate, registers, ModuleOperand, OpTable};

/// Registers tracked per function. The register count comes from the file;
/// a hostile one must not size an allocation.
const MAX_REGISTERS: usize = 1 << 16;
/// Registers of a range call that are looked at.
const MAX_RANGE: u32 = 256;

/// A string an instruction names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StringRef {
    /// Index into the entity table of the method's region.
    Id(u32),
    /// File offset: the 32-bit ids of `deprecated.*` opcodes.
    Offset(u32),
}

impl StringRef {
    fn of(insn: &Instruction<'_>) -> Option<StringRef> {
        let wide = insn.opcode.operand_of(OperandKind::StringId)?.width > 16;
        insn.string_id().map(|id| if wide { StringRef::Offset(id) } else { StringRef::Id(id) })
    }
}

/// A value of the arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ValueId(u32);

impl ValueId {
    /// The value nothing is known about.
    pub(crate) const UNKNOWN: ValueId = ValueId(0);
}

/// Where a value came from.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum Source {
    /// Not set in this block: it comes from another block.
    Unknown,
    /// Computed in this block by something the tracker does not model
    /// (an operator, an object literal, an iterator …).
    Computed,
    /// What the call at the value's instruction returned: `callee(...)`, or
    /// `new callee(...)`.
    CallResult {
        callee: ValueId,
        construct: bool,
    },
    This,
    /// The parent class: the callee of `supercall*`, the base of `ldsuperby*`.
    Super,
    /// The running function itself (`ldfunction`, argument register 0).
    Function,
    NewTarget,
    /// The global object (`ldglobal`).
    GlobalObject,
    /// The `n`-th declared parameter, from 0.
    Argument(u32),
    /// A captured variable (`ldlexvar level, slot`).
    Lexical {
        level: u32,
        slot: u32,
        sendable: bool,
    },
    /// Regular import `n` of the record's module record.
    Import(u32),
    /// The namespace of module request `n`.
    Namespace(u32),
    /// Local export `n` of the record's module record: a module-level binding.
    ModuleLocal(u32),
    /// A global binding read by name.
    Global(StringRef),
    /// A function or class defined here: the method id of `definefunc`,
    /// `definemethod`, `defineclasswithbuffer`.
    Definition(u32),
    Str(StringRef),
    Int(i32),
    Float(f64),
    /// `true`, `null`, `undefined` …: the text is the literal.
    Constant(&'static str),
    /// `base.name`.
    Property {
        base: ValueId,
        name: StringRef,
    },
    /// `base[index]`; `None` for a key that is not a constant.
    Element {
        base: ValueId,
        index: Option<u32>,
    },
}

/// A tracked value: its source and the instruction that produced it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Value {
    pub source: Source,
    /// Offset of the producing instruction; 0 for values of the entry frame.
    pub pc: u32,
}

/// What an instruction does to the tracked state.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
enum Effect {
    /// Nothing the tracker models: results become [`Source::Computed`].
    #[default]
    Generic,
    Lda,
    Sta,
    Mov,
    /// The accumulator becomes a value with this fixed source.
    Load(Source),
    Import,
    Namespace,
    ModuleLocal,
    Global,
    Lexical {
        sendable: bool,
    },
    /// `ldobjbyname`: a property of the accumulator.
    PropertyOfAcc,
    /// `ldthisbyname` / `ldsuperbyname`.
    PropertyOf(Source),
    /// `deprecated.ldobjbyname`: a property of the register.
    PropertyOfReg,
    /// `ldobjbyvalue`: the object is the register, the key the accumulator.
    ElementOfReg,
    /// `ldthisbyvalue` / `ldsuperbyvalue`: the key is the accumulator.
    ElementOf(Source),
    /// `ldobjbyindex`: element `imm` of the accumulator.
    IndexOfAcc,
    Definition,
    Str,
    Int,
    Float,
    Call,
}

impl Effect {
    fn of(opcode: &Opcode) -> Effect {
        match base_name(opcode) {
            "lda" => Effect::Lda,
            "sta" => Effect::Sta,
            "mov" => Effect::Mov,
            "ldthis" => Effect::Load(Source::This),
            "ldfunction" => Effect::Load(Source::Function),
            "ldnewtarget" => Effect::Load(Source::NewTarget),
            "ldglobal" => Effect::Load(Source::GlobalObject),
            "ldtrue" => Effect::Load(Source::Constant("true")),
            "ldfalse" => Effect::Load(Source::Constant("false")),
            "ldnull" => Effect::Load(Source::Constant("null")),
            "ldundefined" => Effect::Load(Source::Constant("undefined")),
            "ldnan" => Effect::Load(Source::Constant("NaN")),
            "ldinfinity" => Effect::Load(Source::Constant("Infinity")),
            "ldhole" => Effect::Load(Source::Constant("hole")),
            "tryldglobalbyname" | "ldglobalvar" => Effect::Global,
            "ldlexvar" => Effect::Lexical { sendable: false },
            "ldsendablevar" => Effect::Lexical { sendable: true },
            "ldobjbyname" => Effect::PropertyOfAcc,
            "ldthisbyname" => Effect::PropertyOf(Source::This),
            "ldsuperbyname" => Effect::PropertyOf(Source::Super),
            "deprecated.ldobjbyname" => Effect::PropertyOfReg,
            "ldobjbyvalue" | "deprecated.ldobjbyvalue" => Effect::ElementOfReg,
            "ldthisbyvalue" => Effect::ElementOf(Source::This),
            "ldsuperbyvalue" => Effect::ElementOf(Source::Super),
            "ldobjbyindex" => Effect::IndexOfAcc,
            "definefunc" | "definemethod" | "defineclasswithbuffer" | "definesendableclass" | "deprecated.defineclasswithbuffer" => {
                Effect::Definition
            }
            "lda.str" => Effect::Str,
            "ldai" => Effect::Int,
            "fldai" => Effect::Float,
            _ => match ModuleOperand::of(opcode) {
                Some(ModuleOperand::RegularImport) => Effect::Import,
                Some(ModuleOperand::Request) => Effect::Namespace,
                Some(ModuleOperand::LocalExport) if opcode.writes_acc() => Effect::ModuleLocal,
                Some(ModuleOperand::LocalExport) | None if opcode.is_call() => Effect::Call,
                Some(ModuleOperand::LocalExport) | None => Effect::Generic,
            },
        }
    }
}

/// Where a call instruction takes its callee from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CalleeAt {
    Acc,
    /// The first register operand (`newobjapply`, the `deprecated.call*` forms).
    FirstRegister,
    /// The first register of the range (`newobjrange`).
    RangeStart,
    /// The parent constructor (`supercall*`).
    Super,
    /// The property the instruction names, of its `this` register
    /// (`callthisNwithname`).
    Named,
}

/// The operand layout of a call opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CallShape {
    callee: CalleeAt,
    /// Whether a `this` value precedes the arguments.
    has_this: bool,
    /// Whether the last register (or the accumulator) is an array of the
    /// arguments, not an argument.
    spread: bool,
    construct: bool,
}

impl CallShape {
    const fn new(callee: CalleeAt) -> CallShape {
        CallShape { callee, has_this: false, spread: false, construct: false }
    }

    fn of(opcode: &Opcode) -> Option<CallShape> {
        if !opcode.is_call() {
            return None;
        }
        let with_this = |callee| CallShape { has_this: true, ..CallShape::new(callee) };
        let name = base_name(opcode);
        Some(match name {
            "callarg0" | "callarg1" | "callargs2" | "callargs3" | "callrange" => CallShape::new(CalleeAt::Acc),
            "callthis0" | "callthis1" | "callthis2" | "callthis3" | "callthisrange" | "callinit" => with_this(CalleeAt::Acc),
            "callthis0withname" | "callthis1withname" | "callthis2withname" | "callthis3withname" | "callthisrangewithname" => {
                with_this(CalleeAt::Named)
            }
            "apply" => CallShape { spread: true, ..with_this(CalleeAt::Acc) },
            "newobjrange" => CallShape { construct: true, ..CallShape::new(CalleeAt::RangeStart) },
            "newobjapply" => CallShape { construct: true, spread: true, ..CallShape::new(CalleeAt::FirstRegister) },
            "supercallthisrange" | "supercallarrowrange" => CallShape::new(CalleeAt::Super),
            "supercallspread" | "supercallforwardallargs" => CallShape { spread: true, ..CallShape::new(CalleeAt::Super) },
            "deprecated.callspread" => CallShape { spread: true, ..with_this(CalleeAt::FirstRegister) },
            "deprecated.callthisrange" => with_this(CalleeAt::RangeStart),
            "deprecated.callrange" => CallShape::new(CalleeAt::RangeStart),
            _ if opcode.prefix == Some(Prefix::Deprecated) => CallShape::new(CalleeAt::FirstRegister),
            // A call opcode this table does not know: its callee is not guessed.
            _ => return None,
        })
    }
}

/// Where a store instruction puts its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreTarget {
    /// A variable of a lexical environment (`stlexvar level, slot`).
    Lexical { level: u32, slot: u32, sendable: bool },
    /// Local export `n` of the record's module record (`stmodulevar n`).
    Module(u32),
}

/// The stores the tracker reports, per opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StoreKind {
    Lexical { sendable: bool },
    Module,
}

impl StoreKind {
    fn of(opcode: &Opcode) -> Option<StoreKind> {
        match base_name(opcode) {
            "stlexvar" | "deprecated.stlexvar" => Some(StoreKind::Lexical { sendable: false }),
            "stsendablevar" => Some(StoreKind::Lexical { sendable: true }),
            "stmodulevar" => Some(StoreKind::Module),
            _ => None,
        }
    }
}

/// What a walk reports to its visitor.
#[derive(Debug)]
pub(crate) enum Event<'t> {
    Call(CallSite<'t>),
    /// A store into a captured variable or a module-level binding, with the
    /// tracked value it stores.
    Store {
        target: StoreTarget,
        value: ValueId,
    },
    /// A class definition (`defineclasswithbuffer`, `definesendableclass`),
    /// with the tracked value of its parent class register.
    Class {
        parent: ValueId,
    },
}

/// Which instructions a walk reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Watch {
    Calls,
    Stores,
    /// Class definitions.
    Classes,
}

impl Watch {
    fn calls(self) -> bool {
        self == Watch::Calls
    }

    fn stores(self) -> bool {
        self == Watch::Stores
    }

    fn classes(self) -> bool {
        self == Watch::Classes
    }
}

/// A call instruction with the tracked values of its operands.
#[derive(Debug)]
pub(crate) struct CallSite<'t> {
    pub callee: ValueId,
    /// The arguments passed one by one, in order.
    pub args: &'t [ValueId],
    /// Whether further arguments come from an array the tracker does not
    /// look into (`apply`, `newobjapply`, `supercallspread`).
    pub spread: bool,
    /// `new callee(...)`.
    pub construct: bool,
}

/// The tracked state at one instruction.
#[derive(Debug, Default)]
pub(crate) struct Frame {
    values: Vec<Value>,
    acc: ValueId,
    regs: Vec<ValueId>,
}

impl Default for ValueId {
    fn default() -> ValueId {
        ValueId::UNKNOWN
    }
}

impl Frame {
    pub(crate) fn value(&self, id: ValueId) -> Value {
        self.values.get(id.0 as usize).copied().unwrap_or(Value { source: Source::Unknown, pc: 0 })
    }

    pub(crate) fn reg(&self, reg: u16) -> ValueId {
        self.regs.get(usize::from(reg)).copied().unwrap_or(ValueId::UNKNOWN)
    }

    fn make(&mut self, source: Source, pc: u32) -> ValueId {
        let id = ValueId(u32::try_from(self.values.len()).unwrap_or(0));
        self.values.push(Value { source, pc });
        id
    }

    fn set_reg(&mut self, reg: u16, value: ValueId) {
        if let Some(slot) = self.regs.get_mut(usize::from(reg)) {
            *slot = value;
        }
    }

    /// The frame on entry: `this`, the function and the parameters in the
    /// argument registers, which follow the `num_vregs` locals.
    fn reset(&mut self, code: &Code<'_>) {
        self.values.clear();
        self.values.push(Value { source: Source::Unknown, pc: 0 });
        self.acc = ValueId::UNKNOWN;
        let (vregs, args) = (code.num_vregs as usize, code.num_args as usize);
        self.regs.clear();
        self.regs.resize(vregs.min(MAX_REGISTERS), ValueId::UNKNOWN);
        for arg in 0..args.min(MAX_REGISTERS - self.regs.len()) {
            let source = match arg {
                0 => Source::Function,
                1 => Source::NewTarget,
                2 => Source::This,
                // Bounded by `MAX_REGISTERS`.
                n => Source::Argument(u32::try_from(n - 3).unwrap_or(u32::MAX)),
            };
            let id = self.make(source, 0);
            self.regs.push(id);
        }
    }

    /// Apply `insn`.
    fn step(&mut self, effect: Effect, insn: &Instruction<'_>) {
        let pc = pc_of(insn);
        let reg_in = |frame: &Frame| registers(insn, OperandKind::RegIn).next().map_or(ValueId::UNKNOWN, |reg| frame.reg(reg));
        let source = match effect {
            Effect::Lda => {
                self.acc = reg_in(self);
                return;
            }
            Effect::Sta => {
                let acc = self.acc;
                registers(insn, OperandKind::RegOut).for_each(|reg| self.set_reg(reg, acc));
                return;
            }
            Effect::Mov => {
                let source = reg_in(self);
                registers(insn, OperandKind::RegOut).for_each(|reg| self.set_reg(reg, source));
                return;
            }
            Effect::Load(source) => Some(source),
            Effect::Import => immediate(insn, 0).map(Source::Import),
            Effect::Namespace => immediate(insn, 0).map(Source::Namespace),
            Effect::ModuleLocal => immediate(insn, 0).map(Source::ModuleLocal),
            Effect::Global => StringRef::of(insn).map(Source::Global),
            Effect::Lexical { sendable } => {
                immediate(insn, 0).zip(immediate(insn, 1)).map(|(level, slot)| Source::Lexical { level, slot, sendable })
            }
            Effect::PropertyOfAcc => StringRef::of(insn).map(|name| Source::Property { base: self.acc, name }),
            Effect::PropertyOf(base) => {
                let base = self.make(base, pc);
                StringRef::of(insn).map(|name| Source::Property { base, name })
            }
            Effect::PropertyOfReg => StringRef::of(insn).map(|name| Source::Property { base: reg_in(self), name }),
            Effect::ElementOfReg => Some(self.element(reg_in(self))),
            Effect::ElementOf(base) => {
                let base = self.make(base, pc);
                Some(self.element(base))
            }
            Effect::IndexOfAcc => Some(Source::Element { base: self.acc, index: immediate(insn, 0) }),
            Effect::Definition => insn.method_id().map(Source::Definition),
            Effect::Str => StringRef::of(insn).map(Source::Str),
            Effect::Int => match insn.operand(0) {
                Some(asc_arkisa::Value::Imm(value)) => i32::try_from(value).ok().map(Source::Int),
                _ => None,
            },
            Effect::Float => match insn.operand(0) {
                Some(asc_arkisa::Value::Float(value)) => Some(Source::Float(value)),
                _ => None,
            },
            // `Tracker::run` gives the result of a call its callee; without one it is only computed.
            Effect::Call => None,
            Effect::Generic => None,
        };
        // The few instructions with an output register write a computed value there.
        if insn.opcode.operand_of(OperandKind::RegOut).is_some() {
            let computed = self.make(Source::Computed, pc);
            registers(insn, OperandKind::RegOut).for_each(|reg| self.set_reg(reg, computed));
        }
        if insn.opcode.writes_acc() {
            self.acc = self.make(source.unwrap_or(Source::Computed), pc);
        }
    }

    /// The store `insn` (of `kind`) makes: the value is the accumulator, or
    /// the register of the `deprecated.` form.
    fn store(&self, kind: StoreKind, insn: &Instruction<'_>) -> Option<Event<'static>> {
        let value = registers(insn, OperandKind::RegIn).next().map_or(self.acc, |reg| self.reg(reg));
        let target = match kind {
            StoreKind::Lexical { sendable } => {
                let (level, slot) = immediate(insn, 0).zip(immediate(insn, 1))?;
                StoreTarget::Lexical { level, slot, sendable }
            }
            StoreKind::Module => StoreTarget::Module(immediate(insn, 0)?),
        };
        Some(Event::Store { target, value })
    }

    /// `base[key]` with the key in the accumulator: a property when the key
    /// is a string constant, an indexed element when it is a small integer.
    fn element(&self, base: ValueId) -> Source {
        match self.value(self.acc).source {
            Source::Str(name) => Source::Property { base, name },
            Source::Int(index) => Source::Element { base, index: u32::try_from(index).ok() },
            _ => Source::Element { base, index: None },
        }
    }
}

/// Code sizes are 32-bit (`uleb` in the code header).
fn pc_of(insn: &Instruction<'_>) -> u32 {
    u32::try_from(insn.pc).unwrap_or(u32::MAX)
}

/// A set of code offsets.
#[derive(Debug, Default)]
struct PcSet(Vec<u64>);

impl PcSet {
    fn reset(&mut self, code_len: usize) {
        self.0.clear();
        self.0.resize(code_len / 64 + 1, 0);
    }

    fn insert(&mut self, pc: usize) {
        if let Some(word) = self.0.get_mut(pc / 64) {
            *word |= 1 << (pc % 64);
        }
    }

    fn contains(&self, pc: usize) -> bool {
        self.0.get(pc / 64).is_some_and(|word| word >> (pc % 64) & 1 != 0)
    }
}

/// Whether `opcode` defines a class from a constructor, a literal array and
/// a parent class register.
fn defines_class(opcode: &Opcode) -> bool {
    matches!(base_name(opcode), "defineclasswithbuffer" | "definesendableclass" | "deprecated.defineclasswithbuffer")
}

/// The per-opcode tables of the tracker, built once per search.
pub(crate) struct Effects {
    effects: OpTable<Effect>,
    calls: OpTable<Option<CallShape>>,
    stores: OpTable<Option<StoreKind>>,
    /// Whether the opcode defines a class: its last register is the parent.
    classes: OpTable<bool>,
}

impl Effects {
    pub(crate) fn new() -> Effects {
        Effects {
            effects: OpTable::build(Effect::of),
            calls: OpTable::build(CallShape::of),
            stores: OpTable::build(StoreKind::of),
            classes: OpTable::build(defines_class),
        }
    }
}

/// Walks functions; its buffers are reused from one function to the next.
#[derive(Debug, Default)]
pub(crate) struct Tracker {
    frame: Frame,
    leaders: PcSet,
    /// Leaders no state flows into: handlers and the targets of backward jumps.
    opaque: PcSet,
    /// What the forward jumps met so far leave for their targets.
    pending: Vec<Pending>,
    /// Register buffers of consumed [`Pending`] states, for reuse.
    spare: Vec<Vec<ValueId>>,
    /// `(pc, register)` of every register write of the function.
    writes: Vec<(usize, u16)>,
    /// What the prologue leaves in each register that nothing writes later;
    /// [`ValueId::UNKNOWN`] for the others.
    stable: Vec<ValueId>,
    args: Vec<ValueId>,
}

impl Tracker {
    /// Walk `code`. `visit` sees every call instruction with the frame as
    /// it is before the call and the tracked values of its operands.
    ///
    /// # Errors
    /// Code that does not decode to its end: nothing is visited then, since
    /// the block structure of the function is not known.
    pub(crate) fn run<'a>(
        &mut self,
        effects: &Effects,
        code: &Code<'a>,
        mut visit: impl FnMut(&Frame, &Instruction<'a>, &CallSite<'_>),
    ) -> Result<(), DecodeError> {
        self.run_events(effects, code, Watch::Calls, |frame, insn, event| {
            if let Event::Call(site) = event {
                visit(frame, insn, &site);
            }
        })
    }

    /// Walk `code`. `visit` sees every instruction `watch` asks for, with
    /// the frame as it is before the instruction.
    ///
    /// # Errors
    /// As [`Tracker::run`].
    pub(crate) fn run_events<'a>(
        &mut self,
        effects: &Effects,
        code: &Code<'a>,
        watch: Watch,
        mut visit: impl FnMut(&Frame, &Instruction<'a>, Event<'_>),
    ) -> Result<(), DecodeError> {
        let bytes = code.instructions();
        let blocks = self.find_blocks(effects, code)?;
        // A function with nothing to report has nothing to show.
        if !(watch.calls() && blocks.has_call || watch.stores() && blocks.has_store || watch.classes() && blocks.has_class) {
            return Ok(());
        }
        let prologue_end = blocks.prologue_end;
        self.frame.reset(code);
        self.spare.extend(self.pending.drain(..).map(|pending| pending.regs));
        let mut in_prologue = true;
        // Whether the instruction before can continue into the current one.
        let mut falls_through = true;
        for insn in asc_arkisa::walk(bytes) {
            let insn = insn?;
            let flows_in = std::mem::replace(&mut falls_through, !insn.opcode.is_terminator());
            if in_prologue && insn.pc >= prologue_end {
                in_prologue = false;
                self.stable.clear();
                self.stable.extend_from_slice(&self.frame.regs);
                for &(_, reg) in self.writes.iter().filter(|&&(pc, _)| pc >= prologue_end) {
                    if let Some(slot) = self.stable.get_mut(usize::from(reg)) {
                        *slot = ValueId::UNKNOWN;
                    }
                }
            }
            if self.leaders.contains(insn.pc) {
                self.enter_block(insn.pc, flows_in, in_prologue);
            }
            if let Some(shape) = effects.calls.of(insn.opcode) {
                let head = self.call_site(shape, &insn);
                if watch.calls() {
                    let args = self.args.get(head.skip..).unwrap_or_default();
                    let site = CallSite { callee: head.callee, args, spread: shape.spread, construct: shape.construct };
                    visit(&self.frame, &insn, Event::Call(site));
                }
                if insn.opcode.writes_acc() {
                    let result = Source::CallResult { callee: head.callee, construct: shape.construct };
                    self.frame.acc = self.frame.make(result, pc_of(&insn));
                }
                continue;
            }
            if watch.classes() && effects.classes.of(insn.opcode) {
                // The parent is the only register of the current forms, the second (after the
                // environment) of the `deprecated.` one.
                let parent = registers(&insn, OperandKind::RegIn).last().map_or(ValueId::UNKNOWN, |reg| self.frame.reg(reg));
                visit(&self.frame, &insn, Event::Class { parent });
            }
            if watch.stores() {
                if let Some(store) = effects.stores.of(insn.opcode).and_then(|kind| self.frame.store(kind, &insn)) {
                    visit(&self.frame, &insn, store);
                }
            }
            self.frame.step(effects.effects.of(insn.opcode), &insn);
            if let Some(target) = insn.jump_target().filter(|&target| target > insn.pc && !self.opaque.contains(target)) {
                self.flow_into(target);
            }
        }
        Ok(())
    }

    /// The frame, as a forward jump leaves it, flows into `target`.
    fn flow_into(&mut self, target: usize) {
        let frame = &self.frame;
        match self.pending.iter_mut().find(|pending| pending.target == target) {
            Some(pending) => pending.merge(frame.acc, &frame.regs),
            None => {
                let mut regs = self.spare.pop().unwrap_or_default();
                regs.clone_from(&frame.regs);
                self.pending.push(Pending { target, acc: frame.acc, regs });
            }
        }
    }

    /// Start the block at leader `pc`. `flows_in` says whether the
    /// instruction before it continues into it.
    fn enter_block(&mut self, pc: usize, flows_in: bool, in_prologue: bool) {
        let jumped = self.pending.iter().position(|pending| pending.target == pc).map(|index| self.pending.swap_remove(index));
        match jumped {
            Some(mut state) if !self.opaque.contains(pc) => {
                if flows_in {
                    state.merge(self.frame.acc, &self.frame.regs);
                }
                self.frame.acc = state.acc;
                std::mem::swap(&mut self.frame.regs, &mut state.regs);
                self.spare.push(state.regs);
            }
            jumped => {
                self.spare.extend(jumped.map(|state| state.regs));
                self.frame.acc = ValueId::UNKNOWN;
                // A leader is never inside the prologue: the prologue ends at the first one.
                if in_prologue {
                    self.frame.regs.fill(ValueId::UNKNOWN);
                } else {
                    self.frame.regs.clone_from(&self.stable);
                }
            }
        }
    }

    /// First pass: the block leaders and the register writes.
    fn find_blocks(&mut self, effects: &Effects, code: &Code<'_>) -> Result<Blocks, DecodeError> {
        let bytes = code.instructions();
        self.leaders.reset(bytes.len());
        self.opaque.reset(bytes.len());
        self.writes.clear();
        let mut prologue_end = usize::MAX;
        let (mut has_call, mut has_store, mut has_class) = (false, false, false);
        for block in code.try_blocks().map_while(|block| block.ok()) {
            prologue_end = prologue_end.min(block.start_pc as usize);
            for catch in block.catch_blocks() {
                self.leaders.insert(catch.handler_pc as usize);
                self.opaque.insert(catch.handler_pc as usize);
                prologue_end = prologue_end.min(catch.handler_pc as usize);
            }
        }
        for insn in asc_arkisa::walk(bytes) {
            let insn = insn?;
            let opcode = insn.opcode;
            has_call |= effects.calls.of(opcode).is_some();
            has_store |= effects.stores.of(opcode).is_some();
            has_class |= effects.classes.of(opcode);
            if let Some(target) = insn.jump_target() {
                self.leaders.insert(target);
                if target <= insn.pc {
                    self.opaque.insert(target);
                }
                prologue_end = prologue_end.min(target);
            }
            if opcode.is_terminator() {
                self.leaders.insert(insn.next_pc());
            }
            if opcode.is_jump() || opcode.is_terminator() {
                prologue_end = prologue_end.min(insn.pc);
            }
            if opcode.operand_of(OperandKind::RegOut).is_some() {
                self.writes.extend(registers(&insn, OperandKind::RegOut).map(|reg| (insn.pc, reg)));
            }
        }
        Ok(Blocks { prologue_end, has_call, has_store, has_class })
    }

    /// The operands of call `insn`. Every register operand goes to
    /// `self.args`; the arguments proper are `self.args[head.skip..]`.
    fn call_site(&mut self, shape: CallShape, insn: &Instruction<'_>) -> CallHead {
        let frame = &mut self.frame;
        self.args.clear();
        match insn.reg_range() {
            Some(range) => {
                let first = u32::from(range.first);
                // A hostile count must not size the list; registers past the frame read as unknown anyway.
                let end = first.saturating_add(range.count).min(first + MAX_RANGE);
                self.args.extend((first..end).map(|reg| u16::try_from(reg).map_or(ValueId::UNKNOWN, |reg| frame.reg(reg))));
            }
            None => self.args.extend(registers(insn, OperandKind::RegIn).map(|reg| frame.reg(reg))),
        }
        let mut skip = 0;
        let mut next = |args: &[ValueId]| {
            let value = args.get(skip).copied();
            skip += usize::from(value.is_some());
            value
        };
        let pc = pc_of(insn);
        let callee_register = matches!(shape.callee, CalleeAt::FirstRegister | CalleeAt::RangeStart).then(|| next(&self.args)).flatten();
        let this = if shape.has_this { next(&self.args) } else { None };
        let callee = match shape.callee {
            CalleeAt::Acc => frame.acc,
            CalleeAt::FirstRegister | CalleeAt::RangeStart => callee_register.unwrap_or(ValueId::UNKNOWN),
            CalleeAt::Super => frame.make(Source::Super, pc),
            CalleeAt::Named => match StringRef::of(insn) {
                Some(name) => frame.make(Source::Property { base: this.unwrap_or(ValueId::UNKNOWN), name }, pc),
                None => ValueId::UNKNOWN,
            },
        };
        // The array of a spread call is its last register, when it has one left.
        if shape.spread && self.args.len() > skip {
            self.args.pop();
        }
        CallHead { callee, skip }
    }
}

/// The state forward jumps carry to one target: what all of them agree on.
#[derive(Debug)]
struct Pending {
    target: usize,
    acc: ValueId,
    regs: Vec<ValueId>,
}

impl Pending {
    /// Keep what `acc` and `regs`, another way into the target, agree with.
    fn merge(&mut self, acc: ValueId, regs: &[ValueId]) {
        if self.acc != acc {
            self.acc = ValueId::UNKNOWN;
        }
        for (known, &other) in self.regs.iter_mut().zip(regs) {
            if *known != other {
                *known = ValueId::UNKNOWN;
            }
        }
    }
}

/// What the first pass over a function found.
struct Blocks {
    /// Offset of the first instruction past the prologue.
    prologue_end: usize,
    /// Whether the function has a call the tracker knows the shape of.
    has_call: bool,
    /// Whether it stores into a captured variable or a module-level binding.
    has_store: bool,
    /// Whether it defines a class.
    has_class: bool,
}

/// [`CallSite`] without its argument slice.
struct CallHead {
    callee: ValueId,
    /// Leading entries of `Tracker::args` that are the callee or `this`.
    skip: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_call_opcode_has_a_shape() {
        for opcode in asc_arkisa::opcodes() {
            assert_eq!(CallShape::of(opcode).is_some(), opcode.is_call(), "{}", opcode.name);
            assert_eq!(Effect::of(opcode) == Effect::Call, opcode.is_call(), "{}", opcode.name);
        }
        let shape = |name: &str| asc_arkisa::opcodes().find(|op| op.name == name).and_then(CallShape::of).unwrap();
        // Every current call takes its callee from the accumulator (`acc: inout` in isa.yaml) …
        for name in ["callarg0", "callargs3", "callrange", "wide.callrange", "callthis2", "wide.callthisrange", "apply"] {
            assert_eq!(shape(name).callee, CalleeAt::Acc, "{name}");
        }
        // … except the constructors and the parent constructor.
        assert_eq!((shape("newobjrange").callee, shape("newobjrange").construct), (CalleeAt::RangeStart, true));
        assert_eq!(shape("wide.supercallthisrange").callee, CalleeAt::Super);
        assert_eq!(shape("callruntime.supercallforwardallargs").callee, CalleeAt::Super);
        assert_eq!(shape("wide.callthisrangewithname"), CallShape { has_this: true, ..CallShape::new(CalleeAt::Named) });
        assert!(shape("callruntime.callinit").has_this && shape("deprecated.callarg1").callee == CalleeAt::FirstRegister);
    }

    #[test]
    fn effects_follow_the_mnemonics() {
        let effect = |name: &str| asc_arkisa::opcodes().find(|op| op.name == name).map(Effect::of).unwrap();
        assert_eq!(effect("wide.ldexternalmodulevar"), Effect::Import);
        assert_eq!(effect("callruntime.wideldlazysendablemodulevar"), Effect::Import);
        assert_eq!(effect("wide.getmodulenamespace"), Effect::Namespace);
        assert_eq!(effect("callruntime.ldsendablelocalmodulevar"), Effect::ModuleLocal);
        // A store is not a load.
        assert_eq!(effect("stmodulevar"), Effect::Generic);
        assert_eq!(effect("callruntime.wideldsendablevar"), Effect::Lexical { sendable: true });
        assert_eq!(effect("wide.ldlexvar"), Effect::Lexical { sendable: false });
        assert_eq!(effect("add2"), Effect::Generic);
        let store = |name: &str| asc_arkisa::opcodes().find(|op| op.name == name).and_then(StoreKind::of);
        assert_eq!(store("wide.stlexvar"), Some(StoreKind::Lexical { sendable: false }));
        assert_eq!(store("deprecated.stlexvar"), Some(StoreKind::Lexical { sendable: false }));
        assert_eq!(store("callruntime.widestsendablevar"), Some(StoreKind::Lexical { sendable: true }));
        assert_eq!(store("wide.stmodulevar"), Some(StoreKind::Module));
        assert_eq!((store("ldlexvar"), store("deprecated.stmodulevar")), (None, None));
        let classes: Vec<&str> = asc_arkisa::opcodes().filter(|op| defines_class(op)).map(|op| op.name).collect();
        assert_eq!(classes.len(), 4, "{classes:?}");
        // Each has a constructor, and its parent in a register.
        for opcode in asc_arkisa::opcodes().filter(|op| defines_class(op)) {
            assert!(
                opcode.operand_of(OperandKind::MethodId).is_some() && opcode.operand_of(OperandKind::RegIn).is_some(),
                "{}",
                opcode.name
            );
        }
        // Every instruction that loads through a module index is modelled.
        for opcode in asc_arkisa::opcodes().filter(|op| ModuleOperand::of(op).is_some() && op.writes_acc()) {
            assert!(matches!(Effect::of(opcode), Effect::Import | Effect::Namespace | Effect::ModuleLocal), "{}", opcode.name);
        }
    }
}
