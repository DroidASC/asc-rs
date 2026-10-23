//! Intra-method values at call sites: what each argument register of an
//! invoke may hold, and whether the invoke's result is read.
//!
//! [`Analyzer::analyze`] runs one forward dataflow pass over a method's
//! basic blocks to a fixpoint and keeps the register state at each block
//! entry; [`MethodValues::args`] then replays one block up to the call site,
//! so a method is analyzed once for all of its call sites.
//!
//! A register holds a small set of *origins*: the instruction that defined
//! the value (a constant, `const-string`, `const-class`, `new-instance`, a
//! field read, or an invoke whose result a `move-result` picked up), one of
//! the method's parameters, or "unknown" (any other computation). Moves and
//! `check-cast` copy the set. Sets merge at join points ("may" semantics) and
//! collapse to unknown beyond [`MAX_CANDIDATES`] origins; an origin is
//! resolved to a [`Value`] only when a call site is queried.
//!
//! Exceptions: a handler's entry state merges the state before every
//! instruction of the try ranges that reach it (an instruction that throws
//! writes nothing), so what a handler sees is a superset of what it can get.
//!
//! Wide values live in the low register of their pair; the high register
//! reads as unknown. Methods whose code cannot be walked (undefined opcodes,
//! truncated instructions, branches into the middle of an instruction) are
//! not analyzed.

use crate::decode::{fetch16, vreg_a, vreg_b, vreg_c};
use crate::walk::walk_insns;
use crate::{opcode, Format, Instruction, Opcode, PACKED_SWITCH_PAYLOAD, SPARSE_SWITCH_PAYLOAD};
use std::cmp::Reverse;
use std::collections::BinaryHeap;

/// Most distinct origins a register keeps before it becomes unknown.
pub const MAX_CANDIDATES: usize = 4;

/// Largest `blocks × registers` state a method may need; bigger methods are
/// not analyzed (about 64 MiB of block states).
const MAX_SLOTS: usize = 1 << 22;

/// A try range (byte offsets into the code, `end` exclusive) and one of its
/// handlers' entry, catch-all or typed: one `Catch` per (try, handler) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Catch {
    pub start: usize,
    pub end: usize,
    pub handler: usize,
}

/// The parts of a `code_item` the analysis reads.
#[derive(Debug, Clone, Copy)]
pub struct MethodCode<'a> {
    pub insns: &'a [u8],
    pub registers: u16,
    /// Parameter registers (`ins_size`), the last ones of the frame.
    pub ins: u16,
    pub catches: &'a [Catch],
}

/// How a field was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FieldAccess {
    Static,
    Instance,
}

/// One value a register may hold at a call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Value {
    /// A literal of any `const*` instruction, as the bits the register (pair)
    /// holds: `const/high16` and `const-wide/high16` are already shifted.
    /// `0` is also how `null` is written.
    Const(i64),
    /// `const-string[/jumbo]`: a string index.
    String(u32),
    /// `const-class`: a type index.
    Class(u32),
    /// The method's own parameter register `pN` (smali numbering: `this` is
    /// `p0` of an instance method, a wide parameter takes two numbers).
    Param(u16),
    /// The result of the invoke at `pc` (a method index; `invoke-custom`
    /// results are [`Value::Unknown`]).
    Ret { pc: usize, method: u32 },
    /// A field read (`iget*` / `sget*`): a field index.
    Field { field: u32, access: FieldAccess },
    /// A fresh `new-instance` of a type index.
    NewInstance(u32),
    /// Anything else: computed, merged beyond [`MAX_CANDIDATES`], or never
    /// written in this method.
    Unknown,
}

/// The values one register may hold, sorted and distinct.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidates {
    len: u8,
    values: [Value; MAX_CANDIDATES],
}

impl Candidates {
    pub fn as_slice(&self) -> &[Value] {
        &self.values[..usize::from(self.len)]
    }

    /// The only value, when the register can hold just one.
    pub fn single(&self) -> Option<Value> {
        match self.as_slice() {
            [v] => Some(*v),
            _ => None,
        }
    }

    /// Whether every value is known: a constraint on the register can then
    /// be answered yes or no rather than "undetermined".
    pub fn is_determined(&self) -> bool {
        !self.as_slice().contains(&Value::Unknown)
    }

    fn push(&mut self, v: Value) {
        let n = usize::from(self.len);
        if !self.values[..n].contains(&v) {
            self.values[n] = v;
            self.len += 1;
            self.values[..=n].sort_unstable();
        }
    }
}

/// Whether an invoke's result is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultUse {
    /// Some path reads the register a `move-result` put it in.
    Used,
    /// No `move-result`, or every path overwrites or abandons it unread.
    Unused,
    /// `pc` is not a reachable invoke of an analyzed method.
    Unknown,
}

/// An origin packed in a `u32`: a defining instruction's pc, a parameter, or
/// one of the markers. Sorted so the markers come last.
type Origin = u32;
const PARAM: Origin = 1 << 30;
const UNKNOWN: Origin = 1 << 31;
const TOP: Origin = u32::MAX - 1;
const EMPTY: Origin = u32::MAX;

/// A register's origin set: sorted, `EMPTY`-padded; `[TOP, ..]` once it
/// overflowed (absorbs everything, so joins stay monotone).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Slot([Origin; MAX_CANDIDATES]);

impl Slot {
    const UNKNOWN: Slot = Slot::one(UNKNOWN);
    const TOP: Slot = Slot::one(TOP);

    const fn one(o: Origin) -> Slot {
        let mut s = [EMPTY; MAX_CANDIDATES];
        s[0] = o;
        Slot(s)
    }

    /// Union `other` into `self`; whether `self` changed.
    fn join(&mut self, other: &Slot) -> bool {
        if self.0[0] == TOP || self == other {
            return false;
        }
        if other.0[0] == TOP {
            *self = Slot::TOP;
            return true;
        }
        let at = |s: &Slot, i: usize| s.0.get(i).copied().unwrap_or(EMPTY);
        let mut out = [EMPTY; MAX_CANDIDATES];
        let (mut i, mut j, mut n) = (0, 0, 0);
        loop {
            let (a, b) = (at(self, i), at(other, j));
            let v = a.min(b);
            if v == EMPTY {
                break;
            }
            i += usize::from(a == v);
            j += usize::from(b == v);
            if n == MAX_CANDIDATES {
                *self = Slot::TOP;
                return true;
            }
            out[n] = v;
            n += 1;
        }
        let changed = out != self.0;
        self.0 = out;
        changed
    }
}

/// How control leaves an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    Next,
    Goto,
    Branch,
    Switch,
    Exit,
}

impl Flow {
    fn of(op: u8) -> Flow {
        match op {
            0x0e..=0x11 | 0x27 => Flow::Exit,
            0x28..=0x2a => Flow::Goto,
            0x2b | 0x2c => Flow::Switch,
            0x32..=0x3d => Flow::Branch,
            _ => Flow::Next,
        }
    }

    fn falls_through(self) -> bool {
        matches!(self, Flow::Next | Flow::Branch | Flow::Switch)
    }
}

/// Registers an instruction writes, starting at `vA`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Width {
    Narrow,
    Wide,
}

/// What the instruction `op` writes to `vA`, if anything.
fn dest(op: u8) -> Option<Width> {
    Some(match op {
        0x04..=0x06 | 0x0b | 0x16..=0x19 | 0x45 | 0x53 | 0x61 => Width::Wide,
        0x7d | 0x7e | 0x80 | 0x81 | 0x83 | 0x86 | 0x88 | 0x89 | 0x8b => Width::Wide,
        0x9b..=0xa5 | 0xab..=0xaf | 0xbb..=0xc5 | 0xcb..=0xcf => Width::Wide,
        0x01..=0x03 | 0x07..=0x0a | 0x0c | 0x0d | 0x12..=0x15 | 0x1a..=0x1c | 0x20..=0x23 => Width::Narrow,
        0x2d..=0x31 | 0x44 | 0x46..=0x4a | 0x52 | 0x54..=0x58 | 0x60 | 0x62..=0x66 => Width::Narrow,
        0x7b..=0x8f | 0x90..=0xe2 | 0xfe | 0xff => Width::Narrow,
        _ => return None,
    })
}

fn is_invoke(op: u8) -> bool {
    matches!(op, 0x6e..=0x72 | 0x74..=0x78 | 0xfa..=0xfd)
}

/// Whether the instruction at `pc` reads register `r` (a wide operand is
/// matched by its low register).
fn reads(code: &[u8], pc: usize, op: &Opcode, r: i64) -> bool {
    let v = op.value;
    let a = || vreg_a(code, pc, op) == Some(r);
    let b = || vreg_b(code, pc, op) == Some(r);
    let c = || vreg_c(code, pc, op) == Some(r);
    match op.format {
        Format::K10x | Format::K11n | Format::K10t | Format::K20t | Format::K30t => false,
        Format::K21s | Format::K21h | Format::K31i | Format::K51l | Format::K31c => false,
        Format::K12x => b() || ((0xb0..=0xcf).contains(&v) && a()),
        Format::K11x => matches!(v, 0x0f..=0x11 | 0x1d | 0x1e | 0x27) && a(),
        Format::K22x | Format::K32x | Format::K22b | Format::K22s => b(),
        Format::K21t | Format::K31t => a(),
        Format::K21c => matches!(v, 0x1f | 0x67..=0x6d) && a(),
        Format::K23x => b() || c() || ((0x4b..=0x51).contains(&v) && a()),
        Format::K22t => a() || b(),
        Format::K22c => b() || ((0x59..=0x5f).contains(&v) && a()),
        Format::K35c | Format::K45cc | Format::K3rc | Format::K4rcc => {
            Instruction::decode(code, pc).is_some_and(|i| i.regs.iter().any(|&x| i64::from(x) == r))
        }
    }
}

/// Branch and switch targets of the instruction at `pc` (byte offsets), or
/// `None` when a switch payload is malformed or a target is negative.
fn branch_targets(code: &[u8], pc: usize, op: &Opcode, out: &mut Vec<usize>) -> Option<()> {
    out.clear();
    let rel = match op.format {
        Format::K10t | Format::K20t | Format::K30t => vreg_a(code, pc, op)?,
        Format::K21t | Format::K31t => vreg_b(code, pc, op)?,
        Format::K22t => vreg_c(code, pc, op)?,
        _ => return Some(()),
    };
    let at = |rel: i64| usize::try_from(pc as i64 + rel * 2).ok();
    if Flow::of(op.value) != Flow::Switch {
        out.push(at(rel)?);
        return Some(());
    }
    let p = at(rel)?;
    let word = |w: usize| (p + w * 2 + 2 <= code.len()).then(|| fetch16(code, p, w));
    let int = |w: usize| Some(i32::from_le_bytes(code.get(p + w * 2..p + w * 2 + 4)?.try_into().ok()?));
    let size = usize::from(word(1)?);
    // Relative targets start after the header: packed has first_key, sparse all keys.
    let first = match word(0)? {
        PACKED_SWITCH_PAYLOAD => 4,
        SPARSE_SWITCH_PAYLOAD => 2 + size * 2,
        _ => return None,
    };
    for k in 0..size {
        out.push(at(i64::from(int(first + k * 2)?))?);
    }
    Some(())
}

/// Reusable buffers of the analysis; one per thread.
#[derive(Debug, Default)]
pub struct Analyzer {
    pcs: Vec<u32>,
    leader: Vec<bool>,
    /// First instruction index of each block.
    blocks: Vec<u32>,
    /// `(block, handler block)`, sorted.
    handlers: Vec<(u32, u32)>,
    states: Vec<Slot>,
    reached: Vec<bool>,
    queued: Vec<bool>,
    queue: BinaryHeap<Reverse<u32>>,
    scratch: Vec<Slot>,
    targets: Vec<usize>,
    visited: Vec<bool>,
    stack: Vec<u32>,
}

/// One analyzed method, answering queries about its call sites.
#[derive(Debug)]
pub struct MethodValues<'a> {
    an: &'a mut Analyzer,
    code: MethodCode<'a>,
}

impl Analyzer {
    pub fn new() -> Analyzer {
        Analyzer::default()
    }

    /// Analyze one method. `None` when its code cannot be walked (see the
    /// module docs) or is too large to analyze.
    pub fn analyze<'a>(&'a mut self, code: MethodCode<'a>) -> Option<MethodValues<'a>> {
        self.build_blocks(&code)?;
        let regs = usize::from(code.registers);
        if code.ins > code.registers || self.blocks.len().saturating_mul(regs) > MAX_SLOTS {
            return None;
        }
        self.solve(&code);
        Some(MethodValues { an: self, code })
    }

    fn insn_at(&self, pc: usize) -> Option<usize> {
        let pc = u32::try_from(pc).ok()?;
        self.pcs.binary_search(&pc).ok()
    }

    fn block_of(&self, insn: usize) -> usize {
        self.blocks.partition_point(|&s| s as usize <= insn) - 1
    }

    fn block_end(&self, b: usize) -> usize {
        self.blocks.get(b + 1).map_or(self.pcs.len(), |&s| s as usize)
    }

    /// The range of `handlers` holding block `b`'s handler blocks.
    fn block_handlers(&self, b: usize) -> std::ops::Range<usize> {
        let b = b as u32;
        self.handlers.partition_point(|&(x, _)| x < b)..self.handlers.partition_point(|&(x, _)| x <= b)
    }

    fn build_blocks(&mut self, code: &MethodCode<'_>) -> Option<()> {
        let insns = code.insns;
        if u32::try_from(insns.len()).ok()? >= PARAM {
            return None;
        }
        self.pcs.clear();
        let pcs = &mut self.pcs;
        // `insns.len() < PARAM`, so every pc fits.
        walk_insns(insns, |s| pcs.push(s.pc as u32)).is_complete().then_some(())?;
        let n = self.pcs.len();
        self.leader.clear();
        self.leader.resize(n, false);
        if let Some(first) = self.leader.first_mut() {
            *first = true;
        }
        let mut targets = std::mem::take(&mut self.targets);
        for i in 0..n {
            let pc = self.pcs[i] as usize;
            let op = opcode(insns[pc])?;
            let flow = Flow::of(op.value);
            if flow == Flow::Next {
                continue;
            }
            if i + 1 < n {
                self.leader[i + 1] = true;
            }
            branch_targets(insns, pc, op, &mut targets)?;
            for &t in &targets {
                let t = self.insn_at(t)?;
                self.leader[t] = true;
            }
        }
        self.targets = targets;
        for c in code.catches {
            for edge in [c.start, c.end] {
                let i = self.pcs.partition_point(|&p| (p as usize) < edge);
                if i < n {
                    self.leader[i] = true;
                }
            }
            let h = self.insn_at(c.handler)?;
            self.leader[h] = true;
        }
        self.blocks.clear();
        self.blocks.extend((0..n).filter(|&i| self.leader[i]).map(|i| i as u32));
        self.handlers.clear();
        for c in code.catches {
            let handler = self.block_of(self.insn_at(c.handler)?) as u32;
            let first = self.pcs.partition_point(|&p| (p as usize) < c.start);
            let last = self.pcs.partition_point(|&p| (p as usize) < c.end);
            if first < last {
                let (lo, hi) = (self.block_of(first), self.block_of(last - 1));
                self.handlers.extend((lo..=hi).map(|b| (b as u32, handler)));
            }
        }
        self.handlers.sort_unstable();
        self.handlers.dedup();
        Some(())
    }

    fn solve(&mut self, code: &MethodCode<'_>) {
        let regs = usize::from(code.registers);
        let nblocks = self.blocks.len();
        self.states.clear();
        self.states.resize(nblocks * regs, Slot::UNKNOWN);
        self.reached.clear();
        self.reached.resize(nblocks, false);
        self.queued.clear();
        self.queued.resize(nblocks, false);
        self.queue.clear();
        if nblocks == 0 {
            return;
        }
        let first_param = regs - usize::from(code.ins);
        for (p, slot) in self.states[first_param..regs].iter_mut().enumerate() {
            *slot = Slot::one(PARAM + p as u32);
        }
        self.reached[0] = true;
        self.queue.push(Reverse(0));
        self.queued[0] = true;
        let mut scratch = std::mem::take(&mut self.scratch);
        let mut targets = std::mem::take(&mut self.targets);
        while let Some(Reverse(b)) = self.queue.pop() {
            let b = b as usize;
            self.queued[b] = false;
            scratch.clear();
            scratch.extend_from_slice(&self.states[b * regs..(b + 1) * regs]);
            let (start, end) = (self.blocks[b] as usize, self.block_end(b));
            let handlers = self.block_handlers(b);
            for i in start..end {
                for k in handlers.clone() {
                    let h = self.handlers[k].1 as usize;
                    self.flow_into(h, &scratch, regs);
                }
                self.transfer(code.insns, i, &mut scratch);
            }
            let last = self.pcs[end - 1] as usize;
            let op = opcode(code.insns[last]).expect("walked instruction has a defined opcode");
            if Flow::of(op.value).falls_through() && end < self.pcs.len() {
                self.flow_into(b + 1, &scratch, regs);
            }
            // Targets were validated while building the blocks.
            if branch_targets(code.insns, last, op, &mut targets).is_some() {
                for &t in &targets {
                    if let Some(t) = self.insn_at(t) {
                        let tb = self.block_of(t);
                        self.flow_into(tb, &scratch, regs);
                    }
                }
            }
        }
        self.scratch = scratch;
        self.targets = targets;
    }

    /// Merge `state` into block `b`'s entry, queueing `b` when it changed.
    fn flow_into(&mut self, b: usize, state: &[Slot], regs: usize) {
        let entry = &mut self.states[b * regs..(b + 1) * regs];
        let changed = if self.reached[b] {
            entry.iter_mut().zip(state).fold(false, |changed, (e, s)| e.join(s) | changed)
        } else {
            entry.copy_from_slice(state);
            self.reached[b] = true;
            true
        };
        if changed && !self.queued[b] {
            self.queued[b] = true;
            self.queue.push(Reverse(b as u32));
        }
    }

    /// Apply instruction `i` to `state`.
    fn transfer(&self, code: &[u8], i: usize, state: &mut [Slot]) {
        let pc = self.pcs[i] as usize;
        let op = opcode(code[pc]).expect("walked instruction has a defined opcode");
        let Some(width) = dest(op.value) else { return };
        let reg = |r: Option<i64>| r.and_then(|r| usize::try_from(r).ok()).filter(|&r| r < state.len());
        let Some(a) = reg(vreg_a(code, pc, op)) else { return };
        let def = Slot::one(pc as Origin);
        let (low, high) = match op.value {
            0x01..=0x03 | 0x07..=0x09 => (reg(vreg_b(code, pc, op)).map_or(Slot::UNKNOWN, |b| state[b]), Slot::UNKNOWN),
            0x04..=0x06 => {
                let b = reg(vreg_b(code, pc, op));
                let high = b.and_then(|b| state.get(b + 1)).copied().unwrap_or(Slot::UNKNOWN);
                (b.map_or(Slot::UNKNOWN, |b| state[b]), high)
            }
            // move-result*: the invoke right before it (the verifier requires
            // the pairing), unless it is an invoke-custom or filled-new-array.
            0x0a..=0x0c => {
                let prev = i.checked_sub(1).map(|p| self.pcs[p] as usize);
                match prev {
                    Some(p) if is_invoke(code[p]) && !matches!(code[p], 0xfc | 0xfd) => (Slot::one(p as Origin), Slot::UNKNOWN),
                    _ => (Slot::UNKNOWN, Slot::UNKNOWN),
                }
            }
            0x12..=0x19 | 0x1a..=0x1c | 0x22 | 0x52..=0x58 | 0x60..=0x66 => (def, Slot::UNKNOWN),
            _ => (Slot::UNKNOWN, Slot::UNKNOWN),
        };
        state[a] = low;
        if width == Width::Wide {
            if let Some(h) = state.get_mut(a + 1) {
                *h = high;
            }
        }
    }
}

impl MethodValues<'_> {
    /// The values of each argument register of the invoke at `pc`, in the
    /// instruction's register order (`{v0, v1}` or `{v4 .. v7}`; a wide
    /// argument takes two entries, its high register unknown). `None` when
    /// `pc` is not an invoke or is unreachable.
    pub fn args(&mut self, pc: usize) -> Option<Vec<Candidates>> {
        let code = self.code.insns;
        let an = &mut *self.an;
        let i = an.insn_at(pc)?;
        if !is_invoke(code[pc]) {
            return None;
        }
        let b = an.block_of(i);
        if !an.reached[b] {
            return None;
        }
        let regs = usize::from(self.code.registers);
        let mut scratch = std::mem::take(&mut an.scratch);
        scratch.clear();
        scratch.extend_from_slice(&an.states[b * regs..(b + 1) * regs]);
        for k in an.blocks[b] as usize..i {
            an.transfer(code, k, &mut scratch);
        }
        let insn = Instruction::decode(code, pc)?;
        let out = insn.regs.iter().map(|&r| resolve(code, scratch.get(usize::from(r)).unwrap_or(&Slot::UNKNOWN))).collect();
        an.scratch = scratch;
        Some(out)
    }

    /// Whether the result of the invoke at `pc` is read on some path.
    pub fn result_use(&mut self, pc: usize) -> ResultUse {
        let code = self.code.insns;
        let an = &mut *self.an;
        let Some(i) = an.insn_at(pc) else { return ResultUse::Unknown };
        if !is_invoke(code[pc]) || !an.reached[an.block_of(i)] {
            return ResultUse::Unknown;
        }
        let Some(&next) = an.pcs.get(i + 1) else { return ResultUse::Unused };
        let next = next as usize;
        let mr = opcode(code[next]).expect("walked instruction has a defined opcode");
        if !matches!(mr.value, 0x0a..=0x0c) {
            return ResultUse::Unused;
        }
        let Some(r) = vreg_a(code, next, mr) else { return ResultUse::Unknown };
        let wide = mr.value == 0x0b;
        let n = an.pcs.len();
        an.visited.clear();
        an.visited.resize(n, false);
        an.stack.clear();
        // Start after the move-result (which cannot throw).
        if i + 2 < n {
            an.stack.push((i + 2) as u32);
        }
        let mut targets = std::mem::take(&mut an.targets);
        let mut used = ResultUse::Unused;
        while let Some(k) = an.stack.pop() {
            let k = k as usize;
            if std::mem::replace(&mut an.visited[k], true) {
                continue;
            }
            let pc = an.pcs[k] as usize;
            let op = opcode(code[pc]).expect("walked instruction has a defined opcode");
            if reads(code, pc, op, r) || (wide && reads(code, pc, op, r + 1)) {
                used = ResultUse::Used;
                break;
            }
            // A throwing instruction writes nothing: its handlers see `r` first.
            let b = an.block_of(k);
            for k in an.block_handlers(b) {
                let h = an.handlers[k].1 as usize;
                an.stack.push(an.blocks[h]);
            }
            let killed = dest(op.value).is_some_and(|w| {
                let a = vreg_a(code, pc, op).unwrap_or(-1);
                let hi = if w == Width::Wide { a + 1 } else { a };
                let rhi = if wide { r + 1 } else { r };
                a <= rhi && r <= hi
            });
            if killed {
                continue;
            }
            let flow = Flow::of(op.value);
            if flow.falls_through() && k + 1 < n {
                an.stack.push((k + 1) as u32);
            }
            if branch_targets(code, pc, op, &mut targets).is_some() {
                for &t in &targets {
                    if let Some(t) = an.insn_at(t) {
                        an.stack.push(t as u32);
                    }
                }
            }
        }
        an.targets = targets;
        used
    }
}

/// The values of an origin set, read back from the defining instructions.
fn resolve(code: &[u8], slot: &Slot) -> Candidates {
    let mut out = Candidates { len: 0, values: [Value::Unknown; MAX_CANDIDATES] };
    for &o in slot.0.iter().take_while(|&&o| o != EMPTY) {
        let v = match o {
            TOP | UNKNOWN => Value::Unknown,
            // Packed by `solve`: `PARAM + p` with `p < ins <= u16::MAX`.
            o if o >= PARAM => Value::Param((o - PARAM) as u16),
            pc => definition(code, pc as usize),
        };
        out.push(v);
    }
    out
}

/// The value the instruction at `pc` defines.
fn definition(code: &[u8], pc: usize) -> Value {
    let Some(op) = opcode(code[pc]) else { return Value::Unknown };
    let (Some(b), c) = (vreg_b(code, pc, op), vreg_c(code, pc, op)) else { return Value::Unknown };
    // Indexes are unsigned 16/32-bit operands; high16 literals are the top bits.
    let idx = b as u32;
    match op.value {
        0x12..=0x14 | 0x16..=0x18 => Value::Const(b),
        0x15 => Value::Const(i64::from(((b as u32) << 16) as i32)),
        0x19 => Value::Const(((b as u64) << 48) as i64),
        0x1a | 0x1b => Value::String(idx),
        0x1c => Value::Class(idx),
        0x22 => Value::NewInstance(idx),
        0x52..=0x58 => c.map_or(Value::Unknown, |c| Value::Field { field: c as u32, access: FieldAccess::Instance }),
        0x60..=0x66 => Value::Field { field: idx, access: FieldAccess::Static },
        v if is_invoke(v) => Value::Ret { pc, method: idx },
        _ => Value::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny assembler: each method appends one instruction and returns its pc.
    #[derive(Default)]
    struct Asm(Vec<u8>);

    impl Asm {
        fn put(&mut self, bytes: &[u8]) -> usize {
            let pc = self.0.len();
            self.0.extend_from_slice(bytes);
            pc
        }
        fn u16(v: u16) -> [u8; 2] {
            v.to_le_bytes()
        }
        fn const4(&mut self, a: u8, v: i8) -> usize {
            self.put(&[0x12, ((v as u8) << 4) | a])
        }
        fn const16(&mut self, a: u8, v: i16) -> usize {
            let [l, h] = (v as u16).to_le_bytes();
            self.put(&[0x13, a, l, h])
        }
        fn const_high16(&mut self, a: u8, v: u16) -> usize {
            let [l, h] = Self::u16(v);
            self.put(&[0x15, a, l, h])
        }
        fn const_wide16(&mut self, a: u8, v: i16) -> usize {
            let [l, h] = (v as u16).to_le_bytes();
            self.put(&[0x16, a, l, h])
        }
        fn const_string(&mut self, a: u8, s: u16) -> usize {
            let [l, h] = Self::u16(s);
            self.put(&[0x1a, a, l, h])
        }
        fn const_class(&mut self, a: u8, t: u16) -> usize {
            let [l, h] = Self::u16(t);
            self.put(&[0x1c, a, l, h])
        }
        fn new_instance(&mut self, a: u8, t: u16) -> usize {
            let [l, h] = Self::u16(t);
            self.put(&[0x22, a, l, h])
        }
        fn check_cast(&mut self, a: u8, t: u16) -> usize {
            let [l, h] = Self::u16(t);
            self.put(&[0x1f, a, l, h])
        }
        fn move_object(&mut self, a: u8, b: u8) -> usize {
            self.put(&[0x07, (b << 4) | a])
        }
        fn move_wide(&mut self, a: u8, b: u8) -> usize {
            self.put(&[0x04, (b << 4) | a])
        }
        fn move_result(&mut self, a: u8) -> usize {
            self.put(&[0x0a, a])
        }
        fn move_result_wide(&mut self, a: u8) -> usize {
            self.put(&[0x0b, a])
        }
        fn move_exception(&mut self, a: u8) -> usize {
            self.put(&[0x0d, a])
        }
        fn sget(&mut self, a: u8, f: u16) -> usize {
            let [l, h] = Self::u16(f);
            self.put(&[0x62, a, l, h])
        }
        fn iget(&mut self, a: u8, b: u8, f: u16) -> usize {
            let [l, h] = Self::u16(f);
            self.put(&[0x54, (b << 4) | a, l, h])
        }
        fn add_lit8(&mut self, a: u8, b: u8, lit: i8) -> usize {
            self.put(&[0xd8, a, b, lit as u8])
        }
        fn invoke(&mut self, op: u8, m: u16, regs: &[u8]) -> usize {
            let r = |k: usize| regs.get(k).copied().unwrap_or(0);
            let [l, h] = Self::u16(m);
            self.put(&[op, ((regs.len() as u8) << 4) | r(4), l, h, (r(1) << 4) | r(0), (r(3) << 4) | r(2)])
        }
        fn invoke_static(&mut self, m: u16, regs: &[u8]) -> usize {
            self.invoke(0x71, m, regs)
        }
        fn invoke_range(&mut self, m: u16, first: u16, count: u8) -> usize {
            let [l, h] = Self::u16(m);
            let [fl, fh] = Self::u16(first);
            self.put(&[0x77, count, l, h, fl, fh])
        }
        fn if_eqz(&mut self, a: u8, to: usize) -> usize {
            let pc = self.0.len();
            let rel = ((to as i64 - pc as i64) / 2) as i16;
            let [l, h] = (rel as u16).to_le_bytes();
            self.put(&[0x38, a, l, h])
        }
        fn goto(&mut self, to: usize) -> usize {
            let pc = self.0.len();
            let rel = ((to as i64 - pc as i64) / 2) as i8;
            self.put(&[0x28, rel as u8])
        }
        fn ret(&mut self, a: u8) -> usize {
            self.put(&[0x0f, a])
        }
        fn return_void(&mut self) -> usize {
            self.put(&[0x0e, 0x00])
        }
        fn throw(&mut self, a: u8) -> usize {
            self.put(&[0x27, a])
        }
        /// Overwrite the 16-bit branch offset of the `if-*z` at `pc`.
        fn patch_if(&mut self, pc: usize, to: usize) {
            let rel = ((to as i64 - pc as i64) / 2) as i16;
            self.0[pc + 2..pc + 4].copy_from_slice(&(rel as u16).to_le_bytes());
        }
        fn patch_goto(&mut self, pc: usize, to: usize) {
            self.0[pc + 1] = ((to as i64 - pc as i64) / 2) as i8 as u8;
        }
        fn here(&self) -> usize {
            self.0.len()
        }
    }

    fn code<'a>(asm: &'a Asm, registers: u16, ins: u16, catches: &'a [Catch]) -> MethodCode<'a> {
        MethodCode { insns: &asm.0, registers, ins, catches }
    }

    fn values(c: Candidates) -> Vec<Value> {
        c.as_slice().to_vec()
    }

    fn args(an: &mut Analyzer, code: MethodCode<'_>, pc: usize) -> Vec<Vec<Value>> {
        an.analyze(code).expect("analyzable").args(pc).expect("an invoke").into_iter().map(values).collect()
    }

    #[test]
    fn straight_line_constants() {
        let mut a = Asm::default();
        a.const4(0, -3);
        a.const16(1, 1000);
        a.const_string(2, 7);
        a.const_class(3, 9);
        a.const_high16(4, 0x7f01);
        a.new_instance(5, 11);
        let call = a.invoke_static(42, &[0, 1, 2, 3, 4]);
        a.return_void();
        let mut an = Analyzer::new();
        let got = args(&mut an, code(&a, 6, 0, &[]), call);
        assert_eq!(
            got,
            vec![
                vec![Value::Const(-3)],
                vec![Value::Const(1000)],
                vec![Value::String(7)],
                vec![Value::Class(9)],
                vec![Value::Const(0x7f01_0000)],
            ]
        );
        let mut m = an.analyze(code(&a, 6, 0, &[])).unwrap();
        let first = m.args(call).unwrap()[0];
        assert_eq!((first.single(), first.is_determined()), (Some(Value::Const(-3)), true));
        // Not an invoke, or not an instruction boundary.
        assert!(m.args(0).is_none() && m.args(call + 2).is_none());
        assert_eq!(m.result_use(0), ResultUse::Unknown);
    }

    #[test]
    fn moves_and_casts_propagate() {
        let mut a = Asm::default();
        a.new_instance(0, 3);
        a.move_object(1, 0);
        a.check_cast(1, 4);
        a.add_lit8(2, 2, 1);
        let call = a.invoke_static(1, &[1, 2]);
        a.return_void();
        let mut an = Analyzer::new();
        assert_eq!(args(&mut an, code(&a, 3, 0, &[]), call), vec![vec![Value::NewInstance(3)], vec![Value::Unknown]]);
    }

    #[test]
    fn branches_merge_into_a_set() {
        // if (p0 == 0) v0 = "a" else v0 = 5; call(v0)
        let mut a = Asm::default();
        let br = a.if_eqz(1, 0);
        a.const_string(0, 1);
        let jump = a.goto(0);
        let other = a.const4(0, 5);
        let join = a.here();
        let call = a.invoke_static(9, &[0]);
        a.return_void();
        a.patch_if(br, other);
        a.patch_goto(jump, join);
        let mut an = Analyzer::new();
        let mut m = an.analyze(code(&a, 2, 1, &[])).unwrap();
        let c = m.args(call).unwrap()[0];
        assert_eq!(values(c), vec![Value::Const(5), Value::String(1)]);
        assert!(c.is_determined() && c.single().is_none());
    }

    #[test]
    fn sets_overflow_to_unknown_and_loops_reach_a_fixpoint() {
        // v0 = 0; loop: call(v0, v1); v0 = v0 + 1; v1 = "s"; if v2 == 0 goto loop
        let mut a = Asm::default();
        a.const4(0, 0);
        let head = a.here();
        let call = a.invoke_static(1, &[0, 1]);
        a.add_lit8(0, 0, 1);
        a.const_string(1, 4);
        a.if_eqz(2, head);
        a.return_void();
        let mut an = Analyzer::new();
        let got = args(&mut an, code(&a, 3, 1, &[]), call);
        assert_eq!(got, vec![vec![Value::Const(0), Value::Unknown], vec![Value::String(4), Value::Unknown]]);

        // Five distinct constants into one register: unknown.
        let mut a = Asm::default();
        let mut jumps = Vec::new();
        for k in 0..5 {
            let br = a.if_eqz(1, 0);
            a.const4(0, k);
            jumps.push((br, a.goto(0)));
        }
        a.const4(0, 6);
        let join = a.here();
        let call = a.invoke_static(1, &[0]);
        a.return_void();
        for (k, &(br, jump)) in jumps.iter().enumerate() {
            let next = jumps.get(k + 1).map_or(join - 2, |&(b, _)| b);
            a.patch_if(br, next);
            a.patch_goto(jump, join);
        }
        assert_eq!(args(&mut an, code(&a, 2, 1, &[]), call), vec![vec![Value::Unknown]]);
    }

    #[test]
    fn params_returns_and_fields() {
        // static f(int p0, Object p1) in 4 registers: v2 = p0, v3 = p1.
        let mut a = Asm::default();
        let first = a.invoke_static(5, &[3]);
        a.move_result(0);
        a.sget(1, 8);
        let call = a.invoke_static(6, &[0, 1, 2, 3]);
        a.iget(1, 3, 12);
        let call2 = a.invoke(0x6e, 7, &[3, 1]);
        a.return_void();
        let mut an = Analyzer::new();
        let mut m = an.analyze(code(&a, 4, 2, &[])).unwrap();
        let got: Vec<_> = m.args(call).unwrap().into_iter().map(values).collect();
        assert_eq!(
            got,
            vec![
                vec![Value::Ret { pc: first, method: 5 }],
                vec![Value::Field { field: 8, access: FieldAccess::Static }],
                vec![Value::Param(0)],
                vec![Value::Param(1)],
            ]
        );
        let got: Vec<_> = m.args(call2).unwrap().into_iter().map(values).collect();
        assert_eq!(got, vec![vec![Value::Param(1)], vec![Value::Field { field: 12, access: FieldAccess::Instance }]]);
    }

    #[test]
    fn range_invokes_and_wide_values() {
        let mut a = Asm::default();
        a.const_wide16(0, -1);
        a.move_wide(2, 0);
        a.const_string(4, 3);
        let call = a.invoke_range(1, 2, 3);
        a.const4(1, 7); // clobbers the high half of v0..v1
        let wide = a.invoke_static(2, &[0, 1]);
        a.move_result_wide(5);
        let call2 = a.invoke_static(3, &[5, 6]);
        a.return_void();
        let mut an = Analyzer::new();
        let mut m = an.analyze(code(&a, 7, 0, &[])).unwrap();
        let got: Vec<_> = m.args(call).unwrap().into_iter().map(values).collect();
        assert_eq!(got, vec![vec![Value::Const(-1)], vec![Value::Unknown], vec![Value::String(3)]]);
        let got: Vec<_> = m.args(wide).unwrap().into_iter().map(values).collect();
        assert_eq!(got, vec![vec![Value::Const(-1)], vec![Value::Const(7)]]);
        let got: Vec<_> = m.args(call2).unwrap().into_iter().map(values).collect();
        assert_eq!(got, vec![vec![Value::Ret { pc: wide, method: 2 }], vec![Value::Unknown]]);
    }

    #[test]
    fn result_use() {
        let mut a = Asm::default();
        let no_move = a.invoke_static(1, &[]);
        let dead = a.invoke_static(2, &[]);
        a.move_result(0);
        a.const4(0, 1); // overwritten before any read
        let read = a.invoke_static(3, &[]);
        a.move_result(1);
        let br = a.if_eqz(0, 0);
        a.ret(1); // one path reads it
        let other = a.return_void();
        let wide = a.invoke_static(4, &[]);
        a.move_result_wide(2);
        a.const4(3, 0); // clobbers the pair's high half
        a.return_void();
        a.patch_if(br, other);
        let mut an = Analyzer::new();
        let mut m = an.analyze(code(&a, 4, 0, &[])).unwrap();
        assert_eq!(m.result_use(no_move), ResultUse::Unused);
        assert_eq!(m.result_use(dead), ResultUse::Unused);
        assert_eq!(m.result_use(read), ResultUse::Used);
        // `wide` sits after a return: unreachable.
        assert_eq!(m.result_use(wide), ResultUse::Unknown);
    }

    #[test]
    fn try_catch_handlers_see_values_from_the_try_range() {
        // try { v0 = "a"; call1(); v0 = 3; call2() } catch { move-exception v1; sink(v0, v1) }
        let mut a = Asm::default();
        let start = a.const_string(0, 1);
        let first = a.invoke_static(1, &[]);
        a.const4(0, 3);
        a.invoke_static(2, &[]);
        let end = a.return_void();
        let handler = a.move_exception(1);
        let sink = a.invoke_static(3, &[0, 1]);
        a.throw(1);
        let catches = [Catch { start, end, handler }];
        let mut an = Analyzer::new();
        let mut m = an.analyze(code(&a, 2, 0, &catches)).unwrap();
        let got: Vec<_> = m.args(sink).unwrap().into_iter().map(values).collect();
        assert_eq!(got, vec![vec![Value::Const(3), Value::String(1), Value::Unknown], vec![Value::Unknown]]);
        assert_eq!(m.result_use(first), ResultUse::Unused);
        assert!(m.args(first).unwrap().is_empty());

        // A result moved into v0 inside the try, overwritten after: the
        // handler still reads it when a later instruction throws.
        let mut a = Asm::default();
        let start = a.invoke_static(1, &[]);
        a.move_result(0);
        a.invoke_static(2, &[]);
        a.const4(0, 1);
        let end = a.return_void();
        let handler = a.ret(0);
        let catches = [Catch { start, end, handler }];
        let mut an = Analyzer::new();
        let mut m = an.analyze(code(&a, 1, 0, &catches)).unwrap();
        assert_eq!(m.result_use(start), ResultUse::Used);
        assert!(an.analyze(code(&a, 1, 0, &[])).unwrap().result_use(start) == ResultUse::Unused);
        // A handler that is not an instruction boundary: not analyzed.
        assert!(an.analyze(code(&a, 1, 0, &[Catch { start, end, handler: handler + 1 }])).is_none());
    }

    #[test]
    fn switches_reach_every_case() {
        // packed-switch v1 -> case0: v0 = 1, case1: v0 = "x"; default: v0 = 2; call(v0)
        let mut a = Asm::default();
        let sw = a.put(&[0x2b, 0x01, 0, 0, 0, 0]);
        a.const4(0, 2);
        let j0 = a.goto(0);
        let case0 = a.const4(0, 1);
        let j1 = a.goto(0);
        let case1 = a.const_string(0, 5);
        let join = a.here();
        let call = a.invoke_static(1, &[0]);
        a.return_void();
        let payload = a.here();
        a.put(&[0x00, 0x01, 0x02, 0x00, 0, 0, 0, 0]);
        a.put(&(((case0 - sw) / 2) as i32).to_le_bytes());
        a.put(&(((case1 - sw) / 2) as i32).to_le_bytes());
        a.0[sw + 2..sw + 6].copy_from_slice(&(((payload - sw) / 2) as i32).to_le_bytes());
        a.patch_goto(j0, join);
        a.patch_goto(j1, join);
        let mut an = Analyzer::new();
        assert_eq!(args(&mut an, code(&a, 2, 1, &[]), call), vec![vec![Value::Const(1), Value::Const(2), Value::String(5)]]);
    }

    #[test]
    fn unwalkable_code_is_not_analyzed() {
        let mut an = Analyzer::new();
        let undefined = [0x3e, 0x00];
        assert!(an.analyze(MethodCode { insns: &undefined, registers: 1, ins: 0, catches: &[] }).is_none());
        // A branch into the middle of an instruction.
        let mut a = Asm::default();
        a.goto(0);
        a.const16(0, 1);
        a.patch_goto(0, 4);
        assert!(an.analyze(code(&a, 1, 0, &[])).is_none());
        // More parameters than registers.
        let mut a = Asm::default();
        a.return_void();
        assert!(an.analyze(code(&a, 1, 2, &[])).is_none());
        // Empty code is fine.
        assert!(an.analyze(MethodCode { insns: &[], registers: 0, ins: 0, catches: &[] }).is_some());
    }

    #[test]
    fn slots_join_as_sorted_sets() {
        let mut s = Slot::one(10);
        assert!(s.join(&Slot::one(4)));
        assert!(!s.join(&Slot::one(10)));
        assert_eq!(s.0, [4, 10, EMPTY, EMPTY]);
        assert!(s.join(&Slot([1, 2, EMPTY, EMPTY])));
        assert_eq!(s.0, [1, 2, 4, 10]);
        assert!(s.join(&Slot::one(3)));
        assert_eq!(s, Slot::TOP);
        assert!(!s.join(&Slot::one(1)));
    }
}
