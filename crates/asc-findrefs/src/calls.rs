//! Call-site constraints ([`Query::Call`]): which calls of a method query to
//! keep, judged by the values their arguments may hold and whether their
//! result is read.
//!
//! The code scan finds the call sites as for the plain method query; only
//! the methods holding one are then analyzed ([`asc_dalvik::values`]), once
//! each for all their sites. Values are "may" facts: a constraint holds when
//! one of an argument's candidate values matches, fails when every candidate
//! is known and none matches, and is *undetermined* when none of the known
//! ones matches but some are unknown (computed, or past the candidate limit).
//! An undetermined site is kept and marked `?` unless the constraint is
//! [`Certainty::Must`], so an agent can read the code instead of trusting a
//! silent drop.

use crate::query::CompiledQuery;
use crate::{FindRefs, Hit, MemberQuery, Query, Result};
use asc_dalvik::values::{Analyzer, Candidates, Catch, MethodCode, MethodValues, ResultUse, Value};
use asc_dex::Dex;
use regex::Regex;
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::Write;

/// Longest string constant a site note quotes whole.
const MAX_NOTE_STRING: usize = 80;

/// The register a value constraint looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    /// The receiver of an instance call (none for a static one).
    This,
    /// A declared parameter of the called method, from 0 (a wide one counts once).
    Arg(u16),
}

/// What an undetermined site does to a constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Certainty {
    /// `=`: kept, marked `?`.
    May,
    /// `==`: dropped; only sites shown to match stay.
    Must,
}

/// The value a [`Slot`] has to hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Want {
    /// `*`: anything; the values are only shown.
    Any,
    /// An integer literal (`true` is 1, `false` and `null` are 0).
    Int(i64),
    /// Exactly this string constant.
    Str(String),
    /// A string constant this regex matches.
    StrRegex(String),
    /// `const-class` of this descriptor.
    Class(String),
    /// A parameter of the calling method (smali `pK`; any one when `None`).
    Param(Option<u16>),
    /// The result of a call to a method this query matches.
    Ret(MemberQuery),
    /// A read of a field this query matches.
    Field(MemberQuery),
    /// A `new-instance` of this descriptor.
    New(String),
}

/// Whether the call's result has to be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultWant {
    Used,
    Unused,
}

/// One constraint of a [`Query::Call`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallConstraint {
    /// `[argN=VALUE]`, `[this=VALUE]`.
    Value { slot: Slot, want: Want, certainty: Certainty },
    /// `[ret=used]`, `[ret=unused]`.
    Result { want: ResultWant, certainty: Certainty },
}

/// A [`Want`] ready to run.
enum CompiledWant {
    Any,
    Int(i64),
    /// MUTF-8, as the string data holds it.
    Str(Vec<u8>),
    StrRegex(Regex),
    Class(Vec<u8>),
    Param(Option<u16>),
    Ret(Box<CompiledQuery>),
    Field(Box<CompiledQuery>),
    New(Vec<u8>),
}

enum CompiledConstraint {
    Value { slot: Slot, want: CompiledWant, certainty: Certainty },
    Result { want: ResultWant, certainty: Certainty },
}

/// The compiled parts of a [`Query::Call`].
pub(crate) struct CompiledCall {
    pub target: Box<CompiledQuery>,
    constraints: Vec<CompiledConstraint>,
}

impl CompiledCall {
    pub(crate) fn new(target: &Query, constraints: &[CallConstraint]) -> Result<CompiledCall> {
        let target = match target {
            Query::Method(_) | Query::MethodSet(_) | Query::Virtual { .. } => Box::new(CompiledQuery::new(target)?),
            _ => return Err(crate::FindError::Invalid("call constraints ([argN=...], [ret=...]) need a method query".into())),
        };
        let constraints = constraints
            .iter()
            .map(|c| {
                Ok(match c {
                    CallConstraint::Value { slot, want, certainty } => {
                        CompiledConstraint::Value { slot: *slot, want: CompiledWant::new(want)?, certainty: *certainty }
                    }
                    CallConstraint::Result { want, certainty } => CompiledConstraint::Result { want: *want, certainty: *certainty },
                })
            })
            .collect::<Result<_>>()?;
        Ok(CompiledCall { target, constraints })
    }
}

impl CompiledWant {
    fn new(w: &Want) -> Result<CompiledWant> {
        let mutf8 = |s: &str| asc_dex::mutf8::encode(s);
        Ok(match w {
            Want::Any => CompiledWant::Any,
            Want::Int(n) => CompiledWant::Int(*n),
            Want::Str(s) => CompiledWant::Str(mutf8(s)),
            Want::StrRegex(r) => CompiledWant::StrRegex(Regex::new(r)?),
            Want::Class(d) => CompiledWant::Class(mutf8(d)),
            Want::Param(k) => CompiledWant::Param(*k),
            Want::Ret(m) => CompiledWant::Ret(Box::new(CompiledQuery::new(&Query::Method(m.clone()))?)),
            Want::Field(m) => CompiledWant::Field(Box::new(CompiledQuery::new(&Query::Field(m.clone()))?)),
            Want::New(d) => CompiledWant::New(mutf8(d)),
        })
    }
}

/// How one constraint judged one site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Verdict {
    Holds,
    Undetermined,
    Fails,
}

thread_local! {
    /// One analyzer per search thread, so its buffers are reused.
    static ANALYZER: RefCell<Analyzer> = RefCell::new(Analyzer::new());
}

/// The per-DEX index sets of the `ret:` / `field:` wants, located once.
struct Located {
    sets: Vec<Option<BTreeSet<u32>>>,
}

impl FindRefs<'_, '_, '_> {
    /// The hits of `call`'s target that its constraints keep, each with a
    /// note of the values it was judged by.
    pub(crate) fn constrain(&self, call: &CompiledCall, hits: Vec<Hit>) -> Result<Vec<Hit>> {
        if hits.is_empty() {
            return Ok(hits);
        }
        let located = Located {
            sets: call
                .constraints
                .iter()
                .map(|c| match c {
                    CompiledConstraint::Value { want: CompiledWant::Ret(q) | CompiledWant::Field(q), .. } => {
                        self.locate_compiled(q).map(Some)
                    }
                    _ => Ok(None),
                })
                .collect::<Result<_>>()?,
        };
        let dex = self.dex;
        let bounds = self.insn_locator()?.method_bounds();
        let mut out = Vec::with_capacity(hits.len());
        let mut rest = hits.as_slice();
        ANALYZER.with(|an| -> Result<()> {
            let mut an = an.borrow_mut();
            while let Some(first) = rest.first() {
                // Hits arrive in offset order: those of one method are adjacent.
                let method = owner(first);
                let start = method.and_then(|m| bounds.get(m as usize)).copied();
                let n = rest.iter().take_while(|h| owner(h) == method).count();
                let (group, tail) = rest.split_at(n);
                rest = tail;
                let Some(start) = start.filter(|&s| s != u32::MAX) else { continue };
                let code = start.checked_sub(16).and_then(|off| dex.code_item(off).ok());
                let catches = code.as_ref().map(catches_of).unwrap_or_default();
                let mut values = code.as_ref().and_then(|c| {
                    an.analyze(MethodCode { insns: c.insns, registers: c.registers_size, ins: c.ins_size, catches: &catches })
                });
                for hit in group {
                    let pc = (hit.offset - start) as usize;
                    if let Some(note) = judge(dex, call, &located, values.as_mut(), hit, pc)? {
                        // Keep a dispatch label of the target after the values.
                        let note = match &hit.note {
                            Some(label) => format!("{note} {label}"),
                            None => note,
                        };
                        out.push(Hit { note: Some(note), ..hit.clone() });
                    }
                }
            }
            Ok(())
        })?;
        Ok(out)
    }
}

/// The first method owning a hit's instruction (methods sharing a code item
/// share its values too).
fn owner(hit: &Hit) -> Option<u32> {
    hit.methods.as_ref().and_then(|m| m.ids().first().copied())
}

/// The try ranges of `code` with each of their handlers, in byte offsets.
fn catches_of(code: &asc_dex::code::CodeItem<'_>) -> Vec<Catch> {
    let mut out = Vec::new();
    for t in &code.tries {
        let Some(h) = code.handlers.iter().find(|h| h.offset == t.handler_off) else { continue };
        let (start, end) = (t.start_addr as usize * 2, (t.start_addr as usize + usize::from(t.insn_count)) * 2);
        for addr in h.catches.iter().map(|&(_, a)| a).chain(h.catch_all_addr) {
            out.push(Catch { start, end, handler: addr as usize * 2 });
        }
    }
    out
}

/// The note of a site every constraint lets through (`[arg1="x"]`, `?`
/// first when one is undetermined), `None` for a site to drop.
fn judge(
    dex: &Dex<'_>,
    call: &CompiledCall,
    located: &Located,
    mut values: Option<&mut MethodValues<'_>>,
    hit: &Hit,
    pc: usize,
) -> Result<Option<String>> {
    let args = values.as_mut().and_then(|v| v.args(pc));
    let regs = register_slots(dex, hit.matched_idx, dex.buf().get(hit.offset as usize).copied())?;
    let mut note = String::from("[");
    let mut undetermined = false;
    for (i, c) in call.constraints.iter().enumerate() {
        if i > 0 {
            note.push_str(", ");
        }
        let (verdict, certainty) = match c {
            CompiledConstraint::Value { slot, want, certainty } => {
                let cands = regs.as_ref().and_then(|r| r.position(*slot)).and_then(|p| args.as_ref().and_then(|a| a.get(p)));
                match slot {
                    Slot::This => note.push_str("this="),
                    Slot::Arg(n) => {
                        let _ = write!(note, "arg{n}=");
                    }
                }
                let verdict = match cands {
                    // A static call has no receiver; a call the proto does not
                    // cover has no such argument.
                    None if regs.as_ref().is_some_and(|r| r.position(*slot).is_none()) => Verdict::Fails,
                    None => {
                        note.push('?');
                        if matches!(want, CompiledWant::Any) {
                            Verdict::Holds
                        } else {
                            Verdict::Undetermined
                        }
                    }
                    Some(cands) => {
                        render(dex, cands, &mut note)?;
                        matches(dex, want, located.sets[i].as_ref(), cands)?
                    }
                };
                (verdict, *certainty)
            }
            CompiledConstraint::Result { want, certainty } => {
                let used = values.as_mut().map_or(ResultUse::Unknown, |v| v.result_use(pc));
                note.push_str(match used {
                    ResultUse::Used => "ret=used",
                    ResultUse::Unused => "ret=unused",
                    ResultUse::Unknown => "ret=?",
                });
                let verdict = match (used, want) {
                    (ResultUse::Unknown, _) => Verdict::Undetermined,
                    (ResultUse::Used, ResultWant::Used) | (ResultUse::Unused, ResultWant::Unused) => Verdict::Holds,
                    (ResultUse::Used, ResultWant::Unused) | (ResultUse::Unused, ResultWant::Used) => Verdict::Fails,
                };
                (verdict, *certainty)
            }
        };
        match (verdict, certainty) {
            (Verdict::Holds, _) => {}
            (Verdict::Undetermined, Certainty::May) => undetermined = true,
            (Verdict::Fails, _) | (Verdict::Undetermined, Certainty::Must) => return Ok(None),
        }
    }
    note.push(']');
    if undetermined {
        note.insert(0, '?');
    }
    Ok(Some(note))
}

/// Where the receiver and each declared parameter sit among an invoke's
/// argument registers.
struct RegisterSlots {
    /// Whether the first register is the receiver.
    receiver: bool,
    /// The register position of each declared parameter.
    params: Vec<usize>,
}

impl RegisterSlots {
    fn position(&self, slot: Slot) -> Option<usize> {
        match slot {
            Slot::This => self.receiver.then_some(0),
            Slot::Arg(n) => self.params.get(usize::from(n)).copied(),
        }
    }
}

/// The argument layout of a call to `method` by the invoke `opcode`; `None`
/// when the method's prototype cannot be read.
fn register_slots(dex: &Dex<'_>, method: u32, opcode: Option<u8>) -> Result<Option<RegisterSlots>> {
    let Ok(id) = dex.method_id(method) else { return Ok(None) };
    let Ok(params) = dex.proto_params(u32::from(id.proto_idx)) else { return Ok(None) };
    // invoke-static and invoke-static/range pass no receiver.
    let receiver = !matches!(opcode, Some(0x71 | 0x77));
    let mut pos = usize::from(receiver);
    let mut out = Vec::with_capacity(params.len());
    for t in params {
        out.push(pos);
        pos += if matches!(dex.type_bytes(u32::from(t))?.first(), Some(b'J' | b'D')) { 2 } else { 1 };
    }
    Ok(Some(RegisterSlots { receiver, params: out }))
}

/// How `want` judges the candidate values of one register.
fn matches(dex: &Dex<'_>, want: &CompiledWant, located: Option<&BTreeSet<u32>>, cands: &Candidates) -> Result<Verdict> {
    if matches!(want, CompiledWant::Any) {
        return Ok(Verdict::Holds);
    }
    for v in cands.as_slice() {
        let hit = match (want, v) {
            (CompiledWant::Int(n), Value::Const(c)) => n == c,
            (CompiledWant::Str(s), Value::String(i)) => dex.string_bytes(*i)? == s.as_slice(),
            (CompiledWant::StrRegex(re), Value::String(i)) => re.is_match(&dex.string(*i)?),
            (CompiledWant::Class(d), Value::Class(t)) | (CompiledWant::New(d), Value::NewInstance(t)) => {
                dex.type_bytes(*t)? == d.as_slice()
            }
            (CompiledWant::Param(k), Value::Param(p)) => k.is_none_or(|k| k == *p),
            (CompiledWant::Ret(_), Value::Ret { method, .. }) => located.is_some_and(|s| s.contains(method)),
            (CompiledWant::Field(_), Value::Field { field, .. }) => located.is_some_and(|s| s.contains(field)),
            _ => false,
        };
        if hit {
            return Ok(Verdict::Holds);
        }
    }
    Ok(if cands.is_determined() { Verdict::Fails } else { Verdict::Undetermined })
}

/// The candidates of one register, `|`-separated.
fn render(dex: &Dex<'_>, cands: &Candidates, out: &mut String) -> Result<()> {
    for (i, v) in cands.as_slice().iter().enumerate() {
        if i > 0 {
            out.push('|');
        }
        match *v {
            Value::Const(c) => {
                let _ = write!(out, "{c}");
            }
            Value::String(s) => {
                let s = dex.string(s)?;
                match s.char_indices().nth(MAX_NOTE_STRING) {
                    Some((cut, _)) => {
                        let _ = write!(out, "{:?}…", &s[..cut]);
                    }
                    None => {
                        let _ = write!(out, "{s:?}");
                    }
                }
            }
            Value::Class(t) => {
                let _ = write!(out, "class:{}", dex.type_descriptor(t)?);
            }
            Value::Param(p) => {
                let _ = write!(out, "param{p}");
            }
            Value::Ret { method, .. } => {
                let _ = write!(out, "ret:{}", dex.method_display(method)?);
            }
            Value::Field { field, .. } => {
                let _ = write!(out, "field:{}", dex.field_display(field)?);
            }
            Value::NewInstance(t) => {
                let _ = write!(out, "new:{}", dex.type_descriptor(t)?);
            }
            Value::Unknown => out.push('?'),
        }
    }
    Ok(())
}
