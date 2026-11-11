//! Measurement of call-site resolution: where the callee of each call comes
//! from, before and after captured variables are resolved, and why the ones
//! that stay unresolved do (`docs/ark-abc-design.md` §7).
//!
//! Not a query: it exists so that the resolution rate can be stated, and so
//! that resolved captured variables can be sampled and checked by hand.

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::atomic::AtomicBool;

use asc_abc::ClassEntry;

use crate::path::{FrameOf, Link, Names, NoLexicals, Origin, Path, PathBuilder};
use crate::refs::{RECORD_CHUNK, Regions, chunks, pc_of, run_units};
use crate::scopes::{RecordScopes, ScopeStats, ScopeTables, Unresolved};
use crate::track::{Source, Tracker};
use crate::{Engine, EngineError, Result};

/// Where the callee of a call site comes from. Property and element links
/// count for their base; a callee that is (a member of) what another call
/// returned is [`CalleeRoot::CallResult`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CalleeRoot {
    Import,
    Global,
    This,
    /// A function or class defined in the record, a module-level binding,
    /// the parent class.
    Local,
    /// The `this` of an enclosing function, through a captured variable.
    CapturedThis,
    /// A parameter of an enclosing function, through a captured variable.
    CapturedArgument,
    /// A captured variable that is not resolved.
    Lexical,
    Argument,
    CallResult,
    /// Anything else computed in the block.
    Other,
    /// Set in another block.
    CrossBlock,
}

impl CalleeRoot {
    pub const ALL: [CalleeRoot; 11] = [
        CalleeRoot::Import,
        CalleeRoot::Global,
        CalleeRoot::This,
        CalleeRoot::Local,
        CalleeRoot::CapturedThis,
        CalleeRoot::CapturedArgument,
        CalleeRoot::Lexical,
        CalleeRoot::Argument,
        CalleeRoot::CallResult,
        CalleeRoot::Other,
        CalleeRoot::CrossBlock,
    ];

    fn of(path: &Path) -> CalleeRoot {
        if path.cut {
            return CalleeRoot::Other;
        }
        if path.links.iter().any(|link| matches!(link, Link::Call { .. })) {
            return CalleeRoot::CallResult;
        }
        match path.origin {
            Origin::Import(_) | Origin::Namespace(_) => CalleeRoot::Import,
            Origin::Global(_) | Origin::GlobalObject => CalleeRoot::Global,
            Origin::This(FrameOf::Own) => CalleeRoot::This,
            Origin::This(FrameOf::Captured(_)) => CalleeRoot::CapturedThis,
            Origin::Definition(_) | Origin::ModuleLocal(_) | Origin::Super(_) => CalleeRoot::Local,
            Origin::Argument(FrameOf::Own, _) => CalleeRoot::Argument,
            Origin::Argument(FrameOf::Captured(_), _) => CalleeRoot::CapturedArgument,
            Origin::Lexical { .. } | Origin::Slot { .. } => CalleeRoot::Lexical,
            Origin::Unknown => CalleeRoot::CrossBlock,
            Origin::Computed
            | Origin::Function(_)
            | Origin::NewTarget(_)
            | Origin::Str(_)
            | Origin::Int(_)
            | Origin::Float(_)
            | Origin::Constant(_) => CalleeRoot::Other,
        }
    }
}

/// A call site whose callee starts at a captured variable that resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCapture {
    pub entry: String,
    pub record: String,
    /// Raw name of the function that holds the call.
    pub function: String,
    /// Offset of the call instruction in the function's code.
    pub call_pc: u32,
    /// Offset of the `ldlexvar` the callee starts at.
    pub load_pc: u32,
    pub level: u32,
    pub slot: u32,
    /// The callee path as `call:` prints it.
    pub callee: String,
    /// Raw name of the function that holds the one store.
    pub writer: String,
    /// Offset of the store instruction in the writer's code.
    pub writer_pc: u32,
    /// File offset of the first instruction of `function`: with a pc, the
    /// file offset an official disassembly prints.
    pub function_code: u32,
    /// File offset of the first instruction of `writer`.
    pub writer_code: u32,
}

/// What [`Engine::call_resolution`] counted.
#[derive(Debug, Clone, Default)]
pub struct CallResolution {
    /// Records looked at.
    pub records: usize,
    /// Records whose captured variables had to be worked out.
    pub scoped_records: usize,
    pub call_sites: usize,
    /// Call sites per root, captured variables left alone.
    pub before: BTreeMap<CalleeRoot, usize>,
    /// Call sites per root, captured variables resolved.
    pub after: BTreeMap<CalleeRoot, usize>,
    /// Callees that start at a captured variable.
    pub captured: usize,
    pub captured_resolved: usize,
    /// The others, by reason.
    pub captured_unresolved: BTreeMap<Unresolved, usize>,
    /// Totals of the per-record passes.
    pub scopes: ScopeStats,
    /// With [`ResolutionOptions::samples`]: every resolved one.
    pub samples: Vec<ResolvedCapture>,
}

impl CallResolution {
    fn merge(&mut self, other: CallResolution) {
        self.records += other.records;
        self.scoped_records += other.scoped_records;
        self.call_sites += other.call_sites;
        for (root, count) in other.before {
            *self.before.entry(root).or_default() += count;
        }
        for (root, count) in other.after {
            *self.after.entry(root).or_default() += count;
        }
        self.captured += other.captured;
        self.captured_resolved += other.captured_resolved;
        for (why, count) in other.captured_unresolved {
            *self.captured_unresolved.entry(why).or_default() += count;
        }
        self.scopes.add(&other.scopes);
        self.samples.extend(other.samples);
    }
}

/// What [`Engine::call_resolution`] looks at.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResolutionOptions<'q> {
    /// Only records whose name contains this (`&entry/` for an
    /// application's own code).
    pub records: Option<&'q str>,
    /// Also list every resolved captured callee.
    pub samples: bool,
}

/// File offset of the first instruction of the method at `method`; 0 when
/// it has no readable code.
fn code_start(abc: &asc_abc::Abc<'_>, method: u32) -> u32 {
    let code = abc.method(method).ok().and_then(|method| method.code().ok().flatten());
    code.map_or(0, |code| code.instructions_off())
}

impl Engine {
    /// Count the call sites of the program by where their callee comes
    /// from. Every record's captured variables are worked out, so this
    /// costs what an unfiltered `call:` search costs.
    ///
    /// # Errors
    /// [`EngineError::Abc`] for an entry whose class index cannot be read,
    /// [`EngineError::Cancelled`].
    pub fn call_resolution(&self, options: &ResolutionOptions<'_>, cancel: &AtomicBool) -> Result<CallResolution> {
        let mut total = CallResolution::default();
        let tables = ScopeTables::new();
        for (index, abc) in self.program.readable() {
            let entry = self.program.info(index).map_or("", |info| info.name.as_str());
            let regions = Regions::of(&abc);
            let classes: Vec<u32> =
                abc.class_index().map_err(|source| EngineError::Abc { entry: entry.to_owned(), source })?.iter().collect();
            let units: Vec<Range<usize>> = chunks(classes.len(), RECORD_CHUNK).collect();
            let counted = run_units(units.len(), self.threads(), cancel, |unit| {
                let mut out = CallResolution::default();
                let mut tracker = Tracker::default();
                let mut scopes = RecordScopes::new(abc, &regions, &tables);
                let (mut before, mut after, mut text) = (Path::default(), Path::default(), String::new());
                for &off in &classes[units[unit].clone()] {
                    let Ok(ClassEntry::Local(class)) = abc.class_entry(off) else { continue };
                    let record = String::from_utf8_lossy(class.name());
                    if options.records.is_some_and(|part| !record.contains(part)) {
                        continue;
                    }
                    out.records += 1;
                    scopes.enter(&class);
                    let module = class.module_record().ok().flatten();
                    let names = Names { abc: &abc, module: module.as_ref() };
                    let Ok(methods) = class.methods() else { continue };
                    for method in methods.map_while(|method| method.ok()) {
                        let Some(function) = regions.function(abc, &method) else { continue };
                        let lexicals = scopes.of_function(method.offset());
                        let entity = |id: u32| function.entity(id);
                        // Code that does not decode has no call sites to count.
                        let _ = tracker.run(tables.effects(), &function.code, |frame, insn, site| {
                            out.call_sites += 1;
                            PathBuilder { frame, function: method.offset(), entity: &entity, lexicals: &NoLexicals }
                                .build(site.callee, &mut before);
                            *out.before.entry(CalleeRoot::of(&before)).or_default() += 1;
                            PathBuilder { frame, function: method.offset(), entity: &entity, lexicals: &lexicals }
                                .build(site.callee, &mut after);
                            scopes.reduce(&mut after);
                            *out.after.entry(CalleeRoot::of(&after)).or_default() += 1;
                            let Origin::Lexical { level, slot, sendable } = before.origin else { return };
                            if before.cut {
                                return;
                            }
                            out.captured += 1;
                            // The `ldlexvar` is where the chain of the callee starts.
                            let mut root = frame.value(site.callee);
                            while let Source::Property { base, .. }
                            | Source::Element { base, .. }
                            | Source::CallResult { callee: base, .. } = root.source
                            {
                                root = frame.value(base);
                            }
                            let resolved = if sendable { Err(Unresolved::Sendable) } else { lexicals.written(root.pc, level, slot) };
                            match resolved {
                                Err(why) => *out.captured_unresolved.entry(why).or_default() += 1,
                                Ok(written) => {
                                    out.captured_resolved += 1;
                                    if options.samples {
                                        text.clear();
                                        names.write(&mut text, &after);
                                        out.samples.push(ResolvedCapture {
                                            entry: entry.to_owned(),
                                            record: record.clone().into_owned(),
                                            function: names.function(Some(method.offset())),
                                            call_pc: pc_of(insn),
                                            load_pc: root.pc,
                                            level,
                                            slot,
                                            callee: text.clone(),
                                            writer: names.function(Some(written.writer.method)),
                                            writer_pc: written.writer.pc,
                                            function_code: function.code.instructions_off(),
                                            writer_code: code_start(&abc, written.writer.method),
                                        });
                                    }
                                }
                            }
                        });
                    }
                    if let Some(built) = scopes.is_built().then(|| scopes.get()).flatten() {
                        out.scoped_records += 1;
                        out.scopes.add(built.stats());
                    }
                }
                out
            })?;
            counted.into_iter().for_each(|part| total.merge(part));
        }
        Ok(total)
    }
}
