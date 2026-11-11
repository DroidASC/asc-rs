//! The environment pass over one function: which `newlexenv` sites are
//! open at each instruction (see the parent module for the rules).

use std::collections::HashMap;

use asc_arkisa::{DecodeError, OperandKind};

use super::{DefinitionKind, FnId, Scopes, SiteId, StackRef};
use crate::ops::{OpTable, base_name};
use crate::refs::Function;
use crate::track::Effects;

/// Sweeps of the data-flow pass over one function; structured code needs two.
const MAX_SWEEPS: usize = 16;
/// Environments one function may have open at once.
const MAX_DEPTH: usize = 64;

/// The instructions the environment pass looks at.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum EnvOp {
    #[default]
    None,
    Push,
    Pop,
    /// `ldlexvar` / `stlexvar`: the stack is recorded for it.
    Access,
    /// A store the value pass has to see.
    Store,
    /// Creates function objects: a method id and / or a literal array.
    Define {
        /// The functions do not capture the frame's environment.
        sealed: bool,
    },
    /// Environments handled as values: not followed.
    Opaque,
}

impl EnvOp {
    fn of(opcode: &asc_arkisa::Opcode) -> EnvOp {
        match base_name(opcode) {
            "newlexenv" | "newlexenvwithname" => EnvOp::Push,
            "poplexenv" => EnvOp::Pop,
            "ldlexvar" | "stlexvar" => EnvOp::Access,
            "stmodulevar" | "stsendablevar" => EnvOp::Store,
            "deprecated.ldlexenv" | "deprecated.poplexenv" | "deprecated.stlexvar" => EnvOp::Opaque,
            "definesendableclass" => EnvOp::Define { sealed: true },
            _ if opcode.operand_of(OperandKind::MethodId).is_some() || opcode.operand_of(OperandKind::LiteralArrayId).is_some() => {
                EnvOp::Define { sealed: opcode.prefix == Some(asc_arkisa::Prefix::Deprecated) }
            }
            _ => EnvOp::None,
        }
    }

    fn is_store(self, opcode: &asc_arkisa::Opcode) -> bool {
        match self {
            EnvOp::Store => true,
            EnvOp::Access | EnvOp::Opaque => matches!(base_name(opcode), "stlexvar" | "deprecated.stlexvar"),
            EnvOp::None | EnvOp::Push | EnvOp::Pop | EnvOp::Define { .. } => false,
        }
    }
}

/// The per-opcode tables of the pass, built once per search.
pub(crate) struct ScopeTables {
    pub(super) ops: OpTable<EnvOp>,
    /// Whether an instruction can raise an exception: only those have an
    /// edge to the handler that covers them.
    may_throw: OpTable<bool>,
    effects: Effects,
}

impl ScopeTables {
    pub(crate) fn new() -> ScopeTables {
        ScopeTables { ops: OpTable::build(EnvOp::of), may_throw: OpTable::build(may_throw), effects: Effects::new() }
    }

    /// The tracker's tables, for the scan that uses these.
    pub(crate) fn effects(&self) -> &Effects {
        &self.effects
    }
}

/// Whether `opcode` can raise an exception. Moves between registers and the
/// accumulator, constants, jumps, returns, the environment instructions and
/// the settling of an async function's promise cannot; everything else is
/// taken to.
fn may_throw(opcode: &asc_arkisa::Opcode) -> bool {
    let quiet = matches!(
        base_name(opcode),
        "mov"
            | "lda"
            | "sta"
            | "ldai"
            | "fldai"
            | "lda.str"
            | "ldundefined"
            | "ldnull"
            | "ldtrue"
            | "ldfalse"
            | "ldhole"
            | "ldnan"
            | "ldinfinity"
            | "ldthis"
            | "ldfunction"
            | "ldnewtarget"
            | "nop"
            | "newlexenv"
            | "newlexenvwithname"
            | "poplexenv"
            | "ldlexvar"
            | "stlexvar"
            | "return"
            | "returnundefined"
            // Settling the promise of an async function does not raise: an abrupt
            // `then` lookup rejects the promise instead. Compilers rely on it and
            // pop the loop environment before these, inside the try range.
            | "asyncfunctionresolve"
            | "asyncfunctionreject"
    );
    !(quiet || opcode.is_jump())
}

/// Union-find over environment sites.
#[derive(Debug, Default)]
pub(super) struct Sites {
    pub parent: Vec<SiteId>,
    /// The function that holds each site.
    pub function: Vec<FnId>,
}

impl Sites {
    fn add(&mut self, function: FnId) -> SiteId {
        let id = u32::try_from(self.parent.len()).unwrap_or(u32::MAX);
        self.parent.push(id);
        self.function.push(function);
        id
    }

    pub(super) fn find(&mut self, mut site: SiteId) -> SiteId {
        while let Some(&parent) = self.parent.get(site as usize) {
            if parent == site {
                break;
            }
            let grand = self.parent.get(parent as usize).copied().unwrap_or(parent);
            self.parent[site as usize] = grand;
            site = grand;
        }
        site
    }

    pub(super) fn union(&mut self, a: SiteId, b: SiteId) {
        let (a, b) = (self.find(a), self.find(b));
        if a != b
            && let Some(parent) = self.parent.get_mut(a.max(b) as usize)
        {
            *parent = a.min(b);
        }
    }
}

/// A handler range of a function.
struct TryRange {
    start: usize,
    end: usize,
    handlers: Vec<usize>,
    catches_all: bool,
}

/// The state of the environment pass over one function.
struct Flow<'s> {
    sites: &'s mut Sites,
    function: FnId,
    /// The site of each `newlexenv` of the function, by pc.
    made: Vec<(usize, SiteId)>,
    /// The stack on entry to each jump target and handler seen so far.
    inbound: HashMap<usize, Vec<SiteId>>,
    /// One bit per code offset: whether `inbound` has it.
    targets: Vec<u64>,
    /// A target at or before the instruction that reached it got its first
    /// stack: the sweep has to be repeated.
    grew: bool,
}

/// The function's environments cannot be followed.
struct NotFollowed;

impl Flow<'_> {
    fn site(&mut self, pc: usize) -> SiteId {
        if let Some(&(_, site)) = self.made.iter().find(|&&(at, _)| at == pc) {
            return site;
        }
        let site = self.sites.add(self.function);
        self.made.push((pc, site));
        site
    }

    fn is_target(&self, pc: usize) -> bool {
        self.targets.get(pc / 64).is_some_and(|word| word >> (pc % 64) & 1 != 0)
    }

    /// `stack` flows from the instruction at `from` into `pc`.
    fn join(&mut self, from: usize, pc: usize, stack: &[SiteId]) -> Result<(), NotFollowed> {
        match self.inbound.get(&pc) {
            None => {
                // A target outside the code is never walked.
                let Some(word) = self.targets.get_mut(pc / 64) else { return Ok(()) };
                *word |= 1 << (pc % 64);
                self.inbound.insert(pc, stack.to_vec());
                // A target further on is picked up by this sweep.
                self.grew |= pc <= from;
            }
            Some(known) if known.len() != stack.len() => return Err(NotFollowed),
            Some(known) => {
                for (&a, &b) in known.iter().zip(stack) {
                    self.sites.union(a, b);
                }
            }
        }
        Ok(())
    }

    /// An exception at `pc` with `stack`: it goes to the first try block
    /// that covers `pc`, and on to the next one only when that one does not
    /// catch everything.
    fn throw(&mut self, tries: &[TryRange], pc: usize, stack: &[SiteId]) -> Result<(), NotFollowed> {
        for block in tries.iter().filter(|block| block.start <= pc && pc < block.end) {
            for &handler in &block.handlers {
                self.join(pc, handler, stack)?;
            }
            if block.catches_all {
                break;
            }
        }
        Ok(())
    }
}

/// What the scan of one function found besides its stacks.
#[derive(Default)]
pub(super) struct Found {
    /// `(pc, stack)` of the instructions that need one, by ascending pc;
    /// the stacks are runs of `pool`.
    pub stacks: Vec<(u32, StackRef)>,
    pub pool: Vec<SiteId>,
    /// `(pc, kind, child method offset, sealed)`.
    pub definitions: Vec<(u32, DefinitionKind, u32, bool)>,
    pub has_store: bool,
}

impl Scopes {
    /// The environments and definitions of one function.
    ///
    /// `Err(Some(_))` is code that does not decode, `Err(None)` a shape that
    /// is not followed; the definitions found are kept either way.
    pub(super) fn scan(
        &mut self,
        function: &Function<'_, '_>,
        id: FnId,
        tables: &ScopeTables,
        sites: &mut Sites,
        found: &mut Found,
    ) -> Result<bool, Option<DecodeError>> {
        let code = function.code.instructions();
        // Most functions make no environment: one walk settles them.
        let mut makes_environments = false;
        for insn in asc_arkisa::walk(code) {
            let insn = insn.map_err(Some)?;
            let op = tables.ops.of(insn.opcode);
            found.has_store |= op.is_store(insn.opcode);
            match op {
                EnvOp::Push | EnvOp::Pop | EnvOp::Opaque => makes_environments = true,
                EnvOp::Define { sealed } => self.definitions_of(function, &insn, sealed, found),
                EnvOp::None | EnvOp::Access | EnvOp::Store => {}
            }
        }
        if !makes_environments {
            return Ok(false);
        }

        let mut tries = Vec::new();
        for block in function.code.try_blocks() {
            // A try table that does not read hides exception edges.
            let block = block.map_err(|_| None)?;
            let handlers: Vec<_> = block.catch_blocks().collect();
            tries.push(TryRange {
                start: block.start_pc as usize,
                end: (block.start_pc as usize).saturating_add(block.length as usize),
                catches_all: handlers.iter().any(|catch| catch.type_idx.is_none()),
                handlers: handlers.iter().map(|catch| catch.handler_pc as usize).collect(),
            });
        }
        let targets = vec![0; code.len() / 64 + 1];
        let mut flow = Flow { sites, function: id, made: Vec::new(), inbound: HashMap::new(), targets, grew: true };
        let mut sweeps = 0;
        while flow.grew {
            flow.grew = false;
            sweeps += 1;
            if sweeps > MAX_SWEEPS {
                return Err(None);
            }
            found.stacks.clear();
            found.pool.clear();
            let mut current: Option<Vec<SiteId>> = Some(Vec::new());
            // The run of `found.pool` that holds `current`, until it changes.
            let mut recorded: Option<StackRef> = None;
            for insn in asc_arkisa::walk(code) {
                let insn = insn.map_err(Some)?;
                let pc = insn.pc;
                if flow.is_target(pc) {
                    if let Some(stack) = &current {
                        flow.join(pc, pc, stack).map_err(|NotFollowed| None)?;
                    }
                    current = flow.inbound.get(&pc).cloned();
                    recorded = None;
                }
                let Some(stack) = current.as_mut() else { continue };
                // An instruction that raises does so before it changes the stack.
                if !tries.is_empty() && tables.may_throw.of(insn.opcode) {
                    flow.throw(&tries, pc, stack).map_err(|NotFollowed| None)?;
                }
                match tables.ops.of(insn.opcode) {
                    EnvOp::Push => {
                        if stack.len() >= MAX_DEPTH {
                            return Err(None);
                        }
                        stack.push(flow.site(pc));
                        recorded = None;
                    }
                    // Popping an environment the function did not make leaves its chain: not followed.
                    EnvOp::Pop => {
                        stack.pop().ok_or(None)?;
                        recorded = None;
                    }
                    EnvOp::Opaque => return Err(None),
                    EnvOp::Access | EnvOp::Define { .. } => {
                        let run = *recorded.get_or_insert_with(|| {
                            let start = u32::try_from(found.pool.len()).unwrap_or(u32::MAX);
                            found.pool.extend_from_slice(stack);
                            StackRef { start, len: u32::try_from(stack.len()).unwrap_or(0) }
                        });
                        found.stacks.push((crate::refs::pc_of(&insn), run));
                    }
                    EnvOp::None | EnvOp::Store => {}
                }
                if let Some(target) = insn.jump_target() {
                    flow.join(pc, target, stack).map_err(|NotFollowed| None)?;
                }
                if insn.opcode.is_terminator() {
                    current = None;
                }
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_instructions_are_classified() {
        let op = |name: &str| asc_arkisa::opcodes().find(|op| op.name == name).map(EnvOp::of).unwrap();
        assert_eq!((op("newlexenv"), op("wide.newlexenvwithname"), op("poplexenv")), (EnvOp::Push, EnvOp::Push, EnvOp::Pop));
        assert_eq!((op("wide.ldlexvar"), op("stlexvar")), (EnvOp::Access, EnvOp::Access));
        assert_eq!(op("deprecated.ldlexenv"), EnvOp::Opaque);
        assert_eq!(op("definefunc"), EnvOp::Define { sealed: false });
        assert_eq!(op("createobjectwithbuffer"), EnvOp::Define { sealed: false });
        assert_eq!(op("callruntime.definesendableclass"), EnvOp::Define { sealed: true });
        assert_eq!(op("deprecated.defineclasswithbuffer"), EnvOp::Define { sealed: true });
        assert_eq!(op("callruntime.newsendableenv"), EnvOp::None);
        // Every store the tracker reports is a store here, so the value pass visits its function.
        for opcode in asc_arkisa::opcodes() {
            let stores = matches!(base_name(opcode), "stlexvar" | "deprecated.stlexvar" | "stsendablevar" | "stmodulevar");
            assert_eq!(EnvOp::of(opcode).is_store(opcode), stores, "{}", opcode.name);
        }
    }

    #[test]
    fn sites_merge_into_the_lowest() {
        let mut sites = Sites::default();
        let ids: Vec<_> = (0..4).map(|_| sites.add(0)).collect();
        sites.union(ids[3], ids[1]);
        sites.union(ids[2], ids[3]);
        assert_eq!((sites.find(ids[3]), sites.find(ids[2]), sites.find(ids[0])), (ids[1], ids[1], ids[0]));
    }
}
