//! The lexical environments of one record: what each captured variable
//! holds, when that can be proved.
//!
//! A closure reads the variables it captures with `ldlexvar level, slot`:
//! `level` environments outward from the current one, variable `slot`. The
//! instruction says nothing about what is stored there. This module finds
//! out, for one record at a time and only from that record's code:
//!
//! 1. **Environments.** Every `newlexenv` instruction is an environment
//!    *site*. A forward data-flow pass over each function gives the stack of
//!    sites that are current at each instruction (`newlexenv` pushes,
//!    `poplexenv` pops; exception edges go to the first handler that covers
//!    an instruction). Where two paths meet with different sites at the same
//!    depth (a loop that makes a fresh environment per iteration), the sites
//!    are merged into one class: an environment is identified by the class
//!    of the site that made it. Paths that meet with different depths, a pop
//!    below the function's own environments, the `deprecated.` forms that
//!    pass environments in registers, and code that does not decode leave
//!    the function without environment identities.
//! 2. **Nesting.** A function object captures the environment that is
//!    current where it is created (`definefunc`, `definemethod`, a class
//!    definition with its constructor and the methods of its literal array,
//!    an object literal with methods). So the chain a function starts with
//!    is the stack at its definition followed by the chain of the defining
//!    function; `func_main_0` starts with nothing. A function that nothing
//!    in the record defines, or that is defined in places whose chains do
//!    not have the same shape, or whose environment does not come from the
//!    frame (sendable classes, the `deprecated.` definitions), has an
//!    unknown chain: only the environments it makes itself are identified.
//! 3. **Writers.** Every `stlexvar` is mapped to the class and slot it
//!    writes. A variable is resolved when exactly one store instruction of
//!    the record can write it and the value it stores is known at that
//!    instruction ([`crate::track`]). A store that copies the variable
//!    into itself (`ldlexvar 0, s; poplexenv; newlexenv; stlexvar 0, s`,
//!    how a loop hands its variables to the next iteration's environment)
//!    is not a writer. A store whose target is not
//!    identified taints the slot number in every environment it could reach
//!    (the ones of its function and of the functions around it; of the
//!    whole record when those are not known either).
//!
//! What this relies on: environments are only written by the store
//! instructions (`isa.yaml`), a suspended generator or async function
//! resumes with the environment it had, and a function object is created in
//! the record that holds its method. Sendable environments
//! (`callruntime.*sendablevar`) are a separate chain and are not modelled:
//! such variables stay unresolved.
//!
//! The same pass records what else of a record's structure is cheap to see
//! on the way: where each function is created, the members of each class
//! literal, and the unique writer of each module-level binding
//! (`stmodulevar`).

mod classes;
mod env;
mod reader;

use std::collections::{HashMap, HashSet};

use asc_abc::{Abc, Class, FunctionName, Method};
use asc_arkisa::OperandKind;

use classes::{class_literal, literal_methods};
pub(crate) use classes::{find_member, ClassInfo, Membership};
pub(crate) use env::ScopeTables;
use env::{Found, Sites};
pub(crate) use reader::{Reader, RecordScopes};

use crate::path::{Link, Origin, Path, PathBuilder};
use crate::refs::{Function, Regions};
use crate::table_bytes;
use crate::track::{Event, StoreTarget, Tracker, Watch};

/// Variables followed from one captured variable to the next before the
/// chain is given up.
const MAX_CHAIN: usize = 8;

/// Why a captured variable is not resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Unresolved {
    /// The environment the instruction reaches is not identified: see the
    /// module documentation for the code shapes that are given up.
    NoIdentity,
    /// The level reaches past the environments of the record.
    Outside,
    /// A sendable environment: not modelled.
    Sendable,
    /// No store of the record writes the variable.
    NoWriter,
    /// Several stores can write it.
    MultipleWriters,
    /// One store writes it, with a value the tracker cannot name.
    UnknownValue,
    /// A store whose target is not identified could write it.
    Tainted,
    /// It is written from another captured variable, more than
    /// [`MAX_CHAIN`] times over or in a cycle.
    Chain,
}

impl Unresolved {
    pub const ALL: [Unresolved; 8] = [
        Unresolved::NoIdentity,
        Unresolved::Outside,
        Unresolved::Sendable,
        Unresolved::NoWriter,
        Unresolved::MultipleWriters,
        Unresolved::UnknownValue,
        Unresolved::Tainted,
        Unresolved::Chain,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Unresolved::NoIdentity => "environment not identified",
            Unresolved::Outside => "outside the record",
            Unresolved::Sendable => "sendable environment",
            Unresolved::NoWriter => "no writer",
            Unresolved::MultipleWriters => "several writers",
            Unresolved::UnknownValue => "unknown written value",
            Unresolved::Tainted => "unidentified store may write it",
            Unresolved::Chain => "chain too long or cyclic",
        }
    }
}

/// What the pass over one record met.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScopeStats {
    /// Functions with code.
    pub functions: usize,
    /// Functions whose environment stack could not be followed.
    pub unidentified_functions: usize,
    /// Functions (other than `func_main_0`) nothing in the record defines.
    pub undefined_functions: usize,
    /// Functions whose starting chain is unknown, for any reason.
    pub unknown_chains: usize,
    /// Functions created at more than one place.
    pub redefined_functions: usize,
    /// `newlexenv` sites.
    pub sites: usize,
    /// Environment classes, after sites that meet were merged.
    pub environments: usize,
    /// Variables with exactly one writer and a known value.
    pub resolved_slots: usize,
    pub multi_writer_slots: usize,
    pub unknown_value_slots: usize,
    /// Stores whose target environment is not identified.
    pub unidentified_stores: usize,
    /// Definitions that name a method outside the record.
    pub foreign_definitions: usize,
    /// Class literals whose layout was not understood.
    pub odd_class_literals: usize,
}

impl ScopeStats {
    pub fn add(&mut self, other: &ScopeStats) {
        self.functions += other.functions;
        self.unidentified_functions += other.unidentified_functions;
        self.undefined_functions += other.undefined_functions;
        self.unknown_chains += other.unknown_chains;
        self.redefined_functions += other.redefined_functions;
        self.sites += other.sites;
        self.environments += other.environments;
        self.resolved_slots += other.resolved_slots;
        self.multi_writer_slots += other.multi_writer_slots;
        self.unknown_value_slots += other.unknown_value_slots;
        self.unidentified_stores += other.unidentified_stores;
        self.foreign_definitions += other.foreign_definitions;
        self.odd_class_literals += other.odd_class_literals;
    }
}

/// How a function object comes to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DefinitionKind {
    /// `definefunc` / `definemethod`.
    Function,
    /// The constructor of a class definition: the class itself.
    Class,
    /// A method item of the literal array of a class definition.
    ClassMember,
    /// A method item of an object literal.
    ObjectMember,
}

/// One place where a function object is created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Definition {
    /// Method offset of the function that holds the instruction.
    pub parent: u32,
    pub pc: u32,
    /// Method offset of the function that is created.
    pub child: u32,
    pub kind: DefinitionKind,
}

type FnId = u32;
type SiteId = u32;

/// A run of the stack pool: the environments open at one instruction,
/// innermost last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StackRef {
    start: u32,
    len: u32,
}

/// The environments a function makes itself, per instruction.
#[derive(Debug)]
enum Own {
    /// It makes none.
    Flat,
    /// The stack at each instruction that reads, writes or captures
    /// environments, by ascending pc.
    Mapped(Vec<(u32, StackRef)>),
    /// Not followed: see the module documentation.
    Failed,
}

/// Where a chain ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tail {
    /// At the top of the record: beyond is the runtime's.
    End,
    Unknown,
}

/// One place a function is created at.
#[derive(Debug, Clone, Copy)]
struct Definer {
    parent: FnId,
    /// The parent's stack there; `None` when the parent's is not followed.
    stack: Option<StackRef>,
    /// The function does not get the frame's environment.
    sealed: bool,
}

#[derive(Debug)]
struct FunctionScope {
    own: Own,
    /// The chain the function starts with, innermost first.
    captured: Vec<SiteId>,
    tail: Tail,
    definers: Vec<Definer>,
    has_store: bool,
    is_main: bool,
}

/// A slot of an environment class, or `None` for every slot of it.
type SlotKey = (SiteId, u32);

/// Which variables an unidentified store may have written.
#[derive(Debug, Default)]
struct Taints {
    /// Slot numbers (`None`: every slot) in every environment of the record.
    record: HashSet<Option<u32>>,
    /// The same, per function whose environments are affected.
    functions: HashSet<(FnId, Option<u32>)>,
}

/// A store instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StoreSite {
    /// Method offset of the function that holds it.
    pub method: u32,
    pub pc: u32,
}

/// The value of a variable and the one store that writes it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Written {
    pub path: Path,
    pub writer: StoreSite,
}

/// The stores that write one variable.
#[derive(Debug, Default)]
struct Writers {
    count: usize,
    /// The first one.
    first: Option<StoreSite>,
    /// Its value, when it is known.
    value: Option<Path>,
}

impl Writers {
    fn add(&mut self, at: StoreSite, value: Option<Path>) {
        self.count += 1;
        if self.count == 1 {
            self.first = Some(at);
            self.value = value;
        } else {
            self.value = None;
        }
    }

    fn state(self) -> Result<Written, Unresolved> {
        match (self.count, self.first, self.value) {
            (1, Some(writer), Some(path)) => Ok(Written { path, writer }),
            (1, _, _) => Err(Unresolved::UnknownValue),
            _ => Err(Unresolved::MultipleWriters),
        }
    }
}

/// See the module documentation.
#[derive(Debug, Default)]
pub(crate) struct Scopes {
    by_method: HashMap<u32, FnId>,
    functions: Vec<FunctionScope>,
    /// Environment classes of every recorded stack.
    pool: Vec<SiteId>,
    slots: HashMap<SlotKey, Result<Written, Unresolved>>,
    module_vars: HashMap<u32, Result<Written, Unresolved>>,
    classes: HashMap<u32, Option<ClassInfo>>,
    members: HashMap<u32, Option<Membership>>,
    definitions: Vec<Definition>,
    /// Slot numbers (`None`: every slot) an unidentified store may have
    /// written, in any environment of the record and per environment class.
    tainted_record: HashSet<Option<u32>>,
    tainted_envs: HashSet<(SiteId, Option<u32>)>,
    /// Some code of the record could not be read: it may hold a
    /// `stmodulevar` nobody saw.
    unread_code: bool,
    stats: ScopeStats,
}

impl Scopes {
    /// Bytes this takes on the heap, roughly.
    pub(crate) fn heap_bytes(&self) -> usize {
        use std::mem::size_of;
        let functions = self.functions.capacity() * size_of::<FunctionScope>()
            + self
                .functions
                .iter()
                .map(|function| {
                    let own = match &function.own {
                        Own::Mapped(stacks) => stacks.capacity() * size_of::<(u32, StackRef)>(),
                        Own::Flat | Own::Failed => 0,
                    };
                    own + function.captured.capacity() * size_of::<SiteId>() + function.definers.capacity() * size_of::<Definer>()
                })
                .sum::<usize>();
        let written =
            |state: &Result<Written, Unresolved>| state.as_ref().map_or(0, |written| written.path.links.capacity() * size_of::<Link>());
        let classes = self
            .classes
            .values()
            .flatten()
            .map(|class| (class.instance.capacity() + class.statics.capacity()) * size_of::<classes::Member>())
            .sum::<usize>();
        functions
            + table_bytes(&self.by_method)
            + self.pool.capacity() * size_of::<SiteId>()
            + table_bytes(&self.slots)
            + self.slots.values().map(written).sum::<usize>()
            + table_bytes(&self.module_vars)
            + self.module_vars.values().map(written).sum::<usize>()
            + table_bytes(&self.classes)
            + classes
            + table_bytes(&self.members)
            + self.definitions.capacity() * size_of::<Definition>()
            + self.tainted_record.capacity() * (size_of::<Option<u32>>() + 1)
            + self.tainted_envs.capacity() * (size_of::<(SiteId, Option<u32>)>() + 1)
    }

    /// Analyse `class`. `tracker` is scratch space.
    pub(crate) fn build<'a>(abc: Abc<'a>, regions: &Regions<'a>, class: &Class<'a>, tables: &ScopeTables, tracker: &mut Tracker) -> Scopes {
        let mut scopes = Scopes::default();
        let mut taints = Taints::default();
        let mut methods: Vec<Method<'a>> = Vec::new();
        match class.methods() {
            Ok(listed) => {
                for method in listed {
                    match method {
                        Ok(method) => methods.push(method),
                        // The functions past a malformed one are not seen: they could store anywhere.
                        Err(_) => {
                            taints.record.insert(None);
                            scopes.unread_code = true;
                            break;
                        }
                    }
                }
            }
            Err(_) => {
                taints.record.insert(None);
                scopes.unread_code = true;
            }
        }
        for method in &methods {
            let id = u32::try_from(scopes.functions.len()).unwrap_or(u32::MAX);
            let is_main = method.name().is_ok_and(|name| name.bytes == FunctionName::MAIN.as_bytes());
            scopes.functions.push(FunctionScope {
                own: Own::Flat,
                captured: Vec::new(),
                tail: Tail::Unknown,
                definers: Vec::new(),
                has_store: false,
                is_main,
            });
            scopes.by_method.entry(method.offset()).or_insert(id);
        }

        let mut sites = Sites::default();
        let functions: Vec<Option<Function<'_, 'a>>> = methods.iter().map(|method| regions.function(abc, method)).collect();
        for (id, function) in functions.iter().enumerate() {
            let id_u32 = u32::try_from(id).unwrap_or(u32::MAX);
            let Some(function) = function else {
                // No code: nothing to follow. Code that cannot be read: it could store anywhere.
                if !matches!(methods[id].code(), Ok(None)) {
                    scopes.functions[id].own = Own::Failed;
                    scopes.taint(&mut taints, id_u32, None);
                }
                continue;
            };
            scopes.stats.functions += 1;
            let mut found = Found::default();
            let followed = scopes.scan(function, id_u32, tables, &mut sites, &mut found);
            scopes.functions[id].has_store = found.has_store;
            let own = match followed {
                Ok(false) => Own::Flat,
                Ok(true) => {
                    let base = u32::try_from(scopes.pool.len()).unwrap_or(u32::MAX);
                    scopes.pool.extend_from_slice(&found.pool);
                    Own::Mapped(found.stacks.iter().map(|&(pc, stack)| (pc, StackRef { start: base + stack.start, ..stack })).collect())
                }
                Err(Some(_decode)) => {
                    scopes.taint(&mut taints, id_u32, None);
                    Own::Failed
                }
                Err(None) => Own::Failed,
            };
            if matches!(own, Own::Failed) {
                scopes.stats.unidentified_functions += 1;
            }
            scopes.functions[id].own = own;
            for &(pc, kind, child, sealed) in &found.definitions {
                scopes.definitions.push(Definition { parent: function.method.offset(), pc, child, kind });
                let Some(&child_id) = scopes.by_method.get(&child) else {
                    scopes.stats.foreign_definitions += 1;
                    continue;
                };
                let stack = scopes.own_stack(id_u32, pc).ok();
                scopes.functions[child_id as usize].definers.push(Definer { parent: id_u32, stack, sealed });
            }
        }

        scopes.link_chains(&mut sites);
        scopes.stats.sites = sites.parent.len();
        scopes.stats.environments = (0..sites.parent.len()).filter(|&site| sites.parent[site] as usize == site).count();
        // From here on a site stands for its class.
        let class_of: Vec<SiteId> = (0..sites.parent.len()).map(|site| sites.find(u32::try_from(site).unwrap_or(u32::MAX))).collect();
        let to_class = |site: &mut SiteId| *site = class_of.get(*site as usize).copied().unwrap_or(*site);
        scopes.pool.iter_mut().for_each(to_class);
        scopes.functions.iter_mut().flat_map(|function| function.captured.iter_mut()).for_each(to_class);

        let (slot_writers, module_writers) = scopes.collect_writers(&functions, tables, tracker, &mut taints);
        scopes.settle(slot_writers, module_writers, &taints, &sites, &class_of);
        scopes
    }

    fn stack(&self, stack: StackRef) -> &[SiteId] {
        self.pool.get(stack.start as usize..(stack.start + stack.len) as usize).unwrap_or_default()
    }

    /// The function's own environments at `pc`.
    fn own_stack(&self, function: FnId, pc: u32) -> Result<StackRef, Unresolved> {
        match &self.functions[function as usize].own {
            Own::Flat => Ok(StackRef { start: 0, len: 0 }),
            // An instruction the pass never reached has no stack.
            Own::Mapped(stacks) => {
                stacks.binary_search_by_key(&pc, |&(at, _)| at).map(|index| stacks[index].1).map_err(|_| Unresolved::NoIdentity)
            }
            Own::Failed => Err(Unresolved::NoIdentity),
        }
    }

    /// The environment class `level` levels out from instruction `pc` of
    /// `function`, and whether the function's own invocation made it.
    fn locate(&self, function: FnId, pc: u32, level: u32) -> Result<(SiteId, bool), Unresolved> {
        let own = self.stack(self.own_stack(function, pc)?);
        let level = level as usize;
        if let Some(index) = own.len().checked_sub(level + 1) {
            return Ok((own[index], true));
        }
        let scope = &self.functions[function as usize];
        match scope.captured.get(level - own.len()) {
            Some(&site) => Ok((site, false)),
            None if scope.tail == Tail::End => Err(Unresolved::Outside),
            None => Err(Unresolved::NoIdentity),
        }
    }

    /// The function objects `insn` creates.
    fn definitions_of(&mut self, function: &Function<'_, '_>, insn: &asc_arkisa::Instruction<'_>, sealed: bool, found: &mut Found) {
        let pc = crate::refs::pc_of(insn);
        let method = insn.method_id().and_then(|id| function.entity(id));
        let literal = insn.literal_array_id().and_then(|id| {
            let wide = insn.opcode.operand_of(OperandKind::LiteralArrayId).is_some_and(|operand| operand.width > 16);
            if wide {
                Some(id)
            } else {
                function.entity(id)
            }
        });
        let is_class = method.is_some() && literal.is_some();
        if let Some(method) = method {
            let kind = if is_class { DefinitionKind::Class } else { DefinitionKind::Function };
            found.definitions.push((pc, kind, method, sealed));
        }
        let Some(literal) = literal else { return };
        let before = found.definitions.len();
        let kind = if is_class { DefinitionKind::ClassMember } else { DefinitionKind::ObjectMember };
        literal_methods(&function.abc, literal, 0, &mut |child| found.definitions.push((pc, kind, child, sealed)));
        if let Some(class) = method.filter(|_| is_class) {
            let info = class_literal(&function.abc, literal);
            if info.is_none() {
                self.stats.odd_class_literals += 1;
            }
            for (member, is_static) in info
                .iter()
                .flat_map(|info| info.instance.iter().map(|member| (member, false)).chain(info.statics.iter().map(|member| (member, true))))
            {
                let membership = Membership { class, is_static };
                // A function that is a member of two classes is a member of neither.
                self.members
                    .entry(member.method)
                    .and_modify(|known| *known = known.filter(|known| *known == membership))
                    .or_insert(Some(membership));
            }
            self.members
                .entry(class)
                .and_modify(|known| *known = known.filter(|known| known.class == class && !known.is_static))
                .or_insert(Some(Membership { class, is_static: false }));
            // A constructor two definitions share, with different members: its members are not known.
            match self.classes.entry(class) {
                std::collections::hash_map::Entry::Occupied(mut known) => {
                    if *known.get() != info {
                        known.insert(None);
                    }
                }
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(info);
                }
            }
        } else if found.definitions.len() > before {
            // Methods of an object literal belong to no class.
            for &(_, _, child, _) in &found.definitions[before..] {
                self.members.insert(child, None);
            }
        }
    }

    /// Give every function the chain it starts with.
    fn link_chains(&mut self, sites: &mut Sites) {
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum State {
            Todo,
            Busy,
            Done,
        }
        let mut states = vec![State::Todo; self.functions.len()];
        // Parents first, without recursion: nesting can be deep.
        let mut work: Vec<FnId> = (0..self.functions.len()).rev().filter_map(|id| u32::try_from(id).ok()).collect();
        while let Some(&id) = work.last() {
            let index = id as usize;
            if states[index] == State::Done {
                work.pop();
                continue;
            }
            let pending: Vec<FnId> = self.functions[index]
                .definers
                .iter()
                .map(|definer| definer.parent)
                .filter(|&parent| states[parent as usize] == State::Todo)
                .collect();
            if states[index] == State::Todo && !pending.is_empty() {
                states[index] = State::Busy;
                work.extend(pending);
                continue;
            }
            // A definer that is still busy is this function's own descendant: a cycle, left unknown.
            let chain = self.chain_of(id, sites, |parent| states[parent as usize] == State::Done);
            let function = &mut self.functions[index];
            if function.definers.len() > 1 {
                self.stats.redefined_functions += 1;
            }
            if function.definers.is_empty() && !function.is_main {
                self.stats.undefined_functions += 1;
            }
            match chain {
                Some((captured, tail)) => {
                    function.captured = captured;
                    function.tail = tail;
                }
                None => {
                    function.captured = Vec::new();
                    function.tail = Tail::Unknown;
                }
            }
            if function.tail == Tail::Unknown {
                self.stats.unknown_chains += 1;
            }
            states[index] = State::Done;
            work.pop();
        }
    }

    /// The chain function `id` starts with: `None` when its definitions do
    /// not agree on one shape.
    fn chain_of(&self, id: FnId, sites: &mut Sites, is_done: impl Fn(FnId) -> bool) -> Option<(Vec<SiteId>, Tail)> {
        let function = &self.functions[id as usize];
        if function.is_main {
            return Some((Vec::new(), Tail::End));
        }
        let mut merged: Option<(Vec<SiteId>, Tail)> = None;
        for definer in &function.definers {
            if definer.sealed || !is_done(definer.parent) {
                return None;
            }
            let parent = &self.functions[definer.parent as usize];
            let mut chain: Vec<SiteId> = self.stack(definer.stack?).iter().rev().copied().collect();
            chain.extend_from_slice(&parent.captured);
            match &merged {
                None => merged = Some((chain, parent.tail)),
                Some((known, tail)) => {
                    if known.len() != chain.len() || *tail != parent.tail {
                        return None;
                    }
                    for (&a, &b) in known.iter().zip(&chain) {
                        sites.union(a, b);
                    }
                }
            }
        }
        merged
    }

    /// The functions whose environments a store in `function` can reach
    /// when its target is not identified: itself and everything around it.
    /// `None` when those are not all known.
    fn around(&self, function: FnId) -> Option<HashSet<FnId>> {
        let mut seen = HashSet::new();
        let mut work = vec![function];
        while let Some(id) = work.pop() {
            if !seen.insert(id) {
                continue;
            }
            let scope = &self.functions[id as usize];
            if scope.definers.is_empty() && !scope.is_main {
                return None;
            }
            work.extend(scope.definers.iter().map(|definer| definer.parent));
        }
        Some(seen)
    }

    fn taint(&mut self, taints: &mut Taints, function: FnId, slot: Option<u32>) {
        self.stats.unidentified_stores += 1;
        // Any slot: the code of the function is not known.
        self.unread_code |= slot.is_none();
        match self.around(function) {
            Some(functions) => taints.functions.extend(functions.into_iter().map(|function| (function, slot))),
            None => {
                taints.record.insert(slot);
            }
        }
    }

    /// Run the tracker over every function that stores and collect, per
    /// variable, the stores that write it.
    fn collect_writers(
        &mut self,
        functions: &[Option<Function<'_, '_>>],
        tables: &ScopeTables,
        tracker: &mut Tracker,
        taints: &mut Taints,
    ) -> (HashMap<SlotKey, Writers>, HashMap<u32, Writers>) {
        let mut slot_writers: HashMap<SlotKey, Writers> = HashMap::new();
        let mut module_writers: HashMap<u32, Writers> = HashMap::new();
        let mut unidentified: Vec<(FnId, Option<u32>)> = Vec::new();
        let mut path = Path::default();
        for (id, function) in functions.iter().enumerate() {
            let Some(function) = function.as_ref().filter(|_| self.functions[id].has_store) else { continue };
            let id = u32::try_from(id).unwrap_or(u32::MAX);
            let this = &*self;
            let reader = Reader::of_writer(this, id);
            let entity = |entity_id: u32| function.entity(entity_id);
            let walked = tracker.run_events(tables.effects(), &function.code, Watch::Stores, |frame, insn, event| {
                let Event::Store { target, value } = event else { return };
                let builder = PathBuilder { frame, function: function.method.offset(), entity: &entity, lexicals: &reader };
                let at = StoreSite { method: function.method.offset(), pc: crate::refs::pc_of(insn) };
                let mut stored = || {
                    builder.build(value, &mut path);
                    // A value read from another variable is known once that variable is.
                    let known = path.is_known() || (!path.cut && matches!(path.origin, Origin::Slot { .. }));
                    known.then(|| path.clone().into_captured(function.method.offset()))
                };
                match target {
                    StoreTarget::Lexical { sendable: true, .. } => {}
                    StoreTarget::Lexical { level, slot, sendable: false } => match this.locate(id, crate::refs::pc_of(insn), level) {
                        Ok((env, _)) => {
                            let value = stored();
                            // A loop that makes an environment per iteration copies each variable from the
                            // old one into the new one: the variable written back into itself is not a
                            // writer, it brings no new value.
                            let copies_itself =
                                value.as_ref().is_some_and(|path| path.links.is_empty() && path.origin == Origin::Slot { env, slot });
                            if !copies_itself {
                                slot_writers.entry((env, slot)).or_default().add(at, value);
                            }
                        }
                        Err(Unresolved::Outside) => {}
                        Err(_) => unidentified.push((id, Some(slot))),
                    },
                    StoreTarget::Module(index) => module_writers.entry(index).or_default().add(at, stored()),
                }
            });
            if walked.is_err() {
                unidentified.push((id, None));
            }
        }
        for (function, slot) in unidentified {
            self.taint(taints, function, slot);
        }
        (slot_writers, module_writers)
    }

    /// Decide every variable: taints first, then the unique writers, then
    /// the variables written from other variables.
    fn settle(
        &mut self,
        slot_writers: HashMap<SlotKey, Writers>,
        module_writers: HashMap<u32, Writers>,
        taints: &Taints,
        sites: &Sites,
        class_of: &[SiteId],
    ) {
        let mut tainted: HashSet<(SiteId, Option<u32>)> = HashSet::new();
        if !taints.functions.is_empty() {
            for (site, &function) in sites.function.iter().enumerate() {
                for slot in taints.functions.iter().filter(|(of, _)| *of == function).map(|&(_, slot)| slot) {
                    tainted.insert((class_of[site], slot));
                }
            }
        }
        self.tainted_record = taints.record.iter().copied().collect();
        self.tainted_envs = tainted;
        let mut direct: HashMap<SlotKey, Result<Written, Unresolved>> = HashMap::with_capacity(slot_writers.len());
        for (key, writers) in slot_writers {
            let state = if self.is_tainted(key) { Err(Unresolved::Tainted) } else { writers.state() };
            match state {
                Err(Unresolved::MultipleWriters) => self.stats.multi_writer_slots += 1,
                Err(Unresolved::UnknownValue) => self.stats.unknown_value_slots += 1,
                _ => {}
            }
            direct.insert(key, state);
        }

        let this = &*self;
        let follow = |start: &Result<Written, Unresolved>| -> Result<Written, Unresolved> {
            let Written { mut path, writer } = start.clone()?;
            let mut seen: Vec<SlotKey> = Vec::new();
            while let Origin::Slot { env, slot } = path.origin {
                if seen.len() == MAX_CHAIN || seen.contains(&(env, slot)) {
                    return Err(Unresolved::Chain);
                }
                seen.push((env, slot));
                let inner = match direct.get(&(env, slot)) {
                    Some(inner) => inner.as_ref().map_err(|&why| why)?,
                    // A tainted variable nothing else writes still has a writer.
                    None if this.is_tainted((env, slot)) => return Err(Unresolved::Tainted),
                    None => return Err(Unresolved::NoWriter),
                };
                path = path.after(&inner.path);
                if path.cut {
                    return Err(Unresolved::UnknownValue);
                }
            }
            Ok(Written { path, writer })
        };
        let slots: HashMap<SlotKey, Result<Written, Unresolved>> = direct.iter().map(|(&key, state)| (key, follow(state))).collect();
        let module_vars = module_writers.into_iter().map(|(index, writers)| (index, follow(&writers.state()))).collect();
        self.module_vars = module_vars;
        self.stats.resolved_slots = slots.values().filter(|state| state.is_ok()).count();
        self.slots = slots;
    }

    fn function_id(&self, method: u32) -> Option<FnId> {
        self.by_method.get(&method).copied()
    }

    fn is_tainted(&self, (env, slot): SlotKey) -> bool {
        self.tainted_record.contains(&None)
            || self.tainted_record.contains(&Some(slot))
            || self.tainted_envs.contains(&(env, None))
            || self.tainted_envs.contains(&(env, Some(slot)))
    }

    /// The value of the module-level binding whose local export entries are
    /// `exports` (entries that share one local name share the variable):
    /// known when the stores into them are one store in all, and all the
    /// code of the record was read.
    pub(crate) fn module_binding(&self, exports: &[u32]) -> Result<&Written, Unresolved> {
        if self.unread_code {
            return Err(Unresolved::Tainted);
        }
        let mut written = exports.iter().filter_map(|index| self.module_vars.get(index));
        match (written.next(), written.next()) {
            (Some(Ok(only)), None) => Ok(only),
            (Some(Err(why)), None) => Err(*why),
            (None, _) => Err(Unresolved::NoWriter),
            (Some(_), Some(_)) => Err(Unresolved::MultipleWriters),
        }
    }

    /// The members of the class whose constructor is at method offset `class`.
    pub(crate) fn class(&self, class: u32) -> Option<&ClassInfo> {
        self.classes.get(&class)?.as_ref()
    }

    /// The class the function at `method` is a method (or the constructor) of.
    pub(crate) fn membership(&self, method: u32) -> Option<Membership> {
        self.members.get(&method).copied().flatten()
    }

    /// Every place a function object is created, in function then code order.
    pub(crate) fn definitions(&self) -> &[Definition] {
        &self.definitions
    }

    pub(crate) fn stats(&self) -> &ScopeStats {
        &self.stats
    }

    /// Rewrite `path` when it starts at a class of this record and goes on
    /// to one of the methods its literal lists: `C.staticMethod` and
    /// `new C().method` become the method itself.
    ///
    /// This takes the class as its definition makes it: a static field or a
    /// later assignment of the same name, or a prototype changed at run
    /// time, are not seen.
    pub(crate) fn reduce(&self, abc: &Abc<'_>, path: &mut Path) {
        self.reduce_named(abc, path, abc);
    }

    /// [`Scopes::reduce`] for a path whose link names are strings of
    /// `names`, which may be another file than the record's `abc`.
    pub(crate) fn reduce_named(&self, abc: &Abc<'_>, path: &mut Path, names: &Abc<'_>) {
        let Origin::Definition(Some(class)) = path.origin else { return };
        if path.cut {
            return;
        }
        let Some(info) = self.class(class) else { return };
        let (members, name, used) = match path.links[..] {
            [Link::Property(Some(name)), ..] => (&info.statics, name, 1),
            [Link::Call { construct: true }, Link::Property(Some(name)), ..] => (&info.instance, name, 2),
            _ => return,
        };
        let Ok(name) = names.string(name) else { return };
        if let Some(member) = find_member(abc, members, name.bytes) {
            path.origin = Origin::Definition(Some(member.method));
            path.links.drain(..used);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_known_writer_resolves() {
        let known = || Some(Path { origin: Origin::Import(1), links: Vec::new(), cut: false });
        let at = StoreSite { method: 100, pc: 4 };
        let mut writers = Writers::default();
        writers.add(at, known());
        assert_eq!(writers.state().map(|written| written.writer), Ok(at));
        let mut unknown = Writers::default();
        unknown.add(at, None);
        assert_eq!(unknown.state(), Err(Unresolved::UnknownValue));
        let mut two = Writers::default();
        two.add(at, known());
        two.add(at, known());
        assert_eq!(two.state(), Err(Unresolved::MultipleWriters));
    }
}
