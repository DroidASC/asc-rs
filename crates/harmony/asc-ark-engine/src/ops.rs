//! Per-opcode lookup tables.
//!
//! A search classifies every instruction it walks. Comparing mnemonics there
//! would cost a string comparison per instruction, so each classification is
//! computed once per opcode, from the mnemonic and the operand kinds of the
//! generated table, and stored in a flat array indexed by opcode number.

use asc_arkisa::{Instruction, Opcode, OperandKind, Prefix, Value};

/// One page of 256 per prefix, the unprefixed opcodes first.
const SLOTS: usize = 5 * 256;

fn slot(opcode: &Opcode) -> usize {
    let page = match opcode.prefix {
        None => 0,
        Some(Prefix::CallRuntime) => 1,
        Some(Prefix::Deprecated) => 2,
        Some(Prefix::Wide) => 3,
        Some(Prefix::Throw) => 4,
    };
    page * 256 + usize::from(opcode.value)
}

/// A value per opcode.
pub(crate) struct OpTable<T>(Box<[T]>);

impl<T: Copy + Default> OpTable<T> {
    /// `of(opcode)` for every opcode of the instruction set.
    pub(crate) fn build(of: impl Fn(&'static Opcode) -> T) -> OpTable<T> {
        let mut table = vec![T::default(); SLOTS].into_boxed_slice();
        for opcode in asc_arkisa::opcodes() {
            table[slot(opcode)] = of(opcode);
        }
        OpTable(table)
    }

    #[inline]
    pub(crate) fn of(&self, opcode: &Opcode) -> T {
        self.0[slot(opcode)]
    }
}

/// The mnemonic without the `wide.` / `callruntime.` prefix that only widens
/// the operands or moves the opcode to another page: `ldexternalmodulevar`
/// for `wide.ldexternalmodulevar`, `ldlazymodulevar` for
/// `callruntime.wideldlazymodulevar`. `deprecated.` and `throw.` mnemonics
/// stay whole: those are different instructions.
pub(crate) fn base_name(opcode: &Opcode) -> &'static str {
    let name = opcode.name;
    match opcode.prefix {
        Some(Prefix::Wide) => name.strip_prefix("wide.").unwrap_or(name),
        Some(Prefix::CallRuntime) => {
            let name = name.strip_prefix("callruntime.").unwrap_or(name);
            // `callruntime.wide…` is the wide form of the `callruntime.…` opcode before it.
            name.strip_prefix("wide")
                .filter(|rest| rest.starts_with("ld") || rest.starts_with("st") || rest.starts_with("new"))
                .unwrap_or(name)
        }
        Some(Prefix::Deprecated | Prefix::Throw) | None => name,
    }
}

/// Which section of the record's module record an instruction's immediate
/// indexes (`libabckit`, `helpers_dynamic.cpp`; the same mapping as
/// `asc-pasm` annotates instructions with).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModuleOperand {
    RegularImport,
    LocalExport,
    Request,
}

impl ModuleOperand {
    pub(crate) fn of(opcode: &Opcode) -> Option<ModuleOperand> {
        match base_name(opcode) {
            "ldexternalmodulevar" | "ldsendableexternalmodulevar" | "ldlazymodulevar" | "ldlazysendablemodulevar" => {
                Some(ModuleOperand::RegularImport)
            }
            "ldlocalmodulevar" | "ldsendablelocalmodulevar" | "stmodulevar" => Some(ModuleOperand::LocalExport),
            "getmodulenamespace" => Some(ModuleOperand::Request),
            _ => None,
        }
    }
}

/// How an instruction uses the name its string operand holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NameUse {
    /// A property of an object, and what is done with it.
    Property(Access),
    /// A global binding.
    Global(Access),
    /// Anything else: string constants, big integers, regular expressions,
    /// the name in a temporal-dead-zone check, the by-name module
    /// instructions of pre-9 bytecode.
    Text,
}

/// What an instruction does with the property or global it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Access {
    Read,
    Write,
    /// Defines an own property: object literal members, class fields.
    Define,
    /// Calls the property as a method.
    Call,
}

impl Access {
    pub const ALL: [Access; 4] = [Access::Read, Access::Write, Access::Define, Access::Call];

    /// The label result rows carry: `read`, `write`, `define`, `call`.
    pub const fn label(self) -> &'static str {
        match self {
            Access::Read => "read",
            Access::Write => "write",
            Access::Define => "define",
            Access::Call => "call",
        }
    }
}

impl std::fmt::Display for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

impl NameUse {
    /// The use of the string operand of `opcode`; `None` when it has none.
    pub(crate) fn of(opcode: &Opcode) -> Option<NameUse> {
        opcode.operand_of(OperandKind::StringId)?;
        Some(match base_name(opcode) {
            "ldobjbyname" | "ldthisbyname" | "ldsuperbyname" | "deprecated.ldobjbyname" | "deprecated.ldsuperbyname" => {
                NameUse::Property(Access::Read)
            }
            "stobjbyname" | "stthisbyname" | "stsuperbyname" => NameUse::Property(Access::Write),
            "stownbyname" | "stownbynamewithnameset" | "definefieldbyname" | "definepropertybyname" => NameUse::Property(Access::Define),
            "callthis0withname" | "callthis1withname" | "callthis2withname" | "callthis3withname" | "callthisrangewithname" => {
                NameUse::Property(Access::Call)
            }
            "tryldglobalbyname" | "ldglobalvar" => NameUse::Global(Access::Read),
            "trystglobalbyname"
            | "stglobalvar"
            | "sttoglobalrecord"
            | "stconsttoglobalrecord"
            | "deprecated.stlettoglobalrecord"
            | "deprecated.stconsttoglobalrecord"
            | "deprecated.stclasstoglobalrecord" => NameUse::Global(Access::Write),
            _ => NameUse::Text,
        })
    }
}

/// The `index`-th immediate of `insn` (inline-cache slots and ids are not
/// immediates), as the unsigned number the module, lexical and index
/// instructions carry.
pub(crate) fn immediate(insn: &Instruction<'_>, index: usize) -> Option<u32> {
    let mut immediates = insn.opcode.operands.iter().zip(insn.operands()).filter_map(|(operand, value)| match value {
        Value::Imm(value) if operand.kind == OperandKind::ImmUnsigned => u32::try_from(value).ok(),
        _ => None,
    });
    immediates.nth(index)
}

/// The registers of `insn` whose operand is of `kind`, in assembly order.
pub(crate) fn registers<'a>(insn: &Instruction<'a>, kind: OperandKind) -> impl Iterator<Item = u16> + 'a + use<'a> {
    insn.opcode.operands.iter().zip(insn.operands()).filter_map(move |(operand, value)| match value {
        Value::Reg(reg) if operand.kind == kind => Some(reg),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_names_drop_only_the_widening_prefixes() {
        let base = |name: &str| asc_arkisa::opcodes().find(|op| op.name == name).map(base_name);
        assert_eq!(base("wide.ldexternalmodulevar"), Some("ldexternalmodulevar"));
        assert_eq!(base("callruntime.wideldlazysendablemodulevar"), Some("ldlazysendablemodulevar"));
        assert_eq!(base("callruntime.widenewsendableenv"), Some("newsendableenv"));
        assert_eq!(base("callruntime.widestsendablevar"), Some("stsendablevar"));
        assert_eq!(base("callruntime.definesendableclass"), Some("definesendableclass"));
        assert_eq!(base("deprecated.ldobjbyname"), Some("deprecated.ldobjbyname"));
        assert_eq!(base("throw.undefinedifholewithname"), Some("throw.undefinedifholewithname"));
        // Every `callruntime.wideX` has its `callruntime.X`.
        for op in asc_arkisa::opcodes().filter(|op| op.name.starts_with("callruntime.wide")) {
            let narrow = format!("callruntime.{}", base_name(op));
            assert!(asc_arkisa::opcodes().any(|other| other.name == narrow), "{}", op.name);
        }
    }

    #[test]
    fn module_operands_agree_with_the_mnemonics() {
        let count = |kind| asc_arkisa::opcodes().filter(|op| ModuleOperand::of(op) == Some(kind)).count();
        // The same 16 opcodes `asc-pasm` annotates.
        assert_eq!((count(ModuleOperand::RegularImport), count(ModuleOperand::LocalExport), count(ModuleOperand::Request)), (8, 6, 2));
        for op in asc_arkisa::opcodes().filter(|op| ModuleOperand::of(op).is_some()) {
            assert!(op.prefix != Some(Prefix::Deprecated) && immediate_kinds(op) == 1, "{}", op.name);
        }
    }

    fn immediate_kinds(op: &Opcode) -> usize {
        op.operands.iter().filter(|operand| operand.kind == OperandKind::ImmUnsigned).count()
    }

    #[test]
    fn every_string_operand_has_a_use() {
        let with_string = || asc_arkisa::opcodes().filter(|op| op.operand_of(OperandKind::StringId).is_some());
        // A new opcode with a string operand must be classified here, not fall into `Text` unseen.
        let mut text: Vec<&str> = with_string().filter(|op| NameUse::of(op) == Some(NameUse::Text)).map(|op| op.name).collect();
        text.sort_unstable();
        text.dedup();
        assert_eq!(
            text,
            [
                "createregexpwithliteral",
                "deprecated.getmodulenamespace",
                "deprecated.ldmodulevar",
                "deprecated.stmodulevar",
                "lda.str",
                "ldbigint",
                "throw.undefinedifholewithname",
            ]
        );
        let count = |wanted: NameUse| with_string().filter(|op| NameUse::of(op) == Some(wanted)).count();
        // Two encodings (8- and 16-bit cache slot) for most of them.
        assert_eq!(count(NameUse::Property(Access::Read)), 2 + 2 + 2 + 1 + 1);
        assert_eq!(count(NameUse::Property(Access::Write)), 2 + 2 + 2);
        assert_eq!(count(NameUse::Property(Access::Define)), 2 + 2 + 1 + 1);
        assert_eq!(count(NameUse::Property(Access::Call)), 4 + 1 + 1);
        assert_eq!(count(NameUse::Global(Access::Read)), 2 + 1);
        assert_eq!(count(NameUse::Global(Access::Write)), 2 + 1 + 1 + 1 + 3);
        assert_eq!(asc_arkisa::opcodes().filter(|op| NameUse::of(op).is_some()).count(), with_string().count());
    }

    #[test]
    fn immediates_skip_cache_slots() {
        // ldlexvar 3, 15
        let lexvar = Instruction::decode(&[0x3c, 0xf3], 0).unwrap();
        assert_eq!((immediate(&lexvar, 0), immediate(&lexvar, 1), immediate(&lexvar, 2)), (Some(3), Some(15), None));
        // definefunc slot 1, method 0x0203, 4 parameters
        let definefunc = Instruction::decode(&[0x33, 0x01, 0x03, 0x02, 0x04], 0).unwrap();
        assert_eq!(immediate(&definefunc, 0), Some(4));
        // callthis1 slot 9, v1, v2
        let call = Instruction::decode(&[0x2e, 0x09, 0x01, 0x02], 0).unwrap();
        assert_eq!(registers(&call, OperandKind::RegIn).collect::<Vec<_>>(), [1, 2]);
    }
}
