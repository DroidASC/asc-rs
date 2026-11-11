//! Dalvik instruction set description and operand decoding.
//!
//! The opcode table mirrors ART's `dex_instruction_list.h`: opcode byte, name,
//! length in 16-bit code units, instruction format, the kind of constant-pool
//! index carried by the instruction, and the verifier flags. Only the flags
//! that identify switch/array payload references are used at runtime.

pub mod decode;
mod table;
pub mod values;
pub mod verify;
pub mod walk;

pub use decode::{Instruction, PayloadKind, get_index, set_index, vreg_a, vreg_b, vreg_c, vreg_h};
pub use table::OPCODES;
pub use walk::{Step, walk};

/// Size of one code unit in bytes.
pub const WORD: usize = 2;

/// Instruction formats (`kXXx` in ART).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum Format {
    /// `op`: no operands (`nop`, `return-void`, payload pseudo-instructions).
    K10x,
    /// `op vA, vB`: two 4-bit registers.
    K12x,
    /// `op vA, #+B`: 4-bit register and signed 4-bit literal.
    K11n,
    /// `op vAA`: one 8-bit register.
    K11x,
    /// `op +AA`: signed 8-bit branch offset.
    K10t,
    /// `op +AAAA`: signed 16-bit branch offset.
    K20t,
    /// `op vAA, vBBBB`: 8-bit and 16-bit registers.
    K22x,
    /// `op vAA, +BBBB`: register and signed 16-bit branch offset.
    K21t,
    /// `op vAA, #+BBBB`: register and signed 16-bit literal.
    K21s,
    /// `op vAA, #+BBBB0000[00000000]`: register and the high 16 bits of a literal.
    K21h,
    /// `op vAA, kind@BBBB`: register and 16-bit constant-pool index.
    K21c,
    /// `op vAA, vBB, vCC`: three 8-bit registers.
    K23x,
    /// `op vAA, vBB, #+CC`: two registers and signed 8-bit literal.
    K22b,
    /// `op vA, vB, +CCCC`: two 4-bit registers and signed 16-bit branch offset.
    K22t,
    /// `op vA, vB, #+CCCC`: two 4-bit registers and signed 16-bit literal.
    K22s,
    /// `op vA, vB, kind@CCCC`: two 4-bit registers and 16-bit constant-pool index.
    K22c,
    /// `op vAAAA, vBBBB`: two 16-bit registers.
    K32x,
    /// `op +AAAAAAAA`: signed 32-bit branch offset.
    K30t,
    /// `op vAA, +BBBBBBBB`: register and signed 32-bit offset (branch or payload).
    K31t,
    /// `op vAA, #+BBBBBBBB`: register and 32-bit literal.
    K31i,
    /// `op vAA, string@BBBBBBBB`: register and 32-bit string index (`const-string/jumbo`).
    K31c,
    /// `op {vC, vD, vE, vF, vG}, kind@BBBB`: up to five 4-bit argument registers.
    K35c,
    /// `op {vCCCC .. vNNNN}, kind@BBBB`: register range of `AA` arguments.
    K3rc,
    /// `op vAA, #+BBBBBBBBBBBBBBBB`: register and 64-bit literal.
    K51l,
    /// `op {vC, vD, vE, vF, vG}, meth@BBBB, proto@HHHH` (`invoke-polymorphic`).
    K45cc,
    /// `op {vCCCC .. vNNNN}, meth@BBBB, proto@HHHH` (`invoke-polymorphic/range`).
    K4rcc,
}

/// Kind of constant-pool index carried by an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndexKind {
    /// No constant-pool index.
    None,
    /// Index into `string_ids`.
    StringRef,
    /// Index into `type_ids`.
    TypeRef,
    /// Never produced by the table; kept because downstream renderers
    /// (`asc-smali`) match on it.
    Unknown,
    /// Index into `field_ids`.
    FieldRef,
    /// Index into `method_ids`.
    MethodRef,
    /// `method_ids` index in `B` plus `proto_ids` index in `H` (`invoke-polymorphic`).
    MethodAndProtoRef,
    /// Index into `call_site_ids` (`invoke-custom`).
    CallSiteRef,
    /// Index into `method_handles` (`const-method-handle`).
    MethodHandleRef,
    /// Index into `proto_ids` (`const-method-type`).
    ProtoRef,
}

/// One row of the opcode table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opcode {
    /// Opcode byte (low byte of the first code unit).
    pub value: u8,
    /// Mnemonic as spelled in the Dalvik bytecode spec, e.g. `const-string`.
    pub name: &'static str,
    /// Length in 16-bit code units.
    pub len: u8,
    /// Operand layout.
    pub format: Format,
    /// Kind of constant-pool index the instruction carries.
    pub index: IndexKind,
    /// Bitset of [`verify`] `VERIFY_*` flags, combined as in ART's table.
    pub verify: u32,
}

impl Opcode {
    /// Length in bytes.
    #[inline]
    pub const fn byte_len(&self) -> usize {
        self.len as usize * WORD
    }

    /// Whether the instruction's `B` operand is a relative offset to a
    /// switch or array-data payload.
    #[inline]
    pub const fn references_payload(&self) -> bool {
        self.verify & (verify::VERIFY_SWITCH_TARGETS | verify::VERIFY_ARRAY_DATA) != 0
    }

    /// Whether the instruction is a branch with a relative target.
    #[inline]
    pub const fn is_branch(&self) -> bool {
        self.verify & verify::VERIFY_BRANCH_TARGET != 0
    }
}

/// Look up the opcode row for an opcode byte.
#[inline]
pub fn opcode(byte: u8) -> Option<&'static Opcode> {
    OPCODES[byte as usize].as_ref()
}

/// Iterate over every defined opcode.
pub fn opcodes() -> impl Iterator<Item = &'static Opcode> {
    OPCODES.iter().filter_map(|o| o.as_ref())
}

/// Identifier of a `packed-switch-payload`: the payload's first code unit,
/// a `nop` whose high byte names the payload kind.
pub const PACKED_SWITCH_PAYLOAD: u16 = 0x0100;
/// Identifier of a `sparse-switch-payload` (see [`PACKED_SWITCH_PAYLOAD`]).
pub const SPARSE_SWITCH_PAYLOAD: u16 = 0x0200;
/// Identifier of a `fill-array-data-payload` (see [`PACKED_SWITCH_PAYLOAD`]).
pub const FILL_ARRAY_DATA_PAYLOAD: u16 = 0x0300;

/// Byte length of every opcode (`0` = undefined), derived from the table at
/// compile time so the verification loop is one load per instruction.
const LEN: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        if let Some(op) = &table::OPCODE_TABLE[i] {
            t[i] = op.len * WORD as u8;
        }
        i += 1;
    }
    t
};

/// Verify that `code[start..end]` is a contiguous sequence of well-formed
/// instructions (every opcode byte is defined and the instruction lengths
/// tile the range exactly). This is the Rust equivalent of the `INSN_VERIFY`
/// regex used by the Python implementation.
///
/// Returns `false` when `start > end`, when `end` exceeds `code.len()`, or
/// when the last instruction crosses `end`.
pub fn verify_range(code: &[u8], start: usize, end: usize) -> bool {
    if start > end || end > code.len() {
        return false;
    }
    let region = &code[start..end];
    let mut pos = 0;
    while pos < region.len() {
        let len = LEN[region[pos] as usize] as usize;
        if len == 0 {
            return false;
        }
        pos += len;
    }
    pos == region.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_partitioned_by_length() {
        let mut seen = std::collections::HashSet::new();
        let mut count = 0;
        for op in opcodes() {
            assert!(seen.insert(op.value));
            assert!((1..=5).contains(&op.len));
            count += 1;
        }
        assert_eq!(count, 224);
        assert_eq!(opcode(0x3e), None);
        assert_eq!(opcode(0x73), None);
        assert_eq!(opcode(0xe3), None);
        assert_eq!(opcode(0xff).unwrap().name, "const-method-type");
    }

    #[test]
    fn verify_range_matches_python_regex_semantics() {
        assert!(verify_range(b"\x0e\x00", 0, 2));
        assert!(verify_range(b"\x0e\x00\x0e\x00", 0, 4));
        assert!(!verify_range(b"\x0e\x00\x3e\x00", 0, 4));
        assert!(!verify_range(b"\x1a\x00\x05\x00\x0e\x00", 0, 2)); // const-string is 2 units
        assert!(verify_range(b"\x1a\x00\x05\x00\x0e\x00", 0, 4));
    }

    #[test]
    fn length_table_matches_opcode_table() {
        for b in 0..=255u8 {
            let expected = opcode(b).map(|op| op.byte_len()).unwrap_or(0);
            assert_eq!(LEN[b as usize] as usize, expected, "opcode {b:#04x}");
        }
    }

    #[test]
    fn verify_range_rejects_bad_bounds() {
        let code = b"\x0e\x00\x0e\x00";
        assert!(!verify_range(code, 4, 2)); // start > end
        assert!(!verify_range(code, 0, 5)); // end > len
        assert!(!verify_range(code, 5, 6)); // both past the end
        assert!(verify_range(code, 2, 2)); // empty range is well-formed
        assert!(verify_range(code, 4, 4));
        // A 5-unit const-wide that crosses `end`.
        let wide = [0x18, 0x00, 1, 2, 3, 4, 5, 6, 7, 8, 0x0e, 0x00];
        assert!(!verify_range(&wide, 0, 8));
        assert!(!verify_range(&wide, 0, 6));
        assert!(verify_range(&wide, 0, 10));
        assert!(verify_range(&wide, 0, 12));
        // Truncated buffer: the instruction runs past `code.len()`.
        assert!(!verify_range(&wide[..8], 0, 8));
    }
}
