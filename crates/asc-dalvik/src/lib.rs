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

pub use decode::{get_index, set_index, vreg_a, vreg_b, vreg_c, vreg_h, Instruction, PayloadKind};
pub use table::OPCODES;
pub use walk::{walk, Step};

/// Size of one code unit in bytes.
pub const WORD: usize = 2;

/// Instruction formats (`kXXx` in ART).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
pub enum Format {
    K10x,
    K12x,
    K11n,
    K11x,
    K10t,
    K20t,
    K22x,
    K21t,
    K21s,
    K21h,
    K21c,
    K23x,
    K22b,
    K22t,
    K22s,
    K22c,
    K32x,
    K30t,
    K31t,
    K31i,
    K31c,
    K35c,
    K3rc,
    K51l,
    K45cc,
    K4rcc,
}

/// Kind of constant-pool index carried by an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndexKind {
    None,
    StringRef,
    TypeRef,
    /// Never produced by the table; kept because downstream renderers
    /// (`asc-smali`) match on it.
    Unknown,
    FieldRef,
    MethodRef,
    MethodAndProtoRef,
    CallSiteRef,
    MethodHandleRef,
    ProtoRef,
}

/// One row of the opcode table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opcode {
    pub value: u8,
    pub name: &'static str,
    /// Length in 16-bit code units.
    pub len: u8,
    pub format: Format,
    pub index: IndexKind,
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

/// Pseudo-opcode identifiers stored in the second byte of a payload `nop`.
pub const PACKED_SWITCH_PAYLOAD: u16 = 0x0100;
pub const SPARSE_SWITCH_PAYLOAD: u16 = 0x0200;
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
