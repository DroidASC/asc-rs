//! Linear, payload-aware instruction walk.
//!
//! The walk visits every real instruction of a method from offset 0 to the
//! end of the code, stepping *over* `packed-switch` / `sparse-switch` /
//! `fill-array-data` payloads wherever they are placed (before or after the
//! instruction that references them). Payloads are recognised the way ART's
//! `Instruction::SizeInCodeUnits` does: a `nop` whose full first code unit is
//! one of the pseudo-opcode identifiers is a payload of the size encoded in
//! its header, so no separate target-collection pass is needed and a payload
//! that precedes its switch instruction is never decoded as bytecode.
//!
//! The walk stops early only on an undefined opcode byte (odex / quickened
//! or corrupt code) or on an instruction that runs past the end of the code,
//! and reports why through [`Stop`]. This replaces the Python
//! `DvmInterpreter` traversal, which simply stopped at the first payload.

use crate::{opcode, Instruction, Opcode};

/// One visited instruction. Payload pseudo-instructions are never reported.
#[derive(Debug, Clone, Copy)]
pub struct Step<'a> {
    pub pc: usize,
    pub opcode: &'a Opcode,
}

/// Why a walk ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    /// Every instruction up to the end of the code was visited.
    End,
    /// Undefined opcode byte at `pc` (odex / quickened / corrupt code).
    Undefined { pc: usize, opcode: u8 },
    /// The instruction or payload at `pc` extends past the end of the code.
    Truncated { pc: usize },
}

/// Result of a walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Walk {
    /// Offset just past the last instruction or payload that was visited.
    pub end: usize,
    pub stop: Stop,
}

impl Walk {
    /// Whether the whole code range was walked.
    #[inline]
    pub fn is_complete(&self) -> bool {
        self.stop == Stop::End
    }
}

/// Walk `code` from offset 0, calling `f` for each real instruction (payloads
/// are skipped) and report where and why the walk stopped.
pub fn walk_insns(code: &[u8], mut f: impl FnMut(Step<'_>)) -> Walk {
    let mut pc = 0usize;
    while pc < code.len() {
        let byte = code[pc];
        let Some(op) = opcode(byte) else {
            return Walk { end: pc, stop: Stop::Undefined { pc, opcode: byte } };
        };
        if op.value == 0 {
            // `nop` or a payload: let the decoder size it (it reads the
            // pseudo-opcode identifier and the payload header).
            let Some(insn) = Instruction::decode(code, pc) else {
                return Walk { end: pc, stop: Stop::Truncated { pc } };
            };
            if insn.payload.is_none() {
                f(Step { pc, opcode: op });
            }
            pc += insn.byte_len();
            continue;
        }
        if pc + op.byte_len() > code.len() {
            return Walk { end: pc, stop: Stop::Truncated { pc } };
        }
        f(Step { pc, opcode: op });
        pc += op.byte_len();
    }
    Walk { end: pc, stop: Stop::End }
}

/// Walk `code` from offset 0, calling `f` for each instruction. Returns the
/// offset where the walk stopped (the end of the code unless an undefined or
/// truncated instruction was met). See [`walk_insns`] for the stop reason.
pub fn walk(code: &[u8], f: impl FnMut(Step<'_>)) -> usize {
    walk_insns(code, f).end
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pcs(code: &[u8]) -> (Vec<usize>, Walk) {
        let mut v = Vec::new();
        let w = walk_insns(code, |s| v.push(s.pc));
        (v, w)
    }

    #[test]
    fn walks_to_the_end_of_plain_code() {
        // const-string v0, @5 ; nop ; return-void
        let (v, w) = pcs(b"\x1a\x00\x05\x00\x00\x00\x0e\x00");
        assert_eq!(v, [0, 4, 6]);
        assert_eq!(w, Walk { end: 8, stop: Stop::End });
    }

    #[test]
    fn skips_payload_placed_before_its_switch() {
        // 0: packed-switch payload, 2 entries (ident 0x0100, size 2, first_key 0, targets 1, 2)
        // 16: packed-switch v0, -8 (=> payload at 0) ; 22: return-void
        let mut code = vec![0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
        code.extend_from_slice(&1i32.to_le_bytes());
        code.extend_from_slice(&2i32.to_le_bytes());
        code.extend_from_slice(&[0x2b, 0x00]);
        code.extend_from_slice(&(-8i32).to_le_bytes());
        code.extend_from_slice(&[0x0e, 0x00]);
        let (v, w) = pcs(&code);
        assert_eq!(v, [16, 22]);
        assert_eq!(w, Walk { end: 24, stop: Stop::End });
    }

    #[test]
    fn skips_payload_after_the_switch_and_continues() {
        // sparse-switch v0, +3 ; return-void ; payload (ident 0x0200, size 1, key 7, target 1)
        let mut code = vec![0x2c, 0x00];
        code.extend_from_slice(&3i32.to_le_bytes());
        code.extend_from_slice(&[0x0e, 0x00]);
        code.extend_from_slice(&[0x00, 0x02, 0x01, 0x00]);
        code.extend_from_slice(&7i32.to_le_bytes());
        code.extend_from_slice(&1i32.to_le_bytes());
        // trailing instruction after the payload is still visited
        code.extend_from_slice(&[0x0e, 0x00]);
        let (v, w) = pcs(&code);
        assert_eq!(v, [0, 6, 20]);
        assert_eq!(w.stop, Stop::End);
        assert_eq!(w.end, code.len());
    }

    #[test]
    fn reports_undefined_and_truncated() {
        let (v, w) = pcs(b"\x0e\x00\x3e\x00\x0e\x00");
        assert_eq!(v, [0]);
        assert_eq!(w, Walk { end: 2, stop: Stop::Undefined { pc: 2, opcode: 0x3e } });
        let (v, w) = pcs(b"\x0e\x00\x1a\x00");
        assert_eq!(v, [0]);
        assert_eq!(w, Walk { end: 2, stop: Stop::Truncated { pc: 2 } });
        // fill-array-data payload header claims more data than present
        let (v, w) = pcs(b"\x00\x03\x04\x00\xff\x00\x00\x00");
        assert!(v.is_empty());
        assert_eq!(w, Walk { end: 0, stop: Stop::Truncated { pc: 0 } });
        assert_eq!(walk(b"\x0e\x00\x0e\x00", |_| {}), 4);
    }
}
