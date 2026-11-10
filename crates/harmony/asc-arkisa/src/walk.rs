//! Linear instruction walk.
//!
//! ABC code has no inline data (no switch or array payloads), so a method's
//! code is a plain sequence of instructions from offset 0 to `code_size`.

use std::iter::FusedIterator;

use crate::{DecodeError, Instruction};

/// Iterator over the instructions of a code slice; see [`walk`].
#[derive(Debug, Clone)]
pub struct Walk<'a> {
    code: &'a [u8],
    pc: usize,
    failed: bool,
}

impl<'a> Walk<'a> {
    /// Offset just past the last instruction that was yielded: `code.len()`
    /// after a complete walk, the offset of the offending instruction after
    /// an error.
    #[inline]
    pub fn pc(&self) -> usize {
        self.pc
    }
}

impl<'a> Iterator for Walk<'a> {
    type Item = Result<Instruction<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.pc >= self.code.len() {
            return None;
        }
        let item = Instruction::decode(self.code, self.pc);
        match &item {
            Ok(insn) => self.pc = insn.next_pc(),
            Err(_) => self.failed = true,
        }
        Some(item)
    }
}

impl FusedIterator for Walk<'_> {}

/// Walk `code` from offset 0, yielding each instruction (its offset is
/// [`Instruction::pc`]).
///
/// An undefined opcode or an instruction that runs past the end of `code` is
/// yielded as one `Err` and ends the walk, so a walk without an `Err` covered
/// the code exactly. Empty code yields nothing.
pub fn walk(code: &[u8]) -> Walk<'_> {
    Walk { code, pc: 0, failed: false }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(code: &[u8]) -> Vec<Result<(usize, &'static str), DecodeError>> {
        walk(code).map(|item| item.map(|insn| (insn.pc, insn.opcode.name))).collect()
    }

    #[test]
    fn walks_to_the_end_of_the_code() {
        // lda.str 1 ; sta v0 ; throw.ifnotobject v0 ; wide.ldlexvar 1, 2 ; returnundefined
        let code = [0x3e, 0x01, 0x00, 0x61, 0x00, 0xfe, 0x05, 0x00, 0xfd, 0x0c, 0x01, 0x00, 0x02, 0x00, 0x65];
        assert_eq!(
            names(&code),
            [Ok((0, "lda.str")), Ok((3, "sta")), Ok((5, "throw.ifnotobject")), Ok((8, "wide.ldlexvar")), Ok((14, "returnundefined"))]
        );
        let mut all = walk(&code);
        assert!(all.by_ref().all(|item| item.is_ok()));
        assert_eq!(all.pc(), code.len());
        assert!(names(&[]).is_empty());
    }

    /// A method of the `contacts.hap` sample (bytecode 12.0.6.0), a `for (i = 0; i < 25; i++)` loop.
    #[test]
    fn real_method_walks_exactly_to_code_size() {
        use crate::Value::{IcSlot, Imm, JumpOffset, Reg, StringId};

        let code = [
            0x44, 0x90, 0x44, 0xa1, 0x44, 0xb2, 0x00, 0x61, 0x03, 0x62, 0x00, 0x00, 0x00, 0x00, 0x61, 0x03, 0x60, 0x03, 0x61, 0x05, 0x62,
            0x19, 0x00, 0x00, 0x00, 0x11, 0x00, 0x05, 0x4f, 0x33, 0x3c, 0x40, 0x61, 0x05, 0x60, 0x03, 0x61, 0x06, 0x3c, 0x30, 0x61, 0x08,
            0x60, 0x08, 0x42, 0x01, 0xa2, 0x00, 0x61, 0x07, 0x60, 0x07, 0x2d, 0x03, 0x08, 0x38, 0x05, 0x05, 0x06, 0x60, 0x03, 0x61, 0x05,
            0x60, 0x05, 0x1e, 0x07, 0x61, 0x05, 0x60, 0x05, 0x21, 0x08, 0x61, 0x03, 0x60, 0x05, 0x4d, 0xc3, 0x00, 0x65,
        ];
        let insns: Vec<_> = walk(&code).collect::<Result<_, _>>().unwrap();
        assert_eq!(insns.len(), 36);
        assert_eq!(insns.last().map(|insn| insn.next_pc()), Some(code.len()));

        let at = |pc: usize| insns.iter().find(|insn| insn.pc == pc).unwrap();
        let listing = |pc: usize| (at(pc).opcode.name, at(pc).operands().collect::<Vec<_>>());
        assert_eq!(listing(0), ("mov", vec![Reg(0), Reg(9)]));
        assert_eq!(listing(20), ("ldai", vec![Imm(25)]));
        assert_eq!(listing(25), ("less", vec![IcSlot(0), Reg(5)]));
        assert_eq!(listing(28), ("jeqz", vec![JumpOffset(51)]));
        assert_eq!(listing(30), ("ldlexvar", vec![Imm(0), Imm(4)]));
        assert_eq!(listing(44), ("ldobjbyname", vec![IcSlot(1), StringId(162)]));
        assert_eq!(listing(52), ("callthis0", vec![IcSlot(3), Reg(8)]));
        assert_eq!(listing(55), ("stobjbyvalue", vec![IcSlot(5), Reg(5), Reg(6)]));
        assert_eq!(listing(77), ("jmp", vec![JumpOffset(-61)]));
        // Loop exit and back edge both land on instruction starts.
        assert_eq!((at(28).jump_target(), at(77).jump_target()), (Some(79), Some(16)));
        assert_eq!((at(79).opcode.name, at(16).opcode.name, at(80).opcode.name), ("ldundefined", "lda", "returnundefined"));
    }

    #[test]
    fn an_error_is_yielded_once_and_ends_the_walk() {
        let undefined = [0x65, 0xe2, 0x65];
        assert_eq!(names(&undefined), [Ok((0, "returnundefined")), Err(DecodeError::Undefined { pc: 1, opcode: 0xe2, sub: None })]);

        let truncated = [0x65, 0x62, 0x01];
        let mut it = walk(&truncated);
        assert!(it.next().is_some_and(|item| item.is_ok()));
        assert_eq!(it.next().map(|item| item.map(|insn| insn.pc)), Some(Err(DecodeError::Truncated { pc: 1 })));
        assert_eq!(it.pc(), 1);
        assert!(it.next().is_none() && it.next().is_none());

        assert_eq!(names(&[0xfc]), [Err(DecodeError::Truncated { pc: 0 })]);
        assert_eq!(names(&[0xfc, 0x2f]), [Err(DecodeError::Undefined { pc: 0, opcode: 0xfc, sub: Some(0x2f) })]);
    }

    /// xorshift64*, enough to get reproducible noise without a dependency.
    struct Noise(u64);

    impl Noise {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn bytes(&mut self, len: usize) -> Vec<u8> {
            (0..len).map(|_| self.next().to_le_bytes()[0]).collect()
        }
    }

    /// Walk `code`, touch every accessor, and check the walk's own invariants.
    fn exercise(code: &[u8]) {
        let mut it = walk(code);
        let mut expected_pc = 0;
        let mut failed = false;
        for item in it.by_ref() {
            assert!(!failed, "items after an error");
            match item {
                Ok(insn) => {
                    assert_eq!(insn.pc, expected_pc);
                    assert_eq!(insn.bytes(), &code[insn.pc..insn.next_pc()]);
                    assert_eq!(insn.operands().count(), insn.opcode.operands.len());
                    assert!(insn.opcode.is_jump() || insn.jump_target().is_none());
                    let _ = (insn.string_id(), insn.method_id(), insn.literal_array_id(), insn.ic_slot(), insn.reg_range());
                    expected_pc = insn.next_pc();
                }
                Err(error) => {
                    assert_eq!(error.pc(), expected_pc);
                    failed = true;
                }
            }
        }
        assert_eq!(it.pc(), expected_pc);
        assert_eq!(failed, expected_pc != code.len());
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut noise = Noise(0x9e37_79b9_7f4a_7c15);
        for round in 0..20_000 {
            let len = usize::try_from(noise.next() % 64).unwrap();
            let mut code = noise.bytes(len);
            // Uniform noise dies on an undefined opcode within a few bytes:
            // bias half of the rounds towards prefixes and defined opcodes.
            if round % 2 == 0 {
                for byte in code.iter_mut().step_by(3) {
                    *byte = match *byte % 4 {
                        0 => 0xfb + *byte % 4,
                        _ => *byte % 0xe2,
                    };
                }
            }
            exercise(&code);
        }
    }

    #[test]
    fn every_truncation_of_valid_code_is_reported() {
        // One of each opcode back to back, operands zero.
        let mut code = Vec::new();
        for op in crate::opcodes() {
            let start = code.len();
            code.resize(start + op.byte_len(), 0);
            match op.prefix {
                None => code[start] = op.value,
                Some(prefix) => code[start..start + 2].copy_from_slice(&[prefix.byte(), op.value]),
            }
        }
        assert_eq!(walk(&code).filter(|item| item.is_ok()).count(), crate::opcodes().count());
        for len in 0..code.len() {
            exercise(&code[..len]);
        }
        // Every start offset, including the middle of instructions.
        for start in 0..code.len() {
            exercise(&code[start..]);
        }
    }
}
