//! `asc-arkisa`: the linear walk and decoding at every offset, with every
//! operand accessor.

use asc_arkisa::Instruction;

pub fn run(code: &[u8]) {
    let mut walk = asc_arkisa::walk(code);
    let mut expected = 0;
    for item in walk.by_ref() {
        match item {
            Ok(insn) => {
                assert_eq!(insn.pc, expected, "walk skipped bytes");
                assert!(insn.next_pc() > insn.pc && insn.next_pc() <= code.len(), "instruction outside the code");
                touch(&insn);
                expected = insn.next_pc();
            }
            Err(error) => assert_eq!(error.pc(), expected, "error away from the failing instruction"),
        }
    }
    assert_eq!(walk.pc(), expected);
    for pc in 0..=code.len() {
        if let Ok(insn) = Instruction::decode(code, pc) {
            touch(&insn);
        }
    }
}

fn touch(insn: &Instruction<'_>) {
    let _ = (insn.bytes(), insn.operands().count(), insn.string_id(), insn.method_id(), insn.literal_array_id());
    let _ = (insn.ic_slot(), insn.jump_offset(), insn.jump_target(), insn.reg_range());
    for index in 0..=insn.opcode.operands.len() {
        let _ = insn.operand(index);
    }
}
