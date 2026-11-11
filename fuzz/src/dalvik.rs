//! `asc-dalvik`: decoding, the payload-aware walk, range verification and
//! the call-site value analysis over arbitrary code units.
//!
//! Layout of the input: byte 0 the frame's register count, byte 1 its
//! parameter count, byte 2 how many of the following 6-byte try/handler
//! triples to read (at most 3), then the code.

use asc_dalvik::values::{Analyzer, Catch, MethodCode};
use asc_dalvik::{IndexKind, Instruction, opcode, verify_range, vreg_a, vreg_b, vreg_c, vreg_h, walk};

pub fn run(data: &[u8]) {
    let [registers, ins, tries, rest @ ..] = data else { return };
    let tries = usize::from(*tries % 4);
    let Some((triples, code)) = rest.split_at_checked(tries * 6) else { return };
    let catches: Vec<Catch> = triples
        .as_chunks::<6>()
        .0
        .iter()
        .map(|t| {
            let at = |i: usize| usize::from(u16::from_le_bytes([t[i], t[i + 1]])) * 2;
            Catch { start: at(0), end: at(2), handler: at(4) }
        })
        .collect();

    let mut pcs = Vec::new();
    let walked = walk::walk_insns(code, |step| pcs.push(step.pc));
    let _ = walked.is_complete();
    for &pc in &pcs {
        let insn = Instruction::decode(code, pc).expect("walked instruction decodes");
        let _ = (insn.target(), insn.byte_len());
        let op = opcode(code[pc]).expect("walked instruction has an opcode");
        if op.index != IndexKind::None {
            let _ = asc_dalvik::get_index(code, pc, op);
        }
    }
    // Every offset, not only instruction boundaries: the scanners probe
    // arbitrary offsets before verifying them.
    for pc in (0..code.len()).step_by(2) {
        let _ = Instruction::decode(code, pc);
        if let Some(op) = opcode(code[pc]) {
            let _ = (vreg_a(code, pc, op), vreg_b(code, pc, op), vreg_c(code, pc, op), vreg_h(code, pc, op));
        }
        let _ = verify_range(code, pc, code.len());
        let _ = verify_range(code, 0, pc);
    }

    let mut analyzer = Analyzer::new();
    let method = MethodCode::new(code, u16::from(*registers), u16::from(*ins), &catches);
    if let Some(mut values) = analyzer.analyze(method) {
        for &pc in &pcs {
            let _ = values.args(pc);
            let _ = values.result_use(pc);
        }
        // Offsets that are not instructions are answered too.
        let _ = values.args(1);
        let _ = values.result_use(code.len());
    }
}
