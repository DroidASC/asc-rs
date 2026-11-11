//! Arbitrary code units never panic the decoder, the walk, range
//! verification or the value analysis: the method bodies of the fixture
//! DEX files, mutated with a fixed seed, plus plain noise biased towards
//! defined opcodes and payload identifiers.

use asc_dalvik::values::{Analyzer, Catch, MethodCode};
use asc_dalvik::{IndexKind, Instruction, get_index, opcode, verify_range, vreg_a, vreg_b, vreg_c, vreg_h, walk};
use asc_dex::Dex;
use asc_fixture::mutate::{Rng, mutate};

fn bodies() -> Vec<(Vec<u8>, u16, u16)> {
    let mut out = Vec::new();
    for data in [asc_fixture::make_rich_dex(), asc_fixture::make_field_access_dex(), asc_fixture::make_dex()] {
        let dex = Dex::parse(&data).unwrap();
        for class in dex.class_defs().flatten() {
            for method in dex.class_data(class.class_data_off).unwrap().methods().filter(|m| m.code_off != 0) {
                let code = dex.code_item(method.code_off).unwrap();
                out.push((code.insns.to_vec(), code.registers_size, code.ins_size));
            }
        }
    }
    out
}

fn exercise(code: &[u8], registers: u16, ins: u16, catches: &[Catch]) {
    let mut pcs = Vec::new();
    walk::walk_insns(code, |step| pcs.push(step.pc));
    for &pc in &pcs {
        let insn = Instruction::decode(code, pc).expect("a walked instruction decodes");
        let _ = insn.target();
        let op = opcode(code[pc]).expect("a walked instruction has an opcode");
        if op.index != IndexKind::None {
            let _ = get_index(code, pc, op);
        }
    }
    for pc in 0..code.len() {
        let _ = Instruction::decode(code, pc);
        if let Some(op) = opcode(code[pc]) {
            let _ = (vreg_a(code, pc, op), vreg_b(code, pc, op), vreg_c(code, pc, op), vreg_h(code, pc, op));
        }
        let _ = verify_range(code, pc, code.len());
    }
    let mut analyzer = Analyzer::new();
    if let Some(mut values) = analyzer.analyze(MethodCode { insns: code, registers, ins, catches }) {
        for &pc in pcs.iter().chain(&[1, code.len()]) {
            let _ = (values.args(pc), values.result_use(pc));
        }
    }
}

fn random_catches(rng: &mut Rng, len: usize) -> Vec<Catch> {
    let mut at = || rng.below(len + 8) & !1;
    let n = at() % 3;
    (0..n).map(|_| Catch { start: at(), end: at(), handler: at() }).collect()
}

#[test]
fn mutated_method_bodies_never_panic() {
    let mut rng = Rng::new(0xda1);
    for (code, registers, ins) in bodies() {
        exercise(&code, registers, ins, &[]);
        for _ in 0..1000 {
            let mut mutant = code.clone();
            mutate(&mut rng, &mut mutant);
            let catches = random_catches(&mut rng, mutant.len());
            let registers = if rng.below(4) == 0 { u16::try_from(rng.below(300)).unwrap() } else { registers };
            exercise(&mutant, registers, ins, &catches);
        }
    }
}

#[test]
fn noise_never_panics() {
    const IDENTS: [[u8; 2]; 3] = [[0x00, 0x01], [0x00, 0x02], [0x00, 0x03]];
    let mut rng = Rng::new(0x0dd);
    for _ in 0..10_000 {
        let len = rng.below(48) * 2;
        let mut code: Vec<u8> = (0..len).map(|_| rng.next_u64().to_le_bytes()[0]).collect();
        // Uniform bytes stop at an undefined opcode within a few units:
        // plant payload identifiers and defined opcodes instead.
        for unit in code.as_chunks_mut::<2>().0 {
            match rng.below(6) {
                0 => unit.copy_from_slice(&IDENTS[rng.below(3)]),
                1 | 2 => unit[0] = [0x12, 0x1a, 0x22, 0x2b, 0x2c, 0x26, 0x6e, 0x71, 0x74, 0x0c, 0x0e, 0x32][rng.below(12)],
                _ => {}
            }
        }
        let catches = random_catches(&mut rng, code.len());
        exercise(&code, 16, u16::try_from(rng.below(18)).unwrap(), &catches);
    }
}
