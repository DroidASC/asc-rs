//! `number:`: numeric constants.
//!
//! A number in ArkTS code is the immediate of `ldai` (a 32-bit integer) or
//! `fldai` (a double), or an `INTEGER` / `FLOAT` / `DOUBLE` item of an array
//! or object literal (`createarraywithbuffer`, `createobjectwithbuffer`).
//! The other immediates are not program data and are not searched:
//! inline-cache slots, register and argument counts, lexical slots, module
//! indexes, element indexes. Neither are the integers of class literals
//! (`defineclasswithbuffer`), which count methods.
//!
//! There is nothing to locate first, constants are inline. A single value
//! is ruled out for the whole file when none of its encodings occurs in it.

use asc_abc::{Abc, Literal};
use asc_arkisa::{DecodeError, OperandKind, Value};
use memchr::memmem;

use super::{Condition, Env, Function, Hit, MAX_LITERAL_DEPTH, NumberQuery, Record, RecordHit, Worker, pc_of};
use crate::ops::{OpTable, base_name};

/// Where an opcode holds a number.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Holds {
    #[default]
    Nothing,
    /// `ldai`, `fldai`: the immediate.
    Immediate,
    /// An array or object literal, named by a 16-bit id.
    Literal,
}

impl Holds {
    fn of(opcode: &asc_arkisa::Opcode) -> Holds {
        let immediate = |kind| opcode.operand_of(kind).is_some();
        if immediate(OperandKind::ImmSigned) || immediate(OperandKind::ImmFloat) {
            Holds::Immediate
        } else if matches!(base_name(opcode), "createarraywithbuffer" | "createobjectwithbuffer") {
            Holds::Literal
        } else {
            Holds::Nothing
        }
    }
}

/// A prepared `number:` search of one ABC entry.
pub(crate) struct Numbers<'q, 'a> {
    abc: Abc<'a>,
    query: &'q NumberQuery,
    operands: OpTable<Holds>,
    impossible: bool,
}

/// Whether no encoding of the single value `value` occurs in `file`.
fn rules_out(query: &NumberQuery, value: f64, file: &[u8]) -> bool {
    let absent = |bytes: &[u8]| memmem::find(file, bytes).is_none();
    // `ldai` and `INTEGER` items: four little-endian bytes.
    let int = (value.fract() == 0.0 && value >= f64::from(i32::MIN) && value <= f64::from(i32::MAX)).then_some(value as i32);
    // `FLOAT` items, when the value is one.
    let single = Some(value as f32).filter(|&single| f64::from(single) == value);
    [int, query.wrapped()].into_iter().flatten().all(|int| absent(&int.to_le_bytes()))
        && single.is_none_or(|single| absent(&single.to_le_bytes()))
        // `fldai` and `DOUBLE` items; -0.0 has its own bits and equals 0.0.
        && absent(&value.to_le_bytes())
        && (value != 0.0 || absent(&(-value).to_le_bytes()))
}

impl<'q, 'a> Numbers<'q, 'a> {
    pub(crate) fn prepare(env: &Env<'q, 'a>, query: &'q NumberQuery) -> Numbers<'q, 'a> {
        let impossible = query.single().is_some_and(|value| rules_out(query, value, env.abc.bytes()));
        Numbers { abc: env.abc, query, operands: OpTable::build(Holds::of), impossible }
    }

    /// The matching numbers of the literal array at `off`, as `[2]=2`.
    fn literal_hits(&self, off: u32, prefix: &str, depth: usize, out: &mut Vec<String>) {
        let Ok(array) = self.abc.literal_array(off) else { return };
        for (index, literal) in array.iter().map_while(|literal| literal.ok()).enumerate() {
            let text = match literal {
                Literal::Integer(value) if self.query.matches_int(value) => int_text(value),
                Literal::Float(value) if self.query.matches_float(f64::from(value)) => format!("{value}"),
                Literal::Double(value) if self.query.matches_float(value) => format!("{value}"),
                Literal::LiteralArray(nested) if depth < MAX_LITERAL_DEPTH => {
                    self.literal_hits(nested, &format!("{prefix}[{index}]"), depth + 1, out);
                    continue;
                }
                _ => continue,
            };
            out.push(format!("{prefix}[{index}]={text}"));
        }
    }
}

/// `1919810 (0x1d4b42)`: both spellings, as the disassembly gives them, so
/// that nobody converts by hand; small numbers stay plain.
fn int_text(value: i32) -> String {
    if (-9..=9).contains(&value) { format!("{value}") } else { format!("{value} ({value:#x})") }
}

impl<'a> Condition<'a> for Numbers<'_, 'a> {
    fn worker<'s>(&'s self) -> Box<dyn Worker<'a> + 's> {
        Box::new(NumbersWorker(self))
    }

    fn is_impossible(&self) -> bool {
        self.impossible
    }
}

struct NumbersWorker<'s, 'q, 'a>(&'s Numbers<'q, 'a>);

impl<'a> Worker<'a> for NumbersWorker<'_, '_, 'a> {
    fn record(&mut self, _: &Record<'_, 'a>, _: &mut Vec<RecordHit>) -> bool {
        true
    }

    fn function(&mut self, function: &Function<'_, 'a>, hits: &mut Vec<Hit>) -> std::result::Result<(), DecodeError> {
        let numbers = self.0;
        for insn in asc_arkisa::walk(function.code.instructions()) {
            let insn = insn?;
            match numbers.operands.of(insn.opcode) {
                Holds::Nothing => {}
                Holds::Immediate => {
                    let matched = match insn.operand(0) {
                        Some(Value::Imm(value)) => {
                            i32::try_from(value).ok().filter(|&value| numbers.query.matches_int(value)).map(int_text)
                        }
                        Some(Value::Float(value)) => numbers.query.matches_float(value).then(|| format!("{value}")),
                        _ => None,
                    };
                    if let Some(matched) = matched {
                        hits.push(Hit { pc: pc_of(&insn), matched: vec![matched], text: function.text(&insn) });
                    }
                }
                Holds::Literal => {
                    let Some(off) = insn.literal_array_id().and_then(|id| function.entity(id)) else { continue };
                    let mut items = Vec::new();
                    numbers.literal_hits(off, "", 0, &mut items);
                    if !items.is_empty() {
                        let text = format!("{} literal@{off:#x} {}", insn.opcode.name, items.join(", "));
                        hits.push(Hit { pc: pc_of(&insn), matched: items, text });
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_constants_are_numbers() {
        let holding = |wanted: Holds| {
            let mut names: Vec<&str> = asc_arkisa::opcodes().filter(|op| Holds::of(op) == wanted).map(|op| op.name).collect();
            names.sort_unstable();
            names.dedup();
            names
        };
        assert_eq!(holding(Holds::Immediate), ["fldai", "ldai"]);
        assert_eq!(holding(Holds::Literal), ["createarraywithbuffer", "createobjectwithbuffer"]);
        // No searched immediate is an inline-cache slot.
        for opcode in asc_arkisa::opcodes().filter(|op| Holds::of(op) == Holds::Immediate) {
            assert!(opcode.ic_slots() == 0 && opcode.operands.len() == 1, "{}", opcode.name);
        }
    }

    #[test]
    fn a_single_value_is_ruled_out_by_its_encodings() {
        let query = |spec: &str| spec.parse::<NumberQuery>().unwrap();
        let rules = |spec: &str, file: &[u8]| rules_out(&query(spec), query(spec).single().unwrap(), file);
        let ldai = [0x62, 0x42, 0x4b, 0x1d, 0x00];
        assert!(!rules("0x1d4b42", &ldai) && rules("0x1d4b43", &ldai));
        // The unsigned spelling is found by the bytes of the negative integer.
        assert!(!rules("0x9e3779b9", &(-1_640_531_527i32).to_le_bytes()));
        assert!(!rules("1.5", &1.5f64.to_le_bytes()) && !rules("1.5", &1.5f32.to_le_bytes()) && rules("1.5", &ldai));
        // An integer may be stored as a double.
        assert!(!rules("3", &3.0f64.to_le_bytes()) && !rules("0", &(-0.0f64).to_le_bytes()));
        assert_eq!(
            (int_text(5), int_text(-1_640_531_527), int_text(1_919_810)),
            ("5".into(), "-1640531527 (0x9e3779b9)".into(), "1919810 (0x1d4b42)".into())
        );
    }
}
