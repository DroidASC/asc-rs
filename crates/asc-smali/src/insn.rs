//! Method body rendering: instructions, labels, payloads, try/catch.

use crate::format::{escape_string, hex_i64};
use crate::{Names, Options, Result};
use asc_dalvik::{Format, IndexKind, Instruction, PayloadKind};
use asc_dex::code::CodeItem;
use asc_dex::debug_info::DebugInfo;
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;

#[derive(Default)]
struct Labels {
    /// address (bytes) → label names
    at: BTreeMap<usize, Vec<String>>,
}

impl Labels {
    fn add(&mut self, addr: usize, label: String) {
        let v = self.at.entry(addr).or_default();
        if !v.contains(&label) {
            v.push(label);
        }
    }
}

fn units(addr: usize) -> usize {
    addr / 2
}

/// One entry of a decoded method body.
enum Entry {
    Insn(Instruction),
    /// Undefined opcode byte (odex / quickened or corrupt code); rendered as
    /// a `# unknown opcode` comment and skipped by one code unit, like
    /// baksmali's `UnknownInstruction`.
    Unknown {
        pc: usize,
        opcode: u8,
    },
    /// A defined instruction or payload that runs past the end of the code;
    /// nothing can follow it.
    Truncated {
        pc: usize,
        opcode: u8,
    },
}

impl Entry {
    fn pc(&self) -> usize {
        match self {
            Entry::Insn(i) => i.pc,
            Entry::Unknown { pc, .. } | Entry::Truncated { pc, .. } => *pc,
        }
    }
}

fn decode_all(code: &CodeItem<'_>) -> Vec<Entry> {
    let insns = code.insns;
    let mut out = Vec::new();
    let mut pc = 0;
    while pc < insns.len() {
        match Instruction::decode(insns, pc) {
            Some(i) => {
                pc += i.byte_len();
                out.push(Entry::Insn(i));
            }
            None => {
                let opcode = insns[pc];
                if asc_dalvik::opcode(opcode).is_none() {
                    out.push(Entry::Unknown { pc, opcode });
                    pc += 2;
                } else {
                    out.push(Entry::Truncated { pc, opcode });
                    break;
                }
            }
        }
    }
    out
}

struct Try {
    catches: Vec<(Option<u32>, usize)>,
}

fn emit_try_end(
    out: &mut String,
    names: &mut Names<'_, '_>,
    addr: usize,
    tries: &[Try],
    try_ends: &BTreeMap<usize, Vec<usize>>,
) -> Result<()> {
    if let Some(list) = try_ends.get(&addr) {
        for &n in list {
            let _ = writeln!(out, "    :try_end_{n}");
            for (ty, target) in &tries[n].catches {
                match ty {
                    Some(ty) => {
                        let _ = writeln!(
                            out,
                            "    .catch {} {{:try_start_{n} .. :try_end_{n}}} :catch_{:x}",
                            names.type_(*ty)?,
                            units(*target)
                        );
                    }
                    None => {
                        let _ = writeln!(out, "    .catchall {{:try_start_{n} .. :try_end_{n}}} :catchall_{:x}", units(*target));
                    }
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn method_body(
    names: &mut Names<'_, '_>,
    code: &CodeItem<'_>,
    debug: Option<&DebugInfo>,
    opts: Options,
    out: &mut String,
    mut marks: Option<&mut Vec<(usize, usize)>>,
) -> Result<()> {
    let entries = decode_all(code);
    let mut labels = Labels::default();
    let by_pc: BTreeMap<usize, &Instruction> = entries
        .iter()
        .filter_map(|e| match e {
            Entry::Insn(i) => Some((i.pc, i)),
            _ => None,
        })
        .collect();
    // payload pc → switch instruction pc (case targets are relative to the switch).
    let mut switch_base: HashMap<usize, usize> = HashMap::new();

    // Branch and payload labels.
    for i in by_pc.values() {
        if let Some(t) = i.target() {
            let name = match i.opcode.format {
                Format::K10t | Format::K20t | Format::K30t => format!(":goto_{:x}", units(t)),
                Format::K21t | Format::K22t => format!(":cond_{:x}", units(t)),
                Format::K31t => match i.opcode.value {
                    0x26 => format!(":array_{:x}", units(t)),
                    0x2b => format!(":pswitch_data_{:x}", units(t)),
                    _ => format!(":sswitch_data_{:x}", units(t)),
                },
                _ => continue,
            };
            labels.add(t, name);
            if i.opcode.value == 0x2b || i.opcode.value == 0x2c {
                switch_base.entry(t).or_insert(i.pc);
                if let Some(p) = by_pc.get(&t) {
                    for target in switch_targets(code.insns, p, i.pc) {
                        let prefix = if i.opcode.value == 0x2b { "pswitch" } else { "sswitch" };
                        labels.add(target, format!(":{prefix}_{:x}", units(target)));
                    }
                }
            }
        }
    }
    // Try/catch labels.
    let mut tries = Vec::with_capacity(code.tries.len());
    let mut try_ends: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (n, t) in code.tries.iter().enumerate() {
        let start = t.start_addr as usize * 2;
        let end = start + t.insn_count as usize * 2;
        labels.add(start, format!(":try_start_{n}"));
        let mut catches = Vec::new();
        if let Some(h) = code.handler_for(t) {
            for (ty, addr) in &h.catches {
                let a = *addr as usize * 2;
                labels.add(a, format!(":catch_{:x}", units(a)));
                catches.push((Some(*ty), a));
            }
            if let Some(a) = h.catch_all_addr {
                let a = a as usize * 2;
                labels.add(a, format!(":catchall_{:x}", units(a)));
                catches.push((None, a));
            }
        }
        tries.push(Try { catches });
        try_ends.entry(end).or_default().push(n);
    }

    let mut lines: BTreeMap<usize, u32> = BTreeMap::new();
    if opts.line_numbers {
        if let Some(d) = debug {
            for (addr, line) in d.positions() {
                lines.entry(addr as usize * 2).or_insert(line);
            }
        }
    }

    let mut last_line: Option<u32> = None;
    for e in &entries {
        let pc = e.pc();
        emit_try_end(out, names, pc, &tries, &try_ends)?;
        if let Some(ls) = labels.at.get(&pc) {
            for l in ls {
                let _ = writeln!(out, "    {l}");
            }
        }
        if let Some(&line) = lines.get(&pc) {
            if last_line != Some(line) {
                let _ = writeln!(out, "    .line {line}");
                last_line = Some(line);
            }
        }
        if let Some(m) = marks.as_deref_mut() {
            m.push((pc, out.len()));
        }
        match e {
            Entry::Insn(i) => {
                if let Some(kind) = i.payload {
                    payload(code.insns, i, kind, switch_base.get(&i.pc).copied().unwrap_or(i.pc), out);
                    continue;
                }
                out.push_str("    ");
                instruction(names, i, out)?;
                out.push('\n');
            }
            Entry::Unknown { opcode, .. } => {
                let _ = writeln!(out, "    # unknown opcode {opcode:#04x}");
            }
            Entry::Truncated { opcode, .. } => {
                let name = asc_dalvik::opcode(*opcode).map_or("payload", |o| o.name);
                let _ = writeln!(out, "    # truncated instruction {name} ({opcode:#04x}) runs past the end of the code");
            }
        }
    }
    emit_try_end(out, names, code.insns.len(), &tries, &try_ends)?;
    if let Some(ls) = labels.at.get(&code.insns.len()) {
        for l in ls {
            let _ = writeln!(out, "    {l}");
        }
    }
    Ok(())
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn i32_at(b: &[u8], o: usize) -> i32 {
    i32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Absolute byte targets of a switch payload, relative to the switch at `base`.
fn switch_targets(insns: &[u8], payload: &Instruction, base: usize) -> Vec<usize> {
    let p = payload.pc;
    let mut out = Vec::new();
    match payload.payload {
        Some(PayloadKind::PackedSwitch) => {
            let size = u16_at(insns, p + 2) as usize;
            for k in 0..size {
                let off = p + 8 + k * 4;
                if off + 4 > insns.len() {
                    break;
                }
                let rel = i32_at(insns, off) as i64;
                let t = base as i64 + rel * 2;
                if t >= 0 {
                    out.push(t as usize);
                }
            }
        }
        Some(PayloadKind::SparseSwitch) => {
            let size = u16_at(insns, p + 2) as usize;
            for k in 0..size {
                let off = p + 4 + size * 4 + k * 4;
                if off + 4 > insns.len() {
                    break;
                }
                let rel = i32_at(insns, off) as i64;
                let t = base as i64 + rel * 2;
                if t >= 0 {
                    out.push(t as usize);
                }
            }
        }
        _ => {}
    }
    out
}

/// Render a payload. `base` is the address of the switch instruction that
/// references it (the payload's own address when no switch was found).
fn payload(insns: &[u8], i: &Instruction, kind: PayloadKind, base: usize, out: &mut String) {
    let p = i.pc;
    match kind {
        PayloadKind::PackedSwitch | PayloadKind::SparseSwitch => {
            let size = u16_at(insns, p + 2) as usize;
            if kind == PayloadKind::PackedSwitch {
                let first_key = i32_at(insns, p + 4);
                let _ = writeln!(out, "    .packed-switch {}", hex_i64(first_key as i64));
                for k in 0..size {
                    let off = p + 8 + k * 4;
                    if off + 4 > insns.len() {
                        break;
                    }
                    let t = base as i64 + i32_at(insns, off) as i64 * 2;
                    let _ = writeln!(out, "        :pswitch_{:x}", units(t.max(0) as usize));
                }
                out.push_str("    .end packed-switch\n");
            } else {
                out.push_str("    .sparse-switch\n");
                for k in 0..size {
                    let koff = p + 4 + k * 4;
                    let toff = p + 4 + size * 4 + k * 4;
                    if toff + 4 > insns.len() {
                        break;
                    }
                    let key = i32_at(insns, koff);
                    let t = base as i64 + i32_at(insns, toff) as i64 * 2;
                    let _ = writeln!(out, "        {} -> :sswitch_{:x}", hex_i64(key as i64), units(t.max(0) as usize));
                }
                out.push_str("    .end sparse-switch\n");
            }
        }
        PayloadKind::FillArrayData => {
            let width = u16_at(insns, p + 2) as usize;
            let size = u32::from_le_bytes([insns[p + 4], insns[p + 5], insns[p + 6], insns[p + 7]]) as usize;
            let _ = writeln!(out, "    .array-data {width}");
            let data = &insns[p + 8..];
            let suffix = match width {
                1 => "t",
                2 => "s",
                8 => "L",
                _ => "",
            };
            // Element widths other than 1/2/4/8 are invalid; render at most
            // the low 8 bytes of each element and never shift past 64 bits.
            for k in 0..size {
                if width == 0 {
                    break;
                }
                let off = k * width;
                if off + width > data.len() {
                    break;
                }
                let mut v: i64 = 0;
                for (n, &b) in data[off..off + width].iter().enumerate().take(8) {
                    v |= (b as i64) << (8 * n);
                }
                let bits = 8 * width.min(8) as u32;
                if bits < 64 {
                    let shift = 64 - bits;
                    v = (v << shift) >> shift;
                }
                let _ = writeln!(out, "        {}{suffix}", hex_i64(v));
            }
            out.push_str("    .end array-data\n");
        }
    }
}

fn reg_list(regs: &[u16]) -> String {
    let parts: Vec<String> = regs.iter().map(|r| format!("v{r}")).collect();
    format!("{{{}}}", parts.join(", "))
}

fn range_list(i: &Instruction) -> String {
    if i.regs.is_empty() {
        "{}".into()
    } else {
        format!("{{v{} .. v{}}}", i.regs[0], i.regs[i.regs.len() - 1])
    }
}

fn index_operand(names: &mut Names<'_, '_>, i: &Instruction, idx: u32, out: &mut String) -> Result<()> {
    match i.opcode.index {
        IndexKind::StringRef => {
            let _ = write!(out, "\"{}\"", escape_string(&names.dex.string(idx)?));
        }
        IndexKind::TypeRef => out.push_str(names.type_(idx)?),
        IndexKind::FieldRef => out.push_str(names.field(idx)?),
        IndexKind::MethodRef => out.push_str(names.method(idx)?),
        IndexKind::MethodAndProtoRef => {
            out.push_str(names.method(idx)?);
            out.push_str(", ");
            out.push_str(names.proto(i.h as u32)?);
        }
        IndexKind::ProtoRef => out.push_str(names.proto(idx)?),
        IndexKind::CallSiteRef => {
            let _ = write!(out, "call_site@{idx}");
        }
        IndexKind::MethodHandleRef => {
            let _ = write!(out, "method_handle@{idx}");
        }
        IndexKind::None | IndexKind::Unknown => {
            let _ = write!(out, "@{idx}");
        }
    }
    Ok(())
}

fn instruction(names: &mut Names<'_, '_>, i: &Instruction, out: &mut String) -> Result<()> {
    let name = i.opcode.name;
    let (a, b, c) = (i.a, i.b, i.c);
    let t = |addr: Option<usize>| units(addr.unwrap_or(0));
    match i.opcode.format {
        Format::K10x => out.push_str(name),
        Format::K12x => {
            let _ = write!(out, "{name} v{a}, v{b}");
        }
        Format::K11n => {
            let _ = write!(out, "{name} v{a}, {}", hex_i64(b));
        }
        Format::K11x => {
            let _ = write!(out, "{name} v{a}");
        }
        Format::K10t | Format::K20t | Format::K30t => {
            let _ = write!(out, "{name} :goto_{:x}", t(i.target()));
        }
        Format::K22x | Format::K32x => {
            let _ = write!(out, "{name} v{a}, v{b}");
        }
        Format::K21t => {
            let _ = write!(out, "{name} v{a}, :cond_{:x}", t(i.target()));
        }
        Format::K21s => {
            let suffix = if i.opcode.value == 0x16 { "L" } else { "" };
            let _ = write!(out, "{name} v{a}, {}{suffix}", hex_i64(b));
        }
        Format::K21h => {
            if i.opcode.value == 0x19 {
                let _ = write!(out, "{name} v{a}, {}L", hex_i64(b << 48));
            } else {
                let _ = write!(out, "{name} v{a}, {}", hex_i64((b as u16 as i16 as i64) << 16));
            }
        }
        Format::K21c => {
            let _ = write!(out, "{name} v{a}, ");
            index_operand(names, i, b as u32, out)?;
        }
        Format::K23x => {
            let _ = write!(out, "{name} v{a}, v{b}, v{c}");
        }
        Format::K22b => {
            let _ = write!(out, "{name} v{a}, v{b}, {}", hex_i64(c));
        }
        Format::K22t => {
            let _ = write!(out, "{name} v{a}, v{b}, :cond_{:x}", t(i.target()));
        }
        Format::K22s => {
            let _ = write!(out, "{name} v{a}, v{b}, {}", hex_i64(c));
        }
        Format::K22c => {
            let _ = write!(out, "{name} v{a}, v{b}, ");
            index_operand(names, i, c as u32, out)?;
        }
        Format::K31t => {
            let target = t(i.target());
            match i.opcode.value {
                0x26 => {
                    let _ = write!(out, "{name} v{a}, :array_{target:x}");
                }
                0x2b => {
                    let _ = write!(out, "{name} v{a}, :pswitch_data_{target:x}");
                }
                _ => {
                    let _ = write!(out, "{name} v{a}, :sswitch_data_{target:x}");
                }
            }
        }
        Format::K31i => {
            let suffix = if i.opcode.value == 0x17 { "L" } else { "" };
            let _ = write!(out, "{name} v{a}, {}{suffix}", hex_i64(b));
        }
        Format::K31c => {
            let _ = write!(out, "{name} v{a}, ");
            index_operand(names, i, b as u32, out)?;
        }
        Format::K35c | Format::K45cc => {
            let _ = write!(out, "{name} {}, ", reg_list(&i.regs));
            index_operand(names, i, b as u32, out)?;
        }
        Format::K3rc | Format::K4rcc => {
            let _ = write!(out, "{name} {}, ", range_list(i));
            index_operand(names, i, b as u32, out)?;
        }
        Format::K51l => {
            let _ = write!(out, "{name} v{a}, {}L", hex_i64(b));
        }
    }
    Ok(())
}
