#!/usr/bin/env python3
"""Generate `src/table.rs` (the ArkCompiler dynamic-ISA opcode table) from the
official `isa/isa.yaml` of arkcompiler_runtime_core.

Usage:
    python3 gen/gen_isa.py ISA_YAML [OUTPUT_RS]

    ISA_YAML  = <arkcompiler_runtime_core>/isa/isa.yaml
    OUTPUT_RS = <this crate>/src/table.rs (default)

Standard library only. `isa.yaml` is read by a small line-based reader that
understands exactly the subset the file uses (`prefixes:` and `groups:` with
block lists, `[a, b]` flow lists and `|` / `>` block scalars) and fails loudly
on anything else, so a layout change upstream is noticed instead of being
silently misread.

The interpretation follows upstream's `isa/isapi.rb`:

* every `(opcode_idx[i], format[i])` pair of an instruction is one opcode;
* a format name (`pref_op_imm1_4_imm2_4`) lists `name_width` fields that are
  laid out in that order, starting at bit 8 (bit 16 when prefixed), least
  significant bit first (`Format#encoding`, `BytecodeInst::Read`);
* operands are reported in *signature* order and looked up in the format by
  name; `*_id` operands map to the format's `id` field (`id1`, `id2`, ... in
  signature order when there is more than one) (`Instruction#operands`);
* an immediate is signed / unsigned / floating according to the signature
  type (`i32`, `u16`, `f64`); its width comes from the format;
* group properties are merged into every instruction of the group.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CRATE = os.path.dirname(HERE)

PREFIX_VARIANTS = {"callruntime": "CallRuntime", "deprecated": "Deprecated", "wide": "Wide", "throw": "Throw"}
ID_KINDS = {"string_id": "StringId", "method_id": "MethodId", "literalarray_id": "LiteralArrayId"}
SCALAR_KEYS = {"sig", "acc", "prefix"}
LIST_KEYS = {"opcode_idx", "format", "properties", "exceptions"}
# Calls outside the "call instructions" group: constructor calls and the two
# callruntime calls. isa.yaml has no `call` property on dynamic instructions.
EXTRA_CALLS = {"newobjapply", "newobjrange", "callinit", "supercallforwardallargs"}


def fail(msg):
    sys.exit(f"gen_isa.py: {msg}")


def scalar(text):
    text = text.strip()
    if re.fullmatch(r"0x[0-9a-fA-F]+", text):
        return int(text, 16)
    return text


def flow_list(text, where):
    text = text.strip()
    if not (text.startswith("[") and text.endswith("]")):
        fail(f"{where}: expected a [flow list], got {text!r}")
    return [scalar(item) for item in text[1:-1].split(",") if item.strip()]


def section(lines, name):
    """Lines of the top-level mapping key `name`, comments and blanks dropped."""
    start = next((i for i, line in enumerate(lines) if line.rstrip() == f"{name}:"), None)
    if start is None:
        fail(f"top-level key {name!r} not found")
    body = []
    for number, line in enumerate(lines[start + 1 :], start + 2):
        if line[:1] not in (" ", "#", "\n", ""):
            break
        if line.strip() and not line.lstrip().startswith("#"):
            body.append((number, line.rstrip("\n")))
    return body


def read_prefixes(lines):
    prefixes = {}
    name = None
    for number, line in section(lines, "prefixes"):
        if m := re.fullmatch(r"  - name: (\w+)", line):
            name = m.group(1)
        elif m := re.fullmatch(r"    opcode_idx: (0x[0-9a-fA-F]+)", line):
            prefixes[name] = int(m.group(1), 16)
        elif not re.fullmatch(r"    description: .*", line):
            fail(f"line {number}: unexpected line in prefixes: {line!r}")
    return prefixes


def read_groups(lines):
    """List of groups: {title, properties: [...], instructions: [{sig, acc, ...}]}."""
    groups = []
    group = insn = None
    open_list = None  # list currently being filled by `- item` lines
    list_indent = 0
    skip_deeper_than = None  # inside a block scalar
    for number, line in section(lines, "groups"):
        indent = len(line) - len(line.lstrip())
        text = line.strip()
        if skip_deeper_than is not None:
            if indent > skip_deeper_than:
                continue
            skip_deeper_than = None
        if open_list is not None and indent == list_indent and text.startswith("- "):
            open_list.append(scalar(text[2:]))
            continue
        open_list = None

        if indent == 2 and text.startswith("- "):
            group = {"properties": [], "exceptions": [], "instructions": []}
            groups.append(group)
            insn = None
            indent, text = 4, text[2:]
        elif indent == 6 and text.startswith("- "):
            if group is None:
                fail(f"line {number}: instruction outside a group")
            insn = {}
            group["instructions"].append(insn)
            indent, text = 8, text[2:]

        m = re.fullmatch(r"([a-z_]+):(?: (.*))?", text)
        if not m:
            fail(f"line {number}: cannot read {line!r}")
        key, value = m.group(1), (m.group(2) or "").strip()
        if indent == 4 and group is not None:
            target, insn = group, None
        elif indent == 8 and insn is not None:
            target = insn
            if key not in SCALAR_KEYS | LIST_KEYS:
                fail(f"line {number}: unknown instruction key {key!r}")
        else:
            fail(f"line {number}: unexpected indentation in {line!r}")

        if value in ("|", ">"):
            skip_deeper_than = indent
        elif key == "instructions":
            pass
        elif value == "":
            open_list, list_indent = [], indent + 2
            target[key] = open_list
        elif key in LIST_KEYS and value.startswith("["):
            target[key] = flow_list(value, f"line {number}")
        else:
            target[key] = scalar(value)
    return groups


class Field:
    def __init__(self, offset, width):
        self.offset = offset
        self.width = width


def format_fields(fmt):
    """`Format#encoding` + `Format#size`: field name -> bit offset/width, and the byte length."""
    prefixed = fmt.startswith("pref_")
    body = fmt.removeprefix("pref_")
    if not body.startswith("op_"):
        fail(f"format {fmt!r} does not start with [pref_]op_")
    body = body.removeprefix("op_")
    offset = 16 if prefixed else 8
    fields = {}
    if body != "none":
        parts = body.split("_")
        if len(parts) % 2:
            fail(f"format {fmt!r}: odd number of name/width parts")
        for name, width in zip(parts[0::2], parts[1::2]):
            if name in fields:
                fail(f"format {fmt!r}: duplicate field {name}")
            fields[name] = Field(offset, int(width))
            offset += int(width)
    if offset % 8:
        fail(f"format {fmt!r}: {offset} bits is not a whole number of bytes")
    return fields, offset // 8


def operand_rows(sig, fmt, props):
    """Operands in signature order as (kind, bit offset, bit width)."""
    fields, length = format_fields(fmt)
    parts = sig.split(" ", 1)
    operands = [p.strip() for p in parts[1].split(",")] if len(parts) == 2 else []
    id_total = sum(1 for o in operands if o.split(":")[0].endswith("id"))
    id_seen = 0
    imm_seen = 0
    rows = []
    used = set()
    for operand in operands:
        bits = operand.split(":")
        name = bits[0]
        base = re.sub(r"[0-9]", "", name)
        if base in ID_KINDS:
            if base not in props:
                fail(f"{sig!r}: operand {name} without the {base} property")
            id_seen += 1
            key = "id" if id_total == 1 else f"id{id_seen}"
            kind = ID_KINDS[base]
        elif base == "v":
            key = name
            direction = bits[1] if len(bits) == 3 else "in"
            kind = {"in": "RegIn", "out": "RegOut"}.get(direction) or fail(f"{sig!r}: register direction {direction!r}")
        elif base == "imm":
            key = name
            imm_seen += 1
            ty = bits[1] if len(bits) == 2 else fail(f"{sig!r}: immediate {name} without a type")
            if "jump" in props:
                if not ty.startswith("i"):
                    fail(f"{sig!r}: unsigned jump offset")
                kind = "JumpOffset"
            elif imm_seen == 1 and ("ic_slot" in props or "jit_ic_slot" in props):
                kind = "IcSlot"
            elif ty in ("f32", "f64"):
                kind = "ImmFloat"
            elif re.fullmatch(r"i(8|16|32|64)", ty):
                kind = "ImmSigned"
            elif re.fullmatch(r"u(1|2|8|16|32|64)", ty):
                kind = "ImmUnsigned"
            else:
                fail(f"{sig!r}: immediate type {ty!r}")
        else:
            fail(f"{sig!r}: unknown operand {operand!r}")
        if key not in fields:
            fail(f"{sig!r}: operand {name} ({key}) is not in format {fmt}")
        field = fields[key]
        used.add(key)
        if kind == "ImmFloat" and field.width != 64:
            fail(f"{sig!r}: float immediate of {field.width} bits")
        if kind == "IcSlot" and (field.width not in (8, 16) or field.offset != (16 if fmt.startswith("pref_") else 8)):
            fail(f"{sig!r}: ic slot is not the 8/16-bit immediate right after the opcode")
        if field.offset % 8 + field.width > 64:
            fail(f"{sig!r}: operand {name} does not fit a 64-bit read")
        # Value ranges the decoder relies on (`Value` in src/decode.rs).
        limit = {"RegIn": 16, "RegOut": 16, "IcSlot": 16, "JumpOffset": 32, "ImmFloat": 64, "ImmSigned": 64, "ImmUnsigned": 32}.get(kind, 32)
        if field.width > limit:
            fail(f"{sig!r}: {kind} operand {name} is {field.width} bits wide, more than {limit}")
        rows.append((kind, field.offset, field.width))
    if used != set(fields):
        fail(f"{sig!r}: format {fmt} fields {sorted(set(fields) - used)} have no operand")
    for id_kind in ID_KINDS.values():
        if sum(1 for row in rows if row[0] == id_kind) > 1:
            fail(f"{sig!r}: more than one {id_kind} operand")
    if ("ic_slot" in props or "jit_ic_slot" in props) and not any(row[0] == "IcSlot" for row in rows):
        fail(f"{sig!r}: ic_slot property but no immediate operand")
    if "jump" in props and sum(1 for row in rows if row[0] == "JumpOffset") != 1:
        fail(f"{sig!r}: jump without exactly one offset")
    if ("range_0" in props or "range_1" in props) and not (
        any(r[0] == "RegIn" for r in rows) and any(r[0] == "ImmUnsigned" for r in rows)
    ):
        fail(f"{sig!r}: range property without a register and a count immediate")
    return rows, length


def flag_names(group, insn, props, rows):
    mnemonic = insn["sig"].split(" ")[0]
    prefix = insn.get("prefix")
    acc = insn.get("acc")
    m = re.fullmatch(r"(none)|(in|out|inout):\w+", acc or "")
    if not m:
        fail(f"{insn['sig']!r}: accumulator signature {acc!r}")
    flags = []
    if m.group(2) in ("in", "inout"):
        flags.append("ACC_READ")
    if m.group(2) in ("out", "inout"):
        flags.append("ACC_WRITE")
    if "jump" in props:
        flags.append("JUMP")
    if "conditional" in props:
        flags.append("CONDITIONAL")
    if "return" in props:
        flags.append("RETURN")
    # `Instruction#is_unconditional_throw_instruction?`
    if prefix == "throw":
        flags.append("THROW_IF" if "conditional_throw" in props else "THROW")
    if group["title"] == "call instructions" or mnemonic.split(".")[-1] in EXTRA_CALLS:
        flags.append("CALL")
    if "range_0" in props:
        flags.append("RANGE_0")
    if "range_1" in props:
        flags.append("RANGE_1")
    if any(row[0] == "IcSlot" for row in rows):
        flags.append("IC_SLOT")
    if "two_slot" in props:
        flags.append("IC_TWO_SLOTS")
    return flags


def build(groups, prefixes):
    """{prefix name or None: {opcode byte: row}} plus the set of distinct formats."""
    tables = {None: {}, **{name: {} for name in prefixes}}
    formats = set()
    for group in groups:
        for insn in group["instructions"]:
            for key in ("sig", "acc", "opcode_idx", "format"):
                if key not in insn:
                    fail(f"{insn.get('sig')!r} in group {group['title']!r}: missing {key}")
            sig = insn["sig"]
            mnemonic = sig.split(" ")[0]
            prefix = insn.get("prefix")
            if prefix is not None and prefix not in prefixes:
                fail(f"{sig!r}: unknown prefix {prefix!r}")
            if len(insn["opcode_idx"]) != len(insn["format"]):
                fail(f"{sig!r}: format and opcode_idx arrays differ in size")
            props = list(dict.fromkeys(group["properties"] + insn.get("properties", [])))
            for value, fmt in zip(insn["opcode_idx"], insn["format"]):
                if fmt.startswith("pref_") != (prefix is not None):
                    fail(f"{sig!r}: format {fmt} disagrees with prefix {prefix!r}")
                if not 0 <= value <= 0xFF or (prefix is None and value in prefixes.values()):
                    fail(f"{sig!r}: opcode {value:#x} out of range or a prefix byte")
                if value in tables[prefix]:
                    fail(f"{sig!r}: opcode {value:#x} already taken by {tables[prefix][value]['name']}")
                rows, length = operand_rows(sig, fmt, props)
                formats.add(fmt)
                tables[prefix][value] = {
                    "name": mnemonic,
                    "len": length,
                    "flags": flag_names(group, insn, props, rows),
                    "operands": rows,
                }
    return tables, formats


def render_row(prefix, value, row):
    flags = " | ".join(row["flags"]) or "0"
    operands = ", ".join(f"o({kind}, {offset}, {width})" for kind, offset, width in row["operands"])
    return f'    op({prefix}, {value:#04x}, "{row["name"]}", {row["len"]}, {flags}, &[{operands}]),'


def render(tables, prefixes, source):
    out = [
        f"// Generated by gen/gen_isa.py from {source}. Do not edit by hand.",
        "",
        "use crate::flag::{ACC_READ, ACC_WRITE, CALL, CONDITIONAL, IC_SLOT, IC_TWO_SLOTS, JUMP, RANGE_0, RANGE_1, RETURN, THROW, THROW_IF};",
        "use crate::OperandKind::{IcSlot, ImmFloat, ImmSigned, ImmUnsigned, JumpOffset, LiteralArrayId, MethodId, RegIn, RegOut, StringId};",
        "use crate::{Opcode, Operand, OperandKind, Prefix};",
        "",
        "const fn op(prefix: Option<Prefix>, value: u8, name: &'static str, len: u8, flags: u16, operands: &'static [Operand]) -> Option<Opcode> {",
        "    Some(Opcode { prefix, value, name, len, flags, operands })",
        "}",
        "",
        "const fn o(kind: OperandKind, offset: u8, width: u8) -> Operand {",
        "    Operand { kind, offset, width }",
        "}",
        "",
        "const P: Option<Prefix> = None;",
    ]
    letters = {}
    for name in sorted(prefixes, key=prefixes.get):
        letter = name[0].upper()
        if letter in letters or letter == "P":
            fail(f"prefix {name!r}: short constant name clashes")
        letters[name] = letter
        out.append(f"const {letter}: Option<Prefix> = Some(Prefix::{PREFIX_VARIANTS[name]});")
    out += [
        "",
        "/// Unprefixed opcodes, indexed by the opcode byte.",
        "#[rustfmt::skip]",
        "pub(crate) static PRIMARY_OPS: [Option<Opcode>; 256] = [",
    ]
    for value in range(256):
        row = tables[None].get(value)
        if row:
            out.append(render_row("P", value, row))
        elif value in prefixes.values():
            out.append(f"    None, // {value:#04x}: prefix")
        else:
            out.append(f"    None, // {value:#04x}")
    out.append("];")
    for name in sorted(prefixes, key=prefixes.get):
        table = tables[name]
        size = max(table) + 1
        out += [
            "",
            f"/// `{name}.*` opcodes (prefix byte `{prefixes[name]:#04x}`), indexed by the sub-opcode byte.",
            "#[rustfmt::skip]",
            f"pub(crate) static {name.upper()}_OPS: [Option<Opcode>; {size}] = [",
        ]
        for value in range(size):
            row = table.get(value)
            out.append(render_row(letters[name], value, row) if row else f"    None, // {value:#04x}")
        out.append("];")
    return "\n".join(out) + "\n"


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    isa_yaml = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) == 3 else os.path.join(CRATE, "src", "table.rs")
    with open(isa_yaml, encoding="utf-8") as f:
        lines = f.readlines()
    prefixes = read_prefixes(lines)
    if set(prefixes) != set(PREFIX_VARIANTS):
        fail(f"prefixes changed: {sorted(prefixes)} (update PREFIX_VARIANTS and `Prefix` in src/lib.rs)")
    version = next((m.group(1) for line in lines if (m := re.fullmatch(r"version: (\S+)\n?", line))), "unknown")
    tables, formats = build(read_groups(lines), prefixes)
    with open(output, "w", encoding="utf-8") as f:
        f.write(render(tables, prefixes, f"arkcompiler_runtime_core isa/isa.yaml (version {version})"))
    counts = ", ".join(f"{name or 'primary'}: {len(table)}" for name, table in tables.items())
    total = sum(len(table) for table in tables.values())
    print(f"{output}: {total} opcodes ({counts}), {len(formats)} formats", file=sys.stderr)


if __name__ == "__main__":
    main()
