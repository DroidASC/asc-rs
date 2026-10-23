//! Text rendering of resource values: one line per value, references shown
//! by name.

use crate::*;

/// Mantissa multipliers of the four complex radixes (23p0, 16p7, 8p15, 0p23),
/// including the `>> 8` shift of the mantissa.
const RADIX_MULTS: [f32; 4] = [1.0 / 256.0, 1.0 / 32_768.0, 1.0 / 8_388_608.0, 1.0 / 2_147_483_648.0];
const DIMENSION_UNITS: [&str; 6] = ["px", "dp", "sp", "pt", "in", "mm"];
const FRACTION_UNITS: [&str; 2] = ["%", "%p"];

/// `TYPE_DIMENSION`/`TYPE_FRACTION` payload as a float (signed 24-bit mantissa).
pub fn complex_to_float(data: u32) -> f32 {
    ((data & 0xffff_ff00) as i32) as f32 * RADIX_MULTS[((data >> 4) & 3) as usize]
}

/// `ResTable_map::ATTR_MIN`: aapt2 keys array items `ATTR_MIN + index`.
const ATTR_MIN: u32 = 0x0100_0001;

/// Names of the special bag keys of a bag of type `type_name`: array
/// indexes (`[3]`; aapt2 writes `ATTR_MIN + i`, aapt `0x02000000 | i`),
/// plurals quantities, and attr metadata (`^type`, `^min`, `^max`, `^l10n`).
pub fn bag_key_name(type_name: &str, key: u32) -> Option<String> {
    if key >> 24 == 0x02 {
        return Some(format!("[{}]", key & 0xffff));
    }
    if type_name == "array" || type_name.ends_with("-array") {
        return (ATTR_MIN..ATTR_MIN + 0x1_0000).contains(&key).then(|| format!("[{}]", key - ATTR_MIN));
    }
    let s = match key {
        0x0100_0000 => "^type",
        0x0100_0001 => "^min",
        0x0100_0002 => "^max",
        0x0100_0003 => "^l10n",
        0x0100_0004 => "other",
        0x0100_0005 => "zero",
        0x0100_0006 => "one",
        0x0100_0007 => "two",
        0x0100_0008 => "few",
        0x0100_0009 => "many",
        _ => return None,
    };
    Some(s.to_string())
}

/// Quote a string value the way JSON does: `"..."` with `\\`, `\"`, `\n`,
/// `\t`, `\r` and every other control character (`\u001b`) escaped, so a
/// value always stays on one line and reads back with any JSON parser.
pub fn quote(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            // Beyond JSON's own set: DEL and the C1 controls hide text just as
            // well. Every control character is in the BMP, so one `\u` does.
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Names binary XML references and app attributes from this table; ids it
/// does not define keep their numeric rendering.
impl asc_axml::Resolver for ResTable {
    fn reference(&self, id: u32) -> Option<String> {
        self.contains(id).then(|| self.ref_name(id))
    }

    fn attr_name(&self, id: u32) -> Option<String> {
        self.name(id).map(|n| n.entry)
    }
}

impl ResTable {
    /// `type/name` for resources of the first (app) package, `pkg:type/name`
    /// for others, `android:0x01xxxxxx` / `0x7fxxxxxx` when not in the table.
    pub fn ref_name(&self, id: u32) -> String {
        match self.name(id) {
            Some(n) if self.packages.first().is_some_and(|p| p.name == n.package) => n.short(),
            Some(n) => n.to_string(),
            None if id >> 24 == 0x01 => format!("android:0x{id:08x}"),
            None => format!("0x{id:08x}"),
        }
    }

    /// Name of a bag item key: the attr name for style items (`colorAccent`,
    /// `android:textSize`), `type/name` for other keys such as the `id`
    /// symbols of an enum attr, then the framework attrs `asc-axml` knows.
    pub fn attr_name(&self, id: u32) -> String {
        if let Some(n) = self.name(id) {
            let own = self.packages.first().is_some_and(|p| p.name == n.package);
            return match (own, n.type_name == "attr") {
                (true, true) => n.entry,
                (true, false) => n.short(),
                (false, true) => format!("{}:{}", n.package, n.entry),
                (false, false) => n.to_string(),
            };
        }
        match asc_axml::android_attr_name(id) {
            Some(n) => format!("android:{n}"),
            None => format!("0x{id:08x}"),
        }
    }

    /// One value as text: strings quoted, references by name, numbers in
    /// their declared notation.
    pub fn format_value(&self, v: &Value) -> String {
        let mut out = String::new();
        self.write_value(v, &mut out);
        out
    }

    fn write_value(&self, v: &Value, out: &mut String) {
        use std::fmt::Write as _;
        let d = v.data;
        let _ = match v.kind {
            TYPE_NULL if d == 1 => write!(out, "@empty"),
            TYPE_NULL => write!(out, "@null"),
            TYPE_REFERENCE | TYPE_DYNAMIC_REFERENCE if d == 0 => write!(out, "@null"),
            TYPE_REFERENCE | TYPE_DYNAMIC_REFERENCE => write!(out, "@{}", self.ref_name(d)),
            TYPE_ATTRIBUTE | TYPE_DYNAMIC_ATTRIBUTE => write!(out, "?{}", self.ref_name(d)),
            TYPE_STRING => {
                match self.string(d) {
                    Some(s) => quote(&s, out),
                    None => out.push_str("\"\""),
                }
                Ok(())
            }
            TYPE_FLOAT => write!(out, "{}", f32::from_bits(d)),
            TYPE_DIMENSION => write!(out, "{}{}", complex_to_float(d), DIMENSION_UNITS.get((d & 0xf) as usize).unwrap_or(&"")),
            // Shown as written in XML (`80%`), rounded to hide the binary mantissa.
            TYPE_FRACTION => {
                let pct = format!("{:.4}", complex_to_float(d) as f64 * 100.0);
                let pct = pct.trim_end_matches('0').trim_end_matches('.');
                write!(out, "{}{}", if pct == "-0" { "0" } else { pct }, FRACTION_UNITS.get((d & 0xf) as usize).unwrap_or(&""))
            }
            TYPE_INT_HEX => write!(out, "0x{d:08x}"),
            TYPE_INT_BOOLEAN => write!(out, "{}", d != 0),
            TYPE_INT_COLOR_ARGB8 | TYPE_INT_COLOR_ARGB4 => write!(out, "#{d:08x}"),
            TYPE_INT_COLOR_RGB8 | TYPE_INT_COLOR_RGB4 => write!(out, "#{:06x}", d & 0xff_ffff),
            TYPE_INT_DEC => write!(out, "{}", d as i32),
            k => write!(out, "(type 0x{k:02x}) 0x{d:08x}"),
        };
    }

    /// A configuration's value of resource `id` on one line. Bags render as
    /// `{parent=@style/X key=value key=value}`, with keys named for the
    /// resource's type (array `[0]`, plurals `one`, attr `^type`, style attrs).
    pub fn format_entry(&self, id: u32, e: &EntryValue) -> String {
        match e {
            EntryValue::Simple(v) => self.format_value(v),
            EntryValue::Bag { parent, items } => {
                let type_name = self.type_name_of(id).unwrap_or_default();
                let mut out = String::from("{");
                if *parent != 0 {
                    out.push_str("parent=@");
                    out.push_str(&self.ref_name(*parent));
                }
                for (k, v) in items {
                    if out.len() > 1 {
                        out.push(' ');
                    }
                    match bag_key_name(&type_name, *k) {
                        Some(n) => out.push_str(&n),
                        None => out.push_str(&self.attr_name(*k)),
                    }
                    out.push('=');
                    self.write_value(v, &mut out);
                }
                out.push('}');
                out
            }
        }
    }
}
