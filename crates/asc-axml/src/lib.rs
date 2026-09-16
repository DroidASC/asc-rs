//! Android binary XML decoder (the format of `AndroidManifest.xml` inside an
//! APK). Produces pretty-printed text XML.
//!
//! The decoder is defensive: malformed or truncated input yields an
//! [`AxmlError`] (or a best-effort string) but never panics, because the CLI is
//! built with `panic = "abort"`.

mod attrs;

use std::fmt::Write as _;

const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_XML_TYPE: u16 = 0x0003;
const RES_XML_START_NAMESPACE_TYPE: u16 = 0x0100;
const RES_XML_END_NAMESPACE_TYPE: u16 = 0x0101;
const RES_XML_START_ELEMENT_TYPE: u16 = 0x0102;
const RES_XML_END_ELEMENT_TYPE: u16 = 0x0103;
const RES_XML_CDATA_TYPE: u16 = 0x0104;
const RES_XML_RESOURCE_MAP_TYPE: u16 = 0x0180;

const UTF8_FLAG: u32 = 1 << 8;
/// Size of `ResStringPool_header`.
const STRING_POOL_HEADER_SIZE: usize = 28;
/// Size of `ResXMLTree_attribute`.
const ATTRIBUTE_SIZE: usize = 20;
/// `android:` framework package id.
const ANDROID_PACKAGE_ID: u32 = 0x01;
const ANDROID_NS_URI: &str = "http://schemas.android.com/apk/res/android";

pub const TYPE_NULL: u8 = 0x00;
pub const TYPE_REFERENCE: u8 = 0x01;
pub const TYPE_ATTRIBUTE: u8 = 0x02;
pub const TYPE_STRING: u8 = 0x03;
pub const TYPE_FLOAT: u8 = 0x04;
pub const TYPE_DIMENSION: u8 = 0x05;
pub const TYPE_FRACTION: u8 = 0x06;
pub const TYPE_DYNAMIC_REFERENCE: u8 = 0x07;
pub const TYPE_DYNAMIC_ATTRIBUTE: u8 = 0x08;
pub const TYPE_INT_DEC: u8 = 0x10;
pub const TYPE_INT_HEX: u8 = 0x11;
pub const TYPE_INT_BOOLEAN: u8 = 0x12;
pub const TYPE_INT_COLOR_ARGB8: u8 = 0x1c;
pub const TYPE_INT_COLOR_RGB8: u8 = 0x1d;
pub const TYPE_INT_COLOR_ARGB4: u8 = 0x1e;
pub const TYPE_INT_COLOR_RGB4: u8 = 0x1f;

#[derive(Debug, thiserror::Error)]
pub enum AxmlError {
    #[error("not a binary XML document")]
    NotAxml,
    #[error("truncated chunk at offset {0:#x}")]
    Truncated(usize),
    #[error("string pool missing before first element")]
    NoStringPool,
    #[error("malformed binary XML: {0}")]
    Malformed(&'static str),
}

pub type Result<T> = std::result::Result<T, AxmlError>;

#[inline]
fn u8_at(b: &[u8], o: usize) -> Result<u8> {
    b.get(o).copied().ok_or(AxmlError::Truncated(o))
}
#[inline]
fn u16_at(b: &[u8], o: usize) -> Result<u16> {
    o.checked_add(2).and_then(|e| b.get(o..e)).map(|s| u16::from_le_bytes([s[0], s[1]])).ok_or(AxmlError::Truncated(o))
}
#[inline]
fn u32_at(b: &[u8], o: usize) -> Result<u32> {
    o.checked_add(4).and_then(|e| b.get(o..e)).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]])).ok_or(AxmlError::Truncated(o))
}

/// Decoded string pool.
#[derive(Debug, Default)]
pub struct StringPool {
    strings: Vec<String>,
}

impl StringPool {
    /// Parse the string pool chunk starting at `chunk` and ending (exclusive) at
    /// `chunk_end`, which must already be clamped to `data.len()`.
    fn parse(data: &[u8], chunk: usize, chunk_end: usize) -> Result<StringPool> {
        let header_size = u16_at(data, chunk + 2)? as usize;
        let count = u32_at(data, chunk + 8)? as usize;
        let style_count = u32_at(data, chunk + 12)? as usize;
        let flags = u32_at(data, chunk + 16)?;
        let strings_start = u32_at(data, chunk + 20)? as usize;
        let utf8 = flags & UTF8_FLAG != 0;

        // The offset arrays live between the header and the string data; they
        // bound how many entries can possibly exist, so never trust `count`
        // (or `style_count`) beyond what fits in the chunk.
        let offsets_start = chunk
            .checked_add(header_size.max(STRING_POOL_HEADER_SIZE))
            .filter(|&o| o <= chunk_end)
            .ok_or(AxmlError::Malformed("string pool header exceeds chunk"))?;
        let available = (chunk_end - offsets_start) / 4;
        if count > available {
            return Err(AxmlError::Malformed("string pool string count exceeds chunk"));
        }
        if style_count > available - count {
            return Err(AxmlError::Malformed("string pool style count exceeds chunk"));
        }
        let data_start = chunk
            .checked_add(strings_start)
            .filter(|&o| o <= chunk_end)
            .ok_or(AxmlError::Malformed("string pool data offset exceeds chunk"))?;

        let mut strings = Vec::with_capacity(count);
        for i in 0..count {
            let rel = u32_at(data, offsets_start + i * 4)? as usize;
            match data_start.checked_add(rel) {
                Some(off) if off < chunk_end => {
                    strings.push(if utf8 { decode_utf8(data, off, chunk_end) } else { decode_utf16(data, off, chunk_end) })
                }
                _ => strings.push(String::new()),
            }
        }
        Ok(StringPool { strings })
    }

    pub fn get(&self, idx: u32) -> Option<&str> {
        self.strings.get(idx as usize).map(|s| s.as_str())
    }

    pub fn len(&self) -> usize {
        self.strings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.strings.is_empty()
    }
}

/// Decode a UTF-8 pool entry at `off`; never reads past `end` (`<= data.len()`).
fn decode_utf8(data: &[u8], mut off: usize, end: usize) -> String {
    // char length (1 or 2 bytes), then byte length (1 or 2 bytes)
    let skip_len = |off: &mut usize| -> usize {
        let b0 = data.get(*off).copied().unwrap_or(0) as usize;
        *off += 1;
        if b0 & 0x80 != 0 {
            let b1 = data.get(*off).copied().unwrap_or(0) as usize;
            *off += 1;
            ((b0 & 0x7f) << 8) | b1
        } else {
            b0
        }
    };
    let _chars = skip_len(&mut off);
    let bytes = skip_len(&mut off);
    let end = end.min(data.len());
    let stop = off.saturating_add(bytes).min(end);
    let slice = &data[off.min(stop)..stop];
    let slice = match slice.iter().position(|&b| b == 0) {
        Some(p) if p < slice.len() && bytes > slice.len() => &slice[..p],
        _ => slice,
    };
    String::from_utf8_lossy(slice).into_owned()
}

/// Decode a UTF-16 pool entry at `off`; never reads past `end` (`<= data.len()`).
fn decode_utf16(data: &[u8], mut off: usize, end: usize) -> String {
    let mut len = u16_at(data, off).unwrap_or(0) as usize;
    off += 2;
    if len & 0x8000 != 0 {
        let lo = u16_at(data, off).unwrap_or(0) as usize;
        off += 2;
        len = ((len & 0x7fff) << 16) | lo;
    }
    let end = end.min(data.len());
    let stop = len.saturating_mul(2).saturating_add(off).min(end);
    let units: Vec<u16> = data[off.min(stop)..stop].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&units)
}

/// Mantissa multipliers for the four complex radix modes (23.0, 16.7, 8.15, 0.23),
/// already including the `>> 8` shift of the mantissa. Exact powers of two like aapt.
const RADIX_MULTS: [f32; 4] = [1.0 / 256.0, 1.0 / 32_768.0, 1.0 / 8_388_608.0, 1.0 / 2_147_483_648.0];
const DIMENSION_UNITS: [&str; 6] = ["px", "dip", "sp", "pt", "in", "mm"];
const FRACTION_UNITS: [&str; 2] = ["%", "%p"];

/// Convert a `TYPE_DIMENSION`/`TYPE_FRACTION` value to a float the way aapt does:
/// the mantissa is a signed 24-bit quantity in the top bits.
fn complex_to_float(data: u32) -> f32 {
    ((data & 0xFFFF_FF00) as i32) as f32 * RADIX_MULTS[((data >> 4) & 3) as usize]
}

fn complex_unit(units: &[&'static str], data: u32) -> &'static str {
    units.get((data & 0xf) as usize).copied().unwrap_or("")
}

fn package_prefix(id: u32) -> &'static str {
    if id >> 24 == ANDROID_PACKAGE_ID {
        "android:"
    } else {
        ""
    }
}

/// Render a typed attribute value the way androguard/aapt do.
pub fn format_value(data_type: u8, data: u32, pool: &StringPool) -> String {
    match data_type {
        TYPE_STRING => pool.get(data).unwrap_or("").to_string(),
        TYPE_REFERENCE | TYPE_DYNAMIC_REFERENCE => format!("@{}{:08X}", package_prefix(data), data),
        TYPE_ATTRIBUTE | TYPE_DYNAMIC_ATTRIBUTE => format!("?{}{:08X}", package_prefix(data), data),
        TYPE_FLOAT => format!("{:.6}", f32::from_bits(data)),
        TYPE_DIMENSION => format!("{:.6}{}", complex_to_float(data), complex_unit(&DIMENSION_UNITS, data)),
        TYPE_FRACTION => format!("{:.6}{}", complex_to_float(data) * 100.0, complex_unit(&FRACTION_UNITS, data)),
        TYPE_INT_HEX => format!("0x{data:08X}"),
        TYPE_INT_BOOLEAN => (if data != 0 { "true" } else { "false" }).to_string(),
        TYPE_INT_COLOR_ARGB8 | TYPE_INT_COLOR_RGB8 | TYPE_INT_COLOR_ARGB4 | TYPE_INT_COLOR_RGB4 => format!("#{data:08X}"),
        TYPE_NULL => String::new(),
        _ => format!("{}", data as i32),
    }
}

fn escape_attr(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\n' => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            '\t' => out.push_str("&#9;"),
            c => out.push(c),
        }
    }
}

fn escape_text(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            c => out.push(c),
        }
    }
}

/// Resolve an attribute name, mirroring androguard's `_fix_name`: when the
/// name index has an entry in the resource map that is a known `android:attr`,
/// the system name wins over whatever the string pool says (obfuscators rename
/// e.g. `android:name` to `android:a` in the pool, but cannot change the id).
/// Returns the name and whether it was taken from the framework table.
fn resolve_attr_name(pool_name: &str, name_idx: u32, resource_ids: &[u32]) -> (String, bool) {
    let Some(&rid) = resource_ids.get(name_idx as usize) else {
        return (pool_name.to_string(), false);
    };
    if let Some(name) = attrs::android_attr_name(rid) {
        return (name.to_string(), true);
    }
    if pool_name.is_empty() {
        return (format!("attr_0x{rid:08x}"), rid >> 24 == ANDROID_PACKAGE_ID);
    }
    (pool_name.to_string(), false)
}

/// Decode a binary XML document into pretty-printed text.
pub fn decode(data: &[u8]) -> Result<String> {
    if data.len() < 8 || u16_at(data, 0)? != RES_XML_TYPE {
        return Err(AxmlError::NotAxml);
    }
    let file_size = (u32_at(data, 4)? as usize).min(data.len());
    let mut pool: Option<StringPool> = None;
    let mut resource_ids: Vec<u32> = Vec::new();
    let mut namespaces: Vec<(String, String)> = Vec::new(); // (prefix, uri) stack
    let mut pending_ns: Vec<(String, String)> = Vec::new();
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    let mut stack: Vec<String> = Vec::new(); // open element qualified names
    let mut open_tag_unclosed = false; // last emitted start tag has not been closed with '>' yet

    let mut p = 8usize;
    while p + 8 <= file_size {
        let kind = u16_at(data, p)?;
        let header_size = u16_at(data, p + 2)? as usize;
        let size = u32_at(data, p + 4)? as usize;
        if size < 8 {
            break;
        }
        if header_size > size {
            return Err(AxmlError::Malformed("chunk header larger than chunk"));
        }
        // Clamp the chunk to the file so a lying `size` can never push offsets
        // past the buffer (or overflow `usize` on 32-bit targets).
        let chunk_end = p.checked_add(size).map_or(file_size, |e| e.min(file_size));
        // Extension data (`ResXMLTree_*Ext`) starts right after the node header.
        let ext = p + header_size;
        match kind {
            RES_STRING_POOL_TYPE => pool = Some(StringPool::parse(data, p, chunk_end)?),
            RES_XML_RESOURCE_MAP_TYPE => {
                let count = chunk_end.saturating_sub(ext) / 4;
                resource_ids = (0..count).map(|i| u32_at(data, ext + i * 4)).collect::<Result<_>>()?;
            }
            RES_XML_START_NAMESPACE_TYPE => {
                let sp = pool.as_ref().ok_or(AxmlError::NoStringPool)?;
                let prefix = sp.get(u32_at(data, ext)?).unwrap_or("").to_string();
                let uri = sp.get(u32_at(data, ext + 4)?).unwrap_or("").to_string();
                namespaces.push((prefix.clone(), uri.clone()));
                pending_ns.push((prefix, uri));
            }
            RES_XML_END_NAMESPACE_TYPE => {
                namespaces.pop();
            }
            RES_XML_START_ELEMENT_TYPE => {
                let sp = pool.as_ref().ok_or(AxmlError::NoStringPool)?;
                if open_tag_unclosed {
                    out.push_str(">\n");
                }
                let ns = u32_at(data, ext)?;
                let name = sp.get(u32_at(data, ext + 4)?).unwrap_or("").to_string();
                let attr_start = u16_at(data, ext + 8)? as usize;
                let attr_size = (u16_at(data, ext + 10)? as usize).max(ATTRIBUTE_SIZE);
                let attr_count = u16_at(data, ext + 12)? as usize;
                let qname = qualify(&namespaces, sp.get(ns), &name);
                for _ in 0..stack.len() {
                    out.push_str("  ");
                }
                out.push('<');
                out.push_str(&qname);
                for (prefix, uri) in pending_ns.drain(..) {
                    if prefix.is_empty() {
                        let _ = write!(out, " xmlns=\"");
                    } else {
                        let _ = write!(out, " xmlns:{prefix}=\"");
                    }
                    escape_attr(&uri, &mut out);
                    out.push('"');
                }
                let base = ext + attr_start;
                for i in 0..attr_count {
                    // All three are u16-derived, but the product can still overflow usize on 32-bit.
                    let a = i.checked_mul(attr_size).and_then(|o| base.checked_add(o)).ok_or(AxmlError::Truncated(base))?;
                    if a + ATTRIBUTE_SIZE > chunk_end {
                        return Err(AxmlError::Truncated(a));
                    }
                    let ans = u32_at(data, a)?;
                    let aname_idx = u32_at(data, a + 4)?;
                    let raw = u32_at(data, a + 8)?;
                    let dtype = u8_at(data, a + 15)?;
                    let dval = u32_at(data, a + 16)?;
                    let (aname, from_framework) = resolve_attr_name(sp.get(aname_idx).unwrap_or(""), aname_idx, &resource_ids);
                    let mut qa = qualify(&namespaces, sp.get(ans), &aname);
                    if from_framework && !qa.contains(':') {
                        // The id proves this is an `android:` attribute even if the namespace was stripped.
                        qa = format!("android:{aname}");
                    }
                    let value = if dtype == TYPE_STRING && raw != 0xFFFF_FFFF {
                        sp.get(raw).unwrap_or("").to_string()
                    } else {
                        format_value(dtype, dval, sp)
                    };
                    out.push(' ');
                    out.push_str(&qa);
                    out.push_str("=\"");
                    escape_attr(&value, &mut out);
                    out.push('"');
                }
                stack.push(qname);
                open_tag_unclosed = true;
            }
            RES_XML_END_ELEMENT_TYPE => {
                if let Some(qname) = stack.pop() {
                    if open_tag_unclosed {
                        out.push_str("/>\n");
                        open_tag_unclosed = false;
                    } else {
                        for _ in 0..stack.len() {
                            out.push_str("  ");
                        }
                        let _ = writeln!(out, "</{qname}>");
                    }
                }
            }
            RES_XML_CDATA_TYPE => {
                let sp = pool.as_ref().ok_or(AxmlError::NoStringPool)?;
                if open_tag_unclosed {
                    out.push_str(">\n");
                    open_tag_unclosed = false;
                }
                let text = sp.get(u32_at(data, ext)?).unwrap_or("");
                for _ in 0..stack.len() {
                    out.push_str("  ");
                }
                escape_text(text.trim(), &mut out);
                out.push('\n');
            }
            _ => {}
        }
        p = chunk_end;
    }
    if open_tag_unclosed {
        out.push_str("/>\n");
        stack.pop();
    }
    while let Some(qname) = stack.pop() {
        let _ = writeln!(out, "</{qname}>");
    }
    Ok(out)
}

fn qualify(namespaces: &[(String, String)], uri: Option<&str>, name: &str) -> String {
    match uri {
        Some(uri) if !uri.is_empty() => {
            let prefix = namespaces.iter().rev().find(|(_, u)| u == uri).map(|(p, _)| p.as_str());
            match prefix {
                Some(p) if !p.is_empty() => format!("{p}:{name}"),
                _ if uri == ANDROID_NS_URI => format!("android:{name}"),
                _ => name.to_string(),
            }
        }
        _ => name.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: u32 = 0xFFFF_FFFF;

    /// Encode a string pool chunk (UTF-16 or UTF-8 flavour).
    fn pool_chunk(strings: &[&str], utf8: bool) -> Vec<u8> {
        let mut offsets = Vec::new();
        let mut sdata = Vec::new();
        for s in strings {
            offsets.push(sdata.len() as u32);
            if utf8 {
                let chars = s.chars().count();
                assert!(chars < 0x80 && s.len() < 0x80, "test builder only supports short strings");
                sdata.push(chars as u8);
                sdata.push(s.len() as u8);
                sdata.extend_from_slice(s.as_bytes());
                sdata.push(0);
            } else {
                let units: Vec<u16> = s.encode_utf16().collect();
                sdata.extend_from_slice(&(units.len() as u16).to_le_bytes());
                for u in units {
                    sdata.extend_from_slice(&u.to_le_bytes());
                }
                sdata.extend_from_slice(&0u16.to_le_bytes());
            }
        }
        while sdata.len() % 4 != 0 {
            sdata.push(0);
        }
        let strings_start = STRING_POOL_HEADER_SIZE + offsets.len() * 4;
        let size = strings_start + sdata.len();
        let mut pool = Vec::new();
        pool.extend_from_slice(&RES_STRING_POOL_TYPE.to_le_bytes());
        pool.extend_from_slice(&(STRING_POOL_HEADER_SIZE as u16).to_le_bytes());
        pool.extend_from_slice(&(size as u32).to_le_bytes());
        pool.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        pool.extend_from_slice(&0u32.to_le_bytes());
        pool.extend_from_slice(&(if utf8 { UTF8_FLAG } else { 0 }).to_le_bytes());
        pool.extend_from_slice(&(strings_start as u32).to_le_bytes());
        pool.extend_from_slice(&0u32.to_le_bytes());
        for o in offsets {
            pool.extend_from_slice(&o.to_le_bytes());
        }
        pool.extend_from_slice(&sdata);
        pool
    }

    /// Wrap already-encoded chunks into a `RES_XML_TYPE` document.
    fn document(chunks: &[&[u8]]) -> Vec<u8> {
        let body: Vec<u8> = chunks.concat();
        let mut doc = Vec::new();
        doc.extend_from_slice(&RES_XML_TYPE.to_le_bytes());
        doc.extend_from_slice(&8u16.to_le_bytes());
        doc.extend_from_slice(&((8 + body.len()) as u32).to_le_bytes());
        doc.extend_from_slice(&body);
        doc
    }

    /// Minimal binary XML encoder for tests (UTF-16 pool followed by `body`).
    fn build(strings: &[&str], body: &[u8]) -> Vec<u8> {
        document(&[&pool_chunk(strings, false), body])
    }

    fn resource_map(ids: &[u32]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&RES_XML_RESOURCE_MAP_TYPE.to_le_bytes());
        v.extend_from_slice(&8u16.to_le_bytes());
        v.extend_from_slice(&((8 + ids.len() * 4) as u32).to_le_bytes());
        for id in ids {
            v.extend_from_slice(&id.to_le_bytes());
        }
        v
    }

    fn node(kind: u16, ext: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&kind.to_le_bytes());
        v.extend_from_slice(&16u16.to_le_bytes());
        v.extend_from_slice(&((16 + ext.len()) as u32).to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        v.extend_from_slice(&NONE.to_le_bytes());
        v.extend_from_slice(ext);
        v
    }

    fn attr(ns: u32, name: u32, raw: u32, dtype: u8, data: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&ns.to_le_bytes());
        v.extend_from_slice(&name.to_le_bytes());
        v.extend_from_slice(&raw.to_le_bytes());
        v.extend_from_slice(&8u16.to_le_bytes());
        v.push(0);
        v.push(dtype);
        v.extend_from_slice(&data.to_le_bytes());
        v
    }

    fn start_namespace(prefix: u32, uri: u32) -> Vec<u8> {
        let mut ns = Vec::new();
        ns.extend_from_slice(&prefix.to_le_bytes());
        ns.extend_from_slice(&uri.to_le_bytes());
        node(RES_XML_START_NAMESPACE_TYPE, &ns)
    }

    fn end_namespace(prefix: u32, uri: u32) -> Vec<u8> {
        let mut ns = Vec::new();
        ns.extend_from_slice(&prefix.to_le_bytes());
        ns.extend_from_slice(&uri.to_le_bytes());
        node(RES_XML_END_NAMESPACE_TYPE, &ns)
    }

    fn start_element(ns: u32, name: u32, attrs: &[Vec<u8>]) -> Vec<u8> {
        let mut el = Vec::new();
        el.extend_from_slice(&ns.to_le_bytes());
        el.extend_from_slice(&name.to_le_bytes());
        el.extend_from_slice(&20u16.to_le_bytes()); // attributeStart
        el.extend_from_slice(&20u16.to_le_bytes()); // attributeSize
        el.extend_from_slice(&(attrs.len() as u16).to_le_bytes());
        el.extend_from_slice(&[0u8; 6]); // id/class/style indexes
        for a in attrs {
            el.extend_from_slice(a);
        }
        node(RES_XML_START_ELEMENT_TYPE, &el)
    }

    fn end_element(ns: u32, name: u32) -> Vec<u8> {
        let mut end = Vec::new();
        end.extend_from_slice(&ns.to_le_bytes());
        end.extend_from_slice(&name.to_le_bytes());
        node(RES_XML_END_ELEMENT_TYPE, &end)
    }

    #[test]
    fn decodes_simple_manifest() {
        // 0 android, 1 uri, 2 manifest, 3 package, 4 com.example, 5 versionCode, 6 application, 7 debuggable
        let strings = ["android", ANDROID_NS_URI, "manifest", "package", "com.example", "versionCode", "application", "debuggable"];
        let mut body = Vec::new();
        body.extend(start_namespace(0, 1));
        body.extend(start_element(NONE, 2, &[attr(NONE, 3, 4, TYPE_STRING, 4), attr(1, 5, NONE, TYPE_INT_DEC, 42)]));
        body.extend(start_element(NONE, 6, &[attr(1, 7, NONE, TYPE_INT_BOOLEAN, NONE)]));
        body.extend(end_element(NONE, 6));
        body.extend(end_element(NONE, 2));
        body.extend(end_namespace(0, 1));
        let doc = build(&strings, &body);
        let xml = decode(&doc).unwrap();
        let expected = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"com.example\" android:versionCode=\"42\">\n  <application android:debuggable=\"true\"/>\n</manifest>\n";
        assert_eq!(xml, expected);
    }

    #[test]
    fn decodes_utf8_string_pool() {
        // 0 android, 1 uri, 2 manifest, 3 package, 4 (non-ASCII) package name, 5 label, 6 label value
        let strings = ["android", ANDROID_NS_URI, "manifest", "package", "com.例子", "label", "示例 & <app>"];
        let mut body = Vec::new();
        body.extend(start_namespace(0, 1));
        body.extend(start_element(NONE, 2, &[attr(NONE, 3, 4, TYPE_STRING, 4), attr(1, 5, 6, TYPE_STRING, 6)]));
        body.extend(end_element(NONE, 2));
        body.extend(end_namespace(0, 1));
        let doc = document(&[&pool_chunk(&strings, true), &body]);
        let xml = decode(&doc).unwrap();
        let expected = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"com.例子\" android:label=\"示例 &amp; &lt;app&gt;\"/>\n";
        assert_eq!(xml, expected);
    }

    #[test]
    fn resource_map_restores_obfuscated_attribute_names() {
        // Strings with a resource id must come first in the pool (their index doubles as the map index).
        // 0 "a" -> targetSdkVersion, 1 "" -> installLocation, 2 "debuggable" -> debuggable (unchanged),
        // 3 "" -> unknown framework id, 4 "keep" -> unknown app id (pool name kept),
        // then 5 android, 6 uri, 7 manifest, 8 package, 9 com.example, 10 application
        let strings = ["a", "", "debuggable", "", "keep", "android", ANDROID_NS_URI, "manifest", "package", "com.example", "application"];
        let ids = [0x0101_0270, 0x0101_02b7, 0x0101_000f, 0x0101_ffff, 0x7f01_0005];
        let mut body = Vec::new();
        body.extend(resource_map(&ids));
        body.extend(start_namespace(5, 6));
        body.extend(start_element(
            NONE,
            7,
            &[
                attr(NONE, 8, 9, TYPE_STRING, 9),
                attr(6, 0, NONE, TYPE_INT_DEC, 33),
                attr(6, 1, NONE, TYPE_INT_DEC, 2),
                attr(6, 3, NONE, TYPE_INT_DEC, 7),
                attr(NONE, 4, NONE, TYPE_INT_DEC, 8),
            ],
        ));
        // Namespace stripped as well: the framework id alone must yield `android:debuggable`.
        body.extend(start_element(NONE, 10, &[attr(NONE, 2, NONE, TYPE_INT_BOOLEAN, 1)]));
        body.extend(end_element(NONE, 10));
        body.extend(end_element(NONE, 7));
        body.extend(end_namespace(5, 6));
        let xml = decode(&build(&strings, &body)).unwrap();
        let expected = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
            <manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"com.example\" \
            android:targetSdkVersion=\"33\" android:installLocation=\"2\" android:attr_0x0101ffff=\"7\" keep=\"8\">\n  \
            <application android:debuggable=\"true\"/>\n\
            </manifest>\n";
        assert_eq!(xml, expected);
    }

    #[test]
    fn framework_attr_table_uses_real_ids() {
        assert_eq!(attrs::android_attr_name(0x0101_0270), Some("targetSdkVersion"));
        assert_eq!(attrs::android_attr_name(0x0101_02b7), Some("installLocation"));
        assert_eq!(attrs::android_attr_name(0x0101_020c), Some("minSdkVersion"));
        assert_eq!(attrs::android_attr_name(0x0101_0003), Some("name"));
        assert_eq!(attrs::android_attr_name(0x0101_021b), Some("versionCode"));
        assert_eq!(attrs::android_attr_name(0x0101_021c), Some("versionName"));
        assert_eq!(attrs::android_attr_name(0x0101_ffff), None);
        assert_eq!(attrs::android_attr_name(0x7f01_0000), None);
    }

    #[test]
    fn value_formatting() {
        let pool = StringPool::default();
        assert_eq!(format_value(TYPE_REFERENCE, 0x7f010001, &pool), "@7F010001");
        assert_eq!(format_value(TYPE_REFERENCE, 0x01010001, &pool), "@android:01010001");
        assert_eq!(format_value(TYPE_INT_HEX, 0x10, &pool), "0x00000010");
        assert_eq!(format_value(TYPE_INT_DEC, 0xFFFF_FFFF, &pool), "-1");
        assert_eq!(format_value(TYPE_INT_COLOR_ARGB8, 0xFF00FF00, &pool), "#FF00FF00");
    }

    #[test]
    fn dimension_and_fraction_formatting() {
        let pool = StringPool::default();
        // mantissa 1 (<< 8), radix 23p0, unit dip
        assert_eq!(format_value(TYPE_DIMENSION, 0x0000_0101, &pool), "1.000000dip");
        assert_eq!(format_value(TYPE_DIMENSION, 0x0000_1000, &pool), "16.000000px");
        assert_eq!(format_value(TYPE_DIMENSION, 0x0000_0205, &pool), "2.000000mm");
        // mantissa -1: aapt treats it as signed, so this is -1dip rather than 16777215dip
        assert_eq!(format_value(TYPE_DIMENSION, 0xFFFF_FF01, &pool), "-1.000000dip");
        assert_eq!(format_value(TYPE_DIMENSION, 0xFFFF_FE02, &pool), "-2.000000sp");
        // 0.5 in radix 16.7 (radix bits = 1 << 4): mantissa 0x4000 * 2^-15
        assert_eq!(format_value(TYPE_FRACTION, 0x0000_4010, &pool), "50.000000%");
        assert_eq!(format_value(TYPE_FRACTION, 0x0000_4011, &pool), "50.000000%p");
        // 128% with radix 23.0 (integer mantissa 0x80 << 8)
        assert_eq!(format_value(TYPE_FRACTION, 0x0000_8000, &pool), "12800.000000%");
        // 1.5dip in radix 16.7 and a negative 0.23 fraction
        assert_eq!(format_value(TYPE_DIMENSION, 0x0000_C011, &pool), "1.500000dip");
        assert_eq!(format_value(TYPE_FRACTION, 0xC000_0030, &pool), "-50.000000%");
        // Out-of-range units (>= table length) must not panic; they render without a suffix.
        assert_eq!(format_value(TYPE_DIMENSION, 0x0000_0106, &pool), "1.000000");
        assert_eq!(format_value(TYPE_DIMENSION, 0x0000_010F, &pool), "1.000000");
        assert_eq!(format_value(TYPE_FRACTION, 0x0000_4012, &pool), "50.000000");
        assert_eq!(format_value(TYPE_FRACTION, 0x0000_401F, &pool), "50.000000");
    }

    #[test]
    fn string_pool_with_impossible_count_is_rejected() {
        let mut pool = pool_chunk(&["a", "b"], false);
        // stringCount claims far more entries than the chunk can hold.
        pool[8..12].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(matches!(decode(&document(&[&pool])), Err(AxmlError::Malformed(_))));

        let mut pool = pool_chunk(&["a", "b"], false);
        pool[8..12].copy_from_slice(&0x1000_0000u32.to_le_bytes());
        assert!(matches!(decode(&document(&[&pool])), Err(AxmlError::Malformed(_))));

        // styleCount is validated the same way.
        let mut pool = pool_chunk(&["a", "b"], false);
        pool[12..16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        assert!(matches!(decode(&document(&[&pool])), Err(AxmlError::Malformed(_))));

        // stringsStart pointing outside the chunk.
        let mut pool = pool_chunk(&["a", "b"], false);
        pool[20..24].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        assert!(matches!(decode(&document(&[&pool])), Err(AxmlError::Malformed(_))));
    }

    #[test]
    fn string_pool_with_bad_offsets_yields_empty_strings() {
        // Offsets pointing past the chunk (including ones that would overflow usize) become "".
        let strings = ["android", ANDROID_NS_URI, "manifest"];
        let mut pool = pool_chunk(&strings, false);
        let off0 = STRING_POOL_HEADER_SIZE;
        pool[off0..off0 + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let off2 = STRING_POOL_HEADER_SIZE + 8;
        pool[off2..off2 + 4].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
        let mut body = Vec::new();
        body.extend(start_namespace(0, 1));
        body.extend(start_element(NONE, 2, &[]));
        body.extend(end_element(NONE, 2));
        let xml = decode(&document(&[&pool, &body])).unwrap();
        assert_eq!(xml, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n< xmlns=\"http://schemas.android.com/apk/res/android\"/>\n");
    }

    #[test]
    fn string_with_length_beyond_chunk_is_truncated_not_panicking() {
        // A UTF-16 length of 0x7fff_ffff units must clamp to the chunk instead of overflowing.
        let strings = ["manifest"];
        let mut pool = pool_chunk(&strings, false);
        let s = STRING_POOL_HEADER_SIZE + 4;
        pool[s..s + 4].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        let body = start_element(NONE, 0, &[]);
        assert!(decode(&document(&[&pool, &body])).is_ok());

        // Same for UTF-8 with a two-byte length.
        let mut pool = pool_chunk(&strings, true);
        let s = STRING_POOL_HEADER_SIZE + 4;
        pool[s..s + 4].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(decode(&document(&[&pool, &body])).is_ok());
    }

    #[test]
    fn resource_map_with_header_larger_than_size_is_rejected() {
        let pool = pool_chunk(&["manifest"], false);
        let mut map = resource_map(&[0x0101_0270]);
        map[2..4].copy_from_slice(&0xFFFFu16.to_le_bytes());
        assert!(matches!(decode(&document(&[&pool, &map])), Err(AxmlError::Malformed(_))));

        // header_size == size is legal and simply yields an empty map.
        let mut map = resource_map(&[]);
        map[2..4].copy_from_slice(&8u16.to_le_bytes());
        assert_eq!(decode(&document(&[&pool, &map])).unwrap(), "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    }

    #[test]
    fn truncated_documents_return_errors() {
        let strings = ["android", ANDROID_NS_URI, "manifest", "versionCode"];
        let mut body = Vec::new();
        body.extend(start_namespace(0, 1));
        body.extend(start_element(NONE, 2, &[attr(1, 3, NONE, TYPE_INT_DEC, 1)]));
        body.extend(end_element(NONE, 2));
        let doc = build(&strings, &body);
        assert!(decode(&doc).is_ok());
        // Cutting the document anywhere must not panic.
        for cut in 0..doc.len() {
            let _ = decode(&doc[..cut]);
        }
        // Attribute count far beyond the chunk.
        let mut doc = build(&strings, &body);
        let pool_len = pool_chunk(&strings, false).len();
        let el = 8 + pool_len + 24; // start of the START_ELEMENT node
        doc[el + 16 + 12..el + 16 + 14].copy_from_slice(&0xFFFFu16.to_le_bytes());
        assert!(matches!(decode(&doc), Err(AxmlError::Truncated(_))));
        // Attribute size/start large enough to overflow arithmetic on small targets.
        doc[el + 16 + 8..el + 16 + 10].copy_from_slice(&0xFFFFu16.to_le_bytes());
        doc[el + 16 + 10..el + 16 + 12].copy_from_slice(&0xFFFFu16.to_le_bytes());
        assert!(matches!(decode(&doc), Err(AxmlError::Truncated(_))));
        // Chunk size lying beyond the file is clamped rather than trusted.
        let mut doc = build(&strings, &body);
        doc[el + 4..el + 8].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        assert!(decode(&doc).is_ok());
    }
}
