//! O(1) instruction-offset → method resolution.
//!
//! ```text
//! +-----------------+
//! | codeitem header | <-- 16 bytes
//! +-----------------+
//! |  insns (u16[])  | <-- at least one code unit
//! +-----------------+
//! | codeitem header |
//! |       ...       |
//! ```
//!
//! Every method's instructions start at `code_off + 16`. Using `offset >> 4`
//! as a bucket key, each method fills the buckets from its first to its last
//! instruction byte. Because code items are 4-byte aligned and carry a 16-byte
//! header, two different methods can never share a bucket; only R8's
//! instruction deduplication (several methods pointing at one `code_item`)
//! produces multi-method buckets.
//!
//! The bucket table is a dense `Vec<u32>` covering the code-item region, so
//! building it is a handful of range fills rather than one hash insert per
//! bucket, and a lookup is a single indexed load. The table stores offsets
//! only; the DEX buffer is handed back in for verification (`locate`).

use asc_dex::{class_data, map_type, Dex, Result};

/// Method(s) owning an instruction offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodRef {
    Single(u32),
    /// Several methods share the same `code_item` (R8 deduplication).
    Shared(Vec<u32>),
}

impl MethodRef {
    pub fn ids(&self) -> &[u32] {
        match self {
            MethodRef::Single(m) => std::slice::from_ref(m),
            MethodRef::Shared(v) => v,
        }
    }
}

const NONE: u32 = u32::MAX;
const SHARED_BIT: u32 = 1 << 31;

/// `(insn_off, insn_size_bytes, method_idx)` for a method with a body.
type Entry = (u32, u32, u32);

/// Record an entry for a method with a body. Entries whose instruction range
/// does not fit in `buf`, or whose method index is beyond `method_cap`, are
/// dropped: they can neither be scanned nor displayed, and trusting them
/// would size the bucket table from attacker-controlled offsets.
fn push_entry(buf: &[u8], entries: &mut Vec<Entry>, method_cap: usize, midx: u32, code_off: u32) {
    if code_off == 0 || midx as usize >= method_cap {
        return;
    }
    let pos = code_off as usize;
    let Some(size_bytes) = pos.checked_add(12).and_then(|p| buf.get(p..p + 4)) else { return };
    let insn_size = u32::from_le_bytes([size_bytes[0], size_bytes[1], size_bytes[2], size_bytes[3]]);
    if insn_size == 0 {
        return;
    }
    let insn_off = pos as u64 + 16;
    let bytes = insn_size as u64 * 2;
    let end = insn_off + bytes;
    if end > buf.len() as u64 || end > u32::MAX as u64 {
        return;
    }
    entries.push((insn_off as u32, bytes as u32, midx));
}

/// Dense bucket table from instruction offsets to methods.
pub struct InsnLocator {
    /// Bucket index of `table[0]`.
    base_bucket: u32,
    /// Per bucket: `NONE`, a method index, or `SHARED_BIT | index into shared`.
    table: Vec<u32>,
    shared: Vec<Vec<u32>>,
    /// First instruction offset per method index (`NONE` when no body).
    method_bounds: Vec<u32>,
    code_item_start: usize,
    code_item_end: usize,
}

impl InsnLocator {
    /// Build the bucket table by walking every `class_data_item`. Prefers the
    /// packed `class_data` map section; falls back to walking class
    /// definitions when the map is absent or lacks that item.
    ///
    /// Malformed `code_off` / `insns_size` values are skipped, so the table
    /// never covers more than the buffer (`table_len() <= buf.len() / 16 + 1`).
    pub fn build(dex: &Dex<'_>) -> Result<InsnLocator> {
        let buf = dex.buf();
        // Every method_id is 8 bytes: the header count cannot exceed that.
        let method_cap = (dex.method_count() as usize).min(buf.len() / 8);
        let mut entries: Vec<Entry> = Vec::with_capacity(method_cap / 2);
        let by_map = match dex.map_item(map_type::CLASS_DATA) {
            Some(item) if dex.header().map_off != 0 => {
                let mut off = item.offset as usize;
                let mut ok = true;
                for _ in 0..item.size {
                    match class_data::walk_methods(buf, off, |m, c| push_entry(buf, &mut entries, method_cap, m, c)) {
                        Ok(next) => off = next,
                        Err(_) => {
                            ok = false;
                            break;
                        }
                    }
                }
                ok
            }
            _ => false,
        };
        if !by_map {
            entries.clear();
            for def in dex.class_defs() {
                let def = def?;
                if def.class_data_off == 0 {
                    continue;
                }
                class_data::walk_methods(buf, def.class_data_off as usize, |m, c| push_entry(buf, &mut entries, method_cap, m, c))?;
            }
        }

        let mut loc = InsnLocator {
            base_bucket: 0,
            table: Vec::new(),
            shared: Vec::new(),
            method_bounds: vec![NONE; method_cap],
            code_item_start: 0,
            code_item_end: 0,
        };
        if entries.is_empty() {
            return Ok(loc);
        }
        // `push_entry` guarantees `insn_off + size <= buf.len() <= u32::MAX`,
        // so the bucket arithmetic below cannot overflow.
        let min_bucket = entries.iter().map(|e| e.0 >> 4).min().unwrap_or(0);
        let max_bucket = entries.iter().map(|e| (e.0 + e.1 - 1) >> 4).max().unwrap_or(0);
        loc.base_bucket = min_bucket;
        loc.table = vec![NONE; (max_bucket - min_bucket + 1) as usize];
        loc.code_item_start = (min_bucket as usize) << 4;
        loc.code_item_end = ((max_bucket as usize) + 1) << 4;
        for (insn_off, size, midx) in entries {
            loc.method_bounds[midx as usize] = insn_off;
            let start = ((insn_off >> 4) - min_bucket) as usize;
            let end = (((insn_off + size - 1) >> 4) - min_bucket) as usize;
            let value = match loc.table[start] {
                NONE => midx,
                old if old & SHARED_BIT != 0 => {
                    loc.shared[(old & !SHARED_BIT) as usize].push(midx);
                    old
                }
                old => {
                    loc.shared.push(vec![midx, old]);
                    SHARED_BIT | (loc.shared.len() as u32 - 1)
                }
            };
            loc.table[start..=end].fill(value);
        }
        Ok(loc)
    }

    pub fn code_item_start(&self) -> usize {
        self.code_item_start
    }

    pub fn code_item_end(&self) -> usize {
        self.code_item_end
    }

    /// Number of buckets in the dense table (empty ones included).
    pub fn table_len(&self) -> usize {
        self.table.len()
    }

    /// Heap bytes held by the bucket, shared-method and bounds tables.
    pub fn heap_bytes(&self) -> usize {
        use crate::locators::vec_bytes;
        vec_bytes(&self.table) + vec_bytes(&self.shared) + self.shared.iter().map(vec_bytes).sum::<usize>() + vec_bytes(&self.method_bounds)
    }

    /// Number of non-empty buckets.
    pub fn bucket_count(&self) -> usize {
        self.table.iter().filter(|&&v| v != NONE).count()
    }

    /// First instruction offset per method index (`u32::MAX` when the method
    /// has no body).
    pub fn method_bounds(&self) -> &[u32] {
        &self.method_bounds
    }

    #[inline]
    fn bucket_value(&self, off: u32) -> u32 {
        let b = off >> 4;
        if b < self.base_bucket {
            return NONE;
        }
        self.table.get((b - self.base_bucket) as usize).copied().unwrap_or(NONE)
    }

    /// Methods owning the bucket that contains `off` (unverified).
    pub fn get(&self, off: u32) -> Option<MethodRef> {
        match self.bucket_value(off) {
            NONE => None,
            v if v & SHARED_BIT != 0 => Some(MethodRef::Shared(self.shared[(v & !SHARED_BIT) as usize].clone())),
            v => Some(MethodRef::Single(v)),
        }
    }

    /// Resolve ascending instruction offsets to their owning methods. An entry
    /// is `None` when the bucket is empty or the bytes between the method
    /// start and the offset do not decode as a clean instruction sequence.
    ///
    /// `buf` must be the DEX buffer the locator was built from. Offsets must
    /// be sorted ascending: the verification start for a method advances to
    /// the last verified offset, so each method body is walked at most once.
    pub fn locate(&self, buf: &[u8], offsets: &[u32]) -> Vec<Option<MethodRef>> {
        // (first method idx, last verified offset) for the method currently
        // being walked; offsets arrive sorted so a single cursor suffices.
        let mut cursor: Option<(u32, u32)> = None;
        offsets
            .iter()
            .map(|&off| {
                let v = self.bucket_value(off);
                if v == NONE {
                    return None;
                }
                let first = if v & SHARED_BIT != 0 { self.shared[(v & !SHARED_BIT) as usize][0] } else { v };
                let bound = *self.method_bounds.get(first as usize)?;
                if bound == NONE {
                    return None;
                }
                let start = match cursor {
                    Some((m, last)) if m == first && last <= off => last,
                    _ => bound,
                };
                if start <= off && asc_dalvik::verify_range(buf, start as usize, off as usize) {
                    cursor = Some((first, off));
                    self.get(off)
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locator_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InsnLocator>();
    }

    #[test]
    fn push_entry_drops_ranges_outside_the_buffer() {
        // A code_item at offset 4: 16-byte header followed by 4 bytes of code.
        let mut buf = vec![0u8; 24];
        buf[16..20].copy_from_slice(&2u32.to_le_bytes());
        let mut entries = Vec::new();
        push_entry(&buf, &mut entries, 4, 1, 4);
        assert_eq!(entries, vec![(20, 4, 1)]);
        // code_off 0 means "no body".
        entries.clear();
        push_entry(&buf, &mut entries, 4, 1, 0);
        assert!(entries.is_empty());
        // insns_size one unit too many.
        buf[16..20].copy_from_slice(&3u32.to_le_bytes());
        push_entry(&buf, &mut entries, 4, 1, 4);
        assert!(entries.is_empty());
        // Absurd insns_size, code_off past the end, header truncated, midx too big.
        buf[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        push_entry(&buf, &mut entries, 4, 1, 4);
        push_entry(&buf, &mut entries, 4, 1, u32::MAX);
        push_entry(&buf, &mut entries, 4, 1, 12);
        buf[16..20].copy_from_slice(&2u32.to_le_bytes());
        push_entry(&buf, &mut entries, 1, 1, 4);
        push_entry(&buf, &mut entries, 4, 1, 0xFFFF_FFF0);
        assert!(entries.is_empty());
        // Zero-length bodies are skipped too.
        buf[16..20].copy_from_slice(&0u32.to_le_bytes());
        push_entry(&buf, &mut entries, 4, 1, 4);
        assert!(entries.is_empty());
    }
}
