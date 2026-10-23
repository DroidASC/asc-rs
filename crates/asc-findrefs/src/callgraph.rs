//! Static call graph of one DEX: which method bodies invoke which method ids.
//!
//! Built in one pass over every method body the [`InsnLocator`] knows: each
//! `invoke-*` (including `/range` and `invoke-polymorphic`) contributes an
//! edge `caller → callee`, both local `method_id` indexes. `invoke-custom`
//! names a call site, not a method, and adds no edge. Edges are deduplicated
//! per caller.
//!
//! A DEX holds at most 65 536 method ids (the invoke operand is 16 bits), so
//! targets are stored as `u16` in two CSR tables (callees by caller, callers
//! by callee): about 4 bytes per edge plus 8 per method id. Methods sharing
//! one `code_item` (R8 deduplication) are walked once.
//!
//! The graph knows nothing of other DEX files or of virtual dispatch: a call
//! through `Lsub;->m()` and one through `Lbase;->m()` are different method
//! ids. Callers align DEX files by method signature.
//!
//! [`CallGraph::to_bytes`] / [`CallGraph::from_bytes`] give a flat
//! little-endian form suited to an on-disk cache (layout in `to_bytes`).

use crate::insn_locator::InsnLocator;
use asc_dalvik::walk::walk_insns;

/// Invoke opcodes whose operand at `pc + 2` is a `method_id` index.
#[inline]
fn is_method_invoke(op: u8) -> bool {
    matches!(op, 0x6e..=0x72 | 0x74..=0x78 | 0xfa | 0xfb)
}

/// Caller → callee edges of one DEX, in both directions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallGraph {
    /// `callees[callee_start[m]..callee_start[m + 1]]` are the ids `m` invokes.
    callee_start: Vec<u32>,
    callees: Vec<u16>,
    /// `callers[caller_start[m]..caller_start[m + 1]]` are the ids invoking `m`.
    caller_start: Vec<u32>,
    callers: Vec<u16>,
    /// Bit per method id: the method has a body in this DEX.
    has_body: Vec<u64>,
}

const MAGIC: &[u8; 4] = b"ACG1";

impl CallGraph {
    /// Build from the method bodies `insn` located in `buf` (the DEX buffer
    /// it was built from).
    pub fn build(buf: &[u8], insn: &InsnLocator) -> CallGraph {
        let bounds = insn.method_bounds();
        let n = bounds.len().min(1 << 16);
        let mut has_body = vec![0u64; n.div_ceil(64)];
        // (insn_off, method) for methods with a body, so shared code items are
        // adjacent and walked once.
        let mut bodies: Vec<(u32, u16)> =
            bounds.iter().take(n).enumerate().filter(|(_, &b)| b != u32::MAX).map(|(m, &b)| (b, m as u16)).collect();
        bodies.sort_unstable();
        let mut edges: Vec<(u16, u16)> = Vec::new();
        let mut last: Option<(u32, usize, usize)> = None; // (insn_off, edges range of its first method)
        let mut scratch: Vec<u16> = Vec::new();
        for &(off, m) in &bodies {
            has_body[m as usize >> 6] |= 1 << (m & 63);
            if let Some((prev, from, to)) = last.filter(|l| l.0 == off) {
                for i in from..to {
                    edges.push((m, edges[i].1));
                }
                last = Some((prev, from, to));
                continue;
            }
            // `InsnLocator` only keeps bodies whose 16-byte header and
            // `insns_size` code units fit in `buf`.
            let size = off
                .checked_sub(4)
                .and_then(|p| buf.get(p as usize..p as usize + 4))
                .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize * 2);
            let Some(code) = buf.get(off as usize..off as usize + size) else { continue };
            scratch.clear();
            walk_insns(code, |step| {
                if is_method_invoke(step.opcode.value) {
                    if let Some(b) = code.get(step.pc + 2..step.pc + 4) {
                        scratch.push(u16::from_le_bytes([b[0], b[1]]));
                    }
                }
            });
            scratch.sort_unstable();
            scratch.dedup();
            let from = edges.len();
            edges.extend(scratch.iter().filter(|&&c| (c as usize) < n).map(|&c| (m, c)));
            last = Some((off, from, edges.len()));
        }
        edges.sort_unstable();
        edges.dedup();
        let (callee_start, callees) = csr(n, edges.iter().map(|&(a, b)| (a, b)));
        let mut rev: Vec<(u16, u16)> = edges.iter().map(|&(a, b)| (b, a)).collect();
        rev.sort_unstable();
        let (caller_start, callers) = csr(n, rev.into_iter());
        CallGraph { callee_start, callees, caller_start, callers, has_body }
    }

    /// Number of method ids covered.
    pub fn method_count(&self) -> usize {
        self.callee_start.len().saturating_sub(1)
    }

    /// Number of distinct caller → callee edges.
    pub fn edge_count(&self) -> usize {
        self.callees.len()
    }

    /// Method ids `method` invokes (ascending; empty without a body here).
    pub fn callees(&self, method: u32) -> &[u16] {
        slice(&self.callee_start, &self.callees, method)
    }

    /// Method ids whose body invokes `method` (ascending).
    pub fn callers(&self, method: u32) -> &[u16] {
        slice(&self.caller_start, &self.callers, method)
    }

    /// Whether `method` has a body in this DEX.
    pub fn has_body(&self, method: u32) -> bool {
        self.has_body.get(method as usize >> 6).is_some_and(|w| w & (1 << (method & 63)) != 0)
    }

    /// Heap bytes held by the tables.
    pub fn heap_bytes(&self) -> usize {
        use crate::locators::vec_bytes;
        vec_bytes(&self.callee_start)
            + vec_bytes(&self.callees)
            + vec_bytes(&self.caller_start)
            + vec_bytes(&self.callers)
            + vec_bytes(&self.has_body)
    }

    /// Flat little-endian form:
    ///
    /// ```text
    /// "ACG1" | n: u32 | edges: u32 | reserved: u32
    /// callee_start: [u32; n + 1] | caller_start: [u32; n + 1]
    /// has_body: [u64; ceil(n / 64)]
    /// callees: [u16; edges] | pad to 4 | callers: [u16; edges] | pad to 4
    /// ```
    ///
    /// Every table starts 4-byte aligned (8 for `has_body`, given an
    /// 8-aligned start), so a mapping of the bytes can be read in place.
    pub fn to_bytes(&self) -> Vec<u8> {
        let n = self.method_count() as u32;
        let mut out = Vec::with_capacity(16 + self.heap_bytes());
        out.extend_from_slice(MAGIC);
        for v in [n, self.callees.len() as u32, 0] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        for v in self.callee_start.iter().chain(&self.caller_start) {
            out.extend_from_slice(&v.to_le_bytes());
        }
        while out.len() % 8 != 0 {
            out.push(0);
        }
        for w in &self.has_body {
            out.extend_from_slice(&w.to_le_bytes());
        }
        for table in [&self.callees, &self.callers] {
            for v in table {
                out.extend_from_slice(&v.to_le_bytes());
            }
            while out.len() % 4 != 0 {
                out.push(0);
            }
        }
        out
    }

    /// Parse [`CallGraph::to_bytes`] output; `None` when it is malformed
    /// (wrong magic, truncated, or offsets out of order / out of range).
    pub fn from_bytes(b: &[u8]) -> Option<CallGraph> {
        let u32_at = |o: usize| b.get(o..o + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]));
        if b.get(..4)? != MAGIC {
            return None;
        }
        let (n, e) = (u32_at(4)? as usize, u32_at(8)? as usize);
        if n > 1 << 16 {
            return None;
        }
        let mut pos = 16;
        let starts = |pos: &mut usize| -> Option<Vec<u32>> {
            let v: Vec<u32> = (0..=n).map(|i| u32_at(*pos + 4 * i)).collect::<Option<_>>()?;
            *pos += 4 * (n + 1);
            (v[0] == 0 && v[n] as usize == e && v.windows(2).all(|w| w[0] <= w[1])).then_some(v)
        };
        let callee_start = starts(&mut pos)?;
        let caller_start = starts(&mut pos)?;
        pos = pos.next_multiple_of(8);
        let words = n.div_ceil(64);
        let has_body: Vec<u64> = (0..words)
            .map(|i| b.get(pos + 8 * i..pos + 8 * i + 8).map(|s| u64::from_le_bytes(s.try_into().unwrap())))
            .collect::<Option<_>>()?;
        pos += 8 * words;
        let targets = |pos: &mut usize| -> Option<Vec<u16>> {
            let v: Vec<u16> =
                (0..e).map(|i| b.get(*pos + 2 * i..*pos + 2 * i + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))).collect::<Option<_>>()?;
            *pos = (*pos + 2 * e).next_multiple_of(4);
            v.iter().all(|&t| (t as usize) < n).then_some(v)
        };
        let callees = targets(&mut pos)?;
        let callers = targets(&mut pos)?;
        Some(CallGraph { callee_start, callees, caller_start, callers, has_body })
    }
}

/// CSR over `n` rows from `(row, value)` pairs sorted by row.
fn csr(n: usize, pairs: impl Iterator<Item = (u16, u16)>) -> (Vec<u32>, Vec<u16>) {
    let mut start = vec![0u32; n + 1];
    let mut values = Vec::new();
    for (row, v) in pairs {
        start[row as usize + 1] += 1;
        values.push(v);
    }
    for i in 0..n {
        start[i + 1] += start[i];
    }
    (start, values)
}

fn slice<'a>(start: &[u32], values: &'a [u16], m: u32) -> &'a [u16] {
    let m = m as usize;
    match (start.get(m), start.get(m + 1)) {
        (Some(&a), Some(&b)) => &values[a as usize..b as usize],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph(n: usize, edges: &[(u16, u16)], bodies: &[u16]) -> CallGraph {
        let mut e = edges.to_vec();
        e.sort_unstable();
        let (callee_start, callees) = csr(n, e.iter().copied());
        let mut r: Vec<(u16, u16)> = e.iter().map(|&(a, b)| (b, a)).collect();
        r.sort_unstable();
        let (caller_start, callers) = csr(n, r.into_iter());
        let mut has_body = vec![0u64; n.div_ceil(64)];
        for &m in bodies {
            has_body[m as usize >> 6] |= 1 << (m & 63);
        }
        CallGraph { callee_start, callees, caller_start, callers, has_body }
    }

    #[test]
    fn csr_lookups_and_byte_round_trip() {
        let g = graph(70, &[(0, 1), (0, 69), (2, 1), (69, 0)], &[0, 2, 69]);
        assert_eq!(g.callees(0), &[1, 69]);
        assert_eq!(g.callers(1), &[0, 2]);
        assert_eq!(g.callers(0), &[69]);
        assert!(g.callees(1).is_empty() && g.callees(1000).is_empty());
        assert!(g.has_body(69) && !g.has_body(1) && !g.has_body(5000));
        let bytes = g.to_bytes();
        assert_eq!(bytes.len() % 4, 0);
        assert_eq!(CallGraph::from_bytes(&bytes), Some(g.clone()));
        // Truncation, bad magic and out-of-range targets are rejected.
        for cut in [0, 3, 16, bytes.len() - 1] {
            assert_eq!(CallGraph::from_bytes(&bytes[..cut]), None, "cut {cut}");
        }
        let mut bad = bytes.clone();
        bad[0] = b'X';
        assert_eq!(CallGraph::from_bytes(&bad), None);
        let mut bad = bytes.clone();
        let last = bad.len() - 4;
        bad[last..last + 2].copy_from_slice(&70u16.to_le_bytes());
        assert_eq!(CallGraph::from_bytes(&bad), None);
        assert_eq!(CallGraph::from_bytes(&CallGraph::default().to_bytes()), None, "n + 1 starts are required");
        let empty = graph(0, &[], &[]);
        assert_eq!(CallGraph::from_bytes(&empty.to_bytes()), Some(empty));
    }
}
