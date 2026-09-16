//! Raw code-region scan for opcodes carrying a constant-pool index.

use crate::insn_locator::InsnLocator;

/// Which index table a query targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefKind {
    String,
    Type,
    Method,
    Field,
}

impl RefKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RefKind::String => "string",
            RefKind::Type => "type",
            RefKind::Method => "method",
            RefKind::Field => "field",
        }
    }
}

/// Dense bitset over constant-pool indexes.
#[derive(Debug, Clone, Default)]
pub struct IdxSet {
    bits: Vec<u64>,
}

impl IdxSet {
    pub fn insert(&mut self, idx: u32) {
        let word = (idx >> 6) as usize;
        if word >= self.bits.len() {
            self.bits.resize(word + 1, 0);
        }
        self.bits[word] |= 1u64 << (idx & 63);
    }

    #[inline]
    pub fn contains(&self, idx: u32) -> bool {
        match self.bits.get((idx >> 6) as usize) {
            Some(w) => w & (1u64 << (idx & 63)) != 0,
            None => false,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|&w| w == 0)
    }

    /// Ascending members.
    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.bits.iter().enumerate().flat_map(|(w, &bits)| {
            let mut bits = bits;
            std::iter::from_fn(move || {
                if bits == 0 {
                    return None;
                }
                let t = bits.trailing_zeros();
                bits &= bits - 1;
                Some((w as u32) * 64 + t)
            })
        })
    }
}

impl FromIterator<u32> for IdxSet {
    fn from_iter<I: IntoIterator<Item = u32>>(iter: I) -> Self {
        let mut s = IdxSet::default();
        for i in iter {
            s.insert(i);
        }
        s
    }
}

/// Opcode byte → operand width (0 = not an opcode of this kind).
#[inline]
fn opcode_width(kind: RefKind, b: u8) -> u8 {
    match kind {
        RefKind::String => match b {
            0x1a => 2,
            0x1b => 4,
            _ => 0,
        },
        RefKind::Type => matches!(b, 0x1c | 0x1f | 0x20 | 0x22 | 0x23 | 0x24 | 0x25) as u8 * 2,
        RefKind::Field => (b.wrapping_sub(0x52) <= 0x6d - 0x52) as u8 * 2,
        RefKind::Method => (b.wrapping_sub(0x6e) <= 4 || b.wrapping_sub(0x74) <= 4 || b == 0xfa || b == 0xfb) as u8 * 2,
    }
}

/// Above this many targets the per-target `memmem` pass costs more than one
/// linear sweep over the region.
const MEMMEM_MAX_TARGETS: usize = 8;

/// Sweeps the code-item region of a DEX.
pub struct CodeScanner<'l> {
    insn: &'l InsnLocator,
}

impl<'l> CodeScanner<'l> {
    pub fn new(insn: &'l InsnLocator) -> Self {
        CodeScanner { insn }
    }

    /// Return `(absolute offset, matched index)` for every position in the code
    /// region of `buf` whose opcode byte belongs to `kind` and whose operand is
    /// in `idxs`, in ascending offset order. Positions are unverified: the
    /// instruction locator decides whether they sit on an instruction boundary.
    ///
    /// `buf` must be the DEX buffer the instruction locator was built from.
    pub fn scan(&self, buf: &[u8], kind: RefKind, idxs: &IdxSet) -> Vec<(u32, u32)> {
        let end = self.insn.code_item_end().min(buf.len());
        let start = self.insn.code_item_start();
        if start >= end || idxs.is_empty() {
            return Vec::new();
        }
        let region = &buf[start..end];
        let targets = idxs.iter().collect::<Vec<u32>>();
        if targets.len() <= MEMMEM_MAX_TARGETS {
            return scan_by_operand(region, start, kind, &targets);
        }
        scan_by_opcode(region, start, kind, idxs)
    }
}

/// Few targets: search the operand bytes with SIMD `memmem` and check the
/// opcode two bytes before each candidate. Operand bytes are far more
/// selective than opcode bytes, so almost every position is skipped.
fn scan_by_operand(region: &[u8], base: usize, kind: RefKind, targets: &[u32]) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    for &idx in targets {
        let narrow = (idx as u16).to_le_bytes();
        let wide = idx.to_le_bytes();
        let needles: [(&[u8], u8); 2] = [(&narrow, 2), (&wide, 4)];
        for (needle, width) in needles {
            if width == 2 && idx > u16::MAX as u32 {
                continue;
            }
            if width == 4 && kind != RefKind::String {
                continue; // only const-string/jumbo carries a 32-bit operand
            }
            let finder = memchr::memmem::Finder::new(needle);
            // `find_iter` skips overlapping matches: with a self-overlapping
            // needle such as `05 05` and a register byte equal to the operand
            // (`1a 05 05 05`) the first hit lands one byte early and the real
            // candidate would be jumped over. Resume one byte after each hit.
            let mut from = 0;
            while let Some(rel) = finder.find(&region[from..]) {
                let pos = from + rel;
                from = pos + 1;
                if pos >= 2 && opcode_width(kind, region[pos - 2]) == width {
                    out.push(((base + pos - 2) as u32, idx));
                }
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Check the candidate whose opcode byte sits at `i` and push it if it
/// references one of `idxs`.
#[inline]
fn check_candidate(region: &[u8], base: usize, kind: RefKind, idxs: &IdxSet, i: usize, out: &mut Vec<(u32, u32)>) {
    let width = opcode_width(kind, region[i]);
    if width == 0 {
        return;
    }
    let idx = if width == 2 {
        let Some(b) = region.get(i + 2..i + 4) else { return };
        u16::from_le_bytes([b[0], b[1]]) as u32
    } else {
        let Some(b) = region.get(i + 2..i + 6) else { return };
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    };
    if idxs.contains(idx) {
        out.push(((base + i) as u32, idx));
    }
}

/// Linear sweep over every byte with a 256-entry opcode-width table.
fn linear_sweep(region: &[u8], base: usize, kind: RefKind, idxs: &IdxSet, out: &mut Vec<(u32, u32)>) {
    let mut table = [0u8; 256];
    for (b, w) in table.iter_mut().enumerate() {
        *w = opcode_width(kind, b as u8);
    }
    let len = region.len();
    for (i, &b) in region.iter().enumerate() {
        let width = table[b as usize];
        if width == 0 {
            continue;
        }
        let idx = if width == 2 {
            if i + 4 > len {
                continue;
            }
            u16::from_le_bytes([region[i + 2], region[i + 3]]) as u32
        } else {
            if i + 6 > len {
                continue;
            }
            u32::from_le_bytes([region[i + 2], region[i + 3], region[i + 4], region[i + 5]])
        };
        if idxs.contains(idx) {
            out.push(((base + i) as u32, idx));
        }
    }
}

/// Whether a `memchr` prefilter on these high operand bytes is worthwhile.
/// `0x00` (indexes below 256) and `0xFF` are everywhere in bytecode (zero
/// registers and padding, `-1` literals), so a prefilter on them fires on
/// most positions and only adds overhead over the linear sweep.
fn prefilter_is_selective(highs: &[u8]) -> bool {
    highs.len() <= 3 && !highs.iter().any(|&b| b == 0x00 || b == 0xFF)
}

/// Many targets. Strings have only two opcodes, so `memchr2` finds the
/// candidates. For the other kinds the high operand byte is usually shared by
/// most targets (R8 packs related ids together): when the targets span at most
/// three distinct, selective high bytes, `memchr` on those bytes prefilters
/// the region; otherwise fall back to one linear sweep over the opcode bytes.
fn scan_by_opcode(region: &[u8], base: usize, kind: RefKind, idxs: &IdxSet) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    if kind == RefKind::String {
        for i in memchr::memchr2_iter(0x1a, 0x1b, region) {
            check_candidate(region, base, kind, idxs, i, &mut out);
        }
        return out;
    }
    let mut highs: Vec<u8> = idxs.iter().map(|i| (i >> 8) as u8).collect();
    highs.sort_unstable();
    highs.dedup();
    if !prefilter_is_selective(&highs) {
        linear_sweep(region, base, kind, idxs, &mut out);
        return out;
    }
    let positions: Box<dyn Iterator<Item = usize>> = match highs.as_slice() {
        [a] => Box::new(memchr::memchr_iter(*a, region)),
        [a, b] => Box::new(memchr::memchr2_iter(*a, *b, region)),
        [a, b, c] => Box::new(memchr::memchr3_iter(*a, *b, *c, region)),
        _ => unreachable!("prefilter_is_selective bounds the byte set"),
    };
    // The high operand byte sits at opcode + 3.
    for p in positions {
        if p >= 3 {
            check_candidate(region, base, kind, idxs, p - 3, &mut out);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefilter_falls_back_on_common_bytes() {
        assert!(prefilter_is_selective(&[0x12]));
        assert!(prefilter_is_selective(&[0x12, 0x13, 0x14]));
        assert!(!prefilter_is_selective(&[0x00]));
        assert!(!prefilter_is_selective(&[0x12, 0xff]));
        assert!(!prefilter_is_selective(&[1, 2, 3, 4]));
    }

    /// Every scan strategy on `region` for `targets`, as (label, candidates).
    fn all_strategies(region: &[u8], kind: RefKind, targets: &[u32]) -> Vec<(&'static str, Vec<(u32, u32)>)> {
        let idxs: IdxSet = targets.iter().copied().collect();
        let mut linear = Vec::new();
        linear_sweep(region, 0, kind, &idxs, &mut linear);
        vec![("operand", scan_by_operand(region, 0, kind, targets)), ("opcode", scan_by_opcode(region, 0, kind, &idxs)), ("linear", linear)]
    }

    fn assert_all_agree(region: &[u8], kind: RefKind, targets: &[u32], expected: &[(u32, u32)]) {
        for (label, got) in all_strategies(region, kind, targets) {
            assert_eq!(got, expected, "{label} strategy for {kind:?} {targets:x?}");
        }
    }

    #[test]
    fn self_overlapping_operand_is_not_skipped() {
        // const-string v5, string@0x0505: the needle `05 05` also matches at
        // the register byte one position earlier.
        let region = [0x1a, 0x05, 0x05, 0x05, 0x0e, 0x00];
        assert_all_agree(&region, RefKind::String, &[0x0505], &[(0, 0x0505)]);
        // iget v5, v0, field@0x0505 (AG byte 0x05 too).
        let region = [0x52, 0x05, 0x05, 0x05, 0x0e, 0x00];
        assert_all_agree(&region, RefKind::Field, &[0x0505], &[(0, 0x0505)]);
        // Longer self-overlap: `05 05 05 05` needle preceded by more 05 bytes.
        let region = [0x00, 0x05, 0x05, 0x1b, 0x05, 0x05, 0x05, 0x05, 0x05, 0x0e, 0x00];
        assert_all_agree(&region, RefKind::String, &[0x0505_0505], &[(3, 0x0505_0505)]);
        // Two adjacent candidates that share operand bytes.
        let region = [0x1a, 0x05, 0x05, 0x05, 0x1a, 0x05, 0x05, 0x05];
        assert_all_agree(&region, RefKind::String, &[0x0505], &[(0, 0x0505), (4, 0x0505)]);
    }

    #[test]
    fn jumbo_string_index_uses_wide_operand() {
        // const-string/jumbo v1, string@0x00012345 followed by a narrow
        // const-string whose 16-bit operand is the low half of the same index.
        let mut region = vec![0x1b, 0x01];
        region.extend_from_slice(&0x0001_2345u32.to_le_bytes());
        region.extend_from_slice(&[0x1a, 0x02, 0x45, 0x23, 0x0e, 0x00]);
        // The jumbo index only matches the wide form.
        assert_all_agree(&region, RefKind::String, &[0x0001_2345], &[(0, 0x0001_2345)]);
        // The narrow index only matches the narrow form (const-string).
        assert_all_agree(&region, RefKind::String, &[0x2345], &[(6, 0x2345)]);
        // Field/method/type kinds never carry a 32-bit operand.
        assert_all_agree(&region, RefKind::Field, &[0x0001_2345], &[]);
    }

    #[test]
    fn strategies_agree() {
        // A synthetic region: field ops with various operands, some noise.
        let mut region = Vec::new();
        for i in 0u32..600 {
            let idx = (i * 7) % 700;
            region.extend_from_slice(&[0x52 + (i % 4) as u8, 0x10]);
            region.extend_from_slice(&(idx as u16).to_le_bytes());
            region.extend_from_slice(&[0x0e, 0x00, 0x00, 0x00]);
        }
        // Targets below 256 (high byte 0x00) force the linear sweep; the
        // operand search must find exactly the same candidates.
        let targets: Vec<u32> = (0..20).map(|i| i * 7).collect();
        let idxs: IdxSet = targets.iter().copied().collect();
        let a = scan_by_operand(&region, 0, RefKind::Field, &targets);
        let b = scan_by_opcode(&region, 0, RefKind::Field, &idxs);
        assert!(!a.is_empty());
        assert_eq!(a, b);
        // Targets sharing one selective high byte (0x02) use the memchr prefilter.
        let targets: Vec<u32> = (74..94).map(|k| k * 7).collect();
        assert!(targets.iter().all(|&t| t >> 8 == 2));
        let idxs: IdxSet = targets.iter().copied().collect();
        let a = scan_by_operand(&region, 0, RefKind::Field, &targets);
        let b = scan_by_opcode(&region, 0, RefKind::Field, &idxs);
        assert!(!a.is_empty());
        assert_eq!(a, b);
    }
}
