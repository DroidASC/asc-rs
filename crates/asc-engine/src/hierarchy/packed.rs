//! The class graph's storage: one byte layout for the graph in memory and in
//! L2, so a graph mapped from the disk cache is used where it lies instead
//! of being decoded into hash maps (which took longer than half a rebuild).
//!
//! Little-endian `u32` words: a header of [`HEADER_WORDS`] counts (DEX
//! files, classes, edges, annotations, annotated classes, hash slots, text
//! bytes), then
//! - `dex`: per DEX name, its `(start, end)` in the text;
//! - `name_end`: per class, the end of its descriptor in the text (each
//!   starts where the previous one ends);
//! - `slots`: an open-addressing table of `class id + 1` by descriptor
//!   ([`hash`], linear probing), 0 = empty; a power of two above the class
//!   count;
//! - `defined`: per class, `(view + 1, class_def index)` of its first
//!   definition, `(0, 0)` when the APK only references it;
//! - `up` / `down`: the `(child, parent, relation)` edges sorted by child /
//!   by parent;
//! - `ann`: per class annotation, `(start, end)` of its descriptor in the
//!   text and the end of its classes in `ann_ids`, sorted by descriptor;
//! - `ann_ids`: the classes carrying each annotation, sorted;
//! - the text: the UTF-8 class descriptors, then the annotation
//!   descriptors and DEX names.

use asc_findrefs::ClassRelation;
use std::collections::BTreeMap;
use std::ops::{Deref, Range};

const HEADER_WORDS: usize = 7;

/// `(child, parent, relation)` between class ids.
pub(super) type Edge = (u32, u32, ClassRelation);

/// The bytes of a graph: built here, or mapped from L2.
enum Backing {
    Owned(Vec<u8>),
    Mapped(asc_cache::Derived),
}

impl Deref for Backing {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Backing::Owned(b) => b,
            Backing::Mapped(d) => d,
        }
    }
}

/// Byte offsets of the sections, from the header's counts.
#[derive(Clone, Copy)]
struct Layout {
    dexes: usize,
    classes: usize,
    edges: usize,
    anns: usize,
    ann_ids: usize,
    slots: usize,
    text_len: usize,
    dex: usize,
    name_end: usize,
    slot: usize,
    defined: usize,
    up: usize,
    down: usize,
    ann: usize,
    ann_id: usize,
    text: usize,
}

impl Layout {
    /// The layout `bytes` declare, if they are exactly that long.
    fn read(bytes: &[u8]) -> Option<Layout> {
        let header = bytes.get(..HEADER_WORDS * 4)?;
        let w = |i: usize| u32::from_le_bytes(header[i * 4..i * 4 + 4].try_into().expect("4 bytes")) as usize;
        let l = Layout::new([w(0), w(1), w(2), w(3), w(4), w(5), w(6)])?;
        (l.text.checked_add(l.text_len)? == bytes.len()).then_some(l)
    }

    fn new([dexes, classes, edges, anns, ann_ids, slots, text_len]: [usize; HEADER_WORDS]) -> Option<Layout> {
        let words = |at: usize, n: usize, per: usize| n.checked_mul(per * 4).and_then(|b| at.checked_add(b));
        let dex = HEADER_WORDS * 4;
        let name_end = words(dex, dexes, 2)?;
        let slot = words(name_end, classes, 1)?;
        let defined = words(slot, slots, 1)?;
        let up = words(defined, classes, 2)?;
        let down = words(up, edges, 3)?;
        let ann = words(down, edges, 3)?;
        let ann_id = words(ann, anns, 3)?;
        let text = words(ann_id, ann_ids, 1)?;
        Some(Layout { dexes, classes, edges, anns, ann_ids, slots, text_len, dex, name_end, slot, defined, up, down, ann, ann_id, text })
    }
}

/// A class graph in the byte layout above.
pub(super) struct Packed {
    bytes: Backing,
    at: Layout,
}

impl Packed {
    /// A graph mapped from L2, checked so that no lookup can index out of
    /// bounds, read text off a character boundary or probe forever; `None`
    /// for bytes that are not such a graph. Order is not checked: a file
    /// from this boot is the one we wrote, an older one passed its CRC.
    pub(super) fn from_mapped(d: asc_cache::Derived) -> Option<Packed> {
        let at = Layout::read(&d)?;
        let g = Packed { bytes: Backing::Mapped(d), at };
        g.is_consistent().then_some(g)
    }

    fn is_consistent(&self) -> bool {
        let Layout { dexes, classes, edges, anns, ann_ids, slots, text_len, .. } = self.at;
        let Ok(text) = std::str::from_utf8(&self.bytes[self.at.text..]) else { return false };
        let bounded = |s: usize, e: usize| s <= e && e <= text_len && text.is_char_boundary(s) && text.is_char_boundary(e);
        let mut start = 0;
        for id in 0..classes {
            let end = self.word(self.at.name_end, id) as usize;
            if !bounded(start, end) || self.word(self.at.defined, 2 * id) as usize > dexes {
                return false;
            }
            start = end;
        }
        let mut ann_end = 0;
        for i in 0..anns {
            let (s, e, ids) = (self.word(self.at.ann, 3 * i), self.word(self.at.ann, 3 * i + 1), self.word(self.at.ann, 3 * i + 2));
            if !bounded(s as usize, e as usize) || (ids as usize) < ann_end || ids as usize > ann_ids {
                return false;
            }
            ann_end = ids as usize;
        }
        slots.is_power_of_two()
            && slots > classes
            && (0..dexes).all(|i| bounded(self.word(self.at.dex, 2 * i) as usize, self.word(self.at.dex, 2 * i + 1) as usize))
            && (0..slots).all(|i| self.word(self.at.slot, i) as usize <= classes)
            && (0..edges * 3).step_by(3).all(|i| {
                [self.at.up, self.at.down].iter().all(|&at| {
                    (self.word(at, i) as usize) < classes && (self.word(at, i + 1) as usize) < classes && self.word(at, i + 2) < 2
                })
            })
            && (0..ann_ids).all(|i| (self.word(self.at.ann_id, i) as usize) < classes)
    }

    /// The bytes to persist.
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Heap the graph holds: none once mapped (file pages, shared and
    /// reclaimable like mapped L1 entries).
    pub(super) fn heap_bytes(&self) -> usize {
        match &self.bytes {
            Backing::Owned(b) => b.capacity(),
            Backing::Mapped(_) => 0,
        }
    }

    fn word(&self, at: usize, i: usize) -> u32 {
        let o = at + 4 * i;
        u32::from_le_bytes(self.bytes[o..o + 4].try_into().expect("4 bytes"))
    }

    fn text(&self, range: Range<usize>) -> &str {
        let start = self.at.text;
        std::str::from_utf8(&self.bytes[start + range.start..start + range.end]).expect("text checked when the graph was made")
    }

    pub(super) fn classes(&self) -> usize {
        self.at.classes
    }

    pub(super) fn name(&self, id: u32) -> &str {
        let id = id as usize;
        let start = if id == 0 { 0 } else { self.word(self.at.name_end, id - 1) as usize };
        self.text(start..self.word(self.at.name_end, id) as usize)
    }

    pub(super) fn id(&self, name: &str) -> Option<u32> {
        let mask = self.at.slots - 1;
        let mut i = hash(name) as usize & mask;
        for _ in 0..self.at.slots {
            match self.word(self.at.slot, i) {
                0 => return None,
                s if self.name(s - 1) == name => return Some(s - 1),
                _ => i = (i + 1) & mask,
            }
        }
        None
    }

    /// `(view + 1, class_def index)` of the class's first definition.
    pub(super) fn defined(&self, id: u32) -> (u32, u32) {
        let i = 2 * id as usize;
        (self.word(self.at.defined, i), self.word(self.at.defined, i + 1))
    }

    pub(super) fn dex_names(&self) -> impl Iterator<Item = &str> + '_ {
        (0..self.at.dexes).map(|i| self.dex_name(i))
    }

    pub(super) fn dex_name(&self, view: usize) -> &str {
        self.text(self.word(self.at.dex, 2 * view) as usize..self.word(self.at.dex, 2 * view + 1) as usize)
    }

    fn edge(&self, at: usize, i: usize) -> Edge {
        let rel = if self.word(at, 3 * i + 2) == 0 { ClassRelation::Extends } else { ClassRelation::Implements };
        (self.word(at, 3 * i), self.word(at, 3 * i + 1), rel)
    }

    /// The edges whose child (`by_parent`: parent) is `id`.
    pub(super) fn edges_of(&self, id: u32, by_parent: bool) -> impl Iterator<Item = Edge> + '_ {
        let at = if by_parent { self.at.down } else { self.at.up };
        let key = move |e: Edge| if by_parent { e.1 } else { e.0 };
        // First edge whose key is not below `id`.
        let (mut lo, mut hi) = (0, self.at.edges);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if key(self.edge(at, mid)) < id {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        (lo..self.at.edges).map(move |i| self.edge(at, i)).take_while(move |&e| key(e) == id)
    }

    /// The classes carrying the class annotation `annotation`.
    pub(super) fn annotated(&self, annotation: &str) -> impl Iterator<Item = u32> + '_ {
        let ann = |i: usize| self.text(self.word(self.at.ann, 3 * i) as usize..self.word(self.at.ann, 3 * i + 1) as usize);
        let (mut lo, mut hi) = (0, self.at.anns);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if ann(mid) < annotation {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        let ids = if lo < self.at.anns && ann(lo) == annotation {
            let start = if lo == 0 { 0 } else { self.word(self.at.ann, 3 * lo - 1) as usize };
            start..self.word(self.at.ann, 3 * lo + 2) as usize
        } else {
            0..0
        };
        ids.map(|i| self.word(self.at.ann_id, i))
    }
}

/// FNV-1a: stable across builds and platforms, as the persisted table needs.
fn hash(name: &str) -> u64 {
    name.bytes().fold(0xcbf2_9ce4_8422_2325, |h, b| (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3))
}

/// Collects classes, definitions, edges and annotations, then lays them out.
/// Descriptors are interned straight into the final text and hash table.
pub(super) struct Builder {
    text: String,
    name_end: Vec<u32>,
    /// `id + 1` by [`hash`], linear probing; kept at most half full.
    table: Vec<u32>,
    defined: Vec<(u32, u32)>,
    up: Vec<Edge>,
    annotated: BTreeMap<String, Vec<u32>>,
}

impl Default for Builder {
    fn default() -> Builder {
        Builder {
            text: String::new(),
            name_end: Vec::new(),
            table: vec![0; 1024],
            defined: Vec::new(),
            up: Vec::new(),
            annotated: BTreeMap::new(),
        }
    }
}

impl Builder {
    fn name(&self, id: usize) -> &str {
        let start = if id == 0 { 0 } else { self.name_end[id - 1] as usize };
        &self.text[start..self.name_end[id] as usize]
    }

    /// The slot of `name` in `table`: where it is, or the empty one it goes to.
    fn slot(&self, name: &str) -> usize {
        let mask = self.table.len() - 1;
        let mut i = hash(name) as usize & mask;
        while self.table[i] != 0 && self.name(self.table[i] as usize - 1) != name {
            i = (i + 1) & mask;
        }
        i
    }

    pub(super) fn intern(&mut self, name: &str) -> u32 {
        let i = self.slot(name);
        if self.table[i] != 0 {
            return self.table[i] - 1;
        }
        let id = len32(self.name_end.len());
        self.text.push_str(name);
        self.name_end.push(len32(self.text.len()));
        self.defined.push((0, 0));
        if self.name_end.len() * 2 > self.table.len() {
            self.table = vec![0; self.table.len() * 2];
            for id in 0..self.name_end.len() {
                let i = self.slot(self.name(id));
                self.table[i] = len32(id + 1);
            }
        } else {
            self.table[i] = id + 1;
        }
        id
    }

    /// Record the first definition of `class`; `false` when it already has one.
    pub(super) fn define(&mut self, class: u32, view: u32, def_idx: u32) -> bool {
        let slot = &mut self.defined[class as usize];
        if slot.0 != 0 {
            return false;
        }
        *slot = (view + 1, def_idx);
        true
    }

    /// An edge; repeats are dropped when the graph is laid out.
    pub(super) fn edge(&mut self, child: u32, parent: u32, rel: ClassRelation) {
        self.up.push((child, parent, rel));
    }

    pub(super) fn annotate(&mut self, class: u32, annotation: String) {
        self.annotated.entry(annotation).or_default().push(class);
    }

    pub(super) fn finish<'a>(mut self, dex_names: impl ExactSizeIterator<Item = &'a str>) -> Packed {
        let classes = self.name_end.len();
        self.up.sort_unstable_by_key(|&(c, p, rel)| (c, p, rel_code(rel)));
        self.up.dedup();
        let mut down = self.up.clone();
        down.sort_unstable_by_key(|&(c, p, _)| (p, c));
        let mut ann_ids: Vec<u32> = Vec::new();
        let mut text = self.text;
        let mut span = |s: &str| {
            let start = len32(text.len());
            text.push_str(s);
            [start, len32(text.len())]
        };
        let anns: Vec<[u32; 3]> = self
            .annotated
            .iter_mut()
            .map(|(a, ids)| {
                ids.sort_unstable();
                ids.dedup();
                ann_ids.extend_from_slice(ids);
                let [s, e] = span(a);
                [s, e, len32(ann_ids.len())]
            })
            .collect();
        let dex: Vec<[u32; 2]> = dex_names.map(&mut span).collect();
        let counts = [dex.len(), classes, self.up.len(), anns.len(), ann_ids.len(), self.table.len(), text.len()];
        let at = Layout::new(counts).expect("in-memory sizes fit");
        let mut out = Vec::with_capacity(at.text + text.len());
        let mut put = |w: u32| out.extend_from_slice(&w.to_le_bytes());
        counts.iter().for_each(|&c| put(len32(c)));
        dex.iter().flatten().for_each(|&w| put(w));
        self.name_end.iter().for_each(|&w| put(w));
        self.table.iter().for_each(|&w| put(w));
        self.defined.iter().for_each(|&(v, d)| {
            put(v);
            put(d);
        });
        for edges in [&self.up, &down] {
            for &(c, p, rel) in edges {
                put(c);
                put(p);
                put(rel_code(rel));
            }
        }
        anns.iter().flatten().for_each(|&w| put(w));
        ann_ids.iter().for_each(|&w| put(w));
        out.extend_from_slice(text.as_bytes());
        debug_assert_eq!(out.len(), at.text + at.text_len);
        Packed { bytes: Backing::Owned(out), at }
    }
}

/// How a relation is stored.
fn rel_code(rel: ClassRelation) -> u32 {
    match rel {
        ClassRelation::Extends => 0,
        ClassRelation::Implements => 1,
    }
}

/// A count or offset as stored: the graph indexes with `u32`.
fn len32(n: usize) -> u32 {
    u32::try_from(n).expect("class graph sizes fit in u32")
}
