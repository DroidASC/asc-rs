//! Text-only `find_refs` rows ([`Engine::find_refs_text`]): each DEX's rows
//! rendered straight into one block, for the CLI's default output. A broad
//! query (`string a`) has hundreds of thousands of rows; building a
//! [`RefResult`](crate::RefResult) for each only to print it dominates such a search.
//!
//! [`Engine::find_refs_text`]: crate::Engine::find_refs_text

use crate::{matched_name, results_from_hits, rows_compiled, FindOptions, Result};
use asc_dex::Dex;
use asc_findrefs::{CompiledQuery, FindRefs, Hit, RefKind};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::Arc;

/// Rows of one DEX entry as text, one per line, each ending in `\n`: what
/// [`RefResult::line`](crate::RefResult::line) would print for them, in the same order.
#[derive(Clone, Default)]
pub struct TextRows {
    text: Text,
    /// The offset of each row's `\n`: a row may itself hold one (a DEX entry
    /// name with a newline), so the rows are not told apart by splitting.
    ends: Vec<usize>,
}

/// The bytes behind [`TextRows`]: built in memory, or a validated range of
/// an L3 file replayed without a copy.
#[derive(Clone)]
enum Text {
    Owned(String),
    Shared { bytes: Arc<dyn AsRef<[u8]> + Send + Sync>, range: Range<usize> },
}

impl Default for Text {
    fn default() -> Self {
        Text::Owned(String::new())
    }
}

impl TextRows {
    /// Every row, each followed by `\n`.
    pub fn as_str(&self) -> &str {
        match &self.text {
            Text::Owned(s) => s,
            // `shared` checked the range is UTF-8.
            Text::Shared { bytes, range } => std::str::from_utf8(&(**bytes).as_ref()[range.clone()]).expect("validated UTF-8"),
        }
    }

    /// The number of rows.
    pub fn len(&self) -> usize {
        self.ends.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ends.is_empty()
    }

    /// The rows, without their `\n`.
    pub fn lines(&self) -> impl Iterator<Item = &str> {
        let text = self.as_str();
        let starts = std::iter::once(0).chain(self.ends.iter().map(|&e| e + 1));
        starts.zip(&self.ends).map(move |(start, &end)| &text[start..end])
    }

    pub(crate) fn ends(&self) -> &[usize] {
        &self.ends
    }

    /// Rows viewed in `bytes[range]`; `None` unless the range is UTF-8 and
    /// `ends` are increasing `\n` offsets, the last one ending the range.
    pub(crate) fn shared(bytes: Arc<dyn AsRef<[u8]> + Send + Sync>, range: Range<usize>, ends: Vec<usize>) -> Option<TextRows> {
        let text = std::str::from_utf8((*bytes).as_ref().get(range.clone())?).ok()?;
        let valid = ends.windows(2).all(|w| w[0] < w[1])
            && ends.iter().all(|&e| text.as_bytes().get(e) == Some(&b'\n'))
            && ends.last().map_or(text.is_empty(), |&e| e + 1 == text.len());
        valid.then_some(TextRows { text: Text::Shared { bytes, range }, ends })
    }

    /// The text to append rows to (a shared block is copied first).
    fn owned(&mut self) -> &mut String {
        if let Text::Shared { .. } = self.text {
            self.text = Text::Owned(self.as_str().to_string());
        }
        match &mut self.text {
            Text::Owned(s) => s,
            Text::Shared { .. } => unreachable!("converted above"),
        }
    }

    /// End the row written since the last one.
    fn end_row(&mut self) {
        let text = self.owned();
        let end = text.len();
        text.push('\n');
        self.ends.push(end);
    }

    /// Append the rows of `other`.
    pub(crate) fn append(&mut self, other: &TextRows) {
        let base = self.owned().len();
        self.owned().push_str(other.as_str());
        self.ends.extend(other.ends.iter().map(|&e| base + e));
    }
}

impl std::fmt::Debug for TextRows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TextRows").field("rows", &self.len()).field("bytes", &self.as_str().len()).finish()
    }
}

impl PartialEq for TextRows {
    fn eq(&self, other: &Self) -> bool {
        self.ends == other.ends && self.as_str() == other.as_str()
    }
}

impl Eq for TextRows {}

/// The text rows of `query` over the DEX `fr` searches, aggregated per
/// method with no context. Plain code queries are rendered straight from
/// their hits; anything else (class relations, compounds, definition
/// predicates, call-site notes) as the lines of its [`RefResult`](crate::RefResult)s.
pub(crate) fn text_rows(fr: &FindRefs<'_, '_, '_>, query: &CompiledQuery) -> Result<TextRows> {
    let plain = query.relation().is_none() && query.compound().is_none() && query.defined().is_none();
    let rows = if plain {
        let hits = fr.find_ref_compiled(query)?;
        if hits.iter().all(|h| h.note.is_none()) {
            return rows_from_hits(fr.dex(), query.kind(), &hits);
        }
        results_from_hits(fr.dex(), query.kind(), &hits, true)?
    } else {
        rows_compiled(fr, query, FindOptions::default())?
    };
    let mut out = TextRows::default();
    for r in &rows {
        out.owned().push_str(&r.line());
        out.end_row();
    }
    Ok(out)
}

/// [`results_from_hits`] (aggregated, without notes) rendered as text: one
/// row per method in method order, its distinct constants in index order.
fn rows_from_hits(dex: &Dex<'_>, kind: RefKind, hits: &[Hit]) -> Result<TextRows> {
    // Method ids index a dense table: a broad search touches most methods,
    // and this needs neither a map entry per method nor a final sort.
    let mut grouped = vec![SmallIdxSet::default(); dex.method_count() as usize];
    for hit in hits {
        for &m in hit.methods.iter().flat_map(|ms| ms.ids()) {
            if let Some(idxs) = grouped.get_mut(m as usize) {
                idxs.insert(hit.matched_idx);
            }
        }
    }
    let mut out = TextRows::default();
    // One constant is often matched in many methods: render it once.
    let mut matched: HashMap<u32, String> = HashMap::new();
    for (m, idxs) in grouped.into_iter().enumerate() {
        if let SmallIdxSet::Empty = idxs {
            continue;
        }
        let m = u32::try_from(m).expect("method ids are u32");
        let text = out.owned();
        text.push_str(dex.name());
        text.push_str(" | ");
        text.push_str(&asc_smali::method_signature(dex, m)?);
        text.push_str(" | ");
        for (i, idx) in idxs.into_sorted().into_iter().enumerate() {
            if i != 0 {
                text.push_str(", ");
            }
            let value = match matched.entry(idx) {
                Entry::Occupied(e) => e.into_mut(),
                Entry::Vacant(e) => e.insert(matched_name(dex, kind, idx)?.to_string()),
            };
            text.push_str(value);
        }
        out.end_row();
    }
    Ok(out)
}

/// A method's distinct matched indexes. Most methods match one or two
/// constants: those stay inline, a set is allocated only for a third.
#[derive(Clone, Default)]
enum SmallIdxSet {
    #[default]
    Empty,
    One(u32),
    Two(u32, u32),
    // Boxed so the table of one slot per method stays three words a slot.
    #[allow(clippy::box_collection)]
    Many(Box<HashSet<u32>>),
}

impl SmallIdxSet {
    fn insert(&mut self, idx: u32) {
        match self {
            SmallIdxSet::Empty => *self = SmallIdxSet::One(idx),
            SmallIdxSet::One(a) if *a == idx => {}
            SmallIdxSet::One(a) => *self = SmallIdxSet::Two(*a, idx),
            SmallIdxSet::Two(a, b) if *a == idx || *b == idx => {}
            SmallIdxSet::Two(a, b) => *self = SmallIdxSet::Many(Box::new(HashSet::from([*a, *b, idx]))),
            SmallIdxSet::Many(set) => {
                set.insert(idx);
            }
        }
    }

    fn into_sorted(self) -> Vec<u32> {
        let mut out = match self {
            SmallIdxSet::Empty => Vec::new(),
            SmallIdxSet::One(a) => vec![a],
            SmallIdxSet::Two(a, b) => vec![a, b],
            SmallIdxSet::Many(set) => set.into_iter().collect(),
        };
        out.sort_unstable();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(lines: &[&str]) -> TextRows {
        let mut out = TextRows::default();
        for l in lines {
            out.owned().push_str(l);
            out.end_row();
        }
        out
    }

    #[test]
    fn rows_keep_their_boundaries_through_append_and_sharing() {
        let mut a = rows(&["x | a", "y\nz | b"]);
        a.append(&rows(&["w | c"]));
        assert_eq!(a.lines().collect::<Vec<_>>(), ["x | a", "y\nz | b", "w | c"]);
        assert_eq!((a.len(), a.as_str()), (3, "x | a\ny\nz | b\nw | c\n"));

        let bytes: Arc<dyn AsRef<[u8]> + Send + Sync> = Arc::new(format!("##{}##", a.as_str()).into_bytes());
        let range = 2..2 + a.as_str().len();
        let shared = TextRows::shared(bytes.clone(), range.clone(), a.ends().to_vec()).unwrap();
        assert_eq!(shared, a);
        // Ends that miss a newline, run past the range or leave text after
        // the last row are refused.
        for ends in [vec![0, 9, 15], vec![5, 11, 99], vec![5, 11]] {
            assert!(TextRows::shared(bytes.clone(), range.clone(), ends).is_none());
        }
        assert!(TextRows::shared(bytes, 0..0, Vec::new()).unwrap().is_empty());
    }

    #[test]
    fn small_sets_sort_and_dedup() {
        let mut s = SmallIdxSet::default();
        for i in [5, 3, 5, 9, 3, 1] {
            s.insert(i);
        }
        assert_eq!(s.into_sorted(), [1, 3, 5, 9]);
        let mut s = SmallIdxSet::default();
        s.insert(2);
        s.insert(2);
        assert_eq!(s.into_sorted(), [2]);
    }
}
