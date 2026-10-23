//! Storage of the locator tables: built on the heap, or viewed in place in
//! bytes a cache mapped from disk (see [`crate::persist`]), so several
//! processes share one copy as file pages instead of each building its own.

use std::ops::Deref;
use std::sync::Arc;

/// Bytes persisted tables are viewed in (typically a memory-mapped cache
/// file). Kept alive by every table viewing it.
pub type Backing = Arc<dyn AsRef<[u8]> + Send + Sync>;

/// Plain element types a table may be viewed as.
pub(crate) trait Pod: bytemuck::Pod + Send + Sync {}
impl Pod for u16 {}
impl Pod for u32 {}
impl Pod for u64 {}
impl Pod for [u32; 2] {}

/// A table of `T`, owned or viewed in [`Backing`] bytes.
pub(crate) enum Table<T: Pod> {
    Owned(Vec<T>),
    Mapped { backing: Backing, off: usize, len: usize },
}

impl<T: Pod> Table<T> {
    /// `len` elements at byte offset `off` of `backing`, if they lie inside
    /// it and are aligned for `T`.
    pub(crate) fn view(backing: &Backing, off: usize, len: usize) -> Option<Table<T>> {
        let bytes = (**backing).as_ref();
        let end = len.checked_mul(std::mem::size_of::<T>())?.checked_add(off)?;
        bytemuck::try_cast_slice::<u8, T>(bytes.get(off..end)?).ok()?;
        Some(Table::Mapped { backing: Arc::clone(backing), off, len })
    }

    /// Heap bytes held (mapped tables live in file pages, not the heap).
    pub(crate) fn heap_bytes(&self) -> usize {
        match self {
            Table::Owned(v) => v.capacity() * std::mem::size_of::<T>(),
            Table::Mapped { .. } => 0,
        }
    }

    /// Bytes viewed in the backing (0 for an owned table).
    pub(crate) fn mapped_bytes(&self) -> usize {
        match self {
            Table::Owned(_) => 0,
            Table::Mapped { len, .. } => len * std::mem::size_of::<T>(),
        }
    }

    /// The elements as native-endian bytes, for persisting.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        bytemuck::cast_slice(self)
    }
}

impl<T: Pod> Clone for Table<T> {
    fn clone(&self) -> Self {
        match self {
            Table::Owned(v) => Table::Owned(v.clone()),
            Table::Mapped { backing, off, len } => Table::Mapped { backing: Arc::clone(backing), off: *off, len: *len },
        }
    }
}

/// Tables compare by their elements, however they are stored.
impl<T: Pod + PartialEq> PartialEq for Table<T> {
    fn eq(&self, other: &Self) -> bool {
        **self == **other
    }
}

impl<T: Pod + Eq> Eq for Table<T> {}

impl<T: Pod + std::fmt::Debug> std::fmt::Debug for Table<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

impl<T: Pod> Default for Table<T> {
    fn default() -> Self {
        Table::Owned(Vec::new())
    }
}

impl<T: Pod> From<Vec<T>> for Table<T> {
    fn from(v: Vec<T>) -> Self {
        Table::Owned(v)
    }
}

impl<T: Pod> Deref for Table<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        match self {
            Table::Owned(v) => v,
            Table::Mapped { backing, off, len } => {
                // `view` checked that the range lies inside the (immutable)
                // backing and is aligned for `T`.
                bytemuck::cast_slice(&(**backing).as_ref()[*off..*off + *len * std::mem::size_of::<T>()])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn views_check_bounds_and_alignment() {
        let words: Vec<u32> = vec![1, 2, 3, 4];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_ne_bytes()).collect();
        // A Vec<u8> allocation is not guaranteed 4-aligned: keep the words in u32 storage.
        struct Words(Vec<u32>);
        impl AsRef<[u8]> for Words {
            fn as_ref(&self) -> &[u8] {
                bytemuck::cast_slice(&self.0)
            }
        }
        let backing: Backing = Arc::new(Words(words.clone()));
        let t = Table::<u32>::view(&backing, 4, 3).unwrap();
        assert_eq!(&*t, &[2, 3, 4]);
        assert_eq!(t.heap_bytes(), 0);
        assert_eq!(t.as_bytes(), &bytes[4..]);
        let pairs = Table::<[u32; 2]>::view(&backing, 0, 2).unwrap();
        assert_eq!(&*pairs, &[[1, 2], [3, 4]]);
        assert!(Table::<u32>::view(&backing, 4, 4).is_none(), "past the end");
        assert!(Table::<u32>::view(&backing, 2, 1).is_none(), "misaligned");
        assert!(Table::<u32>::view(&backing, usize::MAX, 1).is_none(), "overflow");
        let owned: Table<u32> = vec![7u32; 3].into();
        assert_eq!(owned.heap_bytes(), 12);
    }
}
