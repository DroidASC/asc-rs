//! `resources.index`: the compiled resource table of a HAP/HSP, which
//! maps resource ids to types, names and one value per qualifier set.
//!
//! Two layouts exist, told apart by the tool name that opens the file:
//! `Restool <version>` (every value is its own record, found through one
//! id table per qualifier set) and `RestoolV2 <version>` (one name table
//! per type, then per resource the qualifier sets it has a value under).
//! [`ResourceIndex::parse`] reads either and refuses anything else.
//!
//! Parsing walks the tables once and keeps slices of the input: names
//! and values are decoded when asked for.

mod qualifier;
mod reader;
mod v1;
mod v2;
mod value;

use std::borrow::Cow;
use std::fmt;
use std::ops::Range;

pub use qualifier::{Qualifier, QualifierKey, Qualifiers};
use reader::Reader;
pub use value::{Attr, ResourceRef, ResourceType, ResourceValue, UnknownResourceType};

/// Why a `resources.index` could not be read. Offsets are file offsets.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ResourceIndexError {
    /// The file does not open with a tool name this crate knows the
    /// layout of.
    #[error("unknown resource index version {version:?} (known: \"Restool <version>\", \"RestoolV2 <version>\")")]
    UnknownVersion {
        /// The version text of the header, read lossily.
        version: String,
    },
    #[error("{what} at {offset:#x} needs {needed} bytes, {available} are left")]
    Truncated { what: &'static str, offset: usize, needed: usize, available: usize },
    #[error("{what} offset {offset:#x} is outside the index of {len:#x} bytes")]
    OutOfBounds { what: &'static str, offset: u32, len: usize },
    #[error("expected the tag {expected:?} at {offset:#x}, found {found:?}")]
    BadTag { expected: &'static str, offset: usize, found: [u8; 4] },
    /// A table row and the block it points at name different resources.
    #[error("the table lists resource {listed:#010x} at {offset:#x}, where {found:#010x} is stored")]
    IdMismatch { listed: u32, found: u32, offset: usize },
    /// A value names a qualifier set the header does not define.
    #[error("resource {id:#010x} has a value for qualifier set {config}, which the index does not define")]
    UnknownQualifiers { id: u32, config: u32 },
    /// Tables that share or repeat blocks describe more values than a
    /// well-formed index of this size can.
    #[error("the tables describe more than {limit} values, more than an index of this size holds")]
    TooManyValues { limit: usize },
}

type Result<T> = std::result::Result<T, ResourceIndexError>;

/// Which of the two layouts an index uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IndexFormat {
    /// `Restool <version>`.
    V1,
    /// `RestoolV2 <version>`.
    V2,
}

impl IndexFormat {
    /// Whether the stored length of a value counts a closing NUL.
    fn terminates_values(self) -> bool {
        match self {
            IndexFormat::V1 => true,
            IndexFormat::V2 => false,
        }
    }
}

/// One value of one resource, as slices of the input.
#[derive(Debug, Clone, Copy)]
struct Entry<'a> {
    id: u32,
    kind: ResourceType,
    /// Position in `ResourceIndex::qualifiers`.
    qualifiers: usize,
    name: &'a [u8],
    value: &'a [u8],
}

/// Collects the entries of an index under a cap, so tables that point
/// many rows at the same block cannot multiply into unbounded work.
struct Entries<'a> {
    entries: Vec<Entry<'a>>,
    limit: usize,
}

impl<'a> Entries<'a> {
    /// Every value of a well-formed index owns a table row of 8 bytes.
    const MIN_BYTES_PER_VALUE: usize = 8;

    fn for_index(bytes: &[u8]) -> Entries<'a> {
        Entries { entries: Vec::new(), limit: bytes.len() / Self::MIN_BYTES_PER_VALUE }
    }

    fn push(&mut self, entry: Entry<'a>) -> Result<()> {
        if self.entries.len() >= self.limit {
            return Err(ResourceIndexError::TooManyValues { limit: self.limit });
        }
        self.entries.push(entry);
        Ok(())
    }
}

/// What a layout's reader hands back.
struct Tables<'a> {
    qualifiers: Vec<Qualifiers>,
    entries: Vec<Entry<'a>>,
}

/// A parsed `resources.index`, borrowing the bytes it was read from.
///
/// ```
/// # fn demo(bytes: &[u8]) -> Result<(), asc_hap::ResourceIndexError> {
/// use asc_hap::{ResourceIndex, ResourceRef, ResourceType};
///
/// let index = ResourceIndex::parse(bytes)?;
/// // `$r('app.string.app_name')` compiled to `{ id: 0x1000000, type: 10003, .. }`.
/// for resource in index.by_id(0x0100_0000) {
///     println!("{resource}"); // 0x01000000 string/app_name [base] "Bridge"
/// }
/// // `"label": "$string:app_name"` in module.json.
/// let label = ResourceRef::parse("$string:app_name").expect("a reference");
/// assert!(index.resolve(label).all(|r| r.kind() == ResourceType::String));
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct ResourceIndex<'a> {
    version: Cow<'a, str>,
    format: IndexFormat,
    qualifiers: Vec<Qualifiers>,
    /// Sorted by id, then by qualifier set in file order.
    entries: Vec<Entry<'a>>,
    /// Positions in `entries`, sorted by type and name.
    by_name: Vec<usize>,
}

impl<'a> ResourceIndex<'a> {
    /// Bytes of the version text that opens both layouts.
    const VERSION_LEN: usize = 128;

    /// Reads the tables of an index. Values are not decoded here.
    ///
    /// # Errors
    ///
    /// [`ResourceIndexError::UnknownVersion`] when the header names
    /// neither layout; the other variants when a table is cut short,
    /// points outside the file or contradicts another.
    pub fn parse(bytes: &'a [u8]) -> Result<ResourceIndex<'a>> {
        let mut reader = Reader::new(bytes);
        let version = reader.take(Self::VERSION_LEN, "version")?;
        let version = String::from_utf8_lossy(version.split(|&b| b == 0).next().unwrap_or_default());
        let format = match version.split(' ').next() {
            Some("Restool") => IndexFormat::V1,
            Some("RestoolV2") => IndexFormat::V2,
            _ => return Err(ResourceIndexError::UnknownVersion { version: version.into_owned() }),
        };
        let Tables { qualifiers, mut entries } = match format {
            IndexFormat::V1 => v1::read(bytes, reader)?,
            IndexFormat::V2 => v2::read(bytes, reader)?,
        };
        entries.sort_by_key(|e| (e.id, e.qualifiers));
        let mut by_name: Vec<usize> = (0..entries.len()).collect();
        by_name.sort_by_key(|&i| (entries[i].kind.code(), entries[i].name, i));
        Ok(ResourceIndex { version, format, qualifiers, entries, by_name })
    }

    /// The version text of the header: `Restool 5.0.1.011`.
    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn format(&self) -> IndexFormat {
        self.format
    }

    /// The qualifier sets the index defines, in file order.
    pub fn qualifiers(&self) -> &[Qualifiers] {
        &self.qualifiers
    }

    /// Number of values: one per resource and qualifier set.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every value, by id and then by qualifier set in file order.
    pub fn iter(&self) -> Resources<'_> {
        Resources { index: self, order: Order::ById(0..self.entries.len()) }
    }

    /// The values of the resource with this id, one per qualifier set.
    /// The id is the `id` of a compiled `$r(...)` object and the
    /// `labelId` / `iconId` / `descriptionId` of `module.json`.
    pub fn by_id(&self, id: u32) -> Resources<'_> {
        let start = self.entries.partition_point(|e| e.id < id);
        let end = start + self.entries[start..].partition_point(|e| e.id == id);
        Resources { index: self, order: Order::ById(start..end) }
    }

    /// The values of the resource with this type and name.
    pub fn by_name(&self, kind: ResourceType, name: &str) -> Resources<'_> {
        let key = (kind.code(), name.as_bytes());
        let of = |&i: &usize| (self.entries[i].kind.code(), self.entries[i].name);
        let start = self.by_name.partition_point(|i| of(i) < key);
        let end = start + self.by_name[start..].partition_point(|i| of(i) == key);
        Resources { index: self, order: Order::ByName(start..end) }
    }

    /// The values a reference points at: by name, or, for the decimal ids
    /// that values inside the index use (`$color:16777245`), by id among
    /// the resources of that type. A name wins over an id spelled alike.
    pub fn resolve(&self, reference: ResourceRef<'_>) -> Resources<'_> {
        let named = self.by_name(reference.kind, reference.name);
        if named.len() > 0 {
            return named;
        }
        match reference.name.parse() {
            Ok(id) if self.by_id(id).all(|r| r.kind() == reference.kind) => self.by_id(id),
            _ => named,
        }
    }
}

impl<'r> IntoIterator for &'r ResourceIndex<'_> {
    type Item = Resource<'r>;
    type IntoIter = Resources<'r>;

    fn into_iter(self) -> Resources<'r> {
        self.iter()
    }
}

#[derive(Debug, Clone)]
enum Order {
    /// A range of `ResourceIndex::entries`.
    ById(Range<usize>),
    /// A range of `ResourceIndex::by_name`.
    ByName(Range<usize>),
}

/// Values of an index, from [`ResourceIndex::iter`] or one of its lookups.
#[derive(Debug, Clone)]
pub struct Resources<'r> {
    index: &'r ResourceIndex<'r>,
    order: Order,
}

impl<'r> Resources<'r> {
    fn resource(&self, position: usize) -> Resource<'r> {
        let position = match self.order {
            Order::ById(_) => position,
            Order::ByName(_) => self.index.by_name[position],
        };
        Resource { index: self.index, entry: &self.index.entries[position] }
    }

    fn range(&mut self) -> &mut Range<usize> {
        match &mut self.order {
            Order::ById(range) | Order::ByName(range) => range,
        }
    }
}

impl<'r> Iterator for Resources<'r> {
    type Item = Resource<'r>;

    fn next(&mut self) -> Option<Resource<'r>> {
        let position = self.range().next()?;
        Some(self.resource(position))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.order {
            Order::ById(range) | Order::ByName(range) => range.size_hint(),
        }
    }
}

impl DoubleEndedIterator for Resources<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let position = self.range().next_back()?;
        Some(self.resource(position))
    }
}

impl ExactSizeIterator for Resources<'_> {}

/// One value of one resource: its id, type, name, the qualifier set the
/// value is for, and the value.
#[derive(Debug, Clone, Copy)]
pub struct Resource<'r> {
    index: &'r ResourceIndex<'r>,
    entry: &'r Entry<'r>,
}

impl<'r> Resource<'r> {
    pub fn id(&self) -> u32 {
        self.entry.id
    }

    pub fn kind(&self) -> ResourceType {
        self.entry.kind
    }

    /// The name, read lossily when it is not UTF-8. A media or profile
    /// resource is named after its file without the extension.
    pub fn name(&self) -> Cow<'r, str> {
        String::from_utf8_lossy(self.entry.name)
    }

    pub fn qualifiers(&self) -> &'r Qualifiers {
        &self.index.qualifiers[self.entry.qualifiers]
    }

    /// The stored bytes of the value, before any decoding.
    pub fn raw_value(&self) -> &'r [u8] {
        self.entry.value
    }

    pub fn value(&self) -> ResourceValue<'r> {
        ResourceValue::decode(self.entry.kind, self.entry.value, self.index.format.terminates_values())
    }
}

/// `0x01000000 string/app_name [base] "Bridge"`: id, type/name, the
/// qualifier set as its directory name, the value on one line.
impl fmt::Display for Resource<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x} {}/{} [{}] {}", self.id(), self.kind(), self.name(), self.qualifiers(), self.value())
    }
}

#[cfg(test)]
mod tests;
