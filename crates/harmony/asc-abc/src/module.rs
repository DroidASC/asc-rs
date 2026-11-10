//! Module records: the import / export tables of an ES module. They sit
//! where a literal array would (and are counted in the literal array index
//! of older files) but have their own fixed layout.

use std::marker::PhantomData;

use crate::abc::OffsetTable;
use crate::reader::{entity_pos, read_u16, read_u32, Reader};
use crate::{AbcError, Result};

/// A fixed-size entry of one of the module record sections.
pub trait ModuleEntry: Sized {
    /// Encoded size in bytes.
    const SIZE: usize;

    /// Decode from exactly [`ModuleEntry::SIZE`] bytes.
    fn decode(raw: &[u8]) -> Option<Self>;
}

/// `import { import_name as local_name } from <request>`.
/// `ldexternalmodulevar N` reads entry `N` of this section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegularImport {
    pub local_name_off: u32,
    pub import_name_off: u32,
    pub module_request_idx: u16,
}

/// `import * as local_name from <request>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NamespaceImport {
    pub local_name_off: u32,
    pub module_request_idx: u16,
}

/// `export { local_name as export_name }`.
/// `ldlocalmodulevar N` / `stmodulevar N` use entry `N` of this section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalExport {
    pub local_name_off: u32,
    pub export_name_off: u32,
}

/// `export { import_name as export_name } from <request>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndirectExport {
    pub export_name_off: u32,
    pub import_name_off: u32,
    pub module_request_idx: u16,
}

/// `export * from <request>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StarExport {
    pub module_request_idx: u16,
}

impl ModuleEntry for RegularImport {
    const SIZE: usize = 10;

    fn decode(raw: &[u8]) -> Option<Self> {
        Some(RegularImport {
            local_name_off: read_u32(raw, 0).ok()?,
            import_name_off: read_u32(raw, 4).ok()?,
            module_request_idx: read_u16(raw, 8).ok()?,
        })
    }
}

impl ModuleEntry for NamespaceImport {
    const SIZE: usize = 6;

    fn decode(raw: &[u8]) -> Option<Self> {
        Some(NamespaceImport { local_name_off: read_u32(raw, 0).ok()?, module_request_idx: read_u16(raw, 4).ok()? })
    }
}

impl ModuleEntry for LocalExport {
    const SIZE: usize = 8;

    fn decode(raw: &[u8]) -> Option<Self> {
        Some(LocalExport { local_name_off: read_u32(raw, 0).ok()?, export_name_off: read_u32(raw, 4).ok()? })
    }
}

impl ModuleEntry for IndirectExport {
    const SIZE: usize = 10;

    fn decode(raw: &[u8]) -> Option<Self> {
        Some(IndirectExport {
            export_name_off: read_u32(raw, 0).ok()?,
            import_name_off: read_u32(raw, 4).ok()?,
            module_request_idx: read_u16(raw, 8).ok()?,
        })
    }
}

impl ModuleEntry for StarExport {
    const SIZE: usize = 2;

    fn decode(raw: &[u8]) -> Option<Self> {
        Some(StarExport { module_request_idx: read_u16(raw, 0).ok()? })
    }
}

/// One section of a module record: a bounds-checked array of entries.
#[derive(Debug, Clone, Copy)]
pub struct Section<'a, T> {
    bytes: &'a [u8],
    entry: PhantomData<T>,
}

impl<'a, T: ModuleEntry + 'a> Section<'a, T> {
    fn read(r: &mut Reader<'a>, what: &'static str) -> Result<Section<'a, T>> {
        let count = r.u32()? as usize;
        let len = count.checked_mul(T::SIZE).ok_or(AbcError::Truncated { what, offset: r.pos() })?;
        Ok(Section { bytes: r.take(len, what)?, entry: PhantomData })
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len() / T::SIZE
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Entry `index`, the operand of the module variable instructions.
    pub fn get(&self, index: usize) -> Option<T> {
        let start = index.checked_mul(T::SIZE)?;
        self.bytes.get(start..start.checked_add(T::SIZE)?).and_then(T::decode)
    }

    pub fn iter(&self) -> impl Iterator<Item = T> + 'a {
        self.bytes.chunks_exact(T::SIZE).filter_map(T::decode)
    }
}

/// A module record, with all section bounds checked up front.
#[derive(Debug, Clone, Copy)]
pub struct ModuleRecord<'a> {
    off: u32,
    /// The leading `u32`; a literal count that readers skip.
    pub num_literals: u32,
    /// Offsets of the module request strings (`@ohos:net.http`,
    /// `@normalized:N&&&entry/src/main/ets/pages/Index&` …).
    pub requests: OffsetTable<'a>,
    pub regular_imports: Section<'a, RegularImport>,
    pub namespace_imports: Section<'a, NamespaceImport>,
    pub local_exports: Section<'a, LocalExport>,
    pub indirect_exports: Section<'a, IndirectExport>,
    pub star_exports: Section<'a, StarExport>,
}

impl<'a> ModuleRecord<'a> {
    pub(crate) fn parse(buf: &'a [u8], off: u32) -> Result<ModuleRecord<'a>> {
        let mut r = Reader::new(buf, entity_pos(buf, off, "module record")?);
        let num_literals = r.u32()?;
        let num_requests = r.u32()? as usize;
        let requests_len = num_requests.checked_mul(4).ok_or(AbcError::Truncated { what: "module requests", offset: r.pos() })?;
        Ok(ModuleRecord {
            off,
            num_literals,
            requests: OffsetTable::new(r.take(requests_len, "module requests")?),
            regular_imports: Section::read(&mut r, "regular imports")?,
            namespace_imports: Section::read(&mut r, "namespace imports")?,
            local_exports: Section::read(&mut r, "local exports")?,
            indirect_exports: Section::read(&mut r, "indirect exports")?,
            star_exports: Section::read(&mut r, "star exports")?,
        })
    }

    #[inline]
    pub fn offset(&self) -> u32 {
        self.off
    }

    /// String offset of module request `idx` (the `module_request_idx` of an
    /// import or export entry).
    pub fn request(&self, idx: u16) -> Option<u32> {
        self.requests.get(u32::from(idx))
    }
}
