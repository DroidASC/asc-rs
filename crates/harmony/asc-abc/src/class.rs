//! Classes (records), fields and methods. All three are variable-length and
//! stored inline, so the members of a class can only be walked in order.

use std::marker::PhantomData;

use crate::abc::Region;
use crate::reader::{entity_pos, file_off, read_u64, Reader};
use crate::{Abc, AbcError, Code, DebugInfo, FunctionName, LiteralArray, ModuleRecord, RecordKind, RecordName, Result, StringData};

/// Access flag bits shared by classes, fields and methods (`modifiers.h`).
pub mod access {
    pub const PUBLIC: u32 = 0x0001;
    pub const STATIC: u32 = 0x0008;
    /// Class flag: the record is an annotation interface.
    pub const ANNOTATION: u32 = 0x2000;
}

/// Names of the fields the compiler adds to a module's record.
pub mod record_field {
    /// `u32`: offset of the module record.
    pub const MODULE_RECORD_IDX: &[u8] = b"moduleRecordIdx";
    /// `u32`: offset of the scope name literal array (12.0.6.0 and later).
    pub const SCOPE_NAMES: &[u8] = b"scopeNames";
    /// The package name is the rest of the field name: `pkgName@entry`.
    pub const PKG_NAME_PREFIX: &[u8] = b"pkgName@";
    pub const IS_COMMONJS: &[u8] = b"isCommonjs";
    pub const HAS_TOP_LEVEL_AWAIT: &[u8] = b"hasTopLevelAwait";
    pub const IS_SHARED_MODULE: &[u8] = b"isSharedModule";
    /// `u32`: offset of a string holding the content of a JSON module.
    pub const JSON_FILE_CONTENT: &[u8] = b"jsonFileContent";
    /// `u32`: offset of the module request phase table, see
    /// [`crate::Abc::module_request_phases`]. It is listed in the header's
    /// literal array index but is not a literal array.
    pub const MODULE_REQUEST_PHASE_IDX: &[u8] = b"moduleRequestPhaseIdx";
}

/// Names of the records of a file compiled from one source without
/// merging (`es2abc` without `--merge-abc`).
pub mod unmerged {
    /// The record that holds every function.
    pub const GLOBAL: &[u8] = b"_GLOBAL";
    /// The record whose field, named after the source file, holds the
    /// offset of the module record.
    pub const MODULE_RECORD: &[u8] = b"_ESModuleRecord";
    /// The same for the scope name table (12.0.6.0 and later).
    pub const SCOPE_NAMES: &[u8] = b"_ESScopeNamesRecord";
}

/// Source language tag of a class or method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceLang(pub u8);

impl SourceLang {
    pub const ECMASCRIPT: SourceLang = SourceLang(0);
    pub const PANDA_ASSEMBLY: SourceLang = SourceLang(1);
    pub const JAVASCRIPT: SourceLang = SourceLang(2);
    pub const TYPESCRIPT: SourceLang = SourceLang(3);
    pub const ARKTS: SourceLang = SourceLang(4);
}

/// One tagged value kind: reads the payload that follows a tag byte.
trait TagValue<'a>: Sized {
    const WHAT: &'static str;

    fn read(tag: u8, r: &mut Reader<'a>) -> Result<Self>;
}

/// Iterator over a `TaggedValue[]` list, up to its `NOTHING` terminator.
struct Tags<'a, T> {
    r: Reader<'a>,
    done: bool,
    kind: PhantomData<T>,
}

impl<'a, T: TagValue<'a>> Tags<'a, T> {
    fn new(buf: &'a [u8], pos: usize) -> Tags<'a, T> {
        Tags { r: Reader::new(buf, pos), done: false, kind: PhantomData }
    }

    /// Walk the whole list; returns the position just past the terminator.
    fn walk(buf: &'a [u8], pos: usize, mut visit: impl FnMut(T)) -> Result<usize> {
        let mut tags = Self::new(buf, pos);
        for tag in tags.by_ref() {
            visit(tag?);
        }
        Ok(tags.r.pos())
    }
}

impl<'a, T: TagValue<'a>> Iterator for Tags<'a, T> {
    type Item = Result<T>;

    fn next(&mut self) -> Option<Result<T>> {
        if self.done {
            return None;
        }
        let item = match self.r.u8() {
            Ok(0) => None,
            Ok(tag) => Some(T::read(tag, &mut self.r)),
            Err(err) => Some(Err(err)),
        };
        self.done = !matches!(item, Some(Ok(_)));
        item
    }
}

fn unknown_tag<T>(what: &'static str, r: &Reader<'_>) -> Result<T> {
    Err(AbcError::Malformed { what, offset: r.pos().saturating_sub(1), reason: "unknown tag" })
}

/// A list of 16-bit region indexes (unaligned).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexList<'a> {
    bytes: &'a [u8],
}

impl<'a> IndexList<'a> {
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len() / 2
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = u16> + 'a {
        self.bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]]))
    }
}

/// One element of a class's tagged value list (`ClassTag`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassTag<'a> {
    /// Indexes into the region's class table.
    Interfaces(IndexList<'a>),
    SourceLang(SourceLang),
    /// Offset of an annotation.
    RuntimeAnnotation(u32),
    Annotation(u32),
    RuntimeTypeAnnotation(u32),
    TypeAnnotation(u32),
    /// Offset of the source file name string.
    SourceFile(u32),
}

impl<'a> TagValue<'a> for ClassTag<'a> {
    const WHAT: &'static str = "class tag";

    fn read(tag: u8, r: &mut Reader<'a>) -> Result<Self> {
        Ok(match tag {
            0x01 => {
                let count = r.uleb()? as usize;
                let len = count.checked_mul(2).ok_or(AbcError::Truncated { what: "interfaces", offset: r.pos() })?;
                ClassTag::Interfaces(IndexList { bytes: r.take(len, "interfaces")? })
            }
            0x02 => ClassTag::SourceLang(SourceLang(r.u8()?)),
            0x03 => ClassTag::RuntimeAnnotation(r.u32()?),
            0x04 => ClassTag::Annotation(r.u32()?),
            0x05 => ClassTag::RuntimeTypeAnnotation(r.u32()?),
            0x06 => ClassTag::TypeAnnotation(r.u32()?),
            0x07 => ClassTag::SourceFile(r.u32()?),
            _ => return unknown_tag(Self::WHAT, r),
        })
    }
}

/// One element of a field's tagged value list (`FieldTag`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldTag {
    /// Value of a field of an integral type up to 32 bits.
    IntValue(i32),
    /// Four raw bytes; their meaning depends on the field type, see
    /// [`FieldValue::Raw`].
    Value(u32),
    RuntimeAnnotation(u32),
    Annotation(u32),
    RuntimeTypeAnnotation(u32),
    TypeAnnotation(u32),
}

impl<'a> TagValue<'a> for FieldTag {
    const WHAT: &'static str = "field tag";

    fn read(tag: u8, r: &mut Reader<'a>) -> Result<Self> {
        Ok(match tag {
            0x01 => FieldTag::IntValue(r.sleb()?),
            0x02 => FieldTag::Value(r.u32()?),
            0x03 => FieldTag::RuntimeAnnotation(r.u32()?),
            0x04 => FieldTag::Annotation(r.u32()?),
            0x05 => FieldTag::RuntimeTypeAnnotation(r.u32()?),
            0x06 => FieldTag::TypeAnnotation(r.u32()?),
            _ => return unknown_tag(Self::WHAT, r),
        })
    }
}

/// One element of a method's tagged value list (`MethodTag`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodTag {
    /// Offset of the code item.
    Code(u32),
    SourceLang(SourceLang),
    RuntimeAnnotation(u32),
    RuntimeParamAnnotation(u32),
    /// Offset of the debug info item.
    DebugInfo(u32),
    Annotation(u32),
    ParamAnnotation(u32),
    TypeAnnotation(u32),
    RuntimeTypeAnnotation(u32),
}

impl<'a> TagValue<'a> for MethodTag {
    const WHAT: &'static str = "method tag";

    fn read(tag: u8, r: &mut Reader<'a>) -> Result<Self> {
        Ok(match tag {
            0x01 => MethodTag::Code(r.u32()?),
            0x02 => MethodTag::SourceLang(SourceLang(r.u8()?)),
            0x03 => MethodTag::RuntimeAnnotation(r.u32()?),
            0x04 => MethodTag::RuntimeParamAnnotation(r.u32()?),
            0x05 => MethodTag::DebugInfo(r.u32()?),
            0x06 => MethodTag::Annotation(r.u32()?),
            0x07 => MethodTag::ParamAnnotation(r.u32()?),
            0x08 => MethodTag::TypeAnnotation(r.u32()?),
            0x09 => MethodTag::RuntimeTypeAnnotation(r.u32()?),
            _ => return unknown_tag(Self::WHAT, r),
        })
    }
}

/// An entry of the class index.
#[derive(Debug, Clone, Copy)]
pub enum ClassEntry<'a> {
    /// Defined in this file.
    Local(Class<'a>),
    /// Declared here, defined in another file.
    Foreign(ForeignClass<'a>),
}

impl<'a> ClassEntry<'a> {
    #[inline]
    pub fn offset(&self) -> u32 {
        match self {
            ClassEntry::Local(class) => class.off,
            ClassEntry::Foreign(class) => class.off,
        }
    }

    /// The type descriptor, `L<record name>;`.
    #[inline]
    pub fn descriptor(&self) -> StringData<'a> {
        match self {
            ClassEntry::Local(class) => class.descriptor,
            ClassEntry::Foreign(class) => class.descriptor,
        }
    }

    /// The record name: the descriptor without its `L` … `;` wrapping.
    #[inline]
    pub fn name(&self) -> &'a [u8] {
        record_name(self.descriptor().bytes)
    }

    #[inline]
    pub fn local(self) -> Option<Class<'a>> {
        match self {
            ClassEntry::Local(class) => Some(class),
            ClassEntry::Foreign(_) => None,
        }
    }
}

fn record_name(descriptor: &[u8]) -> &[u8] {
    descriptor.strip_prefix(b"L").and_then(|d| d.strip_suffix(b";")).unwrap_or(descriptor)
}

/// A class declared in the foreign region: only its name is stored.
#[derive(Debug, Clone, Copy)]
pub struct ForeignClass<'a> {
    pub off: u32,
    pub descriptor: StringData<'a>,
}

/// A class defined in this file. In the dynamic (ECMAScript) flavour a
/// class is a *record*: one per source module, plus a few pseudo records.
#[derive(Debug, Clone, Copy)]
pub struct Class<'a> {
    abc: Abc<'a>,
    off: u32,
    descriptor: StringData<'a>,
    pub super_class_off: u32,
    pub access_flags: u32,
    pub num_fields: u32,
    pub num_methods: u32,
    /// Position of the tagged value list.
    tags_pos: usize,
}

impl<'a> Class<'a> {
    pub(crate) fn parse(abc: Abc<'a>, off: u32) -> Result<Class<'a>> {
        let mut r = Reader::new(abc.bytes(), entity_pos(abc.bytes(), off, "class")?);
        Ok(Class {
            abc,
            off,
            descriptor: r.string()?,
            super_class_off: r.u32()?,
            access_flags: r.uleb()?,
            num_fields: r.uleb()?,
            num_methods: r.uleb()?,
            tags_pos: r.pos(),
        })
    }

    #[inline]
    pub fn offset(&self) -> u32 {
        self.off
    }

    /// The type descriptor, `L<record name>;`.
    #[inline]
    pub fn descriptor(&self) -> StringData<'a> {
        self.descriptor
    }

    /// The record name: the descriptor without its `L` … `;` wrapping.
    #[inline]
    pub fn name(&self) -> &'a [u8] {
        record_name(self.descriptor.bytes)
    }

    /// The tagged values, in file order.
    pub fn tags(&self) -> impl Iterator<Item = Result<ClassTag<'a>>> + 'a {
        Tags::new(self.abc.bytes(), self.tags_pos)
    }

    fn find_tag<T>(&self, mut pick: impl FnMut(ClassTag<'a>) -> Option<T>) -> Result<Option<T>> {
        for tag in self.tags() {
            if let Some(found) = pick(tag?) {
                return Ok(Some(found));
            }
        }
        Ok(None)
    }

    /// # Errors
    /// A malformed tagged value list.
    pub fn source_lang(&self) -> Result<Option<SourceLang>> {
        self.find_tag(|tag| if let ClassTag::SourceLang(lang) = tag { Some(lang) } else { None })
    }

    /// # Errors
    /// A malformed tagged value list or a bad string offset.
    pub fn source_file(&self) -> Result<Option<StringData<'a>>> {
        let off = self.find_tag(|tag| if let ClassTag::SourceFile(off) = tag { Some(off) } else { None })?;
        off.map(|off| self.abc.string(off)).transpose()
    }

    /// The fields, in file order.
    ///
    /// # Errors
    /// A malformed tagged value list (the fields start right after it).
    pub fn fields(&self) -> Result<Fields<'a>> {
        let pos = Tags::<ClassTag<'a>>::walk(self.abc.bytes(), self.tags_pos, |_| ())?;
        Ok(Fields { abc: self.abc, pos, remaining: self.num_fields, num_methods: self.num_methods, failed: false })
    }

    /// The methods, in file order. They follow the fields, which are walked
    /// first; when iterating both, [`Fields::into_methods`] avoids the
    /// second pass.
    ///
    /// # Errors
    /// A malformed tagged value list or field.
    pub fn methods(&self) -> Result<Methods<'a>> {
        self.fields()?.into_methods()
    }

    /// The field called `name`.
    ///
    /// # Errors
    /// A malformed member before the match.
    pub fn field(&self, name: &[u8]) -> Result<Option<Field<'a>>> {
        for field in self.fields()? {
            let field = field?;
            if field.name()?.bytes == name {
                return Ok(Some(field));
            }
        }
        Ok(None)
    }

    fn field_offset_value(&self, name: &[u8]) -> Result<Option<u32>> {
        Ok(self.field(name)?.and_then(|field| field.raw_value()))
    }

    /// The module record of this record: imports, exports and module
    /// requests, located by the `moduleRecordIdx` field. `None` for records
    /// without one (pseudo records, CommonJS modules).
    ///
    /// A file compiled from one source without merging has its functions
    /// in the record `_GLOBAL` and the offset in the only field of
    /// `_ESModuleRecord`, named after the source file: that is the module
    /// record of `_GLOBAL`.
    ///
    /// # Errors
    /// A malformed member or module record.
    pub fn module_record(&self) -> Result<Option<ModuleRecord<'a>>> {
        let off = self.own_or_unmerged(record_field::MODULE_RECORD_IDX, unmerged::MODULE_RECORD)?;
        off.filter(|&off| off != 0).map(|off| self.abc.module_record(off)).transpose()
    }

    /// The offset in field `name` of this record, or, asked of the
    /// `_GLOBAL` record of an unmerged file, in the only field of the
    /// record `holder`. Several fields there would be several modules, and
    /// nothing says which one this is.
    fn own_or_unmerged(&self, name: &[u8], holder: &[u8]) -> Result<Option<u32>> {
        if let Some(off) = self.field_offset_value(name)? {
            return Ok(Some(off));
        }
        if self.name() != unmerged::GLOBAL {
            return Ok(None);
        }
        let Some(holder) = self.abc.find_record(holder)?.and_then(ClassEntry::local) else { return Ok(None) };
        if holder.num_fields != 1 {
            return Ok(None);
        }
        Ok(holder.fields()?.next().transpose()?.and_then(|field| field.raw_value()))
    }

    /// The phase of each module request of this record, located by the
    /// `moduleRequestPhaseIdx` field; see [`Abc::module_request_phases`].
    /// `None` for records without the field (every request is then an
    /// ordinary import).
    ///
    /// # Errors
    /// A malformed member or table.
    pub fn module_request_phases(&self) -> Result<Option<&'a [u8]>> {
        self.field_offset_value(record_field::MODULE_REQUEST_PHASE_IDX)?
            .filter(|&off| off != 0)
            .map(|off| self.abc.module_request_phases(off))
            .transpose()
    }

    /// The package this record belongs to, taken from the name of its
    /// `pkgName@<package>` field.
    ///
    /// # Errors
    /// A malformed member before the match.
    pub fn package_name(&self) -> Result<Option<&'a [u8]>> {
        for field in self.fields()? {
            if let Some(package) = field?.name()?.bytes.strip_prefix(record_field::PKG_NAME_PREFIX) {
                return Ok(Some(package));
            }
        }
        Ok(None)
    }

    /// Whether the record is an annotation interface (`ACC_ANNOTATION`).
    #[inline]
    pub fn is_annotation(&self) -> bool {
        self.access_flags & access::ANNOTATION != 0
    }

    /// What the record stands for: what its name says, except that the
    /// record itself knows whether it is an annotation interface (a name
    /// can be read both ways, and outside the normalized form says
    /// nothing). The compiler's own annotation interfaces stay
    /// [`RecordKind::Service`].
    pub fn kind(&self) -> RecordKind {
        match RecordName::parse(&String::from_utf8_lossy(self.name())).kind() {
            RecordKind::Module | RecordKind::Annotation if self.is_annotation() => RecordKind::Annotation,
            RecordKind::Module | RecordKind::Annotation => RecordKind::Module,
            pseudo @ (RecordKind::Service | RecordKind::SystemModule) => pseudo,
        }
    }

    /// Entry `index` of the scope name table: what `@<hex>` in a mangled
    /// function name of this record stands for.
    ///
    /// # Errors
    /// A malformed member, literal array or string.
    pub fn scope_name(&self, index: u32) -> Result<Option<StringData<'a>>> {
        let Some(names) = self.scope_names()? else { return Ok(None) };
        names.get(index)?.and_then(|literal| literal.string_off()).map(|off| self.abc.string(off)).transpose()
    }

    /// [`FunctionName::restore`] with this record's scope names. Indexes
    /// that cannot be resolved stay as `@<hex>`.
    pub fn restore_function_name(&self, raw: &str) -> String {
        FunctionName::parse(raw).restore(|index| self.scope_name(index).ok().flatten().map(|name| name.to_str()))
    }

    /// The scope name table of this record, located by the `scopeNames`
    /// field: a literal array of strings that `@<hex>` in mangled function
    /// names indexes (see [`crate::FunctionName`]). Of the `_GLOBAL`
    /// record of an unmerged file it is the one the only field of
    /// `_ESScopeNamesRecord` locates.
    ///
    /// # Errors
    /// A malformed member or literal array header.
    pub fn scope_names(&self) -> Result<Option<LiteralArray<'a>>> {
        let off = self.own_or_unmerged(record_field::SCOPE_NAMES, unmerged::SCOPE_NAMES)?;
        off.filter(|&off| off != 0).map(|off| self.abc.literal_array(off)).transpose()
    }
}

/// Iterator over the fields of a class.
#[derive(Debug, Clone)]
pub struct Fields<'a> {
    abc: Abc<'a>,
    pos: usize,
    remaining: u32,
    num_methods: u32,
    failed: bool,
}

impl<'a> Fields<'a> {
    /// Skip the remaining fields and continue with the methods.
    ///
    /// # Errors
    /// A malformed field.
    pub fn into_methods(mut self) -> Result<Methods<'a>> {
        for field in self.by_ref() {
            field?;
        }
        if self.failed {
            // An earlier `next` already reported why; the method list is unreachable.
            return Err(AbcError::Malformed { what: "field", offset: self.pos, reason: "methods follow a field that failed to parse" });
        }
        Ok(Methods { abc: self.abc, pos: self.pos, remaining: self.num_methods })
    }
}

impl<'a> Iterator for Fields<'a> {
    type Item = Result<Field<'a>>;

    fn next(&mut self) -> Option<Result<Field<'a>>> {
        if self.remaining == 0 {
            return None;
        }
        let field = Field::parse_local(self.abc, self.pos);
        match &field {
            Ok(field) => {
                self.pos = field.end;
                self.remaining -= 1;
            }
            Err(_) => {
                self.remaining = 0;
                self.failed = true;
            }
        }
        Some(field)
    }
}

/// Iterator over the methods of a class.
#[derive(Debug, Clone)]
pub struct Methods<'a> {
    abc: Abc<'a>,
    pos: usize,
    remaining: u32,
}

impl<'a> Iterator for Methods<'a> {
    type Item = Result<Method<'a>>;

    fn next(&mut self) -> Option<Result<Method<'a>>> {
        if self.remaining == 0 {
            return None;
        }
        let method = Method::parse_local(self.abc, self.pos);
        match &method {
            Ok(method) => {
                self.pos = method.end;
                self.remaining -= 1;
            }
            Err(_) => self.remaining = 0,
        }
        Some(method)
    }
}

/// Type of a field: an entry of the region's class table (`FieldType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    U1,
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    F32,
    F64,
    I64,
    U64,
    /// Encoding `0x0b`: a reference without a class.
    Reference,
    /// Encoding `0x0c`, `any`: a tagged dynamic value.
    Any,
    /// Offset of a class or foreign class.
    Class(u32),
}

impl FieldType {
    /// Decode a class table entry. Offsets inside the file header cannot be
    /// entities, which is what makes room for the primitive codes.
    pub fn from_entry(entry: u32) -> FieldType {
        match entry {
            0x00 => FieldType::U1,
            0x01 => FieldType::I8,
            0x02 => FieldType::U8,
            0x03 => FieldType::I16,
            0x04 => FieldType::U16,
            0x05 => FieldType::I32,
            0x06 => FieldType::U32,
            0x07 => FieldType::F32,
            0x08 => FieldType::F64,
            0x09 => FieldType::I64,
            0x0a => FieldType::U64,
            0x0b => FieldType::Reference,
            0x0c => FieldType::Any,
            off => FieldType::Class(off),
        }
    }

    /// Whether a `VALUE` tag of this type holds the offset of an 8-byte
    /// value rather than the value itself.
    pub fn is_wide(&self) -> bool {
        matches!(self, FieldType::I64 | FieldType::U64 | FieldType::F64)
    }
}

/// Stored value of a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldValue {
    /// `INT_VALUE` tag.
    Int(i32),
    /// `VALUE` tag: `u32` / `f32` bits inline; for 64-bit types the offset
    /// of the 8-byte value; for everything else the offset of an entity
    /// (string, literal array, class …).
    Raw(u32),
}

/// A field (local or foreign).
#[derive(Debug, Clone, Copy)]
pub struct Field<'a> {
    abc: Abc<'a>,
    off: u32,
    /// Index of the declaring class in the region's class table.
    pub class_idx: u16,
    /// Index of the field type in the region's class table.
    pub type_idx: u16,
    pub name_off: u32,
    /// Zero for foreign fields, which store none.
    pub access_flags: u32,
    value: Option<FieldValue>,
    /// Position of the tagged value list; `None` for foreign fields.
    tags_pos: Option<usize>,
    end: usize,
}

impl<'a> Field<'a> {
    pub(crate) fn parse(abc: Abc<'a>, pos: usize) -> Result<Field<'a>> {
        if abc.header().is_foreign(file_off(pos)) {
            let mut r = Reader::new(abc.bytes(), pos);
            let (class_idx, type_idx, name_off) = (r.u16()?, r.u16()?, r.u32()?);
            Ok(Field { abc, off: file_off(pos), class_idx, type_idx, name_off, access_flags: 0, value: None, tags_pos: None, end: r.pos() })
        } else {
            Self::parse_local(abc, pos)
        }
    }

    fn parse_local(abc: Abc<'a>, pos: usize) -> Result<Field<'a>> {
        let mut r = Reader::new(abc.bytes(), pos);
        let (class_idx, type_idx, name_off, access_flags) = (r.u16()?, r.u16()?, r.u32()?, r.uleb()?);
        let tags_pos = r.pos();
        let mut value = None;
        let end = Tags::walk(abc.bytes(), tags_pos, |tag| {
            let found = match tag {
                FieldTag::IntValue(v) => Some(FieldValue::Int(v)),
                FieldTag::Value(v) => Some(FieldValue::Raw(v)),
                FieldTag::RuntimeAnnotation(_)
                | FieldTag::Annotation(_)
                | FieldTag::RuntimeTypeAnnotation(_)
                | FieldTag::TypeAnnotation(_) => None,
            };
            value = value.or(found);
        })?;
        Ok(Field { abc, off: file_off(pos), class_idx, type_idx, name_off, access_flags, value, tags_pos: Some(tags_pos), end })
    }

    #[inline]
    pub fn offset(&self) -> u32 {
        self.off
    }

    #[inline]
    pub fn is_foreign(&self) -> bool {
        self.tags_pos.is_none()
    }

    #[inline]
    pub fn is_static(&self) -> bool {
        self.access_flags & access::STATIC != 0
    }

    /// # Errors
    /// A bad name offset or string.
    pub fn name(&self) -> Result<StringData<'a>> {
        self.abc.string(self.name_off)
    }

    /// # Errors
    /// `NoRegion` or a `type_idx` outside the region's class table.
    pub fn field_type(&self) -> Result<FieldType> {
        self.abc.region_of(self.off)?.class_entry(self.type_idx).map(FieldType::from_entry)
    }

    /// The stored value, if any.
    #[inline]
    pub fn value(&self) -> Option<FieldValue> {
        self.value
    }

    /// The four bytes of a `VALUE` tag. For the special fields of dynamic
    /// records (`moduleRecordIdx`, `scopeNames`, `jsonFileContent` …) this
    /// is a file offset.
    #[inline]
    pub fn raw_value(&self) -> Option<u32> {
        match self.value {
            Some(FieldValue::Raw(v)) => Some(v),
            Some(FieldValue::Int(_)) | None => None,
        }
    }

    /// The 8-byte value a `VALUE` tag of an `i64` / `u64` / `f64` field
    /// points to.
    ///
    /// # Errors
    /// `BadOffset` or `Truncated`.
    pub fn wide_value(&self) -> Result<Option<u64>> {
        self.raw_value().map(|off| read_u64(self.abc.bytes(), entity_pos(self.abc.bytes(), off, "field value")?)).transpose()
    }

    /// The tagged values, in file order (empty for foreign fields).
    pub fn tags(&self) -> impl Iterator<Item = Result<FieldTag>> + 'a {
        self.tags_pos.map(|pos| Tags::new(self.abc.bytes(), pos)).into_iter().flatten()
    }
}

/// What kind of function a method is; stored in bits 8–15 of its access
/// flags (`FunctionKind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionKind(pub u8);

impl FunctionKind {
    pub const NONE: u8 = 0x0;
    pub const FUNCTION: u8 = 0x1;
    pub const NC_FUNCTION: u8 = 0x2;
    pub const GENERATOR_FUNCTION: u8 = 0x3;
    pub const ASYNC_FUNCTION: u8 = 0x4;
    pub const ASYNC_GENERATOR_FUNCTION: u8 = 0x5;
    pub const ASYNC_NC_FUNCTION: u8 = 0x6;
    pub const CONCURRENT_FUNCTION: u8 = 0x7;
    /// Bit or-ed into the kinds above for sendable functions.
    pub const SENDABLE: u8 = 0x8;

    /// The kind without the sendable bit.
    #[inline]
    pub fn base(&self) -> u8 {
        self.0 & !Self::SENDABLE
    }

    #[inline]
    pub fn is_sendable(&self) -> bool {
        self.0 & Self::SENDABLE != 0
    }
}

/// A method (local or foreign). In the dynamic flavour every function,
/// method and closure of a module is a method of the module's record.
#[derive(Debug, Clone, Copy)]
pub struct Method<'a> {
    abc: Abc<'a>,
    off: u32,
    /// Index of the declaring class in the region's class table.
    pub class_idx: u16,
    /// Index of the prototype in the region's proto table.
    pub proto_idx: u16,
    pub name_off: u32,
    /// Bits 0–7 flags, 8–15 [`FunctionKind`], 16–31 the region number the
    /// writer assigned (see [`Method::region`]).
    pub access_flags: u32,
    code_off: Option<u32>,
    debug_info_off: Option<u32>,
    source_lang: Option<SourceLang>,
    /// Position of the tagged value list; `None` for foreign methods.
    tags_pos: Option<usize>,
    end: usize,
}

impl<'a> Method<'a> {
    pub(crate) fn parse(abc: Abc<'a>, pos: usize) -> Result<Method<'a>> {
        if abc.header().is_foreign(file_off(pos)) {
            let mut r = Reader::new(abc.bytes(), pos);
            let (class_idx, proto_idx, name_off, access_flags) = (r.u16()?, r.u16()?, r.u32()?, r.uleb()?);
            let off = file_off(pos);
            Ok(Method {
                abc,
                off,
                class_idx,
                proto_idx,
                name_off,
                access_flags,
                code_off: None,
                debug_info_off: None,
                source_lang: None,
                tags_pos: None,
                end: r.pos(),
            })
        } else {
            Self::parse_local(abc, pos)
        }
    }

    fn parse_local(abc: Abc<'a>, pos: usize) -> Result<Method<'a>> {
        let mut r = Reader::new(abc.bytes(), pos);
        let (class_idx, proto_idx, name_off, access_flags) = (r.u16()?, r.u16()?, r.u32()?, r.uleb()?);
        let tags_pos = r.pos();
        let (mut code_off, mut debug_info_off, mut source_lang) = (None, None, None);
        let end = Tags::walk(abc.bytes(), tags_pos, |tag| match tag {
            MethodTag::Code(off) => code_off = code_off.or(Some(off)),
            MethodTag::DebugInfo(off) => debug_info_off = debug_info_off.or(Some(off)),
            MethodTag::SourceLang(lang) => source_lang = source_lang.or(Some(lang)),
            MethodTag::RuntimeAnnotation(_)
            | MethodTag::RuntimeParamAnnotation(_)
            | MethodTag::Annotation(_)
            | MethodTag::ParamAnnotation(_)
            | MethodTag::TypeAnnotation(_)
            | MethodTag::RuntimeTypeAnnotation(_) => {}
        })?;
        let off = file_off(pos);
        Ok(Method {
            abc,
            off,
            class_idx,
            proto_idx,
            name_off,
            access_flags,
            code_off,
            debug_info_off,
            source_lang,
            tags_pos: Some(tags_pos),
            end,
        })
    }

    #[inline]
    pub fn offset(&self) -> u32 {
        self.off
    }

    #[inline]
    pub fn is_foreign(&self) -> bool {
        self.tags_pos.is_none()
    }

    #[inline]
    pub fn is_static(&self) -> bool {
        self.access_flags & access::STATIC != 0
    }

    /// The raw (mangled) name; see [`crate::FunctionName`] to take it apart.
    ///
    /// # Errors
    /// A bad name offset or string.
    pub fn name(&self) -> Result<StringData<'a>> {
        self.abc.string(self.name_off)
    }

    #[inline]
    pub fn function_kind(&self) -> FunctionKind {
        FunctionKind(self.access_flags.to_le_bytes()[1])
    }

    #[inline]
    pub fn source_lang(&self) -> Option<SourceLang> {
        self.source_lang
    }

    #[inline]
    pub fn code_off(&self) -> Option<u32> {
        self.code_off
    }

    /// # Errors
    /// A bad code offset or a malformed code header.
    pub fn code(&self) -> Result<Option<Code<'a>>> {
        self.code_off.map(|off| self.abc.code(off)).transpose()
    }

    #[inline]
    pub fn debug_info_off(&self) -> Option<u32> {
        self.debug_info_off
    }

    /// # Errors
    /// A bad debug info offset or a malformed item.
    pub fn debug_info(&self) -> Result<Option<DebugInfo<'a>>> {
        self.debug_info_off.map(|off| self.abc.debug_info(off)).transpose()
    }

    /// The tagged values, in file order (empty for foreign methods).
    pub fn tags(&self) -> impl Iterator<Item = Result<MethodTag>> + 'a {
        self.tags_pos.map(|pos| Tags::new(self.abc.bytes(), pos)).into_iter().flatten()
    }

    /// The region number the writer stored in the access flags
    /// (`MethodItem::SetHeaderIndex`). A hint only: see [`Method::region`].
    #[inline]
    pub fn region_hint(&self) -> u32 {
        self.access_flags >> 16
    }

    /// The region whose index tables this method's instructions use.
    ///
    /// The method's offset decides (`File::GetIndexHeader`). The region
    /// number in the access flags is tried first, but only believed when
    /// that region really contains the method.
    ///
    /// # Errors
    /// `NoRegion` when no region covers the method.
    pub fn region(&self) -> Result<Region<'a>> {
        let regions = self.abc.regions()?;
        regions
            .get(self.region_hint())
            .filter(|region| region.contains(self.off))
            .or_else(|| regions.containing(self.off))
            .ok_or(AbcError::NoRegion { offset: self.off })
    }

    /// Resolve a 16-bit string / method / literal array id from this
    /// method's instructions to a file offset.
    ///
    /// # Errors
    /// `NoRegion`, `IndexOutOfRange` or `Truncated`.
    pub fn resolve(&self, idx: u16) -> Result<u32> {
        self.region()?.entity_offset(idx)
    }

    /// Offset of the declaring class.
    ///
    /// # Errors
    /// `NoRegion` or a `class_idx` outside the region's class table.
    pub fn class_off(&self) -> Result<u32> {
        self.region()?.class_entry(self.class_idx)
    }

    /// Offset of the prototype item, or `None` when the region has no proto
    /// table: dynamic-language files since 12.0.x store none, and
    /// `proto_idx` is then meaningless. The item itself (a shorty of 4-bit
    /// type codes) is not decoded by this crate.
    ///
    /// # Errors
    /// `NoRegion` or `Truncated`.
    pub fn proto_off(&self) -> Result<Option<u32>> {
        Ok(self.region()?.proto_table()?.get(u32::from(self.proto_idx)))
    }
}
