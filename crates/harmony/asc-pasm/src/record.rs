//! Record level: the header (kind, package, source file, module record),
//! the fields, and the per-record lookups instructions need.

use std::fmt::{self, Write};

use asc_abc::{
    record_field, Abc, AbcError, Class, Field, FieldType, FieldValue, FunctionName, LiteralArray, ModuleRecord, RecordKind, RecordName,
};

use crate::literal::{method_name, write_literal_array};
use crate::module::ModuleText;
use crate::text::{write_count, write_error, write_f32, write_imm, write_name, write_quoted, ELLIPSIS};
use crate::Options;

/// What rendering the functions of a record needs from the record itself,
/// looked up once per record rather than once per instruction.
pub(crate) struct RecordInfo<'a> {
    /// The table `@<hex>` in mangled function names indexes; `None` when the
    /// record has none (older files) or it cannot be read.
    scope_names: Option<LiteralArray<'a>>,
    pub(crate) module: Result<Option<ModuleRecord<'a>>, AbcError>,
    /// Phase of each module request; empty without a phase table. A table
    /// that cannot be read is reported where the field is listed.
    phases: &'a [u8],
}

impl<'a> RecordInfo<'a> {
    pub(crate) fn load(class: &Class<'a>) -> RecordInfo<'a> {
        RecordInfo {
            scope_names: class.scope_names().ok().flatten(),
            module: class.module_record(),
            phases: class.module_request_phases().ok().flatten().unwrap_or_default(),
        }
    }

    /// For instructions that refer to nothing of their record.
    pub(crate) fn none() -> RecordInfo<'a> {
        RecordInfo { scope_names: None, module: Ok(None), phases: &[] }
    }

    /// For a method whose record cannot be found: names stay raw and module
    /// operands report `error`.
    pub(crate) fn unresolved(error: AbcError) -> RecordInfo<'a> {
        RecordInfo { scope_names: None, module: Err(error), phases: &[] }
    }

    /// The readable form of a raw function name (`Index.build` for
    /// `#~@0>#build`); `None` when it would add nothing over the raw name.
    pub(crate) fn restored_name(&self, abc: &Abc<'a>, raw: &str) -> Option<String> {
        let name = FunctionName::parse(raw);
        if !name.is_scoped() && name.base_name() == raw {
            return None;
        }
        let scope_name = |index: u32| {
            let literal = self.scope_names.as_ref()?.get(index).ok()??;
            Some(abc.string(literal.string_off()?).ok()?.to_str())
        };
        Some(name.restore(scope_name)).filter(|restored| restored != raw)
    }

    pub(crate) fn restored_method_name(&self, abc: &Abc<'a>, method_off: u32) -> Option<String> {
        self.restored_name(abc, &method_name(abc, method_off).ok()?)
    }
}

fn kind_text(class: &Class<'_>, name: &RecordName<'_>) -> &'static str {
    match name.kind() {
        _ if class.is_annotation() => "annotation interface",
        RecordKind::Module => "module",
        RecordKind::Service => "compiler service record",
        RecordKind::SystemModule => "system module placeholder",
    }
}

/// `.record <name>`, a summary line, and the module record.
pub(crate) fn write_header<W: Write>(
    out: &mut W,
    abc: &Abc<'_>,
    class: &Class<'_>,
    info: &RecordInfo<'_>,
    opts: &Options<'_>,
) -> fmt::Result {
    let name = String::from_utf8_lossy(class.name());
    out.write_str(".record ")?;
    write_name(out, &name)?;
    let parsed = RecordName::parse(&name);
    write!(out, "\n; {}", kind_text(class, &parsed))?;

    match class.package_name() {
        Ok(Some(package)) => {
            out.write_str(", package ")?;
            write_name(out, &String::from_utf8_lossy(package))?;
        }
        Ok(None) => {
            if let Some(package) = parsed.package() {
                out.write_str(", package ")?;
                write_name(out, package)?;
            }
        }
        // The field walk below reports the same failure.
        Err(_) => {}
    }
    match class.source_file() {
        Ok(Some(source)) => {
            out.write_str(", source ")?;
            write_quoted(out, &source.to_str(), usize::MAX)?;
        }
        Ok(None) => {}
        Err(error) => {
            out.write_str(", source ")?;
            write_error(out, error)?;
        }
    }
    out.write_str(", ")?;
    write_count(out, class.num_fields, "field")?;
    out.write_str(", ")?;
    write_count(out, class.num_methods, "function")?;
    out.write_char('\n')?;
    if let Some(source) = &opts.source {
        out.write_str("; source ")?;
        write_name(out, source.file)?;
        out.write_str(
            " (by the source map: \"line N\" of a function is a line of the compiled file, from 0; \"source line\" is the line here)\n",
        )?;
    }

    match &info.module {
        Ok(Some(module)) => ModuleText { abc, module }.write_sections(out, info.phases),
        Ok(None) => Ok(()),
        Err(error) => {
            out.write_str(".module ; ")?;
            write_error(out, error)?;
            out.write_char('\n')
        }
    }
}

fn write_type<W: Write>(out: &mut W, abc: &Abc<'_>, field: &Field<'_>) -> fmt::Result {
    let name = match field.field_type() {
        Ok(FieldType::U1) => "u1",
        Ok(FieldType::I8) => "i8",
        Ok(FieldType::U8) => "u8",
        Ok(FieldType::I16) => "i16",
        Ok(FieldType::U16) => "u16",
        Ok(FieldType::I32) => "i32",
        Ok(FieldType::U32) => "u32",
        Ok(FieldType::F32) => "f32",
        Ok(FieldType::F64) => "f64",
        Ok(FieldType::I64) => "i64",
        Ok(FieldType::U64) => "u64",
        Ok(FieldType::Reference) => "ref",
        Ok(FieldType::Any) => "any",
        // A class starts with its descriptor, local or foreign.
        Ok(FieldType::Class(off)) => {
            return match abc.string(off) {
                Ok(descriptor) => write_name(out, &descriptor.to_str()),
                Err(error) => write_error(out, format_args!("type @{off:#x}: {error}")),
            }
        }
        Err(error) => return write_error(out, format_args!("type: {error}")),
    };
    out.write_str(name)
}

/// `[ 0, 1, 0 ]`, bounded like a literal array.
fn write_phases<W: Write>(out: &mut W, phases: &[u8], opts: &Options) -> fmt::Result {
    out.write_char('[')?;
    for (shown, phase) in phases.iter().enumerate() {
        out.write_str(if shown == 0 { " " } else { ", " })?;
        if shown == opts.literal_limit {
            write!(out, "{ELLIPSIS} (+{} more)", phases.len() - shown)?;
            break;
        }
        write!(out, "{phase}")?;
    }
    out.write_str(" ]")
}

fn write_raw_value<W: Write>(out: &mut W, abc: &Abc<'_>, field: &Field<'_>, name: &[u8], raw: u32, opts: &Options) -> fmt::Result {
    if name == record_field::SCOPE_NAMES {
        return write_literal_array(out, abc, raw, opts);
    }
    if name == record_field::MODULE_REQUEST_PHASE_IDX {
        // One untagged byte per module request, not a literal array.
        return match abc.module_request_phases(raw) {
            Ok(phases) => write_phases(out, phases, opts),
            Err(error) => write_error(out, error),
        };
    }
    if name == record_field::MODULE_RECORD_IDX {
        // Rendered as `.module` in the header.
        return write!(out, "@{raw:#x}");
    }
    if name == record_field::JSON_FILE_CONTENT {
        return match abc.string(raw) {
            Ok(content) => write_quoted(out, &content.to_str(), opts.string_limit),
            Err(error) => write_error(out, error),
        };
    }
    match field.field_type() {
        Ok(FieldType::F32) => write_f32(out, f32::from_bits(raw)),
        Ok(kind) if kind.is_wide() => match field.wide_value() {
            Ok(Some(wide)) => write!(out, "{wide:#x}"),
            Ok(None) => write!(out, "@{raw:#x}"),
            Err(error) => write_error(out, error),
        },
        Ok(FieldType::Reference | FieldType::Any | FieldType::Class(_)) | Err(_) => write!(out, "@{raw:#x}"),
        Ok(_) => write_imm(out, i64::from(raw)),
    }
}

/// `.field <type> <name>[ = <value>]`.
pub(crate) fn write_field<W: Write>(out: &mut W, abc: &Abc<'_>, field: &Field<'_>, opts: &Options) -> fmt::Result {
    out.write_str(".field ")?;
    write_type(out, abc, field)?;
    out.write_char(' ')?;
    let name = match field.name() {
        Ok(name) => name,
        Err(error) => {
            write_error(out, format_args!("name: {error}"))?;
            return out.write_char('\n');
        }
    };
    write_name(out, &name.to_str())?;
    match field.value() {
        Some(FieldValue::Int(value)) => {
            out.write_str(" = ")?;
            write_imm(out, i64::from(value))?;
        }
        Some(FieldValue::Raw(raw)) => {
            out.write_str(" = ")?;
            write_raw_value(out, abc, field, name.bytes, raw, opts)?;
        }
        None => {}
    }
    out.write_char('\n')
}
