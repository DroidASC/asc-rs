//! Inline rendering of literal arrays: `[ "name", 0x1d4b42 (1919810), method:#~@0>#build, … (+3 more) ]`.
//!
//! Strings, numbers, booleans and `null` are written bare; every other item
//! carries the tag name the official disassembler prints (`method:`,
//! `method_affiliate:` …). A nested array is not expanded, it is named by
//! its file offset.

use std::fmt::{self, Write};

use asc_abc::{Abc, AbcError, Literal};

use crate::Options;
use crate::text::{ELLIPSIS, write_error, write_f32, write_f64, write_i32, write_name, write_quoted};

/// Write the literal array at file offset `off`, at most
/// `opts.literal_limit` items of it. A failure becomes an error marker in
/// place of the item (or of the whole array) it concerns.
pub(crate) fn write_literal_array<W: Write>(out: &mut W, abc: &Abc<'_>, off: u32, opts: &Options) -> fmt::Result {
    let array = match abc.literal_array(off) {
        Ok(array) => array,
        Err(error) => return write_error(out, format_args!("literal array @{off:#x}: {error}")),
    };
    if array.is_empty() {
        return out.write_str("[]");
    }
    out.write_char('[')?;
    for (shown, item) in array.iter().enumerate() {
        out.write_str(if shown == 0 { " " } else { ", " })?;
        if shown == opts.literal_limit {
            // `len` is what the header declares; a typed array further on would make it an overestimate.
            let rest = (array.len() as usize).saturating_sub(shown);
            write!(out, "{ELLIPSIS} (+{rest} more)")?;
            break;
        }
        match item {
            Ok(literal) => write_literal(out, abc, &literal, opts)?,
            Err(error) => write_error(out, error)?,
        }
    }
    out.write_str(" ]")
}

fn write_literal<W: Write>(out: &mut W, abc: &Abc<'_>, literal: &Literal, opts: &Options) -> fmt::Result {
    match *literal {
        Literal::Bool(value) => write!(out, "{value}"),
        Literal::Integer(value) => write_i32(out, value),
        Literal::Float(value) => write_f32(out, value),
        Literal::Double(value) => write_f64(out, value),
        Literal::String(off) => write_string(out, abc, off, opts),
        Literal::Null(_) => out.write_str("null"),
        Literal::Method(off) => write_method(out, abc, "method", off),
        Literal::GeneratorMethod(off) => write_method(out, abc, "generator_method", off),
        Literal::AsyncGeneratorMethod(off) => write_method(out, abc, "async_generator_method", off),
        Literal::Getter(off) => write_method(out, abc, "getter", off),
        Literal::Setter(off) => write_method(out, abc, "setter", off),
        Literal::MethodAffiliate(params) => write!(out, "method_affiliate:{params}"),
        Literal::Accessor(value) => write!(out, "accessor:{value}"),
        Literal::LiteralBufferIndex(index) => write!(out, "lit_index:{index}"),
        Literal::LiteralArray(off) => write!(out, "literal_array:@{off:#x}"),
        Literal::BuiltinTypeIndex(index) => write!(out, "builtin_type:{index}"),
        Literal::EtsImplements(off) => {
            out.write_str("ets_implements:")?;
            write_string(out, abc, off, opts)
        }
        Literal::TagValue(value) => write!(out, "tag_value:{value}"),
        Literal::TypedArray { tag, data_off } => write!(out, "typed_array:{tag:#x}@{data_off:#x}"),
        // A tag newer than this writer.
        _ => write!(out, "{literal:?}"),
    }
}

fn write_string<W: Write>(out: &mut W, abc: &Abc<'_>, off: u32, opts: &Options) -> fmt::Result {
    match abc.string(off) {
        Ok(string) => write_quoted(out, &string.to_str(), opts.string_limit),
        Err(error) => write_error(out, error),
    }
}

fn write_method<W: Write>(out: &mut W, abc: &Abc<'_>, tag: &str, off: u32) -> fmt::Result {
    write!(out, "{tag}:")?;
    match method_name(abc, off) {
        Ok(name) => write_name(out, &name),
        Err(error) => write_error(out, error),
    }
}

/// The raw name of the method at file offset `off`.
pub(crate) fn method_name<'a>(abc: &Abc<'a>, off: u32) -> Result<std::borrow::Cow<'a, str>, AbcError> {
    Ok(abc.method(off)?.name()?.to_str())
}
