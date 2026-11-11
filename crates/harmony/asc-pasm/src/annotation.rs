//! The annotations a program declares (`@interface`, bytecode of API 20 and
//! later): what a function carries, and the values an annotation interface
//! gives its fields by default.
//!
//! ```text
//! .function #~@0<#make  ; Tagged.make
//! ; vregs 2, args 3 (a0 func, a1 new.target, a2 this, 0 params), code 14 bytes, line 27
//! ; @&entry/src/main/ets/Marks&.Marked(level=-0.5, tags=[ "only" ])
//! ```
//!
//! The annotation of a class stands on its constructor. The compiler's own
//! annotations (`_ESSlotNumberAnnotation` …) are bookkeeping and left out.

use std::fmt::{self, Write};

use asc_abc::{Abc, AnnotationElement, ElementValue, Literal, Method, MethodTag, RecordName};

use crate::Options;
use crate::text::{ELLIPSIS, write_error, write_f64, write_imm, write_name, write_quoted};

/// Arrays inside arrays deeper than this are not followed: a literal array
/// may name itself.
const MAX_ARRAY_DEPTH: usize = 4;

/// The array an annotation value is: `[ "a", "b" ]`, at most
/// `opts.literal_limit` items of it, arrays inside it in place.
pub(crate) fn write_array<W: Write>(out: &mut W, abc: &Abc<'_>, off: u32, opts: &Options<'_>, depth: usize) -> fmt::Result {
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
            write!(out, "{ELLIPSIS} (+{} more)", (array.len() as usize).saturating_sub(shown))?;
            break;
        }
        match item {
            Ok(Literal::Bool(value)) => write!(out, "{value}")?,
            Ok(Literal::Double(value)) => write_f64(out, value)?,
            Ok(Literal::String(off)) => write_string(out, abc, off, opts)?,
            Ok(Literal::LiteralArray(off)) if depth < MAX_ARRAY_DEPTH => write_array(out, abc, off, opts, depth + 1)?,
            Ok(Literal::LiteralArray(off)) => write!(out, "literal_array:@{off:#x}")?,
            Ok(other) => write_error(out, format_args!("not a value of an annotation: {other:?}"))?,
            Err(error) => write_error(out, error)?,
        }
    }
    out.write_str(" ]")
}

pub(crate) fn write_string<W: Write>(out: &mut W, abc: &Abc<'_>, off: u32, opts: &Options<'_>) -> fmt::Result {
    match abc.string(off) {
        Ok(string) => write_quoted(out, &string.to_str(), opts.string_limit),
        Err(error) => write_error(out, error),
    }
}

/// `name=value` of one element.
fn write_element<W: Write>(out: &mut W, abc: &Abc<'_>, element: &AnnotationElement, opts: &Options<'_>) -> fmt::Result {
    match abc.string(element.name_off) {
        Ok(name) => write_name(out, &name.to_str())?,
        Err(error) => write_error(out, format_args!("name: {error}"))?,
    }
    out.write_char('=')?;
    match element.typed(abc) {
        Ok(ElementValue::Bool(value)) => write!(out, "{value}"),
        Ok(ElementValue::Int(value)) => write_imm(out, i64::from(value)),
        Ok(ElementValue::F64(value)) => write_f64(out, value),
        Ok(ElementValue::String(off)) => write_string(out, abc, off, opts),
        Ok(ElementValue::Array(off)) => write_array(out, abc, off, opts, 0),
        Ok(ElementValue::Other(value)) => write!(out, "{value:#x} (type tag {:?})", char::from(element.tag)),
        Err(error) => write_error(out, error),
    }
}

/// One line per annotation of `method` that the program declares:
/// `; @RECORD(name=value, …)`, `RECORD` the annotation interface, a record
/// of its own. Nothing for a function without one.
pub(crate) fn write_annotations<W: Write>(out: &mut W, abc: &Abc<'_>, method: &Method<'_>, opts: &Options<'_>) -> fmt::Result {
    // A tag list that does not read is reported where the code would stand.
    for tag in method.tags().map_while(Result::ok) {
        let (MethodTag::Annotation(off) | MethodTag::RuntimeAnnotation(off)) = tag else { continue };
        let annotation = match abc.annotation(off) {
            Ok(annotation) => annotation,
            Err(error) => {
                out.write_str("; ")?;
                write_error(out, format_args!("annotation @{off:#x}: {error}"))?;
                out.write_char('\n')?;
                continue;
            }
        };
        let descriptor = annotation.class_off(abc).and_then(|class| abc.string(class));
        let name = match &descriptor {
            Ok(descriptor) => descriptor.to_str(),
            Err(error) => {
                out.write_str("; ")?;
                write_error(out, format_args!("annotation @{off:#x}: {error}"))?;
                out.write_char('\n')?;
                continue;
            }
        };
        let name = name.strip_prefix('L').and_then(|name| name.strip_suffix(';')).unwrap_or(&name);
        if RecordName::parse(name).is_pseudo() {
            continue;
        }
        out.write_str("; @")?;
        write_name(out, name)?;
        if !annotation.is_empty() {
            out.write_char('(')?;
            for (shown, element) in annotation.elements().enumerate() {
                if shown > 0 {
                    out.write_str(", ")?;
                }
                if shown == opts.literal_limit {
                    write!(out, "{ELLIPSIS} (+{} more)", annotation.len() - shown)?;
                    break;
                }
                write_element(out, abc, &element, opts)?;
            }
            out.write_char(')')?;
        }
        out.write_char('\n')?;
    }
    Ok(())
}
