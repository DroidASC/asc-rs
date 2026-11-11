//! `method_handle_item` and `call_site_id_item` / call site parsing.
//!
//! Both tables are only reachable through the map list (the header has no
//! fields for them); [`crate::Dex::method_handle`] and
//! [`crate::Dex::call_site`] look them up there.

use crate::encoded::{self, EncodedValue};
use crate::{DexError, Result, u16_at};
use std::fmt;

/// `method_handle_type` of a `method_handle_item`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MethodHandleKind {
    /// `0x00`: static field setter.
    StaticPut,
    /// `0x01`: static field getter.
    StaticGet,
    /// `0x02`: instance field setter.
    InstancePut,
    /// `0x03`: instance field getter.
    InstanceGet,
    /// `0x04`: static method invoker.
    InvokeStatic,
    /// `0x05`: instance method invoker.
    InvokeInstance,
    /// `0x06`: constructor invoker.
    InvokeConstructor,
    /// `0x07`: direct method invoker.
    InvokeDirect,
    /// `0x08`: interface method invoker.
    InvokeInterface,
}

impl MethodHandleKind {
    /// Whether `field_or_method_id` is a field index (the four accessor
    /// kinds) rather than a method index.
    pub fn is_field_accessor(self) -> bool {
        match self {
            Self::StaticPut | Self::StaticGet | Self::InstancePut | Self::InstanceGet => true,
            Self::InvokeStatic | Self::InvokeInstance | Self::InvokeConstructor | Self::InvokeDirect | Self::InvokeInterface => false,
        }
    }

    /// The name smali uses for the kind (`invoke-static`, `instance-get`, ...).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaticPut => "static-put",
            Self::StaticGet => "static-get",
            Self::InstancePut => "instance-put",
            Self::InstanceGet => "instance-get",
            Self::InvokeStatic => "invoke-static",
            Self::InvokeInstance => "invoke-instance",
            Self::InvokeConstructor => "invoke-constructor",
            Self::InvokeDirect => "invoke-direct",
            Self::InvokeInterface => "invoke-interface",
        }
    }
}

impl TryFrom<u16> for MethodHandleKind {
    /// The unknown type code.
    type Error = u16;

    fn try_from(code: u16) -> std::result::Result<Self, u16> {
        Ok(match code {
            0x00 => Self::StaticPut,
            0x01 => Self::StaticGet,
            0x02 => Self::InstancePut,
            0x03 => Self::InstanceGet,
            0x04 => Self::InvokeStatic,
            0x05 => Self::InvokeInstance,
            0x06 => Self::InvokeConstructor,
            0x07 => Self::InvokeDirect,
            0x08 => Self::InvokeInterface,
            _ => return Err(code),
        })
    }
}

impl fmt::Display for MethodHandleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// `method_handle_item`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MethodHandle {
    /// `method_handle_type`.
    pub kind: MethodHandleKind,
    /// Field index when [`MethodHandleKind::is_field_accessor`], method
    /// index otherwise.
    pub field_or_method_idx: u16,
}

impl MethodHandle {
    /// Size of a `method_handle_item` in bytes (two `u16` fields, each
    /// followed by an unused `u16`).
    pub const SIZE: usize = 8;

    /// Parse the `method_handle_item` at `off`.
    ///
    /// # Errors
    ///
    /// `Truncated` when the item is out of `buf`, `Malformed` for an unknown
    /// `method_handle_type`.
    pub fn parse(buf: &[u8], off: usize) -> Result<MethodHandle> {
        let code = u16_at(buf, off)?;
        let kind = MethodHandleKind::try_from(code).map_err(|_| DexError::Malformed {
            what: "method_handle_item",
            offset: off,
            reason: "unknown method_handle_type",
        })?;
        Ok(MethodHandle { kind, field_or_method_idx: u16_at(buf, off.saturating_add(4))? })
    }
}

/// A call site: the `encoded_array_item` a `call_site_id_item` points to,
/// with its three mandatory leading elements decoded.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct CallSite {
    /// Method handle index of the bootstrap linker method.
    pub bootstrap: u32,
    /// String index of the method name to link.
    pub method_name: u32,
    /// Proto index of the method type to link.
    pub method_type: u32,
    /// Remaining static arguments passed to the bootstrap method.
    pub extra_args: Vec<EncodedValue>,
}

impl CallSite {
    /// Decode the `encoded_array_item` at `off` as a call site.
    ///
    /// # Errors
    ///
    /// Any error of [`encoded::parse_array`] (truncation, nesting deeper
    /// than [`encoded::MAX_NESTING`]), and `Malformed` when the array has
    /// fewer than three elements or they are not a method handle, a string
    /// and a method type, in that order.
    pub fn parse(buf: &[u8], off: usize) -> Result<CallSite> {
        let malformed = |reason| DexError::Malformed { what: "call_site_item", offset: off, reason };
        let (values, _) = encoded::parse_array(buf, off)?;
        let mut values = values.into_iter();
        let (Some(bootstrap), Some(name), Some(ty)) = (values.next(), values.next(), values.next()) else {
            return Err(malformed("fewer than three elements"));
        };
        let EncodedValue::MethodHandle(bootstrap) = bootstrap else {
            return Err(malformed("bootstrap is not a method handle"));
        };
        let EncodedValue::String(method_name) = name else {
            return Err(malformed("method name is not a string"));
        };
        let EncodedValue::MethodType(method_type) = ty else {
            return Err(malformed("method type is not a method type"));
        };
        Ok(CallSite { bootstrap, method_name, method_type, extra_args: values.collect() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoded::{Identity, VALUE_ARRAY, write_array};

    #[test]
    fn method_handle_kinds_roundtrip_their_codes() {
        let kinds: Vec<MethodHandleKind> = (0..9u16).map(|c| MethodHandleKind::try_from(c).unwrap()).collect();
        assert_eq!(kinds.iter().filter(|k| k.is_field_accessor()).count(), 4);
        assert_eq!(kinds[0].to_string(), "static-put");
        assert_eq!(kinds[3].as_str(), "instance-get");
        assert_eq!(kinds[4].as_str(), "invoke-static");
        assert_eq!(kinds[8].as_str(), "invoke-interface");
        assert_eq!(MethodHandleKind::try_from(9), Err(9));
        assert_eq!(MethodHandleKind::try_from(0xffff), Err(0xffff));

        for (code, kind) in kinds.iter().enumerate() {
            let mut buf = vec![0xaa; 2];
            buf.extend_from_slice(&(code as u16).to_le_bytes());
            buf.extend_from_slice(&[0, 0, 0x34, 0x12, 0, 0]);
            assert_eq!(MethodHandle::parse(&buf, 2), Ok(MethodHandle { kind: *kind, field_or_method_idx: 0x1234 }));
        }
    }

    #[test]
    fn malformed_method_handles_are_errors() {
        let buf = [0x09, 0, 0, 0, 1, 0, 0, 0];
        assert!(matches!(MethodHandle::parse(&buf, 0), Err(DexError::Malformed { what: "method_handle_item", .. })));
        let buf = [0x04, 0, 0, 0, 1, 0, 0, 0];
        assert!(matches!(MethodHandle::parse(&buf[..5], 0), Err(DexError::Truncated { .. })));
        assert!(MethodHandle::parse(&buf, usize::MAX).is_err());
        assert!(MethodHandle::parse(&buf, usize::MAX - 2).is_err());
    }

    fn array(values: &[EncodedValue]) -> Vec<u8> {
        let mut out = vec![0xee];
        write_array(&mut out, values, &Identity);
        out
    }

    #[test]
    fn decodes_call_sites() {
        let extra = vec![EncodedValue::MethodType(3), EncodedValue::MethodHandle(0), EncodedValue::Primitive { kind: 0x04, raw: vec![7] }];
        let mut values = vec![EncodedValue::MethodHandle(1), EncodedValue::String(300), EncodedValue::MethodType(2)];
        values.extend(extra.iter().cloned());
        let site = CallSite::parse(&array(&values), 1).unwrap();
        assert_eq!(site, CallSite { bootstrap: 1, method_name: 300, method_type: 2, extra_args: extra });

        let bare = CallSite::parse(&array(&values[..3]), 1).unwrap();
        assert!(bare.extra_args.is_empty());
    }

    #[test]
    fn rejects_malformed_call_sites() {
        let reason = |values: &[EncodedValue]| match CallSite::parse(&array(values), 1) {
            Err(DexError::Malformed { what: "call_site_item", offset: 1, reason }) => reason,
            other => panic!("{other:?}"),
        };
        let (mh, s, mt) = (EncodedValue::MethodHandle(0), EncodedValue::String(0), EncodedValue::MethodType(0));
        assert_eq!(reason(&[]), "fewer than three elements");
        assert_eq!(reason(&[mh.clone(), s.clone()]), "fewer than three elements");
        assert_eq!(reason(&[EncodedValue::Method(0), s.clone(), mt.clone()]), "bootstrap is not a method handle");
        assert_eq!(reason(&[mh.clone(), EncodedValue::Type(0), mt.clone()]), "method name is not a string");
        assert_eq!(reason(&[mh.clone(), s.clone(), EncodedValue::Null]), "method type is not a method type");

        // Truncated array: claims 0xffffffff elements but holds three.
        let mut buf = array(&[mh, s, mt]);
        buf.splice(1..2, [0xff, 0xff, 0xff, 0xff, 0x0f]);
        assert!(matches!(CallSite::parse(&buf, 1), Err(DexError::Truncated { .. })));
        assert!(matches!(CallSite::parse(&buf, buf.len()), Err(DexError::Truncated { .. })));
        assert!(CallSite::parse(&buf, usize::MAX).is_err());

        // A deeply nested extra argument hits the decoder's nesting limit.
        let mut buf = array(&[EncodedValue::MethodHandle(0), EncodedValue::String(0), EncodedValue::MethodType(0)]);
        buf[1] = 4;
        for _ in 0..10_000 {
            buf.extend_from_slice(&[VALUE_ARRAY, 1]);
        }
        buf.push(0x1e);
        assert!(matches!(CallSite::parse(&buf, 1), Err(DexError::Malformed { reason: "nesting too deep", .. })));
    }
}
