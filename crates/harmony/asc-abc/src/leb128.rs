//! LEB128 as libpandafile reads it: values are 32 bits wide, an encoding is
//! at most five bytes long, and a fifth byte that still has its continuation
//! bit set (or, for unsigned values, carries more than four payload bits) is
//! rejected (`DecodeUnsigned<uint32_t>` reports it as not "full" and the
//! runtime refuses the file).

use crate::{AbcError, Result};

/// Longest valid encoding of a 32-bit value.
pub const MAX_LEN: usize = 5;

/// Read an unsigned LEB128 value at `pos`. Returns `(value, byte_length)`.
///
/// # Errors
/// `Truncated` when the buffer ends inside the encoding, `Malformed` when the
/// value does not fit in 32 bits.
#[inline]
pub fn read_uleb128(buf: &[u8], pos: usize) -> Result<(u32, usize)> {
    let mut result = 0u32;
    for i in 0..MAX_LEN {
        let b = *pos.checked_add(i).and_then(|p| buf.get(p)).ok_or(AbcError::Truncated { what: "uleb128", offset: pos })?;
        if i == MAX_LEN - 1 && b > 0x0f {
            break;
        }
        result |= u32::from(b & 0x7f) << (7 * i);
        if b < 0x80 {
            return Ok((result, i + 1));
        }
    }
    Err(AbcError::Malformed { what: "uleb128", offset: pos, reason: "value does not fit in 32 bits" })
}

/// Read a signed LEB128 value at `pos`. Returns `(value, byte_length)`.
///
/// # Errors
/// `Truncated` when the buffer ends inside the encoding, `Malformed` when the
/// fifth byte does not terminate it.
#[inline]
pub fn read_sleb128(buf: &[u8], pos: usize) -> Result<(i32, usize)> {
    let mut result = 0i64;
    for i in 0..MAX_LEN {
        let b = *pos.checked_add(i).and_then(|p| buf.get(p)).ok_or(AbcError::Truncated { what: "sleb128", offset: pos })?;
        let shift = 7 * i;
        result |= i64::from(b & 0x7f) << shift;
        if b < 0x80 {
            if b & 0x40 != 0 {
                result |= -1i64 << (shift + 7);
            }
            // Bits above 32 are sign extension only; dropping them is the intent.
            return Ok((result as i32, i + 1));
        }
    }
    Err(AbcError::Malformed { what: "sleb128", offset: pos, reason: "value does not fit in 32 bits" })
}

/// Append the unsigned LEB128 encoding of `value` to `out`.
pub fn write_uleb128(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Append the signed LEB128 encoding of `value` to `out`.
pub fn write_sleb128(out: &mut Vec<u8>, mut value: i32) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0) {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_uleb() {
        for v in [0u32, 1, 127, 128, 300, 16383, 16384, 0x7fff_ffff, u32::MAX] {
            let mut out = Vec::new();
            write_uleb128(&mut out, v);
            assert!(out.len() <= MAX_LEN);
            assert_eq!(read_uleb128(&out, 0).unwrap(), (v, out.len()));
        }
    }

    #[test]
    fn roundtrip_sleb() {
        for v in [0i32, 1, -1, 63, 64, -64, -65, 127, -128, i32::MAX, i32::MIN] {
            let mut out = Vec::new();
            write_sleb128(&mut out, v);
            assert!(out.len() <= MAX_LEN);
            assert_eq!(read_sleb128(&out, 0).unwrap(), (v, out.len()));
        }
    }

    #[test]
    fn rejects_truncated_and_oversized() {
        assert_eq!(read_uleb128(&[], 0), Err(AbcError::Truncated { what: "uleb128", offset: 0 }));
        assert_eq!(read_uleb128(&[0x80, 0x80], 0), Err(AbcError::Truncated { what: "uleb128", offset: 0 }));
        assert!(read_uleb128(&[0x80], usize::MAX).is_err());
        // Six bytes, and a fifth byte with more than four payload bits.
        assert!(matches!(read_uleb128(&[0xff, 0xff, 0xff, 0xff, 0xff, 0x01], 0), Err(AbcError::Malformed { .. })));
        assert!(matches!(read_uleb128(&[0xff, 0xff, 0xff, 0xff, 0x1f], 0), Err(AbcError::Malformed { .. })));
        assert_eq!(read_uleb128(&[0xff, 0xff, 0xff, 0xff, 0x0f], 0).unwrap(), (u32::MAX, 5));
        assert!(matches!(read_sleb128(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x00], 0), Err(AbcError::Malformed { .. })));
        assert_eq!(read_sleb128(&[0x7f], 0).unwrap(), (-1, 1));
    }
}
