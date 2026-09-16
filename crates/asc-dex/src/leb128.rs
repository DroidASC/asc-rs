//! LEB128 helpers tuned for DEX: values fit in 32 bits, so an encoding is at
//! most five bytes long. Like ART's `DecodeUnsignedLeb128`, the readers never
//! consume more than five bytes: the fifth byte always terminates the value,
//! its continuation bit is ignored and only its low four bits contribute
//! (ART "tolerates garbage in the four high-order bits").

use crate::{DexError, Result};

/// Longest valid encoding of a 32-bit value.
pub const MAX_LEN: usize = 5;

/// Read an unsigned LEB128 value. Returns `(value, byte_length)`.
///
/// Errors with `Truncated` when the buffer ends inside the encoding. The
/// fifth byte always ends the value (as in ART), so no more than
/// [`MAX_LEN`] bytes are ever consumed.
#[inline]
pub fn read_uleb128(buf: &[u8], pos: usize) -> Result<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift = 0u32;
    let mut p = pos;
    loop {
        let b = *buf.get(p).ok_or(DexError::Truncated { what: "uleb128", offset: pos })?;
        p += 1;
        // The fifth byte only contributes its low four bits (high bits and
        // its continuation bit are dropped, as ART does).
        result |= ((b & 0x7f) as u32) << shift;
        if b < 0x80 || p - pos >= MAX_LEN {
            return Ok((result, p - pos));
        }
        shift += 7;
    }
}

/// Length in bytes of the unsigned LEB128 value starting at `pos`.
#[inline]
pub fn uleb128_len(buf: &[u8], pos: usize) -> Result<usize> {
    let mut p = pos;
    loop {
        let b = *buf.get(p).ok_or(DexError::Truncated { what: "uleb128", offset: pos })?;
        p += 1;
        if b < 0x80 || p - pos >= MAX_LEN {
            return Ok(p - pos);
        }
    }
}

/// Read a `uleb128p1` value (value + 1 encoded, so `0` means `-1`/none).
#[inline]
pub fn read_uleb128p1(buf: &[u8], pos: usize) -> Result<(Option<u32>, usize)> {
    let (v, n) = read_uleb128(buf, pos)?;
    Ok((if v == 0 { None } else { Some(v - 1) }, n))
}

/// Read a signed LEB128 value. Returns `(value, byte_length)`.
#[inline]
pub fn read_sleb128(buf: &[u8], pos: usize) -> Result<(i32, usize)> {
    let mut result: i64 = 0;
    let mut shift = 0u32;
    let mut p = pos;
    let mut byte;
    loop {
        byte = *buf.get(p).ok_or(DexError::Truncated { what: "sleb128", offset: pos })?;
        p += 1;
        result |= ((byte & 0x7f) as i64) << shift;
        shift += 7;
        // The fifth byte always terminates (ART's DecodeSignedLeb128).
        if byte & 0x80 == 0 || p - pos >= MAX_LEN {
            break;
        }
    }
    if (byte & 0x40) != 0 {
        result |= -1i64 << shift;
    }
    Ok((result as i32, p - pos))
}

/// Append the unsigned LEB128 encoding of `value` to `out`.
#[inline]
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

/// Append the `uleb128p1` encoding of `value` (`None` encodes as 0).
///
/// `Some(u32::MAX)` cannot be represented (it would need `u32::MAX + 1`); it
/// saturates to `u32::MAX`, which reads back as `Some(u32::MAX - 1)`.
#[inline]
pub fn write_uleb128p1(out: &mut Vec<u8>, value: Option<u32>) {
    write_uleb128(out, value.map_or(0, |v| v.saturating_add(1)));
}

/// Append the signed LEB128 encoding of `value` to `out`.
#[inline]
pub fn write_sleb128(out: &mut Vec<u8>, mut value: i32) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
        if done {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

/// Number of bytes `write_uleb128` would emit.
#[inline]
pub fn uleb128_size(mut value: u32) -> usize {
    let mut n = 1;
    while value >= 0x80 {
        value >>= 7;
        n += 1;
    }
    n
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
            assert_eq!(out.len(), uleb128_size(v));
            assert_eq!(read_uleb128(&out, 0).unwrap(), (v, out.len()));
            assert_eq!(uleb128_len(&out, 0).unwrap(), out.len());
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
    fn roundtrip_uleb128p1() {
        for v in [None, Some(0), Some(1), Some(127), Some(u32::MAX - 1)] {
            let mut out = Vec::new();
            write_uleb128p1(&mut out, v);
            assert_eq!(read_uleb128p1(&out, 0).unwrap(), (v, out.len()));
        }
        let mut out = Vec::new();
        write_uleb128p1(&mut out, Some(u32::MAX));
        assert_eq!(read_uleb128p1(&out, 0).unwrap().0, Some(u32::MAX - 1));
    }

    #[test]
    fn truncated_and_over_length() {
        // Continuation bit set on the last available byte.
        assert_eq!(read_uleb128(&[0x80], 0), Err(DexError::Truncated { what: "uleb128", offset: 0 }));
        assert_eq!(read_uleb128(&[], 0), Err(DexError::Truncated { what: "uleb128", offset: 0 }));
        assert_eq!(read_uleb128(&[0x01, 0x80, 0x80], 1), Err(DexError::Truncated { what: "uleb128", offset: 1 }));
        assert_eq!(uleb128_len(&[0x80, 0x80], 0), Err(DexError::Truncated { what: "uleb128", offset: 0 }));
        assert_eq!(read_sleb128(&[0x80], 0), Err(DexError::Truncated { what: "sleb128", offset: 0 }));
        // Five bytes is the limit: the fifth byte terminates even with its
        // continuation bit set, and the sixth byte is never read (ART).
        let six = [0x80, 0x80, 0x80, 0x80, 0x80, 0x00];
        assert_eq!(read_uleb128(&six, 0).unwrap(), (0, 5));
        assert_eq!(uleb128_len(&six, 0).unwrap(), 5);
        assert_eq!(read_sleb128(&six, 0).unwrap(), (0, 5));
        assert_eq!(read_uleb128(&[0x80, 0x80, 0x80, 0x80, 0x81, 0x00], 0).unwrap(), (1 << 28, 5));
        assert_eq!(read_uleb128(&[0x80, 0x80, 0x80, 0x80, 0x80], 0).unwrap(), (0, 5));
        // sign extension of a five-byte sleb128 comes from bit 6 of the fifth byte
        assert_eq!(read_sleb128(&[0x80, 0x80, 0x80, 0x80, 0xc0], 0).unwrap(), (0, 5));
        assert_eq!(read_sleb128(&[0xff, 0xff, 0xff, 0xff, 0xff], 0).unwrap(), (-1, 5));
        // Exactly five bytes still decodes.
        assert_eq!(read_uleb128(&[0x80, 0x80, 0x80, 0x80, 0x01], 0).unwrap(), (1 << 28, 5));
        assert_eq!(read_uleb128(&[0xff, 0xff, 0xff, 0xff, 0x0f], 0).unwrap(), (u32::MAX, 5));
        // Garbage in the high bits of the fifth byte is dropped, as in ART.
        assert_eq!(read_uleb128(&[0xff, 0xff, 0xff, 0xff, 0x7f], 0).unwrap(), (u32::MAX, 5));
    }
}
