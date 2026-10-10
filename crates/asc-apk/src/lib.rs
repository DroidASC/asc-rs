//! Read-only APK (zip) access.
//!
//! The archive is memory-mapped and only its central directory is walked.
//! Entries are extracted on demand: stored entries are borrowed straight from
//! the mapping, Deflate entries are inflated (optionally with a cancellation
//! flag; the streaming decoder polls it on every input read, the libdeflate
//! path once per entry, so a parallel class search can abandon the remaining
//! DEX files as soon as one worker hits).

use memmap2::Mmap;
use std::borrow::Cow;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

const CD_SIG: &[u8; 4] = b"PK\x01\x02";
const LH_SIG: &[u8; 4] = b"PK\x03\x04";
const EOCD_SIG: &[u8; 4] = b"PK\x05\x06";
const ZIP64_EOCD_SIG: &[u8; 4] = b"PK\x06\x06";
const ZIP64_LOCATOR_SIG: &[u8; 4] = b"PK\x06\x07";
const DEFLATE_CHUNK: usize = 1 << 19;
/// Deflate cannot expand data by more than about 1032:1; a central directory
/// claiming more is corrupt or hostile and must not drive an allocation.
const MAX_DEFLATE_RATIO: u64 = 1032;
/// A declared size is reserved up front only up to the larger of this and
/// [`TYPICAL_RATIO`] times the compressed payload; anything bigger grows on
/// demand, so a lying central directory cannot force a large allocation
/// while real DEX entries still get a single exact one.
const INITIAL_CAPACITY: usize = 64 << 20;
/// Real DEX files inflate well under this ratio.
const TYPICAL_RATIO: usize = 16;

pub const METHOD_STORED: u16 = 0;
pub const METHOD_DEFLATE: u16 = 8;

#[derive(Debug, thiserror::Error)]
pub enum ApkError {
    #[error("io error on {path}: {source}")]
    Io { path: PathBuf, source: std::io::Error },
    #[error("end of central directory not found")]
    NoEocd,
    #[error("central directory out of range")]
    BadCentralDirectory,
    #[error("bad local header signature for entry {0}")]
    BadLocalHeader(String),
    #[error("unsupported compression method {0}")]
    UnsupportedMethod(u16),
    #[error("inflate failed for entry {name}: {source}")]
    Inflate { name: String, source: std::io::Error },
    #[error("size mismatch for entry {name}: expected {expected}, got {actual}")]
    SizeMismatch { name: String, expected: usize, actual: usize },
    #[error("entry {0} not found")]
    NotFound(String),
    #[error("entry {name} declares an implausible size (compressed {comp_size}, uncompressed {uncomp_size})")]
    ImplausibleSize { name: String, comp_size: u64, uncomp_size: u64 },
    #[error("cancelled")]
    Cancelled,
}

pub type Result<T> = std::result::Result<T, ApkError>;

/// One central-directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub method: u16,
    pub comp_size: u64,
    pub uncomp_size: u64,
    pub local_header_off: u64,
}

impl Entry {
    /// Whether this is a root-level `*.dex` (`classes.dex`, `classes2.dex`, ...).
    pub fn is_root_dex(&self) -> bool {
        self.name.ends_with(".dex") && !self.name.contains('/')
    }
}

/// A memory-mapped APK.
pub struct Apk {
    path: PathBuf,
    map: Mmap,
}

/// `n` bytes at `o`, or `None` if they are not all inside `b` (offsets come
/// from the archive, so the addition itself must not be trusted either).
#[inline]
fn bytes_at(b: &[u8], o: usize, n: usize) -> Option<&[u8]> {
    b.get(o..o.checked_add(n)?)
}
#[inline]
fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    bytes_at(b, o, 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
#[inline]
fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    bytes_at(b, o, 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
#[inline]
fn u64_at(b: &[u8], o: usize) -> Option<u64> {
    bytes_at(b, o, 8).map(|s| u64::from_le_bytes(s.try_into().expect("8 bytes")))
}
/// A `u64` archive offset as `usize`, or `None` when it cannot even be
/// represented (32-bit hosts).
#[inline]
fn offset(v: u64) -> Option<usize> {
    usize::try_from(v).ok()
}

impl Apk {
    /// Map `path` read-only.
    pub fn open(path: impl AsRef<Path>) -> Result<Apk> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path).map_err(|source| ApkError::Io { path: path.clone(), source })?;
        // SAFETY: the mapping is read-only and the file is not expected to be
        // modified while it is mapped (same contract as the Python mmap use).
        let map = unsafe { Mmap::map(&file) }.map_err(|source| ApkError::Io { path: path.clone(), source })?;
        Ok(Apk { path, map })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The raw archive bytes.
    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.map
    }

    /// Locate the central directory as `(offset, size)`, honouring zip64.
    fn central_directory(&self) -> Result<(usize, usize)> {
        let data = self.data();
        let search_start = data.len().saturating_sub(65536 + 22);
        let eocd = memchr::memmem::rfind(&data[search_start..], EOCD_SIG).map(|p| p + search_start).ok_or(ApkError::NoEocd)?;
        let mut cd_size = u32_at(data, eocd + 12).ok_or(ApkError::NoEocd)? as u64;
        let mut cd_off = u32_at(data, eocd + 16).ok_or(ApkError::NoEocd)? as u64;
        if cd_size == 0xFFFF_FFFF || cd_off == 0xFFFF_FFFF {
            // zip64: locator sits right before the EOCD.
            if eocd >= 20 && &data[eocd - 20..eocd - 16] == ZIP64_LOCATOR_SIG {
                let rec = u64_at(data, eocd - 20 + 8).and_then(offset).ok_or(ApkError::NoEocd)?;
                if bytes_at(data, rec, 4) == Some(ZIP64_EOCD_SIG) {
                    cd_size = rec.checked_add(40).and_then(|o| u64_at(data, o)).ok_or(ApkError::NoEocd)?;
                    cd_off = rec.checked_add(48).and_then(|o| u64_at(data, o)).ok_or(ApkError::NoEocd)?;
                }
            }
        }
        let (Some(off), Some(size)) = (offset(cd_off), offset(cd_size)) else {
            return Err(ApkError::BadCentralDirectory);
        };
        if off.checked_add(size).map(|e| e > data.len()).unwrap_or(true) {
            return Err(ApkError::BadCentralDirectory);
        }
        Ok((off, size))
    }

    /// Walk the central directory. `keep` filters entries by name early so
    /// the full name list is never materialised for large archives.
    pub fn entries_filtered(&self, mut keep: impl FnMut(&[u8]) -> bool) -> Result<Vec<Entry>> {
        let data = self.data();
        let (cd_off, cd_size) = self.central_directory()?;
        let cd_end = cd_off + cd_size;
        let mut entries = Vec::new();
        let mut p = cd_off;
        while p + 46 <= cd_end {
            if &data[p..p + 4] != CD_SIG {
                break;
            }
            let name_len = u16_at(data, p + 28).unwrap_or(0) as usize;
            let extra_len = u16_at(data, p + 30).unwrap_or(0) as usize;
            let comment_len = u16_at(data, p + 32).unwrap_or(0) as usize;
            let name_start = p + 46;
            let name_end = name_start + name_len;
            if name_end > cd_end {
                break;
            }
            let name = &data[name_start..name_end];
            if keep(name) {
                let mut comp_size = u32_at(data, p + 20).unwrap_or(0) as u64;
                let mut uncomp_size = u32_at(data, p + 24).unwrap_or(0) as u64;
                let mut local_header_off = u32_at(data, p + 42).unwrap_or(0) as u64;
                if comp_size == 0xFFFF_FFFF || uncomp_size == 0xFFFF_FFFF || local_header_off == 0xFFFF_FFFF {
                    // zip64 extra field (id 0x0001).
                    let mut q = name_end;
                    let extra_end = name_end + extra_len;
                    while q + 4 <= extra_end {
                        let id = u16_at(data, q).unwrap_or(0);
                        let len = u16_at(data, q + 2).unwrap_or(0) as usize;
                        if id == 0x0001 {
                            let mut r = q + 4;
                            if uncomp_size == 0xFFFF_FFFF {
                                uncomp_size = u64_at(data, r).unwrap_or(0);
                                r += 8;
                            }
                            if comp_size == 0xFFFF_FFFF {
                                comp_size = u64_at(data, r).unwrap_or(0);
                                r += 8;
                            }
                            if local_header_off == 0xFFFF_FFFF {
                                local_header_off = u64_at(data, r).unwrap_or(0);
                            }
                            break;
                        }
                        q += 4 + len;
                    }
                }
                entries.push(Entry {
                    name: String::from_utf8_lossy(name).into_owned(),
                    method: u16_at(data, p + 10).unwrap_or(0),
                    comp_size,
                    uncomp_size,
                    local_header_off,
                });
            }
            p = name_end + extra_len + comment_len;
        }
        Ok(entries)
    }

    /// Every entry of the archive.
    pub fn entries(&self) -> Result<Vec<Entry>> {
        self.entries_filtered(|_| true)
    }

    /// Root-level DEX entries sorted by compressed size (smallest first, so a
    /// parallel scan finishes the cheap ones early). Duplicate names keep the
    /// last occurrence, like [`Apk::find_entry`] (and `zipfile`).
    pub fn dex_entries(&self) -> Result<Vec<Entry>> {
        let mut entries = self.dex_entries_in_order()?;
        entries.sort_by_key(|e| e.comp_size);
        Ok(entries)
    }

    /// The entries of [`Apk::dex_entries`] in central-directory order.
    pub fn dex_entries_in_order(&self) -> Result<Vec<Entry>> {
        let mut entries = self.entries_filtered(|n| n.ends_with(b".dex") && !n.contains(&b'/'))?;
        // Last occurrence wins: walk from the back keeping first-seen names.
        entries.reverse();
        let mut seen = std::collections::HashSet::with_capacity(entries.len());
        entries.retain(|e| seen.insert(e.name.clone()));
        entries.reverse();
        Ok(entries)
    }

    /// Find an entry by exact name.
    pub fn find_entry(&self, name: &str) -> Result<Option<Entry>> {
        let mut found = self.entries_filtered(|n| n == name.as_bytes())?;
        Ok(found.pop())
    }

    /// Compressed payload of `entry` inside the mapping.
    pub fn raw_payload(&self, entry: &Entry) -> Result<&[u8]> {
        let data = self.data();
        let bad = || ApkError::BadLocalHeader(entry.name.clone());
        let lh = offset(entry.local_header_off).ok_or_else(bad)?;
        if bytes_at(data, lh, 4) != Some(LH_SIG) {
            return Err(bad());
        }
        // The signature check bounds `lh`, so these small additions cannot overflow.
        let name_len = u16_at(data, lh + 26).ok_or_else(bad)? as usize;
        let extra_len = u16_at(data, lh + 28).ok_or_else(bad)? as usize;
        let start = lh + 30 + name_len + extra_len;
        let end = offset(entry.comp_size).and_then(|n| start.checked_add(n));
        end.and_then(|end| data.get(start..end)).ok_or_else(bad)
    }

    /// The raw bytes of the central directory (used as a cache key).
    pub fn central_directory_bytes(&self) -> Result<&[u8]> {
        let (off, size) = self.central_directory()?;
        Ok(&self.data()[off..off + size])
    }

    /// Extract `entry`: stored entries are borrowed straight from the mapping,
    /// Deflate entries are inflated into a fresh buffer.
    pub fn read_entry(&self, entry: &Entry) -> Result<Cow<'_, [u8]>> {
        self.read_entry_cancellable(entry, None)
    }

    /// Extract `entry`, polling `cancel` between input chunks. Returns
    /// `Err(ApkError::Cancelled)` when the flag is raised mid-way.
    pub fn read_entry_cancellable(&self, entry: &Entry, cancel: Option<&AtomicBool>) -> Result<Cow<'_, [u8]>> {
        if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
            return Err(ApkError::Cancelled);
        }
        let payload = self.raw_payload(entry)?;
        let bound = self.check_declared_size(entry)?;
        let out = match entry.method {
            METHOD_STORED => {
                if entry.uncomp_size != 0 && payload.len() as u64 != entry.uncomp_size {
                    return Err(ApkError::SizeMismatch {
                        name: entry.name.clone(),
                        expected: entry.uncomp_size as usize,
                        actual: payload.len(),
                    });
                }
                return Ok(Cow::Borrowed(payload));
            }
            #[cfg(feature = "libdeflate")]
            METHOD_DEFLATE if entry.uncomp_size > 0 => {
                if let Some(c) = cancel {
                    if c.load(Ordering::Relaxed) {
                        return Err(ApkError::Cancelled);
                    }
                }
                let mut out = vec![0u8; entry.uncomp_size as usize];
                let n = libdeflater::Decompressor::new()
                    .deflate_decompress(payload, &mut out)
                    .map_err(|e| ApkError::Inflate { name: entry.name.clone(), source: std::io::Error::other(format!("{e:?}")) })?;
                out.truncate(n);
                out
            }
            METHOD_DEFLATE => {
                let reader = CancelReader { data: payload, pos: 0, cancel };
                let decoder = flate2::read::DeflateDecoder::new(reader);
                let reserve = (entry.uncomp_size as usize).min(INITIAL_CAPACITY.max(payload.len().saturating_mul(TYPICAL_RATIO)));
                let mut out = Vec::with_capacity(reserve);
                // Stop one byte past the bound so an over-long stream is detected
                // instead of inflated without limit (an entry that declares no
                // uncompressed size has no other cap).
                match decoder.take(bound.saturating_add(1)).read_to_end(&mut out) {
                    Ok(_) => {}
                    Err(_) if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) => return Err(ApkError::Cancelled),
                    Err(e) => return Err(ApkError::Inflate { name: entry.name.clone(), source: e }),
                }
                if out.len() as u64 > bound {
                    return Err(self.implausible(entry));
                }
                out
            }
            m => return Err(ApkError::UnsupportedMethod(m)),
        };
        if let Some(c) = cancel {
            if c.load(Ordering::Relaxed) {
                return Err(ApkError::Cancelled);
            }
        }
        if entry.uncomp_size != 0 && out.len() as u64 != entry.uncomp_size {
            return Err(ApkError::SizeMismatch { name: entry.name.clone(), expected: entry.uncomp_size as usize, actual: out.len() });
        }
        Ok(Cow::Owned(out))
    }

    /// Reject Deflate entries whose declared uncompressed size cannot come out
    /// of their compressed payload, before anything is allocated for them.
    /// Returns the most an inflated entry may legitimately grow to; it also
    /// bounds entries that declare no uncompressed size at all.
    fn check_declared_size(&self, entry: &Entry) -> Result<u64> {
        let bound = entry.comp_size.saturating_mul(MAX_DEFLATE_RATIO).saturating_add(1024);
        if entry.method == METHOD_DEFLATE && entry.uncomp_size > bound {
            return Err(self.implausible(entry));
        }
        Ok(bound)
    }

    fn implausible(&self, entry: &Entry) -> ApkError {
        ApkError::ImplausibleSize { name: entry.name.clone(), comp_size: entry.comp_size, uncomp_size: entry.uncomp_size }
    }

    /// Convenience: extract a named entry.
    pub fn read(&self, name: &str) -> Result<Vec<u8>> {
        let entry = self.find_entry(name)?.ok_or_else(|| ApkError::NotFound(name.to_string()))?;
        Ok(self.read_entry(&entry)?.into_owned())
    }
}

/// Decision returned by the callback of [`Apk::inflate_until`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixStep {
    /// Keep inflating; stop once at least this many bytes are available
    /// (`0` = undecided, ask again after the next chunk).
    Continue(usize),
    /// A prefix is not useful for this entry; stop now.
    Abort,
}

/// Outcome of [`Apk::inflate_until`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prefix {
    /// The whole entry (the stream ended before or at the requested length).
    Complete(Vec<u8>),
    /// At least the requested number of leading bytes.
    Partial(Vec<u8>),
    /// The callback aborted; holds whatever was inflated so far.
    Aborted(Vec<u8>),
}

impl Apk {
    /// Inflate a Deflate entry incrementally, letting `decide` inspect the
    /// leading bytes after every chunk to say how much of the entry is
    /// actually needed. Stored entries are returned whole.
    pub fn inflate_until(&self, entry: &Entry, mut decide: impl FnMut(&[u8]) -> PrefixStep) -> Result<Prefix> {
        const CHUNK: usize = 1 << 18;
        if entry.method != METHOD_DEFLATE {
            return Ok(Prefix::Complete(self.read_entry(entry)?.into_owned()));
        }
        let compressed = self.raw_payload(entry)?;
        let bound = self.check_declared_size(entry)?;
        let mut d = flate2::Decompress::new(false);
        let mut out: Vec<u8> = Vec::with_capacity((entry.uncomp_size as usize).min(4 * CHUNK));
        let mut target: Option<usize> = None;
        loop {
            if out.len() as u64 > bound {
                return Err(self.implausible(entry));
            }
            let base = out.len();
            out.resize(base + CHUNK, 0);
            let consumed = d.total_in() as usize;
            let status = d
                .decompress(&compressed[consumed.min(compressed.len())..], &mut out[base..], flate2::FlushDecompress::None)
                .map_err(|e| ApkError::Inflate { name: entry.name.clone(), source: std::io::Error::other(e) })?;
            let written = d.total_out() as usize - base;
            out.truncate(base + written);
            if target.is_none() {
                match decide(&out) {
                    PrefixStep::Continue(0) => {}
                    PrefixStep::Continue(limit) => {
                        // An entry that declares no size cannot cap the request.
                        target = Some(if entry.uncomp_size == 0 { limit } else { limit.min(entry.uncomp_size as usize) })
                    }
                    PrefixStep::Abort => return Ok(Prefix::Aborted(out)),
                }
            }
            if status == flate2::Status::StreamEnd {
                return Ok(Prefix::Complete(out));
            }
            if let Some(limit) = target {
                if out.len() >= limit {
                    return Ok(Prefix::Partial(out));
                }
            }
            if written == 0 && d.total_in() as usize == consumed {
                return Err(ApkError::Inflate { name: entry.name.clone(), source: std::io::Error::other("deflate made no progress") });
            }
        }
    }
}

/// Slice reader that serves bounded chunks and honours a cancellation flag.
struct CancelReader<'a> {
    data: &'a [u8],
    pos: usize,
    cancel: Option<&'a AtomicBool>,
}

impl Read for CancelReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(c) = self.cancel {
            if c.load(Ordering::Relaxed) {
                return Err(std::io::Error::other("cancelled"));
            }
        }
        let remaining = &self.data[self.pos..];
        let n = remaining.len().min(buf.len()).min(DEFLATE_CHUNK);
        buf[..n].copy_from_slice(&remaining[..n]);
        self.pos += n;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(bytes).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn enumerates_and_inflates_dex_entries() {
        let dex = asc_fixture::make_dex();
        for deflate in [false, true] {
            let apk_bytes = asc_fixture::make_apk(
                &[("classes.dex", &dex), ("lib/x/classes.dex", &dex), ("classes2.dex", &dex), ("AndroidManifest.xml", b"xml")],
                deflate,
            );
            let f = write_temp(&apk_bytes);
            let apk = Apk::open(f.path()).unwrap();
            let entries = apk.dex_entries().unwrap();
            let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
            assert_eq!(names.len(), 2);
            assert!(names.contains(&"classes.dex") && names.contains(&"classes2.dex"));
            for e in &entries {
                assert_eq!(apk.read_entry(e).unwrap().as_ref(), dex.as_slice());
            }
            assert_eq!(apk.read("AndroidManifest.xml").unwrap(), b"xml");
            let cancel = AtomicBool::new(true);
            let r = apk.read_entry_cancellable(&entries[0], Some(&cancel));
            assert!(matches!(r, Err(ApkError::Cancelled)));
            if deflate {
                // A lying central directory must not drive a huge allocation.
                let mut lying = entries[0].clone();
                lying.uncomp_size = 1 << 40;
                assert!(matches!(apk.read_entry(&lying), Err(ApkError::ImplausibleSize { .. })));
                assert!(matches!(apk.inflate_until(&lying, |_| PrefixStep::Continue(0)), Err(ApkError::ImplausibleSize { .. })));
                let mut truncated = entries[0].clone();
                truncated.comp_size = u64::MAX;
                assert!(matches!(apk.read_entry(&truncated), Err(ApkError::BadLocalHeader(_))));
            }
        }
    }

    /// Deflate stream of `n` zero bytes (compresses about 1000:1).
    fn zeros_deflated(n: usize) -> Vec<u8> {
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
        e.write_all(&vec![0u8; n]).unwrap();
        e.finish().unwrap()
    }

    /// Hand-rolled zip (the `zip` crate refuses duplicate names and always
    /// writes true sizes): `(name, method, payload, comp_size, uncomp_size)`.
    fn raw_zip(entries: &[(&str, u16, &[u8], u32, u32)]) -> Vec<u8> {
        let mut z = Vec::new();
        let mut cd = Vec::new();
        for (name, method, payload, comp_size, uncomp_size) in entries {
            let lh = z.len() as u32;
            z.extend_from_slice(LH_SIG);
            z.extend_from_slice(&[20, 0, 0, 0]);
            z.extend_from_slice(&method.to_le_bytes());
            z.extend_from_slice(&[0; 8]);
            z.extend_from_slice(&comp_size.to_le_bytes());
            z.extend_from_slice(&uncomp_size.to_le_bytes());
            z.extend_from_slice(&(name.len() as u16).to_le_bytes());
            z.extend_from_slice(&0u16.to_le_bytes());
            z.extend_from_slice(name.as_bytes());
            z.extend_from_slice(payload);
            cd.extend_from_slice(CD_SIG);
            cd.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
            cd.extend_from_slice(&method.to_le_bytes());
            cd.extend_from_slice(&[0; 8]);
            cd.extend_from_slice(&comp_size.to_le_bytes());
            cd.extend_from_slice(&uncomp_size.to_le_bytes());
            cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
            cd.extend_from_slice(&[0; 12]);
            cd.extend_from_slice(&lh.to_le_bytes());
            cd.extend_from_slice(name.as_bytes());
        }
        let cd_off = z.len() as u32;
        z.extend_from_slice(&cd);
        z.extend_from_slice(EOCD_SIG);
        z.extend_from_slice(&[0, 0, 0, 0]);
        z.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        z.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        z.extend_from_slice(&(cd.len() as u32).to_le_bytes());
        z.extend_from_slice(&cd_off.to_le_bytes());
        z.extend_from_slice(&[0, 0]);
        z
    }

    #[test]
    fn undeclared_size_is_still_bounded() {
        // 1 MiB of zeros deflates to about 1 KiB; the 1032:1 bound allows it.
        let ok = zeros_deflated(1 << 20);
        let f = write_temp(&raw_zip(&[("classes.dex", METHOD_DEFLATE, &ok, ok.len() as u32, 0)]));
        let apk = Apk::open(f.path()).unwrap();
        let e = apk.dex_entries().unwrap().remove(0);
        assert_eq!(e.uncomp_size, 0);
        assert_eq!(apk.read_entry(&e).unwrap().len(), 1 << 20);
        match apk.inflate_until(&e, |_| PrefixStep::Continue(4096)).unwrap() {
            Prefix::Partial(v) => assert!(v.len() >= 4096),
            Prefix::Complete(v) => assert_eq!(v.len(), 1 << 20),
            Prefix::Aborted(_) => panic!("unexpected abort"),
        }
        // A shorter compressed size lowers the bound and truncates the stream:
        // either way the entry is rejected instead of inflated open-endedly.
        let mut lying = e.clone();
        lying.comp_size = 200;
        assert!(apk.read_entry(&lying).is_err());
        assert!(apk.inflate_until(&lying, |_| PrefixStep::Continue(0)).is_err());
    }

    #[test]
    fn hostile_offsets_do_not_overflow() {
        let dex = asc_fixture::make_dex();
        let f = write_temp(&asc_fixture::make_apk(&[("classes.dex", &dex)], true));
        let apk = Apk::open(f.path()).unwrap();
        let mut e = apk.dex_entries().unwrap().remove(0);
        for off in [u64::MAX, u64::MAX - 3, u64::MAX - 40, u32::MAX as u64] {
            e.local_header_off = off;
            assert!(matches!(apk.read_entry(&e), Err(ApkError::BadLocalHeader(_))));
            assert!(matches!(apk.inflate_until(&e, |_| PrefixStep::Continue(0)), Err(ApkError::BadLocalHeader(_))));
        }
        // zip64 locator pointing at an offset near usize::MAX.
        let mut bytes = asc_fixture::make_apk(&[("classes.dex", &dex)], false);
        let eocd = bytes.len() - 22;
        bytes[eocd + 16..eocd + 20].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let mut locator = Vec::new();
        locator.extend_from_slice(ZIP64_LOCATOR_SIG);
        locator.extend_from_slice(&0u32.to_le_bytes());
        locator.extend_from_slice(&(u64::MAX - 2).to_le_bytes());
        locator.extend_from_slice(&1u32.to_le_bytes());
        let tail = bytes.split_off(eocd);
        bytes.extend_from_slice(&locator);
        bytes.extend_from_slice(&tail);
        let f = write_temp(&bytes);
        let apk = Apk::open(f.path()).unwrap();
        assert!(matches!(apk.dex_entries(), Err(ApkError::NoEocd | ApkError::BadCentralDirectory)));
    }

    #[test]
    fn duplicate_root_dex_names_keep_the_last() {
        let a = asc_fixture::make_dex();
        let mut b = a.clone();
        b.push(0); // different content, same name
        let (la, lb) = (a.len() as u32, b.len() as u32);
        let f = write_temp(&raw_zip(&[
            ("classes.dex", METHOD_STORED, &a, la, la),
            ("classes2.dex", METHOD_STORED, &a, la, la),
            ("classes.dex", METHOD_STORED, &b, lb, lb),
        ]));
        let apk = Apk::open(f.path()).unwrap();
        let entries = apk.dex_entries().unwrap();
        let mut names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        names.sort();
        assert_eq!(names, ["classes.dex", "classes2.dex"]);
        let dup = entries.iter().find(|e| e.name == "classes.dex").unwrap();
        assert_eq!(apk.read_entry(dup).unwrap().as_ref(), b.as_slice());
        assert_eq!(apk.find_entry("classes.dex").unwrap().unwrap(), *dup);
        // Central-directory order, the duplicate at its last position.
        let ordered: Vec<String> = apk.dex_entries_in_order().unwrap().into_iter().map(|e| e.name).collect();
        assert_eq!(ordered, ["classes2.dex", "classes.dex"]);
    }

    #[test]
    fn inflate_until_streams_prefixes() {
        let dex = asc_fixture::make_dex();
        let apk_bytes = asc_fixture::make_apk(&[("classes.dex", &dex)], true);
        let f = write_temp(&apk_bytes);
        let apk = Apk::open(f.path()).unwrap();
        let entry = apk.dex_entries().unwrap().remove(0);
        match apk.inflate_until(&entry, |_| PrefixStep::Continue(8)).unwrap() {
            Prefix::Complete(v) | Prefix::Partial(v) => assert!(v.starts_with(b"dex\n") && v.len() >= 8),
            Prefix::Aborted(_) => panic!("unexpected abort"),
        }
        assert!(matches!(apk.inflate_until(&entry, |_| PrefixStep::Abort).unwrap(), Prefix::Aborted(_)));
    }
}
