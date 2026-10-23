//! Class enumeration (`listclass`, MCP `listclass`).

use crate::{load_entry, names, Engine, EngineError, Result};
use asc_dex::container::logical_dex_iter;
use asc_dex::{mutf8, Dex, DexError};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// A class definition and the (logical) DEX that defines it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassListing {
    pub descriptor: String,
    pub dex_name: String,
}

/// The classes one logical DEX defines, in `class_def` order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DexClasses {
    pub dex_name: String,
    pub descriptors: Vec<String>,
    /// Why the DEX could not be enumerated at all (`descriptors` is empty).
    pub error: Option<DexError>,
    /// `class_def`s whose descriptor could not be read; they are skipped.
    pub bad_class_defs: usize,
    /// The first of those, as `(class_def index, error)`.
    pub first_bad_class_def: Option<(u32, DexError)>,
}

impl DexClasses {
    /// The first problem as an error, if any.
    pub fn check(&self) -> Result<()> {
        if let Some(e) = &self.error {
            return Err(EngineError::BadDex { dex: self.dex_name.clone(), reason: e.to_string() });
        }
        if let Some((i, e)) = &self.first_bad_class_def {
            return Err(EngineError::BadDex { dex: self.dex_name.clone(), reason: format!("class_def {i}: {e}") });
        }
        Ok(())
    }
}

/// The classes of one DEX entry: its logical DEXes, or why it could not be read.
#[derive(Debug)]
pub struct EntryClasses {
    pub entry_name: String,
    pub result: Result<Vec<DexClasses>>,
}

/// A descriptor prefix ready to test raw descriptors against.
enum Prefix {
    /// ASCII: compared on the raw bytes, no decoding.
    Bytes(Vec<u8>),
    /// Non-ASCII: compared on the decoded name, so a non-canonical encoding of
    /// the same characters (which the listing decodes like any other) matches.
    Decoded(String),
}

impl Prefix {
    fn new(prefix: &str) -> Prefix {
        if prefix.is_ascii() {
            Prefix::Bytes(prefix.as_bytes().to_vec())
        } else {
            Prefix::Decoded(prefix.to_string())
        }
    }

    /// The decoded descriptor when `raw` starts with this prefix.
    fn matches(&self, raw: &[u8]) -> Option<String> {
        match self {
            Prefix::Bytes(p) => raw.starts_with(p).then(|| mutf8::decode(raw)),
            Prefix::Decoded(p) => Some(mutf8::decode(raw)).filter(|name| name.starts_with(p.as_str())),
        }
    }
}

/// Enumerate the classes of one logical DEX whose descriptor starts with
/// `prefix` (a descriptor prefix, used as is; `None` keeps every class).
/// Unreadable `class_def`s are counted and skipped.
pub fn dex_classes(dex_name: &str, buf: &[u8], prefix: Option<&str>) -> DexClasses {
    dex_classes_with(dex_name, buf, prefix.map(Prefix::new).as_ref(), false)
}

/// [`dex_classes`]; `strict` stops at the first unreadable `class_def`.
fn dex_classes_with(dex_name: &str, buf: &[u8], prefix: Option<&Prefix>, strict: bool) -> DexClasses {
    let mut out = DexClasses { dex_name: dex_name.to_string(), ..Default::default() };
    let dex = match Dex::with_name(buf, dex_name) {
        Ok(d) => d,
        Err(e) => {
            out.error = Some(e);
            return out;
        }
    };
    // A corrupt size must not drive billions of failing lookups. No
    // class_defs at all is fine whatever the offset says.
    let defs = dex.header().class_defs;
    if defs.size == 0 {
        return out;
    }
    if defs.off as u64 + defs.size as u64 * asc_dex::ClassDef::SIZE as u64 > buf.len() as u64 {
        out.error = Some(DexError::BadRange { what: "class_defs", offset: defs.off as usize });
        return out;
    }
    for (i, def) in dex.class_defs().enumerate() {
        let bytes = def.and_then(|d| dex.type_bytes(d.class_idx));
        match bytes {
            Ok(b) => match prefix {
                None => out.descriptors.push(mutf8::decode(b)),
                Some(p) => out.descriptors.extend(p.matches(b)),
            },
            Err(e) => {
                out.bad_class_defs += 1;
                if out.first_bad_class_def.is_none() {
                    out.first_bad_class_def = Some((i as u32, e));
                }
                if strict {
                    break;
                }
            }
        }
    }
    out
}

impl Engine {
    /// Enumerate the classes of every root DEX entry whose descriptor starts
    /// with `prefix` (a Dalvik descriptor prefix, used as is).
    ///
    /// Entries are read in parallel, largest first; the result follows the
    /// central-directory order, and each entry's logical DEXes and classes
    /// keep their file order. `progress(done, total)` runs after each entry.
    /// Problems are reported per entry / DEX, never as a failure of the call;
    /// only an unreadable APK fails it.
    pub fn scan_classes(&self, prefix: Option<&str>, progress: impl Fn(usize, usize) + Sync) -> Result<Vec<EntryClasses>> {
        self.scan(prefix, false, progress)
    }

    /// [`Engine::scan_classes`]; `strict` stops each DEX at its first bad
    /// `class_def` (the caller fails on it anyway).
    fn scan(&self, prefix: Option<&str>, strict: bool, progress: impl Fn(usize, usize) + Sync) -> Result<Vec<EntryClasses>> {
        let t0 = Instant::now();
        let apk = self.open()?;
        let entries = apk.dex_entries_in_order()?;
        let key = self.apk_key(&apk);
        let total = entries.len();
        let mut order: Vec<usize> = (0..total).collect();
        order.sort_by_key(|&i| std::cmp::Reverse(entries[i].comp_size));
        let prefix = prefix.map(Prefix::new);
        let slots: Vec<Mutex<Option<EntryClasses>>> = (0..total).map(|_| Mutex::new(None)).collect();
        let next = AtomicUsize::new(0);
        let done = AtomicUsize::new(0);
        let workers = self.threads().min(total).max(1);
        std::thread::scope(|s| {
            for _ in 0..workers {
                let (apk, entries, order, slots, key, prefix) = (&apk, &entries, &order, &slots, key.as_ref(), prefix.as_ref());
                let (next, done, progress) = (&next, &done, &progress);
                s.spawn(move || {
                    while let Some(&i) = order.get(next.fetch_add(1, Ordering::Relaxed)) {
                        let entry = &entries[i];
                        let result = load_entry(apk, key, entry, self.cache.as_deref(), &self.stats, None).map(|(loaded, _)| {
                            logical_dex_iter(&entry.name, loaded.bytes())
                                .map(|(name, buf)| dex_classes_with(&name, &buf, prefix, strict))
                                .collect()
                        });
                        *slots[i].lock().unwrap() = Some(EntryClasses { entry_name: entry.name.clone(), result });
                        progress(done.fetch_add(1, Ordering::Relaxed) + 1, total);
                    }
                });
            }
        });
        let out: Vec<EntryClasses> = slots.into_iter().map(|s| s.into_inner().unwrap().expect("every entry is scanned")).collect();
        if self.debug {
            let mut count = 0;
            for e in &out {
                for d in e.result.iter().flatten() {
                    count += d.descriptors.len();
                    self.log(format!("[APK] '{}' class_count={}", d.dex_name, d.descriptors.len()));
                }
            }
            self.log(format!("[APK] listclass total={} us count={count} workers={workers}", t0.elapsed().as_micros()));
        }
        Ok(out)
    }

    /// Every class of the APK, optionally restricted to a package / class
    /// prefix (`com.poc`, `com/poc` or `Lcom/poc`), in DEX order. Strict: the
    /// first unreadable entry, unparsable DEX or bad `class_def` fails the call.
    pub fn list_classes(&self, prefix: Option<&str>) -> Result<Vec<ClassListing>> {
        let prefix = prefix.map(names::class_prefix).transpose()?;
        let mut out = Vec::new();
        for entry in self.scan(prefix.as_deref(), true, |_, _| {})? {
            for dex in entry.result? {
                dex.check()?;
                let dex_name = dex.dex_name;
                out.extend(dex.descriptors.into_iter().map(|descriptor| ClassListing { descriptor, dex_name: dex_name.clone() }));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dex_classes_filters_by_raw_prefix_and_reports_bad_defs() {
        let dex = asc_fixture::make_dex();
        let all = dex_classes("classes.dex", &dex, None);
        assert_eq!(all.descriptors, ["Lexample/Test;"]);
        assert!(all.check().is_ok());
        assert!(dex_classes("classes.dex", &dex, Some("Lexample/")).descriptors.len() == 1);
        assert!(dex_classes("classes.dex", &dex, Some("Lother")).descriptors.is_empty());

        let mut bad = dex.clone();
        let off = u32::from_le_bytes(bad[0x64..0x68].try_into().unwrap()) as usize;
        bad[off..off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let r = dex_classes("classes.dex", &bad, None);
        assert!(r.descriptors.is_empty());
        assert_eq!(r.bad_class_defs, 1);
        let msg = r.check().unwrap_err().to_string();
        assert!(msg.starts_with("classes.dex: class_def 0: type index"), "{msg}");

        let mut huge = dex.clone();
        huge[0x60..0x64].copy_from_slice(&u32::MAX.to_le_bytes());
        let r = dex_classes("classes.dex", &huge, None);
        assert!(matches!(r.error, Some(DexError::BadRange { what: "class_defs", .. })));

        // No class_defs: the offset is not looked at.
        let mut none = dex.clone();
        none[0x60..0x68].copy_from_slice(&[0, 0, 0, 0, 0x00, 0xff, 0xff, 0xff]);
        let r = dex_classes("classes.dex", &none, None);
        assert_eq!(r.error, None);
        assert!(r.descriptors.is_empty() && r.check().is_ok());

        let r = dex_classes("x.dex", b"not a dex", None);
        assert!(r.error.is_some() && r.check().is_err());

        let only = asc_fixture::make_class_only_dex(&["Lb/B;", "La/A;"], 0, false);
        assert_eq!(
            dex_classes("c.dex", &only, None),
            DexClasses { dex_name: "c.dex".into(), descriptors: vec!["Lb/B;".into(), "La/A;".into()], ..Default::default() }
        );
    }

    #[test]
    fn strict_stops_at_the_first_bad_class_def() {
        let only = asc_fixture::make_class_only_dex(&["La/A;", "Lb/B;", "Lc/C;"], 0, false);
        let off = u32::from_le_bytes(only[0x64..0x68].try_into().unwrap()) as usize;
        let mut bad = only.clone();
        for i in 0..2 {
            bad[off + i * 32..off + i * 32 + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        }
        let lenient = dex_classes("c.dex", &bad, None);
        assert_eq!((lenient.bad_class_defs, lenient.descriptors.as_slice()), (2, &["Lc/C;".to_string()][..]));
        let strict = dex_classes_with("c.dex", &bad, None, true);
        assert_eq!((strict.bad_class_defs, strict.descriptors.len()), (1, 0));
        assert_eq!(strict.check().unwrap_err().to_string(), lenient.check().unwrap_err().to_string());
    }

    #[test]
    fn non_ascii_prefix_matches_decoded_names() {
        let name = "L\u{1f600}/A;";
        let canonical = asc_fixture::make_class_only_dex(&[name], 0, false);
        // The same class with its descriptor stored as 4-byte UTF-8 (same
        // byte length as the placeholder), which the listing decodes alike.
        let mut four = asc_fixture::make_class_only_dex(&["Lxxxx/A;"], 0, false);
        let at = four.windows(8).position(|w| w == b"Lxxxx/A;").unwrap();
        four[at + 1..at + 5].copy_from_slice("\u{1f600}".as_bytes());
        for data in [&canonical, &four] {
            assert_eq!(dex_classes("c.dex", data, None).descriptors, [name]);
            assert_eq!(dex_classes("c.dex", data, Some("L\u{1f600}")).descriptors, [name]);
            assert_eq!(dex_classes("c.dex", data, Some("L\u{1f600}/A")).descriptors, [name]);
            assert!(dex_classes("c.dex", data, Some("L\u{1f601}")).descriptors.is_empty());
        }
    }
}
