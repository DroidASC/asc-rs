//! `asc-apk`: the central directory scan, then every entry read, inflated
//! by prefix and opened as a nested archive, under the zip-bomb limits the
//! engine sweeps untrusted APKs with.

use asc_apk::{Apk, Limits, PrefixStep};

/// Small enough that a hostile entry hits the limits within the fuzzer's
/// memory budget, as the guarded limits do at real sizes.
const LIMITS: Limits = Limits { max_entry_bytes: 64 << 20, max_ratio: 100, max_dex_total_bytes: 256 << 20 };

pub fn run(data: &[u8]) {
    let apk = Apk::from_bytes("fuzz.apk", data.to_vec()).with_limits(LIMITS);
    let _ = (apk.directories(), apk.stamp(), apk.stem());
    let _ = apk.dex_entries();
    let _ = apk.find_entry("AndroidManifest.xml");
    let _ = apk.read("classes.dex");
    let Ok(entries) = apk.entries() else { return };
    for entry in entries.iter().take(64) {
        let _ = apk.raw_payload(entry);
        if let Ok(bytes) = apk.read_entry(entry) {
            assert!(bytes.len() as u64 <= LIMITS.max_entry_bytes, "{} inflated past the limit", entry.name);
        }
        let _ = apk.inflate_until(entry, |prefix| if prefix.len() < 64 { PrefixStep::Continue(0) } else { PrefixStep::Continue(4096) });
        let _ = apk.inflate_until(entry, |_| PrefixStep::Abort);
        if let Ok(nested) = apk.open_nested(entry)
            && let Ok(inner) = nested.entries()
        {
            for entry in inner.iter().take(8) {
                let _ = nested.read_entry(entry);
            }
        }
    }
}
