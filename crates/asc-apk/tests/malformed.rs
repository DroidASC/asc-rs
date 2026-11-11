//! A malformed archive returns errors, never a panic, and never inflates
//! past the limits: deterministic mutants of the fixture archives, every
//! entry read whole, by prefix and as a nested archive.

use asc_apk::{Apk, Limits, PrefixStep};
use asc_fixture::mutate::mutants;

const LIMITS: Limits = Limits { max_entry_bytes: 16 << 20, max_ratio: 100, max_dex_total_bytes: 64 << 20 };

fn exercise(data: &[u8]) {
    let apk = Apk::from_bytes("mutant.apk", data.to_vec()).with_limits(LIMITS);
    let _ = (apk.dex_entries(), apk.find_entry("classes.dex"), apk.directories());
    let Ok(entries) = apk.entries() else { return };
    for entry in entries.iter().take(16) {
        if let Ok(bytes) = apk.read_entry(entry) {
            assert!(bytes.len() as u64 <= LIMITS.max_entry_bytes, "{} inflated past the limit", entry.name);
        }
        let _ = apk.inflate_until(entry, |prefix| PrefixStep::Continue(if prefix.is_empty() { 0 } else { 32 }));
        if let Ok(nested) = apk.open_nested(entry) {
            let _ = nested.entries();
        }
    }
}

#[test]
fn mutated_archives_never_panic() {
    let dex = asc_fixture::make_dex();
    let seeds = [
        asc_fixture::make_apk(&[("classes.dex", &dex), ("res/a.xml", b"<a/>")], true),
        asc_fixture::make_apk(&[("classes.dex", &dex), ("classes2.dex", &dex)], false),
        asc_fixture::make_app(&[("entry.hap", &asc_fixture::make_hap(&asc_fixture::make_abc()))], asc_fixture::hap::Compression::Deflated),
        dex,
    ];
    for (i, seed) in seeds.iter().enumerate() {
        exercise(seed);
        for mutant in mutants(seed, 0xa9c + i as u64, 1000) {
            exercise(&mutant);
        }
    }
}

#[test]
fn in_memory_archive_reads_like_a_file() {
    let dex = asc_fixture::make_dex();
    let apk = Apk::from_bytes("app.apk", asc_fixture::make_apk(&[("classes.dex", &dex)], true));
    assert_eq!(apk.read("classes.dex").unwrap(), dex);
    assert_eq!(apk.dex_entries().unwrap().len(), 1);
    let bare = Apk::from_bytes("classes.dex", dex.clone());
    assert_eq!(bare.read("classes.dex").unwrap(), dex);
}
