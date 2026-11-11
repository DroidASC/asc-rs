//! Archives read from memory.

use asc_apk::Apk;

#[test]
fn in_memory_archive_reads_like_a_file() {
    let dex = asc_fixture::make_dex();
    let apk = Apk::from_bytes("app.apk", asc_fixture::make_apk(&[("classes.dex", &dex)], true));
    assert_eq!(apk.read("classes.dex").unwrap(), dex);
    assert_eq!(apk.dex_entries().unwrap().len(), 1);
    let bare = Apk::from_bytes("classes.dex", dex.clone());
    assert_eq!(bare.read("classes.dex").unwrap(), dex);
}
