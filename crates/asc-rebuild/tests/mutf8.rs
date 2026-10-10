//! Rebuilt string data stays MUTF-8 (MG1937/ASC issue #33 follow-up).

use asc_dex::Dex;
use asc_fixture::{ClassSpec, DexBuilder};
use asc_rebuild::rebuild_class_bytes;

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn rebuilt_dex_writes_modified_utf8() {
    let name = "Lexample/\u{1f600};";
    let mut d = DexBuilder::new();
    d.type_(name);
    let mut ids = d.resolve();
    ids.add_class(ClassSpec { descriptor: name.into(), access: 0x1, ..Default::default() });
    let data = ids.finish();

    let rebuilt = rebuild_class_bytes(&data, name).unwrap();
    // U+1F600 as the surrogate pair D83D DE00, never the 4-byte UTF-8 form.
    assert!(contains(&rebuilt.bytes, b"\xed\xa0\xbd\xed\xb8\x80"));
    assert!(!contains(&rebuilt.bytes, b"\xf0\x9f\x98\x80"));

    let dex = Dex::parse(&rebuilt.bytes).unwrap();
    let n = dex.header().string_ids.size;
    let idx = (0..n).find(|&i| dex.string(i).unwrap() == name).expect("descriptor string");
    // utf16_size counts code units: 10 ASCII + 2 for the surrogate pair.
    assert_eq!(dex.string_item(idx).unwrap().utf16_len, 12);
}
