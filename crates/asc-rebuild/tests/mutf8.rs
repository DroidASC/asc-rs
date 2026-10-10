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

/// A one-class DEX for `name`, plus the offset of its descriptor's
/// `string_data_item`.
fn one_class(name: &str) -> (Vec<u8>, usize) {
    let mut d = DexBuilder::new();
    d.type_(name);
    let mut ids = d.resolve();
    ids.add_class(ClassSpec { descriptor: name.into(), access: 0x1, ..Default::default() });
    let data = ids.finish();
    let dex = Dex::parse(&data).unwrap();
    let idx = dex.type_string_idx(0).unwrap();
    let off = dex.string_data_off(idx).unwrap() as usize;
    (data, off)
}

/// The rebuilt descriptor string of `name`'s class.
fn rebuilt_descriptor(data: &[u8], name: &str) -> (Vec<u8>, u32) {
    let rebuilt = rebuild_class_bytes(data, name).unwrap();
    let dex = Dex::parse(&rebuilt.bytes).unwrap();
    let (_, def) = dex.find_class_def(&asc_dex::mutf8::encode(name)).unwrap().expect("class in rebuilt DEX");
    let item = dex.string_item(dex.type_string_idx(def.class_idx).unwrap()).unwrap();
    assert_eq!(dex.type_descriptor(def.class_idx).unwrap(), name);
    (item.bytes.to_vec(), item.utf16_len)
}

#[test]
fn rebuild_recounts_a_wrong_declared_length() {
    // 3 + 6 * 2 + 1 = 16 code units in 40 bytes; an older tool wrote the
    // code-point count (10), which leaves the NUL outside `3 * 10 + 1` bytes.
    let name = "La/\u{1f600}\u{1f600}\u{1f600}\u{1f600}\u{1f600}\u{1f600};";
    let (mut data, off) = one_class(name);
    assert_eq!(data[off], 16);
    data[off] = 10;
    let (bytes, len) = rebuilt_descriptor(&data, name);
    assert_eq!(len, 16);
    assert_eq!(bytes, asc_dex::mutf8::encode(name));
}

#[test]
fn rebuild_reencodes_four_byte_utf8_as_surrogates() {
    // Same byte length as the 4-byte UTF-8 form of U+1F600: patch it in.
    let (mut data, off) = one_class("La/xxxx;");
    assert_eq!(&data[off..off + 10], b"\x08La/xxxx;\0");
    data[off] = 6;
    data[off + 4..off + 8].copy_from_slice("\u{1f600}".as_bytes());
    let name = "La/\u{1f600};";
    let (bytes, len) = rebuilt_descriptor(&data, name);
    assert_eq!(len, 6);
    assert_eq!(bytes, b"La/\xed\xa0\xbd\xed\xb8\x80;");
}
