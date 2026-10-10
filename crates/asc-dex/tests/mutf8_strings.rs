//! MUTF-8 string data and descriptor lookups (MG1937/ASC issue #33).

use asc_dex::{mutf8, Dex, DexError};
use asc_fixture::{ClassSpec, DexBuilder};

/// The DEX attached to the upstream issue: two classes whose names hold
/// non-ASCII BMP characters (`U+06E1`, `U+1A7B`).
const ISSUE_DEX: [u8; 237] = [
    0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xed, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x03, 0x00,
    0x00, 0x00, 0x7c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0xdc, 0x00, 0x00, 0x00, 0xe4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
    0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x12, 0x4c, 0x6a, 0x61, 0x76, 0x61, 0x2f, 0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x3b, 0x00,
    0x05, 0x4c, 0x6c, 0x2f, 0xdb, 0xa1, 0x3b, 0x00, 0x05, 0x4c, 0x6c, 0x2f, 0xe1, 0xa9, 0xbb, 0x3b, 0x00,
];

/// A DEX that defines one empty class per descriptor.
fn class_dex(names: &[&str]) -> Vec<u8> {
    let mut d = DexBuilder::new();
    for name in names {
        d.type_(name);
    }
    let mut ids = d.resolve();
    for name in names {
        ids.add_class(ClassSpec { descriptor: name.to_string(), access: 0x1, ..Default::default() });
    }
    ids.finish()
}

#[test]
fn issue_fixture_decodes_and_finds_non_ascii_classes() {
    let dex = Dex::parse(&ISSUE_DEX).unwrap();
    let strings: Vec<String> = (0..3).map(|i| dex.string(i).unwrap()).collect();
    assert_eq!(strings, ["Ljava/lang/Object;", "Ll/\u{06e1};", "Ll/\u{1a7b};"]);
    for name in ["Ll/\u{06e1};", "Ll/\u{1a7b};"] {
        assert!(dex.find_class_def(&mutf8::encode(name)).unwrap().is_some(), "{name}");
    }
}

#[test]
fn special_forms_decode() {
    assert_eq!(mutf8::decode(b"a\xc0\x80b"), "a\0b");
    assert_eq!(mutf8::decode(b"\xed\xa0\xbd\xed\xb8\x80"), "\u{1f600}");
    assert_eq!(mutf8::decode(b"a\xffb"), "a\u{fffd}b");
    assert_eq!(mutf8::decode(b"a\xc0\x80\xffb"), "a\0\u{fffd}b");
}

#[test]
fn lookup_follows_utf16_sort_order() {
    // U+10000 is the surrogate pair D800 DC00 and sorts before U+E000 by
    // UTF-16 code units, although its code point (and UTF-8 form) is larger.
    let names = ["Ll/\u{10000};", "Ll/\u{e000};"];
    let data = class_dex(&names);
    let dex = Dex::parse(&data).unwrap();
    for name in names {
        let (_, def) = dex.find_class_def(&mutf8::encode(name)).unwrap().unwrap_or_else(|| panic!("{name}"));
        assert_eq!(dex.type_descriptor(def.class_idx).unwrap(), name);
    }
    // The UTF-8 form of a supplementary character is not what the DEX stores,
    // but it names the same code units, so the lookup still finds it.
    assert_eq!(dex.find_type_idx(names[0].as_bytes()).unwrap(), dex.find_type_idx(&mutf8::encode(names[0])).unwrap());
}

#[test]
fn lookup_sorts_nul_first() {
    // `U+0000` is `C0 80`: above `/` as bytes, below everything in UTF-16.
    // A byte-order search walks the wrong way and misses its neighbours.
    for names in [["LA;", "La\0;", "La/;"], ["La\0;", "La/;", "Lb;"]] {
        let data = class_dex(&names);
        let dex = Dex::parse(&data).unwrap();
        for name in names {
            let enc = mutf8::encode(name);
            let (_, def) = dex.find_class_def(&enc).unwrap().unwrap_or_else(|| panic!("{name:?} in {names:?}"));
            assert_eq!(dex.type_descriptor(def.class_idx).unwrap(), name);
            assert!(asc_dex::quick::dex_defines_class(&data, &enc).unwrap(), "{name:?} in {names:?}");
            let s = dex.find_string_idx(&enc).unwrap().unwrap();
            assert_eq!(dex.string(s).unwrap(), name);
        }
        assert_eq!(dex.find_string_idx(b"La;").unwrap(), None);
    }
}

#[test]
fn unterminated_string_is_rejected() {
    let mut data = class_dex(&["Lexample/Test;"]);
    let off = Dex::parse(&data).unwrap().string_data_off(0).unwrap() as usize;
    data[off..].fill(b'x');
    data[off] = 14; // keep a plausible uleb128 length
    let dex = Dex::parse(&data).unwrap();
    assert_eq!(dex.string_item(0), Err(DexError::UnterminatedString(off)));
}
