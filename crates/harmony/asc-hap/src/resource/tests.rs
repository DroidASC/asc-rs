use super::{IndexFormat, QualifierKey, ResourceIndex, ResourceIndexError, ResourceRef, ResourceType, ResourceValue};

const STRING: u32 = 9;
const STRARRAY: u32 = 10;
const COLOR: u32 = 14;
const THEME: u32 = 16;
const PLURAL: u32 = 17;
const MEDIA: u32 = 19;
const PATTERN: u32 = 22;

/// Qualifier values as the tool packs them.
const ZH: (u32, u32) = (0, 0x7a68);
const CN: (u32, u32) = (1, 0x434e);
const DARK: (u32, u32) = (6, 0);

fn put32(out: &mut Vec<u8>, value: usize) {
    out.extend(u32::try_from(value).unwrap().to_le_bytes());
}

fn put16(out: &mut Vec<u8>, value: usize) {
    out.extend(u16::try_from(value).unwrap().to_le_bytes());
}

fn header(version: &str) -> Vec<u8> {
    let mut out = version.as_bytes().to_vec();
    out.resize(128, 0);
    out
}

/// A list value: each item with its length and an uncounted NUL.
fn list(items: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for item in items {
        put16(&mut out, item.len());
        out.extend(item.as_bytes());
        out.push(0);
    }
    out
}

/// One value of the sample table, in neither layout's spelling.
struct Sample {
    id: u32,
    kind: u32,
    name: &'static str,
    /// Position in [`SETS`].
    set: usize,
    value: Vec<u8>,
}

const SETS: &[&[(u32, u32)]] = &[&[], &[ZH, CN], &[DARK]];

fn sample(id: u32, kind: u32, name: &'static str, set: usize, value: impl Into<Vec<u8>>) -> Sample {
    Sample { id, kind, name, set, value: value.into() }
}

fn samples() -> Vec<Sample> {
    vec![
        sample(0x0100_0000, STRING, "app_name", 0, "Shop"),
        sample(0x0100_0000, STRING, "app_name", 1, "商店"),
        sample(0x0100_0001, MEDIA, "icon", 0, "entry/resources/base/media/icon.png"),
        sample(0x0100_0002, COLOR, "accent", 0, "#FF0000"),
        sample(0x0100_0002, COLOR, "accent", 2, "$color:16777219"),
        sample(0x0100_0003, COLOR, "accent_dark", 0, "#00FF00"),
        sample(0x0100_0004, STRARRAY, "sizes", 0, list(&["S", "M", ""])),
        sample(0x0100_0005, PLURAL, "files", 0, list(&["one", "%d file", "other", "%d files"])),
        sample(0x0100_0006, THEME, "app_theme", 0, list(&["$theme:16777223", "width", "10vp"])),
        sample(0x0100_0007, PATTERN, "base_pattern", 0, list(&["height", "20vp", "note", "a \"b\"\n"])),
        sample(0x0100_0008, 77, "mystery", 0, [1, 2, 3]),
    ]
}

/// The first layout: per qualifier set an id table, per value a record.
fn build_v1(version: &str, values: &[Sample]) -> Vec<u8> {
    let keys_len: usize = SETS.iter().map(|set| 12 + 8 * set.len()).sum();
    let tables_len: usize = SETS.iter().enumerate().map(|(i, _)| 8 + 8 * values.iter().filter(|v| v.set == i).count()).sum();
    let mut keys = Vec::new();
    let mut tables = Vec::new();
    let mut records = Vec::new();
    let tables_start = 136 + keys_len;
    for (i, set) in SETS.iter().enumerate() {
        keys.extend(b"KEYS");
        put32(&mut keys, tables_start + tables.len());
        put32(&mut keys, set.len());
        for &(key, value) in *set {
            keys.extend(key.to_le_bytes());
            keys.extend(value.to_le_bytes());
        }
        let members: Vec<&Sample> = values.iter().filter(|v| v.set == i).collect();
        tables.extend(b"IDSS");
        put32(&mut tables, members.len());
        for value in members {
            tables.extend(value.id.to_le_bytes());
            put32(&mut tables, tables_start + tables_len + records.len());
            put32(&mut records, 8 + 2 + value.value.len() + 1 + 2 + value.name.len() + 1);
            records.extend(value.kind.to_le_bytes());
            records.extend(value.id.to_le_bytes());
            put16(&mut records, value.value.len() + 1);
            records.extend(&value.value);
            records.push(0);
            put16(&mut records, value.name.len() + 1);
            records.extend(value.name.as_bytes());
            records.push(0);
        }
    }
    let mut out = header(version);
    put32(&mut out, 136 + keys.len() + tables.len() + records.len());
    put32(&mut out, SETS.len());
    out.extend(keys);
    out.extend(tables);
    out.extend(records);
    out
}

/// The second layout: a name table per type, a value list per resource.
/// Qualifier set `i` gets the id `10 + i`, so ids are not positions.
fn build_v2(version: &str, values: &[Sample]) -> Vec<u8> {
    let mut keys = Vec::new();
    for (i, set) in SETS.iter().enumerate() {
        keys.extend(b"KEYS");
        put32(&mut keys, 10 + i);
        put32(&mut keys, set.len());
        for &(key, value) in *set {
            keys.extend(key.to_le_bytes());
            keys.extend(value.to_le_bytes());
        }
    }
    let mut kinds: Vec<u32> = values.iter().map(|v| v.kind).collect();
    kinds.dedup();
    let mut ids: Vec<u32> = values.iter().map(|v| v.id).collect();
    ids.dedup();
    let name_of = |id: u32| values.iter().find(|v| v.id == id).unwrap().name;
    let ids_len = 16 + 12 * kinds.len() + ids.iter().map(|&id| 12 + name_of(id).len()).sum::<usize>();
    let infos_len = 12 + 12 * ids.len() + 8 * values.len();
    let data_start = 140 + keys.len() + ids_len;
    let pool_start = data_start + infos_len;

    let mut infos = Vec::new();
    let mut pool = Vec::new();
    let mut info_offsets = Vec::new();
    infos.extend(b"DATA");
    put32(&mut infos, infos_len);
    put32(&mut infos, ids.len());
    for &id in &ids {
        let members: Vec<&Sample> = values.iter().filter(|v| v.id == id).collect();
        info_offsets.push(data_start + infos.len());
        infos.extend(id.to_le_bytes());
        put32(&mut infos, 12 + 8 * members.len());
        put32(&mut infos, members.len());
        for value in members {
            put32(&mut infos, 10 + value.set);
            put32(&mut infos, pool_start + pool.len());
            put16(&mut pool, value.value.len());
            pool.extend(&value.value);
        }
    }

    let mut table = Vec::new();
    table.extend(b"IDSS");
    put32(&mut table, ids_len);
    put32(&mut table, kinds.len());
    put32(&mut table, ids.len());
    for kind in kinds {
        let members: Vec<usize> = (0..ids.len()).filter(|&i| values.iter().any(|v| v.id == ids[i] && v.kind == kind)).collect();
        table.extend(kind.to_le_bytes());
        put32(&mut table, 12 + members.iter().map(|&i| 12 + name_of(ids[i]).len()).sum::<usize>());
        put32(&mut table, members.len());
        for i in members {
            table.extend(ids[i].to_le_bytes());
            put32(&mut table, info_offsets[i]);
            put32(&mut table, name_of(ids[i]).len());
            table.extend(name_of(ids[i]).as_bytes());
        }
    }
    assert_eq!(table.len(), ids_len);
    assert_eq!(infos.len(), infos_len);

    let mut out = header(version);
    put32(&mut out, pool_start + pool.len());
    put32(&mut out, SETS.len());
    put32(&mut out, data_start);
    out.extend(keys);
    out.extend(table);
    out.extend(infos);
    out.extend(pool);
    out
}

fn both() -> [Vec<u8>; 2] {
    [build_v1("Restool 5.0.1.011", &samples()), build_v2("RestoolV2 6.0.0.001", &samples())]
}

fn lines(index: &ResourceIndex<'_>) -> Vec<String> {
    index.iter().map(|r| r.to_string()).collect()
}

fn set32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn get32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn find(bytes: &[u8], needle: &[u8]) -> usize {
    bytes.windows(needle.len()).position(|w| w == needle).unwrap()
}

#[test]
fn both_layouts_read_the_same_table() {
    let [v1, v2] = both();
    let first = ResourceIndex::parse(&v1).unwrap();
    let second = ResourceIndex::parse(&v2).unwrap();
    assert_eq!((first.format(), first.version()), (IndexFormat::V1, "Restool 5.0.1.011"));
    assert_eq!((second.format(), second.version()), (IndexFormat::V2, "RestoolV2 6.0.0.001"));
    assert_eq!(lines(&first), lines(&second));
    assert_eq!(
        lines(&first),
        [
            r#"0x01000000 string/app_name [base] "Shop""#,
            r#"0x01000000 string/app_name [zh_CN] "商店""#,
            r#"0x01000001 media/icon [base] entry/resources/base/media/icon.png"#,
            r##"0x01000002 color/accent [base] "#FF0000""##,
            r#"0x01000002 color/accent [dark] "$color:16777219""#,
            r##"0x01000003 color/accent_dark [base] "#00FF00""##,
            r#"0x01000004 strarray/sizes [base] ["S", "M", ""]"#,
            r#"0x01000005 plural/files [base] {"one": "%d file", "other": "%d files"}"#,
            r#"0x01000006 theme/app_theme [base] {parent: "$theme:16777223", "width": "10vp"}"#,
            r#"0x01000007 pattern/base_pattern [base] {"height": "20vp", "note": "a \"b\"\n"}"#,
            r#"0x01000008 type77/mystery [base] <3 bytes>"#,
        ]
    );
    assert_eq!((first.len(), first.is_empty(), first.iter().len()), (11, false, 11));
    assert_eq!(first.qualifiers().iter().map(ToString::to_string).collect::<Vec<_>>(), ["base", "zh_CN", "dark"]);
}

#[test]
fn lookups_by_id_and_by_name() {
    for bytes in both() {
        let index = ResourceIndex::parse(&bytes).unwrap();
        let name: Vec<_> = index.by_id(0x0100_0000).map(|r| (r.kind(), r.name().into_owned(), r.qualifiers().to_string())).collect();
        assert_eq!(
            name,
            [
                (ResourceType::String, "app_name".to_owned(), "base".to_owned()),
                (ResourceType::String, "app_name".to_owned(), "zh_CN".to_owned())
            ]
        );
        assert_eq!(index.by_id(0x0100_0009).len(), 0);
        assert_eq!(index.by_id(0).len() + index.by_id(u32::MAX).len(), 0);

        let accent: Vec<_> = index.by_name(ResourceType::Color, "accent").map(|r| r.id()).collect();
        assert_eq!(accent, [0x0100_0002, 0x0100_0002]);
        // The type is part of the key, and a name is not a prefix match.
        assert_eq!(index.by_name(ResourceType::String, "accent").len(), 0);
        assert_eq!(index.by_name(ResourceType::Color, "accent_").len(), 0);
        assert_eq!(index.by_name(ResourceType::Other(77), "mystery").len(), 1);

        let dark = index.by_name(ResourceType::Color, "accent").next_back().unwrap();
        assert_eq!(dark.qualifiers().get(QualifierKey::ColorMode), Some(0));
        assert!(!dark.qualifiers().is_base());
        assert_eq!(dark.value(), ResourceValue::Text("$color:16777219".into()));
        assert_eq!(dark.raw_value().len(), if index.format() == IndexFormat::V1 { 16 } else { 15 });
    }
}

#[test]
fn references_resolve_by_name_then_by_id() {
    for bytes in both() {
        let index = ResourceIndex::parse(&bytes).unwrap();
        let resolve = |text| index.resolve(ResourceRef::parse(text).unwrap()).map(|r| r.to_string()).collect::<Vec<_>>();
        assert_eq!(resolve("$media:icon"), ["0x01000001 media/icon [base] entry/resources/base/media/icon.png"]);
        assert_eq!(resolve("app.string.app_name").len(), 2);
        // What the dark accent stores: a decimal id of the same type.
        assert_eq!(resolve("$color:16777219"), [r##"0x01000003 color/accent_dark [base] "#00FF00""##]);
        // The id exists, but under another type.
        assert!(resolve("$string:16777219").is_empty());
        assert!(resolve("$string:missing").is_empty());
    }
}

#[test]
fn reference_spellings() {
    let parsed = ResourceRef::parse("$profile:main_pages").unwrap();
    assert_eq!((parsed.kind, parsed.name, parsed.to_string().as_str()), (ResourceType::Profile, "main_pages", "$profile:main_pages"));
    assert_eq!(ResourceRef::parse("app.float.title.size").unwrap().name, "title.size");
    for text in ["", "$", "$string", "$string:", "$nope:x", "string:x", "sys.string.x", "$ohos:string:x", "app.string", "app..x"] {
        assert_eq!(ResourceRef::parse(text), None, "{text:?}");
    }
}

#[test]
fn type_names_and_codes() {
    for code in 0..40 {
        let kind = ResourceType::from_code(code);
        assert_eq!(kind.code(), code);
        assert_eq!(kind.to_string().parse::<ResourceType>(), Ok(kind));
    }
    assert_eq!(ResourceType::from_code(20).to_string(), "profile");
    assert_eq!(ResourceType::from_code(13).to_string(), "type13");
    assert!("strings".parse::<ResourceType>().is_err() && "type".parse::<ResourceType>().is_err());
    // The `type` of the object a `$r(...)` call compiles to.
    assert_eq!(ResourceType::from_object_code(10003), Some(ResourceType::String));
    assert_eq!(ResourceType::from_object_code(20000), Some(ResourceType::Media));
    assert_eq!(ResourceType::from_object_code(30000), None);
    assert_eq!((ResourceType::Color.object_code(), ResourceType::Profile.object_code()), (Some(10001), None));
}

#[test]
fn values_by_type() {
    let index_bytes = build_v2("RestoolV2 6.0.0.001", &samples());
    let index = ResourceIndex::parse(&index_bytes).unwrap();
    let value = |id| index.by_id(id).next().unwrap().value();
    assert_eq!(value(0x0100_0001).archive_path(), Some("resources/base/media/icon.png"));
    assert_eq!(value(0x0100_0000).archive_path(), None);
    assert_eq!(value(0x0100_0004), ResourceValue::Array(vec!["S".into(), "M".into(), "".into()]));
    let ResourceValue::Plural(forms) = value(0x0100_0005) else { panic!("not a plural") };
    assert_eq!((forms.len(), forms[1].name.as_ref(), forms[1].value.as_ref()), (2, "other", "%d files"));
    let ResourceValue::Map { parent, attrs } = value(0x0100_0006) else { panic!("not a theme") };
    assert_eq!((parent.as_deref(), attrs.len(), attrs[0].name.as_ref()), (Some("$theme:16777223"), 1, "width"));
    assert_eq!(value(0x0100_0008), ResourceValue::Raw(&[1, 2, 3]));
}

#[test]
fn a_list_that_does_not_read_as_one_stays_raw() {
    let mut cut = list(&["one", "%d file"]);
    cut.truncate(cut.len() - 2);
    let odd = list(&["one", "%d file", "other"]);
    let unterminated = [1, 0, b'x', b'y'];
    for value in [cut, odd, unterminated.to_vec()] {
        let value = [sample(1, PLURAL, "n", 0, value)];
        for bytes in [build_v1("Restool 1", &value), build_v2("RestoolV2 1", &value)] {
            let index = ResourceIndex::parse(&bytes).unwrap();
            assert_eq!(index.iter().next().unwrap().value(), ResourceValue::Raw(&value[0].value));
        }
    }
    // Text that is not UTF-8 is read lossily.
    let bytes = build_v1("Restool 1", &[sample(1, STRING, "n", 0, [b'a', 0xff])]);
    assert_eq!(ResourceIndex::parse(&bytes).unwrap().iter().next().unwrap().value(), ResourceValue::Text("a\u{fffd}".into()));
}

#[test]
fn qualifier_spellings() {
    use super::qualifier::{Qualifier, Qualifiers};
    let set = |params: &[(u32, u32)]| Qualifiers::new(params.iter().map(|&(k, v)| Qualifier::from_raw(k, v)).collect()).to_string();
    assert_eq!(set(&[]), "base");
    assert_eq!(set(&[(0, 0x656e), (1, 0x5553)]), "en_US");
    assert_eq!(set(&[(0, 0x7a68), (5, 0x4861_6e74), (1, 0x434e)]), "zh_Hant_CN");
    assert_eq!(set(&[(7, 460), (8, 1), (0, 0x7a68)]), "mcc460_mnc1-zh");
    assert_eq!(set(&[(3, 1), (4, 7), (6, 1), (2, 480), (10, 0)]), "horizontal-2in1-light-xxldpi-pointingdevice");
    // Values and keys without a spelling keep their numbers.
    assert_eq!(set(&[(4, 99), (9, 5), (2, 1)]), "device=99-key9=5-density=1");
    assert_eq!(set(&[(0, 0x0001_7a68)]), "?zh");
}

#[test]
fn unknown_versions_are_refused() {
    for version in ["", "Restool", "Restool3 1.0", "RestoolV3 7.0.0.001", "restool 5.0", "PANDA"] {
        let mut bytes = build_v1("Restool 5.0", &samples());
        bytes[..128].fill(0);
        bytes[..version.len()].copy_from_slice(version.as_bytes());
        let parsed = ResourceIndex::parse(&bytes);
        if version == "Restool" {
            // The tool name alone still names the first layout.
            assert!(parsed.is_ok());
            continue;
        }
        assert_eq!(parsed.unwrap_err(), ResourceIndexError::UnknownVersion { version: version.to_owned() });
    }
    let mut bytes = build_v2("RestoolV2 6", &samples());
    bytes[0] = 0xff;
    assert!(matches!(ResourceIndex::parse(&bytes), Err(ResourceIndexError::UnknownVersion { .. })));
}

#[test]
fn every_truncation_is_an_error() {
    assert!(matches!(ResourceIndex::parse(&[]), Err(ResourceIndexError::Truncated { what: "version", needed: 128, available: 0, .. })));
    for bytes in both() {
        for len in 0..bytes.len() {
            assert!(ResourceIndex::parse(&bytes[..len]).is_err(), "a prefix of {len} bytes parsed");
        }
        // Bytes after the last table are not part of it.
        let mut longer = bytes.clone();
        longer.extend([0xaa; 9]);
        assert_eq!(lines(&ResourceIndex::parse(&longer).unwrap()), lines(&ResourceIndex::parse(&bytes).unwrap()));
    }
}

/// Reads everything an index offers, as a caller would.
fn exercise(bytes: &[u8]) {
    let Ok(index) = ResourceIndex::parse(bytes) else { return };
    for resource in &index {
        let _ = resource.to_string();
        assert!(index.by_id(resource.id()).len() >= 1);
        assert!(index.by_name(resource.kind(), &resource.name()).len() >= 1 || resource.name().contains('\u{fffd}'));
    }
}

#[test]
fn corrupt_fields_never_panic() {
    for bytes in both() {
        for offset in 0..bytes.len() {
            let mut corrupt = bytes.clone();
            for value in [0x00, 0x01, 0x7f, 0x80, 0xff] {
                corrupt[offset] = value;
                exercise(&corrupt);
            }
            if offset + 4 > bytes.len() {
                continue;
            }
            let original = get32(&bytes, offset);
            for value in
                [0, 1, 135, 136, 0x7fff_ffff, u32::MAX, original.wrapping_add(1), original.wrapping_sub(1), original.wrapping_mul(2)]
            {
                let mut corrupt = bytes.clone();
                set32(&mut corrupt, offset, value);
                exercise(&corrupt);
            }
        }
    }
}

#[test]
fn offsets_outside_the_file() {
    let [v1, v2] = both();
    // First layout: the id table of the first qualifier set, then a record.
    let mut bytes = v1.clone();
    set32(&mut bytes, 136 + 4, u32::MAX);
    assert_eq!(
        ResourceIndex::parse(&bytes).unwrap_err(),
        ResourceIndexError::OutOfBounds { what: "id set", offset: u32::MAX, len: v1.len() }
    );
    let table = find(&v1, b"IDSS");
    let mut bytes = v1.clone();
    set32(&mut bytes, table + 12, u32::try_from(v1.len()).unwrap() + 1);
    assert!(matches!(ResourceIndex::parse(&bytes), Err(ResourceIndexError::OutOfBounds { what: "record", .. })));
    // An offset that is inside the file but not at a table.
    let mut bytes = v1.clone();
    set32(&mut bytes, 136 + 4, 3);
    assert_eq!(ResourceIndex::parse(&bytes).unwrap_err(), ResourceIndexError::BadTag { expected: "IDSS", offset: 3, found: *b"tool" });

    // Second layout: the data block, a resource's value list, a value.
    let mut bytes = v2.clone();
    set32(&mut bytes, 136, u32::MAX);
    assert!(matches!(ResourceIndex::parse(&bytes), Err(ResourceIndexError::OutOfBounds { what: "data block", .. })));
    let mut bytes = v2.clone();
    set32(&mut bytes, 136, 0);
    assert!(matches!(ResourceIndex::parse(&bytes), Err(ResourceIndexError::BadTag { expected: "DATA", offset: 0, .. })));
    let item = find(&v2, b"IDSS") + 16 + 12;
    let mut bytes = v2.clone();
    set32(&mut bytes, item + 4, u32::MAX);
    assert!(matches!(ResourceIndex::parse(&bytes), Err(ResourceIndexError::OutOfBounds { what: "resource info", .. })));
    let info = usize::try_from(get32(&v2, item + 4)).unwrap();
    let mut bytes = v2.clone();
    set32(&mut bytes, info + 12 + 4, u32::MAX - 1);
    assert!(matches!(ResourceIndex::parse(&bytes), Err(ResourceIndexError::OutOfBounds { what: "value", .. })));
}

#[test]
fn counts_larger_than_the_file() {
    let [v1, v2] = both();
    let cases = [
        (v1.clone(), 132, "qualifier set count"),
        (v1.clone(), 136 + 8, "qualifier count"),
        (v1.clone(), find(&v1, b"IDSS") + 4, "id count"),
        (v2.clone(), 132, "qualifier set count"),
        (v2.clone(), find(&v2, b"IDSS") + 8, "type count"),
        (v2.clone(), find(&v2, b"IDSS") + 16 + 8, "resource count"),
        (v2.clone(), find(&v2, b"IDSS") + 16 + 12 + 8, "resource name length"),
        (v2.clone(), find(&v2, b"DATA") + 12 + 8, "value count"),
    ];
    for (mut bytes, offset, what) in cases {
        for count in [u32::MAX, 0x1000_0000] {
            set32(&mut bytes, offset, count);
            // Refused at the count itself, before a table of that size is allocated.
            let Err(ResourceIndexError::Truncated { what: found, offset: at, .. }) = ResourceIndex::parse(&bytes) else {
                panic!("{what}: {count:#x} was accepted")
            };
            assert_eq!((found, at), (what, offset));
        }
    }
    // A record or a value longer than what is left.
    let record = usize::try_from(get32(&v1, find(&v1, b"IDSS") + 12)).unwrap();
    let mut bytes = v1.clone();
    set32(&mut bytes, record, u32::MAX);
    assert!(matches!(ResourceIndex::parse(&bytes), Err(ResourceIndexError::Truncated { what: "record", .. })));
    let mut bytes = v1.clone();
    bytes[record + 12..record + 14].copy_from_slice(&u16::MAX.to_le_bytes());
    assert!(matches!(ResourceIndex::parse(&bytes), Err(ResourceIndexError::Truncated { what: "record value", .. })));
}

#[test]
fn contradicting_tables() {
    let [v1, v2] = both();
    let row = find(&v1, b"IDSS") + 8;
    let mut bytes = v1.clone();
    set32(&mut bytes, row, 0x0100_00ff);
    assert!(matches!(ResourceIndex::parse(&bytes), Err(ResourceIndexError::IdMismatch { listed: 0x0100_00ff, found: 0x0100_0000, .. })));

    let item = find(&v2, b"IDSS") + 16 + 12;
    let mut bytes = v2.clone();
    set32(&mut bytes, item, 0x0100_00ff);
    assert!(matches!(ResourceIndex::parse(&bytes), Err(ResourceIndexError::IdMismatch { listed: 0x0100_00ff, found: 0x0100_0000, .. })));
    let info = usize::try_from(get32(&v2, item + 4)).unwrap();
    let mut bytes = v2.clone();
    set32(&mut bytes, info + 12, 3);
    assert_eq!(ResourceIndex::parse(&bytes).unwrap_err(), ResourceIndexError::UnknownQualifiers { id: 0x0100_0000, config: 3 });
}

#[test]
fn shared_tables_cannot_multiply() {
    // First layout: 300 qualifier sets that all use one id table of 300
    // rows, each row the same record: 90 000 values in under 7 KiB.
    const N: usize = 300;
    let mut bytes = header("Restool 5.0");
    let table = 136 + 12 * N;
    let record = table + 8 + 8 * N;
    put32(&mut bytes, 0);
    put32(&mut bytes, N);
    for _ in 0..N {
        bytes.extend(b"KEYS");
        put32(&mut bytes, table);
        put32(&mut bytes, 0);
    }
    bytes.extend(b"IDSS");
    put32(&mut bytes, N);
    for _ in 0..N {
        put32(&mut bytes, 7);
        put32(&mut bytes, record);
    }
    put32(&mut bytes, 8 + 2 + 2 + 2 + 2);
    put32(&mut bytes, 9);
    put32(&mut bytes, 7);
    bytes.extend([2, 0, b'v', 0, 2, 0, b'n', 0]);
    assert_eq!(ResourceIndex::parse(&bytes).unwrap_err(), ResourceIndexError::TooManyValues { limit: bytes.len() / 8 });

    // The same table used once is an ordinary index.
    set32(&mut bytes, 132, 1);
    assert_eq!(ResourceIndex::parse(&bytes).unwrap().len(), N);

    // Second layout: 300 names that all point at one list of 300 values.
    let mut bytes = header("RestoolV2 6.0");
    let data = 140 + 12 + 16 + 12 + 13 * N;
    put32(&mut bytes, 0);
    put32(&mut bytes, 1);
    put32(&mut bytes, data);
    bytes.extend(b"KEYS");
    put32(&mut bytes, 0);
    put32(&mut bytes, 0);
    bytes.extend(b"IDSS");
    put32(&mut bytes, 0);
    put32(&mut bytes, 1);
    put32(&mut bytes, N);
    put32(&mut bytes, 9);
    put32(&mut bytes, 0);
    put32(&mut bytes, N);
    for _ in 0..N {
        put32(&mut bytes, 7);
        put32(&mut bytes, data + 12);
        put32(&mut bytes, 1);
        bytes.push(b'n');
    }
    assert_eq!(bytes.len(), data);
    bytes.extend(b"DATA");
    put32(&mut bytes, 0);
    put32(&mut bytes, 1);
    put32(&mut bytes, 7);
    put32(&mut bytes, 0);
    put32(&mut bytes, N);
    let value = data + 12 + 12 + 8 * N;
    for _ in 0..N {
        put32(&mut bytes, 0);
        put32(&mut bytes, value);
    }
    bytes.extend([1, 0, b'v']);
    assert_eq!(ResourceIndex::parse(&bytes).unwrap_err(), ResourceIndexError::TooManyValues { limit: bytes.len() / 8 });
}

#[test]
fn a_record_may_point_at_itself() {
    // Offsets that loop back are only ever read as data: a record whose
    // offset is the id table itself parses or fails, but terminates.
    let [v1, v2] = both();
    let table = find(&v1, b"IDSS");
    let mut bytes = v1.clone();
    set32(&mut bytes, table + 12, u32::try_from(table).unwrap());
    assert!(ResourceIndex::parse(&bytes).is_err());
    let item = find(&v2, b"IDSS") + 16 + 12;
    let mut bytes = v2.clone();
    set32(&mut bytes, item + 4, u32::try_from(item).unwrap());
    // The row is its own value list: the id matches, the name length is
    // read as a value count.
    exercise(&bytes);
}
