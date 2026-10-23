use super::*;

fn chunk(kind: u16, header: &[u8], body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&kind.to_le_bytes());
    v.extend_from_slice(&((8 + header.len()) as u16).to_le_bytes());
    v.extend_from_slice(&((8 + header.len() + body.len()) as u32).to_le_bytes());
    v.extend_from_slice(header);
    v.extend_from_slice(body);
    v
}

fn pool(strings: &[&str], utf8: bool) -> Vec<u8> {
    let mut offsets = Vec::new();
    let mut sdata = Vec::new();
    for s in strings {
        offsets.extend_from_slice(&(sdata.len() as u32).to_le_bytes());
        if utf8 {
            sdata.push(s.chars().count() as u8);
            sdata.push(s.len() as u8);
            sdata.extend_from_slice(s.as_bytes());
            sdata.push(0);
        } else {
            let units: Vec<u16> = s.encode_utf16().collect();
            sdata.extend_from_slice(&(units.len() as u16).to_le_bytes());
            units.iter().for_each(|u| sdata.extend_from_slice(&u.to_le_bytes()));
            sdata.extend_from_slice(&[0, 0]);
        }
    }
    while sdata.len() % 4 != 0 {
        sdata.push(0);
    }
    let mut header = Vec::new();
    header.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&(if utf8 { 1u32 << 8 } else { 0 }).to_le_bytes());
    header.extend_from_slice(&((28 + offsets.len()) as u32).to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    chunk(RES_STRING_POOL_TYPE, &header, &[offsets, sdata].concat())
}

fn config(set: impl FnOnce(&mut [u8; 64])) -> [u8; 64] {
    let mut c = [0u8; 64];
    c[0..4].copy_from_slice(&64u32.to_le_bytes());
    set(&mut c);
    c
}

fn simple(key: u32, kind: u8, data: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&8u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&key.to_le_bytes());
    v.extend_from_slice(&8u16.to_le_bytes());
    v.push(0);
    v.push(kind);
    v.extend_from_slice(&data.to_le_bytes());
    v
}

fn compact(key: u16, kind: u8, data: u32) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&key.to_le_bytes());
    v.extend_from_slice(&(ENTRY_FLAG_COMPACT | (kind as u16) << 8).to_le_bytes());
    v.extend_from_slice(&data.to_le_bytes());
    v
}

fn bag(key: u32, parent: u32, items: &[(u32, u8, u32)]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&16u16.to_le_bytes());
    v.extend_from_slice(&ENTRY_FLAG_COMPLEX.to_le_bytes());
    v.extend_from_slice(&key.to_le_bytes());
    v.extend_from_slice(&parent.to_le_bytes());
    v.extend_from_slice(&(items.len() as u32).to_le_bytes());
    for &(name, kind, data) in items {
        v.extend_from_slice(&name.to_le_bytes());
        v.extend_from_slice(&8u16.to_le_bytes());
        v.push(0);
        v.push(kind);
        v.extend_from_slice(&data.to_le_bytes());
    }
    v
}

#[derive(Clone, Copy)]
enum Enc {
    U32,
    Off16,
    Sparse,
}

fn type_chunk(id: u8, cfg: [u8; 64], entries: &[Option<Vec<u8>>], enc: Enc) -> Vec<u8> {
    let mut offsets = Vec::new();
    let mut body = Vec::new();
    let mut present = 0u32;
    for (i, e) in entries.iter().enumerate() {
        match (e, enc) {
            (Some(_), Enc::U32) => offsets.extend_from_slice(&(body.len() as u32).to_le_bytes()),
            (Some(_), Enc::Off16) => offsets.extend_from_slice(&((body.len() / 4) as u16).to_le_bytes()),
            (Some(_), Enc::Sparse) => {
                offsets.extend_from_slice(&(i as u16).to_le_bytes());
                offsets.extend_from_slice(&((body.len() / 4) as u16).to_le_bytes());
            }
            (None, Enc::U32) => offsets.extend_from_slice(&NO_ENTRY.to_le_bytes()),
            (None, Enc::Off16) => offsets.extend_from_slice(&NO_ENTRY16.to_le_bytes()),
            (None, Enc::Sparse) => {}
        }
        if let Some(e) = e {
            body.extend_from_slice(e);
            present += 1;
        }
    }
    while offsets.len() % 4 != 0 {
        offsets.push(0);
    }
    let (flags, count) = match enc {
        Enc::U32 => (0u8, entries.len() as u32),
        Enc::Off16 => (TYPE_FLAG_OFFSET16, entries.len() as u32),
        Enc::Sparse => (TYPE_FLAG_SPARSE, present),
    };
    let mut header = vec![id, flags, 0, 0];
    header.extend_from_slice(&count.to_le_bytes());
    header.extend_from_slice(&((8 + 12 + 64 + offsets.len()) as u32).to_le_bytes());
    header.extend_from_slice(&cfg);
    chunk(RES_TABLE_TYPE_TYPE, &header, &[offsets, body].concat())
}

fn type_spec(id: u8, flags: &[u32]) -> Vec<u8> {
    let mut header = vec![id, 0, 0, 0];
    header.extend_from_slice(&(flags.len() as u32).to_le_bytes());
    let body: Vec<u8> = flags.iter().flat_map(|f| f.to_le_bytes()).collect();
    chunk(RES_TABLE_TYPE_SPEC_TYPE, &header, &body)
}

fn utf16_field(s: &str, units: usize) -> Vec<u8> {
    let mut v: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    v.resize(units * 2, 0);
    v
}

fn package(id: u32, name: &str, types: &[&str], keys: &[&str], children: &[Vec<u8>]) -> Vec<u8> {
    let tp = pool(types, false);
    let kp = pool(keys, true);
    let mut header = Vec::new();
    header.extend_from_slice(&id.to_le_bytes());
    header.extend_from_slice(&utf16_field(name, 128));
    header.extend_from_slice(&(PACKAGE_HEADER_SIZE as u32).to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&((PACKAGE_HEADER_SIZE + tp.len()) as u32).to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes());
    let body = [vec![tp, kp], children.to_vec()].concat().concat();
    chunk(RES_TABLE_PACKAGE_TYPE, &header, &body)
}

fn table(strings: &[&str], packages: &[Vec<u8>]) -> Vec<u8> {
    let body = [vec![pool(strings, false)], packages.to_vec()].concat().concat();
    chunk(RES_TABLE_TYPE, &(packages.len() as u32).to_le_bytes(), &body)
}

const APP_NAME: u32 = 0x7f01_0000;
const ALIAS: u32 = 0x7f01_0001;
const THEME: u32 = 0x7f02_0000;
const FLAG: u32 = 0x7f03_0000;
const LOOP_A: u32 = 0x7f01_0002;
const LOOP_B: u32 = 0x7f01_0003;
const ARRAY: u32 = 0x7f04_0000;

fn sample() -> Vec<u8> {
    let strings = ["Hello", "你好", "item\n2", "res/xml/a.xml"];
    let types = ["string", "style", "bool", "array"];
    let keys = ["app_name", "alias", "Theme", "flag", "loop_a", "loop_b", "items"];
    let default = config(|_| {});
    let zh = config(|c| c[8..10].copy_from_slice(b"zh"));
    let v21 = config(|c| c[24..26].copy_from_slice(&21u16.to_le_bytes()));
    let library = {
        let mut body = 0x02u32.to_le_bytes().to_vec();
        body.extend_from_slice(&utf16_field("com.lib", 128));
        chunk(RES_TABLE_LIBRARY_TYPE, &1u32.to_le_bytes(), &body)
    };
    let staged = {
        let body = [0x0101_0000u32.to_le_bytes(), 0x0101_0001u32.to_le_bytes()].concat();
        chunk(RES_TABLE_STAGED_ALIAS_TYPE, &1u32.to_le_bytes(), &body)
    };
    let overlayable = {
        let policy = chunk(RES_TABLE_OVERLAYABLE_POLICY_TYPE, &[1u32.to_le_bytes(), 1u32.to_le_bytes()].concat(), &FLAG.to_le_bytes());
        let header = [utf16_field("Ov", 256), utf16_field("actor", 256)].concat();
        chunk(RES_TABLE_OVERLAYABLE_TYPE, &header, &policy)
    };
    let pkg = package(
        0x7f,
        "com.example",
        &types,
        &keys,
        &[
            type_spec(1, &[SPEC_PUBLIC, 0, 0, 0]),
            type_chunk(
                1,
                default,
                &[
                    Some(simple(0, TYPE_STRING, 0)),
                    Some(simple(1, TYPE_REFERENCE, APP_NAME)),
                    Some(simple(4, TYPE_REFERENCE, LOOP_B)),
                    Some(simple(5, TYPE_REFERENCE, LOOP_A)),
                ],
                Enc::U32,
            ),
            type_chunk(1, zh, &[Some(simple(0, TYPE_STRING, 1)), None, None, None], Enc::Sparse),
            type_spec(2, &[0]),
            type_chunk(2, default, &[Some(bag(2, 0x0103_0005, &[(0x0101_0003, TYPE_STRING, 0), (FLAG, TYPE_REFERENCE, FLAG)]))], Enc::U32),
            type_chunk(3, default, &[Some(simple(3, TYPE_INT_BOOLEAN, 1))], Enc::Off16),
            type_chunk(3, v21, &[Some(compact(3, TYPE_INT_BOOLEAN, 0))], Enc::U32),
            type_chunk(4, default, &[Some(bag(6, 0, &[(0x0200_0000, TYPE_STRING, 2), (0x0100_0002, TYPE_INT_DEC, 7)]))], Enc::U32),
            library,
            staged,
            overlayable,
        ],
    );
    table(&strings, &[pkg])
}

#[test]
fn names_lookup_and_values() {
    let t = ResTable::parse(sample()).unwrap();
    assert!(t.warnings().is_empty(), "{:?}", t.warnings());
    assert_eq!(t.name(APP_NAME).unwrap().to_string(), "com.example:string/app_name");
    assert_eq!(t.name(FLAG).unwrap().short(), "bool/flag");
    assert_eq!(t.lookup("string/app_name"), Some(APP_NAME));
    assert_eq!(t.lookup("@com.example:bool/flag"), Some(FLAG));
    assert_eq!(t.lookup("string/nope"), None);
    assert_eq!(t.name(0x7f01_0009), None);
    assert_eq!(t.ids(), vec![APP_NAME, ALIAS, LOOP_A, LOOP_B, THEME, FLAG, ARRAY]);
    assert_eq!(t.spec_flags(APP_NAME), Some(SPEC_PUBLIC));

    let v = t.values(APP_NAME);
    assert_eq!(v.len(), 2);
    assert_eq!(v[1].config.to_string(), "zh");
    assert_eq!(t.format_entry(APP_NAME, &v[1].value), "\"你好\"");
    // Offset16 in the default config, compact entry in v21.
    let v = t.values(FLAG);
    assert_eq!(
        v.iter().map(|v| (v.config.to_string(), t.format_entry(FLAG, &v.value))).collect::<Vec<_>>(),
        [(String::new(), "true".to_string()), ("v21".to_string(), "false".to_string())]
    );
    assert_eq!(
        t.format_entry(THEME, &t.values(THEME)[0].value),
        "{parent=@android:0x01030005 android:name=\"Hello\" bool/flag=@bool/flag}"
    );
    assert_eq!(t.format_entry(ARRAY, &t.values(ARRAY)[0].value), "{[0]=\"item\\n2\" [1]=7}");

    let p = &t.packages()[0];
    assert_eq!(p.libraries, [Library { package_id: 2, name: "com.lib".into() }]);
    assert_eq!(p.staged_aliases, [StagedAlias { staged: 0x0101_0000, finalized: 0x0101_0001 }]);
    assert_eq!(p.overlayables[0].actor, "actor");
    assert_eq!(p.overlayables[0].policies, [OverlayablePolicy { flags: 1, ids: vec![FLAG] }]);

    let mut strings = Vec::new();
    t.for_each_string(|id, c, s| strings.push((id, c.to_string(), s.to_string())));
    assert_eq!(
        strings,
        [
            (APP_NAME, String::new(), "Hello".to_string()),
            (APP_NAME, "zh".to_string(), "你好".to_string()),
            (THEME, String::new(), "Hello".to_string()),
            (ARRAY, String::new(), "item\n2".to_string()),
        ]
    );
}

#[test]
fn resolve_follows_references_by_config() {
    let t = ResTable::parse(sample()).unwrap();
    let r = t.resolve_default(ALIAS).unwrap();
    assert_eq!(r.chain, [ALIAS, APP_NAME]);
    assert_eq!(t.format_entry(APP_NAME, &r.value), "\"Hello\"");
    let zh = Config { language: *b"zh", sdk_version: 34, ..Config::default() };
    assert_eq!(t.format_entry(APP_NAME, &t.resolve(ALIAS, &zh).unwrap().value), "\"你好\"");
    // v21 wins on a new device, the default on an old one.
    assert_eq!(t.format_entry(FLAG, &t.resolve_default(FLAG).unwrap().value), "false");
    let old = Config { sdk_version: 19, ..Config::default() };
    assert_eq!(t.format_entry(FLAG, &t.resolve(FLAG, &old).unwrap().value), "true");
    assert_eq!(t.resolve_default(LOOP_A), Err(ResolveError::Cycle(vec![LOOP_A, LOOP_B, LOOP_A])));
    assert_eq!(t.resolve_default(0x7f09_0000), Err(ResolveError::NotFound(0x7f09_0000)));
    // A value only defined for zh still resolves, flagged as a fallback.
    let en = Config { language: *b"en", ..Config::any_device() };
    let mut only_zh = t.resolve(APP_NAME, &en).unwrap();
    assert!(!only_zh.fallback, "default config matches en");
    only_zh = t.resolve(THEME, &en).unwrap();
    assert!(matches!(only_zh.value, EntryValue::Bag { parent: 0x0103_0005, .. }));
}

#[test]
fn malformed_tables_never_panic() {
    let good = sample();
    assert!(matches!(ResTable::parse(Vec::new()), Err(ArscError::NotArsc)));
    for cut in 0..good.len() {
        if let Ok(t) = ResTable::parse(good[..cut].to_vec()) {
            exercise(&t);
        }
    }
    // Flip every byte to a few hostile values.
    for i in 0..good.len() {
        for b in [0x00, 0x7f, 0xff] {
            let mut bad = good.clone();
            bad[i] = b;
            if let Ok(t) = ResTable::parse(bad) {
                exercise(&t);
            }
        }
    }
}

fn exercise(t: &ResTable) {
    for id in t.ids().into_iter().chain([APP_NAME, ALIAS, THEME, FLAG, LOOP_A, ARRAY]) {
        let _ = t.name(id);
        for v in t.values(id) {
            let _ = t.format_entry(id, &v.value);
            let _ = v.config.to_string();
        }
        let _ = t.resolve_default(id);
    }
    let _ = t.lookup("string/app_name");
    t.for_each_string(|_, _, _| {});
}

#[test]
fn damaged_chunks_are_skipped_with_a_warning() {
    let mut data = sample();
    // Point the first type chunk's entriesStart past its end: that chunk is
    // dropped, everything else still parses.
    let at = find_type_chunk(&data);
    data[at + 16..at + 20].copy_from_slice(&0xffff_0000u32.to_le_bytes());
    let t = ResTable::parse(data).unwrap();
    assert_eq!(t.warnings().len(), 1, "{:?}", t.warnings());
    assert_eq!(t.values(APP_NAME).len(), 1, "zh value survives");
    assert!(t.contains(FLAG));
}

/// Offset of the first type chunk (by its type and header-size bytes).
fn find_type_chunk(data: &[u8]) -> usize {
    let kind = RES_TABLE_TYPE_TYPE.to_le_bytes();
    let hs = (8 + 12 + 64u16).to_le_bytes();
    (0..data.len() - 4).find(|&i| data[i..i + 2] == kind && data[i + 2..i + 4] == hs).unwrap()
}
