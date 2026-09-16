use asc_dex::Dex;
use asc_findrefs::{ClassQuery, CompiledQuery, FindRefs, IdxSet, InsnLocator, MemberQuery, MethodRef, Query, RefKind, StringLocator};
use asc_fixture::{make_dex, make_static_field_dex};
use std::collections::BTreeSet;

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn search(data: &[u8]) -> Vec<Option<MethodRef>> {
    let dex = Dex::with_name(data, "fixture.dex").unwrap();
    let fr = FindRefs::new(&dex);
    let idxs: BTreeSet<u32> = [5].into_iter().collect();
    fr.scan_idxs(RefKind::String, &idxs).unwrap().into_iter().map(|h| h.methods).collect()
}

fn ids(m: &Option<MethodRef>) -> BTreeSet<u32> {
    m.as_ref().unwrap().ids().iter().copied().collect()
}

#[test]
fn shared_code_keeps_method_zero() {
    let results = search(&make_dex());
    assert_eq!(results.len(), 1);
    assert_eq!(ids(&results[0]), [0, 1].into_iter().collect());
}

#[test]
fn repeated_scans_preserve_method_bounds() {
    let data = make_dex();
    let dex = Dex::parse(&data).unwrap();
    let fr = FindRefs::new(&dex);
    let before = fr.insn_locator().unwrap().method_bounds().to_vec();
    for _ in 0..2 {
        let hits = fr.find_ref(&Query::String("token".into())).unwrap();
        assert_eq!(ids(&hits[0].methods), [0, 1].into_iter().collect());
        assert_eq!(fr.insn_locator().unwrap().method_bounds(), &before[..]);
    }
}

#[test]
fn fallback_without_class_data_map_entry() {
    let mut data = make_dex();
    let map_off = u32_at(&data, 52) as usize;
    let count = u32_at(&data, map_off) as usize;
    for off in (map_off + 4..map_off + 4 + count * 12).step_by(12) {
        if u16::from_le_bytes([data[off], data[off + 1]]) == 0x2000 {
            data[off..off + 2].copy_from_slice(&0xffffu16.to_le_bytes());
        }
    }
    assert_eq!(ids(&search(&data)[0]), [0, 1].into_iter().collect());
}

#[test]
fn empty_or_absent_map_uses_class_definitions() {
    for empty in [true, false] {
        let mut data = make_dex();
        let map_off = u32_at(&data, 52) as usize;
        let target = if empty { map_off } else { 52 };
        data[target..target + 4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(ids(&search(&data)[0]), [0, 1].into_iter().collect(), "empty={empty}");
    }
}

#[test]
fn class_without_method_bodies_has_no_references() {
    let mut data = make_dex();
    let class_off = u32_at(&data, 100) as usize;
    let class_data = u32_at(&data, class_off + 24) as usize;
    data[class_data..class_data + 10].copy_from_slice(b"\0\0\x02\0\0\x09\0\x01\x09\0");
    assert!(search(&data).is_empty());
}

#[test]
fn last_string_is_searchable() {
    let data = make_dex();
    let dex = Dex::parse(&data).unwrap();
    let loc = StringLocator::build(&dex).unwrap();
    assert_eq!(loc.locate_pattern(dex.buf(), "token").unwrap(), [5].into_iter().collect());
    assert_eq!(loc.locate_pattern(dex.buf(), "first").unwrap(), [3].into_iter().collect());
    assert!(loc.locate_pattern(dex.buf(), "").unwrap().is_empty());
    let re = regex::bytes::Regex::new("first|second").unwrap();
    assert_eq!(loc.locate(dex.buf(), &re), [3, 4].into_iter().collect());
}

#[test]
fn empty_string_table() {
    let mut data = make_dex();
    data[56..64].copy_from_slice(&[0u8; 8]);
    let dex = Dex::parse(&data).unwrap();
    let loc = StringLocator::build(&dex).unwrap();
    assert!(loc.locate_pattern(dex.buf(), "token").unwrap().is_empty());
    assert_eq!(loc.string_count(), 0);
}

#[test]
fn member_queries() {
    let data = make_dex();
    let dex = Dex::parse(&data).unwrap();
    let fr = FindRefs::new(&dex);
    let precise = |name: Option<&str>| {
        Query::Method(MemberQuery {
            class: Some(ClassQuery { pattern: "Lexample/Test;".into(), precise: true }),
            name: name.map(String::from),
        })
    };
    assert_eq!(fr.locate(&precise(None)).unwrap(), [0, 1].into_iter().collect());
    assert_eq!(fr.locate(&precise(Some("sec"))).unwrap(), [1].into_iter().collect());
    let fuzzy =
        Query::Method(MemberQuery { class: Some(ClassQuery { pattern: "example".into(), precise: false }), name: Some("first".into()) });
    assert_eq!(fr.locate(&fuzzy).unwrap(), [0].into_iter().collect());
    let by_name = Query::Method(MemberQuery { class: None, name: Some("(first|second)".into()) });
    assert_eq!(fr.locate(&by_name).unwrap(), [0, 1].into_iter().collect());
    let set: IdxSet = [1u32, 70].into_iter().collect();
    assert!(set.contains(70) && !set.contains(2));
    // Nothing to match on: empty result, no error.
    let none = Query::Method(MemberQuery { class: None, name: None });
    assert!(fr.locate(&none).unwrap().is_empty());
    let empty_class = Query::Method(MemberQuery { class: Some(ClassQuery { pattern: String::new(), precise: true }), name: None });
    assert!(fr.locate(&empty_class).unwrap().is_empty());
    // Invalid regex surfaces as a pattern error.
    assert!(fr.locate(&Query::String("(".into())).is_err());
    assert!(fr.find_ref(&Query::Type("[".into())).is_err());
}

#[test]
fn compiled_queries_match_plain_queries() {
    let queries = vec![
        Query::String("token".into()),
        Query::String("tok".into()),
        Query::String("^V$".into()),
        Query::String(String::new()),
        Query::Type("example".into()),
        Query::Type("Ljava/lang/Object;".into()),
        Query::Type("nothing-here".into()),
        Query::Method(MemberQuery { class: Some(ClassQuery { pattern: "Lexample/Test;".into(), precise: true }), name: None }),
        Query::Method(MemberQuery {
            class: Some(ClassQuery { pattern: "Lexample/Test;".into(), precise: true }),
            name: Some("sec".into()),
        }),
        Query::Method(MemberQuery { class: Some(ClassQuery { pattern: "example".into(), precise: false }), name: Some("first".into()) }),
        Query::Method(MemberQuery { class: None, name: Some("(first|second)".into()) }),
        Query::Method(MemberQuery { class: None, name: None }),
        Query::Field(MemberQuery { class: None, name: Some("SECOND".into()) }),
        Query::Field(MemberQuery {
            class: Some(ClassQuery { pattern: "Lexample/Statics;".into(), precise: true }),
            name: Some("FIR".into()),
        }),
        Query::Field(MemberQuery { class: Some(ClassQuery { pattern: "Statics".into(), precise: false }), name: None }),
    ];
    for data in [make_dex(), make_static_field_dex()] {
        let dex = Dex::parse(&data).unwrap();
        let fr = FindRefs::new(&dex);
        for q in &queries {
            let compiled = CompiledQuery::new(q).unwrap();
            assert_eq!(compiled.kind(), q.kind());
            assert_eq!(compiled.query(), q);
            assert_eq!(fr.locate_compiled(&compiled).unwrap(), fr.locate(q).unwrap(), "locate {q:?}");
            assert_eq!(fr.find_ref_compiled(&compiled).unwrap(), fr.find_ref(q).unwrap(), "find_ref {q:?}");
        }
    }
    // The compiled query is reusable across DEX files and threads.
    let compiled = CompiledQuery::new(&Query::Field(MemberQuery { class: None, name: Some("SECOND".into()) })).unwrap();
    let data = make_static_field_dex();
    std::thread::scope(|s| {
        for _ in 0..2 {
            s.spawn(|| {
                let dex = Dex::parse(&data).unwrap();
                let hits = FindRefs::new(&dex).find_ref_compiled(&compiled).unwrap();
                assert_eq!(hits.len(), 1);
                assert_eq!(hits[0].matched_idx, 1);
                assert_eq!(hits[0].methods, Some(MethodRef::Single(0)));
            });
        }
    });
}

#[test]
fn search_state_is_reusable() {
    let data = make_dex();
    let dex = Dex::parse(&data).unwrap();
    let state = asc_findrefs::SearchState::new();
    assert!(!state.is_warm());
    let hits = FindRefs::with_state(&dex, &state).find_ref(&Query::String("token".into())).unwrap();
    assert_eq!(hits.len(), 1);
    assert!(state.is_warm());
    let again = FindRefs::with_state(&dex, &state).find_ref(&Query::String("token".into())).unwrap();
    assert_eq!(hits, again);
}

/// Offset of the single code_item in `make_dex()`.
fn code_item_off(data: &[u8]) -> usize {
    let map_off = u32_at(data, 52) as usize;
    let count = u32_at(data, map_off) as usize;
    (map_off + 4..map_off + 4 + count * 12)
        .step_by(12)
        .find(|&off| u16::from_le_bytes([data[off], data[off + 1]]) == 0x2001)
        .map(|off| u32_at(data, off + 8) as usize)
        .expect("code map item")
}

#[test]
fn malformed_code_items_do_not_panic_or_over_allocate() {
    let data = make_dex();
    let code = code_item_off(&data);
    let dex = Dex::parse(&data).unwrap();
    let good = InsnLocator::build(&dex).unwrap();
    assert_eq!(good.bucket_count(), 1);
    assert!(good.table_len() <= data.len() / 16 + 1);

    // insns_size that runs past the end of the buffer.
    for size in [u32::MAX, 0x8000_0000, (data.len() as u32) / 2, (data.len() - code - 16) as u32 / 2 + 1] {
        let mut bad = data.clone();
        bad[code + 12..code + 16].copy_from_slice(&size.to_le_bytes());
        let dex = Dex::parse(&bad).unwrap();
        let loc = InsnLocator::build(&dex).unwrap();
        assert_eq!(loc.bucket_count(), 0, "insns_size {size:#x}");
        assert!(loc.table_len() <= bad.len() / 16 + 1);
        assert_eq!(loc.code_item_start(), loc.code_item_end());
        assert!(loc.get(code as u32 + 16).is_none());
        assert!(search(&bad).is_empty());
    }

    // code_off (a 2-byte uleb128 in the fixture) pointing far past the buffer
    // for both methods.
    let class_off = u32_at(&data, 100) as usize;
    let class_data = u32_at(&data, class_off + 24) as usize;
    let mut bad = data.clone();
    for p in [class_data + 6, class_data + 10] {
        assert_eq!(
            &bad[p..p + 2],
            &{
                let mut v = Vec::new();
                asc_dex::leb128::write_uleb128(&mut v, code as u32);
                v
            }[..]
        );
        bad[p..p + 2].copy_from_slice(&[0xff, 0x7f]); // 16383
    }
    let dex = Dex::parse(&bad).unwrap();
    let loc = InsnLocator::build(&dex).unwrap();
    assert_eq!(loc.bucket_count(), 0);
    assert!(loc.table_len() <= bad.len() / 16 + 1);
    assert!(search(&bad).is_empty());

    // A code_off just inside the buffer whose header is truncated.
    let mut bad = data.clone();
    let tail = (bad.len() - 8) as u32;
    let mut enc = Vec::new();
    asc_dex::leb128::write_uleb128(&mut enc, tail);
    if enc.len() == 2 {
        bad[class_data + 6..class_data + 8].copy_from_slice(&enc);
        let dex = Dex::parse(&bad).unwrap();
        let loc = InsnLocator::build(&dex).unwrap();
        // Only the second method (still valid) contributes.
        assert_eq!(loc.bucket_count(), 1);
        assert_eq!(loc.get(code as u32 + 16), Some(MethodRef::Single(1)));
    }

    // A header method count far beyond the buffer must not blow up the
    // method table.
    let mut bad = data;
    bad[88..92].copy_from_slice(&u32::MAX.to_le_bytes());
    let dex = Dex::parse(&bad).unwrap();
    let loc = InsnLocator::build(&dex).unwrap();
    assert!(loc.method_bounds().len() <= bad.len() / 8);
    assert_eq!(loc.bucket_count(), 1);
}

#[test]
fn out_of_range_indexes_are_ignored_without_allocating() {
    let data = make_dex();
    let dex = Dex::with_name(&data, "fixture.dex").unwrap();
    let fr = FindRefs::new(&dex);
    // Indexes that no id table of this DEX can hold must not make the dense
    // bitset grow (u32::MAX alone would be a 512 MiB allocation).
    let idxs: BTreeSet<u32> = [u32::MAX, 1 << 30, data.len() as u32].into_iter().collect();
    assert!(fr.scan_idxs(RefKind::String, &idxs).unwrap().is_empty());
    // Mixing them with a real index still finds the real one.
    let idxs: BTreeSet<u32> = [5, u32::MAX].into_iter().collect();
    let hits = fr.scan_idxs(RefKind::String, &idxs).unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].matched_idx, 5);
}

#[test]
fn self_overlapping_operand_is_found_end_to_end() {
    // `const-string v0, string@0` is encoded `1a 00 00 00`: the operand needle
    // `00 00` also matches one byte early at the register byte, and a
    // non-overlapping search would skip the real candidate. This is the most
    // common real-world shape of the bug (register 0, index 0).
    let data = make_dex();
    let code = code_item_off(&data);
    let insns = code + 16;
    let mut patched = data.clone();
    let p = (insns..data.len() - 3).find(|&p| patched[p] == 0x1a && patched[p + 2] == 5 && patched[p + 3] == 0).expect("const-string 5");
    patched[p + 1..p + 4].copy_from_slice(&[0, 0, 0]);
    let dex = Dex::with_name(&patched, "fixture.dex").unwrap();
    let fr = FindRefs::new(&dex);
    let idxs: BTreeSet<u32> = [0].into_iter().collect();
    let hits = fr.scan_idxs(RefKind::String, &idxs).unwrap();
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert_eq!(hits[0].offset as usize, p);
    assert_eq!(hits[0].matched_idx, 0);
    assert_eq!(ids(&hits[0].methods), [0, 1].into_iter().collect());
}
