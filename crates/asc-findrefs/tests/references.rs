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
fn anchors_apply_to_each_string() {
    let data = make_dex();
    let dex = Dex::parse(&data).unwrap();
    let loc = StringLocator::build(&dex).unwrap();
    let find = |p: &str| loc.locate_pattern(dex.buf(), p).unwrap().into_iter().collect::<Vec<_>>();
    // Strings: Lexample/Test; Ljava/lang/Object; V first second token
    assert_eq!(find("^first$"), [3]);
    assert_eq!(find("^L"), [0, 1]);
    assert_eq!(find(";$"), [0, 1]);
    assert_eq!(find(r"\Aseco"), [4]);
    assert_eq!(find("(?m)^V$"), [2]);
    assert!(find("^irst").is_empty() && find("^firs$").is_empty());
    // `[^...]` is a class, not an anchor: still one pass over the region.
    assert_eq!(find("[^a-z]oken"), Vec::<u32>::new());
}

#[test]
fn matches_never_run_from_one_string_into_the_next() {
    let data = make_dex();
    let dex = Dex::parse(&data).unwrap();
    let loc = StringLocator::build(&dex).unwrap();
    let find = |p: &str| loc.locate_pattern(dex.buf(), p).unwrap().into_iter().collect::<Vec<_>>();
    // Strings: Lexample/Test; Ljava/lang/Object; V first second token
    // Over the whole region `st.{2}se` would join "first" to "second".
    assert!(find("st.{2}se").is_empty() && find("st[^x]+se").is_empty());
    // A greedy match from the first string across all of them must not hide
    // the strings that match alone.
    assert_eq!(find("e.*n"), [4, 5]);
    assert_eq!(find("irst[^z]*"), [3]);
    // A spelled NUL is the terminator: class patterns end descriptors so.
    assert_eq!(find(r";\x00"), [0, 1]);
    assert_eq!(find(r"[/L]Test;\x00"), [0]);
    assert!(find(r"t\x00s").is_empty());
    // Word boundaries see each string's edges, not the length prefix.
    assert_eq!(find(r"\btoken"), [5]);
}

#[test]
fn method_sets_are_the_union_of_their_members() {
    let data = make_dex();
    let dex = Dex::parse(&data).unwrap();
    let fr = FindRefs::new(&dex);
    let member = |name: &str| MemberQuery { name: Some(name.into()), exact_name: true, ..Default::default() };
    let one = |name: &str| fr.locate(&Query::Method(member(name))).unwrap();
    let all: BTreeSet<u32> = ["first", "second"].iter().flat_map(|n| one(n)).collect();
    let set = Query::MethodSet(vec![member("first"), member("second"), member("absent")]);
    assert_eq!(fr.locate(&set).unwrap(), all);
    assert!(fr.locate(&Query::MethodSet(Vec::new())).unwrap().is_empty());
    let err = CompiledQuery::new(&Query::Nested(Box::new(Query::String("x".into())))).unwrap_err().to_string();
    assert!(err.contains("resolved over every DEX"), "{err}");
}

#[test]
fn literal_strings_are_plain_substrings() {
    let data = make_dex();
    let dex = Dex::parse(&data).unwrap();
    let fr = FindRefs::new(&dex);
    let lit = |s: &str| fr.locate(&Query::StringLiteral(s.into())).unwrap();
    let set = |v: &[u32]| v.iter().copied().collect::<BTreeSet<u32>>();
    // Strings: Lexample/Test; Ljava/lang/Object; V first second token
    assert_eq!(lit("e"), set(&[0, 1, 4, 5]));
    assert_eq!(lit("/"), set(&[0, 1]));
    assert_eq!(lit("Object;"), set(&[1]));
    // Regex syntax is literal: `.` is a dot (no string has one), `f|s` a bar.
    assert!(lit(".").is_empty() && lit("f|s").is_empty() && lit("^t").is_empty());
    assert_eq!(fr.locate(&Query::String(".".into())).unwrap().len(), 6);
    assert!(lit("").is_empty());
    assert!(lit("tokens").is_empty());
    // Same set as the escaped regex for every substring of every string.
    let words = ["Lexample/Test;", "Ljava/lang/Object;", "V", "first", "second", "token"];
    for w in words {
        for i in 0..w.len() {
            for j in i + 1..=w.len() {
                let needle = &w[i..j];
                assert_eq!(lit(needle), fr.locate(&Query::String(regex::escape(needle))).unwrap(), "{needle}");
            }
        }
    }
    // End to end: the code scan runs on the located strings like a regex query.
    let hits = fr.find_ref(&Query::StringLiteral("oke".into())).unwrap();
    assert_eq!(hits, fr.find_ref(&Query::String("oke".into())).unwrap());
    assert_eq!(hits.len(), 1);
}

#[test]
fn class_relations_resolve_without_a_code_scan() {
    let data = make_dex();
    let dex = Dex::parse(&data).unwrap();
    let fr = FindRefs::new(&dex);
    let q = CompiledQuery::new(&Query::Extends("Ljava/lang/Object;".into())).unwrap();
    assert_eq!(fr.class_relation(&q).unwrap(), Some(vec![0]));
    assert_eq!(fr.locate_compiled(&q).unwrap(), [0].into_iter().collect());
    assert!(fr.find_ref_compiled(&q).unwrap().is_empty());
    let q = CompiledQuery::new(&Query::Implements("Ljava/lang/Object;".into())).unwrap();
    assert_eq!(fr.class_relation(&q).unwrap(), Some(vec![]));
    let q = CompiledQuery::new(&Query::String("token".into())).unwrap();
    assert_eq!(fr.class_relation(&q).unwrap(), None);
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
            exact_name: false,
            signature: None,
        })
    };
    assert_eq!(fr.locate(&precise(None)).unwrap(), [0, 1].into_iter().collect());
    assert_eq!(fr.locate(&precise(Some("sec"))).unwrap(), [1].into_iter().collect());
    let fuzzy = Query::Method(MemberQuery {
        class: Some(ClassQuery { pattern: "example".into(), precise: false }),
        name: Some("first".into()),
        exact_name: false,
        signature: None,
    });
    assert_eq!(fr.locate(&fuzzy).unwrap(), [0].into_iter().collect());
    let by_name = Query::Method(MemberQuery { class: None, name: Some("(first|second)".into()), exact_name: false, signature: None });
    assert_eq!(fr.locate(&by_name).unwrap(), [0, 1].into_iter().collect());
    let set: IdxSet = [1u32, 70].into_iter().collect();
    assert!(set.contains(70) && !set.contains(2));
    // Nothing to match on: empty result, no error.
    let none = Query::Method(MemberQuery { class: None, name: None, exact_name: false, signature: None });
    assert!(fr.locate(&none).unwrap().is_empty());
    let empty_class = Query::Method(MemberQuery {
        class: Some(ClassQuery { pattern: String::new(), precise: true }),
        name: None,
        exact_name: false,
        signature: None,
    });
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
        Query::Method(MemberQuery {
            class: Some(ClassQuery { pattern: "Lexample/Test;".into(), precise: true }),
            name: None,
            exact_name: false,
            signature: None,
        }),
        Query::Method(MemberQuery {
            class: Some(ClassQuery { pattern: "Lexample/Test;".into(), precise: true }),
            name: Some("sec".into()),
            exact_name: false,
            signature: None,
        }),
        Query::Method(MemberQuery {
            class: Some(ClassQuery { pattern: "example".into(), precise: false }),
            name: Some("first".into()),
            exact_name: false,
            signature: None,
        }),
        Query::Method(MemberQuery { class: None, name: Some("(first|second)".into()), exact_name: false, signature: None }),
        Query::Method(MemberQuery { class: None, name: None, exact_name: false, signature: None }),
        Query::Field(MemberQuery { class: None, name: Some("SECOND".into()), exact_name: false, signature: None }),
        Query::Field(MemberQuery {
            class: Some(ClassQuery { pattern: "Lexample/Statics;".into(), precise: true }),
            name: Some("FIR".into()),
            exact_name: false,
            signature: None,
        }),
        Query::Field(MemberQuery {
            class: Some(ClassQuery { pattern: "Statics".into(), precise: false }),
            name: None,
            exact_name: false,
            signature: None,
        }),
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
    let compiled =
        CompiledQuery::new(&Query::Field(MemberQuery { class: None, name: Some("SECOND".into()), exact_name: false, signature: None }))
            .unwrap();
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

#[test]
fn search_state_reports_its_table_bytes() {
    let data = make_dex();
    let dex = Dex::parse(&data).unwrap();
    let state = asc_findrefs::SearchState::new();
    assert_eq!(state.heap_bytes(), 0);
    let fr = FindRefs::with_state(&dex, &state);
    fr.find_ref(&Query::String("token".into())).unwrap();
    // String table plus the instruction bucket table.
    let strings = fr.string_locator().unwrap().heap_bytes() + fr.insn_locator().unwrap().heap_bytes();
    assert!(strings > 0);
    assert_eq!(state.heap_bytes(), strings);
    // A method query adds the type and method tables on top.
    fr.find_ref(&Query::Method(MemberQuery { class: None, name: Some("run".into()), exact_name: false, signature: None })).unwrap();
    let grown = state.heap_bytes();
    assert_eq!(grown, strings + fr.type_locator().unwrap().heap_bytes() + fr.method_locator().unwrap().heap_bytes());
    assert!(grown > strings);
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

/// Members whose names are prefixes / extensions of each other, in two
/// classes, plus non-ASCII names (one outside the BMP).
fn exact_name_dex() -> Vec<u8> {
    let mut d = asc_fixture::DexBuilder::new();
    for c in ["Lexample/A;", "Lexample/B;"] {
        d.method(c, "first", "V", &[]).method(c, "firstX", "V", &[]).field(c, "f", "I").field(c, "ff", "I");
    }
    d.method("Lexample/A;", "x\u{1F600}", "V", &[]).method("Lexample/A;", "\u{06e1}", "V", &[]).method("Lexample/A;", "first", "V", &["I"]);
    d.resolve().finish()
}

fn exact(class: Option<(&str, bool)>, name: &str) -> MemberQuery {
    MemberQuery {
        class: class.map(|(pattern, precise)| ClassQuery { pattern: pattern.into(), precise }),
        name: Some(name.into()),
        exact_name: true,
        signature: None,
    }
}

#[test]
fn exact_member_names() {
    let data = exact_name_dex();
    let dex = Dex::parse(&data).unwrap();
    let fr = FindRefs::new(&dex);
    // `Lcls;name` of every located id.
    let methods = |q: &MemberQuery| -> Vec<String> {
        let ids = fr.locate(&Query::Method(q.clone())).unwrap();
        ids.into_iter()
            .map(|i| {
                let m = dex.method_id(i).unwrap();
                format!("{}{}", dex.type_descriptor(m.class_idx as u32).unwrap(), dex.string(m.name_idx).unwrap())
            })
            .collect()
    };
    let fields = |q: &MemberQuery| -> Vec<String> {
        let ids = fr.locate(&Query::Field(q.clone())).unwrap();
        ids.into_iter()
            .map(|i| {
                let f = dex.field_id(i).unwrap();
                format!("{}{}", dex.type_descriptor(f.class_idx as u32).unwrap(), dex.string(f.name_idx).unwrap())
            })
            .collect()
    };
    let a = Some(("Lexample/A;", true));
    let fuzzy = Some(("example/[AB]", false));

    // No class: every class's member with exactly that name (both overloads of A.first).
    assert_eq!(methods(&exact(None, "first")), ["Lexample/A;first", "Lexample/A;first", "Lexample/B;first"]);
    assert_eq!(fields(&exact(None, "f")), ["Lexample/A;f", "Lexample/B;f"]);
    // Precise class.
    assert_eq!(methods(&exact(a, "first")), ["Lexample/A;first", "Lexample/A;first"]);
    assert_eq!(fields(&exact(a, "f")), ["Lexample/A;f"]);
    // Fuzzy class.
    assert_eq!(methods(&exact(fuzzy, "firstX")), ["Lexample/A;firstX", "Lexample/B;firstX"]);
    assert_eq!(fields(&exact(fuzzy, "ff")), ["Lexample/A;ff", "Lexample/B;ff"]);
    // A name is never a pattern: no prefix, substring or regex matches.
    for name in ["firs", "irst", "first.", "f.*", "(first|firstX)"] {
        for class in [None, a, fuzzy] {
            assert!(methods(&exact(class, name)).is_empty(), "{class:?} {name}");
            assert!(fields(&exact(class, name)).is_empty(), "{class:?} {name}");
        }
    }
    // The non-exact modes do match the longer names.
    let loose = |class, name: &str| MemberQuery { exact_name: false, ..exact(class, name) };
    assert_eq!(methods(&loose(a, "first")).len(), 3);
    assert_eq!(methods(&loose(None, "first")).len(), 5);
    assert_eq!(fields(&loose(fuzzy, "f")).len(), 4);
    // Non-ASCII names, including a surrogate pair in MUTF-8.
    for class in [None, a, fuzzy] {
        assert_eq!(methods(&exact(class, "x\u{1F600}")), ["Lexample/A;x\u{1F600}"]);
        assert_eq!(methods(&exact(class, "\u{06e1}")), ["Lexample/A;\u{06e1}"]);
        assert!(methods(&exact(class, "x")).is_empty());
    }
    // An absent or empty name with a class still means "every member".
    assert_eq!(fields(&MemberQuery { name: None, ..exact(a, "") }).len(), 2);
    assert_eq!(fields(&exact(a, "")).len(), 2);
}

#[test]
fn exact_member_queries_compile_like_plain_ones() {
    let data = make_dex();
    let dex = Dex::parse(&data).unwrap();
    let fr = FindRefs::new(&dex);
    for q in [exact(None, "first"), exact(Some(("Lexample/Test;", true)), "second"), exact(Some(("example", false)), "first")] {
        let q = Query::Method(q);
        let compiled = CompiledQuery::new(&q).unwrap();
        assert_eq!(fr.locate(&q).unwrap().len(), 1, "{q:?}");
        assert_eq!(fr.locate_compiled(&compiled).unwrap(), fr.locate(&q).unwrap());
        assert_eq!(fr.find_ref_compiled(&compiled).unwrap(), fr.find_ref(&q).unwrap());
    }
}

#[test]
fn find_many_matches_one_search_per_query() {
    let data = asc_fixture::make_rich_dex();
    let dex = Dex::with_name(&data, "rich.dex").unwrap();
    let member = |name: &str| MemberQuery { class: None, name: Some(name.into()), exact_name: false, signature: None };
    let queries = [
        Query::String("l".into()),
        Query::StringLiteral("wörld".into()),
        Query::Type("Exception".into()),
        Query::Method(member("compute")),
        Query::Method(member(".")),
        Query::Field(member("COUNT")),
        Query::Field(member("value")),
        Query::Implements("Lexample/Iface;".into()),
        Query::All { all: vec![Query::String("l".into())], none: vec![] },
        Query::String("no such string".into()),
    ];
    let compiled: Vec<CompiledQuery> = queries.iter().map(|q| CompiledQuery::new(q).unwrap()).collect();
    let fr = FindRefs::new(&dex);
    let many = fr.find_many(&compiled.iter().collect::<Vec<_>>()).unwrap();
    for (i, q) in compiled.iter().enumerate() {
        // A fresh state, so nothing is shared with the merged run.
        assert_eq!(many[i], FindRefs::new(&dex).find_ref_compiled(q).unwrap(), "{:?}", queries[i]);
    }
    assert!(!many[0].is_empty() && !many[3].is_empty() && !many[5].is_empty());
}

#[test]
fn cannot_match_agrees_with_the_search_and_never_guesses_on_a_short_prefix() {
    let data = asc_fixture::make_rich_dex();
    let member = |name: &str| MemberQuery { class: None, name: Some(name.into()), exact_name: false, signature: None };
    let queries = [
        Query::String("l".into()),
        Query::String("no such string".into()),
        Query::StringLiteral("wörld".into()),
        Query::Type("Exception".into()),
        Query::Type("Lno/Such;".into()),
        Query::Method(member("compute")),
        Query::Method(member("nothing")),
        Query::Field(member("COUNT")),
        Query::Implements("Lexample/Iface;".into()),
        Query::Extends("Lno/Such;".into()),
        Query::All { all: vec![Query::String("l".into()), Query::String("no such string".into())], none: vec![] },
    ];
    let compiled: Vec<CompiledQuery> = queries.iter().map(|q| CompiledQuery::new(q).unwrap()).collect();
    let dex = Dex::with_name(&data, "rich.dex").unwrap();
    let whole: Vec<bool> = compiled.iter().map(|q| FindRefs::new(&dex).cannot_match(q).unwrap()).collect();
    for (q, &ruled_out) in compiled.iter().zip(&whole) {
        if ruled_out {
            assert!(FindRefs::new(&dex).find_ref_compiled(q).unwrap().is_empty(), "{q:?}");
        }
    }
    assert!(whole[1] && whole[4] && whole[6] && whole[9] && whole[10]);
    assert!(!whole[0] && !whole[5] && !whole[8]);

    // The id tables plus the string data are enough for the same answers;
    // anything shorter either still agrees or fails, never flips to "ruled out".
    let needed = asc_dex::quick::id_tables_needed_len(&data).unwrap();
    for cut in (0x70..data.len()).step_by(7) {
        let prefix = &data[..cut];
        let Ok(dex) = Dex::with_name(prefix, "rich.dex") else { continue };
        for (q, &ruled_out) in compiled.iter().zip(&whole) {
            match FindRefs::new(&dex).cannot_match(q) {
                Ok(answer) if cut > needed + 64 => assert_eq!(answer, ruled_out, "{q:?} at {cut}"),
                Ok(true) => assert!(ruled_out, "{q:?} ruled out from a {cut}-byte prefix"),
                _ => {}
            }
        }
    }
}

#[test]
fn signatures_pick_one_overload() {
    use asc_findrefs::{MemberSignature, TypeMatch};
    let mut d = asc_fixture::DexBuilder::new();
    let a = "Lexample/A;";
    d.method(a, "m", "V", &[])
        .method(a, "m", "V", &["I"])
        .method(a, "m", "J", &["I"])
        .method(a, "m", "V", &["Ljava/lang/String;"])
        .method(a, "m", "V", &["[Ljava/lang/String;"])
        .method(a, "m", "V", &["Lcom/x/MyString;"])
        .method(a, "m", "V", &["I", "Ljava/lang/String;"])
        .field(a, "f", "I")
        .field("Lexample/B;", "f", "Ljava/lang/String;");
    let data = d.resolve().finish();
    let dex = Dex::parse(&data).unwrap();
    let fr = FindRefs::new(&dex);
    let desc = |d: &str| TypeMatch::Descriptor(d.into());
    let simple = |n: &str, dims| TypeMatch::Simple { name: n.into(), dims };
    let protos = |params: Vec<TypeMatch>, ret: Option<TypeMatch>| -> Vec<String> {
        let q = MemberQuery { signature: Some(MemberSignature::Method { params, ret }), ..exact(Some((a, true)), "m") };
        let ids = fr.locate(&Query::Method(q)).unwrap();
        ids.into_iter()
            .map(|i| {
                let proto = dex.proto_id(dex.method_id(i).unwrap().proto_idx as u32).unwrap();
                let params: String =
                    dex.type_list(proto.parameters_off).unwrap().into_iter().map(|t| dex.type_descriptor(t as u32).unwrap()).collect();
                format!("m({params}){}", dex.type_descriptor(proto.return_type_idx).unwrap())
            })
            .collect()
    };
    // Parameters and return type: exactly one overload.
    assert_eq!(protos(vec![desc("I")], Some(desc("V"))), ["m(I)V"]);
    assert_eq!(protos(vec![desc("I")], Some(desc("J"))), ["m(I)J"]);
    // Parameters only: every return type.
    assert_eq!(protos(vec![desc("I")], None), ["m(I)J", "m(I)V"]);
    assert_eq!(protos(vec![], None), ["m()V"]);
    assert_eq!(protos(vec![desc("I"), desc("Ljava/lang/String;")], None), ["m(ILjava/lang/String;)V"]);
    // A simple name matches its class in any package, not a longer name.
    assert_eq!(protos(vec![simple("String", 0)], None), ["m(Ljava/lang/String;)V"]);
    assert_eq!(protos(vec![simple("String", 1)], None), ["m([Ljava/lang/String;)V"]);
    assert_eq!(protos(vec![simple("MyString", 0)], None), ["m(Lcom/x/MyString;)V"]);
    assert!(protos(vec![desc("J")], None).is_empty());
    assert_eq!(fr.locate(&Query::Method(exact(Some((a, true)), "m"))).unwrap().len(), 7);

    // Fields: by type, across classes.
    let fields = |t: TypeMatch| {
        fr.locate(&Query::Field(MemberQuery { signature: Some(MemberSignature::Field(t)), ..exact(None, "f") })).unwrap().len()
    };
    assert_eq!(fields(desc("I")), 1);
    assert_eq!(fields(simple("String", 0)), 1);
    assert_eq!(fields(desc("J")), 0);
    // A method signature on a field query (and the reverse) is a query error.
    let wrong = MemberQuery { signature: Some(MemberSignature::Field(desc("I"))), ..exact(None, "m") };
    assert!(CompiledQuery::new(&Query::Method(wrong)).is_err());
}
