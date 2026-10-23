use asc_dex::Dex;
use asc_findrefs::{Backing, ClassQuery, FindRefs, MemberQuery, Query, SearchState};
use asc_fixture::{make_dex, make_rich_dex, make_unsorted_static_field_dex};
use std::sync::Arc;

/// Persisted bytes in 8-byte aligned storage, as a mapped file would be.
struct Aligned(Vec<u64>, usize);

impl AsRef<[u8]> for Aligned {
    fn as_ref(&self) -> &[u8] {
        &bytemuck::cast_slice(&self.0)[..self.1]
    }
}

fn backing(bytes: &[u8]) -> Backing {
    let mut words = vec![0u64; bytes.len().div_ceil(8)];
    bytemuck::cast_slice_mut::<u64, u8>(&mut words)[..bytes.len()].copy_from_slice(bytes);
    Arc::new(Aligned(words, bytes.len()))
}

fn queries() -> Vec<Query> {
    let member = |class: Option<&str>, name: &str| MemberQuery {
        class: class.map(|c| ClassQuery { pattern: c.into(), precise: true }),
        name: Some(name.into()),
        exact_name: false,
        signature: None,
    };
    vec![
        Query::String("token".into()),
        Query::String(".".into()),
        Query::Type("L.*;".into()),
        Query::Method(member(None, ".")),
        Query::Field(member(None, ".")),
        Query::Field(member(Some("Lexample/Rich;"), "")),
    ]
}

fn hits(fr: &FindRefs<'_, '_, '_>) -> Vec<String> {
    let mut out: Vec<String> = queries().iter().map(|q| format!("{:?}", fr.find_ref(q).unwrap())).collect();
    out.push(format!("{:?}", fr.call_graph().unwrap()));
    out
}

#[test]
fn persisted_tables_answer_like_freshly_built_ones() {
    for data in [make_dex(), make_rich_dex(), make_unsorted_static_field_dex()] {
        let dex = Dex::parse(&data).unwrap();
        let built = SearchState::new();
        let fresh = FindRefs::with_state(&dex, &built);
        let expected = hits(&fresh);
        let bytes = built.persist(&dex);
        let loaded = SearchState::from_persisted(&dex, backing(&bytes)).expect("loads");
        assert_eq!(loaded.table_mask(), built.table_mask());
        // Every table is viewed in place, the call graph too.
        assert_eq!(loaded.heap_bytes(), 0);
        assert!(loaded.call_graph().unwrap().mapped_bytes() > 0);
        assert!(loaded.mapped_bytes() > 0 && loaded.mapped_bytes() <= bytes.len());
        // Adopting a loaded state fills only what is missing.
        let target = SearchState::new();
        FindRefs::with_state(&dex, &target).string_locator().unwrap();
        let heap = target.heap_bytes();
        target.fill_from(SearchState::from_persisted(&dex, backing(&bytes)).unwrap());
        assert_eq!(target.table_mask(), built.table_mask());
        // Its own string table is kept; the rest is added as views.
        assert_eq!(target.heap_bytes(), heap);
        assert_eq!(hits(&FindRefs::with_state(&dex, &target)), expected);
        assert_eq!(hits(&FindRefs::with_state(&dex, &loaded)), expected);
        // Re-persisting a loaded state gives the same bytes.
        assert_eq!(loaded.persist(&dex), bytes);
    }
}

#[test]
fn partial_states_build_the_missing_tables_on_demand() {
    let data = make_rich_dex();
    let dex = Dex::parse(&data).unwrap();
    let partial = SearchState::new();
    FindRefs::with_state(&dex, &partial).string_locator().unwrap();
    let loaded = SearchState::from_persisted(&dex, backing(&partial.persist(&dex))).unwrap();
    assert_eq!(loaded.table_mask(), partial.table_mask());
    let fr = FindRefs::with_state(&dex, &loaded);
    assert_eq!(hits(&fr), hits(&FindRefs::new(&dex)));
    assert!(loaded.table_mask() > partial.table_mask());
    assert!(loaded.heap_bytes() > 0, "the tables built since live on the heap");
}

#[test]
fn persisted_tables_of_another_dex_or_a_damaged_file_are_refused() {
    let (a, b) = (make_dex(), make_rich_dex());
    let (da, db) = (Dex::parse(&a).unwrap(), Dex::parse(&b).unwrap());
    let state = SearchState::new();
    let _ = hits(&FindRefs::with_state(&da, &state));
    let bytes = state.persist(&da);
    assert!(SearchState::from_persisted(&db, backing(&bytes)).is_none(), "other DEX");
    assert!(SearchState::from_persisted(&da, backing(&bytes[..bytes.len() - 4])).is_none(), "truncated");
    let mut bad_magic = bytes.clone();
    bad_magic[0] ^= 1;
    assert!(SearchState::from_persisted(&da, backing(&bad_magic)).is_none());
    let mut bad_version = bytes.clone();
    bad_version[8] ^= 0xff;
    assert!(SearchState::from_persisted(&da, backing(&bad_version)).is_none());
    // Flipping any byte of the header or directory never panics.
    for i in 0..bytes.len().min(512) {
        let mut damaged = bytes.clone();
        damaged[i] ^= 0x5a;
        if let Some(s) = SearchState::from_persisted(&da, backing(&damaged)) {
            let _ = hits(&FindRefs::with_state(&da, &s));
        }
    }
}
