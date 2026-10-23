//! Leaving out Deflate entries a search cannot match, decided from a streamed
//! prefix: same rows as a full search, and a fall back to it whenever the
//! prefix cannot tell.

use asc_engine::{names, CacheConfig, Engine, FindOptions};
use asc_findrefs::{ClassQuery, MemberQuery, Query};
use asc_fixture::{make_apk, make_padded_dex};
use std::io::Write;
use std::sync::atomic::AtomicBool;

/// Big enough to be worth a probe, small enough to keep tests fast.
const PAD: usize = 1 << 20;

fn temp_apk(dex: &[u8], deflate: bool) -> tempfile::NamedTempFile {
    let bytes = make_apk(&[("classes.dex", dex)], deflate);
    let mut f = tempfile::Builder::new().suffix(".apk").tempfile().unwrap();
    f.write_all(&bytes).unwrap();
    f.flush().unwrap();
    f
}

/// Sorted result lines and the number of entries skipped.
fn search(engine: &Engine, q: &Query) -> (Vec<String>, u64) {
    let before = engine.cache_stats().skipped;
    let mut out = Vec::new();
    engine.find_refs(q, |b| out.extend(b.results.iter().map(|r| r.line()))).unwrap();
    out.sort();
    (out, engine.cache_stats().skipped - before)
}

/// Queries, and whether the id tables and strings alone rule each out.
fn queries() -> Vec<(Query, bool)> {
    let method = |class: Option<&str>, name: &str| {
        Query::Method(MemberQuery {
            class: class.map(|c| ClassQuery { pattern: c.into(), precise: true }),
            name: Some(name.into()),
            exact_name: false,
            signature: None,
        })
    };
    vec![
        (Query::String("tok".into()), false),
        (Query::String("absent".into()), true),
        (Query::StringLiteral("token".into()), false),
        (Query::StringLiteral("nothing here".into()), true),
        // Referenced by no code, but in the type table: the full search decides.
        (Query::Type("Lexample/Test;".into()), false),
        (Query::Type("Lmissing/Type;".into()), true),
        (method(Some("Lexample/Test;"), "first"), false),
        (method(Some("Lexample/Test;"), "third"), true),
        (method(Some("Lmissing/Type;"), "first"), true),
        (method(None, "sec"), false),
        (Query::Extends("Ljava/lang/Object;".into()), false),
        (Query::Extends("Lmissing/Base;".into()), true),
        (Query::Implements("Lmissing/Iface;".into()), true),
        (Query::All { all: vec![Query::String("tok".into()), Query::String("absent".into())], none: vec![] }, true),
        (Query::All { all: vec![Query::String("tok".into())], none: vec![Query::String("absent".into())] }, false),
    ]
}

#[test]
fn front_string_data_skips_only_what_cannot_match() {
    // String data right after the id tables, the rest of the file padding.
    let dex = make_padded_dex(0, PAD);
    let deflated = temp_apk(&dex, true);
    let stored = temp_apk(&dex, false);
    let (probed, plain) = (Engine::new(deflated.path()).with_threads(1), Engine::new(stored.path()).with_threads(1));
    for (q, ruled_out) in queries() {
        let (rows, skipped) = search(&probed, &q);
        let (expected, never) = search(&plain, &q);
        assert_eq!(rows, expected, "{q:?}");
        assert_eq!(never, 0, "stored entries are never probed");
        assert_eq!(skipped, u64::from(ruled_out), "{q:?}");
    }
}

#[test]
fn late_string_data_or_a_kept_entry_is_searched_whole() {
    // String data behind a large gap, as d8 lays it out: past the share a
    // probe may inflate, so the entry is searched as usual.
    let late = temp_apk(&make_padded_dex(PAD, 0), true);
    let engine = Engine::new(late.path()).with_threads(1);
    for (q, _) in queries() {
        assert_eq!(search(&engine, &q).1, 0, "{q:?}");
    }
    assert_eq!(search(&engine, &Query::String("tok".into())).0.len(), 2);

    // A memory cache keeps the inflated entry for later queries: no probe.
    let front = temp_apk(&make_padded_dex(0, PAD), true);
    let cached = Engine::new(front.path()).with_cache(CacheConfig { memory_bytes: 64 << 20, ..Default::default() });
    assert_eq!(search(&cached, &Query::String("absent".into())), (Vec::new(), 0));
}

#[test]
fn rule_sets_skip_an_entry_only_when_no_rule_can_match() {
    let front = temp_apk(&make_padded_dex(0, PAD), true);
    let engine = Engine::new(front.path()).with_threads(1);
    let run = |rules: &[&str]| {
        let rules: Vec<Query> = rules.iter().map(|r| names::parse_condition(r).unwrap()).collect();
        let before = engine.cache_stats().skipped;
        let mut totals = vec![0; rules.len()];
        let opts = FindOptions { aggregate: true, ..Default::default() };
        engine.find_refs_rules(&rules, opts, &AtomicBool::new(false), &mut |i, b| totals[i] += b.results.len()).unwrap();
        (totals, engine.cache_stats().skipped - before)
    };
    assert_eq!(run(&["string:absent", "type:Lmissing/Type;"]), (vec![0, 0], 1));
    assert_eq!(run(&["string:absent", "string:tok"]), (vec![0, 2], 0));
}
