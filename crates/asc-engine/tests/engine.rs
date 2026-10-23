use asc_engine::{names, Engine};
use asc_findrefs::Query;
use asc_fixture::{make_apk, make_dex};
use std::io::Write;

/// `bytes` as an `.apk` file that lives as long as the returned handle.
fn temp_apk_from(bytes: &[u8]) -> tempfile::NamedTempFile {
    let mut f = tempfile::Builder::new().suffix(".apk").tempfile().unwrap();
    f.write_all(bytes).unwrap();
    f.flush().unwrap();
    f
}

fn temp_apk(deflate: bool) -> tempfile::NamedTempFile {
    let dex = make_dex();
    temp_apk_from(&make_apk(&[("classes.dex", &dex), ("classes2.dex", &dex)], deflate))
}

#[test]
fn findrefs_and_getclass_on_stored_and_deflated_apk() {
    for deflate in [false, true] {
        let apk = temp_apk(deflate);
        let engine = Engine::new(apk.path()).with_threads(2);
        let mut lines = Vec::new();
        let summary = engine
            .find_refs(&Query::String("token".into()), |batch| {
                assert!(batch.error.is_none(), "{:?}", batch.error);
                lines.extend(batch.results.iter().map(|r| r.line()));
            })
            .unwrap();
        assert_eq!(summary.entries, 2);
        assert_eq!(lines.len(), 4, "{lines:?}");
        lines.sort();
        assert_eq!(lines[0], "classes.dex | Lexample/Test;->first | matched=(token)");
        let src = engine.get_class(&names::format_class_name("example.Test").unwrap()).unwrap();
        assert!(src.source.contains(".class public Lexample/Test;"));
        assert!(src.source.contains("const-string v0, \"token\""));
        assert!(engine.get_class("Lnope/Missing;").is_err());
    }
}

#[test]
fn class_relations_and_literals_stream_like_reference_queries() {
    use asc_engine::ClassRelation;
    let dex = asc_fixture::make_rich_dex();
    let apk = temp_apk_from(&make_apk(&[("classes.dex", &dex), ("classes2.dex", &make_dex())], true));
    // Cold and warm (memory-cached locator state) must agree.
    let cfg = asc_engine::CacheConfig { memory_bytes: 64 << 20, disk: None };
    let engine = Engine::new(apk.path()).with_threads(2).with_cache(cfg);
    let run = |q: &Query| {
        let mut rows = Vec::new();
        engine.find_refs(q, |b| rows.extend(b.results)).unwrap();
        rows.sort_by_key(|r| r.line());
        rows
    };
    for _ in 0..2 {
        let rows = run(&Query::Implements("Lexample/Iface;".into()));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].relation, Some(ClassRelation::Implements));
        assert_eq!(rows[0].method, "Lexample/Rich;");
        assert_eq!(rows[0].matched, ["Lexample/Iface;"]);
        assert_eq!(rows[0].line(), "classes.dex | Lexample/Rich; implements Lexample/Iface;");
        let rows = run(&Query::Extends("Ljava/lang/Object;".into()));
        assert_eq!(rows.len(), 5);
        assert!(rows.iter().all(|r| r.relation == Some(ClassRelation::Extends) && r.line().ends_with(" extends Ljava/lang/Object;")));
        let lit = run(&Query::StringLiteral("token".into()));
        assert_eq!(lit, run(&Query::String("token".into())));
        assert!(lit.iter().all(|r| r.relation.is_none()));
        assert!(run(&Query::StringLiteral("t.ken".into())).is_empty());
    }
    // The one-DEX helper takes the same path.
    let lines = asc_engine::find_refs_lines("classes.dex", &dex, &Query::Implements("Lexample/Iface;".into()), true).unwrap();
    assert_eq!(lines, ["classes.dex | Lexample/Rich; implements Lexample/Iface;"]);
}

#[test]
fn method_filter_is_validated_before_the_apk_is_read() {
    let engine = Engine::new("/nonexistent/app.apk");
    let err = engine.get_class_method("Lexample/Test;", Default::default(), Some("first")).err().unwrap();
    assert!(err.to_string().starts_with("method signature must include"), "{err}");
    let apk = temp_apk(true);
    let engine = Engine::new(apk.path());
    let src = engine.get_class_method("Lexample/Test;", Default::default(), Some("second()V")).unwrap();
    assert!(src.source.contains(".method public static second()V") && !src.source.contains("first"), "{}", src.source);
    assert!(src.rebuilt.is_some());
}

#[test]
fn caches_serve_repeated_queries() {
    let apk = temp_apk(true);
    let dir = tempfile::tempdir().unwrap();
    let cfg = asc_engine::CacheConfig { memory_bytes: 64 << 20, disk: Some(asc_engine::asc_cache::DiskCache::open(dir.path())) };
    let engine = Engine::new(apk.path()).with_threads(2).with_cache(cfg);
    let q = Query::String("token".into());
    let mut sources = Vec::new();
    engine.find_refs(&q, |b| sources.push(b.source)).unwrap();
    assert_eq!(sources, ["inflate", "inflate"]);
    let mut sources = Vec::new();
    let mut n = 0;
    engine
        .find_refs(&q, |b| {
            sources.push(b.source);
            n += b.results.len();
        })
        .unwrap();
    assert_eq!(sources, ["memory", "memory"]);
    assert_eq!(n, 4);
    let stats = engine.cache_stats();
    assert_eq!((stats.inflates, stats.memory_hits, stats.disk_hits), (2, 2, 0));
    // Disk writes are asynchronous; a new process would see them once landed.
    engine.flush_cache_writes();
    // A fresh engine (new process equivalent) hits the disk cache.
    let cfg = asc_engine::CacheConfig { memory_bytes: 0, disk: Some(asc_engine::asc_cache::DiskCache::open(dir.path())) };
    let engine2 = Engine::new(apk.path()).with_threads(2).with_cache(cfg);
    let mut sources = Vec::new();
    engine2.find_refs(&q, |b| sources.push(b.source)).unwrap();
    assert_eq!(sources, ["disk", "disk"]);
    assert!(engine2.get_class("Lexample/Test;").unwrap().source.contains("const-string v0, \"token\""));
    assert!(engine2.cache_stats().disk_hits >= 3);
}

#[test]
fn written_entries_are_remapped_from_the_disk_cache() {
    let apk = temp_apk(true);
    let dex = make_dex();
    let dir = tempfile::tempdir().unwrap();
    let cfg = asc_engine::CacheConfig { memory_bytes: 64 << 20, disk: Some(asc_engine::asc_cache::DiskCache::open(dir.path())) };
    let engine = Engine::new(apk.path()).with_threads(2).with_cache(cfg);
    let q = Query::String("token".into());
    let lines = |engine: &Engine| {
        let mut out = Vec::new();
        engine.find_refs(&q, |b| out.extend(b.results.iter().map(|r| r.line()))).unwrap();
        out.sort();
        out
    };
    let before = lines(&engine);
    assert_eq!(before.len(), 4);
    let charged = engine.memory_cache_bytes();
    // The writer swaps each heap copy for a mapping of the file it wrote.
    engine.flush_cache_writes();
    assert_eq!(engine.memory_cache_mapped_bytes(), 2 * dex.len());
    // Same bytes, same charge, and the tables built before the swap are kept.
    assert_eq!(engine.memory_cache_bytes(), charged);
    assert!(charged > 2 * dex.len());
    let apk_handle = engine.open().unwrap();
    let key = engine.apk_key(&apk_handle);
    for entry in apk_handle.dex_entries().unwrap() {
        assert_eq!(&**engine.entry_bytes(&apk_handle, key.as_ref(), &entry).unwrap(), &dex[..]);
    }
    let mut sources = Vec::new();
    engine.find_refs(&q, |b| sources.push(b.source)).unwrap();
    assert_eq!(sources, ["memory", "memory"]);
    assert_eq!(lines(&engine), before);
    // Clearing the cache directory under a live mapping is harmless: the
    // mapped inode outlives its directory entry.
    asc_engine::asc_cache::DiskCache::open(dir.path()).clear().unwrap();
    assert_eq!(lines(&engine), before);
}

#[test]
fn memory_only_cache_keeps_heap_entries() {
    let apk = temp_apk(true);
    let cfg = asc_engine::CacheConfig { memory_bytes: 64 << 20, disk: None };
    let engine = Engine::new(apk.path()).with_threads(2).with_cache(cfg);
    engine.find_refs(&Query::String("token".into()), |_| {}).unwrap();
    engine.flush_cache_writes();
    assert_eq!(engine.memory_cache_mapped_bytes(), 0);
    assert!(engine.memory_cache_bytes() > 0);
}

#[test]
fn locator_tables_count_against_the_memory_budget() {
    let apk = temp_apk(true);
    let dex_len = make_dex().len();
    // Room for both inflated entries, but not for their locator tables too.
    let cap = 2 * dex_len + 1;
    let cfg = asc_engine::CacheConfig { memory_bytes: cap, disk: None };
    let engine = Engine::new(apk.path()).with_threads(1).with_cache(cfg);
    let q = Query::String("token".into());
    let mut sources = Vec::new();
    engine.find_refs(&q, |b| sources.push(b.source)).unwrap();
    assert_eq!(sources, ["inflate", "inflate"]);
    // Charging the first entry's tables pushed it over the cap; one entry is left.
    let used = engine.memory_cache_bytes();
    assert!(used > dex_len && used < 2 * dex_len, "used {used}, dex {dex_len}");
    // Without the tables in the charge both entries would have stayed.
    let roomy = Engine::new(apk.path()).with_threads(1).with_cache(asc_engine::CacheConfig { memory_bytes: 2 * cap, disk: None });
    roomy.find_refs(&q, |_| {}).unwrap();
    assert!(roomy.memory_cache_bytes() > cap);
    let mut sources = Vec::new();
    roomy.find_refs(&q, |b| sources.push(b.source)).unwrap();
    assert_eq!(sources, ["memory", "memory"]);
}

#[test]
fn invalid_pattern_is_reported_once_up_front() {
    let apk = temp_apk(false);
    let engine = Engine::new(apk.path()).with_threads(2);
    let mut batches = 0;
    let err = engine.find_refs(&Query::String("(".into()), |_| batches += 1).unwrap_err();
    assert!(err.to_string().contains("pattern"), "{err}");
    assert_eq!(batches, 0);
}

#[test]
fn concurrent_queries_share_one_inflate() {
    let apk = temp_apk(true);
    let dir = tempfile::tempdir().unwrap();
    let cfg = asc_engine::CacheConfig { memory_bytes: 64 << 20, disk: Some(asc_engine::asc_cache::DiskCache::open(dir.path())) };
    let engine = std::sync::Arc::new(Engine::new(apk.path()).with_threads(2).with_cache(cfg));
    let q = Query::String("token".into());
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let (engine, q) = (std::sync::Arc::clone(&engine), q.clone());
            std::thread::spawn(move || {
                let mut n = 0;
                engine.find_refs(&q, |b| n += b.results.len()).unwrap();
                n
            })
        })
        .collect();
    for h in handles {
        assert_eq!(h.join().unwrap(), 4);
    }
    // Two entries, four concurrent queries: each entry is inflated exactly once.
    assert_eq!(engine.cache_stats().inflates, 2);
    engine.flush_cache_writes();
    assert_eq!(asc_engine::asc_cache::DiskCache::open(dir.path()).stats().0, 1);
}

#[test]
fn dropping_the_engine_lands_cache_writes() {
    let apk = temp_apk(true);
    let dir = tempfile::tempdir().unwrap();
    {
        let cfg = asc_engine::CacheConfig { memory_bytes: 0, disk: Some(asc_engine::asc_cache::DiskCache::open(dir.path())) };
        let engine = Engine::new(apk.path()).with_threads(2).with_cache(cfg);
        assert!(engine.get_class("Lexample/Test;").is_ok());
    }
    let (dirs, files, _) = asc_engine::asc_cache::DiskCache::open(dir.path()).stats();
    assert_eq!(dirs, 1);
    assert!(files >= 1);
}

#[test]
fn engines_share_one_cache_budget() {
    let (a, b) = (temp_apk(true), temp_apk_from(&make_apk(&[("classes.dex", &make_dex())], true)));
    let dir = tempfile::tempdir().unwrap();
    let cfg = asc_engine::CacheConfig { memory_bytes: 64 << 20, disk: Some(asc_engine::asc_cache::DiskCache::open(dir.path())) };
    let shared = asc_engine::SharedCache::new(cfg, |_| {});
    let q = Query::String("token".into());
    let ea = Engine::new(a.path()).with_threads(2).with_shared_cache(&shared);
    ea.find_refs(&q, |_| {}).unwrap();
    let after_a = shared.memory_bytes();
    assert!(after_a > 0);
    {
        let eb = Engine::new(b.path()).with_threads(2).with_shared_cache(&shared);
        eb.find_refs(&q, |_| {}).unwrap();
        assert!(shared.memory_bytes() > after_a);
    }
    // Dropping an engine leaves the shared cache usable for the others.
    let mut sources = Vec::new();
    ea.find_refs(&q, |b| sources.push(b.source)).unwrap();
    assert_eq!(sources, ["memory", "memory"]);
    drop(shared);
    // Dropping the shared cache lands the queued disk writes of both APKs.
    assert_eq!(asc_engine::asc_cache::DiskCache::open(dir.path()).stats().0, 2);
}

#[test]
fn getclass_keeps_looking_after_a_broken_entry() {
    // A malformed first entry must be reported per entry, not end the search
    // early: the class defined in the second entry is still found.
    let dex = make_dex();
    let mut broken = dex.clone();
    // string_ids_size = huge -> "bad string_ids range" from the quick probe.
    broken[0x38..0x3c].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    let bytes = make_apk(&[("classes.dex", &broken), ("classes2.dex", &dex)], false);
    let f = temp_apk_from(&bytes);
    for threads in [1, 2] {
        let engine = Engine::new(f.path()).with_threads(threads).with_cache(asc_engine::CacheConfig { memory_bytes: 0, disk: None });
        let hit = engine.get_class_dex("Lexample/Test;").unwrap().expect("class found in classes2.dex");
        assert_eq!(hit.dex_name, "classes2.dex");
        // A class in neither entry surfaces the broken entry's error.
        assert!(engine.get_class_dex("Lexample/Missing;").is_err());
    }
}

#[test]
fn list_classes_follows_central_directory_order() {
    let (a, b) = (make_dex(), asc_fixture::make_static_field_dex());
    let container = asc_fixture::make_dex041_container();
    // Sizes differ, so a size-ordered scan would reorder them.
    let bytes = make_apk(&[("classes2.dex", &b), ("classes.dex", &container), ("classes3.dex", &a)], true);
    let f = temp_apk_from(&bytes);
    let dir = tempfile::tempdir().unwrap();
    for (threads, memory_bytes) in [(1, 0), (3, 0), (3, 64 << 20)] {
        let cfg = asc_engine::CacheConfig { memory_bytes, disk: Some(asc_engine::asc_cache::DiskCache::open(dir.path())) };
        let engine = Engine::new(f.path()).with_threads(threads).with_cache(cfg);
        // Twice: the second run is served from the caches.
        for _ in 0..2 {
            let got: Vec<(String, String)> = engine.list_classes(None).unwrap().into_iter().map(|c| (c.dex_name, c.descriptor)).collect();
            let want = [
                ("classes2.dex", "Lexample/Statics;"),
                ("classes.dex!classes1.dex", "Lalpha/First;"),
                ("classes.dex!classes1.dex", "Lshared/Duplicate;"),
                ("classes.dex!classes2.dex", "Lbeta/Second;"),
                ("classes.dex!classes2.dex", "Lshared/Duplicate;"),
                ("classes3.dex", "Lexample/Test;"),
            ];
            assert_eq!(got, want.map(|(d, c)| (d.to_string(), c.to_string())));
            engine.flush_cache_writes();
        }
        let shared: Vec<String> = engine.list_classes(Some("shared")).unwrap().into_iter().map(|c| c.dex_name).collect();
        assert_eq!(shared, ["classes.dex!classes1.dex", "classes.dex!classes2.dex"]);
    }
}

#[test]
fn scan_classes_reports_problems_per_entry() {
    let dex = make_dex();
    let mut bad_def = dex.clone();
    let off = u32::from_le_bytes(bad_def[0x64..0x68].try_into().unwrap()) as usize;
    bad_def[off..off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    let bytes = make_apk(&[("classes.dex", &dex), ("classes2.dex", b"not a dex"), ("classes3.dex", &bad_def)], false);
    let f = temp_apk_from(&bytes);
    let engine = Engine::new(f.path()).with_threads(2);
    let calls = std::sync::Mutex::new(Vec::new());
    let scanned = engine.scan_classes(None, |done, total| calls.lock().unwrap().push((done, total))).unwrap();
    let mut calls = calls.into_inner().unwrap();
    calls.sort_unstable();
    assert_eq!(calls, [(1, 3), (2, 3), (3, 3)]);
    let names: Vec<&str> = scanned.iter().map(|e| e.entry_name.as_str()).collect();
    assert_eq!(names, ["classes.dex", "classes2.dex", "classes3.dex"]);
    let dexes: Vec<_> = scanned.iter().map(|e| &e.result.as_ref().unwrap()[0]).collect();
    assert_eq!(dexes[0].descriptors, ["Lexample/Test;"]);
    assert!(dexes[1].error.is_some());
    assert_eq!((dexes[2].descriptors.len(), dexes[2].bad_class_defs), (0, 1));
    // The strict listing fails on the first problem, in entry order.
    let err = engine.list_classes(None).unwrap_err().to_string();
    assert!(err.starts_with("classes2.dex: "), "{err}");
    assert_eq!(engine.list_classes(Some("")).unwrap_err().to_string(), "Class prefix cannot be empty");
}
