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
