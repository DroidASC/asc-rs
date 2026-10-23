//! Annotation and `in:{annotation:}` definition predicates, on the rich DEX
//! fixture (its `Lexample/Rich;` carries a class annotation `Lexample/Marker;`
//! and its `handle` method a method annotation of the same type).

use asc_engine::{names, Engine};
use asc_findrefs::Query;
use asc_fixture::{make_apk, make_rich_dex};
use std::io::Write;

fn temp_apk() -> tempfile::NamedTempFile {
    let bytes = make_apk(&[("classes.dex", &make_rich_dex())], true);
    let mut f = tempfile::Builder::new().suffix(".apk").tempfile().unwrap();
    f.write_all(&bytes).unwrap();
    f.flush().unwrap();
    f
}

fn lines(engine: &Engine, spec: &str) -> Vec<String> {
    let q: Query = names::parse_rule(spec).unwrap();
    let mut out = Vec::new();
    engine.find_refs(&q, |b| out.extend(b.results.iter().map(|r| r.line()))).unwrap();
    out.sort();
    out
}

#[test]
fn annotation_predicates_match_method_and_class_annotations() {
    let apk = temp_apk();
    let engine = Engine::new(apk.path()).with_threads(2);

    // Method-level: only `handle` carries `@Marker`.
    assert_eq!(
        lines(&engine, "annotation:example.Marker"),
        ["classes.dex | Lexample/Rich;->handle(Ljava/lang/String;I)V | @Lexample/Marker;"]
    );

    // Class-level: `in:{annotation:}` takes every method of the annotated class.
    let in_marker = lines(&engine, "in:{annotation:example.Marker}");
    assert!(in_marker.iter().all(|l| l.contains("Lexample/Rich;->")), "{in_marker:?}");
    assert!(in_marker.iter().any(|l| l.contains("->compute(II)I")), "{in_marker:?}");
    assert!(in_marker.iter().any(|l| l.contains("->handle(")), "{in_marker:?}");

    // Composed with a flag: the annotated class's static methods only.
    let statics = lines(&engine, "in:{annotation:example.Marker} & flag:static");
    assert!(statics.iter().any(|l| l.contains("->compute(II)I")), "{statics:?}");
    assert!(!statics.iter().any(|l| l.contains("->handle(")), "handle is abstract, not static: {statics:?}");

    // in:{type:...}: methods of classes whose descriptor matches the regex.
    let iface = lines(&engine, "in:{type:Lexample/Iface;}");
    assert_eq!(iface, ["classes.dex | Lexample/Iface;->run()V | in"]);

    // An annotation type absent from the program matches nothing.
    assert!(lines(&engine, "annotation:example.Absent").is_empty());
    assert!(lines(&engine, "in:{annotation:example.Absent}").is_empty());
}

#[test]
fn the_class_graph_is_kept_on_disk_for_later_processes() {
    use asc_engine::asc_cache::DiskCache;
    use asc_engine::CacheConfig;
    let apk = temp_apk();
    let dir = tempfile::tempdir().unwrap();
    let cached = || {
        let disk =
            DiskCache::open(dir.path()).with_capacity(1 << 30).with_min_dex_bytes(0).with_min_derived_cost(std::time::Duration::ZERO);
        Engine::new(apk.path()).with_threads(2).with_cache(CacheConfig { memory_bytes: 64 << 20, disk: Some(disk), ..Default::default() })
    };
    let specs = ["in:{annotation:example.Marker}", "in:{extends:java.lang.Object} & flag:static", "override:example.Iface->run"];
    let uncached = Engine::new(apk.path()).with_threads(2);
    let want: Vec<Vec<String>> = specs.iter().map(|s| lines(&uncached, s)).collect();
    assert!(want.iter().all(|w| !w.is_empty()), "{want:?}");

    // The first process builds the graph and queues it for L2.
    let first = cached();
    assert_eq!(lines(&first, specs[0]), want[0]);
    first.flush_cache_writes();
    let graph_files = || -> Vec<std::path::PathBuf> {
        let mut out = Vec::new();
        let mut stack = vec![dir.path().to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.file_name().unwrap().to_string_lossy().contains("~classgraph.") {
                    out.push(p);
                }
            }
        }
        out
    };
    let files = graph_files();
    assert_eq!(files.len(), 1, "{files:?}");

    // A later process maps it back and answers alike; a varied `!` part
    // keeps L3 from replaying an earlier run.
    let run = |engine: &Engine, nop: &str| {
        for (spec, want) in specs.iter().zip(&want) {
            assert_eq!(strip(&lines(engine, &format!("{spec} & !flag:{nop}"))), strip(want), "{spec}");
        }
        engine.cache_stats().derived_hits
    };
    let with_graph = run(&cached(), "bridge");
    // Without the file the same queries map one index fewer (and build the
    // graph again, which also gives the same rows).
    std::fs::remove_file(&files[0]).unwrap();
    let without = run(&cached(), "enum");
    assert_eq!(with_graph, without + 1, "the graph is mapped from L2 once, then kept in memory");

    // A damaged file is a miss, not a wrong graph.
    let later = cached();
    run(&later, "varargs");
    later.flush_cache_writes();
    let files = graph_files();
    let mut bytes = std::fs::read(&files[0]).unwrap();
    bytes.truncate(bytes.len() - 3);
    std::fs::write(&files[0], bytes).unwrap();
    assert_eq!(run(&cached(), "synthetic"), without);
}

/// Rows without their matched column (the predicate labels differ).
fn strip(rows: &[String]) -> Vec<&str> {
    rows.iter().map(|l| l.rsplit_once(" | ").unwrap().0).collect()
}
