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

    // A `!annotation:` part drops the annotated method only.
    let unmarked = lines(&engine, "in:{annotation:example.Marker} & !annotation:example.Marker");
    assert_eq!(unmarked.len(), in_marker.len() - 1, "{unmarked:?}");
    assert!(!unmarked.iter().any(|l| l.contains("->handle(")), "{unmarked:?}");

    // in:{type:...}: methods of classes whose descriptor matches the regex.
    let iface = lines(&engine, "in:{type:Lexample/Iface;}");
    assert_eq!(iface, ["classes.dex | Lexample/Iface;->run()V | in"]);

    // An annotation type absent from the program matches nothing.
    assert!(lines(&engine, "annotation:example.Absent").is_empty());
}
