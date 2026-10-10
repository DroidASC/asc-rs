//! Class names outside the BMP: user input is UTF-8, DEX descriptors are
//! MUTF-8, so every exact lookup must encode before it compares.

use asc_engine::{names, Engine};
use asc_findrefs::Query;
use asc_fixture::{make_apk, ClassSpec, CodeSpec, DexBuilder, MethodSpec};
use std::io::Write;

const CLASS: &str = "Lexample/\u{1f600};";

/// `CLASS` with a static int `f` and `static m()V { sget v0, f; invoke-static m; return-void }`.
fn supplementary_dex() -> Vec<u8> {
    let mut d = DexBuilder::new();
    d.field(CLASS, "f", "I").method(CLASS, "m", "V", &[]);
    let mut ids = d.resolve();
    let f = ids.field(CLASS, "f", "I");
    let m = ids.method(CLASS, "m", "V", &[]);
    let mut insns = vec![0x60, 0x00];
    insns.extend((f as u16).to_le_bytes());
    insns.extend([0x71, 0x00]);
    insns.extend((m as u16).to_le_bytes());
    insns.extend([0x00, 0x00, 0x0e, 0x00]);
    ids.add_class(ClassSpec {
        descriptor: CLASS.into(),
        access: 0x1,
        static_fields: vec![(f, 0x9)],
        direct_methods: vec![MethodSpec { idx: m, access: 0x9, code: Some(CodeSpec { registers: 1, insns, ..Default::default() }) }],
        ..Default::default()
    });
    ids.finish()
}

fn temp_apk(deflate: bool) -> tempfile::NamedTempFile {
    let dex = supplementary_dex();
    let mut f = tempfile::Builder::new().suffix(".apk").tempfile().unwrap();
    f.write_all(&make_apk(&[("classes.dex", &dex)], deflate)).unwrap();
    f.flush().unwrap();
    f
}

fn lines(engine: &Engine, query: &Query) -> Vec<String> {
    let mut out = Vec::new();
    engine
        .find_refs(query, |batch| {
            assert!(batch.error.is_none(), "{:?}", batch.error);
            out.extend(batch.results.iter().map(|r| r.line()));
        })
        .unwrap();
    out
}

#[test]
fn supplementary_class_names_are_found() {
    for deflate in [false, true] {
        let apk = temp_apk(deflate);
        let engine = Engine::new(apk.path()).with_threads(1);

        let hit = engine.get_class_dex(CLASS).unwrap();
        assert!(hit.is_some(), "deflate={deflate}");
        let src = engine.get_class(CLASS).unwrap();
        assert!(src.rebuilt.is_some(), "{:?}", src.warning);
        assert!(src.source.contains(CLASS), "{}", src.source);

        for kind in ["method", "field"] {
            let name = if kind == "method" { "m" } else { "f" };
            let q = names::member_query(kind, Some(CLASS), false, Some(name)).unwrap();
            let q = if kind == "method" { Query::Method(q) } else { Query::Field(q) };
            let found = lines(&engine, &q);
            assert_eq!(found.len(), 1, "{kind} deflate={deflate}: {found:?}");
            assert!(found[0].contains(CLASS), "{found:?}");
        }
    }
}
