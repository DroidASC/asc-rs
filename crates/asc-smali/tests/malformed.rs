//! Disassembling a malformed DEX fails with an error, never a panic:
//! deterministic mutants of the fixtures, every class and method of each.

use asc_dex::Dex;
use asc_fixture::mutate::mutants;
use asc_fixture::{ClassSpec, CodeSpec, DexBuilder, MethodSpec};
use asc_smali::{Options, SmaliError};

fn exercise(data: &[u8]) {
    let Ok(dex) = Dex::parse(data) else { return };
    for index in 0..dex.class_def_count().min(16) {
        let _ = asc_smali::disassemble_class_def(&dex, index, Options::default());
        let Ok(class) = dex.class_def(index) else { continue };
        let Ok(data) = dex.class_data(class.class_data_off) else { continue };
        for method in data.methods().take(64) {
            if let Ok(listing) = asc_smali::disassemble_method(&dex, method.method_idx, Options::default().param_names(false)) {
                let _ = listing.source_line(0);
            }
        }
    }
}

#[test]
fn mutated_fixtures_never_panic() {
    let seeds = [
        asc_fixture::make_dex(),
        asc_fixture::make_static_field_dex(),
        asc_fixture::make_rich_dex(),
        asc_fixture::make_truncated_insn_dex(),
        asc_fixture::make_short_static_values_dex(),
    ];
    for (i, seed) in seeds.iter().enumerate() {
        exercise(seed);
        for mutant in mutants(seed, 0x5a1 + i as u64, 500) {
            exercise(&mutant);
        }
    }
}

/// A DEX whose one method `LBig;->run()V` names a 64 KiB string `times` times.
fn naming_a_long_string(times: usize) -> Vec<u8> {
    let long = "x".repeat(1 << 16);
    let mut builder = DexBuilder::new();
    builder.string(&long).method("LBig;", "run", "V", &[]);
    let mut ids = builder.resolve();
    let string = ids.string(&long);
    let mut insns = Vec::new();
    for _ in 0..times {
        insns.extend_from_slice(&[0x1b, 0x00]); // const-string/jumbo v0
        insns.extend_from_slice(&string.to_le_bytes());
    }
    insns.extend_from_slice(&[0x0e, 0x00]); // return-void
    let code = CodeSpec { registers: 1, insns, ..CodeSpec::default() };
    let run = MethodSpec { idx: ids.method("LBig;", "run", "V", &[]), access: asc_dex::access::STATIC, code: Some(code) };
    ids.add_class(ClassSpec { descriptor: "LBig;".into(), direct_methods: vec![run], ..ClassSpec::default() }).finish()
}

/// 200 names of a 64 KiB string: 13 MB of text from a 66 KB DEX. A listing
/// stops at 64 times the DEX plus 1 MiB, so items named over and over
/// (shared code items and annotation sets, long strings) cannot expand a
/// small file without bound.
#[test]
fn a_listing_out_of_proportion_to_the_dex_is_cut_off() {
    let data = naming_a_long_string(200);
    let dex = Dex::parse(&data).unwrap();
    let err = asc_smali::disassemble_class(&dex, "LBig;", Options::default()).unwrap_err();
    assert!(matches!(err, SmaliError::TooLarge(_)), "{err}");
    let data = naming_a_long_string(4);
    let dex = Dex::parse(&data).unwrap();
    assert!(asc_smali::disassemble_class(&dex, "LBig;", Options::default()).unwrap().len() > 4 << 16);
}
