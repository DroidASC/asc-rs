//! Disassembling a malformed DEX fails with an error, never a panic:
//! deterministic mutants of the fixtures, every class and method of each.

use asc_dex::Dex;
use asc_fixture::mutate::mutants;
use asc_smali::Options;

fn exercise(data: &[u8]) {
    let Ok(dex) = Dex::parse(data) else { return };
    for index in 0..dex.class_def_count().min(16) {
        let _ = asc_smali::disassemble_class_def(&dex, index, Options::default());
        let Ok(class) = dex.class_def(index) else { continue };
        let Ok(data) = dex.class_data(class.class_data_off) else { continue };
        for method in data.methods().take(64) {
            if let Ok(listing) = asc_smali::disassemble_method(&dex, method.method_idx, Options { line_numbers: true, param_names: false })
            {
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
