//! Rebuilding a class of a malformed DEX fails with an input error, never
//! a panic or an internal error, and whatever it does write is a DEX that
//! defines the class: deterministic mutants of the fixtures, every class of
//! each.

use asc_dex::Dex;
use asc_fixture::mutate::mutants;
use asc_rebuild::RebuildError;

fn exercise(data: &[u8]) {
    let Ok(dex) = Dex::parse(data) else { return };
    for class in dex.class_defs().take(16).flatten() {
        let Ok(descriptor) = dex.type_descriptor(class.class_idx) else { continue };
        let rebuilt = match asc_rebuild::rebuild_class(&dex, &descriptor) {
            Ok(rebuilt) => rebuilt,
            // Internal means a pipeline bug; malformed input has its own errors.
            Err(e @ RebuildError::Internal(_)) => panic!("{descriptor}: {e}"),
            Err(_) => continue,
        };
        let again = Dex::parse(&rebuilt.bytes).expect("a rebuilt DEX parses");
        assert!(matches!(again.find_class_def(&asc_dex::mutf8::encode(&descriptor)), Ok(Some(_))), "rebuilt DEX lacks {descriptor}");
    }
}

#[test]
fn mutated_fixtures_never_panic() {
    let seeds = [
        asc_fixture::make_dex(),
        asc_fixture::make_static_field_dex(),
        asc_fixture::make_rich_dex(),
        asc_fixture::make_class_only_dex(&["LA;", "LA$1;", "LA$1$b;"], 0, false),
        asc_fixture::make_short_static_values_dex(),
    ];
    for (i, seed) in seeds.iter().enumerate() {
        exercise(seed);
        for mutant in mutants(seed, 0x4eb + i as u64, 1000) {
            exercise(&mutant);
        }
    }
}
