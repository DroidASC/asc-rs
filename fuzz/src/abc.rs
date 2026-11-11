//! `asc-abc`: open an ABC file strictly and leniently and walk everything
//! it holds (regions, classes, fields, methods, code, try blocks, debug
//! info, annotations, module records, literal arrays), with the walk
//! asc-abc's own tests use.

use asc_abc::Abc;

#[allow(dead_code, clippy::all)]
#[path = "../../crates/harmony/asc-abc/tests/common/mod.rs"]
mod common;

pub fn run(data: &[u8]) {
    if let Ok(abc) = Abc::parse(data) {
        let _ = (abc.classes_are_sorted(), abc.compute_checksum());
        let _ = common::walk(&abc, false);
        let _ = common::walk(&abc.with_sorted_classes(true), false);
    }
    if let Ok(abc) = Abc::parse_lenient(data) {
        let _ = abc.check_layout();
        let _ = common::walk(&abc, false);
        if let Ok(regions) = abc.regions() {
            for off in [0, 60, 0x100, u32::MAX] {
                let _ = (regions.containing(off), abc.region_of(off));
            }
        }
    }
}
