//! `asc-rebuild` and `asc-smali`: rebuild every class of a DEX, disassemble
//! it in place and from the rebuilt file, and check that a rebuilt file
//! parses again.

use asc_dex::Dex;
use asc_rebuild::RebuildError;
use asc_smali::Options;

/// Most classes rebuilt per input: each rebuild copies what the class
/// reaches, so a few are enough to cover the pipeline.
const MAX_CLASSES: u32 = 16;

pub fn run(data: &[u8]) {
    let Ok(dex) = Dex::parse(data) else { return };
    for index in 0..dex.class_def_count().min(MAX_CLASSES) {
        let _ = asc_smali::disassemble_class_def(&dex, index, Options::default());
        let Ok(class) = dex.class_def(index) else { continue };
        let Ok(descriptor) = dex.type_descriptor(class.class_idx) else { continue };
        let _ = asc_smali::disassemble_class(&dex, &descriptor, Options::debug_info(false));
        if let Ok(data) = dex.class_data(class.class_data_off) {
            for method in data.methods().take(crate::MAX_ITEMS as usize) {
                if let Ok(listing) = asc_smali::disassemble_method(&dex, method.method_idx, Options::default()) {
                    let _ = (listing.line_of(0), listing.source_line(0));
                }
            }
        }
        let rebuilt = match asc_rebuild::rebuild_class(&dex, &descriptor) {
            Ok(rebuilt) => rebuilt,
            // Internal means a pipeline bug; malformed input has its own errors.
            Err(e @ RebuildError::Internal(_)) => panic!("{descriptor}: {e}"),
            Err(_) => continue,
        };
        // What the rebuild writes is a well-formed DEX defining the class.
        let again = Dex::parse(&rebuilt.bytes).expect("rebuilt DEX parses");
        let found = again.find_class_def(&asc_dex::mutf8::encode(&descriptor));
        assert!(matches!(found, Ok(Some(_))), "rebuilt DEX lacks {descriptor}: {found:?}");
        asc_smali::disassemble_class(&again, &descriptor, Options::default()).expect("rebuilt class disassembles");
    }
}
