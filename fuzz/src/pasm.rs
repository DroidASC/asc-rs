//! `asc-pasm`: the pandasm listing of every record of an ABC file, with
//! the default options and with every optional annotation turned on.

use asc_abc::{Abc, ClassEntry};
use asc_pasm::Options;

/// Most records listed per input.
const MAX_RECORDS: usize = 64;

pub fn run(data: &[u8]) {
    let Ok(abc) = Abc::parse_lenient(data) else { return };
    let Ok(classes) = abc.classes() else { return };
    let verbose = Options::default().literal_limit(4).string_limit(16).ic_slots(true).lines(true).locals(true).source(None);
    for entry in classes.take(MAX_RECORDS) {
        let Ok(ClassEntry::Local(class)) = entry else { continue };
        for opts in [Options::default(), verbose] {
            let mut out = String::new();
            let _ = asc_pasm::write_record(&mut out, &abc, &class, &opts);
        }
    }
}
