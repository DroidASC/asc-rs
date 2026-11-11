#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| asc_fuzz::findrefs::run(data));
