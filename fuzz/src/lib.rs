//! Drivers of the fuzz targets: each `run` hands untrusted bytes to the
//! entry points the engine uses and walks as deep as the API reaches.
//! Errors are expected and ignored; a panic, a hang or a runaway
//! allocation is the bug.

pub mod abc;
pub mod apk;
pub mod arkisa;
pub mod arsc;
pub mod axml;
pub mod dalvik;
pub mod dex;
pub mod findrefs;
pub mod hap_json;
pub mod hap_resources;
pub mod pasm;
pub mod rebuild;

/// Most items of one table a driver visits: a count read from a damaged
/// header may claim billions of entries, each failing on its own, and the
/// library's own loops are what is under test, not the driver's.
pub const MAX_ITEMS: u32 = 2048;
