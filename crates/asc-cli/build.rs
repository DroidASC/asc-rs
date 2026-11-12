//! The `asc` binary's main thread gets the stack Linux gives it (8 MiB):
//! Windows starts the main thread with 1 MiB, which deep query parsing and
//! a debug build's command-line parser overflow.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os == "windows" {
        if target_env == "msvc" {
            println!("cargo:rustc-link-arg-bin=asc=/STACK:8388608");
        } else {
            println!("cargo:rustc-link-arg-bin=asc=-Wl,--stack,8388608");
        }
    }
}
