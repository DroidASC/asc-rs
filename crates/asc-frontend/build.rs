//! Bakes the target triple in: the auto-install fetches the worker built for it.

fn main() {
    let target = std::env::var("TARGET").expect("cargo sets TARGET for build scripts");
    println!("cargo:rustc-env=ASC_BUILD_TARGET={target}");
    println!("cargo:rerun-if-changed=build.rs");
}
