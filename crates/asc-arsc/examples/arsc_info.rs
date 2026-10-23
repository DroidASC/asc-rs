//! Print the chunk layout of a resources.arsc file: packages, their type
//! ids, and every type chunk's configuration and encoding.
//!
//! usage: cargo run -p asc-arsc --example arsc_info -- resources.arsc

fn main() {
    let path = std::env::args().nth(1).expect("usage: arsc_info resources.arsc");
    let data = std::fs::read(&path).expect("read");
    let t0 = std::time::Instant::now();
    let table = asc_arsc::ResTable::parse(data).expect("parse");
    println!("parsed in {} us", t0.elapsed().as_micros());
    for w in table.warnings() {
        println!("warning: {w}");
    }
    for p in table.packages() {
        println!(
            "package 0x{:02x} {} libraries={:?} staged={} overlayables={}",
            p.id,
            p.name,
            p.libraries,
            p.staged_aliases.len(),
            p.overlayables.len()
        );
        for t in p.type_ids() {
            println!("  type 0x{t:02x} {}", table.type_name(p, t).unwrap_or_default());
            for (config, flags, count) in p.type_chunks(t) {
                println!("    [{config}] flags=0x{flags:02x} entries={count}");
            }
        }
    }
}
