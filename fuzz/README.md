# Fuzzing

libFuzzer targets for every parser asc runs on untrusted input. The contract
under test: malformed input returns an error, never panics, never allocates
out of proportion to its size and never loops forever.

This is a [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) crate with its
own workspace, excluded from the main one: it needs a nightly toolchain and is
neither built by `cargo build --workspace` nor published.

## Running

```sh
cargo install cargo-fuzz            # or: cargo binstall cargo-fuzz
rustup toolchain install nightly

cd fuzz
cargo run --example gen_seeds       # seed corpora into corpus/<target>/
cargo +nightly fuzz run -s none dex corpus/dex -- \
    -max_total_time=600 -rss_limit_mb=2048 -malloc_limit_mb=2048 -timeout=10
```

`-s none` drops AddressSanitizer: the parsers are safe Rust, so it only slows
the run down. Overflow checks and debug assertions stay on.

A crash lands in `artifacts/<target>/`. Minimise it, then replay it:

```sh
cargo +nightly fuzz tmin -s none dex artifacts/dex/crash-…
cargo +nightly fuzz run -s none dex artifacts/dex/minimized-from-…
```

Fix the library (return the crate's error, bound the allocation or the loop
by the input size), and keep the minimised input as a unit test in the crate
it broke, so `cargo test` replays it on stable. `corpus/`, `artifacts/` and
`target/` are ignored by git.

## Targets

Each target is a thin wrapper over a driver in `src/`, which walks as deep as
the crate's API reaches.

| Target | Crate | What one input goes through |
| --- | --- | --- |
| `dex` | asc-dex | DEX041 container split, header, every id table, class defs, class data, code items, debug info, annotations, static values (re-encoded and parsed back), `quick` probes |
| `dalvik` | asc-dalvik | walk, decode at every offset, operand accessors, range verification, the call-site value analysis (input: registers, ins, try count, try triples, code) |
| `findrefs` | asc-findrefs | a query of every kind (strings, types, members, field access, call constraints, class relations, definitions, compound), raw index scans, the call graph |
| `rebuild` | asc-rebuild, asc-smali | disassemble every class and method in place, rebuild every class, check the rebuilt DEX parses and disassembles |
| `axml` | asc-axml | binary XML to text and to a tree, with and without a resolver |
| `arsc` | asc-arsc | table index, every id named, listed, formatted and resolved; `ResTable_config` matching |
| `apk` | asc-apk | central directory, every entry read, inflated by prefix and opened as a nested archive under tight zip-bomb limits |
| `abc` | asc-abc | strict and lenient open, the full walk of asc-abc's tests (regions, classes, fields, methods, code, debug info, annotations, module records, literal arrays) |
| `arkisa` | asc-arkisa | walk and decode at every offset with every operand accessor |
| `pasm` | asc-pasm | the pandasm listing of every record, default and verbose options |
| `hap_json` | asc-hap | `module.json`, `pack.info`, `pkgContextInfo.json`, page list, route table, source maps |
| `hap_resources` | asc-hap | `resources.index` (both formats): every resource, lookups by id, name and reference |

The same walks, on deterministic mutants of the fixtures, run on stable in
`cargo test` (`tests/malformed.rs` of each crate and the crates' own
"never panics" tests), so CI covers them without a nightly toolchain.
