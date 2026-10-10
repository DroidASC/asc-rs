# asc-rs — Droid ASC in Rust

Rust port of [Droid ASC](https://github.com/MG1937/ASC) ("R8 Compiler Optimization as a
DeCompiler Primitive"): a stateless, zero-preprocessing engine that treats an APK as a
read-only database. It locates a class, searches cross references or decodes the manifest
directly from the compressed artifact in milliseconds, without building any global index.

```
usage: droidasc [--debug] [--threads N] [--no-cache] [--cache-dir DIR] <COMMAND>

  getclass     Locate the target class in APK, extract one DEX in memory, then disassemble.
  listclass    List classes across all DEX entries (--prefix com.poc to filter).
  getmanifest  Decode AndroidManifest.xml from APK and print it as XML.
  findrefs     Find code references for string/type/method/field across all DEX entries in APK.
  gui          Launch the graphical browser.
  cache        Inspect or clear the on-disk cache (path | stats | clear).

  --threads N      worker threads (default: number of logical CPUs)
  --no-cache       bypass the on-disk cache of inflated DEX files
  --cache-dir DIR  use DIR instead of the default cache directory
  --debug          profiling output on stderr

examples:
  droidasc app.apk --gui
  droidasc getclass app.apk 'Lcom/poc/Main;' -o Main.smali
  droidasc getclass app.apk com.poc.Main --threads 16 --dump-dex Main.dex
  droidasc listclass app.apk --prefix com.poc -o classes.txt
  droidasc getmanifest app.apk -o AndroidManifest.xml
  droidasc findrefs app.apk string token -o string_refs.txt
  droidasc findrefs app.apk type com.poc.Main
  droidasc findrefs app.apk method onCreate --class com.poc.Main
  droidasc findrefs app.apk method notify --class MainActivity --fuzzy-class -o method_refs.txt
  droidasc findrefs app.apk field apiKey -o field_refs.txt
  droidasc findrefs app.apk string token --no-cache
  droidasc cache stats
```

Exit status is 0 on success, 1 on error and 2 when `findrefs` finished but some DEX entries
could not be searched (a warning per entry is printed on stderr).

The command line, query semantics and `findrefs` output format
(`classes2.dex | Lcom/x/Y;->m | matched=(token)`) are the same as the Python tool.

## Build

```sh
cargo build --release                       # CLI + GUI  -> target/release/droidasc
cargo build --release --no-default-features # CLI only (no egui/winit dependencies)
cargo test --workspace
```

Rust 1.85 or newer. The GUI (egui/eframe, OpenGL) needs a display; the CLI is headless.

## Workspace layout

| crate | role |
|---|---|
| `asc-dex` | Zero-copy DEX parser: header, id tables, MUTF-8, LEB128, class data, code items, encoded values, debug info, annotations, DEX 041 containers, checksum/signature. |
| `asc-dalvik` | Dalvik opcode table (generated from ART's `dex_instruction_list.h`), instruction formats, operand decoding, payload-aware instruction walk. |
| `asc-findrefs` | Cross-reference search on one DEX: regex string locator, type/method/field locators, dense 16-byte-bucket instruction→method resolver, raw code-region opcode scan. |
| `asc-rebuild` | Extracts one class plus everything it references and writes a minimal, spec-valid DEX (sorted id tables, annotations, debug info, try/catch, static values, Adler-32 + SHA-1). |
| `asc-smali` | baksmali-style disassembler used as the built-in output backend. |
| `asc-apk` | Memory-mapped zip access: central directory (incl. zip64), root-level DEX enumeration, Deflate inflation (libdeflate, or streaming zlib-rs for prefixes / cancellation). |
| `asc-cache` | Inflated-DEX caches: an on-disk cache shared across processes and a byte-bounded in-memory LRU for resident hosts. |
| `asc-axml` | Android binary XML → text XML for `AndroidManifest.xml`. |
| `asc-engine` | Orchestration: parallel class lookup with early stop, streaming multi-DEX reference search, class rebuild + disassembly, manifest decoding. |
| `asc-cli` | `droidasc` binary (clap). |
| `asc-gui` | egui browser: package tree with context menus, tabbed disassembly with find and jump-to-method, streaming reference searches kept as a history panel, class-name suggestions, manifest view; panel sizes, theme and search preferences persist across runs. |
| `asc-fixture` | Synthetic DEX/APK fixtures shared by the tests. |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the pieces map onto the Python
modules and where the port deliberately differs.

## Differences from the Python implementation

* **Output of `getclass` is smali, not Java.** The Python tool leans on androguard's
  decompiler; there is no equivalent Rust library. Instead the rebuilt DEX is a fully valid
  single-class DEX (canonically sorted tables, correct checksum and signature), so it can be
  written out with `--dump-dex` and fed to jadx, baksmali, dexdump or any other tool. jadx
  has been verified to decompile such DEX files to Java.
* **Correct string decoding.** Non-ASCII class and member names (common in obfuscated apps)
  are decoded as MUTF-8; the Python version truncates them.
* **Threads instead of processes** for `findrefs`; results still stream per DEX as they
  complete. `getclass` returns as soon as one worker finds the class; workers still
  inflating another DEX finish in the background.
* Global `--debug` / `--threads` flags can appear anywhere on the command line.
* `invoke-polymorphic` method and proto operands are remapped during rebuild
  (the Python version leaves them dangling); `invoke-custom` / method handles are still not
  rebuilt. A class that cannot be rebuilt (undefined opcode, `invoke-custom`) is still
  shown, disassembled straight from the original DEX, with a warning on stderr;
  `--dump-dex` is refused for it.
* Regex details differ at the edges: a match that spans several string items is
  attributed to the item where it *starts* (Python: where it ends); patterns use
  `regex` Unicode semantics, so `.` does not cross MUTF-8-encoded NUL bytes or
  surrogates the way Python's byte-`re` does; an empty `string` pattern matches nothing
  (Python: every string).
* `getmanifest` names attributes from the resource id whenever it is a known framework
  attribute (androguard only when the pool name is empty), so obfuscated manifests show
  `android:name` instead of `android:a`; unknown ids print as `attr_0x........`.
* `gui` runs in the foreground; the Python tool forks a detached process.

## Performance

Measured on Linux (this workstation, 8 threads, warm page cache, median of 5 fresh
processes, output discarded) against a synthetic 14-DEX / 95 MB APK assembled from real
apps, side by side with the upstream `rust` branch (`rasc`) and the Python reference
(CPython 3, androguard 4.1.3):

| scenario | rasc | asc-rs | Python | rows rasc / asc-rs / Python |
|---|---:|---:|---:|---|
| `findrefs string Authorization` | 64 ms | 64 ms | 208 ms | 44 / 44 / 44 |
| `findrefs string okhttp` | 63 ms | 63 ms | 206 ms | 19 / 19 / 19 |
| `findrefs type Gson` | 63 ms | 65 ms | 229 ms | 369 / 369 / 369 |
| `findrefs method onCreate` | 64 ms | 69 ms | 287 ms | 645 / 654 / 654 |
| `findrefs method onCreate --class androidx --fuzzy-class` | 64 ms | 66 ms | 263 ms | 168 / 168 / 168 |
| `findrefs field INSTANCE` | 64 ms | 65 ms | 267 ms | 530 / 531 / 531 |
| `getclass` early class (`classes.dex`) | 251 ms | 36 ms | 2041 ms | Java / smali / Java |
| `getclass` late class (`classes13.dex`) | 88 ms | 82 ms | 288 ms | |
| `getclass` missing class | 30 ms | 20 ms | 258 ms | |
| `getmanifest` | 3 ms | 2 ms | 128 ms | |
| **geometric mean speed-up vs Python** | **5.6×** | **7.3×** | | |
| geometric mean, `findrefs` only | 3.8× | 3.7× | | |

asc-rs reproduces the Python reference row-for-row; rasc uses literal, instruction-boundary
matching and drops a few rows. `getclass` outputs differ in kind (rasc decompiles to
Java, asc-rs disassembles), so that row measures different work. The upstream README's
8.0× figure was taken on macOS, where the Python process pool is far slower to start; on
Linux both Rust ports land at 3-4× for reference search, which is bounded by inflating the
largest DEX.

What it took to get there, in order of impact:

* the instruction→method bucket table is a dense `Vec<u32>` over the code region (range
  fills instead of one hash insert per 16-byte bucket);
* Deflate entries are inflated with libdeflate (`asc-apk` feature `libdeflate`, on by
  default; `--no-default-features` keeps the pure-Rust zlib-rs path);
* `findrefs` hands out the largest DEX first: its inflate is the critical path and must
  not queue behind the small ones (the Python and rasc order is smallest-first);
* `getclass` streams only the id tables and string data of each DEX (typically a third of
  it) to decide whether the class is defined there, and fully inflates just the hit;
* release profile with fat LTO and a single codegen unit.

## Caching for repeated queries

Inflating the largest DEX is the critical path of every query and always yields the same
bytes, so the engine caches inflated entries. Nothing is precomputed: the first query pays
the normal cost and fills the cache as a side effect.

* **On-disk cache** (`~/.cache/droidasc`, or `$DROIDASC_CACHE_DIR` / `$XDG_CACHE_HOME`),
  on by default for the CLI and shared between processes. Entries are keyed by the APK's
  size, mtime and central directory, written atomically, memory-mapped on the next run and
  evicted least-recently-used above 4 GiB. Writes are queued to a background thread, so a
  query never waits for its own cache entry to be written (the process still lands queued
  writes before exiting). The directory carries a `CACHEDIR.TAG`; a `--cache-dir` that
  already holds other files (dot-files included) is refused outright with a warning and the
  disk cache is disabled (nothing is written, tagged, evicted or cleared there), and eviction and `cache clear` only ever touch entry directories of the
  cache's own naming shape. `--no-cache` bypasses it,
  `--cache-dir` moves it, `droidasc cache path|stats|clear` manages it.
* **In-memory LRU** (GUI and embedders, `CacheConfig::resident`) that also keeps the
  locator tables built for each DEX, so a second query only runs the regex, the scan and
  the offset→method resolution.

Same 14-DEX / 95 MB APK, 8 threads, median of 5 fresh processes:

| scenario | cold | disk cache warm |
|---|---:|---:|
| `findrefs string Authorization` | 65 ms | 9 ms |
| `findrefs string okhttp` | 63 ms | 9 ms |
| `findrefs type Gson` | 64 ms | 12 ms |
| `findrefs field INSTANCE` | 65 ms | 19 ms |
| `findrefs method onCreate` | 65 ms | 21 ms |
| `getclass` early class | 38 ms | 12 ms |
| `getclass` late class | 80 ms | 3 ms |
| `getclass` missing class | 25 ms | 2 ms |

With a warm in-memory cache a reference search over the same archive is one scan per DEX
(about 4 ms for a 4 MB code region) with no table builds at all.

The scan itself adapts to the query: up to eight target indexes are found with SIMD
`memmem` over the operand bytes (0.2 ms per 4 MB instead of 3 ms), string queries use
`memchr2` over their two opcodes, and clustered index sets are prefiltered with `memchr`
on the shared high operand byte before the linear sweep.

## License

Apache-2.0, same as the original project.
