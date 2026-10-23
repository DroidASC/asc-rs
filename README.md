# asc-rs — Droid ASC in Rust

Rust port of [Droid ASC](https://github.com/MG1937/ASC) ("R8 Compiler Optimization as a
DeCompiler Primitive"): a stateless, zero-preprocessing engine that treats an APK as a
read-only database. It locates a class, searches cross references or decodes the manifest
directly from the compressed artifact in milliseconds, without building any global index.

```
usage: droidasc [--debug] [--threads N] [--no-cache] [--cache-dir DIR] [--cache-max-mb MIB]
                [--memory-mb MIB] <COMMAND>

  getclass     Locate the target class in APK, extract one DEX in memory, then disassemble.
  disassemble  Same, without debug directives unless --debuginfo (Python's smali command).
  listclass    List classes across all DEX entries (--prefix com.poc to filter). Alias: classes.
  getmanifest  Decode AndroidManifest.xml from APK and print it as XML (--resolve: resource
               references by name). Alias: manifest.
  manifest-summary  The manifest's attack surface, one record per line (--json): exported
               components and why, permissions, providers, deep links, FileProvider paths,
               network security config.
  resources    Query resources.arsc: one resource (id or type/name, --resolve), --search, or
               the whole table, one line per resource and configuration.
  xml          Decode any binary XML file of the APK (res/xml/..., layouts) with names.
  findrefs     Find code references for string/type/method/field, or subclasses / implementors
               (extends / impl), across all DEX entries in APK.
  callgraph    Callers (default) or callees of a method across all DEX entries, as a tree.
  gui          Launch the graphical browser.
  mcp          Serve MCP tools over stdio, keeping opened APKs resident.
  cache        Inspect or clear the on-disk cache (path | stats | clear).

  --threads N      worker threads (default: number of logical CPUs); --thread N also works
  --no-cache       bypass the on-disk cache of inflated DEX files
  --cache-dir DIR  use DIR instead of the default cache directory
  --cache-max-mb MIB  on-disk cache budget (default: automatic, see "Caching")
  --memory-mb MIB  in-memory budget of gui / mcp (default: automatic)
  --debug          profiling output on stderr
  -v, -V, --version

examples:
  droidasc app.apk --gui
  droidasc getclass app.apk 'Lcom/poc/Main;' -o Main.smali
  droidasc getclass app.apk com.poc.Main --threads 16 --dump-dex Main.dex
  droidasc disassemble app.apk com.poc.Main --debuginfo
  droidasc disassemble app.apk com.poc.Main --method 'run(I)V'
  droidasc listclass app.apk --prefix com.poc -o classes.txt
  droidasc getmanifest app.apk -o AndroidManifest.xml
  droidasc getmanifest app.apk --resolve
  droidasc manifest-summary app.apk | grep exported=true
  droidasc resources app.apk string/app_name
  droidasc resources app.apk 0x7f0d0001 --resolve
  droidasc resources app.apk --search 'https?://' --in value
  droidasc xml app.apk res/xml/network_security_config.xml
  droidasc getclass app.apk com.poc.Main --res-names
  droidasc findrefs app.apk string token -o string_refs.txt
  droidasc findrefs app.apk string 'https://' --literal
  droidasc findrefs app.apk type com.poc.Main
  droidasc findrefs app.apk extends android.app.Activity -o subclasses.txt
  droidasc findrefs app.apk impl android.os.IInterface
  droidasc findrefs app.apk method onCreate --class com.poc.Main
  droidasc findrefs app.apk method notify --class MainActivity --fuzzy-class -o method_refs.txt
  droidasc findrefs app.apk method run --class com.poc.Main --exact
  droidasc findrefs app.apk field apiKey -o field_refs.txt
  droidasc findrefs app.apk string token --no-cache
  droidasc findrefs app.apk string token --context 3
  droidasc findrefs app.apk method loadUrl --context-method
  droidasc callgraph app.apk com.poc.Main onCreate --depth 3
  droidasc callgraph app.apk com.poc.Main 'run(I)V' --callees
  droidasc mcp --memory-mb 4096
  droidasc cache stats
```

Exit status is 0 on success, 1 on error and 2 when `findrefs` or `callgraph` finished but
some DEX entries could not be searched (a warning per entry is printed on stderr).

The command line, query semantics and `findrefs` output format
(`classes2.dex | Lcom/x/Y;->m | matched=(token)`, and `classes.dex | Lcom/x/Sub; extends
Lcom/x/Base;` for `extends` / `impl`) are the same as the Python tool.

`getclass` and `disassemble` take `--method 'run(I)V'` to render a single method given its
exact signature (a bare name is rejected). `findrefs extends` / `impl` list the classes
whose direct superclass / one of whose direct interfaces is the target (dotted or Dalvik
form). `findrefs string --literal` matches a plain substring instead of a regex.

`findrefs --context N` prints, after each result, where the references are and the smali
around them, so the next step rarely needs a `getclass`; `--context-method` prints the
whole method (a method over 150 lines shows 10 lines around each reference instead):

```
classes.dex | Lcom/poc/Main;->run | matched=(token)
  @ pc 0x4 line 12
        .line 12
  >     const-string v0, "token"
        invoke-static {v0}, Lcom/poc/Net;->send(Ljava/lang/String;)V
```

`callgraph APK CLASS METHOD` walks callers (or `--callees`) `--depth` levels (default 2,
at most `--max-nodes` methods, default 500), across DEX files. `METHOD` is a name (every
overload) or an exact `name(params)ret`. One line per call; `[no body]` marks methods no
DEX of the APK defines (framework / SDK), `(repeated)` methods expanded elsewhere:

```
0 Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V [no body]
  1 <- Lcom/poc/Web;->open(Ljava/lang/String;)V
    2 <- Lcom/poc/DeepLink;->onCreate(Landroid/os/Bundle;)V
# 3 rows, 3 distinct methods (callers, depth 2)
```

The graph is the static references in the bytecode: a call through `Lcom/poc/Sub;->m()V`
is not a call of `Lcom/poc/Base;->m()V`.

Scripts written for the other Rust ports keep working: `classes` and `manifest` are
aliases of `listclass` and `getmanifest` (as in rasc), `--thread` of `--threads` (as in
rust_ASC), and `--literal` gives their literal string matching.

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
| `asc-findrefs` | Cross-reference search on one DEX: regex / literal (`memmem`) string locator, subclass / implementor lookup over `class_def_item`s, type/method/field locators, dense 16-byte-bucket instruction→method resolver, raw code-region opcode scan. |
| `asc-rebuild` | Extracts one class plus everything it references and writes a minimal, spec-valid DEX (sorted id tables, annotations, debug info, try/catch, static values, Adler-32 + SHA-1). |
| `asc-smali` | baksmali-style disassembler used as the built-in output backend. |
| `asc-apk` | Memory-mapped zip access: central directory (incl. zip64), root-level DEX enumeration, Deflate inflation (libdeflate, or streaming zlib-rs for prefixes / cancellation). |
| `asc-cache` | Inflated-DEX caches: an on-disk cache shared across processes and a byte-bounded in-memory LRU for resident hosts. |
| `asc-axml` | Android binary XML: text XML, an element tree, names for references through a resolver; lazy string pools. |
| `asc-arsc` | `resources.arsc` reader: indexes chunks only and decodes names and values on demand (u32 / 16-bit / sparse entry tables, compact entries, bags, library / overlayable / staged-alias chunks); per-config values, AOSP config matching and reference resolution. Checked against `aapt2 dump resources` (`bench/arsc-compare`). |
| `asc-engine` | Orchestration: parallel class lookup with early stop, streaming multi-DEX reference search, class rebuild + disassembly, manifest decoding and summary, resource queries. |
| `asc-mcp` | MCP server over stdio (`droidasc mcp`): one resident session, several APKs sharing one memory budget, CLI-format text plus structured results, paging. |
| `asc-cli` | `droidasc` binary (clap). |
| `asc-gui` | egui browser: package tree with context menus, tabbed disassembly with find and jump-to-method, `X` for references to the member under the cursor and Ctrl+click to its declaration, streaming reference searches kept as a history panel, class-name suggestions, manifest view; panel sizes, theme and search preferences persist across runs. |
| `asc-fixture` | Synthetic DEX/APK fixtures shared by the tests. |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the pieces map onto the Python
modules and where the port deliberately differs.

## Differences from the Python implementation

* **Output of `getclass` is smali, not Java.** The Python tool leans on androguard's
  decompiler; there is no equivalent Rust library. Instead the rebuilt DEX is a fully valid
  single-class DEX (canonically sorted tables, correct checksum and signature), so it can be
  written out with `--dump-dex` and fed to jadx, baksmali, dexdump or any other tool. jadx
  has been verified to decompile such DEX files to Java. `disassemble` (upstream's smali
  command) shares the same backend: baksmali-style output rather than dadguard's format,
  and `--debug` adds timings but no per-instruction offset comments.
* **Correct string decoding.** Non-ASCII class and member names (common in obfuscated apps)
  are decoded as MUTF-8; the Python version truncates them.
* **Threads instead of processes** for `findrefs`; results still stream per DEX as they
  complete. `getclass` returns as soon as one worker finds the class; workers still
  inflating another DEX finish in the background.
* Global `--debug` / `--threads` flags can appear anywhere on the command line;
  `--threads 0` runs one worker (Python's `listclass` rejects it).
* Every root-level `*.dex` is a DEX entry (Python prefers `classes*` names), and a
  duplicated entry name resolves to its last central-directory record (Python: the
  first). This holds for `getclass`, `findrefs` and `listclass` alike.
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
* `findrefs extends` compares each `class_def_item`'s superclass field directly; Python
  scans the packed table with a non-overlapping regex, which could in principle hide an
  aligned match behind an unaligned one (no row differs on the reference fixtures).
  `findrefs string --literal` and the `classes` / `manifest` aliases are extensions with
  no Python counterpart; `classes` keeps the `listclass` output (not rasc's
  `dex | descriptor | java name | package= | class=` rows) and has no `-f/--filter`.
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
  size, mtime and central directory, written atomically and memory-mapped on the next run,
  in three tiers under one budget (see below):

  | tier | holds | written when | evicted |
  |---|---|---|---|
  | L1 | inflated DEX entries | inflated, 4 MiB or larger (`$DROIDASC_CACHE_MIN_DEX_MB`): re-inflating a small DEX is cheaper than writing it | first, largest and oldest first |
  | L2 | locator tables and call graphs per DEX, in a form the next process maps and reads in place (every process mapping them shares one copy) | built in 2 ms or more | last, least rebuild time saved per byte first |
  | L3 | `findrefs` results, keyed by the query, its options and the build of the tool | the query ran without errors, result under 4 MiB | own budget: min(128 MiB, 1/8 of the total), oldest first |

  Entries of APKs that were deleted or replaced since go before anything else.
  `$DROIDASC_CACHE_TIERS=dex,derived,rendered` picks the tiers (all by default).
  Writes are queued to a background thread, so a
  query never waits for its own cache entry to be written (the process still lands queued
  writes before exiting). The directory carries a `CACHEDIR.TAG`; a `--cache-dir` that
  already holds other files (dot-files included) is refused outright with a warning and the
  disk cache is disabled (nothing is written, tagged, evicted or cleared there), and eviction and `cache clear` only ever touch entry directories of the
  cache's own naming shape. `--no-cache` bypasses it,
  `--cache-dir` moves it, `droidasc cache path|stats|clear` manages it (`stats` prints
  each tier's usage, the budget, where it comes from and the file system's free space).
* **In-memory LRU** (GUI and embedders, `CacheConfig::resident` / `resident_auto`) that
  also keeps the locator tables built for each DEX, so a second query only runs the
  regex, the scan and the offset→method resolution. Its budget counts those tables too
  (102 MB on top of Douyin's 437 MB of DEX after string and type queries), and the GUI sizes it
  from the machine: a quarter of the available memory (`MemAvailable`, or the cgroup v2
  headroom when lower), clamped to 64 MiB–2 GiB, so several open browsers do not each
  claim 2 GiB. With the disk cache on, an entry inflated on the heap is swapped for a
  mapping of its cache file as soon as that file is written (after a byte-for-byte
  check), and locator tables for a view of their L2 file, so resident entries are
  file-backed pages the OS can reclaim and share between processes rather than anonymous
  memory. Entries an APK stores uncompressed (nearly every system app) are mapped from
  the APK itself.

Both caches size themselves from the machine unless given a number:

| | automatic budget | explicit |
|---|---|---|
| disk | 20 % of what the cache could hold (its own bytes + the file system's free space), at most 4 GiB, and never so much that less than max(1 GiB, 5 % of the file system) stays free; 4 GiB where the free space cannot be read (Windows) | `--cache-max-mb MIB`, else `$DROIDASC_CACHE_MAX_MB` |
| memory (gui, mcp) | one budget for all of the user's running `gui` / `mcp` processes, split evenly: a quarter of (available memory + what their caches hold), divided by the number of processes, 64 MiB–2 GiB each; 2 GiB where it cannot be read. Each process registers in `$XDG_RUNTIME_DIR/droidasc` and re-reads the registry at most once a second | `--memory-mb MIB` (fixed; still registered, so the others count it) |

The disk budget is re-evaluated at every eviction pass (once per burst of writes, the
same directory walk as before) and each automatic-budget write first checks the free
space with one `statvfs`: an entry that would cut into the reserve is not written, and
when another program has filled the disk the next eviction shrinks the cache below what
it holds, oldest APKs first. One-shot CLI commands keep no memory cache, so
`--memory-mb` only matters for `gui` and `mcp`.

Resident memory of one process holding the GUI's engine state (16 threads, Douyin
40.7.0 = 437 MB of DEX, then Kuaishou and Xiaohongshu opened in the same process; class
scan plus three queries each):

| | anonymous before | anonymous after | file-backed after |
|---|---:|---:|---:|
| Douyin, first open (disk cache cold) | 549 MB | 111 MB | 439 MB |
| three APKs, first open | 1150 MB | 224 MB | 910 MB |
| three APKs, disk cache warm | 227 MB | 225 MB | 923 MB |
| three APKs, `--no-cache` | 1148 MB | 1146 MB | 2 MB |

What stays anonymous is the locator tables. Without a disk cache the bytes have nowhere
to be mapped from, so `--no-cache` keeps them on the heap as before.

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

## MCP server

`droidasc mcp` is a resident session for agents: an MCP server on stdio (JSON-RPC 2.0, one
message per line). It keeps every APK it opens in one process, so the inflated DEX files
and locator tables stay in memory between calls instead of being rebuilt by a new process
per question. All opened APKs share one in-memory budget (`--memory-mb`, default a quarter of available memory, at most 2048 MiB); `close_apk` releases that APK's share; the
on-disk cache is used as by the CLI (`--no-cache`, `--cache-dir`). Tool calls run concurrently (a slow
query does not block `ping` or other calls; replies carry their request id and may arrive
out of order), and a panic inside one call is returned as an error result rather than
ending the session.

```json
{
  "mcpServers": {
    "droidasc": { "command": "/absolute/path/to/droidasc", "args": ["mcp"] }
  }
}
```

| tool | arguments | result |
|---|---|---|
| `open_apk` | `apk`, `warm` (default true: inflate every DEX now); or `apks` / `dir` | `apk_id`; the same path returns the same id. For many APKs: one line per APK (id, DEX count and size, path), nothing inflated |
| `close_apk` | `apk_id` or `apk` | releases that APK's share of the memory cache |
| `getclass` | `class`, `debug_info`, `method` (exact signature), `resource_names` (default true) | smali, as `droidasc getclass [--method] --res-names`: constants that are resource ids end in `# @type/name` |
| `findrefs` | `kind` (`string`/`type`/`method`/`field`/`extends`/`impl`), `value` or `name`, `literal`, `class`, `fuzzy_class`, `exact`, `context` (N lines or `"method"`), `offset`, `limit` (500) | `findrefs` lines in DEX order (each followed by its context), then a `# N results` line; with `context`, `structuredContent` rows carry `sites` (`pc`, `line`, `matched`) and `context` |
| `callgraph` | `class`, `method` (name or `name(params)ret`), `direction` (`callers`/`callees`), `depth` (2), `max_nodes` (200) | the `droidasc callgraph` tree; `rows` with `depth`, `parent`, `method`, `dex`, `repeated` |
| `listclass` | `prefix`, `offset`, `limit` (1000) | class descriptors |
| `getmanifest` | `resolve` | decoded XML (references by name with `resolve`) |
| `manifest_summary` | `filter` (`all` / `exported`); or `apks` / `dir` | the `droidasc manifest-summary` records; `exported` keeps what other apps can reach (exported components, deep links, non-signature permissions, cleartext domains). For many APKs (default `exported`): per APK `apkN \| package \| minSdk / targetSdk \| exported: 3 activity, 1 provider \| flags: debuggable,allowBackup,cleartext`, then its records |
| `resources` | `query` (+ `resolve`), `search` (+ `in`, `literal`), `limit`, or `xml` (a path in the APK); or `apks` / `dir` | `droidasc resources` rows (`0x7f0d0001 string/app_name [zh-rCN] "..."`), or the decoded XML file |

Every tool except `open_apk` takes `apk_id` or an `apk` path (opened on first use). Results
carry the CLI text as `content` and the same data as `structuredContent` (`total` and
`next_offset` for paged tools). Failures come back as `isError: true` results; the session
keeps running.

`notifications/cancelled` stops a running call (work not yet started is skipped and the call
gets no reply). Every APK is treated as untrusted: an entry that would inflate past 1 GiB or
expand more than 100:1 is refused (`--max-entry-mb`, `--max-ratio`), and only that APK fails.

#### Many APKs in one call

`findrefs`, `listclass`, `open_apk`, `manifest_summary` and `resources` also take `apks` (paths) or `dir` (with `glob`,
default `*.apk`, and `recursive`, default true) instead of one APK. Every DEX of every APK
goes on one work queue (heaviest APK first), and the reply has one section per APK, every
line prefixed with its `apk_id` (excerpt of a real reply; a section can also end with
`apkN | more | 3 more: findrefs {"apk_id":"apkN","kind":…,"offset":10,…}` hints whose JSON is
the complete arguments of the follow-up call (also in `structuredContent` as `next`), `apkN | sdk | Landroidx/ 23, …` folded counts and warnings).
A findrefs sweep replays an APK's rows from the disk cache when the same query already ran on
that APK version (one-APK and sweep calls share them), and searches a DEX that several APKs
carry byte for byte only once (`structuredContent`: `apks_from_result_cache`, `dex_shared`):

```
# findrefs method addJavascriptInterface over 312 APKs: 20 with hits, 103 hits, 0 errors, 193 ms
apk15 | 1 hits | /data/apks/com.android.carrierdefaultapp.apk
apk15 | classes.dex | Lcom/android/carrierdefaultapp/SlicePurchaseActivity;->setupWebView | matched=(Landroid/webkit/WebView;->addJavascriptInterface)
apk124 | 6 hits | /data/apks/com.android.vending.apk
apk124 | classes3.dex | Lzlc;->c | matched=(Landroid/webkit/WebView;->addJavascriptInterface)
apk124 | classes3.dex | Lzln;-><init> | matched=(Lzlm;->addJavascriptInterface)
...
# nothing in the other 292 APKs
# APKs 0..4 of 20 shown (output budget 32768 bytes); call findrefs with cursor="1:4" for the rest
```

| argument | effect |
|---|---|
| `per_apk` (10) | rows shown per APK; the `more` line says how to page that APK |
| `collapse_sdks` (true for many APKs) / `sdk_prefixes` | fold hits in common SDK packages (androidx, kotlin, gms, okhttp3, …; `--sdk-prefixes` replaces the list) into per-SDK counts |
| `group: "package"`, `package_depth` (3) | one line per package with its hit count and an example, instead of rows |
| `max_bytes` (32768) | output budget; whole APK sections that do not fit are left for `cursor` |
| `cursor` | pass back alone to the same tool for the next page (the session keeps the last 16 reports) |
| `release` | drop each APK's DEX from memory once searched (default: when the selected APKs' DEX would not fit the memory budget) |

Exposure audit with [`bench/multi-apk/audit.py`](bench/multi-apk/audit.py): the 8 rules of the
multi-APK benchmark over the 312 system APKs of a Pixel 6 (3.8 GB, 405 DEX, 1.28 GB of DEX),
one `droidasc --no-cache mcp`:

| | tool calls | reply text | wall | peak RSS |
|---|---:|---:|---:|---:|
| one call per APK per rule, a rule's 312 calls pipelined | 2,496 | 762 KiB | 416 ms | 1,667 MB |
| one `dir` call per rule, first page only | **8** | **166 KiB** | 480 ms | 1,695 MB |
| one `dir` call per rule, every cursor page | 14 | 297 KiB | 480 ms | 1,691 MB |
| one `dir` call per rule, `release: true` | 8 | 166 KiB | 1,573 ms | 565 MB |

### Agent session benchmark

The 17 analysis goals (47 steps) of the [dexsql-release agent audit](https://github.com/LSPosed/dexsql-release/tree/main/benchmarks/agent-audit),
replayed by [`bench/agent-audit/replay_mcp.py`](bench/agent-audit/replay_mcp.py) on
Douyin 40.7.0 (343 MiB, 56 DEX, 551,080 classes). Same machine (Linux, 16 threads, 12 GB),
dexsql 0.1.1 linux-amd64 measured with its own `dexsql_replay.py` / `whole_suite.py`; asc-rs
with `--no-cache` unless noted. Medians of 7.

| | asc-rs `mcp` | asc-rs `mcp`, disk cache warm | dexsql 0.1.1 MCP | rasc (process per step) |
|---|---:|---:|---:|---:|
| open the APK | 77 ms | 18 ms | 589 ms | — |
| whole session: start, open, 17 goals, exit | **218 ms** | 153 ms | 1,112 ms | 3,819 ms |
| per goal once open, geometric mean | **5.3 ms** | 5.3 ms | 22.6 ms | — |
| peak RSS | 646 MB | 522 MB | ~1.35 GB (two processes) | ~350 MB per step |

Every goal finds its evidence; three of the expected tokens are Java spellings that read
differently in smali (`new java.io.File` → `Ljava/io/File;-><init>`, `36865` → `0x9001`,
`return true` → `const/4 v0, 0x1` / `return v0`). dexsql answers SQL, including multi-hop
call-graph joins that `findrefs` cannot express; this compares only these goals.

## License

Apache-2.0, same as the original project.
