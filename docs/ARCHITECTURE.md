# Architecture

asc-rs answers queries against an APK without preprocessing it: the APK is a read-only
database, and everything a query needs (inflated DEX, locator tables, results) is built
lazily and cached. The crates follow the data: *format* → *search / rebuild* →
*orchestration* → *front ends*.

```
                     +-----------+        +-------------+
   APK (mmap) ─────> |  asc-apk  | ─DEX─> |   asc-dex   | <──── asc-dalvik (opcodes)
                     +-----------+        +------+------+
                                                 │
                 ┌───────────────────────────────┼──────────────────────────┐
                 v                               v                          v
          +--------------+               +--------------+            +-----------+
          | asc-findrefs |               |  asc-rebuild | ──DEX──>   | asc-smali |
          +--------------+               +--------------+            +-----------+
                 │                               │                          │
                 └──────────────► asc-engine ◄───┴──────────────────────────┘
                                     │     (+ asc-axml, asc-arsc, asc-cache)
                          ┌──────────┤
                       asc-cli ── asc-mcp
```

| Crate | Role |
|---|---|
| `asc-apk` | Memory-mapped zip: central directory, root DEX entries, cancellable inflate (libdeflate, zlib-rs for streamed prefixes), size / ratio limits against zip bombs |
| `asc-dex` | Zero-copy lazy DEX accessors (nothing cached), MUTF-8, encoded values, debug info, DEX 041 containers |
| `asc-dalvik` | Opcode table, operand decoding, payload-aware instruction walk |
| `asc-findrefs` | Locator tables (string / type / method / field / instruction), code scanner, call graph, `SearchState` |
| `asc-rebuild` | Extract one class and its dependencies into a minimal, valid DEX |
| `asc-smali` | baksmali-style disassembly of one class or method |
| `asc-axml`, `asc-arsc` | Binary XML and `resources.arsc` |
| `asc-cache` | Disk tiers, memory LRU, process registry |
| `asc-engine` | Queries over an APK: class lookup, findrefs, rules, call graph, hierarchy, manifest summary, multi-APK sweeps |
| `asc-cli` | `droidasc` binary and its daemon |
| `asc-mcp` | `droidasc mcp`: resident stdio MCP session |
| `asc-fixture` | Synthetic DEX / APK fixtures for tests |

## Query syntax and output

One parser (`asc_engine::names`) reads every way of writing a target, for the CLI, MCP and
rule sets alike: `Lc;->m(sig)`, `c.B->m`, `c.B#m`, `c.B.m`, `B.m`. A signature after the
name (`m(I)V`, `m(I)`, `m(int, String)`, `f:I`) selects one overload; the locators check it
against proto and type ids, so other overloads are never scanned. MCP additionally repairs
aliased argument keys (`asc-mcp/src/lenient.rs`) and reads enumerated values leniently
(case, plurals, synonyms), so schemas describe values instead of enforcing `enum`s. Errors
and zero-result replies say what to try next (`asc-engine/src/hints.rs`), computed only on
those paths.

Text output is one record per line with ` | ` columns, so an agent can grep and cut:
`dex | Lcls;->name(params)ret | matched`. Strings are quoted with JSON escapes, so every
record stays on one line. Row *content* matches the Python ASC semantically
(`benchmark/parity/semantic.py`); the format is asc-rs's own.

## Search

* **Locate, then scan.** Targets are resolved in the id tables and string data first
  (string / type queries are regexes over raw MUTF-8 string data; `--literal` uses
  `memmem`). The code scanner then looks for the located indexes (`memmem` for few targets,
  `memchr` on opcode or high operand bytes, else a table-driven sweep), and every candidate
  is verified by walking instruction lengths from the method start. Methods sharing one
  `code_item` (R8 dedup) are reported together.
* **Rule sets and compound queries.** `find_many` locates each query on its own, unions the
  sets per index kind and scans each DEX once; `all` / `none` combine per method. A rule set
  loads every entry once and returns one batch per rule.
* **Prefix-skip** (`engine::skip`). For a Deflate entry no cache will keep (one-shot
  `--no-cache` runs, entries below the L1 minimum), a worker first streams the prefix up to
  the end of the string data and skips the entry when no query can match. It runs only while
  it pays (string data early in the entry, most probes skipping); resident hosts never probe,
  since their cache keeps the inflated entry. Rows never change: an unreadable prefix falls
  back to the normal path.
* **Parallelism.** Class lookup probes entries smallest first and stops at the first hit;
  findrefs inflates largest first and streams batches as entries finish (the CLI reorders
  them into DEX order). Every root `*.dex` entry counts; a duplicated name resolves to its
  last record.
* **Call graph and hierarchy.** A per-DEX CSR call graph (`u16` targets, built on first
  use, persisted in L2) is walked by signature across DEX files. The class hierarchy is one
  graph over all `class_def_item`s, kept on the engine; virtual-call resolution uses it.

## Class extraction

`getclass` rebuilds the class into a standalone DEX: collect every index it depends on,
sort the new id tables canonically, rewrite operands and data, seal with checksum and
signature — the output is spec-valid (`dexdump` and jadx accept it, `--dump-dex` exports it).
It is rendered as baksmali-style smali. Classes the rebuild refuses (undefined opcodes,
`invoke-custom`, index overflow) are disassembled in place with a warning. `--method`
accepts a full signature, a prefix or a bare name.

## Caches

Caches are filled by queries themselves, so the "no preprocessing" property holds.

* **Disk tiers**, keyed by `ApkKey` (size, mtime, hash of the central directory), one cap:
  - L1: inflated DEX entries (≥ 4 MiB), with a CRC trailer.
  - L2: locator tables and call graphs that were costly to build, mapped back in place.
  - L3: rendered findrefs results, keyed by query, options and the executable.

  Writes are temp file + `rename`, never synced: the cache holds nothing that cannot be
  rebuilt, and `fsync` is very slow on macOS. Files older than the boot are CRC-checked once
  (a crash may have left torn pages), then touched; damaged files are deleted. The default
  cap is min(20 % of the disk, 32 GiB) with a free-space reserve; eviction weighs age, size
  and rebuild cost per tier.
* **Write queue.** Writer threads (one per 8 CPUs, at most 4, low CPU priority) do the
  disk work so queries never wait for it. Queued bytes are bounded by min(512 MiB, the
  memory budget); past it an L1 job keeps only the entry name and the writer re-inflates it
  later, so a cold sweep's heap stays bounded and L1 still ends up complete.
* **Memory LRU.** Holds inflated entries and their `SearchState` tables. Heap bytes count in
  full, file-backed mappings at 1/8 (shared, reclaimable page cache). Once written to L1,
  an entry's heap copy is swapped for a mapping.
* **Background prebuild.** After `open_apk` with `warm`, idle low-priority threads map or
  build the locator tables of cached entries, pausing whenever a query runs.

## Several processes

A `ProcessRegistry` (one file per process in `$XDG_RUNTIME_DIR/droidasc`; Linux and macOS)
records each process's cache bytes and whether it is serving a request.

* **Memory.** Without `--memory-mb`, a resident process sizes its LRU to (available memory +
  bytes held by registered processes) / 4 / processes.
* **Threads.** Without `--threads`, workers = clamp(4 × CPUs / busy processes, 2, CPUs). A
  process marks itself busy when a request starts and ends, the registry is re-read every
  100 ms, and multi-APK sweeps re-check the count between work units, so a burst of
  servers waking up together shares the CPUs instead of each taking all of them. The
  factor 4 avoids idle CPUs while the processes with the largest APKs finish.

## Front ends

**CLI daemon.** One-shot CLI commands are forwarded over a per-user Unix socket to a daemon
that keeps engines and caches warm. It is a transparent accelerator: no session state, and
output is byte-identical with or without it (`crates/asc-cli/tests/daemon.rs`).

* Every command writes through `output::Io`, locally or over the socket.
* `--debug` and `--no-cache` runs stay local.
* The socket name hashes the binary, the cache configuration and the umask, so a client
  only meets a daemon that would print the same.
* The socket directory must be private, and both ends check the peer uid.
* A missing daemon is spawned on demand (wait `DROIDASC_DAEMON_WAIT_MS`, default 300 ms)
  and exits after `DROIDASC_DAEMON_IDLE` seconds idle (default 900).
* A client hang-up cancels the request.
* Open engines' class graphs and resource tables count against the memory budget.
* `DROIDASC_DAEMON=off` disables it.

**MCP session.**
* One `Engine` per opened APK, all on one shared cache.
* Each tool call runs on its own thread, so a slow query does not block the next message.
  Panics become `isError` results, and `notifications/cancelled` stops the work.
* Multi-APK tools (`apks` / `dir`) plan every APK into weighted units on one worker pool,
  heaviest first, releasing each APK when it is done. Identical DEX across APKs (same CRC
  and size, confirmed by SHA-256 since both are attacker-controlled) are searched once.
* Replies are held to a byte budget (`max_bytes`, 16 KiB by default). Past it, the full text
  is spilled to a file under the cache directory and the reply carries its head, the path
  and a method index for smali; with `spill: never` the text is paged instead, and the
  footer holds the next call's arguments.
* The CLI has the same window through `--limit` / `--max-bytes` / `--offset`.

## Resources and the manifest

`asc-arsc` follows AOSP `libs/androidfw` and decodes lazily: parsing only records where each
type chunk's entries are, so a large table indexes in under a millisecond. It handles
multiple package chunks per id, aapt vs aapt2 bag keys and CESU-8 strings. Resolution picks
values as AOSP would for a default device config. Output matches `aapt2 dump resources`
apart from aapt2's own notation quirks (`benchmark/arsc-compare`).

The manifest summary resolves references through the table and reports the attack surface:
exported components (explicit, or implicit through intent filters by targetSdk),
permissions and the effective cleartext policy.

## Testing

`cargo test --workspace` runs unit tests per crate and integration tests on synthetic
fixtures, covering shared code items, map-less DEX, rebuilt DEX validity, stored and
Deflate APKs, cache consistency, daemon parity and MCP schemas.
