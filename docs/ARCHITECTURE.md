# Architecture

The port keeps the Python pipeline but splits it into crates along the natural seams of the
data: *format* → *search / rebuild* → *orchestration* → *front ends*.

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
                                     │              (+ asc-axml for the manifest)
                          ┌──────────┼──────────┐
                       asc-cli ── asc-mcp    asc-gui
```

## Mapping to the Python modules

| Python | Rust |
|---|---|
| `asc_client/apk_handler.py` (EOCD / central directory scan, chunked inflate with stop event, thread pool with early exit, process pool for findrefs, `list_classes`) | `asc-apk` (zip + inflate) and `asc-engine` (`get_class_dex`, `find_refs`, `list_classes` / `scan_classes`) |
| `asc_client/dex_container.py` (DEX 041 logical DEX split) | `asc_dex::container` |
| `asc_client/asc_handler.py` (`getclass`, `findrefs` line formatting) | `asc_engine::{decompile_dex_class, find_refs_in_dex, RefResult::line}` |
| `asc_client/manifest_handler.py` (androguard AXMLPrinter) | `asc-axml` |
| `asc_core/utils/tinydex.py` (lazy DEX model) | `asc_dex::Dex` (every accessor computes from header offsets; nothing is cached) |
| `asc_core/utils/leb128.py`, `dex_parser.py` (encoded values, debug info, annotations) | `asc_dex::{leb128, encoded, debug_info, annotations}` |
| `asc_core/models/dvm_opcode.py`, `resource/gen_dvmopcode.py` | `asc_dalvik::table` (generated from the same table) |
| `asc_core/utils/dvm_regdec.py` | `asc_dalvik::decode` |
| `asc_core/core/dvm_interpreter.py`, `dvm_handlers.py` (IndexHandler) | `asc_dalvik::walk` + `asc_rebuild::{collect, writer::rewrite_insns}` |
| `asc_core/findrefs/locator/string_locator.py` (regex over the string-data region, offset → idx map) | `asc_findrefs::StringLocator` (regex over the same region, binary search over sorted data offsets) |
| `.../type_locator.py`, `method_locator.py`, `field_locator.py` | `asc_findrefs::{TypeLocator, MethodLocator, FieldLocator}` |
| `.../insn_locator.py` (16-byte bucket table in a dict, `INSN_VERIFY` regex) | `asc_findrefs::InsnLocator` (same buckets in a dense `Vec<u32>` over the code region, filled by ranges; verification is a linear opcode-length walk, `asc_dalvik::verify_range`) |
| `.../scan/code_item_scan.py` (regex / translate prefilter over the code region) | `asc_findrefs::CodeScanner` (single pass with a 256-entry opcode table and a bitset of target indexes) |
| `.../scan/class_def_item_scan.py` (`findrefs extends` / `impl`) | `asc_findrefs::FindRefs::class_relation` (`classdefs` module) |
| `asc_client/apk/dex_reader.py::class_defines_prefix_len` + `loader.py::_inflate_dex_prefix` (prefix-only inflate for `getclass`) | `asc_dex::quick::probe_needed_len` + `asc_apk::Apk::inflate_until` (already there before upstream added it) |
| `dadguard/disassembler.py` (`disassemble`, `--method`, `--debuginfo`) | `asc_smali::disassemble_class_method` behind `getclass` / `disassemble` |
| `asc_core/core/dex/dex_constructor.py` (DexHollower) | `asc_rebuild::hollow` |
| `asc_core/core/dex/dex_remapper.py` (DexIndexMapper) | `asc_rebuild::{collect, tables}` |
| `asc_core/core/dex/dex_builder.py` (DexBuilder) | `asc_rebuild::writer` |
| `asc_core/utils/decompiler.py` (androguard DAD) | `asc-smali` (disassembly) — see below |
| `asc_client/gui/*` (Tk) | `asc-gui` (egui) |
| — (no equivalent) | `asc-cache` (disk + memory caches of inflated entries), `asc_findrefs::SearchState` (reusable locator tables) |
| — (no equivalent) | `asc-mcp` (`droidasc mcp`: resident MCP session over stdio; one `Engine` per opened APK, all attached to one `asc_engine::SharedCache`) |
| `tests/dex_fixture.py` | `asc-fixture` |

## Where the port deliberately differs

### Rebuilt DEX is spec-valid

The Python builder assigns new indexes in first-seen order and emits the id tables
unsorted, pins the class's own fields first so `class_data` deltas stay valid, and zeroes
checksum and signature (androguard is patched to ignore that). The Rust rebuild instead:

1. **collects** every original index the class depends on (bytecode operands, prototypes,
   catch types, annotation values, static values, debug info) and closes the set over the
   id tables;
2. **sorts** the new tables canonically (strings by UTF-16 code units, types by string,
   protos by return type + parameters, fields/methods by class, name, type/proto);
3. **rewrites** bytecode operands with the final mapping and re-encodes class data, code
   items (tries/handlers), debug info, annotations and static values;
4. **seals** the file with the standard layout (header, ids, class_def, data, map list),
   Adler-32 checksum and SHA-1 signature.

Because the input DEX is valid, the class's own fields sorted canonically keep their
original order, so `static_values` stays aligned with the field list — the failure mode the
Python "pin own fields" fix addressed. The rebuild additionally re-orders `static_values`
to the emitted field order so inconsistent inputs cannot misalign initialisers.

`dexdump` verifies the checksum and disassembles the output; jadx decompiles it to Java.

### Disassembly instead of decompilation

When the rebuild refuses a class (`RebuildError::is_input_limitation()`: `Bytecode` for an
undefined or truncated instruction, `Unsupported` for `invoke-custom` / method handles,
`TooManyItems` for a class whose references overflow 16-bit indexes),
`Engine::get_class` falls back to disassembling the class in place from the original DEX
and sets `ClassSource::warning`; `ClassSource::rebuilt` is `None` in that case.

There is no Rust equivalent of androguard's decompiler. `asc-smali` renders the rebuilt
class as baksmali-style smali: class/field/method headers with access flags, annotations,
static initialisers, `.registers`, `.param` names and `.line` directives from debug info,
labels for branches, switch payloads, `fill-array-data` and try/catch blocks. The engine's
`Rebuilt::bytes` is exposed (and `--dump-dex` on the CLI) for external decompilers.

Upstream later added its own smali renderer as a separate `disassemble` command (the Java
`getclass` stays). Here both commands share one path (`Engine::get_class_method`) and
differ only as Python's do: `disassemble` leaves out debug directives unless
`--debuginfo` is given and `-o` writes only the file, while `getclass` keeps `.line` /
`.param` (`--no-debug-info`) and also prints to stdout. The output stays baksmali-style
rather than copying dadguard's format (`# CLASS:` / `## METHOD:` comments, `.locals`), and
`--debug` does not add per-instruction offset comments. `--method 'name(params)ret'`
(both commands) is normalised as in Python (whitespace dropped from the descriptors, a
bare name rejected) and keeps the class header, interfaces and class annotations, no
fields, and only that method; the rebuilt DEX (`--dump-dex`) still holds the whole class.

### Search semantics kept from Python

* String and type queries are **regular expressions** matched against raw MUTF-8 string
  data (Python used `re` on bytes; Rust uses `regex::bytes`). Two edge cases differ on
  purpose: a match spanning several `string_data_item`s is attributed to the item where
  it starts (Python takes the item where it ends, via the next NUL), and `regex` keeps
  its Unicode semantics, so `.`/`\w`/`\xNN` do not match arbitrary bytes the way Python's
  byte-`re` does. An empty `string` pattern matches nothing rather than everything.
  Patterns are UTF-8 while the data is MUTF-8: a literal supplementary character
  (`😀`, stored as a surrogate pair) never matches, exactly as in Python, and `.` matches
  one *UTF-8* character — it can match a 2- or 3-byte BMP character (Python's byte `.`
  cannot) but not either half of a surrogate pair (Python's can, byte by byte). Spell a
  supplementary character as its surrogate bytes (`\xED\xA0\xBD\xED\xB8\x80`, with
  `(?-u)`) to find it.
* `Query::StringLiteral` (`findrefs string --literal`, an extension compatible with the
  literal string queries of rasc / rust_ASC) skips the regex: the value is MUTF-8 encoded
  (so a supplementary character does match) and found with `memchr::memmem` over the same
  region, attributed to the string where it starts. After a hit the rest of that string is
  skipped, which is exact because a needle without NUL never crosses a terminator. It
  returns the same rows as the regex `regex::escape(value)`.
* `Query::Extends` / `Query::Implements` (`findrefs extends` / `impl`) do no code scan:
  the target descriptor is resolved with the same binary search as a precise class, then
  every `class_def_item`'s `superclass_idx` / interface list is compared with it (direct
  relations only, in `class_defs` order). Rows carry `RefResult::relation` and print as
  `classes.dex | Lsub; extends Lbase;`. Python finds the superclass with a regex over the
  packed table and keeps 32-byte-aligned matches; because `finditer` does not overlap, a
  match straddling the preceding `access_flags` could in principle hide an aligned one.
  The direct comparison has no such blind spot (no row differed on the fixtures).
  Upstream's "grouped" `find_ref(group=True)` (one result list per key of a multi-key
  query) is not ported: no CLI path builds a multi-key query.
* Member queries: with a precise class, the member name is a **substring** match; with a
  fuzzy or absent class the member name is a regex against the string table.
  `MemberQuery::exact_name` (`--exact`, and the GUI's "references to this member") makes
  it a whole-name equality under any class constraint, as the Python GUI's exact-member
  xref does. Without a class the name string is one binary search over the sorted string
  table; within a class's members names are compared as MUTF-8 bytes (decoded only for
  non-ASCII strings).
* Exact descriptors (`getclass`, a precise member-query class) are MUTF-8 encoded before
  the binary search over the type table, so class names with supplementary characters
  (stored as surrogate pairs) are found. The search compares in UTF-16 code-unit order
  (`asc_dex::mutf8::cmp_utf16`, ART's comparison), the order the DEX sorts its strings in;
  raw MUTF-8 byte order agrees except for `U+0000` (`C0 80`). Python compares decoded
  code points and needs a linear fallback for the same case.
* Rebuilt string data is re-encoded as canonical MUTF-8 with a recounted `utf16_size`
  (as the Python builder now does): an input whose declared length is wrong (accepted on
  read, see `Dex::string_item_at`) or that holds 4-byte UTF-8 does not carry the defect
  into the output.
* Bucket resolution is fuzzy by design; every hit is verified by walking instruction
  lengths from the method start (or the previously verified offset) to the hit. That
  walk treats the leading `nop` of a switch / array payload as a one-unit instruction
  (the Python `INSN_VERIFY` regex does the same), so a reference placed *after* a payload
  in the same method is dropped. The rebuild walk (`asc_dalvik::walk`) is payload-aware:
  it skips payload ranges wherever they sit and reports undefined or truncated opcodes
  instead of silently emitting a half-remapped method.
* R8 instruction deduplication: several methods sharing one `code_item` are reported
  together (`MethodRef::Shared`).

### Concurrency

`get_class_dex` spawns workers over the DEX entries sorted by compressed size (smallest
first). Each worker first streams a prefix of the entry with zlib-rs — header, id tables
and string data, as computed by `asc_dex::quick::probe_needed_len` — and answers the
class probe from that when it covers less than 70% of the DEX; only a hit (or an
inconclusive prefix, e.g. a 041 container) is inflated fully with libdeflate. The call
returns through an mpsc channel as soon as one worker reports a hit; the stop flag makes the other
workers give up before their next entry (with the default libdeflate inflater a DEX cannot
be abandoned mid-way, so a worker that is already inflating finishes in the background;
the zlib-rs fallback path polls the flag every 512 KiB). `find_refs` uses scoped threads
and an mpsc channel and hands out the largest entries first (every entry must be searched,
so the longest inflate should start immediately); batches reach the caller in completion
order, exactly like the Python process pool. `scan_classes` (behind `listclass` and the GUI
package tree) also runs largest first, but puts each entry's classes back in its
central-directory slot, so the listing is in DEX order like the Python `list_classes`.
`list_classes` fails on the first unreadable entry or bad `class_def`; the GUI keeps the
classes of the other entries and reports the broken ones.

The GUI turns that listing into a `ClassIndex` that stores each descriptor once: sorted and
deduplicated in one string arena with end offsets, the DEX label as a `u16` into a name
table, and the package tree as a flat node table whose children and classes are ranges
into two `u32` arrays (children by name, as the old `BTreeMap` had them; classes in
descriptor order). `contains` is a binary search; the class filter searches the whole arena
at once ignoring ASCII case and lower-cases (Unicode rules) only the non-ASCII
descriptors, so it returns exactly what `to_lowercase().contains(..)` would. On a
551,080-class APK the index builds in about 70 ms and holds about 22 MB.

A DEX 041 container is split lazily (`asc_dex::container::logical_dex_iter`): every
logical DEX after the first is a full copy of the container with its header moved to
offset 0, so the uncached paths hold one such copy at a time. The memory cache keeps all
of them (`CachedEntry::logical`, accounted in `resident_bytes`).

### Entry selection (kept the same in every command)

These differ from the Python CLI on purpose and apply to `getclass`, `findrefs` and
`listclass` alike:

* Every root-level `*.dex` entry is a DEX entry. Python's central-directory scan keys
  on the substring `classes` and only falls back to all root `*.dex` when nothing
  matches, so an extra `foo.dex` next to `classes.dex` is ignored there.
* A duplicated entry name resolves to its **last** central-directory record (as zip
  readers and `Apk::find_entry` do); Python keeps the first (or, in its fallback path,
  both).
* `--threads 0` is accepted and runs one worker (the flag is global); Python's
  `listclass` rejects it.
* The GUI package tree labels a class defined by several DEX files with the first one in
  central-directory order; `getclass` opens whichever entry answers its parallel probe
  first (smallest entries are probed first), which can be another of them.

### Caches

`asc-cache` adds two layers that keep the "no preprocessing" property (they are filled
lazily by the queries themselves):

* `DiskCache`: `<dir>/<apk-key>/<entry>` files with the inflated bytes, keyed by size,
  mtime and an FNV hash of the central directory; atomic `rename` writes, `populate`d
  mmap reads, LRU eviction by APK directory above a byte cap. The cap is a
  `DiskCapacity`: `Fixed(bytes)` (`--cache-max-mb`, `$DROIDASC_CACHE_MAX_MB`) or `Auto`
  (default), which `capacity_for(used)` turns into `auto_disk_bytes_for(disk_space(dir),
  used)` = min(20 % of used + free, 4 GiB, used + free - `auto_disk_reserve(total)`),
  the reserve being max(1 GiB, 5 % of the file system). `evict` recomputes it on every
  pass, so a disk filled by someone else shrinks the cache below its current size;
  `put` refuses (`CacheError::LowDiskSpace`) an entry that would leave less than the
  reserve free, at the cost of one `statvfs` per entry. `disk_space` returns `None`
  off Unix, where `Auto` means the old 4 GiB. `budget()` reports cap, usage and free
  space for `cache stats`. The engine queues writes
  to one background thread (writing and syncing a 30 MiB entry costs as much as the whole
  query it came from) and evicts once per burst rather than after every entry;
  `Engine::flush_cache_writes` / `Drop` wait for the queue. Concurrent queries that need
  the same entry share a single inflate, so a burst of GUI requests cannot replace each
  other's locator tables.
* `MemoryCache<T>`: byte-bounded LRU keyed by `(apk key, entry name)`; the engine stores a
  `CachedEntry` per entry, which owns the bytes and, per logical DEX, an
  `Arc<SearchState>` (`OnceLock`s for the string/type/member/instruction locators).
  `FindRefs::with_state` reuses those tables; `FindRefs::new` builds throw-away ones.
  An entry is charged `resident_bytes` on insertion; after each search `recharge` adds
  `SearchState::heap_bytes` (vector capacities of the built locators) through
  `MemoryCache::resize`, which evicts least recently used entries when that crosses the
  cap. `CacheConfig::resident_auto` sizes the cap with `auto_memory_bytes` (a quarter of
  `available_memory()`, clamped to 64 MiB–2 GiB; 2 GiB where it cannot be read).
* Remapping: a freshly inflated entry that goes into the memory cache is queued for the
  disk writer together with a `Weak` handle to it. Once the file is renamed into place
  the writer maps it, compares it with the heap bytes, and swaps the LRU slot for a
  `CachedEntry` over the mapping that shares the old `SearchState`s
  (`MemoryCache::replace`, only if the slot still holds that entry). Queries that hold
  the old entry keep using the heap copy until they drop it. Container entries keep
  their normalised logical copies (owned) and only remap the container itself.
* Allocator: the first engine with a memory cache fixes glibc's mmap threshold at 1 MiB
  (`mallopt(M_MMAP_THRESHOLD)`, Linux/glibc only, process-wide). glibc otherwise raises
  the threshold to every large block freed (up to 32 MiB), after which DEX-sized buffers
  are carved from the heap arenas, interleaved with long-lived locator tables, and a
  remapped or evicted entry's bytes stay resident (`malloc_trim` cannot return them).

Mapped files and cache maintenance: entries are only ever replaced by `rename`, never
rewritten in place, and `evict` / `cache clear` unlink whole directories, so a live
mapping keeps its inode (POSIX) and stays valid. A third party truncating a cache file in
place would fault the mapping (SIGBUS), exactly as for disk hits; on Windows a mapped file
cannot be deleted, so eviction skips it and `cache clear` reports the error.

Stored (uncompressed) entries are borrowed straight from the APK mapping and never copied
unless an in-memory cache wants to keep their tables.

`SharedCache` wraps one such cache (memory LRU, disk cache, writer thread) for several
engines. Because the LRU is keyed by APK, engines over different APKs attached with
`Engine::with_shared_cache` compete for one byte budget; dropping one of them leaves the
writer running, and dropping the `SharedCache` lands the queued writes.

### MCP session

`asc-mcp` is the resident front end for agents. `serve` reads one JSON-RPC message per
line. `initialize`, `ping` and `tools/list` are answered on the reading thread; each tool
call runs on its own scoped thread (and the engine's worker threads, as in the CLI), so a
slow query does not hold up the next message, and replies are written as calls finish. To
keep request order where it matters, the APK a call opens is registered (and gets its
`apk_id`) before the next line is read, and `close_apk` first joins the calls still
running. Each call runs under `catch_unwind` (the release profile unwinds for this), so a
panic in the engine becomes an `isError` result instead of ending the process. Each `open_apk` (or first use of an `apk` path) creates an `Engine` attached
to the server's `SharedCache`; `open_apk` with `warm` runs `scan_classes`, which inflates
every entry into the LRU, so later `findrefs` / `getclass` calls only build locator tables
once and then scan. Results are paged over a stable order (entries sorted as
`classes.dex, classes2.dex, …`), because the engine streams entries as they finish. Tool
failures are `isError` results, protocol errors JSON-RPC errors; neither ends the session.

### Scan strategy

`CodeScanner::scan` picks a strategy from the query: ≤ 8 targets → `memmem` over each
target's little-endian operand bytes, verifying the opcode two bytes earlier; string
queries → `memchr2` over `const-string` / `const-string/jumbo`; other kinds whose targets
share at most three distinct high operand bytes → `memchr{,2,3}` on that byte at
`opcode + 3`; otherwise a linear sweep with a 256-entry opcode table. All paths produce
the same unverified candidates, which the instruction locator then confirms.

## Testing

`cargo test --workspace` runs unit tests per crate plus integration tests that recreate the
Python regression suite on synthetic fixtures: shared code items keep both methods, map-less
and class_data-less DEX fall back to class definitions, empty string tables, last string
searchable, rebuilt DEX validity (checksum, sorted tables, static value alignment), stored
and Deflate APKs through the engine, and CLI-level class name normalisation.
