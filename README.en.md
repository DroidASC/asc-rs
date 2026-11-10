English | [简体中文](README.md)

# asc-rs

Treats an APK as a read-only database: locate classes, search cross-references, disassemble, and decode
the manifest and resources straight from the archive, in milliseconds, with no preprocessing or global
index; HarmonyOS HAP / ABC files answer the same commands (see [HarmonyOS](#harmonyos-hap--abc)). Built for
people and agents: CLI first (with a transparent warm daemon on Unix), plus an MCP server. The binary is
`asc`.

## Build

```sh
cargo build --release        # -> target/release/asc (Rust 1.85+)
cargo test --workspace
```

## Quick start

```sh
asc manifest-summary app.apk | grep exported=true          # attack surface
asc findrefs app.apk string 'https?://' --limit 50         # who uses this string
asc findrefs app.apk method 'android.webkit.WebView->loadUrl' --context 3
asc getclass app.apk com.poc.Main --method onCreate        # read smali
asc callgraph app.apk com.poc.Main onCreate --depth 3      # caller tree
asc findrefs app.apk rules 'string:http://' 'method:java.lang.Runtime->exec'
```

## Commands

| command | what it does |
|---|---|
| `getclass` / `disassemble` | Locate a class, rebuild a one-class DEX in memory and print smali; `--method` for one method, `--dump-dex` writes the DEX for jadx and friends |
| `listclass` (`classes`) | List classes, `--prefix` to filter |
| `findrefs` | Code references to a `string` / `type` / `method` / `field`, direct subclasses and implementers (`extends` / `impl`); `all` combines conditions, `rules` answers many rules in one scan |
| `callgraph` | Callers (default) or `--callees` of a method; `--virtual` follows dispatch through the class hierarchy |
| `hierarchy` | Transitive subclasses / implementers, or `--supers`; `--method` marks overrides |
| `getmanifest` (`manifest`) / `manifest-summary` | Decode the manifest; the summary is one record per line: exported components and why, permissions, providers, deep links, FileProvider, network security config |
| `resources` / `xml` | Query `resources.arsc`; decode any binary XML |
| `mcp` / `daemon` / `cache` | MCP server; daemon control; on-disk cache (`path` / `stats` / `clear`) |

All options: `asc --help` and `asc <command> --help`. Exit status: 0 success, 1 error, 2 some
DEX (or ABC) entries could not be searched (the other results are valid).

## Output and query syntax

One record per line, columns separated by ` | `; lines starting with `#` are headers, totals and hints, so
grep / cut work. A `findrefs` row is `dex | method (full signature) | matched`:

```
classes.dex | LWV/qE;-><clinit>()V | "http://", "http://www."
classes4.dex | Lcom/…/ConversationView;->onRestoreInstanceState(Landroid/os/Parcelable;)V | Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
classes.dex | Lcom/a/Store;->update()V | Lcom/a/Store;->count:I [read], Lcom/a/Store;->count:I [write]
```

- Classes are `com.a.B` or `Lcom/a/B;`.
- Members are written the same way in the CLI, MCP and rules: `Lcom/a/B;->name(I)V`, `com.a.B->name`,
  `com.a.B#name`, `com.a.B.name`, `B.name` (a class without a package matches any package). A bare name is a
  regex / substring; `=name` is exact.
- A signature picks that overload: `run(I)V`, parameters only `run(I)`, Java style `run(int, String)`;
  fields `f:I`.
- Field references are labelled `[read]` for `iget*` / `sget*` and `[write]` for `iput*` / `sput*`.
  `findrefs app.apk field TARGET --access read` (or `write`) keeps only that access; omitting it prints both.
- Conditions are `KIND:VALUE` (`string:`, `literal:`, `type:`, `method:`, `field:`); in `rules` they combine
  with `&`, or come from `--file`, one per line.
- An empty result prints `hint:` lines on stderr: DEX entries searched, case sensitivity, a framework class
  the APK does not define, the closest class or the methods it has, and so on.

## HarmonyOS (HAP / ABC)

The same `asc` and the same commands read ArkCompiler bytecode (the `.abc` ArkTS / JS compiles to); the
format is detected from the file:

- **Inputs**: a `.hap` / `.hsp`, an `.app` (inner haps may be compressed), a bare `.abc`, or a directory /
  `,` list read as one program; every `ets/*.abc` of a hap is read, and the entry column of a row says which
  one it came from. The files of a directory are recognized by content (the `PANDA` magic, a zip holding
  `module.json` / `ets/*.abc`), whatever their names and extensions.
- **Encrypted packages**: a hap from the app store has an encrypted `ets/modules.abc`. It is named in a
  `# warning:` on stderr and left out (`findrefs` / `callgraph` exit with 2); nothing is decrypted. Put the
  decrypted abc next to the hap and pass that directory: code comes from the decrypted file, `module.json`,
  resources and the rest from the hap. The two are paired by the header (version, size, checksum) and the
  checksum of the body, not by file name.
- **Names**: a class is a record (a module: `&entry/src/main/ets/pages/Index&`, libraries carry a version,
  `&@ohos/lib/Index&1.0.0`, older files have `com.a.b/entry/ets/pages/Index`; a path suffix, `pages/Index`,
  is enough), a method is a function (raw `#~@0>#build` or restored `Index.build`).

| command | Android | HarmonyOS |
|---|---|---|
| `listclass` | classes | records; `--all` adds pseudo records (annotations) |
| `getclass` / `disassemble` | smali | pandasm-style disassembly; `--method` for one function, `--entry` picks the abc |
| `getmanifest` / `manifest-summary` | `AndroidManifest.xml` | `module.json` (`--file pack.info` / `pkgContextInfo.json`); in the summary each ability / extension carries `record=`, and a `callbacks` line lists its `onXxx` functions |
| `findrefs string` / `method` / `all` | ✓ | ✓ (`method` finds where a function is **defined**, not its calls) |
| `findrefs prop` / `global` / `import` / `number` / `call` | — | ✓ |
| `findrefs type` / `field` / `extends` / `impl` / `rules`, `--context` | ✓ | — |
| `callgraph` | ✓ | ✓: `--to call:REGEX`, `--from method:NAME`, `--no-defines`, `--unresolved`, `--entry`; no `--virtual` / `--unless` |
| `hierarchy` | ✓ | ✓: the parent is read where each class is defined; `CLASS` is a class name, `RECORD->CLASS`, or a parent outside the program, `import:REGEX` / `global:REGEX`; `--method` sees the members of the class literal |
| `resources` | `resources.arsc` | `resources.index`, same options; QUERY is `0x…`, `string/name`, `$string:name` or `app.string.name` |
| `xml` | binary XML | prints a text file of the package as it is: `'$profile:main_pages'` (page list, route table) or a path in the package |
| `getclass --res-names` | resource id constants | appends `# string/name "value"` to the row of a `$r(...)` object |

```sh
asc manifest-summary entry.hap | grep -E '^(ability|callbacks|uri)'    # exported abilities, callbacks, deep links
asc getclass entry.hap entryability/EntryAbility --method EntryAbility.onCreate
asc findrefs entry.hap import '@ohos:' --requests                      # which system modules are used
asc findrefs entry.hap call '^import:@ohos:net\.http'                  # who calls into the http module
asc findrefs entry.hap prop request --exact --access call              # calls by member name, any receiver
asc findrefs entry.hap all 'call:^import:@ohos:net\.http' 'string:^https?://'
asc hierarchy entry.hap UIAbility --method onCreate                    # who extends UIAbility, who overrides onCreate
asc xml entry.hap '$profile:main_pages'                                # the page list; the routerMap likewise
asc resources entry.hap --search 'Sign in' --in value                  # text -> id, then findrefs number ID
asc callgraph entry.hap entryability/EntryAbility EntryAbility.onCreate --callees --depth 3
asc callgraph entry.hap --to 'call:^import:@ohos:net\.http' --depth 6  # who reaches http
asc callgraph app-dir/ --to 'call:^import:@ohos:net\.http' --from 'method:^EntryAbility\.on' --depth 8 --max-nodes 5000
```

A `findrefs` row is `entry | RECORD->function+0xPC | restored name | instruction ; resolved callee`; the second
column can be pasted as it is into `getclass` / `callgraph`:

```
ets/modules.abc | &entry/src/main/ets/common/Utils/utils&->#~@0<#o0O0OOoo+0xef | utils.o0O0OOoo | callthis2 v10, v11, v12 ; import:@ohos:net.http#default.createHttp().request(expr, expr)
```

An ArkTS call instruction names no callee; its origin is tracked inside the function only, so results say how
much is known:

- Callee paths (what `findrefs call` and `callgraph --to` match): `import:REQUEST#NAME.member`,
  `global:NAME.member`, `this.member` and `local:FUNCTION` are known origins; `argN` is the Nth parameter of
  the function, `this@F` / `argN@F` the `this` / parameter of the enclosing function F captured by a closure,
  `x().member` a member of a call result, `lex(level,slot)` a captured variable with several writers, `?`
  unknown.
- `callgraph` rows: no mark is a proved call; `[new]` a construction; `[this-class]` is `this.m()` matched by
  name in the class of the caller, not guaranteed; `[defines]` creates a closure, it is not a call
  (`--no-defines` drops them); `[external]` is a leaf rooted at an import / global for which the program has
  no function (system APIs, but also members of call results and imports that did not resolve);
  `[unresolved]` is a leaf of unknown origin (`--callees --unresolved` lists them, otherwise a row ends in
  the count, `unresolved=N`); `(repeated)` marks a node expanded elsewhere.
- Callbacks the system calls (lifecycle `onXxx`, event handlers) have no callers; where a path stops at
  `[unresolved]`, continue by name: `findrefs method NAME --exact` (who defines it), `findrefs prop NAME
  --exact --access call` (the other call sites).

- `hierarchy` rows: `[external]` is a parent outside the program (a system class, a global), `[unresolved]` a
  parent of unknown origin, `[reassigned]` a class a decorator assigned again after its definition (the
  subclass extends it or what the decorator put there, not guaranteed), `[function]` a plain function used
  as a base class.
- A resource id is unique within one package only; `resources` rows of a program of several packages start
  with the package, and the hits of `findrefs number ID` are to be matched on the entry column.

Limits: a HarmonyOS program is served by the same daemon as APKs (the analyses stay resident), but has no
disk cache (it opens in milliseconds); the call graph does not use the class hierarchy (`super()` and
inherited methods are `[unresolved]`); `findrefs all` takes no excluded conditions; static ArkTS
(`modules_static.abc`) is not supported; abc versions above 24.x have not been checked
against real samples; a directory mixing DEX and HarmonyOS files is an Android program, so pass the HarmonyOS
files by their own path.

## For agents

- **Cut output, spilled to a file**: nothing is cut unless asked. `--limit N` / `--max-bytes N` (or
  `$ASC_LIMIT` / `$ASC_MAX_BYTES`) keep stdout short; the whole output goes to `out/` in the cache
  directory and the last line says where and how to continue:

  ```
  # records 1-50 of 523 shown; full output in /home/u/.cache/asc/out/3f2a….txt (grep it, or rerun with --offset 50)
  ```

- **Skill**: [`skills/asc/SKILL.md`](skills/asc/SKILL.md) is an
  [Agent Skill](https://agentskills.io/specification) for agents that work through a shell.
- **Daemon** (Unix): one-shot commands are handed to a per-user daemon that keeps opened APKs resident; the
  output (stdout, stderr, exit status) is byte-identical to running without it. The first command starts
  it and it exits when idle; Ctrl-C in the client cancels the query in the daemon. `asc daemon
  status|stop|start` controls it, `ASC_DAEMON=off` turns it off.
- **MCP**: `asc mcp` is a resident session over stdio with the tools `getclass`, `findrefs`,
  `callgraph`, `hierarchy`, `listclass`, `getmanifest`, `manifest_summary`, `resources`. Passing an
  `apk` path opens it; the `apk_id` in replies can stand in for the path. `apk` may also be a HarmonyOS
  program: `listclass`, `getclass`, `findrefs`, `callgraph`, `getmanifest` and `manifest_summary` work on it, and
  the first reply says what those tools take there. `findrefs`, `listclass`, `manifest_summary` and `resources` take `apks` / `dir` to cover many
  APKs in one call. Replies stay within `max_bytes` (default 16384); the rest is spilled to a file or paged,
  per `spill`.
  Field queries accept `"access": "read"` / `"write"`; `field_accesses` aligns with `matched`, and contextual
  sites also carry `access`.

  ```json
  { "mcpServers": { "asc": { "command": "/absolute/path/to/asc", "args": ["mcp"] } } }
  ```

## Caching and resources

Inflated DEX files, derived search tables and query results are cached on disk (shared across processes,
on by default); resident processes (`mcp`, the daemon) also keep an in-memory LRU. The cache only speeds
things up and can be deleted at any time; files carry a CRC, so damage is just a miss.

Threads, memory and disk are one set of settings. `asc config` lists each with its value, its source
and what it comes to on this machine (`--json` for scripts and agents). A flag (`--set KEY=VALUE`) beats
the environment (`$ASC_<KEY>`, named in `--json`), which beats the config file
`~/.config/asc/config.toml` (under `$XDG_CONFIG_HOME`, or `$ASC_CONFIG`; empty reads none), which
beats the default. `auto` defaults are computed for this machine, and resident processes register so they
split memory and threads.

| setting | default |
|---|---|
| `threads` (`--threads`) | auto: the logical CPUs; with other busy processes 4 × CPUs / busy processes, at least 2 |
| `memory.max` (`--memory-mb`) | auto = 25%: (available memory + what resident processes hold) × 25% / resident processes; or `4G`, `40%` |
| `memory.ceiling` | auto: 1/16 of physical memory within 2G..8G (2G on a 12 GB machine, 6G on 96 GB) |
| `memory.split` | on: split between resident processes |
| `cache.enabled` (`--no-cache`), `cache.dir` (`--cache-dir`) | on; `$XDG_CACHE_HOME/asc` or `~/.cache/asc` |
| `cache.max` (`--cache-max-mb`) | auto = 20%: (free space + the cache) × 20%, at most `cache.ceiling` (32G), keeping 1 GiB / 5% free |
| `cache.tiers`, `cache.min_dex` | `dex,derived,rendered`; DEX under 4M are not written to L1 |
| `cache.write_queue`, `cache.writers` | 512M (and at most the memory budget); auto: one per 8 CPUs, 1..4 |
| `cache.spill` (`--spill-mb`) | 64M: budget of `out/`, where cut outputs go |
| `daemon.idle`, `daemon.wait` | 15m; 300ms. `ASC_DAEMON=off` turns the daemon off |

```toml
# ~/.config/asc/config.toml
threads = 8
[memory]
max = "4G"
[cache]
max = "10%"
```

`--debug` prints timing and cache statistics on stderr.

## Performance

A 47-step agent replay on Douyin (360 MB, 56 DEX files): about 60 ms through a warm MCP session. 836 APKs ×
8 rules in one scan: about 0.5 s in one warm MCP process. Full numbers, the tools compared and how to
reproduce them: [benchmark/README.md](benchmark/README.md).

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): crates, implementation and design trade-offs.
- [benchmark/README.md](benchmark/README.md): correctness and performance evaluation.
- [docs/ark-abc-design.md](docs/ark-abc-design.md) (Chinese): design of the HarmonyOS / ABC support, measured call
  resolution precision.

## Credits

asc-rs grew out of the ideas and original implementation of [ASC](https://github.com/MG1937/ASC) (MG1937,
"R8 Compiler Optimization as a DeCompiler Primitive").

## License

Apache-2.0, same as the original project.
