English | [简体中文](README.md)

# asc-rs

Treats an APK as a read-only database: locate classes, search cross-references, disassemble, and decode
the manifest and resources straight from the archive, in milliseconds, with no preprocessing or global
index. Built for people and agents: CLI first (with a transparent warm daemon on Unix), plus an MCP
server. The binary is `droidasc`.

## Build

```sh
cargo build --release        # -> target/release/droidasc (Rust 1.85+)
cargo test --workspace
```

## Quick start

```sh
droidasc manifest-summary app.apk | grep exported=true          # attack surface
droidasc findrefs app.apk string 'https?://' --limit 50         # who uses this string
droidasc findrefs app.apk method 'android.webkit.WebView->loadUrl' --context 3
droidasc getclass app.apk com.poc.Main --method onCreate        # read smali
droidasc callgraph app.apk com.poc.Main onCreate --depth 3      # caller tree
droidasc findrefs app.apk rules 'string:http://' 'method:java.lang.Runtime->exec'
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

All options: `droidasc --help` and `droidasc <command> --help`. Exit status: 0 success, 1 error, 2 some
DEX entries could not be searched (the other results are valid).

## Output and query syntax

One record per line, columns separated by ` | `; lines starting with `#` are headers, totals and hints, so
grep / cut work. A `findrefs` row is `dex | method (full signature) | matched`:

```
classes.dex | LWV/qE;-><clinit>()V | "http://", "http://www."
classes4.dex | Lcom/…/ConversationView;->onRestoreInstanceState(Landroid/os/Parcelable;)V | Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
```

- Classes are `com.a.B` or `Lcom/a/B;`.
- Members are written the same way in the CLI, MCP and rules: `Lcom/a/B;->name(I)V`, `com.a.B->name`,
  `com.a.B#name`, `com.a.B.name`, `B.name` (a class without a package matches any package). A bare name is a
  regex / substring; `=name` is exact.
- A signature picks that overload: `run(I)V`, parameters only `run(I)`, Java style `run(int, String)`;
  fields `f:I`.
- Conditions are `KIND:VALUE` (`string:`, `literal:`, `type:`, `method:`, `field:`); in `rules` they combine
  with `&`, or come from `--file`, one per line.
- An empty result prints `hint:` lines on stderr: DEX entries searched, case sensitivity, a framework class
  the APK does not define, the closest class or the methods it has, and so on.

## For agents

- **Cut output, spilled to a file**: nothing is cut unless asked. `--limit N` / `--max-bytes N` (or
  `$DROIDASC_LIMIT` / `$DROIDASC_MAX_BYTES`) keep stdout short; the whole output goes to `out/` in the cache
  directory and the last line says where and how to continue:

  ```
  # records 1-50 of 523 shown; full output in /home/u/.cache/droidasc/out/3f2a….txt (grep it, or rerun with --offset 50)
  ```

- **Skill**: [`skills/droidasc/SKILL.md`](skills/droidasc/SKILL.md) is an
  [Agent Skill](https://agentskills.io/specification) for agents that work through a shell.
- **Daemon** (Unix): one-shot commands are handed to a per-user daemon that keeps opened APKs resident; the
  output (stdout, stderr, exit status) is byte-identical to running without it. The first command starts
  it and it exits when idle; Ctrl-C in the client cancels the query in the daemon. `droidasc daemon
  status|stop|start` controls it, `DROIDASC_DAEMON=off` turns it off.
- **MCP**: `droidasc mcp` is a resident session over stdio with the tools `getclass`, `findrefs`,
  `callgraph`, `hierarchy`, `listclass`, `getmanifest`, `manifest_summary`, `resources`. Passing an
  `apk` path opens it; the `apk_id` in replies can stand in for the path. `findrefs`, `listclass`, `manifest_summary` and `resources` take `apks` / `dir` to cover many
  APKs in one call. Replies stay within `max_bytes` (default 16384); the rest is spilled to a file or paged,
  per `spill`.

  ```json
  { "mcpServers": { "droidasc": { "command": "/absolute/path/to/droidasc", "args": ["mcp"] } } }
  ```

## Caching and resources

Inflated DEX files, derived search tables and query results are cached on disk (shared across processes,
on by default); resident processes (`mcp`, the daemon) also keep an in-memory LRU. The cache only speeds
things up and can be deleted at any time; files carry a CRC, so damage is just a miss. Budgets are sized
to the machine by default, and resident processes register so they split memory and threads.

| option / variable | effect |
|---|---|
| `--no-cache` | Do not read or write the on-disk cache |
| `--cache-dir DIR`, `$DROIDASC_CACHE_DIR` | Cache location (default `$XDG_CACHE_HOME/droidasc` or `~/.cache/droidasc`) |
| `--cache-max-mb MIB`, `$DROIDASC_CACHE_MAX_MB` | Disk budget (default: 20% of the cache plus free space, at most 32 GiB, keeping at least 1 GiB / 5% free) |
| `--memory-mb MIB` | Memory budget of `mcp` / the daemon (default: a quarter of available memory, at most 2 GiB, split between processes) |
| `--threads N` | Worker threads (default: the logical CPUs, split with other busy resident processes) |
| `DROIDASC_DAEMON`, `DROIDASC_DAEMON_WAIT_MS`, `DROIDASC_DAEMON_IDLE` | Turn the daemon off; ms the first command waits for it (300); idle seconds before it exits (900) |
| `--debug` | Timing and cache statistics on stderr |

## Performance

A 47-step agent replay on Douyin (360 MB, 56 DEX files): about 60 ms through a warm MCP session. 836 APKs ×
8 rules in one scan: about 0.5 s in one warm MCP process. Full numbers, the tools compared and how to
reproduce them: [benchmark/README.md](benchmark/README.md).

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): crates, implementation and design trade-offs.
- [benchmark/README.md](benchmark/README.md): correctness and performance evaluation.

## Credits

asc-rs grew out of the ideas and original implementation of [ASC](https://github.com/MG1937/ASC) (MG1937,
"R8 Compiler Optimization as a DeCompiler Primitive").

## License

Apache-2.0, same as the original project.
