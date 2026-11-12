English | [简体中文](README.md)

# asc-rs

Treats an APK as a read-only database: locate classes, search cross-references, disassemble, and decode
the manifest and resources straight from the archive, in milliseconds, with no preprocessing or global
index; HarmonyOS HAP / ABC files answer the same commands (see [HarmonyOS](#harmonyos-hap--abc)). Built for
people and agents: CLI first (with a transparent warm daemon on Unix), plus an MCP server. The binary is
`asc`; the decompiler `asc decompile` runs is a second one, `asc-dexdec-worker`.

## Install and build

A [release](https://github.com/Ylarod/asc-rs/releases)'s `asc-v<version>-<target>.tar.gz` (Linux, macOS and Windows, x86_64 and aarch64) holds `asc` (as does
`cargo binstall asc-cli`). The decompile worker `asc decompile` runs, `asc-dexdec-worker`, is released on its own
from [DroidASC/asc-dexdec](https://github.com/DroidASC/asc-dexdec): without one, the first `asc decompile`
downloads `asc-dexdec-worker-p<protocol>-<target>.tar.gz` for its protocol version from the latest release there,
checks its SHA-256 and installs it in `~/.local/share/asc/tools/`; `asc install dexdec` does the same on demand. To stay offline set `ASC_AUTO_INSTALL=off` (or `--set decompile.auto_install=off`):
`asc decompile` then falls back to smali and says how to install the worker. On an offline machine put the
worker next to `asc`, on `PATH`, or name it in `[decompilers.dexdec]` `command` (see
[configuration.en.md](docs/configuration.en.md)).

```sh
cargo build --release                                            # -> target/release/asc (Rust 1.98+)
cargo test --workspace
```

## Quick start

```sh
asc manifest-summary app.apk | grep exported=true          # attack surface
asc findrefs app.apk string 'https?://' --limit 50         # who uses this string
asc findrefs app.apk method 'android.webkit.WebView->loadUrl' --context 3
asc getclass app.apk rs.asc.Main --method onCreate         # read smali
asc callgraph app.apk rs.asc.Main onCreate --depth 3       # caller tree
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
| `mcp` / `daemon` / `cache` / `install` | MCP server; daemon control; on-disk cache (`path` / `stats` / `clear`); `install dexdec` downloads the latest decompiler worker speaking this asc's protocol version |

The APK argument may also be a jar, a `.dex`, or several files analysed as one program (a directory, or paths
joined with `,`): see [docs/query.en.md](docs/query.en.md#several-files-as-one-program).

All options: `asc --help` and `asc <command> --help`. Exit status: 0 success, 1 error, 2 some
DEX (or ABC) entries could not be searched (the other results are valid).

Output is one record per line, columns separated by ` | `; lines starting with `#` are headers, totals and
hints. How classes and members are written, overloads by signature, field read / write labels, `KIND:VALUE`
conditions and rules: [docs/query.en.md](docs/query.en.md).

## HarmonyOS (HAP / ABC)

The same `asc` and the same commands read ArkCompiler bytecode (the `.abc` ArkTS / JS compiles to); the
format is detected from the content: a `.hap` / `.hsp`, an `.app`, a bare `.abc`, an unpacked package
directory, or a directory holding such files. A class is a record, a method is a function.

```sh
asc manifest-summary entry.hap | grep -E '^(ability|callbacks|uri)'    # exported abilities, callbacks, deep links
asc getclass entry.hap entryability/EntryAbility --method EntryAbility.onCreate
asc findrefs entry.hap call '^import:@ohos:net\.http'                  # who calls into the http module
asc callgraph entry.hap --to 'call:^import:@ohos:net\.http' --depth 6  # who reaches http
```

Inputs, encrypted packages, the command table next to Android, what each call graph mark means, and the
limits: [docs/harmonyos.en.md](docs/harmonyos.en.md).

## For agents

- **Skill**: [`skills/asc/SKILL.md`](skills/asc/SKILL.md) is an
  [Agent Skill](https://agentskills.io/specification) for agents that work through a shell.
- **Daemon** (Unix): a one-shot command is handed to a per-user daemon that keeps programs open; the output
  is byte for byte what it is without the daemon. `ASC_DAEMON=off` turns it off.
- **MCP**: `asc mcp` is a resident session on stdio.
- **Cut output**: nothing is cut unless asked (`--limit` / `--max-bytes`); the whole output goes to a file
  and the last line says how to continue.

Details and the MCP configuration: [docs/agents.en.md](docs/agents.en.md).

## Caching and settings

Inflated DEX, derived search tables and query results are cached on disk (on by default, safe to delete);
resident processes also keep an in-memory LRU. `asc config` lists each setting of threads, memory and disk
with its value and source; all settings and defaults: [docs/configuration.en.md](docs/configuration.en.md).
`--debug` prints timings and cache statistics on stderr.

## Performance

A 47-step agent replay on Douyin (360 MB, 56 DEX files): about 60 ms through a warm MCP session. 836 APKs ×
8 rules in one scan: about 0.5 s in one warm MCP process. Full numbers, the tools compared and how to
reproduce them: [benchmark/README.md](benchmark/README.md).

## Documentation

- [docs/query.en.md](docs/query.en.md): output format, query syntax, several files as one program.
- [docs/harmonyos.en.md](docs/harmonyos.en.md): using asc on HarmonyOS (HAP / ABC).
- [docs/agents.en.md](docs/agents.en.md): cut output and spill files, the daemon, MCP.
- [docs/configuration.en.md](docs/configuration.en.md): cache, thread and memory settings.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): crates, implementation and design trade-offs.
- [docs/ark-abc-design.md](docs/ark-abc-design.md) (Chinese): design of the HarmonyOS / ABC support, measured call
  resolution precision.
- [benchmark/README.md](benchmark/README.md): correctness and performance evaluation.

## Credits

asc-rs grew out of the ideas and original implementation of [ASC](https://github.com/MG1937/ASC) (MG1937,
"R8 Compiler Optimization as a DeCompiler Primitive").

## License

Apache-2.0, same as the original project.
