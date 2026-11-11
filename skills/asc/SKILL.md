---
name: asc
description: Search and read Android APK bytecode (and HarmonyOS HAP / ABC) from the shell with the asc CLI - the manifest's attack surface (exported components, providers, deep links), code references to strings / types / methods / fields, smali of a class or method, call graphs and class hierarchies, resources. Use when auditing or reverse engineering an APK or a HarmonyOS .hap / .app / .abc, or answering "which code calls / uses X" in one or many APKs.
---

# asc

`asc` answers questions about an APK directly from the file, in milliseconds, without
decompiling it first. Every command takes the APK path first; class names may be written
`rs.asc.B` or `Lrs/asc/B;`.

## Output

- One record per line, columns separated by ` | `; lines starting with `#` are headers,
  totals and hints. Grep it freely.
- findrefs rows: `dex | Lcls;->method(params)ret | matched`, matched strings JSON-quoted. Field
  matches end in `[read]` (`iget*` / `sget*`) or `[write]` (`iput*` / `sput*`).
- Keep replies short with `--limit N` (records) or `--max-bytes N`. When cut, the last line
  names a file with the whole output: grep that file, or rerun with the `--offset` it gives.

```sh
asc findrefs app.apk string 'https?://' --limit 50
# records 1-50 of 523 shown; full output in /home/u/.cache/asc/out/3f2a….txt (grep it, or rerun with --offset 50)
```

- A query with no results prints `hint:` lines on stderr (DEX entries searched, case
  sensitivity, a framework class the APK does not define, ...): follow them.
- Exit status 2: some DEX entries could not be searched; the other results are still valid.

## Read the part for your input

The commands, rules and output marks differ between the two formats; read the file for yours
before the first query:

- APK, jar or `.dex` (or a directory / `,` list of them): [android.md](android.md).
- HarmonyOS `.hap`, `.hsp`, `.app`, `.abc`, or an unpacked package directory: [harmony.md](harmony.md).
- A directory whose content you do not know: `asc listclass DIR --limit 5` shows which (Android
  classes are `Lrs/asc/B;`, HarmonyOS records `&entry/src/main/ets/pages/Index&`); read the
  matching file, or both.

On HarmonyOS a class is a *record* and a method a *function*; findrefs `type` / `field` /
`extends` / `impl`, `--virtual` and call-site values (`method:X[...]`) are Android only.

## Tuning

`asc config --json` shows every setting (threads, memory, disk cache), its source and
what `auto` comes to on this machine; change one with `--set KEY=VALUE` on a command, its
`env` variable for a session, or `~/.config/asc/config.toml` for good.

- Small machine, or memory pressure: `memory.max=1G` (or `10%`), `threads=4`.
- Several agents at once: keep `auto` (processes split memory and threads); if they still
  crowd the machine, lower `memory.max` to a percentage.
- Little disk: `cache.max=2G`, or `cache.tiers=derived,rendered` to skip inflated DEX.
- One-off sweep you will not repeat: `--no-cache`, or `ASC_CACHE=off` for the session.

## Notes

- Repeated commands are fast: a per-user daemon keeps opened programs resident and gives the same
  output; `ASC_DAEMON=off` runs each command in its own process.
- `asc --help` lists every command and the global options; `asc <command> --help`
  lists that command's options.
