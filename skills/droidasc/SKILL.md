---
name: droidasc
description: Search and read Android APK bytecode from the shell with the droidasc CLI - the manifest's attack surface (exported components, providers, deep links), code references to strings / types / methods / fields, smali of a class or method, call graphs and class hierarchies, resources. Use when auditing or reverse engineering an APK, or answering "which code calls / uses X" in one or many APKs.
---

# droidasc

`droidasc` answers questions about an APK directly from the file, in milliseconds, without
decompiling it first. Every command takes the APK path first; class names may be written
`com.a.B` or `Lcom/a/B;`.

## Output

- One record per line, columns separated by ` | `; lines starting with `#` are headers,
  totals and hints. Grep it freely.
- findrefs rows: `dex | Lcls;->method(params)ret | matched`, matched strings JSON-quoted.
- Keep replies short with `--limit N` (records) or `--max-bytes N`. When cut, the last line
  names a file with the whole output: grep that file, or rerun with the `--offset` it gives.

```sh
droidasc findrefs app.apk string 'https?://' --limit 50
# records 1-50 of 523 shown; full output in /home/u/.cache/droidasc/out/3f2a….txt (grep it, or rerun with --offset 50)
```

- A query with no results prints `hint:` lines on stderr (DEX entries searched, case
  sensitivity, a framework class the APK does not define, ...): follow them.
- Exit status 2: some DEX entries could not be searched; the other results are still valid.

## Commands

| question | command |
|---|---|
| attack surface | `droidasc manifest-summary app.apk` (`| grep exported=true`, `--json`) |
| who uses a string | `droidasc findrefs app.apk string 'regex'` (`(?i)` ignores case, `--literal` for plain text) |
| who calls a method | `droidasc findrefs app.apk method 'android.webkit.WebView->loadUrl'` |
| who reads / writes a field | `droidasc findrefs app.apk field 'android.os.Build->SERIAL'` |
| who uses a type | `droidasc findrefs app.apk type android.content.ClipboardManager` |
| subclasses / implementers | `droidasc findrefs app.apk extends android.webkit.WebViewClient` (`impl` for interfaces); all levels: `droidasc hierarchy app.apk android.app.Service` |
| several queries at once | `droidasc findrefs app.apk rules 'method:java.lang.Runtime->exec' 'string:(?i)password'` (rows prefixed `r1 |`, `r2 |`) |
| conditions in one method | `droidasc findrefs app.apk all 'string:https?://' 'method:android.webkit.WebView->loadUrl'` |
| code around each hit | add `--context 3`, or `--context method` for the whole method |
| read code | `droidasc getclass app.apk com.a.B` (smali); one method: `--method onReceive` |
| callers / callees | `droidasc callgraph app.apk com.a.B onReceive --depth 3` (`--callees`, `--virtual`) |
| classes | `droidasc listclass app.apk --prefix com.a` |
| resources | `droidasc resources app.apk string/app_name`, `--search 'https?://' --in value`; `droidasc xml app.apk res/xml/file_paths.xml` |

Member targets accept `Lcom/a/B;->name(sig)`, `com.a.B->name`, `com.a.B#name`, `com.a.B.name`,
or `B.name` (any package). A name alone is a substring / regex (`=name` or a signature: exact). A signature picks that
overload: `run(I)V`, `run(I)` (any return), `run(int, String)`; `f:I` a field of that type.

## Audit workflow

1. `droidasc manifest-summary app.apk | grep exported=true`: exported components, providers
   (authorities, grantUriPermissions), deep links, FileProvider paths, network security config.
2. For each entry point, find what it reaches: `droidasc findrefs app.apk method 'Lcom/a/Entry;->onReceive' --context method`,
   or the sensitive sinks directly: `droidasc findrefs app.apk rules 'method:android.webkit.WebView->addJavascriptInterface' 'method:java.lang.Runtime->exec' 'method:android.content.Context->openFileOutput'`.
3. Read the relevant method: `droidasc getclass app.apk com.a.Entry --method onReceive`.
4. Walk the path: `droidasc callgraph app.apk com.a.Helper writeFile --depth 3` (callers) or `--callees`.

## Tuning

`droidasc config --json` shows every setting (threads, memory, disk cache), its source and
what `auto` comes to on this machine; change one with `--set KEY=VALUE` on a command, its
`env` variable for a session, or `~/.config/droidasc/config.toml` for good.

- Small machine, or memory pressure: `memory.max=1G` (or `10%`), `threads=4`.
- Several agents at once: keep `auto` (processes split memory and threads); if they still
  crowd the machine, lower `memory.max` to a percentage.
- Little disk: `cache.max=2G`, or `cache.tiers=derived,rendered` to skip inflated DEX.
- One-off sweep you will not repeat: `--no-cache`, or `DROIDASC_CACHE=off` for the session.

## Notes

- Repeated commands are fast: a per-user daemon keeps APKs resident and gives the same
  output; `DROIDASC_DAEMON=off` runs each command in its own process.
- `droidasc --help` lists every command and the global options; `droidasc <command> --help`
  lists that command's options.
