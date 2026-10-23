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
| several queries at once | `droidasc findrefs app.apk rules 'method:java.lang.Runtime->exec' 'string:(?i)password'` (rows prefixed `r1 |`, `r2 |`; `--file` for many) |
| conditions in one method | `droidasc findrefs app.apk all 'string:https?://' 'method:android.webkit.WebView->loadUrl' '!string:localhost'` |
| callers of the methods that use X | `droidasc findrefs app.apk method '{literal:device_id}'` (one call, any depth of `{}`) |
| calls of a list of methods | `droidasc findrefs app.apk method @methods.txt` |
| code around each hit | add `--context 3`, or `--context method` for the whole method |
| read code | `droidasc getclass app.apk com.a.B` (smali); one method: `--method onReceive` |
| callers / callees | `droidasc callgraph app.apk com.a.B onReceive --depth 3` (`--callees`, `--virtual`) |
| paths from a source to a sink | `droidasc callgraph app.apk --to 'method:Runtime.exec' --from 'method:Intent.getStringExtra' --unless 'method:Validator.check' --depth 4` |
| classes | `droidasc listclass app.apk --prefix com.a` |
| resources | `droidasc resources app.apk string/app_name`, `--search 'https?://' --in value`; `droidasc xml app.apk res/xml/file_paths.xml` |

Member targets accept `Lcom/a/B;->name(sig)`, `com.a.B->name`, `com.a.B#name`, `com.a.B.name`,
or `B.name` (any package). A name alone is a substring / regex (`=name` or a signature: exact). A signature picks that
overload: `run(I)V`, `run(I)` (any return), `run(int, String)`; `f:I` a field of that type.

## Several archives as one program

Framework and system-app paths span files (`framework.jar` -> `services.jar` -> `TeleService.apk`).
Pass a directory (every `*.apk`, `*.jar`, `*.zip`, `*.dex` below it) or paths joined with `,`
wherever an APK goes: findrefs, callgraph, hierarchy and getclass then span every archive.

```sh
droidasc findrefs system/framework impl com.android.internal.telephony.ITelephony
droidasc callgraph framework.jar,telephony-common.jar,TeleService.apk android.telephony.TelephonyManager getImei --depth 3
```

DEX names start with their archive (`services.jar/classes2.dex | ...`), callgraph rows end with
`[services.jar]`. Archives with no `classes*.dex` (odex/vdex only) are listed as `# warning:` on
stderr: deodex them first.

## Rules: composing conditions in one call

A rule is `KIND:VALUE` (code: `string`, `literal`, `type`, `method`, `field`, `extends`, `impl`;
how a method is declared: `override`, `annotation`, `flag`, `in`), several joined with `&` (all
in one method), `!` before a part to drop methods matching it. `rules`, `all`,
`callgraph --to/--from/--unless` and MCP's `rule` / `rules` all take them.

- `method:{RULE}`: calls of the methods whose own code matches RULE. Nest freely:
  `method:{method:{literal:imei}}` is two levels up. Answered in one pass per level, so prefer
  it to looping `findrefs` over a list of methods.
- `method:@FILE`: calls of the methods FILE lists, one per line; earlier findrefs / callgraph
  output works as it is (the first `Lcls;->m(..)` on each line is taken), as do other spellings.
- `method:{RULE}` and `method:@FILE` follow virtual dispatch by default: a call naming the same
  method on a supertype of the matched class (an interface it implements) or on a subclass that
  inherits it is listed too, with a `(dispatch Lcls;)` note. This is what catches an interface
  or base-class call to a framework method the program implements. It over-approximates (every
  class with that signature on the line, not only the one that runs); write `method:={RULE}` /
  `method:=@FILE` for exact matches on the set's own methods only. A matched method with a very
  general supertype (`Runnable.run`, a Kotlin `FunctionN.invoke`, a lifecycle callback) pulls in
  that supertype's calls everywhere — prefer `=`, or narrow RULE, when the set holds such methods.
- `string:` regexes match each string on its own: `^abc$` is the whole string. Write `\&` for
  a literal `&` in a regex.

Definition predicates name method **definitions** (rows have no call site; the matched column
names the predicate). They answer from the class definitions, not a code scan, and span every
archive of the program:

- `override:CLASS->name`: every method overriding or implementing it, through the hierarchy
  (the class's own definition and every subtype's). `override:android.os.IInterface->asBinder`.
- `annotation:TYPE`: methods carrying that annotation; `in:{annotation:TYPE}` the methods of a
  class carrying it. `annotation:androidx.annotation.RequiresPermission`.
- `flag:public,static` (comma = all); `!flag:abstract` drops them. public, private, protected,
  static, final, synchronized, native, abstract, synthetic, constructor.
- `in:{CLASS-COND}`: methods declared in a matching class. `in:{extends:C}` / `in:{impl:C}`
  take C's subtree (C exact); `in:{type:REGEX}` matches the declaring class descriptor by
  regex (e.g. every `$Stub` class, `in:{type:.*\$Stub;}`); `in:{annotation:TYPE}`.

```sh
# every AIDL stub's declared methods (the $Stub classes themselves)
droidasc findrefs system/framework rules 'in:{type:.*\$Stub;}'
# binder-exposed implementations of one interface that reach an identifier getter,
# skipping any path through a permission check
droidasc callgraph system/framework \
  --from 'override:com.android.internal.telephony.ITelephony->getDeviceId' \
  --to 'method:android.telephony.TelephonyManager->getImei' \
  --unless 'method:~enforce.*Permission' --depth 6
# native methods that also load a crypto string
droidasc findrefs app.apk rules 'flag:native & string:AES'
```

```sh
# who calls the methods that build a device id, minus test code
droidasc findrefs app.apk rules 'method:{literal:device_id} & !type:Lcom/a/test/'
# paths from methods that read an Intent extra to Runtime.exec, none through a method
# that calls the app's validator
droidasc callgraph app.apk --to 'method:java.lang.Runtime->exec' \
  --from 'method:android.content.Intent->getStringExtra' \
  --unless 'method:com.a.Validator->check' --depth 5
```

`--to RULE` targets every method whose code matches it (callers walk); `--from RULE` keeps only
the caller paths that start at a matching method (marked `[from]`), or alone walks its callees;
`--unless RULE` (repeatable) leaves out methods whose code matches it and what only they reach.

### Call-site values: `method:X[...]`

Brackets after any method condition (`X`, `{RULE}`, `@FILE`) keep only the calls whose values
match, all of them: `[arg1="android_id", ret=unused]` or `[arg1="android_id"][ret=unused]`.

- `argN` = Nth declared parameter of the called method (from 0, a long counts once); `this`
  = the receiver. Values: `*` (show only), numbers (`0x10`, `-1`, `true`, `null`), `"text"`,
  `~regex` (quote it, `~"a,b"`, if it holds `,` or `]`), `param` / `paramK` (the caller's own
  `pK`, smali numbering), `ret:METHOD` (result of that call), `field:FIELD`, `new:TYPE`,
  `class:TYPE`. `ret=used` / `ret=unused`: whether the call's result is read.
- Values come from the calling method alone (constants, moves, casts, joins). The row shows
  what the site may hold: `[arg1="a"|"b"]`, `arg0=param1`, `?` for computed values. `=` keeps
  sites it cannot decide, marked `?[...]`; `==` keeps only sites shown to match. Check `?` rows
  with `--context`.
- `findrefs APK method 'X[...]'` takes them directly; they work in rules, `{}` and callgraph.

```sh
droidasc findrefs fw/ method 'android.provider.Settings$Secure->getString[arg1=="android_id"]'
droidasc findrefs fw/ method 'android.os.SystemProperties->get[arg0==~^ro\.serial]'
# permission checks whose answer is ignored
droidasc findrefs fw/ method 'android.content.Context->checkCallingOrSelfPermission[ret==unused]'
# what is passed: show the values of every call
droidasc findrefs app.apk method 'android.content.Intent->putExtra[arg0=*, arg1=*]'
```

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
