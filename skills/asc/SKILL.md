---
name: asc
description: Search and read Android APK bytecode (and HarmonyOS HAP / ABC) from the shell with the asc CLI - the manifest's attack surface (exported components, providers, deep links), code references to strings / types / methods / fields, smali of a class or method, call graphs and class hierarchies, resources. Use when auditing or reverse engineering an APK or a HarmonyOS .hap / .app / .abc, or answering "which code calls / uses X" in one or many APKs.
---

# asc

`asc` answers questions about an APK directly from the file, in milliseconds, without
decompiling it first. Every command takes the APK path first; class names may be written
`com.a.B` or `Lcom/a/B;`.

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

## Commands

| question | command |
|---|---|
| attack surface | `asc manifest-summary app.apk` (`| grep exported=true`, `--json`) |
| who uses a string | `asc findrefs app.apk string 'regex'` (`(?i)` ignores case, `--literal` for plain text) |
| who calls a method | `asc findrefs app.apk method 'android.webkit.WebView->loadUrl'` |
| who reads / writes a field | `asc findrefs app.apk field 'android.os.Build->SERIAL'` (`--access read` or `--access write` to filter) |
| who uses a type | `asc findrefs app.apk type android.content.ClipboardManager` |
| subclasses / implementers | `asc findrefs app.apk extends android.webkit.WebViewClient` (`impl` for interfaces); all levels: `asc hierarchy app.apk android.app.Service` |
| several queries at once | `asc findrefs app.apk rules 'method:java.lang.Runtime->exec' 'string:(?i)password'` (rows prefixed `r1 |`, `r2 |`; `--file` for many) |
| conditions in one method | `asc findrefs app.apk all 'string:https?://' 'method:android.webkit.WebView->loadUrl' '!string:localhost'` |
| callers of the methods that use X | `asc findrefs app.apk method '{literal:device_id}'` (one call, any depth of `{}`) |
| calls of a list of methods | `asc findrefs app.apk method @methods.txt` |
| code around each hit | add `--context 3`, or `--context method` for the whole method |
| read code | `asc getclass app.apk com.a.B` (smali); one method: `--method onReceive` |
| callers / callees | `asc callgraph app.apk com.a.B onReceive --depth 3` (`--callees`, `--virtual`) |
| paths from a source to a sink | `asc callgraph app.apk --to 'method:Runtime.exec' --from 'method:Intent.getStringExtra' --unless 'method:Validator.check' --depth 4` |
| classes | `asc listclass app.apk --prefix com.a` |
| resources | `asc resources app.apk string/app_name`, `--search 'https?://' --in value`; `asc xml app.apk res/xml/file_paths.xml` |

Member targets accept `Lcom/a/B;->name(sig)`, `com.a.B->name`, `com.a.B#name`, `com.a.B.name`,
or `B.name` (any package). A name alone is a substring / regex (`=name` or a signature: exact). A signature picks that
overload: `run(I)V`, `run(I)` (any return), `run(int, String)`; `f:I` a field of that type.
Field output always says `[read]` or `[write]`; without `--access`, a method that does both lists both.

## Several archives as one program

Framework and system-app paths span files (`framework.jar` -> `services.jar` -> `TeleService.apk`).
Pass a directory (every `*.apk`, `*.jar`, `*.zip`, `*.dex` below it) or paths joined with `,`
wherever an APK goes: findrefs, callgraph, hierarchy and getclass then span every archive.

```sh
asc findrefs system/framework impl com.android.internal.telephony.ITelephony
asc callgraph framework.jar,telephony-common.jar,TeleService.apk android.telephony.TelephonyManager getImei --depth 3
```

DEX names start with their archive (`services.jar/classes2.dex | ...`), callgraph rows end with
`[services.jar]`. Archives with no `classes*.dex` (odex/vdex only) are listed as `# warning:` on
stderr (MCP: `notes`): deodex them first, or an empty answer may just mean the code was not there.
A class several archives define resolves like a class loader (first archive in program order,
then `classes.dex`, `classes2.dex`, ...); getclass names the others (`also defined in`).

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
  inherits it is listed too, with a `(dispatch Lcls;)` note. This is what catches an AIDL or
  base-class call to a method the program implements (`Build.getSerial` ->
  `IDeviceIdentifiersPolicyService->getSerialForPackage (dispatch ...DeviceIdentifiersPolicy)`).
  It over-approximates: the call may run another implementer.
- A supertype's method is not followed when more than 16 classes of the program implement it,
  or its type has over 1024 subclasses (`Runnable.run`, Kotlin `FunctionN.invoke`, OkHttp
  `Interceptor.intercept`): its calls say nothing about which one runs. Each one left out is a
  `# dispatch not followed via Lsup;->m(..) (N implementers)` line (MCP: `notes`); to include
  one, add `method:Lsup;->m` as its own rule, or write `method:*{RULE}` to follow every
  supertype. `method:={RULE}` / `method:=@FILE` match only the set's own methods.
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
asc findrefs system/framework rules 'in:{type:.*\$Stub;}'
# binder-exposed implementations of one interface that reach an identifier getter,
# skipping any path through a permission check
asc callgraph system/framework \
  --from 'override:com.android.internal.telephony.ITelephony->getDeviceId' \
  --to 'method:android.telephony.TelephonyManager->getImei' \
  --unless 'method:~enforce.*Permission' --depth 6
# native methods that also load a crypto string
asc findrefs app.apk rules 'flag:native & string:AES'
```

```sh
# who calls the methods that build a device id, minus test code
asc findrefs app.apk rules 'method:{literal:device_id} & !type:Lcom/a/test/'
# paths from methods that read an Intent extra to Runtime.exec, none through a method
# that calls the app's validator
asc callgraph app.apk --to 'method:java.lang.Runtime->exec' \
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
asc findrefs fw/ method 'android.provider.Settings$Secure->getString[arg1=="android_id"]'
asc findrefs fw/ method 'android.os.SystemProperties->get[arg0==~^ro\.serial]'
# permission checks whose answer is ignored
asc findrefs fw/ method 'android.content.Context->checkCallingOrSelfPermission[ret==unused]'
# what is passed: show the values of every call
asc findrefs app.apk method 'android.content.Intent->putExtra[arg0=*, arg1=*]'
```

## Audit workflow

1. `asc manifest-summary app.apk | grep exported=true`: exported components, providers
   (authorities, grantUriPermissions), deep links, FileProvider paths, network security config.
2. For each entry point, find what it reaches: `asc findrefs app.apk method 'Lcom/a/Entry;->onReceive' --context method`,
   or the sensitive sinks directly: `asc findrefs app.apk rules 'method:android.webkit.WebView->addJavascriptInterface' 'method:java.lang.Runtime->exec' 'method:android.content.Context->openFileOutput'`.
3. Read the relevant method: `asc getclass app.apk com.a.Entry --method onReceive`.
4. Walk the path: `asc callgraph app.apk com.a.Helper writeFile --depth 3` (callers) or `--callees`.

## HarmonyOS (.hap / .hsp / .app / .abc)

The same commands read ArkTS bytecode; the format is detected from the file, and what does not
apply fails with one line naming what does. A directory or `,` list is one program. An app-store
hap has an encrypted `ets/modules.abc` (`# warning:` on stderr, exit 2, nothing found in it): put
the decrypted `modules.abc` next to the hap and pass the directory.

A class is a *record* (a module): `&entry/src/main/ets/pages/Index&`, libraries end in a version
(`&@ohos/lib/Index&1.0.0`); quote the `&`, or give a path suffix (`pages/Index`). A method is a
*function*: raw `#~@0>#build`, restored `Index.build`. Rows are
`entry | RECORD->FUNCTION+0xPC | restored name | instruction ; resolved callee`: paste column 2
as it is into `getclass` / `callgraph`.

Reading order: `asc manifest-summary entry.hap` (abilities / extensions with `exported=`,
deep-link `uri` lines; each has `record=NAME`, and a `callbacks` line lists its `onXxx`
functions) -> `asc getclass entry.hap entryability/EntryAbility --method EntryAbility.onCreate`
(or the whole record; `listclass --prefix entry/` lists them) -> `findrefs` / `callgraph`.

| question | command |
|---|---|
| who uses a string | `asc findrefs entry.hap string 'https?://'` (`--literal`: plain text; in `all`, `literal:TEXT` is that plain-text string search too) |
| who uses a number | `asc findrefs entry.hap number 0x67452301` (or `A..B`) |
| system modules used | `asc findrefs entry.hap import '@ohos:' --requests`; uses of one: `import '@ohos:net\.http'` |
| who calls X | `asc findrefs entry.hap call '^import:@ohos:net\.http'` (regex over the resolved callee path); by member name, any receiver: `asc findrefs entry.hap prop request --exact --access call` |
| where a function is defined | `asc findrefs entry.hap method EntryAbility.onCreate --exact` (or `'=EntryAbility.onCreate'`): **definition sites, not calls**. Raw names are full of regex metacharacters: use `--exact` |
| property / global access | `asc findrefs entry.hap prop token --access write`, `global console --exact` |
| conditions in one function | `asc findrefs entry.hap all 'call:^import:@ohos:net\.http' 'string:^https?://'` (one scan instead of a query per hit; `prop:=name` is exact). `'!string:...'` or `--none` drops functions matching it. Combined with other parts, `method:NAME` means "the function is named NAME" |
| callers of the functions matching a rule | `asc findrefs entry.hap call '{string:(?i)oaid}'`; nests: `all 'call:{call:{string:(?i)oaid}}' '!method:(?i)test'`; `call:{@FILE}` takes a file of function rows (findrefs / callgraph output) |
| several queries at once | `asc findrefs entry.hap rules 'call:^import:@ohos:net\.http & !string:^https' 'string:(?i)token'` (rows prefixed `r1 \|`; `--file`) |
| code around each hit | add `--context 3`, or `--context method` for the whole function: the `getclass` listing with `>` on the hit rows |
| callees / callers | `asc callgraph entry.hap entryability/EntryAbility EntryAbility.onCreate --callees --depth 3` (callers without `--callees`) |
| who extends X / overrides m | `asc hierarchy entry.hap UIAbility --method onCreate` (a class name, `RECORD->CLASS`, or a parent outside the program: `'import:@ohos:app\.'`, `'^global:ViewPU$'`); `--supers` walks up |
| pages and routes | `asc manifest-summary entry.hap \| grep -E '^(page\|route) '`: each row has `record=` (and a route its `buildFunction=`) for `getclass RECORD --method F`; `asc xml entry.hap '$profile:NAME'` prints the file itself (`customData`) |
| resources | `asc resources entry.hap string/app_name` (or `0x...`, `$string:x`, `app.string.x`), `--search REGEX --in value`, `--resolve` |
| where a text / resource is used | `asc resources entry.hap --search TEXT --in value` gives the id, then `asc findrefs entry.hap number ID`; by-name uses: `findrefs string 'app\.string\.NAME'`; while reading code: `getclass ... --res-names` |
| who reaches a system API | `asc callgraph entry.hap --to 'call:^import:@ohos:net\.http' --depth 6`; only the paths from entry points: add `--from 'method:^EntryAbility\.on'`; `--unless RULE` (repeatable) leaves out matching functions and what only they reach. `--to` / `--from` / `--unless` take any rule (`--to 'string:...'` roots at the functions using it) |

A call names no callee in ArkTS; its origin is tracked inside the function, and output says how
far that got:

- Callee paths: `import:REQUEST#NAME.m`, `global:NAME.m`, `this.m`, `local:FUNCTION` are known
  origins. `argN`: a parameter; `this@F` / `argN@F`: those of the enclosing function F, captured
  by a closure; `x().m`: member of a call result; `lex(L,S)`: a captured variable with several
  writers; `?`: unknown.
- callgraph rows: no mark = proved call. `[new]`. `[super]`: the parent's constructor /
  method. `[this-class]` / `[inherited]` / `[instance]`: a method matched by name (caller's
  class, an ancestor, the class of an object: an exported `new C()` or what `C.getInstance()` /
  a static property hands out), not guaranteed. `[reassigned]`: through
  a class a decorator assigned again. `[defines]`: a closure is created there, not called
  (`--no-defines` drops them). `[external]`: a leaf rooted outside the program - a system
  module, a native library, a global. `[unlinked]`: a leaf rooted at a record of the program but
  linked to no function (member of a call result ...): continue by hand at the record its path names,
  or `--to 'call:PATH'`. `[N+ subclasses skipped]`: over 512 subclasses, the rest not searched.
  `[unresolved]`: a leaf of unknown origin; `unresolved=N` counts them on a row, `--callees
  --unresolved` lists them.
- Callbacks the system calls (lifecycle `onXxx`, event handlers) have no callers, and a path
  stops at `[unresolved] x.NAME`. Continue by name: `findrefs method NAME --exact` (the functions
  that could be meant; `--class RECORD` narrows), `findrefs prop NAME --exact --access call` (the
  other call sites), then `callgraph` from the candidates. Pages and UI are wired by strings
  (`loadContent`, router names): `findrefs string`.

- hierarchy rows: `[external]` = a parent outside the program (system class, global);
  `[unresolved]` = parent of unknown origin; `[reassigned]` = a class a decorator assigned again
  (not guaranteed); an `override ...` row can be pasted into `getclass` / `callgraph`. `super()` and
  inherited methods stay leaves where the parent is outside the program.
- A resource id is unique within one package only: with several packages, `resources` rows start
  with the package: `findrefs number ID --entry PACKAGE` (every command takes `--entry`: an entry
  name, a `/` suffix of it, or a package).
- A paired decrypted abc is one `# note:` (the `abc` rows of manifest-summary say which file);
  only an unpaired encrypted entry is a `# warning:` with exit code 2.
- A string over 2048 bytes is cut, `"..."... (+N bytes)`; a match behind the cut adds `match at
  byte N` and the text around it. Debug builds name locals: `; locals [from, to): v3 name`.
- A directory is one program; its files are recognized by content, whatever they are called, and
  a decrypted abc pairs with its encrypted package entry by header and checksum. An unpacked
  package directory (`module.json` + `ets/*.abc`) works like the package; packages nested in zips
  are found too, entries named by their whole path (`shop.app/entry.hap/ets/modules.abc`).
- `getclass --lines` marks each source line change (`; line N`). A user annotation on a function is
  `; @RECORD(name=value)`. In rules, kind aliases work (`property:`, `function:`). Who navigates to
  a route / page: `findrefs string '=NAME'`.
- With `ets/sourceMaps.map` (debug builds): the record is headed `; source PATH`, a function `line N
  (source line M)`; `(no source line)` = generated by the build (state accessors, `rerender`), skip it.

Not on HarmonyOS: `--virtual`, call-site value constraints (`method:X[arg0=...]`), `getmanifest --resolve`,
findrefs `type` / `field` / `extends` / `impl` (use `hierarchy`), static ArkTS (`modules_static.abc`).
Rule parts are the HarmonyOS kinds only: `string` `literal` `number` `prop` `global` `import` `call` `method`.

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
