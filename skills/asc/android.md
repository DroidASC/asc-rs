# asc on Android (APK / jar / dex)

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
| read code | `asc getclass app.apk rs.asc.B` (smali); one method: `--method onReceive` |
| callers / callees | `asc callgraph app.apk rs.asc.B onReceive --depth 3` (`--callees`, `--virtual`) |
| paths from a source to a sink | `asc callgraph app.apk --to 'method:Runtime.exec' --from 'method:Intent.getStringExtra' --unless 'method:Validator.check' --depth 4` |
| classes | `asc listclass app.apk --prefix rs.asc` |
| resources | `asc resources app.apk string/app_name`, `--search 'https?://' --in value`; `asc xml app.apk res/xml/file_paths.xml` |

Member targets accept `Lrs/asc/B;->name(sig)`, `rs.asc.B->name`, `rs.asc.B#name`, `rs.asc.B.name`,
or `B.name` (any package). A name alone is a substring / regex (`=name` or a signature: exact). A signature picks that
overload: `run(I)V`, `run(I)` (any return), `run(int, String)`; `f:I` a field of that type.
Names copied from decompiled Java / Kotlin work when nothing matches as written: `rs.asc.Outer.Inner` (`Outer$Inner`),
`Outer.Anonymous1` (`$1`), `Cdo` (`do`), `a$2` (`a`), `` `in` ``, the class name for a constructor; a `#` line names the match.
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
- `method:{@FILE}` (or `method:@FILE`): calls of the methods FILE lists, one per line; earlier findrefs / callgraph
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
- `string:` regexes match each string on its own: `^abc$` is the whole string. A `&` joins
  parts only where `KIND:` follows it; write `\&` there for a literal `&` in a regex.

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
asc findrefs app.apk rules 'method:{literal:device_id} & !type:Lrs/asc/test/'
# paths from methods that read an Intent extra to Runtime.exec, none through a method
# that calls the app's validator
asc callgraph app.apk --to 'method:java.lang.Runtime->exec' \
  --from 'method:android.content.Intent->getStringExtra' \
  --unless 'method:rs.asc.Validator->check' --depth 5
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
2. For each entry point, find what it reaches: `asc findrefs app.apk method 'Lrs/asc/Entry;->onReceive' --context method`,
   or the sensitive sinks directly: `asc findrefs app.apk rules 'method:android.webkit.WebView->addJavascriptInterface' 'method:java.lang.Runtime->exec' 'method:android.content.Context->openFileOutput'`.
3. Read the relevant method: `asc getclass app.apk rs.asc.Entry --method onReceive`.
4. Walk the path: `asc callgraph app.apk rs.asc.Helper writeFile --depth 3` (callers) or `--callees`.
