English | [简体中文](query.md)

# Output and query syntax

Output format and query syntax on the Android (DEX) side; for HarmonyOS see [harmonyos.en.md](harmonyos.en.md).

One record per line, columns separated by ` | `; lines starting with `#` are headers, totals and hints, so
grep / cut work. A `findrefs` row is `dex | method (full signature) | matched`:

```
classes.dex | LWV/qE;-><clinit>()V | "http://", "http://www."
classes4.dex | Lcom/…/ConversationView;->onRestoreInstanceState(Landroid/os/Parcelable;)V | Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
classes.dex | Lrs/asc/Store;->update()V | Lrs/asc/Store;->count:I [read], Lrs/asc/Store;->count:I [write]
```

- Classes are `rs.asc.B` or `Lrs/asc/B;`.
- Members are written the same way in the CLI, MCP and rules: `Lrs/asc/B;->name(I)V`, `rs.asc.B->name`,
  `rs.asc.B#name`, `rs.asc.B.name`, `B.name` (a class without a package matches any package). A bare name is a
  regex / substring; `=name` is exact.
- A signature picks that overload: `run(I)V`, parameters only `run(I)`, Java style `run(int, String)`;
  fields `f:I`.
- Field references are labelled `[read]` for `iget*` / `sget*` and `[write]` for `iput*` / `sput*`.
  `findrefs app.apk field TARGET --access read` (or `write`) keeps only that access; omitting it prints both.
- Conditions are `KIND:VALUE` (`string:`, `literal:`, `type:`, `method:`, `field:`); in `rules` they combine
  with `&`, or come from `--file`, one per line.
- An empty result prints `hint:` lines on stderr: DEX entries searched, case sensitivity, a framework class
  the APK does not define, the closest class or the methods it has, and so on.

## Rule syntax

One syntax for the DEX and the HarmonyOS side, in the CLI (`all`, `rules`, `callgraph --to / --from / --unless`)
and in MCP (`rule`, `rules`, `all` / `none` strings); only the kinds differ:

- A rule is `KIND:VALUE` parts joined with `&`, `!` before a part a method must not match.
- A `&` joins two parts only where `KIND:` or `!KIND:` follows it (blanks allowed), and only outside `{}` /
  `()`; anywhere else it belongs to the value: `string:a&b` is the regex `a&b`. `\&` never joins, `\{`, `\}`,
  `\(`, `\)` are no brackets.
- A set of methods: `method:{RULE}` (calls of the methods whose code matches RULE) and `method:{@FILE}` /
  `method:@FILE` (of the methods FILE lists). `=` in front keeps the set's own methods, `*` follows every
  supertype (see the skill for dispatch). On HarmonyOS the set goes under `call:` (`call:{RULE}`,
  `call:{@FILE}`), where `@` alone starts a callee path (`call:@ohos:net`).
- Sets nest at most 8 levels deep. An unmatched `}` closes the set it is in.
- An error names the rule, what is wrong and the column: `bad rule "method:{string:a": expected `}` at column 17`.

Changes in this version: on DEX code a `&` that is not followed by `KIND:` no longer splits the rule (it was an
error; `string:a & ` was one too), `method:{@FILE}` is a new spelling of `method:@FILE`, and `in:{…}` with
several conditions says that it takes one. On HarmonyOS
code `&` inside `()` no longer joins, a rule in braces ends at the first unmatched `}` (`call:{string:a}b}`
is now an error, it was the regex `a}b`), `call:={RULE}` is `call:{RULE}` and `call:*{RULE}` is an error, and
an unknown kind or an empty value reads like the other errors (`bad rule "prop:": empty value at column 6`).

## Several files as one program

The APK argument may also be a jar, a `.dex`, or several files analysed as one program: a directory (every
`*.apk`, `*.jar`, `*.zip`, `*.dex` under it), or paths joined with `,` (`framework.jar,services.jar,TeleService.apk`).
The class hierarchy, the call graph and findrefs span all the files; a DEX name carries its file
(`services.jar/classes2.dex`), a `callgraph` row ends in `[services.jar]`, and `listclass` has a file column.
A file without `classes*.dex` (only odex/vdex left) is listed on stderr as a `# warning:` (in MCP, the `notes`
field and the first line of the text): deodex it first. When several files define the same class, findrefs
reports every place; `getclass` takes the one a class loader would: the earlier file of the program (a
directory in path order, a `,` list in the order given), within a file `classes.dex`, `classes2.dex`, ..., and
lists the other definitions as `# … also defined in …`. The disk cache keeps inflated DEX and indexes per
file: changing one jar invalidates only its own entries, and analysing a jar alone reuses what the program
read; rendered results (L3) are kept per program.
