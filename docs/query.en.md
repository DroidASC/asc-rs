English | [简体中文](query.md)

# Output and query syntax

Output format and query syntax on the Android (DEX) side; for HarmonyOS see [harmonyos.en.md](harmonyos.en.md).

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
