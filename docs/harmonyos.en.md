English | [简体中文](harmonyos.md)

# HarmonyOS (HAP / ABC)

The same `asc` and the same commands read ArkCompiler bytecode (the `.abc` ArkTS / JS compiles to); the
format is detected from the file:

- **Inputs**: a `.hap` / `.hsp`, an `.app` (inner haps may be compressed), a bare `.abc`, or a directory /
  `,` list read as one program; every `ets/*.abc` of a hap is read, and the entry column of a row says which
  one it came from. The files of a directory are recognized by content (the `PANDA` magic, a zip holding
  `module.json` / `ets/*.abc`), whatever their names and extensions (but a file named `.apk` / `.dex` / `.jar` / `.aar` / `.apex` is an
  Android file, and is not looked into). An unpacked package directory
  (`module.json` and `ets/*.abc`) is the package: manifest, resources and `xml` work on it. Packages inside a
  zip are found by content, at any depth up to 4 zips in a file (4 GiB inflated in all); an entry carries
  its whole path, `shop.app/entry.hap/ets/modules.abc`.
- **Encrypted packages**: a hap from the app store has an encrypted `ets/modules.abc`. It is named in a
  `# warning:` on stderr and left out (`findrefs` / `callgraph` exit with 2); nothing is decrypted. Put the
  decrypted abc next to the hap and pass that directory: code comes from the decrypted file, `module.json`,
  resources and the rest from the hap. The two are paired by the header (version, size, checksum) and the
  checksum of the body, not by file name; an unpacked hap pairs the same way, with the decrypted file in or
  next to its directory.
- **Names**: a class is a record (a module: `&entry/src/main/ets/pages/Index&`, libraries carry a version,
  `&@ohos/lib/Index&1.0.0`, older files have `rs.asc/entry/ets/pages/Index`; a path suffix, `pages/Index`,
  is enough), a method is a function (raw `#~@0>#build` or restored `Index.build`).

| command | Android | HarmonyOS |
|---|---|---|
| `listclass` | classes | records; an annotation interface the program declares is marked `kind=annotation`; `--all` adds the compiler's pseudo records |
| `getclass` / `disassemble` | smali | pandasm-style disassembly; `--method` for one function, `--entry` picks the abc |
| `getmanifest` / `manifest-summary` | `AndroidManifest.xml` | `module.json` (`--file pack.info` / `pkgContextInfo.json`); in the summary each ability / extension carries `record=`, and a `callbacks` line lists its `onXxx` functions |
| `findrefs string` / `method` / `all` / `rules`, `--context` | ✓ | ✓ (`method` finds where a function is **defined**, not its calls; combined with other parts it means "the function is named so"); `!PART` / `--none` exclude; `call:{RULE}` is "calls a function matching RULE" and nests |
| `findrefs prop` / `global` / `import` / `number` / `call` | — | ✓ |
| `findrefs type` / `field` / `extends` / `impl` | ✓ | — (`hierarchy` answers inheritance) |
| `callgraph` | ✓ | ✓: `--to` / `--from` / `--unless` take rules (`--to call:REGEX` roots at a callee path), `--no-defines`, `--unresolved`, `--entry`; no `--virtual` |
| `hierarchy` | ✓ | ✓: the parent is read where each class is defined; `CLASS` is a class name, `RECORD->CLASS`, or a parent outside the program, `import:REGEX` / `global:REGEX`; `--method` sees the members (those defined after an accessor too) of the class |
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
asc findrefs entry.hap all 'call:^import:@ohos:net\.http' '!string:^https?://' --context 3   # an exclusion; with context
asc findrefs entry.hap call '{string:(?i)oaid}'                        # who calls the functions using that string
asc hierarchy entry.hap UIAbility --method onCreate                    # who extends UIAbility, who overrides onCreate
asc xml entry.hap '$profile:main_pages'                                # the page list; the routerMap likewise
asc resources entry.hap --search 'Sign in' --in value                  # text -> id, then findrefs number ID
asc callgraph entry.hap entryability/EntryAbility EntryAbility.onCreate --callees --depth 3
asc callgraph entry.hap --to 'call:^import:@ohos:net\.http' --depth 6  # who reaches http
asc callgraph app-dir/ --to 'call:^import:@ohos:net\.http' --from 'method:^EntryAbility\.on' --unless 'string:(?i)mock' --depth 8 --max-nodes 5000
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
- `callgraph` rows: no mark is a proved call; `[new]` a construction; `[super]` links `super()` / `super.m()` to
  the parent; `[this-class]` / `[inherited]` / `[instance]` are methods matched by name (in the class of the
  caller, in an ancestor, on an object of a known class: an exported `new C()`, or what a function / static property such
  as `C.getInstance()` hands out), not guaranteed; `[reassigned]`
  went through a class a decorator assigned again and holds if the decorator kept the class; `[defines]` creates a closure, it is not a call
  (`--no-defines` drops them); `[external]` is a leaf rooted outside the program (a system module, a
  native library, a global); `[unlinked]` is a leaf rooted at a record of the program but linked to no function
  (a member of a call result and the like): its path names the record, continue there by hand;
  `[unresolved]` is a leaf of unknown origin (`--callees --unresolved` lists them, otherwise a row ends in
  the count, `unresolved=N`); `(repeated)` marks a node expanded elsewhere; `[N+ subclasses skipped]`
  says the class has more than 512 subclasses and call sites inherited through the rest were not looked for.
- Callbacks the system calls (lifecycle `onXxx`, event handlers) have no callers; where a path stops at
  `[unresolved]`, continue by name: `findrefs method NAME --exact` (who defines it), `findrefs prop NAME
  --exact --access call` (the other call sites).

- `hierarchy` rows: `[external]` is a parent outside the program (a system class, a global), `[unresolved]` a
  parent of unknown origin, `[reassigned]` a class a decorator assigned again after its definition (the
  subclass extends it or what the decorator put there, not guaranteed), `[function]` a plain function used
  as a base class.
- A resource id is unique within one package only; with several packages, `findrefs number ID --entry
  PACKAGE` keeps the search to one package (`listclass` and the others take `--entry` too).
- `manifest-summary` also has `page` / `route` rows (each item of the page list and the route table, with
  `record=`, ready for `getclass`) and `abc` rows (each abc entry, and the decrypted file standing in for an
  encrypted one); a `pack.info` that is the same in several packages is listed once.
- A string over 2048 bytes is written `"…"… (+N bytes)`; a match behind the cut adds `match at byte N` and
  the text around it.
- Where a debug build names its local variables, a function header of `getclass` has a line
  `; locals [from, to): v3 name, …`.
- `getclass --lines` (`disassemble --debuginfo` likewise) writes `; line N` where the source line changes; a
  user annotation on a function is written `; @RECORD(name=value)` (`findrefs string` finds the strings of
  annotations too, on rows marked `annotation`); in an abc compiled without merging, the
  functions are all in the record `_GLOBAL`.
- A package with `ets/sourceMaps.map` (debug builds only) gets a `source-maps … modules=N` row in
  `manifest-summary`; `getclass` heads the record with `; source ORIGINAL-PATH` and a function with `line N
  (source line M)`: `line N` is a line of the compiled intermediate file, from 0, `source line` the line of
  the source; a function marked `(no source line)` was generated by the build (state accessors, `rerender`).

Limits: a HarmonyOS program is served by the same daemon as APKs (the analyses stay resident), but has no
disk cache (it opens in milliseconds); `super()` / inherited methods whose parent is outside the
program stay leaves, and a singleton getter is linked only where what it returns is certain (not when it
forwards to another class or keeps instances by key; a hot-fix stub at the entry of a function is not counted
as what it returns, so the edge is that of the code as shipped); there are no call-site value constraints (`method:X[arg0=…]`) and no virtual dispatch; static ArkTS
(`modules_static.abc`) is not supported; versions 9.0.0.0–24.0.0.0 were checked
against the official disassembler on output of the official compiler, later ones were not; a directory mixing DEX and HarmonyOS files is an Android program, so pass the HarmonyOS
files by their own path.

Design and measurements: [ark-abc-design.md](ark-abc-design.md) (Chinese).
