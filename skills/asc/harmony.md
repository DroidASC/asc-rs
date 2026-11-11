# asc on HarmonyOS (.hap / .hsp / .app / .abc)

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
  `; @RECORD(name=value)`; `findrefs string` matches annotation values too (rows marked `annotation`,
  no `+0xPC`); an annotation interface is `kind=annotation` in `listclass`. In rules, kind aliases work (`property:`, `function:`). Who navigates to
  a route / page: `findrefs string '=NAME'`.
- With `ets/sourceMaps.map` (debug builds): the record is headed `; source PATH`, a function `line N
  (source line M)`; `(no source line)` = generated by the build (state accessors, `rerender`), skip it.

Not on HarmonyOS: `--virtual`, call-site value constraints (`method:X[arg0=...]`), `getmanifest --resolve`,
findrefs `type` / `field` / `extends` / `impl` (use `hierarchy`), static ArkTS (`modules_static.abc`).
Rule parts are the HarmonyOS kinds only: `string` `literal` `number` `prop` `global` `import` `call` `method`.
