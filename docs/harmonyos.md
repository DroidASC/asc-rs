[English](harmonyos.en.md) | 简体中文

# HarmonyOS（HAP / ABC）

同一个 `asc`、同样的命令也读 ArkCompiler 字节码（ArkTS / JS 编译出的 `.abc`），按文件内容自动识别：

- **输入**：`.hap` / `.hsp`、`.app`（内层 hap 可以是压缩的）、裸 `.abc`，或一个目录 / `,` 列表（当作一个程序；一个 hap
  里的每个 `ets/*.abc` 都读，行首的 entry 列说明来自哪个）。目录里的文件按内容识别（`PANDA` 魔数、zip 里有
  `module.json` / `ets/*.abc`），叫什么名字、用什么扩展名都可以（例外：名字是 `.apk` / `.dex` / `.jar` / `.aar` / `.apex` 的文件直接按 Android 处理，不看内容）。解包后的包目录（有 `module.json` 和 `ets/*.abc`）
  与原包等价：清单、资源、`xml` 都能用。zip 里的包也按内容找，可以多层（一个文件里至多 4 层，解压总量至多
  4 GiB），条目名带完整路径，如 `shop.app/entry.hap/ets/modules.abc`。
- **加密的包**：应用市场下载的 hap 里 `ets/modules.abc` 是加密的，会在 stderr 以 `# warning:` 点名并跳过（`findrefs` /
  `callgraph` 退出码 2），不做解密。把解密后的 abc 放在 hap 旁边并传这个目录：代码取自解密文件，`module.json`、
  资源等仍取自 hap（hap 解包成目录时同理，解密文件放在目录里或目录旁）。配对只看文件头（版本、大小、校验和）和正文的校验和，不看文件名。
- **名字**：类 = record（一个模块：`&entry/src/main/ets/pages/Index&`，三方库带版本 `&@ohos/lib/Index&1.0.0`，旧版本
  是 `rs.asc/entry/ets/pages/Index`；可以只写路径后缀 `pages/Index`），方法 = 函数（原始名 `#~@0>#build` 或还原名
  `Index.build`）。

| 命令 | Android | HarmonyOS |
|---|---|---|
| `listclass` | 类 | record；用户声明的注解接口标 `kind=annotation`；`--all` 连同编译器自己的伪 record |
| `getclass` / `disassemble` | smali | pandasm 风格反汇编；`--method` 只看一个函数，`--entry` 指定 abc |
| `getmanifest` / `manifest-summary` | `AndroidManifest.xml` | `module.json`（`--file pack.info` / `pkgContextInfo.json`）；摘要里每个 ability / extension 带 `record=`，`callbacks` 行列出它的 `onXxx` 函数 |
| `findrefs string` / `method` / `all` / `rules`，`--context` | ✓ | ✓（`method` 找的是函数的**定义位置**，不是调用；与其他条件组合时指“函数名匹配”）；`!条件` / `--none` 排除；`call:{规则}` 是“调用了匹配该规则的函数”，可嵌套 |
| `findrefs prop` / `global` / `import` / `number` / `call` | — | ✓ |
| `findrefs type` / `field` / `extends` / `impl` | ✓ | —（继承关系用 `hierarchy`） |
| `callgraph` | ✓ | ✓：`--to` / `--from` / `--unless` 都接受规则（`--to call:REGEX` 以被调用路径为根），`--no-defines`、`--unresolved`、`--entry`；没有 `--virtual` |
| `hierarchy` | ✓ | ✓：父类取自每个类定义处；`CLASS` 可以是类名、`RECORD->CLASS`，或程序外的父类 `import:REGEX` / `global:REGEX`；`--method` 看类的成员（含访问器之后才定义的方法） |
| `resources` | `resources.arsc` | `resources.index`，参数相同；QUERY 可写 `0x…`、`string/name`、`$string:name`、`app.string.name` |
| `xml` | 二进制 XML | 原样打印包内的文本文件：`'$profile:main_pages'`（页面清单、路由表）或包内路径 |
| `getclass --res-names` | 资源 id 常量 | `$r(...)` 对象所在行追加 `# string/name "值"` |
| `decompile` | Java / Kotlin（dexdec 等） | JavaScript（arkdec，按需启用：设 `$ASC_ARKDEC_WORKER` 或 `[decompilers.arkdec] command`，或把 `asc-arkdec-worker` 放在 asc 旁边 / `PATH` 上）；`--method`、`--entry`、`--raw`（不去语法糖）、`--level pc-dispatch`；没有 worker 或后端失败时给出 `getclass` 的反汇编（退出码 2）。见 [decompile-backends.md](decompile-backends.md) §6.5、§9、§12 |

```sh
asc manifest-summary entry.hap | grep -E '^(ability|callbacks|uri)'    # 导出的 ability、回调、deep link
asc getclass entry.hap entryability/EntryAbility --method EntryAbility.onCreate
asc findrefs entry.hap import '@ohos:' --requests                      # 用到哪些系统模块
asc findrefs entry.hap call '^import:@ohos:net\.http'                  # 谁调用了 http 模块
asc findrefs entry.hap prop request --exact --access call              # 按成员名找调用，不管接收者
asc findrefs entry.hap all 'call:^import:@ohos:net\.http' 'string:^https?://'
asc findrefs entry.hap all 'call:^import:@ohos:net\.http' '!string:^https?://' --context 3   # 排除条件；带上下文
asc findrefs entry.hap call '{string:(?i)oaid}'                        # 谁调用了用到该字符串的函数
asc hierarchy entry.hap UIAbility --method onCreate                         # 谁继承 UIAbility、谁重写了 onCreate
asc xml entry.hap '$profile:main_pages'                                     # 页面清单；routerMap 同理
asc resources entry.hap --search '登录' --in value                          # 文案 → id，再 findrefs number ID
ASC_ARKDEC_WORKER=~/asc-arkdec/target/release/asc-arkdec-worker asc decompile entry.hap pages/Index --method Index.build
asc callgraph entry.hap entryability/EntryAbility EntryAbility.onCreate --callees --depth 3
asc callgraph entry.hap --to 'call:^import:@ohos:net\.http' --depth 6  # 谁能走到 http
asc callgraph app-dir/ --to 'call:^import:@ohos:net\.http' --from 'method:^EntryAbility\.on' --unless 'string:(?i)mock' --depth 8 --max-nodes 5000
```

`findrefs` 的一行是 `entry | RECORD->函数+0xPC | 还原名 | 指令 ; 解析出的被调用者`，第二列可以原样贴给 `getclass` /
`callgraph`。`getclass`（CLI 与 MCP 一致）先按原样查函数，找不到再去掉 `+0xPC` 查，无论它写在 `->` 后还是
`--method` 里；记录里没有的函数会报错并列出该记录有哪些函数。

```
ets/modules.abc | &entry/src/main/ets/common/Utils/utils&->#~@0<#o0O0OOoo+0xef | utils.o0O0OOoo | callthis2 v10, v11, v12 ; import:@ohos:net.http#default.createHttp().request(expr, expr)
```

ArkTS 的调用指令不带被调用者，只在函数内追踪它的来源，所以结果会说明知道多少：

- 被调用者路径（`findrefs call`、`callgraph --to` 匹配的就是它）：`import:请求#名字.成员`、`global:名字.成员`、
  `this.成员`、`local:函数` 是可确定的来源；`argN` 是本函数的第 N 个参数，`this@F` / `argN@F` 是闭包捕获的外层函数 F
  的 `this` / 参数，`x().成员` 是调用返回值的成员，`lex(层,槽)` 是有多个写入者的捕获变量，`?` 是未知。
- `callgraph` 的行：无标记是可证明的调用；`[new]` 构造；`[super]` 是 `super()` / `super.m()` 接到父类；
  `[this-class]` / `[inherited]` / `[instance]` 是按名字匹配的方法（在调用者所在的类、在祖先类、在某个确定类的对象上：导出的 `new C()`，
  或 `C.getInstance()` 这类函数 / 静态属性交出的对象），不保证；`[reassigned]` 表示途中经过被装饰器重新赋值的类，装饰器没换掉类时成立；`[defines]` 是创建闭包而不是调用（`--no-defines` 去掉）；`[external]` 是根在程序外的叶子
  （系统模块、native 库、全局对象）；`[unlinked]` 是根在程序内某个 record、但没接到具体函数的叶子（调用返回值的成员等），
  路径里有 record，可以手工接着查；`[unresolved]` 是来源未知的叶子
  （`--callees --unresolved` 列出，否则只在行尾计数 `unresolved=N`）；`(repeated)` 表示该节点已在别处展开；
  `[N+ subclasses skipped]` 表示该类子类超过 512 个，经更多子类继承来的调用点没有找。
- 系统回调（生命周期 `onXxx`、事件处理函数）没有调用者；路径断在 `[unresolved]` 时按名字接着查：
  `findrefs method NAME --exact`（谁定义了它）、`findrefs prop NAME --exact --access call`（还有哪些调用点）。

- `hierarchy` 的行：`[external]` 是程序外的父类（系统类、全局），`[unresolved]` 是追不到来源的父类，`[reassigned]` 是
  定义后又被装饰器重新赋值的类（子类继承的是它或装饰器换上的东西，不保证），`[function]` 是当作基类用的普通函数。
- 资源 id 只在一个包内唯一；多包程序的 `resources` 行首是包名，多包时用 `findrefs number ID --entry 包名` 把搜索限定在
  一个包里（`listclass` 等也有 `--entry`）。
- `manifest-summary` 另有 `page` / `route` 行（页面清单和路由表的每一项，带 `record=`，可直接给 `getclass`）、
  `abc` 行（每个 abc 条目，加密的条目由哪个解密文件顶替）；多个包里相同的 `pack.info` 只列一次。
- 超过 2048 字节的字符串写成 `"…"… (+N bytes)`，匹配点在截断之后时带 `match at byte N` 和命中处的片段。
- `getclass --lines`（`disassemble --debuginfo` 同义）在源码行变化处写 `; line N`；函数上的用户注解（`findrefs string` 也搜注解里的字符串，行上标 `annotation`）写成
  `; @RECORD(name=value)`；不合并编译的 abc 里函数都在 `_GLOBAL` record。
- 调试构建带局部变量名时，`getclass` 的函数头多一行 `; locals [起, 止): v3 name, …`。
- 包里带 `ets/sourceMaps.map`（调试构建才有）时，`manifest-summary` 多一行 `source-maps … modules=N`；`getclass` 的
  record 头多一行 `; source 原始路径`，函数头写成 `line N (source line M)`：`line N` 是编译中间文件的行（从 0 计），
  `source line` 才是源码行；`(no source line)` 的函数是构建生成的（状态变量访问器、`rerender` 等）。

- 规则（`findrefs all` / `rules`、`callgraph --to / --from / --unless`）写法与 DEX 侧相同（[query.md](query.md#规则写法)）：
  `&` 只在后面紧跟 `KIND:` / `!KIND:` 且不在 `{}` / `()` 内时才连接，record 名里的 `&` 保持原样。本版本的变化：`()` 内的
  `&` 不再连接；花括号里的规则在第一个未配对的 `}` 处结束（`call:{string:a}b}` 报错，以前是正则 `a}b`）；
  `call:={RULE}` 等同 `call:{RULE}`，`call:*{RULE}` 报错（分派只有 DEX 有）；未知 KIND 和空值与规则的其他错误一样报成
  `bad rule "规则": 原因 at column N`。
- 行、反汇编和资源值里的字符串把双向控制符、零宽及其他不可见格式字符像控制字符一样转义（`\u202e`、`\u200b`；本版本新增，
  与 DEX 侧相同：[query.md](query.md)）。

限制：HarmonyOS 程序和 APK 共用同一个 daemon（调用图等分析结果驻留复用），但没有磁盘 cache（打开是毫秒级）；
父类在程序外的 `super()` / 继承方法仍是叶子，单例 getter 只在返回值来源确定时才接上（转发给别的类、按 key 存的多例
不接；函数入口的热修复桩不算作它的返回值，边反映的是出厂代码）；没有调用点取值约束（`method:X[arg0=…]`）和虚分派；
不支持静态 ArkTS（`modules_static.abc`）；9.0.0.0–24.0.0.0 各版本用官方编译器的产物对照过官方反汇编，更高版本没有验证；
目录里 DEX 与 HarmonyOS 文件混放时按 Android 程序处理，HarmonyOS 文件要单独给路径。

设计与实测数据见 [ark-abc-design.md](ark-abc-design.md)。
