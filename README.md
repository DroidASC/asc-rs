[English](README.en.md) | 简体中文

# asc-rs

把 APK 当作只读数据库：直接在压缩包上定位类、搜索交叉引用、反汇编、解码 manifest 和资源，毫秒级，
不需要预处理或全局索引；HarmonyOS 的 HAP / ABC 也用同一套命令查（见 [HarmonyOS](#harmonyoshap--abc)）。
面向人和 agent：CLI 为主（Unix 上有透明的预热 daemon），也提供 MCP 服务器。可执行文件叫 `asc`。

## 构建

```sh
cargo build --release        # -> target/release/asc（需要 Rust 1.85+）
cargo test --workspace
```

## 快速上手

```sh
asc manifest-summary app.apk | grep exported=true          # 暴露面
asc findrefs app.apk string 'https?://' --limit 50         # 谁用了这个字符串
asc findrefs app.apk method 'android.webkit.WebView->loadUrl' --context 3
asc getclass app.apk com.poc.Main --method onCreate        # 读 smali
asc callgraph app.apk com.poc.Main onCreate --depth 3      # 调用者树
asc findrefs app.apk rules 'string:http://' 'method:java.lang.Runtime->exec'
```

## 命令

| 命令 | 作用 |
|---|---|
| `getclass` / `disassemble` | 定位类、在内存中重建单类 DEX 并输出 smali；`--method` 只看某个方法，`--dump-dex` 写出 DEX 交给 jadx 等工具 |
| `listclass`（`classes`） | 列出类，`--prefix` 过滤 |
| `findrefs` | 对 `string` / `type` / `method` / `field` 的代码引用，`extends` / `impl` 直接子类和实现类；`all` 组合条件，`rules` 一次扫描回答多条规则 |
| `callgraph` | 方法的调用者（默认）或 `--callees`，`--virtual` 沿类层次跟踪分派 |
| `hierarchy` | 传递的子类 / 实现类，或 `--supers`；`--method` 标出重写 |
| `getmanifest`（`manifest`）/ `manifest-summary` | 解码 manifest；摘要每行一条记录：导出组件及原因、权限、provider、deep link、FileProvider、网络安全配置 |
| `resources` / `xml` | 查询 `resources.arsc`；解码任意二进制 XML |
| `mcp` / `daemon` / `cache` | MCP 服务器；daemon 管理；磁盘 cache 管理（`path` / `stats` / `clear`） |

APK 参数也可以是 jar、`.dex`，或作为一个程序一起分析的多个文件：一个目录（其下所有 `*.apk`、`*.jar`、`*.zip`、`*.dex`），
或用 `,` 连接的多个路径（如 `framework.jar,services.jar,TeleService.apk`）。类层次、调用图和 findrefs 跨所有文件，
DEX 名带上所属文件（`services.jar/classes2.dex`），`callgraph` 行尾标 `[services.jar]`，`listclass` 多一列文件名；
没有 `classes*.dex` 的文件（只剩 odex/vdex）在 stderr 以 `# warning:` 列出（MCP 回复的 `notes` 字段和文本首行），需先 deodex。
同一个类在多个文件中都有定义时，findrefs 报告所有位置；`getclass` 按类加载器的顺序取：程序中靠前的文件（目录按路径排序，
`,` 列表按给出的顺序），同一文件内 `classes.dex`、`classes2.dex`……，并用 `# … also defined in …` 列出其他文件中的定义。
磁盘 cache 的解压 DEX 和索引按单个文件存放：改动一个 jar 只让它自己的条目失效，单独分析某个 jar 也复用程序里读过的条目；
渲染结果（L3）仍按整个程序存放。

完整选项见 `asc --help` 和 `asc <命令> --help`。退出码：0 成功，1 出错，2 部分 DEX（或 ABC）条目无法搜索（其余结果有效）。

## 输出与查询写法

每行一条记录，列以 ` | ` 分隔，`#` 开头的行是表头、合计和提示，便于 grep / cut。`findrefs` 的一行是
`dex | 方法（完整签名） | 匹配内容`：

```
classes.dex | LWV/qE;-><clinit>()V | "http://", "http://www."
classes4.dex | Lcom/…/ConversationView;->onRestoreInstanceState(Landroid/os/Parcelable;)V | Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
classes.dex | Lcom/a/Store;->update()V | Lcom/a/Store;->count:I [read], Lcom/a/Store;->count:I [write]
```

- 类名可写 `com.a.B` 或 `Lcom/a/B;`。
- 成员在 CLI、MCP 和规则里写法统一：`Lcom/a/B;->name(I)V`、`com.a.B->name`、`com.a.B#name`、`com.a.B.name`、
  `B.name`（不带包名的类匹配任意包）。只写名字是 regex / 子串，`=name` 精确匹配。
- 带签名时只命中该重载：`run(I)V`、只写参数的 `run(I)`、Java 写法 `run(int, String)`，字段 `f:I`。
- 字段引用按 Dalvik opcode 标记 `[read]`（`iget*` / `sget*`）或 `[write]`（`iput*` / `sput*`）。
  `findrefs app.apk field TARGET --access read` 或 `--access write` 只保留对应引用；不指定时两者都打印。
- 条件写作 `KIND:VALUE`（`string:`、`literal:`、`type:`、`method:`、`field:`），`rules` 中可用 `&` 组合，
  也可以用 `--file` 每行一条。
- 查不到时 stderr 会给出 `hint:`：搜了多少 DEX、大小写、APK 未定义的 framework 类、最接近的类或已有的方法等。

## HarmonyOS（HAP / ABC）

同一个 `asc`、同样的命令也读 ArkCompiler 字节码（ArkTS / JS 编译出的 `.abc`），按文件内容自动识别：

- **输入**：`.hap` / `.hsp`、`.app`（内层 hap 可以是压缩的）、裸 `.abc`，或一个目录 / `,` 列表（当作一个程序；一个 hap
  里的每个 `ets/*.abc` 都读，行首的 entry 列说明来自哪个）。目录里的文件按内容识别（`PANDA` 魔数、zip 里有
  `module.json` / `ets/*.abc`），叫什么名字、用什么扩展名都可以。解包后的包目录（有 `module.json` 和 `ets/*.abc`）
  与原包等价：清单、资源、`xml` 都能用。zip 里的包也按内容找，可以多层（一个文件里至多 4 层，解压总量至多
  4 GiB），条目名带完整路径，如 `shop.app/entry.hap/ets/modules.abc`。
- **加密的包**：应用市场下载的 hap 里 `ets/modules.abc` 是加密的，会在 stderr 以 `# warning:` 点名并跳过（`findrefs` /
  `callgraph` 退出码 2），不做解密。把解密后的 abc 放在 hap 旁边并传这个目录：代码取自解密文件，`module.json`、
  资源等仍取自 hap（hap 解包成目录时同理，解密文件放在目录里或目录旁）。配对只看文件头（版本、大小、校验和）和正文的校验和，不看文件名。
- **名字**：类 = record（一个模块：`&entry/src/main/ets/pages/Index&`，三方库带版本 `&@ohos/lib/Index&1.0.0`，旧版本
  是 `com.a.b/entry/ets/pages/Index`；可以只写路径后缀 `pages/Index`），方法 = 函数（原始名 `#~@0>#build` 或还原名
  `Index.build`）。

| 命令 | Android | HarmonyOS |
|---|---|---|
| `listclass` | 类 | record；`--all` 连同注解等伪 record |
| `getclass` / `disassemble` | smali | pandasm 风格反汇编；`--method` 只看一个函数，`--entry` 指定 abc |
| `getmanifest` / `manifest-summary` | `AndroidManifest.xml` | `module.json`（`--file pack.info` / `pkgContextInfo.json`）；摘要里每个 ability / extension 带 `record=`，`callbacks` 行列出它的 `onXxx` 函数 |
| `findrefs string` / `method` / `all` / `rules`，`--context` | ✓ | ✓（`method` 找的是函数的**定义位置**，不是调用；与其他条件组合时指“函数名匹配”）；`!条件` / `--none` 排除；`call:{规则}` 是“调用了匹配该规则的函数”，可嵌套 |
| `findrefs prop` / `global` / `import` / `number` / `call` | — | ✓ |
| `findrefs type` / `field` / `extends` / `impl` | ✓ | —（继承关系用 `hierarchy`） |
| `callgraph` | ✓ | ✓：`--to` / `--from` / `--unless` 都接受规则（`--to call:REGEX` 以被调用路径为根），`--no-defines`、`--unresolved`、`--entry`；没有 `--virtual` |
| `hierarchy` | ✓ | ✓：父类取自每个类定义处；`CLASS` 可以是类名、`RECORD->CLASS`，或程序外的父类 `import:REGEX` / `global:REGEX`；`--method` 只看类字面量里的成员 |
| `resources` | `resources.arsc` | `resources.index`，参数相同；QUERY 可写 `0x…`、`string/name`、`$string:name`、`app.string.name` |
| `xml` | 二进制 XML | 原样打印包内的文本文件：`'$profile:main_pages'`（页面清单、路由表）或包内路径 |
| `getclass --res-names` | 资源 id 常量 | `$r(...)` 对象所在行追加 `# string/name "值"` |

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
asc callgraph entry.hap entryability/EntryAbility EntryAbility.onCreate --callees --depth 3
asc callgraph entry.hap --to 'call:^import:@ohos:net\.http' --depth 6  # 谁能走到 http
asc callgraph app-dir/ --to 'call:^import:@ohos:net\.http' --from 'method:^EntryAbility\.on' --unless 'string:(?i)mock' --depth 8 --max-nodes 5000
```

`findrefs` 的一行是 `entry | RECORD->函数+0xPC | 还原名 | 指令 ; 解析出的被调用者`，第二列可以原样贴给 `getclass` /
`callgraph`：

```
ets/modules.abc | &entry/src/main/ets/common/Utils/utils&->#~@0<#o0O0OOoo+0xef | utils.o0O0OOoo | callthis2 v10, v11, v12 ; import:@ohos:net.http#default.createHttp().request(expr, expr)
```

ArkTS 的调用指令不带被调用者，只在函数内追踪它的来源，所以结果会说明知道多少：

- 被调用者路径（`findrefs call`、`callgraph --to` 匹配的就是它）：`import:请求#名字.成员`、`global:名字.成员`、
  `this.成员`、`local:函数` 是可确定的来源；`argN` 是本函数的第 N 个参数，`this@F` / `argN@F` 是闭包捕获的外层函数 F
  的 `this` / 参数，`x().成员` 是调用返回值的成员，`lex(层,槽)` 是有多个写入者的捕获变量，`?` 是未知。
- `callgraph` 的行：无标记是可证明的调用；`[new]` 构造；`[super]` 是 `super()` / `super.m()` 接到父类；
  `[this-class]` / `[inherited]` / `[instance]` 是按名字匹配的方法（在调用者所在的类、在祖先类、在导出的 `new C()`
  所属的类里），不保证；`[reassigned]` 表示途中经过被装饰器重新赋值的类，装饰器没换掉类时成立；`[defines]` 是创建闭包而不是调用（`--no-defines` 去掉）；`[external]` 是以导入 / 全局为根、程序里找不到
  对应函数的叶子（系统 API，也包括调用返回值的成员和没解析出来的导入）；`[unresolved]` 是来源未知的叶子
  （`--callees --unresolved` 列出，否则只在行尾计数 `unresolved=N`）；`(repeated)` 表示该节点已在别处展开。
- 系统回调（生命周期 `onXxx`、事件处理函数）没有调用者；路径断在 `[unresolved]` 时按名字接着查：
  `findrefs method NAME --exact`（谁定义了它）、`findrefs prop NAME --exact --access call`（还有哪些调用点）。

- `hierarchy` 的行：`[external]` 是程序外的父类（系统类、全局），`[unresolved]` 是追不到来源的父类，`[reassigned]` 是
  定义后又被装饰器重新赋值的类（子类继承的是它或装饰器换上的东西，不保证），`[function]` 是当作基类用的普通函数。
- 资源 id 只在一个包内唯一；多包程序的 `resources` 行首是包名，多包时用 `findrefs number ID --entry 包名` 把搜索限定在
  一个包里（`listclass` 等也有 `--entry`）。
- `manifest-summary` 另有 `page` / `route` 行（页面清单和路由表的每一项，带 `record=`，可直接给 `getclass`）、
  `abc` 行（每个 abc 条目，加密的条目由哪个解密文件顶替）；多个包里相同的 `pack.info` 只列一次。
- 超过 2048 字节的字符串写成 `"…"… (+N bytes)`，匹配点在截断之后时带 `match at byte N` 和命中处的片段。
- 调试构建带局部变量名时，`getclass` 的函数头多一行 `; locals [起, 止): v3 name, …`。
- 包里带 `ets/sourceMaps.map`（调试构建才有）时，`manifest-summary` 多一行 `source-maps … modules=N`；`getclass` 的
  record 头多一行 `; source 原始路径`，函数头写成 `line N (source line M)`：`line N` 是编译中间文件的行（从 0 计），
  `source line` 才是源码行；`(no source line)` 的函数是构建生成的（状态变量访问器、`rerender` 等）。

限制：HarmonyOS 程序和 APK 共用同一个 daemon（调用图等分析结果驻留复用），但没有磁盘 cache（打开是毫秒级）；
父类在程序外的 `super()` / 继承方法、单例 getter 返回的对象上的调用仍是叶子；没有调用点取值约束（`method:X[arg0=…]`）和虚分派；
不支持静态 ArkTS（`modules_static.abc`）；24.x 以上版本的 abc 没有真实样本验证过；
目录里 DEX 与 HarmonyOS 文件混放时按 Android 程序处理，HarmonyOS 文件要单独给路径。

## 给 agent 用

- **截断与写文件**：只有显式要求时才截断。`--limit N` / `--max-bytes N`（或 `$ASC_LIMIT` /
  `$ASC_MAX_BYTES`）截断 stdout，完整输出写入 cache 目录下的 `out/`，最后一行给出路径和续读方式：

  ```
  # records 1-50 of 523 shown; full output in /home/u/.cache/asc/out/3f2a….txt (grep it, or rerun with --offset 50)
  ```

- **Skill**：[`skills/asc/SKILL.md`](skills/asc/SKILL.md) 是给通过 shell 工作的 agent 的
  [Agent Skill](https://agentskills.io/specification)。
- **Daemon**（Unix）：一次性命令自动交给按用户运行的 daemon，它让打开的 APK 常驻，输出（stdout、stderr、
  退出码）与不用 daemon 时逐字节相同。第一个命令自动启动它，空闲后自动退出；客户端 Ctrl-C 会取消 daemon
  中的查询。`asc daemon status|stop|start` 管理，`ASC_DAEMON=off` 关闭。
- **MCP**：`asc mcp` 是 stdio 上的常驻会话，工具有 `getclass`、`findrefs`、`callgraph`、`hierarchy`、
  `listclass`、`getmanifest`、`manifest_summary`、`resources`，传 `apk` 路径即打开，回复里的 `apk_id` 可代替路径。
  `apk` 也可以是 HarmonyOS 程序：`listclass`、`getclass`、`findrefs`、`callgraph`、`getmanifest`、`manifest_summary`
  可用，第一条回复会说明这些工具在 HarmonyOS 上接受的参数。
  `findrefs`、`listclass`、`manifest_summary`、`resources` 可用 `apks` / `dir` 一次处理多个 APK。回复控制在
  `max_bytes`（默认 16384）内，超出部分按 `spill` 写文件或分页。
  field 查询可传 `"access": "read"` / `"write"`；结果的 `field_accesses` 与 `matched` 对齐，带 context 时每个
  site 也有 `access`。

  ```json
  { "mcpServers": { "asc": { "command": "/absolute/path/to/asc", "args": ["mcp"] } } }
  ```

## 缓存与资源

解压后的 DEX、派生的搜索表和查询结果会缓存到磁盘（跨进程共享，默认开启），常驻进程（`mcp`、daemon）另有
内存 LRU。cache 只是加速，随时可删；文件带 CRC，损坏只会变成未命中。

线程、内存和磁盘都是同一套设置，`asc config` 列出每项的值、来源和在本机的实际值（`--json` 给脚本和
agent）。优先级：命令行（`--set KEY=VALUE`）> 环境变量（`$ASC_<KEY>`，名字见 `--json`）> 配置文件
`~/.config/asc/config.toml`（`$XDG_CONFIG_HOME`，或 `$ASC_CONFIG` 指定；空值表示不读）> 默认值。
`auto` 默认值按本机计算，多个常驻进程会登记并平分内存和线程。

| 设置 | 默认 |
|---|---|
| `threads`（`--threads`） | auto：逻辑 CPU；有其他忙碌进程时 4 × CPU / 忙碌进程数，至少 2 |
| `memory.max`（`--memory-mb`） | auto = 25%：(可用内存 + 常驻进程已占) × 25% / 常驻进程数；也可写 `4G` 或 `40%` |
| `memory.ceiling` | auto：物理内存的 1/16，在 2G..8G 之间（12 GB 机器 2G，96 GB 机器 6G） |
| `memory.split` | on：在常驻进程间平分 |
| `cache.enabled`（`--no-cache`）、`cache.dir`（`--cache-dir`） | on；`$XDG_CACHE_HOME/asc` 或 `~/.cache/asc` |
| `cache.max`（`--cache-max-mb`） | auto = 20%：(剩余空间 + cache 自身) × 20%，不超过 `cache.ceiling`（32G），保留 1 GiB / 5% 剩余空间 |
| `cache.tiers`、`cache.min_dex` | `dex,derived,rendered`；小于 4M 的 DEX 不写 L1 |
| `cache.write_queue`、`cache.writers` | 512M（且不超过内存预算）；auto：每 8 个 CPU 一个，1..4 |
| `cache.spill`（`--spill-mb`） | 64M：截断输出写入 `out/` 的预算 |
| `daemon.idle`、`daemon.wait` | 15m；300ms。`ASC_DAEMON=off` 关闭 daemon |

```toml
# ~/.config/asc/config.toml
threads = 8
[memory]
max = "4G"
[cache]
max = "10%"
```

`--debug` 在 stderr 上打印耗时和 cache 统计。

## 性能

抖音（360 MB、56 个 DEX）的 47 步 agent 回放：MCP 热缓存约 60 ms；836 个 APK × 8 条规则一次扫描：单个 MCP
进程热缓存约 0.5 s。完整数据、对照工具和复现方法见 [benchmark/README.md](benchmark/README.md)。

## 文档

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)：crate 划分、实现与设计取舍。
- [benchmark/README.md](benchmark/README.md)：正确性与性能评测。
- [docs/ark-abc-design.md](docs/ark-abc-design.md)：HarmonyOS / ABC 接入的设计，调用解析精度的实测。

## 致谢

asc-rs 源于 [ASC](https://github.com/MG1937/ASC)（MG1937，"R8 Compiler Optimization as a DeCompiler
Primitive"）的思路与原实现。

## 许可证

Apache-2.0，与原项目相同。
