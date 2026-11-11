# 反编译后端接入设计

状态：提案（2026-11-10）。配套文档：[rebuild-slice.md](rebuild-slice.md)（给后端喂的闭包切片）。

目标：`asc` 能把一个类交给可替换的反编译后端（dexdec、JEB、jadx …）得到 Java / Kotlin 源码，不在进程内
链接任何后端，并利用 asc-rebuild 的切片让整包加载慢的后端提速。

## 1. 结论

- **后端是子进程，走 stdio**，协议是按行分隔的 JSON-RPC 2.0，传输层与生命周期照搬 MCP（`initialize` /
  `initialized`、`notifications/cancelled`、`notifications/progress`、日志走 stderr）；方法是自己的
  （`program/open`、`decompile/classes`、`program/close`），不用 `tools/call`：asc 要的是有类型的契约
  （能力、逐方法状态、缓存键），自由参数的 tool 给不了。
- **不监听端口、不做 FFI**。崩溃、栈溢出、OOM 都只伤一个子进程（dexdec 在 ART `159-app-image-fields` 上
  栈溢出 abort，正是这种情况）。
- **后端进程归 asc daemon / `asc mcp` 会话所有**，按需拉起、空闲退出、崩溃重启。一次性 CLI 经现有
  daemon 转发；`ASC_DAEMON=off` 时临时拉起，能用但慢（JEB 冷启动以秒计）。
- **配置写在 `config.toml` 的 `[decompilers.<name>]`**，形如 MCP 的 `command` / `args` / `env`。
- **输入形态由后端声明**：dexdec 吃原始程序（它本来就按需加载），JEB / jadx 吃闭包切片。

## 2. 依据（2026-11-10 实测）

MT2.26.8（5 个 DEX，34 MB），反编译 `bin.mt.json.JSONObject`：

以下单类切片数据来自默认包含 `$` 附属类之前的实现；现有 `getclass --dump-dex`
已经包含目标及同一 DEX 内的 `$` 附属类，这些历史数据不代表新默认行为。

| 路径 | 耗时 |
|---|---|
| `asc getclass --dump-dex`（单类切片） | 0.024 s |
| dexdec，整包 | 0.448 s |
| dexdec，切片 | 0.383 s |
| jadx 1.5.6 `--single-class`，整包 | 6.13 s |
| jadx，切片 | 0.64 s |

- 整包加载慢的后端收益大（jadx 约 10×）；dexdec 几乎无收益，所以 dexdec 不走切片。
- 单类切片有质量代价：两个后端都丢 `@Override`；dexdec 多出冗余强转（`((PluginView) x).requireId()`）；
  jadx 不再内联匿名类（少约 40 行）、丢 `throws` 的 import、反混淆别名与整包不同（`C8652` → `ۢۤܺ`，
  jadx 按全局文件名冲突改名）。前三项由闭包切片解决；最后一项靠关掉后端自带的反混淆改名，名字就与输入形态
  无关（§7）。
- 上一轮差分测试（598 个 ART 用例，重编译后比对运行结果）：dexdec 549 通过、jadx 527，两者的错误
  互不重叠。多后端并存有实际价值：一个后端失败或可疑时可以换另一个。

## 3. 结构

```
asc CLI ──(现有 daemon 转发)──▶ asc daemon / asc mcp
                                  │  asc-decompile：配置、进程池、JSON-RPC 客户端、L3 结果缓存
                                  │  asc-engine：类定位、ClassGraph、切片（asc-rebuild）
                                  ├─stdio─▶ dexdec serve --stdio
                                  ├─stdio─▶ java -jar jeb-server.jar --stdio
                                  └─stdio─▶ jadx-worker
```

新 crate `asc-decompile`，依赖 `asc-engine`、`asc-cache`；CLI / MCP 只调用它。

## 4. 配置

```toml
# ~/.config/asc/config.toml
[decompile]
default = "dexdec"            # 不写 --decompiler 时用哪个
fallback = ["jadx"]           # 默认后端失败时依次尝试；空 = 不回退

[decompilers.dexdec]
command = "dexdec"
args = ["serve", "--stdio"]

[decompilers.jeb]
command = "java"
args = ["-Xmx6g", "-jar", "/opt/jeb-server/jeb-server.jar", "--stdio"]
env = { JEB_HOME = "/opt/jeb" }
instances = 1                  # 进程数；每个进程同时处理的请求数由后端在 initialize 里声明
idle = "10m"                   # 空闲多久退出
timeout = "60s"                # 单个请求的超时
startup_timeout = "60s"        # 等 initialize 的超时
options = { finally_rebuilder = true, deobfuscators = false }   # 原样透传，进入缓存键

[decompilers.jadx]
command = "jadx-worker"
instances = 2
```

| 键 | 类型 | 默认 | 说明 |
|---|---|---|---|
| `command` | 字符串 | 必填 | 可执行文件；不含 `/` 时按 `PATH` 查找 |
| `args` | 字符串数组 | `[]` | |
| `env` | 表 | `{}` | 在继承的环境上追加 |
| `cwd` | 路径 | cache 目录下的 `decompilers/<name>/` | |
| `instances` | 整数 | 1 | |
| `idle` / `timeout` / `startup_timeout` | 时长 | 10m / 60s / 30s | |
| `options` | 表 | `{}` | 不解释，放进 `initialize` 的 `options` |
| `enabled` | 布尔 | true | |

实现注意：`asc_engine::config` 把整个文件展开成标量键并逐个校验（`config.rs` 的 `flatten`），
`[decompilers.*]` 必须在展开前摘出来单独解析，否则会被当成未知键报错。`asc config` 另起一节列出后端：
名字、命令、来源，以及最近一次 `initialize` 报告的版本。

## 5. 传输与生命周期

- 每条消息一行 UTF-8 JSON，以 `\n` 结尾，消息内不出现裸换行（源码里的换行在 JSON 字符串里转义）。
- **后端的 stdout 只能输出协议消息**，日志一律写 stderr。asc 把 stderr 收进环形缓冲（每个进程最近
  64 KiB），在 `asc decompile --debug` 和错误信息里给出。JVM 后端在 `--stdio` 模式下启动时，要先把
  `System.out` 重定向到 `System.err`：JEB 引擎和 jadx 的日志默认写 stdout，会弄乱协议流。
- 单条消息上限 64 MiB，超过就视为协议错误，杀掉进程。
- 启动：asc 发 `initialize`，后端回能力；asc 再发 `initialized` 通知，之后才发请求。
- 关闭：asc 发 `shutdown` 请求，等回复后关闭 stdin；2 s 内不退出就 SIGTERM，再等 2 s 就 SIGKILL。
- 崩溃：进程意外退出时，在途请求一律失败（`reason = "backend exited: <状态>，<stderr 末尾>"`）。
  重启带退避（1 s、2 s、4 s … 最长 60 s），连续 5 次启动失败后，本会话内停用该后端。
- 空闲：最后一个请求结束后过 `idle` 就关闭。程序会话（§6.2）随进程一起消失，asc 记得重新打开。

## 6. 方法

记号：`→` 是 asc 发出的，`←` 是后端发出的。字段名用 camelCase。

### 6.1 `initialize`

```json
→ {"jsonrpc":"2.0","id":1,"method":"initialize","params":{
     "protocolVersion":1,
     "client":{"name":"asc","version":"0.1.0"},
     "options":{"finally_rebuilder":true}}}
← {"jsonrpc":"2.0","id":1,"result":{
     "protocolVersion":1,
     "backend":{"name":"jeb","version":"5.20.0"},
     "optionsHash":"9f2c…",
     "inputs":["slice"],
     "languages":["java"],
     "mappings":true,
     "methodStatus":true,
     "maxConcurrency":1,
     "platform":"android-35"}}
```

| 字段 | 含义 |
|---|---|
| `protocolVersion` | 后端支持的最高协议版本，不大于 asc 发来的；asc 不认识这个版本就停用该后端 |
| `optionsHash` | 后端对“实际生效的选项 + 影响输出的配置”求的哈希，进入缓存键（§8）；由后端计算，因为只有后端知道默认值 |
| `inputs` | `archive`（原始 APK / DEX 路径）和 / 或 `slice`（闭包切片）；两个都有时 asc 优先用 `archive` |
| `languages` | `java`、`kotlin` |
| `mappings` | 是否接受 `program/open` 里的命名映射 |
| `methodStatus` | 能否逐方法报告失败；不能时 asc 只记整个类的状态 |
| `maxConcurrency` | 一个进程能同时处理多少个 `decompile/classes`；超出的请求由 asc 排队 |
| `platform` | 后端自带的平台 classpath，只作提示 |

### 6.2 `program/open` / `program/close`

```json
→ {"id":2,"method":"program/open","params":{
     "input":{"kind":"slice","files":["/home/u/.cache/asc/slices/3a/3a7f….dex"],
              "manifest":{"targets":["Lbin/mt/json/JSONObject;"],
                          "attached":["Lbin/mt/json/JSONObject$Member;"],
                          "shells":["Lbin/mt/json/JSONValue;"]}},
     "mappings":{"classes":{"Ll/ۢۤܺ;":"Lbin/mt/json/LinkedTable;"},
                 "fields":{"Lbin/mt/json/JSONObject;->a:I":"size",
                           "Lbin/mt/json/JSONObject;->b:Ll/ۢۤܺ;":"table"},
                 "methods":{"Lbin/mt/json/JSONObject;->a(Ll/ۢۤܺ;I)V":"put"}}}}
← {"id":2,"result":{"programId":"p1"}}

→ {"id":9,"method":"program/close","params":{"programId":"p1"}}
← {"id":9,"result":{}}
```

- `input.kind = "archive"`：`files` 是原始程序（APK / jar / DEX，可以有多个，作为一个程序分析）。
- `input.kind = "slice"`：`files` 是 asc 写在 cache 目录下、按内容寻址的切片，后端只读不改；`manifest`
  标出哪些类是请求目标、哪些是附属类、哪些是壳类（含义见 rebuild-slice.md）。后端不输出壳类，也不该
  把壳类里合成的方法体当真。
- `mappings` 用 asc 的成员写法（与 `findrefs` 一致）。后端把它当作用户改名：输出时用新名字，引用处一起改。
  键一律是 DEX 里的名字（混淆后的），包括成员签名里的类型：上例 `b` 字段的类型写 `Ll/ۢۤܺ;` 而不是改名后的类；
  值是要显示的名字。`classes` 的值是完整描述符，包名可以变（mapping.txt 记录的是原始全名），内部类的值是完整
  的二进制名（`Lpkg/Outer$Inner;`）；类换了包时，结果的 `path` 跟着新名字走。`fields` / `methods` 的值是简单名，
  构造器（`<init>` / `<clinit>`）不出现。没有映射时三个表都为空。
- 切片会话的生命周期由 asc 管：一次请求开一个，用完就关。archive 会话按程序常驻，被进程池的 LRU 淘汰
  时才关。后端必须真正释放会话（JEB 是 `unloadProject`），否则项目越积越多。

### 6.3 `decompile/classes`

```json
→ {"id":3,"method":"decompile/classes","params":{
     "programId":"p1","classes":["Lbin/mt/json/JSONObject;"],
     "language":"java","nested":true,"progressToken":"t3"}}
← {"method":"notifications/progress","params":{"progressToken":"t3","progress":0,"total":1}}
← {"id":3,"result":{"units":[{
     "class":"Lbin/mt/json/JSONObject;",
     "status":"partial",
     "path":"bin/mt/json/JSONObject.java",
     "text":"package bin.mt.json;\n…",
     "methods":[{"signature":"toString()Ljava/lang/String;","status":"failed",
                 "reason":"region recovery: irreducible loop"}],
     "diagnostics":[{"severity":"warning","message":"…","method":"…"}],
     "lines":[{"line":120,"method":"put(Ljava/lang/String;I)Lbin/mt/json/JSONObject;","pc":4}]}]}}
```

- `status`：`ok` | `partial`（有方法失败，`methods` 里列出） | `failed`（没有 `text`，`reason` 必填）。
  一个类失败不影响同批其它类，所以协议层只用 `result` 报告，不返回 JSON-RPC 错误。
- 不允许把失败的方法“伪装”成成功：后端自己输出的失败桩（如 dexdec 的
  `throw new UnsupportedOperationException("Method could not be decompiled …")`）必须同时在 `methods` 里报告。
- `lines` 可选：源码行到（方法，dex pc）的对应，供 `--method` 截取和跳转。没有时 asc 按方法签名匹配源码。
- `nested = true`：内部类、匿名类并入外部类的源码，这是 jadx / dexdec 的默认行为。

### 6.4 取消、进度与错误

- 取消：`{"method":"notifications/cancelled","params":{"requestId":3}}`。后端尽力中止，然后回 `-32800`；
  如果已经做完，也可以照常回结果。asc 在客户端断开（Ctrl-C）或超时时发出取消。超时后 5 s 还没回，
  asc 就杀掉进程。
- 进度：可选，asc 只转发给 MCP 客户端。
- 错误码：`-32700` / `-32600` / `-32601` / `-32602` 沿用 JSON-RPC；`-32800` 表示已取消；后端自定义的错误从
  `-33000` 起：`-33001` 找不到程序会话，`-33002` 不支持这种输入，`-33003` 许可证或功能不可用（例如 JEB
  不是 Pro 版）。

## 7. 命名

- 名字一律以 asc 为准，而 asc 唯一的名字来源是用户提供的映射文件，主要是 R8 / ProGuard 的 `mapping.txt`
  （`NameMappings::from_proguard_file`；命令行 `--mapping` 与配置项另行接入）。asc 面向 agent 做分析，不提供改名
  命令、不持久化改名，也不自动生成反混淆别名；没有映射文件时名字保持 DEX 原样。理由是同一个类在不同切片、
  不同后端里必须叫同一个名字，agent 才能交叉引用；jadx 在切片上自动生成的别名和整包下就不一样。
- 映射只作用于反编译出的源码。`findrefs`、smali 等查询输出始终用 DEX 原来的描述符，agent 拿源码里的名字回查时
  需要自己对照（或不带映射再反编译一次）。
- mapping.txt 的成员签名用的是原始类型名，asc 解析时按类映射逆向翻译成 DEX 里的类型（R8 给了
  `residualsignature` 时直接用它，参数被删、类型被改窄的方法只能靠它对上）。R8 内联栈只取最外层帧，带别的类
  限定名的帧（内联进来或被搬过来的方法）不改名；同一个 DEX 名字映射两次时保留第一个并给出警告。
- 后端自带的反混淆改名要关掉（jadx 不开 `--deobf`，并把 `--rename-flags` 设为只保留 `valid`；JEB 关掉自动改名），只保留
  “非法标识符转义”。
- 后端不支持 `mappings` 时，asc 不做源码层的文本替换（容易误伤），而是在结果头部注明“名字未统一”。

## 8. 结果缓存

结果写入 L3，键为 `(ApkKey, 输入指纹, backend.name, backend.version, optionsHash, mappings 哈希, language, nested)`。

- mappings 哈希：`NameMappings::hash`，对 `program/open` 实际下发的（按请求裁剪后的）条目计算，与插入顺序无关；
  编码改动时提升其中的版本标签（当前 `asc-name-mappings/2`）。

- 输入指纹：切片用切片的 SHA-256。切片输出是规范化的（id 表排序固定），所以同一个类闭包每次得到相同的哈希。
  archive 用 `ApkKey` 加类描述符。
- `status = failed` 的结果也缓存，但只保留 10 分钟（失败往往和超时、资源有关）。

## 9. 选后端与回退

- `asc decompile <apk> <class> [--decompiler NAME] [--language java|kotlin] [--method M]`，MCP 工具
  `decompile` 参数相同。不指定时用 `decompile.default`。
- 回退：默认后端整类失败（`failed`、超时、进程崩溃）时，按 `fallback` 顺序重试，结果头部注明实际用了哪个
  后端。`partial` 不回退，只在 `methods` 里列出失败的方法；需要对照时用 `--decompiler` 显式指定。
- 都失败时回到现有的 smali 输出，并给出提示。
- 切片构建失败时（见 rebuild-slice.md §7），只接受 `slice` 的后端退回默认目标及 `$` 附属类切片并注明；默认切片也构建不了，
  就换一个接受 `archive` 的后端。

## 10. 并发

- 每个后端一个进程池，进程数是 `instances`，每个进程同时最多处理 `maxConcurrency` 个请求。排队按先来
  先服务，MCP 交互请求优先于批量请求。
- JEB 的引擎能否在多线程下安全反编译同一个单元，目前未验证，所以 jeb-server 先声明 `maxConcurrency = 1`，
  靠多开进程取得并行（代价是内存）。
- 所有后端进程的常驻内存都计入 daemon 的内存预算（`SharedCache::fit_resident_bytes`）；超出时先关闭空闲
  时间最长的进程。

## 11. 安全

- 只用 stdio，不监听端口。后端以当前用户身份运行，没有额外权限。
- 切片和 cache 目录同权限（只有当前用户可读写）。传给后端的只有路径，不经过 shell 拼接。
- 后端输出属于不可信数据：asc 只解析 JSON，路径字段（`path`）只用来显示，不用来写文件；`asc decompile -o`
  的输出路径由 asc 自己根据描述符生成。

## 12. 各后端的工作

### dexdec

- 新增 `dexdec serve --stdio`：直接复用 `Decompiler`（`open` / `generate_classes`）。
- 声明 `inputs = ["archive"]`。会话期间常驻 `DexFileReader`，各类按需加载。
- 失败的方法照常输出桩，同时写进 `methods`；CLI 现在把这种桩计为成功，这一点需要一起修正。
- `optionsHash` 由 `DecompileOptions` 加二进制版本计算。

### jeb-server（`../jeb-cli`）

- 新增 `--stdio` 模式和一个新的分发层，内部复用现有 handler 的逻辑。启动时把 `System.out` 重定向到 stderr。
- `program/open` 对应 `createProject` + `processArtifact`，`program/close` 对应 `unloadProject`；声明
  `inputs = ["slice"]`、`maxConcurrency = 1`。
- 把 `applyFastMode` 里写死的属性改成由 `options` 控制，默认值放进 `optionsHash`。现在它会关掉
  FinallyRebuilder、调用目标解析等功能，对输出质量影响明显；切片已经把规模压小，可以先默认打开再测。
- `mappings` 用 `RenameHandler` 已有的改名逻辑批量应用。逐方法状态用 `decompileMethod` 的返回值收集。
- 现有 TCP / Unix socket 模式的两个问题，如果继续保留这两种模式就得修：
  - Unix 模式里，对 Unix 通道调用 `SocketChannel.socket()` 会抛 `UnsupportedOperationException`
    （JDK 21 实测），accept 循环接不住，第一个客户端连上服务就挂了。
  - TCP 绑定所有网卡、没有认证，又开放了 `exec`（Jython），同网段的人都能在这台机器上执行任意代码。
    至少要只绑定 `127.0.0.1` 并加 token。

### jadx

- 小型 Java worker：用 `JadxDecompiler`，每个会话一个实例，常驻 JVM。
- 关掉自动改名（§7），`mappings` 走 jadx 的用户改名接口。逐方法状态从 `MethodNode` 的错误或警告标记
  （`contains(AFlag.INCONSISTENT_CODE)`、JADX WARN 注释）里收集。
- 声明 `inputs = ["slice"]`；`maxConcurrency` 视 `JadxDecompiler` 的线程安全性而定，先设为 1。

## 13. 分期

| 期 | 内容 | 验收 |
|---|---|---|
| P1 | `asc-decompile`：配置解析、进程池、JSON-RPC 客户端；`dexdec serve --stdio`；`asc decompile` 和 MCP 工具；L3 缓存 | daemon 常驻时，第二次反编译同一个类直接命中缓存；杀掉 dexdec 后自动重启 |
| P2 | asc-rebuild 闭包切片（rebuild-slice.md 的 S1–S2）；jadx worker | 在 MT2 等 3 个样本上，jadx 切片与整包输出的差异行数降到单类切片的 1/5 以下，耗时不超过整包的 1/5 |
| P3 | jeb-server `--stdio`；映射下发；回退链 | JEB 与 dexdec 输出的名字一致 |
| P4 | 差分测试接入 CI：ART 语料，后端 × 输入形态 | 每个后端的通过率不低于当前基线（dexdec 549 / 598，jadx 527 / 598） |

## 14. 待定

- Kotlin 输出：dexdec 原生支持；JEB、jadx 不支持，`languages` 里不声明即可。要不要为它们做 Kotlin 回退？
- 切片里壳类的成员范围（rebuild-slice.md §4）对 JEB 质量的影响，需要等 P3 实测。
- `lines` 的精度：JEB 有坐标 API，dexdec 有源码位置；jadx 只有行号。要不要把 `--method` 截取统一建在 `lines` 上？
- 远程后端（不在本机）：先不支持；以后可以用 `ssh host cmd` 当作 `command`，切片改为内联 base64。
