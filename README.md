[English](README.en.md) | 简体中文

# asc-rs

把 APK 当作只读数据库：直接在压缩包上定位类、搜索交叉引用、反汇编、解码 manifest 和资源，毫秒级，
不需要预处理或全局索引。面向人和 agent：CLI 为主（Unix 上有透明的预热 daemon），也提供 MCP 服务器。
可执行文件叫 `droidasc`。

## 构建

```sh
cargo build --release        # -> target/release/droidasc（需要 Rust 1.85+）
cargo test --workspace
```

## 快速上手

```sh
droidasc manifest-summary app.apk | grep exported=true          # 暴露面
droidasc findrefs app.apk string 'https?://' --limit 50         # 谁用了这个字符串
droidasc findrefs app.apk method 'android.webkit.WebView->loadUrl' --context 3
droidasc getclass app.apk com.poc.Main --method onCreate        # 读 smali
droidasc callgraph app.apk com.poc.Main onCreate --depth 3      # 调用者树
droidasc findrefs app.apk rules 'string:http://' 'method:java.lang.Runtime->exec'
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

完整选项见 `droidasc --help` 和 `droidasc <命令> --help`。退出码：0 成功，1 出错，2 部分 DEX 条目无法搜索（其余结果有效）。

## 输出与查询写法

每行一条记录，列以 ` | ` 分隔，`#` 开头的行是表头、合计和提示，便于 grep / cut。`findrefs` 的一行是
`dex | 方法（完整签名） | 匹配内容`：

```
classes.dex | LWV/qE;-><clinit>()V | "http://", "http://www."
classes4.dex | Lcom/…/ConversationView;->onRestoreInstanceState(Landroid/os/Parcelable;)V | Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
```

- 类名可写 `com.a.B` 或 `Lcom/a/B;`。
- 成员在 CLI、MCP 和规则里写法统一：`Lcom/a/B;->name(I)V`、`com.a.B->name`、`com.a.B#name`、`com.a.B.name`、
  `B.name`（不带包名的类匹配任意包）。只写名字是 regex / 子串，`=name` 精确匹配。
- 带签名时只命中该重载：`run(I)V`、只写参数的 `run(I)`、Java 写法 `run(int, String)`，字段 `f:I`。
- 条件写作 `KIND:VALUE`（`string:`、`literal:`、`type:`、`method:`、`field:`），`rules` 中可用 `&` 组合，
  也可以用 `--file` 每行一条。
- 查不到时 stderr 会给出 `hint:`：搜了多少 DEX、大小写、APK 未定义的 framework 类、最接近的类或已有的方法等。

## 给 agent 用

- **截断与写文件**：只有显式要求时才截断。`--limit N` / `--max-bytes N`（或 `$DROIDASC_LIMIT` /
  `$DROIDASC_MAX_BYTES`）截断 stdout，完整输出写入 cache 目录下的 `out/`，最后一行给出路径和续读方式：

  ```
  # records 1-50 of 523 shown; full output in /home/u/.cache/droidasc/out/3f2a….txt (grep it, or rerun with --offset 50)
  ```

- **Skill**：[`skills/droidasc/SKILL.md`](skills/droidasc/SKILL.md) 是给通过 shell 工作的 agent 的
  [Agent Skill](https://agentskills.io/specification)。
- **Daemon**（Unix）：一次性命令自动交给按用户运行的 daemon，它让打开的 APK 常驻，输出（stdout、stderr、
  退出码）与不用 daemon 时逐字节相同。第一个命令自动启动它，空闲后自动退出；客户端 Ctrl-C 会取消 daemon
  中的查询。`droidasc daemon status|stop|start` 管理，`DROIDASC_DAEMON=off` 关闭。
- **MCP**：`droidasc mcp` 是 stdio 上的常驻会话，工具有 `getclass`、`findrefs`、`callgraph`、`hierarchy`、
  `listclass`、`getmanifest`、`manifest_summary`、`resources`，传 `apk` 路径即打开，回复里的 `apk_id` 可代替路径。
  `findrefs`、`listclass`、`manifest_summary`、`resources` 可用 `apks` / `dir` 一次处理多个 APK。回复控制在
  `max_bytes`（默认 16384）内，超出部分按 `spill` 写文件或分页。

  ```json
  { "mcpServers": { "droidasc": { "command": "/absolute/path/to/droidasc", "args": ["mcp"] } } }
  ```

## 缓存与资源

解压后的 DEX、派生的搜索表和查询结果会缓存到磁盘（跨进程共享，默认开启），常驻进程（`mcp`、daemon）另有
内存 LRU。cache 只是加速，随时可删；文件带 CRC，损坏只会变成未命中。

线程、内存和磁盘都是同一套设置，`droidasc config` 列出每项的值、来源和在本机的实际值（`--json` 给脚本和
agent）。优先级：命令行（`--set KEY=VALUE`）> 环境变量（`$DROIDASC_<KEY>`，名字见 `--json`）> 配置文件
`~/.config/droidasc/config.toml`（`$XDG_CONFIG_HOME`，或 `$DROIDASC_CONFIG` 指定；空值表示不读）> 默认值。
`auto` 默认值按本机计算，多个常驻进程会登记并平分内存和线程。

| 设置 | 默认 |
|---|---|
| `threads`（`--threads`） | auto：逻辑 CPU；有其他忙碌进程时 4 × CPU / 忙碌进程数，至少 2 |
| `memory.max`（`--memory-mb`） | auto = 25%：(可用内存 + 常驻进程已占) × 25% / 常驻进程数；也可写 `4G` 或 `40%` |
| `memory.ceiling` | auto：物理内存的 1/16，在 2G..8G 之间（12 GB 机器 2G，96 GB 机器 6G） |
| `memory.split` | on：在常驻进程间平分 |
| `cache.enabled`（`--no-cache`）、`cache.dir`（`--cache-dir`） | on；`$XDG_CACHE_HOME/droidasc` 或 `~/.cache/droidasc` |
| `cache.max`（`--cache-max-mb`） | auto = 20%：(剩余空间 + cache 自身) × 20%，不超过 `cache.ceiling`（32G），保留 1 GiB / 5% 剩余空间 |
| `cache.tiers`、`cache.min_dex` | `dex,derived,rendered`；小于 4M 的 DEX 不写 L1 |
| `cache.write_queue`、`cache.writers` | 512M（且不超过内存预算）；auto：每 8 个 CPU 一个，1..4 |
| `cache.spill`（`--spill-mb`） | 64M：截断输出写入 `out/` 的预算 |
| `daemon.idle`、`daemon.wait` | 15m；300ms。`DROIDASC_DAEMON=off` 关闭 daemon |

```toml
# ~/.config/droidasc/config.toml
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

## 致谢

asc-rs 源于 [ASC](https://github.com/MG1937/ASC)（MG1937，"R8 Compiler Optimization as a DeCompiler
Primitive"）的思路与原实现。

## 许可证

Apache-2.0，与原项目相同。
