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
- **MCP**：`droidasc mcp` 是 stdio 上的常驻会话，工具有 `open_apk`、`close_apk`、`getclass`、`findrefs`、
  `callgraph`、`hierarchy`、`listclass`、`getmanifest`、`manifest_summary`、`resources`。
  `findrefs`、`listclass`、`manifest_summary`、`resources` 可用 `apks` / `dir` 一次处理多个 APK。回复控制在
  `max_bytes`（默认 16384）内，超出部分按 `spill` 写文件或分页。

  ```json
  { "mcpServers": { "droidasc": { "command": "/absolute/path/to/droidasc", "args": ["mcp"] } } }
  ```

## 缓存与资源

解压后的 DEX、派生的搜索表和查询结果会缓存到磁盘（跨进程共享，默认开启），常驻进程（`mcp`、daemon）另有
内存 LRU。cache 只是加速，随时可删；文件带 CRC，损坏只会变成未命中。预算默认按机器自动确定，多个常驻进程
会登记并平分内存和线程。

| 选项 / 环境变量 | 作用 |
|---|---|
| `--no-cache` | 不读写磁盘 cache |
| `--cache-dir DIR`、`$DROIDASC_CACHE_DIR` | cache 位置（默认 `$XDG_CACHE_HOME/droidasc` 或 `~/.cache/droidasc`） |
| `--cache-max-mb MIB`、`$DROIDASC_CACHE_MAX_MB` | 磁盘预算（默认：cache 自身加文件系统剩余空间的 20%，最多 32 GiB，并保留至少 1 GiB / 5% 剩余空间） |
| `--memory-mb MIB` | `mcp` / daemon 的内存预算（默认：可用内存的四分之一，最多 2 GiB，按进程平分） |
| `--threads N` | worker 线程数（默认：逻辑 CPU，与其他忙碌的常驻进程平分） |
| `DROIDASC_DAEMON`、`DROIDASC_DAEMON_WAIT_MS`、`DROIDASC_DAEMON_IDLE` | 关闭 daemon；首次等待 daemon 就绪的毫秒数（300）；空闲退出秒数（900） |
| `--debug` | stderr 上打印耗时和 cache 统计 |

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
