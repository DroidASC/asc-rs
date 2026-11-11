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

APK 参数也可以是 jar、`.dex`，或作为一个程序一起分析的多个文件（一个目录，或用 `,` 连接的路径），见
[docs/query.md](docs/query.md#多个文件作为一个程序)。

完整选项见 `asc --help` 和 `asc <命令> --help`。退出码：0 成功，1 出错，2 部分 DEX（或 ABC）条目无法搜索（其余结果有效）。

输出每行一条记录，列以 ` | ` 分隔，`#` 开头的行是表头、合计和提示。类和成员的写法、带签名的重载、字段读写标记、
`KIND:VALUE` 条件和规则见 [docs/query.md](docs/query.md)。

## HarmonyOS（HAP / ABC）

同一个 `asc`、同样的命令也读 ArkCompiler 字节码（ArkTS / JS 编译出的 `.abc`），按文件内容自动识别：`.hap` / `.hsp`、
`.app`、裸 `.abc`、解包后的包目录，或放着这些文件的目录。类对应 record，方法对应函数。

```sh
asc manifest-summary entry.hap | grep -E '^(ability|callbacks|uri)'    # 导出的 ability、回调、deep link
asc getclass entry.hap entryability/EntryAbility --method EntryAbility.onCreate
asc findrefs entry.hap call '^import:@ohos:net\.http'                  # 谁调用了 http 模块
asc callgraph entry.hap --to 'call:^import:@ohos:net\.http' --depth 6  # 谁能走到 http
```

输入形态、加密的包、与 Android 的命令对照、调用图各标记的含义和限制见 [docs/harmonyos.md](docs/harmonyos.md)。

## 给 agent 用

- **Skill**：[`skills/asc/SKILL.md`](skills/asc/SKILL.md) 是给通过 shell 工作的 agent 的
  [Agent Skill](https://agentskills.io/specification)。
- **Daemon**（Unix）：一次性命令自动交给按用户运行的 daemon，打开的程序常驻，输出与不用 daemon 时逐字节相同；
  `ASC_DAEMON=off` 关闭。
- **MCP**：`asc mcp` 是 stdio 上的常驻会话。
- **截断**：只有显式要求（`--limit` / `--max-bytes`）才截断，完整输出写入文件并给出续读方式。

细节和 MCP 配置见 [docs/agents.md](docs/agents.md)。

## 缓存与设置

解压后的 DEX、派生的搜索表和查询结果会缓存到磁盘（默认开启，随时可删），常驻进程另有内存 LRU。`asc config`
列出线程、内存、磁盘每项设置的值和来源；全部设置和默认值见 [docs/configuration.md](docs/configuration.md)。
`--debug` 在 stderr 上打印耗时和 cache 统计。

## 性能

抖音（360 MB、56 个 DEX）的 47 步 agent 回放：MCP 热缓存约 60 ms；836 个 APK × 8 条规则一次扫描：单个 MCP
进程热缓存约 0.5 s。完整数据、对照工具和复现方法见 [benchmark/README.md](benchmark/README.md)。

## 文档

- [docs/query.md](docs/query.md)：输出格式、查询写法、多个文件作为一个程序。
- [docs/harmonyos.md](docs/harmonyos.md)：HarmonyOS（HAP / ABC）的用法。
- [docs/agents.md](docs/agents.md)：截断与写文件、daemon、MCP。
- [docs/configuration.md](docs/configuration.md)：缓存、线程、内存设置。
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)：crate 划分、实现与设计取舍。
- [docs/ark-abc-design.md](docs/ark-abc-design.md)：HarmonyOS / ABC 接入的设计，调用解析精度的实测。
- [benchmark/README.md](benchmark/README.md)：正确性与性能评测。

## 致谢

asc-rs 源于 [ASC](https://github.com/MG1937/ASC)（MG1937，"R8 Compiler Optimization as a DeCompiler
Primitive"）的思路与原实现。

## 许可证

Apache-2.0，与原项目相同。
