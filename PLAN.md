# asc-rs 改进计划

更新：2026-10-23。最初的基线是 main `3a1e5cd`；A–D 四条线及之后的工作都已合入 main（见第 6 节）。

## 0. 目标场景

两个场景都由 agent（例如 Claude 挂一个 goal）通过 `droidasc mcp` 驱动，不做单独的批处理子命令。

| 场景 | 典型任务 | 主要成本 |
|---|---|---|
| **S1 单 APK 精细化分析** | 从入口（导出组件、字符串、API）出发，沿调用链读代码、确认数据流 | agent 的**调用次数**（每次调用就是一轮 LLM），单次延迟已经只有几毫秒 |
| **S2 多 APK 并行审计** | 几百个 APK（合计约 500 MB）的漏洞暴露面统计和审计 | 调用次数、**上下文体积**、多个子 agent 进程的**内存叠加**、跨会话的重复计算 |

## 1. 现状（已在 main）

| 能力 | 状态 |
|---|---|
| CLI：getclass、disassemble（`--method`）、listclass/classes、getmanifest/manifest、findrefs（string 正则或 `--literal`、type、method、field、extends、impl） | 与 Python 上游 9216fe2 逐行一致 |
| `droidasc mcp`：常驻会话，多个 APK 共用一份缓存，工具调用并发执行，panic 时只让该次调用报错 | 已完成 |
| 内存缓存：自动预算（可用内存的 25%，最多 2 GiB）；索引表计入预算；解压出的 DEX 写盘后改为映射缓存文件 | 已完成 |
| 磁盘缓存：自动预算（剩余空间的 20%，最多 4 GiB，保留 max(1 GiB, 磁盘的 5%)），空间紧张时淘汰并拒绝新写入；`--cache-max-mb`、`--memory-mb` | 已完成 |
| GUI 类索引：Douyin 上从 287 ms / +208 MiB 降到 67 ms / +22 MiB | 已完成；2026-10 GUI 整体删除（没人用，agent 走 CLI / MCP） |
| manifest | 只输出解码后的原始 XML；`@0x7f…` 引用无法解析 |
| resources.arsc、res/xml | **不支持** |

### 基准数据（本机：16 线程，12 GB 内存，Linux）

> 后续各轮的完整数字与复现方法见 [benchmark/README.md](benchmark/README.md)。

**S1：Douyin 40.7.0**（56 个 DEX，55 万个类），回放 dexsql-release agent-audit 的 17 个目标（47 步）：

| | asc-rs mcp | asc-rs CLI，磁盘缓存命中 | dexsql 0.1.1 | rasc |
|---|---:|---:|---:|---:|
| 打开 APK | 75 ms | — | 589 ms | — |
| 整轮会话 | **208 ms** | 336 ms | 1112 ms | 3819 ms |
| 每个目标几何平均 | 4.7 ms | 18 ms | 22.6 ms | 189 ms |
| 内存 | 峰值 647 MB（匿名内存约 110 MB） | — | 常驻约 1.13 GB | — |

**S2：100 个 APK（514 MB），8 条审计规则，共 800 次查询：**

| 跑法 | 耗时 |
|---|---:|
| CLI，16 个进程，每个进程 1 线程 | 396 ms |
| CLI，开磁盘缓存，第一次 | 939 ms（写盘拖慢了 2.4 倍） |
| CLI，开磁盘缓存，再次运行 | 267 ms |
| 一个 MCP 进程，800 个调用并发 | **143–174 ms**，峰值 475 MB |

评测脚本：`benchmark/agent-audit/replay_mcp.py`，通过 `HARNESS` 环境变量指向 dexsql-release 的 harness 目录。

## 2. 优先级

| 优先级 | 项目 | S1 | S2 | 工作线 |
|---|---|:-:|:-:|:-:|
| **P0** | resources.arsc + res/xml 解码 | ✓ | ✓ | A |
| **P0** | 结构化 manifest 摘要（暴露面） | ✓ | ✓ | A |
| **P0** | findrefs 返回上下文（命中位置的 smali） | ✓ | ✓ | B |
| **P0** | 调用图 / 多层调用者和被调用者 | ✓ | | B |
| **P0** | MCP 一次查多个 APK，结果按 APK 汇总，控制上下文体积 | | ✓ | C |
| **P1** | 磁盘缓存分层（L2 派生索引可直接映射、跨进程共享，L3 渲染结果） | ✓ | ✓ | D |
| **P1** | 内存预算考虑同时运行的多个 MCP 进程 | | ✓ | D |
| **P1** | 组合条件查询（同一方法内同时满足 A 和 B） | ✓ | ✓ | B（后续） |
| **P1** | 继承关系递归查询（所有子类、实现类）+ 方法重写 | ✓ | | B（后续） |
| P2 | 打开 APK 时后台预建索引 | ✓ | | D |
| P2 | 按 DEX 的 CRC32 和大小跨 APK 去重、复用结果 | | ✓ | C/D |
| P2 | 多条规则一次扫描 | | ✓ | B |
| — | Java 反编译输出 | | | 不做（radguard 错误太多） |

## 3. 工作线

四条线在独立的 worktree 里并行推进，改动位置互不重叠。C 依赖 A 和 B 的接口：先做多 APK 的 findrefs 和汇总，等 A、B 完成后再接入它们的新能力。

### A. 资源与 manifest（新 crate `asc-arsc`，加上 asc-axml、engine 的 manifest 部分）

**参照与对比对象**
- 格式以 AOSP `frameworks/base/libs/androidfw` 为准（`ResourceTypes.h`、`LoadedArsc.cpp`；选配置的规则看 `ResTable_config::isBetterThan`/`match`）。
- 应对畸形和混淆资源时参考 apktool `ARSCDecoder`；输出格式参考 androguard `ARSCParser`。
- 逐项对比的标准答案：`aapt2 dump resources`（本机 `~/Android/Sdk/build-tools/37.0.0/aapt2`）；第二参照是 `apk-info-axml`（只作为开发期依赖，只比默认配置）。
- 不直接依赖现成的 crate。原因：它们大多一次性把整张表解析成独立分配的结构、只支持默认配置，或已不维护、依赖太重；asc-rs 需要和 asc-dex、asc-axml 一致的"不复制数据、按需解析、全部边界检查"。

**格式范围**
- 表头；全局字符串池（UTF-8/UTF-16，复用 asc-axml 的字符串池）。
- package（包 ID、包名、类型字符串池、key 字符串池）、TypeSpec、Type。
- 条目编码：u32 偏移表、稀疏表（`FLAG_SPARSE`）、16 位偏移（`FLAG_OFFSET16`）、紧凑条目（`ENTRY_FLAG_COMPACT`）。
- 复合条目（style/array/plurals/attr）、Library chunk（动态包 ID）、Overlayable、StagedAlias。
- 解析方式：先只建 package、类型、条目偏移的索引，查询时才解码值。

**接口**
- `name(id)` → `pkg:type/name`；`lookup(type, name)` → id。
- `resolve(id, config)`：顺着引用链取值，限制最大深度、检测循环。
- `values(id)`：列出所有配置下的取值。审计时，配置之间取值不一致要全部列出，例如 `exported="@bool/x"` 在 `values-v31` 中可能不同。
- 遍历全部字符串资源，供搜索用。

**接入**
- manifest 和 res/xml 解码时解析 `@0x7f…` 引用，应用自定义的属性从 arsc 取名字。
- 新增读取 res/xml 二进制 XML（network_security_config、FileProvider 路径配置、shortcuts 等）。
- 代码里 `const` 指令中的 `0x7f…` 对应回资源名（getclass 输出时加注释）。
- **结构化 manifest 摘要**：
  - 导出组件：显式 `exported`，以及 targetSdk < 31 时由 intent-filter 带来的隐式导出；
  - 权限和保护级别；
  - Provider 的 authorities、`grantUriPermissions`、读写权限；
  - deep link（scheme/host/path）；
  - 应用开关：debuggable、allowBackup、usesCleartextTraffic、networkSecurityConfig（解析出内容）；
  - sharedUserId、minSdk/targetSdk；
  - 每个组件对应的类名（便于直接接 getclass）。
- 新增 CLI 子命令和 MCP 工具：`resources`（按 id/名字查询、搜索）、`manifest_summary`（文本和 JSON 两种输出）。

**健壮性**：偏移和计数做边界检查；引用链和父链限制深度；遇到重复 ID 或损坏的 chunk 时跳过并给出警告，不让整次解析失败；补充畸形输入测试。

**验证**：在 100 个 APK 的测试集和 Douyin、Taobao、快手、小红书、美团上，与 aapt2 逐个资源 ID 对比名字和各配置下的取值。差异要么修掉，要么写明原因。资源被混淆的大厂 APK 作为重点样本。

**估计**：asc-arsc 1.5–2 天；接入 manifest/res/xml 和摘要约 1 天。

### B. 调用图与查询表达能力（asc-findrefs、asc-smali、engine 的查询部分）

- **findrefs 返回上下文**：可选返回命中指令的偏移、源码行号（来自调试信息）、前后 N 行 smali，或整个命中方法。CLI 加 `--context N`，MCP 加 `context` 参数。目标：dexsql 那 47 步回放里"findrefs 之后接 getclass"的步数明显减少。
- **调用图**：第一次需要时对每个 DEX 扫描一遍代码，建出"调用方 → 被调用方"的边表（method_idx 对），跨 DEX 按方法签名对齐。
  - 查询：`callers(method, depth)` / `callees(method, depth)`，返回带层级的树，带去重和数量上限；
  - 边表计入内存预算，以后可以进 D 线的 L2 磁盘缓存；
  - 评估：Douyin 上的边数、建表耗时和内存。
- （后续）**组合条件**：在同一方法内对多条条件求交集，例如"引用字符串 A 且调用方法 B"。
- （后续）**继承关系递归**：所有子类、实现类；方法重写查询。
- （P2）多条规则一次扫描：字符串规则合成一个多模式匹配，类型、方法、字段的 index 集合合并后一次扫描代码，再把结果分回各条规则。

### C. MCP 面向多 APK 的工具（asc-mcp）

- `findrefs`、`manifest_summary`、`resources` 接受 `apks`（路径列表）或 `dir`（目录，可加 glob）。
  - 服务端按 APK 和 DEX 统一调度，最大的 DEX 先处理；
  - 默认返回每个 APK 的命中数和前 N 条结果，可以按 APK 继续分页。
- 控制上下文体积：
  - 按包名前缀合并命中；
  - 标出常见第三方 SDK 的包名（可配置），可以选择折叠；
  - 每个 APK 和总输出都设字节上限，超出时给出继续查询的方式。
- 打开 APK 的策略：多 APK 时默认不预热，按需解压；处理完的 APK 允许被淘汰。
- 支持取消：响应 `notifications/cancelled`，中断正在执行的长调用（引擎已有 cancel 标志）。
- 防解压炸弹：限制解压后大小和压缩比；单个 APK 出错时记进结果，不影响其他 APK。
- （P2）跨 APK 去重：以 DEX 的 CRC32 和大小（zip 目录里现成就有）作键，共享解压结果、索引表和查询结果。

### D. 缓存分层与多进程内存（asc-cache、engine 的缓存部分）

| 层 | 内容 | 重建成本 | 淘汰策略 |
|---|---|---|---|
| L1 | 解压后的 DEX（现有） | 低：每个 APK 10–80 ms | 按体积加权的 LRU，空间紧张时最先淘汰 |
| L2 | 派生索引：索引表、调用图边表（可直接映射的格式）、类清单、manifest 摘要、资源表索引 | 中：每个进程都要重建 | 按"重建成本 ÷ 体积"打分，APK 还在就尽量保留；多个进程映射同一份文件，内存不再叠加 |
| L3 | 渲染结果：smali、findrefs 结果，以"APK、查询、工具版本"作键 | 低到中 | 按条数和字节数的 LRU，单独的小预算（例如 128 MB） |

- 三层共用自动磁盘总预算，各自设上限；空间紧张时按 L1 → L3 → L2 的顺序淘汰。
- 缓存键带上格式版本号，工具升级后旧格式自动失效。
- 一次性大批量处理（S2 第一次运行）时，小 DEX（例如解压后小于 4 MB）不写 L1：数据显示写盘比重新解压更贵。
- 多进程内存：自动内存预算要考虑同一用户下正在运行的其他 droidasc 进程。例如在缓存目录里登记各进程的占用，或按"可用内存 ÷ 进程数"重新分配。可直接映射的 L2 让索引表从匿名内存变成共享的文件页。
- （P2）打开 APK 时后台预建索引，首次查询从约 30 ms 降到约 5 ms。

## 4. 验收评测

> 全部评测结论、版本与复现方法统一记录在 [benchmark/README.md](benchmark/README.md)；本文只保留简短结论。

下表是计划时定的验收方式，以**脚本回放**（固定的步骤或规则）为主；后来又补了真实 agent（grok）评测，结果同样在 benchmark/README.md。

| 场景 | 方法 | 指标 |
|---|---|---|
| S1 | dexsql 那 17 个目标，加上新增的调用链目标（例如"导出 Provider → 文件读写"、"deep link → WebView loadUrl"） | **每个目标的调用次数**、整轮耗时、每个目标的几何平均、内存峰值；和 dexsql 对比 |
| S2 | 100 个 APK 的测试集（以后换成真实的几百个 APK）；模拟一个暴露面审计 goal：manifest 摘要 → 规则查询 → 对可疑点 getclass | 调用次数、返回的总字节数（上下文体积）、耗时、单进程和 N 个子 agent 进程同时运行时的内存 |
| 资源 | 与 aapt2 逐项对比 | 差异数为 0，或每类差异都写明原因 |
| 回归 | `cargo test --workspace`、clippy、fmt；与 Python 上游做语义对比（reference-workload 和 Douyin） | 全部通过，结果集合差异为 0 |

## 5. 待确认

1. 已定：删除 GUI（`asc-gui`、`droidasc gui`、`app.apk --gui`），不再维护。
2. 已定：不追求兼容 rasc 和 rust_ASC 的输出格式。`classes`、`manifest`、`--thread` 只作为方便迁移的别名，输出按 asc-rs 自己的格式，以对 agent 好用为准。新增的输出（manifest 摘要、多 APK 汇总、调用图）都按这个原则设计：每行一条记录、可直接 grep，MCP 同时给 JSON。
   也不追求与 Python 上游逐字节一致，不留 `--raw`。与上游只做**语义对比**：把双方输出解析成（dex，方法，命中值集合）再比较。待 B2 合入后统一 findrefs 等文本格式：方法带完整签名；字符串加引号并转义（`\n`、`\t`、`\\`、控制字符），保证每行一条记录；各工具统一用 `|` 分隔、固定列序；可选在行尾带命中位置。
3. 已定：S2 真实数据集先用测试机（Pixel 6）上安装的全部系统 APK（`adb shell pm list packages -f -s`，约 320 个、3.8 GB），拉到 `target/device-apks/`（不入库）。C、D 线的 S2 评测以它为准，100 个 APK 的合成集只作对照。
4. 暂定：资源对比以 aapt2 为准；aapt2 拒绝或丢弃而我们能恢复的条目（apktool 式），单独标记为“恢复”，不算差异。

## 6. 完成情况

四条工作线（A 资源与 manifest、B 调用图与查询表达、C MCP 多 APK、D 缓存分层与多进程内存）的计划项都已合入 main，包括后来补上的组合条件、继承递归、多规则一次扫描、跨 APK 去重、后台预建、调用图原地映射和映射页计费。此后合入的工作：

- 输出：asc-rs 自己的文本格式（完整签名、字符串转义、固定 `|` 列）；MCP 输出预算与超长写文件、getclass 大纲；CLI `--limit` / `--max-bytes` / `--offset`（超出时写文件并给出续读提示），findrefs 按 DEX 自然序输出，子命令 help 不再重复全局选项，`skills/droidasc/SKILL.md`。
- 接口：CLI、MCP、rules 共用一套成员写法；参数宽松化；可操作的报错与零结果提示；CLI 透明 daemon（无会话状态，有无 daemon 输出逐字节相同）。
- 性能与资源：prefix-skip；写盘队列有界，超限时延后重新解压而不是丢弃；写盘线程与预建降优先级；aarch64 硬件 SHA-256；缓存写入去掉 fsync、文件带 CRC、跨重启才校验；线程按忙碌进程分摊、磁盘自动上限 32 GiB、macOS 进程注册表。
- 删除 GUI（asc-gui 与 egui 依赖）。
- 上游字符串下标问题已报：MG1937/ASC#54、MG1937/rust_ASC#8。
- 查询与 MCP：findrefs 按签名选重载（`m(I)V`、`m(I)`、`m(int, String)`、`f:I`，在定位阶段过滤）；多 APK 与规则集的零结果提示，成员列表截到 8 项；MCP 的枚举参数改为宽松字符串；工具定义补参数说明与默认值、`outputSchema`、annotations。
- daemon：callgraph / hierarchy / getclass 可取消（MCP 同）；打开的 APK 常驻结构计入内存预算；`DROIDASC_DAEMON_WAIT_MS`、`DROIDASC_DAEMON_IDLE`。
- 多进程：注册表 busy 标记与 100 ms 重读，多 APK 扫描中途按线程数排队，空闲后的突发扫描线程会收缩；写盘队列按内存预算封顶。多 APK 扫描接 prefix-skip 实测无收益，未合入；macOS 降优先级测不出差别，保留。

## 7. 评测结论

全部数字、版本、语料与局限见 [benchmark/README.md](benchmark/README.md)。最关键的几条：

- 正确性：与 Python 上游语义一致、与 dexdump 一致；资源与 aapt2 在 1094 万个取值上只差 4 处；开关缓存、开关 daemon 输出一致。
- 单 APK（Douyin 47 步）：MCP 热缓存约 60 ms；CLI 冷查询比 r1 快约 22%（prefix-skip）。
- 多 APK（836 个 APK × 8 条规则）：规则集模式单 MCP 进程热缓存约 0.5 s、4–8 个进程约 0.23 s；dexsql 约 2.4 s，rust_ASC 约 10.7 s。
- agent（grok-4.7，单一模型）：超长写文件的组每目标 207k token，约为 dexsql 的 1/4、r1 的 1/3，证据持平；416 个 APK 的 S2 两边都全对，droidasc 每目标 104k token，dexsql 4.8M。

**方向（2026-10-23）**：CLI 是一等的 agent 接口，MCP 保留为另一种接入；参考 pi 的工具设计（统一截断、可操作的续页与报错、参数修复），预算交给客户端决定，不按单一模型调参。不再做新的 agent 评测。

## 8. 待做

- Windows：daemon 与进程注册表不支持（优先级低）。
- MCP 服务自己打开的 APK 尚未计入内存预算（daemon 已计入），可复用 `resident_bytes` / `set_reserved`。
- 自动内存份额（可用内存的四分之一，按忙碌进程分）是否下调，待定。
- 签名过滤在真实 APK 的 prefix-skip 路径上未专门测（前缀里读不到参数列表时退回完整搜索）；`outputSchema` 只描述单 APK 的形状。
- 是否去掉 open_apk / close_apk。
- 评测：不再做新的 agent 评测（2026-10-23）。若以后重启：S1 证据先用 40.8.0 重新标注，加「只用 CLI + skill」组，并换一个模型。
