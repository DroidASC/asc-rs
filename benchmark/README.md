# 评测

asc-rs 的全部评测结论，以及复现它们所需的脚本和步骤。APK 不在仓库里，[corpus.md](corpus.md) 给出了每个语料的设备、系统版本、拉取方法，以及逐个 APK 的版本号和 sha256 清单。

评测分两类：

- **确定性评测**：固定的步骤或规则，用脚本回放，度量耗时、内存，并核对结果是否一致。不经过模型，可以重复跑。
- **agent 评测**：让真实 agent（grok headless）只接一个工具去完成分析目标，度量调用次数、token、费用、耗时，以及证据或答案是否正确。结果依赖模型，只做了 grok-4.7 一个模型。2026-10-23 起不再做新的 agent 评测，这里只记录已有结果和当时的做法。

数字均取自 `*/results/` 下的结果文件，或当时的运行日志；没有测的写「未测」。

**结果文件不入库**：所有 `results/` 目录、语料清单 `*.tsv` 和 `agent/s2/ref-k80.json` 都保存在仓库之外，目录结构与这里相同：本地 `target/benchmark-data/benchmark/`，ams `~/asc-eval/results/benchmark-data/benchmark/`。下文提到的这些路径都相对于那里；脚本会把新结果写到同样的位置。

## 目录

| 路径 | 内容 |
|---|---|
| [corpus.md](corpus.md)、[corpus/](corpus/) | 语料与版本、设备信息、拉取脚本 `pull.sh`、清单生成脚本 `manifest.py`（清单本身不入库） |
| [deterministic/](deterministic/) | 第二轮确定性评测（S1 回放、S2 多 APK、big-machine、prefix-skip、缓存一致性与 no-fsync、rust_ASC 对比），及结果汇总 |
| [agent/](agent/) | grok agent 评测：S1、S2 的 runner 和打分脚本、每次运行的指标（CSV）、工作区配置 |
| [cli-native/](cli-native/) | 失败调用回放：两轮 agent 评测里所有失败的 droidasc 调用，在 cli-native 改动前后的版本上重放 |
| [agent-audit/](agent-audit/) | 第一轮：S1 Douyin 47 步回放（MCP），`replay_mcp.py` |
| [multi-apk/](multi-apk/) | 第一轮：S2 多 APK 暴露面审计（`audit.py`）和规则集（`rules.py`） |
| [parity/](parity/) | 与 Python 上游的语义对比（`semantic.py`） |
| [arsc-compare/](arsc-compare/) | `resources` 与 `aapt2 dump resources` 的逐项对比 |

## 机器与工具版本

| | 说明 |
|---|---|
| 本地 | AMD Ryzen 7 8745H（16 线程），12 GB 内存，Arch Linux，内核 7.2.11，ext4 / NVMe |
| ams | Apple M3 Ultra（32 核），96 GB 内存，macOS 15.7.3（24G419）。**多人共用**，评测期间 load 在 4–30 之间波动；有异常值的配置都交替重跑过 |
| asc-rs | 第一轮 agent 评测和第二轮对照组「r1」：`8b7a09e`（ams 上的 `bin/droidasc-r1`，sha256 `37c1c62f…4581`）。第二轮确定性评测的「new」：S1 用合入 prefix-skip 后的 `0e08806`，S2 用 `a23650e`（写盘队列修复 + sha2 asm）。第二轮 agent 评测：`a23650e`。big-machine 验证：旧 `36ab1e2`，新 `c1fc2da`。失败调用回放：前 `f344edf`，后 `c1fc2da` 之后的 HEAD |
| Python ASC | `9216fe2`（MG1937/ASC） |
| rust_ASC | dev `6db7135`，main `236dd09`（MG1937/rust_ASC，radguard 子模块 `290de20`） |
| dexsql | 0.1.1（LSPosed/dexsql-release），ams 上 darwin-arm64 二进制 sha256 `d983de33007e11c56e681aaa238ae15637eff961623335f1131527f8d2c82a77` |
| dexsql-release harness | `3ac6fb1`，MIT 许可。S1 的 17 个目标（47 步）来自它的 `benchmarks/agent-audit/harness/rasc_replay.py`（`SCENARIOS`），脚本在运行时通过 `HARNESS` 环境变量导入，不复制进本仓库 |
| grok | grok CLI 1.0.67（`2fe064390d07`），模型 grok-4.7-build，headless（`-p … --output-format streaming-json`） |

## 第一轮（本地 Linux，2026-10-22）

### 确定性评测

**S1：Douyin 40.7.0（56 个 DEX，55 万个类），dexsql-release 的 17 个目标（47 步）**。脚本 [`agent-audit/replay_mcp.py`](agent-audit/replay_mcp.py)。仓库里只留了最后一次的结果 `agent-audit/results/asc_mcp_benchmark.json`（`integrate/plan`，磁盘缓存命中，整轮 81 ms，7 次中位数）；下表其余数字取自当时的运行记录。

| | asc-rs mcp | asc-rs CLI，磁盘缓存命中 | dexsql 0.1.1 | rasc |
|---|---:|---:|---:|---:|
| 整轮会话 | 208 ms | 336 ms | 1112 ms | 3819 ms |
| 每个目标几何平均 | 4.7 ms | 18 ms | 22.6 ms | 189 ms |

`integrate/plan` 合入后，不开缓存整轮 242 ms、峰值 648 MB；磁盘缓存命中时整轮 82 ms、峰值 227 MB。

**S2：Pixel 6 上的 312 个系统 APK（3.8 GB），8 条规则，2496 次查询**。脚本 [`multi-apk/audit.py`](multi-apk/audit.py)。

| 跑法 | main `3a1e5cd` | `integrate/plan` |
|---|---:|---:|
| 一个 MCP 进程，空缓存 | 683–842 ms，峰值 1.75 GB | 428 ms，峰值 1.49 GB |
| 一个 MCP 进程，缓存已建好 | — | 144 ms，峰值 122 MB |
| CLI，16 个进程 | 949 ms，每进程 108 MB | 525 ms，每进程 21 MB |

**资源对比**：419 个 APK、160 万个资源 id、1094 万个取值，与 aapt2 只差 4 处，都是 aapt2 文本输出无法拆准的带样式字符串。脚本 [`arsc-compare/compare.py`](arsc-compare/compare.py)。第三方 APK 部分（快手、美团、拼多多、淘宝两个版本、小红书）当时没有记录版本，APK 也已不在本地，**无法按版本复现**；设备 APK 和 Douyin 部分见 corpus.md。

**与上游的一致性**：reference-workload 上与 Python 上游语义对比差异为 0（[`parity/semantic.py`](parity/semantic.py)）；40 个设备 APK × 9 条查询，开缓存与不开缓存的输出一致（[`deterministic/cache/consistency.py`](deterministic/cache/consistency.py)）。

**rust_ASC 对比**（dev `6db7135`，16 线程）：

- 47 步回放：rust_ASC dev CLI 2586 ms（main 4618 ms），dev MCP 2357 ms / 509 MB；asc-rs CLI 不开缓存 2627 ms / 328 MB，CLI 磁盘缓存 169 ms，MCP 不开缓存 290 ms，MCP 磁盘缓存 81 ms。
- S2（312 个 APK × 8 条规则，16 进程）：rust_ASC dev CLI 2946 ms / 每进程 219 MB，dev MCP 3138 ms / 进程树 4.6 GB（它的 MCP 每次调用都起一个 CLI 进程）；asc-rs CLI 不开缓存 1188 ms，热缓存 688 ms / 每进程 21 MB，MCP 393 ms，热 179 ms / 124 MB。
- **上游 bug**：312 个 APK 里有 24 个（APK，规则）组合，rust_ASC main、dev 和 Python ASC `9216fe2` 给出的是同样的错误行。例如 `getDeviceId` 误中 `Display.getDeviceProductInfo`，同时漏掉 dexdump 能看到的 14 处 `MotionEvent.getDeviceId` 调用。受影响的 DEX 全都是 string_data 顺序与 string_ids 不一致的（约 14.8k 处逆序，见于 dialer、GoogleCamera 的 classes.dex），上游看起来是按数据顺序映射字符串索引。asc-rs 的结果与 dexdump 一致。脚本 [`deterministic/rust-asc/`](deterministic/rust-asc/)。

当时的计时脚本依赖 Linux 的 `/proc`，已由 [`deterministic/s1.py`](deterministic/s1.py)（`rust-cli` / `rust-mcp`）和 [`deterministic/s2.py`](deterministic/s2.py)（`rust`）替代，这两个脚本 Linux、macOS 都能跑。

### agent 评测（grok，Douyin 40.7.0，17 个目标 × 2 次，只接 MCP）

每次运行的指标在 `agent/results/round1-s1.csv`。

| 工具 | MCP 调用/目标（中位数） | 失败调用 | token/目标 | $/目标 | 耗时 | 证据 |
|---|---:|---:|---:|---:|---:|---:|
| dexsql | 38 | 55 | 659k | 0.173 | 105 s | 92/100 |
| droidasc（`8b7a09e`） | 26.5 | 78 | 610k | 0.167 | 112 s | 86/100 |

- droidasc 的证据缺失全部出在 manifest_exported_components：单 APK 的 manifest 摘要被 grok 截断（约 20 KB），又没有办法翻页。
- 78 次失败里有 58 次是 getclass 的方法签名写法不被接受。
- 165/922 次 droidasc 返回超过 20 KB（dexsql 是 47/1329）。

这些问题催生了第二轮的 agent-ux 改动：16 KiB 输出预算加超长写文件、getclass 大纲、manifest_summary 过滤、宽松参数。

## 第二轮：确定性评测（ams，Douyin 40.8.0 与 836 个小米设备 APK）

驱动脚本与结果见 [deterministic/README.md](deterministic/README.md)。全部汇总表：`results/round2/summary.md`、`results/round2-bm/summary.md`。

### S1：Douyin 40.8.0，47 步，5 次中位数

| 配置 | new | r1 `8b7a09e` | rust_ASC dev |
|---|---:|---:|---:|
| CLI 不开缓存 | 2065 ms / 352 MB | 2649 ms / 504 MB | 2528 ms / 362 MB |
| CLI 磁盘缓存（热） | 317 ms / 19 MB | 307 ms / 19 MB | — |
| MCP 不开缓存 | 134 ms / 643 MB | 137 ms / 643 MB | 2691 ms / 354 MB |
| MCP 磁盘缓存 | 61 ms / 103 MB | 61 ms / 107 MB | — |

- 新旧版输出一致：21 个 findrefs/manifest 步骤的行集合相同，26 个 getclass 文本逐字相同（[`s1_same.py`](deterministic/s1_same.py)）。
- 回放脚本里写死了 40.7.0 的混淆类名，所以每个工具在 40.8.0 上都缺 13–14 个证据；droidasc 各配置缺的完全相同。dexsql 写死的 method id 导致 18 次 decode 报错，只能当作工作量相近的计时参考：整轮约 722 ms（open 443 ms + 场景 279 ms），进程树 2.4 GB（[`dexsql_replay.patch`](deterministic/dexsql_replay.patch)）。
- CLI 冷查询比 r1 快约 22%，主要来自 prefix-skip（见下）。CLI 热缓存比本地 Linux 慢（317 vs 169 ms），应该是 macOS 上起进程的开销。

### S2：836 个 APK（K80 416 + Xiaomi 17 420）× 8 条规则，3 次中位数

| 配置 | new `a23650e` | r1 `8b7a09e` |
|---|---:|---:|
| 每条规则一个 CLI 进程，P=16：不开缓存 / 冷 / 热 | 11.5 / 42.6 / 8.0 s | 12.0 / 42.7 / 8.1 s |
| 规则集，每个 APK 一个 CLI 进程：不开缓存 / 冷 / 热 | 1.54 / 7.17 / 1.06 s | 1.50 / 6.68 / 4.90 s |
| MCP 单进程规则集：不开缓存 / 冷 / 热 | 1.16 / 1.39 s（3.2 GB）/ 0.48 s（180 MB） | 1.26 / 1.18 s（12.2 GB）/ 1.13 s（7.2 GB） |
| MCP 规则集，N=4 / 8 / 16，冷 | 0.99 / 1.00 / 1.28 s | 0.94 / 0.98 / 1.61 s |
| MCP 规则集，N=4 / 8 / 16，热 | 0.24 / 0.23 / 0.53 s | 0.94 / 1.06 / 1.32 s |
| rust_ASC dev CLI，P=16 | 10.7 s / 1.8 GB | |
| dexsql，每个 APK 一个进程跑 8 条 SQL，P=16 T=2 | 2.4 s / 1.8 GB | |

- 命中 APK 集合：新版与 r1、新版与 rust_ASC 在 8 条规则上完全一致（[`s2_cmp.py`](deterministic/s2_cmp.py)）。与 dexsql 有 7 条一致；password 规则 dexsql 多 4 个 APK，原因是它的 `LIKE` 不区分大小写，droidasc 的正则区分大小写。没有 droidasc 漏报。
- r1 的「热」规则集 CLI 每进程峰值约 700 MB、进程树约 2 GB（新版 14 MB / 64 MB），说明它其实在重新解压；原因没有查。
- 第一轮按「每条规则一次调用」测 S2，对 droidasc 不公平，因为 dexsql 一个进程就跑完 8 条 SQL。规则集模式才是同口径的比较。

### 期间发现并修复的问题（第二轮）

| 问题 | 现象 | 修复 | 实测 |
|---|---|---|---|
| 写盘队列不限长（旧 bug，r1 同样存在） | 一个 MCP 进程冷扫 416 个 APK，4 s 内涨到 28–44 GB，缓存目录 8.6 GB，是预算的两倍 | `4d701d8`：排队写入超过 512 MiB 就丢弃新写入；写入期间也淘汰 | 836 个 APK 每条规则调用一次：从超过 30 GB 被强制终止，变为 6.5 s / 5.2 GB；规则集 1.4 s / 3.2 GB |
| aarch64 上 sha2 走软件实现 | 跨 APK 去重的 SHA-256 成为采样热点，两台手机的系统 APK 大量重复 | `a23650e`：aarch64 上开启 `asm` feature | 836 个 APK 规则集冷跑：修复前 2055 ms，修复后 1713 ms，r1 1732 ms（交替 5 轮）。修复前的数据在 `results/round2/pre-sha/` |
| macOS 上 `sync_data` 等于 `F_FULLFSYNC` | 每个 8 MiB 文件 9.8 ms，普通 fsync 2.0 ms | no-fsync：去掉 fsync，文件带 CRC，重启前写入的文件读取时校验一次 | ams 上用临时去掉同步的构建：每条规则一个进程冷跑 52.7 → 21.1 s，规则集冷跑 8.0 → 4.0 s。合入版本在 macOS 上的正式前后对比**未测**。本地 Linux 见下 |

### prefix-skip（本地 Linux，Douyin 40.7.0，`--no-cache` 冷查询中位数）

脚本 [`deterministic/prefix_skip.py`](deterministic/prefix_skip.py)。

| 查询 | 79f01d9 | prefix-skip |
|---|---:|---:|
| `method exec --class java.lang.Runtime` | 77 ms / 328 MB | 57 ms / 201 MB（55 个 DEX 跳过 37 个） |
| `type DexClassLoader` | 72 ms / 325 MB | 54 ms / 200 MB |
| `string ttdownloaderClickId` | 71 ms / 319 MB | 47 ms / 186 MB |
| `field SDK_INT`、`string http://`（覆盖面广） | 95 / 92 ms | 97 / 92 ms |
| 47 步回放，CLI 每步一个进程 | 2724 ms | 2212 ms |

MCP 会话不触发（常驻缓存），不压缩存放的 APK（GMS）和字符串数据在后部的 DEX（Chrome）结果持平。正确性：60 组行级对比、720 组缓存一致性、9 条上游语义对比，差异都是 0。ams 上 Douyin 40.8.0 的 56 个 DEX 跳过 22 个。

### no-fsync（本地 Linux，ext4 / NVMe，5 次中位数，交替跑）

脚本 [`deterministic/cache/nofsync_bench.py`](deterministic/cache/nofsync_bench.py)、[`nofsync_check.sh`](deterministic/cache/nofsync_check.sh)。

| 场景 | `a23650e` | no-fsync |
|---|---:|---:|
| Douyin 冷缓存单条查询（写约 380 MB） | 447 ms | 180 ms |
| Douyin 热缓存 | 12 ms | 8 ms |
| Douyin 重启后第一次 / 第二次查询 | 7 / 6 ms | 20 / 6 ms |
| 312 个 Pixel APK 规则集冷跑（P=16） | 263 ms | 276 ms |

重启后第一次读取要多花 14–22 ms 算 CRC。Pixel 语料的 DEX 大多不写 L1，所以冷跑只多了 CRC 的开销（约 5%）。结果一致性：冷、热、模拟重启后三种状态，输出都与 `--no-cache` 相同；人为损坏 L1 文件后结果仍正确，文件会被重新写回。

### big-machine（ams，旧 `36ab1e2` 对新 `c1fc2da`，交替 3 次中位数）

驱动 [`deterministic/bm.sh`](deterministic/bm.sh)，结果 `results/round2-bm/`。

| 规则集，自动线程 | 冷：旧 → 新 | 热：旧 → 新 |
|---|---:|---:|
| N=1 | 1436 → 1454 ms | 509 → 500 ms |
| N=4 | 929 → 907 ms | 703 → 267 ms |
| N=8 | 868 → 880 ms | 2956 → 244 ms |
| N=16 | 1086 → 1128 ms | 964 → 251 ms |

- **主要价值是 macOS 上的进程注册表终于生效**：N=16 冷扫时，注册表里的登记从 0 个变为 16 个；扫描期间一次性查询的 worker 从 32 个降为 7 个。
- 冷跑持平，差异在 ±4% 以内。旧版热跑的慢值不可靠：N=8 时重跑，旧版自动线程是 249–311 ms，新版 233–284 ms（`diag-*`）。热跑**不算** big-machine 的确定收益。
- N=16 冷跑、每进程固定线程数：2 / 4 / 8 / 32 线程分别是 1263 / 951 / 1053 / 1136 ms，自动线程 1128 ms。每进程线程太少会造成长尾，这一点成立；但约 1 s 的突发扫描里，注册表还没来得及反映忙碌进程（最多每秒读一次），自动线程没有收缩。
- 内存：两版 N=16 冷跑合计都约 21 GB（每进程约 2 GB），主要是解压中的数据和映射页，不是内存缓存。
- 磁盘上限 32 GiB 没测到：836 个 APK 冷扫只写了 1.1–1.3 GB，因为大部分 L1 写入被 512 MiB 的写盘队列上限丢掉了。
- S1 无退化：CLI 不开缓存 1791 → 1805 ms，MCP 热 47 → 50 ms。

### daemon（本地 Linux，Douyin 40.7.0，16 线程，`b3320c2`）

| 场景 | 无 daemon | 有 daemon |
|---|---:|---:|
| 47 步回放，磁盘缓存热 | 176 ms | 135 ms |
| 同样 47 步，MCP 同一进程 | 55 ms | — |
| 空缓存第一条查询 / 换一类的第二条 | 256 / 234 ms | 81 / 9 ms |
| `hierarchy android.app.Activity`（1343 行）首次 / 重复 | 433 / 408 ms | 326 / 6 ms |
| `callgraph WebView loadUrl --virtual` 首次 / 重复 | 425 / 398 ms | 22 / 5 ms |

当时用的计时脚本没有保留。47 步回放可以用 `DROIDASC_DAEMON=auto python3 deterministic/s1.py asc-cli …` 复现（benchmark 脚本默认设 `DROIDASC_DAEMON=off`）。输出一致性由 `crates/asc-cli/tests/daemon.rs` 保证：26 种命令开关 daemon，stdout、stderr、退出码逐字节比较。macOS 上 7 种查询逐字节相同，`callgraph --virtual` 首次调用 daemon 261 ms、本地 276 ms。

## 第二轮：agent 评测（ams，grok-4.7）

做法见 [agent/README.md](agent/README.md)。每次运行的指标在 `agent/results/`；原始记录（含 Douyin 反编译代码片段，体积约 80 MB）不提交，位置见 agent/README.md。

### S1：Douyin 40.8.0，17 个目标 × 2 次，每组只接一个工具

| 组 | MCP 调用/目标 | 失败调用 | token/目标 | $/目标 | 耗时 | 证据 | 总费用 |
|---|---:|---:|---:|---:|---:|---:|---:|
| C：dexsql，MCP + 读文件 | 42.5 | 68 | 785k | 0.201 | 162 s | 92/100 | $9.04 |
| D：r1 `8b7a09e`，只 MCP | 25.0 | 63 | 578k | 0.162 | 136 s | 86/100 | $7.69 |
| A：new `a23650e`，只 MCP，超长时分页（`--spill-mb 0`） | 24.5 | 15 | 379k | 0.119 | 116 s | 92/100 | $4.08 |
| B：new `a23650e`，MCP + 读文件，超长时写文件 | 11.0 | 5 | 207k | 0.071 | 83 s | 92/100 | $3.28 |

- **评测本身可信**：D 组的结果与第一轮本地、40.7.0 上同一版本的结果几乎相同（25 对 26.5 次调用，578k 对 610k token，证据都是 86/100）。
- A 对 D：token 少 34%，失败调用从 63 次降到 15 次，manifest_exported_components 从 0/3 变成满分。
- B 对 A：token 再少 45%，调用数减半。B 组用了 read_file 和 grep 去读写出来的文件，说明这个设计 agent 是真的在用。
- B 对 dexsql：token 约 1/4，费用约 1/3，耗时约一半，证据持平。
- **局限**：
  - 证据已经饱和：三组都缺同样 8 条证据，就是 40.7.0 写死的混淆名。
  - 只有 grok-4.7 一个模型，结论不一定适用于其他模型。
  - 第 3 次重复只跑完 18 次，不计入（CSV 里有）。
  - 第一次以 14 路并发开跑时被 grok 限流，那批结果已全部丢弃，正式结果是 4 路并发、带退避重试跑的。

### S2：K80 的 416 个 APK，4 个「哪些 APK 调用了某 API」目标 × 1 次

参考答案先由 droidasc 生成，再用 dexsql 独立交叉核对。四个目标里三个完全一致；剩下一个差异来自 com.android.bluetooth，它只调用了 `sendTextMessageWithoutPersisting`（droidasc 的方法名是模糊匹配），记为可选项。

| 工具 | 召回 | 准确 | 调用/目标（全部工具） | token/目标 | $/目标 | 耗时 | 总费用 |
|---|---:|---:|---:|---:|---:|---:|---:|
| droidasc（MCP + 读文件） | 1.00 | 1.00 | 6 | 104k | 0.039 | 74 s | $0.16 |
| dexsql（MCP + 读文件） | 1.00 | 1.00 | 110 | 4815k | 1.225 | 716 s | $5.86 |

两边答案都完全正确。dexsql 每个 dataset 最多 64 个输入，只能分批打开、逐批写 SQL，token 约为 droidasc 的 46 倍。dexsql 组运行时 ams 上同时在跑 big-machine 基准，耗时略受影响。每个目标只跑了 1 次。

## 失败调用回放（cli-native，本地 Linux，Douyin 40.7.0）

两轮 agent 评测里一共提取出 104 次失败调用，其中 12 次是客户端调用了不存在的 `bash`、`Read` 工具，不属于我们。剩下 92 次 droidasc 调用，在同一个 MCP 会话里分别用改前（`f344edf`）和改后的版本重放。脚本和数据见 [cli-native/](cli-native/)。

| 版本 | 成功 | 报错且有可操作提示 | 报错没有提示 |
|---|---:|---:|---:|
| 改前 `f344edf` | 46 | 31 | 15 |
| 改后（统一查询语法、宽松参数、可操作报错） | 49 | 43 | 0 |

「有可操作提示」是用 `replay.py` 里的正则判定的，两个版本用同一个正则。合并时的汇报里写的是 28/18 → 41/2，那是另一种更严的人工分类，以本表为准。r2s1 那一轮的调用实际是在 40.8.0 上发出的，这里在 40.7.0 上重放，部分混淆类名对不上，所以这部分结果只说明「找不到时的提示质量」，不代表在原版本上会成功。
