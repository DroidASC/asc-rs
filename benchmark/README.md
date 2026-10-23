# 评测

asc-rs 的全部评测结论按问题组织，每个问题给出当前版本的实测结果。旧版本和其他工具作为对照列出现。复现所需的脚本见文末[复现](#复现)。

评测分两类：

- **确定性评测**：用脚本回放固定的步骤或规则，度量耗时和内存，并核对结果是否一致。不经过模型，可以重复跑。
- **agent 评测**：让真实 agent（grok headless）只接一个工具去完成分析目标，度量调用次数、token、费用、耗时，以及证据或答案是否正确。只用过 grok-4.7 一个模型。2026-10-23 起不再做新的 agent 评测。

数字均取自结果文件或当时的运行日志，没有测的写「未测」。同一指标测过多个版本时，以最新版本为主，旧值作对照并注明版本。不同机器的数字不放在同一列里比较。

**结果文件不入库**：所有 `results/` 目录、语料清单 `*.tsv` 和 `agent/s2/ref-k80.json` 都保存在仓库之外，目录结构与这里相同：本地 `target/benchmark-data/benchmark/`，ams `~/asc-eval/results/benchmark-data/benchmark/`。下文提到的这些路径都相对于那里，脚本也会把新结果写到同样的位置。

## 总览

| 问题 | 结论 | 关键数字 | 详见 |
|---|---|---|---|
| 结果对不对 | 与 Python 上游语义一致、与 dexdump 一致；上游在 string_data 乱序的 DEX 上会出错 | 语义差异 0；312 个系统 APK 上，上游有 24 个（APK，规则）组合出错，已报 issue | [正确性](#正确性) |
| 资源解码 | 与 aapt2 基本一致 | 419 个 APK、1094 万个取值，只差 4 处 | [正确性](#正确性) |
| 单 APK 有多快 | 常驻进程是最快的用法；CLI 冷查询靠 prefix-skip 提速 | Douyin 47 步：MCP 热缓存 61 ms，CLI 不开缓存 2065 ms（r1 2649，rust_ASC 2528） | [单 APK](#单-apkdouyin47-步回放) |
| 多 APK 有多快 | 规则集模式是关键：一次扫描跑完全部规则 | 836 个 APK × 8 条规则：MCP 热缓存 0.48 s，4–8 个进程 0.23 s；dexsql 2.4 s，rust_ASC 10.7 s | [多 APK](#多-apk) |
| 内存和多进程 | 写盘队列内存有界，冷扫之后 L1 完整；macOS 上进程注册表已生效 | 冷扫从超过 30 GB 被强制终止降到 3.1 GB 峰值；L1 从 86 个文件增至 866 个 | [缓存、内存与多进程](#缓存内存与多进程) |
| agent 用起来怎么样 | 超长时写文件这个设计最省 token；比 dexsql 省得多 | S1 每目标 207k token（dexsql 785k，r1 578k）；S2 416 个 APK 每目标 104k token（dexsql 4.8M），两边都全对 | [agent 评测](#agent-评测grok-47) |
| 报错能不能帮 agent | 失败调用几乎都变成成功，或者给出下一步怎么做 | 92 次历史失败调用：没有提示的从 15 次降到 0 次 | [agent 评测](#agent-评测grok-47) |

## 测试环境与版本

| | 说明 |
|---|---|
| 本地 | AMD Ryzen 7 8745H（16 线程），12 GB 内存，Arch Linux，内核 7.2.11，ext4 / NVMe |
| ams | Apple M3 Ultra（32 核），96 GB 内存，macOS 15.7.3（24G419）。**多人共用**，评测期间 load 在 4–30 之间波动，出现异常值的配置都交替重跑过 |
| asc-rs（被测版本） | 各节表头注明 commit。「r1」= `8b7a09e`，作为旧版本对照（ams 上是 `bin/droidasc-r1`，sha256 `37c1c62f…4581`）。agent 评测用的是 `a23650e` |
| Python ASC | `9216fe2`（MG1937/ASC） |
| rust_ASC | dev `6db7135`，main `236dd09`（MG1937/rust_ASC，radguard 子模块 `290de20`） |
| dexsql | 0.1.1（LSPosed/dexsql-release），ams 上 darwin-arm64 二进制 sha256 `d983de33007e11c56e681aaa238ae15637eff961623335f1131527f8d2c82a77` |
| dexsql-release harness | `3ac6fb1`，MIT 许可。S1 的 17 个目标（47 步）来自其中的 `benchmarks/agent-audit/harness/rasc_replay.py`（`SCENARIOS`）。脚本运行时通过 `HARNESS` 环境变量导入，不复制进本仓库 |
| grok | grok CLI 1.0.67（`2fe064390d07`），模型 grok-4.7-build，headless 模式（`-p … --output-format streaming-json`） |
| 语料 | 见 [corpus.md](corpus.md)：Douyin 40.7.0（本地）、Douyin 40.8.0（K80）、REDMI K80 的 416 个 APK、Xiaomi 17 的 420 个、Pixel 6 的 312 个系统 APK |

## 正确性

**结论：asc-rs 的结果与 Python 上游语义一致、与 dexdump 一致；开关缓存、开关 daemon 的输出都相同。**

| 检查 | 方法 | 结果 |
|---|---|---|
| 与 Python 上游的语义对比 | 双方输出解析成（dex，方法，命中值集合）再比较，[`parity/semantic.py`](parity/semantic.py)；数据是 reference-workload，以及 prefix-skip 合入时用的 9 条查询 | 差异 0 |
| 与 dexdump 对比、上游 bug | 312 个 Pixel 6 系统 APK × 8 条规则，[`deterministic/rust-asc/`](deterministic/rust-asc/) | asc-rs 与 dexdump 一致。Python ASC `9216fe2`、rust_ASC main 和 dev 在 24 个（APK，规则）组合上给出同样的错误行，见下 |
| 资源 | 419 个 APK、160 万个资源 id、1094 万个取值，与 `aapt2 dump resources` 逐项对比，[`arsc-compare/compare.py`](arsc-compare/compare.py) | 只差 4 处，都是 aapt2 的文本输出没法准确拆分的带样式字符串 |
| 开关缓存一致 | 40 个设备 APK × 9 条查询，冷、热缓存与 `--no-cache` 逐块比较，[`deterministic/cache/consistency.py`](deterministic/cache/consistency.py)；prefix-skip 合入时又跑了 720 组 | 内容一致 |
| 新旧版本一致 | Douyin 40.8.0 上 47 步回放，新版对 r1：21 个 findrefs / manifest 步骤比较行集合，26 个 getclass 比较全文，[`deterministic/s1_same.py`](deterministic/s1_same.py)；836 个 APK × 8 条规则比较命中 APK 集合，[`s2_cmp.py`](deterministic/s2_cmp.py) | 完全相同；69470 行结果一致 |
| 与 dexsql、rust_ASC 的 APK 级命中 | 836 个 APK × 8 条规则 | 与 rust_ASC 8 条规则完全一致。与 dexsql 7 条一致；password 规则 dexsql 多 4 个 APK，原因是它的 `LIKE` 不区分大小写，droidasc 的正则区分大小写。droidasc 没有漏报 |
| 开关 daemon 一致 | `crates/asc-cli/tests/daemon.rs`：26 种命令比较 stdout、stderr、退出码；macOS 上另跑 7 种查询 | 逐字节相同，包括退出码 1、零结果、截断输出 |
| 缓存文件损坏 | no-fsync 版本：整页清零、翻转一个字节、截断，[`nofsync_check.sh`](deterministic/cache/nofsync_check.sh) | 全部检出，文件被删除后重新写回，结果与 `--no-cache` 相同 |

**上游的字符串下标 bug**：已报给上游，见 [MG1937/ASC#54](https://github.com/MG1937/ASC/issues/54) 和 [MG1937/rust_ASC#8](https://github.com/MG1937/rust_ASC/issues/8)。

上游的 `StringLocator` 假设 string_data 的条目按 string_ids 的顺序首尾相连地存放，这个假设在两处出错：

- 搜索区间取的是从第 0 个字符串到最后一个字符串，顺序乱了就会漏掉一部分。
- 命中之后，用「物理上紧跟着的下一个字符串的下标减 1」作为结果，顺序乱了就会对应到别的字符串。

经过布局优化的系统 APK 会触发这个问题，例如 dialer、GoogleCamera 的 classes.dex 里约有 14.8k 处逆序，d8 的产物则不受影响。实际例子：`getDeviceId` 误中 `Display.getDeviceProductInfo`，同时漏掉 dexdump 能看到的 14 处 `MotionEvent.getDeviceId` 调用。issue 里附了不依赖第三方 APK 的最小复现：一个 Java 类，加一个重排 string_data 的脚本。

## 单 APK（Douyin，47 步回放）

**结论：常驻进程（MCP 或 daemon）最快；一次性 CLI 冷查询比 r1 快约 22%，主要来自 prefix-skip；asc-rs 的各种用法都比 rust_ASC 和 dexsql 快。**

dexsql-release 的 17 个目标，共 47 步。表中是 5 次的中位数，格式为耗时 / 峰值 RSS。

**ams，Douyin 40.8.0：**

| 配置 | asc-rs `0e08806` | r1 `8b7a09e` | rust_ASC dev | dexsql 0.1.1 |
|---|---:|---:|---:|---:|
| CLI，不开缓存 | 2065 ms / 352 MB | 2649 ms / 504 MB | 2528 ms / 362 MB | — |
| CLI，磁盘缓存热 | 317 ms / 19 MB | 307 ms / 19 MB | — | — |
| MCP，不开缓存 | 134 ms / 643 MB | 137 ms / 643 MB | 2691 ms / 354 MB | 约 722 ms（open 443 + 场景 279），进程树 2.4 GB |
| MCP，磁盘缓存 | 61 ms / 103 MB | 61 ms / 107 MB | — | — |

- 回放脚本写死了 40.7.0 的混淆类名，所以每个工具在 40.8.0 上都会缺 13–14 个证据，droidasc 各配置缺的完全相同。dexsql 写死的 method id 导致 18 次 decode 报错，它的数字只能当作工作量相近时的计时参考。
- CLI 热缓存比本地 Linux 慢（317 ms 对 176 ms），应该是 macOS 起进程的开销。
- big-machine 合入（`c1fc2da`）后复测没有退化：CLI 不开缓存 1805 ms，MCP 热缓存 50 ms。

**本地 Linux，Douyin 40.7.0：**

| 配置 | asc-rs | 对照 |
|---|---:|---:|
| CLI，不开缓存（每步一个进程） | 2212 ms（prefix-skip 之后） | 2724 ms（`79f01d9`，prefix-skip 之前）；rust_ASC dev 2586 ms，main 4618 ms |
| CLI，磁盘缓存热 | 176 ms；经 daemon 135 ms（`b3320c2`） | — |
| MCP，同一进程 | 55 ms（`b3320c2`）；磁盘缓存命中 81 ms（`integrate/plan`） | dexsql 1112 ms；rasc 3819 ms；rust_ASC dev MCP 2357 ms / 509 MB |
| 每个目标的几何平均（MCP） | 4.7 ms（`integrate/plan`） | dexsql 22.6 ms；rasc 189 ms |

**prefix-skip**：一次性冷查询先只解开每个 DEX 开头的 id 表和字符串数据，能确定不会命中的 DEX 就跳过。下表是本地 Linux、Douyin 40.7.0 上 `--no-cache` 冷查询的中位数，脚本 [`deterministic/prefix_skip.py`](deterministic/prefix_skip.py)：

| 查询 | `79f01d9` | prefix-skip |
|---|---:|---:|
| `method exec --class java.lang.Runtime` | 77 ms / 328 MB | 57 ms / 201 MB（55 个 DEX 跳过 37 个） |
| `type DexClassLoader` | 72 ms / 325 MB | 54 ms / 200 MB |
| `string ttdownloaderClickId` | 71 ms / 319 MB | 47 ms / 186 MB |
| `field SDK_INT`、`string http://`（覆盖面广） | 95 / 92 ms | 97 / 92 ms |

MCP 会话有常驻缓存，不会触发 prefix-skip。不压缩存放的 APK（GMS），以及字符串数据放在后部的 DEX（Chrome），结果都持平。ams 上 Douyin 40.8.0 的 56 个 DEX 跳过了 22 个。

**daemon**：本地 Linux，Douyin 40.7.0，`b3320c2`。

| 场景 | 不经 daemon | 经 daemon |
|---|---:|---:|
| 空缓存第一条查询 / 换一类的第二条 | 256 / 234 ms | 81 / 9 ms |
| `hierarchy android.app.Activity`（1343 行），首次 / 重复 | 433 / 408 ms | 326 / 6 ms |
| `callgraph WebView loadUrl --virtual`，首次 / 重复 | 425 / 398 ms | 22 / 5 ms |

macOS 上 `callgraph --virtual` 第一次调用：经 daemon 261 ms，本地 276 ms。

## 多 APK

**结论：规则集模式（一次扫描跑完全部规则）是多 APK 审计的正确用法，热缓存下比 dexsql 快约 5–10 倍，比 rust_ASC 快约 20 倍；只按「每条规则一次调用」测会大幅低估 asc-rs。**

**ams，836 个 APK（K80 416 个 + Xiaomi 17 420 个）× 8 条规则，3 次中位数：**

| 配置 | asc-rs `a23650e` | r1 `8b7a09e` |
|---|---:|---:|
| 每条规则一个 CLI 进程，P=16：不开缓存 / 冷 / 热 | 11.5 / 42.6 / 8.0 s | 12.0 / 42.7 / 8.1 s |
| 规则集，每个 APK 一个 CLI 进程：不开缓存 / 冷 / 热 | 1.54 / 7.17 / 1.06 s | 1.50 / 6.68 / 4.90 s |
| MCP 单进程规则集：不开缓存 / 冷 / 热 | 1.16 / 1.39 s（3.2 GB）/ 0.48 s（180 MB） | 1.26 / 1.18 s（12.2 GB）/ 1.13 s（7.2 GB） |
| MCP 规则集，N=4 / 8 / 16 个进程，冷 | 0.99 / 1.00 / 1.28 s | 0.94 / 0.98 / 1.61 s |
| MCP 规则集，N=4 / 8 / 16 个进程，热 | 0.24 / 0.23 / 0.53 s | 0.94 / 1.06 / 1.32 s |
| rust_ASC dev CLI，P=16 | 10.7 s / 1.8 GB | |
| dexsql，每个 APK 一个进程跑 8 条 SQL，P=16、T=2 | 2.4 s / 1.8 GB | |

- r1 的「热」规则集 CLI，每个进程峰值约 700 MB、进程树约 2 GB（新版是 14 MB / 64 MB），说明它其实在重新解压。原因没有查。
- big-machine 合入（`c1fc2da`）后，自动线程下的规则集复测见[缓存、内存与多进程](#缓存内存与多进程)。

**本地 Linux，Pixel 6 的 312 个系统 APK（3.8 GB）× 8 条规则：**

| 配置 | asc-rs | 对照 |
|---|---:|---:|
| MCP 单进程，空缓存 / 缓存已建好 | 393 ms / 179 ms，124 MB（rust_ASC 对比时测，16 线程）；`integrate/plan` 合入时测为 428 ms（1.49 GB）/ 144 ms（122 MB） | main `3a1e5cd`：683–842 ms，1.75 GB |
| CLI，16 个进程，不开缓存 / 热缓存 | 1188 ms / 688 ms，每进程 21 MB（rust_ASC 对比时测）；`integrate/plan` 合入时测为 525 ms | main `3a1e5cd`：949 ms，每进程 108 MB；rust_ASC dev CLI 2946 ms，每进程 219 MB |
| rust_ASC dev MCP | — | 3138 ms，进程树 4.6 GB（它的 MCP 每次调用都起一个 CLI 进程） |

## 缓存、内存与多进程

**结论：冷扫的内存现在有上限，冷扫之后 L1 基本完整；macOS 上的进程注册表、去重的 SHA-256 和写盘同步这几个问题都已修好。剩下的问题是突发扫描时自动线程不收缩，以及多进程合计内存的来源还没查清。**

| 改动 | 现象 | 做法 | 实测（ams，836 个 APK，除非另注） |
|---|---|---|---|
| 写盘队列有界 | 旧版（r1 也一样）一个 MCP 进程冷扫 416 个 APK，4 s 内涨到 28–44 GB，缓存目录 8.6 GB，是预算的两倍 | `4d701d8`：排队写入超过 512 MiB 就丢弃新的写入；写入期间也做淘汰 | 每条规则调用一次的冷扫：从超过 30 GB 被强制终止，变为 6.5 s / 5.2 GB；规则集 1.4 s / 3.2 GB |
| 超限时延后写入，不再丢弃 | 上面的丢弃让冷扫后 L1 很不完整，热跑只能靠 L3 | `db29fc6`：超限的 L1 写入只记下是哪个条目，由写盘线程之后从 APK 重新解压再写；写盘线程按 CPU 数 1–4 个 | 冷扫后 L1 从 86 个文件 / 1.2 GB 增至 866 个 / 7.4 GB；之后对 30 个最重的 APK 各跑一次 CLI，合计 1873 → 909 ms。代价：冷扫回答 1452 → 1541 ms，到进程退出 2489 → 3867 ms；峰值 RSS 3403 → 3090 MB |
| 写盘与预建降优先级 | 上面多出来的重新解压会和查询抢 CPU | `7a6123d`：Linux nice 19，Apple 用 utility QoS | Linux 上确认写盘线程 nice 为 19。macOS 上对争用的实际影响**未测** |
| aarch64 硬件 SHA-256 | 跨 APK 去重时的 SHA-256 是采样第一的热点，两台手机的系统 APK 大量重复 | `a23650e`：aarch64 上开启 sha2 的 `asm` | 规则集冷跑 2055 → 1713 ms（r1 1732 ms，交替 5 轮） |
| 写缓存去掉 fsync | macOS 上 `sync_data` 实际是 `F_FULLFSYNC`：每个 8 MiB 文件 9.8 ms，普通 fsync 2.0 ms | 不再 fsync；文件带 CRC，重启之前写入的文件在读取时校验一次 | ams 上用临时去掉同步的构建测：每条规则一个进程冷跑 52.7 → 21.1 s，规则集冷跑 8.0 → 4.0 s；合入版本在 macOS 上**未正式测**。本地 Linux 见下表 |
| 进程注册表在 macOS 生效 | 注册表原来只在 Linux 上实现，macOS 上一直没有登记，内存预算和线程都没有按进程分摊 | `c1fc2da`（big-machine） | N=16 冷扫时，登记从 0 个变为 16 个；扫描期间一次性查询的 worker 从 32 个降到 7 个 |

**no-fsync，本地 Linux（ext4 / NVMe，5 次中位数，交替跑）**，脚本 [`cache/nofsync_bench.py`](deterministic/cache/nofsync_bench.py)：

| 场景 | `a23650e` | no-fsync |
|---|---:|---:|
| Douyin 冷缓存单条查询（写约 380 MB） | 447 ms | 180 ms |
| Douyin 热缓存 | 12 ms | 8 ms |
| Douyin 重启后第一次 / 第二次查询 | 7 / 6 ms | 20 / 6 ms |
| 312 个 Pixel APK 规则集冷跑，P=16 | 263 ms | 276 ms |

重启后第一次读取要多花 14–22 ms 算 CRC。Pixel 语料的 DEX 大多不写 L1，省不到 fsync，只多了 CRC 的开销。

**big-machine，ams，规则集，旧 `36ab1e2` 对新 `c1fc2da`，交替 3 次中位数**，驱动 [`deterministic/bm.sh`](deterministic/bm.sh)：

| N 个 MCP 进程（自动线程） | 冷：旧 → 新 | 热：旧 → 新 |
|---|---:|---:|
| 1 | 1436 → 1454 ms | 509 → 500 ms |
| 4 | 929 → 907 ms | 703 → 267 ms |
| 8 | 868 → 880 ms | 2956 → 244 ms |
| 16 | 1086 → 1128 ms | 964 → 251 ms |

- 冷跑新旧持平，差异在 ±4% 以内。
- 旧版热跑的慢值不可靠：N=8 时重跑，旧版自动线程是 249–311 ms，新版 233–284 ms。所以热跑**不算** big-machine 的确定收益。
- N=16 冷跑时固定每进程线程数：2 / 4 / 8 / 32 线程分别为 1263 / 951 / 1053 / 1136 ms，自动线程 1128 ms。说明每进程线程太少会出现长尾。但扫描只有约 1 s，而注册表最多每秒读一次，各进程还来不及看到彼此忙碌，自动线程没有收缩。
- 磁盘自动上限 32 GiB：在这次验证时，大部分 L1 写入被 512 MiB 队列上限丢掉，没有碰到上限。延后写入之后冷扫写了 7.4 GB，仍在上限之内。

**内存峰值**：N=16 个 MCP 进程冷跑，新旧版合计都约 21 GB，每进程约 2 GB。主要是解压中的数据和映射页，不是内存缓存，具体来源还没查清。另外 macOS 的 `ps` RSS 包含映射的文件页。

## agent 评测（grok-4.7）

**结论：超长输出写到文件、由 agent 按需 grep，是最省 token 的设计。新版每个目标的 token 约为 dexsql 的 1/4、r1 的 1/3，证据持平。多 APK 问题上，droidasc 的 token 只有 dexsql 的约 1/46，两边答案都全对。**

**S1：ams，Douyin 40.8.0，17 个目标 × 2 次，每组只接一个工具**

| 组 | MCP 调用/目标 | 失败调用 | token/目标 | $/目标 | 耗时 | 证据 | 总费用 |
|---|---:|---:|---:|---:|---:|---:|---:|
| asc-rs `a23650e`，MCP + 读文件，超长时写文件 | 11.0 | 5 | 207k | 0.071 | 83 s | 92/100 | $3.28 |
| asc-rs `a23650e`，只 MCP，超长时分页（`--spill-mb 0`） | 24.5 | 15 | 379k | 0.119 | 116 s | 92/100 | $4.08 |
| r1 `8b7a09e`，只 MCP | 25.0 | 63 | 578k | 0.162 | 136 s | 86/100 | $7.69 |
| dexsql，MCP + 读文件 | 42.5 | 68 | 785k | 0.201 | 162 s | 92/100 | $9.04 |

- 分页组对比 r1：token 少 34%，失败调用从 63 次降到 15 次。r1 在 manifest_exported_components 上 0/3，原因是单 APK 的 manifest 摘要被 grok 截断（约 20 KB），又没有办法翻页；新版这一项满分。
- 写文件组对比分页组：token 再少 45%，调用数减半。写文件组的 agent 确实用了 read_file 和 grep 去读写出来的文件。
- 对照，本地 Linux、Douyin 40.7.0，同样 17 个目标 × 2 次，只接 MCP：r1 26.5 次调用、610k token、$0.167、112 s、证据 86/100，其中 78 次失败里有 58 次是 getclass 方法签名的写法不被接受，922 次返回里有 165 次超过 20 KB；dexsql 38 次调用、659k token、$0.173、105 s、92/100。r1 在两台机器、两个 Douyin 版本上的结果几乎一样，说明换机器、换版本没有带来明显偏差。

**S2：ams，K80 的 416 个 APK，4 个「哪些 APK 调用了某 API」目标 × 1 次**

参考答案先由 droidasc 生成，再用 dexsql 独立交叉核对。四个目标里三个完全一致；剩下一个差异来自 com.android.bluetooth，它只调用了 `sendTextMessageWithoutPersisting`，droidasc 的方法名是模糊匹配所以命中了它，这里记为可选项。

| 工具 | 召回 | 准确 | 调用/目标（全部工具） | token/目标 | $/目标 | 耗时 | 总费用 |
|---|---:|---:|---:|---:|---:|---:|---:|
| asc-rs `a23650e`，MCP + 读文件 | 1.00 | 1.00 | 6 | 104k | 0.039 | 74 s | $0.16 |
| dexsql，MCP + 读文件 | 1.00 | 1.00 | 110 | 4815k | 1.225 | 716 s | $5.86 |

dexsql 每个 dataset 最多 64 个输入，只能分批打开、逐批写 SQL。

**失败调用回放：本地 Linux，Douyin 40.7.0**

把 agent 评测里全部 92 次失败的 droidasc 调用，在同一个 MCP 会话里重放。另有 12 次是客户端调用了不存在的工具，已去掉。

| 版本 | 成功 | 报错但有可操作提示 | 报错且无提示 |
|---|---:|---:|---:|
| `f344edf`（统一查询语法之前） | 46 | 31 | 15 |
| 统一查询语法、宽松参数、可操作报错之后 | 49 | 43 | 0 |

「有可操作提示」用 `cli-native/replay.py` 里的正则判定，两个版本用同一个正则。

## 已知局限与未测项

- **agent 评测**：
  - 只测了 grok-4.7 一个模型，结论不一定适用于其他模型。
  - S1 的证据指标已经饱和：各组都缺同样 8 条证据，就是 40.7.0 写死的混淆名。
  - S2 每个目标只跑 1 次。
  - S1 的第 3 次重复只跑完 18 次，没有计入。
  - 14 路并发会被限流，被限流的那批已全部丢弃，正式结果是 4 路并发、带退避重试跑的。
  - S2 的 dexsql 组运行时，ams 上同时在跑基准，耗时略受影响。
- **失败调用回放**：S1 第二组调用原本是在 40.8.0 上发出的，这里在 40.7.0 上重放，部分混淆类名对不上。所以这部分只能说明「找不到时的提示质量」，不代表在原版本上会成功。
- **S1 回放**：回放脚本写死了 40.7.0 的混淆名，在 40.8.0 上每个工具都会缺证据；dexsql 写死的 method id 在 40.8.0 上会报错。
- **ams 是共享机器**：有异常值的配置都交替重跑过，旧版热跑的个别慢值不可靠。
- **未测**：
  - 合入的 no-fsync 版本在 macOS 上的正式前后对比。
  - macOS 上降优先级对写盘与查询争用的影响。
  - big-machine 合入后自动线程在长时间负载下的收缩。
  - N=16 时合计约 21 GB 内存的具体来源。
  - 修改输出格式之后，用 rust_ASC 对比脚本重跑。
- **无法复现**：
  - 资源对比里 6 个第三方 APK（快手、美团、拼多多、淘宝两个版本、小红书）当时没有记录版本，APK 也已不在本地。
  - daemon 单条查询的计时脚本没有保留；47 步回放可以用 `DROIDASC_DAEMON=auto` 跑 `deterministic/s1.py` 复现。
  - 本地的 47 步回放只保留了最后一次的结果（81 ms 那次）。

## 复现

| 问题 | 脚本 |
|---|---|
| 语料、版本、拉取、清单 | [corpus.md](corpus.md)、[corpus/](corpus/)（`pull.sh`、`manifest.py`） |
| 单 APK 47 步回放、多 APK 矩阵、prefix-skip、缓存一致性、no-fsync、big-machine、rust_ASC 与 dexsql 对照 | [deterministic/README.md](deterministic/README.md) |
| 本地 MCP 47 步回放（早期脚本） | [agent-audit/replay_mcp.py](agent-audit/replay_mcp.py) |
| 本地多 APK 暴露面审计与规则集（早期脚本） | [multi-apk/](multi-apk/)（`audit.py`、`rules.py`） |
| 与 Python 上游语义对比 | [parity/semantic.py](parity/semantic.py) |
| 资源与 aapt2 对比 | [arsc-compare/compare.py](arsc-compare/compare.py) |
| agent 评测（S1、S2 的 runner、参考答案、打分、指标提取） | [agent/README.md](agent/README.md) |
| 失败调用回放 | [cli-native/README.md](cli-native/README.md) |
