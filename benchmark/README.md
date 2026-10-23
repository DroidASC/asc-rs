# 评测

按问题组织的实测结论。两类评测：

- **确定性**：脚本回放固定步骤或规则，测耗时、内存和结果一致性，可重复。
- **agent**：grok headless 只接一个工具完成分析目标，测调用、token、费用与正确性。只测过 grok-4.7，2026-10-23 起不再做。

旧版本与对照工具（Python ASC、rust_ASC、dexsql）作对照列；不同机器的数字分表。结果文件（`results/`、`*.tsv`、`agent/s2/ref-k80.json`）不入库，放在本地 `target/benchmark-data/benchmark/`，目录结构与这里相同。

## 总览

| 问题 | 结论 | 关键数字 |
|---|---|---|
| [结果对不对](#正确性) | 与 Python ASC、dexdump 语义一致；资源与 aapt2 一致 | 语义差异 0；1094 万个资源取值只差 4 处 |
| [单 APK](#单-apkdouyin47-步) | 常驻进程最快；CLI 冷查询靠 prefix-skip | Douyin 47 步：MCP 热 61 ms，CLI 不开缓存 2065 ms（r1 2649，rust_ASC 2528） |
| [多 APK](#多-apk) | 规则集模式一次扫完全部规则 | 836 APK × 8 规则：MCP 热 0.48 s，4–8 进程 0.23 s；dexsql 2.4 s，rust_ASC 10.7 s |
| [内存与多进程](#缓存内存与多进程) | 冷扫内存有界、L1 完整；空闲后突发扫描线程会收缩 | 冷扫从 >30 GB 被杀降到 3.1 GB；N=16 空闲后热扫 4148 → 695 ms |
| [agent](#agent-评测grok-47) | 超长输出写文件最省 token | S1 每目标 207k token（dexsql 785k，r1 578k）；S2 104k（dexsql 4.8M），都全对 |
| [报错](#失败调用回放) | 失败调用都变成成功或带下一步提示 | 92 次历史失败中无提示的 15 → 0 |

## 环境与版本

| | |
|---|---|
| 本地 | Ryzen 7 8745H（16 线程），12 GB，Arch Linux 7.2.11，ext4 / NVMe |
| Mac | M3 Ultra（32 核），96 GB，macOS 15.7.3。多人共用，load 4–30，异常值都交替重跑过 |
| asc-rs | 各表注明 commit；r1 = `8b7a09e`（旧版对照）；agent 评测用 `a23650e` |
| Python ASC | MG1937/ASC `9216fe2` |
| rust_ASC | MG1937/rust_ASC dev `6db7135`，main `236dd09` |
| dexsql | 0.1.1（LSPosed/dexsql-release），darwin-arm64 sha256 `d983de33…2a77`；harness `3ac6fb1`（MIT），S1 的 17 个目标取自 `rasc_replay.py`，运行时经 `HARNESS` 导入 |
| grok | CLI 1.0.67，grok-4.7-build，headless |
| 语料 | [corpus.md](corpus.md) |

## 正确性

| 检查 | 方法 | 结果 |
|---|---|---|
| 与 Python ASC | 解析成（dex，方法，命中集合）比较，[`parity/semantic.py`](parity/semantic.py) | 差异 0 |
| 与 dexdump | 312 个 Pixel 系统 APK × 8 规则，[`deterministic/rust-asc/`](deterministic/rust-asc/) | 一致；Python ASC 与 rust_ASC 在 24 个（APK，规则）上出错，见下 |
| 资源 | 419 APK、1094 万取值对比 `aapt2 dump resources`，[`arsc-compare/`](arsc-compare/compare.py) | 差 4 处，都是 aapt2 文本无法拆分的带样式字符串 |
| 开关缓存 | 40 APK × 9 查询，冷 / 热 / `--no-cache` 比较，[`cache/consistency.py`](deterministic/cache/consistency.py) | 一致 |
| 新旧版本 | Douyin 47 步对 r1，[`s1_same.py`](deterministic/s1_same.py)；836 APK × 8 规则，[`s2_cmp.py`](deterministic/s2_cmp.py) | 完全相同 |
| APK 级命中 | 836 APK × 8 规则对照 | 与 rust_ASC 全同；与 dexsql 7 条同，password 规则 dexsql 多 4 个（其 `LIKE` 不分大小写） |
| 开关 daemon | `crates/asc-cli/tests/daemon.rs`，26 种命令 | stdout、stderr、退出码逐字节相同 |
| 缓存文件损坏 | 清零、翻字节、截断，[`nofsync_check.sh`](deterministic/cache/nofsync_check.sh) | 全部检出并重写 |

**对照工具的字符串下标 bug**（[MG1937/ASC#54](https://github.com/MG1937/ASC/issues/54)、[MG1937/rust_ASC#8](https://github.com/MG1937/rust_ASC/issues/8)）：它们假设 string_data 按 string_ids 顺序连续存放；布局优化过的系统 APK（如 dialer、GoogleCamera）不满足，会漏报并把命中对到别的字符串。例：`getDeviceId` 误中 `Display.getDeviceProductInfo`，漏掉 14 处 `MotionEvent.getDeviceId`。

## 单 APK（Douyin，47 步）

dexsql-release 的 17 个目标共 47 步，5 次中位数，耗时 / 峰值 RSS。

**Mac，Douyin 40.8.0**

| 配置 | asc-rs `0e08806` | r1 | rust_ASC dev | dexsql |
|---|---:|---:|---:|---:|
| CLI，不开缓存 | 2065 ms / 352 MB | 2649 ms / 504 MB | 2528 ms / 362 MB | — |
| CLI，磁盘缓存热 | 317 ms / 19 MB | 307 ms / 19 MB | — | — |
| MCP，不开缓存 | 134 ms / 643 MB | 137 ms / 643 MB | 2691 ms / 354 MB | 约 722 ms，2.4 GB |
| MCP，磁盘缓存 | 61 ms / 103 MB | 61 ms / 107 MB | — | — |

回放写死了 40.7.0 的混淆名，各工具在 40.8.0 上都缺 13–14 个证据（droidasc 各配置缺得相同）；dexsql 写死的 method id 有 18 次报错，只作计时参考。

**本地 Linux，Douyin 40.7.0**

| 配置 | asc-rs | 对照 |
|---|---:|---:|
| CLI，不开缓存 | 2212 ms | `79f01d9`（prefix-skip 前）2724 ms；rust_ASC dev 2586 ms |
| CLI，缓存热 | 176 ms；经 daemon 135 ms | — |
| MCP | 55 ms | dexsql 1112 ms；rust_ASC dev 2357 ms |

**prefix-skip**（一次性冷查询先只解 DEX 前缀，跳过不可能命中的 DEX；本地，`--no-cache`，[`prefix_skip.py`](deterministic/prefix_skip.py)）

| 查询 | 之前 | 之后 |
|---|---:|---:|
| `method exec --class java.lang.Runtime` | 77 ms / 328 MB | 57 ms / 201 MB（55 个 DEX 跳过 37） |
| `type DexClassLoader` | 72 ms | 54 ms |
| `string ttdownloaderClickId` | 71 ms | 47 ms |
| `field SDK_INT`、`string http://` | 95 / 92 ms | 97 / 92 ms |

**签名选重载走 prefix-skip**（本地，`--no-cache`，3 次中位数，[`sig_prefix.py`](deterministic/sig_prefix.py)）：Douyin 40.7.0 与 4 个 Pixel 大 APK 上，带签名的结果与「只写名字的结果按签名收窄」逐行相同，CLI 与 MCP 常驻路径（不探测）相同；Dalvik、只写参数、Java 三种写法一致。Douyin 上 `getDeviceId()` 63 ms（跳过 38 个 DEX，与只写名字相同）；不存在的重载 `getDeviceId(I)`、`valueOf(UUID)` 跳过 39 个，零结果提示列出已有重载，94–96 ms（提示改为读前缀前约 133 ms）。Pixel 的 APK 字符串数据在后部，不探测。

**daemon**（本地，`b3320c2`）

| 场景 | 不经 daemon | 经 daemon |
|---|---:|---:|
| 空缓存首条 / 换一类的第二条 | 256 / 234 ms | 81 / 9 ms |
| `hierarchy android.app.Activity` 首次 / 重复 | 433 / 408 ms | 326 / 6 ms |
| `callgraph … --virtual` 首次 / 重复 | 425 / 398 ms | 22 / 5 ms |

## 多 APK

**Mac，836 个 APK（K80 416 + Xiaomi 17 420）× 8 规则，3 次中位数**

| 配置 | asc-rs `a23650e` | r1 |
|---|---:|---:|
| 每条规则一个 CLI 进程，P=16：不开缓存 / 冷 / 热 | 11.5 / 42.6 / 8.0 s | 12.0 / 42.7 / 8.1 s |
| 规则集，每 APK 一个 CLI 进程：不开缓存 / 冷 / 热 | 1.54 / 7.17 / 1.06 s | 1.50 / 6.68 / 4.90 s |
| MCP 单进程规则集：不开缓存 / 冷 / 热 | 1.16 / 1.39 s（3.2 GB）/ 0.48 s（180 MB） | 1.26 / 1.18 s（12.2 GB）/ 1.13 s |
| MCP 规则集 N=4 / 8 / 16，热 | 0.24 / 0.23 / 0.53 s | 0.94 / 1.06 / 1.32 s |
| rust_ASC dev CLI，P=16 | 10.7 s / 1.8 GB | |
| dexsql，P=16、T=2 | 2.4 s / 1.8 GB | |

只按「每条规则一次调用」测会大幅低估 asc-rs；规则集模式是多 APK 审计的用法。

**本地 Linux，Pixel 6 的 312 个系统 APK × 8 规则**

| 配置 | asc-rs | 对照 |
|---|---:|---:|
| MCP 单进程，空缓存 / 已建 | 393 / 179 ms | `3a1e5cd` 683–842 ms；rust_ASC dev MCP 3138 ms（4.6 GB） |
| CLI 16 进程，不开缓存 | 1188 ms | rust_ASC dev CLI 2946 ms |

## 缓存、内存与多进程

Mac，836 APK，除非另注。

| 改动 | 问题 | 效果 |
|---|---|---|
| 写盘队列有界（`4d701d8`） | 冷扫 416 APK 时单进程 4 s 涨到 28–44 GB | 每条规则一次冷扫：从 >30 GB 被杀到 6.5 s / 5.2 GB；规则集 1.4 s / 3.2 GB |
| 超限延后重新解压（`db29fc6`） | 丢弃写入使冷扫后 L1 不完整 | L1 86 → 866 个文件；之后 30 个最重 APK 的 CLI 合计 1873 → 909 ms。代价：冷扫 1452 → 1541 ms，退出 2489 → 3867 ms |
| aarch64 硬件 SHA-256（`a23650e`） | 去重的 SHA-256 是首要热点 | 规则集冷跑 2055 → 1713 ms |
| 去掉 fsync，文件带 CRC | macOS `sync_data` 是 `F_FULLFSYNC`，每 8 MiB 9.8 ms | 临时构建：每规则冷跑 52.7 → 21.1 s，规则集 8.0 → 4.0 s；本地见下表 |
| macOS 进程注册表（`c1fc2da`） | macOS 上未登记，预算与线程不分摊 | N=16 登记 0 → 16 个；一次性查询 worker 32 → 7 |
| 突发扫描线程收缩（`f3c4238`） | 忙碌只看 5 s 内更新，agent 调用间空闲后各进程都用满 32 CPU | 见下表 |
| 写盘队列按内存预算（`dc46cce`） | 512 MiB 上限不随进程数分摊 | `--memory-mb 64`、N=16：峰值 footprint 之和 10.1 → 4.1 GB，L1 不变；L2 写入多丢（约 2 → 0.3 GB），之后重建 |
| 写盘与预建降优先级（`7a6123d`） | 重新解压与查询抢 CPU | Linux nice 19；macOS 上测不出差别，保留 |

**no-fsync，本地 Linux，5 次中位数**（[`nofsync_bench.py`](deterministic/cache/nofsync_bench.py)）

| 场景 | 之前 | 之后 |
|---|---:|---:|
| Douyin 冷缓存单查询（写约 380 MB） | 447 ms | 180 ms |
| Douyin 热缓存 | 12 ms | 8 ms |
| 重启后第一次查询（CRC 校验） | 7 ms | 20 ms |
| 312 Pixel APK 规则集冷跑 | 263 ms | 276 ms |

**突发扫描，规则集，自动线程，`938a3dc` → `f3c4238`**（[`s2.py`](deterministic/s2.py) `AUTO=1`，空闲列加 `IDLE=7`）

| N 进程 | 冷 | 热 | 空闲 7 s 后热 |
|---|---:|---:|---:|
| 1 | 1362 → 1393 ms | 765 → 577 ms | 857 → 826 ms |
| 4 | 929 → 918 ms | 220 → 222 ms | 693 → 709 ms |
| 8 | 881 → 887 ms | 371 → 222 ms | **3336 → 683 ms** |
| 16 | 924 → 896 ms | 226 → 669 ms | **4148 → 695 ms** |
| 16，固定 4 / 8 线程 | 933 / 881 ms | 220 / 308 ms | 689 / 626 ms |

「热」列是噪声：这台机器热跑在约 220 与约 650 ms 两档间随机跳，固定线程也一样。读一次注册表约 1.1 ms，写约 0.2 ms。

**内存，N=16 MCP 进程冷扫**（[`mem/footprint.py`](deterministic/mem/footprint.py)）

| 配置 | `ps` RSS 合计 | 峰值 footprint 之和 |
|---|---:|---:|
| 默认 | 22.3 GB | 12.4 GB |
| `--no-cache` | 13.9 GB | 11.4 GB |
| `--memory-mb 64` | 12.6 GB | 10.0 GB |
| 两者都加 | 7.1 GB | 2.9 GB |

RSS 里约 10 GB 是映射 APK 与 L1 的干净文件页。真实堆主要是内存缓存（自动份额为可用内存的 1/4 按进程分，每进程约 700 MB），其余是解压中的数据和写盘队列（已按预算封顶）。

**macOS 降优先级**（冷扫后紧接 12 次单 APK + 12 次多 APK 查询，[`after_scan.py`](deterministic/cache/after_scan.py)）：多 APK 合计 8.7–8.9 s 对不降优先级 8.5–9.0 s，单 APK 75–92 对 68–80 ms，无可分辨差别。

**多 APK 扫描接 prefix-skip（未合入）**：8 条规则一起慢约 4–5%（`http://` 几乎每个 DEX 都命中），单条稀有规则最多快约 7%，且跳过的条目不进 L1。

## agent 评测（grok-4.7）

**S1：Mac，Douyin 40.8.0，17 个目标 × 2 次，每组只接一个工具**

| 组 | MCP 调用/目标 | 失败 | token/目标 | $/目标 | 耗时 | 证据 |
|---|---:|---:|---:|---:|---:|---:|
| asc-rs，MCP + 读文件，超长写文件 | 11.0 | 5 | 207k | 0.071 | 83 s | 92/100 |
| asc-rs，只 MCP，超长分页 | 24.5 | 15 | 379k | 0.119 | 116 s | 92/100 |
| r1，只 MCP | 25.0 | 63 | 578k | 0.162 | 136 s | 86/100 |
| dexsql，MCP + 读文件 | 42.5 | 68 | 785k | 0.201 | 162 s | 92/100 |

r1 在 manifest_exported_components 上 0/3：单 APK 的 manifest 摘要被 grok 截断（约 20 KB）且无法翻页。本地 Linux、40.7.0 上的 r1 与 dexsql 结果几乎相同，换机器、换版本没有明显偏差。

**S2：Mac，K80 的 416 个 APK，4 个「哪些 APK 调用了某 API」目标 × 1 次**

| 工具 | 召回 | 准确 | 调用/目标 | token/目标 | $/目标 | 耗时 |
|---|---:|---:|---:|---:|---:|---:|
| asc-rs，MCP + 读文件 | 1.00 | 1.00 | 6 | 104k | 0.039 | 74 s |
| dexsql，MCP + 读文件 | 1.00 | 1.00 | 110 | 4815k | 1.225 | 716 s |

参考答案由 droidasc 生成、dexsql 独立核对。dexsql 每个 dataset 最多 64 个输入，只能分批。

### 失败调用回放

agent 评测中 92 次失败的 droidasc 调用在同一 MCP 会话重放（本地，Douyin 40.7.0）：

| 版本 | 成功 | 报错带提示 | 报错无提示 |
|---|---:|---:|---:|
| `f344edf`（统一查询语法前） | 46 | 31 | 15 |
| 之后 | 49 | 43 | 0 |

## 已知局限

- agent 评测只用了一个模型；S1 证据已饱和（各组都缺 40.7.0 写死的 8 条）；S2 每目标 1 次。
- 回放脚本写死 40.7.0 的混淆名，40.8.0 上各工具都缺证据；失败调用回放的部分调用原本发自 40.8.0。
- Mac 是共享机器，个别热跑慢值不可靠。
- 未测：合入版 no-fsync 在 macOS 上的正式对比；小机器上降优先级的效果；输出格式改动后重跑 rust_ASC 对比。
- 资源对比的 6 个第三方 APK 版本未记录，已无法复现。

## 复现

| 内容 | 位置 |
|---|---|
| 语料与清单 | [corpus.md](corpus.md)、[corpus/](corpus/) |
| 单 / 多 APK、缓存、内存、对照工具 | [deterministic/](deterministic/README.md) |
| 早期 MCP 回放、多 APK 审计 | [agent-audit/](agent-audit/replay_mcp.py)、[multi-apk/](multi-apk/) |
| 语义对比、资源对比 | [parity/](parity/semantic.py)、[arsc-compare/](arsc-compare/compare.py) |
| agent 评测 | [agent/](agent/README.md) |
| 失败调用回放 | [cli-native/](cli-native/README.md) |
