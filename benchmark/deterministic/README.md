# 确定性评测

> 结果文件（`results/`、`*.tsv`、`s2/ref-k80.json`）不入库，保存在本地 `target/benchmark-data/benchmark/`，见 [benchmark/README.md](../README.md)。

结论见 [../README.md](../README.md)。脚本都只用 Python 3.9 标准库（macOS 自带的是 3.9），Linux 和 macOS 都能跑。

- **内存**：峰值 RSS 用 `wait4` 取单个进程的值，或者每 50 ms 轮询一次 `ps -axo pid,ppid,rss` 汇总整棵进程树（`common.py` 的 `TreeSampler`）。注意 macOS 的 RSS 包含映射的文件页。
- **daemon**：脚本默认设 `DROIDASC_DAEMON=off`。新版 droidasc 默认会把一次性命令转发给 daemon，要测 daemon 就显式设成 `auto`。

## 环境

| 变量 | 默认 | 含义 |
|---|---|---|
| `HARNESS` | `~/asc-eval/harness/dexsql-release/benchmarks/agent-audit/harness` | dexsql-release harness 目录（`rasc_replay.py` 的 `SCENARIOS`） |
| `CORPUS_BASE`、`CORPUS` | `~/asc-eval/apks`、`k80:mi17` | S2 语料目录；`CORPUS` 用冒号分隔，相对路径相对于 `CORPUS_BASE` |
| `BENCH_TMP` | `/private/tmp/asc-bench` | 缓存和切片目录（每次冷跑前清空） |
| `ASC_EVAL` | `~/asc-eval` | 驱动脚本（`*.sh`）使用的目录布局：`src/`（本仓库，已 release 编译）、`bin/droidasc-r1`、`bin/dexsql`、`apks/{k80,mi17}`、`rust_ASC/`、`results/` |
| `AUTO`、`THREADS` | — | `s2.py` 的 MCP 模式：`AUTO=1` 不传 `--threads`（自动线程）；`THREADS=n` 固定每个进程的线程数；都不设时每进程 `CPU 数 / N` |
| `TRIALS`、`VERSIONS` | 各脚本不同 | 驱动脚本的重复次数，以及要跑的版本（`new old`） |

## 脚本

| 脚本 | 对应结论 | 用法 |
|---|---|---|
| `s1.py` | S1 47 步回放：droidasc CLI / MCP，以及 rust_ASC CLI / MCP | `s1.py FLAVOR BIN APK TRIALS OUT.json [droidasc 全局参数]`，FLAVOR ∈ `asc-cli asc-mcp asc-mcp-hot rust-cli rust-mcp` |
| `s1_same.py` | S1 新旧版输出一致（行集合、getclass 文本） | `s1_same.py NEW.json OLD.json` |
| `s2.py` | S2 836 个 APK × 8 条规则：每条规则一个进程、规则集、MCP N 个进程、rust_ASC | `s2.py MODE BIN OUT.json ARGS… [-- 全局参数]`，MODE ∈ `cli clirules mcp mcprules rust` |
| `s2_cmp.py` | 两次 S2 运行的命中 APK 集合比较（需要 `hits`，结果目录里的副本已去掉该字段，要重新跑） | `s2_cmp.py A.json B.json` |
| `dexsql_s2.py` | S2 的 dexsql 对照（8 条规则写成等价 SQL） | `dexsql_s2.py DEXSQL OUT.json K P T`（K 个输入一个 dataset，P 个进程，每进程 T 线程） |
| `dexsql_replay.patch` | S1 的 dexsql MCP 计时：在 dexsql-release 的 `dexsql_replay.py` 上打的补丁（decode 失败时记录、不中断，40.7.0 写死的 method id 在 40.8.0 上会失败；线程候选、次数可配） | 在 harness 目录 `patch -p0 < dexsql_replay.patch` 后运行 |
| `aggregate.py` | 结果目录 → 每个配置的中位数表 | `aggregate.py RESULTS_DIR` |
| `guard.sh` | 任意 droidasc 进程超过内存上限就终止整棵进程树（写盘队列 bug 曾让单进程涨到 40 GB 以上） | `guard.sh LIMIT_MB CMD…` |
| `rsswrap.py` | 记录一个命令整棵进程树的峰值 RSS | `rsswrap.py OUT.txt CMD…` |
| `s1_all.sh`、`s2_all.sh`、`s2_rules.sh`、`s2_rest.sh` | Mac 上的完整矩阵（S1；S2 每条规则一次；S2 规则集；rust_ASC 与 dexsql） | 在上面的 `ASC_EVAL` 布局下 `zsh s2_rules.sh` |
| `bm.sh` | big-machine 验证：自动线程 N=1/4/8/16 冷热、N=16 固定线程、磁盘上限、S1 回归，新旧版交替 | 需要 `src-r2/`、`src-bm/` 两个编译好的版本 |
| `prefix_skip.py` | prefix-skip：一次性冷查询的墙钟中位数和峰值 RSS | `prefix_skip.py APK N BIN… -- QUERY ; QUERY …` |
| `cache/consistency.py` | 缓存一致性：40 个随机 APK × 9 条查询，冷缓存、热缓存与 `--no-cache` 逐块比较 | `consistency.py DROIDASC CORPUS_DIR CACHE_DIR` |
| `cache/nofsync_bench.py` | no-fsync 计时：冷、热、模拟重启后 | `nofsync_bench.py BASE NEW DOUYIN CORPUS_DIR CACHE_ROOT TRIALS` |
| `cache/nofsync_check.sh` | no-fsync 正确性：新鲜、重启前写入、L1 文件被损坏三种情况下，结果都与 `--no-cache` 相同 | `nofsync_check.sh BASE NEW APK CACHE_DIR` |
| `rust-asc/cmp.py` | rust_ASC 对比：findrefs 行的语义比较（rust_ASC CLI 文本 vs droidasc MCP JSON） | `cmp.py RUST_ASC DROIDASC APK [kind…]` |
| `rust-asc/s2diff.py` | rust_ASC 对比：8 条规则在一个语料目录上的 APK 级差异（发现上游字符串索引 bug 的脚本） | `s2diff.py RUST_ASC DROIDASC CORPUS_DIR` |

`rust-asc/` 下的两个脚本写于输出格式改动之前。之后 droidasc 的文本格式和 MCP 默认值都变了（compact structuredContent、16 KiB 预算），所以 `cmp.py` 现在显式请求 `--structured full`、`max_bytes` 和 `spill: never`。改动之后**没有**再对 rust_ASC 跑过。

## 结果（`results/`）

| 目录 | 内容 |
|---|---|
| `round2/` | Mac 上的 S1 / S2 矩阵（`s1-*`、`s2-*` 每条规则一次、`s2r-*` 规则集、`s2-dexsql*`、`s2-rust-cli*`），`summary.md` 是汇总表，`*.log` 是运行日志（含每次冷跑后的缓存大小）；`pre-sha/` 是 sha2 asm 修复之前新版的数据 |
| `round2-bm/` | big-machine 验证：`auto-*`、`fixed-*`、`cap-*`、`diag-*`（N=8 热跑的重测）、`s1-*`；`summary.md` 和 `bm.log`（含 load） |

结果 JSON 去掉了 S1 的逐步输出（`outputs`，含 Douyin 的 smali）和 S2 的逐 APK 命中（`hits`），其余字段保留。完整版本保存在 Mac 测试机上。
