# 确定性评测

结论见 [../README.md](../README.md)。脚本只用 Python 3.9 标准库，Linux 与 macOS 都能跑。峰值 RSS 用 `wait4` 取单进程值，或由 `common.py` 的 `TreeSampler` 每 50 ms 汇总进程树（macOS 的 RSS 含映射文件页）。脚本默认 `DROIDASC_DAEMON=off`，测 daemon 时设 `auto`。

## 环境变量

| 变量 | 默认 | 含义 |
|---|---|---|
| `HARNESS` | `~/asc-eval/harness/dexsql-release/benchmarks/agent-audit/harness` | dexsql-release harness（`SCENARIOS`） |
| `CORPUS_BASE`、`CORPUS` | `~/asc-eval/apks`、`k80:mi17` | S2 语料；`CORPUS` 冒号分隔，相对 `CORPUS_BASE` |
| `BENCH_TMP` | `/private/tmp/asc-bench` | 缓存与切片目录，冷跑前清空 |
| `ASC_EVAL` | `~/asc-eval` | `*.sh` 的目录布局：`src/`（已编译）、`bin/droidasc-r1`、`bin/dexsql`、`apks/`、`rust_ASC/`、`results/` |
| `AUTO`、`THREADS` | — | `s2.py` MCP 模式：`AUTO=1` 用自动线程；`THREADS=n` 固定；都不设为 `CPU / N` |
| `IDLE`、`RULES` | — | `s2.py` MCP 模式：先空闲 S 秒再调用；只跑这几条规则（下标） |
| `TRIALS`、`VERSIONS` | 各脚本不同 | 重复次数；要跑的版本 |

## 脚本

| 脚本 | 用途 | 用法 |
|---|---|---|
| `s1.py` | 47 步回放：droidasc / rust_ASC 的 CLI 与 MCP | `s1.py FLAVOR BIN APK TRIALS OUT.json [全局参数]`，FLAVOR ∈ `asc-cli asc-mcp asc-mcp-hot rust-cli rust-mcp` |
| `s1_same.py` | 两版 47 步输出一致性 | `s1_same.py NEW.json OLD.json` |
| `s2.py` | 多 APK × 8 规则 | `s2.py MODE BIN OUT.json ARGS… [-- 全局参数]`，MODE ∈ `cli clirules mcp mcprules rust` |
| `s2_cmp.py` | 两次 S2 的命中 APK 集合比较（需 `hits`） | `s2_cmp.py A.json B.json` |
| `dexsql_s2.py` | dexsql 对照（8 规则写成 SQL） | `dexsql_s2.py DEXSQL OUT.json K P T` |
| `dexsql_replay.patch` | dexsql MCP 计时补丁（decode 失败记录而不中断） | harness 目录下 `patch -p0 <` |
| `aggregate.py` | 结果目录 → 中位数表 | `aggregate.py RESULTS_DIR` |
| `guard.sh` | 任一 droidasc 超内存上限就杀进程树 | `guard.sh LIMIT_MB CMD…` |
| `rsswrap.py` | 记录命令进程树峰值 RSS | `rsswrap.py OUT.txt CMD…` |
| `s1_all.sh`、`s2_all.sh`、`s2_rules.sh`、`s2_rest.sh` | 完整矩阵（S1；每规则一次；规则集；rust_ASC 与 dexsql） | `ASC_EVAL` 布局下 `zsh s2_rules.sh` |
| `bm.sh` | 多进程自动线程、固定线程、磁盘上限，新旧版交替 | 需要 `src-r2/`、`src-bm/` |
| `prefix_skip.py` | 一次性冷查询的耗时与 RSS | `prefix_skip.py APK N BIN… -- QUERY ; QUERY …` |
| `cache/consistency.py` | 冷 / 热 / `--no-cache` 结果比较 | `consistency.py DROIDASC CORPUS_DIR CACHE_DIR` |
| `cache/nofsync_bench.py` | no-fsync 计时 | `nofsync_bench.py BASE NEW DOUYIN CORPUS_DIR CACHE_ROOT TRIALS` |
| `cache/nofsync_check.sh` | 新鲜 / 重启前写入 / 损坏时结果与 `--no-cache` 相同 | `nofsync_check.sh BASE NEW APK CACHE_DIR` |
| `cache/after_scan.py` | 冷扫后紧接的查询延迟 | `after_scan.py DROIDASC CORPUS_DIR DOUYIN OUT.json [--cache-dir C]` |
| `mem/footprint.py` | 包住 `s2.py`，采样 RSS 与 macOS `footprint` | `AUTO=1 footprint.py OUT.mem.json 0.3 python3 s2.py mcprules DROIDASC OUT.json 16 -- --cache-dir C` |
| `rust-asc/cmp.py` | findrefs 行与 rust_ASC 的语义比较 | `cmp.py RUST_ASC DROIDASC APK [kind…]` |
| `rust-asc/s2diff.py` | 8 规则在语料目录上与 rust_ASC 的 APK 级差异 | `s2diff.py RUST_ASC DROIDASC CORPUS_DIR` |

`rust-asc/` 写于输出格式改动之前，`cmp.py` 现显式请求 `--structured full`、`max_bytes`、`spill: never`；之后未再对 rust_ASC 跑过。结果目录 `results/round2/`（S1 / S2 矩阵）、`results/round2-bm/`（多进程验证）、`results/burst/`、`results/dmem/`，JSON 已去掉逐步输出和逐 APK 命中。
