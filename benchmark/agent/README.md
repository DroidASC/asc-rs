# agent 评测（grok headless）

> 结果文件（`results/`、`*.tsv`、`s2/ref-k80.json`）不入库，保存在本地 `target/benchmark-data/benchmark/` 和 ams `~/asc-eval/results/benchmark-data/benchmark/`，见 [benchmark/README.md](../README.md)。

结论见 [../README.md](../README.md)。这里记录当时的做法，便于复现或查验。2026-10-23 起不再做新的 agent 评测。

## 做法

- **agent**：grok CLI 1.0.67，模型 grok-4.7-build，headless 模式，每个目标一个新会话：

  ```
  grok -p PROMPT --trust --disallowed-tools LIST --no-subagents --no-plan --disable-web-search \
       --always-approve --output-format streaming-json
  ```

  `--trust` 必须加：headless 模式下不受信任的目录不会启动项目级 MCP 服务器。
- **每组只接一个工具**：每组一个工作区目录 `ws-<组名>/`，用 `grok mcp add -s project` 只配置一个 MCP 服务器。二进制和 APK 用硬链接放进工作区，因为 Linux 的 `--sandbox strict` 不允许执行工作区之外的程序。
- **禁用其他能力**：`--disallowed-tools` 列出 shell、编辑、写文件、子 agent、调度、生图等全部内置工具，完整列表见 `s1/run.py` 的 `DIS`。「+ 读文件」的组额外放开 `read_file`、`grep`、`list_dir`，用来读工具写出的超长结果文件。
- **防止读到答案**：grok 把历次会话的工具输出存在 `~/.grok/sessions/`，所以：
  - Linux：`--sandbox strict`，并 `--deny Read(~/.grok/**)`、`--deny Grep(~/.grok/**)`。
  - macOS（ams）：strict 沙箱起不来（docker.sock 的符号链接问题），于是把工作区放在 `/Users` 之外的 `/private/tmp/asc-grok/`，并 `--deny Read/Grep(/Users/**)`、`--deny Read/Grep(/Volumes/**)`。
- **限流**：14 路并发一分钟内就会被限流（`rate_limit_error`）。正式结果是 4 路并发跑的（两批 runner 各 2 路）。runner 遇到限流会退避重试，每次运行的 `attempts` 列记录了尝试次数。被限流污染的那批结果已全部丢弃。

## S1：Douyin 单 APK，17 个目标（[`s1/`](s1/)）

- 目标来自 dexsql-release `benchmarks/agent-audit/harness/rasc_replay.py` 的 `SCENARIOS`，去掉 class_inventory。通过 `HARNESS` 环境变量指向 harness 目录，运行时导入。
- prompt = APK 路径 + 目标的 `intent` + 一句起点提示（取自该目标第一步查询的对象，例如 `the string "…"`、`the method … (class …)`）+ 「用现有工具完成目标，简要回答并引用代码证据」。见 `s1/run.py` 的 `prompt()`。
- 证据：目标的 `expect` 字符串出现在工具输出或回答里就算命中。
- 第二轮的四组：

| 组 | 工作区 | MCP 配置 | 读文件 |
|---|---|---|---|
| dnewA | `ws-dnewA` | `droidasc mcp --spill-mb 0`（超预算时分页，不写文件），`DROIDASC_CACHE_DIR=<ws>/cache` | 否 |
| dnewB | `ws-dnewB` | `droidasc mcp`（超预算时写文件到 `<ws>/cache/out/`） | 是 |
| dexsql | `ws-dexsql` | `dexsql mcp` | 是 |
| dr1 | `ws-dr1` | r1 `8b7a09e` 的 `droidasc mcp` | 否 |

```
export HARNESS=…/dexsql-release/benchmarks/agent-audit/harness GROK=~/.grok/bin/grok
R=/private/tmp/asc-grok        # 有 ws-<组>/、apks/douyin.apk、runs/
# 例：配置一个工作区
cd $R/ws-dnewB && grok mcp add -s project droidasc -e DROIDASC_CACHE_DIR=$R/ws-dnewB/cache -- $R/ws-dnewB/droidasc mcp
# 跑：ROOT TAG REPS CONC 组...（--files 放开读文件）
python3 s1/run.py $R r2s1 3 2 dnewA dr1 &
python3 s1/run.py $R r2s1 3 2 dnewB dexsql --files &
python3 s1/summary.py $R r2s1 -v
```

## S2：一个目录里的 416 个 APK（[`s2/`](s2/)）

- 目标见 `s2/goals.py`：4 个「哪些 APK 调用了某 API」的问题，答案大小在 7–25 个 APK 之间。候选目标的命中数是用 `s2/probe.py` 筛出来的。
- 参考答案：`s2/reference.py`（droidasc 规则集逐个 APK 跑）生成，再用 `s2/crosscheck.py`（dexsql 的 `method_calls` 表）独立核对，结果存在 `s2/ref-k80.json`。差异只有 com.android.bluetooth（只调用 `sendTextMessageWithoutPersisting`），记为 optional：答了不算错，没答也不算漏。94 个不含 DEX 的 APK，dexsql 无法打开，不影响结果。
- prompt：目录路径和 APK 数量 + 目标 + 「检查目录里的每个 APK，最后每个命中的 APK 输出一行 `APK: <去掉 .apk 的文件名>`，并写明调用所在的类或方法」。两组都放开读文件，因为 agent 需要 `list_dir` 才能看到目录内容。
- 打分：`s2/score.py`，按 `APK:` 行统计召回和准确。

```
R=/private/tmp/asc-grok/s2     # ws-droidasc/k80、ws-dexsql/k80（硬链接的 APK）、runs/
python3 s2/run.py $R r2s2 1 4 droidasc dexsql
python3 s2/score.py $R r2s2 s2/ref-k80.json -v
```

## 每次运行的指标（`results/`）

[`extract.py`](extract.py) 从原始 ndjson 中提取，一次运行一行：

```
HARNESS=… python3 extract.py s1 RUNS_DIR ROUND > round2-s1.csv
python3 extract.py s2 RUNS_DIR ROUND s2/ref-k80.json > round2-s2.csv
```

| 文件 | 内容 |
|---|---|
| `round1-s1.csv` | 第一轮，本地 Linux，Douyin 40.7.0；组 `droidasc`（`8b7a09e`）、`dexsql`，各 34 次 |
| `round2-s1.csv` | 第二轮，ams，Douyin 40.8.0；4 组 × 第 1、2 次各 17 个目标，另有第 3 次的 18 次（汇总时不计入） |
| `round2-s2.csv` | 第二轮 S2，2 组 × 4 个目标 × 1 次 |

列说明：
- `calls`：全部工具调用数。
- `mcp_calls`：经 grok `use_tool` 的 MCP 调用，也就是汇总表里的「MCP 调用」。
- `failed`：失败的工具调用数。
- `tokens`：会话的 total_tokens。
- `cost_usd`、`wall_s`：会话的费用（美元）和墙钟耗时（秒）。
- `attempts`：被限流后的总尝试次数。
- `tool_out_kb`：所有工具输出的总大小（KB）。
- `evidence_hit` / `evidence_total`：S1 证据的命中数和总数。
- `recall` / `precision` / `missed` / `extra`：S2 答案的召回率、准确率，以及漏掉和多出的 APK。
- `tool_calls`：按工具名统计的调用次数（JSON）。

**原始记录不提交**：其中有 Douyin 的反编译代码片段，总共约 80 MB。存放位置：
- 第一轮：本地 `target/grok-eval/runs/round1/`。
- 第二轮 S1：ams `~/asc-eval/results/agent-raw/s1-runs/r2s1/`（评测结束后从 `/private/tmp/asc-grok/runs/` 移来，macOS 重启会清空 /private/tmp），本地也有一份 `target/grok-eval/runs/r2s1/`，只有第 1、2 次。
- 第二轮 S2：ams `~/asc-eval/results/agent-raw/s2-runs/r2s2/`（同样移自 `/private/tmp/asc-grok/s2/runs/`）。

`/private/tmp` 下的内容可能被系统清理。
