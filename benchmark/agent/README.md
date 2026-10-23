# agent 评测（grok headless）

结论见 [../README.md](../README.md#agent-评测grok-47)。2026-10-23 起不再做新的 agent 评测。

## 做法

```
grok -p PROMPT --trust --disallowed-tools LIST --no-subagents --no-plan --disable-web-search \
     --always-approve --output-format streaming-json
```

- 每个目标一个新会话；`--trust` 必须加，否则 headless 不启动项目级 MCP。
- 每组一个工作区 `ws-<组>/`，`grok mcp add -s project` 只配一个 MCP 服务器；二进制和 APK 硬链接进工作区（Linux strict 沙箱不允许执行工作区外的程序）。
- `--disallowed-tools` 禁掉全部内置工具（列表见 `s1/run.py` 的 `DIS`）；「+ 读文件」组额外放开 `read_file`、`grep`、`list_dir`。
- 防止读到历史会话（`~/.grok/sessions/`）：Linux 用 `--sandbox strict` 并 deny `~/.grok/**`；macOS strict 起不来，工作区放在 `/private/tmp/asc-grok/`，deny `/Users/**`、`/Volumes/**`。
- 14 路并发会被限流；正式结果是 4 路并发，runner 遇限流退避重试（`attempts` 列）。

## S1：Douyin 单 APK，17 个目标（[`s1/`](s1/)）

目标取自 dexsql-release harness 的 `SCENARIOS`（去掉 class_inventory），经 `HARNESS` 导入。prompt = APK 路径 + `intent` + 起点提示 + 「简要回答并引用代码证据」（`s1/run.py` 的 `prompt()`）；`expect` 字符串出现在工具输出或回答里即算证据命中。

| 组 | MCP 配置 | 读文件 |
|---|---|---|
| dnewA | `droidasc mcp --spill-mb 0`（超长分页） | 否 |
| dnewB | `droidasc mcp`（超长写文件） | 是 |
| dexsql | `dexsql mcp` | 是 |
| dr1 | r1 `8b7a09e` 的 `droidasc mcp` | 否 |

```
export HARNESS=…/dexsql-release/benchmarks/agent-audit/harness GROK=~/.grok/bin/grok
R=/private/tmp/asc-grok        # ws-<组>/、apks/douyin.apk、runs/
cd $R/ws-dnewB && grok mcp add -s project droidasc -e DROIDASC_CACHE_DIR=$R/ws-dnewB/cache -- $R/ws-dnewB/droidasc mcp
python3 s1/run.py $R r2s1 3 2 dnewA dr1 &           # ROOT TAG REPS CONC 组...
python3 s1/run.py $R r2s1 3 2 dnewB dexsql --files &
python3 s1/summary.py $R r2s1 -v
```

## S2：一个目录里的 416 个 APK（[`s2/`](s2/)）

- 目标：`s2/goals.py`，4 个「哪些 APK 调用了某 API」，答案 7–25 个 APK（候选用 `s2/probe.py` 筛）。
- 参考答案：`s2/reference.py` 生成，`s2/crosscheck.py`（dexsql）独立核对，存为 `s2/ref-k80.json`；com.android.bluetooth 记为 optional。
- prompt 要求每个命中 APK 输出一行 `APK: <文件名>`；`s2/score.py` 按此算召回与准确。

```
R=/private/tmp/asc-grok/s2
python3 s2/run.py $R r2s2 1 4 droidasc dexsql
python3 s2/score.py $R r2s2 s2/ref-k80.json -v
```

## 指标提取

```
HARNESS=… python3 extract.py s1 RUNS_DIR ROUND > round2-s1.csv
python3 extract.py s2 RUNS_DIR ROUND s2/ref-k80.json > round2-s2.csv
```

每次运行一行：`calls`、`mcp_calls`、`failed`、`tokens`、`cost_usd`、`wall_s`、`attempts`、`tool_out_kb`、`evidence_hit/total`（S1）、`recall/precision/missed/extra`（S2）、`tool_calls`。原始 ndjson（约 80 MB，含反编译片段）不入库。macOS 重启会清空 `/private/tmp`，跑完要及时移走。
