# 失败调用回放

> 结果文件（`results/`、`*.tsv`、`s2/ref-k80.json`）不入库，保存在本地 `target/benchmark-data/benchmark/` 和 ams `~/asc-eval/results/benchmark-data/benchmark/`，见 [benchmark/README.md](../README.md)。

把两轮 grok 评测里所有失败的 droidasc MCP 调用，原样在一个 MCP 会话里重放，比较 cli-native 改动（统一查询语法、宽松参数、可操作报错、零结果提示）前后的版本。结论见 [../README.md](../README.md#失败调用回放cli-native本地-linuxdouyin-4070)。

```
python3 failed.py RUN_DIR... > failed.jsonl          # 从 grok 原始记录中提取失败调用
python3 replay.py DROIDASC DOUYIN_APK results/failed-calls.jsonl > replay.jsonl
```

- `replay.py` 先 `open_apk` 一次，再把每次调用参数里的 `apk` 改写为同一个 APK，然后逐个发出。输出每次调用的 `ok`（`isError` 为 false），以及 `actionable`（回复是否带有可操作的提示，用脚本里的正则 `ACTIONABLE` 判定）。
- `results/failed-calls.jsonl`：92 次 droidasc 调用的参数和当时的错误文本（截断到 300 字），可以直接作为 `replay.py` 的输入。客户端调用不存在的工具（`bash`、`Read`）的 12 次已去掉。
- `results/replay-before.jsonl` / `replay-after.jsonl`：在 Douyin 40.7.0 上，分别用 `f344edf` 和 `c1fc2da` 之后的 HEAD 重放的结果。只保留失败回复的前 200 字，成功的回复不保留（里面是 smali）。
