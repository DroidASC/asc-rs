# 失败调用回放

把 agent 评测（`round1`、`r2s1`）中失败的 droidasc MCP 调用在一个 MCP 会话里原样重放，结论见 [../README.md](../README.md#失败调用回放)。

```
python3 failed.py RUN_DIR... > failed.jsonl                                  # 从 grok 原始记录提取
python3 replay.py DROIDASC DOUYIN_APK results/failed-calls.jsonl > replay.jsonl
```

`replay.py` 把每次调用的 `apk` 改成同一个 APK 再发出，输出 `ok` 与 `actionable`（回复是否带可操作提示，按脚本里的 `ACTIONABLE` 正则）。`results/failed-calls.jsonl` 是 92 次调用的参数与当时的错误文本（不含调用不存在工具的 12 次）。
