[English](agents.en.md) | 简体中文

# 给 agent 用

- **截断与写文件**：只有显式要求时才截断。`--limit N` / `--max-bytes N`（或 `$ASC_LIMIT` /
  `$ASC_MAX_BYTES`）截断 stdout，完整输出写入 cache 目录下的 `out/`，最后一行给出路径和续读方式：

  ```
  # records 1-50 of 523 shown; full output in /home/u/.cache/asc/out/3f2a….txt (grep it, or rerun with --offset 50)
  ```

- **Skill**：[`skills/asc/SKILL.md`](../skills/asc/SKILL.md) 是给通过 shell 工作的 agent 的
  [Agent Skill](https://agentskills.io/specification)。
- **Daemon**（Unix）：一次性命令自动交给按用户运行的 daemon，它让打开的 APK 常驻，输出（stdout、stderr、
  退出码）与不用 daemon 时逐字节相同。第一个命令自动启动它，空闲后自动退出；客户端 Ctrl-C 会取消 daemon
  中的查询。`asc daemon status|stop|start` 管理，`ASC_DAEMON=off` 关闭。
- **MCP**：`asc mcp` 是 stdio 上的常驻会话，工具有 `getclass`、`findrefs`、`callgraph`、`hierarchy`、
  `listclass`、`getmanifest`、`manifest_summary`、`resources`，传 `apk` 路径即打开，回复里的 `apk_id` 可代替路径。
  `apk` 也可以是 HarmonyOS 程序：`listclass`、`getclass`、`findrefs`、`callgraph`、`getmanifest`、`manifest_summary`
  可用，第一条回复会说明这些工具在 HarmonyOS 上接受的参数。
  `findrefs`、`listclass`、`manifest_summary`、`resources` 可用 `apks` / `dir` 一次处理多个 APK。回复控制在
  `max_bytes`（默认 16384）内，超出部分按 `spill` 写文件或分页。
  field 查询可传 `"access": "read"` / `"write"`；结果的 `field_accesses` 与 `matched` 对齐，带 context 时每个
  site 也有 `access`。

  ```json
  { "mcpServers": { "asc": { "command": "/absolute/path/to/asc", "args": ["mcp"] } } }
  ```
