English | [简体中文](agents.md)

# For agents

- **Cut output, spilled to a file**: nothing is cut unless asked. `--limit N` / `--max-bytes N` (or
  `$ASC_LIMIT` / `$ASC_MAX_BYTES`) keep stdout short; the whole output goes to `out/` in the cache
  directory and the last line says where and how to continue:

  ```
  # records 1-50 of 523 shown; full output in /home/u/.cache/asc/out/3f2a….txt (grep it, or rerun with --offset 50)
  ```

- **Skill**: [`skills/asc/SKILL.md`](../skills/asc/SKILL.md) is an
  [Agent Skill](https://agentskills.io/specification) for agents that work through a shell.
- **Daemon** (Unix): one-shot commands are handed to a per-user daemon that keeps opened APKs resident; the
  output (stdout, stderr, exit status) is byte-identical to running without it. The first command starts
  it and it exits when idle; Ctrl-C in the client cancels the query in the daemon. `asc daemon
  status|stop|start` controls it, `ASC_DAEMON=off` turns it off.
- **MCP**: `asc mcp` is a resident session over stdio with the tools `getclass`, `findrefs`,
  `callgraph`, `hierarchy`, `listclass`, `getmanifest`, `manifest_summary`, `resources`. Passing an
  `apk` path opens it; the `apk_id` in replies can stand in for the path. `apk` may also be a HarmonyOS
  program: `listclass`, `getclass`, `findrefs`, `callgraph`, `getmanifest` and `manifest_summary` work on it, and
  the first reply says what those tools take there. `findrefs`, `listclass`, `manifest_summary` and `resources` take `apks` / `dir` to cover many
  APKs in one call. Replies stay within `max_bytes` (default 16384); the rest is spilled to a file or paged,
  per `spill`.
  Field queries accept `"access": "read"` / `"write"`; `field_accesses` aligns with `matched`, and contextual
  sites also carry `access`.

  ```json
  { "mcpServers": { "asc": { "command": "/absolute/path/to/asc", "args": ["mcp"] } } }
  ```
