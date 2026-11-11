[English](configuration.en.md) | 简体中文

# 缓存与资源设置

解压后的 DEX、派生的搜索表和查询结果会缓存到磁盘（跨进程共享，默认开启），常驻进程（`mcp`、daemon）另有
内存 LRU。cache 只是加速，随时可删；文件带 CRC，损坏只会变成未命中。

线程、内存和磁盘都是同一套设置，`asc config` 列出每项的值、来源和在本机的实际值（`--json` 给脚本和
agent）。优先级：命令行（`--set KEY=VALUE`）> 环境变量（`$ASC_<KEY>`，名字见 `--json`）> 配置文件
`~/.config/asc/config.toml`（`$XDG_CONFIG_HOME`，或 `$ASC_CONFIG` 指定；空值表示不读）> 默认值。
`auto` 默认值按本机计算，多个常驻进程会登记并平分内存和线程。

| 设置 | 默认 |
|---|---|
| `threads`（`--threads`） | auto：逻辑 CPU；有其他忙碌进程时 4 × CPU / 忙碌进程数，至少 2 |
| `memory.max`（`--memory-mb`） | auto = 25%：(可用内存 + 常驻进程已占) × 25% / 常驻进程数；也可写 `4G` 或 `40%` |
| `memory.ceiling` | auto：物理内存的 1/16，在 2G..8G 之间（12 GB 机器 2G，96 GB 机器 6G） |
| `memory.split` | on：在常驻进程间平分 |
| `cache.enabled`（`--no-cache`）、`cache.dir`（`--cache-dir`） | on；`$XDG_CACHE_HOME/asc` 或 `~/.cache/asc` |
| `cache.max`（`--cache-max-mb`） | auto = 20%：(剩余空间 + cache 自身) × 20%，不超过 `cache.ceiling`（32G），保留 1 GiB / 5% 剩余空间 |
| `cache.tiers`、`cache.min_dex` | `dex,derived,rendered`；小于 4M 的 DEX 不写 L1 |
| `cache.write_queue`、`cache.writers` | 512M（且不超过内存预算）；auto：每 8 个 CPU 一个，1..4 |
| `cache.spill`（`--spill-mb`） | 64M：截断输出写入 `out/` 的预算 |
| `daemon.idle`、`daemon.wait` | 15m；300ms。`ASC_DAEMON=off` 关闭 daemon |

```toml
# ~/.config/asc/config.toml
threads = 8
[memory]
max = "4G"
[cache]
max = "10%"
```

`--debug` 在 stderr 上打印耗时和 cache 统计。
