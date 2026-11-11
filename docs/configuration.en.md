English | [简体中文](configuration.md)

# Caching and resource settings

Inflated DEX files, derived search tables and query results are cached on disk (shared across processes,
on by default); resident processes (`mcp`, the daemon) also keep an in-memory LRU. The cache only speeds
things up and can be deleted at any time; files carry a CRC, so damage is just a miss.

Threads, memory and disk are one set of settings. `asc config` lists each with its value, its source
and what it comes to on this machine (`--json` for scripts and agents). A flag (`--set KEY=VALUE`) beats
the environment (`$ASC_<KEY>`, named in `--json`), which beats the config file
`~/.config/asc/config.toml` (under `$XDG_CONFIG_HOME`, or `$ASC_CONFIG`; empty reads none), which
beats the default. `auto` defaults are computed for this machine, and resident processes register so they
split memory and threads.

| setting | default |
|---|---|
| `threads` (`--threads`) | auto: the logical CPUs; with other busy processes 4 × CPUs / busy processes, at least 2 |
| `memory.max` (`--memory-mb`) | auto = 25%: (available memory + what resident processes hold) × 25% / resident processes; or `4G`, `40%` |
| `memory.ceiling` | auto: 1/16 of physical memory within 2G..8G (2G on a 12 GB machine, 6G on 96 GB) |
| `memory.split` | on: split between resident processes |
| `cache.enabled` (`--no-cache`), `cache.dir` (`--cache-dir`) | on; `$XDG_CACHE_HOME/asc` or `~/.cache/asc` |
| `cache.max` (`--cache-max-mb`) | auto = 20%: (free space + the cache) × 20%, at most `cache.ceiling` (32G), keeping 1 GiB / 5% free |
| `cache.tiers`, `cache.min_dex` | `dex,derived,rendered`; DEX under 4M are not written to L1 |
| `cache.write_queue`, `cache.writers` | 512M (and at most the memory budget); auto: one per 8 CPUs, 1..4 |
| `cache.spill` (`--spill-mb`) | 64M: budget of `out/`, where cut outputs go |
| `daemon.idle`, `daemon.wait` | 15m; 300ms. `ASC_DAEMON=off` turns the daemon off |

```toml
# ~/.config/asc/config.toml
threads = 8
[memory]
max = "4G"
[cache]
max = "10%"
```

`--debug` prints timing and cache statistics on stderr.
