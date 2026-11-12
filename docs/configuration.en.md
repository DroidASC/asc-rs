English | [简体中文](configuration.md)

# Caching and resource settings

Inflated DEX files, derived search tables and query results are cached on disk (shared across processes,
on by default); resident processes (`mcp`, the daemon) also keep an in-memory LRU. The cache only speeds
things up and can be deleted at any time; files carry a CRC, so damage is just a miss.

Threads, memory and disk are one set of settings. `asc config` lists each with its value, its source
and what it comes to on this machine (`--json` for scripts and agents). A flag (`--set KEY=VALUE`) beats
the environment (`$ASC_<KEY>`, named in `--json`), which beats the config file
`~/.config/asc/config.toml` (under `$XDG_CONFIG_HOME`; on Windows `%APPDATA%\asc\config.toml`; or `$ASC_CONFIG`, empty reads none), which
beats the default. `auto` defaults are computed for this machine, and resident processes register so they
split memory and threads.

| setting | default |
|---|---|
| `threads` (`--threads`) | auto: the logical CPUs; with other busy processes 4 × CPUs / busy processes, at least 2; for APKs and HarmonyOS programs alike |
| `memory.max` (`--memory-mb`) | auto = 25%: (available memory + what resident processes hold) × 25% / resident processes; or `4G`, `40%` |
| `memory.ceiling` | auto: 1/16 of physical memory within 2G..8G (2G on a 12 GB machine, 6G on 96 GB) |
| `memory.split` | on: split between resident processes |
| `cache.enabled` (`--no-cache`), `cache.dir` (`--cache-dir`) | on; `$XDG_CACHE_HOME/asc`, on Windows `%LOCALAPPDATA%\asc\cache`, else `~/.cache/asc` |
| `cache.max` (`--cache-max-mb`) | auto = 20%: (free space + the cache) × 20%, at most `cache.ceiling` (32G), keeping 1 GiB / 5% free |
| `cache.tiers`, `cache.min_dex` | `dex,derived,rendered`; DEX under 4M are not written to L1 |
| `cache.write_queue`, `cache.writers` | 512M (and at most the memory budget); auto: one per 8 CPUs, 1..4 |
| `cache.spill` (`--spill-mb`) | 64M: budget of `out/`, where cut outputs go |
| `daemon.idle`, `daemon.wait` | 15m; 300ms. `ASC_DAEMON=off` turns the daemon off |
| `decompile.default` (`$ASC_DECOMPILER`) | `dexdec`: the backend of `asc decompile` without `--decompiler` |
| `decompile.fallback` (`$ASC_DECOMPILE_FALLBACK`) | none: backends tried in order when the default fails on a whole class (an array in the file, `,`-separated in `--set` and the environment) |
| `decompile.mapping` (`--mapping`) | none: R8 / ProGuard `mapping.txt` whose names decompiled source shows; give an absolute or `~/` path in the file |
| `decompile.auto_install` (`$ASC_AUTO_INSTALL`) | on: download the latest worker speaking this asc's protocol version when no `asc-dexdec-worker` is found; off: smali, with a hint |
| `decompile.release_url` (`$ASC_RELEASE_URL`) | `https://github.com/DroidASC/asc-dexdec/releases/latest/download`: where `asc install dexdec` and the auto-install download from (for a mirror) |

```toml
# ~/.config/asc/config.toml
threads = 8
[memory]
max = "4G"
[cache]
max = "10%"
```

`--debug` prints timing and cache statistics on stderr.

## Decompiler backends

`asc decompile` and the MCP tool `decompile` hand a class to a decompiler backend (a subprocess speaking
JSON-RPC over stdio, see [decompile-backends.md](decompile-backends.md)). With nothing configured there
is only the built-in `dexdec`: the executable `asc-dexdec-worker`, on the original program
(`inputs = ["archive"]`). Other backends go in `[decompilers.<name>]`. A `[decompilers.dexdec]` table without
`command` keeps the worker asc finds and changes its other keys (`timeout`, `options = { indent = "  " }`);
with a `command` it replaces it.

The worker is built and released in its own repository
([DroidASC/asc-dexdec](https://github.com/DroidASC/asc-dexdec)); its version is not tied to asc's, the two only
have to speak the same decompile protocol version. asc looks for the worker in this order: `[decompilers.dexdec]`
`command` → `asc-dexdec-worker` in the directory of `asc` → the one asc installed for its protocol version,
`$XDG_DATA_HOME/asc/tools/asc-dexdec-worker-p<protocol>-<target>/` (`~/.local/share/asc/…` by default, `%LOCALAPPDATA%\asc\…` on Windows) → `PATH`.
When there is none, the first request that needs dexdec downloads `asc-dexdec-worker-p<protocol>-<target>.tar.gz`
from `decompile.release_url`: it checks the archive against its `.sha256`, takes only the worker out (any other
entry, a link or a path outside the directory refuses the archive), runs it once with `--protocol-version`, and
renames it into place, under a lock file so that the daemon and a
command installing at once download it once. Progress goes to stderr (a command bound for the daemon installs in its
own process first; MCP logs it), never to stdout. After a failure (offline, timeouts of 10 s to connect / 60 s in
all, no worker for this protocol version) it is not tried again for an hour: the answer is smali, its header says
why and what to do; `asc install dexdec` downloads the latest one whenever asked. A debug build does not download
from the default URL. A worker speaking another protocol version than asc (an old one on `PATH`) gives way to
asc's own install (installed if missing), or the request fails over to smali saying why. A worker file that changes (reinstalled,
rebuilt) gets a new process on the next request.

```toml
[decompile]
default = "dexdec"
fallback = ["jadx"]           # tried in order when the default fails on a whole class (failed, crash, timeout, no start); partial does not fall back
mapping = "~/work/app/mapping.txt"

[decompilers.jeb]
command = "java"
args = ["-Xmx6g", "-jar", "/opt/jeb-server/jeb-server.jar", "--stdio"]
env = { JEB_HOME = "/opt/jeb" }
instances = 1
max_concurrency = 1
idle = "10m"
timeout = "60s"
startup_timeout = "60s"
inputs = ["slice"]
options = { finally_rebuilder = true }

[decompilers.jadx]
command = "jadx-worker"
instances = 2
```

| key | default | meaning |
|---|---|---|
| `command` | required (but for `dexdec`) | the executable; looked up on `PATH` when it has no `/` |
| `args` | `[]` | arguments, never through a shell |
| `env` | `{}` | added to the inherited environment |
| `cwd` | `decompilers/<name>/` in the cache directory | working directory, created when missing |
| `instances` | 1 | processes |
| `max_concurrency` | what the backend declares | requests one process takes at once (only lowers what `initialize` declares) |
| `idle` / `timeout` / `startup_timeout` | 10m / 60s / 30s | idle time before exit; deadline of a request; deadline of `initialize` (a number is seconds) |
| `inputs` | what the backend declares | what asc may hand it: `archive` (the original APK / DEX), `slice` (closure slices, not built yet) |
| `options` | `{}` | passed as `initialize`'s `options`; part of the cache key through the backend's `optionsHash` |
| `enabled` | true | false keeps the table but never starts the backend |

- Processes belong to the daemon or the `asc mcp` session: started on demand, stopped when idle,
  restarted with backoff after a crash (disabled for the session after 5 failed starts in a row). Without a
  daemon (`ASC_DAEMON=off`, `--debug`) each command starts a pool of its own and stops it at the end: it
  works, slowly.
- The backend processes' resident memory (`VmRSS`) counts against the daemon's / mcp's memory budget with
  the open programs; beyond it the longest idle processes stop first.
- Results are kept in L3, keyed by (program, class, backend name, version, `optionsHash`, mapping hash,
  language, nested); failures for 10 minutes only.
- A backend that takes no mappings (`mappings = false` in `initialize`) gets no text substitution; the
  header says `names not unified`.
- `asc config` ends with each backend's name, command line, source (built-in / file) and role (default,
  fallback N, disabled).
