[English](configuration.en.md) | 简体中文

# 缓存与资源设置

解压后的 DEX、派生的搜索表和查询结果会缓存到磁盘（跨进程共享，默认开启），常驻进程（`mcp`、daemon）另有
内存 LRU。cache 只是加速，随时可删；文件带 CRC，损坏只会变成未命中。

线程、内存和磁盘都是同一套设置，`asc config` 列出每项的值、来源和在本机的实际值（`--json` 给脚本和
agent）。优先级：命令行（`--set KEY=VALUE`）> 环境变量（`$ASC_<KEY>`，名字见 `--json`）> 配置文件
`~/.config/asc/config.toml`（`$XDG_CONFIG_HOME`；Windows 上 `%APPDATA%\asc\config.toml`；或 `$ASC_CONFIG` 指定，空值表示不读）> 默认值。
`auto` 默认值按本机计算，多个常驻进程会登记并平分内存和线程。

| 设置 | 默认 |
|---|---|
| `threads`（`--threads`） | auto：逻辑 CPU；有其他忙碌进程时 4 × CPU / 忙碌进程数，至少 2；APK 与 HarmonyOS 程序相同 |
| `memory.max`（`--memory-mb`） | auto = 25%：(可用内存 + 常驻进程已占) × 25% / 常驻进程数；也可写 `4G` 或 `40%` |
| `memory.ceiling` | auto：物理内存的 1/16，在 2G..8G 之间（12 GB 机器 2G，96 GB 机器 6G） |
| `memory.split` | on：在常驻进程间平分 |
| `cache.enabled`（`--no-cache`）、`cache.dir`（`--cache-dir`） | on；`$XDG_CACHE_HOME/asc`，Windows 上 `%LOCALAPPDATA%\asc\cache`，否则 `~/.cache/asc` |
| `cache.max`（`--cache-max-mb`） | auto = 20%：(剩余空间 + cache 自身) × 20%，不超过 `cache.ceiling`（32G），保留 1 GiB / 5% 剩余空间 |
| `cache.tiers`、`cache.min_dex` | `dex,derived,rendered`；小于 4M 的 DEX 不写 L1 |
| `cache.write_queue`、`cache.writers` | 512M（且不超过内存预算）；auto：每 8 个 CPU 一个，1..4 |
| `cache.spill`（`--spill-mb`） | 64M：截断输出写入 `out/` 的预算 |
| `daemon.idle`、`daemon.wait` | 15m；300ms。`ASC_DAEMON=off` 关闭 daemon |
| `decompile.default`（`$ASC_DECOMPILER`） | `dexdec`：`asc decompile` 不带 `--decompiler` 时用的后端 |
| `decompile.fallback`（`$ASC_DECOMPILE_FALLBACK`） | none：默认后端整类失败时依次尝试的后端（文件里写数组，`--set` / 环境变量用 `,` 分隔） |
| `decompile.mapping`（`--mapping`） | none：R8 / ProGuard `mapping.txt`，反编译源码用其中的名字；文件里请写绝对路径或 `~/` |
| `decompile.auto_install`（`$ASC_AUTO_INSTALL`） | on：找不到 `asc-dexdec-worker` 时下载最新的、协议版本与本 asc 相同的 worker；off 时退回 smali 并提示 |
| `decompile.release_url`（`$ASC_RELEASE_URL`） | `https://github.com/DroidASC/asc-dexdec/releases/latest/download`：`asc install dexdec` 和自动安装从这里下载（镜像可改） |

```toml
# ~/.config/asc/config.toml
threads = 8
[memory]
max = "4G"
[cache]
max = "10%"
```

`--debug` 在 stderr 上打印耗时和 cache 统计。

## 反编译后端

`asc decompile` 和 MCP 工具 `decompile` 把类交给反编译后端（子进程，stdio 上的 JSON-RPC，见
[decompile-backends.md](decompile-backends.md)）。什么都不配时只有内置的 `dexdec`：可执行文件
`asc-dexdec-worker`，吃原始程序（`inputs = ["archive"]`）。其他后端写在 `[decompilers.<name>]`；
`[decompilers.dexdec]` 不写 `command` 时仍用 asc 找到的 worker，只改其余键（如 `timeout`、`options = { indent = "  " }`）；
写了 `command` 就换成那个程序。

worker 在自己的仓库（[DroidASC/asc-dexdec](https://github.com/DroidASC/asc-dexdec)）构建和发布，版本号与 asc 无关，
两者只需说同一个反编译协议版本。asc 按顺序找 worker：`[decompilers.dexdec]` 的 `command` → `asc` 所在目录的
`asc-dexdec-worker` → asc 为本协议版本安装的 `$XDG_DATA_HOME/asc/tools/asc-dexdec-worker-p<协议版本>-<target>/`
（默认 `~/.local/share/asc/…`，Windows 上 `%LOCALAPPDATA%\asc\…`）→ `PATH`。都没有时，第一个需要 dexdec 的请求从 `decompile.release_url` 下载
`asc-dexdec-worker-p<协议版本>-<target>.tar.gz`：先取 `.sha256` 校验，只解出 worker（其它条目、链接、越界路径一律拒绝），
运行一次 `--protocol-version` 确认协议版本后原子改名就位；
有锁文件，daemon 和命令同时装也只下载一次。进度写 stderr（经 daemon 的命令在自己进程里先装好再转发；MCP 写日志），
不写 stdout。失败（离线、超时 10 s 连接 / 60 s 总计、没有这个协议版本的 worker）后一小时内不再自动重试，结果退回 smali，
头部写明原因和办法；`asc install dexdec` 随时下载最新的并覆盖。debug 构建在默认 URL 下不下载。找到的 worker 说的协议
版本与 asc 不同（例如 `PATH` 上的旧版本）时改用 asc 自己安装的那份（没有就自动安装），装不了就报错退回 smali。
worker 文件变了（重装、重新编译）时，下一个请求换新进程。

```toml
[decompile]
default = "dexdec"
fallback = ["jadx"]           # 默认后端整类失败（failed、崩溃、超时、起不来）时依次尝试；partial 不回退
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

| 键 | 默认 | 说明 |
|---|---|---|
| `command` | 必填（`dexdec` 除外） | 可执行文件；不含 `/` 时按 `PATH` 查找 |
| `args` | `[]` | 参数，不经过 shell |
| `env` | `{}` | 在继承的环境上追加 |
| `cwd` | cache 目录下的 `decompilers/<name>/` | 工作目录，不存在时创建 |
| `instances` | 1 | 进程数 |
| `max_concurrency` | 后端声明的值 | 每个进程同时处理的请求数上限（只能比后端在 `initialize` 里声明的小） |
| `idle` / `timeout` / `startup_timeout` | 10m / 60s / 30s | 空闲多久退出；单个请求的超时；等 `initialize` 的超时（数字是秒） |
| `inputs` | 后端声明的值 | asc 可以交给它的输入：`archive`（原始 APK / DEX）、`slice`（闭包切片，尚未实现） |
| `options` | `{}` | 原样放进 `initialize` 的 `options`，经后端的 `optionsHash` 进入缓存键 |
| `enabled` | true | false：保留配置但不启动 |

- 进程归 daemon 或 `asc mcp` 会话所有：按需启动，空闲退出，崩溃后带退避重启（连续 5 次起不来就在本会话停用）。
  没有 daemon（`ASC_DAEMON=off`、`--debug`）时每条命令临时起一个池，结束即关，能用但慢。
- 后端进程的常驻内存（`VmRSS`）和打开的程序一起计入 daemon / mcp 的内存预算，超出时先关空闲最久的进程。
- 结果缓存在 L3，键为（程序、类、后端名、版本、`optionsHash`、mapping 哈希、语言、nested）；失败的结果只留 10 分钟。
- 后端不接受 mapping（`initialize` 里 `mappings = false`）时不做文本替换，结果头部注明 `names not unified`。
- `asc config` 末尾列出每个后端的名字、命令行、来源（built-in / file）和角色（default、fallback N、disabled）。
