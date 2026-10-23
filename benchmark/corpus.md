# 语料

APK 不放进仓库，逐个 APK 的清单（包名、versionName、versionCode、大小、sha256）也不入库：其中两份是个人手机上安装的全部应用。下面只记录每个语料的来源、数量、设备和系统版本，以及怎么重新拉取和生成清单。

清单用 [`corpus/manifest.py`](corpus/manifest.py) 生成，包名和版本取自 `droidasc manifest-summary` 的第一行；复现时用 sha256 核对拿到的 APK 是不是同一个文件：

```
python3 benchmark/corpus/manifest.py DROIDASC DIR... > corpus.tsv
```

清单与全部结果文件保存在仓库之外：本地 `target/benchmark-data/`，ams `~/asc-eval/results/benchmark-data/`。

| 语料 | 数量 | 来源 | 版本 | 用于 |
|---|---:|---|---|---|
| Douyin 40.7.0 | 1 | 本地文件 | `com.ss.android.ugc.aweme`，versionCode 400701，359908938 字节，sha256 `86ee431640c9fe5035135092079af2dcddf947feb7e02cb78aaf459c821f80c0` | 本地单 APK 回放与 grok 评测（`round1`）；prefix-skip、no-fsync、daemon 的本地测量；失败调用回放 |
| Douyin 40.8.0 | 1 | REDMI K80 上安装的版本（属于下面 K80 语料） | versionCode 400801，360503779 字节，sha256 `84f56e2ad392044676b50f6550cdd66fa37350416aecf3073417474bd86e6211` | ams 上的单 APK 回放与 grok 评测（`r2s1`） |
| REDMI K80 | 416 | 设备上全部包的 base APK（系统 + 第三方），2026-10-22 在 ams 上用 [`corpus/pull.sh`](corpus/pull.sh) 拉取 | 见下方设备版本；单个 APK 版本见仓库外的清单 | ams 上的多 APK 评测与 S2 agent 评测（`r2s2`） |
| Xiaomi 17 | 420 | 同上 | 同上 | ams 上的多 APK 评测 |
| Pixel 6 系统 APK | 312 | `adb shell pm list packages -f -s` 列出的系统包，拉到本地 `target/device-apks/` | 见下方设备版本 | 本地多 APK 评测、资源对比、rust_ASC 对比与上游 bug、缓存一致性、no-fsync |
| 合成集 | 100 | `target/corpus/app001.apk` … `app100.apk`，早期生成的合成 APK，514 MB | — | 早期多 APK 评测的对照 |
| 资源对比的第三方 APK | 6 | 快手、美团、拼多多、淘宝（两个版本）、小红书 | **版本未记录，APK 已不在本地** | 资源对比（419 = 312 个 Pixel 系统 APK + Douyin 40.7.0 + 这 6 个 + 合成集 100 个） |

## 设备

| 设备 | 型号 | Android | 系统版本 |
|---|---|---|---|
| Pixel 6 | Pixel 6 | 16 | CP1A.260405.005 |
| REDMI K80 | 24117RK2CC | 16 | Xiaomi HyperOS OS3.0.308.0 |
| Xiaomi 17 | 25113PN0EC | 16 | Xiaomi HyperOS OS3.0.313.0 |

设备信息来自 `adb shell getprop`（`ro.product.model`、`ro.build.version.release`、`ro.build.version.incremental`）。手机上的应用会自动更新，即使是同一台设备，日后重新拉取得到的版本也可能不同，要以清单里的 versionCode 和 sha256 为准。

## 拉取

```
# ams 上，每台设备一次：SERIAL 见 adb devices，NAME 是目标子目录（k80 / mi17）
zsh benchmark/corpus/pull.sh SERIAL NAME     # 写到 ~/asc-eval/apks/NAME/<package>.apk
```

`pull.sh` 拉取 `pm list packages -f` 列出的每个包的 base APK（不含 split APK），已存在且非空的文件会跳过。脚本里写死了 macOS 上 Android SDK 的 adb 路径，在其他机器上要先改 `A=`。
