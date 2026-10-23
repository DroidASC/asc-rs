# 语料

APK 和逐 APK 清单都不入库（其中两份是个人手机上的全部应用），这里只记来源、数量和版本。清单用 [`corpus/manifest.py`](corpus/manifest.py) 生成，复现时按 sha256 核对：

```
python3 benchmark/corpus/manifest.py DROIDASC DIR... > corpus.tsv
```

| 语料 | 数量 | 来源与版本 | 用于 |
|---|---:|---|---|
| Douyin 40.7.0 | 1 | `com.ss.android.ugc.aweme` versionCode 400701，359908938 字节，sha256 `86ee431640c9fe5035135092079af2dcddf947feb7e02cb78aaf459c821f80c0` | 本地单 APK 回放、agent 评测 `round1`、失败调用回放 |
| Douyin 40.8.0 | 1 | K80 上安装的版本，versionCode 400801，360503779 字节，sha256 `84f56e2ad392044676b50f6550cdd66fa37350416aecf3073417474bd86e6211` | Mac 单 APK 回放、agent 评测 `r2s1` |
| REDMI K80 | 416 | 设备上全部 base APK，2026-10-22 用 [`corpus/pull.sh`](corpus/pull.sh) 拉取 | Mac 多 APK、agent 评测 `r2s2` |
| Xiaomi 17 | 420 | 同上 | Mac 多 APK |
| Pixel 6 系统 APK | 312 | `pm list packages -f -s` 的系统包 | 本地多 APK、资源对比、dexdump 对比、缓存一致性 |
| 合成集 | 100 | 早期生成的合成 APK，514 MB | 早期对照、资源对比 |
| 第三方 APK | 6 | 快手、美团、拼多多、淘宝 ×2、小红书；**版本未记录** | 资源对比 |

| 设备 | 型号 | Android | 系统版本 |
|---|---|---|---|
| Pixel 6 | Pixel 6 | 16 | CP1A.260405.005 |
| REDMI K80 | 24117RK2CC | 16 | HyperOS OS3.0.308.0 |
| Xiaomi 17 | 25113PN0EC | 16 | HyperOS OS3.0.313.0 |

应用会自动更新，重新拉取的版本以清单的 versionCode 和 sha256 为准。

```
zsh benchmark/corpus/pull.sh SERIAL NAME   # 每台设备一次，写到 ~/asc-eval/apks/NAME/<package>.apk
```

`pull.sh` 只拉 base APK（不含 split），跳过已存在的文件；adb 路径写死为 macOS SDK 的位置，其他机器先改 `A=`。
