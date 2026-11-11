# 接入 ArkCompiler ABC（HarmonyOS）设计

状态：提案（2026-11-09），2026-11-10 按评审修订（分期顺序、`.app` 嵌套、region 定位、record 名写法），P1 进行中。

目标：让 asc-rs 像对待 APK 一样对待 HAP / ABC —— 把它当只读数据库，不预处理、按需解析、毫秒级回答
类定位、交叉引用、反汇编、调用图和 manifest 查询。DEX 是第一套格式，ABC 是第二套。

## 1. 结论

- **自研纯 Rust、零拷贝、惰性的 ABC 读取器**，不在运行时依赖 abcd-rs；abcd-rs / `ark_disasm` 只作测试对照。
- **同一仓库、同一 workspace、同一个 `asc` 二进制**，打开时按格式自动识别；鸿蒙支持做成默认开启的 cargo feature。
- **先写 ABC、后重构**：`asc-abc` / `asc-arkisa` / `asc-pasm` 不依赖现有代码，先做出来并用一个最小的鸿蒙引擎跑通
  `listclass` / `getclass` / `findrefs string:`（P1–P2）；有了两个实例再把格式无关的基础设施从 `asc-engine` 拆出（P3）。
  只有 DEX 一个实例时先定共享层的边界，大概率要返工。
- 每种格式一个引擎，CLI / MCP 在打开时按格式分派。不用一个大 trait 统一两种格式：ArkTS 是动态语言，
  没有 Dalvik 那种带签名的方法引用，强行统一会退化成最小公分母。

## 2. 参考资料评估（`../ark`）

| 项目 | 结论 |
|---|---|
| **abcd-rs**（Rust） | 不作依赖。理由见下。只有 `abcd-hap`（纯 Rust zip）可直接用，但 `asc-apk` 已有同等能力。`design/isa-compat.md` 很有价值：24.0.0.0 的操作码表能解码 9.x–24 的所有文件，没有重新编号。 |
| **arkcompiler_runtime_core**（官方 C++） | 格式规范与对照来源：`libpandafile/*`、`isa/isa.yaml`、`disassembler/`、`libabckit/src/adapter_dynamic/helpers_dynamic.cpp`（模块变量解析）、`panda_guard/obfuscate/function.cpp`（函数名规则）。 |
| **ReArk**（Qt，闭源 hyle 后端） | 只参考功能设计。它的 agent 工具（类树、字符串、字面量数组、xref、调用参数流、组合查询）验证了哪些原语有用；CTF 复盘（`docs/shctf-analysis-path.md`）暴露的缺口：没有数值常量搜索、没有方法级反汇编、每次查询都重新解析、agent 手算十六进制出错。 |

abcd-rs 不作依赖的原因：

- 解码必须经过 C++ FFI（libpandafile + bridge），构建要 Ruby（ERB codegen）、libclang（bindgen）、C++17 和两份
  runtime_core submodule（本地目前是空目录，编不过）。我们的预编译二进制（linux x86_64 / aarch64、macOS）目前只需要
  一个 C 编译器（`libdeflater`，可关），这条构建链重得多。
- `decode(&[u8]) -> File` 一次性把所有类、方法、字节码解成自有结构体，不保留原始字节码，没有按需访问；
  惰性的 `AbcFile<'data>` 是 `pub(crate)`。
- edition 2024 + let-chains，需要 Rust ≥ 1.88；本 workspace 声明 1.85（次要理由，可以调）。
- 反汇编（与 `ark_disasm` 逐字节一致）和反编译都只接受整个文件 / 模块；反编译慢（2.4 MB 的 abc 约 57 s）。

## 3. 格式要点（影响设计的部分）

本地样本 `../ark/ReArk/samples/`：

| 样本 | abc 版本 | 大小 | 备注 |
|---|---|---|---|
| `Bridge.hap` | 13.0.1.0 | 58 KB | 文件头无字面量数组索引（`0xFFFFFFFF`） |
| `contacts.hap` | 12.0.6.0 | 3.6 MB | 1990 个字面量数组，含三方库 record |
| `遥遥领先.hap` | 12.0.2.0 | 34 KB | 带 `libs/arm64-v8a/*.so` |
| `EasyHap-default-unsigned.app` | 9.0.0.0 | 16 KB | 内层 hap 为 Stored；类索引含 1 个外部类 |
| `fpt-default-signed.app` | 12.0.6.0 | 107 KB | 内层 hap 为 **Deflate**；record 名被混淆（`a/b`） |
| `shctf.app` | 12.0.2.0 | 50 KB | 内层 hap 为 **Deflate** |

大型样本 A（应用商店上架包，本机，不随仓库分发）：

| 文件 | abc 版本 | 大小 | 备注 |
|---|---|---|---|
| `modules.abc`（散放，已解密） | 12.0.6.0 | 32 MB | 4840 个类、**4 个 region**（方法索引表 0xfffb / 0xfffe / 0xfffe / 0x44f9 项）、50139 个字面量数组；校验和与 adler32 一致 |
| `entry.hap!ets/modules.abc` | 12.0.6.0 | 32 MB | **已加密**：60 字节文件头是明文，其后全部是密文（与解密版逐字节不同，类索引偏移越界，校验和对不上） |
| `entry.hap!ets/widgets.abc` | 12.0.6.0 | 32 KB | 未加密，卡片用的第二个 abc |
| `entry.hap` 其余 | — | 58 MB | `module.json`、`pkgContextInfo.json`（46 KB）、`resources.index` 为 Stored；53 个 `.so` 为 Deflate |

HAP 内的 `ets/modules.abc`、`module.json`、`resources.index` 全部是 Stored，直接 mmap 切片即可零拷贝；
`.app` 的内层 hap 则常被压缩，要先解压（走 L1）。

由此得出的三条要求：

- **一个 HAP 可以有多个 abc**：条目按 `ets/*.abc` 选，不是只取 `ets/modules.abc`。
- **上架包的 abc 是加密的**：文件头正常，正文是密文。打开时必须识别出来（校验和不符，且类索引偏移越界），
  报成可操作的错误（“已加密，请提供解密后的 .abc”），不能当作损坏文件或输出垃圾。不做解密。
- **裸 `.abc` 是一等输入**：解密后的 abc 通常是单独一个文件；同目录的 hap 里 `module.json` 等未加密条目仍可用，
  “目录 = 一个程序”时让裸 abc 顶替 hap 内文件头相同的加密条目（不看文件名）。

**覆盖缺口**：ReArk 的 6 个样本都只有 1 个 region；多 region 和“毫秒级”的验收用 样本 A 的解密 abc。
仍然没有 24.x 以上版本、HSP、`modules_static.abc`。

- **布局**：小端，引用都是 u32 文件偏移；文件头 60 字节，魔数 `PANDA\0\0\0`。偏移 ≤ 文件头大小视为无效。
  `foreign_off..+foreign_size` 内是外部实体。
- **类索引**按名字（MUTF-8 字节序，ASCII 下等同）排序 → 对 `&[u32]` 二分查找即可定位类，O(log n)。
  名字是 `L<name>;`。索引里也包含外部类。排序是写入端的约定：读取时不假定成立，二分落空后退回线性查找。
- **region 解析**：字符串、方法、字面量数组共用每个 region 的同一张 16 位索引表（动态格式的
  `METHOD_STRING_LITERAL`），按**方法项**（不是代码项）所在 region 解析。以方法项偏移落在哪个 region 的
  `[start, end)` 为准（官方 `File::GetIndexHeader` 的做法，region 数很少，二分或线性都可）。
  写入端还把 region 编号放在 `access_flags >> 16`（`MethodItem::SetHeaderIndex`），只当快速路径用：
  越界或与偏移区间不符时以偏移区间为准，混淆过或旧版本的文件不保证这一位可靠。
  反向查询时先在每个 region 把目标偏移换算成 idx，再扫该 region 的方法 —— 与 DEX 的“先定位、再扫描”一致。
- **类 / 方法 / 字段**都是变长、内联，带 tag 列表；类内的字段、方法只能顺序遍历，方法偏移表按类惰性缓存。
- **代码项**：`uleb num_vregs, num_args, code_size, tries_size`，随后是指令和 try 块（`length` 是字节长度，catch 的 type_idx 存 +1）。
- **字面量数组**：`u32 num`（= 2 × 项数），随后是未对齐的 `(u8 tag, value)`；STRING / METHOD / LITERALARRAY 等值是原始文件偏移。
  12.0.6.0 之后的版本文件头不再有字面量数组索引（两个字段为 `0xFFFFFFFF`），需从字段和指令操作数收集。
  文件头的这张索引里**混有模块记录和 phase 表的偏移**（样本 A 的 50139 项 = 45309 个字面量数组 + 4820 个模块记录
  + 10 张 phase 表），要用各 record 的 `moduleRecordIdx` / `moduleRequestPhaseIdx` 排除，不能逐项当字面量数组解析。
  `moduleRequestPhaseIdx` 指向 `u32 count` 加 `count` 个无 tag 的字节，每个模块请求一个；1 表示 lazy import
  （对应 `callruntime.ldlazymodulevar`）。
- **region 的 field / proto 表**在 12.x 以后不存在（偏移和大小都是 `0xFFFFFFFF`），9.0.0.0 里是正常的表。
- **模块记录**是另一种非 tag 布局：requests、regular imports、namespace imports、local exports、indirect exports、
  star exports，经 record 的 `moduleRecordIdx` 字段找到。
- **指令**：1 字节操作码，`0xfb`–`0xfe` 为前缀（callruntime / deprecated / wide / throw）再跟 1 字节子码；
  长度只由格式决定（71 种），查表即可线性遍历。共 332 个操作码（主表 226，前缀表 28 / 47 / 21 / 10）；
  `0xe2`–`0xfa` 和 `0xff` 无效，遇到即停止该方法的遍历。
  - `isa.yaml` 的动态指令没有“调用”属性，`asc-arkisa` 的 `is_call` 是手工名单（生成器的 `EXTRA_CALLS`）。
  - 带 `ic_slot` 属性的指令第一个立即数是内联缓存槽号，不是常量，`literal:` 搜索要跳过。
  - 8 个 `deprecated.*` 操作码带 32 位 id，是文件偏移而不是 region 索引。
- **ArkTS 动态语义**：
  - 调用（`callarg*`、`callthis*`、`callrange` …）不带 method_id，被调用者来自累加器 / 寄存器，常见
    `ldobjbyname "foo"` → `sta vN` → `callthisN`。
  - 带 method_id 的只有 `definefunc` / `definemethod` / `defineclasswithbuffer`，表示定义 / 创建闭包。
  - 属性访问按名字（`ld/st/define*byname`），无类型。
  - 导入：`ldexternalmodulevar k` → regular import k → 模块请求字符串（`@ohos:net.http`、`@normalized:N&…`）。
  - record 名是模块路径，样本里有三种写法，都要支持：
    `com.hmos.exam5.pkg/entry/ets/pages/Home`（包名开头，13.0.1.0 的文件也有）、
    `&entry/src/main/ets/pages/Index&`（normalized）、`&@ohos/crypto-js/index&2.0.0`（带版本的三方库）。
  - 类索引里还有伪 record：`_ESSlotNumberAnnotation`、`_ESTypeAnnotation`、`_ESTypeInfoRecord`、
    `_ESConcurrentModuleRequestsAnnotation` 等注解类，以及 `@ohos.app` 这类系统模块占位。`listclass` 默认不列，可用选项显示。
  - 函数名形如 `#~@0>#build`
    （`~` 类、`>` 实例方法、`<` 静态方法、`=` 构造函数、`*` 普通函数、`%` enum、`&` namespace，
    `@N` 查 scopeNames，`^N` 重名后缀；`@N` 和 `^N` 都是十六进制；标记后为空表示匿名）。
    scopeNames 只在 12.0.6.0 及以后出现，更早的版本用 `#<十进制数>#name` 或普通名字。
  - 行号：release 构建里 `line_start` 常是 -1，行表里也穿插 -1 行，取第一个有效行；有的文件没有任何行表行。
  - 闭包捕获走词法环境（`newlexenv`、`ldlexvar` / `stlexvar level, slot`）：被捕获的函数和类在使用处只是一个槽位，
    方法内追踪到此为止（见第 7 节的精度约定）。
- **`ets/sourceMaps.map`**：样本里都有，可作为后期的源码行号来源，不在当前范围。
- **版本**：0.0.0.2 – 26.0.1.0（`isa.yaml` 的 `api_version_map`）；不因版本不符失败。
  静态 ArkTS（`modules_static.abc`）文件头和 ISA 都不同，最后再做。

## 4. 仓库组织：合在一个项目

理由：

1. 共享部分占大头且仍在变：归档读取、三级磁盘缓存、内存 LRU、写入队列、多进程登记、配置、多归档调度、
   输出截断与落盘、daemon、MCP 会话。ABC 专有代码约 6–7k 行。拆仓库就要发布共享 crate 或锁 git 版本，
   重构期间接口频繁调整，跨仓库同步代价最高。
2. agent 只需一套查询语法、一份 SKILL.md、一个 MCP 配置、一个 daemon；两种格式的热缓存共用一份内存预算。
3. 样本目录常常 APK 与 HAP 混放；现有的“目录 / 逗号列表 = 一个程序”和多 APK sweep 可直接覆盖两种格式。
4. daemon 逐字节一致、缓存一致性、MCP schema 等测试只维护一套。

代价与对策：

| 代价 | 对策 |
|---|---|
| 编译时间、二进制体积 | 新增依赖都是纯 Rust，预计 +1–2 MB；先不加 feature 开关（只会多出 CI 组合），真有裁剪需求再加 |
| 两侧代码互相渗透 | `crates/android` 与 `crates/harmony` 互不依赖，只依赖 `crates/core`；CI 用 `cargo tree` 检查 |
| 名字带 “droid” | 暂不改；需要时加 argv[0] 别名（如 `arkasc`）或整体改名，与拆不拆无关 |
| 想接 abcd-rs 反编译（C++ FFI） | 唯一需要隔离的部分：做成外部工具或独立仓库，主二进制保持纯 Rust |

鸿蒙一侧交给别的团队、发版节奏明显不同，或共享层稳定到能单独发布时，再把 `crates/harmony` 移出去，成本很低。

目录：

```
crates/
  core/      asc-archive  asc-cache  asc-host                       (格式无关)
  android/   asc-dex  asc-dalvik  asc-findrefs  asc-rebuild  asc-smali  asc-axml  asc-arsc  asc-engine
  harmony/   asc-abc  asc-arkisa  asc-abcrefs  asc-pasm  asc-hap  asc-ark-engine
  asc-cli  asc-mcp  asc-fixture
```

在 P3 重构之前，新 crate 直接放进 `crates/harmony/`，现有 crate 原地不动。

## 5. 共享层重构（P3，行为不变）

放在 ABC 读取器和最小引擎之后做：届时共享层的边界由两个实例决定。在此之前鸿蒙引擎可以暂时直接依赖
`asc-apk` / `asc-cache`，前端用最薄的一层分派接入。

验收：`cargo test --workspace` 全部通过，Android 侧输出与 daemon 逐字节一致性不变，benchmark 不退化。

工作量比看上去大，按 3–5 个 PR 估：CLI / MCP 调用约 32 个不同的 `Engine` 方法；`asc-engine` 对外导出
`asc_arsc`、`SmaliOptions`、`ManifestSummary`、`DexClasses` 等 DEX 专有类型；CLI / MCP 还直接使用
`asc_findrefs::Query`，它是 DEX 形状的（`Type`、`Method(MemberQuery)`、`Virtual`）。

CLI / MCP 目前不直接引用 `asc_dex`，重构面主要在 `asc-engine` 内部（`lib.rs`、`classes`、`callgraph`、`hierarchy`、
`compose`、`condition`、`rules`、`hints`、`compact`、`prebuild`、`skip`、`defs` 直接使用 `Dex<'_>`）。

1. **新建 `asc-host`**，从 `asc-engine` 迁入：`config`、`budget`、`tiers`（线程 / 忙碌进程）、`text`；
   `EngineCache` 编排（内存 LRU、写入队列、并发解压去重、L2 预算）；`sweep` 的多归档调度与按内容去重
   （`Claim` / `DexDedup` 泛化为按条目）；`prebuild` 框架；程序打开（多文件、目录、逗号列表、`ApkKey`）。
2. **`asc-apk` 泛化为 `asc-archive`**：
   - `dex_entries()` 改为按格式选条目：DEX = 根目录 `classes*.dex`；ABC = `ets/*.abc`（以后加 `modules_static.abc`）；
     裸 `.dex` / `.abc` 文件。
   - 嵌套 zip（`.app` 装多个 `.hap`）：内层是 Stored 时直接在切片上解析；是 Deflate 时（样本里更常见）解压进 L1，
     再在缓存的映射上解析，不落临时文件。嵌套支持本身在 P2 就要有，这里只是把它并入通用归档层。
   - 条目名带所属包：`entry.hap/ets/modules.abc`，与 `services.jar/classes2.dex` 同一写法。
3. **`asc-cache` 去 DEX 命名**：`DexData` → `EntryData`；L2 kind 加格式前缀（`abc.region_inv`、`abc.callgraph` …）。
   HAP 内的 abc 本就是 Stored，不进 L1；L1 用于 `.app` 里被压缩的内层 hap。
   几 MB 的 abc 全量扫描本身就是毫秒级，`abc.*` 的 L2 先不做，在大型样本上量过再决定。
4. **查询语法分两层**：`KIND:VALUE`、`&`、`@file`、`{}` 嵌套、`all` / `rules`、`--limit` / `--offset` / spill 进
   `asc-host::query`；原子条件（kind 与名字写法）由各格式注册。`names.rs`（`Lc;->m(sig)`）留在 DEX 引擎。
   `condition.rs` / `rules.rs` 拆开语法解析与求值。`asc_findrefs::Query` 留给 DEX，鸿蒙侧有自己的查询类型；
   前端只持有“已解析的语法树 + 格式”，不再直接构造 `Query`。
5. **前端分派**：`enum Program { Android(asc_engine::Engine), Harmony(asc_ark_engine::Engine) }`，
   按扩展名和魔数（`dex\n` / `PANDA\0\0\0` / zip 内容）识别。命令名不变，各格式自己实现；
   不支持的选项给出可操作的报错（如 `--virtual is DEX-only`）。daemon socket 哈希、L3 key、MCP `apk_id` 不变。
6. **结果模型**：`RefResult` / `RefBatch` 移入 `asc-host`，行仍是 `entry | 位置 | 匹配内容`，位置由各格式格式化。

## 6. 新增 crate

| crate | 对应 | 内容 | 估计行数 |
|---|---|---|---|
| `asc-abc` | `asc-dex` | 零拷贝惰性读取：文件头、类索引二分、region、类 / 字段 / 方法 / 代码 / proto 访问器、MUTF-8、字面量数组、模块记录、调试信息、函数名还原；所有偏移做边界检查，畸形 / 混淆文件不 panic | ~2000 |
| `asc-arkisa` | `asc-dalvik` | 由脚本从 `isa.yaml` 一次生成并提交的操作码表（构建不需要 Ruby），操作数类型、线性遍历 | ~300 + 600 生成 |
| `asc-abcrefs` | `asc-findrefs` | 定位表（字符串 / 方法 / 字面量数组 / 属性名 / 导入）、代码扫描、方法内累加器 / 寄存器来源追踪 | ~1200 |
| `asc-pasm` | `asc-smali` | 按 record / 函数输出 pandasm 风格反汇编，字面量内联，立即数同时给十六进制和十进制 | ~700 |
| `asc-hap` | `asc-axml` / `asc-arsc` | `module.json`、`pkgContextInfo.json`（serde_json）；`resources.index` 后期 | ~300 + 后期 |
| `asc-ark-engine` | `asc-engine` 的 DEX 部分 | 鸿蒙查询编排 | ~1500 |
| `asc-fixture` 扩展 | — | 合成 abc / hap 写入器 | ~500 |

ABC 不需要 `asc-rebuild` 的对应物：按 record 反汇编可直接在原文件上做。反编译不做，SKILL.md 指向外部 `abcd decompile`。

## 7. ABC 查询原语

只提供原语，不内置规则或预设（领域知识由外部 agent 组合）。

| 命令 | ABC 语义 |
|---|---|
| `listclass` | record（模块），带 source_file 和函数数；`--prefix` 按模块路径过滤 |
| `getclass <record> [--method]` | pandasm 风格反汇编，字面量内联，数值写成 `0x1d4b42 (1919810)` |
| `findrefs string:` | `lda.str` 等字符串操作数 + 字面量数组中的 STRING |
| `findrefs prop:` | 属性名读写与定义：`ld/st/define*byname`，含 `callthisNwithname` |
| `findrefs global:` | `tryldglobalbyname`、`ldglobalvar` 等全局访问 |
| `findrefs import:` | `import:@ohos:net.http`、`@ohos:net.http#default`；`ldexternalmodulevar k` 解析到导入项 |
| `findrefs call:` | 方法内来源追踪的调用目标：`import:X.a.b(...)`、`this.foo(...)`、`global.f(...)`、本地 `definefunc`；追不到的标注出来 |
| `findrefs method:` | 函数的定义 / 创建位置（method_id 操作数与字面量 METHOD 项） |
| `findrefs literal:` | 数值常量：`ldai` / `fldai` 立即数与字面量 INTEGER |
| `callgraph` | 可解析的调用边：本地函数，导入 → 模块记录 → 导出 → 跨模块函数；不可解析的逐个标注 |
| `listclass --all` | 连同注解类、系统模块占位等伪 record 一起列出 |
| `hierarchy` | 每个 `defineclasswithbuffer`（含 sendable 变体）的父类寄存器按追踪器求值：无父类（hole）、本 record、跨 record（导入 → 导出 → 唯一写入者）、`[external]`、`[unresolved]`；装饰器重新赋值的类标 `[reassigned]`（弱解析）。`--method` 只看类字面量里的成员 |
| `getmanifest` / `manifest-summary` | `module.json`：abilities / extensionAbilities 的 exported、skills uris（deep link）、requestPermissions |
| `resources` / `xml` / `getclass --res-names` | `resources.index`（两种布局）；`xml` 原样打印包内文本文件（`$profile:NAME` 或路径，索引里没有的构建生成 profile 按 `resources/base/profile/NAME.json` 回退）；`$r` 对象字面量（`"id", N, "type", T`）按所在包的索引标注 |

与现有边界一致：只做方法内来源追踪，不做过程间污点分析。

`call:` / `callgraph` 的精度约定：

- 追踪以基本块为单位，线性前向：累加器和寄存器各记一个来源（导入项、全局名、`this`、属性链、本地 `definefunc`、
  字面量）。handler 和后向跳转的目标处清空状态；只被前向跳转（和落入）到达的目标，以所有入边一致的值开始，
  不一致或未知即未知（2026-11-10 放宽：带自引用的导出类编译成 `try … jmp L; L: … stmodulevar`，类值必须跨过标签，
  否则跨 record 的边只有 21,328 条，放宽后 50,594 条）。
- 来源是词法环境槽位（`ldlexvar`）、参数、调用返回值或跨块值时不猜，标为 `lex(level,slot)` / `arg N` / `?`。
- 例外（sound）：只在序言（第一个跳转 / 跳转目标 / try 起点之前的直线段）里写过、此后再没写过的寄存器，
  来源跨块保留。编译器把 `this` 和参数 `mov` 进这类寄存器。

实测（2026-11-10，`asc-ark-engine/examples/callsites.rs`，按被调用者的根来源分类，属性链并入根）：

| 根来源 | 样本 A（284,565 个调用点） | contacts 仅 `&entry/`（318） | contacts 全量（21,116） |
|---|---|---|---|
| Import | 28.0% | 10.4% | 0.2% |
| Global | 25.3% | 41.2% | 21.1% |
| This | 9.8% | 11.3% | 12.2% |
| 本地定义 / 模块局部 / Super | 2.0% | 4.1% | 2.2% |
| Lexical（`ldlexvar`） | 16.6% | 18.6% | 35.3% |
| Argument | 2.4% | 3.5% | 10.5% |
| CallResult | 6.4% | 6.3% | 10.5% |
| 其他块内计算值 | 0.5% | 0 | 0.7% |
| 跨块（未知） | 9.1% | 4.7% | 7.4% |

- 可直接解析（前四行）在 样本 A 上约 65%；不带序言例外时是 60.5%，跨块 15.6%，所以例外值得要。
- 词法环境在应用代码里占 16–19%（contacts 全量被一个 browserify 打包的三方库拉高），其中大头是
  “捕获的对象上的方法调用”。**结论：P4 做“同一 record 内 `stlexvar` 的唯一写入者”解析。**
- 被调用者位置：现行 `call*` / `callthis*` / `call*range` / `apply` 都在累加器；`newobjrange` 取区间首寄存器。

上表是最初的测量。词法环境解析和上面的规则放宽落地后（同日），样本 A 上：Import 29.1%、Global 26.3%、This 14.4%、
本地 / 模块局部 / Super 5.1%、外层函数的 `this@F` / `argN@F` 8.6%、未解析的词法槽位 1.5%（原 16.6%）、
Argument 2.8%、CallResult 9.0%、其他 0.7%、跨块 2.4%（原 9.1%）。

词法环境解析（`asc-ark-engine/src/scopes*`）：按 record 惰性做一趟；每条 `newlexenv` 是一个环境 site，
前向数据流求每条指令处的环境栈，汇合处同深度的 site 并成一类；函数的起始链来自定义它的指令处的栈。
一个（环境类，槽位）恰好有一条 `stlexvar` 写入且写入值可知才解析，链式最多 8 层。环境身份建立不了的函数
不解析，并污染相关槽位。样本 A 上以捕获变量为根的 53,548 个被调用者解析了 91.7%，剩下的主要是多个写入者。
代价：`call` 过滤查询 15 → 26 ms，全量 81 → 102 ms（16 线程）。

`callgraph`（`asc-ark-engine/src/callgraph*`，仅引擎）：边分为本 record 调用、经导入的跨 record 调用
（请求 → record → 导出链 → 唯一写入者 → 函数 / 类方法）、`[this-class]`（`this.name()` 按类字面量里的名字匹配，
不保证）、`[defines]`（创建闭包，不是调用）；其余调用点是 `[external]`（导入 / 全局为根，如系统 API）或
`[unresolved]` 叶子，不丢弃。无全局预处理：callees 只算涉及的 record，callers 按模块请求预筛选。
样本 A 全图 346,983 条边，16 线程 49 ms；callers 深度 3 为 18 ms，以 `^import:@ohos:net\.http` 这类外部路径为根 77 ms。
验证：用官方反汇编独立重推，49,094 个已解析的捕获变量、50,594 条跨 record 边、30,000 个随机调用点均未发现错误边；
callers / callees 双向一致。依赖但未在运行时源码里核实的语义：闭包捕获定义点的环境、生成器恢复后环境不变、
handler 进入时的环境、`stmodulevar N` 的索引空间。未做：sendable 环境、调用结果的类型（后来的进展见第 10 节）。

## 8. 分期

| 阶段 | 内容 | 验收 |
|---|---|---|
| P1 | `asc-arkisa`（生成器 + 操作码表 + 线性遍历）、`asc-abc`（读取器，含加密识别）、合成 abc fixture（含多 region） | ReArk 6 个样本和 样本 A 的解密 abc、`widgets.abc` 全部可解析，每个方法的指令流都能走到代码末尾；样本 A 加密的 abc 报“已加密”；畸形输入不 panic |
| P2 | `asc-pasm`；最小鸿蒙引擎 + 前端薄分派：`listclass`、`getclass`、`findrefs string:`；HAP（多个 abc）、裸 `.abc`、`.app` 嵌套（含 Deflate 内层）；调用点可解析率统计 | 全部样本端到端可查，样本 A 上给出耗时；反汇编与 `ark_disasm` / `abcd dis` 按语义比对一致（对照工具可用时） |
| P3 | 第 5 节共享层重构 | 测试全过，Android 输出逐字节不变，benchmark 不退化 |
| P4 | `findrefs` 其余原语（prop / global / method / literal / import / call）、跨模块调用图、module.json 摘要；HSP / 目录多模块程序视图；MCP 与 SKILL.md 补 ABC 用法 | 结果与对照一致；在补充的大型 HAP 上毫秒级；多模型 agent 评测，不对单一模型调参 |
| P5 | `resources.index`、`hierarchy`、`sourceMaps.map`；静态 ArkTS 视需要 | — |

ABC 主体（P1、P2、P4）约 6–7k 行；P3 约 3–5 个 PR。

## 9. 待定

1. crate 命名：倾向保留 `asc-engine` 不改名，新增 `asc-ark-engine`；`asc-host` / `asc-archive` 到 P3 再定。
2. 位置显示：位置列用规范名（可回填到查询），record 与函数之间用 `->`（与 DEX 行一致；带版本的 record 名
   `…&1.0.1` 后面接 `.` 很难读），如 `&entry/src/main/ets/pages/Index&->#~@0>#build+0x12`，
   追加一列还原名 `Index.build`；查询同时接受 `pages/Index.ets#Index.build`、`Index.build`（规则同 DEX 的 `B.name`）。
   三种 record 名写法都要能还原。
3. 对照工具：本机没有 `ark_disasm` / abcd-rs；样本 A 有一份官方 `ark_disasm` 的输出（本机，
   170 个 `.pa`，93,930 个函数，每条指令带文件偏移和原始字节），用它做全量语义比对。其他样本没有对照。
4. 样本：多 region 的大型样本、13.0.1.0 和 HSP 都已有（样本 A–D，见第 10 节）；9.0.0.0–24.0.0.0 由官方编译器现场编译覆盖；`modules_static.abc` 已定不做。
5. 已定：目录里加密的 hap 和解密的裸 abc 自动配对，只看文件头（版本、`file_size`、校验和字段相同）和正文确实
   算得出该校验和，不看文件名；目录里的文件按内容识别（魔数、zip 内容），扩展名只是兜底。
6. 数值常量搜索的 kind 名：第 7 节写的 `findrefs literal:` 与 DEX 侧已有的 `literal:TEXT`（字符串子串）冲突。
   倾向鸿蒙侧的 `literal:` 保持“字符串子串”的含义（CLI 已这样接入），数值常量另起名（如 `number:`）。
7. 同一目录里 DEX 与 HAP 混放：目前走 Android，stderr 提示鸿蒙文件被略过；已定：不做混合程序，鸿蒙文件单独给路径。
8. `asc-fixture` 依赖了 `asc-abc` / `asc-arkisa`，Android 侧 crate 的测试依赖链因此会编译鸿蒙侧 crate。
   “两侧互不依赖”的 CI 检查只看正式依赖，或到 P3 把 fixture 拆成两个 crate。
9. 裸包名形式的模块请求不解析到 record（样本 A 有 1007 个这样的请求，调用显示成 `[external]`）。
   需要用 `pkgContextInfo.json` 把包名映射到入口 record。
10. `[external]` 不等于系统 API：调用返回值的成员、没解析出的程序内静态方法也标 `[external]`。已做：后者改标 `[unlinked]`。
11. 经数组 / 表分发的调用（`handlerList[].handle`）是调用图的断点，只能用 `findrefs method NAME --exact --class RECORD`
    列出同名定义再逐个走；字面量行已补还原名。
12. 已定：子命令两种精确写法都接受（`--exact` 和 `=NAME`）；`--to` / `--from` / `--unless` 的过滤在引擎的遍历里做，前端只传规则。

## 10. 进度（2026-11-10）

- P1 完成：`asc-arkisa`、`asc-abc`、`asc-fixture` 的 ABC / HAP 写入器。
- P2 完成：`asc-pasm`、`asc-ark-engine`（`listclass` / `getclass` / `findrefs string:`，hap / 裸 abc / `.app` / 目录，
  加密识别与解密 abc 配对）、`asc` 薄分派（当时在进程内回答，P3a 起走 daemon；新增 `--all`、`--entry`）。
  调用点可解析率已量（第 7 节）。
- 与官方 `ark_disasm` 输出的全量比对（样本 A，`asc-pasm/tests/oracle.rs`，由 `$ASC_ABC_PA_DIR` 开启）：93,930 个函数、
  4,710,206 条指令及全部操作数、字面量数组、try 块、行号表逐项一致；查出并修掉 1 个 bug（phase 表被当成字面量数组）。
  对照没覆盖到的：样本 A 只用到 332 个操作码中的 158 个（`deprecated.*` 0 个、`wide.*` 4 个）；没有带类型的 catch、
  负立即数；`callthisrange` 的寄存器区间官方工具不打印；只有 12.0.6.0 这一个版本有对照。
- P4 进行中：
  - `findrefs` 其余原语已完成（引擎 + CLI）：`prop` / `global` / `import` / `method` / `number` / `call`，以及函数级合取的 `all`。
    与官方 `ark_disasm` 输出按指令偏移对比了 53 组完整命中集，差异为 0；`call` 的 284,565 个调用点一一对应。
    与第 7 节原文的出入：数值常量的 kind 叫 `number`；调用返回值写成带来源的链
    （`import:@ohos:net.http#default.createHttp().request`）；参数写成 `argN`；`call` 没有预过滤（样本 A 上全量 81 ms）。
  - MCP 已接入 `listclass` / `getclass` / `findrefs`（字符串）；新的引用种类和清单工具待接。
  - `asc-hap`（`module.json` / `pack.info` / `pkgContextInfo.json` 的模型与摘要、`srcEntry` → record 名规则）已完成，待接入引擎和前端。
  - 清单命令已接入引擎 / CLI / MCP（`getmanifest`、`manifest-summary`，每个 ability 的 `srcEntry` 接到实际的 record
    并列出 `onXxx` 回调；7 个样本全部解析）；MCP 的 `findrefs` 已补齐全部种类，工具列表体积未增加。
  - 词法环境解析和 `callgraph` 已完成（第 7 节），CLI / MCP 已接入：沿用 Android 的参数，`--to call:REGEX` 以外部路径为根，
    `--from method:NAME` 只保留从匹配函数到根的路径（前端按树过滤，引擎没有这个能力），另有 `--no-defines`、
    `--unresolved`、`--entry`。README（中英）和 SKILL.md 已补鸿蒙用法。
  - 审计走查（样本 A，“导出的 EntryAbility 的 deep link 流是否到达网络或 WebView”）：10 条命令、约 500 ms 走完。
    走不下去的地方见第 9 节 9–12。
- P4 完成。`all` 的排除与嵌套、`--context`、`callgraph --unless` 后补，见本节末。
- P3a 完成：daemon 驻留鸿蒙引擎，进程内与 daemon 输出逐字节一致，Android 输出与线协议不变。接缝只有三处：
  `asc_mcp::format::ProgramFormat`（唯一的格式判定）、`Engines::harmony`、`SharedCache::fit_resident_bytes`
  （两种引擎共用一份内存预算，映射字节按 1/8 计）。引擎提供 `stamp` / `is_current`（按文件大小和 mtime 判过期）、
  `memory_use` / `release_analyses`。样本 A 热态：`getclass` 2.4 ms、`callgraph --to` 26 ms（进程内 126 ms）；
  鸿蒙程序仍不走 L2 / L3。
- P3 其余部分的取舍：crate 改名、目录搬迁、新建 `asc-host` 暂不做（行为收益为零，`EngineCache` 没有鸿蒙使用者，
  等 `abc.*` 的 L2 有需求再定边界）。候选：`.app` 的 Deflate 内层包进 L1（缺大样本）、DEX + ABC 混合程序（第 9 节第 7 项）。
- P3b：`findrefs call` 与调用图共用词法环境分析，并按 record 保留调用点的被调用者路径；样本 A 上 daemon 热态
  30 → 4 ms，输出不变。首次查询多付约 6 ms（建缓存）。daemon 里缓存格式判定实测只省 0.05 ms，没做。
- P5（`hierarchy`、资源）完成：
  - `hierarchy`：样本 A 的 5843 个类定义里 66.3% 无父类、12.9% 在程序内（其中 137 处经 `[reassigned]`）、20.8% 外部、
    2 处追不到；用独立脚本对官方反汇编重推 5830 处，零差异。“hole = 无父类”没有在运行时源码里核实，依据是
    “构造函数有 `supercall` 当且仅当有父类”在样本上零例外。
  - 资源：索引每条命令解析一次、不缓存（16 个包 2.8 万个值约 6 ms）。资源 id 只在包内唯一。数组、复数、主题等
    复合值和密度、方向等限定词只按公开源码实现，没有样本。
- 新增三个大型样本（B、C：13.0.1.0；D：12.0.6.0、16 个包，其中 15 个 HSP，最大的 abc 91 MB）：
  - 官方对照扩到 22 个 abc：约 90 万个函数、4660 万条指令，零未知分歧；操作码覆盖 177 / 332。官方工具的原始输出是
    每个 abc 一个 `.pa`（带或不带 `--verbose`），由 `$ASC_ABC_PA` 给出，按内容与 abc 配对。不带 `--verbose` 的清单
    没有偏移和行号表，所以 13.0.1.0 的调试信息没有官方对照。
  - 13.0.1.0 的差异：文件头没有字面量数组索引；多一种注解 `_ESExpectedPropertyCountAnnotation`；没有表外操作码。
  - 可解析率（来源可确定 / 捕获变量已解析）：A 74.9% / 91.7%，B 71.5% / 82.7%，C 69.9% / 92.1%，D 73.3% / 86.1%。
  - 跨包静态导入（`@normalized:N&模块&…`）能解析到另一个包里的定义。跨包查 record 时，不含它的 abc 原先在二分
    未命中后整表扫描；现在每个 abc 只问一次索引是否有序（样本 D 上 callers 1.87 s → 0.64 s）。
- 对外名字改为 `asc`（命令、`ASC_*` 环境变量、配置与缓存目录、skill），不兼容旧名。
- 补全（同日）：
  - 调用图：装饰器类用与 `hierarchy` 共用的一份规则（`[reassigned]`）；`[super]`（父构造函数 / 父类方法）、
    `[inherited]`（本类没有、在最近的祖先里按名找到）、`[instance]`（模块级绑定的唯一写入者是 `new C()`）；callers
    方向逐层找子类，不做全局预处理（深度 1 约慢 15%，子类很多的基类最坏趋向全程序）；跨包请求先按指名的模块定位包
    （现有样本上 0 条边变化，只有合成夹具证明）；裸包名请求经 `pkgContextInfo.json` 解析（样本 A 1007 / 1007）。
    指向程序内函数的边：A 13.5 万 → 15.9 万，D 66.0 万 → 67.1 万。没做：单例 getter 的返回值、箭头函数里的 `super`、
    被第二个写入者写过的绑定。未在运行时源码里核实：`supercallthisrange` / `ldsuperbyname` 的语义、模块按名选包。
  - 输出：超过 2048 字节的字符串截断并带匹配处片段；多包相同的 `pack.info` 只列一次；配对成功合并成一行 `# note:`，
    对应关系在 `manifest-summary` 的 `abc` 行；页面清单和路由表展开成 `page` / `route` 行并接到 record（四个样本
    154 条路由、19 个页面全部接上）；所有命令都有 `--entry`（条目名、`/` 后缀或包名）。
  - 调试信息：本机装了官方 `ark_disasm`，全部样本导出了 `--verbose` 清单。行号表约 720 万行、列号表约 562 万行、
    局部变量约 4.6 万行全部一致；6 个小样本（9.0.0.0、12.0.2.0 等）首次有官方对照；合成夹具由官方工具现场反汇编
    对照（`$ASC_ARK_DISASM`）。列号是 32 位，`0xFFFFFFFF` 表示无列号（官方工具符号扩展成 64 位打印）。13.0.1.0 与
    12.0.6.0 的调试信息格式无差异。`getclass` 默认在函数头列出调试信息里的局部变量名（编译器自己的变量不列）。
  - 查询面对齐：规则只在引擎解析一次（`Query::rule`）。`all` 支持 `!条件` / `--none`；`call:{规则}` 是“调用了匹配该规则的
    函数”，走调用图的边，可嵌套 8 层，`call:{@FILE}` 读函数清单；`rules` 每条规则搜一次；`--context N|method` 输出
    `getclass` 清单并在命中行前加 `>`；`callgraph --to/--from/--unless` 都收规则，在遍历里过滤，命中 `--from` 处停止。
    组合里的 `method:` 指函数本身（单独用仍是定义位置）；`unresolved=N` 只统计本次遍历扫过的 record（原先冷热不一致）。
    没有调用点取值约束和虚分派。
  - 输入形态：解包目录（`module.json` + `ets/*.abc`）是一个包（`Root::{Zip, Directory}`、`Lazy::{Entry, Loose}`），
    `xml` 读的路径跟随符号链接后必须仍在包目录内，`Stamp` 覆盖每个成员；非模块包的 zip 按内容找内层包，
    上限：一个文件里 4 层、单条目 1 GiB、解压总量 4 GiB、超过 64 MiB 的压缩候选只按扩展名打开。
  - `ets/sourceMaps.map`：一个 JSON 对象，键 `构建包|所属包|版本|产物路径`，值是 source map v3（样本里 `names` 为空）。
    只在调试 / 自建包里有，上架样本都没有。abc 调试信息的行号是编译中间文件的 0 基行，不是源码行；map 把它映射回
    源码行，并能分出构建生成的函数（没有映射行）。只索引顶层字节范围，按需解析一个模块。
  - 调用图第二轮：类的成员不只在类字面量里——类体里第一个访问器（或计算名方法）之后的成员是定义后用
    `definemethod` + `stownbyname` / `definegettersetterbyvalue` 补上的（样本 A 里约 5000 个方法、5000 处访问器），
    现在都算类成员，`[this-class]` 因此增加 37%–83%。`[instance]` 扩到“函数 / 静态属性交出的确定类的对象”
    （`callgraph/made.rs`：每个 `return` 都是 `new K` / 持有 K 的静态属性 / 空值才算；样本 A 的 `getInstance().m`
    叶子 2333 → 831）；函数入口的热修复桩（“问补丁运行时是否
    被替换，是则返回它给的结果”）按固定形状识别（`callgraph/stub.rs`：对导入对象的一次调用，传一个各函数互异的整数、
    `this` 和全部参数；同一 record 至少 3 个函数同模板），它的 `return` 不计入；样本 D 的 `[instance]` 6132 → 12046，
    样本 A–C 不变。箭头函数里的 `super.m()` 沿
    `definefunc` 链找外层成员。`[external]` 只留给根在程序外的叶子，根在程序内而没接上的是 `[unlinked]`
    （占全部边的 2%–6%）。callers 方向每个类最多跟随 512 个子类（样本里最大的族是 387，上限从不触发），超出时
    行上标 `[N+ subclasses skipped]`。全图冷构建慢约 5%–8%。
  - 高版本：官方 `es2abc` 可产出 9.0.0.0（API 9–10）、11.0.2.0（11）、12.0.2.0（12）、12.0.6.0（12 beta3–17）、
    13.0.1.0（18–23）、24.0.0.0（24–26）。8 份自写源码的 141 个产物与官方反汇编零差异（`$ASC_ES2ABC` +
    `$ASC_ARK_DISASM` 开启的测试）。24.0.0.0 与 13.0.1.0 的同源产物除版本和校验和外相同。修了不合并布局
    （函数在 `_GLOBAL`，模块记录在 `_ESModuleRecord`，scope names 在 `_ESScopeNamesRecord`）和注解字段默认值；
    函数头列出用户注解。
  - 零散：`getclass --lines`；解包目录里 `xml` 读的文件同样限 1 GiB；source map 多个 `sources` 按 source index 映射；
    索引计入 `MemoryUse.source_maps`；包内 abc 条目按名字排序；kind 别名表只在引擎一处，CLI 也接受。
  - 注解与带名调用：`callthisNwithname` 与它前面同名的 `ldobjbyname` 在 `findrefs prop` 下合为一行 `[call]`，位置在调用
    指令；`findrefs string` 也搜用户注解的值和注解接口字段的默认值（`annotation @RECORD name="…"` / `annotation default …`，
    不参与 `all` 组合）；注解接口 record 名是 `<模块 record 名>.<接口名>`，以 `ACC_ANNOTATION` 标志为准，`listclass` 默认
    列出并标 `kind=annotation`。
  - 性能（同一大 APK，12 条命令，三种模式）：Android 输出与 `main` 逐字节相同，耗时内存持平。名字是 `.apk` / `.dex` /
    `.jar` / `.aar` / `.apex` 的文件不再打开来探测鸿蒙内容（否则每条命令多约 1 ms）。`--context` 连续命中同一函数时只
    反汇编一次（样本 D 上 1.5 s → 0.3 s）。鸿蒙热态 `findrefs` 每次重扫指令（10–80 ms），没有驻留的倒排索引。
- 待办：不带 callable-name 的调用行在 `ldobjbyname` 上，比调用点早几个字节；桩前有默认参数初始化、或 record 内带桩函数
  不足 3 个的不认；转发型 / 访问器型单例 getter、箭头函数里的 `super()`、命名空间成员调用仍是叶子；
  `hierarchy` 的 `[unresolved]` 与调用图的 `[unlinked]` 未统一。“路由名 → 导航调用点”用 `findrefs string` 回答，不设原语。
