[English](README.en.md) | 简体中文

# asc-rs — Droid ASC 的 Rust 实现

[Droid ASC](https://github.com/MG1937/ASC)（"R8 Compiler Optimization as a
DeCompiler Primitive"）的 Rust 移植版：一个无状态、零预处理的引擎，把 APK 当作只读数据库来用。
它直接在压缩产物上定位类、搜索交叉引用或解码 manifest，耗时以毫秒计，无需构建任何全局索引。

```
usage: droidasc [--debug] [--threads N] [--no-cache] [--cache-dir DIR] [--cache-max-mb MIB]
                [--memory-mb MIB] <COMMAND>

  getclass     Locate the target class in APK, extract one DEX in memory, then disassemble.
  disassemble  Same, without debug directives unless --debuginfo (Python's smali command).
  listclass    List classes across all DEX entries (--prefix com.poc to filter). Alias: classes.
  getmanifest  Decode AndroidManifest.xml from APK and print it as XML (--resolve: resource
               references by name). Alias: manifest.
  manifest-summary  The manifest's attack surface, one record per line (--json): exported
               components and why, permissions, providers, deep links, FileProvider paths,
               network security config.
  resources    Query resources.arsc: one resource (id or type/name, --resolve), --search, or
               the whole table, one line per resource and configuration.
  xml          Decode any binary XML file of the APK (res/xml/..., layouts) with names.
  findrefs     Find code references for string/type/method/field, or subclasses / implementors
               (extends / impl), across all DEX entries in APK.
  callgraph    Callers (default) or callees of a method across all DEX entries, as a tree.
  hierarchy    Transitive subclasses / implementers (or --supers) of a class, and overrides.
  mcp          Serve MCP tools over stdio, keeping opened APKs resident.
  cache        Inspect or clear the on-disk cache (path | stats | clear).

  --threads N      worker threads (default: logical CPUs split with your other busy mcp / daemon processes); --thread N also works
  --no-cache       bypass the on-disk cache of inflated DEX files
  --cache-dir DIR  use DIR instead of the default cache directory
  --cache-max-mb MIB  on-disk cache budget (default: automatic, see "Caching")
  --memory-mb MIB  in-memory budget of mcp / the daemon (default: automatic)
  --debug          profiling output on stderr
  --limit N / --max-bytes N / --offset N
                   keep stdout to N records / bytes (whole records), from record N;
                   the whole output goes to a file the last line names
  -v, -V, --version

examples:
  droidasc getclass app.apk 'Lcom/poc/Main;' -o Main.smali
  droidasc getclass app.apk com.poc.Main --threads 16 --dump-dex Main.dex
  droidasc disassemble app.apk com.poc.Main --debuginfo
  droidasc disassemble app.apk com.poc.Main --method 'run(I)V'
  droidasc listclass app.apk --prefix com.poc -o classes.txt
  droidasc getmanifest app.apk -o AndroidManifest.xml
  droidasc getmanifest app.apk --resolve
  droidasc manifest-summary app.apk | grep exported=true
  droidasc resources app.apk string/app_name
  droidasc resources app.apk 0x7f0d0001 --resolve
  droidasc resources app.apk --search 'https?://' --in value
  droidasc xml app.apk res/xml/network_security_config.xml
  droidasc getclass app.apk com.poc.Main --res-names
  droidasc findrefs app.apk string token -o string_refs.txt
  droidasc findrefs app.apk string 'https://' --literal
  droidasc findrefs app.apk type com.poc.Main
  droidasc findrefs app.apk extends android.app.Activity -o subclasses.txt
  droidasc findrefs app.apk impl android.os.IInterface
  droidasc findrefs app.apk method onCreate --class com.poc.Main
  droidasc findrefs app.apk method notify --class MainActivity --fuzzy-class -o method_refs.txt
  droidasc findrefs app.apk method run --class com.poc.Main --exact
  droidasc findrefs app.apk field apiKey -o field_refs.txt
  droidasc findrefs app.apk string token --no-cache
  droidasc findrefs app.apk string token --context 3
  droidasc findrefs app.apk method loadUrl --context method
  droidasc findrefs app.apk method android.webkit.WebView.loadUrl
  droidasc callgraph app.apk com.poc.Main onCreate --depth 3
  droidasc callgraph app.apk com.poc.Main 'run(I)V' --callees
  droidasc callgraph app.apk com.poc.Base run --virtual
  droidasc findrefs app.apk all 'string:https?://' 'method:android.webkit.WebView->loadUrl'
  droidasc findrefs app.apk all 'method:getDeviceId' --none 'method:~Log->d'
  droidasc findrefs app.apk rules 'string:http://' 'method:java.lang.Runtime->exec' --file rules.txt
  droidasc hierarchy app.apk android.webkit.WebViewClient --method shouldOverrideUrlLoading
  droidasc mcp --memory-mb 4096
  droidasc cache stats
```

成功时退出码为 0，出错时为 1；`findrefs` 或 `callgraph` 执行完毕但有部分 DEX 条目无法搜索时为 2
（每个这样的条目都会在 stderr 上打印一条警告）。

命令行和查询语义与 Python 工具一致；输出格式则是 asc-rs 自己的：每条记录一行，以 `|` 分列，便于
grep 和 cut。`findrefs` 的一行是 `dex | method | matched`：先是带完整签名的方法（可直接交给
`getclass --method` 或 `callgraph`），然后是它引用的内容，以 `, ` 分隔：字符串加引号并按 JSON
转义（多行字符串仍保持在同一行），类型写成描述符，方法写成 `Lcls;->name(params)ret`，字段写成
`Lcls;->name:type`。`extends` / `impl` 的行是 `dex | class | extends Lbase;`：

```
classes.dex | LWV/qE;-><clinit>()V | "http://", "http://www."
classes.dex | LWV/Sh;->onClick(Landroid/content/DialogInterface;I)V | "\n* If this app is available on Google Play, please include a URL:\n\nSteps to reproduce:\n…"
classes4.dex | Lcom/…/ConversationView;->onRestoreInstanceState(Landroid/os/Parcelable;)V | Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
classes8.dex | Lcgjc;->apply(Ljava/lang/Object;)Ljava/lang/Object; | Landroid/os/Build$VERSION;->SDK_INT:I
classes4.dex | Ldxbs; | extends Landroid/webkit/WebViewClient;
```

找到的行与 Python 工具相同（`benchmark/parity/semantic.py` 按 dex、方法和匹配集合对两者做比较）。

`getclass` 和 `disassemble` 支持 `--method`，只输出部分方法：可以是方法名（所有重载）、精确签名
（`'run(I)V'`）、签名前缀或 Java 风格的签名（`'run(int)'`）；若类中没有该方法，命令会失败并列出它
已有的方法。`findrefs extends` / `impl` 列出直接父类 / 某个直接接口为目标的类（目标可用点分形式或
Dalvik 形式）。`findrefs string --literal` 按普通子串匹配，而不是 regex。

`findrefs --context N` 在每条结果之后打印引用所在的位置及其周围的 smali，这样下一步很少还需要
`getclass`；`--context method` 打印整个方法（超过 150 行的方法改为显示每处引用前后各 10 行）：

```
classes.dex | Lcom/poc/Main;->run()V | "token"
  @ pc 0x4 line 12
        .line 12
  >     const-string v0, "token"
        invoke-static {v0}, Lcom/poc/Net;->send(Ljava/lang/String;)V
```

`callgraph APK CLASS METHOD` 跨 DEX 文件遍历调用者（或 `--callees` 被调用者），共 `--depth` 层
（默认 2，最多 `--max-nodes` 个方法，默认 500）。`METHOD` 是方法名（所有重载）或精确的
`name(params)ret`。每次调用一行；`[no body]` 标记 APK 中没有任何 DEX 定义的方法（framework / SDK），
`(repeated)` 标记已在别处展开过的方法：

```
0 Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V [no body]
  1 <- Lcom/poc/Web;->open(Ljava/lang/String;)V
    2 <- Lcom/poc/DeepLink;->onCreate(Landroid/os/Bundle;)V
# 3 rows, 3 distinct methods (callers, depth 2)
```

调用图基于字节码中的静态引用：通过 `Lcom/poc/Sub;->m()V` 发起的调用不算作对
`Lcom/poc/Base;->m()V` 的调用。加上 `--virtual` 后，它会沿类层次跟踪分派：一个方法的调用者还包括
各个父类型上同一签名的调用者（`(via Lcom/poc/Base;)`），被调用者还包括每个被调用方法在其子类中的
重写（`(override of Lcom/poc/Base;)`）。

`findrefs APK all COND...` 查找代码满足所有条件的方法，`--none COND` 排除满足另一条件的方法。条件
写作 `KIND:VALUE`：`string:REGEX`、`literal:TEXT`、`type:PATTERN`、`method:TARGET`、
`field:TARGET`。TARGET 是 `[CLASS->]NAME`，也可写成 `com.a.B.name`、`com.a.B#name` 或
`Lcom/a/B;->name(I)V`（CLASS 为精确匹配，`~CLASS` 为模糊匹配，不带包名的类如 `WebView` 可匹配任意
包；NAME 为 regex / 子串，`=NAME` 或带签名的名字为精确匹配）。带签名时只命中该重载：`name(I)V`、只写参数的
`name(I)`（任意返回类型）、Java 写法 `name(int, String)`（不带包名的类匹配任意包），字段写 `f:I`。`findrefs method` / `field` 也接受同样
的 TARGET 来代替名字，且 kind 的写法很宽松（`methods:`、`Method:`）。matched 列按顺序列出每个条件
匹配到的内容。`findrefs APK rules RULE...`（以及 `--file`，每行一条规则）在每个 DEX 上只扫描一遍就
回答多个查询，结果行带有 `r1 | `、`r2 | `... 前缀；一条规则可以是一个条件、`extends:CLASS` /
`impl:CLASS`，或用 `&` 连接的多个条件。在抖音上，八条审计规则用一次 `rules` 调用耗时 114 ms，而作为
八个 `findrefs` 进程则需 700 ms。

查不到结果时会提示接下来该怎么做。APK 中未定义的类要么是 framework 类（可用 `findrefs type` /
`extends` 查找其用法），要么会给出 APK 中最接近的已定义类；找不到方法时会列出该类的方法；没有结果的
搜索会在 stderr 上（MCP 中为 `# hint:` 行）打印搜索了多少个 DEX 条目，以及可能找不到的原因
（模式区分大小写、没有任何 DEX 引用该类、成员存在但从未被引用）；缺失的资源文件和名称会提示布局已被
shrink。

`hierarchy APK CLASS` 跨 DEX 文件打印传递的子类和实现类（`--supers`：父类和接口），每个类一行，附带
其所在 DEX 或 `[not in APK]`；`--method NAME` 标记定义了该方法的类，并为每处定义添加一行
`override Lcom/poc/Sub;->m(...)V classes2.dex`：

```
0 Landroid/webkit/WebViewClient; [not in APK]
  1 subclass Lcom/poc/WebClient; classes.dex [defines shouldOverrideUrlLoading(Landroid/webkit/WebView;Ljava/lang/String;)Z]
    2 subclass Lcom/poc/StrictClient; classes2.dex
override Lcom/poc/WebClient;->shouldOverrideUrlLoading(Landroid/webkit/WebView;Ljava/lang/String;)Z classes.dex
# 3 rows, 3 distinct classes (subclasses, depth 16); 1 define shouldOverrideUrlLoading
```

为其他 Rust 移植版编写的脚本仍然可用：`classes` 和 `manifest` 是 `listclass` 与 `getmanifest` 的
别名（同 rasc），`--thread` 是 `--threads` 的别名（同 rust_ASC），`--literal` 提供它们的字面量字符串
匹配。

## 构建

```sh
cargo build --release                       # -> target/release/droidasc
cargo test --workspace
```

需要 Rust 1.85 或更高版本。

## Workspace 结构

| crate | 作用 |
|---|---|
| `asc-dex` | 零拷贝 DEX 解析器：header、id 表、MUTF-8、LEB128、class data、code item、encoded value、debug info、annotation、DEX 041 容器、checksum/signature。 |
| `asc-dalvik` | Dalvik 操作码表（由 ART 的 `dex_instruction_list.h` 生成）、指令格式、操作数解码、能识别 payload 的指令遍历。 |
| `asc-findrefs` | 单个 DEX 上的交叉引用搜索：regex / 字面量（`memmem`）字符串定位器、基于 `class_def_item` 的子类 / 实现类查找、类型/方法/字段定位器、稠密的 16 字节分桶 指令→方法 解析器、原始代码区操作码扫描。 |
| `asc-rebuild` | 提取一个类及其引用的全部内容，写出一个最小且符合规范的 DEX（排序的 id 表、annotation、debug info、try/catch、静态值、Adler-32 + SHA-1）。 |
| `asc-smali` | baksmali 风格的反汇编器，作为内置输出后端。 |
| `asc-apk` | 内存映射的 zip 访问：central directory（含 zip64）、根目录 DEX 枚举、Deflate 解压（libdeflate，或用于前缀 / 取消的流式 zlib-rs；一次性 `findrefs` 先流式解压前缀，跳过据此可判定不可能匹配的条目）。 |
| `asc-cache` | 解压后 DEX 的缓存：跨进程共享的磁盘 cache，以及供常驻宿主使用、按字节限额的内存 LRU。 |
| `asc-axml` | Android 二进制 XML：文本 XML、元素树、通过 resolver 将引用解析为名称；惰性字符串池。 |
| `asc-arsc` | `resources.arsc` 读取器：只索引 chunk，按需解码名称和值（u32 / 16 位 / 稀疏 entry 表、紧凑 entry、bag、library / overlayable / staged-alias chunk）；按配置取值、AOSP 配置匹配和引用解析。已与 `aapt2 dump resources` 对照验证（`benchmark/arsc-compare`）。 |
| `asc-engine` | 编排层：带提前终止的并行类查找、流式多 DEX 引用搜索、类重建 + 反汇编、manifest 解码与摘要、资源查询。 |
| `asc-mcp` | 基于 stdio 的 MCP 服务器（`droidasc mcp`）：一个常驻会话，多个 APK 共享同一内存预算，CLI 格式的文本加结构化结果，分页。 |
| `asc-cli` | `droidasc` 可执行文件（clap）。 |
| `asc-fixture` | 测试共用的合成 DEX/APK fixture。 |

各部分如何对应 Python 模块、移植在哪些地方有意与之不同，见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。

## 与 Python 实现的差异

* **`getclass` 输出的是 smali，而不是 Java。** Python 工具依赖 androguard 的反编译器，而 Rust 中没有
  等价的库。作为替代，重建出的 DEX 是一个完全合法的单类 DEX（表按规范排序，checksum 和 signature
  正确），因此可以用 `--dump-dex` 写出，再交给 jadx、baksmali、dexdump 或任何其他工具。已验证 jadx
  能把这样的 DEX 文件反编译为 Java。`disassemble`（上游的 smali 命令）共用同一后端：输出为 baksmali
  风格而非 dadguard 格式，`--debug` 会加上耗时信息，但不加逐指令的偏移注释。
* **正确的字符串解码。** 非 ASCII 的类名和成员名（在混淆应用中很常见）按 MUTF-8 解码；Python 版本会
  将其截断。
* `findrefs` **使用线程而非进程**；结果按 DEX 顺序流式输出（前面的 DEX 完成后立即输出）。`getclass` 在任一 worker 找到该类
  后立即返回；仍在解压其他 DEX 的 worker 会在后台完成。
* 全局的 `--debug` / `--threads` 参数可以出现在命令行的任意位置；`--threads 0` 以一个 worker 运行
  （Python 的 `listclass` 会拒绝它）。
* 根目录下的每个 `*.dex` 都是一个 DEX 条目（Python 优先选 `classes*` 名称），重名条目取 central
  directory 中的最后一条记录（Python：第一条）。这一点对 `getclass`、`findrefs` 和 `listclass` 都成立。
* 重建时会重映射 `invoke-polymorphic` 的方法和 proto 操作数（Python 版本让它们悬空）；
  `invoke-custom` / method handle 仍不重建。无法重建的类（未定义的操作码、`invoke-custom`）仍会显示，
  直接从原始 DEX 反汇编，并在 stderr 上给出警告；此时 `--dump-dex` 会被拒绝。
* regex 的边界细节有所不同：跨越多个字符串项的匹配归属于它*开始*所在的项（Python：结束所在的项）；
  模式使用 `regex` 的 Unicode 语义，因此 `.` 不会像 Python 的字节 `re` 那样跨过 MUTF-8 编码的 NUL
  字节或代理项；空的 `string` 模式什么也不匹配（Python：匹配所有字符串）。
* `findrefs extends` 直接比较每个 `class_def_item` 的 superclass 字段；Python 用非重叠 regex 扫描紧凑
  排列的表，理论上可能让一个对齐的匹配被一个未对齐的匹配遮住（在参考 fixture 上没有任何一行不同）。
  `findrefs string --literal` 以及 `classes` / `manifest` 别名是扩展功能，Python 中没有对应项；
  `classes` 保持 `listclass` 的输出（而不是 rasc 的 `dex | descriptor | java name | package= | class=`
  行），也没有 `-f/--filter`。
* 只要资源 id 是已知的 framework 属性，`getmanifest` 就根据资源 id 为属性命名（androguard 只在池中名称
  为空时才这么做），因此混淆过的 manifest 显示为 `android:name` 而不是 `android:a`；未知 id 打印为
  `attr_0x........`。
* 没有 GUI：Python 工具的 Tk 浏览器没有移植（egui 浏览器在 2026-10 前存在过；agent 使用 CLI 和 MCP）。

## 性能

在 Linux 上测量（本工作站，8 线程，page cache 已预热，取 5 个全新进程的中位数，输出丢弃），测试对象
是由真实应用拼装而成的合成 14-DEX / 95 MB APK，并与上游 `rust` 分支（`rasc`）和 Python 参考实现
（CPython 3，androguard 4.1.3）并列对比：

| 场景 | rasc | asc-rs | Python | 行数 rasc / asc-rs / Python |
|---|---:|---:|---:|---|
| `findrefs string Authorization` | 64 ms | 64 ms | 208 ms | 44 / 44 / 44 |
| `findrefs string okhttp` | 63 ms | 63 ms | 206 ms | 19 / 19 / 19 |
| `findrefs type Gson` | 63 ms | 65 ms | 229 ms | 369 / 369 / 369 |
| `findrefs method onCreate` | 64 ms | 69 ms | 287 ms | 645 / 654 / 654 |
| `findrefs method onCreate --class androidx --fuzzy-class` | 64 ms | 66 ms | 263 ms | 168 / 168 / 168 |
| `findrefs field INSTANCE` | 64 ms | 65 ms | 267 ms | 530 / 531 / 531 |
| `getclass` 靠前的类（`classes.dex`） | 251 ms | 36 ms | 2041 ms | Java / smali / Java |
| `getclass` 靠后的类（`classes13.dex`） | 88 ms | 82 ms | 288 ms | |
| `getclass` 不存在的类 | 30 ms | 20 ms | 258 ms | |
| `getmanifest` | 3 ms | 2 ms | 128 ms | |
| **相对 Python 的几何平均加速比** | **5.6×** | **7.3×** | | |
| 几何平均，仅 `findrefs` | 3.8× | 3.7× | | |

asc-rs 找到的行与 Python 参考实现相同（采用自己的行格式）；rasc 使用字面量、按指令边界的匹配，会漏掉
少数几行。`getclass` 的输出性质不同（rasc 反编译为 Java，asc-rs 反汇编），因此这一行衡量的是不同的
工作。上游 README 中的 8.0× 数据是在 macOS 上测得的，那里 Python 进程池的启动要慢得多；在 Linux 上，
两个 Rust 移植版在引用搜索上都在 3-4×，其上限取决于解压最大的那个 DEX。

达到这一结果所做的工作，按影响大小排序：

* 指令→方法 的分桶表是覆盖代码区的稠密 `Vec<u32>`（按区间填充，而不是每个 16 字节桶做一次哈希插入）；
* Deflate 条目用 libdeflate 解压（`asc-apk` 的 `libdeflate` feature，默认开启；
  `--no-default-features` 保留纯 Rust 的 zlib-rs 路径）；
* `findrefs` 先分发最大的 DEX：它的解压是关键路径，不能排在小 DEX 后面（Python 和 rasc 的顺序是
  从小到大）；
* `getclass` 对每个 DEX 只流式读取 id 表和字符串数据（通常约为三分之一）来判断类是否定义在其中，只完整
  解压命中的那个；
* release profile 使用 fat LTO 和单个 codegen unit。

## 重复查询的缓存

解压最大的 DEX 是每次查询的关键路径，而且每次得到的字节都相同，所以引擎会缓存解压后的条目。不做任何
预计算：第一次查询付出正常开销，并顺带填充 cache。

* **磁盘 cache**（`~/.cache/droidasc`，或 `$DROIDASC_CACHE_DIR` / `$XDG_CACHE_HOME`），CLI 默认开启，
  在进程间共享。条目以 APK 的大小、mtime 和 central directory 为键，原子写入，下次运行时通过内存映射
  读取，分为三层，共用一个预算（见下文）。写入不做 sync（cache 总能重建）；每个文件都带 CRC-32，对于在
  上次重启之前写入的文件，会在第一次读取时校验，因此因崩溃而写了一半的文件只会是未命中，绝不会给出错误
  答案：

  | 层 | 存放内容 | 写入时机 | 淘汰 |
  |---|---|---|---|
  | L1 | 解压后的 DEX 条目 | 解压后大小不小于 4 MiB（`$DROIDASC_CACHE_MIN_DEX_MB`）：重新解压小 DEX 比写盘更便宜 | 最先淘汰，按最大、最旧优先 |
  | L2 | 每个 DEX 的定位表和调用图，格式可供下一个进程映射后原地读取（所有映射它们的进程共享同一份） | 构建耗时不少于 2 ms | 最后淘汰，按每字节节省的重建时间从少到多 |
  | L3 | `findrefs` 结果，以查询、其选项和工具的构建版本为键 | 查询无错误完成且结果小于 4 MiB | 独立预算：min(128 MiB, 总量的 1/8)，最旧优先 |

  此后被删除或替换的 APK 的条目最先被清理。`$DROIDASC_CACHE_TIERS=dex,derived,rendered` 选择启用
  哪些层（默认全部）。写入由后台线程排队执行，因此查询从不等待自己的 cache 条目写完（进程退出前仍会
  完成已排队的写入）。目录中带有 `CACHEDIR.TAG`；如果 `--cache-dir` 中已有其他文件（包括点文件），会被
  直接拒绝并给出警告，磁盘 cache 随之禁用（不在那里写入、打标记、淘汰或清理任何东西），而且淘汰和
  `cache clear` 只会处理符合 cache 自身命名形式的条目目录。`--no-cache` 绕过它，`--cache-dir` 改变其
  位置，`droidasc cache path|stats|clear` 管理它（`stats` 打印每层的用量、预算及其来源，以及文件系统的
  剩余空间）。
* **内存 LRU**（`mcp`、daemon 和嵌入方，`CacheConfig::resident`），还会保留为每个 DEX 构建的
  定位表，因此第二次查询只需运行 regex、扫描以及 偏移→方法 解析。它的预算也把这些表计算在内（在字符串
  和类型查询之后，抖音 437 MB 的 DEX 之外还有 102 MB），常驻进程会根据机器来确定预算：可用内存
  （`MemAvailable`，若 cgroup v2 余量更低则取后者）的四分之一，限制在 64 MiB–2 GiB 之间，这样同时运行
  多个常驻进程时不会各自占用 2 GiB。开启磁盘 cache 时，堆上解压的条目会在其 cache 文件写好后（经过逐字节
  校验）立即替换为对该文件的映射，定位表也替换为其 L2 文件的视图，因此常驻条目是操作系统可以回收、并可
  在进程间共享的文件页，而不是匿名内存。APK 中以未压缩方式存储的条目（几乎所有系统应用都是如此）直接从
  APK 本身映射。

除非指定具体数值，两种 cache 都会根据机器自动确定大小：

| | 自动预算 | 显式指定 |
|---|---|---|
| 磁盘 | cache 可容纳量（自身字节数 + 文件系统剩余空间）的 20 %，最多 32 GiB，且绝不会使剩余空间少于 max(1 GiB, 文件系统的 5 %)；无法读取剩余空间时（Windows）为 4 GiB | `--cache-max-mb MIB`，否则 `$DROIDASC_CACHE_MAX_MB` |
| 内存（mcp、daemon） | 用户所有正在运行的 `mcp` / daemon 进程共用一个预算，平均分配：(可用内存 + 它们的 cache 所占) 的四分之一，除以进程数，每个 64 MiB–2 GiB；无法读取时为 2 GiB。每个进程在 `$XDG_RUNTIME_DIR/droidasc` 中登记，并最多每秒重读一次登记表 | `--memory-mb MIB`（固定值；仍会登记，以便其他进程将其计入） |
| 线程 | 逻辑 CPU 在本进程与该用户其他已登记、且正在处理请求（MCP 工具调用或 daemon 命令）的 `mcp` / daemon 进程之间平均分配（agent 两次调用之间空闲的服务器不计入），总数最多每个 CPU 4 个 worker：忙碌进程不超过 4 个时每个进程都用满全部 CPU，最少 2 个；注册表最多每 100 ms 读一次，多 APK 扫描在进行中也会随其他进程开始、结束而收缩或恢复。一次性命令会计入常驻进程，但自己不登记 | `--threads N` |

磁盘预算在每次淘汰时重新计算（每一批写入一次，与之前同样的目录遍历），每次按自动预算写入前先用一次
`statvfs` 检查剩余空间：会侵占保留空间的条目不会写入；当其他程序把磁盘写满时，下一次淘汰会把 cache
缩小到低于当前占用，最旧的 APK 优先。一次性 CLI 命令不保留内存 cache，所以 `--memory-mb` 只对 `mcp`
和 daemon 有意义。

一个持有常驻引擎的进程的常驻内存（16 线程，抖音 40.7.0 = 437 MB 的 DEX，然后在同一进程中打开快手
和小红书；每个都做类扫描加三次查询）：

| | 之前的匿名内存 | 之后的匿名内存 | 之后的文件页 |
|---|---:|---:|---:|
| 抖音，首次打开（磁盘 cache 冷） | 549 MB | 111 MB | 439 MB |
| 三个 APK，首次打开 | 1150 MB | 224 MB | 910 MB |
| 三个 APK，磁盘 cache 已预热 | 227 MB | 225 MB | 923 MB |
| 三个 APK，`--no-cache` | 1148 MB | 1146 MB | 2 MB |

仍是匿名内存的部分是定位表。没有磁盘 cache 时这些字节无处可映射，所以 `--no-cache` 像以前一样把它们
留在堆上。

同一个 14-DEX / 95 MB APK，8 线程，取 5 个全新进程的中位数：

| 场景 | 冷 | 磁盘 cache 已预热 |
|---|---:|---:|
| `findrefs string Authorization` | 65 ms | 9 ms |
| `findrefs string okhttp` | 63 ms | 9 ms |
| `findrefs type Gson` | 64 ms | 12 ms |
| `findrefs field INSTANCE` | 65 ms | 19 ms |
| `findrefs method onCreate` | 65 ms | 21 ms |
| `getclass` 靠前的类 | 38 ms | 12 ms |
| `getclass` 靠后的类 | 80 ms | 3 ms |
| `getclass` 不存在的类 | 25 ms | 2 ms |

内存 cache 已预热时，对同一归档的引用搜索只是每个 DEX 一次扫描（4 MB 代码区约 4 ms），完全不需要构建表。

扫描本身会根据查询自适应：最多八个目标索引时，用 SIMD `memmem` 在操作数字节上查找（每 4 MB 0.2 ms，
而不是 3 ms），字符串查询对其两个操作码使用 `memchr2`，而聚集的索引集合在线性扫描前先用 `memchr`
按共同的高位操作数字节做预过滤。

## 面向 agent 的输出

每个一次性命令每行输出一条记录（`dex | Lcls;->m(..)V | "matched"`，各列以 ` | ` 分隔）；以 `#` 开头的行是
表头、合计和提示。`findrefs`（单条查询和 `rules`）按 DEX 顺序输出（`classes.dex`、`classes2.dex`……然后是
其他名字），每次运行都相同，前面的 DEX 完成后立即流式输出。

只有显式要求时才截断长输出，脚本仍能拿到完整输出：

| 选项 | 作用 |
|---|---|
| `--limit N` | stdout 最多 N 条记录（findrefs 的一条结果连同其 `--context` 行算一条；smali、类名和树的每行各算一条） |
| `--max-bytes N` | stdout 最多 N 字节的记录，只输出完整记录 |
| `--offset N` | 跳过前 N 条记录（下一页） |
| `--spill-mb MIB` | 截断输出写入目录的预算（cache 目录下的 `out/`，默认 64；0 表示不写文件） |
| `$DROIDASC_LIMIT`、`$DROIDASC_MAX_BYTES` | `--limit` / `--max-bytes` 的默认值，供 agent 宿主统一设置 |

窗口截断输出时，完整输出写入一个文件（按内容命名，重跑会得到同一个文件；给了 `-o FILE` 时就是该文件），
stdout 的最后一行说明显示了哪些、其余在哪里：

```
# records 1-50 of 523 shown; full output in /home/u/.cache/droidasc/out/3f2a….txt (grep it, or rerun with --offset 50)
```

`#` 表头和合计行（`# r1 ...`、`# r1 523 results`、树的页脚）总是显示。子命令的 help 只列出该命令自己的选项；
cache 和线程选项由 `droidasc --help` 统一列出一次。[`skills/droidasc/SKILL.md`](skills/droidasc/SKILL.md) 是一个
[Agent Skill](https://agentskills.io/specification)，包含命令、查询语法和审计流程，供通过 shell 工作的 agent 使用。

## Daemon：预热的一次性命令

在 Unix 上，每个一次性命令（`findrefs`、`getclass`、`callgraph`、`hierarchy`、`manifest-summary`……）
都通过一个按用户运行的 daemon 来应答，daemon 会让已打开的 APK 常驻内存，因此逐步调用 CLI 的 shell 或
agent 无需 MCP 客户端也能获得接近 MCP 的延迟。命令的写法和输出都没有任何变化：stdout、stderr 和退出码
与不使用 daemon 运行时逐字节一致。

* 第一个命令会启动 daemon（`droidasc daemon serve`，分离运行），最多等它 300 ms
  （`DROIDASC_DAEMON_WAIT_MS`），就绪后把自己交给它处理，否则自己运行；daemon 空闲 15 分钟后退出
  （`DROIDASC_DAEMON_IDLE`，单位秒，取启动它的那个命令的环境）。
* 客户端断开（Ctrl-C）会取消正在执行的命令：`findrefs`、`getclass`、`callgraph`、`hierarchy`
  都会在 DEX 之间停下。
* 打开的 APK 的类图和资源表计入 daemon 的内存预算，最多占一半，超出时关闭最久未用的 APK，其余预算留给
  解压后的 DEX。
* `--debug` 和 `--no-cache` 总是在调用进程中运行，`mcp`、`cache` 和 `daemon` 也是如此。
  `DROIDASC_DAEMON=off` 关闭 daemon。
* 每种构建和 cache 配置（`--cache-dir`、`--cache-max-mb`、`DROIDASC_*`（`DROIDASC_DAEMON*` 除外）、umask）对应一个 daemon：重新
  构建的二进制会启动新的 daemon，并让旧的退役。
* `droidasc daemon status` 列出正在运行的 daemon，`daemon stop` 停止它们，`daemon start` 提前启动一个。
* socket 位于只有该用户能进入的目录（`$DROIDASC_RUNTIME_DIR/daemon`、`$XDG_RUNTIME_DIR/droidasc/daemon`，
  否则为 `<temp dir>/droidasc-<uid>/daemon`），两端都会校验对端的 uid。用 Ctrl-C 杀掉的客户端会取消它在
  daemon 中的搜索。

抖音（360 MB，55 个 DEX，16 线程），每个命令一个进程，磁盘 cache 已预热：

| | 不用 daemon | 使用 daemon |
|---|---:|---:|
| 47 步 agent-audit 回放 | 176 ms | 135 ms（MCP 会话：55 ms） |
| 首次查询，cache 为空 | 256 ms | 81 ms |
| 第二次查询，换一种类型 | 234 ms | 9 ms |
| `hierarchy android.app.Activity`（1343 行），重复执行 | 500 ms | 6 ms |
| `callgraph WebView loadUrl --virtual`，重复执行 | 400 ms | 5 ms |

每个命令约有 1.6 ms 是进程启动本身，daemon 无法消除；包含大量调用的长会话仍然是走 MCP 更划算。

## MCP 服务器

`droidasc mcp` 是面向 agent 的常驻会话：一个基于 stdio 的 MCP 服务器（JSON-RPC 2.0，每行一条消息）。它
把打开的每个 APK 都保留在同一进程中，因此解压后的 DEX 文件和定位表在调用之间留在内存里，而不必每个问题
都由新进程重新构建。所有已打开的 APK 共享一个内存预算（`--memory-mb`，默认为可用内存的四分之一，最多
2048 MiB；从磁盘 cache 或 APK 映射的 DEX 和表按其大小的 1/8 计算，因为它们是共享的、可回收的文件页）；
`close_apk` 释放该 APK 占用的份额；磁盘 cache 的用法与 CLI 相同（`--no-cache`、`--cache-dir`）。工具
调用并发执行（慢查询不会阻塞 `ping` 或其他调用；回复带有其请求 id，可能乱序到达），单个调用内的 panic
会作为错误结果返回，而不会终止会话。

```json
{
  "mcpServers": {
    "droidasc": { "command": "/absolute/path/to/droidasc", "args": ["mcp"] }
  }
}
```

| 工具 | 参数 | 结果 |
|---|---|---|
| `open_apk` | `apk`、`warm`（默认 true：立即解压所有 DEX）、`prebuild`（默认 true：随后在后台构建搜索表，查询优先）；或 `apks` / `dir` | `apk_id`；同一路径返回同一 id。对于多个 APK：每个 APK 一行（id、DEX 数量和大小、路径），不做任何解压 |
| `close_apk` | `apk_id` 或 `apk` | 释放该 APK 在内存 cache 中的份额 |
| `getclass` | `class`、`method`（方法名：所有重载；`name(params)ret` 或其前缀）、`full`、`debug_info`（默认 false）、`resource_names`（默认 true） | smali，同 `droidasc getclass --res-names`：值为资源 id 的常量以 `# @type/name` 结尾。超出输出预算的类会以大纲形式给出（header、字段、每个方法的声明及其指令数和大小），除非指定 `full`；未知的 `method` 会报错并列出该类的签名 |
| `findrefs` | `kind`（`string`/`type`/`method`/`field`/`extends`/`impl`）、`value` 或 `name`、`literal`、`class`、`fuzzy_class`、`exact`、`context`（N 行或 `"method"`）、`offset`、`limit`（500） | 按 DEX 顺序的 `findrefs` 行（每行后跟其上下文），然后是一行 `# N results`；`structuredContent` 的行包含 `dex`、`method`、`signature`（完整）和 `matched`（不带引号的值）；带 `context` 时还包含 `sites`（`pc`、`line`、`matched`）和 `context` |
| `findrefs`（多个条件） | `all` / `none`：条件对象（`kind`、`value` / `name`、`class`……）的列表，代替 `kind` | 满足所有 `all` 条件且不满足任何 `none` 条件的方法 |
| `findrefs`（规则集） | `rules`：查询列表（单个或 `all` / `none`）；每条规则的 `limit`（100） | 每条规则一行 `# r1 string "http://": 12 results` 及其 `r1 \| ...` 行；`structuredContent` 中的 `rules`，每条在 `next` 中带有完整的后续调用 |
| `callgraph` | `class`、`method`（方法名或 `name(params)ret`）、`direction`（`callers`/`callees`）、`depth`（2）、`max_nodes`（200）、`virtual` | `droidasc callgraph` 的树；`rows` 包含 `depth`、`parent`、`method`、`dex`、`repeated`、`via` |
| `hierarchy` | `class`、`direction`（`subclasses`/`supers`）、`depth`（16）、`max_nodes`（500）、`method` | `droidasc hierarchy` 的树和 `override` 行；`rows` 包含 `depth`、`parent`、`class`、`relation`、`dex`、`defines` |
| `listclass` | `prefix`、`offset`、`limit`（1000） | 类描述符 |
| `getmanifest` | `resolve` | 解码后的 XML（带 `resolve` 时引用以名称显示） |
| `manifest_summary` | `filter`（`all` / `exported`）、`kind`（记录类型：`provider`、`activity`、`uses-permission`、`deeplink`……；字符串或列表）、`name`（对记录做不区分大小写的 regex）、`offset`；或 `apks` / `dir` | `droidasc manifest-summary` 的记录；`exported`（除非用 `kind` / `name` 缩小范围，否则为默认值）保留其他应用可触达的内容（导出组件、deep link、非 signature 级权限、明文流量域名）。对于多个 APK：每个 APK 一行 `apkN \| package \| minSdk / targetSdk \| exported: 3 activity, 1 provider \| flags: debuggable,allowBackup,cleartext`，然后是它的记录 |
| `resources` | `query`（+ `resolve`）、`search`（+ `in`、`literal`）、`limit`，或 `xml`（APK 内的路径）；或 `apks` / `dir` | `droidasc resources` 的行（`0x7f0d0001 \| string/app_name [zh-rCN] \| "..."`），或解码后的 XML 文件 |

除 `open_apk` 外，每个工具都接受 `apk_id` 或 `apk` 路径（首次使用时打开）。结果以 `content` 携带 CLI
文本，以 `structuredContent` 携带相同的数据（分页工具还有 `total` 和 `next_offset`）。有些客户端（例如
Grok Build）会把两者都展示给模型，因此 `droidasc mcp` 默认发送精简的 `structuredContent`，省略文本中
已包含的、长度超过 256 字节的值（行、smali；由 `omitted` 列出名称）；`--structured full` 保留全部内容。
失败以 `isError: true` 结果返回；会话继续运行。整数参数可以用数字字符串给出，布尔值可以用 `"true"` /
`"false"`。

#### 输出预算与溢出文件

客户端会截断过长的工具结果（Grok Build 约在 20 KB 处），而且回复的每个字节在之后的每一轮都会被重新读取，
因此每条回复都控制在 `max_bytes`（默认 16384）之内。放不下的部分按 `spill` 的设置处理：

| `spill` | 回复 | 适用于 |
|---|---|---|
| `auto`（默认） | 放得下就给出文本，否则给出其前几行；然后是 `# full output (N lines, M bytes) in /abs/path.txt` 以及改为分页读取的调用。类会额外附带索引（`#   10-580 LJII(I)V`：每个方法在该文件中的行范围）。该文件同时作为一个 `resource_link` 内容项给出，`structuredContent` 中列出 `file`、`lines`、`bytes`、`index` | 能读文件的 agent（Claude Code、Codex、带文件工具的 Grok Build）：它们会 grep 或读取所需的行 |
| `always` | 每条回复都写入文件；内联只给出开头部分和路径 | 同上，适合连中等大小的回复也不想放进上下文的场景 |
| `never` | 由完整记录组成的页（一行及其下方缩进的行：一条 findrefs 结果及其上下文、一个 smali 方法），每页以 `# page 0 of 0..5 …; next page: tool {…}` 结尾，附带下一次调用的完整参数（`structuredContent` 中的 `next`） | agent 无法读取本地文件的客户端（远程或沙箱中的 agent） |

文件按内容命名（`out/<sha256>.txt`，权限 0600，目录 0700），位于 cache 目录中，没有 cache 目录时则位于
`$XDG_RUNTIME_DIR/droidasc/out`；相同的回复复用同一文件，目录保持在 64 MiB 以内（`--spill-mb`，最近最少
使用的优先清理；`--spill-mb 0` 改为分页）。`droidasc cache clear` 会将其与 cache 的其余部分一并删除。
多 APK 报告仍按 `cursor` 分页，当它还有更多页时，会把整个报告溢出到第一个文件旁边。把 `more` / `next`
提示作为 `cursor` 传回（作为 JSON 对象，或提示中的 `tool {…}` 文本），即会执行它所指向的调用。

`notifications/cancelled` 会停止正在运行的调用（尚未开始的工作被跳过，该调用不会收到回复）。每个 APK 都
被视为不可信：解压后会超过 1 GiB 或膨胀比超过 100:1 的条目会被拒绝（`--max-entry-mb`、`--max-ratio`），
且只有该 APK 失败。

#### 一次调用处理多个 APK

`findrefs`、`listclass`、`open_apk`、`manifest_summary` 和 `resources` 也接受 `apks`（路径列表）或 `dir`
（配合 `glob`，默认 `*.apk`，以及 `recursive`，默认 true）来代替单个 APK。所有 APK 的所有 DEX 都放进同一个
工作队列（最重的 APK 优先），回复中每个 APK 一节，每行都以其 `apk_id` 为前缀（以下摘自一次真实回复；一节
还可能以 `apkN | more | 3 more: findrefs {"apk_id":"apkN","kind":…,"offset":10,…}` 提示结尾，其中的 JSON
是后续调用的完整参数（也在 `structuredContent` 的 `next` 中），以及 `apkN | sdk | Landroidx/ 23, …` 折叠
计数和警告）。当同一查询已在某个 APK 的同一版本上运行过时，findrefs 批量扫描会从磁盘 cache 回放该 APK 的
结果行（单 APK 调用与批量调用共享这些结果），而多个 APK 中逐字节相同的 DEX 只搜索一次
（`structuredContent`：`apks_from_result_cache`、`dex_shared`）：

```
# findrefs method addJavascriptInterface over 312 APKs: 20 with hits, 103 hits, 0 errors, 193 ms
apk15 | 1 hits | /data/apks/com.android.carrierdefaultapp.apk
apk15 | classes.dex | Lcom/android/carrierdefaultapp/SlicePurchaseActivity;->setupWebView()V | Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
apk124 | 6 hits | /data/apks/com.android.vending.apk
apk124 | classes3.dex | Lzlc;->c(Ljava/lang/String;)V | Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
apk124 | classes3.dex | Lzln;-><init>(Lzlj;Lzjk;…)V | Lzlm;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
...
# nothing in the other 292 APKs
# APKs 0..4 of 20 shown (output budget 16384 bytes); call findrefs with cursor="1:4" for the rest
```

| 参数 | 作用 |
|---|---|
| `per_apk` (10) | 每个 APK 显示的行数；`more` 行说明如何对该 APK 分页 |
| `collapse_sdks`（多个 APK 时为 true）/ `sdk_prefixes` | 把常见 SDK 包（androidx、kotlin、gms、okhttp3……；`--sdk-prefixes` 替换该列表）中的命中折叠为按 SDK 的计数 |
| `group: "package"`、`package_depth` (3) | 每个包一行，给出命中数和一个示例，代替逐行结果 |
| `max_bytes` (16384) | 输出预算；放不下的整个 APK 小节留给 `cursor` |
| `cursor` | 单独传回给同一工具以获取下一页（会话保留最近 16 份报告） |
| `release` | 每个 APK 搜索完后从内存中丢弃其 DEX（默认：当所选 APK 的 DEX 超出内存预算时） |

用 [`benchmark/multi-apk/audit.py`](benchmark/multi-apk/audit.py) 做暴露面审计：在 Pixel 6 的 312 个系统 APK
（3.8 GB，405 个 DEX，1.28 GB 的 DEX）上运行多 APK 基准的 8 条规则，使用一个 `droidasc --no-cache mcp`：

| | 工具调用次数 | 回复文本 | 墙钟时间 | 峰值 RSS |
|---|---:|---:|---:|---:|
| 每条规则每个 APK 调用一次，一条规则的 312 次调用流水线化 | 2,496 | 762 KiB | 416 ms | 1,667 MB |
| 每条规则一次 `dir` 调用，只取第一页 | **8** | **166 KiB** | 480 ms | 1,695 MB |
| 每条规则一次 `dir` 调用，取所有 cursor 页 | 14 | 297 KiB | 480 ms | 1,691 MB |
| 每条规则一次 `dir` 调用，`release: true` | 8 | 166 KiB | 1,573 ms | 565 MB |

### Agent 会话基准

[dexsql-release agent audit](https://github.com/LSPosed/dexsql-release/tree/main/benchmarks/agent-audit)
的 17 个分析目标（47 步），由 [`benchmark/agent-audit/replay_mcp.py`](benchmark/agent-audit/replay_mcp.py) 在
抖音 40.7.0（343 MiB，56 个 DEX，551,080 个类）上回放。同一台机器（Linux，16 线程，12 GB），dexsql 0.1.1
linux-amd64 使用其自带的 `dexsql_replay.py` / `whole_suite.py` 测量；除非另有说明，asc-rs 使用
`--no-cache`。取 7 次的中位数。

| | asc-rs `mcp` | asc-rs `mcp`，磁盘 cache 已预热 | dexsql 0.1.1 MCP | rasc（每步一个进程） |
|---|---:|---:|---:|---:|
| 打开 APK | 77 ms | 18 ms | 589 ms | — |
| 整个会话：启动、打开、17 个目标、退出 | **218 ms** | 153 ms | 1,112 ms | 3,819 ms |
| 打开后每个目标，几何平均 | **5.3 ms** | 5.3 ms | 22.6 ms | — |
| 峰值 RSS | 646 MB | 522 MB | ~1.35 GB（两个进程） | 每步 ~350 MB |

每个目标都能找到其证据；其中三个预期 token 是 Java 写法，在 smali 中的形式不同
（`new java.io.File` → `Ljava/io/File;-><init>`，`36865` → `0x9001`，`return true` → `const/4 v0, 0x1` /
`return v0`）。dexsql 回答的是 SQL，包括 `findrefs` 无法表达的多跳调用图 join；这里只比较这些目标。

## 许可证

Apache-2.0，与原项目相同。
