[English](query.en.md) | 简体中文

# 输出与查询写法

Android（DEX）侧的输出格式和查询写法；HarmonyOS 的对应内容见 [harmonyos.md](harmonyos.md)。

每行一条记录，列以 ` | ` 分隔，`#` 开头的行是表头、合计和提示，便于 grep / cut。`findrefs` 的一行是
`dex | 方法（完整签名） | 匹配内容`：

```
classes.dex | LWV/qE;-><clinit>()V | "http://", "http://www."
classes4.dex | Lcom/…/ConversationView;->onRestoreInstanceState(Landroid/os/Parcelable;)V | Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
classes.dex | Lrs/asc/Store;->update()V | Lrs/asc/Store;->count:I [read], Lrs/asc/Store;->count:I [write]
```

- 类名可写 `rs.asc.B` 或 `Lrs/asc/B;`。
- 成员在 CLI、MCP 和规则里写法统一：`Lrs/asc/B;->name(I)V`、`rs.asc.B->name`、`rs.asc.B#name`、`rs.asc.B.name`、
  `B.name`（不带包名的类匹配任意包）。只写名字是 regex / 子串，`=name` 精确匹配。
- 带签名时只命中该重载：`run(I)V`、只写参数的 `run(I)`、Java 写法 `run(int, String)`，字段 `f:I`。
- 字段引用按 Dalvik opcode 标记 `[read]`（`iget*` / `sget*`）或 `[write]`（`iput*` / `sput*`）。
  `findrefs app.apk field TARGET --access read` 或 `--access write` 只保留对应引用；不指定时两者都打印。
- 条件写作 `KIND:VALUE`（`string:`、`literal:`、`type:`、`method:`、`field:`），`rules` 中可用 `&` 组合，
  也可以用 `--file` 每行一条。
- 查不到时 stderr 会给出 `hint:`：搜了多少 DEX、大小写、APK 未定义的 framework 类、最接近的类或已有的方法等。

## 多个文件作为一个程序

APK 参数也可以是 jar、`.dex`，或作为一个程序一起分析的多个文件：一个目录（其下所有 `*.apk`、`*.jar`、`*.zip`、`*.dex`），
或用 `,` 连接的多个路径（如 `framework.jar,services.jar,TeleService.apk`）。类层次、调用图和 findrefs 跨所有文件，
DEX 名带上所属文件（`services.jar/classes2.dex`），`callgraph` 行尾标 `[services.jar]`，`listclass` 多一列文件名；
没有 `classes*.dex` 的文件（只剩 odex/vdex）在 stderr 以 `# warning:` 列出（MCP 回复的 `notes` 字段和文本首行），需先 deodex。
同一个类在多个文件中都有定义时，findrefs 报告所有位置；`getclass` 按类加载器的顺序取：程序中靠前的文件（目录按路径排序，
`,` 列表按给出的顺序），同一文件内 `classes.dex`、`classes2.dex`……，并用 `# … also defined in …` 列出其他文件中的定义。
磁盘 cache 的解压 DEX 和索引按单个文件存放：改动一个 jar 只让它自己的条目失效，单独分析某个 jar 也复用程序里读过的条目；
渲染结果（L3）仍按整个程序存放。
