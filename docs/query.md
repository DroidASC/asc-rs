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

- 程序里的字符串用 JSON 引号写在一行内。控制字符、行 / 段分隔符、双向控制符（`\u202e`、`\u2066`）、零宽及其他不可见
  格式字符（`\u200b`、`\ufeff`、tag 字符）都写成 `\uXXXX` 转义，行里显示的就是字符串实际的内容；smali 字符串字面量和
  HarmonyOS 反汇编转义同样的字符。（本版本新增：以前只转义控制字符。）
- 类名可写 `rs.asc.B` 或 `Lrs/asc/B;`。
- 成员在 CLI、MCP 和规则里写法统一：`Lrs/asc/B;->name(I)V`、`rs.asc.B->name`、`rs.asc.B#name`、`rs.asc.B.name`、
  `B.name`（不带包名的类匹配任意包）。只写名字是 regex / 子串，`=name` 精确匹配。
- 带签名时只命中该重载：`run(I)V`、只写参数的 `run(I)`、Java 写法 `run(int, String)`，字段 `f:I`。
- 字段引用按 Dalvik opcode 标记 `[read]`（`iget*` / `sget*`）或 `[write]`（`iput*` / `sput*`）。
  `findrefs app.apk field TARGET --access read` 或 `--access write` 只保留对应引用；不指定时两者都打印。
- 条件写作 `KIND:VALUE`（`string:`、`literal:`、`type:`、`method:`、`field:`），`rules` 中可用 `&` 组合，
  也可以用 `--file` 每行一条。
- 查不到时 stderr 会给出 `hint:`：搜了多少 DEX、大小写、APK 未定义的 framework 类、最接近的类或已有的方法等。

## 规则写法

DEX 与 HarmonyOS 共用一套写法，CLI（`all`、`rules`、`callgraph --to / --from / --unless`）和 MCP（`rule`、`rules`、
`all` / `none` 的字符串）都一样，只是 KIND 不同：

- 规则由 `KIND:VALUE` 用 `&` 连接，`!` 开头的部分表示方法不能匹配它。
- `&` 只在后面紧跟 `KIND:` 或 `!KIND:`（可有空白）且不在 `{}` / `()` 内时才连接两部分，否则属于值本身：
  `string:a&b` 是正则 `a&b`。`\&` 从不连接，`\{`、`\}`、`\(`、`\)` 不算括号。
- 方法集合：`method:{RULE}`（调用了代码匹配 RULE 的方法）、`method:{@FILE}` / `method:@FILE`（FILE 列出的方法）。
  前面加 `=` 只取集合自身的方法，加 `*` 沿所有父类型分派（见 skill）。HarmonyOS 上集合写在 `call:` 下
  （`call:{RULE}`、`call:{@FILE}`），因为单独的 `@` 是被调用路径的开头（`call:@ohos:net`）。
- 集合最多嵌套 8 层；未配对的 `}` 结束它所在的集合。
- 出错时给出规则、原因和列号：`bad rule "method:{string:a": expected `}` at column 17`。

本版本的变化：DEX 上后面不跟 `KIND:` 的 `&` 不再切分规则（以前报错，`string:a & ` 也报错），`method:{@FILE}` 是
`method:@FILE` 的新写法，`in:{…}` 里写多个条件时明确报错只收一个。HarmonyOS 上 `()` 内的 `&` 不再连接；花括号里的规则在第一个未配对的 `}` 处结束
（`call:{string:a}b}` 现在报错，以前是正则 `a}b`）；`call:={RULE}` 等同 `call:{RULE}`，`call:*{RULE}` 报错；未知 KIND
和空值的报错与其他错误格式一致（`bad rule "prop:": empty value at column 6`）。

## 多个文件作为一个程序

APK 参数也可以是 jar、`.dex`，或作为一个程序一起分析的多个文件：一个目录（其下所有 `*.apk`、`*.jar`、`*.zip`、`*.dex`），
或用 `,` 连接的多个路径（如 `framework.jar,services.jar,TeleService.apk`）。类层次、调用图和 findrefs 跨所有文件，
DEX 名带上所属文件（`services.jar/classes2.dex`），`callgraph` 行尾标 `[services.jar]`，`listclass` 多一列文件名；
没有 `classes*.dex` 的文件（只剩 odex/vdex）在 stderr 以 `# warning:` 列出（MCP 回复的 `notes` 字段和文本首行），需先 deodex。
同一个类在多个文件中都有定义时，findrefs 报告所有位置；`getclass` 按类加载器的顺序取：程序中靠前的文件（目录按路径排序，
`,` 列表按给出的顺序），同一文件内 `classes.dex`、`classes2.dex`……，并用 `# … also defined in …` 列出其他文件中的定义。
磁盘 cache 的解压 DEX 和索引按单个文件存放：改动一个 jar 只让它自己的条目失效，单独分析某个 jar 也复用程序里读过的条目；
渲染结果（L3）仍按整个程序存放。
