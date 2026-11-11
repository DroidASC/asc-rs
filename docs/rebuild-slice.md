# asc-rebuild：闭包切片设计

状态：提案（2026-11-10）。使用方：[decompile-backends.md](decompile-backends.md)。

目标：给定若干目标类，输出一个合规的 DEX，里面除了目标类，还带上反编译器为了产出与整包同等质量的
源码所需要的上下文，同时尽量小、尽量快，并且输出确定（同一个闭包总是得到相同的字节）。现有的
`rebuild_class` 默认重建目标类和同一 DEX 内描述符位于其 `$` 命名空间下的所有附属类：
`LA;` 包含 `LA$a;`、`LA$a$b;`；`LA$a;` 包含 `LA$a$b;`，不包含 `LA;` 或兄弟类。
后续闭包切片接口须保留这个默认行为；多来源、壳类和仅类定义档仍属于本提案。

## 1. 结论

- 切片里的类分三档：**完整**（带代码）、**壳**（类定义和成员表，方法体换成合成的 `throw null`）、
  **仅类定义**（只有 `class_def`，没有成员）。
- 闭包由 asc-engine 计算（它有跨 DEX 的 `ClassGraph`），asc-rebuild 只负责按清单写出多类、多来源的 DEX。
  两边的接口是一份清单（`SliceSpec`），不是策略。
- 同一来源的多个完整类已可共用 ID 表写出，`class_def` 保留输入顺序。后续改动集中在三处：
  每个原始索引都要带上来源（哪个 DEX）；多来源的 `class_def` 做拓扑排序；新增壳类和
  合成方法体。id 表本来就是按内容排序去重的（`tables.rs` 的 `assign`），合并多个来源基本不需要改。
- invoke-custom、method handle 放到第三阶段支持（S3）。在那之前遇到这类类，按现在的做法报 `Unsupported`，
  由上层回退。

## 2. 为什么单类不够

单类切片已经带着所有被引用成员的 `method_id` / `field_id`，名字、所属类型和签名都在。缺的是**被引用类型
本身的定义**。

| 缺的东西 | 实测后果（MT2 `JSONObject`，整包对比单类切片） | 补法 |
|---|---|---|
| 父类和接口链、成员表 | 两个后端都丢 `@Override`；dexdec 推断不出 `PluginCompoundButton` 是 `PluginView`，多出强转 | 祖先类做成壳 |
| 被引用类型的父类 | 赋值兼容判断失败，多出冗余强转 `(Iterator) new C1ad8c2(…)` | 被引用类型至少给出仅类定义档 |
| 内部类、匿名类、lambda 类的代码 | jadx 不再内联匿名类，少约 40 行 | 附属类做成完整档 |
| `Throws` / `Signature` 注解 | jadx 丢了 `throws` 对应的 import；泛型信息缺失 | 壳类保留这几种系统注解 |
| 枚举 switch map、`$$Nest$` 访问器 | 枚举 switch 还原不出来；访问器调用残留（上一轮差分测试中，dexdec 有 6 个测试因此编译失败） | switch map 类做完整档；访问器所在的类做壳，只保留被调用访问器的方法体 |
| 全局命名 | jadx 按全局文件名冲突改名，单类时结果不同 | 不归 rebuild 管，由 asc 下发映射 |

## 3. 闭包计算（asc-engine）

输入：目标类集合 T（通常是一个顶层类，或一次批量请求里的多个类）。输出：`SliceSpec`，即每个类的
`(描述符, 来源 DEX, 档位, 需要保留代码的方法)`。

1. **附属类 A**，做完整档。按以下顺序确定，满足任一条件即可：
   - 成员类：外部类的 `dalvik.annotation.MemberClasses` 列出的类。
   - 反向归属：`EnclosingClass` / `EnclosingMethod` 指向 T 的类。用 `ClassGraph::defined_classes_matching`
     找出 `^L<外部类>\$` 前缀的候选，再逐个核对注解，不扫描全部类。
   - lambda 与合成类：T 的代码里 `new-instance` / `sget` / `invoke-static` 引用到的类，满足带 `@LambdaMethod`、
     类名含 `$$ExternalSyntheticLambda` / `$$Lambda$`、或者是只有一个构造器的 `ACC_SYNTHETIC` 类之一。
   - 枚举 switch map：被 T 的 `sget-object` 引用、名为 `$SwitchMap$*` / `$EnumSwitchMapping$*` 的字段，
     它所属的类。
   - Kotlin：`$WhenMappings`、`$DefaultImpls`、`$Companion`（只有当 T 的代码引用到它们时才算）。
   - 对 A 也做一遍，深度上限 3。R8 混淆后注解可能被删，所以后两条按引用判断，不依赖类名。
2. **外部类 O**：T 和 A 的外部类。如果外部类不在 T 中，做成壳；T 和 A 实际调用到的 `$$Nest$*` / `access$*`
   方法保留方法体，以便后端内联合成访问器。
3. **祖先 P**：T ∪ A ∪ O 在程序内的所有父类和接口，传递闭包。用 `ClassGraph::reachable` 沿父类方向查找，
   做成壳。平台类（程序里不存在定义的）不放进切片，交给后端自带的 classpath。
4. **被引用类型 R**：T ∪ A 的代码、签名、catch 类型里出现、但不在上面三类中的程序内类型，做成仅类定义档；
   它们的祖先也一并补成仅类定义档，这样才能判断赋值兼容。
5. **选来源**：同一个描述符出现在多个 DEX 里时，取 engine 解析类时选中的那个（程序顺序中的第一个，
   和 `getclass` 一致）。
6. **预算**：见 §7，超出时按顺序降档。

闭包计算是只读的，大部分开销在读 T ∪ A 的字节码。这一步复用 `collect` 已经收集到的类型集合（见 §5.1 的
两遍方案），不额外遍历字节码。

## 4. 三个档位

| 档位 | `class_def` | `class_data` | 方法体 | 注解 | 静态值 | debug info |
|---|---|---|---|---|---|---|
| 完整 | 原样 | 原样 | 原样 | 原样 | 原样 | 原样 |
| 壳 | 原样 | 非 private 成员，加上 T ∪ A 引用到的成员 | 合成的 `throw null`；清单指定的方法保留原样 | 只留系统注解（见下） | 保留 | 去掉（被保留方法体的方法除外） |
| 仅类定义 | 原样 | 无 | — | 只留 `Signature`、`InnerClass`、`EnclosingClass` | 无 | 无 |

- **系统注解白名单**：`dalvik.annotation.{Signature, Throws, InnerClass, EnclosingClass, EnclosingMethod,
  MemberClasses, AnnotationDefault}`、`kotlin.Metadata`。其它注解去掉，因为它们会拖进大量类型和字符串。
  可以用开关 `keep_annotations` 全部保留。
- **合成方法体**：DEX 规范要求，非 `abstract`、非 `native` 的方法必须有 `code_item`（`code_off = 0` 只能
  用于这两种），所以不能简单清空，也不能改访问标志（改了会影响后端判断 override 和修饰符）。统一写成：
  ```
  registers_size = ins_size + 1, ins_size = 参数字数(+1 给 this), outs_size = 0, tries_size = 0,
  debug_info_off = 0, insns = [0x0012 /* const/4 v0, #0 */, 0x0027 /* throw v0 */]
  ```
  这样的方法体能通过校验，所有壳方法共用一份。后端通过 `manifest.shells` 得知哪些类是壳，不会把它们
  输出出来。
- **为什么壳类保留非 private 成员**：判断 `@Override`、重载决议、字段遮蔽都需要知道父类“有哪些成员”，
  不能只留被引用的那几个。private 成员对子类不可见，可以去掉。

## 5. asc-rebuild 改动

### 5.1 接口

```rust
/// 一个来源 DEX。`id` 由调用方编号，在一次 rebuild 内必须唯一。
pub struct Source<'a> { pub id: u16, pub dex: &'a Dex<'a> }

pub enum Depth {
    Full,
    /// `keep_code`：保留原方法体的方法（原 method_idx）。
    Shell { keep_code: BTreeSet<u32> },
    DefOnly,
}

pub struct SliceClass { pub source: u16, pub descriptor: String, pub depth: Depth }

pub struct SliceSpec<'a> {
    pub sources: Vec<Source<'a>>,
    pub classes: Vec<SliceClass>,
    pub keep_annotations: bool,
}

pub struct Slice {
    pub bytes: Vec<u8>,
    pub sha256: [u8; 32],
    pub classes: Vec<(String, DepthKind)>,   // 实际写出的类和档位（降档之后）
    pub stats: Stats,
    pub timings: Timings,
}

pub fn rebuild_slice(spec: &SliceSpec<'_>) -> Result<Slice>;

/// 兼容入口：一个来源，目标类及其 `$` 附属类均为完整档。
pub fn rebuild_class(dex: &Dex<'_>, descriptor: &str) -> Result<Rebuilt>;
```

`rebuild_class` 改为包装 `rebuild_slice` 时，须传入目标类及其同一 DEX 内的全部 `$` 附属类。
现有的测试（`tests/rebuild.rs`、`tests/mutf8.rs`、`asc-smali` 的测试）必须继续通过；
没有附属类时保持原有输出，附属类集合及重映射由 `tests/nested.rs` 验证。

### 5.2 各阶段

**hollow**（`hollow.rs`）

- `Hollow::extract(dex, descriptor)` 增加一个 `depth` 参数：
  - 壳：只收集 `keep_code` 里列出的方法的 `code_item` / `debug_info`，按 §4 过滤 `class_data` 和注解；
  - 仅类定义：只保留 `def`、接口和白名单注解。
- 注解相关的 map 目前以原始文件偏移为键，改成 `(source, offset)`，否则不同 DEX 里相同的偏移会撞在一起。

**collect**（`collect.rs`）

- `RefSet` 里的元素从 `u32` 改成 `(u16 source, u32 idx)`；`close` 按各自的来源 DEX 做闭包。
- 合成方法体本身不引用任何常量。壳方法的 `method_id` 仍然要收集（`class_data` 里要用到），它连带的
  proto、名字、类型也一起收集。
- 两遍方案：engine 先用 `collect` 跑一遍 T ∪ A，拿到被引用的类型集合，再决定 O / P / R；这一遍的结果直接
  复用，不重复遍历。为此把 `collect::collect` 设为 `pub`，返回只读的类型集合视图。

**tables**（`tables.rs`）

- 原始索引改成 `(source, idx)`，`*_map` 改成 `HashMap<(u16, u32), u32>`。
- 排序键已经是按内容计算的（字符串用 UTF-16 内容，类型用新的字符串索引，proto、field、method 用新索引
  组成的元组），所以来自不同 DEX 的同一个项会自然合并成一项，算法不用改。
- `check_limit` 不变（type、proto、field、method 各自最多 65535 项）。字符串没有上限，但非 jumbo 的
  `const-string` 只能放 16 位索引，这个现有检查保留。

**writer**（`writer.rs`）

- `class_defs` 写 N 项，并做**拓扑排序**：规范要求，如果某个类的父类或接口也在本文件里，它们必须排在
  这个类前面。同一层内按描述符排序，保证输出确定。如果出现环（畸形输入），报 `RebuildError::Bytecode`
  这类输入限制错误，不报内部错误。
- 每种数据段在 map_list 里只能出现一次，而且同类型的项必须连续。所以各段的写法要从“写一个类的各段”
  改成“按段遍历所有类”：所有类的 `class_data` 写在一起，所有 `code_item` 写在一起，依此类推。
  现有的顺序是 string_data → type_list → debug → code → class_data → 注解 → encoded_array，保持不变。
- 合成方法体只写一份 `code_item`，所有壳方法的 `code_off` 都指向它。
- DEX 版本取所有来源中的最大值（规则同现在：≥41 写 040，<35 写 035）。

### 5.3 确定性

- 所有输出顺序都只由内容键、描述符和 `(source, offset)` 决定，不依赖 HashMap 的遍历顺序。现有代码在写出
  前都已经排过序，改动时要保持这一点。
- `Slice::sha256` 对最终字节计算（DEX 自带的 SHA-1 签名覆盖不到整个文件头）。它作为切片文件名和
  反编译结果缓存键的一部分。
- 来源编号由 engine 按程序顺序分配，所以同一个程序、同一个闭包，总是产生相同的字节。

## 6. invoke-custom 与 method handle（S3）

目前 `collect` 一遇到 `CallSiteRef` / `MethodHandleRef` / `VALUE_METHOD_HANDLE` 就报 `Unsupported`。
支持它们需要：

- collect：收集 `call_site_id → call_site_item`（一个 encoded_array，内容是 method handle、名字字符串、
  method type proto，以及额外参数），以及 `method_handle_item`（类型，加上 field 或 method 的 id）。
  额外参数里可能出现 `VALUE_METHOD_TYPE` / `VALUE_METHOD_HANDLE` / 字符串 / 类型，要递归收集。
- tables：新增 `call_sites` 和 `method_handles` 两张表。method handle 按 `(type, 新 field/method 索引)` 排序；
  call site 按 `call_site_item` 的偏移顺序，规范要求按 `call_site_off` 升序。
- writer：在 `class_defs` 之后写 `CALL_SITE_ID_ITEM`（0x0007）和 `METHOD_HANDLE_ITEM`（0x0008），在 data 区
  写 `CALL_SITE_ITEM`（0x2007）；改写 `invoke-custom`(/range) 和 `const-method-handle` 的操作数；`Remap`
  里的 `method_handle` 改成真正查表；输出版本至少为 038。
- 测试：用 smali 3（jadx lib 里自带 `smali-3.0.9.jar`）手写包含 `invoke-custom`、`const-method-handle` 和
  method handle 注解值的样本，与 `dexdump -d` 的输出对照。

注意：后端自身可能也不支持这类指令（dexdec 目前对 0xfa–0xff 不做解码）。切片层支持只能保证“喂得进去”，
反编译能否成功由后端决定。

## 7. 预算与降档

- 硬限制：type / proto / field / method 各自最多 65535 项（16 位索引）。
- 软预算：默认切片不超过 4 MiB，或程序内的类不超过 2000 个，可以配置。
- 超出时按以下顺序降档，每降一步就重新计算：
  1. R 中各类的祖先 → 去掉；
  2. R → 去掉（被引用的 `method_id` / `field_id` 仍然存在，只是少了类定义）；
  3. P 中的壳 → 仅类定义（只保留继承链，不保留成员表）；
  4. O 中未保留代码的成员 → 去掉；
  5. 仍然超出时，T ∪ A 不再降档，报 `TooManyItems`，由上层回退到默认目标类及 `$` 附属类切片。
     默认切片也无法重建时，沿用从原 DEX 反汇编的兜底。
- 实际降到哪一档写在 `Slice::classes` 里。上层把它放进后端返回结果的头部，用户和 agent 能看到这次的
  上下文是否完整。

## 8. 接入

- engine：新增 `Engine::slice(targets, policy) -> Result<SliceFile>`。它计算闭包，调用 `rebuild_slice`，把
  结果按 `sha256` 写到 `<cache>/slices/<前两位>/<哈希>.dex`（先写临时文件再 rename，和现有 cache 的写法
  一致；切片计入 L2 的容量和淘汰），并返回路径和清单。
- CLI：`asc getclass --dump-dex FILE` 保持默认目标类及 `$` 附属类切片；新增 `--closure` 输出更完整的闭包切片，再加 `--manifest`
  把清单打印到 stderr，方便直接拿去喂 jadx 等工具。
- MCP：不单独做切片工具，由 `decompile` 内部使用。

## 9. 验证

| 项 | 方法 |
|---|---|
| 合规性 | 每个切片都要能被 `asc_dex::Dex::parse` 解析、被 `dexdump -d` 读取；再加一个可选测试：用 `d8` 把切片和平台库一起编译，不报错 |
| 默认行为兼容 | 没有附属类时保留原有输出；`tests/nested.rs` 验证目标及 `$` 附属类集合、各类元数据、共享注解和重复重建的字节一致性 |
| 合并正确 | 跨 DEX 的闭包（父类在 `classes2.dex`）：把切片 smali 化后，与分别从原始 DEX 反汇编的结果逐行比较 |
| 确定性 | 同一个闭包构建两次，比较哈希；打乱 `SliceSpec.classes` 的顺序后结果不变 |
| 质量 | 差分：dexdec、jadx 分别处理“整包 / 单类切片 / 闭包切片”三种输入，统计相对整包的差异行数。目标是闭包切片的差异不超过单类切片的 1/5 |
| 速度 | MT2 等 3 个样本，各取 100 个类：闭包计算加写出的 P95 不超过 50 ms；jadx 处理闭包切片的耗时不超过整包的 1/5 |

## 10. 分期

| 期 | 内容 |
|---|---|
| S1 | 多来源的 `(source, idx)` 改造；N 个完整档类的写出（拓扑排序、按段遍历所有类）；`rebuild_class` 改为包装；`--closure` 先只做 T ∪ A |
| S2 | 壳和仅类定义两档、合成方法体、注解白名单；engine 计算 O / P / R；预算与降档；切片缓存 |
| S3 | invoke-custom 和 method handle |

## 11. 待定

- **R 类常量**：jadx 能把资源 id 常量还原成 `R.id.xxx`，前提是 R 类在场。是否在目标代码出现 `0x7f……`
  常量时，把对应的 `R$*` 做成只带静态值的壳？还是交给 asc 根据 `resources.arsc` 自己替换？
- **壳类保留哪些成员**：目前是“非 private 成员 + 被引用成员”。对于 Android support 库这种巨大的祖先类，
  这样可能会撑爆预算；是否改成“只保留与 T 中方法同名的成员”？需要 S2 实测后决定。
- 批量请求（一次处理多个顶层类）时，是合并成一个大切片，还是每个顶层类各出一个切片？前者能共享壳类，
  后者缓存命中率更高。
