use asc_dex::Dex;
use asc_fixture::{make_dex, make_static_field_dex};
use asc_smali::{disassemble_class, Options};

#[test]
fn single_method_listing_maps_pcs_to_lines() {
    let data = asc_fixture::make_rich_dex();
    let dex = Dex::parse(&data).unwrap();
    let find = |m: &str| (0..dex.method_count()).find(|&i| dex.method_display(i).unwrap() == m).unwrap();
    let l = asc_smali::disassemble_method(&dex, find("Lexample/Rich;->compute"), Options::default()).unwrap();
    let lines: Vec<&str> = l.text.lines().collect();
    assert_eq!(lines[0], ".method public static compute(II)I");
    assert_eq!(*lines.last().unwrap(), ".end method");
    // The method alone renders exactly as it does inside its class listing.
    let class = disassemble_class(&dex, "Lexample/Rich;", Options::default()).unwrap();
    assert!(class.contains(&l.text), "{}", l.text);
    // const-string at byte 0x20 (pc 0x10) and invoke-static at pc 0x12.
    let hit = format!("    const-string v0, \"{}\"", asc_fixture::RICH_STRING);
    assert_eq!(lines[l.line_of(0x10).unwrap() as usize], hit, "{}", l.text);
    assert!(lines[l.line_of(0x12).unwrap() as usize].starts_with("    invoke-static {v2, v3}"), "{}", l.text);
    assert_eq!(l.line_of(0x11), None);
    // Debug positions: pc 8 -> 10, 13 -> 12, 16 -> 14.
    assert_eq!((l.source_line(7), l.source_line(8), l.source_line(0x0f), l.source_line(0x12)), (None, Some(10), Some(12), Some(14)));
    // Abstract methods have no code but still render.
    let h = asc_smali::disassemble_method(&dex, find("Lexample/Rich;->handle"), Options::default()).unwrap();
    assert!(h.text.starts_with(".method public abstract handle(Ljava/lang/String;I)V\n") && h.insns.is_empty(), "{}", h.text);
    // A method the DEX only references (no definition) is an error.
    assert!(asc_smali::disassemble_method(&dex, find("Ljava/lang/Object;-><init>"), Options::default()).is_err());
}

#[test]
fn disassembles_fixture_class() {
    let data = make_dex();
    let dex = Dex::parse(&data).unwrap();
    let text = disassemble_class(&dex, "Lexample/Test;", Options::default()).unwrap();
    assert!(text.starts_with(".class public Lexample/Test;\n.super Ljava/lang/Object;\n"), "{text}");
    assert!(
        text.contains(".method public static first()V\n    .registers 1\n\n    const-string v0, \"token\"\n    return-void\n.end method"),
        "{text}"
    );
    assert!(text.contains(".method public static second()V"));
}

#[test]
fn disassembles_rebuilt_static_class() {
    let out = asc_rebuild::rebuild_class_bytes(&make_static_field_dex(), "Lexample/Statics;").unwrap();
    let dex = Dex::parse(&out.bytes).unwrap();
    let text = disassemble_class(&dex, "Lexample/Statics;", Options::default()).unwrap();
    assert!(text.contains(".field public static FIRST:I = 0xb\n"), "{text}");
    assert!(text.contains(".field public static SECOND:I = 0x16\n"), "{text}");
    assert!(text.contains("sget v0, Lexample/Statics;->SECOND:I\n    return v0"), "{text}");
}

// ---------------------------------------------------------------------------
// Rich fixture
// ---------------------------------------------------------------------------

use asc_fixture::{make_rich_dex, make_truncated_insn_dex};

const RICH: &str = "Lexample/Rich;";

fn rebuilt_rich(opts: Options) -> String {
    let out = asc_rebuild::rebuild_class_bytes(&make_rich_dex(), RICH).unwrap();
    let dex = Dex::parse(&out.bytes).unwrap();
    disassemble_class(&dex, RICH, opts).unwrap()
}

fn original(descriptor: &str) -> String {
    let data = make_rich_dex();
    let dex = Dex::parse(&data).unwrap();
    disassemble_class(&dex, descriptor, Options::default()).unwrap()
}

#[test]
fn class_header_interfaces_annotations_and_fields() {
    let text = rebuilt_rich(Options::default());
    let expected = concat!(
        ".class public abstract Lexample/Rich;\n",
        ".super Ljava/lang/Object;\n",
        ".source \"Rich.java\"\n",
        "\n",
        "\n",
        "# interfaces\n",
        ".implements Lexample/Iface;\n",
        "\n",
        "\n",
        "# annotations\n",
        ".annotation runtime Lexample/Marker;\n",
        "    value = \"c\"\n",
        ".end annotation\n",
        "\n",
        "\n",
        "# static fields\n",
        ".field public static COUNT:I = 0x7\n",
        "    .annotation runtime Lexample/Marker;\n",
        "        value = \"f\"\n",
        "    .end annotation\n",
        ".end field\n",
        "\n",
        ".field public static NAME:Ljava/lang/String; = \"héllo wörld\"\n",
        "\n",
        "\n",
        "# instance fields\n",
        ".field public value:I\n",
        "\n",
        "\n",
        "# direct methods\n",
        ".method public constructor <init>()V\n",
        "    .registers 1\n",
        "\n",
        "    invoke-direct {v0}, Ljava/lang/Object;-><init>()V\n",
        "    return-void\n",
        ".end method\n",
    );
    assert!(text.starts_with(expected), "{text}");
}

#[test]
fn packed_switch_payload_before_switch_with_try_catch_lines_and_params() {
    let text = rebuilt_rich(Options::default());
    let expected = concat!(
        ".method public static compute(II)I\n",
        "    .registers 4\n",
        "    .param v2, \"a\"    # I\n",
        "    .param v3, \"b\"    # I\n",
        "\n",
        "    :pswitch_data_0\n",
        "    .packed-switch 0x0\n",
        "        :pswitch_d\n",
        "        :pswitch_10\n",
        "    .end packed-switch\n",
        "    :try_start_0\n",
        "    .line 10\n",
        "    packed-switch v2, :pswitch_data_0\n",
        "    const/4 v0, 0x7\n",
        "    :try_end_0\n",
        "    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_17\n",
        "    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_1a\n",
        "    .catchall {:try_start_0 .. :try_end_0} :catchall_1d\n",
        "    return v0\n",
        "    :pswitch_d\n",
        "    .line 12\n",
        "    sget v0, Lexample/Rich;->COUNT:I\n",
        "    return v0\n",
        "    :pswitch_10\n",
        "    .line 14\n",
        "    const-string v0, \"héllo wörld\"\n",
        "    invoke-static {v2, v3}, Lexample/Rich;->compute(II)I\n",
        "    move-result v0\n",
        "    return v0\n",
        "    :catch_17\n",
        "    move-exception v1\n",
        "    const/4 v0, -0x1\n",
        "    return v0\n",
        "    :catch_1a\n",
        "    move-exception v1\n",
        "    const/4 v0, -0x2\n",
        "    return v0\n",
        "    :catchall_1d\n",
        "    move-exception v1\n",
        "    throw v1\n",
        ".end method\n",
    );
    assert!(text.contains(expected), "{text}");
}

#[test]
fn sparse_switch_fill_array_data_and_jumbo_string() {
    let text = rebuilt_rich(Options::default());
    let jumbo = concat!(
        ".method public static jumbo()Ljava/lang/String;\n",
        "    .registers 1\n",
        "\n",
        "    const-string/jumbo v0, \"héllo wörld\"\n",
        "    return-object v0\n",
        ".end method\n",
    );
    assert!(text.contains(jumbo), "{text}");
    let table = concat!(
        ".method public static table()[I\n",
        "    .registers 2\n",
        "\n",
        "    const/4 v1, 0x1\n",
        "    sparse-switch v1, :sswitch_data_e\n",
        "    const/4 v0, 0x3\n",
        "    new-array v0, v0, [I\n",
        "    fill-array-data v0, :array_14\n",
        "    return-object v0\n",
        "    :sswitch_b\n",
        "    const/4 v0, 0x0\n",
        "    return-object v0\n",
        "    nop\n",
        "    :sswitch_data_e\n",
        "    .sparse-switch\n",
        "        0x2a -> :sswitch_b\n",
        "    .end sparse-switch\n",
        "    :array_14\n",
        "    .array-data 4\n",
        "        0x1\n",
        "        0x2\n",
        "        0x3\n",
        "    .end array-data\n",
        ".end method\n",
    );
    assert!(text.contains(table), "{text}");
}

#[test]
fn abstract_method_keeps_param_and_annotations() {
    let text = rebuilt_rich(Options::default());
    let expected = concat!(
        "# virtual methods\n",
        ".method public abstract handle(Ljava/lang/String;I)V\n",
        "    .param v1    # Ljava/lang/String;\n",
        "        .annotation runtime Lexample/Marker;\n",
        "            value = \"p\"\n",
        "        .end annotation\n",
        "    .end param\n",
        "    .annotation runtime Lexample/Marker;\n",
        "        value = \"m\"\n",
        "    .end annotation\n",
        ".end method\n",
        "\n",
        ".method public run()V\n",
        "    .registers 2\n",
        "\n",
        "    iget v0, v1, Lexample/Rich;->value:I\n",
        "    return-void\n",
        ".end method\n",
    );
    assert!(text.ends_with(expected), "{text}");
    let iface = original("Lexample/Iface;");
    assert!(iface.ends_with("# virtual methods\n.method public abstract run()V\n.end method\n"), "{iface}");
}

#[test]
fn method_filter_keeps_one_exact_signature() {
    use asc_smali::{disassemble_class_method, normalize_method_signature, SmaliError};
    let out = asc_rebuild::rebuild_class_bytes(&make_rich_dex(), RICH).unwrap();
    let dex = Dex::parse(&out.bytes).unwrap();
    let full = disassemble_class(&dex, RICH, Options::default()).unwrap();
    let text = disassemble_class_method(&dex, RICH, Options::default(), Some("compute(II)I")).unwrap();
    // The class header, interfaces and class annotations stay; fields and
    // every other method go.
    assert!(text.starts_with(".class public abstract Lexample/Rich;\n.super Ljava/lang/Object;\n"), "{text}");
    assert!(text.contains(".implements Lexample/Iface;") && text.contains(".annotation runtime Lexample/Marker;"), "{text}");
    assert!(!text.contains(".field") && !text.contains("# virtual methods"), "{text}");
    assert_eq!(text.matches(".method ").count(), 1, "{text}");
    let start = full.find(".method public static compute(II)I").unwrap();
    let end = start + full[start..].find(".end method\n").unwrap() + ".end method\n".len();
    assert!(text.ends_with(&full[start..end]), "{text}");
    // A virtual, code-less one, with whitespace inside the descriptors.
    let text = disassemble_class_method(&dex, RICH, Options::default(), Some("handle( Ljava/lang/String; I ) V")).unwrap();
    assert!(text.contains("# virtual methods\n.method public abstract handle(Ljava/lang/String;I)V"), "{text}");
    assert!(!text.contains("# direct methods"), "{text}");
    // Constructors match by their real name.
    assert!(disassemble_class_method(&dex, RICH, Options::default(), Some("<init>()V")).unwrap().contains("constructor <init>()V"));

    assert!(matches!(
        disassemble_class_method(&dex, RICH, Options::default(), Some("compute(I)I")),
        Err(SmaliError::MethodNotFound(s)) if s == "compute(I)I"
    ));
    for bad in ["compute", "compute(II", "(II)I", "compute(II)", "compute(II)  "] {
        assert!(matches!(normalize_method_signature(bad), Err(SmaliError::BadMethodSignature(_))), "{bad}");
        assert!(disassemble_class_method(&dex, RICH, Options::default(), Some(bad)).is_err(), "{bad}");
    }
    // Only the descriptors are compacted, as in Python; the name is kept.
    assert_eq!(normalize_method_signature("run ( I , J ) V").unwrap(), "run (I,J)V");
    assert_eq!(normalize_method_signature("run(I J)V").unwrap(), "run(IJ)V");
    assert_eq!(disassemble_class_method(&dex, RICH, Options::default(), None).unwrap(), full);
}

#[test]
fn options_disable_lines_and_param_names() {
    let text = rebuilt_rich(Options { line_numbers: false, param_names: true });
    assert!(!text.contains(".line"), "{text}");
    assert!(text.contains(".param v2, \"a\"    # I\n"), "{text}");
    let text = rebuilt_rich(Options { line_numbers: true, param_names: false });
    assert!(text.contains("    .line 10\n"), "{text}");
    assert!(!text.contains(".param v2"), "{text}");
    // the annotated parameter of the abstract method is still emitted
    assert!(text.contains("    .param v1    # Ljava/lang/String;\n        .annotation runtime Lexample/Marker;\n"), "{text}");
}

#[test]
fn unknown_opcode_is_commented_and_skipped() {
    let text = original("Lexample/Broken;");
    assert!(
        text.contains(".method public static broken()V\n    .registers 1\n\n    # unknown opcode 0x3e\n    return-void\n.end method\n"),
        "{text}"
    );
}

#[test]
fn invoke_custom_renders_call_site_index() {
    let text = original("Lexample/Custom;");
    assert!(text.contains("    invoke-custom {}, call_site@0\n    return-void\n"), "{text}");
}

#[test]
fn truncated_instruction_is_commented() {
    let data = make_truncated_insn_dex();
    let dex = Dex::parse(&data).unwrap();
    let text = disassemble_class(&dex, "Lexample/Cut;", Options::default()).unwrap();
    assert!(
        text.contains("    return-void\n    # truncated instruction const-string (0x1a) runs past the end of the code\n.end method\n"),
        "{text}"
    );
}

#[test]
fn inconsistent_register_counts_do_not_panic() {
    let mut data = make_rich_dex();
    let dex = Dex::parse(&data).unwrap();
    let (_, def) = dex.find_class_def(RICH.as_bytes()).unwrap().unwrap();
    let cd = dex.class_data(def.class_data_off).unwrap();
    let compute = cd.methods().find(|m| dex.string(dex.method_id(m.method_idx).unwrap().name_idx).unwrap() == "compute").unwrap();
    let off = compute.code_off as usize;
    data[off + 2..off + 4].copy_from_slice(&9u16.to_le_bytes()); // ins_size 9 > registers_size 4
    let dex = Dex::parse(&data).unwrap();
    let text = disassemble_class(&dex, RICH, Options::default()).unwrap();
    assert!(
        text.contains("    .registers 4\n    # malformed code_item: ins_size 9 exceeds registers_size 4\n    .param v0, \"a\"    # I\n"),
        "{text}"
    );
}

#[test]
fn single_byte_corruption_never_panics() {
    let base = make_rich_dex();
    let data_off = Dex::parse(&base).unwrap().header().data_off as usize;
    let mut data = base.clone();
    for pos in data_off..base.len() {
        for flip in [0xffu8, 0x80, 0x01] {
            data[pos] = base[pos] ^ flip;
            if let Ok(dex) = Dex::parse(&data) {
                for class in [RICH, "Lexample/Iface;", "Lexample/Broken;", "Lexample/Custom;"] {
                    let _ = disassemble_class(&dex, class, Options::default());
                }
            }
        }
        data[pos] = base[pos];
    }
}

#[test]
fn high16_literals_render_signed() {
    use asc_fixture::{ClassSpec, CodeSpec, DexBuilder, MethodSpec};
    const H: &str = "Lexample/High;";
    let mut d = DexBuilder::new();
    d.method(H, "hi", "V", &[]);
    let mut ids = d.resolve();
    let m = ids.method(H, "hi", "V", &[]);
    // const/high16 v0, 0x8000 ; const/high16 v0, 0x7fff ; const-wide/high16 v0, 0x8000 ; return-void
    let insns = vec![0x15, 0x00, 0x00, 0x80, 0x15, 0x00, 0xff, 0x7f, 0x19, 0x00, 0x00, 0x80, 0x0e, 0x00];
    ids.add_class(ClassSpec {
        descriptor: H.into(),
        access: 0x1,
        direct_methods: vec![MethodSpec { idx: m, access: 0x9, code: Some(CodeSpec { registers: 2, insns, ..Default::default() }) }],
        ..Default::default()
    });
    let data = ids.finish();
    let dex = Dex::parse(&data).unwrap();
    let text = disassemble_class(&dex, H, Options::default()).unwrap();
    assert!(
        text.contains(
            "    const/high16 v0, -0x80000000
"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "    const/high16 v0, 0x7fff0000
"
        ),
        "{text}"
    );
    assert!(
        text.contains(
            "    const-wide/high16 v0, -0x8000000000000000L
"
        ),
        "{text}"
    );
}
